package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type producerFixture struct {
	SetupManifest            model.SetupOperation               `json:"setupManifest"`
	WorkspaceRequestManifest model.ManagedWorkspaceRequestV1    `json:"workspaceRequestManifest"`
	WorkspaceCatalogReport   model.ProjectCatalogReportV1       `json:"workspaceCatalogReport"`
	ServiceManifest          model.ManagedServiceV1             `json:"serviceManifest"`
	ServiceReport            model.ManagedServiceReportV1       `json:"serviceReport"`
	EnrollmentRequest        model.ManagedServiceFetchRequestV1 `json:"enrollmentRequest"`
	EnrollmentResponse       model.ManagedServiceEnrollmentV1   `json:"enrollmentResponse"`
	InstructionRequest       model.ManagedServiceFetchRequestV1 `json:"instructionRequest"`
	InstructionResponse      model.ManagedServiceInstructionV1  `json:"instructionResponse"`
}

type sandboxSupervisorReceiptFixture struct {
	FormatVersion   int             `json:"formatVersion"`
	NativeVersion   string          `json:"nativeVersion"`
	ProviderID      string          `json:"providerId"`
	ModelID         string          `json:"modelId"`
	AuthMode        string          `json:"authMode"`
	BindingRevision int64           `json:"bindingRevision"`
	UnboundStart    json.RawMessage `json:"unboundStart"`
	UnboundStatus   json.RawMessage `json:"unboundStatus"`
	Rebind          json.RawMessage `json:"rebind"`
	BoundStart      json.RawMessage `json:"boundStart"`
	BoundStatus     json.RawMessage `json:"boundStatus"`
	Admit           json.RawMessage `json:"admit"`
	// NegotiatedStatus is an actual packaged-Sandbox producer status receipt
	// captured with runtimeContractVersion 0.1.32 negotiation (nativeGuard).
	NegotiatedStatus json.RawMessage `json:"negotiatedStatus"`
}

type fakeManagedControl struct {
	fixture      producerFixture
	enrollErr    error
	enrollments  []model.ManagedServiceFetchRequestV1
	instructions []model.ManagedServiceFetchRequestV1
}

func (control *fakeManagedControl) ManagedServiceEndpoint() string {
	return "https://api.warpmetal.example"
}

func (control *fakeManagedControl) ManagedServiceEnrollment(_ context.Context, serviceID string, request model.ManagedServiceFetchRequestV1) (model.ManagedServiceEnrollmentV1, error) {
	if serviceID != control.fixture.ServiceManifest.Identity.ServiceRegistrationID {
		return model.ManagedServiceEnrollmentV1{}, errors.New("wrong service")
	}
	control.enrollments = append(control.enrollments, request)
	if control.enrollErr != nil {
		return model.ManagedServiceEnrollmentV1{}, control.enrollErr
	}
	return control.fixture.EnrollmentResponse, nil
}

func (control *fakeManagedControl) ManagedServiceInstructions(_ context.Context, serviceID string, request model.ManagedServiceFetchRequestV1) (model.ManagedServiceInstructionV1, error) {
	if serviceID != control.fixture.ServiceManifest.Identity.ServiceRegistrationID {
		return model.ManagedServiceInstructionV1{}, errors.New("wrong service")
	}
	control.instructions = append(control.instructions, request)
	return control.fixture.InstructionResponse, nil
}

type managedInvocation struct {
	action  string
	request map[string]any
}

type controlledManagedRuntime struct {
	base            *fakeManagedRuntime
	mu              sync.Mutex
	executeCalls    int
	executeStarted  chan struct{}
	executeCanceled chan struct{}
}

func (runtime *controlledManagedRuntime) ExecManagedSupervisor(ctx context.Context, sandboxID string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	return runtime.base.ExecManagedSupervisor(ctx, sandboxID, action, payload)
}

func (runtime *controlledManagedRuntime) ExecManagedWorker(ctx context.Context, sandboxID string, action containers.ManagedWorkerAction, payload []byte) ([]byte, []byte, error) {
	if action != containers.ManagedWorkerExecute {
		return runtime.base.ExecManagedWorker(ctx, sandboxID, action, payload)
	}
	runtime.mu.Lock()
	runtime.executeCalls++
	if runtime.executeCalls == 1 {
		close(runtime.executeStarted)
	}
	runtime.mu.Unlock()
	<-ctx.Done()
	select {
	case <-runtime.executeCanceled:
	default:
		close(runtime.executeCanceled)
	}
	return nil, nil, ctx.Err()
}

func (runtime *controlledManagedRuntime) calls() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.executeCalls
}

type fakeManagedRuntime struct {
	store                      *state.Store
	serviceID                  string
	startCalls                 int
	enrollmentCalls            int
	failStart                  bool
	failRebind                 bool
	invocations                []managedInvocation
	fixture                    producerFixture
	actualRebindReceipt        bool
	sourceRegistrationMismatch bool
	workerStatusReceipt        []byte
	// statusProbe, when set, answers a supervisor status probe. A nil payload
	// with a nil error falls through to the fixture's default status receipt.
	statusProbe func(sandboxID string, request map[string]any) ([]byte, error)
	startProbe  func(*state.LocalManagedService)
}

func (runtime *fakeManagedRuntime) ExecManagedSupervisor(_ context.Context, _ string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	runtime.invocations = append(runtime.invocations, managedInvocation{string(action), request})
	if string(action) == "rebind" {
		if runtime.failRebind {
			runtime.failRebind = false
			return nil, nil, errors.New("ambiguous lost rebind response")
		}
		if runtime.actualRebindReceipt {
			receipts, err := loadSandboxSupervisorReceiptFixture()
			return receipts.Rebind, nil, err
		}
		receipt, err := json.Marshal(map[string]any{
			"schemaVersion": 1, "command": "rebind", "status": "applied", "applied": true, "restarted": false,
			"instance": request["instance"], "sandboxId": request["sandboxId"],
			"profileId": request["profileId"], "profileDigest": request["profileDigest"],
			"bindingRevision": request["bindingRevision"],
			"binding":         map[string]any{"provider": "openai", "model": "gpt-6-astra", "authMode": "api_key"},
		})
		return receipt, nil, err
	}
	switch action {
	case containers.ManagedSupervisorEnroll:
		// The backend enrollment token binds the sandbox generation, independently
		// of the managed service's process generation.
		if request["generation"] != float64(runtime.fixture.ServiceManifest.Identity.SandboxGeneration) {
			return nil, nil, errors.New("enrollment sandbox generation binding mismatch")
		}
		runtime.enrollmentCalls++
		receipt, err := json.Marshal(map[string]any{
			"leaseId":       fmt.Sprintf("tel_renewal_%04d", runtime.enrollmentCalls),
			"schemaVersion": 1, "command": "enroll", "status": "enrolled", "stored": true,
			"leaseTokenPresent": true, "leaseRole": runtime.fixture.ServiceManifest.Identity.Role,
			"leaseExpired": false, "generation": runtime.fixture.ServiceManifest.Identity.SandboxGeneration,
		})
		return receipt, nil, err
	case containers.ManagedSupervisorStart, containers.ManagedSupervisorRestart:
		persisted, err := runtime.store.ManagedService(context.Background(), runtime.serviceID)
		if err != nil || persisted == nil || !persisted.CreationDispatched {
			return nil, nil, errors.New("creation was dispatched before its durable intent")
		}
		if runtime.startProbe != nil {
			runtime.startProbe(persisted)
		}
		runtime.startCalls++
		if action == containers.ManagedSupervisorStart && runtime.failStart && runtime.startCalls == 1 {
			return nil, nil, errors.New("ambiguous lost start response")
		}
		instruction := runtime.fixture.InstructionResponse
		command := string(action)
		status := "ready"
		payload, err := json.Marshal(map[string]any{
			"schemaVersion": 1, "command": command, "status": status, "phase": "running", "ready": true,
			"instance": "default", "sandboxId": runtime.fixture.ServiceManifest.Identity.SandboxID,
			"profileId": "opencode", "profileDigest": runtime.fixture.ServiceManifest.Profile.ProfileDigest,
			"profileRevision": runtime.fixture.ServiceManifest.Profile.ProfileRevision, "version": "2.0.14", "port": 18443,
			"sessionId": "ses_managedservice0001", "sessionCreated": false, "sessionReused": true,
			"sessionCreatedCount": 1, "conversationCount": 0, "sessionMode": "lookup_only",
			"nativeProjectId":      "0123456789abcdef0123456789abcdef01234567",
			"nativeLocationDigest": "sha256:d9cf96858af585c5acc19643dfba975c35894edd0b85f88e96e82f88988beab6",
			"instructionRevision":  instruction.InstructionRevision, "instructionDigest": instruction.InstructionDigest,
			"instructionApplied":  true,
			"managerPluginDigest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
			"managerPluginLoaded": true,
			"managerProfile":      map[string]any{"profileId": "warpmetal-insights-manager", "profileRevision": 1, "profileDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
			"managerProviderId":   "openai", "managerModelId": "gpt-6-astra", "managerNativeProtocol": "open_responses",
			"managerProviderRouteDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			"managerRecommendAvailable":  true, "managerCapabilityReason": nil,
			"managerRecipeIds": []string{"inspect_first_failure@1", "check_repeated_operation@1", "refine_query@1", "inspect_active_phase@1"},
		})
		return payload, nil, err
	case containers.ManagedSupervisorRegisterSource:
		registration := request["registration"].(map[string]any)
		identity := registration["identity"].(map[string]any)
		source := registration["source"].(map[string]any)
		nativeSessionID := source["nativeSessionId"]
		if runtime.sourceRegistrationMismatch {
			nativeSessionID = "ses_foreign_registration"
		}
		payload, err := json.Marshal(map[string]any{
			"schemaVersion": 1, "command": "register-source", "status": "registered", "ready": false,
			"instance": request["instance"], "sandboxId": request["sandboxId"], "profileId": request["profileId"],
			"serviceRegistrationId": identity["serviceRegistrationId"], "serviceGeneration": identity["serviceGeneration"],
			"registeredSourceId": source["registeredSourceId"], "workspaceEpoch": identity["workspaceEpoch"],
			"nativeSessionId": nativeSessionID, "nativeProjectId": source["nativeProjectId"],
			"nativeLocationDigest": source["nativeLocationDigest"], "profileRevision": identity["profileRevision"],
			"profileDigest": identity["profileDigest"], "instructionRevision": identity["instructionRevision"],
			"instructionDigest": identity["instructionDigest"],
		})
		return payload, nil, err
	case containers.ManagedSupervisorDrain:
		return []byte(`{"schemaVersion":1,"command":"drain","status":"drained","phase":"drained"}`), nil, nil
	case containers.ManagedSupervisorStatus:
		if runtime.statusProbe != nil {
			sandboxID, _ := request["sandboxId"].(string)
			if payload, err := runtime.statusProbe(sandboxID, request); payload != nil || err != nil {
				return payload, nil, err
			}
		}
		instruction := runtime.fixture.InstructionResponse
		payload, err := json.Marshal(map[string]any{
			"schemaVersion": 1, "command": "status", "status": "running", "phase": "running", "ready": true,
			"sessionId": "ses_managedservice0001", "nativeProjectId": "0123456789abcdef0123456789abcdef01234567",
			"nativeLocationDigest": "sha256:d9cf96858af585c5acc19643dfba975c35894edd0b85f88e96e82f88988beab6",
			"instructionRevision":  instruction.InstructionRevision, "instructionDigest": instruction.InstructionDigest,
			"instructionApplied":  true,
			"managerPluginDigest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
			"managerPluginLoaded": true,
			"managerProfile":      map[string]any{"profileId": "warpmetal-insights-manager", "profileRevision": 1, "profileDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
			"managerProviderId":   "openai", "managerModelId": "gpt-6-astra", "managerNativeProtocol": "open_responses",
			"managerProviderRouteDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			"managerRecommendAvailable":  true, "managerCapabilityReason": nil,
			"managerRecipeIds": []string{"inspect_first_failure@1", "check_repeated_operation@1", "refine_query@1", "inspect_active_phase@1"},
		})
		return payload, nil, err
	case containers.ManagedSupervisorStop:
		return []byte(`{"schemaVersion":1,"command":"stop","status":"stopped","phase":"stopped"}`), nil, nil
	default:
		return nil, nil, fmt.Errorf("unexpected supervisor action %s", action)
	}
}

func (runtime *fakeManagedRuntime) ExecManagedWorker(_ context.Context, _ string, action containers.ManagedWorkerAction, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	runtime.invocations = append(runtime.invocations, managedInvocation{string(action), request})
	if runtime.fixture.ServiceManifest.Identity.Role == "manager" && action != containers.ManagedWorkerStatus {
		return []byte(`{"schemaVersion":1,"status":"error","code":"policy_denied"}`), nil, errors.New("manager cannot claim broker work")
	}
	switch action {
	case containers.ManagedWorkerReconcile:
		return []byte(`{"schemaVersion":1,"command":"reconcile","status":"idle","taskId":null,"messageId":null,"attempt":null,"outcome":null,"deduped":false}`), nil, nil
	case containers.ManagedWorkerStatus:
		if runtime.workerStatusReceipt != nil {
			return append([]byte(nil), runtime.workerStatusReceipt...), nil, nil
		}
		return []byte(`{"schemaVersion":1,"command":"status","status":"ok","instance":"default","busy":false,"activeTask":null}`), nil, nil
	case containers.ManagedWorkerExecute:
		return []byte(`{"schemaVersion":1,"command":"execute","status":"idle","instance":"default"}`), nil, nil
	default:
		return nil, nil, fmt.Errorf("unexpected worker action %s", action)
	}
}

type sandboxWorkerStatusFixture struct {
	FormatVersion int             `json:"formatVersion"`
	Producer      string          `json:"producer"`
	Busy          json.RawMessage `json:"busy"`
	Settled       json.RawMessage `json:"settled"`
	Idle          json.RawMessage `json:"idle"`
}

func loadSandboxWorkerStatusFixture(t *testing.T) sandboxWorkerStatusFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("testdata", "agent-worker-status-contract-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture sandboxWorkerStatusFixture
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.FormatVersion != 1 || fixture.Producer != "runner/warpmetal_team_worker.py:run_status" {
		t.Fatalf("worker status fixture identity = %#v", fixture)
	}
	return fixture
}

func TestManagedWorkerStatusConsumesExactSandboxNestedTaskAuthority(t *testing.T) {
	fixture := loadSandboxWorkerStatusFixture(t)
	desired := loadProducerFixture(t).ServiceManifest
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runtime := &fakeManagedRuntime{workerStatusReceipt: fixture.Busy}
	reconciler := &Reconciler{Store: store, ManagedRuntime: runtime, Now: func() time.Time {
		return time.Date(2026, 9, 27, 20, 0, 10, 0, time.UTC)
	}}
	if _, err := reconciler.runManagedWorkerBoundary(context.Background(), desired); err != nil {
		t.Fatalf("actual Sandbox busy status was rejected: %v", err)
	}
	authority, err := store.ManagedTaskAuthority(context.Background(), desired.Identity.ServiceRegistrationID)
	if err != nil || authority == nil || !authority.Busy || authority.TaskID == nil ||
		*authority.TaskID != "task_workerstatus_fixture0001" || authority.TaskAttempt == nil || *authority.TaskAttempt != 3 {
		t.Fatalf("nested busy task authority = %#v %v", authority, err)
	}

	runtime.workerStatusReceipt = fixture.Settled
	if _, err := reconciler.runManagedWorkerBoundary(context.Background(), desired); err != nil {
		t.Fatalf("actual Sandbox settled status was rejected: %v", err)
	}
	authority, err = store.ManagedTaskAuthority(context.Background(), desired.Identity.ServiceRegistrationID)
	if err != nil || authority == nil || authority.Busy || authority.TaskID != nil || authority.TaskAttempt != nil {
		t.Fatalf("settled latest marker remained active task authority = %#v %v", authority, err)
	}

	runtime.workerStatusReceipt = fixture.Idle
	if _, err := reconciler.runManagedWorkerBoundary(context.Background(), desired); err != nil {
		t.Fatalf("actual Sandbox idle status was rejected: %v", err)
	}
	authority, err = store.ManagedTaskAuthority(context.Background(), desired.Identity.ServiceRegistrationID)
	if err != nil || authority == nil || authority.Busy || authority.TaskID != nil || authority.TaskAttempt != nil {
		t.Fatalf("idle status did not preserve cleared task authority = %#v %v", authority, err)
	}
}

func TestManagedWorkerStatusRejectsMissingMalformedOrSubstitutedNestedAuthority(t *testing.T) {
	fixture := loadSandboxWorkerStatusFixture(t)
	desired := loadProducerFixture(t).ServiceManifest
	var actual map[string]any
	if err := json.Unmarshal(fixture.Busy, &actual); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name           string
		injectTopLevel bool
		mutate         func(map[string]any)
	}{
		{"missing nested authority", false, func(value map[string]any) { delete(value, "activeTask") }},
		{"missing nested authority with top-level substitution", true, func(value map[string]any) { delete(value, "activeTask") }},
		{"malformed nested authority", false, func(value map[string]any) { value["activeTask"] = []any{"task_workerstatus_fixture0001", 3} }},
		{"malformed nested authority with top-level substitution", true, func(value map[string]any) { value["activeTask"] = []any{"task_workerstatus_fixture0001", 3} }},
		{"foreign-typed nested task id", true, func(value map[string]any) {
			value["activeTask"].(map[string]any)["taskId"] = float64(17)
		}},
		{"foreign-typed nested attempt", true, func(value map[string]any) {
			value["activeTask"].(map[string]any)["attempt"] = "3"
		}},
		{"foreign top-level substitution", false, func(value map[string]any) {
			value["taskId"] = "task_foreign_fixture0001"
			value["attempt"] = float64(99)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var candidate map[string]any
			payload, _ := json.Marshal(actual)
			if err := json.Unmarshal(payload, &candidate); err != nil {
				t.Fatal(err)
			}
			test.mutate(candidate)
			// Supplying plausible legacy top-level fields must not make a missing
			// or malformed nested producer authority acceptable.
			if test.injectTopLevel {
				candidate["taskId"] = "task_workerstatus_fixture0001"
				candidate["attempt"] = float64(3)
			}
			status, _ := json.Marshal(candidate)
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			reconciler := &Reconciler{Store: store, ManagedRuntime: &fakeManagedRuntime{workerStatusReceipt: status}}
			if _, err := reconciler.runManagedWorkerBoundary(context.Background(), desired); err == nil {
				t.Fatal("invalid nested Sandbox task authority was accepted")
			}
		})
	}
}

func TestManagedServicePersistsInitialIntentAndRecoversLookupOnlyBeforePublishingSource(t *testing.T) {
	for _, variant := range []struct{ role, contract string }{
		{"worker", ""}, {"worker", "0.1.32"},
		{"reviewer", ""},
		{"manager", ""}, {"manager", "0.1.32"},
	} {
		role, contract := variant.role, variant.contract
		name := role
		if contract != "" {
			name += "/negotiated_wire32"
		}
		t.Run(name, func(t *testing.T) {
			fixture := loadProducerFixture(t)
			fixture.ServiceManifest.Identity.Role = role
			fixture.ServiceManifest.RuntimeContractVersion = contract
			// Reused/refreshed sandboxes and new services have different generations.
			fixture.ServiceManifest.Identity.SandboxGeneration = 2
			fixture.SetupManifest.SandboxGeneration = 2
			fixture.InstructionRequest.SandboxGeneration = 2
			fixture.EnrollmentRequest.SandboxGeneration = 2
			producerReceipts, err := loadSandboxSupervisorReceiptFixture()
			if err != nil {
				t.Fatal(err)
			}
			var actualRebind managedSupervisorReceipt
			if err := decodeManagedSupervisorReceipt(producerReceipts.Rebind, &actualRebind); err != nil {
				t.Fatalf("actual Sandbox rebind receipt rejected: %v", err)
			}
			foreignRuntime := &fakeManagedRuntime{fixture: fixture, actualRebindReceipt: true}
			foreignReconciler := &Reconciler{ManagedRuntime: foreignRuntime}
			if _, err := foreignReconciler.rebindManagedServiceAuthority(context.Background(), fixture.ServiceManifest); err == nil {
				t.Fatal("actual Sandbox rebind receipt from another sandbox/profile was accepted")
			}
			producerDesired := fixture.ServiceManifest
			producerDesired.Identity.SandboxID = actualRebind.SandboxID
			producerDesired.Identity.Instance = actualRebind.Instance
			producerDesired.Profile.ProfileID = actualRebind.ProfileID
			producerDesired.Profile.ProfileDigest = actualRebind.ProfileDigest
			if _, err := foreignReconciler.rebindManagedServiceAuthority(context.Background(), producerDesired); err != nil {
				t.Fatalf("actual Sandbox rebind receipt rejected for its exact identity: %v", err)
			}
			databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
			store, err := state.Open(databasePath)
			if err != nil {
				t.Fatal(err)
			}
			seedReadyProfile(t, store, fixture.SetupManifest)
			anchor := t.TempDir()
			catalog := &workspacecatalog.Catalog{State: store, Now: func() time.Time { return time.Date(2026, 9, 27, 17, 0, 0, 0, time.UTC) }}
			workspace, err := catalog.EnsureDefault(context.Background(), workspacecatalog.DefaultProjectRequest{
				Anchor: anchor, ServerID: fixture.ServiceManifest.Identity.ServerID, TeamID: fixture.ServiceManifest.Identity.TeamID,
				MemberID: fixture.ServiceManifest.Identity.MemberID, SandboxID: fixture.ServiceManifest.Identity.SandboxID,
				SandboxGeneration:     fixture.ServiceManifest.Identity.SandboxGeneration,
				ServiceRegistrationID: fixture.ServiceManifest.Identity.ServiceRegistrationID,
				AllocationDigest:      fixture.WorkspaceRequestManifest.AllocationDigest, ConfigDigest: fixture.ServiceManifest.ConfigDigest,
			})
			if err != nil {
				t.Fatal(err)
			}
			fixture.ServiceManifest.Workspace.SelectionID = workspace.Report.SelectionID
			fixture.ServiceManifest.Workspace.ProjectID = workspace.Report.ProjectID
			fixture.ServiceManifest.Workspace.WorkspaceEpoch = workspace.Report.WorkspaceEpoch
			fixture.ServiceManifest.Workspace.RootAttestation = workspace.Report.RootAttestation
			control := &fakeManagedControl{fixture: fixture}
			runtime := &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture, failStart: true, failRebind: true}
			probeRuntimes := []*fakeManagedRuntime{runtime}
			fixedNow := func() time.Time { return time.Date(2026, 9, 27, 17, 0, 30, 0, time.UTC) }
			reconciler := &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, Now: fixedNow}
			manifest := model.Manifest{ServerID: fixture.ServiceManifest.Identity.ServerID, DesiredRevision: fixture.ServiceManifest.DesiredRevision, ManagedServices: []model.ManagedServiceV1{fixture.ServiceManifest}}

			if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err == nil {
				t.Fatal("ambiguous initial start returned success")
			}
			if sources, err := store.ContinuitySources(context.Background()); err != nil || len(sources) != 0 {
				t.Fatalf("ambiguous start published source: %#v %v", sources, err)
			}
			pending, err := store.ManagedService(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID)
			if err != nil || pending == nil || pending.Report.ObservedState != "registering" || pending.Report.LastError != nil ||
				pending.Report.InstructionApplied || pending.Report.NativeRegistration != nil {
				t.Fatalf("ambiguous start did not persist honest recoverable progress: %#v %v", pending, err)
			}
			pendingDigest := pending.Report.ReceiptDigest
			firstInvocations := append([]managedInvocation(nil), runtime.invocations...)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = state.Open(databasePath)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			catalog = &workspacecatalog.Catalog{State: store, Now: fixedNow}
			runtime = &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture, failStart: true}
			probeRuntimes = append(probeRuntimes, runtime)
			reconciler = &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, Now: fixedNow}
			// Honest test-only validated authority context for the producer
			// manifest under test (no all-history default).
			reconciler.setCurrentAuthority(manifest)
			pending, err = store.ManagedService(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID)
			if err != nil || pending == nil || pending.Report.ObservedState != "registering" || pending.Report.ReceiptDigest != pendingDigest {
				t.Fatalf("reopened progress report drifted: %#v %v", pending, err)
			}
			progressEnvelope, err := reconciler.Report(context.Background(), fixture.ServiceManifest.Identity.ServerID, "test")
			if err != nil || len(progressEnvelope.ManagedServices) != 1 || progressEnvelope.ManagedServices[0].ObservedState != "registering" ||
				progressEnvelope.ManagedServices[0].LastError != nil {
				t.Fatalf("reopened outbound progress report = %#v %v", progressEnvelope.ManagedServices, err)
			}
			progressJSON, err := json.Marshal(progressEnvelope.ManagedServices[0])
			if err != nil || bytes.Contains(progressJSON, []byte(`"lastError"`)) {
				t.Fatalf("nonterminal progress leaked terminal error: %s %v", progressJSON, err)
			}
			if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err == nil {
				t.Fatal("replayed ambiguous lookup unexpectedly succeeded")
			}
			replayed, err := store.ManagedService(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID)
			if err != nil || replayed == nil || replayed.Report.ObservedState != "registering" || replayed.Report.ReceiptDigest != pendingDigest || replayed.Report.LastError != nil {
				t.Fatalf("replayed nonterminal progress drifted: %#v %v", replayed, err)
			}
			secondInvocations := append([]managedInvocation(nil), runtime.invocations...)
			runtime = &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture}
			probeRuntimes = append(probeRuntimes, runtime)
			reconciler = &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, Now: fixedNow}
			// Honest test-only validated authority context for the producer
			// manifest under test (no all-history default).
			reconciler.setCurrentAuthority(manifest)
			if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
				t.Fatal(err)
			}
			var starts []map[string]any
			var rebinds []map[string]any
			allInvocations := append(firstInvocations, secondInvocations...)
			allInvocations = append(allInvocations, runtime.invocations...)
			for index, invocation := range allInvocations {
				if invocation.action == string(containers.ManagedSupervisorEnroll) {
					if invocation.request["generation"] != float64(2) || invocation.request["processInstance"] != "wmsup-default-0001" {
						t.Fatalf("enrollment conflated sandbox and service generations: %#v", invocation.request)
					}
				}
				if invocation.action == "rebind" {
					rebinds = append(rebinds, invocation.request)
				}
				if invocation.action == string(containers.ManagedSupervisorStart) {
					if index == 0 || allInvocations[index-1].action != "rebind" {
						t.Fatalf("managed start was not immediately preceded by authority rebind: %#v", allInvocations)
					}
					starts = append(starts, invocation.request)
				}
			}
			if len(rebinds) != 4 {
				t.Fatalf("authority rebind count = %d: %#v", len(rebinds), allInvocations)
			}
			if len(allInvocations) < 4 || allInvocations[0].action != string(containers.ManagedSupervisorEnroll) ||
				allInvocations[1].action != "rebind" || allInvocations[2].action != "rebind" ||
				allInvocations[3].action != string(containers.ManagedSupervisorStart) {
				t.Fatalf("lost rebind response was not replayed with its exact fence before start: %#v", allInvocations)
			}
			if !reflect.DeepEqual(allInvocations[1].request, allInvocations[2].request) {
				t.Fatalf("lost rebind response changed the replay tuple: first=%#v replay=%#v", allInvocations[1].request, allInvocations[2].request)
			}
			for _, rebind := range rebinds {
				if rebind["provider"] != "openai" || rebind["model"] != "openai/gpt-6-astra" ||
					rebind["authMode"] != "api_key" || rebind["bindingRevision"] != float64(17) || rebind["restart"] != false ||
					rebind["profileDigest"] != fixture.ServiceManifest.Profile.ProfileDigest {
					t.Fatalf("closed authority rebind request = %#v", rebind)
				}
			}
			if len(starts) != 3 || starts[0]["sessionMode"] != "create_initial" || starts[1]["sessionMode"] != "lookup_only" || starts[2]["sessionMode"] != "lookup_only" {
				t.Fatalf("initial recovery session modes = %#v", starts)
			}
			second := starts[2]
			if second["projectRoot"] != workspace.ContainerRoot || second["instructionText"] != fixture.InstructionResponse.Content ||
				second["instructionDigest"] != fixture.InstructionResponse.InstructionDigest ||
				second["instructionRevision"] != float64(fixture.InstructionResponse.InstructionRevision) {
				t.Fatalf("managed start lost workspace/instruction binding: %#v", second)
			}
			sources, err := store.ContinuitySources(context.Background())
			if err != nil || len(sources) != 1 || sources[0].Root != workspace.HostRoot ||
				sources[0].Report.ServiceRegistrationID != fixture.ServiceManifest.Identity.ServiceRegistrationID ||
				sources[0].Report.SandboxGeneration != 2 || sources[0].Report.ServiceGeneration != 1 ||
				sources[0].Report.NativeLocationDigest != "sha256:d9cf96858af585c5acc19643dfba975c35894edd0b85f88e96e82f88988beab6" ||
				sources[0].Report.InstructionRevision != fixture.InstructionResponse.InstructionRevision {
				t.Fatalf("verified managed source = %#v %v", sources, err)
			}
			report, err := reconciler.Report(context.Background(), fixture.ServiceManifest.Identity.ServerID, "test")
			if err != nil || len(report.ManagedWorkspaceSelections) != 1 || len(report.ManagedServices) != 1 || report.ManagedServices[0].ObservedState != "ready" {
				t.Fatalf("managed report = %#v %v", report, err)
			}
			if len(control.enrollments) == 0 || len(control.instructions) == 0 || !reflect.DeepEqual(control.instructions[len(control.instructions)-1], fixture.InstructionRequest) {
				t.Fatalf("node fetch bindings = enroll %#v instructions %#v", control.enrollments, control.instructions)
			}
			capability, err := store.ManagerCapability(context.Background(), sources[0].Report.RegisteredSourceID)
			if err != nil || capability == nil || !capability.Available ||
				capability.ServiceGeneration != fixture.ServiceManifest.Identity.ExpectedServiceGeneration ||
				capability.ProviderID != "openai" || capability.ModelID != "gpt-6-astra" ||
				capability.NativeProtocol != "open_responses" ||
				capability.ProviderRouteDigest != "sha256:1111111111111111111111111111111111111111111111111111111111111111" ||
				capability.ManagerProfile.ProfileID != "warpmetal-insights-manager" || len(capability.RecipeIDs) != 4 {
				t.Fatalf("manager capability was not persisted from the exact ready supervisor receipt: %#v %v", capability, err)
			}
			actualReceipts, err := loadSandboxSupervisorReceiptFixture()
			if err != nil {
				t.Fatal(err)
			}
			var unboundStart, unboundStatus, boundStart, boundStatus managedSupervisorReceipt
			for _, item := range []struct {
				payload json.RawMessage
				target  *managedSupervisorReceipt
			}{{actualReceipts.UnboundStart, &unboundStart}, {actualReceipts.UnboundStatus, &unboundStatus},
				{actualReceipts.BoundStart, &boundStart}, {actualReceipts.BoundStatus, &boundStatus}} {
				if err := decodeManagedSupervisorReceipt(item.payload, item.target); err != nil {
					t.Fatalf("actual Sandbox supervisor receipt rejected: %v", err)
				}
			}
			for _, receipt := range []managedSupervisorReceipt{unboundStart, unboundStatus, actualRebind, boundStart, boundStatus} {
				if receipt.SessionID != actualRebind.SessionID || receipt.SessionCreatedCount != 1 || receipt.ConversationCount != 1 {
					t.Fatalf("actual Sandbox rebind/start/status changed native session or conversation counts: %#v", receipt)
				}
			}
			unboundDesired := fixture.ServiceManifest
			unboundDesired.Authority = nil
			unboundCapability, err := managedManagerCapability(unboundDesired, sources[0].Report.RegisteredSourceID, unboundStart, unboundStatus)
			if err != nil || unboundCapability.Available || unboundCapability.Reason != "native_guard_unqualified" ||
				unboundCapability.ProviderID != "" || unboundCapability.ModelID != "" || unboundCapability.NativeProtocol != "" {
				t.Fatalf("actual unbound Sandbox capability = %#v %v", unboundCapability, err)
			}
			boundCapability, err := managedManagerCapability(fixture.ServiceManifest, sources[0].Report.RegisteredSourceID, boundStart, boundStatus)
			if err != nil || !boundCapability.Available || boundCapability.ProviderID != "openai" ||
				boundCapability.ModelID != "gpt-6-astra" || boundCapability.NativeProtocol != "open_responses" || boundCapability.Reason != "" {
				t.Fatalf("actual bound Sandbox capability = %#v %v", boundCapability, err)
			}
			workerActions := map[string]bool{}
			for _, invocation := range runtime.invocations {
				workerActions[invocation.action] = true
			}
			requiredActions := []string{string(containers.ManagedWorkerStatus), string(containers.ManagedSupervisorRegisterSource)}
			if role != "manager" {
				requiredActions = append(requiredActions, string(containers.ManagedWorkerReconcile), string(containers.ManagedWorkerExecute))
			} else {
				if workerActions[string(containers.ManagedWorkerReconcile)] || workerActions[string(containers.ManagedWorkerExecute)] {
					t.Fatal("manager dispatched worker task claim/reconciliation")
				}
				if !sources[0].NoAdmittedExecution {
					t.Fatal("idle manager source was not marked idle from its status receipt")
				}
			}
			for _, required := range requiredActions {
				if !workerActions[required] {
					t.Fatalf("managed worker lifecycle omitted %s: %#v", required, runtime.invocations)
				}
			}

			// Lease renewal is a fresh health observation, not a new terminal
			// action receipt. Backend rejects changed receipts at this revision.
			beforeRenewal, err := store.ManagedService(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.MarkManagedServiceCreationDispatched(context.Background(), runtime.serviceID, "sha256:foreign-config"); !errors.Is(err, state.ErrManagedServiceConflict) {
				t.Fatalf("completed creation marker bypassed the exact config fence: %v", err)
			}
			// Keep the ordinary reconciler paused at its supervisor start boundary
			// while a real gateway connection opens the already verified session.
			// The prior report remains ready during this health renewal.
			renewalHandoff := managedRenewalGateway(t, store, beforeRenewal, fixedNow())
			startProbes := 0
			runtime.startProbe = func(current *state.LocalManagedService) {
				startProbes++
				renewalHandoff()
				if current.Phase != "ready" || !current.CreationDispatched || !reflect.DeepEqual(current.Report, beforeRenewal.Report) {
					t.Fatalf("ordinary renewal changed completed native readiness: phase=%s dispatched=%t", current.Phase, current.CreationDispatched)
				}
			}
			reconciler.Now = func() time.Time { return fixedNow().Add(time.Second) }
			if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
				t.Fatal(err)
			}
			runtime.startProbe = nil
			if startProbes != 1 {
				t.Fatalf("ordinary renewal supervisor boundary calls = %d, want 1", startProbes)
			}
			afterRenewal, err := store.ManagedService(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID)
			if err != nil || !reflect.DeepEqual(beforeRenewal.Report, afterRenewal.Report) {
				t.Fatalf("lease renewal rewrote the completed action receipt: before=%#v after=%#v error=%v", beforeRenewal.Report, afterRenewal.Report, err)
			}
			freshSources, err := store.ContinuitySources(context.Background())
			if err != nil || len(freshSources) != 1 || !freshSources[0].Report.LastObservedAt.Equal(reconciler.Now()) {
				t.Fatalf("stable completion receipt suppressed fresh source health: %#v %v", freshSources, err)
			}

			if err := store.PutContinuityBarrier(context.Background(), "op_capture_owned0001", []byte(`{"owner":"capture"}`), []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = state.Open(databasePath)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			catalog = &workspacecatalog.Catalog{State: store, Now: fixedNow}
			runtime = &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture}
			probeRuntimes = append(probeRuntimes, runtime)
			reconciler = &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, Now: fixedNow}
			// Honest test-only validated authority context for the producer
			// manifest under test (no all-history default).
			reconciler.setCurrentAuthority(manifest)
			for revision, desired := range []string{"paused", "stopped", "retired"} {
				fixture.ServiceManifest.OperationID = fmt.Sprintf("op_managed_%s_0001", desired)
				fixture.ServiceManifest.ActionRevision = int64(revision + 3)
				fixture.ServiceManifest.DesiredRevision = int64(revision + 2)
				fixture.ServiceManifest.DesiredState = desired
				fixture.ServiceManifest.SessionMode = "lookup_only"
				manifest.ManagedServices = []model.ManagedServiceV1{fixture.ServiceManifest}
				manifest.DesiredRevision = fixture.ServiceManifest.DesiredRevision
				if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
					t.Fatalf("%s managed service: %v", desired, err)
				}
				wantAction := string(containers.ManagedSupervisorStop)
				if desired == "paused" {
					wantAction = string(containers.ManagedSupervisorDrain)
				}
				invocation := runtime.invocations[len(runtime.invocations)-1]
				wantRequest := map[string]any{
					"schemaVersion": float64(1),
					"sandboxId":     fixture.ServiceManifest.Identity.SandboxID,
					"instance":      fixture.ServiceManifest.Identity.Instance,
					"profileId":     fixture.ServiceManifest.Profile.ProfileID,
					"graceSeconds":  float64(15),
				}
				if invocation.action != wantAction || !reflect.DeepEqual(invocation.request, wantRequest) {
					t.Errorf("%s closed supervisor lifecycle request = %#v %#v, want %s %#v", desired, invocation.action, invocation.request, wantAction, wantRequest)
				}
				if desired == "stopped" || desired == "retired" {
					// A completed lifecycle receipt belongs to its old generation. Replay
					// must not act on a replacement container or block its reconciliation.
					before, err := store.ManagedService(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID)
					if err != nil {
						t.Fatal(err)
					}
					sandbox, err := store.Sandbox(context.Background(), fixture.ServiceManifest.Identity.SandboxID)
					if err != nil || sandbox == nil {
						t.Fatalf("sandbox missing: %v", err)
					}
					prior := *sandbox
					sandbox.ObservedGeneration++
					if err := store.PutSandbox(context.Background(), *sandbox); err != nil {
						t.Fatal(err)
					}
					calls := len(runtime.invocations)
					if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
						t.Fatalf("completed %s replay blocked replacement generation: %v", desired, err)
					}
					after, err := store.ManagedService(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID)
					if err != nil || !reflect.DeepEqual(before, after) || len(runtime.invocations) != calls {
						t.Fatalf("completed %s replay changed state or invoked replacement: %v", desired, err)
					}
					reconciler.setCurrentAuthority(manifest)
					outbound, err := reconciler.Report(context.Background(), fixture.ServiceManifest.Identity.ServerID, "test")
					if err != nil || len(outbound.ManagedWorkspaceSelections) != 0 || len(outbound.ManagedServices) != 1 {
						t.Fatalf("replacement generation advertised a stale catalog selection: %#v %v", outbound.ManagedWorkspaceSelections, err)
					}
					retained, err := catalog.Reports(context.Background())
					if err != nil || len(retained) != 1 {
						t.Fatalf("historical catalog record was removed: %#v %v", retained, err)
					}
					changed := manifest
					changed.ManagedServices = append([]model.ManagedServiceV1(nil), manifest.ManagedServices...)
					changed.ManagedServices[0].OperationID = "op_changed_lifecycle_0001"
					if _, err := reconciler.reconcileManagedServices(context.Background(), changed); err == nil || len(runtime.invocations) != calls {
						t.Fatal("changed lifecycle intent reused an unrelated terminal receipt")
					}
					if err := store.PutSandbox(context.Background(), prior); err != nil {
						t.Fatal(err)
					}
				}
				barriers, err := store.ContinuityBarriers(context.Background())
				if err != nil || len(barriers) != 1 || barriers[0].OperationID != "op_capture_owned0001" {
					t.Fatalf("%s cleared independent continuity hold: %#v %v", desired, barriers, err)
				}
			}
			sources, err = store.ContinuitySources(context.Background())
			if err != nil || len(sources) != 1 || sources[0].Report.Availability != "unavailable" || stringValue(sources[0].Report.Reason) != "service_retired" {
				t.Fatalf("retired source tombstone = %#v %v", sources, err)
			}
			var probeInvocations []managedInvocation
			for _, probe := range probeRuntimes {
				probeInvocations = append(probeInvocations, probe.invocations...)
			}
			assertManagedCapabilityProbeEquality(t, probeInvocations, fixture)
		})
	}
}

type managedRenewalBridge struct {
	calls chan containers.SessionHandoffLaunch
}

func (bridge *managedRenewalBridge) ExecSessionHandoff(_ context.Context, _ string, launch containers.SessionHandoffLaunch, _ containers.SessionInput, _, _ io.Writer) error {
	bridge.calls <- launch
	return nil
}

func managedRenewalGateway(t *testing.T, store *state.Store, service *state.LocalManagedService, now time.Time) func() {
	t.Helper()
	manifest, native := service.Manifest, service.Report.NativeRegistration
	if service.Phase != "ready" || native == nil {
		t.Fatal("renewal gateway requires the ordinary producer's completed service")
	}
	identity := manifest.Identity
	target := model.SessionHandoffV1{
		FormatVersion: 1, Action: "open_session", HandoffID: "handoff_ordinary_renewal_0001", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Identity: model.SessionHandoffIdentityV1{
			ServerID: identity.ServerID, TeamID: identity.TeamID, MemberID: identity.MemberID, SandboxID: identity.SandboxID,
			SandboxGeneration: identity.SandboxGeneration, ServiceRegistrationID: identity.ServiceRegistrationID,
			ServiceGeneration: service.ServiceGeneration, Instance: identity.Instance, Role: identity.Role,
			ProjectID: manifest.Workspace.ProjectID, WorkspaceEpoch: manifest.Workspace.WorkspaceEpoch,
			ProfileID: manifest.Profile.ProfileID, ProfileRevision: manifest.Profile.ProfileRevision, ProfileDigest: manifest.Profile.ProfileDigest,
			InstructionRevision: manifest.Instructions.InstructionRevision, InstructionDigest: manifest.Instructions.InstructionDigest,
		},
		Source: model.SessionHandoffSourceV1{RegisteredSourceID: native.RegisteredSourceID, NativeSessionID: native.NativeSessionID,
			NativeProjectID: native.NativeProjectID, NativeLocationDigest: native.NativeLocationDigest},
	}
	if err := model.ValidateSessionHandoffV1(target, now); err != nil {
		t.Fatalf("ordinary producer target is invalid: %v", err)
	}
	const grantID = "grant_ordinaryrenewal0001"
	if err := store.PutGrant(context.Background(), state.LocalGrant{ID: grantID, SandboxID: identity.SandboxID, DesiredState: "active", ObservedState: "applied"}); err != nil {
		t.Fatal(err)
	}
	// Keep the Unix path below the platform limit regardless of the test name.
	directory, err := os.MkdirTemp("", "wm-renewal-")
	if err != nil {
		t.Fatal(err)
	}
	bridge := &managedRenewalBridge{calls: make(chan containers.SessionHandoffLaunch, 1)}
	gateway := &access.Gateway{Store: store, SessionHandoffEngine: bridge, HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Now: func() time.Time { return now }}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	socket := filepath.Join(directory, "g.sock")
	go func() { stopped <- gateway.Serve(ctx, socket) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-stopped:
			if err != nil {
				t.Errorf("renewal gateway stopped: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("renewal gateway did not stop")
		}
		_ = os.RemoveAll(directory)
	})
	hello, err := json.Marshal(map[string]any{"protocol": "wm-team-control/1", "handoff": target})
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, len(hello)+5)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(hello)+1))
	frame[4] = 0x01
	copy(frame[5:], hello)
	return func() {
		t.Helper()
		var connection net.Conn
		deadline := time.Now().Add(time.Second)
		for {
			connection, err = net.Dial("unix", socket)
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if err != nil {
			t.Fatalf("connect ordinary renewal gateway: %v", err)
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		if err := json.NewEncoder(connection).Encode(map[string]any{"grantId": grantID, "command": "warpmetal-team-control", "tty": true, "sessionHandoff": target, "sessionHandoffHello": frame}); err != nil {
			t.Fatal(err)
		}
		var response struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if err := json.NewDecoder(connection).Decode(&response); err != nil {
			t.Fatalf("decode ordinary renewal gateway response: %v", err)
		}
		if !response.OK {
			t.Fatalf("ordinary ready-service renewal denied actual gateway handoff: %s", response.Error)
		}
		select {
		case launch := <-bridge.calls:
			if !bytes.Equal(launch.HelloFrame, frame) || launch.Grant.Engine.Port != service.Port || launch.Grant.Instance != identity.Instance {
				t.Fatal("renewal gateway changed the exact bridge launch")
			}
		case <-time.After(time.Second):
			t.Fatal("renewal gateway did not reach the fixed bridge boundary")
		}
	}
}

func TestManagedServiceRefusesSourceExposureWhenPackagedRegistrationReceiptChangesIdentity(t *testing.T) {
	fixture := loadProducerFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, fixture.SetupManifest)
	now := func() time.Time { return time.Date(2026, 9, 27, 17, 0, 30, 0, time.UTC) }
	catalog := &workspacecatalog.Catalog{State: store, Now: now}
	workspace, err := catalog.EnsureDefault(context.Background(), workspacecatalog.DefaultProjectRequest{
		Anchor: t.TempDir(), ServerID: fixture.ServiceManifest.Identity.ServerID,
		TeamID: fixture.ServiceManifest.Identity.TeamID, MemberID: fixture.ServiceManifest.Identity.MemberID,
		SandboxID: fixture.ServiceManifest.Identity.SandboxID, SandboxGeneration: fixture.ServiceManifest.Identity.SandboxGeneration,
		ServiceRegistrationID: fixture.ServiceManifest.Identity.ServiceRegistrationID,
		AllocationDigest:      fixture.WorkspaceRequestManifest.AllocationDigest, ConfigDigest: fixture.ServiceManifest.ConfigDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.ServiceManifest.Workspace.SelectionID = workspace.Report.SelectionID
	fixture.ServiceManifest.Workspace.ProjectID = workspace.Report.ProjectID
	fixture.ServiceManifest.Workspace.WorkspaceEpoch = workspace.Report.WorkspaceEpoch
	fixture.ServiceManifest.Workspace.RootAttestation = workspace.Report.RootAttestation
	control := &fakeManagedControl{fixture: fixture}
	runtime := &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture, sourceRegistrationMismatch: true}
	reconciler := &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, Now: now}
	manifest := model.Manifest{ServerID: fixture.ServiceManifest.Identity.ServerID, DesiredRevision: fixture.ServiceManifest.DesiredRevision, ManagedServices: []model.ManagedServiceV1{fixture.ServiceManifest}}
	if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err == nil {
		t.Fatal("changed packaged source registration receipt exposed a source")
	}
	sources, err := store.ContinuitySources(context.Background())
	if err != nil || len(sources) != 0 {
		t.Fatalf("unverified source registration was published: %#v %v", sources, err)
	}
}

func TestManagedWorkerExecutionOutlivesPollDeadlineAndPolicyCancelsIt(t *testing.T) {
	fixture := loadProducerFixture(t)
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, fixture.SetupManifest)
	fixedNow := func() time.Time { return time.Date(2026, 9, 27, 17, 0, 30, 0, time.UTC) }
	catalog := &workspacecatalog.Catalog{State: store, Now: fixedNow}
	workspace, err := catalog.EnsureDefault(context.Background(), workspacecatalog.DefaultProjectRequest{
		Anchor: t.TempDir(), ServerID: fixture.ServiceManifest.Identity.ServerID,
		TeamID: fixture.ServiceManifest.Identity.TeamID, MemberID: fixture.ServiceManifest.Identity.MemberID,
		SandboxID: fixture.ServiceManifest.Identity.SandboxID, SandboxGeneration: fixture.ServiceManifest.Identity.SandboxGeneration,
		ServiceRegistrationID: fixture.ServiceManifest.Identity.ServiceRegistrationID,
		AllocationDigest:      fixture.WorkspaceRequestManifest.AllocationDigest, ConfigDigest: fixture.ServiceManifest.ConfigDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.ServiceManifest.Workspace.SelectionID = workspace.Report.SelectionID
	fixture.ServiceManifest.Workspace.ProjectID = workspace.Report.ProjectID
	fixture.ServiceManifest.Workspace.WorkspaceEpoch = workspace.Report.WorkspaceEpoch
	fixture.ServiceManifest.Workspace.RootAttestation = workspace.Report.RootAttestation
	control := &fakeManagedControl{fixture: fixture}
	base := &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture}
	runtime := &controlledManagedRuntime{base: base, executeStarted: make(chan struct{}), executeCanceled: make(chan struct{})}
	lifecycle, cancelLifecycle := context.WithCancel(context.Background())
	reconciler := &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, ManagedExecutionContext: lifecycle, Now: fixedNow}
	manifest := model.Manifest{ServerID: fixture.ServiceManifest.Identity.ServerID, DesiredRevision: fixture.ServiceManifest.DesiredRevision, ManagedServices: []model.ManagedServiceV1{fixture.ServiceManifest}}

	// Normal bounded reconciliation backstop (CI-appropriate seconds, not a
	// wall-clock proxy): the controlled worker blocks the INDEPENDENT lifecycle
	// context, so a successful start proves the launch mechanism.
	pollContext, cancelPoll := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelPoll()
	if _, err := reconciler.reconcileManagedServices(pollContext, manifest); err != nil {
		t.Fatalf("bounded worker execution incorrectly consumed the poll deadline: %v", err)
	}
	select {
	case <-runtime.executeStarted:
	case <-time.After(time.Second):
		t.Fatal("worker execution was not launched")
	}
	sources, err := store.ContinuitySources(context.Background())
	if err != nil || len(sources) != 1 || sources[0].NoAdmittedExecution {
		t.Fatalf("running worker source authority = %#v %v", sources, err)
	}

	// Explicit deliberate poll-context cancellation after a successful start:
	// the independent worker lifecycle must remain active because the worker
	// blocks the lifecycle context, never the control-plane poll.
	cancelPoll()
	select {
	case <-lifecycle.Done():
		t.Fatal("independent worker lifecycle was canceled by the poll context")
	default:
	}

	// A second ordinary reconciliation must return without waiting for the
	// blocked worker or launching a replacement. The bounded channel proves the
	// non-waiting property deterministically; the 30s context only prevents a
	// hang in case of a construction bug.
	secondContext, cancelSecond := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelSecond()
	secondResult := make(chan error, 1)
	go func() {
		_, err := reconciler.reconcileManagedServices(secondContext, manifest)
		secondResult <- err
	}()
	select {
	case err := <-secondResult:
		if err != nil {
			t.Fatalf("active worker blocked regular reconciliation: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancelSecond()
		t.Fatal("ordinary reconciliation waited on the independent worker lifecycle")
	}
	if runtime.calls() != 1 {
		t.Fatalf("duplicate worker execution launched for one member: %d", runtime.calls())
	}

	// A daemon shutdown cancels the independent execution. A new reconciler
	// must run the durable worker reconciliation boundary before starting one
	// replacement one-shot for this member.
	cancelLifecycle()
	if err := reconciler.cancelManagedWorkerExecution(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	catalog = &workspacecatalog.Catalog{State: store, Now: fixedNow}
	base = &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture}
	runtime = &controlledManagedRuntime{base: base, executeStarted: make(chan struct{}), executeCanceled: make(chan struct{})}
	lifecycle, cancelLifecycle = context.WithCancel(context.Background())
	defer cancelLifecycle()
	reconciler = &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, ManagedExecutionContext: lifecycle, Now: fixedNow}
	if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
		t.Fatalf("restart reconciliation failed: %v", err)
	}
	select {
	case <-runtime.executeStarted:
	case <-time.After(time.Second):
		t.Fatal("restart did not launch one reconciled worker execution")
	}
	if runtime.calls() != 1 || len(base.invocations) < 3 || base.invocations[len(base.invocations)-3].action != string(containers.ManagedWorkerReconcile) || base.invocations[len(base.invocations)-2].action != string(containers.ManagedWorkerStatus) || base.invocations[len(base.invocations)-1].action != string(containers.ManagedSupervisorRegisterSource) {
		t.Fatalf("restart worker order/call count = %d %#v", runtime.calls(), base.invocations)
	}

	fixture.ServiceManifest.OperationID = "op_managed_pause_0001"
	fixture.ServiceManifest.ActionRevision++
	fixture.ServiceManifest.DesiredRevision++
	fixture.ServiceManifest.DesiredState = "paused"
	fixture.ServiceManifest.SessionMode = "lookup_only"
	manifest.DesiredRevision = fixture.ServiceManifest.DesiredRevision
	manifest.ManagedServices = []model.ManagedServiceV1{fixture.ServiceManifest}
	if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runtime.executeCanceled:
	case <-time.After(time.Second):
		t.Fatal("pause policy did not cancel the independent worker execution")
	}
}

func TestManagedServiceDecodesActualNegotiatedSandboxSupervisorReceipts(t *testing.T) {
	receipts, err := loadSandboxSupervisorReceiptFixture()
	if err != nil {
		t.Fatal(err)
	}
	// The packaged Sandbox producer negotiates nativeGuard on every receipt when
	// the request carries runtimeContractVersion 0.1.32. The before-start
	// observation carries the closed six-field guard with no facts yet; the
	// strict Runtime decoder must accept it and keep the guard semantics.
	var negotiated managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(receipts.NegotiatedStatus, &negotiated); err != nil {
		t.Fatalf("actual negotiated Sandbox status receipt rejected: %v", err)
	}
	if negotiated.Command != "status" || negotiated.NativeGuard == nil {
		t.Fatalf("actual negotiated Sandbox status receipt lost its closed guard: %#v", negotiated)
	}
	guard := negotiated.NativeGuard
	if guard.GuardVersion != "" || guard.CustomVersion != "" || guard.SourceRevision != "" ||
		guard.PatchDigest != "" || guard.ArtifactSHA256 != "" || guard.BinarySHA256 != "" {
		t.Fatalf("pre-start negotiated guard carried invented facts: %#v", *guard)
	}
	// Legacy receipts that never negotiated must keep decoding without a guard.
	var legacy managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(receipts.UnboundStatus, &legacy); err != nil || legacy.NativeGuard != nil {
		t.Fatalf("legacy Sandbox status receipt = %#v %v", legacy, err)
	}
	// A negotiated-but-incomplete guard can never satisfy ready capability.
	producer := loadProducerFixture(t)
	var boundStart, boundStatus managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(receipts.BoundStart, &boundStart); err != nil {
		t.Fatal(err)
	}
	if err := decodeManagedSupervisorReceipt(receipts.BoundStatus, &boundStatus); err != nil {
		t.Fatal(err)
	}
	boundStart.NativeGuard = negotiated.NativeGuard
	if _, err := managedManagerCapability(producer.ServiceManifest, "source_actual_fixture", boundStart, boundStatus); err == nil ||
		!strings.Contains(err.Error(), "invalid native guard") {
		t.Fatalf("incomplete negotiated guard capability = %v", err)
	}
	// Every other unknown receipt field stays rejected by the closed decoder.
	renamed := bytes.Replace(receipts.NegotiatedStatus, []byte(`"nativeGuard"`), []byte(`"nativeGuardX"`), 1)
	var rejected managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(renamed, &rejected); err == nil ||
		!strings.Contains(err.Error(), `unknown field "nativeGuardX"`) {
		t.Fatalf("unknown negotiated receipt field was not rejected: %v", err)
	}
}

// wireContractConsumerRuntime decorates the existing producer fake so the
// unmodified shipped Sandbox closed validators see the exact payload bytes the
// Runtime producer emits. Only the physical sandbox root path is remapped to a
// temporary directory (opaque path fixture); field names, body shape and
// authority values are untouched. A validator refusal fails the production
// call, so the same journey is RED while the two RF blocks emit the
// un-negotiated field and GREEN once they stop, with no test edits in between.
type wireContractConsumerRuntime struct {
	*fakeManagedRuntime
	python           string
	workerScript     string
	supervisorScript string
	root             string
}

const wireWorkerValidatorAdapter = `
import importlib.machinery
import importlib.util
import json
import sys
loader = importlib.machinery.SourceFileLoader("wire_worker_consumer", sys.argv[1])
spec = importlib.util.spec_from_loader("wire_worker_consumer", loader)
consumer = importlib.util.module_from_spec(spec)
loader.exec_module(consumer)
try:
    normalized = consumer.validate_document(json.load(sys.stdin))
except consumer.WorkerError as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)
json.dump({"command": normalized.get("command")}, sys.stdout, sort_keys=True)
`

const wireSupervisorValidatorAdapter = `
import importlib.util
import json
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("wire_supervisor_consumer", sys.argv[1])
consumer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = consumer
spec.loader.exec_module(consumer)
try:
    normalized = consumer.validate_request("register-source", json.load(sys.stdin), root=Path(sys.argv[2]))
except consumer.RequestError as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)
json.dump({"registration": normalized.get("registration")}, sys.stdout, sort_keys=True)
`

func (runtime *wireContractConsumerRuntime) validateWorkerPayload(action string, payload []byte) error {
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		return err
	}
	document["root"] = runtime.root
	remapped, err := json.Marshal(document)
	if err != nil {
		return err
	}
	command := exec.CommandContext(context.Background(), runtime.python, "-c", wireWorkerValidatorAdapter, runtime.workerScript)
	command.Stdin = bytes.NewReader(remapped)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("actual Sandbox worker validator refused %s: %s", action, strings.TrimSpace(string(output)))
	}
	return nil
}

func (runtime *wireContractConsumerRuntime) validateSupervisorRegisterSource(payload []byte) error {
	command := exec.CommandContext(context.Background(), runtime.python, "-c", wireSupervisorValidatorAdapter, runtime.supervisorScript, runtime.root)
	command.Stdin = bytes.NewReader(payload)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("actual Sandbox supervisor validator refused register-source: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func (runtime *wireContractConsumerRuntime) ExecManagedWorker(ctx context.Context, sandboxID string, action containers.ManagedWorkerAction, payload []byte) ([]byte, []byte, error) {
	if err := runtime.validateWorkerPayload(string(action), payload); err != nil {
		return nil, nil, err
	}
	return runtime.fakeManagedRuntime.ExecManagedWorker(ctx, sandboxID, action, payload)
}

func (runtime *wireContractConsumerRuntime) ExecManagedSupervisor(ctx context.Context, sandboxID string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	if action == containers.ManagedSupervisorRegisterSource {
		if err := runtime.validateSupervisorRegisterSource(payload); err != nil {
			return nil, nil, err
		}
	}
	return runtime.fakeManagedRuntime.ExecManagedSupervisor(ctx, sandboxID, action, payload)
}

// TestManagedServiceActualSandboxClosedContractsAcceptProductionWireRequests
// extends the existing managed-service producer journey: the decorated runtime
// hands the exact Runtime-emitted worker boundary and register-source payload
// bytes to the unmodified shipped Sandbox validators. The empty-contract
// baseline is the ordinary non-negotiated path and must pass; the negotiated
// 0.1.32 path is the causal RED while the two RF blocks emit the field and
// GREEN once the EXACT two removals land, with this test unchanged.
func TestManagedServiceActualSandboxClosedContractsAcceptProductionWireRequests(t *testing.T) {
	sandboxSource := os.Getenv("WARP_METAL_SANDBOX_SOURCE")
	image := os.Getenv("WARP_METAL_SANDBOX_IMAGE")
	var workerScript, supervisorScript string
	switch {
	case sandboxSource != "":
		workerScript = filepath.Join(sandboxSource, "runner", "warpmetal_team_worker.py")
		supervisorScript = filepath.Join(sandboxSource, "runner", "warpmetal_opencode_supervisor.py")
	case image != "":
		workerScript, supervisorScript = extractSandboxValidatorScriptsFromImage(t, image)
	default:
		if os.Getenv("WARPMETAL_WIRE_CONTRACT_EVIDENCE") != "" {
			t.Fatal("WARP_METAL_SANDBOX_SOURCE or WARP_METAL_SANDBOX_IMAGE is required for real wire-contract evidence")
		}
		t.Skip("WARP_METAL_SANDBOX_SOURCE and WARP_METAL_SANDBOX_IMAGE are not set")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}

	newJourney := func(t *testing.T) (*wireContractConsumerRuntime, *fakeManagedRuntime, producerFixture) {
		t.Helper()
		fixture := loadProducerFixture(t)
		// Bind the canonical 24-character sandbox identity the published
		// Sandbox registration validator requires; every other fixture ID is
		// already canonical.
		fixture.ServiceManifest.Identity.SandboxID = "sbx_0123456789abcdef01234567"
		store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		base := &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture}
		decorated := &wireContractConsumerRuntime{
			fakeManagedRuntime: base, python: python, workerScript: workerScript,
			supervisorScript: supervisorScript, root: t.TempDir(),
		}
		return decorated, base, fixture
	}
	desiredWithContract := func(fixture producerFixture, contract string) model.ManagedServiceV1 {
		desired := fixture.ServiceManifest
		desired.RuntimeContractVersion = contract
		return desired
	}
	nativeReceipt := func() managedSupervisorReceipt {
		return managedSupervisorReceipt{
			SessionID:            "ses_0123456789abcdef01234567",
			NativeProjectID:      strings.Repeat("c", 40),
			NativeLocationDigest: "sha256:" + strings.Repeat("d", 64),
		}
	}
	t.Run("worker_boundary_baseline_actual_rf_path", func(t *testing.T) {
		decorated, base, fixture := newJourney(t)
		reconciler := &Reconciler{Store: base.store, ManagedRuntime: decorated}
		if _, err := reconciler.runManagedWorkerBoundary(context.Background(), desiredWithContract(fixture, "")); err != nil {
			t.Fatalf("baseline worker boundary refused: %v", err)
		}
	})
	t.Run("worker_boundary_negotiated_wire32", func(t *testing.T) {
		decorated, base, fixture := newJourney(t)
		reconciler := &Reconciler{Store: base.store, ManagedRuntime: decorated}
		if _, err := reconciler.runManagedWorkerBoundary(context.Background(), desiredWithContract(fixture, "0.1.32")); err != nil {
			t.Fatalf("RF worker boundary payload was refused by the shipped validator: %v", err)
		}
	})
	t.Run("register_source_baseline_actual_rf_path", func(t *testing.T) {
		decorated, _, fixture := newJourney(t)
		reconciler := &Reconciler{ManagedRuntime: decorated}
		desired := desiredWithContract(fixture, "")
		if _, err := reconciler.registerManagedSource(context.Background(), desired, "source_0123456789abcdef01234567", nativeReceipt(), fixture.InstructionResponse); err != nil {
			t.Fatalf("baseline register-source refused: %v", err)
		}
	})
	t.Run("register_source_negotiated_wire32", func(t *testing.T) {
		decorated, _, fixture := newJourney(t)
		reconciler := &Reconciler{ManagedRuntime: decorated}
		desired := desiredWithContract(fixture, "0.1.32")
		if _, err := reconciler.registerManagedSource(context.Background(), desired, "source_0123456789abcdef01234567", nativeReceipt(), fixture.InstructionResponse); err != nil {
			t.Fatalf("RF register-source payload was refused by the shipped validator: %v", err)
		}
	})
}

// extractSandboxValidatorScriptsFromImage reads the packaged closed helper
// files out of the exact published Sandbox image with a stopped container
// (docker create + docker cp). No process, provider or native code runs.
func extractSandboxValidatorScriptsFromImage(t *testing.T, image string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	container := fmt.Sprintf("wire-contract-%d", time.Now().UnixNano())
	run := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(context.Background(), "docker", args...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s failed: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
	run("pull", "--platform", "linux/amd64", image)
	run("create", "--platform", "linux/amd64", "--name", container, image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	worker := filepath.Join(directory, "warpmetal_team_worker.py")
	supervisor := filepath.Join(directory, "warpmetal_opencode_supervisor.py")
	run("cp", container+":/usr/local/libexec/warpmetal-agent-teams/warpmetal_team_worker.py", worker)
	run("cp", container+":/usr/local/bin/warpmetal-opencode-supervisor", supervisor)
	run("rm", container)
	for _, path := range []string{worker, supervisor} {
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			t.Fatalf("extracted Sandbox validator %s is unavailable: %v", path, err)
		}
	}
	return worker, supervisor
}

// managedCapabilitySeamAdapter drives the unchanged packaged Supervisor
// negotiation/receipt code on a fixture sandbox root. It is a non-provider
// seam: the guard GET is served loopback with the actual observed guard
// version and the metadata is the actual published native metadata. It never
// replays a live Start and never executes native code.
const managedCapabilitySeamAdapter = `
import hashlib
import importlib.machinery
import importlib.util
import json
import socketserver
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

payload = json.load(sys.stdin)
start = payload["start"]
status = payload["status"]
manager = payload["manager"]
guard = payload["guard"]

base = Path(tempfile.mkdtemp(prefix="wire-seam-"))
instance = base / ".warpmetal/opencode/instances/default"
instance.mkdir(parents=True)
digest = start["profileDigest"]
version_root = base / ".warpmetal/tools/opencode" / digest.removeprefix("sha256:")
(version_root / "install/bin").mkdir(parents=True)
binary = version_root / "install/bin/opencode"
binary.write_bytes(b"fixture-managed-binary\n")
(version_root / "install/.warpmetal-binary.sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
(version_root / ".warpmetal-ready.json").write_text(json.dumps({
    "profileId": "opencode", "profileDigest": digest, "profileRevision": 2, "status": "ready",
}))
(version_root / "native-metadata.json").write_text(json.dumps({
    "formatVersion": 1,
    "archiveSha256": guard["artifactSha256"],
    "manifest": {
        "version": guard["customVersion"],
        "sourceRevision": guard["sourceRevision"],
        "patchDigest": guard["patchDigest"],
    },
}))
(instance / "credentials.json").write_text(json.dumps({"password": "fixture-guard-password-0123456789"}))

class GuardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"data": {"nativeGuardVersion": guard["guardVersion"]}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

server = socketserver.TCPServer(("127.0.0.1", 0), GuardHandler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()

state = {
    "phase": "stopped",
    "version": guard["customVersion"],
    "profileDigest": digest,
    "sessionId": "ses_fixtureprobe0001",
    "port": port,
    "managerPluginDigest": manager["managerPluginDigest"],
    "managerPluginLoaded": True,
    "managerProfile": manager["managerProfile"],
    "managerProviderId": manager["managerProviderId"],
    "managerModelId": manager["managerModelId"],
    "managerNativeProtocol": manager["managerNativeProtocol"],
    "managerProviderRouteDigest": manager["managerProviderRouteDigest"],
    "managerRecommendAvailable": True,
    "managerCapabilityReason": None,
    "managerRecipeIds": manager["managerRecipeIds"],
}
(instance / "state.json").write_text(json.dumps(state))

loader = importlib.machinery.SourceFileLoader("wire_seam", sys.argv[1])
spec = importlib.util.spec_from_loader("wire_seam", loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)

def status_document(identity, contract_source):
    document = {
        "schemaVersion": 1,
        "sandboxId": identity["sandboxId"],
        "instance": identity["instance"],
        "profileId": identity["profileId"],
        "profileDigest": identity["profileDigest"],
        "probe": False,
        "requestTimeoutSeconds": 30,
    }
    if contract_source.get("runtimeContractVersion"):
        document["runtimeContractVersion"] = contract_source["runtimeContractVersion"]
    return document

supervisor = module.Supervisor(root=base)
print(json.dumps({
    "startReceipt": supervisor.run("status", status_document(start, start)),
    "statusReceipt": supervisor.run("status", status_document(status, status)),
}))
`

// assertManagedCapabilityProbeEquality feeds the actual RF-emitted start and
// supervisor status request payloads from the journey capture through the
// unchanged packaged Supervisor negotiation/receipt seam and the actual
// managedManagerCapability consumer. Labels: the RF payloads are replayed
// actual emissions; the receipts are helper-generated by the packaged
// Supervisor code on a fixture root with the actual observed guard metadata;
// this is not a live Start or an end-to-end claim.
func assertManagedCapabilityProbeEquality(t *testing.T, invocations []managedInvocation, fixture producerFixture) {
	t.Helper()
	sandboxSource := os.Getenv("WARP_METAL_SANDBOX_SOURCE")
	image := os.Getenv("WARP_METAL_SANDBOX_IMAGE")
	var supervisorScript string
	switch {
	case sandboxSource != "":
		supervisorScript = filepath.Join(sandboxSource, "runner", "warpmetal_opencode_supervisor.py")
	case image != "":
		_, supervisorScript = extractSandboxValidatorScriptsFromImage(t, image)
	default:
		if os.Getenv("WARPMETAL_WIRE_CONTRACT_EVIDENCE") != "" {
			t.Fatal("WARP_METAL_SANDBOX_SOURCE or WARP_METAL_SANDBOX_IMAGE is required for the packaged Supervisor seam")
		}
		t.Skip("packaged Supervisor seam unavailable")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	var startRequest, statusRequest map[string]any
	for _, invocation := range invocations {
		// Supervisor probes carry the sandbox/profile identity; the broker
		// worker status carries a command envelope instead.
		if _, ok := invocation.request["profileId"]; !ok {
			continue
		}
		switch invocation.action {
		case "start":
			startRequest = invocation.request
		case "status":
			statusRequest = invocation.request
		}
	}
	if startRequest == nil || statusRequest == nil {
		t.Fatalf("journey did not emit the start/status probes: %#v", invocations)
	}
	canonical := func(request map[string]any) map[string]any {
		copy := make(map[string]any, len(request))
		for key, value := range request {
			copy[key] = value
		}
		// Bind the canonical 24-character sandbox identity the packaged
		// validator requires; the RF fixture identity is not canonical.
		copy["sandboxId"] = "sbx_0123456789abcdef01234567"
		return copy
	}
	guard := map[string]any{
		"guardVersion":   "warpmetal.atomic-input.v1",
		"customVersion":  "2.0.14-wm.1",
		"sourceRevision": "08462140ec0de1e4b17d4a353d8d5827f53cf7b0",
		"patchDigest":    "sha256:5bcf0104d17a31d5141d9ad773b7ca7fbeddeb71a4a36689d5baee9f72f0f47b",
		"artifactSha256": "sha256:69e7db9c21c2de97317b6aab50e06de3fc0a622fdd70ba4f305088825d65e844",
		"binarySha256":   "sha256:efc368d45d9226386d8a235cb85adfa17c5bff32f9208630cd771707378e92f9",
	}
	manager := map[string]any{
		"managerPluginDigest": "sha256:f7d9cec7e6bcfef134b0d27c5bd1526a0199859b5954c0dae523ff843eaf7a94",
		"managerProfile": map[string]any{
			"profileId": "warpmetal-insights-manager", "profileRevision": 1,
			"profileDigest": "sha256:4ea596774c5b66bfc395bda3f6c00765d4e89e22f270235a327872b3760e5e17",
		},
		"managerProviderId":          "deepseek",
		"managerModelId":             "deepseek-flash",
		"managerNativeProtocol":      "openai_chat",
		"managerProviderRouteDigest": "sha256:09434ec9b4a8638d088a0ca5c52e52f0161a1f74b56f9b966227b7dcae01305e",
		"managerRecipeIds": []string{
			"inspect_first_failure@1", "check_repeated_operation@1", "refine_query@1", "inspect_active_phase@1",
		},
	}
	requestPayload, err := json.Marshal(map[string]any{
		"start": canonical(startRequest), "status": canonical(statusRequest),
		"guard": guard, "manager": manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(context.Background(), python, "-c", managedCapabilitySeamAdapter, supervisorScript)
	command.Stdin = bytes.NewReader(requestPayload)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("packaged Supervisor seam failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
	var receipts struct {
		StartReceipt  managedSupervisorReceipt `json:"startReceipt"`
		StatusReceipt managedSupervisorReceipt `json:"statusReceipt"`
	}
	if err := json.Unmarshal(output, &receipts); err != nil {
		t.Fatalf("packaged Supervisor seam receipt decode: %v: %s", err, strings.TrimSpace(string(output)))
	}
	desired := fixture.ServiceManifest
	modelID, authMode := "deepseek-flash", "api_key"
	desired.Authority = &model.ManagedServiceAuthorityV1{
		TeamRevision: 5, ProviderID: "deepseek", ModelID: &modelID, AuthMode: &authMode,
	}
	if _, err := managedManagerCapability(desired, "source_probe_fixture0001", receipts.StartReceipt, receipts.StatusReceipt); err != nil {
		t.Fatalf("actual RF probe sequence refused by managedManagerCapability: %v (startContract=%v statusContract=%v)",
			err, startRequest["runtimeContractVersion"], statusRequest["runtimeContractVersion"])
	}
	mutatedAuthority := receipts.StartReceipt
	mutatedAuthority.ManagerProviderID = "foreign-provider"
	if _, err := managedManagerCapability(desired, "source_probe_fixture0001", mutatedAuthority, receipts.StatusReceipt); err == nil {
		t.Fatal("material authority change was not refused by managedManagerCapability")
	}
	if receipts.StartReceipt.NativeGuard != nil {
		guardCopy := *receipts.StartReceipt.NativeGuard
		guardCopy.GuardVersion = "foreign.guard.v1"
		mutatedGuard := receipts.StartReceipt
		mutatedGuard.NativeGuard = &guardCopy
		if _, err := managedManagerCapability(desired, "source_probe_fixture0001", mutatedGuard, receipts.StatusReceipt); err == nil {
			t.Fatal("material guard change was not refused by managedManagerCapability")
		}
	}
}

func loadProducerFixture(t *testing.T) producerFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "api", "testdata", "agent-managed-service-v1.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture producerFixture
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func loadSandboxSupervisorReceiptFixture() (sandboxSupervisorReceiptFixture, error) {
	payload, err := os.ReadFile(filepath.Join("testdata", "agent-openai-astra-supervisor-receipts-v1.json"))
	if err != nil {
		return sandboxSupervisorReceiptFixture{}, err
	}
	var fixture sandboxSupervisorReceiptFixture
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		return sandboxSupervisorReceiptFixture{}, err
	}
	return fixture, nil
}

func seedReadyProfile(t *testing.T, store *state.Store, setup model.SetupOperation) {
	t.Helper()
	if err := store.PutSandbox(context.Background(), state.LocalSandbox{
		ID: setup.SandboxID, Name: "managed-service", DesiredState: "running", ObservedState: "running",
		Generation: setup.SandboxGeneration, ObservedGeneration: setup.SandboxGeneration, Lifetime: "persistent",
		Resources: model.Resources{CPUMillicores: 1, MemoryMiB: 1, WorkspaceDiskGiB: 1, PIDs: 1},
	}); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(setup)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
	value := state.LocalSetupOperation{ID: setup.ID, SandboxID: setup.SandboxID, SandboxGeneration: setup.SandboxGeneration, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest, DesiredRevision: 1, BodyDigest: digest, RequestJSON: payload, State: "pending"}
	if err := store.PutSetupOperation(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionSetupOperation(context.Background(), setup.ID, "applying", nil, "", ""); err != nil {
		t.Fatal(err)
	}
	receipt, _ := json.Marshal(map[string]any{"status": "ready", "receiptDigest": digest})
	if err := store.TransitionSetupOperation(context.Background(), setup.ID, "ready", receipt, "", ""); err != nil {
		t.Fatal(err)
	}
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
