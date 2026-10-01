package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

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
	for _, role := range []string{"worker", "reviewer", "manager"} {
		t.Run(role, func(t *testing.T) {
			fixture := loadProducerFixture(t)
			fixture.ServiceManifest.Identity.Role = role
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
			reconciler = &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, Now: fixedNow}
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
			reconciler = &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, Now: fixedNow}
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
			reconciler.Now = func() time.Time { return fixedNow().Add(time.Second) }
			if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
				t.Fatal(err)
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
			reconciler = &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, Now: fixedNow}
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
		})
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

	pollContext, cancelPoll := context.WithTimeout(context.Background(), 100*time.Millisecond)
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

	secondContext, cancelSecond := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelSecond()
	if _, err := reconciler.reconcileManagedServices(secondContext, manifest); err != nil {
		t.Fatalf("active worker blocked regular reconciliation: %v", err)
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
	if err := store.TransitionSetupOperation(context.Background(), setup.ID, "ready", []byte(`{"status":"ready"}`), "", ""); err != nil {
		t.Fatal(err)
	}
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
