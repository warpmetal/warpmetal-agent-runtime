package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

const cellTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const cellTestFence = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
const cellTestFirstText = "perform the cell step"

var cellTestInstructionDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(cellTestFirstText)))

func cellTestEntry(profile model.ManagedServiceV2Profile) model.ManagedServiceV2 {
	provider := "openai"
	modelID := "gpt-6-astra"
	authMode := "api_key"
	return model.ManagedServiceV2{
		FormatVersion: 2, TargetKind: "cell_session",
		OperationID: "op_managed_cell_0001", LaunchOperationID: "op_cell_0001",
		ActionRevision: 3, DesiredRevision: 5, DesiredState: "active",
		SessionMode: "create_initial", ServiceRegistrationID: "service_cellchild01",
		ConfigDigest: cellTestDigest,
		OwnerCellID:  "cell_manager001", OwnerRole: "manager", OwnerGeneration: 2,
		SandboxID: "sbx_cellchild01", SandboxGeneration: 1, ServiceGeneration: 1, Fence: cellTestFence,
		Attempt:  1,
		Instance: "default", Role: "worker",
		NativeSessionID: "ses_owner0001", NativeProjectID: "0123456789abcdef0123456789abcdef01234567",
		WorkspaceEpoch: "epoch_cellchild01",
		Workspace: model.ManagedServiceV2Workspace{
			SelectionID: "selection_cell0001", ProjectID: "0123456789abcdef0123456789abcdef01234567",
			WorkspaceEpoch: "epoch_cellchild01", ScopeRevision: 1, RootAttestation: cellTestDigest,
		},
		Instructions: model.ManagedServiceV2Instructions{
			InstructionRevision: 1, InstructionDigest: cellTestInstructionDigest,
		},
		Profile:   profile,
		Authority: &model.ManagedServiceV2Authority{ProviderID: provider, ModelID: &modelID, AuthMode: &authMode},
	}
}

func cellTestSetup(entry model.ManagedServiceV2) model.SetupOperation {
	return model.SetupOperation{
		ID: "setup_cell0001", SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration,
		ProfileID: "opencode", ProfileRevision: 1, ProfileDigest: cellTestDigest,
	}
}

func seedCellProject(t *testing.T, store *state.Store, entry model.ManagedServiceV2, containerRoot string) {
	seedCellProjectForServer(t, store, entry, containerRoot, "")
}

func seedCellProjectForServer(t *testing.T, store *state.Store, entry model.ManagedServiceV2, containerRoot, serverID string) {
	t.Helper()
	serviceID := entry.ServiceRegistrationID
	if err := store.PutManagedProject(context.Background(), state.LocalManagedProject{
		Phase: "ready", ServerID: serverID,
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: entry.Workspace.SelectionID, ProjectID: entry.Workspace.ProjectID,
			WorkspaceEpoch: entry.Workspace.WorkspaceEpoch, SandboxID: entry.SandboxID,
			SandboxGeneration: entry.SandboxGeneration, ServiceRegistrationID: &serviceID,
			Designation: "team_project", RootAttestation: entry.Workspace.RootAttestation,
		},
		ContainerRoot: containerRoot,
		ScopeRevision: entry.Workspace.ScopeRevision,
	}); err != nil {
		t.Fatal(err)
	}
}

type cellTestControl struct {
	instruction model.ManagedServiceInstructionV1
	fetch       []model.ManagedServiceFetchRequestV1
}

func (c *cellTestControl) ManagedServiceEndpoint() string { return "https://api.warpmetal.example" }
func (c *cellTestControl) InsightPolicies(context.Context) (model.InsightPolicyEnvelopeV1, error) {
	return model.InsightPolicyEnvelopeV1{}, nil
}
func (c *cellTestControl) ManagedServiceEnrollment(context.Context, string, model.ManagedServiceFetchRequestV1) (model.ManagedServiceEnrollmentV1, error) {
	return model.ManagedServiceEnrollmentV1{}, errors.New("unexpected enrollment")
}
func (c *cellTestControl) ManagedServiceInstructions(_ context.Context, _ string, fetch model.ManagedServiceFetchRequestV1) (model.ManagedServiceInstructionV1, error) {
	c.fetch = append(c.fetch, fetch)
	return c.instruction, nil
}
func (c *cellTestControl) CellCredential(context.Context, string) (api.CellCredentialResult, error) {
	return api.CellCredentialResult{}, nil
}

func (c *cellTestControl) ReportCellPreparation(context.Context, model.CellPreparationReport) (model.CellPreparationView, error) {
	return model.CellPreparationView{}, nil
}

type cellTestRuntime struct {
	store  *state.Store
	result []byte
	err    error
	// diagnostic is the bounded stderr the trusted adapter writes on a refusal.
	diagnostic []byte
	calls      []managedCellCallV1
	payloads   [][]byte
	// startCalls records every native-server start invoked before the adapter.
	startCalls int
	startErr   error
	// started tracks whether the mock server has been started, so the status probe
	// returns "stopped" before the first start and "running" afterwards.
	started bool
	// drained models a stopped instance that already owns a native session (the
	// supervisor's state after a binding-change drain).
	drained bool
	// statusSessionID overrides the manager session echoed by the status probe.
	// Empty keeps the default: the manager session only exists once the mock
	// server was started or drained.
	statusSessionID string
	// statusRoleReadback, when non-nil, makes the status receipt carry the
	// controller-parent role readback, exactly like a controller-parent instance.
	statusRoleReadback map[string]any
	// statusErr simulates a supervisor status transport failure.
	statusErr error
	// statusRequests records the exact lookup-only manager status requests.
	statusRequests []map[string]any
	// startRequests records every native-server start request in dispatch order.
	startRequests []map[string]any
	// actions records every supervisor action in dispatch order, so a test can
	// prove the manager was bound before the native server was started.
	actions []containers.ManagedSupervisorAction
	// rebindRequests records the exact product-issued binding requests.
	rebindRequests []map[string]any
	rebindErr      error
	// rebindReceipt/rebindDiagnostic model a supervisor that refused the command
	// and wrote its own safe receipt before exiting non-zero. Both are bounded,
	// non-secret surfaces exactly like the real supervisor's stdout/stderr, and
	// they are returned alongside the error so the caller can name the predicate.
	rebindReceipt    []byte
	rebindDiagnostic []byte
	// rebindBinding overrides the tuple echoed by the rebind receipt.
	rebindBinding map[string]any
	// managerProviderID/managerModelID are the tuple the mock supervisor builds
	// the manager route from; status/start echo them like the real supervisor.
	managerProviderID string
	managerModelID    string
	// startManagerProviderID/startManagerModelID override only the start/status
	// receipt readback, modelling a supervisor that ignored the stored binding.
	startManagerProviderID string
	startManagerModelID    string
	// onCall observes durable state at the exact moment of the adapter call, so
	// the test can prove the intent was persisted before any effect.
	onCall func()
}

func (r *cellTestRuntime) managerFacts() (string, string) {
	providerID, modelID := r.managerProviderID, r.managerModelID
	if r.startManagerProviderID != "" {
		providerID = r.startManagerProviderID
	}
	if r.startManagerModelID != "" {
		modelID = r.startManagerModelID
	}
	return providerID, modelID
}

func (r *cellTestRuntime) ExecManagedSupervisor(_ context.Context, _ string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	r.actions = append(r.actions, action)
	if action == containers.ManagedSupervisorRebind {
		var request map[string]any
		if err := json.Unmarshal(payload, &request); err != nil {
			return nil, nil, err
		}
		r.rebindRequests = append(r.rebindRequests, request)
		if r.rebindErr != nil {
			return r.rebindReceipt, r.rebindDiagnostic, r.rebindErr
		}
		binding := map[string]any{
			"provider": request["provider"], "model": request["model"], "authMode": request["authMode"],
		}
		if r.rebindBinding != nil {
			binding = r.rebindBinding
		}
		r.managerProviderID, _ = binding["provider"].(string)
		r.managerModelID, _ = binding["model"].(string)
		receipt := map[string]any{
			"schemaVersion": 1, "command": "rebind", "status": "applied", "applied": true, "restarted": false,
			"instance": request["instance"], "sandboxId": request["sandboxId"],
			"profileId": request["profileId"], "profileDigest": request["profileDigest"],
			"bindingRevision": 1, "binding": binding,
		}
		encoded, _ := json.Marshal(receipt)
		return encoded, nil, nil
	}
	if action == containers.ManagedSupervisorStatus {
		var request map[string]any
		if err := json.Unmarshal(payload, &request); err != nil {
			return nil, nil, err
		}
		r.statusRequests = append(r.statusRequests, request)
		if r.statusErr != nil {
			return nil, nil, r.statusErr
		}
		sessionID := ""
		if r.statusSessionID != "" {
			sessionID = r.statusSessionID
		} else if r.started || r.drained {
			sessionID = "ses_manager0001"
		}
		if r.started {
			providerID, modelID := r.managerFacts()
			receipt := map[string]any{
				"schemaVersion": 1, "command": "status", "status": "running", "ready": true,
				"instance": "default", "sandboxId": "sbx_cellchild01", "profileId": "opencode", "profileDigest": cellTestDigest,
				"sessionId": sessionID, "managerProviderId": providerID, "managerModelId": modelID,
			}
			if r.statusRoleReadback != nil {
				receipt["nativeRoleReadback"] = r.statusRoleReadback
			}
			encoded, _ := json.Marshal(receipt)
			return encoded, nil, nil
		}
		status := "stopped"
		receipt := map[string]any{
			"schemaVersion": 1, "command": "status", "status": status,
			"instance": "default", "sandboxId": "sbx_cellchild01", "profileId": "opencode", "profileDigest": cellTestDigest,
		}
		if r.drained {
			receipt["status"] = "drained"
		}
		if sessionID != "" {
			receipt["sessionId"] = sessionID
		}
		encoded, _ := json.Marshal(receipt)
		return encoded, nil, nil
	}
	if action == containers.ManagedSupervisorStart {
		r.startCalls++
		r.started = true
		var request map[string]any
		if err := json.Unmarshal(payload, &request); err != nil {
			return nil, nil, err
		}
		r.startRequests = append(r.startRequests, request)
		if r.startErr != nil {
			return nil, nil, r.startErr
		}
		providerID, modelID := r.managerFacts()
		receipt := map[string]any{
			"schemaVersion": 1, "command": "start", "status": "ready", "phase": "running", "ready": true,
			"instance": "default", "sandboxId": "sbx_cellchild01", "profileId": "opencode", "profileDigest": cellTestDigest,
			"sessionId": "ses_manager0001", "nativeProjectId": "0123456789abcdef0123456789abcdef01234567",
			"port": managedServicePort, "managerProviderId": providerID, "managerModelId": modelID,
		}
		encoded, _ := json.Marshal(receipt)
		return encoded, nil, nil
	}
	if action == containers.ManagedSupervisorCredential {
		receipt := map[string]any{
			"schemaVersion": 1, "command": "credential", "status": "applied", "ready": true,
			"instance": "default", "sandboxId": "sbx_cellchild01", "profileId": "opencode", "profileDigest": cellTestDigest,
		}
		encoded, _ := json.Marshal(receipt)
		return encoded, nil, nil
	}
	if action != containers.ManagedSupervisorCell {
		return nil, nil, fmt.Errorf("unexpected supervisor action %s", action)
	}
	var call managedCellCallV1
	if err := json.Unmarshal(payload, &call); err != nil {
		return nil, nil, err
	}
	r.calls = append(r.calls, call)
	r.payloads = append(r.payloads, append([]byte(nil), payload...))
	if r.onCall != nil {
		r.onCall()
	}
	if r.err != nil {
		return nil, r.diagnostic, r.err
	}
	return r.result, nil, nil
}

func (r *cellTestRuntime) ExecManagedWorker(context.Context, string, containers.ManagedWorkerAction, []byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("unexpected worker action")
}

func cellTestResult(state string, outcome *string, exhausted bool, contract string) []byte {
	receipt := managedCellResultV1{
		SchemaVersion: 1, Status: "ok", RuntimeContractVersion: contract,
		OperationID: "op_cell_0001", SessionID: "ses_owner0001", MessageID: "msg_owner0001",
		State: state, Attempt: 1, Outcome: outcome, Exhausted: exhausted, ReceiptDigest: cellTestDigest,
	}
	payload, _ := json.Marshal(receipt)
	return payload
}

func newCellReconciler(t *testing.T, store *state.Store, control ManagedServiceControl, runtime ManagedSandboxRuntime) *Reconciler {
	t.Helper()
	return &Reconciler{
		Store: store, ManagedControl: control, ManagedRuntime: runtime,
		Now: func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) },
	}
}

func cellInstruction(t *testing.T) model.ManagedServiceInstructionV1 {
	t.Helper()
	content := cellTestFirstText
	return model.ManagedServiceInstructionV1{
		InstructionRevision: 1, Content: content,
		InstructionDigest: cellTestInstructionDigest,
		ExpiresAt:         time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC),
	}
}

func TestEnsureCellNativeServerReusesLiveServer(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)

	runtime := &cellTestRuntime{}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	instruction := cellInstruction(t).Content

	if _, err := reconciler.ensureCellNativeServer(context.Background(), entry, "/home/agent/projects/cell", instruction); err != nil {
		t.Fatalf("first ensure failed: %v", err)
	}
	if runtime.startCalls != 1 {
		t.Fatalf("first ensure should start once, got %d", runtime.startCalls)
	}
	if len(runtime.startRequests) != 1 || runtime.startRequests[0]["sessionMode"] != "create_initial" {
		t.Fatalf("a session-less manager must create its first session: %#v", runtime.startRequests)
	}
	// The second ensure must reuse the live server via the status probe, not start again.
	if _, err := reconciler.ensureCellNativeServer(context.Background(), entry, "/home/agent/projects/cell", instruction); err != nil {
		t.Fatalf("second ensure failed: %v", err)
	}
	if runtime.startCalls != 1 {
		t.Fatalf("second ensure must not re-start: startCalls=%d", runtime.startCalls)
	}
}

// TestEnsureCellNativeServerReusesDrainedSession proves the binding-change
// recovery path: a rebind that changes the tuple drains the running manager, so
// the follow-up start must look up the saved session instead of refusing a
// second create_initial.
func TestEnsureCellNativeServerReusesDrainedSession(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)

	runtime := &cellTestRuntime{drained: true}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	parent, err := reconciler.ensureCellNativeServer(context.Background(), entry, "/home/agent/projects/cell", cellTestFirstText)
	if err != nil || parent != "ses_manager0001" {
		t.Fatalf("drained manager recovery failed: %q %v", parent, err)
	}
	if runtime.startCalls != 1 || len(runtime.startRequests) != 1 || runtime.startRequests[0]["sessionMode"] != "lookup_only" {
		t.Fatalf("a drained manager must reuse its saved session: %#v", runtime.startRequests)
	}
}

func TestEnsureCellNativeServerFailsClosedOnStartFailure(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)

	runtime := &cellTestRuntime{startErr: errors.New("native server failed to start")}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)

	if _, err := reconciler.ensureCellNativeServer(context.Background(), entry, "/home/agent/projects/cell", cellInstruction(t).Content); err == nil {
		t.Fatal("a start failure must fail closed")
	}
}

func TestEnsureCellNativeServerKeepsLegacyV2CredentialEnvelope(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/internal/runtime/cell-credential" || request.Method != "POST" {
			t.Errorf("unexpected credential transport: %s %s", request.Method, request.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"credentialId":"cred_legacy0001","apiKey":"synthetic-legacy-key"}`)
	}))
	defer server.Close()
	client := api.Client{Origin: server.URL, NodeToken: "rtn_fixture", HTTP: server.Client()}
	runtime := &cellTestRuntime{started: true}
	r := newCellReconciler(t, store, client, runtime)
	parent, err := r.ensureCellNativeServer(context.Background(), entry, "/home/agent/projects/cell", cellTestFirstText)
	if err != nil || parent != "ses_manager0001" {
		t.Fatalf("legacy V2 was forced through V3 lease identity: %q %v", parent, err)
	}
}

func TestCellCallBindsManagerAsParentNotChild(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)
	seedCellProject(t, store, entry, "/home/agent/projects/cell")

	outcome := "succeeded"
	runtime := &cellTestRuntime{result: cellTestResult("terminal", &outcome, false, model.CellExecutionContractVersion)}
	control := &cellTestControl{instruction: cellInstruction(t)}
	reconciler := newCellReconciler(t, store, control, runtime)

	if err := reconciler.reconcileCellService(context.Background(), entry); err != nil {
		t.Fatalf("cell reconcile failed: %v", err)
	}
	if len(runtime.calls) != 1 {
		t.Fatalf("adapter call count = %d", len(runtime.calls))
	}
	call := runtime.calls[0]
	if call.ParentSessionID != "ses_manager0001" {
		t.Fatalf("parentSessionId must be the manager session, got %q", call.ParentSessionID)
	}
	if call.NativeSessionID != "ses_owner0001" {
		t.Fatalf("nativeSessionId must be the deterministic child, got %q", call.NativeSessionID)
	}
	if call.ParentSessionID == call.NativeSessionID {
		t.Fatalf("parent and child sessions must be distinct")
	}

	// R-WP28-1: the Runtime itself must carry the manifest's exact manager
	// authority into the supervisor binding store before the native server
	// starts. This is the product path; no venue/harness rebind is involved.
	if len(runtime.rebindRequests) != 1 {
		t.Fatalf("manager binding request count = %d", len(runtime.rebindRequests))
	}
	rebind := runtime.rebindRequests[0]
	if rebind["provider"] != "openai" || rebind["model"] != "gpt-6-astra" || rebind["authMode"] != "api_key" ||
		rebind["restart"] != false || rebind["instance"] != "default" {
		t.Fatalf("manager binding request changed the manifest authority: %#v", rebind)
	}
	if _, invented := rebind["bindingRevision"]; invented {
		t.Fatalf("manager binding request invented a revision: %#v", rebind)
	}
	rebindIndex, startIndex := -1, -1
	for index, action := range runtime.actions {
		switch action {
		case containers.ManagedSupervisorRebind:
			if rebindIndex < 0 {
				rebindIndex = index
			}
		case containers.ManagedSupervisorStart:
			if startIndex < 0 {
				startIndex = index
			}
		}
	}
	if rebindIndex < 0 || startIndex < 0 || rebindIndex > startIndex {
		t.Fatalf("manager was not bound before start: actions=%v", runtime.actions)
	}
	// The start receipt echo proves the native manager configuration was built
	// from the bound tuple, not merely that a file was written.
	if runtime.managerProviderID != "openai" || runtime.managerModelID != "gpt-6-astra" {
		t.Fatalf("manager route echo = %q/%q", runtime.managerProviderID, runtime.managerModelID)
	}
}

// TestCellLaunchNormalizesManagerModelBinding proves the request carries the
// bare native model id the supervisor validates, even when the manifest names
// it with the provider prefix.
func TestCellLaunchNormalizesManagerModelBinding(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	prefixed := "openai/gpt-6-astra"
	entry.Authority.ModelID = &prefixed
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)

	runtime := &cellTestRuntime{}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if _, err := reconciler.ensureCellNativeServer(context.Background(), entry, "/home/agent/projects/cell", cellTestFirstText); err != nil {
		t.Fatalf("prefixed manifest model was not bound: %v", err)
	}
	if len(runtime.rebindRequests) != 1 || runtime.rebindRequests[0]["model"] != "gpt-6-astra" ||
		runtime.rebindRequests[0]["provider"] != "openai" || runtime.rebindRequests[0]["authMode"] != "api_key" {
		t.Fatalf("manager binding request was not the bare exact tuple: %#v", runtime.rebindRequests)
	}
}

// TestCellLaunchFailsClosedWithoutExactManagerBinding proves the R-WP28-1
// fail-closed boundary: a cell launch with absent/invalid authority, a changed
// binding receipt, or a start receipt that did not build the manager route from
// the bound tuple must stop before the adapter admits a child. Before the fix
// the start simply proceeded and the manager fell back to the default provider
// route (the venue had to rebind by hand).
func TestCellLaunchFailsClosedWithoutExactManagerBinding(t *testing.T) {
	outcome := "succeeded"
	cases := []struct {
		name         string
		mutate       func(*model.ManagedServiceV2)
		runtime      func(*cellTestRuntime)
		wantStart    bool
		wantNoAction bool
	}{
		{
			name:         "absent authority",
			mutate:       func(entry *model.ManagedServiceV2) { entry.Authority = nil },
			wantNoAction: true,
		},
		{
			name:         "absent model",
			mutate:       func(entry *model.ManagedServiceV2) { entry.Authority.ModelID = nil },
			wantNoAction: true,
		},
		{
			name: "invalid auth mode",
			mutate: func(entry *model.ManagedServiceV2) {
				mode := "none"
				entry.Authority.AuthMode = &mode
			},
			wantNoAction: true,
		},
		{
			name: "changed binding receipt",
			runtime: func(runtime *cellTestRuntime) {
				runtime.rebindBinding = map[string]any{"provider": "openai", "model": "gpt-4o-mini", "authMode": "api_key"}
			},
		},
		{
			name: "start route not bound",
			runtime: func(runtime *cellTestRuntime) {
				runtime.startManagerModelID = "gpt-4o-mini"
			},
			wantStart: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			entry := cellTestEntry(model.ManagedServiceV2Profile{})
			setup := cellTestSetup(entry)
			entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
			if testCase.mutate != nil {
				testCase.mutate(&entry)
			}
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			seedReadyProfile(t, store, setup)
			seedCellProject(t, store, entry, "/home/agent/projects/cell")

			runtime := &cellTestRuntime{result: cellTestResult("terminal", &outcome, false, model.CellExecutionContractVersion)}
			if testCase.runtime != nil {
				testCase.runtime(runtime)
			}
			reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
			if err := reconciler.reconcileCellService(context.Background(), entry); err == nil {
				t.Fatal("a cell launch without an exact manager binding must fail closed")
			}
			if len(runtime.calls) != 0 {
				t.Fatalf("adapter admitted a child without an exact manager binding: %d calls", len(runtime.calls))
			}
			if testCase.wantStart {
				if runtime.startCalls != 1 {
					t.Fatalf("start call count = %d", runtime.startCalls)
				}
			} else if runtime.startCalls != 0 {
				t.Fatalf("native start occurred before the binding was proven: actions=%v", runtime.actions)
			}
			if testCase.wantNoAction && len(runtime.actions) != 0 {
				t.Fatalf("supervisor effect occurred before the authority was refused: actions=%v", runtime.actions)
			}
			local, err := store.CellOperation(context.Background(), entry.OperationID)
			if err != nil || local == nil {
				t.Fatalf("cell operation hold not durable: %#v %v", local, err)
			}
			if local.Phase == "terminal" || local.Phase == "ready" {
				t.Fatalf("unbound launch was recorded as terminal: %#v", local)
			}
		})
	}
}

func TestValidateManagedServiceV2AcceptsCellEntryAndKeepsMemberV1Compatible(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{
		SetupOperationID: setup.ID, ProfileID: setup.ProfileID,
		ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest,
	}
	if err := model.ValidateManagedServiceV2(entry, entry.SandboxGeneration, true, &setup); err != nil {
		t.Fatalf("valid formatVersion 2 cell entry was rejected: %v", err)
	}

	// The entry must never be mistaken for a Team member: a v1-tagged or
	// non-cell-targeted entry is refused, and it carries no member/team identity.
	v1 := entry
	v1.FormatVersion = 1
	if err := model.ValidateManagedServiceV2(v1, entry.SandboxGeneration, true, &setup); err == nil {
		t.Fatal("formatVersion 1 entry was accepted on the cell path")
	}
	notCell := entry
	notCell.TargetKind = "team_member"
	if err := model.ValidateManagedServiceV2(notCell, entry.SandboxGeneration, true, &setup); err == nil {
		t.Fatal("non-cell target kind was accepted on the cell path")
	}

	// Member formatVersion 1 stays byte-compatible: a v1 object round-trips and
	// a manifest JSON object carrying both member and cell arrays decodes.
	member := model.ManagedServiceV1{FormatVersion: 1, OperationID: "op_member_0001", ActionRevision: 1, DesiredRevision: 1, ConfigDigest: cellTestDigest}
	payload, err := json.Marshal(member)
	if err != nil {
		t.Fatal(err)
	}
	var decodedMember model.ManagedServiceV1
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decodedMember); err != nil {
		t.Fatalf("member formatVersion 1 no longer decodes: %v", err)
	}
	if decodedMember.FormatVersion != 1 || decodedMember.OperationID != "op_member_0001" {
		t.Fatalf("member formatVersion 1 changed: %#v", decodedMember)
	}

	manifestJSON := fmt.Sprintf(`{"serverId":"srv_cell0001","desiredRevision":1,"imageDigest":"","capacity":{},"sandboxes":[],"accessGrants":[],"managedServices":[],"cellServices":[%s]}`,
		mustJSON(t, entry))
	var manifest model.Manifest
	manifestDecoder := json.NewDecoder(bytes.NewReader([]byte(manifestJSON)))
	manifestDecoder.DisallowUnknownFields()
	if err := manifestDecoder.Decode(&manifest); err != nil {
		t.Fatalf("manifest with cellServices did not decode: %v", err)
	}
	if len(manifest.CellEntries) != 1 || manifest.CellEntries[0].ServiceRegistrationID != entry.ServiceRegistrationID {
		t.Fatalf("cellServices were not preserved: %#v", manifest.CellEntries)
	}
}

func TestReconcileCellServicePersistsBeforeEffectAndReportsCompletion(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)
	containerRoot := "/home/agent/projects/cell"
	seedCellProject(t, store, entry, containerRoot)

	outcome := "succeeded"
	runtime := &cellTestRuntime{result: cellTestResult("terminal", &outcome, false, model.CellExecutionContractVersion)}
	runtime.onCall = func() {
		persisted, readErr := store.CellOperation(context.Background(), entry.OperationID)
		if readErr != nil || persisted == nil || persisted.Phase != "pending" {
			t.Errorf("durable operation was not persisted before the adapter effect: %#v %v", persisted, readErr)
		}
	}
	control := &cellTestControl{instruction: cellInstruction(t)}
	reconciler := newCellReconciler(t, store, control, runtime)

	if err := reconciler.reconcileCellService(context.Background(), entry); err != nil {
		t.Fatalf("cell reconcile failed: %v", err)
	}
	if len(runtime.calls) != 1 {
		t.Fatalf("adapter call count = %d", len(runtime.calls))
	}
	call := runtime.calls[0]
	if call.Action != "launch" || call.OperationID != entry.LaunchOperationID ||
		call.ParentSessionID != "ses_manager0001" || call.WorktreeDir != containerRoot ||
		call.FirstText != "perform the cell step" || call.Model.ProviderID != "openai" || call.Model.ID != "gpt-6-astra" ||
		call.RuntimeContractVersion != model.CellExecutionContractVersion {
		t.Fatalf("adapter call document is not the scoped launch: %#v", call)
	}
	// The instruction fetch must carry the ACTUAL cell tuple: the canonical
	// service registration and service generation, the entry's pinned
	// instruction/config digest, and a nonempty derived process instance.
	if len(control.fetch) != 1 {
		t.Fatalf("instruction fetch count = %d", len(control.fetch))
	}
	fetch := control.fetch[0]
	if fetch.ServiceRegistrationID != entry.ServiceRegistrationID ||
		fetch.ConfigDigest != entry.ConfigDigest ||
		fetch.ServiceGeneration != entry.ServiceGeneration ||
		fetch.ProcessInstance == "" ||
		fetch.ProcessInstance != model.ManagedServiceProcessInstance(entry.Instance, entry.ServiceGeneration) {
		t.Fatalf("cell instruction fetch tuple is wrong: %#v", fetch)
	}
	persisted, err := store.CellOperation(context.Background(), entry.OperationID)
	if err != nil || persisted == nil {
		t.Fatalf("cell operation missing: %v", err)
	}
	if persisted.Phase != "terminal" || persisted.Report.ObservedState != "ready" || persisted.Report.Exhausted ||
		persisted.Child == nil || persisted.Child.Outcome == nil || *persisted.Child.Outcome != "succeeded" ||
		persisted.Report.Attempt != 1 {
		t.Fatalf("ordinary completion report is wrong: %#v", persisted)
	}
}

func TestReconcileCellServiceExhaustionIsNotCompletionAndSurvivesRestart(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	seedReadyProfile(t, store, setup)
	seedCellProject(t, store, entry, "/home/agent/projects/cell")

	runtime := &cellTestRuntime{result: cellTestResult("exhausted", nil, true, model.CellExecutionContractVersion)}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if err := reconciler.reconcileCellService(context.Background(), entry); err != nil {
		t.Fatalf("exhausted cell reconcile failed: %v", err)
	}
	persisted, err := store.CellOperation(context.Background(), entry.OperationID)
	if err != nil || persisted == nil || !persisted.Exhausted || persisted.Phase != "exhausted" || persisted.Report.ObservedState != "exhausted" {
		t.Fatalf("exhausted effect was not recorded as non-terminal: %#v %v", persisted, err)
	}
	if persisted.Report.ObservedState == "ready" {
		t.Fatal("exhausted effect was reported as an ordinary terminal completion")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart: the exhausted marker must survive, and a later ordinary terminal
	// observation must not clear it or turn it into a completion.
	store, err = state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	outcome := "failed"
	runtime = &cellTestRuntime{result: cellTestResult("terminal", &outcome, false, model.CellExecutionContractVersion)}
	reconciler = newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if err := reconciler.reconcileCellService(context.Background(), entry); err != nil {
		t.Fatalf("post-restart cell reconcile failed: %v", err)
	}
	replayed, err := store.CellOperation(context.Background(), entry.OperationID)
	if err != nil || replayed == nil || !replayed.Exhausted || replayed.Phase != "exhausted" ||
		replayed.Report.ObservedState != "exhausted" {
		t.Fatalf("exhausted marker did not survive restart: %#v %v", replayed, err)
	}
}

func TestReconcileCellServiceRejectsNonCellContract(t *testing.T) {
	if CellExecutionEnabled("0.1.46") {
		t.Fatal("0.1.46 must not advertise cell execution")
	}
	if !CellExecutionEnabled("0.1.47") {
		t.Fatal("0.1.47 must advertise cell execution")
	}
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)
	seedCellProject(t, store, entry, "/home/agent/projects/cell")

	outcome := "succeeded"
	runtime := &cellTestRuntime{result: cellTestResult("terminal", &outcome, false, "0.1.46")}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if err := reconciler.reconcileCellService(context.Background(), entry); err != nil {
		t.Fatalf("cell reconcile failed: %v", err)
	}
	persisted, err := store.CellOperation(context.Background(), entry.OperationID)
	if err != nil || persisted == nil {
		t.Fatalf("cell operation missing: %v", err)
	}
	if persisted.Report.ObservedState == "ready" || persisted.Exhausted {
		t.Fatalf("0.1.46 result was claimed as a cell completion: %#v", persisted.Report)
	}
	if persisted.Report.LastError == nil || persisted.Report.LastError.Code != "cell_contract_unsupported" {
		t.Fatalf("0.1.46 result did not fail closed: %#v", persisted.Report.LastError)
	}
}

func TestReconcileCellServiceLostEffectIsUnknownNotCompletion(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)
	seedCellProject(t, store, entry, "/home/agent/projects/cell")

	runtime := &cellTestRuntime{err: errors.New("lost adapter response")}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if err := reconciler.reconcileCellService(context.Background(), entry); err == nil {
		t.Fatal("lost adapter effect returned success")
	}
	persisted, err := store.CellOperation(context.Background(), entry.OperationID)
	if err != nil || persisted == nil || persisted.Report.ObservedState == "ready" || persisted.Phase == "terminal" {
		t.Fatalf("lost adapter effect was reported as terminal: %#v %v", persisted, err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func seedCellLaunch(t *testing.T, store *state.Store, entry model.ManagedServiceV2) {
	t.Helper()
	if err := store.PutCellOperation(context.Background(), state.LocalCellOperation{Entry: entry, Phase: "pending", Attempt: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileCellCancelReportsCancelledOnlyOnExactQuiescence(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	entry.DesiredState = "retired"
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)
	seedCellProject(t, store, entry, "/home/agent/projects/cell")
	seedCellLaunch(t, store, entry)

	interrupted := "interrupted"
	runtime := &cellTestRuntime{started: true, result: cellTestResult("terminal", &interrupted, false, model.CellExecutionContractVersion)}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if err := reconciler.reconcileCellService(context.Background(), entry); err != nil {
		t.Fatalf("cancel reconcile failed: %v", err)
	}
	if len(runtime.calls) != 1 || runtime.calls[0].Action != "cancel" || runtime.calls[0].Attempt != 1 {
		t.Fatalf("cancel action was not sent with the exact attempt: %#v", runtime.calls)
	}
	// The trusted adapter verifies the child's native parentID. The cancel call
	// must carry the manager/supervisor session recorded by launch/bind, never
	// the deterministic child as its own parent.
	if runtime.calls[0].ParentSessionID != "ses_manager0001" {
		t.Fatalf("cancel parentSessionId must be the manager session, got %q", runtime.calls[0].ParentSessionID)
	}
	if runtime.calls[0].ParentSessionID == runtime.calls[0].NativeSessionID {
		t.Fatal("cancel sent the child session as its own parent")
	}
	if len(runtime.statusRequests) != 1 || runtime.statusRequests[0]["probe"] != false ||
		runtime.statusRequests[0]["instance"] != entry.Instance || runtime.statusRequests[0]["sandboxId"] != entry.SandboxID ||
		runtime.statusRequests[0]["profileDigest"] != entry.Profile.ProfileDigest {
		t.Fatalf("manager identity was not resolved with the exact lookup-only status request: %#v", runtime.statusRequests)
	}
	persisted, err := store.CellOperation(context.Background(), entry.OperationID)
	if err != nil || persisted == nil {
		t.Fatalf("cell operation missing: %v", err)
	}
	if persisted.Report.ObservedState != "cancelled" || persisted.Report.Fence != entry.Fence ||
		persisted.Report.ServiceGeneration != entry.ServiceGeneration || persisted.Report.ReceiptDigest == "" {
		t.Fatalf("cancelled report did not carry the exact fence/generation/receipt: %#v", persisted.Report)
	}
}

func TestReconcileCellCancelNeverReportsCancelledOnUnresolvedEffect(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	entry.DesiredState = "retired"
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)
	seedCellProject(t, store, entry, "/home/agent/projects/cell")
	seedCellLaunch(t, store, entry)

	// A still-running child (interrupt accepted but not yet stopped) must never be
	// reported as a clean terminal.
	runtime := &cellTestRuntime{started: true, result: cellTestResult("running", nil, false, model.CellExecutionContractVersion)}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if err := reconciler.reconcileCellService(context.Background(), entry); err != nil {
		t.Fatalf("cancel reconcile failed: %v", err)
	}
	persisted, err := store.CellOperation(context.Background(), entry.OperationID)
	if err != nil || persisted == nil {
		t.Fatalf("cell operation missing: %v", err)
	}
	if persisted.Report.ObservedState != "unknown" || persisted.Report.ReceiptDigest == "" {
		t.Fatalf("unresolved effect was reported as a clean terminal: %#v", persisted.Report)
	}
}

func TestReconcileCellCancelWithoutLocalLaunchSurfacesUnresolvedHold(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	entry.DesiredState = "retired"
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)
	seedCellProject(t, store, entry, "/home/agent/projects/cell")

	// No durable launch record and the adapter observes a child that is still
	// running: identity/absence of a settled native execution cannot be proven.
	// The Runtime must reconcile against the persisted binding WITHOUT
	// relaunching and surface an explicit durable non-terminal hold -- never an
	// invisible deferral and never a fabricated "cancelled".
	runtime := &cellTestRuntime{started: true, result: cellTestResult("running", nil, false, model.CellExecutionContractVersion)}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if err := reconciler.reconcileCellService(context.Background(), entry); err != nil {
		t.Fatalf("cancel without local launch errored: %v", err)
	}
	if len(runtime.calls) != 1 || runtime.calls[0].Action != "cancel" {
		t.Fatalf("local-state reconciliation must observe the persisted binding without relaunching: %#v", runtime.calls)
	}
	if runtime.calls[0].Attempt != entry.Attempt {
		t.Fatalf("local-state reconciliation did not carry the authoritative attempt: %#v", runtime.calls[0])
	}
	persisted, err := store.CellOperation(context.Background(), entry.OperationID)
	if err != nil || persisted == nil {
		t.Fatalf("local-state hold was not persisted: %#v %v", persisted, err)
	}
	if persisted.Report.ObservedState != "unknown" || persisted.Phase == "terminal" ||
		persisted.Report.Attempt != entry.Attempt {
		t.Fatalf("local-state hold is not an explicit non-terminal record: %#v", persisted)
	}
	if persisted.Report.ObservedState == "cancelled" {
		t.Fatal("local-state hold fabricated a cancelled")
	}
	if persisted.Report.LastError == nil || persisted.Report.LastError.Code != "cell_local_state_missing" {
		t.Fatalf("local-state hold did not surface its explicit unresolved reason: %#v", persisted.Report.LastError)
	}
}

// TestReconcileCellCancelFailsClosedWithoutManagerIdentity proves a cancellation
// never sends a guessed parent to the trusted adapter. A missing recorded
// manager session, a supervisor that echoes the deterministic child, and a
// status transport failure each stop before any adapter effect and persist a
// precise non-terminal hold.
func TestReconcileCellCancelFailsClosedWithoutManagerIdentity(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*cellTestRuntime, model.ManagedServiceV2)
		code      string
	}{
		{
			name:      "missing manager session",
			configure: func(*cellTestRuntime, model.ManagedServiceV2) {},
			code:      "cell_manager_identity_missing",
		},
		{
			name: "child echoed as manager",
			configure: func(runtime *cellTestRuntime, entry model.ManagedServiceV2) {
				runtime.statusSessionID = entry.NativeSessionID
			},
			code: "cell_manager_identity_invalid",
		},
		{
			name: "status unavailable",
			configure: func(runtime *cellTestRuntime, _ model.ManagedServiceV2) {
				runtime.statusErr = errors.New("supervisor status unavailable")
			},
			code: "cell_manager_status_unavailable",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			entry := cellTestEntry(model.ManagedServiceV2Profile{})
			entry.DesiredState = "retired"
			setup := cellTestSetup(entry)
			entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			seedReadyProfile(t, store, setup)
			seedCellProject(t, store, entry, "/home/agent/projects/cell")
			seedCellLaunch(t, store, entry)

			interrupted := "interrupted"
			runtime := &cellTestRuntime{result: cellTestResult("terminal", &interrupted, false, model.CellExecutionContractVersion)}
			testCase.configure(runtime, entry)
			reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
			if err := reconciler.reconcileCellService(context.Background(), entry); err == nil {
				t.Fatal("cancel without a proven manager identity returned success")
			}
			for _, action := range runtime.actions {
				if action == containers.ManagedSupervisorCell {
					t.Fatalf("adapter was called without a proven manager identity: %v", runtime.actions)
				}
			}
			if len(runtime.calls) != 0 {
				t.Fatalf("adapter was called without a proven manager identity: %#v", runtime.calls)
			}
			persisted, err := store.CellOperation(context.Background(), entry.OperationID)
			if err != nil || persisted == nil {
				t.Fatalf("fail-closed hold was not persisted: %#v %v", persisted, err)
			}
			if persisted.Report.ObservedState != "unknown" || persisted.Phase == "terminal" {
				t.Fatalf("fail-closed hold was reported terminal: %#v", persisted)
			}
			if persisted.Report.LastError == nil || persisted.Report.LastError.Code != testCase.code {
				t.Fatalf("fail-closed hold reason = %#v, want %q", persisted.Report.LastError, testCase.code)
			}
		})
	}
}

// TestReconcileCellCancelUsesRecordedManagerAcrossProfileRevision proves the
// manager identity is scoped by sandbox/instance, not by the manifest's current
// profile digest: the supervisor state records the profile the child was
// actually launched under, and a later profile revision must not block
// cancellation of that older child.
func TestReconcileCellCancelUsesRecordedManagerAcrossProfileRevision(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	entry.DesiredState = "retired"
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{
		SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: 2,
		ProfileDigest: "sha256:" + strings.Repeat("b", 64),
	}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedCellProject(t, store, entry, "/home/agent/projects/cell")
	seedCellLaunch(t, store, entry)

	interrupted := "interrupted"
	runtime := &cellTestRuntime{started: true, result: cellTestResult("terminal", &interrupted, false, model.CellExecutionContractVersion)}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if err := reconciler.reconcileCellService(context.Background(), entry); err != nil {
		t.Fatalf("profile revision blocked cancellation of the older child: %v", err)
	}
	if len(runtime.calls) != 1 || runtime.calls[0].Action != "cancel" ||
		runtime.calls[0].ParentSessionID != "ses_manager0001" {
		t.Fatalf("cancel did not use the recorded manager identity: %#v", runtime.calls)
	}
	persisted, err := store.CellOperation(context.Background(), entry.OperationID)
	if err != nil || persisted == nil || persisted.Report.ObservedState != "cancelled" {
		t.Fatalf("quiescence was not reported: %#v %v", persisted, err)
	}
}

func TestReconcileCellServiceTransportRetryDoesNotChangeReportedAttempt(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	entry.Attempt = 4
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)
	seedCellProject(t, store, entry, "/home/agent/projects/cell")

	// Each reconcile loses the transport outcome, advancing the LOCAL retry
	// counter while the authoritative execution attempt stays immutable.
	runtime := &cellTestRuntime{err: errors.New("lost adapter response")}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	for pass := int64(1); pass <= 2; pass++ {
		if err := reconciler.reconcileCellService(context.Background(), entry); err == nil {
			t.Fatalf("transport-lost reconcile %d returned success", pass)
		}
		persisted, err := store.CellOperation(context.Background(), entry.OperationID)
		if err != nil || persisted == nil {
			t.Fatalf("cell operation missing after pass %d: %v", pass, err)
		}
		if persisted.Report.Attempt != entry.Attempt {
			t.Fatalf("pass %d reported attempt %d, want authoritative %d", pass, persisted.Report.Attempt, entry.Attempt)
		}
		if persisted.Attempt != pass {
			t.Fatalf("pass %d local retry counter = %d, want %d", pass, persisted.Attempt, pass)
		}
	}
	for _, call := range runtime.calls {
		if call.Attempt != entry.Attempt {
			t.Fatalf("adapter call carried attempt %d, want authoritative %d", call.Attempt, entry.Attempt)
		}
	}
}

// cellTestWorkspaces is the trusted workspace-anchor seam for the materialize
// journey: Ensure returns a disposable anchor without touching a real sandbox.
type cellTestWorkspaces struct {
	anchor string
	calls  int
}

func (w *cellTestWorkspaces) Ensure(context.Context, string, int) (string, error) {
	w.calls++
	return w.anchor, nil
}

func (w *cellTestWorkspaces) Destroy(context.Context, string) error { return nil }

func TestReconcileCellServiceMaterializesOrdinaryWorkspaceBeforePrompt(t *testing.T) {
	entry := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(entry)
	entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedReadyProfile(t, store, setup)
	// No project is pre-registered: the Runtime must materialize and register
	// the exact ordinary-directory binding from the manifest's workspace
	// contract BEFORE it fetches a prompt or admits the child. It must create no
	// repository/Git metadata and use no legacy Team workspace path.
	anchor := t.TempDir()
	workspaces := &cellTestWorkspaces{anchor: anchor}
	outcome := "succeeded"
	runtime := &cellTestRuntime{result: cellTestResult("terminal", &outcome, false, model.CellExecutionContractVersion)}
	runtime.onCall = func() {
		if workspaces.calls != 1 {
			t.Errorf("workspace binding was not materialized before the adapter effect: %d", workspaces.calls)
		}
	}
	reconciler := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	reconciler.Workspaces = workspaces
	reconciler.ServerID = "srv_celltest0001"
	reconciler.ManagedCatalog = &workspacecatalog.Catalog{State: store}

	if err := reconciler.reconcileCellService(context.Background(), entry); err != nil {
		t.Fatalf("cell reconcile failed: %v", err)
	}
	wantHostRoot := filepath.Join(anchor, "projects", entry.Workspace.ProjectID)
	if info, err := os.Stat(wantHostRoot); err != nil || !info.IsDir() {
		t.Fatalf("ordinary cell workspace directory was not materialized: %v", err)
	}
	wantContainerRoot := "/home/agent/projects/" + entry.Workspace.ProjectID
	if len(runtime.calls) != 1 || runtime.calls[0].WorktreeDir != wantContainerRoot {
		t.Fatalf("adapter call did not use the materialized ordinary workspace: %#v", runtime.calls)
	}
	projects, err := store.ManagedProjects(context.Background())
	if err != nil || len(projects) != 1 ||
		projects[0].Report.SelectionID != entry.Workspace.SelectionID ||
		projects[0].Report.ProjectID != entry.Workspace.ProjectID ||
		projects[0].Report.WorkspaceEpoch != entry.Workspace.WorkspaceEpoch ||
		projects[0].Report.SandboxGeneration != entry.SandboxGeneration ||
		projects[0].Report.RootAttestation == entry.Workspace.RootAttestation ||
		projects[0].ScopeRevision != entry.Workspace.ScopeRevision {
		t.Fatalf("cell workspace binding was not registered from the manifest contract: %#v %v", projects, err)
	}
	// The root must be the ACTUAL attested root (filesystem device/inode/mount),
	// not the manifest's caller-supplied digest.
	if !setupReceiptDigestPattern.MatchString(projects[0].Report.RootAttestation) {
		t.Fatalf("cell workspace root is not an attested sha256 digest: %#v", projects[0].Report.RootAttestation)
	}
}

// V3 lifecycle regression uses the real Runtime journal/reconciler boundary.
// The supervisor/control transports here are component doubles, not native proof.
func cellV3TestEntry(t *testing.T) model.CellServiceV3 {
	t.Helper()
	v2 := cellTestEntry(model.ManagedServiceV2Profile{})
	setup := cellTestSetup(v2)
	v2.Profile = model.ManagedServiceV2Profile{SetupOperationID: setup.ID, ProfileID: setup.ProfileID, ProfileRevision: setup.ProfileRevision, ProfileDigest: setup.ProfileDigest}
	var entry model.CellServiceV3
	if err := json.Unmarshal([]byte(mustJSON(t, v2)), &entry); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(entry.LaunchOperationID))
	entry.NativeSessionID = "ses_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	entry.FormatVersion, entry.LifecyclePhase = 3, "prepare"
	entry.PreparationID, entry.ControllerID = "prep_cell0001", "ctl_cell0001"
	entry.ControllerRevision, entry.AuthorityRevision = 1, 1
	entry.ParentIdentity = model.CellParentIdentityV3{PacketID: "packet_cell0001", PacketRevision: 1}
	entry.RequestDigest = strings.Repeat("a", 64)
	entry.CredentialBinding = model.CellCredentialBindingV3{ConnectionID: "conn_cell0001", ConnectionRevision: 1, ProviderID: "openai", AuthMode: "api_key"}
	return entry
}

func cellV3TestReceipt(t *testing.T, entry model.CellServiceV3) model.PreparedReceipt {
	t.Helper()
	return cellV3TestReceiptWithCredentials(t, entry, "cred_cell0001", "native_cell0001")
}

func cellV3TestReceiptWithCredentials(t *testing.T, entry model.CellServiceV3, credentialID, nativeCredentialID string) model.PreparedReceipt {
	t.Helper()
	tuple, err := entry.PreparedTuple()
	if err != nil {
		t.Fatal(err)
	}
	receipt := model.PreparedReceipt{FormatVersion: 3, PreparedTuple: tuple, CredentialID: credentialID, NativeCredentialID: nativeCredentialID}
	digest := func(value any) string {
		sum := sha256.Sum256([]byte(mustJSON(t, value)))
		return fmt.Sprintf("sha256:%x", sum)
	}
	receipt.BindingDigest = digest(map[string]any{"preparedTuple": jsonMap(t, tuple), "credentialId": receipt.CredentialID, "nativeCredentialId": receipt.NativeCredentialID})
	receipt.PreparedReceiptDigest = digest(map[string]any{"preparedTuple": jsonMap(t, tuple), "credentialId": receipt.CredentialID, "nativeCredentialId": receipt.NativeCredentialID, "bindingDigest": receipt.BindingDigest})
	if err := receipt.ValidateFor(entry); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func jsonMap(t *testing.T, value any) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal([]byte(mustJSON(t, value)), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func cellV3TestExecute(t *testing.T, entry model.CellServiceV3, receipt model.PreparedReceipt) model.CellServiceV3 {
	t.Helper()
	entry.LifecyclePhase, entry.PreparedReceiptDigest = "execute", &receipt.PreparedReceiptDigest
	tuple := receipt.PreparedTuple
	digest := func(value any) string {
		sum := sha256.Sum256([]byte(mustJSON(t, value)))
		return fmt.Sprintf("sha256:%x", sum)
	}
	entry.ExecutionGrant = &model.CellExecutionGrantV3{GrantID: "grant_cell0001", OperationID: entry.LaunchOperationID, SessionID: entry.NativeSessionID, InputID: "msg_" + strings.TrimPrefix(entry.NativeSessionID, "ses_"), ControllerID: entry.ControllerID, ControllerRevision: entry.ControllerRevision, AuthorityRevision: entry.AuthorityRevision, Attempt: entry.Attempt, Fence: entry.Fence, PacketID: entry.ParentIdentity.PacketID, PacketRevision: entry.ParentIdentity.PacketRevision, ConfigDigest: entry.ConfigDigest, ProfileDigest: entry.Profile.ProfileDigest, WorkspaceDigest: tuple.WorkspaceDigest, CredentialBindingDigest: digest(jsonMap(t, entry.CredentialBinding)), PreparedReceiptDigest: receipt.PreparedReceiptDigest, ExpiresAt: "2026-10-09T12:30:00Z"}
	return entry
}

type cellV3TestControl struct {
	cellTestControl
	reports         int
	reportErr       error
	lease           api.CellCredentialResult
	leaseErrors     []error
	leaseErr        error
	credentialCalls int
	reported        []model.CellPreparationReport
	onReport        func()
}

func (c *cellV3TestControl) CellCredential(context.Context, string) (api.CellCredentialResult, error) {
	c.credentialCalls++
	if c.leaseErr != nil {
		return api.CellCredentialResult{}, c.leaseErr
	}
	if len(c.leaseErrors) > 0 {
		err := c.leaseErrors[0]
		c.leaseErrors = c.leaseErrors[1:]
		if err != nil {
			return api.CellCredentialResult{}, err
		}
	}
	return c.lease, nil
}
func (c *cellV3TestControl) ReportCellPreparation(_ context.Context, report model.CellPreparationReport) (model.CellPreparationView, error) {
	c.reports++
	c.reported = append(c.reported, report)
	if c.onReport != nil {
		c.onReport()
	}
	receipt := report.PreparedReceipt
	tuple := receipt.PreparedTuple
	encoded, _ := json.Marshal(jsonMapForCellBinding(tuple.CredentialBinding))
	sum := sha256.Sum256(encoded)
	return model.CellPreparationView{PreparationID: report.PreparationID, TargetKind: "cell_session", LifecyclePhase: "prepare", State: "prepared", OperationID: tuple.OperationID, SandboxGeneration: tuple.SandboxGeneration, ControllerID: tuple.ControllerID, ControllerRevision: tuple.ControllerRevision, AuthorityRevision: tuple.AuthorityRevision, WorkspaceDigest: tuple.WorkspaceDigest, CredentialBindingDigest: fmt.Sprintf("sha256:%x", sum), PreparedReceiptDigest: receipt.PreparedReceiptDigest, CredentialID: receipt.CredentialID, NativeCredentialID: receipt.NativeCredentialID}, c.reportErr
}

func jsonMapForCellBinding(binding model.CellCredentialBindingV3) map[string]any {
	return map[string]any{"connectionId": binding.ConnectionID, "connectionRevision": binding.ConnectionRevision, "providerId": binding.ProviderID, "authMode": binding.AuthMode}
}

func TestCellV3ReplayRejectsMaterialDriftBeforeEffectOrOldReport(t *testing.T) {
	for _, phase := range []string{"pending", "prepared", "reported"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			entry := cellV3TestEntry(t)
			if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
				t.Fatal(err)
			}
			if phase != "pending" {
				receipt := cellV3TestReceipt(t, entry)
				if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: phase, Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
					t.Fatal(err)
				}
			}
			drift := entry
			drift.CredentialBinding.ConnectionRevision++
			runtime := &cellTestRuntime{}
			control := &cellV3TestControl{}
			r := newCellReconciler(t, store, control, runtime)
			if err := r.reconcileCellServiceV3Prepare(ctx, drift); !errors.Is(err, state.ErrCellV3OperationConflict) {
				t.Fatalf("material drift did not fail at pre-effect journal boundary: %v", err)
			}
			if runtime.startCalls != 0 || len(runtime.calls) != 0 || control.reports != 0 {
				t.Fatalf("drift caused effects/report: starts=%d calls=%d reports=%d", runtime.startCalls, len(runtime.calls), control.reports)
			}
		})
	}
}

type deniedCellQualificationRuntime struct {
	*cellTestRuntime
	reason        error
	verifications int
}

// Explicit SOURCE installed/native supplier. These flags select the production
// reconciler family; they confer NO real installed, qualification or grant credit.
type productHTTPBoundaryRuntime struct {
	*deniedCellQualificationRuntime
}

func (*productHTTPBoundaryRuntime) NeedsCellProductControl(context.Context, model.Sandbox, model.CellServiceV3) (bool, error) {
	return true, nil
}
func (*productHTTPBoundaryRuntime) AdoptCellProductControl(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, model.ChildProductDelivery, []byte) (string, error) {
	return "", errors.New("unexpected adoption: signed product delivery absent")
}

type productHTTPBoundaryControl struct {
	*cellV3TestControl
	delivery api.Client
}

func (c productHTTPBoundaryControl) ChildProductControl(ctx context.Context, preparation string) (model.ChildProductDelivery, error) {
	return c.delivery.ChildProductControl(ctx, preparation)
}

func TestCellV3ProductJoinsFixedNodeHTTPAndDoesNotReportThroughQualification(t *testing.T) {
	ctx := context.Background()
	entry := cellV3TestEntry(t)
	selected := qualification.RealModel
	entry.Authority.ModelID = &selected
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration,
		ObservedGeneration: entry.SandboxGeneration, ObservedState: "running", ImageDigest: "explicitly-synthetic-installed-supplier"}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		if req.Method != http.MethodGet || req.URL.Path != "/internal/runtime/workspace-workflow/child-preparations/"+entry.PreparationID+"/product-control" ||
			req.URL.RawQuery != "" || req.Header.Get("Authorization") != "Bearer synthetic-node-only" || req.Header.Get("X-WarpMetal-Workflow-Lease") != "" || req.ContentLength > 0 {
			t.Error("PRODUCT request changed fixed node-only transport")
		}
		http.Error(w, "synthetic absent full product publication", http.StatusNotFound)
	}))
	defer server.Close()
	legacy := &deniedCellQualificationRuntime{cellTestRuntime: &cellTestRuntime{}, reason: errors.New("PRODUCT must not enter qualification1")}
	runtime := &productHTTPBoundaryRuntime{legacy}
	control := productHTTPBoundaryControl{cellV3TestControl: &cellV3TestControl{}, delivery: api.Client{Origin: server.URL, NodeToken: "synthetic-node-only", HTTP: server.Client()}}
	r := newCellReconciler(t, store, control, runtime)
	manifest := model.Manifest{CellEntriesV3: []model.CellServiceV3{entry}}
	_, failed := r.reconcileCellServicesV3(ctx, manifest)
	if failed == nil || calls != 1 {
		t.Fatalf("joined node control boundary not reached once: calls=%d error=%v", calls, failed)
	}
	if legacy.verifications != 0 || runtime.startCalls != 0 || len(runtime.calls) != 0 || control.reports != 0 {
		t.Fatal("absent PRODUCT caused legacy/effect/report fallback")
	}
	// Direct report callers have no independently current manifest. A retained
	// synthetic native receipt cannot waive that current PRODUCT gate.
	receipt := cellV3TestReceipt(t, entry)
	if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "prepared", Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	local, err := store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		t.Fatal(err)
	}
	failed = r.reportCellV3Preparation(ctx, *local)
	if failed == nil || !strings.Contains(failed.Error(), "independently observed current manifest") || legacy.verifications != 0 || control.reports != 0 {
		t.Fatalf("PRODUCT report re-entered qualification or bypassed current authority: %v, legacy=%d reports=%d", failed, legacy.verifications, control.reports)
	}
	t.Log("joined SOURCE: one actual local TLS GET; absent full PRODUCT publication holds before effects; all installed/native/qualification facts synthetic")
}

func (*deniedCellQualificationRuntime) CellQualificationEnabled() bool { return true }
func (r *deniedCellQualificationRuntime) VerifyCellQualification(context.Context, model.Sandbox, model.CellServiceV3, string) (string, string, error) {
	r.verifications++
	return "", "", r.reason
}

// Named rule not diagnosable by the isolated Podman journey: the real Runtime
// prepared/reported replay branches must never bypass the admission verifier.
// Only the verifier transport is doubled; journal, replay and report are real.
func TestCellV3QualificationDenialGuardsPreparedAndReportedReplay(t *testing.T) {
	for _, phase := range []string{"prepared", "reported"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			entry := cellV3TestEntry(t)
			control := &cellV3TestControl{}
			runtime := &cellTestRuntime{}
			r := newCellReconciler(t, store, control, runtime)
			if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ObservedGeneration: entry.SandboxGeneration, ObservedState: "running", ImageDigest: "component-only-image"}); err != nil {
				t.Fatal(err)
			}
			if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
				t.Fatal(err)
			}
			if err := store.PutCellV3NativeContext(ctx, entry, "ses_parent", "/home/agent/projects/component"); err != nil {
				t.Fatal(err)
			}
			receipt := cellV3TestReceipt(t, entry)
			local := state.LocalCellV3Operation{Entry: entry, Phase: phase, Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}
			if err := store.UpdateCellV3Operation(ctx, local); err != nil {
				t.Fatal(err)
			}
			denied := errors.New("fixture expired or revoked")
			guard := &deniedCellQualificationRuntime{cellTestRuntime: runtime, reason: denied}
			r.ManagedRuntime = guard
			if err := r.reconcileCellServiceV3Prepare(ctx, entry); !errors.Is(err, denied) {
				t.Fatalf("fast replay bypassed fixture denial: %v", err)
			}
			persisted, err := store.CellV3Operation(ctx, entry.PreparationID)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.reportCellV3Preparation(ctx, *persisted); !errors.Is(err, denied) {
				t.Fatalf("direct report bypassed fixture denial: %v", err)
			}
			if guard.verifications != 2 || control.reports != 0 || runtime.startCalls != 0 || len(runtime.calls) != 0 {
				t.Fatal("denied fixture caused effect/report")
			}
		})
	}
}

func TestCellV3ExecuteUsesAcceptedReceiptAndPersistsGrantBeforeEffect(t *testing.T) {
	if os.Getenv("WARPMETAL_CHILD_REVIEWER_SOURCE_BOUNDARY") == "1" {
		t.Run("prepared_reviewer_own_reads_before_dispatch", testCellV3PreparedReviewerOwnReadsBeforeDispatch)
	}
	if os.Getenv("WARPMETAL_CHILD_INTEGRATION_DELIVERY_BOUNDARY") == "1" {
		t.Run("published_integrator_source_before_dispatch", testCellV3PublishedIntegratorSourceBeforeDispatch)
	}
	if os.Getenv("WARPMETAL_CHILD_WORKER_SOURCE_BOUNDARY") == "1" {
		t.Run("published_worker_source_before_dispatch", testCellV3PublishedWorkerSourceBeforeDispatch)
	}
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entry := cellV3TestEntry(t)
	receipt := cellV3TestReceipt(t, entry)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCellV3NativeContext(ctx, entry, "ses_manager0001", "/home/agent/projects/cell"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "reported", Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	entry = cellV3TestExecute(t, entry, receipt)
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: 1, ObservedGeneration: 1, ObservedState: "running"}); err != nil {
		t.Fatal(err)
	}
	seedReadyProfile(t, store, cellTestSetup(cellV2View(entry)))
	seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
	runtime := &cellTestRuntime{started: true}
	outcome := "succeeded"
	result := managedCellResultV1{SchemaVersion: 1, Status: "applied", RuntimeContractVersion: model.CellExecutionContractVersion, OperationID: entry.LaunchOperationID, SessionID: entry.NativeSessionID, MessageID: entry.ExecutionGrant.InputID, State: "terminal", Outcome: &outcome, Attempt: entry.Attempt}
	// Admission evidence is part of the V3 result, rather than mock readiness.
	resultMap := jsonMap(t, result)
	resultMap["guardReceipt"] = map[string]any{"formatVersion": 1, "sessionID": entry.NativeSessionID, "inboxID": entry.ExecutionGrant.InputID, "guardID": entry.ExecutionGrant.GrantID, "bindingDigest": receipt.BindingDigest, "state": "delivered", "admittedAt": 1, "availableAt": 2, "settledAt": nil, "refusalCode": nil, "logCursor": 2}
	runtime.result = []byte(mustJSON(t, resultMap))
	runtime.onCall = func() {
		values, err := store.CellV3Operations(ctx)
		if err != nil || len(values) != 1 || values[0].Entry.ExecutionGrant == nil {
			t.Errorf("authorized grant not durable before effect: %#v %v", values, err)
		}
	}
	r := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if _, fatal := r.reconcileCellServicesV3(ctx, model.Manifest{CellEntriesV3: []model.CellServiceV3{entry}}); fatal != nil {
		t.Fatal(fatal)
	}
	if len(runtime.calls) != 1 || runtime.calls[0].Action != "execute" {
		t.Fatalf("execute manifest was skipped or fell back to unguarded launch: %#v", runtime.calls)
	}
	var call managedCellExecuteCallV3
	if err := json.Unmarshal(runtime.payloads[0], &call); err != nil {
		t.Fatal(err)
	}
	if call.PreparedReceipt == nil || !reflect.DeepEqual(*call.PreparedReceipt, receipt) || !reflect.DeepEqual(call.ExecutionGrant, entry.ExecutionGrant) ||
		call.Model.ProviderID != receipt.PreparedTuple.Authority.ProviderID || call.Model.ID != receipt.PreparedTuple.Authority.ModelID {
		t.Fatalf("execute caller changed receipt/grant/model authority: %#v", call)
	}
	r.setCurrentAuthority(model.Manifest{CellEntriesV3: []model.CellServiceV3{entry}})
	report, err := r.Report(ctx, "srv_celltest", "0.1.47")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.CellServices) != 1 || report.CellServices[0].ObservedState != "ready" {
		t.Fatalf("V3 execution did not reach existing cell report boundary: %#v", report.CellServices)
	}
}

func TestCellV3PreparedRevocationDoesNotReleaseBeforeNativeQuiescence(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entry := cellV3TestEntry(t)
	receipt := cellV3TestReceipt(t, entry)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCellV3NativeContext(ctx, entry, "ses_manager0001", "/home/agent/projects/cell"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "reported", Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	entry.DesiredState = "retired"
	entry.DesiredRevision++
	entry.ActionRevision++
	runtime := &cellTestRuntime{err: errors.New("lost native cancel acknowledgement")}
	r := newCellReconciler(t, store, &cellTestControl{}, runtime)
	if err := r.reconcileCellServiceV3Prepare(ctx, entry); err == nil {
		t.Fatal("lost cancellation acknowledgement returned success")
	}
	if len(runtime.calls) != 1 || runtime.calls[0].Action != "cancel" {
		t.Fatalf("prepared revocation skipped native cancel: %#v", runtime.calls)
	}
	local, err := store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		t.Fatal(err)
	}
	if local.ControlReport.ObservedState != "unknown" {
		t.Fatalf("lost cancellation released prepared work: %#v", local)
	}
	if execution, err := store.CellV3Execution(ctx, entry.PreparationID); err != nil || execution != nil {
		t.Fatalf("cancellation minted execution authority: %#v %v", execution, err)
	}
	result := map[string]any{"schemaVersion": 1, "status": "applied", "runtimeContractVersion": model.CellExecutionContractVersion, "operationId": entry.LaunchOperationID, "sessionId": entry.NativeSessionID, "messageId": "msg_" + strings.TrimPrefix(entry.NativeSessionID, "ses_"), "state": "terminal", "attempt": entry.Attempt, "outcome": "interrupted", "exhausted": false, "interrupted": true, "receiptDigest": "", "error": "", "preparedReceipt": receipt}
	runtime.err = nil
	runtime.result = []byte(mustJSON(t, result))
	if err := r.reconcileCellServiceV3Prepare(ctx, entry); err != nil {
		t.Fatal(err)
	}
	r.setCurrentAuthority(model.Manifest{CellEntriesV3: []model.CellServiceV3{entry}})
	report, err := r.Report(ctx, "srv_celltest", "0.1.47")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.CellServices) != 1 || report.CellServices[0].FormatVersion != 3 || report.CellServices[0].ObservedState != "cancelled" {
		t.Fatalf("quiescent revocation did not reach V3 STATE report: %#v", report.CellServices)
	}
	if err := r.reconcileCellServiceV3Prepare(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if len(runtime.calls) != 2 {
		t.Fatal("cancel receipt replay repeated a settled native effect")
	}
}

type cellV3PrepareRuntime struct {
	cellTestRuntime
	t           *testing.T
	entry       model.CellServiceV3
	prepares    int
	credentials int
	payloads    [][]byte
}

func (runtime *cellV3PrepareRuntime) ExecManagedSupervisor(ctx context.Context, sandbox string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	if action == containers.ManagedSupervisorCredential {
		runtime.credentials++
	}
	if action != containers.ManagedSupervisorPrepare {
		return runtime.cellTestRuntime.ExecManagedSupervisor(ctx, sandbox, action, payload)
	}
	runtime.prepares++
	runtime.payloads = append(runtime.payloads, append([]byte(nil), payload...))
	local, err := runtime.store.CellV3Operation(ctx, runtime.entry.PreparationID)
	if err != nil || local == nil || local.ParentSessionID != "ses_manager0001" {
		runtime.t.Fatalf("prepare context not durable before effect: %#v %v", local, err)
	}
	var call managedCellPrepareCallV1
	if err := json.Unmarshal(payload, &call); err != nil {
		return nil, nil, err
	}
	if err := model.ValidateCellCredentialMaterial(call.Material, call.Provider, call.AuthMode); err != nil {
		return nil, nil, err
	}
	expectedTuple, err := runtime.entry.PreparedTuple()
	if err != nil {
		return nil, nil, err
	}
	if !reflect.DeepEqual(call.PreparedTuple, expectedTuple) || call.Model.ProviderID != expectedTuple.Authority.ProviderID ||
		call.Model.ID != expectedTuple.Authority.ModelID || call.AuthMode != expectedTuple.Authority.AuthMode {
		runtime.t.Fatalf("prepare caller changed prepared authority: %#v", call)
	}
	receipt := cellV3TestReceipt(runtime.t, runtime.entry)
	return []byte(mustJSON(runtime.t, managedCellPrepareResultV1{SchemaVersion: 1, Command: "prepare", Status: "prepared", Ready: true, SandboxID: runtime.entry.SandboxID, Instance: runtime.entry.Instance, ProfileDigest: runtime.entry.Profile.ProfileDigest, PreparedReceipt: &receipt})), nil, nil
}

// R-WP110-2: the credential round-trip returned 200 while the Runtime's
// per-request client timeout had already expired, so the pass discarded its own
// successful lease and stayed pending at credential_lease. The pass must retry
// the idempotent fetch and consume the eventual 200, then persist/report the
// prepared receipt. A definitive 4xx authority refusal stays final.
func TestCellV3CredentialLeaseConsumesSuccessAfterTransportTimeout(t *testing.T) {
	oldDelay := cellCredentialRetryDelay
	cellCredentialRetryDelay = time.Millisecond
	t.Cleanup(func() { cellCredentialRetryDelay = oldDelay })
	entry := cellV3TestEntry(t)
	lease := api.CellCredentialResult{CredentialID: "cred_cell0001", ConnectionID: entry.CredentialBinding.ConnectionID, ConnectionRevision: 1, Material: json.RawMessage(`{"type":"key","key":"synthetic-protected-key"}`)}
	for _, testCase := range []struct {
		name      string
		first     error
		wantCalls int
		wantReady bool
	}{
		{name: "client timeout then 200", first: fmt.Errorf("control-plane request failed: %w", context.DeadlineExceeded), wantCalls: 2, wantReady: true},
		{name: "transient 503 then 200", first: &api.ResponseError{Status: http.StatusServiceUnavailable, Code: "cell_credential_unavailable"}, wantCalls: 2, wantReady: true},
		{name: "definitive 403 is final", first: &api.ResponseError{Status: http.StatusForbidden, Code: "cell_credential_denied"}, wantCalls: 1, wantReady: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: 1, ObservedGeneration: 1, ObservedState: "running"}); err != nil {
				t.Fatal(err)
			}
			seedReadyProfile(t, store, cellTestSetup(cellV2View(entry)))
			seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
			control := &cellV3TestControl{cellTestControl: cellTestControl{instruction: cellInstruction(t)}, lease: lease, leaseErrors: []error{testCase.first}}
			runtime := &cellV3PrepareRuntime{cellTestRuntime: cellTestRuntime{store: store}, t: t, entry: entry}
			r := newCellReconciler(t, store, control, runtime)
			prepareErr := r.reconcileCellServiceV3Prepare(ctx, entry)
			local, err := store.CellV3Operation(ctx, entry.PreparationID)
			if err != nil {
				t.Fatal(err)
			}
			if control.credentialCalls != testCase.wantCalls {
				t.Fatalf("credential fetch calls = %d, want %d", control.credentialCalls, testCase.wantCalls)
			}
			if testCase.wantReady {
				if prepareErr != nil {
					t.Fatalf("consumed 200 did not advance the preparation: %v", prepareErr)
				}
				if local == nil || local.Phase != "reported" || local.ErrorCode != "" || runtime.prepares != 1 || control.reports != 1 {
					t.Fatalf("preparation did not advance to prepared/reported: %#v prepares=%d reports=%d", local, runtime.prepares, control.reports)
				}
				return
			}
			if prepareErr == nil || local == nil || local.Phase != "pending" || local.ErrorCode != "credential_lease" {
				t.Fatalf("definitive refusal was retried or advanced: err=%v local=%#v", prepareErr, local)
			}
		})
	}
}

// Only the protected native observer is a SOURCE supplier. The normal prepare
// journal, backend acknowledgement ordering and restart replay remain real.
type qualificationHeaderReplayRuntime struct {
	*cellV3PrepareRuntime
	headers int
}

func (s *qualificationHeaderReplayRuntime) CaptureCellQualificationAuthorization(ctx context.Context, _ model.Sandbox, entry model.CellServiceV3, receipt model.PreparedReceipt, _ string) error {
	local, err := s.store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "reported" || !reflect.DeepEqual(local.Receipt, receipt) {
		return errors.New("header observed before durable backend receipt acknowledgement")
	}
	s.headers++
	if s.headers == 1 {
		return errors.New("SOURCE protected header observer unavailable")
	}
	return nil
}

func TestCellV3PreparationReceiptPersistsBeforeLostBackendAckAndReplaysAfterRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	entry := cellV3TestEntry(t)
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: 1, ObservedGeneration: 1, ObservedState: "running"}); err != nil {
		t.Fatal(err)
	}
	seedReadyProfile(t, store, cellTestSetup(cellV2View(entry)))
	seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
	control := &cellV3TestControl{cellTestControl: cellTestControl{instruction: cellInstruction(t)}, lease: api.CellCredentialResult{CredentialID: "cred_cell0001", ConnectionID: entry.CredentialBinding.ConnectionID, ConnectionRevision: 1, Material: json.RawMessage(`{"type":"key","key":"synthetic-protected-key"}`)}, reportErr: errors.New("backend committed receipt; acknowledgement lost")}
	control.onReport = func() {
		local, err := store.CellV3Operation(ctx, entry.PreparationID)
		if err != nil || local == nil || local.Phase != "prepared" || len(local.ReceiptJSON) == 0 {
			t.Errorf("receipt not durable before report: %#v %v", local, err)
		}
	}
	runtime := &qualificationHeaderReplayRuntime{cellV3PrepareRuntime: &cellV3PrepareRuntime{cellTestRuntime: cellTestRuntime{store: store}, t: t, entry: entry}}
	r := newCellReconciler(t, store, control, runtime)
	if err := r.reconcileCellServiceV3Prepare(ctx, entry); err == nil {
		t.Fatal("lost backend ack was accepted")
	}
	local, err := store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(local.ReceiptJSON, []byte("synthetic-protected-key")) || bytes.Contains([]byte(mustJSON(t, local.Entry)), []byte("synthetic-protected-key")) {
		t.Fatal("protected material was journaled")
	}
	if runtime.prepares != 1 || runtime.credentials != 0 || len(runtime.calls) != 0 || runtime.headers != 0 {
		t.Fatal("prepare used a credential activation or prompt fallback")
	}
	// R-WP28-1 on the V3 prepare path: the product launch sequence binds the
	// manager from the V3 manifest authority before the native server starts and
	// before the adapter prepares the child.
	if runtime.startCalls != 1 || len(runtime.rebindRequests) != 1 {
		t.Fatalf("V3 manager binding before start: starts=%d rebinds=%d", runtime.startCalls, len(runtime.rebindRequests))
	}
	rebind := runtime.rebindRequests[0]
	if rebind["provider"] != "openai" || rebind["model"] != "gpt-6-astra" || rebind["authMode"] != "api_key" {
		t.Fatalf("V3 manager binding changed the manifest authority: %#v", rebind)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	control.reportErr = nil
	control.onReport = nil
	runtime.store = store
	r.Store = store
	if err := r.reconcileCellServiceV3Prepare(ctx, entry); err == nil || runtime.headers != 1 {
		t.Fatalf("acknowledged receipt did not reach protected header observer: %v calls=%d", err, runtime.headers)
	}
	if err := r.reconcileCellServiceV3Prepare(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if runtime.headers != 2 || runtime.prepares != 1 || len(control.reported) != 3 || !bytes.Equal([]byte(mustJSON(t, control.reported[0])), []byte(mustJSON(t, control.reported[1]))) || !reflect.DeepEqual(control.reported[1], control.reported[2]) {
		t.Fatal("restart changed receipt or repeated credential preparation")
	}
}

func TestCellV3HoldAndRevocationUsePinnedGrantAndRetainUnknownEffects(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entry := cellV3TestEntry(t)
	receipt := cellV3TestReceipt(t, entry)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCellV3NativeContext(ctx, entry, "ses_manager0001", "/home/agent/projects/cell"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "reported", Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	entry = cellV3TestExecute(t, entry, receipt)
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: 1, ObservedGeneration: 1, ObservedState: "running"}); err != nil {
		t.Fatal(err)
	}
	seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
	result := func(childState, guardState string, outcome *string, interrupted bool) []byte {
		return []byte(mustJSON(t, managedCellExecuteResultV3{managedCellResultV1: managedCellResultV1{SchemaVersion: 1, Status: "applied", RuntimeContractVersion: model.CellExecutionContractVersion, OperationID: entry.LaunchOperationID, SessionID: entry.NativeSessionID, MessageID: entry.ExecutionGrant.InputID, State: childState, Outcome: outcome, Attempt: entry.Attempt, Interrupted: interrupted}, GuardReceipt: &cellGuardReceipt{FormatVersion: 1, SessionID: entry.NativeSessionID, InboxID: entry.ExecutionGrant.InputID, GuardID: entry.ExecutionGrant.GrantID, BindingDigest: receipt.BindingDigest, State: guardState}}))
	}
	runtime := &cellTestRuntime{result: result("pending", "admitted", nil, false)}
	source := &sourceCellTerminalTestRuntime{cellTestRuntime: runtime}
	r := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, source)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCellV3Execution(ctx, entry, state.LocalCellV3Execution{PreparationID: entry.PreparationID, Grant: *entry.ExecutionGrant, Phase: "pending", ParentSessionID: "ses_manager0001", WorktreeDir: "/home/agent/projects/cell"}); err != nil {
		t.Fatal(err)
	}
	if err := r.reconcileCellServiceV3Execute(ctx, entry); err != nil {
		t.Fatal(err)
	}
	execution, err := store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || execution.Phase != "admitted" {
		t.Fatalf("native admission was not journaled: %#v %v", execution, err)
	}
	entry.DesiredState = "paused"
	entry.DesiredRevision++
	entry.ActionRevision++
	runtime.result = result("running", "delivered", nil, true)
	if err := r.reconcileCellServiceV3Execute(ctx, entry); err != nil {
		t.Fatal(err)
	}
	execution, err = store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || execution.Phase != "unknown" || execution.Report.ObservedState != "unknown" {
		t.Fatalf("hold released unresolved writer: %#v %v", execution, err)
	}
	// Native stop/quiescence is not backend terminal-release authority. The
	// current backend settles cancellation only for retired service authority.
	entry.DesiredState = "stopped"
	entry.DesiredRevision++
	entry.ActionRevision++
	stoppedOutcome := "interrupted"
	runtime.result = result("terminal", "delivered", &stoppedOutcome, true)
	if err := r.reconcileCellServiceV3Execute(ctx, entry); err != nil {
		t.Fatal(err)
	}
	execution, err = store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || execution.Phase != "unknown" || execution.Report.ObservedState != "unknown" || execution.Report.Child == nil || execution.Report.Child.State != "terminal" {
		t.Fatalf("stopped authority falsely released writer or lost quiescence evidence: %#v %v", execution, err)
	}
	entry.DesiredState = "retired"
	entry.DesiredRevision++
	entry.ActionRevision++
	runtime.err = errors.New("lost interrupt outcome")
	source.failBefore = true
	if err := r.reconcileCellServiceV3Execute(ctx, entry); err == nil {
		t.Fatal("lost interrupt returned success")
	}
	if reason, err := r.sandboxActiveWorkReason(ctx, entry.SandboxID); err != nil || reason == "" {
		t.Fatalf("unknown cancellation lost drain fence: %q %v", reason, err)
	}
	if len(runtime.calls) != 4 {
		t.Fatal("SOURCE capture failure inhibited the actual interrupt", len(runtime.calls))
	}
	source.failBefore = false
	outcome := "interrupted"
	runtime.err = nil
	runtime.result = result("terminal", "delivered", &outcome, true)
	if err := r.reconcileCellServiceV3Execute(ctx, entry); err != nil {
		t.Fatal(err)
	}
	execution, err = store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || execution.Phase != "terminal" || execution.Report.ObservedState != "cancelled" {
		t.Fatalf("exact quiescence was not recorded: %#v %v", execution, err)
	}
	for _, call := range runtime.calls[1:] {
		if call.Action != "cancel" || call.ParentSessionID != "ses_manager0001" {
			t.Fatalf("hold/revoke used unguarded or wrong-parent effect: %#v", call)
		}
	}
	if len(source.before) != 4 || len(source.after) != 4 {
		t.Fatal("normal cancellation did not own pre/post terminal capture", source.before, source.after)
	}
	for i, index := range source.before {
		if source.after[i] != index+1 {
			t.Fatal("pre-cancel capture did not bracket native effect", source.before, source.after)
		}
	}
}

// Detached SOURCE consumer; native effects still pass through the existing
// normal v3 cancellation journey. Capture refusal cannot inhibit interruption.
type sourceCellTerminalTestRuntime struct {
	*cellTestRuntime
	before, after []int
	failBefore    bool
}

func (r *sourceCellTerminalTestRuntime) SourceTerminalBeforeCancel(context.Context, string) error {
	r.before = append(r.before, len(r.calls))
	if r.failBefore {
		return errors.New("SOURCE pre-cancel capture unavailable")
	}
	return nil
}
func (r *sourceCellTerminalTestRuntime) SourceTerminalComplete(context.Context, string) error {
	r.after = append(r.after, len(r.calls))
	return nil
}

func TestCellV3ExecuteNeverRematerializesMissingPreparedWorkspace(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entry := cellV3TestEntry(t)
	receipt := cellV3TestReceipt(t, entry)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCellV3NativeContext(ctx, entry, "ses_manager0001", "/home/agent/projects/"+entry.Workspace.ProjectID); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "reported", Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	entry = cellV3TestExecute(t, entry, receipt)
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: 1, ObservedGeneration: 1, ObservedState: "running", Resources: model.Resources{WorkspaceDiskGiB: 10}}); err != nil {
		t.Fatal(err)
	}
	runtime := &cellTestRuntime{}
	control := &cellTestControl{instruction: cellInstruction(t)}
	r := newCellReconciler(t, store, control, runtime)
	workspaces := &cellTestWorkspaces{anchor: t.TempDir()}
	r.Workspaces = workspaces
	r.ManagedCatalog = &workspacecatalog.Catalog{State: store}
	r.ServerID = "srv_celltest0001"
	if err := r.reconcileCellServiceV3Execute(ctx, entry); err == nil {
		t.Fatal("missing prepared workspace was accepted")
	}
	if workspaces.calls != 0 || len(runtime.calls) != 0 || len(control.fetch) != 0 {
		t.Fatalf("missing prepared workspace caused rematerialization/fetch/admission: workspace=%d native=%d fetch=%d", workspaces.calls, len(runtime.calls), len(control.fetch))
	}
}

func TestCellV3PrepareRejectsLegacyOrCaseFoldedMaterialBeforeAdoption(t *testing.T) {
	for _, material := range []json.RawMessage{nil, json.RawMessage(`{"type":"key","key":"synthetic-protected-key","KEY":"different-key"}`)} {
		t.Run(string(material), func(t *testing.T) {
			ctx := context.Background()
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			entry := cellV3TestEntry(t)
			if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: 1, ObservedGeneration: 1, ObservedState: "running"}); err != nil {
				t.Fatal(err)
			}
			seedReadyProfile(t, store, cellTestSetup(cellV2View(entry)))
			seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
			control := &cellV3TestControl{cellTestControl: cellTestControl{instruction: cellInstruction(t)}, lease: api.CellCredentialResult{CredentialID: "cred_cell0001", APIKey: "legacy-key-not-v3-material", ConnectionID: entry.CredentialBinding.ConnectionID, ConnectionRevision: 1, Material: material}}
			runtime := &cellV3PrepareRuntime{cellTestRuntime: cellTestRuntime{store: store}, t: t, entry: entry}
			r := newCellReconciler(t, store, control, runtime)
			if err := r.reconcileCellServiceV3Prepare(ctx, entry); err == nil {
				t.Fatal("invalid V3 material was adopted")
			}
			if runtime.prepares != 0 || control.reports != 0 {
				t.Fatal("invalid V3 material reached adoption/report")
			}
		})
	}
}

func TestCellV3PendingPreparationCancelRetainsUnknownAndStillInterrupts(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entry := cellV3TestEntry(t)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCellV3NativeContext(ctx, entry, "ses_manager0001", "/home/agent/projects/cell"); err != nil {
		t.Fatal(err)
	}
	entry.DesiredState = "retired"
	entry.DesiredRevision++
	entry.ActionRevision++
	runtime := &cellTestRuntime{err: errors.New("native preparation/cancel outcome unknown")}
	r := newCellReconciler(t, store, &cellTestControl{}, runtime)
	if err := r.reconcileCellServiceV3Prepare(ctx, entry); err == nil {
		t.Fatal("pending preparation cancel silently succeeded")
	}
	if len(runtime.calls) != 1 || runtime.calls[0].Action != "cancel" {
		t.Fatal("pending preparation skipped native interrupt")
	}
	local, err := store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local.ControlReport.ObservedState != "unknown" {
		t.Fatalf("pending preparation lost unknown hold: %#v %v", local, err)
	}
}

func TestCellV3UnexpectedInterruptedInputDoesNotReleaseWriter(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entry := cellV3TestEntry(t)
	receipt := cellV3TestReceipt(t, entry)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCellV3NativeContext(ctx, entry, "ses_manager0001", "/home/agent/projects/cell"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "reported", Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	entry = cellV3TestExecute(t, entry, receipt)
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: 1, ObservedGeneration: 1, ObservedState: "running"}); err != nil {
		t.Fatal(err)
	}
	seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
	outcome := "interrupted"
	result := managedCellExecuteResultV3{managedCellResultV1: managedCellResultV1{SchemaVersion: 1, Status: "applied", RuntimeContractVersion: model.CellExecutionContractVersion, OperationID: entry.LaunchOperationID, SessionID: entry.NativeSessionID, MessageID: entry.ExecutionGrant.InputID, State: "terminal", Outcome: &outcome, Attempt: entry.Attempt}, GuardReceipt: &cellGuardReceipt{FormatVersion: 1, SessionID: entry.NativeSessionID, InboxID: entry.ExecutionGrant.InputID, GuardID: entry.ExecutionGrant.GrantID, BindingDigest: receipt.BindingDigest, State: "delivered"}}
	runtime := &cellTestRuntime{result: []byte(mustJSON(t, result))}
	r := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	if err := r.reconcileCellServiceV3Execute(ctx, entry); err != nil {
		t.Fatal(err)
	}
	execution, err := store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || execution.Phase != "unknown" || execution.Report.ObservedState != "unknown" {
		t.Fatalf("unexpected interruption became ordinary completion: %#v %v", execution, err)
	}
}

// R-WP108-1 regression. A V3 preparation whose managed child is never created
// must name the refusing predicate in bounded form instead of leaving the
// durable row at phase=pending/attempt=0 with an empty error code. The in-cell
// supervisor exits non-zero and writes its own safe receipt; the Runtime has to
// surface that closed reason (or, with no receipt, a bounded diagnostic line)
// and persist it, while still failing closed: no unbound native start, no
// adapter effect and no backend report.
func TestCellV3PrepareRecordsBoundedChildCreationBlocker(t *testing.T) {
	cases := []struct {
		name       string
		receipt    []byte
		diagnostic []byte
		code       string
		message    string
	}{
		{
			name:    "supervisor receipt reason",
			receipt: []byte(`{"schemaVersion":1,"command":"rebind","status":"failed","applied":false,"error":"install_not_ready"}`),
			code:    "native_server:install_not_ready",
			message: "receipt status=failed error=install_not_ready",
		},
		{
			name:       "supervisor stderr without a receipt",
			diagnostic: []byte("warpmetal_capability_launcher_capset_failed\n"),
			code:       "native_server",
			message:    "diagnostic: warpmetal_capability_launcher_capset_failed",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			entry := cellV3TestEntry(t)
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration,
				ObservedGeneration: entry.SandboxGeneration, ObservedState: "running"}); err != nil {
				t.Fatal(err)
			}
			seedReadyProfile(t, store, cellTestSetup(cellV2View(entry)))
			seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
			runtime := &cellTestRuntime{
				rebindErr:        errors.New("exit status 1"),
				rebindReceipt:    testCase.receipt,
				rebindDiagnostic: testCase.diagnostic,
			}
			control := &cellV3TestControl{cellTestControl: cellTestControl{instruction: cellInstruction(t)}}
			r := newCellReconciler(t, store, control, runtime)
			_, blocked := r.reconcileCellServicesV3(ctx, model.Manifest{CellEntriesV3: []model.CellServiceV3{entry}})
			if blocked == nil {
				t.Fatal("refused managed-child creation was accepted")
			}
			if !strings.Contains(blocked.Error(), testCase.message) {
				t.Fatalf("blocker did not name the refusing predicate: %v", blocked)
			}
			if runtime.startCalls != 0 || len(runtime.calls) != 0 || control.reports != 0 {
				t.Fatalf("refusal admitted a start/effect/report: starts=%d calls=%d reports=%d",
					runtime.startCalls, len(runtime.calls), control.reports)
			}
			local, err := store.CellV3Operation(ctx, entry.PreparationID)
			if err != nil {
				t.Fatal(err)
			}
			if local.Phase != "pending" || local.Attempt != 0 || local.PreparedReceiptDigest != "" {
				t.Fatalf("refusal changed the durable preparation: %#v", local)
			}
			if local.ErrorCode != testCase.code {
				t.Fatalf("persisted blocker = %q, want %q", local.ErrorCode, testCase.code)
			}
			// A replay of the identical refusal keeps the same bounded code and
			// never promotes the row: the diagnostic is durable, not a success.
			changed, err := store.SetCellV3PrepareBlocked(ctx, entry.PreparationID, testCase.code)
			if err != nil || changed {
				t.Fatalf("identical blocker churned the row: changed=%v err=%v", changed, err)
			}
			// Only the closed shape is accepted, so no prompt/secret/free text can
			// ever reach the durable diagnostic.
			for _, invalid := range []string{"", "Native Server", "native_server:Install Not Ready", strings.Repeat("a", 97)} {
				if _, err := store.SetCellV3PrepareBlocked(ctx, entry.PreparationID, invalid); !errors.Is(err, state.ErrCellV3OperationConflict) {
					t.Fatalf("invalid blocker %q was accepted: %v", invalid, err)
				}
			}
			// A prepared/reported row never accepts a pending blocker.
			receipt := cellV3TestReceipt(t, entry)
			if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "prepared", Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
				t.Fatal(err)
			}
			if changed, err := store.SetCellV3PrepareBlocked(ctx, entry.PreparationID, "report"); err != nil || changed {
				t.Fatalf("prepared row accepted a pending blocker: changed=%v err=%v", changed, err)
			}
			t.Log("bounded blocker names the refusing predicate; refusal stays pending/attempt 0 with no start, effect or report")
		})
	}
}

// R-WP108-1 regression, exact venue shape. A V3 fixture-candidate preparation is
// issued with sessionMode=lookup_only: the child attaches to the ALREADY-RUNNING
// controller-parent manager. The retained in-cell supervisor refuses every
// binding mutation on such an instance with `controller_activity_dependency_pending`,
// which is why the installed 0.1.52 never created the managed worker child. The
// preparation must prove the signed live manager session with a read-only status
// probe (never rebind/start) and let the trusted adapter create the child.
func TestCellV3ControllerParentPreparationProbesParentAndNeverRebinds(t *testing.T) {
	for _, role := range []string{"worker", "reviewer"} {
		t.Run(role, func(t *testing.T) { testCellV3ControllerParentPreparation(t, role) })
	}
}

func testCellV3ControllerParentPreparation(t *testing.T, role string) {
	t.Helper()
	ctx := context.Background()
	entry := cellV3TestEntry(t)
	entry.Role = role
	entry.SessionMode = "lookup_only"
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration,
		ObservedGeneration: entry.SandboxGeneration, ObservedState: "running"}); err != nil {
		t.Fatal(err)
	}
	seedReadyProfile(t, store, cellTestSetup(cellV2View(entry)))
	seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
	control := &cellV3TestControl{cellTestControl: cellTestControl{instruction: cellInstruction(t)}, lease: api.CellCredentialResult{
		CredentialID: "cred_cell0001", ConnectionID: entry.CredentialBinding.ConnectionID, ConnectionRevision: 1,
		Material: json.RawMessage(`{"type":"key","key":"synthetic-protected-key"}`)}}
	runtime := &cellV3PrepareRuntime{cellTestRuntime: cellTestRuntime{store: store, started: true,
		statusRoleReadback: map[string]any{"role": "manager", "nativeAgentId": "warpmetal-controller-manager",
			"sessionAgentId": "warpmetal-controller-manager", "parentSessionId": nil,
			"roleAgentDigest": cellTestDigest}}, t: t, entry: entry}
	r := newCellReconciler(t, store, control, runtime)
	if err := r.reconcileCellServiceV3PrepareCurrent(ctx, entry, nil); err != nil {
		t.Fatal(err)
	}
	if len(runtime.rebindRequests) != 0 || runtime.startCalls != 0 || len(runtime.startRequests) != 0 {
		t.Fatalf("lookup preparation mutated the controller parent: rebinds=%d starts=%d",
			len(runtime.rebindRequests), runtime.startCalls)
	}
	if len(runtime.statusRequests) != 1 || runtime.prepares != 1 || len(control.reported) != 1 {
		t.Fatalf("lookup preparation did not probe/adopt/report exactly once: status=%d prepares=%d reports=%d",
			len(runtime.statusRequests), runtime.prepares, len(control.reported))
	}
	if len(runtime.payloads) != 1 {
		t.Fatal("prepare payload not captured")
	}
	var call managedCellPrepareCallV1
	if err := json.Unmarshal(runtime.payloads[0], &call); err != nil {
		t.Fatal(err)
	}
	if call.ParentSessionID != "ses_manager0001" || call.Instance != entry.Instance || call.Action != "prepare" {
		t.Fatalf("prepare call did not bind the live controller-parent session: %#v", call)
	}
	local, err := store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || (local.Phase != "prepared" && local.Phase != "reported") || local.ErrorCode != "" || local.PreparedReceiptDigest == "" || len(local.ReceiptJSON) == 0 {
		t.Fatalf("lookup preparation did not persist its receipt: %#v %v", local, err)
	}
	t.Log("lookup V3 preparation probes the signed manager session, never rebinds/starts it, and persists the prepared receipt")
}

// The same branch fails closed before the adapter effect when the supervisor's
// signed role readback is not the preparation's manager role.
func TestCellV3ControllerParentPreparationRefusesNonManagerParent(t *testing.T) {
	ctx := context.Background()
	entry := cellV3TestEntry(t)
	entry.SessionMode = "lookup_only"
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration,
		ObservedGeneration: entry.SandboxGeneration, ObservedState: "running"}); err != nil {
		t.Fatal(err)
	}
	seedReadyProfile(t, store, cellTestSetup(cellV2View(entry)))
	seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
	control := &cellV3TestControl{cellTestControl: cellTestControl{instruction: cellInstruction(t)}}
	runtime := &cellV3PrepareRuntime{cellTestRuntime: cellTestRuntime{store: store, started: true,
		statusRoleReadback: map[string]any{"role": "orchestrator", "nativeAgentId": "warpmetal-controller-orchestrator"}}, t: t, entry: entry}
	r := newCellReconciler(t, store, control, runtime)
	if err := r.reconcileCellServiceV3PrepareCurrent(ctx, entry, nil); err == nil {
		t.Fatal("a non-manager role hosted the child")
	}
	if len(runtime.statusRequests) != 1 || len(runtime.rebindRequests) != 0 || runtime.startCalls != 0 || runtime.prepares != 0 || len(control.reported) != 0 {
		t.Fatal("refusal reached a binding mutation, the adapter or the backend")
	}
	local, err := store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local.Phase != "pending" || local.ErrorCode != "native_server" {
		t.Fatalf("refusal did not persist the bounded native_server code: %#v %v", local, err)
	}
}

// cellV3DeadlineTestControl records the explicit per-request transport deadline
// the idempotent lease fetch asks for, so a bounded test can prove the deadline
// is actually raised above the control-plane default (R-WP120-1).
type cellV3DeadlineTestControl struct {
	*cellV3TestControl
	timeouts []time.Duration
}

func (c *cellV3DeadlineTestControl) CellCredentialWithTimeout(ctx context.Context, serviceRegistrationID string, timeout time.Duration) (api.CellCredentialResult, error) {
	c.timeouts = append(c.timeouts, timeout)
	return c.cellV3TestControl.CellCredential(ctx, serviceRegistrationID)
}

// cellV3PrepareFixture builds the durable preconditions one V3 prepare needs and
// returns the reconciler plus the durable row accessor.
func cellV3PrepareFixture(t *testing.T, control ManagedServiceControl) (*Reconciler, *state.Store, model.CellServiceV3, api.CellCredentialResult) {
	t.Helper()
	entry := cellV3TestEntry(t)
	lease := api.CellCredentialResult{CredentialID: "cred_cell0001", ConnectionID: entry.CredentialBinding.ConnectionID, ConnectionRevision: 1, Material: json.RawMessage(`{"type":"key","key":"synthetic-protected-key"}`)}
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: 1, ObservedGeneration: 1, ObservedState: "running"}); err != nil {
		t.Fatal(err)
	}
	seedReadyProfile(t, store, cellTestSetup(cellV2View(entry)))
	seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
	runtime := &cellV3PrepareRuntime{cellTestRuntime: cellTestRuntime{store: store}, t: t, entry: entry}
	return newCellReconciler(t, store, control, runtime), store, entry, lease
}

// TestCellV3CredentialLeaseRetriesWithinBudgetBeyondFixedAttempts is the
// R-WP120-1 regression: the idempotent lease fetch is bounded by a wall-clock
// budget, not by three attempts, so a slow venue that answers on the fifth try
// still advances the preparation instead of persisting credential_lease.
func TestCellV3CredentialLeaseRetriesWithinBudgetBeyondFixedAttempts(t *testing.T) {
	oldDelay, oldMax := cellCredentialRetryDelay, cellCredentialRetryMaxDelay
	cellCredentialRetryDelay, cellCredentialRetryMaxDelay = time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { cellCredentialRetryDelay, cellCredentialRetryMaxDelay = oldDelay, oldMax })
	timeout := fmt.Errorf("control-plane request failed: %w", context.DeadlineExceeded)
	control := &cellV3TestControl{cellTestControl: cellTestControl{instruction: cellInstruction(t)}}
	r, store, entry, lease := cellV3PrepareFixture(t, control)
	control.lease = lease
	control.leaseErrors = []error{timeout, timeout, timeout, timeout}
	if err := r.reconcileCellServiceV3Prepare(context.Background(), entry); err != nil {
		t.Fatalf("budgeted retries did not consume the fifth-attempt lease: %v", err)
	}
	if control.credentialCalls != 5 {
		t.Fatalf("credential fetch calls = %d, want 5", control.credentialCalls)
	}
	local, err := store.CellV3Operation(context.Background(), entry.PreparationID)
	if err != nil {
		t.Fatal(err)
	}
	if local == nil || local.Phase != "reported" || local.ErrorCode != "" {
		t.Fatalf("preparation did not advance after budgeted retries: %#v", local)
	}
}

// TestCellV3CredentialLeaseRequestsExtendedTransportDeadline proves the fetch
// asks the control client for an explicit per-request deadline (60s) instead of
// inheriting the shorter control-plane default that aborted every attempt.
func TestCellV3CredentialLeaseRequestsExtendedTransportDeadline(t *testing.T) {
	control := &cellV3DeadlineTestControl{cellV3TestControl: &cellV3TestControl{cellTestControl: cellTestControl{instruction: cellInstruction(t)}}}
	r, _, entry, lease := cellV3PrepareFixture(t, control)
	control.lease = lease
	if err := r.reconcileCellServiceV3Prepare(context.Background(), entry); err != nil {
		t.Fatalf("prepare with the extended deadline failed: %v", err)
	}
	if len(control.timeouts) != 1 || control.timeouts[0] != cellCredentialAttemptTimeout {
		t.Fatalf("credential deadlines = %v, want one %s", control.timeouts, cellCredentialAttemptTimeout)
	}
	if cellCredentialAttemptTimeout <= 30*time.Second {
		t.Fatalf("attempt timeout %s does not exceed the control-plane default", cellCredentialAttemptTimeout)
	}
}

// cellV3ClientTimeoutError reproduces the measured control-plane failure: a
// net.Error timeout raised by the HTTP client, not a context refusal.
type cellV3ClientTimeoutError struct{}

func (cellV3ClientTimeoutError) Error() string {
	return "control-plane request failed: context deadline exceeded (Client.Timeout exceeded while awaiting headers)"
}
func (cellV3ClientTimeoutError) Timeout() bool   { return true }
func (cellV3ClientTimeoutError) Temporary() bool { return true }

// TestCellV3CredentialLeaseBudgetExhaustionFailsClosedBounded proves an
// unrecoverable lease keeps the fail-closed preparation row AND stays bounded:
// the number of attempts is capped and the error names the closed cause.
func TestCellV3CredentialLeaseBudgetExhaustionFailsClosedBounded(t *testing.T) {
	oldBudget, oldAttempt, oldDelay, oldMax := cellCredentialLeaseBudget, cellCredentialAttemptTimeout, cellCredentialRetryDelay, cellCredentialRetryMaxDelay
	cellCredentialLeaseBudget, cellCredentialAttemptTimeout = 150*time.Millisecond, 20*time.Millisecond
	cellCredentialRetryDelay, cellCredentialRetryMaxDelay = 5*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() {
		cellCredentialLeaseBudget, cellCredentialAttemptTimeout = oldBudget, oldAttempt
		cellCredentialRetryDelay, cellCredentialRetryMaxDelay = oldDelay, oldMax
	})
	control := &cellV3TestControl{cellTestControl: cellTestControl{instruction: cellInstruction(t)}}
	r, store, entry, _ := cellV3PrepareFixture(t, control)
	control.leaseErrors = nil
	// The exact measured production class: the control-plane client aborted the
	// request while awaiting response headers (R-WP120-1).
	control.leaseErr = cellV3ClientTimeoutError{}
	err := r.reconcileCellServiceV3Prepare(context.Background(), entry)
	if err == nil || !strings.Contains(err.Error(), "credential lease unavailable") {
		t.Fatalf("exhausted budget did not fail closed with a bounded cause: %v", err)
	}
	if !strings.Contains(err.Error(), "cause=transport_timeout") {
		t.Fatalf("bounded cause token missing from %v", err)
	}
	if control.credentialCalls < 2 || control.credentialCalls > cellCredentialMaxAttempts {
		t.Fatalf("attempt count %d is not bounded", control.credentialCalls)
	}
	local, lookupErr := store.CellV3Operation(context.Background(), entry.PreparationID)
	if lookupErr != nil {
		t.Fatal(lookupErr)
	}
	if local == nil || local.Phase != "pending" || local.ErrorCode != "credential_lease" {
		t.Fatalf("fail-closed row changed shape: %#v", local)
	}
}

// R-WP121-1: an expired, never-consumed grant is a BOUNDED WAIT. Failing the
// whole reconcile suppressed the report as well and turned one expired grant
// into an unrecoverable conflict; the deferral must be named durably instead.
func TestCellV3ExecuteExpiredGrantDefersAsBoundedWait(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entry := cellV3TestEntry(t)
	receipt := cellV3TestReceipt(t, entry)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCellV3NativeContext(ctx, entry, "ses_manager0001", "/home/agent/projects/cell"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "reported", Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	entry = cellV3TestExecute(t, entry, receipt)
	// Fixed test clock is 2026-10-09T12:00Z: this grant expired before admission.
	entry.ExecutionGrant.ExpiresAt = "2026-10-09T11:00:00Z"
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: 1, ObservedGeneration: 1, ObservedState: "running"}); err != nil {
		t.Fatal(err)
	}
	seedReadyProfile(t, store, cellTestSetup(cellV2View(entry)))
	seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
	runtime := &cellTestRuntime{started: true}
	r := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	deferred, fatal := r.reconcileCellServicesV3(ctx, model.Manifest{CellEntriesV3: []model.CellServiceV3{entry}})
	if fatal != nil {
		t.Fatalf("expired grant failed the whole reconcile: %v", fatal)
	}
	if deferred == nil {
		t.Fatal("expired grant was not reported as a bounded deferral")
	}
	if len(runtime.calls) != 0 {
		t.Fatalf("expired grant admitted a native effect: %#v", runtime.calls)
	}
	value, err := store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || value == nil {
		t.Fatalf("preparation row missing: %v", err)
	}
	if value.ErrorCode != "deferred:grant_expired" {
		t.Fatalf("durable block code = %q, want deferred:grant_expired", value.ErrorCode)
	}
	if value.Phase != "reported" {
		t.Fatalf("deferral moved the preparation phase: %q", value.Phase)
	}
}

// R-WP119-1 at the Runtime boundary: a backend renewal (same accepted
// attempt/fence identity, distinct grant id, later expiry) is adoptable ONLY
// while no native effect was attempted. Every other grant change fails closed.
func TestCellV3GrantRenewalAdoptedOnlyBeforeAnyNativeEffect(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entry := cellV3TestEntry(t)
	receipt := cellV3TestReceipt(t, entry)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCellV3NativeContext(ctx, entry, "ses_manager0001", "/home/agent/projects/cell"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "reported", Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	original := cellV3TestExecute(t, entry, receipt)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: original, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	// A grant that moves the fence is never a renewal.
	moved := original
	movedGrant := *original.ExecutionGrant
	movedGrant.GrantID = "grant_cell0009"
	movedGrant.Fence = strings.Repeat("b", 64)
	movedGrant.ExpiresAt = "2026-10-09T13:00:00Z"
	moved.ExecutionGrant = &movedGrant
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: moved, Phase: "pending"}); !errors.Is(err, state.ErrCellV3OperationConflict) {
		t.Fatalf("fence-moving grant was not refused: %v", err)
	}
	// The bounded renewal is adoptable before any native effect.
	renewed := original
	renewedGrant := *original.ExecutionGrant
	renewedGrant.GrantID = "grant_cell0002"
	renewedGrant.ExpiresAt = "2026-10-09T13:00:00Z"
	renewed.ExecutionGrant = &renewedGrant
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: renewed, Phase: "pending"}); err != nil {
		t.Fatalf("bounded grant renewal was refused: %v", err)
	}
	// Once a native effect exists, a further grant change fails closed.
	if err := store.PutCellV3Execution(ctx, renewed, state.LocalCellV3Execution{PreparationID: renewed.PreparationID, Grant: renewedGrant, Phase: "admitted", ParentSessionID: "ses_manager0001", WorktreeDir: "/home/agent/projects/cell"}); err != nil {
		t.Fatal(err)
	}
	third := renewed
	thirdGrant := renewedGrant
	thirdGrant.GrantID = "grant_cell0003"
	thirdGrant.ExpiresAt = "2026-10-09T14:00:00Z"
	third.ExecutionGrant = &thirdGrant
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: third, Phase: "pending"}); !errors.Is(err, state.ErrCellV3OperationConflict) {
		t.Fatalf("grant changed after a native effect was not refused: %v", err)
	}
}

// R-WP121-1: a CLOSED in-cell refusal (the adapter's own bounded reason line and
// no receipt) proves the child was never admitted. It must stay `pending` and be
// named, so a renewed grant (R-WP119-1) can still be adopted; an unclassified
// failure keeps the unknown/ownership semantics.
func TestCellV3ExecuteInCellRefusalStaysPendingAndRenewable(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entry := cellV3TestEntry(t)
	receipt := cellV3TestReceipt(t, entry)
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCellV3NativeContext(ctx, entry, "ses_manager0001", "/home/agent/projects/cell"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "reported", Receipt: receipt, PreparedReceiptDigest: receipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	entry = cellV3TestExecute(t, entry, receipt)
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: 1, ObservedGeneration: 1, ObservedState: "running"}); err != nil {
		t.Fatal(err)
	}
	seedReadyProfile(t, store, cellTestSetup(cellV2View(entry)))
	seedCellProject(t, store, cellV2View(entry), "/home/agent/projects/cell")
	runtime := &cellTestRuntime{started: true, err: errors.New("exit status 1"), diagnostic: []byte("warpmetal_cell_adapter: V3 exact credential binding is missing or revoked\n")}
	r := newCellReconciler(t, store, &cellTestControl{instruction: cellInstruction(t)}, runtime)
	deferred, fatal := r.reconcileCellServicesV3(ctx, model.Manifest{CellEntriesV3: []model.CellServiceV3{entry}})
	if fatal != nil {
		t.Fatalf("a closed in-cell refusal failed the whole reconcile: %v", fatal)
	}
	if deferred == nil {
		t.Fatal("a closed in-cell refusal was not a bounded deferral")
	}
	execution, err := store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || execution == nil {
		t.Fatalf("execution row missing: %v", err)
	}
	if execution.Phase != "pending" {
		t.Fatalf("closed refusal persisted phase %q, want pending", execution.Phase)
	}
	value, err := store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || value == nil {
		t.Fatalf("preparation row missing: %v", err)
	}
	if value.ErrorCode != "deferred:effect_refused" {
		t.Fatalf("durable block code = %q, want deferred:effect_refused", value.ErrorCode)
	}
	// The bounded renewal is still adoptable after a definite non-admission.
	renewed := entry
	grant := *entry.ExecutionGrant
	grant.GrantID, grant.ExpiresAt = "grant_cell0031", "2026-10-09T13:30:00Z"
	renewed.ExecutionGrant = &grant
	if err := store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: renewed, Phase: "pending"}); err != nil {
		t.Fatalf("renewed grant refused after a closed refusal: %v", err)
	}
}

// R-WP121-1 (fail-closed detail): the adapter raises two refusals AT or AFTER the
// durable guard journal + native prompt. Those must NOT be reclassified as a
// provable non-admission, or the Runtime would drop the unknown/ownership record
// of an effect that may already have posted the first text.
func TestCellV3PostGuardRefusalsKeepUnknownOwnership(t *testing.T) {
	entry := cellV3TestEntry(t)
	receipt := cellV3TestReceipt(t, entry)
	entry = cellV3TestExecute(t, entry, receipt)
	for _, reason := range []string{
		"warpmetal_cell_adapter: V3 execution grant expired before admission\n",
		"warpmetal_cell_adapter: V3 guarded admission outcome is unknown\n",
	} {
		failure := &managedSupervisorActionFailure{Action: "cell", Err: errors.New("exit status 1"), Diagnostic: strings.TrimSpace(reason)}
		if cellV3RefusedBeforeAdmission(nil, failure) {
			t.Fatalf("post-guard refusal %q was treated as provable non-admission", reason)
		}
	}
	// A pre-admission refusal with no receipt IS provable.
	failure := &managedSupervisorActionFailure{Action: "cell", Err: errors.New("exit status 1"), Diagnostic: "warpmetal_cell_adapter: V3 exact credential binding is missing or revoked"}
	if !cellV3RefusedBeforeAdmission(nil, failure) {
		t.Fatal("pre-admission refusal was not classified")
	}
	// Any receipt bytes or unclassified failure keeps the unknown semantics.
	if cellV3RefusedBeforeAdmission([]byte("{}"), failure) {
		t.Fatal("a refusal with receipt bytes was classified as non-admission")
	}
	if cellV3RefusedBeforeAdmission(nil, errors.New("exit status 1")) {
		t.Fatal("an unclassified failure was classified as non-admission")
	}
}
