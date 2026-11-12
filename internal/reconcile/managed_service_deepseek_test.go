package reconcile

// DeepSeek/ACP managed-service start path. The OpenCode manager capability and
// wire behaviour stay pinned by the existing journeys; these tests cover only
// the DeepSeek supervisor's managed-service receipts (enroll -> rebind -> start
// -> status) and the explicit, plugin-free manager capability the Runtime
// derives from the already verified native/instruction/authority facts.
//
// TestDeepSeekManagedServiceStartResolvesCapabilityWithoutPlugin runs the real
// Runtime producer against receipts that mirror the shipped Sandbox supervisor
// (including its profileRevision default). TestDeepSeekManagedServiceActualSandboxReceipts
// hands the exact Runtime-emitted payloads to the unmodified Sandbox checkout
// named by WARP_METAL_SANDBOX_SOURCE and feeds the actual returned receipts
// through the same Runtime path.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// deepSeekManagerFixture derives the producer fixture into the DeepSeek/ACP
// managed-service manager: profileId deepseek, role manager and the pinned
// DeepSeek Flash api_key authority. The fixture intentionally keeps the
// profile revision at 2, the value the shipped supervisor can only echo when
// the Runtime actually sends it.
func deepSeekManagerFixture(t *testing.T) producerFixture {
	t.Helper()
	fixture := loadProducerFixture(t)
	flash := providerpolicy.Flash()
	modelID, authMode := flash.ModelID, flash.AuthMode
	fixture.ServiceManifest.Identity.Role = "manager"
	fixture.ServiceManifest.Profile = model.ManagedServiceProfileV1{
		SetupOperationID: fixture.SetupManifest.ID,
		ProfileID:        "deepseek",
		ProfileRevision:  2,
		ProfileDigest:    deepSeekPin("2"),
	}
	fixture.SetupManifest.ProfileID = "deepseek"
	fixture.SetupManifest.ProfileRevision = 2
	fixture.SetupManifest.ProfileDigest = deepSeekPin("2")
	fixture.SetupManifest.Materializer = model.SetupMaterializer{}
	fixture.ServiceManifest.Authority = &model.ManagedServiceAuthorityV1{
		TeamRevision: 17, ProviderID: flash.ProviderID, ModelID: &modelID, AuthMode: &authMode,
	}
	fixture.ServiceManifest.RuntimeContractVersion = ""
	return fixture
}

// deepSeekManagedControl answers the managed-service fetch with the fixture's
// enrollment and instruction tuples and exposes the test loopback endpoint.
type deepSeekManagedControl struct {
	*fakeManagedControl
	endpoint string
}

func (control *deepSeekManagedControl) ManagedServiceEndpoint() string {
	return control.endpoint
}

// deepSeekSupervisor receipts use closed, deterministic native identities so the
// start and status probes prove the same session/project/location.
const (
	deepSeekSessionID      = "ses_0123456789abcdef0123456789abcdef"
	deepSeekNativeProject  = "0123456789abcdef0123456789abcdef01234567"
	deepSeekManagedPort    = 18443
	deepSeekWorkerStatusOK = `{"schemaVersion":1,"command":"status","status":"ok","instance":"default","busy":false,"activeTask":null}`
)

func deepSeekNativeLocation() string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(deepSeekNativeProject)))
}

// deepSeekManagedRuntime is the closed managed-runtime boundary used by the
// journey. When receipts are supplied it returns those exact bytes (the actual
// Sandbox receipt contract); otherwise it synthesizes the shipped DeepSeek
// supervisor's managed-service responses, including its profileRevision
// default when the launch tuple omits the field.
type deepSeekManagedRuntime struct {
	fixture          producerFixture
	receipts         map[containers.ManagedSupervisorAction][]byte
	returned         map[containers.ManagedSupervisorAction][]byte
	invocations      []managedInvocation
	workerProfileIDs []string
}

func (runtime *deepSeekManagedRuntime) record(action containers.ManagedSupervisorAction, receipt []byte) {
	if runtime.returned == nil {
		runtime.returned = make(map[containers.ManagedSupervisorAction][]byte, 8)
	}
	runtime.returned[action] = append([]byte(nil), receipt...)
}

func (runtime *deepSeekManagedRuntime) ExecManagedSupervisor(_ context.Context, _ string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	runtime.invocations = append(runtime.invocations, managedInvocation{string(action), request})
	if receipt, ok := runtime.receipts[action]; ok {
		runtime.record(action, receipt)
		return append([]byte(nil), receipt...), nil, nil
	}
	identity := runtime.fixture.ServiceManifest.Identity
	instruction := runtime.fixture.InstructionResponse
	switch action {
	case containers.ManagedSupervisorEnroll:
		receipt, err := json.Marshal(map[string]any{
			"schemaVersion": 1, "command": "enroll", "profileId": "deepseek", "status": "enrolled",
			"instance": request["instance"], "sandboxId": request["sandboxId"], "stored": true,
			"leaseTokenPresent": true, "leaseRole": identity.Role, "leaseExpired": false,
			"generation": identity.SandboxGeneration,
		})
		runtime.record(action, receipt)
		return receipt, nil, err
	case containers.ManagedSupervisorRebind:
		receipt, err := json.Marshal(map[string]any{
			"schemaVersion": 1, "command": "rebind", "profileId": "deepseek", "status": "applied",
			"applied": true, "restarted": false, "instance": request["instance"], "sandboxId": request["sandboxId"],
			"profileDigest": request["profileDigest"], "bindingRevision": request["bindingRevision"],
			"binding": map[string]any{"provider": request["provider"], "model": request["model"], "authMode": request["authMode"]},
		})
		runtime.record(action, receipt)
		return receipt, nil, err
	case containers.ManagedSupervisorStart, containers.ManagedSupervisorRestart:
		// The shipped DeepSeek supervisor echoes an explicit profileRevision and
		// otherwise falls back to the image-pinned revision 1. A launch tuple that
		// omits it therefore cannot prove a revision-2 profile.
		profileRevision := int64(1)
		if value, ok := request["profileRevision"].(float64); ok {
			profileRevision = int64(value)
		}
		command := string(action)
		receipt, err := json.Marshal(map[string]any{
			"schemaVersion": 1, "command": command, "profileId": "deepseek",
			"status": "ready", "phase": "running", "ready": true,
			"instance": request["instance"], "sandboxId": request["sandboxId"],
			"profileDigest": request["profileDigest"], "profileRevision": profileRevision,
			"version": request["version"], "pid": 4242, "port": deepSeekManagedPort,
			"sessionId": deepSeekSessionID, "sessionMode": request["sessionMode"],
			"nativeProjectId": deepSeekNativeProject, "nativeLocationDigest": deepSeekNativeLocation(),
			"instructionRevision": instruction.InstructionRevision, "instructionDigest": instruction.InstructionDigest,
			"instructionApplied": true, "monitorEnabled": request["monitorEnabled"] == true,
			"nativeRoleReadback": nil,
		})
		runtime.record(action, receipt)
		return receipt, nil, err
	case containers.ManagedSupervisorStatus:
		receipt, err := json.Marshal(map[string]any{
			"schemaVersion": 1, "command": "status", "profileId": "deepseek",
			"status": "running", "phase": "running", "ready": true,
			"instance": request["instance"], "sandboxId": request["sandboxId"],
			"profileDigest": request["profileDigest"], "profileRevision": runtime.fixture.ServiceManifest.Profile.ProfileRevision,
			"sessionId": deepSeekSessionID, "nativeProjectId": deepSeekNativeProject,
			"nativeLocationDigest": deepSeekNativeLocation(),
			"instructionRevision":  instruction.InstructionRevision, "instructionDigest": instruction.InstructionDigest,
			"instructionApplied": true,
		})
		runtime.record(action, receipt)
		return receipt, nil, err
	case containers.ManagedSupervisorRegisterSource:
		receipt, diagnostic, err := deepSeekManagedRegistrationReceipt(request)
		if err == nil {
			runtime.record(action, receipt)
		}
		return receipt, diagnostic, err
	default:
		return nil, nil, fmt.Errorf("%s is not supported by the DeepSeek managed-service contract", action)
	}
}

// deepSeekManagedRegistrationReceipt is the managed-service registration
// acknowledgement. It is explicitly a separate contract from the controller-
// parent register-source v2 envelope the DeepSeek controller owns.
func deepSeekManagedRegistrationReceipt(request map[string]any) ([]byte, []byte, error) {
	registration, _ := request["registration"].(map[string]any)
	identity, _ := registration["identity"].(map[string]any)
	source, _ := registration["source"].(map[string]any)
	receipt, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "command": "register-source", "status": "registered", "ready": false,
		"instance": request["instance"], "sandboxId": request["sandboxId"], "profileId": request["profileId"],
		"serviceRegistrationId": identity["serviceRegistrationId"], "serviceGeneration": identity["serviceGeneration"],
		"registeredSourceId": source["registeredSourceId"], "workspaceEpoch": identity["workspaceEpoch"],
		"nativeSessionId": source["nativeSessionId"], "nativeProjectId": source["nativeProjectId"],
		"nativeLocationDigest": source["nativeLocationDigest"], "profileRevision": identity["profileRevision"],
		"profileDigest": identity["profileDigest"], "instructionRevision": identity["instructionRevision"],
		"instructionDigest": identity["instructionDigest"],
	})
	return receipt, nil, err
}

func (runtime *deepSeekManagedRuntime) ExecManagedWorker(_ context.Context, _ string, action containers.ManagedWorkerAction, profileID string, payload []byte) ([]byte, []byte, error) {
	runtime.workerProfileIDs = append(runtime.workerProfileIDs, profileID)
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	runtime.invocations = append(runtime.invocations, managedInvocation{string(action), request})
	if action != containers.ManagedWorkerStatus {
		return nil, nil, fmt.Errorf("%s is not supported by the DeepSeek managed-service contract", action)
	}
	return []byte(deepSeekWorkerStatusOK), nil, nil
}

func (runtime *deepSeekManagedRuntime) startInvocation(t *testing.T) managedInvocation {
	t.Helper()
	for _, invocation := range runtime.invocations {
		if invocation.action == string(containers.ManagedSupervisorStart) {
			return invocation
		}
	}
	t.Fatal("managed service never dispatched a start")
	return managedInvocation{}
}

// deepSeekManagedJourney is one seeded production managed-service boundary.
// The desired manifest is the exact value the reconciler consumes, so a caller
// can drive the identical Sandbox requests and lifecycle transitions.
type deepSeekManagedJourney struct {
	reconciler *Reconciler
	manifest   model.Manifest
	desired    model.ManagedServiceV1
	store      *state.Store
}

// newDeepSeekManagedJourney seeds one ready profile/project and builds the
// production reconciler for the DeepSeek manager.
func newDeepSeekManagedJourney(t *testing.T, fixture producerFixture, runtime *deepSeekManagedRuntime) *deepSeekManagedJourney {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedReadyProfile(t, store, fixture.SetupManifest)
	anchor := t.TempDir()
	fixedNow := func() time.Time { return time.Date(2026, 9, 27, 17, 0, 30, 0, time.UTC) }
	catalog := &workspacecatalog.Catalog{State: store, Now: fixedNow}
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
	control := &deepSeekManagedControl{fakeManagedControl: &fakeManagedControl{fixture: fixture}, endpoint: "https://api.warpmetal.example"}
	runtime.fixture = fixture
	reconciler := &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, Now: fixedNow}
	manifest := model.Manifest{
		ServerID: fixture.ServiceManifest.Identity.ServerID, DesiredRevision: fixture.ServiceManifest.DesiredRevision,
		ManagedServices: []model.ManagedServiceV1{fixture.ServiceManifest},
	}
	return &deepSeekManagedJourney{reconciler: reconciler, manifest: manifest, desired: fixture.ServiceManifest, store: store}
}

// reconcile runs one production managed-service reconciliation pass for the
// requested desired state and returns the durable row.
func (journey *deepSeekManagedJourney) reconcile(t *testing.T, desiredState string) *state.LocalManagedService {
	t.Helper()
	desired := journey.desired
	if desired.DesiredState != desiredState {
		// Every lifecycle intent the backend issues carries a fresh action
		// revision; the store refuses a same-revision manifest change.
		desired.DesiredState = desiredState
		desired.ActionRevision++
		desired.DesiredRevision++
	}
	journey.desired = desired
	journey.manifest.DesiredRevision = desired.DesiredRevision
	journey.manifest.ManagedServices = []model.ManagedServiceV1{desired}
	journey.reconciler.setCurrentAuthority(journey.manifest)
	if _, err := journey.reconciler.reconcileManagedServices(context.Background(), journey.manifest); err != nil {
		t.Fatalf("DeepSeek managed-service %s reconcile refused: %v", desiredState, err)
	}
	local, err := journey.store.ManagedService(context.Background(), desired.Identity.ServiceRegistrationID)
	if err != nil || local == nil {
		t.Fatalf("DeepSeek managed-service %s durable row = %#v, %v", desiredState, local, err)
	}
	return local
}

// runDeepSeekManagedServiceJourney seeds one ready profile/project and runs the
// production managed-service reconciliation for the DeepSeek manager.
func runDeepSeekManagedServiceJourney(t *testing.T, fixture producerFixture, runtime *deepSeekManagedRuntime) *state.Store {
	t.Helper()
	journey := newDeepSeekManagedJourney(t, fixture, runtime)
	local := journey.reconcile(t, "active")
	if local.Phase != "ready" || local.ErrorCode != "" ||
		local.Report.ObservedState != "ready" || local.Report.NativeRegistration == nil {
		t.Fatalf("DeepSeek managed-service durable report = %#v", local)
	}
	raw := runtime.returned[containers.ManagedSupervisorStart]
	var started managedSupervisorReceipt
	if len(raw) == 0 || decodeManagedSupervisorReceipt(raw, &started) != nil {
		t.Fatalf("DeepSeek managed-service start receipt = %s", raw)
	}
	if local.Report.NativeRegistration.NativeSessionID != started.SessionID ||
		local.Report.NativeRegistration.NativeProjectID != started.NativeProjectID ||
		local.Report.NativeRegistration.NativeLocationDigest != started.NativeLocationDigest {
		t.Fatalf("DeepSeek managed-service native registration = %#v, start = %#v", local.Report.NativeRegistration, started)
	}
	return journey.store
}

func TestDeepSeekManagedServiceStartResolvesCapabilityWithoutPlugin(t *testing.T) {
	fixture := deepSeekManagerFixture(t)
	runtime := &deepSeekManagedRuntime{}
	store := runDeepSeekManagedServiceJourney(t, fixture, runtime)

	// The DeepSeek supervisor addresses the launch by profile revision. Without
	// the exact tuple it defaults to revision 1, which cannot prove this
	// revision-2 profile and used to fail closed as invalid_start_receipt.
	start := runtime.startInvocation(t)
	if start.request["profileRevision"] != float64(2) {
		t.Fatalf("DeepSeek start request profileRevision = %#v", start.request["profileRevision"])
	}
	// The worker seam selects the DeepSeek worker from the same desired
	// profile; the OpenCode request bytes never carry this selector.
	if len(runtime.workerProfileIDs) != 1 || runtime.workerProfileIDs[0] != "deepseek" {
		t.Fatalf("DeepSeek worker boundary profiles = %#v", runtime.workerProfileIDs)
	}
	if start.request["profileId"] != "deepseek" || start.request["version"] != "" {
		t.Fatalf("DeepSeek start request = %#v", start.request)
	}
	// The OpenCode supervisor rejects unknown launch fields, so the same
	// composition must stay byte-identical for every other profile.
	openCode := managedLaunchComposition{ProfileID: "opencode", ProfileRevision: 4, Version: "2.0.14"}.request()
	if _, ok := openCode["profileRevision"]; ok {
		t.Fatalf("OpenCode launch tuple gained the deepseek-only profileRevision: %#v", openCode)
	}

	// No manager plugin exists for the DeepSeek supervisor. The capability is
	// derived from the verified receipts and is explicitly unavailable, so
	// every existing capability consumer still fails closed.
	capability, err := store.ManagerCapability(context.Background(), managedSourceID(fixture.ServiceManifest.Identity.ServiceRegistrationID))
	if err != nil || capability == nil {
		t.Fatalf("DeepSeek manager capability = %#v, %v", capability, err)
	}
	if capability.ManagerPluginDigest != "" || capability.ManagerProfile != (model.InsightsManagerProfileV1{}) ||
		len(capability.RecipeIDs) != 0 || capability.Available || capability.Reason != "" {
		t.Fatalf("DeepSeek manager capability claimed OpenCode plugin proof: %#v", capability)
	}
	if capability.Protocol != deepSeekManagerProtocol || capability.NativeProtocol != providerpolicy.Flash().Transport.Protocol ||
		capability.ProviderID != providerpolicy.Flash().ProviderID || capability.ModelID != providerpolicy.Flash().ModelID ||
		!setupReceiptDigestPattern.MatchString(capability.ProviderRouteDigest) {
		t.Fatalf("DeepSeek manager capability route = %#v", capability)
	}
	if capability.NativeSourceRevision != "" {
		t.Fatalf("DeepSeek manager capability claimed the OpenCode native source revision: %#v", capability)
	}

	// A DeepSeek receipt that claims an OpenCode plugin proof is never trusted.
	receipts := decodeDeepSeekJourneyReceipts(t, runtime)
	claimed := receipts.start
	claimed.ManagerPluginDigest = deepSeekPin("9")
	claimed.ManagerPluginLoaded = true
	if _, err := managedManagerCapability(fixture.ServiceManifest, "source_fixture", claimed, receipts.status); err == nil {
		t.Fatal("DeepSeek manager capability trusted an OpenCode plugin claim")
	}
	// A manipulated live instruction/native join is refused as well.
	mutated := receipts.status
	mutated.InstructionDigest = deepSeekPin("8")
	if _, err := managedManagerCapability(fixture.ServiceManifest, "source_fixture", receipts.start, mutated); err == nil {
		t.Fatal("DeepSeek manager capability accepted diverging ready receipts")
	}
}

type deepSeekJourneyReceipts struct {
	start  managedSupervisorReceipt
	status managedSupervisorReceipt
}

func decodeDeepSeekJourneyReceipts(t *testing.T, runtime *deepSeekManagedRuntime) deepSeekJourneyReceipts {
	t.Helper()
	var receipts deepSeekJourneyReceipts
	for action, target := range map[containers.ManagedSupervisorAction]*managedSupervisorReceipt{
		containers.ManagedSupervisorStart: &receipts.start, containers.ManagedSupervisorStatus: &receipts.status,
	} {
		raw := runtime.returned[action]
		if len(raw) == 0 || decodeManagedSupervisorReceipt(raw, target) != nil {
			t.Fatalf("journey %s receipt = %s", action, raw)
		}
	}
	return receipts
}

// TestDeepSeekManagedServiceActualSandboxReceipts runs the exact Runtime-emitted
// enroll/rebind/start/status payloads against the unmodified Sandbox checkout,
// requires every actual receipt to decode through the Runtime's closed decoder,
// and then feeds those actual receipts through the production managed-service
// journey.
func TestDeepSeekManagedServiceActualSandboxReceipts(t *testing.T) {
	sandbox := os.Getenv("WARP_METAL_SANDBOX_SOURCE")
	if sandbox == "" {
		t.Skip("WARP_METAL_SANDBOX_SOURCE is not set")
	}
	supervisor := filepath.Join(sandbox, "runner", "warpmetal_deepseek_supervisor.py")
	if _, err := os.Stat(supervisor); err != nil {
		t.Fatalf("Sandbox DeepSeek supervisor unavailable: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	if !deepSeekPortFree(deepSeekManagedPort) {
		t.Skip("managed DeepSeek contract port 18443 is busy")
	}
	t.Setenv("WM_FAKE_ACP_SESSIONS", filepath.Join(t.TempDir(), "fake-acp-sessions.log"))
	root := t.TempDir()
	projectRoot := filepath.Join(root, "project")
	if err := os.MkdirAll(projectRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(root, "fake-acp")
	if err := os.WriteFile(launcher, []byte(deepSeekFakeACPLauncher), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = deepSeekMakeWritable(root) })

	fixture := deepSeekManagerFixture(t)
	instruction := fixture.InstructionResponse

	// The managed enrollment exchange is a real signed loopback HTTPS exchange;
	// the Runtime's own closed request shape is what the Sandbox validates.
	enrollment := fixture.EnrollmentResponse
	enrollment.EnrollmentToken = "ten_" + strings.Repeat("a", 32)
	enrollment.EnrollmentExpiresAt = time.Now().UTC().Add(time.Minute)
	exchange := newDeepSeekEnrollmentExchange(t, fixture.ServiceManifest.Identity.Role)
	env := append(os.Environ(), "SSL_CERT_FILE="+exchange.certPath, "WM_FAKE_ACP_SESSIONS="+os.Getenv("WM_FAKE_ACP_SESSIONS"))

	// The production journey owns the catalog-resolved desired manifest. Drive
	// the Sandbox with exactly that value so every actual receipt is a byte the
	// production reconciliation accepts.
	runtime := &deepSeekManagedRuntime{}
	journey := newDeepSeekManagedJourney(t, fixture, runtime)
	desired := journey.desired
	if desired.Profile.ProfileID != "deepseek" {
		t.Fatalf("managed journey profile = %q", desired.Profile.ProfileID)
	}
	processInstance := model.ManagedServiceProcessInstance(desired.Identity.Instance, desired.Identity.ExpectedServiceGeneration)

	enrollRaw, enrollExit := runDeepSeekContractSupervisor(t, python, supervisor, root, launcher, env, containers.ManagedSupervisorEnroll,
		deepSeekMustJSON(t, managedEnrollmentRequest(desired, enrollment, processInstance, exchange.endpoint)))
	var enrolled managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(enrollRaw, &enrolled); err != nil {
		t.Fatalf("actual Sandbox enroll receipt refused by the Runtime decoder: %v\n%s", err, enrollRaw)
	}
	assertDeepSeekReceiptClosed(t, "enroll", enrollRaw)
	if enrollExit != 0 || enrolled.SchemaVersion != 1 || enrolled.Command != "enroll" ||
		(enrolled.Status != "enrolled" && enrolled.Status != "refreshed") ||
		!enrolled.Stored || !enrolled.LeaseTokenPresent || enrolled.LeaseExpired ||
		enrolled.LeaseRole != desired.Identity.Role || enrolled.Generation != desired.Identity.SandboxGeneration {
		t.Fatalf("actual Sandbox enroll receipt (exit %d) = %#v", enrollExit, enrolled)
	}
	if len(exchange.requests) != 1 || exchange.requests[0] != "/internal/runtime/agent-teams/enrollments/exchange" {
		t.Fatalf("actual Sandbox enrollment exchange requests = %#v", exchange.requests)
	}

	// Rebind runs through the production Runtime validation with the actual
	// Sandbox receipt.
	execRuntime := &deepSeekExecSupervisor{python: python, supervisor: supervisor, root: root, launcher: launcher, env: env}
	rebindRaw, err := (&Reconciler{ManagedRuntime: execRuntime}).rebindManagedServiceAuthority(context.Background(), desired)
	if err != nil {
		t.Fatalf("actual Sandbox rebind receipt refused by the Runtime: %v", err)
	}
	var rebound managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(rebindRaw, &rebound); err != nil {
		t.Fatalf("actual Sandbox rebind receipt refused by the Runtime decoder: %v", err)
	}
	assertDeepSeekReceiptClosed(t, "rebind", rebindRaw)
	if rebound.Command != "rebind" || rebound.Status != "applied" || !rebound.Applied || rebound.Restarted {
		t.Fatalf("actual Sandbox rebind receipt = %#v", rebound)
	}
	var binding struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
		AuthMode string `json:"authMode"`
	}
	if err := json.Unmarshal(rebound.Binding, &binding); err != nil || binding.Provider != providerpolicy.Flash().ProviderID ||
		binding.Model != providerpolicy.Flash().ModelID || binding.AuthMode != providerpolicy.Flash().AuthMode {
		t.Fatalf("actual Sandbox rebind binding = %s, %v", rebound.Binding, err)
	}

	stop := func() {
		_, _ = runDeepSeekContractSupervisor(t, python, supervisor, root, launcher, env, containers.ManagedSupervisorStop,
			deepSeekMustJSON(t, managedLifecycleRequest(desired)))
	}
	defer stop()

	// The Runtime launch tuple carries the exact profile revision; a receipt
	// that echoed the supervisor default could not prove this profile.
	startRequest := managedLaunchComposition{
		SandboxID: desired.Identity.SandboxID, Instance: desired.Identity.Instance,
		ProfileID: desired.Profile.ProfileID, ProfileDigest: desired.Profile.ProfileDigest,
		ProfileRevision: desired.Profile.ProfileRevision, Version: "",
		Port: deepSeekManagedPort, ProjectRoot: projectRoot, SessionMode: "create_initial",
		InstructionText: instruction.Content, InstructionDigest: instruction.InstructionDigest,
		InstructionRevision: instruction.InstructionRevision,
	}.request()
	startRaw, startExit := runDeepSeekContractSupervisor(t, python, supervisor, root, launcher, env, containers.ManagedSupervisorStart, deepSeekMustJSON(t, startRequest))
	var started managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(startRaw, &started); err != nil {
		t.Fatalf("actual Sandbox start receipt refused by the Runtime decoder: %v\n%s", err, startRaw)
	}
	assertDeepSeekReceiptClosed(t, "start", startRaw)
	if startExit != 0 || started.SchemaVersion != 1 || started.Command != "start" ||
		(started.Status != "ready" && started.Status != "already_running") || !started.Ready || started.Phase != "running" ||
		started.Instance != desired.Identity.Instance || started.SandboxID != desired.Identity.SandboxID ||
		started.ProfileID != "deepseek" || started.ProfileDigest != desired.Profile.ProfileDigest ||
		started.ProfileRevision != desired.Profile.ProfileRevision || started.Version != "" ||
		started.Port != deepSeekManagedPort || !managedNativeProjectPattern.MatchString(started.NativeProjectID) ||
		!setupReceiptDigestPattern.MatchString(started.NativeLocationDigest) || started.SessionID == "" ||
		started.InstructionRevision != instruction.InstructionRevision || started.InstructionDigest != instruction.InstructionDigest ||
		!started.InstructionApplied {
		t.Fatalf("actual Sandbox DeepSeek start receipt = %#v", started)
	}

	statusRaw, statusExit := runDeepSeekContractSupervisor(t, python, supervisor, root, launcher, env, containers.ManagedSupervisorStatus, deepSeekMustJSON(t, managedStatusRequest(desired)))
	var current managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(statusRaw, &current); err != nil {
		t.Fatalf("actual Sandbox status receipt refused by the Runtime decoder: %v\n%s", err, statusRaw)
	}
	assertDeepSeekReceiptClosed(t, "status", statusRaw)
	if statusExit != 0 || current.Command != "status" || current.Status != "running" || !current.Ready ||
		current.SessionID != started.SessionID || current.NativeProjectID != started.NativeProjectID ||
		current.NativeLocationDigest != started.NativeLocationDigest ||
		current.InstructionRevision != instruction.InstructionRevision || current.InstructionDigest != instruction.InstructionDigest ||
		!current.InstructionApplied {
		t.Fatalf("actual Sandbox DeepSeek status receipt = %#v", current)
	}

	// The managed-service source registration is the Runtime's closed
	// formatVersion 1 document, bound by the Sandbox to the running native
	// process and the live lease.
	registerRaw, registerExit := runDeepSeekContractSupervisor(t, python, supervisor, root, launcher, env, containers.ManagedSupervisorRegisterSource,
		deepSeekMustJSON(t, managedSourceRegistrationRequest(desired, managedSourceID(desired.Identity.ServiceRegistrationID), started, instruction)))
	var registered managedSourceRegistrationReceipt
	if err := decodeManagedReceipt(registerRaw, &registered, true); err != nil {
		t.Fatalf("actual Sandbox register-source receipt refused by the Runtime decoder: %v\n%s", err, registerRaw)
	}
	assertDeepSeekReceiptClosed(t, "register-source", registerRaw)
	if registerExit != 0 || registered.SchemaVersion != 1 || registered.Command != "register-source" ||
		(registered.Status != "registered" && registered.Status != "unchanged") || registered.Ready ||
		registered.Instance != desired.Identity.Instance || registered.SandboxID != desired.Identity.SandboxID ||
		registered.ProfileID != "deepseek" || registered.ServiceRegistrationID != desired.Identity.ServiceRegistrationID ||
		registered.ServiceGeneration != desired.Identity.ExpectedServiceGeneration ||
		registered.RegisteredSourceID != managedSourceID(desired.Identity.ServiceRegistrationID) ||
		registered.WorkspaceEpoch != desired.Workspace.WorkspaceEpoch ||
		registered.NativeSessionID != started.SessionID || registered.NativeProjectID != started.NativeProjectID ||
		registered.NativeLocationDigest != started.NativeLocationDigest ||
		registered.ProfileRevision != desired.Profile.ProfileRevision || registered.ProfileDigest != desired.Profile.ProfileDigest ||
		registered.InstructionRevision != instruction.InstructionRevision || registered.InstructionDigest != instruction.InstructionDigest {
		t.Fatalf("actual Sandbox register-source receipt = %#v", registered)
	}

	// Drain keeps the instance resumable; Stop removes it. Both flow through the
	// production inactive transition payload.
	drainRaw, drainExit := runDeepSeekContractSupervisor(t, python, supervisor, root, launcher, env, containers.ManagedSupervisorDrain, deepSeekMustJSON(t, managedLifecycleRequest(desired)))
	var drained managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(drainRaw, &drained); err != nil {
		t.Fatalf("actual Sandbox drain receipt refused by the Runtime decoder: %v\n%s", err, drainRaw)
	}
	assertDeepSeekReceiptClosed(t, "drain", drainRaw)
	if drainExit != 0 || drained.Command != "drain" || drained.Status != "drained" || drained.Ready || !drained.Drained {
		t.Fatalf("actual Sandbox drain receipt = %#v", drained)
	}
	stopRaw, stopExit := runDeepSeekContractSupervisor(t, python, supervisor, root, launcher, env, containers.ManagedSupervisorStop, deepSeekMustJSON(t, managedLifecycleRequest(desired)))
	var stopped managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(stopRaw, &stopped); err != nil {
		t.Fatalf("actual Sandbox stop receipt refused by the Runtime decoder: %v\n%s", err, stopRaw)
	}
	assertDeepSeekReceiptClosed(t, "stop", stopRaw)
	if stopExit != 0 || stopped.Command != "stop" || (stopped.Status != "stopped" && stopped.Status != "not_running") || stopped.Ready {
		t.Fatalf("actual Sandbox stop receipt = %#v", stopped)
	}

	// The actual receipts are exactly the bytes the production journey consumes.
	runtime.receipts = map[containers.ManagedSupervisorAction][]byte{
		containers.ManagedSupervisorEnroll:         enrollRaw,
		containers.ManagedSupervisorRebind:         rebindRaw,
		containers.ManagedSupervisorStart:          startRaw,
		containers.ManagedSupervisorStatus:         statusRaw,
		containers.ManagedSupervisorRegisterSource: registerRaw,
		containers.ManagedSupervisorDrain:          drainRaw,
		containers.ManagedSupervisorStop:           stopRaw,
	}
	local := journey.reconcile(t, "active")
	if local.Phase != "ready" || local.ErrorCode != "" || local.Report.ObservedState != "ready" ||
		local.Report.ProfileStatus != "ready" || local.Report.EnrollmentStatus != "ready" || local.Report.NativeRegistration == nil ||
		local.Report.NativeRegistration.NativeSessionID != started.SessionID ||
		local.Report.NativeRegistration.NativeProjectID != started.NativeProjectID ||
		local.Report.NativeRegistration.NativeLocationDigest != started.NativeLocationDigest {
		t.Fatalf("actual Sandbox DeepSeek durable ready report = %#v", local)
	}
	capability, err := journey.store.ManagerCapability(context.Background(), managedSourceID(desired.Identity.ServiceRegistrationID))
	if err != nil || capability == nil {
		t.Fatalf("DeepSeek manager capability = %#v, %v", capability, err)
	}
	if capability.ManagerPluginDigest != "" || capability.ManagerProfile != (model.InsightsManagerProfileV1{}) ||
		len(capability.RecipeIDs) != 0 || capability.Available || capability.Reason != "" ||
		capability.Protocol != deepSeekManagerProtocol ||
		capability.NativeProtocol != providerpolicy.Flash().Transport.Protocol ||
		capability.ProviderID != providerpolicy.Flash().ProviderID ||
		capability.ModelID != providerpolicy.Flash().ModelID ||
		!setupReceiptDigestPattern.MatchString(capability.ProviderRouteDigest) ||
		capability.NativeSourceRevision != "" {
		t.Fatalf("actual Sandbox DeepSeek manager capability = %#v", capability)
	}

	// The production inactive transitions consume the actual drain/stop receipts.
	if paused := journey.reconcile(t, "paused"); paused.Phase != "paused" || paused.ErrorCode != "" ||
		paused.Report.ObservedState != "paused" || paused.Report.WorkerStatus != "paused" {
		t.Fatalf("actual Sandbox DeepSeek paused report = %#v", paused)
	}
	if ended := journey.reconcile(t, "stopped"); ended.Phase != "stopped" || ended.ErrorCode != "" ||
		ended.Report.ObservedState != "stopped" || ended.Report.WorkerStatus != "stopped" {
		t.Fatalf("actual Sandbox DeepSeek stopped report = %#v", ended)
	}

	// A real receipt that omits the runtime-pinned profile revision is refused,
	// proving success above depended on the exact launch tuple.
	withoutRevision := make(map[string]any, len(startRequest))
	for key, value := range startRequest {
		withoutRevision[key] = value
	}
	delete(withoutRevision, "profileRevision")
	stop()
	legacyRaw, _ := runDeepSeekContractSupervisor(t, python, supervisor, root, launcher, env, containers.ManagedSupervisorStart, deepSeekMustJSON(t, withoutRevision))
	var legacy managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(legacyRaw, &legacy); err != nil {
		t.Fatalf("revision-less Sandbox start receipt did not decode: %v", err)
	}
	if legacy.ProfileRevision == desired.Profile.ProfileRevision {
		t.Fatalf("revision-less Sandbox start receipt unexpectedly proved the requested profile: %#v", legacy)
	}
}

// assertDeepSeekReceiptClosed proves the actual Sandbox receipt carries only
// fields the Runtime's closed managed-supervisor decoder accepts.
func assertDeepSeekReceiptClosed(t *testing.T, name string, raw []byte) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("%s receipt is not a JSON object: %v", name, err)
	}
	for field := range fields {
		if !managedSupervisorReceiptFields[field] {
			t.Fatalf("%s receipt has unknown field %q", name, field)
		}
	}
}

// deepSeekExecSupervisor runs the actual Sandbox supervisor for one managed
// supervisor action. It is only used for actions the shipped supervisor
// implements and expects an encoded receipt on success.
type deepSeekExecSupervisor struct {
	python, supervisor, root, launcher string
	env                                []string
}

func (runtime *deepSeekExecSupervisor) ExecManagedSupervisor(_ context.Context, _ string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	command := exec.Command(runtime.python, runtime.supervisor, string(action), "--root", runtime.root, "--launcher", runtime.launcher)
	command.Env = runtime.env
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("sandbox supervisor %s: %w: %s", action, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func (runtime *deepSeekExecSupervisor) ExecManagedWorker(context.Context, string, containers.ManagedWorkerAction, string, []byte) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("worker boundary is covered by the managed-service journey stub")
}

func runDeepSeekContractSupervisor(t *testing.T, python, supervisor, root, launcher string, env []string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, int) {
	t.Helper()
	command := exec.Command(python, supervisor, string(action), "--root", root, "--launcher", launcher)
	command.Env = env
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	lines := bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n"))
	if len(lines) == 0 || len(bytes.TrimSpace(lines[len(lines)-1])) == 0 {
		t.Fatalf("sandbox supervisor %s returned no receipt: %v %s", action, err, stderr.String())
	}
	exit := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			t.Fatalf("sandbox supervisor %s failed: %v %s", action, err, stderr.String())
		}
		exit = exitError.ExitCode()
	}
	return lines[len(lines)-1], exit
}

func deepSeekMustJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// deepSeekEnrollmentExchange is the signed loopback HTTPS exchange the Sandbox
// enrollment helper actually posts to. It answers the exact closed lease
// document the helper verifies.
type deepSeekEnrollmentExchange struct {
	endpoint string
	certPath string
	server   *httptest.Server
	requests []string
}

func newDeepSeekEnrollmentExchange(t *testing.T, role string) *deepSeekEnrollmentExchange {
	t.Helper()
	exchange := &deepSeekEnrollmentExchange{}
	exchange.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/internal/runtime/agent-teams/enrollments/exchange" {
			http.Error(writer, `{"error":{"code":"enrollment_rejected"}}`, http.StatusUnauthorized)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			http.Error(writer, `{"error":{"code":"enrollment_rejected"}}`, http.StatusUnauthorized)
			return
		}
		exchange.requests = append(exchange.requests, request.URL.Path)
		issued := time.Now().UTC().Truncate(time.Second)
		stamp := func(value time.Time) string { return value.Format("2006-01-02T15:04:05Z") }
		lease := map[string]any{
			"leaseId": "tel_" + strings.Repeat("0", 12), "leaseToken": "tls_" + strings.Repeat("1", 32),
			"audience": "warpmetal-agent-team",
			"serverId": body["serverId"], "teamId": body["teamId"], "memberId": body["memberId"],
			"sandboxId": body["sandboxId"], "generation": body["generation"], "processInstance": body["processInstance"],
			"role": role, "allowedOperations": []string{"task.delegate", "task.status", "message.send"},
			"teamRevision": 17, "policyRevision": 3,
			"issuedAt": stamp(issued), "expiresAt": stamp(issued.Add(300 * time.Second)),
			"ttlSeconds": 300, "serverTime": stamp(issued),
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(lease)
	}))
	t.Cleanup(exchange.server.Close)
	exchange.endpoint = exchange.server.URL
	leaf := exchange.server.Certificate()
	if leaf == nil {
		t.Fatal("enrollment exchange has no certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	exchange.certPath = filepath.Join(t.TempDir(), "enrollment-ca.pem")
	if err := os.WriteFile(exchange.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// The Sandbox helper builds its own default SSL context, which honours
	// SSL_CERT_FILE; the loopback origin is exactly this test server.
	return exchange
}

// deepSeekWorkerExecRuntime is the fake exec seam for the cross-repo DeepSeek
// worker journey. It runs the unmodified Sandbox worker with the production
// closed request document; only the opaque container root is remapped to a host
// workspace. An idle status/reconcile never reaches the broker transport: the
// seeded lease and the running-supervisor state are the only test state the
// worker reads before returning its open receipt.
type deepSeekWorkerExecRuntime struct {
	python   string
	worker   string
	root     string
	profiles []string
	launcher [][]string
	requests []map[string]any
}

func (runtime *deepSeekWorkerExecRuntime) ExecManagedSupervisor(context.Context, string, containers.ManagedSupervisorAction, []byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("worker boundary journey must not invoke the supervisor")
}

func (runtime *deepSeekWorkerExecRuntime) ExecManagedWorker(_ context.Context, _ string, action containers.ManagedWorkerAction, profileID string, payload []byte) ([]byte, []byte, error) {
	runtime.profiles = append(runtime.profiles, profileID)
	launcher, document, err := containers.ManagedWorkerInvocation(profileID, payload)
	if err != nil {
		return nil, nil, err
	}
	runtime.launcher = append(runtime.launcher, launcher)
	var request map[string]any
	if err := json.Unmarshal(document, &request); err != nil {
		return nil, nil, err
	}
	runtime.requests = append(runtime.requests, request)
	request["root"] = runtime.root
	remapped, err := json.Marshal(request)
	if err != nil {
		return nil, nil, err
	}
	command := exec.Command(runtime.python, runtime.worker)
	command.Stdin = bytes.NewReader(remapped)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("sandbox deepseek worker %s: %w: %s", action, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

// deepSeekWorkerLease is the enrolled lease an idle worker reads before any
// broker work. It is never sent to a broker by this journey.
func deepSeekWorkerLease(t *testing.T, desired model.ManagedServiceV1) []byte {
	t.Helper()
	issued := time.Now().UTC().Truncate(time.Second)
	stamp := func(value time.Time) string { return value.Format("2006-01-02T15:04:05Z") }
	payload, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "leaseId": "tel_" + strings.Repeat("0", 12), "leaseToken": "tls_" + strings.Repeat("1", 32),
		"audience": "warpmetal-agent-team", "serverId": desired.Identity.ServerID,
		"teamId": desired.Identity.TeamID, "memberId": desired.Identity.MemberID,
		"sandboxId": desired.Identity.SandboxID, "generation": desired.Identity.SandboxGeneration,
		"processInstance":   model.ManagedServiceProcessInstance(desired.Identity.Instance, desired.Identity.ExpectedServiceGeneration),
		"role":              desired.Identity.Role,
		"allowedOperations": []string{"task.claim", "task.delegate", "task.status", "message.send"},
		"teamRevision":      17, "policyRevision": 3,
		"issuedAt": stamp(issued), "expiresAt": stamp(issued.Add(300 * time.Second)),
		"ttlSeconds": 300, "serverTime": stamp(issued),
		"endpoint": "127.0.0.1:18443", "enrolledAt": stamp(issued),
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// deepSeekWorkerState is the supervisor state the packaged worker probes for
// liveness before publishing task authority. The pid is this test process, so
// the state is coherent without starting a real managed serve.
func deepSeekWorkerState(t *testing.T, desired model.ManagedServiceV1) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"instance":  desired.Identity.Instance,
		"phase":     "running",
		"pid":       os.Getpid(),
		"port":      deepSeekManagedPort,
		"password":  "test-supervisor-password",
		"sessionId": deepSeekSessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// TestDeepSeekManagedServiceActualSandboxWorkerReceipts runs the production
// runManagedWorkerBoundary for a DeepSeek worker against the unmodified Sandbox
// DeepSeek team worker, requires both actual receipts to decode through the
// Runtime's closed worker decoder, and proves the request that reached the real
// worker carried the additive profileId selector.
func TestDeepSeekManagedServiceActualSandboxWorkerReceipts(t *testing.T) {
	sandbox := os.Getenv("WARP_METAL_SANDBOX_SOURCE")
	if sandbox == "" {
		t.Skip("WARP_METAL_SANDBOX_SOURCE is not set")
	}
	worker := filepath.Join(sandbox, "runner", "warpmetal_deepseek_team_worker.py")
	if _, err := os.Stat(worker); err != nil {
		t.Fatalf("Sandbox DeepSeek team worker unavailable: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	fixture := deepSeekManagerFixture(t)
	desired := fixture.ServiceManifest
	desired.Identity.Role = "worker"
	// The worker reads its lease and the running supervisor state from its own
	// packaged instance directory. Both are test state only: the idle status
	// never opens the loopback plane, and reconcile never reaches the broker.
	directory := filepath.Join(root, ".warpmetal", "deepseek-supervisor", desired.Identity.Instance)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "lease.json"), deepSeekWorkerLease(t, desired), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "state.json"), deepSeekWorkerState(t, desired), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	runtime := &deepSeekWorkerExecRuntime{python: python, worker: worker, root: root}
	reconciler := &Reconciler{Store: store, ManagedRuntime: runtime, Now: func() time.Time { return time.Now().UTC() }}
	receipts, err := reconciler.runManagedWorkerBoundary(context.Background(), desired)
	if err != nil {
		t.Fatalf("actual Sandbox DeepSeek worker boundary refused: %v", err)
	}
	if len(receipts) != 2 {
		t.Fatalf("DeepSeek worker boundary receipts = %d", len(receipts))
	}
	for index, action := range []containers.ManagedWorkerAction{containers.ManagedWorkerReconcile, containers.ManagedWorkerStatus} {
		receipt, err := validateManagedWorkerReceipt(receipts[index], string(action))
		if err != nil {
			t.Fatalf("actual Sandbox DeepSeek %s receipt refused by the Runtime decoder: %v\n%s", action, err, receipts[index])
		}
		if action == containers.ManagedWorkerStatus && receipt.Instance != desired.Identity.Instance {
			t.Fatalf("actual Sandbox DeepSeek status receipt instance = %#v", receipt)
		}
	}
	var status managedWorkerReceipt
	if err := decodeManagedReceipt(receipts[1], &status, false); err != nil {
		t.Fatalf("actual Sandbox DeepSeek status receipt = %s, %v", receipts[1], err)
	}
	if status.Busy || !bytes.Equal(bytes.TrimSpace(status.ActiveTask), []byte("null")) {
		t.Fatalf("actual Sandbox DeepSeek idle status = %s", receipts[1])
	}
	if len(runtime.profiles) != 2 || runtime.profiles[0] != "deepseek" || runtime.profiles[1] != "deepseek" {
		t.Fatalf("DeepSeek worker boundary profiles = %#v", runtime.profiles)
	}
	for index, request := range runtime.requests {
		if request["profileId"] != "deepseek" {
			t.Fatalf("DeepSeek worker request %d omitted profileId: %#v", index, request)
		}
		if request["command"] != string([]containers.ManagedWorkerAction{containers.ManagedWorkerReconcile, containers.ManagedWorkerStatus}[index]) {
			t.Fatalf("DeepSeek worker request %d command = %#v", index, request["command"])
		}
	}
	for _, launcher := range runtime.launcher {
		if len(launcher) != 2 || launcher[1] != "/usr/local/libexec/warpmetal-agent-teams/warpmetal_deepseek_team_worker.py" {
			t.Fatalf("DeepSeek worker launcher = %#v", launcher)
		}
	}
}
