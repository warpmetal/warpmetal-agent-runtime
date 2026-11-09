package reconcile

// DeepSeek Harness controller identity wire contract. The OpenCode behaviour is
// pinned by the existing journeys; these tests cover only the closed
// deepseek-only controllerIdentity envelope and, when the Sandbox source is
// provided, run the unmodified shipped Sandbox controller on the exact bytes the
// Runtime producer emits.

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

const deepSeekInstruction = "controller instruction sentinel\n"

func deepSeekPin(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func deepSeekInstructionDigest() string {
	sum := sha256.Sum256([]byte(deepSeekInstruction))
	return fmt.Sprintf("sha256:%x", sum)
}

// deepSeekControllerFixture builds one valid parent intent/projection and the
// observed native registration a DeepSeek controller parent reports.
func deepSeekControllerFixture() (model.ControllerParentIntent, model.ControllerRoleProjection, model.ManagedNativeRegistrationV1, model.ControllerIdentity) {
	pin := deepSeekPin
	serviceID := "parent_source_manager"
	instance := fmt.Sprintf("parent-manager-%x", sha256.Sum256([]byte(serviceID)))[:len("parent-manager-")+12]
	owner := model.ControllerOwner{
		AccountID: "account_1", TaskID: "task_1", ServerID: "srv_1",
		SandboxID: "sbx_" + strings.Repeat("s", 24), SandboxGeneration: 1,
		CellID: "cell_1", ControllerID: "controller_1", ControllerRevision: 1, AuthorityRevision: 1,
	}
	flash := providerpolicy.Flash()
	approved := model.ApprovedExpertiseProfile{ProfileID: "profile_expert", ProfileRevision: 1, ProfileDigest: pin("1"), BundleDigest: pin("1")}
	modelSelection := &model.WorkspaceModelSelection{
		Authority:         model.CellPreparedAuthorityV3{ProviderID: flash.ProviderID, ModelID: flash.ModelID, AuthMode: flash.AuthMode},
		CredentialBinding: &model.CellCredentialBindingV3{ConnectionID: "connection_1", ConnectionRevision: 1, ProviderID: flash.ProviderID, AuthMode: flash.AuthMode},
	}
	instructionDigest := deepSeekInstructionDigest()
	projection := model.ControllerRoleProjection{
		NativeAgentID:     "warpmetal-controller-manager",
		SystemDigest:      instructionDigest,
		ApprovedProfile:   approved,
		ModelSelection:    modelSelection,
		ToolsDisabled:     true,
		MCPDisabled:       true,
		ToolClosureDigest: pin("4"),
	}
	workspace := model.ManagedServiceWorkspaceV1{
		SelectionID: "selection_1", ProjectID: "project_1", WorkspaceEpoch: "epoch_1",
		ScopeRevision: 1, Designation: "team_project", RootAttestation: pin("5"),
	}
	parent := model.ControllerParentIntent{
		FormatVersion:            2,
		TargetKind:               "controller_parent",
		OperationID:              "operation_1",
		ActionRevision:           1,
		DesiredRevision:          1,
		DesiredState:             "active",
		SessionMode:              "create_initial",
		Owner:                    owner,
		Role:                     "manager",
		ServiceRegistrationID:    serviceID,
		ServiceGeneration:        1,
		Instance:                 instance,
		Profile:                  model.ManagedServiceProfileV1{SetupOperationID: "setup_operation_1", ProfileID: "deepseek", ProfileRevision: 2, ProfileDigest: pin("2")},
		Instructions:             model.ManagedServiceInstructionsV1{InstructionRevision: 1, InstructionDigest: instructionDigest},
		Workspace:                workspace,
		ApplicationOperationID:   "workspace_application_1",
		ConnectionRevisionDigest: pin("7"),
		ModelAuthorityDigest:     pin("8"),
		RoleAgentDigest:          model.WorkspaceDigest(projection),
		RuntimeContractVersion:   "0.1.52",
	}
	raw, err := json.Marshal(parent)
	if err != nil {
		panic(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		panic(err)
	}
	delete(fields, "configDigest")
	parent.ConfigDigest = model.WorkspaceDigest(fields)
	if err := parent.Validate(); err != nil {
		panic(fmt.Sprintf("deepseek fixture parent refused: %v", err))
	}
	native := model.ManagedNativeRegistrationV1{
		RegisteredSourceID:   "source_registration_1",
		WorkspaceEpoch:       workspace.WorkspaceEpoch,
		NativeSessionID:      "ses_" + strings.Repeat("a", 32),
		NativeProjectID:      strings.Repeat("b", 40),
		NativeLocationDigest: pin("c"),
	}
	application, err := controllerApplicationIdentity(parent, projection, native)
	if err != nil {
		panic(err)
	}
	expected, err := controllerExpectedNativeIdentity(application)
	if err != nil {
		panic(err)
	}
	return parent, projection, native, expected
}

func TestDeepSeekControllerIdentityDerivation(t *testing.T) {
	parent, projection, native, expected := deepSeekControllerFixture()
	application, err := controllerApplicationIdentity(parent, projection, native)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(application.Intent, parent) || !reflect.DeepEqual(application.Projection, projection) {
		t.Fatalf("application identity changed the issued intent/projection")
	}
	if application.Source.FormatVersion != 2 || application.Source.Source.RegisteredSourceID != native.RegisteredSourceID ||
		application.Source.Source.NativeSessionID != native.NativeSessionID || application.Source.Source.NativeProjectID != native.NativeProjectID ||
		application.Source.Source.NativeLocationDigest != native.NativeLocationDigest {
		t.Fatalf("application source identity = %#v", application.Source)
	}
	if application.Source.Identity.ServiceRegistrationID != parent.ServiceRegistrationID ||
		application.Source.Identity.ProfileID != parent.Profile.ProfileID ||
		application.Source.Identity.ProjectID != parent.Workspace.ProjectID {
		t.Fatalf("application source pins = %#v", application.Source.Identity)
	}
	// The expected native identity is the DeepSeek Flash derivation: approved
	// profile substitution plus re-derived role-agent/config digests.
	if expected.Intent.Profile.ProfileID != projection.ApprovedProfile.ProfileID {
		t.Fatalf("native intent profile = %#v", expected.Intent.Profile)
	}
	if expected.Intent.Profile.ProfileDigest != projection.ApprovedProfile.ProfileDigest {
		t.Fatalf("native intent profile digest = %q", expected.Intent.Profile.ProfileDigest)
	}
	nativeProjection := expected.Projection
	nativeProjection.ToolClosureDigest = ""
	if expected.Intent.RoleAgentDigest != model.WorkspaceDigest(nativeProjection) {
		t.Fatalf("native role agent digest = %q", expected.Intent.RoleAgentDigest)
	}
	raw, _ := json.Marshal(expected.Intent)
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "configDigest")
	if expected.Intent.ConfigDigest != model.WorkspaceDigest(fields) {
		t.Fatalf("native config digest = %q", expected.Intent.ConfigDigest)
	}
	if expected.Source.Identity.ProfileID != projection.ApprovedProfile.ProfileID ||
		expected.Source.Identity.ProfileDigest != projection.ApprovedProfile.ProfileDigest {
		t.Fatalf("native source profile = %#v", expected.Source.Identity)
	}
	if expected.Source.Source != application.Source.Source {
		t.Fatalf("native source registration changed")
	}
}

func TestDeepSeekControllerIdentityOnlyAddedForDeepSeekProfile(t *testing.T) {
	parent, projection, native, expected := deepSeekControllerFixture()

	deepSeekRequest := map[string]any{}
	if err := addDeepSeekControllerIdentity(deepSeekRequest, parent, projection, native); err != nil {
		t.Fatal(err)
	}
	raw, ok := deepSeekRequest["controllerIdentity"]
	if !ok {
		t.Fatal("deepseek request is missing controllerIdentity")
	}
	var decoded model.ControllerIdentity
	encoded, _ := json.Marshal(raw)
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, expected) {
		t.Fatalf("deepseek controllerIdentity = %#v", decoded)
	}

	openCodeParent := parent
	openCodeParent.Profile.ProfileID = "opencode"
	openCodeRequest := map[string]any{"schemaVersion": 1, "profileId": "opencode"}
	before, _ := json.Marshal(openCodeRequest)
	if err := addDeepSeekControllerIdentity(openCodeRequest, openCodeParent, projection, native); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(openCodeRequest)
	if !bytes.Equal(before, after) {
		t.Fatalf("opencode request envelope changed: %s -> %s", before, after)
	}

	registration, err := controllerSourceRegistrationRequest(parent, projection, native)
	if err != nil {
		t.Fatal(err)
	}
	encodedRegistration, _ := json.Marshal(registration)
	var registrationFields map[string]json.RawMessage
	if err := json.Unmarshal(encodedRegistration, &registrationFields); err != nil {
		t.Fatal(err)
	}
	if len(registrationFields) != 6 {
		t.Fatalf("deepseek register-source outer fields = %v", registrationFields)
	}
	for _, key := range []string{"schemaVersion", "sandboxId", "instance", "profileId", "registration", "controllerIdentity"} {
		if _, ok := registrationFields[key]; !ok {
			t.Fatalf("deepseek register-source is missing %q", key)
		}
	}
	var registrationBody struct {
		FormatVersion int            `json:"formatVersion"`
		Identity      map[string]any `json:"identity"`
		Source        struct {
			RegisteredSourceID   string `json:"registeredSourceId"`
			NativeSessionID      string `json:"nativeSessionId"`
			NativeProjectID      string `json:"nativeProjectId"`
			NativeLocationDigest string `json:"nativeLocationDigest"`
		} `json:"source"`
	}
	if err := json.Unmarshal(registrationFields["registration"], &registrationBody); err != nil {
		t.Fatal(err)
	}
	if registrationBody.FormatVersion != 2 || len(registrationBody.Identity) != 20 ||
		registrationBody.Source.RegisteredSourceID != native.RegisteredSourceID ||
		registrationBody.Source.NativeSessionID != native.NativeSessionID ||
		registrationBody.Source.NativeProjectID != native.NativeProjectID ||
		registrationBody.Source.NativeLocationDigest != native.NativeLocationDigest {
		t.Fatalf("deepseek registration body = %#v", registrationBody)
	}

	openCodeRegistration, err := controllerSourceRegistrationRequest(openCodeParent, projection, native)
	if err != nil {
		t.Fatal(err)
	}
	encodedOpenCode, _ := json.Marshal(openCodeRegistration)
	var openCodeFields map[string]json.RawMessage
	if err := json.Unmarshal(encodedOpenCode, &openCodeFields); err != nil {
		t.Fatal(err)
	}
	if _, ok := openCodeFields["controllerIdentity"]; ok {
		t.Fatal("opencode register-source carries the deepseek-only identity")
	}
	if len(openCodeFields) != 5 {
		t.Fatalf("opencode register-source outer fields = %v", openCodeFields)
	}
}

// TestDeepSeekControllerActualSandboxWireContract hands the exact Runtime-emitted
// identity bytes to the unmodified shipped Sandbox controller. It requires
// WARP_METAL_SANDBOX_SOURCE to point at a Sandbox checkout containing the
// controller identity implementation (the same explicit SOURCE pattern used by
// the managed-service wire contract test).
func TestDeepSeekControllerActualSandboxWireContract(t *testing.T) {
	sandbox := os.Getenv("WARP_METAL_SANDBOX_SOURCE")
	if sandbox == "" {
		t.Skip("WARP_METAL_SANDBOX_SOURCE is not set")
	}
	controller := filepath.Join(sandbox, "runner", "warpmetal_deepseek_controller.py")
	if _, err := os.Stat(controller); err != nil {
		t.Fatalf("Sandbox controller unavailable: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	parent, projection, native, expected := deepSeekControllerFixture()
	root := t.TempDir()

	registration, err := controllerSourceRegistrationRequest(parent, projection, native)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(registration)
	response := runSandboxDeepSeekController(t, python, controller, root, "register-source", payload)
	var registerReceipt struct {
		SchemaVersion int    `json:"schemaVersion"`
		Command       string `json:"command"`
		Status        string `json:"status"`
		Ready         bool   `json:"ready"`
		Registered    string `json:"registeredSourceId"`
		NativeSession string `json:"nativeSessionId"`
		NativeProject string `json:"nativeProjectId"`
		Location      string `json:"nativeLocationDigest"`
	}
	if err := json.Unmarshal(response, &registerReceipt); err != nil {
		t.Fatal(err)
	}
	if registerReceipt.SchemaVersion != 1 || registerReceipt.Command != "register-source" || registerReceipt.Status != "registered" ||
		!registerReceipt.Ready || registerReceipt.Registered != native.RegisteredSourceID ||
		registerReceipt.NativeSession != native.NativeSessionID || registerReceipt.NativeProject != native.NativeProjectID ||
		registerReceipt.Location != native.NativeLocationDigest {
		t.Fatalf("Sandbox register-source receipt = %s", response)
	}

	statusRequest := parentRequest(parent)
	statusRequest["controllerIdentity"] = expected
	payload, _ = json.Marshal(statusRequest)
	response = runSandboxDeepSeekController(t, python, controller, root, "status", payload)
	binding := decodeDeepSeekStatusBinding(t, response)
	if !reflect.DeepEqual(binding.Identity, expected) || binding.State != "registered" || binding.PreparedReceipt != nil {
		t.Fatalf("Sandbox status binding = %#v", binding)
	}

	preparedTuple := model.ControllerPreparedTuple{
		Owner:                 parent.Owner,
		Role:                  parent.Role,
		ServiceRegistrationID: parent.ServiceRegistrationID,
		ServiceGeneration:     parent.ServiceGeneration,
		NativeRegistration:    native,
		RoleAgentDigest:       expected.Intent.RoleAgentDigest,
		ConfigurationDigest:   deepSeekPin("9"),
		ConfigDigest:          expected.Intent.ConfigDigest,
		InputID:               "input_1",
		InputDigest:           fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("exact controller input\n"))),
		Authority:             expected.Projection.ModelSelection.Authority,
		CredentialBinding:     *expected.Projection.ModelSelection.CredentialBinding,
	}
	prepareRequest := map[string]any{
		"schemaVersion": 1,
		"sandboxId":     parent.Owner.SandboxID,
		"instance":      parent.Instance,
		"profileId":     "deepseek",
		"preparationId": "preparation_1",
		"preparedTuple": preparedTuple,
		"credential": map[string]any{
			"providerId": "deepseek",
			"authMode":   "api_key",
			"material":   map[string]any{"type": "key", "key": "sk-test-12121212"},
		},
	}
	payload, _ = json.Marshal(prepareRequest)
	response = runSandboxDeepSeekController(t, python, controller, root, "controller-prepare", payload)
	var prepared struct {
		SchemaVersion   int                             `json:"schemaVersion"`
		Command         string                          `json:"command"`
		Status          string                          `json:"status"`
		PreparedReceipt model.ControllerPreparedReceipt `json:"preparedReceipt"`
	}
	if err := model.DecodeControllerTransportReceipt(response, "controller-prepare", &prepared); err != nil {
		t.Fatalf("Sandbox controller-prepare receipt refused by the Runtime decoder: %v\n%s", err, response)
	}
	if prepared.SchemaVersion != 1 || prepared.Command != "controller-prepare" || prepared.Status != "prepared" {
		t.Fatalf("Sandbox controller-prepare outer receipt = %s", response)
	}
	if !reflect.DeepEqual(prepared.PreparedReceipt.PreparedTuple, preparedTuple) {
		t.Fatalf("Sandbox prepared tuple = %#v", prepared.PreparedReceipt.PreparedTuple)
	}
	if err := prepared.PreparedReceipt.Validate(); err != nil {
		t.Fatalf("Sandbox prepared receipt refused: %v", err)
	}

	payload, _ = json.Marshal(statusRequest)
	response = runSandboxDeepSeekController(t, python, controller, root, "status", payload)
	binding = decodeDeepSeekStatusBinding(t, response)
	if binding.State != "bound" || binding.PreparedReceipt == nil || !reflect.DeepEqual(*binding.PreparedReceipt, prepared.PreparedReceipt) {
		t.Fatalf("Sandbox bound status binding = %#v", binding)
	}
	if err := binding.PreparedReceipt.PreparedTuple.ValidateControllerPolicyIdentity(expected); err != nil {
		t.Fatalf("Sandbox bound receipt identity join refused: %v", err)
	}
}

type deepSeekStatusBinding struct {
	Identity        model.ControllerIdentity
	State           string
	PreparedReceipt *model.ControllerPreparedReceipt
}

func decodeDeepSeekStatusBinding(t *testing.T, response []byte) deepSeekStatusBinding {
	t.Helper()
	var receipt struct {
		SchemaVersion int             `json:"schemaVersion"`
		Command       string          `json:"command"`
		Status        string          `json:"status"`
		Binding       json.RawMessage `json:"binding"`
	}
	if err := json.Unmarshal(response, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.SchemaVersion != 1 || receipt.Command != "status" || receipt.Status != "ready" || len(receipt.Binding) == 0 {
		t.Fatalf("Sandbox status receipt = %s", response)
	}
	var binding struct {
		Identity        model.ControllerIdentity         `json:"identity"`
		State           string                           `json:"state"`
		PreparedReceipt *model.ControllerPreparedReceipt `json:"preparedReceipt"`
	}
	var fields map[string]json.RawMessage
	if err := model.DecodePhysicalClosed(receipt.Binding, &binding); err != nil || json.Unmarshal(receipt.Binding, &fields) != nil || len(fields) != 3 || fields["preparedReceipt"] == nil {
		t.Fatalf("Sandbox status binding shape = %s", receipt.Binding)
	}
	if binding.State != "registered" && binding.State != "bound" {
		t.Fatalf("Sandbox status binding state = %q", binding.State)
	}
	if binding.State == "registered" && binding.PreparedReceipt != nil {
		t.Fatalf("registered binding carries a prepared receipt")
	}
	if binding.State == "bound" && binding.PreparedReceipt == nil {
		t.Fatalf("bound binding has no prepared receipt")
	}
	return deepSeekStatusBinding{Identity: binding.Identity, State: binding.State, PreparedReceipt: binding.PreparedReceipt}
}

const deepSeekControllerAdapter = `
import importlib.util
import json
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("deepseek_controller_consumer", sys.argv[1])
consumer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = consumer
spec.loader.exec_module(consumer)
request = json.load(sys.stdin)
function = {
    "register-source": consumer.register_source,
    "status": consumer.status,
    "controller-prepare": consumer.controller_prepare,
}[sys.argv[3]]
receipt = function(Path(sys.argv[2]), request)
print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
`

func runSandboxDeepSeekController(t *testing.T, python, script, root, command string, payload []byte) []byte {
	t.Helper()
	call := exec.Command(python, "-c", deepSeekControllerAdapter, script, root, command)
	call.Stdin = bytes.NewReader(payload)
	output, err := call.CombinedOutput()
	if err != nil {
		t.Fatalf("actual Sandbox controller refused %s: %v\n%s", command, err, output)
	}
	return output
}

// deepSeekExpertiseBundle builds the exact data-only v1 bundle/manifest pair the
// Runtime stages for a controller parent profile dependency.
func deepSeekExpertiseBundle(t *testing.T) (map[string]any, model.AppliedExpertiseProfile) {
	t.Helper()
	raw := []byte("# reviewed expertise entry")
	sha := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	gitBlob := fmt.Sprintf("%x", sha1.Sum(append([]byte(fmt.Sprintf("blob %d\x00", len(raw))), raw...)))
	manifest := map[string]any{
		"formatVersion": 1,
		"repository":    map[string]any{"id": 1, "owner": "warpmetal", "name": "workspace-profiles"},
		"commitSha":     strings.Repeat("a", 40),
		"rootTreeSha":   strings.Repeat("b", 40),
		"approvedPaths": []any{"expert"},
		"files": []any{map[string]any{
			"path": "expert/README.md", "gitMode": "100644", "gitBlobSha": gitBlob,
			"sizeBytes": len(raw), "sha256": sha,
		}},
	}
	bundleDigest := model.WorkspaceDigest(manifest)
	bundle := map[string]any{
		"manifest":     manifest,
		"bundleDigest": bundleDigest,
		"blobs":        map[string]any{sha: base64.StdEncoding.EncodeToString(raw)},
	}
	expected := model.AppliedExpertiseProfile{
		ApprovedProfile: model.ApprovedExpertiseProfile{ProfileID: "profile_expert", ProfileRevision: 1, ProfileDigest: deepSeekPin("1"), BundleDigest: bundleDigest},
		EntryPath:       "expert/README.md",
		Files:           []model.ExpertiseFile{{Path: "expert/README.md", SHA256: sha, ByteCount: int64(len(raw))}},
	}
	return bundle, expected
}

// TestDeepSeekControllerActualSandboxParentJourney runs the exact Runtime wire
// against the unmodified shipped Sandbox supervisor: start -> native readiness
// -> register-source -> status.binding -> controller-prepare -> controller-prompt
// over the real loopback ACP compatibility plane. Only the DeepSeek Harness ACP
// process is substituted; no native/provider/root authority is claimed.
func TestDeepSeekControllerActualSandboxParentJourney(t *testing.T) {
	sandbox := os.Getenv("WARP_METAL_SANDBOX_SOURCE")
	if sandbox == "" {
		t.Skip("WARP_METAL_SANDBOX_SOURCE is not set")
	}
	supervisor := filepath.Join(sandbox, "runner", "warpmetal_deepseek_supervisor.py")
	if _, err := os.Stat(supervisor); err != nil {
		t.Fatalf("Sandbox supervisor unavailable: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	const port = 18444
	if !deepSeekPortFree(port) {
		t.Skip("contract manager port 18444 is busy")
	}
	// The fake ACP launcher persists its session ids so a new launcher process
	// can prove the retained session-resume path.
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
	// The image-owned controller path is a fixed CLI default; this source copy is
	// the explicit test seam used only by this retained cross-repo contract test.
	controllerBytes, err := os.ReadFile(filepath.Join(sandbox, "runner", "warpmetal_deepseek_controller.py"))
	if err != nil {
		t.Fatal(err)
	}
	controllerCopy := filepath.Join(root, "warpmetal-deepseek-controller")
	if err := os.WriteFile(controllerCopy, controllerBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = deepSeekMakeWritable(root) })
	parent, projection, _, _ := deepSeekControllerFixture()
	start := map[string]any{
		"schemaVersion":          1,
		"sandboxId":              parent.Owner.SandboxID,
		"instance":               parent.Instance,
		"profileId":              parent.Profile.ProfileID,
		"profileDigest":          parent.Profile.ProfileDigest,
		"profileRevision":        parent.Profile.ProfileRevision,
		"version":                "0.2.2-rc.1",
		"port":                   port,
		"projectRoot":            projectRoot,
		"sessionMode":            "create_initial",
		"instructionText":        deepSeekInstruction,
		"instructionDigest":      deepSeekInstructionDigest(),
		"instructionRevision":    1,
		"materializerDigest":     deepSeekPin("3"),
		"monitorEnabled":         false,
		"runtimeContractVersion": parent.RuntimeContractVersion,
		"controllerParent":       parent,
		"roleProjection":         projection,
		"readinessSeconds":       90,
	}
	run := func(command string, payload any) []byte {
		return runDeepSeekSupervisor(t, python, supervisor, root, launcher, controllerCopy, command, payload)
	}
	defer func() {
		_ = runDeepSeekSupervisor(t, python, supervisor, root, launcher, controllerCopy, "stop", map[string]any{
			"schemaVersion": 1,
			"sandboxId":     parent.Owner.SandboxID,
			"instance":      parent.Instance,
			"profileId":     parent.Profile.ProfileID,
		})
	}()

	bundle, expectedProfile := deepSeekExpertiseBundle(t)
	stageInstance := "profile-0123456789ab"
	materializeRequest := map[string]any{
		"schemaVersion": 1, "sandboxId": parent.Owner.SandboxID, "instance": stageInstance,
		"profileId": parent.Profile.ProfileID, "expected": expectedProfile, "bundle": bundle,
		"materializerDigest": deepSeekPin("d"),
	}
	var materializeReceipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(run("materialize-profile", materializeRequest), &materializeReceipt); err != nil {
		t.Fatal(err)
	}
	if materializeReceipt.SchemaVersion != 1 || materializeReceipt.Command != "materialize-profile" || materializeReceipt.Status != "ready" ||
		!materializeReceipt.Ready || materializeReceipt.SandboxID != parent.Owner.SandboxID || materializeReceipt.Instance != stageInstance ||
		materializeReceipt.MaterializerDigest != deepSeekPin("d") || materializeReceipt.AppliedProfile == nil ||
		!reflect.DeepEqual(*materializeReceipt.AppliedProfile, expectedProfile) {
		t.Fatalf("deepseek materialize-profile receipt = %#v", materializeReceipt)
	}

	var startReceipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(run("start", start), &startReceipt); err != nil {
		t.Fatal(err)
	}
	if startReceipt.Status != "ready" || !startReceipt.Ready || startReceipt.Phase != "running" {
		t.Fatalf("deepseek start receipt = %#v", startReceipt)
	}
	if err := validateParentNativeReceipt(parent, &startReceipt, deepSeekPin("3")); err != nil {
		t.Fatalf("Runtime parent native readback refused the deepseek start receipt: %v", err)
	}
	if startReceipt.Port != port || startReceipt.PID < 1 {
		t.Fatalf("deepseek start process/port = %d/%d", startReceipt.PID, startReceipt.Port)
	}
	if len(startReceipt.NativeProjectID) != 40 {
		t.Fatalf("deepseek nativeProjectId = %q", startReceipt.NativeProjectID)
	}
	expectedLocation := model.WorkspaceDigest(map[string]any{"directory": projectRoot, "projectId": startReceipt.NativeProjectID, "workspaceId": nil})
	if startReceipt.NativeLocationDigest != expectedLocation {
		t.Fatalf("deepseek nativeLocationDigest = %q, want %q", startReceipt.NativeLocationDigest, expectedLocation)
	}
	if !strings.HasPrefix(startReceipt.SessionID, "ses_") || startReceipt.InstructionDigest != deepSeekInstructionDigest() || !startReceipt.InstructionApplied {
		t.Fatalf("deepseek start identity/instruction = %#v", startReceipt)
	}
	if startReceipt.NativeRoleReadback == nil || startReceipt.NativeRoleReadback.Role != parent.Role ||
		startReceipt.NativeRoleReadback.NativeAgentID != "warpmetal-controller-"+parent.Role ||
		startReceipt.NativeRoleReadback.RoleAgentDigest != parent.RoleAgentDigest {
		t.Fatalf("deepseek native role readback = %#v", startReceipt.NativeRoleReadback)
	}
	installed, err := os.ReadFile(filepath.Join(projectRoot, "AGENTS.md"))
	if err != nil || string(installed) != deepSeekInstruction {
		t.Fatalf("deepseek applied instruction = %q %v", installed, err)
	}

	native := model.ManagedNativeRegistrationV1{
		RegisteredSourceID:   managedSourceID(parent.ServiceRegistrationID),
		WorkspaceEpoch:       parent.Workspace.WorkspaceEpoch,
		NativeSessionID:      startReceipt.SessionID,
		NativeProjectID:      startReceipt.NativeProjectID,
		NativeLocationDigest: startReceipt.NativeLocationDigest,
	}
	registerRequest, err := controllerSourceRegistrationRequest(parent, projection, native)
	if err != nil {
		t.Fatal(err)
	}
	var registerReceipt managedSourceRegistrationReceipt
	if err := decodeManagedSupervisorReceipt(run("register-source", registerRequest), &registerReceipt); err != nil {
		t.Fatal(err)
	}
	if registerReceipt.SchemaVersion != 1 || registerReceipt.Command != "register-source" || registerReceipt.Status != "registered" ||
		registerReceipt.Instance != parent.Instance || registerReceipt.SandboxID != parent.Owner.SandboxID ||
		registerReceipt.RegisteredSourceID != native.RegisteredSourceID || registerReceipt.NativeSessionID != native.NativeSessionID ||
		registerReceipt.NativeProjectID != native.NativeProjectID || registerReceipt.NativeLocationDigest != native.NativeLocationDigest ||
		registerReceipt.ProfileID != parent.Profile.ProfileID || registerReceipt.ProfileDigest != parent.Profile.ProfileDigest {
		t.Fatalf("deepseek register-source receipt = %#v", registerReceipt)
	}

	application, err := controllerApplicationIdentity(parent, projection, native)
	if err != nil {
		t.Fatal(err)
	}
	expectedNative, err := controllerExpectedNativeIdentity(application)
	if err != nil {
		t.Fatal(err)
	}
	statusRequest := parentRequest(parent)
	statusRequest["probe"] = true
	statusRequest["requestTimeoutSeconds"] = 30
	if err := addDeepSeekControllerIdentity(statusRequest, parent, projection, native); err != nil {
		t.Fatal(err)
	}
	var statusReceipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(run("status", statusRequest), &statusReceipt); err != nil {
		t.Fatal(err)
	}
	if err := validateParentNativeReceipt(parent, &statusReceipt, deepSeekPin("3")); err != nil {
		t.Fatalf("Runtime parent native readback refused the deepseek status receipt: %v", err)
	}
	if statusReceipt.SessionID != native.NativeSessionID || statusReceipt.NativeProjectID != native.NativeProjectID || statusReceipt.NativeLocationDigest != native.NativeLocationDigest {
		t.Fatalf("deepseek status native identity drifted: %#v", statusReceipt)
	}
	if err := controllerStatusBinding(statusReceipt.Binding, expectedNative); err != nil {
		t.Fatalf("Runtime status.binding join refused the deepseek registration: %v", err)
	}

	text := "exact controller input\n"
	preparedTuple := model.ControllerPreparedTuple{
		Owner:                 parent.Owner,
		Role:                  parent.Role,
		ServiceRegistrationID: parent.ServiceRegistrationID,
		ServiceGeneration:     parent.ServiceGeneration,
		NativeRegistration:    native,
		RoleAgentDigest:       expectedNative.Intent.RoleAgentDigest,
		ConfigurationDigest:   deepSeekPin("9"),
		ConfigDigest:          expectedNative.Intent.ConfigDigest,
		InputID:               "input_1",
		InputDigest:           fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text))),
		Authority:             expectedNative.Projection.ModelSelection.Authority,
		CredentialBinding:     *expectedNative.Projection.ModelSelection.CredentialBinding,
	}
	prepareRequest := parentRequest(parent)
	prepareRequest["preparationId"] = "preparation_1"
	prepareRequest["preparedTuple"] = preparedTuple
	prepareRequest["credential"] = map[string]any{
		"providerId": "deepseek",
		"authMode":   "api_key",
		"material":   map[string]any{"type": "key", "key": "sk-test-12121212"},
	}
	prepareRequest["policyDigest"] = deepSeekPin("b")
	var prepared struct {
		SchemaVersion   int                             `json:"schemaVersion"`
		Command         string                          `json:"command"`
		Status          string                          `json:"status"`
		PreparedReceipt model.ControllerPreparedReceipt `json:"preparedReceipt"`
	}
	if err := model.DecodeControllerTransportReceipt(run("controller-prepare", prepareRequest), "controller-prepare", &prepared); err != nil {
		t.Fatalf("Sandbox controller-prepare receipt refused by the Runtime decoder: %v", err)
	}
	if prepared.Status != "prepared" || prepared.PreparedReceipt.Validate() != nil || !reflect.DeepEqual(prepared.PreparedReceipt.PreparedTuple, preparedTuple) {
		t.Fatalf("Sandbox controller-prepare receipt = %#v", prepared)
	}
	headerRequest := parentRequest(parent)
	headerRequest["preparedReceipt"] = prepared.PreparedReceipt
	headerRequest["policyDigest"] = deepSeekPin("b")
	var header struct {
		SchemaVersion     int                                      `json:"schemaVersion"`
		Command           string                                   `json:"command"`
		Status            string                                   `json:"status"`
		HeaderObservation model.ControllerAuthorizationObservation `json:"headerObservation"`
	}
	headerRaw := run("controller-header", headerRequest)
	if err := model.DecodeControllerTransportReceipt(headerRaw, "controller-header", &header); err != nil {
		t.Fatalf("Sandbox controller-header receipt refused by the Runtime decoder: %v", err)
	}
	if header.Status != "observed" || header.HeaderObservation.FormatVersion != 1 ||
		header.HeaderObservation.TargetKind != "controller_authorization" ||
		header.HeaderObservation.PreparationID != prepared.PreparedReceipt.PreparationID ||
		header.HeaderObservation.PreparedReceiptDigest != prepared.PreparedReceipt.PreparedReceiptDigest ||
		!strings.HasPrefix(header.HeaderObservation.AuthorizationSHA256, "sha256:") || len(header.HeaderObservation.AuthorizationSHA256) != 71 {
		t.Fatalf("Sandbox controller-header observation = %#v", header)
	}
	if replay := run("controller-header", headerRequest); !bytes.Equal(replay, headerRaw) {
		t.Fatalf("controller-header replay changed: %s vs %s", replay, headerRaw)
	}

	admission := model.ControllerAdmission{
		FormatVersion:   1,
		TargetKind:      "controller_activity",
		PreparedReceipt: prepared.PreparedReceipt,
		Grant: model.ControllerActivityGrant{
			FormatVersion: 1, TargetKind: "controller_activity", GrantID: "grant_1", PreparationID: "preparation_1",
			PreparedReceiptDigest: prepared.PreparedReceipt.PreparedReceiptDigest, ReservationID: "reservation_1",
			CaseID: "case_1", CaseManifestDigest: deepSeekPin("a"), PolicyDigest: deepSeekPin("b"),
			RequestIndex: 1, PhysicalIndex: 1, MaxInputTokens: 1000, MaxOutputTokens: 1000, MaxUSDMicros: 2000,
			DeadlineAt: "2030-01-01T00:00:00Z", ExpiresAt: "2030-01-01T00:00:05Z",
		},
	}
	promptRequest := parentRequest(parent)
	promptRequest["admission"] = admission
	promptRequest["text"] = text
	var prompt struct {
		SchemaVersion   int             `json:"schemaVersion"`
		Command         string          `json:"command"`
		Status          string          `json:"status"`
		NativeAdmission json.RawMessage `json:"nativeAdmission"`
	}
	if err := model.DecodeControllerTransportReceipt(run("controller-prompt", promptRequest), "controller-prompt", &prompt); err != nil {
		t.Fatalf("Sandbox controller-prompt receipt refused by the Runtime decoder: %v", err)
	}
	if prompt.Status != "admitted" || len(prompt.NativeAdmission) == 0 || bytes.Equal(bytes.TrimSpace(prompt.NativeAdmission), []byte("null")) {
		t.Fatalf("Sandbox controller-prompt receipt = %#v", prompt)
	}
	outputRequest := parentRequest(parent)
	outputRequest["admission"] = admission
	var output struct {
		SchemaVersion int                                  `json:"schemaVersion"`
		Command       string                               `json:"command"`
		Status        string                               `json:"status"`
		NativeOutput  model.ControllerOutputNativeReadback `json:"nativeOutput"`
		NativeLog     []json.RawMessage                    `json:"nativeLog"`
	}
	outputRaw := run("controller-output", outputRequest)
	if err := model.DecodeControllerTransportReceipt(outputRaw, "controller-output", &output); err != nil {
		t.Fatalf("Sandbox controller-output receipt refused by the Runtime decoder: %v\n%s", err, outputRaw)
	}
	if output.Status != "observed" {
		t.Fatalf("Sandbox controller-output status = %q", output.Status)
	}
	identityJSON, _ := json.Marshal(expectedNative)
	capture := qualification.ControllerCapture{NativeOutput: output.NativeOutput, NativeLog: output.NativeLog}
	lineage, err := capture.Verify(text, identityJSON, admission)
	if err != nil {
		t.Fatalf("Runtime qualification refused the DSH controller output capture: %v", err)
	}
	if lineage.OutputText != "controller output\n" || lineage.TerminalOutcome != "succeeded" ||
		lineage.AssistantModel.ProviderID != providerpolicy.Flash().ProviderID || lineage.AssistantModel.ID != providerpolicy.Flash().ModelID {
		t.Fatalf("DSH controller output lineage = %#v", lineage)
	}
	if replay := run("controller-output", outputRequest); !bytes.Equal(replay, outputRaw) {
		t.Fatalf("controller-output replay changed")
	}

	acpLog, err := os.ReadFile(filepath.Join(root, ".warpmetal", "deepseek-supervisor", parent.Instance, "acp.log"))
	if err != nil || !bytes.Contains(acpLog, []byte("session/prompt")) {
		t.Fatalf("deepseek prompt did not reach the ACP transport: %v", err)
	}

	// The same admission is never dispatched twice.
	var again struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	second, _ := runDeepSeekSupervisorAllowingRefusal(t, python, supervisor, root, launcher, controllerCopy, "controller-prompt", promptRequest)
	_ = json.Unmarshal(second, &again)
	if again.Status != "failed" || again.Error != "controller_prompt_unknown" {
		t.Fatalf("second controller-prompt = %s", second)
	}

	// Unexpected supervisor exit: kill the serve process, keep the durable state,
	// then reattach with a lookup_only launch and run one more activity.
	statePath := filepath.Join(root, ".warpmetal", "deepseek-supervisor", parent.Instance, "state.json")
	stateRaw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var supervisorState struct {
		PID       int    `json:"pid"`
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(stateRaw, &supervisorState); err != nil {
		t.Fatal(err)
	}
	if supervisorState.SessionID != startReceipt.SessionID || supervisorState.PID < 1 {
		t.Fatalf("supervisor state identity = %#v", supervisorState)
	}
	if err := syscall.Kill(supervisorState.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for !deepSeekPortFree(port) {
		if time.Now().After(deadline) {
			t.Fatalf("killed serve process did not release port %d", port)
		}
		time.Sleep(25 * time.Millisecond)
	}
	lookupPayload, err := json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	var lookup map[string]any
	if err := json.Unmarshal(lookupPayload, &lookup); err != nil {
		t.Fatal(err)
	}
	lookup["sessionMode"] = "lookup_only"
	var resumed managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(run("start", lookup), &resumed); err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "ready" || !resumed.Ready || resumed.Phase != "running" ||
		resumed.SessionID != startReceipt.SessionID || resumed.NativeProjectID != startReceipt.NativeProjectID ||
		resumed.NativeLocationDigest != startReceipt.NativeLocationDigest {
		t.Fatalf("deepseek resumed start receipt = %#v", resumed)
	}
	if err := validateParentNativeReceipt(parent, &resumed, deepSeekPin("3")); err != nil {
		t.Fatalf("Runtime parent native readback refused the resumed deepseek start: %v", err)
	}
	resumedStateRaw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var resumedState struct {
		Journal []json.RawMessage `json:"journal"`
	}
	if err := json.Unmarshal(resumedStateRaw, &resumedState); err != nil {
		t.Fatal(err)
	}
	if len(resumedState.Journal) != len(output.NativeLog) {
		t.Fatalf("resume lost the retained journal: %d != %d", len(resumedState.Journal), len(output.NativeLog))
	}

	text2 := "second controller input\n"
	preparedTuple2 := preparedTuple
	preparedTuple2.InputID = "input_2"
	preparedTuple2.InputDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text2)))
	prepareRequest2 := map[string]any{
		"schemaVersion": 1,
		"sandboxId":     parent.Owner.SandboxID,
		"instance":      parent.Instance,
		"profileId":     "deepseek",
		"preparationId": "preparation_2",
		"preparedTuple": preparedTuple2,
		"credential":    prepareRequest["credential"],
		"policyDigest":  deepSeekPin("b"),
	}
	var prepared2 struct {
		SchemaVersion   int                             `json:"schemaVersion"`
		Command         string                          `json:"command"`
		Status          string                          `json:"status"`
		PreparedReceipt model.ControllerPreparedReceipt `json:"preparedReceipt"`
	}
	if err := model.DecodeControllerTransportReceipt(
		run("controller-prepare", prepareRequest2), "controller-prepare", &prepared2); err != nil {
		t.Fatalf("Sandbox controller-prepare receipt refused after resume: %v", err)
	}
	headerRequest2 := parentRequest(parent)
	headerRequest2["preparedReceipt"] = prepared2.PreparedReceipt
	headerRequest2["policyDigest"] = deepSeekPin("b")
	var header2 struct {
		SchemaVersion     int                                      `json:"schemaVersion"`
		Command           string                                   `json:"command"`
		Status            string                                   `json:"status"`
		HeaderObservation model.ControllerAuthorizationObservation `json:"headerObservation"`
	}
	if err := model.DecodeControllerTransportReceipt(
		run("controller-header", headerRequest2), "controller-header", &header2); err != nil {
		t.Fatalf("Sandbox controller-header refused after resume: %v", err)
	}
	if header2.Status != "observed" || header2.HeaderObservation.PreparationID != "preparation_2" {
		t.Fatalf("resumed controller-header observation = %#v", header2)
	}
	admission2 := model.ControllerAdmission{
		FormatVersion:   1,
		TargetKind:      "controller_activity",
		PreparedReceipt: prepared2.PreparedReceipt,
		Grant: func() model.ControllerActivityGrant {
			grant := admission.Grant
			grant.GrantID = "grant_2"
			grant.PreparationID = "preparation_2"
			grant.PreparedReceiptDigest = prepared2.PreparedReceipt.PreparedReceiptDigest
			return grant
		}(),
	}
	promptRequest2 := parentRequest(parent)
	promptRequest2["admission"] = admission2
	promptRequest2["text"] = text2
	var prompt2 struct {
		SchemaVersion   int             `json:"schemaVersion"`
		Command         string          `json:"command"`
		Status          string          `json:"status"`
		NativeAdmission json.RawMessage `json:"nativeAdmission"`
	}
	if err := model.DecodeControllerTransportReceipt(
		run("controller-prompt", promptRequest2), "controller-prompt", &prompt2); err != nil {
		t.Fatalf("Sandbox controller-prompt refused after resume: %v", err)
	}
	if prompt2.Status != "admitted" || len(prompt2.NativeAdmission) == 0 {
		t.Fatalf("resumed controller-prompt receipt = %#v", prompt2)
	}
	outputRequest2 := parentRequest(parent)
	outputRequest2["admission"] = admission2
	var output2 struct {
		SchemaVersion int                                  `json:"schemaVersion"`
		Command       string                               `json:"command"`
		Status        string                               `json:"status"`
		NativeOutput  model.ControllerOutputNativeReadback `json:"nativeOutput"`
		NativeLog     []json.RawMessage                    `json:"nativeLog"`
	}
	if err := model.DecodeControllerTransportReceipt(
		run("controller-output", outputRequest2), "controller-output", &output2); err != nil {
		t.Fatalf("Sandbox controller-output refused after resume: %v", err)
	}
	if output2.Status != "observed" || len(output2.NativeLog) <= len(output.NativeLog) {
		t.Fatalf("resumed controller-output = %s", output2.Status)
	}
	capture2 := qualification.ControllerCapture{NativeOutput: output2.NativeOutput, NativeLog: output2.NativeLog}
	lineage2, err := capture2.Verify(text2, identityJSON, admission2)
	if err != nil {
		t.Fatalf("Runtime qualification refused the resumed controller output capture: %v", err)
	}
	if lineage2.OutputText != "controller output\n" {
		t.Fatalf("resumed output lineage = %#v", lineage2)
	}
}

func deepSeekPortFree(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

// runDeepSeekSupervisorAllowingRefusal returns the typed refusal receipt even
// when the supervisor exits nonzero (expected for the duplicate dispatch).
func runDeepSeekSupervisorAllowingRefusal(t *testing.T, python, script, root, launcher, controller, command string, payload any) ([]byte, error) {
	t.Helper()
	requestRaw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	call := exec.Command(python, script, command, "--root", root, "--launcher", launcher, "--controller", controller)
	call.Stdin = bytes.NewReader(requestRaw)
	var stderr bytes.Buffer
	call.Stderr = &stderr
	output, err := call.Output()
	if len(bytes.TrimSpace(output)) == 0 {
		t.Fatalf("Sandbox supervisor %s returned no typed receipt: %v %s", command, err, stderr.String())
	}
	lines := bytes.Split(bytes.TrimSpace(output), []byte("\n"))
	return lines[len(lines)-1], err
}

func runDeepSeekSupervisor(t *testing.T, python, script, root, launcher, controller, command string, payload any) []byte {
	t.Helper()
	requestRaw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	call := exec.Command(python, script, command, "--root", root, "--launcher", launcher, "--controller", controller)
	call.Stdin = bytes.NewReader(requestRaw)
	var stderr bytes.Buffer
	call.Stderr = &stderr
	output, err := call.Output()
	if err != nil {
		t.Fatalf("Sandbox supervisor %s failed: %v\nstdout=%s\nstderr=%s", command, err, output, stderr.String())
	}
	lines := bytes.Split(bytes.TrimSpace(output), []byte("\n"))
	if len(lines) == 0 || len(bytes.TrimSpace(lines[len(lines)-1])) == 0 {
		t.Fatalf("Sandbox supervisor %s returned no receipt: %s", command, stderr.String())
	}
	return lines[len(lines)-1]
}

const deepSeekFakeACPLauncher = `#!/usr/bin/env python3
import json
import os
import sys

sessions_path = os.environ.get("WM_FAKE_ACP_SESSIONS")


def persisted():
    try:
        with open(sessions_path, encoding="utf-8") as stream:
            return {line.strip() for line in stream if line.strip()}
    except (OSError, TypeError):
        return set()


def persist(value):
    if not sessions_path:
        return
    with open(sessions_path, "a", encoding="utf-8") as stream:
        stream.write(value + "\n")


def send(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


session = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    message = json.loads(line)
    if "result" in message or "error" in message:
        continue
    method = message.get("method")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": 1, "agentCapabilities": {"sessionCapabilities": {"resume": {}}}}})
        send({"jsonrpc": "2.0", "id": "permission-1", "method": "session/request_permission", "params": {"options": ["allow", "deny"]}})
    elif method == "session/new":
        session += 1
        session_id = "acp-session-uuid-" + str(session) + "-" + os.urandom(4).hex()
        persist(session_id)
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"sessionId": session_id}})
    elif method in ("session/resume", "session/load"):
        requested = (message.get("params") or {}).get("sessionId")
        if requested and requested in persisted():
            send({"jsonrpc": "2.0", "id": message["id"], "result": {"configOptions": []}})
        else:
            send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32002, "message": "session not found"}})
    elif method == "session/prompt":
        os.write(2, b"session/prompt\n")
        send({"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": message["params"]["sessionId"],
            "update": {"sessionUpdate": "agent_message_chunk", "messageId": "msg_test",
                       "content": {"type": "text", "text": "controller output\n"}}}})
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"stopReason": "end_turn"}})
    else:
        send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "unknown method"}})
`

// deepSeekMakeWritable restores test-only permissions on the immutable expertise
// publication so the temporary sandbox root can be removed.
func deepSeekMakeWritable(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		mode := os.FileMode(0o600)
		if info.IsDir() {
			mode = 0o700
		}
		_ = os.Chmod(path, mode)
		return nil
	})
}
