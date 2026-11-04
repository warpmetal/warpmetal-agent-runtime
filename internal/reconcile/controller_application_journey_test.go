package reconcile

// Source composition journey: real Runtime/Reconciler, SQLite reopen, registered
// filesystem catalog and TLS API transport. Mocks are explicitly the backend
// authorization/acceptance, existing ready engine receipt and Sandbox/native
// helper transport. The separate Sandbox subprocess journey tests that helper.
// No installed-native, real registered signer, model/provider or live acceptance.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type parentSourceRuntime struct {
	t           *testing.T
	store       *state.Store
	parents     []model.ControllerParentIntent
	calls       []managedInvocation
	sessions    map[string]string
	roots       map[string]string
	lostStart   bool
	key         *ecdsa.PrivateKey
	now         func() time.Time
	attestCalls int
	helper      *sourceSupervisorHelper
	sourceHTTP  func(http.ResponseWriter, *http.Request) bool
}

// Explicit SOURCE applicability/lease supplier. These methods must never turn
// absent originals into an installed/native preparation in this boundary check.
type firstTaskSourceRuntime struct{ *parentSourceRuntime }

// Native/install/key/backend suppliers are explicitly SOURCE substitutes. The
// normal Reconciler, node TLS routes and durable operation/proof/lease joins run.
type firstTaskEnrollmentSourceRuntime struct{ *firstTaskSourceRuntime }

func (s *firstTaskEnrollmentSourceRuntime) ReadControllerFirstTaskApplicability(_ context.Context, _ model.Manifest, w qualification.ControllerPolicyWitness) (qualification.Applicability, error) {
	o := w.Identity.Intent.Owner
	return qualification.Applicability{AccountID: o.AccountID, TaskID: o.TaskID, ServerID: o.ServerID, SandboxID: o.SandboxID, SandboxGeneration: o.SandboxGeneration, Connection: *w.Identity.Projection.ModelSelection.CredentialBinding}, nil
}
func (s *firstTaskEnrollmentSourceRuntime) AttestWorkflowRole(_ context.Context, op model.WorkflowRoleOperation, w qualification.WorkspaceApplicationWitness, registered model.WorkspaceRegisteredProducer) (model.WorkflowRoleEnvelope, error) {
	n := w.Report.NativeRegistration
	stamp := s.now().Format(time.RFC3339Nano)
	p := model.WorkflowRolePayload{FormatVersion: 1, Purpose: "workspace_workflow_role", RequestID: "wfrole_receipt_" + op.OperationDigest[7:39], TaskID: op.Subject.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: op.ManagedServiceReceiptDigest, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Subject: op.Subject, NativeContextDigest: op.NativeContextDigest, NativeReceipt: model.WorkflowRoleNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: w.Parent.ServiceRegistrationID, ServiceGeneration: w.Parent.ServiceGeneration, NativeSessionID: n.NativeSessionID, NativeProjectID: n.NativeProjectID, NativeLocationDigest: n.NativeLocationDigest, Role: w.Parent.Role, RootAttestation: w.Parent.Workspace.RootAttestation, ObservedAt: stamp, Readback: model.WorkflowRoleReadback{Subject: op.Subject, NativeContextDigest: op.NativeContextDigest}}}
	raw, _ := model.WorkspaceCanonicalJSON(p)
	h := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	return model.WorkflowRoleEnvelope{Payload: p, KeyID: registered.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}, err
}

func (*firstTaskSourceRuntime) VerifyControllerPolicy(context.Context, model.Sandbox, string, qualification.ControllerPolicyWitness) (qualification.ControllerPolicy, error) {
	return qualification.ControllerPolicy{}, ErrControllerActivityPending
}
func (*firstTaskSourceRuntime) ReadControllerActivation(context.Context, model.Sandbox, qualification.ControllerPolicy, model.ControllerPreparedReceipt, bool) (qualification.ControllerActivation, error) {
	return qualification.ControllerActivation{}, ErrControllerActivityPending
}
func (*firstTaskSourceRuntime) AttestControllerPrepared(context.Context, model.ControllerPreparedReceipt, qualification.ControllerOutputWitness) (model.ControllerPreparedEnvelope, error) {
	return model.ControllerPreparedEnvelope{}, ErrControllerActivityPending
}
func (*firstTaskSourceRuntime) AttestControllerOutput(context.Context, model.ControllerOutputOperation, qualification.ControllerCapture, qualification.ControllerOutputWitness) (model.ControllerOutputEnvelope, error) {
	return model.ControllerOutputEnvelope{}, ErrControllerActivityPending
}
func (*firstTaskSourceRuntime) ObserveControllerAuthorization(context.Context, model.ControllerPreparedReceipt, qualification.ControllerOutputWitness) (model.ControllerAuthorizationEnvelope, error) {
	return model.ControllerAuthorizationEnvelope{}, ErrControllerActivityPending
}

// Explicit SYNTHETIC root-key authority. Production uses NewProducer's root-only
// key/evidence protections; the qualification witness test checks the real typed
// payload/root binding. This mock signs the actual closed wire for TLS verification.
func (s *parentSourceRuntime) AttestWorkspaceApplication(_ context.Context, readback model.WorkspaceApplicationReadback, witnesses []qualification.WorkspaceApplicationWitness) (model.WorkspaceApplicationEnvelope, error) {
	s.attestCalls++
	parents := []model.ControllerParentIntent{}
	reports := []model.ControllerParentReport{}
	for _, w := range witnesses {
		parents = append(parents, w.Parent)
		reports = append(reports, w.Report)
	}
	if err := readback.Validate(parents, reports); err != nil {
		return model.WorkspaceApplicationEnvelope{}, err
	}
	op := readback.Operation
	manager := readback.RoleBindings[0]
	stamp := s.now().Format(time.RFC3339Nano)
	payload := model.WorkspaceApplicationPayload{FormatVersion: 1, Purpose: "workspace_workflow_application", RequestID: "wfapp_receipt_source", TaskID: op.TaskID, NodeTokenHash: op.Producer.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: reports[0].ReceiptDigest, OperationID: op.OperationID, OperationDigest: op.OperationDigest,
		NativeReceipt: model.WorkspaceApplicationNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: manager.Binding.ServiceRegistrationID, ServiceGeneration: manager.Binding.ServiceGeneration, NativeSessionID: manager.NativeRegistration.NativeSessionID, NativeProjectID: manager.NativeRegistration.NativeProjectID, NativeLocationDigest: manager.NativeRegistration.NativeLocationDigest, Role: "manager", RootAttestation: parents[0].Workspace.RootAttestation, ObservedAt: stamp, Readback: readback}}
	body, _ := model.WorkspaceCanonicalJSON(payload)
	sum := sha256.Sum256(body)
	signature, err := ecdsa.SignASN1(rand.Reader, s.key, sum[:])
	return model.WorkspaceApplicationEnvelope{Payload: payload, KeyID: op.Producer.KeyID, Signature: base64.StdEncoding.EncodeToString(signature)}, err
}

func (s *parentSourceRuntime) ExecManagedWorker(context.Context, string, containers.ManagedWorkerAction, []byte) ([]byte, []byte, error) {
	s.t.Fatal("parent dispatched worker")
	return nil, nil, nil
}
func (s *parentSourceRuntime) ExecManagedSupervisor(_ context.Context, sandbox string, action containers.ManagedSupervisorAction, raw []byte) ([]byte, []byte, error) {
	var request map[string]any
	_ = json.Unmarshal(raw, &request)
	s.calls = append(s.calls, managedInvocation{string(action), request})
	if s.helper != nil {
		return s.helper.call(action, request)
	}
	instance, _ := request["instance"].(string)
	receipt := map[string]any{"schemaVersion": 1, "command": string(action), "status": "ready", "ready": true, "sandboxId": sandbox, "instance": instance, "profileId": "opencode", "receiptDigest": "sha256:" + strings.Repeat("a", 64)}
	if action == containers.ManagedSupervisorMaterializeProfile {
		receipt["appliedProfile"] = request["expected"]
		receipt["materializerDigest"] = request["materializerDigest"]
	} else {
		var parent model.ControllerParentIntent
		for _, p := range s.parents {
			if p.Instance == instance {
				parent = p
			}
		}
		if parent.Instance == "" {
			s.t.Fatal("unowned parent helper invocation")
		}
		role := parent.Role
		port := 18444
		if role == "orchestrator" {
			port = 18445
		}
		if action == containers.ManagedSupervisorStart {
			if request["controllerParent"] == nil || request["roleProjection"] == nil || request["monitorEnabled"] != false || request["port"] != float64(port) {
				s.t.Fatalf("bad dedicated launch: %#v", request)
			}
			if s.sessions[instance] != "" && request["sessionMode"] != "lookup_only" {
				s.t.Fatal("creation replayed after durable/reopened dispatch")
			}
			if s.sessions[instance] == "" {
				s.sessions[instance] = "ses_source_" + role
			}
			if s.roots == nil {
				s.roots = map[string]string{}
			}
			s.roots[instance] = request["projectRoot"].(string)
			if s.lostStart {
				s.lostStart = false
				return nil, nil, fmt.Errorf("source mock: lost start response")
			}
		}
		if action == containers.ManagedSupervisorRegisterSource {
			registration := request["registration"].(map[string]any)
			source := registration["source"].(map[string]any)
			identity := registration["identity"].(map[string]any)
			if registration["formatVersion"] != float64(2) || identity["teamId"] != nil || identity["memberId"] != nil {
				s.t.Fatal("parent relabeled Team member")
			}
			receipt = map[string]any{"schemaVersion": 1, "command": "register-source", "status": "registered", "ready": false, "instance": instance, "sandboxId": sandbox, "profileId": "opencode", "serviceRegistrationId": parent.ServiceRegistrationID, "serviceGeneration": parent.ServiceGeneration, "registeredSourceId": source["registeredSourceId"], "workspaceEpoch": identity["workspaceEpoch"], "nativeSessionId": source["nativeSessionId"], "nativeProjectId": source["nativeProjectId"], "nativeLocationDigest": source["nativeLocationDigest"], "profileRevision": identity["profileRevision"], "profileDigest": identity["profileDigest"], "instructionRevision": identity["instructionRevision"], "instructionDigest": identity["instructionDigest"]}
		} else {
			receipt["phase"] = "running"
			receipt["pid"] = port
			receipt["port"] = port
			receipt["sessionId"] = s.sessions[instance]
			receipt["profileDigest"] = parent.Profile.ProfileDigest
			receipt["profileRevision"] = parent.Profile.ProfileRevision
			receipt["nativeProjectId"] = strings.Repeat("a", 40)
			receipt["nativeLocationDigest"] = model.WorkspaceDigest(map[string]any{"directory": s.roots[instance], "projectId": strings.Repeat("a", 40), "workspaceId": nil})
			receipt["instructionApplied"] = true
			receipt["instructionRevision"] = parent.Instructions.InstructionRevision
			receipt["instructionDigest"] = parent.Instructions.InstructionDigest
			receipt["materializerDigest"] = controllerMaterializerCandidateDigest
			receipt["nativeRoleReadback"] = model.ControllerRoleReadback{Role: role, NativeAgentID: "warpmetal-controller-" + role, SessionAgentID: "warpmetal-controller-" + role, RoleAgentDigest: parent.RoleAgentDigest}
			if action == containers.ManagedSupervisorStatus {
				i := model.ControllerIdentity{Intent: parent}
				for _, call := range s.calls {
					if call.request["instance"] != instance {
						continue
					}
					if call.action == string(containers.ManagedSupervisorStart) {
						raw, _ := json.Marshal(call.request["roleProjection"])
						_ = json.Unmarshal(raw, &i.Projection)
					}
					if call.action == string(containers.ManagedSupervisorRegisterSource) {
						raw, _ := json.Marshal(call.request["registration"])
						_ = json.Unmarshal(raw, &i.Source)
					}
				}
				if i.Source.FormatVersion == 2 {
					if i.Projection.ModelSelection != nil && i.Projection.ModelSelection.Authority.ProviderID == providerpolicy.Flash().ProviderID {
						var err error
						i, err = i.DeriveWM8NativeIdentity()
						if err != nil {
							s.t.Fatal("SOURCE native identity derivation", err)
						}
					}
					receipt["binding"] = map[string]any{"identity": i, "state": "registered", "preparedReceipt": nil}
				}
			}
		}
	}
	bytes, err := json.Marshal(receipt)
	return bytes, nil, err
}

func sourceParentApplication(t *testing.T, j *managerPolicyJourney, workspaceOverride ...model.ManagedServiceWorkspaceV1) (model.WorkspaceApplicationOperation, []model.ControllerParentIntent) {
	t.Helper()
	d := "sha256:" + strings.Repeat("c", 64)
	ref := model.ApprovedExpertiseProfile{ProfileID: "expert_source", ProfileRevision: 1, ProfileDigest: d, BundleDigest: d}
	config := model.WorkspaceConfiguration{FormatVersion: 1, WorkspaceName: "Source fixture", Purpose: "Parent metadata only", Profiles: []model.WorkspaceProfileDeclaration{{ProfileID: "profile_source", Name: "Source profile", ApprovedProfile: &ref, Tools: []model.WorkspaceTool{}}}, Roles: model.WorkspaceRoleDeclaration{ManagerProfileID: "profile_source", AdvisorProfileID: "profile_source"}, Lanes: []model.WorkspaceLaneDeclaration{}}
	owner := model.ControllerOwner{AccountID: "account_source", TaskID: "task_source", ServerID: j.reconciler.ServerID, SandboxID: j.fixture.SetupManifest.SandboxID, SandboxGeneration: 2, CellID: "cell_source", ControllerID: "controller_source", ControllerRevision: 1, AuthorityRevision: 1}
	engine := j.fixture.ServiceManifest.Profile
	workspace := j.fixture.ServiceManifest.Workspace
	if len(workspaceOverride) > 0 {
		workspace = workspaceOverride[0]
	}
	registeredRoot, err := j.store.ManagedProject(context.Background(), workspace.SelectionID)
	if err != nil || registeredRoot == nil {
		t.Fatalf("registered source root: %v", err)
	}
	workspace.ScopeRevision = registeredRoot.ScopeRevision
	setup, err := j.store.SetupOperation(context.Background(), engine.SetupOperationID)
	if err != nil {
		t.Fatal(err)
	}
	instruction := "PRIVATE_INSTRUCTION_SOURCE_SENTINEL reviewed recipe bytes.\n"
	system := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(instruction)))
	// Same version-1 wire the WP-40 composer emits. The empty deny-by-default
	// closure is the only controller-parent surface the Runtime stages.
	closure := &model.WorkspaceToolClosure{FormatVersion: 1, Policy: "deny_by_default", NativeEditCeiling: model.WorkspaceNativeEditCeiling{Mode: "workspace_scoped", Tools: []string{"write", "edit", "patch"}}, Tools: []model.WorkspaceTool{}, MCP: model.WorkspaceMCPClosure{Mode: "disabled", Allow: []model.WorkspaceConnectorApproval{}}, Delegation: "denied", Subagents: "denied", HostNetwork: "denied"}
	closureDigest := model.WorkspaceDigest(closure)
	if closureDigest == "" {
		t.Fatal("source closure digest")
	}
	bindings := []model.ApplicationRoleTarget{}
	roles := []model.ApplicationRoleDependency{}
	for _, role := range []string{"manager", "orchestrator"} {
		binding := model.ApplicationRoleTarget{Owner: owner, Role: role, ServiceRegistrationID: "parent_source_" + role, ServiceGeneration: 1, ApprovedProfile: ref}
		bindings = append(bindings, binding)
		roles = append(roles, model.ApplicationRoleDependency{Binding: binding, Projection: model.ControllerRoleProjection{NativeAgentID: "warpmetal-controller-" + role, SystemDigest: system, ApprovedProfile: ref, ToolsDisabled: true, MCPDisabled: true, ToolClosureDigest: closureDigest}, Instructions: model.ManagedServiceInstructionsV1{InstructionRevision: 1, InstructionDigest: system}, Workspace: workspace, Profile: engine})
	}
	deps := model.WorkspaceApplicationDependencies{FormatVersion: 1, Phase: "prompt_free", SetupReceipts: []model.ApplicationSetupReceipt{{SetupOperationID: setup.ID, ReceiptDigest: setup.ReceiptDigest}}, Profiles: []model.AppliedExpertiseProfile{{ApprovedProfile: ref, EntryPath: "expert/README.md", Files: []model.ExpertiseFile{{Path: "expert/README.md", SHA256: system, ByteCount: int64(len(instruction))}}}}, Roles: roles, Tools: []model.WorkspaceTool{}, ToolClosure: closure}
	op := model.WorkspaceApplicationOperation{FormatVersion: 1, Kind: "configuration_application", OperationID: "wfapp_source_journey", AccountID: owner.AccountID, TaskID: owner.TaskID, ServerID: owner.ServerID, SandboxID: owner.SandboxID, SandboxGeneration: owner.SandboxGeneration, SetupIntentID: "setup_intent_source", ConfigurationID: "configuration_source", ConfigurationRevision: 1, ConfigurationDigest: model.WorkspaceDigest(config), TargetRuntimeRevision: j.manifest.DesiredRevision, SetupOperationIDs: []string{setup.ID}, Profiles: []model.ApprovedExpertiseProfile{ref}, MaterializerDigest: controllerMaterializerCandidateDigest, RoleBindings: bindings, Limits: config.Limits, Configuration: config, Dependencies: deps, DependencyDigest: model.WorkspaceDigest(deps), ConnectionRevisionDigest: model.WorkspaceDigest([]any{map[string]any{"profileId": "profile_source", "credentialBinding": nil}}), ModelAuthorityDigest: model.WorkspaceDigest([]any{map[string]any{"profileId": "profile_source", "authority": nil}}), Producer: model.WorkspaceRegisteredProducer{KeyID: "source_key", KeySHA256: d, ServerID: owner.ServerID, NodeTokenHash: strings.Repeat("d", 64)}, ExpiresAt: j.reconciler.now().Add(300000000000).Format("2006-01-02T15:04:05Z07:00")}
	raw, _ := json.Marshal(op)
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	delete(object, "operationDigest")
	op.OperationDigest = model.WorkspaceDigest(object)
	if err := op.Validate(); err != nil {
		t.Fatal(err)
	}
	parents := []model.ControllerParentIntent{}
	for _, role := range roles {
		p := model.ControllerParentIntent{FormatVersion: 2, TargetKind: "controller_parent", OperationID: op.OperationID, ActionRevision: 1, DesiredRevision: 1, DesiredState: "active", SessionMode: "create_initial", Owner: owner, Role: role.Binding.Role, ServiceRegistrationID: role.Binding.ServiceRegistrationID, ServiceGeneration: 1, Profile: engine, Instructions: role.Instructions, Workspace: workspace, ApplicationOperationID: op.OperationID, ConnectionRevisionDigest: op.ConnectionRevisionDigest, ModelAuthorityDigest: op.ModelAuthorityDigest, RoleAgentDigest: model.WorkspaceDigest(role.Projection), RuntimeContractVersion: "0.1.52"}
		p.Instance = fmt.Sprintf("parent-%s-%x", p.Role, sha256.Sum256([]byte(p.ServiceRegistrationID)))[:len("parent-"+p.Role+"-")+12]
		bytes, _ := json.Marshal(p)
		object = map[string]any{}
		_ = json.Unmarshal(bytes, &object)
		delete(object, "configDigest")
		p.ConfigDigest = model.WorkspaceDigest(object)
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		parents = append(parents, p)
	}
	return op, parents
}

// seedControllerParentCellWorkspace registers the backend-authorized cell
// workspace selection the controller parents run on: the ordinary-directory
// team_project EnsureCellDefault creates, with NO Git repository, owned by the
// same cell id the parent application owners carry (R-WP94-2). The real
// installed cell has this exact layout; the prior source journey used a member
// project and therefore never exercised the controller-parent cell resolve.
func seedControllerParentCellWorkspace(t *testing.T, j *managerPolicyJourney, ownerCellID string) model.ManagedServiceWorkspaceV1 {
	t.Helper()
	anchor := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(anchor, 0700); err != nil {
		t.Fatal(err)
	}
	catalog := &workspacecatalog.Catalog{State: j.store, Now: j.reconciler.now}
	project, err := catalog.EnsureCellDefault(context.Background(), workspacecatalog.CellDefaultProjectRequest{
		Anchor: anchor, ServerID: j.reconciler.ServerID,
		SandboxID: j.fixture.SetupManifest.SandboxID, SandboxGeneration: 2,
		ServiceRegistrationID: "service_parent_cell_source",
		AllocationDigest:      "sha256:" + strings.Repeat("e", 64),
		OwnerCellID:           ownerCellID, OwnerRole: "manager", OwnerGeneration: 1,
		SelectionID: "sel_parent_cell_source", ProjectID: "global",
		WorkspaceEpoch: "wpe_parent_cell_source", ScopeRevision: 1,
	})
	if err != nil {
		t.Fatalf("seed controller-parent cell workspace: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(project.HostRoot, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("controller-parent cell workspace carries Git metadata: %v", err)
	}
	return model.ManagedServiceWorkspaceV1{
		SelectionID: project.Report.SelectionID, ProjectID: project.Report.ProjectID,
		WorkspaceEpoch: project.Report.WorkspaceEpoch, ScopeRevision: project.ScopeRevision,
		Designation: project.Report.Designation, RootAttestation: project.Report.RootAttestation,
	}
}

func TestControllerParentSourceJourneyReconcileReadyAndReopen(t *testing.T) {
	var diagnostics bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&diagnostics)
	defer log.SetOutput(previous)
	runControllerParentSourceJourney(t, false)
	if strings.Contains(diagnostics.String(), "PRIVATE_INSTRUCTION_SOURCE_SENTINEL") {
		t.Fatal("controller startup diagnostics exposed private instruction content")
	}
}

// TestControllerParentCellWorkspaceSourceJourneyReconcileReadyAndReopen runs
// the exact same parent application journey on the real no-git cell workspace:
// the controller-parent resolve must use the cell-aware path, stage profiles,
// start both parents, attest the application root, survive SQLite reopen and
// keep the retained application identity.
func TestControllerParentCellWorkspaceSourceJourneyReconcileReadyAndReopen(t *testing.T) {
	runControllerParentSourceJourneyFor(t, false, true)
}

func TestOwnerFirstTaskCurrentReconcileRetainsOriginalBeforePreparation(t *testing.T) {
	runControllerParentSourceJourney(t, false, false, true)
}

func TestOwnerFirstTaskNormalParentSelectorAndBoundedObservation(t *testing.T) {
	runControllerParentSourceJourney(t, false, false, true, true)
}

func TestOwnerFirstTaskNormalRoleEnrollmentAndDurableAttachment(t *testing.T) {
	if os.Getenv("WARPMETAL_CHILD_ISSUER_SOURCE") != "" {
		t.Run("current_child_delivery2", testCurrentChildIssuerSource)
	}
	if os.Getenv("WARPMETAL_PARENT_OPERATOR_SOURCE") != "" {
		t.Run("current_parent_operator_delivery4", testCurrentParentOperatorDeliverySource)
	}
	if os.Getenv("WARPMETAL_SINGLE_CONTEXT_SOURCE") != "" {
		t.Run("closed_single_context4", testCurrentSingleContextSource)
	}
	if os.Getenv("WARPMETAL_SINGLE_OUTPUT_SOURCE") != "" {
		t.Run("current_parent_output4", testCurrentSingleParentOutputSource)
	}
	runControllerParentSourceJourney(t, os.Getenv("F3_SANDBOX_SOURCE") != "", false, true, false, true)
	t.Run("closed_provider2", func(t *testing.T) {
		selection := &model.WorkspaceModelSelection{Authority: model.CellPreparedAuthorityV3{ProviderID: "deepseek", ModelID: "deepseek-flash", AuthMode: "api_key"}, CredentialBinding: &model.CellCredentialBindingV3{ConnectionID: "source_flash_connection", ConnectionRevision: 1, ProviderID: "deepseek", AuthMode: "api_key"}}
		runControllerParentSourceJourneyAccepted(t, false, false, selection, nil, false, true, false, true)
	})
}

// Continuation from explicitly retained SOURCE acceptance originals. Normal
// enrollment still runs; child prepare/execute are driven ONLY by Reconcile's
// manifest passes. No test calls a parent/child dispatch or binds a role lease.
func TestOwnerFirstTaskAcceptedManagerChildTerminalAcrossNormalPasses(t *testing.T) {
	if os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET") == "" || os.Getenv("WARPMETAL_CONTROLLER_OUTPUT_SOURCE_FIXTURE") == "" {
		t.Skip("requires documented retained SOURCE context/native-output transport fixtures")
	}
	for _, scenario := range []struct {
		name               string
		lostChildPrepare   bool
		undeliveredPrepare bool
	}{{"completed", false, false}, {"lost-child-prepare-ACK", true, false}, {"undelivered-child-prepare-policy", false, true}} {
		t.Run(scenario.name, func(t *testing.T) {
			runControllerParentSourceJourney(t, false, false, true, false, true, false, true, scenario.lostChildPrepare, scenario.undeliveredPrepare)
		})
	}
}

// SAME journey, fresh public delivery rather than retained grant/policy/admission
// authority. Root ownership and upstream native/qualification facts are SOURCE.
func TestOwnerFirstTaskNormalPublicOperatorDeliveryAcrossNormalPasses(t *testing.T) {
	if os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET") == "" || os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE") == "" {
		t.Skip("requires retained SOURCE fixtures")
	}
	runControllerParentSourceJourney(t, false, false, true, false, true, false, true, false, false, true)
}
func TestOwnerFirstTaskNormalRoleEnrollmentLostAckNeverReissues(t *testing.T) {
	runControllerParentSourceJourney(t, false, false, true, false, true, true)
}

func TestControllerParentSourceLostLaunchResponseUsesLookupOnly(t *testing.T) {
	runControllerParentSourceJourney(t, false, true)
}

func TestControllerParentComposedSandboxSourceJourney(t *testing.T) {
	if os.Getenv("F3_SANDBOX_SOURCE") == "" {
		t.Skip("source composition requires F3_SANDBOX_SOURCE; Sandbox/native fixture is not installed proof")
	}
	runControllerParentSourceJourney(t, true)
}

// Named mount-namespace substitution ONLY: source fixture has no container
// namespace. Every real catalog root/dev/inode/attestation check is retained;
// native sees that exact host root as its container directory, without aliases.
type sourceSharedFilesystemCatalog struct{ *workspacecatalog.Catalog }

func (c sourceSharedFilesystemCatalog) Resolve(ctx context.Context, request workspacecatalog.ResolveProjectRequest) (workspacecatalog.RegisteredProject, error) {
	project, err := c.Catalog.Resolve(ctx, request)
	if err != nil {
		return project, err
	}
	project.ContainerRoot, err = filepath.EvalSymlinks(project.HostRoot)
	return project, err
}

type sourceSupervisorHelper struct {
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	stderr  bytes.Buffer
	command *exec.Cmd
}

func (s *sourceSupervisorHelper) call(action containers.ManagedSupervisorAction, request map[string]any) ([]byte, []byte, error) {
	raw, _ := json.Marshal(map[string]any{"action": string(action), "request": request})
	raw = append(raw, '\n')
	if _, err := s.stdin.Write(raw); err != nil {
		return nil, nil, err
	}
	output, err := s.stdout.ReadBytes('\n')
	var failure struct {
		Error  string `json:"sourceFixtureError"`
		Status string `json:"status"`
		Code   string `json:"error"`
	}
	_ = json.Unmarshal(output, &failure)
	if failure.Error != "" {
		return nil, nil, fmt.Errorf("source fixture %s: %s", action, failure.Error)
	}
	if failure.Status == "failed" {
		return output, nil, fmt.Errorf("source Supervisor %s failed: %s", action, failure.Code)
	}
	return output, nil, err
}

func runControllerParentSourceJourney(t *testing.T, composed bool, lostLaunch ...bool) {
	runControllerParentSourceJourneyFor(t, composed, false, lostLaunch...)
}

func runControllerParentSourceJourneyFor(t *testing.T, composed, cellWorkspace bool, lostLaunch ...bool) {
	runControllerParentSourceJourneyAccepted(t, composed, cellWorkspace, nil, nil, lostLaunch...)
}

// Test-only seam for exporting pre-execution signed SOURCE documents after the
// same accepted application/reopen journey. It grants no native output credit.
func runControllerParentSourceJourneyAccepted(t *testing.T, composed, cellWorkspace bool, selectionOverride *model.WorkspaceModelSelection, acceptedHook func(*managerPolicyJourney, *parentSourceRuntime, model.WorkspaceApplicationOperation, []model.ControllerParentIntent), lostLaunch ...bool) {
	var j *managerPolicyJourney
	if os.Getenv("WARPMETAL_CHILD_COMPLETION_SOURCE") == "1" {
		// Fresh generated SOURCE authorities share one actual clock. Retained
		// native event/history bytes are not retimed or granted execution credit.
		captured := time.Now().UTC()
		j = newManagerPolicyJourneyForSandboxAt(t, "sbx_"+strings.Repeat("s", 24), func() time.Time { return captured })
	} else {
		j = newManagerPolicyJourneyForSandbox(t, "sbx_"+strings.Repeat("s", 24))
	}
	ctx := context.Background()
	var workspaceOverride []model.ManagedServiceWorkspaceV1
	if cellWorkspace {
		workspaceOverride = []model.ManagedServiceWorkspaceV1{seedControllerParentCellWorkspace(t, j, "cell_source")}
	}
	op, parents := sourceParentApplication(t, j, workspaceOverride...)
	firstTask := len(lostLaunch) > 1 && lostLaunch[1]
	if firstTask {
		if len(lostLaunch) > 2 && lostLaunch[2] {
			if _, ok := any(j.reconciler).(interface {
				ReadControllerFirstTaskParentPreparation(context.Context, string, string) (model.ControllerPreparedReceipt, error)
			}); !ok {
				t.Fatal("normal first task has no original initialDecision selector/bounded read-only completion boundary")
			}
		}
		selection := &model.WorkspaceModelSelection{Authority: model.CellPreparedAuthorityV3{ProviderID: "openai", ModelID: qualification.RealModel, AuthMode: "api_key"}, CredentialBinding: &model.CellCredentialBindingV3{ConnectionID: "source_connection", ConnectionRevision: 1, ProviderID: "openai", AuthMode: "api_key"}}
		if selectionOverride != nil {
			selection = selectionOverride
		}
		op.Configuration.Profiles[0].ModelSelection = selection
		op.ConfigurationDigest = model.WorkspaceDigest(op.Configuration)
		op.ConnectionRevisionDigest = model.WorkspaceDigest([]any{map[string]any{"profileId": "profile_source", "credentialBinding": selection.CredentialBinding}})
		op.ModelAuthorityDigest = model.WorkspaceDigest([]any{map[string]any{"profileId": "profile_source", "authority": selection.Authority}})
		for i := range parents {
			op.Dependencies.Roles[i].Projection.ModelSelection = selection
			parents[i].RoleAgentDigest = model.WorkspaceDigest(op.Dependencies.Roles[i].Projection)
			parents[i].ConnectionRevisionDigest = op.ConnectionRevisionDigest
			parents[i].ModelAuthorityDigest = op.ModelAuthorityDigest
			raw, _ := json.Marshal(parents[i])
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(raw, &fields)
			delete(fields, "configDigest")
			parents[i].ConfigDigest = model.WorkspaceDigest(fields)
		}
		op.DependencyDigest = model.WorkspaceDigest(op.Dependencies)
	}
	instructions := map[string]string{"manager": "PRIVATE_INSTRUCTION_SOURCE_SENTINEL reviewed recipe bytes.\n", "orchestrator": "PRIVATE_INSTRUCTION_SOURCE_SENTINEL reviewed recipe bytes.\n"}
	bundle := json.RawMessage(`{"manifest":{},"blobs":{}}`)
	var helper *sourceSupervisorHelper
	var childJourney *firstTaskChildTerminalFixture
	catalog := j.reconciler.ManagedCatalog.(*workspacecatalog.Catalog)
	if composed {
		root, err := j.store.ManagedProject(ctx, parents[0].Workspace.SelectionID)
		if err != nil {
			t.Fatal(err)
		}
		helper = &sourceSupervisorHelper{command: exec.Command("python3", "testdata/controller_parent_source_helper.py")}
		helper.command.Stderr = &helper.stderr
		stdout, err := helper.command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		helper.stdout = bufio.NewReader(stdout)
		helper.stdin, err = helper.command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := helper.command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			helper.stdin.Close()
			if err := helper.command.Wait(); err != nil {
				t.Errorf("source Supervisor fixture: %v %s", err, helper.stderr.String())
			}
		})
		setup, _ := j.store.SetupOperation(ctx, parents[0].Profile.SetupOperationID)
		var installed model.SetupOperation
		_ = json.Unmarshal(setup.RequestJSON, &installed)
		initial, _ := json.Marshal(map[string]any{"root": root.Anchor, "profileDigest": parents[0].Profile.ProfileDigest, "profileRevision": parents[0].Profile.ProfileRevision, "version": installed.Materializer.Bin.Version})
		_, _ = helper.stdin.Write(append(initial, '\n'))
		line, err := helper.stdout.ReadBytes('\n')
		if err != nil {
			t.Fatalf("source fixture startup: %v %s", err, helper.stderr.String())
		}
		var fixture struct {
			Bundle       json.RawMessage               `json:"bundle"`
			Expected     model.AppliedExpertiseProfile `json:"expected"`
			Instructions map[string]string             `json:"instructions"`
		}
		if err := json.Unmarshal(line, &fixture); err != nil {
			t.Fatal(err)
		}
		bundle = fixture.Bundle
		instructions = fixture.Instructions
		op.Profiles = []model.ApprovedExpertiseProfile{fixture.Expected.ApprovedProfile}
		op.Dependencies.Profiles = []model.AppliedExpertiseProfile{fixture.Expected}
		op.Configuration.Profiles[0].ApprovedProfile = &fixture.Expected.ApprovedProfile
		for i := range parents {
			op.RoleBindings[i].ApprovedProfile = fixture.Expected.ApprovedProfile
			op.Dependencies.Roles[i].Binding = op.RoleBindings[i]
			projection := &op.Dependencies.Roles[i].Projection
			projection.ApprovedProfile = fixture.Expected.ApprovedProfile
			projection.SystemDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(instructions[parents[i].Role])))
			op.Dependencies.Roles[i].Instructions.InstructionDigest = projection.SystemDigest
			parents[i].Instructions = op.Dependencies.Roles[i].Instructions
			parents[i].RoleAgentDigest = model.WorkspaceDigest(projection)
			raw, _ := json.Marshal(parents[i])
			var value map[string]any
			_ = json.Unmarshal(raw, &value)
			delete(value, "configDigest")
			parents[i].ConfigDigest = model.WorkspaceDigest(value)
		}
		op.ConfigurationDigest = model.WorkspaceDigest(op.Configuration)
		op.DependencyDigest = model.WorkspaceDigest(op.Dependencies)
		j.reconciler.ManagedCatalog = sourceSharedFilesystemCatalog{catalog}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	op.Producer.KeySHA256 = fmt.Sprintf("sha256:%x", sha256.Sum256(public))
	// This generated SOURCE authority binds the same node token the real TLS
	// client below uses. No retained application or signature is rewritten.
	op.Producer.NodeTokenHash = fmt.Sprintf("%x", sha256.Sum256([]byte("rtn_source")))
	opBytes, _ := json.Marshal(op)
	var opMap map[string]any
	_ = json.Unmarshal(opBytes, &opMap)
	delete(opMap, "operationDigest")
	op.OperationDigest = model.WorkspaceDigest(opMap)
	j.manifest.ManagedServices = nil
	j.manifest.ParentServices = parents
	j.manifest.InsightsManagerPolicies = nil
	j.reconciler.Manager = nil
	j.reconciler.ContinuityControl = nil
	runtime := &parentSourceRuntime{t: t, store: j.store, parents: parents, sessions: map[string]string{}, key: key, now: j.reconciler.now, helper: helper}
	j.reconciler.ManagedRuntime = runtime
	acknowledged := false
	var submitted []byte
	applicationPosts := 0
	firstTaskReads := 0
	firstTaskPreparationPosts := 0
	normalEnrollment := len(lostLaunch) > 3 && lostLaunch[3]
	lostEnrollment := len(lostLaunch) > 4 && lostLaunch[4]
	roleOperations, roleEnrolls := 0, 0
	roleGrants := map[string]model.WorkflowRoleOperation{}
	wrongFirstTaskOwner := false
	var taskOriginal map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer rtn_source" {
			t.Error("missing protected node auth")
		}
		w.Header().Set("Content-Type", "application/json")
		if runtime.sourceHTTP != nil && runtime.sourceHTTP(w, r) {
			return
		}
		if childJourney != nil && childJourney.serve(w, r) {
			return
		}
		switch {
		case r.URL.Path == "/internal/runtime/workspace-workflow/enrollment-operations":
			roleOperations++
			var call model.WorkflowRoleOperationRequest
			if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&call) != nil || r.Header.Get("Idempotency-Key") != call.RequestID {
				t.Fatal("normal role operation lost exact request/auth")
			}
			var selected *model.ControllerParentIntent
			for i := range parents {
				if parents[i].ServiceRegistrationID == call.Subject.ServiceRegistrationID {
					selected = &parents[i]
				}
			}
			if selected == nil {
				t.Fatal("caller-selected role service")
			}
			current, e := j.reconciler.Store.ControllerParent(ctx, selected.ServiceRegistrationID)
			if e != nil || current == nil || call.Subject != model.CurrentWorkflowRoleSubject(*selected, *current.Report.NativeRegistration) {
				t.Fatal("normal role operation not current actual parent")
			}
			pinned, e := j.reconciler.Store.OwnedContinuationResult(ctx, "firsttask_source", "owner-original", mustCanonicalSourceTask(t, taskOriginal))
			if e != nil || len(pinned) == 0 {
				t.Fatal("enrollment effect preceded immutable owner")
			}
			grant := model.WorkflowRoleOperation{FormatVersion: 1, OperationID: "wfroleop_source_" + selected.Role, Subject: call.Subject, NativeContextDigest: model.WorkspaceDigest(current.Report.NativeRegistration), ManagedServiceReceiptDigest: current.Report.ReceiptDigest, NodeTokenHash: op.Producer.NodeTokenHash, ExpiresAt: j.reconciler.now().Add(4 * time.Minute).Format(time.RFC3339Nano)}
			fields, _ := json.Marshal(grant)
			var preimage map[string]any
			_ = json.Unmarshal(fields, &preimage)
			delete(preimage, "operationDigest")
			grant.OperationDigest = model.WorkspaceDigest(preimage)
			roleGrants[grant.OperationID] = grant
			_ = json.NewEncoder(w).Encode(grant)
		case r.URL.Path == "/internal/runtime/workspace-workflow/enroll":
			roleEnrolls++
			var proof model.WorkflowRoleEnvelope
			if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&proof) != nil || proof.Validate() != nil || r.Header.Get("Idempotency-Key") != proof.Payload.RequestID {
				t.Fatal("normal enrollment did not submit exact role envelope")
			}
			grant, ok := roleGrants[proof.Payload.OperationID]
			if !ok || proof.Payload.OperationDigest != grant.OperationDigest || proof.Payload.Subject != grant.Subject || proof.Payload.NativeReceipt.Readback.Subject != grant.Subject || proof.Payload.NativeReceipt.Readback.NativeContextDigest != grant.NativeContextDigest || proof.Payload.ManagedServiceReceiptDigest != grant.ManagedServiceReceiptDigest {
				t.Fatal("application/other role substituted for current role proof")
			}
			body, _ := model.WorkspaceCanonicalJSON(proof.Payload)
			h := sha256.Sum256(body)
			sig, _ := base64.StdEncoding.DecodeString(proof.Signature)
			if !ecdsa.VerifyASN1(&key.PublicKey, h[:], sig) {
				t.Fatal("SOURCE role proof signature mismatch")
			}
			if lostEnrollment {
				http.Error(w, "SOURCE lost enrollment ACK", 502)
				return
			}
			_ = json.NewEncoder(w).Encode(model.WorkflowRoleEnrollment{FormatVersion: 1, RoleBindingID: "wrole_source_" + grant.Subject.Role, RoleBindingRevision: 1, ExpiresAt: grant.ExpiresAt, Lease: "wfl_source_" + grant.Subject.Role})
		case r.URL.Path == "/internal/runtime/workspace-workflow/controller-preparations":
			firstTaskPreparationPosts++
			var call api.ControllerPreparationRequest
			if !firstTask || r.Method != "POST" || json.NewDecoder(r.Body).Decode(&call) != nil || r.Header.Get("Idempotency-Key") != call.RequestID || model.WorkspaceDigest(call) != model.WorkspaceDigest(taskOriginal["parentActivityRequest"]) {
				t.Error("actual parent caller changed immutable R53 request")
			}
			pinned, e := j.reconciler.Store.OwnedContinuationResult(ctx, "firsttask_source", "owner-original", mustCanonicalSourceTask(t, taskOriginal))
			if e != nil || len(pinned) == 0 {
				t.Error("parent preparation preceded durable first-task original")
			}
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"error":{"code":"source_installed_context_original_unavailable"}}`))
		case strings.HasSuffix(r.URL.Path, "/first-task"):
			firstTaskReads++
			if r.Method != "GET" || r.URL.RawQuery != "" || r.ContentLength > 0 || r.Header.Get("X-WarpMetal-Workflow-Lease") != "" || r.URL.Path != "/internal/runtime/workspace-workflow/application-operations/"+op.OperationID+"/first-task" {
				t.Error("first task was not an exact node-only current application read")
			}
			if !firstTask {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"error":{"code":"workspace_first_task_not_found"}}`))
				return
			}
			if taskOriginal == nil {
				t.Error("first task read before applied application")
				w.WriteHeader(500)
				return
			}
			copy := map[string]any{}
			for k, v := range taskOriginal {
				copy[k] = v
			}
			if wrongFirstTaskOwner {
				owner := parents[1].Owner
				owner.AccountID = "other_account"
				copy["owner"] = owner
			}
			_ = json.NewEncoder(w).Encode(copy)
		case r.URL.Path == "/internal/runtime/report":
			var report model.Report
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Error(err)
			}
			if len(report.ParentServices) != 2 {
				t.Fatal("protected ACK missing parent reports")
			}
			for i, p := range report.ParentServices {
				if err := p.ValidateReady(parents[i]); err != nil {
					t.Error(err)
				}
			}
			acknowledged = true
			_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
		case r.URL.Path == "/internal/runtime/workspace-workflow/applications":
			applicationPosts++
			if !acknowledged || r.Header.Get("Idempotency-Key") == "" {
				t.Error("application preceded exact report ACK")
			}
			var envelope model.WorkspaceApplicationEnvelope
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				t.Error(err)
			}
			if err := envelope.Validate(); err != nil {
				t.Error(err)
			}
			body, _ := model.WorkspaceCanonicalJSON(envelope.Payload)
			sum := sha256.Sum256(body)
			signature, _ := base64.StdEncoding.DecodeString(envelope.Signature)
			if !ecdsa.VerifyASN1(&key.PublicKey, sum[:], signature) {
				t.Error("source physical TLS envelope signature mismatch")
			}
			bytes, _ := json.Marshal(envelope)
			if submitted != nil && string(submitted) != string(bytes) {
				t.Error("lost-ACK replay changed signed bytes")
			}
			submitted = bytes
			if applicationPosts == 1 {
				http.Error(w, "source mock: lost acceptance response", 502)
				return
			}
			_ = json.NewEncoder(w).Encode(api.WorkspaceApplicationAccepted{ApplicationID: "wapp_source", State: "applied"})
		case strings.HasSuffix(r.URL.Path, "/instructions"):
			service := parents[0].ServiceRegistrationID
			if strings.Contains(r.URL.Path, parents[1].ServiceRegistrationID) {
				service = parents[1].ServiceRegistrationID
			}
			role := "manager"
			if service == parents[1].ServiceRegistrationID {
				role = "orchestrator"
			}
			_ = json.NewEncoder(w).Encode(api.WorkspaceApplicationInstructions{ServiceRegistrationID: service, InstructionRevision: 1, InstructionDigest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(instructions[role]))), Content: instructions[role]})
		case strings.HasSuffix(r.URL.Path, "/bundle"):
			_, _ = w.Write(bundle)
		default:
			_ = json.NewEncoder(w).Encode(op)
		}
	}))
	defer server.Close()
	j.reconciler.ManagedControl = api.Client{Origin: server.URL, NodeToken: "rtn_source", HTTP: server.Client()}
	if len(lostLaunch) > 0 && lostLaunch[0] {
		runtime.lostStart = true
		if err := j.reconciler.Reconcile(ctx, j.manifest); err == nil {
			t.Fatal("lost launch response fabricated ready")
		}
		local, err := j.store.ControllerParent(ctx, parents[0].ServiceRegistrationID)
		if err != nil || local == nil || !local.CreationDispatched || local.Report.ObservedState != "failed" || runtime.attestCalls != 0 || applicationPosts != 0 {
			t.Fatal("lost native launch lost durable unknown/failure boundary")
		}
	}
	if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatalf("tools-empty valid source bridge permanently deferred: %v", err)
	}
	report, err := j.reconciler.Report(ctx, j.reconciler.ServerID, "0.1.52")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.ParentServices) != 2 {
		t.Fatalf("parent report: %#v", report.ParentServices)
	}
	for _, parent := range report.ParentServices {
		if parent.ObservedState != "ready" || parent.NativeRegistration == nil || parent.NativeRoleReadback == nil {
			t.Fatalf("not current ready parent: %#v", parent)
		}
	}
	if report.ParentServices[0].NativeRegistration.NativeSessionID == report.ParentServices[1].NativeRegistration.NativeSessionID {
		t.Fatal("parent roles shared session")
	}
	client := j.reconciler.ManagedControl.(api.Client)
	changed := report
	changed.ParentServices = append([]model.ControllerParentReport(nil), report.ParentServices...)
	changed.ParentServices[0].ReceiptDigest = "sha256:" + strings.Repeat("f", 64)
	if err := j.reconciler.CompleteWorkspaceApplications(ctx, changed); err == nil || runtime.attestCalls != 0 || applicationPosts != 0 {
		t.Fatal("changed ACK borrowed parent authority")
	}
	if err := client.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	if err := j.reconciler.CompleteWorkspaceApplications(ctx, report); err == nil || applicationPosts != 1 {
		t.Fatalf("expected source lost acceptance response, got: %v posts=%d", err, applicationPosts)
	}
	localApp, err := j.store.WorkspaceApplication(ctx, op.OperationID)
	if err != nil || localApp == nil || len(localApp.EnvelopeJSON) == 0 || localApp.Applied {
		t.Fatal("unknown acceptance was fabricated or signed envelope lost")
	}
	if err := j.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(j.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	j.reconciler.Store = reopened
	runtime.store = reopened
	catalog.State = reopened
	if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatal(err)
	}
	again, err := j.reconciler.Report(ctx, j.reconciler.ServerID, "0.1.52")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again.ParentServices, report.ParentServices) {
		t.Fatal("native identity/report changed after reopen")
	}
	if err := client.Report(ctx, again); err != nil {
		t.Fatal(err)
	}
	if err := j.reconciler.CompleteWorkspaceApplications(ctx, again); err != nil {
		t.Fatal(err)
	}
	accepted, err := reopened.WorkspaceApplication(ctx, op.OperationID)
	if err != nil || accepted == nil || !accepted.Applied || accepted.ApplicationID != "wapp_source" || runtime.attestCalls != 1 || applicationPosts != 2 {
		t.Fatal("application replay/reopen failed to retain exact identity and one signature")
	}
	if acceptedHook != nil {
		acceptedHook(j, runtime, op, parents)
		return
	}
	if firstTask {
		text := "  Exact SOURCE initialAdvice input.\n"
		local, e := reopened.ControllerParent(ctx, parents[1].ServiceRegistrationID)
		if e != nil || local == nil {
			t.Fatal(e)
		}
		request := api.ControllerPreparationRequest{FormatVersion: 1, RequestID: "initial_advice_request", ServiceRegistrationID: parents[1].ServiceRegistrationID, InputID: "initial_advice_input", InputDigest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text))), ModelSelection: *op.Dependencies.Roles[1].Projection.ModelSelection}
		if selectionOverride != nil {
			request.FormatVersion = 2
			request.ProviderPolicyDigest = providerpolicy.FlashDigest
		}
		taskOriginal = map[string]any{"formatVersion": 1, "firstTaskId": "firsttask_source", "setupIntentId": op.SetupIntentID, "requestId": "owner_source_request", "applicationId": accepted.ApplicationID, "applicationOperationId": op.OperationID, "applicationOperationDigest": op.OperationDigest, "configurationId": op.ConfigurationID, "configurationRevision": op.ConfigurationRevision, "configurationDigest": op.ConfigurationDigest, "owner": parents[1].Owner, "parent": map[string]any{"serviceRegistrationId": parents[1].ServiceRegistrationID, "serviceGeneration": parents[1].ServiceGeneration, "role": "orchestrator", "configDigest": parents[1].ConfigDigest, "desiredRevision": parents[1].DesiredRevision, "nativeRegistration": local.Report.NativeRegistration}, "inputText": text, "parentActivityRequest": request, "createdAt": j.reconciler.now().Format(time.RFC3339Nano), "statusUrl": "/internal/account/agent-workspace-setup-intents/" + op.SetupIntentID + "/tasks/firsttask_source", "status": map[string]any{"state": "accepted", "preparationId": nil, "preparedReceiptDigest": nil, "activityId": nil, "contextId": nil, "outputReceiptDigest": nil}}
		if selectionOverride != nil {
			taskOriginal["formatVersion"] = 2
		}
		before := len(runtime.calls)
		if normalEnrollment {
			j.reconciler.ManagedRuntime = &firstTaskEnrollmentSourceRuntime{&firstTaskSourceRuntime{runtime}}
			if len(lostLaunch) > 5 && lostLaunch[5] {
				freshDelivery := len(lostLaunch) > 8 && lostLaunch[8]
				childJourney = newFirstTaskChildTerminalFixture(t, j, runtime, op, parents, taskOriginal, freshDelivery)
				childJourney.lostChildPrepare = len(lostLaunch) > 6 && lostLaunch[6]
				childJourney.undeliveredPrepare = len(lostLaunch) > 7 && lostLaunch[7]
				if childJourney.undeliveredPrepare {
					childJourney.configureUndeliveredPreparation(t)
				}
				childJourney.run(t, j, client)
				if roleOperations != 2 || roleEnrolls != 2 || firstTaskPreparationPosts != 0 {
					t.Fatal("accepted-original continuation bypassed normal BOTH enrollment or redispatched parents")
				}
				return
			}
			e = j.reconciler.Reconcile(ctx, j.manifest)
			if lostEnrollment {
				if e == nil || roleOperations != 1 || roleEnrolls != 1 || firstTaskPreparationPosts != 0 {
					t.Fatalf("normal enrollment owning lost ACK boundary absent: op=%d enroll=%d prep=%d err=%v", roleOperations, roleEnrolls, firstTaskPreparationPosts, e)
				}
			} else {
				if e == nil || roleOperations != 2 || roleEnrolls != 2 || firstTaskPreparationPosts != 1 {
					t.Fatalf("normal daemon did not enroll BOTH roles before parent prepare: op=%d enroll=%d prep=%d err=%v", roleOperations, roleEnrolls, firstTaskPreparationPosts, e)
				}
				if j.reconciler.firstTaskAuthority == nil || j.reconciler.firstTaskManagerAuthority == nil || j.reconciler.firstTaskAuthority.lease != "wfl_source_orchestrator" || j.reconciler.firstTaskManagerAuthority.lease != "wfl_source_manager" {
					t.Fatal("normal bindings did not retain actual enroll responses")
				}
				if _, err := j.reconciler.ReadControllerFirstTaskParentPreparation(ctx, "firsttask_source", parents[1].ServiceRegistrationID); !errors.Is(err, state.ErrOwnedContinuationUnknown) {
					t.Fatal("normal selector fabricated completion of lost/denied preparation", err)
				}
				if _, err := j.reconciler.ReadControllerFirstTaskParentPreparation(ctx, "firsttask_source", parents[0].ServiceRegistrationID); !errors.Is(err, ErrControllerFirstTaskPending) {
					t.Fatal("manager original absent before accepted advice", err)
				}
			}
			ops, enrolls, preps := roleOperations, roleEnrolls, firstTaskPreparationPosts
			if e = j.reconciler.Reconcile(ctx, j.manifest); !errors.Is(e, state.ErrOwnedContinuationUnknown) || roleOperations != ops || roleEnrolls != enrolls || firstTaskPreparationPosts != preps {
				t.Fatal("UNKNOWN reissued normal role/activity originals", e)
			}
			return // actual TLS/current caller, SOURCE native/install/key suppliers; no joined/installed credit.
		}
		if e = j.reconciler.Reconcile(ctx, j.manifest); e != nil || firstTaskReads != 1 {
			t.Fatalf("ordinary pending owner task became reconcile failure: reads=%d err=%v", firstTaskReads, e)
		}
		// A missing independent lease/installed applicability is not accepted task
		// authority. The immutable original must already be on SAME durable Store.
		original, e := reopened.OwnedContinuationResult(ctx, "firsttask_source", "owner-original", mustCanonicalSourceTask(t, taskOriginal))
		if e != nil || len(original) == 0 {
			t.Fatal("first-task original not retained before authority/effects", e)
		}
		var retained map[string]any
		_ = json.Unmarshal(original, &retained)
		if retained["inputText"] != text {
			t.Fatal("task read changed text")
		}
		if len(lostLaunch) > 2 && lostLaunch[2] {
			for _, parent := range parents {
				prepared, err := j.reconciler.ReadControllerFirstTaskParentPreparation(ctx, "firsttask_source", parent.ServiceRegistrationID)
				if !errors.Is(err, ErrControllerFirstTaskPending) || prepared.PreparationID != "" {
					t.Fatal("known missing normal original not pending", parent.Role, err)
				}
			}
			if _, err := j.reconciler.ReadControllerFirstTaskParentPreparation(ctx, "firsttask_source", "source_derived_preparation"); !errors.Is(err, state.ErrControllerActivityConflict) {
				t.Fatal("nonregistration selector became pending/success", err)
			}
			bounded, cancel := context.WithCancel(ctx)
			cancel()
			if _, err := j.reconciler.ReadControllerFirstTaskParentPreparation(bounded, "firsttask_source", parents[0].ServiceRegistrationID); !errors.Is(err, context.Canceled) {
				t.Fatal("owning read ignored current I/O context", err)
			}
		}
		for _, call := range runtime.calls[before:] {
			if strings.HasPrefix(call.action, "controller-") {
				t.Fatal("task read caused native activity effects")
			}
		}
		if e = j.reconciler.Reconcile(ctx, j.manifest); e != nil || firstTaskReads != 2 {
			t.Fatal("same owner pending replay lost current check", e)
		}
		// CURRENT node GET includes derived status; it is not part of the
		// immutable consent hash and must not cause a new native admission.
		taskOriginal["status"] = map[string]any{"state": "preparing", "preparationId": "source_derived_preparation", "preparedReceiptDigest": nil, "activityId": nil, "contextId": nil, "outputReceiptDigest": nil}
		if e = j.reconciler.Reconcile(ctx, j.manifest); e != nil || firstTaskReads != 3 {
			t.Fatal("derived status rebound immutable first-task identity", e)
		}
		wrongFirstTaskOwner = true
		if e = j.reconciler.Reconcile(ctx, j.manifest); e == nil || firstTaskReads != 4 {
			t.Fatal("wrong-owner original admitted", e)
		}
		wrongFirstTaskOwner = false
		j.reconciler.ManagedRuntime = &firstTaskSourceRuntime{runtime}
		installed := qualification.Applicability{AccountID: parents[1].Owner.AccountID, TaskID: parents[1].Owner.TaskID, ServerID: parents[1].Owner.ServerID, SandboxID: parents[1].Owner.SandboxID, SandboxGeneration: parents[1].Owner.SandboxGeneration, Connection: *request.ModelSelection.CredentialBinding}
		if e = j.reconciler.BindControllerFirstTaskAuthority(ctx, op.OperationID, installed, "wfl_explicitly_synthetic"); e != nil {
			t.Fatal("source-only authority attachment", e)
		}
		if e = j.reconciler.Reconcile(ctx, j.manifest); e == nil || firstTaskPreparationPosts != 1 {
			t.Fatal("current caller did not invoke SAME parent preparation boundary", e, firstTaskPreparationPosts)
		}
		if e = j.reconciler.Reconcile(ctx, j.manifest); !errors.Is(e, state.ErrOwnedContinuationUnknown) || firstTaskPreparationPosts != 1 {
			t.Fatal("same-owner replay duplicated an unknown preparation", e, firstTaskPreparationPosts)
		}
		if len(lostLaunch) > 2 && lostLaunch[2] {
			before := len(runtime.calls)
			if _, err := j.reconciler.ReadControllerFirstTaskParentPreparation(ctx, "firsttask_source", parents[1].ServiceRegistrationID); !errors.Is(err, state.ErrOwnedContinuationUnknown) {
				t.Fatal("owning lost ACK became expected absence", err)
			}
			if _, err := j.reconciler.ReadControllerFirstTaskParentPreparation(ctx, "firsttask_source", parents[0].ServiceRegistrationID); !errors.Is(err, ErrControllerFirstTaskPending) {
				t.Fatal("manager borrowed orchestrator unknown preparation", err)
			}
			if firstTaskPreparationPosts != 1 || len(runtime.calls) != before {
				t.Fatal("read-only selector dispatched owning/native work")
			}
		}
		if context, text, e := j.reconciler.ReadControllerParentApprovedInput(ctx, "source_derived_preparation"); e == nil || context.ContextID != "" || text != "" {
			t.Fatal("read-only observer manufactured approved input from derived status")
		}
		if action, e := j.reconciler.ReadControllerParentActionReceipt(ctx, "source_derived_preparation"); e == nil || len(action) != 0 {
			t.Fatal("read-only observer completed/fabricated missing action")
		}
		return // explicit source supplier block; no installed/native activity credit.
	}
	j.reconciler.Now = func() time.Time { return time.Date(2026, 9, 27, 17, 6, 0, 0, time.UTC) }
	if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatalf("accepted immutable metadata lost on expiry: %v", err)
	}
	retained, err := j.reconciler.Report(ctx, j.reconciler.ServerID, "0.1.52")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(retained.ParentServices, again.ParentServices) {
		t.Fatal("accepted expiry changed retained native metadata")
	}
	if err := j.reconciler.CompleteWorkspaceApplications(ctx, retained); err != nil || applicationPosts != 2 || runtime.attestCalls != 1 {
		t.Fatal("accepted expiry reminted activity/application authority")
	}
	if root := os.Getenv("F3_Q38_SOURCE_EVIDENCE"); root != "" && composed {
		var envelope model.WorkspaceApplicationEnvelope
		_ = json.Unmarshal(accepted.EnvelopeJSON, &envelope)
		calls := []map[string]any{}
		for _, call := range runtime.calls {
			calls = append(calls, map[string]any{"action": call.action, "request": call.request})
		}
		facts := map[string]any{"mockBoundaries": []string{"backend authorization/report/application acceptance", "native HTTP/binary installation stand-in", "root P-256 registration", "shared source mount namespace"}, "parents": parents, "reports": again.ParentServices, "envelope": envelope, "helperCalls": calls}
		raw, err := json.MarshalIndent(facts, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		name := os.Getenv("F3_Q38_SOURCE_FACTS")
		if name == "" {
			name = "runtime-parent-composed-source-facts.json"
		}
		file, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write(raw)
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			t.Fatal(err)
		}
	}
	updated := parents[0]
	updated.ActionRevision++
	updated.DesiredRevision++
	raw, _ := json.Marshal(updated)
	var value map[string]any
	_ = json.Unmarshal(raw, &value)
	delete(value, "configDigest")
	updated.ConfigDigest = model.WorkspaceDigest(value)
	if err := reopened.PutControllerParentIntent(ctx, updated); err != nil {
		t.Fatal(err)
	}
	current := j.manifest
	current.ParentServices = append([]model.ControllerParentIntent(nil), parents...)
	current.ParentServices[0] = updated
	j.reconciler.setCurrentAuthority(current)
	unobserved, err := j.reconciler.Report(ctx, j.reconciler.ServerID, "0.1.52")
	if err != nil {
		t.Fatal(err)
	}
	if unobserved.ParentServices[0].ObservedState == "ready" || unobserved.ParentServices[0].ConfigDigest != updated.ConfigDigest {
		t.Fatal("new parent action borrowed prior native-ready report")
	}
}

func mustCanonicalSourceTask(t *testing.T, response map[string]any) []byte {
	t.Helper()
	original := map[string]any{}
	for k, v := range response {
		if k != "status" {
			original[k] = v
		}
	}
	raw, err := model.WorkspaceCanonicalJSON(original)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
