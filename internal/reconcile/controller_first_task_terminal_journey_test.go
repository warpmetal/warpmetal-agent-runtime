package reconcile

// Data suppliers for the EXISTING first-task journey, not a runner or normal
// issuer. Retained parent acceptance/admission and native/STATE transport replies
// are explicitly SOURCE fixtures. Only normal manifest passes dispatch the child.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

type firstTaskChildTerminalFixture struct {
	t                                                        *testing.T
	r                                                        *Reconciler
	entry                                                    model.CellServiceV3
	handle                                                   model.IntentHandle
	selected                                                 model.ManagerIntentSelection
	actual                                                   model.ActualPreparationAssociation
	assignment                                               json.RawMessage
	admission                                                model.ChildAdmissionAssociation
	backendState                                             string
	backendDigest                                            *string
	readError                                                bool
	lostChildPrepare                                         bool
	undeliveredPrepare                                       bool
	prepareSigningIntent                                     json.RawMessage
	policyIntentGets                                         int
	effectStatus                                             string
	reports                                                  int
	prepares, assigns, reads, nativePrepares, nativeExecutes int
	nativeState                                              string
	freshDelivery                                            bool
	deliveryParents                                          map[string]firstTaskDeliveryParent
	delivery                                                 *firstTaskPublicDeliveryFixture
	completion                                               *childCompletionSource
	resultInput                                              string
	managerLease                                             string
	ownerScopedProject                                       bool
	credentialID, nativeCredentialID                         string
}

func fixtureRaw(v any) json.RawMessage {
	raw, err := model.WorkspaceCanonicalJSON(v)
	if err != nil {
		panic(err)
	}
	return raw
}
func fixtureDigestField(v any, field string) string {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(fixtureRaw(v), &fields)
	delete(fields, field)
	return model.WorkspaceDigest(fields)
}
func fixtureComplete(t *testing.T, r *Reconciler, id, step string, claim, result any) {
	t.Helper()
	raw := fixtureRaw(claim)
	if err := r.Store.ClaimOwnedContinuation(context.Background(), id, step, raw); err != nil {
		t.Fatal(err)
	}
	if err := r.Store.CompleteOwnedContinuation(context.Background(), id, step, raw, fixtureRaw(result)); err != nil {
		t.Fatal(err)
	}
}

func newFirstTaskChildTerminalFixture(t *testing.T, j *managerPolicyJourney, native *parentSourceRuntime, app model.WorkspaceApplicationOperation, parents []model.ControllerParentIntent, task map[string]any, fresh ...bool) *firstTaskChildTerminalFixture {
	t.Helper()
	ctx := context.Background()
	f := &firstTaskChildTerminalFixture{t: t, r: j.reconciler, backendState: "admitted", nativeState: "running"}
	f.freshDelivery = len(fresh) > 0 && fresh[0]
	f.deliveryParents = map[string]firstTaskDeliveryParent{}
	var owner api.OwnerFirstTaskResponse
	if err := json.Unmarshal(fixtureRaw(task), &owner); err != nil {
		t.Fatal(err)
	}
	packet, err := os.ReadFile(os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET"))
	if err != nil {
		t.Fatal(err)
	}
	var specimens struct {
		Specimens []struct {
			Context map[string]any `json:"context"`
			Text    string         `json:"text"`
		} `json:"specimens"`
	}
	if err = json.Unmarshal(packet, &specimens); err != nil || len(specimens.Specimens) < 2 {
		t.Fatal("documented context fixture", err)
	}
	base := specimens.Specimens[1].Context
	if f.freshDelivery {
		f.configurePublicDelivery(t, native, app, base)
	}
	var target map[string]any
	_ = json.Unmarshal(fixtureRaw(base["target"]), &target)
	members := target["members"].(map[string]any)
	for _, v := range members {
		item := v.(map[string]any)
		scope := item["scope"].(map[string]any)
		scope["owner"] = parents[0].Owner
		item["intentDigest"] = fixtureDigestField(item, "intentDigest")
	}
	advice := target["advice"].(map[string]any)
	advice["plan"] = base["plan"]
	nativePacket, err := os.ReadFile(os.Getenv("WARPMETAL_CONTROLLER_OUTPUT_SOURCE_FIXTURE"))
	if err != nil {
		t.Fatal(err)
	}
	var outputs struct {
		NativeResponses []model.ControllerOutputNativeReadback `json:"nativeResponses"`
	}
	if err = json.Unmarshal(nativePacket, &outputs); err != nil || len(outputs.NativeResponses) == 0 {
		t.Fatal("documented native output fixture", err)
	}
	n := outputs.NativeResponses[0].Data.ControllerOutput
	// Already accepted SOURCE envelope fixture, not a fresh native capture claim.
	lineage := model.ControllerOutputLineage{ControllerActivity: model.ControllerActivity{Admission: n.Admission, InputID: n.Lineage.InputID, InputSeq: n.Lineage.InputSeq, ExecutionStartedSeq: n.Lineage.ExecutionStartedSeq}, InputText: "Retained SOURCE transport fixture input", ExecutionTerminalSeq: n.Lineage.ExecutionTerminalSeq, TerminalAt: time.UnixMilli(n.Events.Terminal.Created).UTC().Format(time.RFC3339Nano), TerminalOutcome: "succeeded", AssistantMessageID: n.Lineage.AssistantMessageID, AssistantAgentID: n.Lineage.Agent, AssistantCompletedAt: time.UnixMilli(n.Events.StepEnded.Created).UTC().Format(time.RFC3339Nano), AssistantFinish: "stop", OutputText: n.Output.Text, OutputByteCount: len(n.Output.Text), OutputDigest: model.RawPhysicalDigest([]byte(n.Output.Text)), EventRefs: n.Events}
	lineage.AssistantModel.ProviderID, lineage.AssistantModel.ID = n.Lineage.Model.ProviderID, n.Lineage.Model.ID
	var declared qualification.ControllerDeclaredInput
	for _, parent := range []model.ControllerParentIntent{parents[1], parents[0]} {
		local, err := j.reconciler.Store.ControllerParent(ctx, parent.ServiceRegistrationID)
		if err != nil || local == nil {
			t.Fatal(err)
		}
		input, text := owner.ParentActivityRequest.InputID, owner.InputText
		var contextFields map[string]any
		_ = json.Unmarshal(fixtureRaw(base), &contextFields)
		if parent.Role == "manager" {
			input, text = "initial_decision_input", "Retained SOURCE initialDecision input."
			contextFields["workflowRequestId"] = "initial_decision_request"
			contextFields["target"] = target
		} else {
			contextFields["workflowRequestId"] = owner.ParentActivityRequest.RequestID
			contextFields["target"] = map[string]any{"kind": "advice", "role": "orchestrator", "resourceId": nil, "advice": nil}
		}
		prep := sourceControllerPrepared(t, parent, app, *local.Report.NativeRegistration, input, text)
		contextFields["preparationId"], contextFields["inputId"], contextFields["inputDigest"] = prep.PreparationID, input, prep.PreparedTuple.InputDigest
		contextFields["contextId"] = "source_context_" + parent.Role
		if parent.Role == "manager" {
			declFields := map[string]any{}
			for _, key := range []string{"inputId", "policyDigest", "workflowRequestId", "target", "plan", "allocationId", "preparationOrdinal", "physicalIndex"} {
				declFields[key] = contextFields[key]
			}
			declFields["inputText"], declFields["serviceRegistrationId"] = text, parent.ServiceRegistrationID
			if err = json.Unmarshal(fixtureRaw(declFields), &declared); err != nil {
				t.Fatal(err)
			}
			contextFields["declarationItemDigest"] = model.WorkspaceDigest(declared)
		}
		contextFields["contextDigest"] = fixtureDigestField(contextFields, "contextDigest")
		var c model.ControllerApprovedInputContext
		if err = json.Unmarshal(fixtureRaw(contextFields), &c); err != nil {
			t.Fatal("accepted fixture context", err)
		}
		if f.freshDelivery {
			c = f.delivery.parentContext(t, parent, prep, c)
			if parent.Role == "manager" {
				declared.PolicyDigest = c.PolicyDigest
				declared.AllocationID = c.AllocationID
				declared.PreparationOrdinal = c.PreparationOrdinal
				declared.PhysicalIndex = c.PhysicalIndex
				c.DeclarationItemDigest = model.WorkspaceDigest(declared)
				c.ContextDigest = fixtureDigestField(c, "contextDigest")
			}
		}
		var proposalBody map[string]any
		_ = json.Unmarshal([]byte(specimens.Specimens[1].Text), &proposalBody)
		proposalBody["requestId"] = c.WorkflowRequestID
		if parent.Role == "orchestrator" {
			delete(proposalBody, "choice")
			delete(proposalBody, "expectedAdviceRevision")
		}
		op := model.ControllerOutputOperation{FormatVersion: 2, Kind: "controller_output", OperationID: "source_output_" + parent.Role, RequestID: "source_output_request_" + parent.Role, Context: c, RoleBindingID: "source_binding_" + parent.Role, RoleBindingRevision: 1, Subject: model.ControllerOutputSubject{AccountID: parent.Owner.AccountID, TaskID: parent.Owner.TaskID, ServerID: parent.Owner.ServerID, SandboxID: parent.Owner.SandboxID, SandboxGeneration: parent.Owner.SandboxGeneration, CellID: parent.Owner.CellID, Role: parent.Role, ControllerID: parent.Owner.ControllerID, ControllerRevision: parent.Owner.ControllerRevision, AuthorityRevision: parent.Owner.AuthorityRevision, ServiceRegistrationID: parent.ServiceRegistrationID, ServiceGeneration: parent.ServiceGeneration, NativeSessionID: local.Report.NativeRegistration.NativeSessionID}, Workspace: parent.Workspace, RoleAgentDigest: parent.RoleAgentDigest, ConfigurationDigest: app.ConfigurationDigest, ConfigDigest: parent.ConfigDigest, ManagedServiceReceiptDigest: local.Report.ReceiptDigest, Producer: app.Producer, Lineage: lineage, Proposal: model.ControllerWorkflowProposal{Target: c.Target, Body: json.RawMessage(specimens.Specimens[1].Text)}, ExpiresAt: app.ExpiresAt}
		op.Proposal.Body = fixtureRaw(proposalBody)
		op.OperationDigest = fixtureDigestField(op, "operationDigest")
		envelope := model.ControllerOutputEnvelope{Payload: model.ControllerOutputPayload{FormatVersion: 1, Purpose: "workspace_workflow_controller_output", RequestID: op.RequestID, TaskID: parent.Owner.TaskID, NodeTokenHash: app.Producer.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: j.reconciler.now().Format(time.RFC3339Nano), NotAfter: app.ExpiresAt, ManagedServiceReceiptDigest: local.Report.ReceiptDigest, OperationID: op.OperationID, OperationDigest: op.OperationDigest, NativeReceipt: model.ControllerOutputReadback{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: parent.ServiceRegistrationID, ServiceGeneration: parent.ServiceGeneration, NativeSessionID: local.Report.NativeRegistration.NativeSessionID, NativeProjectID: local.Report.NativeRegistration.NativeProjectID, NativeLocationDigest: local.Report.NativeRegistration.NativeLocationDigest, Role: parent.Role, RootAttestation: parent.Workspace.RootAttestation, ObservedAt: j.reconciler.now().Format(time.RFC3339Nano), Lineage: lineage, NativeReadback: outputs.NativeResponses[0]}}, KeyID: app.Producer.KeyID, Signature: strings.Repeat("A", 96)}
		grant := model.ControllerGrantEnvelope{Payload: model.ControllerActivityGrant{PreparationID: prep.PreparationID, PreparedReceiptDigest: prep.PreparedReceiptDigest}}
		activation := json.RawMessage(`{"sourceAcceptedFixture":true}`)
		claim, step := any(owner.OwnerFirstTaskOriginal), "parent"
		var action any = advice
		if parent.Role == "manager" {
			claim = controllerInitialDecisionOriginal{owner.OwnerFirstTaskOriginal, fixtureRaw(advice), parent, declared}
			step = "initial-decision"
			fixtureComplete(t, j.reconciler, owner.FirstTaskID, "initial-decision-original", claim, declared)
			var pair model.IntentPairReceipt
			pair.FormatVersion, pair.ContextID, pair.OperationID = 1, c.ContextID, op.OperationID
			for _, name := range []string{"first", "second"} {
				item := members[name].(map[string]any)
				ref := model.IntentRef{IntentID: item["intentId"].(string), IntentRevision: 1, IntentDigest: item["intentDigest"].(string)}
				d := model.IntentAcceptance{Intent: ref, Choice: "decline", DecisionDigest: model.WorkspaceDigest(name), ReceiptDigest: model.WorkspaceDigest(name + "_receipt")}
				if name == "first" {
					id := "source_child_handle"
					d.Choice = "admit"
					d.Handle = &id
					pair.First = d
				} else {
					pair.Second = d
				}
			}
			pair.AssociationDigest = fixtureDigestField(pair, "associationDigest")
			action = pair
			f.selected, err = op.ManagerIntentSelection(pair, "first")
			if err != nil {
				t.Fatal("accepted fixture selection", err)
			}
			f.handle = model.IntentHandle{FormatVersion: 1, HandleID: *pair.First.Handle, Intent: f.selected.Ref, AssociationDigest: pair.AssociationDigest, ContextID: c.ContextID, OperationID: op.OperationID, Owner: parent.Owner, RoleBindingID: op.RoleBindingID, RoleBindingRevision: 1, AllocationID: f.selected.AllocationID, NotAfter: app.ExpiresAt}
			f.handle.NotAfter = time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
			if os.Getenv("WARPMETAL_CHILD_COMPLETION_SOURCE") == "1" {
				f.handle.NotAfter = j.reconciler.now().Add(10 * time.Minute).Format(time.RFC3339Nano)
			}
			f.handle.HandleDigest = fixtureDigestField(f.handle, "handleDigest")
		}
		fixtureComplete(t, j.reconciler, owner.FirstTaskID, step+"-prepare", claim, prep)
		if !f.freshDelivery {
			fixtureComplete(t, j.reconciler, owner.FirstTaskID, step+"-admit", map[string]any{"original": claim, "grant": grant, "activation": activation}, true)
		}
		f.deliveryParents[parent.Role] = firstTaskDeliveryParent{prepared: prep, context: c, text: text, operation: op, output: envelope, action: fixtureRaw(action)}
		stages := map[state.ControllerActivityStage]any{state.ControllerNativePrepared: model.ControllerPreparedEnvelope{Payload: prep, KeyID: app.Producer.KeyID, Signature: strings.Repeat("A", 96)}, state.ControllerApprovedContext: controllerApprovedInput{Context: c, InputText: text}, state.ControllerInstalledApplicability: qualification.Applicability{}, state.ControllerGrantOriginal: grant, state.ControllerActivated: activation, state.ControllerOutputOperation: op, state.ControllerOutputEnvelope: envelope, state.ControllerActionReceipt: action}
		if f.freshDelivery {
			delete(stages, state.ControllerGrantOriginal)
			delete(stages, state.ControllerActivated)
		}
		for stage, value := range stages {
			raw := []byte(fixtureRaw(value))
			if f.freshDelivery && stage == state.ControllerApprovedContext {
				raw, err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
			} // Same upstream writer bytes, not a reconstructed canonical replacement.
			if err = j.reconciler.Store.PinControllerActivityStage(ctx, prep.PreparationID, stage, raw); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.entry = cellV3TestEntry(t)
	if os.Getenv("WARPMETAL_CHILD_RESULT_SOURCE") == "1" {
		// Existing selected SOURCE intent content, fixed before this child tuple
		// and its binding/receipts are constructed. No foreign original retagging.
		content := members["first"].(map[string]any)["prepareBody"].(map[string]any)["content"]
		f.resultInput = string(fixtureRaw(map[string]any{"formatVersion": 1, "kind": "workspace_workflow_packet", "content": content}))
		f.entry.Instructions.InstructionDigest = model.RawPhysicalDigest([]byte(f.resultInput))
	}
	f.configureChildTerminalSource(t, j, parents[0], app)
	j.reconciler.ManagedRuntime = &firstTaskChildTerminalRuntime{firstTaskEnrollmentSourceRuntime: &firstTaskEnrollmentSourceRuntime{&firstTaskSourceRuntime{native}}, fixture: f}
	if f.freshDelivery {
		f.finishPublicDeliverySetup(t, native, app)
	}
	return f
}

// Child-only SOURCE construction shared with later stages. No first-task,
// manager pair, parent action or terminal STATE is introduced here.
func (f *firstTaskChildTerminalFixture) configureChildTerminalSource(t *testing.T, j *managerPolicyJourney, p model.ControllerParentIntent, app model.WorkspaceApplicationOperation) {
	t.Helper()
	f.entry.SandboxID, f.entry.SandboxGeneration = p.Owner.SandboxID, p.Owner.SandboxGeneration
	f.entry.OwnerCellID, f.entry.ControllerID, f.entry.ControllerRevision, f.entry.AuthorityRevision = p.Owner.CellID, p.Owner.ControllerID, p.Owner.ControllerRevision, p.Owner.AuthorityRevision
	f.entry.Profile = model.ManagedServiceV2Profile{SetupOperationID: p.Profile.SetupOperationID, ProfileID: p.Profile.ProfileID, ProfileRevision: p.Profile.ProfileRevision, ProfileDigest: p.Profile.ProfileDigest}
	// Already accepted child workspace metadata is an explicit SOURCE supplier,
	// distinct from the actual parent catalog root. It is NOT installed root proof.
	if f.ownerScopedProject {
		existing, e := j.reconciler.Store.ManagedProject(context.Background(), f.entry.Workspace.SelectionID)
		if e != nil {
			t.Fatal(e)
		}
		if existing == nil {
			e = j.reconciler.Store.PutManagedProject(context.Background(), state.LocalManagedProject{Phase: "ready", ServerID: j.manifest.ServerID, Report: model.ProjectCatalogReportV1{FormatVersion: 1, SelectionID: f.entry.Workspace.SelectionID, ProjectID: f.entry.Workspace.ProjectID, WorkspaceEpoch: f.entry.Workspace.WorkspaceEpoch, SandboxID: f.entry.SandboxID, SandboxGeneration: f.entry.SandboxGeneration, ServiceRegistrationID: nil, Label: f.entry.OwnerCellID, Designation: "team_project", RootAttestation: f.entry.Workspace.RootAttestation, Availability: "available"}, ContainerRoot: "/home/agent/projects/cell", ScopeRevision: f.entry.Workspace.ScopeRevision})
			if e != nil {
				t.Fatal(e)
			}
		} else if existing.Report.ServiceRegistrationID != nil || existing.Report.Label != f.entry.OwnerCellID || existing.Report.RootAttestation != f.entry.Workspace.RootAttestation || existing.ScopeRevision != f.entry.Workspace.ScopeRevision {
			t.Fatal("cumulative SOURCE owner workspace changed")
		}
	} else if os.Getenv("WARPMETAL_CHILD_COMPLETION_SOURCE") == "1" {
		seedCellProjectForServer(t, j.reconciler.Store, cellV2View(f.entry), "/home/agent/projects/cell", j.manifest.ServerID)
	} else {
		seedCellProject(t, j.reconciler.Store, cellV2View(f.entry), "/home/agent/projects/cell")
	}
	f.entry.DesiredRevision = j.manifest.DesiredRevision
	f.entry.CredentialBinding = *app.Dependencies.Roles[0].Projection.ModelSelection.CredentialBinding
	f.entry.RequestDigest = f.selected.LifecycleRequestDigest
}

type firstTaskChildTerminalRuntime struct {
	*firstTaskEnrollmentSourceRuntime
	fixture *firstTaskChildTerminalFixture
}

func (s *firstTaskChildTerminalRuntime) ExecManagedSupervisor(ctx context.Context, box string, action containers.ManagedSupervisorAction, raw []byte) ([]byte, []byte, error) {
	f := s.fixture
	var request map[string]any
	_ = json.Unmarshal(raw, &request)
	if request["instance"] != f.entry.Instance && request["instance"] != model.ManagedServiceProcessInstance(f.entry.Instance, f.entry.ServiceGeneration) {
		return s.parentSourceRuntime.ExecManagedSupervisor(ctx, box, action, raw)
	}
	providerID, modelID, authMode := "", "", ""
	if authority := f.entry.Authority; authority != nil {
		providerID = authority.ProviderID
		if authority.ModelID != nil {
			modelID = strings.TrimPrefix(*authority.ModelID, providerID+"/")
		}
		if authority.AuthMode != nil {
			authMode = *authority.AuthMode
		}
	}
	managerRoute := map[string]any{"managerProviderId": providerID, "managerModelId": modelID}
	switch action {
	case containers.ManagedSupervisorRebind:
		// The product launch sequence must carry the manifest authority; the
		// native manager route below is then built from this exact tuple.
		if request["provider"] != providerID || request["model"] != modelID ||
			request["authMode"] != authMode || request["restart"] != false {
			return nil, nil, fmt.Errorf("SOURCE manager binding changed the manifest authority: %#v", request)
		}
		return fixtureRaw(map[string]any{"schemaVersion": 1, "command": "rebind", "status": "applied", "applied": true, "restarted": false, "sandboxId": box, "instance": f.entry.Instance, "profileId": f.entry.Profile.ProfileID, "profileDigest": f.entry.Profile.ProfileDigest, "bindingRevision": 1, "binding": map[string]any{"provider": providerID, "model": modelID, "authMode": authMode}}), nil, nil
	case containers.ManagedSupervisorStatus, containers.ManagedSupervisorStart:
		receipt := map[string]any{"schemaVersion": 1, "command": string(action), "status": "running", "ready": true, "sandboxId": box, "instance": f.entry.Instance, "profileId": f.entry.Profile.ProfileID, "profileDigest": f.entry.Profile.ProfileDigest, "sessionId": "ses_source_nativeparent", "nativeProjectId": f.entry.NativeProjectID, "port": 18446}
		for key, value := range managerRoute {
			receipt[key] = value
		}
		return fixtureRaw(receipt), nil, nil
	case containers.ManagedSupervisorPrepare:
		f.nativePrepares++
		receipt := f.preparedSourceReceipt()
		return fixtureRaw(managedCellPrepareResultV1{SchemaVersion: 1, Command: "prepare", Status: "prepared", Ready: true, SandboxID: box, Instance: f.entry.Instance, ProfileDigest: f.entry.Profile.ProfileDigest, PreparedReceipt: &receipt}), nil, nil
	case containers.ManagedSupervisorCell:
		f.nativeExecutes++
		var call managedCellExecuteCallV3
		if err := json.Unmarshal(raw, &call); err != nil {
			return nil, nil, err
		}
		if call.PreparedReceipt == nil || call.ExecutionGrant == nil || call.ExecutionGrant.PreparedReceiptDigest != call.PreparedReceipt.PreparedReceiptDigest {
			return nil, nil, fmt.Errorf("SOURCE native tuple/grant missing")
		}
		var outcome *string
		if f.nativeState == "terminal" {
			value := "succeeded"
			outcome = &value
		}
		return fixtureRaw(managedCellExecuteResultV3{managedCellResultV1: managedCellResultV1{SchemaVersion: 1, RuntimeContractVersion: model.CellExecutionContractVersion, OperationID: f.entry.LaunchOperationID, SessionID: f.entry.NativeSessionID, MessageID: call.ExecutionGrant.InputID, Attempt: f.entry.Attempt, State: f.nativeState, Outcome: outcome}, GuardReceipt: &cellGuardReceipt{FormatVersion: 1, SessionID: f.entry.NativeSessionID, InboxID: call.ExecutionGrant.InputID, GuardID: call.ExecutionGrant.GrantID, BindingDigest: call.PreparedReceipt.BindingDigest, State: "delivered"}}), nil, nil
	default:
		return nil, nil, fmt.Errorf("unexpected SOURCE child action %s", action)
	}
}

func (f *firstTaskChildTerminalFixture) sourceCredentialIDs() (string, string) {
	if f.credentialID == "" && f.nativeCredentialID == "" {
		return "cred_cell0001", "native_cell0001"
	}
	if f.credentialID == "" || f.nativeCredentialID == "" {
		f.t.Fatal("partial SOURCE credential lease identity")
	}
	return f.credentialID, f.nativeCredentialID
}
func (f *firstTaskChildTerminalFixture) preparedSourceReceipt() model.PreparedReceipt {
	credential, native := f.sourceCredentialIDs()
	return cellV3TestReceiptWithCredentials(f.t, f.entry, credential, native)
}

func (f *firstTaskChildTerminalFixture) serve(w http.ResponseWriter, r *http.Request) bool {
	if f.completion != nil && f.completion.serve(w, r) {
		return true
	}
	if f.freshDelivery && f.delivery.serve(w, r) {
		return true
	}
	const bridge = "/internal/runtime/workspace-workflow/"
	path := r.URL.Path
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case path == bridge+"manager-intents/"+f.handle.HandleID:
		lease := f.managerLease
		if lease == "" {
			lease = "wfl_source_manager"
		}
		if r.Header.Get("X-WarpMetal-Workflow-Lease") != lease {
			f.t.Error("normal manager lease not enrolled")
		}
		write(f.handle)
	case path == bridge+"manager-intents/"+f.handle.HandleID+"/preparations":
		f.prepares++
		if f.lostChildPrepare {
			w.WriteHeader(502)
			write(map[string]any{"error": map[string]string{"code": "source_child_prepare_lost_ACK"}})
			return true
		}
		write(model.IntentPreparationReference{FormatVersion: 1, HandleID: f.handle.HandleID, Intent: f.handle.Intent, PreparationID: f.entry.PreparationID, LifecycleRequestDigest: f.selected.LifecycleRequestDigest})
	case path == bridge+"manager-intents/"+f.handle.HandleID+"/preparation-policy-intent" && f.undeliveredPrepare:
		f.policyIntentGets++
		write(f.prepareSigningIntent)
	case path == bridge+"manager-intents/"+f.handle.HandleID+"/prepared-association":
		write(f.actual)
	case path == bridge+"executions/"+f.actualExecution()+"/workflow-assignment":
		f.assigns++
		write(f.assignment)
	case path == "/internal/runtime/workspace-workflow-observations/executions/"+f.actualExecution()+"/current-snapshot":
		f.reads++
		if f.readError {
			w.WriteHeader(503)
			write(map[string]any{"error": map[string]string{"code": "source_terminal_read_unavailable"}})
			return true
		}
		write(f.currentSnapshot())
	case path == "/internal/runtime/report":
		var report model.Report
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&report) != nil {
			f.t.Fatal("normal authenticated STATE report lost child")
		}
		var observed *model.CellServiceReportV1
		for _, value := range report.CellServices {
			if value.OperationID == f.entry.OperationID && value.ServiceRegistrationID == f.entry.ServiceRegistrationID && value.NativeSessionID == f.entry.NativeSessionID && value.Child != nil && value.Child.OperationID == f.entry.LaunchOperationID {
				if observed != nil {
					f.t.Fatal("duplicate current child report")
				}
				copy := value
				observed = &copy
			}
		}
		local, err := f.r.Store.CellV3Execution(r.Context(), f.entry.PreparationID)
		if err != nil || local == nil || local.Phase != "terminal" || observed == nil || model.WorkspaceDigest(local.Report) != model.WorkspaceDigest(observed) {
			f.t.Fatal("STATE report not retained before transport", err)
		}
		f.reports++
		f.backendState = "completed"
		digest := observed.ReceiptDigest
		f.backendDigest = &digest
		write(map[string]any{"accepted": true})
	case path == "/internal/runtime/cell-credential":
		credential, _ := f.sourceCredentialIDs()
		write(api.CellCredentialResult{CredentialID: credential, ConnectionID: f.entry.CredentialBinding.ConnectionID, ConnectionRevision: f.entry.CredentialBinding.ConnectionRevision, Material: json.RawMessage(`{"type":"key","key":"SOURCE_not_provider_material"}`)})
	case path == "/internal/runtime/cell-preparation":
		var report model.CellPreparationReport
		_ = json.NewDecoder(r.Body).Decode(&report)
		control := cellV3TestControl{}
		reply, err := control.ReportCellPreparation(r.Context(), report)
		if err != nil {
			f.t.Error(err)
		}
		write(reply)
	case strings.Contains(path, f.entry.ServiceRegistrationID) && strings.HasSuffix(path, "/instructions"):
		instruction := cellInstruction(f.t)
		if f.resultInput != "" {
			instruction.Content = f.resultInput
			instruction.InstructionDigest = f.entry.Instructions.InstructionDigest
		}
		instruction.ExpiresAt = f.r.now().Add(time.Minute)
		write(instruction)
	default:
		return false
	}
	return true
}

func (f *firstTaskChildTerminalFixture) currentSnapshot() map[string]any {
	effects := []any{}
	if f.effectStatus != "" {
		effects = append(effects, map[string]any{"receiptId": "source_settled_effect", "receiptDigest": model.WorkspaceDigest("source_settled_effect_original"), "status": f.effectStatus})
	}
	return map[string]any{"executionState": f.backendState, "executionReceiptDigest": f.backendDigest, "desiredState": f.entry.DesiredState, "desiredRevision": f.entry.DesiredRevision, "managedServiceReceiptDigest": model.WorkspaceDigest("source_current_receipt"), "nativeContextDigest": model.WorkspaceDigest("source_current_native"), "role": f.entry.Role, "grants": []any{map[string]any{"grantId": f.entry.ExecutionGrant.GrantID, "state": "consumed", "fence": f.entry.Fence, "attempt": f.entry.Attempt}}, "children": []any{}, "effects": effects}
}

func (f *firstTaskChildTerminalFixture) run(t *testing.T, j *managerPolicyJourney, client api.Client) {
	t.Helper()
	ctx := context.Background()
	if f.freshDelivery {
		f.runPublicDelivery(t, j)
		return
	}
	if f.undeliveredPrepare {
		if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
			t.Fatal("expected missing prepare original", err)
		}
		j.manifest.CellEntriesV3 = []model.CellServiceV3{f.entry}
		if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
			t.Fatal("listed child tuple cannot outrun its independent prepare original", err)
		}
		if f.prepares != 1 || f.policyIntentGets != 1 || f.nativePrepares != 0 || f.nativeExecutes != 0 {
			t.Fatal("missing independent prepare control dispatched/reissued", f)
		}
		claim, err := f.r.Store.OwnedContinuationClaim(ctx, f.handle.HandleID, "prepare-policy")
		if err != nil || len(claim) != 0 {
			t.Fatal("missing original claimed owning policy POST", err)
		}
		missing := f.r.ManagedRuntime.(*firstTaskMissingPreparationRuntime)
		missing.unexpected = true
		if err := j.reconciler.Reconcile(ctx, j.manifest); err == nil || errors.Is(err, ErrControllerFirstTaskPending) {
			t.Fatal("unexpected protected read became pending/success", err)
		}
		if f.nativePrepares != 0 || f.policyIntentGets != 1 {
			t.Fatal("refusal retried signing window/native prepare", f)
		}
		return
	}
	if f.lostChildPrepare {
		if err := j.reconciler.Reconcile(ctx, j.manifest); err == nil || errors.Is(err, ErrControllerFirstTaskPending) {
			t.Fatal("lost child prepare ACK became success/pending", err)
		}
		if err := j.reconciler.Reconcile(ctx, j.manifest); !errors.Is(err, state.ErrOwnedContinuationUnknown) {
			t.Fatal("normal continuation retried lost child prepare ACK", err)
		}
		if f.prepares != 1 || f.nativePrepares != 0 || f.nativeExecutes != 0 {
			t.Fatal("UNKNOWN consumed another dispatch", f)
		}
		if _, err := f.r.ReadControllerFirstTaskResult(ctx, "firsttask_source"); !errors.Is(err, ErrControllerFirstTaskPending) {
			t.Fatal("UNKNOWN created a terminal result", err)
		}
		return
	}
	if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatal("accepted manager normal continuation", err)
	}
	if f.prepares != 1 || f.nativePrepares != 0 {
		t.Fatal("child preparation did not wait for normal manifest", f.prepares, f.nativePrepares)
	}
	j.manifest.CellEntriesV3 = []model.CellServiceV3{f.entry}
	// Create the exact domain binding from THIS child receipt; no terminal/STATE is
	// seeded. Preparation and reporting below are the ordinary V3 manifest path.
	receipt := cellV3TestReceipt(t, f.entry)
	binding := map[string]any{"workId": "source_child_work", "workRevision": 1, "bindingId": "source_child_binding", "bindingRevision": 1, "executionId": "source_child_execution", "preparationId": f.entry.PreparationID, "parentExecutionId": nil, "parentPacketId": nil, "packetId": f.entry.ParentIdentity.PacketID, "packetRevision": 1, "attempt": f.entry.Attempt, "fence": f.entry.Fence, "serviceRegistrationId": f.entry.ServiceRegistrationID, "serviceGeneration": f.entry.ServiceGeneration, "sandboxGeneration": f.entry.SandboxGeneration, "nativeSessionId": f.entry.NativeSessionID, "nativeProjectId": f.entry.NativeProjectID, "nativeLocationDigest": model.WorkspaceDigest("source_child_location"), "projectId": f.entry.Workspace.ProjectID, "workspaceEpoch": f.entry.WorkspaceEpoch, "selectionId": f.entry.Workspace.SelectionID, "scopeRevision": f.entry.Workspace.ScopeRevision, "rootAttestation": f.entry.Workspace.RootAttestation, "instructionRevision": f.entry.Instructions.InstructionRevision, "instructionDigest": f.entry.Instructions.InstructionDigest, "profileDigest": f.entry.Profile.ProfileDigest, "configDigest": f.entry.ConfigDigest}
	var body map[string]any
	claim, err := f.r.Store.OwnedContinuationClaim(ctx, "firsttask_source", "initial-decision-original")
	if err != nil {
		t.Fatal(err)
	}
	var initial controllerInitialDecisionOriginal
	_ = json.Unmarshal(claim, &initial)
	body = map[string]any{"formatVersion": 1, "requestId": f.selected.AssignmentRequestID, "binding": binding, "purpose": "implement", "plan": initial.DeclaredInput.Plan, "target": nil}
	f.actual = model.ActualPreparationAssociation{FormatVersion: 1, HandleID: f.handle.HandleID, Intent: f.handle.Intent, PreparationID: f.entry.PreparationID, PreparedReceipt: receipt, Binding: fixtureRaw(binding), AssignmentBody: fixtureRaw(body)}
	f.actual.AssociationDigest = fixtureDigestField(f.actual, "associationDigest")
	if err := f.actual.ValidateIntegrity(); err != nil {
		t.Fatal("actual domain binding rejected before normal pass", err)
	}
	for field, value := range map[string]string{"fence": strings.Repeat("b", 64), "rootAttestation": model.WorkspaceDigest("foreign_workspace")} {
		badActual := f.actual
		var badBinding map[string]any
		_ = json.Unmarshal(f.actual.Binding, &badBinding)
		badBinding[field] = value
		badActual.Binding = fixtureRaw(badBinding)
		badBody := jsonMap(t, body)
		badBody["binding"] = badBinding
		badActual.AssignmentBody = fixtureRaw(badBody)
		badActual.AssociationDigest = fixtureDigestField(badActual, "associationDigest")
		if badActual.ValidateIntegrity() == nil {
			t.Fatal("different native binding authority accepted", field)
		}
	}
	f.assignment = fixtureRaw(map[string]any{"formatVersion": 1, "assignmentId": "source_child_assignment", "assignmentDigest": model.WorkspaceDigest(body), "executionId": "source_child_execution", "purpose": "implement", "plan": initial.DeclaredInput.Plan, "target": nil, "createdAt": f.r.now().Format(time.RFC3339Nano)})
	if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatal("normal child prepare/report/assignment", err)
	}
	if f.nativePrepares != 1 || f.assigns != 1 {
		t.Fatal("prepare/assignment not normal once", f.nativePrepares, f.assigns)
	}
	f.entry = cellV3TestExecute(t, f.entry, receipt)
	f.entry.ExecutionGrant.ExpiresAt = f.r.now().Add(time.Minute).Format(time.RFC3339Nano)
	j.manifest.CellEntriesV3 = []model.CellServiceV3{f.entry}
	f.admission = model.ChildAdmissionAssociation{FormatVersion: 1, HandleID: f.handle.HandleID, PreparationAssociationDigest: f.actual.AssociationDigest, Assignment: f.assignment, AllocationID: f.selected.AllocationID, ReservationID: "source_child_reservation", PolicyDigest: model.WorkspaceDigest("source_product_policy"), ActivationDigest: model.WorkspaceDigest("source_activation"), Grant: *f.entry.ExecutionGrant}
	f.admission.AssociationDigest = fixtureDigestField(f.admission, "associationDigest")
	fixtureComplete(t, f.r, f.handle.HandleID, "adopt", map[string]any{"handleDigest": f.handle.HandleDigest, "preparedAssociationDigest": f.actual.AssociationDigest, "assignment": f.assignment, "policyDigest": f.admission.PolicyDigest, "grant": f.entry.ExecutionGrant}, f.admission)
	if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatal("native running is pending not failure", err)
	}
	if _, err := f.r.ReadControllerFirstTaskResult(ctx, "firsttask_source"); err == nil {
		t.Fatal("running child became durable task terminal")
	}
	f.nativeState = "terminal"
	if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatal("terminal report awaiting backend STATE", err)
	}
	report, err := f.r.Report(ctx, f.r.ServerID, "0.1.52")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.CellServices) != 1 {
		t.Fatal("normal report missing child", report)
	}
	if err = client.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	digest := report.CellServices[0].ReceiptDigest
	if f.reports != 1 || f.backendDigest == nil || *f.backendDigest != digest {
		t.Fatal("terminal readback bypassed actual authenticated report transport")
	}
	if os.Getenv("WARPMETAL_CHILD_COMPLETION_SOURCE") == "1" {
		f.completion = startChildCompletionSource(t, f)
	}
	err = j.reconciler.Reconcile(ctx, j.manifest)
	if os.Getenv("WARPMETAL_CHILD_RESULT_SOURCE") == "1" {
		if err == nil || !strings.Contains(err.Error(), "own required source acknowledgement missing") || f.completion.results != 0 {
			t.Fatal("missing own read ACK did not block result", err)
		}
		f.completion.artifact.assertForeignMetadataDenied(t, j.manifest)
		f.completion.result.allowRead = true
		err = j.reconciler.Reconcile(ctx, j.manifest)
	}
	if os.Getenv("WARPMETAL_CHILD_RESULT_LOST_ACK_SOURCE") == "1" {
		f.completion.result.assertLostAcknowledgement(t, j.databasePath, j.manifest, err)
		return
	}
	if os.Getenv("WARPMETAL_CHILD_SETTLEMENT_LOST_ACK_SOURCE") == "1" {
		f.completion.facts.assertLostAcknowledgement(t, j.databasePath, j.manifest, err)
		return
	}
	if os.Getenv("WARPMETAL_CHILD_ARTIFACT_LOST_ACK_SOURCE") == "1" {
		f.completion.artifact.assertLostAcknowledgement(t, j.databasePath, j.manifest, err)
		return
	}
	if err != nil {
		if f.completion != nil {
			t.Logf("child completion transport counts: operations=%d proofs=%d enrollments=%d", f.completion.operations, f.completion.proofs, f.completion.enrollments)
		}
		t.Fatal("normal authenticated terminal readback", err)
	}
	result, err := f.r.ReadControllerFirstTaskResult(ctx, "firsttask_source")
	if err != nil || result.State != "completed" || len(result.Children) != 1 || result.Children[0].ExecutionID != "source_child_execution" || result.Children[0].NativeReport.ReceiptDigest != digest {
		t.Fatal("durable owning result absent", result, err)
	}
	if f.prepares != 1 || f.assigns != 1 || f.nativePrepares != 1 || f.nativeExecutes != 2 {
		t.Fatal("terminal read redispatched native work", f)
	}
	if f.completion != nil {
		f.completion.assertEnrolled(t)
		if f.completion.artifact != nil && f.completion.result == nil {
			f.completion.artifact.assertForeignMetadataDenied(t, j.manifest)
		}
	}
	if os.Getenv("WARPMETAL_COMPLETED_FACT_EXPIRY_SOURCE") == "1" {
		runCompletedFactExpirySource(t, f, j)
	}
	// Existing settled business-effect records do not make exact native STATE
	// terminal unavailable and do not relabel it as business/cash acceptance.
	f.effectStatus = "settled"
	if err = j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatal("settled current effect blocked immutable terminal replay", err)
	}
	f.effectStatus = "unknown"
	if err = j.reconciler.Reconcile(ctx, j.manifest); err == nil || errors.Is(err, ErrControllerFirstTaskPending) {
		t.Fatal("UNKNOWN effect became expected pending/success", err)
	}
	f.effectStatus = "settled"
	f.readError = true
	if err = j.reconciler.Reconcile(ctx, j.manifest); err == nil {
		t.Fatal("unexpected authenticated readback failure became pending/success")
	}
	f.readError = false
	bad := model.WorkspaceDigest("wrong_terminal")
	f.backendDigest = &bad
	if err = j.reconciler.Reconcile(ctx, j.manifest); err == nil {
		t.Fatal("mismatched durable original became pending/success")
	}
	claim, err = f.r.Store.OwnedContinuationClaim(ctx, "firsttask_source", "result")
	if err != nil || len(claim) == 0 {
		t.Fatal("result not durable", err)
	}
	if err = f.r.Store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(j.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	f.r.Store = reopened
	f.r.ManagedCatalog.(*workspacecatalog.Catalog).State = reopened
	if f.completion != nil {
		f.completion.runtime.parentSourceRuntime.store = reopened
	} else {
		f.r.ManagedRuntime.(*firstTaskChildTerminalRuntime).parentSourceRuntime.store = reopened
	}
	retained, err := f.r.ReadControllerFirstTaskResult(ctx, "firsttask_source")
	if err != nil || model.WorkspaceDigest(retained) != model.WorkspaceDigest(result) {
		t.Fatal("terminal original changed/lost after SAME SQLite reopen", err)
	}
	if f.completion != nil {
		f.backendDigest = &digest
		if err = j.reconciler.Reconcile(ctx, j.manifest); err != nil {
			t.Fatal("completed child enrollment replay after SAME SQLite reopen", err)
		}
		f.completion.assertEnrolled(t)
	}
	if os.Getenv("WARPMETAL_LATER_CONTROLLER_STAGE_SOURCE") == "1" {
		runLaterControllerStageSource(t, f, j)
	}
}

// Existing offline fixture generator supplies the unsigned policy wire ONLY.
// Missing/private-file ownership is a SOURCE supplier here; the separate Store
// test executes protected leaf reads. This is NOT positive policy delivery proof.
func (f *firstTaskChildTerminalFixture) configureUndeliveredPreparation(t *testing.T) {
	t.Helper()
	base := os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE")
	if base == "" {
		t.Skip("requires retained SOURCE fixture root")
	}
	root, err := os.MkdirTemp(base, "firsttask-undelivered-prepare-")
	if err != nil {
		t.Fatal(err)
	}
	packet := filepath.Join(root, "fixture.json")
	command := exec.Command("python3", "-B", "../qualification/testdata/child_product_boundary_fixture.py", "../workflowcontract/schema", os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET"), packet)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("existing SOURCE unsigned wire supplier: %v %s", err, out)
	}
	raw, err := os.ReadFile(packet)
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		AuthoritySynthetic bool `json:"authoritySynthetic"`
		Prepare            struct {
			Generation struct {
				PreparationPolicy struct {
					Payload json.RawMessage `json:"payload"`
				} `json:"preparationPolicy"`
			} `json:"generation"`
		} `json:"prepare"`
	}
	if json.Unmarshal(raw, &source) != nil || !source.AuthoritySynthetic {
		t.Fatal("unsigned SOURCE policy fixture provenance refused")
	}
	f.prepareSigningIntent = fixtureRaw(map[string]any{"formatVersion": 1, "handleId": f.handle.HandleID, "stage": "prepare", "payload": source.Prepare.Generation.PreparationPolicy.Payload, "policyBinding": nil, "notBefore": time.Now().UTC().Format(time.RFC3339Nano)})
	f.r.ManagedRuntime = &firstTaskMissingPreparationRuntime{firstTaskChildTerminalRuntime: f.r.ManagedRuntime.(*firstTaskChildTerminalRuntime), root: root}
	t.Log("retained SOURCE unsigned/missing prepare fixture", root)
}

type firstTaskMissingPreparationRuntime struct {
	*firstTaskChildTerminalRuntime
	root       string
	unexpected bool
}

func (s *firstTaskMissingPreparationRuntime) ReadChildPolicyOriginal(context.Context, model.Sandbox, model.IntentHandle, string, string, json.RawMessage) (json.RawMessage, error) {
	if s.unexpected {
		return nil, qualification.ErrUntrusted
	}
	return nil, qualification.ErrOperatorDeliveryPending
}
func (s *firstTaskMissingPreparationRuntime) ReadChildActivationOriginal(context.Context, model.Sandbox, model.IntentHandle, qualification.RealCase, json.RawMessage) (json.RawMessage, error) {
	return nil, qualification.ErrUntrusted
}
func (s *firstTaskMissingPreparationRuntime) ExportChildSigningIntent(_ context.Context, _ model.Sandbox, h model.IntentHandle, stage string, raw []byte) error {
	if stage != "prepare" {
		return qualification.ErrUntrusted
	}
	path := filepath.Join(s.root, "child-prepare-policy-intent-"+h.HandleID+".json")
	if original, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(original, raw) {
			return qualification.ErrUntrusted
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}

// Existing synthetic preparation construction, shared by SOURCE output fixtures
// and the pre-execution exporter. It is never an installed-native observation.
func sourceControllerPrepared(t *testing.T, parent model.ControllerParentIntent, app model.WorkspaceApplicationOperation, native model.ManagedNativeRegistrationV1, input, text string) model.ControllerPreparedReceipt {
	t.Helper()
	prep := sourceControllerPreparedShape(parent, app, native, input, text)
	if err := prep.Validate(); err != nil {
		t.Fatal("accepted fixture receipt", err)
	}
	return prep
}

// Schema supplier only: a fresh declared SOURCE shape, never native evidence.
// Executable legacy callers retain their Validate check in the wrapper above.
func sourceControllerPreparedShape(parent model.ControllerParentIntent, app model.WorkspaceApplicationOperation, native model.ManagedNativeRegistrationV1, input, text string) model.ControllerPreparedReceipt {
	prep := model.ControllerPreparedReceipt{FormatVersion: 1, TargetKind: "controller_activity", PreparationID: "source_accepted_" + parent.Role, CredentialID: "source_credential", NativeCredentialID: "source_native_credential", PreparedTuple: model.ControllerPreparedTuple{Owner: parent.Owner, Role: parent.Role, ServiceRegistrationID: parent.ServiceRegistrationID, ServiceGeneration: parent.ServiceGeneration, NativeRegistration: native, RoleAgentDigest: parent.RoleAgentDigest, ConfigurationDigest: app.ConfigurationDigest, ConfigDigest: parent.ConfigDigest, InputID: input, InputDigest: model.RawPhysicalDigest([]byte(text)), Authority: app.Dependencies.Roles[0].Projection.ModelSelection.Authority, CredentialBinding: *app.Dependencies.Roles[0].Projection.ModelSelection.CredentialBinding}}
	bindingPreimage := map[string]any{"preparationId": prep.PreparationID, "preparedTuple": prep.PreparedTuple, "credentialId": prep.CredentialID, "nativeCredentialId": prep.NativeCredentialID}
	prep.BindingDigest = model.WorkspaceDigest(bindingPreimage)
	bindingPreimage["bindingDigest"] = prep.BindingDigest
	prep.PreparedReceiptDigest = model.WorkspaceDigest(bindingPreimage)
	return prep
}
