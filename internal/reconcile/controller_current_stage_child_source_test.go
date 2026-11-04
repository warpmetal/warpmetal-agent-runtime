package reconcile

// Opt-in continuation of the SAME current app/declaration journey. Parent
// acceptance/native facts are freshly constructed SOURCE suppliers before any
// hashes/signatures. No backend success row, prior signature or output is reused.
import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

func TestControllerCurrentAcceptedLaterIntentThroughNormalReconcile(t *testing.T) {
	t.Setenv("WARPMETAL_CURRENT_STAGE_CHILD_SOURCE", "1")
	TestControllerCurrentLaterStageDiscoveryThroughNormalReconcile(t)
}

type currentStageAcceptedSource struct {
	Stage    controllerStageOriginal
	ID       string
	Selected model.ManagerIntentSelection
	Handle   model.IntentHandle
}

func seedCurrentStageAcceptedChildSource(t *testing.T, j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, runtime *currentStageSourceRuntime, readout model.ControllerStageReadout, prepared model.ControllerPreparedReceipt, contextBody, policy, intent map[string]any, s *laterControllerStageSource, resultClaim, resultRaw json.RawMessage) currentStageAcceptedSource {
	t.Helper()
	ctx := context.Background()
	app := runtime.application
	parent := runtime.policy.ApplicationIdentity().Intent
	raw, e := os.ReadFile(os.Getenv("WARPMETAL_CURRENT_STAGE_TEMPLATE"))
	if e != nil {
		t.Fatal(e)
	}
	var template map[string]any
	if json.Unmarshal(raw, &template) != nil {
		t.Fatal("actual unsigned output4 shape")
	}
	var contextValue model.ControllerApprovedInputContext
	publicDeliveryDecode(t, contextBody, &contextValue)
	var item qualification.ControllerDeclaredInput
	publicDeliveryDecode(t, readout.Item, &item)
	purpose := intent["purpose"].(string)
	childKind := map[string]string{"integrate": "integrator", "review": "reviewer"}[purpose]
	if childKind == "" || readout.AllocationName != "manager_"+purpose {
		t.Fatal("current SOURCE accepted stage purpose/allocation")
	}
	filename := func(name string) string {
		if purpose == "integrate" {
			return name
		}
		return strings.Replace(name, "current-stage-", "current-stage-"+purpose+"-", 1)
	}
	ref := model.IntentRef{IntentID: intent["intentId"].(string), IntentRevision: 1, IntentDigest: intent["intentDigest"].(string)}
	body := map[string]any{"formatVersion": 2, "requestId": contextValue.WorkflowRequestID, "plan": contextValue.Plan, "purpose": purpose, "member": map[string]any{"intent": ref, "expectedAdmissionRevision": intent["expectedAdmissionRevision"], "choice": "admit", "reason": "Explicit SOURCE accepted later " + purpose + " decision"}}
	proposal, e := model.ControllerProposal(contextValue, string(fixtureRaw(body)))
	if e != nil {
		t.Fatal("fresh SOURCE manager decision", e)
	}
	op, proof := sourceCurrentAcceptedParentOutput(t, j, native, d, app, runtime.policy, prepared, contextValue, item, body, purpose, template)
	handleID := "source_current_" + childKind + "_handle"
	receipt := model.IntentReceipt{FormatVersion: 2, ContextID: contextValue.ContextID, OperationID: op.OperationID, AssociationDigest: model.WorkspaceDigest(map[string]any{"operationDigest": op.OperationDigest, "proofDigest": model.WorkspaceDigest(proof.Payload), "lineageDigest": model.WorkspaceDigest(op.Lineage), "body": proposal.Body, "action": contextValue.Target.Kind, "resource": contextValue.ContextID}), Member: model.IntentAcceptance{Intent: ref, ExpectedAdmissionRevision: 0, Choice: "admit", DecisionDigest: model.WorkspaceDigest(body), Handle: &handleID, ReceiptDigest: model.WorkspaceDigest(map[string]any{"classification": "SOURCE decision receipt", "body": body})}}
	var accepted model.ManagerActionReceipt
	publicDeliveryDecode(t, receipt, &accepted)
	if accepted.ValidateOutput(op, proof) != nil {
		t.Fatal("fresh SOURCE association recipe")
	}
	selected, e := accepted.Select(op, "member")
	if e != nil {
		t.Fatal("fresh SOURCE single selection", e)
	}
	handle := model.IntentHandle{FormatVersion: 1, HandleID: handleID, ContextID: op.Context.ContextID, OperationID: op.OperationID, AssociationDigest: receipt.AssociationDigest, Intent: ref, Owner: parent.Owner, RoleBindingID: op.RoleBindingID, RoleBindingRevision: op.RoleBindingRevision, AllocationID: selected.AllocationID, NotAfter: selected.NotAfter}
	handle.HandleDigest = fixtureDigestField(handle, "handleDigest")
	stage := controllerStageOriginal{readout, item}
	id := "ctrlstage_" + model.WorkspaceDigest(map[string]any{"caseManifestDigest": readout.CaseManifestDigest, "allocationId": item.AllocationID, "serviceRegistrationId": parent.ServiceRegistrationID})[7:]
	fixtureComplete(t, j.reconciler, id, "parent-prepare", stage, prepared)
	var preparedEnvelope model.ControllerPreparedEnvelope
	publicDeliveryDecode(t, sourceSigned(t, native.key, app.Producer.KeyID, prepared), &preparedEnvelope)
	for name, value := range map[state.ControllerActivityStage]any{state.ControllerNativePrepared: preparedEnvelope, state.ControllerApprovedContext: controllerApprovedInput{Context: contextValue, InputText: item.InputText}, state.ControllerPolicyVerified: runtime.policy, state.ControllerInstalledApplicability: runtime.policy.Applicability, state.ControllerOutputOperation: op, state.ControllerOutputEnvelope: proof, state.ControllerActionReceipt: receipt} {
		if e = j.reconciler.Store.PinControllerActivityStage(ctx, prepared.PreparationID, name, fixtureRaw(value)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = j.reconciler.readControllerParentActionReceiptLocked(ctx, prepared.PreparationID); e != nil {
		t.Fatal("SOURCE current accepted-action readout", e)
	}
	d.writeOriginal(t, filepath.Join(d.root, filename("current-stage-accepted-action.json")), fixtureRaw(map[string]any{"classification": "new explicit SOURCE upstream parent acceptance and native values; no actual native/provider/backend acceptance claimed", "operation": op, "proof": proof, "receipt": receipt, "handle": handle}), 0600)
	return currentStageAcceptedSource{stage, id, selected, handle}
}

func runCurrentStageAcceptedChildSource(t *testing.T, j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, runtime *currentStageSourceRuntime, readout model.ControllerStageReadout, prepared model.ControllerPreparedReceipt, contextBody, policy, intent map[string]any, s *laterControllerStageSource, resultClaim, resultRaw json.RawMessage) {
	t.Helper()
	accepted := seedCurrentStageAcceptedChildSource(t, j, native, d, runtime, readout, prepared, contextBody, policy, intent, s, resultClaim, resultRaw)
	stage, id, selected, handle := accepted.Stage, accepted.ID, accepted.Selected, accepted.Handle
	handleID, ref := handle.HandleID, handle.Intent
	ctx := context.Background()
	app := runtime.application
	if os.Getenv("WARPMETAL_CURRENT_STAGE_TERMINAL_SOURCE") == "1" {
		runCurrentStageTerminalSource(t, j, native, d, runtime, stage, id, selected, handle, intent, resultClaim, resultRaw)
		return
	}

	gets, prepares := 0, 0
	previous := native.sourceHTTP
	native.sourceHTTP = func(w http.ResponseWriter, req *http.Request) bool {
		prefix := "/internal/runtime/workspace-workflow/manager-intents/" + handleID
		if req.URL.Path == prefix || req.URL.Path == prefix+"/preparations" {
			if req.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_current_stage" {
				t.Error("later child lost exact manager lease")
				w.WriteHeader(400)
				return true
			}
			if req.URL.Path == prefix {
				if req.Method != "GET" {
					t.Error("handle method")
				}
				gets++
				_, _ = w.Write(fixtureRaw(handle))
				return true
			}
			var call model.IntentPrepareRequest
			if req.Method != "POST" || json.NewDecoder(req.Body).Decode(&call) != nil || call.HandleID != handle.HandleID || call.RequestID != selected.PrepareRequestID || call.ExpectedAdmissionRevision != selected.ExpectedAdmissionRevision {
				t.Error("later child prepare request drift")
				w.WriteHeader(400)
				return true
			}
			prepares++
			_, _ = w.Write(fixtureRaw(model.IntentPreparationReference{FormatVersion: 1, HandleID: handleID, Intent: ref, PreparationID: "source_current_integrator_preparation", LifecycleRequestDigest: selected.LifecycleRequestDigest}))
			return true
		}
		return previous(w, req)
	}
	err := j.reconciler.Reconcile(ctx, j.manifest)
	after, e := j.reconciler.Store.OwnedContinuationResult(ctx, app.OperationID, "source-reported-result", resultClaim)
	if e != nil || string(after) != string(resultRaw) {
		t.Fatal("upstream SOURCE result changed", e)
	}
	d.writeOriginal(t, filepath.Join(d.root, "current-stage-child-observation.json"), fixtureRaw(map[string]any{"classification": "normal SOURCE later-child continuation from explicit accepted parent original", "stageReads": s.reads, "handleGET": gets, "childPrepare": prepares, "reconcileError": func() any {
		if err != nil {
			return err.Error()
		}
		return nil
	}(), "nativeRuns": 0, "externalProviderRequests": 0}), 0600)
	t.Log("retained current accepted later-child SOURCE boundary", d.root)
	if gets != 1 || prepares != 1 {
		t.Fatalf("normal accepted later manager_intent did not progress distinct integrator: handleGET=%d childPrepare=%d err=%v", gets, prepares, err)
	}
	if err != nil {
		t.Fatal("later child preparation SOURCE pass", err)
	}
	if e = j.reconciler.Store.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := state.Open(j.databasePath)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	j.reconciler.Store, native.store = reopened, reopened
	j.reconciler.ManagedCatalog.(*workspacecatalog.Catalog).State = reopened
	if e = j.reconciler.Reconcile(ctx, j.manifest); e != nil {
		t.Fatal("later child same SQLite replay", e)
	}
	if prepares != 1 {
		t.Fatal("later child duplicated preparation after reopen", prepares)
	}
}

// Shared only by fresh SOURCE accepted-parent constructors. Original caller
// choices/identity and canonical output/proof recipes are preserved.
func sourceCurrentAcceptedParentOutput(t *testing.T, j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, app model.WorkspaceApplicationOperation, policy qualification.ControllerPolicy, prepared model.ControllerPreparedReceipt, contextValue model.ControllerApprovedInputContext, item qualification.ControllerDeclaredInput, body any, purpose string, template map[string]any, requestID ...string) (model.ControllerOutputOperation, model.ControllerOutputEnvelope) {
	t.Helper()
	ctx, now := context.Background(), j.reconciler.now()
	parent, n := policy.ApplicationIdentity().Intent, policy.NativeIdentity()
	proposal, e := model.ControllerProposal(contextValue, string(fixtureRaw(body)))
	if e != nil {
		t.Fatal("fresh SOURCE parent proposal", e)
	}
	var output model.ControllerOutputNativeReadback
	publicDeliveryDecode(t, sourceObject(sourceObject(sourceObject(template["proof"])["payload"])["nativeReceipt"])["nativeReadback"], &output)
	var published struct {
		Demand qualification.ChildEnvelope[qualification.DemandManifest]
	}
	raw, e := os.ReadFile(filepath.Join(d.root, "controller-provider-preexecution-source.json"))
	if e != nil || json.Unmarshal(raw, &published) != nil {
		t.Fatal("fresh current demand", e)
	}
	if published.Demand.Payload.FormatVersion != 3 {
		t.Fatal("current SOURCE stage requires demand3")
	}
	modelIndex := 1
	for _, a := range published.Demand.Payload.AllocationList {
		if a.LastPhysicalIndex < item.PhysicalIndex {
			modelIndex += a.ModelRequests
		}
	}
	grant := model.ControllerActivityGrant{FormatVersion: 1, TargetKind: "controller_activity", GrantID: "grant_source_current_" + purpose, PreparationID: prepared.PreparationID, PreparedReceiptDigest: prepared.PreparedReceiptDigest, ReservationID: "reservation_source_current_" + purpose, CaseID: contextValue.CaseID, CaseManifestDigest: contextValue.CaseManifestDigest, PolicyDigest: contextValue.PolicyDigest, RequestIndex: modelIndex, PhysicalIndex: item.PhysicalIndex, MaxInputTokens: 1000, MaxOutputTokens: 1000, MaxUSDMicros: 421000, DeadlineAt: now.Add(105 * time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(110 * time.Second).Format(time.RFC3339Nano)}
	no := &output.Data.ControllerOutput
	no.Identity = fixtureRaw(n)
	no.Admission = model.ControllerAdmission{FormatVersion: 1, TargetKind: "controller_activity", PreparedReceipt: prepared, Grant: grant}
	no.Output.Text = string(fixtureRaw(body))
	no.Lineage.SessionID = prepared.PreparedTuple.NativeRegistration.NativeSessionID
	no.Lineage.InputID = prepared.PreparedTuple.InputID
	no.Lineage.InputDigest = prepared.PreparedTuple.InputDigest
	no.Lineage.InputUTF8Bytes = len(item.InputText)
	no.Lineage.GrantID = grant.GrantID
	no.Lineage.PreparationID = prepared.PreparationID
	no.Lineage.PreparedReceiptDigest = prepared.PreparedReceiptDigest
	no.Lineage.AssistantMessageID = "msg_source_current_" + purpose
	no.Lineage.Agent = n.Projection.NativeAgentID
	no.Lineage.Model.ProviderID = "deepseek"
	no.Lineage.Model.ID = "deepseek-flash"
	no.Lineage.OutputDigest = model.ControllerTextDigest(no.Output.Text)
	no.Lineage.OutputUTF8Bytes = len(no.Output.Text)
	setEvent := func(event *model.ControllerEventRef) {
		prefix := "evt_current_stage_"
		if purpose == "review" {
			prefix = "evt_current_stage_review_"
		}
		event.ID = prefix + strings.TrimPrefix(event.ID, "evt_")
		event.Created = now.UnixMilli()
		event.Durable.AggregateID = no.Lineage.SessionID
	}
	for _, event := range []*model.ControllerEventRef{&no.Events.Enqueued, &no.Events.ExecutionStarted, &no.Events.Delivered, &no.Events.StepEnded, &no.Events.Terminal} {
		setEvent(event)
	}
	for i := range no.Events.StepStarted {
		setEvent(&no.Events.StepStarted[i])
	}
	for i := range no.Events.TextParts {
		setEvent(&no.Events.TextParts[i].Started)
		setEvent(&no.Events.TextParts[i].Ended)
	}
	no.Current.ObservedAt = now.UnixMilli()
	lineage, e := output.Normalize(item.InputText)
	if e != nil {
		t.Fatal("fresh SOURCE native deterministic lineage", e)
	}
	local, e := j.reconciler.Store.ControllerParent(ctx, parent.ServiceRegistrationID)
	if e != nil || local == nil {
		t.Fatal(e)
	}
	o := parent.Owner
	op := model.ControllerOutputOperation{FormatVersion: 4, Kind: "controller_output", OperationID: "source_current_" + purpose + "_output", RequestID: "source_current_" + purpose + "_output_request", Context: contextValue, RoleBindingID: "source_current_manager_binding", RoleBindingRevision: 1, Subject: model.ControllerOutputSubject{AccountID: o.AccountID, TaskID: o.TaskID, ServerID: o.ServerID, SandboxID: o.SandboxID, SandboxGeneration: o.SandboxGeneration, CellID: o.CellID, Role: parent.Role, ControllerID: o.ControllerID, ControllerRevision: o.ControllerRevision, AuthorityRevision: o.AuthorityRevision, ServiceRegistrationID: parent.ServiceRegistrationID, ServiceGeneration: parent.ServiceGeneration, NativeSessionID: no.Lineage.SessionID}, Workspace: parent.Workspace, ApplicationRoleAgentDigest: parent.RoleAgentDigest, ApplicationConfigDigest: parent.ConfigDigest, NativeRoleAgentDigest: n.Intent.RoleAgentDigest, NativeConfigDigest: n.Intent.ConfigDigest, IdentityAssociationDigest: policy.IdentityAssociation.AssociationDigest, ProviderPolicyDigest: policy.ProviderPolicyDigest, ConfigurationDigest: app.ConfigurationDigest, ManagedServiceReceiptDigest: local.Report.ReceiptDigest, Producer: app.Producer, Lineage: lineage, Proposal: proposal, ExpiresAt: now.Add(110 * time.Second).Format(time.RFC3339Nano)}
	if len(requestID) > 0 {
		op.RequestID = requestID[0]
	}
	op.OperationDigest = fixtureDigestField(op, "operationDigest")
	d.writeOriginal(t, filepath.Join(d.root, "current-parent-"+purpose+"-output4-preimage.json"), fixtureRaw(op), 0600)
	var verified model.ControllerOutputOperation
	if e = json.Unmarshal(fixtureRaw(op), &verified); e != nil {
		t.Fatal("fresh SOURCE output4 preimage", e)
	}
	payload := model.ControllerOutputPayload{FormatVersion: 1, Purpose: "workspace_workflow_controller_output", RequestID: op.RequestID, TaskID: o.TaskID, NodeTokenHash: app.Producer.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: now.Format(time.RFC3339Nano), NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: local.Report.ReceiptDigest, OperationID: op.OperationID, OperationDigest: op.OperationDigest, NativeReceipt: model.ControllerOutputReadback{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: parent.ServiceRegistrationID, ServiceGeneration: parent.ServiceGeneration, NativeSessionID: no.Lineage.SessionID, NativeProjectID: prepared.PreparedTuple.NativeRegistration.NativeProjectID, NativeLocationDigest: prepared.PreparedTuple.NativeRegistration.NativeLocationDigest, Role: parent.Role, RootAttestation: parent.Workspace.RootAttestation, ObservedAt: now.Format(time.RFC3339Nano), Lineage: lineage, NativeReadback: output}}
	var proof model.ControllerOutputEnvelope
	publicDeliveryDecode(t, sourceSigned(t, native.key, app.Producer.KeyID, payload), &proof)
	if e = workflowcontract.Validate(workflowcontract.Producer, "controllerOutputEnvelope", fixtureRaw(proof)); e != nil {
		t.Fatal("fresh SOURCE output envelope", e)
	}
	return op, proof
}
