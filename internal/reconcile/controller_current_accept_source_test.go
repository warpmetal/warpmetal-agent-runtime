package reconcile

// Continues the SAME current SOURCE declaration/child/review journey through
// the ordinary manager output operation and signed action transport. Upstream
// prepared/admitted native DATA and signer remain explicit SOURCE suppliers.
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

func TestControllerCurrentManagerAcceptanceThroughNormalReconcile(t *testing.T) {
	if source := os.Getenv("WARPMETAL_CONTROLLER_CAPTURE_EXPORT_SOURCE"); source != "" {
		exportCurrentControllerCaptureSource(t, source, os.Getenv("WARPMETAL_CONTROLLER_CAPTURE_EXPORT_ROOT"))
		return
	}
	t.Setenv("WARPMETAL_CURRENT_ACCEPT_SOURCE", "1")
	t.Setenv("WARPMETAL_CURRENT_STAGE_REVIEW_SOURCE", "1")
	t.Setenv("WARPMETAL_CURRENT_STAGE_FACT_EXPIRY_SOURCE", "1")
	t.Setenv("WARPMETAL_REVIEW_TERMINAL_MODE", "valid")
	TestControllerCurrentLaterIntegratorTerminalThroughNormalReconcile(t)
}

type currentAcceptSourceRuntime struct {
	*currentStageTerminalSourceRuntime
	t                *testing.T
	policy           qualification.ControllerPolicy
	activation       qualification.ControllerActivation
	operation        model.ControllerOutputOperation
	proof            model.ControllerOutputEnvelope
	capture          qualification.ControllerCapture
	captures, proofs int
}

func (s *currentAcceptSourceRuntime) VerifyControllerPolicy(_ context.Context, _ model.Sandbox, digest string, w qualification.ControllerPolicyWitness) (qualification.ControllerPolicy, error) {
	if digest != model.WorkspaceDigest(s.policy) || model.WorkspaceDigest(w.Identity) != model.WorkspaceDigest(s.policy.ApplicationIdentity()) {
		return qualification.ControllerPolicy{}, qualification.ErrUntrusted
	}
	return s.policy, nil
}
func (s *currentAcceptSourceRuntime) ReadControllerActivation(_ context.Context, _ model.Sandbox, p qualification.ControllerPolicy, r model.ControllerPreparedReceipt, _ bool) (qualification.ControllerActivation, error) {
	if model.WorkspaceDigest(p) != model.WorkspaceDigest(s.policy) || !reflect.DeepEqual(r, s.activation.Admission.PreparedReceipt) {
		return qualification.ControllerActivation{}, qualification.ErrUntrusted
	}
	return s.activation, nil
}
func (s *currentAcceptSourceRuntime) AttestControllerOutput(_ context.Context, op model.ControllerOutputOperation, c qualification.ControllerCapture, w qualification.ControllerOutputWitness) (model.ControllerOutputEnvelope, error) {
	if !reflect.DeepEqual(op, s.operation) || model.WorkspaceDigest(c) != model.WorkspaceDigest(s.capture) || model.WorkspaceDigest(w.Policy) != model.WorkspaceDigest(s.policy) {
		return model.ControllerOutputEnvelope{}, qualification.ErrUntrusted
	}
	s.proofs++
	return s.proof, nil
}
func (s *currentAcceptSourceRuntime) ExecManagedSupervisor(ctx context.Context, box string, action containers.ManagedSupervisorAction, raw []byte) ([]byte, []byte, error) {
	if action == containers.ManagedSupervisorControllerOutput {
		var v struct{ Admission model.ControllerAdmission }
		_ = json.Unmarshal(raw, &v)
		if !reflect.DeepEqual(v.Admission, s.activation.Admission) {
			s.t.Fatal("accept SOURCE admission drift")
		}
		s.captures++
		return fixtureRaw(map[string]any{"schemaVersion": 1, "command": "controller-output", "status": "observed", "nativeOutput": s.capture.NativeOutput, "nativeLog": s.capture.NativeLog}), nil, nil
	}
	return s.currentStageTerminalSourceRuntime.ExecManagedSupervisor(ctx, box, action, raw)
}

func runCurrentManagerAcceptSource(t *testing.T, j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, reviewer *currentStageTerminalSourceRuntime, reviewStage controllerStageOriginal, reviewID string, review *currentStageReviewCompletionSource, candidate map[string]any, resultClaim, resultRaw json.RawMessage) {
	t.Helper()
	ctx := context.Background()
	now := j.reconciler.now()
	runtime := reviewer.currentStageSourceRuntime
	app := runtime.application
	parent := runtime.policy.ApplicationIdentity().Intent
	var result map[string]any
	publicDeliveryDecode(t, resultRaw, &result)
	target := map[string]any{"resultId": result["resultId"], "resultRevision": result["resultRevision"], "resultDigest": result["resultDigest"]}
	var reviewed map[string]any
	publicDeliveryDecode(t, review.receipt, &reviewed)
	selected := map[string]any{"kind": "result_decision", "role": "manager", "resourceId": result["resultId"], "result": target, "resultReceipt": json.RawMessage(resultRaw), "candidate": candidate, "review": json.RawMessage(review.receipt), "expectedDecisionRevision": 0}
	var published struct {
		Demand qualification.ChildEnvelope[qualification.DemandManifest]
	}
	raw, e := os.ReadFile(filepath.Join(d.root, "controller-provider-preexecution-source.json"))
	if e != nil || json.Unmarshal(raw, &published) != nil {
		t.Fatal(e)
	}
	var allocation qualification.DemandAllocation
	for _, a := range published.Demand.Payload.AllocationList {
		if a.Name == "manager_accept" {
			allocation = a
		}
	}
	if allocation.AllocationID == "" {
		t.Fatal("SOURCE manager_accept allocation absent")
	}
	policy := runtime.policy
	policy.AllocationID = allocation.AllocationID
	policy.ExpiresAt = now.Add(115 * time.Second).Format(time.RFC3339Nano)
	text := "SOURCE manager_accept: decide only the original result after exact first integration candidate and independent reviewer approval."
	var item qualification.ControllerDeclaredInput
	publicDeliveryDecode(t, map[string]any{"serviceRegistrationId": parent.ServiceRegistrationID, "inputId": "msg_source_current_accept", "inputText": text, "policyDigest": model.WorkspaceDigest(policy), "workflowRequestId": "request_source_current_accept", "plan": reviewStage.Declared.Plan, "target": selected, "allocationId": allocation.AllocationID, "preparationOrdinal": allocation.PreparationOrdinal, "physicalIndex": allocation.FirstPhysicalIndex}, &item)
	readout := reviewStage.Readout
	readout.AllocationName = "manager_accept"
	readout.Item = fixtureRaw(item)
	readout.DeclarationItemDigest = model.WorkspaceDigest(item)
	var oldEnvelope struct{ Payload json.RawMessage }
	publicDeliveryDecode(t, runtime.declaration, &oldEnvelope)
	declaration := publicDeliveryMap(oldEnvelope.Payload)
	declaration["inputs"] = append(declaration["inputs"].([]any), publicDeliveryMap(item))
	declaration["declaredAt"], declaration["notAfter"] = now.Format(time.RFC3339Nano), now.Add(110*time.Second).Format(time.RFC3339Nano)
	if e = workflowcontract.Validate(workflowcontract.ManagerSingle, "inputDeclarationPayload4", fixtureRaw(declaration)); e != nil {
		t.Fatal("cumulative accept declaration", e)
	}
	runtime.declaration = sourceSigned(t, d.operator, "source_independent_operator", declaration)
	runtime.readouts["manager_accept"] = readout
	stage := controllerStageOriginal{readout, item}
	id := controllerStageID(stage)
	local, e := j.reconciler.Store.ControllerParent(ctx, parent.ServiceRegistrationID)
	if e != nil || local == nil {
		t.Fatal(e)
	}
	prepared := sourceControllerPreparedShape(policy.NativeIdentity().Intent, app, *local.Report.NativeRegistration, item.InputID, text)
	prepared.PreparationID = "source_prepared_manager_accept"
	basis := map[string]any{"preparationId": prepared.PreparationID, "preparedTuple": prepared.PreparedTuple, "credentialId": prepared.CredentialID, "nativeCredentialId": prepared.NativeCredentialID}
	prepared.BindingDigest = model.WorkspaceDigest(basis)
	basis["bindingDigest"] = prepared.BindingDigest
	prepared.PreparedReceiptDigest = model.WorkspaceDigest(basis)
	var template map[string]any
	raw, e = os.ReadFile(os.Getenv("WARPMETAL_CURRENT_STAGE_TEMPLATE"))
	if e != nil {
		t.Fatal(e)
	}
	publicDeliveryDecode(t, json.RawMessage(raw), &template)
	contextMap := publicDeliveryMap(template["context"])
	for k, v := range map[string]any{"contextId": "context_source_current_accept", "preparationId": prepared.PreparationID, "caseId": policy.Case.CaseID, "caseManifestDigest": policy.Case.CaseManifestDigest, "demandManifestDigest": policy.Case.DemandManifestDigest, "policyDigest": model.WorkspaceDigest(policy), "inputId": item.InputID, "inputDigest": model.ControllerTextDigest(text), "workflowRequestId": item.WorkflowRequestID, "plan": item.Plan, "target": selected, "declarationItemDigest": model.WorkspaceDigest(item), "allocationId": item.AllocationID, "preparationOrdinal": item.PreparationOrdinal, "physicalIndex": item.PhysicalIndex, "identityAssociationDigest": policy.IdentityAssociation.AssociationDigest, "providerPolicyDigest": policy.ProviderPolicyDigest} {
		contextMap[k] = v
	}
	contextMap["contextDigest"] = fixtureDigestField(contextMap, "contextDigest")
	var contextValue model.ControllerApprovedInputContext
	publicDeliveryDecode(t, contextMap, &contextValue)
	body := map[string]any{"formatVersion": 1, "requestId": item.WorkflowRequestID, "target": target, "plan": item.Plan, "expectedDecisionRevision": 0, "decision": "accept", "review": map[string]any{"reviewId": reviewed["reviewId"], "reviewDigest": reviewed["reviewDigest"]}, "integration": candidate["integration"], "reason": "SOURCE model-declared acceptance of exact original document, integration and own reviewer"}
	op, proof := sourceCurrentAcceptedParentOutput(t, j, native, d, app, policy, prepared, contextValue, item, body, "accept", template, "ctrlout_"+model.WorkspaceDigest(contextValue.ContextID)[7:39])
	var grant model.ControllerGrantEnvelope
	publicDeliveryDecode(t, sourceSigned(t, d.operator, "source_independent_operator", op.Lineage.ControllerActivity.Admission.Grant), &grant)
	activation := qualification.ControllerActivation{FormatVersion: 4, TargetKind: "controller_activity", Mode: "real_provider", Purpose: "controller_activity", PolicyDigest: model.WorkspaceDigest(policy), Admission: op.Lineage.ControllerActivity.Admission, GrantEnvelopeDigest: model.WorkspaceDigest(grant), AuthorizationSHA256: model.WorkspaceDigest("SOURCE accept header"), PreparationIndex: allocation.PreparationOrdinal, IssuedAt: now.Format(time.RFC3339Nano), AllocationID: allocation.AllocationID, DemandManifestDigest: policy.Case.DemandManifestDigest, ContextDigest: contextValue.ContextDigest, IdentityAssociationDigest: policy.IdentityAssociation.AssociationDigest, ProviderPolicyDigest: policy.ProviderPolicyDigest, AccountingVersion: 2}
	if e = workflowcontract.Validate(workflowcontract.ControllerProvider, "controllerActivation4", fixtureRaw(activation)); e != nil {
		t.Fatal("fresh SOURCE activation4", e)
	}
	activated := sourceSigned(t, d.operator, "source_independent_operator", activation)
	var preparedEnvelope model.ControllerPreparedEnvelope
	publicDeliveryDecode(t, sourceSigned(t, native.key, app.Producer.KeyID, prepared), &preparedEnvelope)
	for key, value := range map[state.ControllerActivityStage]any{state.ControllerNativePrepared: preparedEnvelope, state.ControllerApprovedContext: controllerApprovedInput{Context: contextValue, InputText: text}, state.ControllerInstalledApplicability: policy.Applicability, state.ControllerPolicyVerified: policy, state.ControllerGrantOriginal: grant, state.ControllerActivated: json.RawMessage(activated)} {
		if e = j.reconciler.Store.PinControllerActivityStage(ctx, prepared.PreparationID, key, fixtureRaw(value)); e != nil {
			t.Fatal(e)
		}
	}
	fixtureComplete(t, j.reconciler, id, "parent-prepare", stage, prepared)
	fixtureComplete(t, j.reconciler, id, "parent-admit", map[string]any{"original": stage, "grant": grant, "activation": json.RawMessage(activated)}, true)
	capture := sourceCurrentParentCapture(t, d, proof.Payload.NativeReceipt.NativeReadback, text)
	s := &currentAcceptSourceRuntime{currentStageTerminalSourceRuntime: reviewer, t: t, policy: policy, activation: activation, operation: op, proof: proof, capture: capture}
	j.reconciler.ManagedRuntime = s
	operations, actions := 0, 0
	decision := fixtureRaw(map[string]any{"formatVersion": 1, "decisionId": "decision_source_current_accept", "decisionRevision": 1, "target": target, "plan": item.Plan, "decision": "accept", "review": body["review"], "integration": candidate["integration"], "decisionDigest": model.WorkspaceDigest(body), "createdAt": now.Format(time.RFC3339Nano)})
	if workflowcontract.Validate(workflowcontract.Domain, "decisionReceipt", decision) != nil {
		t.Fatal("SOURCE decision shape")
	}
	fallback := native.sourceHTTP
	native.sourceHTTP = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/internal/runtime/workspace-workflow/application-operations/"+app.OperationID+"/controller-inputs/"+parent.ServiceRegistrationID+"/manager_accept" {
			_ = json.NewEncoder(w).Encode(readout)
			return true
		}
		if r.URL.Path == "/internal/runtime/workspace-workflow/controller-preparations/"+prepared.PreparationID+"/workflow-context" {
			_ = json.NewEncoder(w).Encode(contextValue)
			return true
		}
		if r.URL.Path == "/internal/runtime/workspace-workflow/controller-output-operations" {
			var call model.ControllerOutputOperationRequest
			if r.Method != "POST" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_current_stage" || json.NewDecoder(r.Body).Decode(&call) != nil || call.RequestID != op.RequestID || !reflect.DeepEqual(call.Lineage, op.Lineage) || model.WorkspaceDigest(call.Proposal) != model.WorkspaceDigest(op.Proposal) {
				t.Fatal("normal accept output operation changed")
			}
			operations++
			_ = json.NewEncoder(w).Encode(op)
			return true
		}
		if r.URL.Path == "/internal/runtime/workspace-workflow/controller-output-operations/"+op.OperationID+"/actions" {
			var got model.ControllerOutputEnvelope
			if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&got) != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(proof) {
				t.Fatal("normal signed accept action changed")
			}
			actions++
			_ = json.NewEncoder(w).Encode(json.RawMessage(decision))
			return true
		}
		if strings.Contains(r.URL.Path, "/decisions") {
			t.Fatal("manager acceptance bypassed signed output action")
		}
		return fallback(w, r)
	}
	err := j.reconciler.Reconcile(ctx, j.manifest)
	check := func() {
		t.Helper()
		if err != nil || operations != 1 || actions != 1 || s.captures != 1 || s.proofs != 1 {
			t.Fatalf("normal signed manager_accept incomplete/repeated: err=%v operations=%d actions=%d capture=%d proof=%d", err, operations, actions, s.captures, s.proofs)
		}
		got, e := j.reconciler.Store.ControllerActivityStage(ctx, prepared.PreparationID, state.ControllerActionReceipt)
		if e != nil || model.WorkspaceDigest(json.RawMessage(got)) != model.WorkspaceDigest(decision) {
			t.Fatal("manager decision original lost", e)
		}
		original, e := j.reconciler.Store.OwnedContinuationResult(ctx, app.OperationID, "source-reported-result", resultClaim)
		if e != nil || string(original) != string(resultRaw) {
			t.Fatal("accepted result changed", e)
		}
	}
	d.writeOriginal(t, filepath.Join(d.root, "current-manager-accept-observation.json"), fixtureRaw(map[string]any{"classification": "SOURCE prepared/admitted native/signer, actual normal output/action TLS; no direct decision/native/ROOT/provider", "declaration": json.RawMessage(runtime.declaration), "policy": policy, "operation": op, "proof": proof, "decision": json.RawMessage(decision), "operations": operations, "actions": actions, "error": func() any {
		if err != nil {
			return err.Error()
		}
		return nil
	}()}), 0600)
	check()
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
	err = j.reconciler.Reconcile(ctx, j.manifest)
	check()
	t.Log("retained normal signed manager_accept SOURCE boundary", d.root)
}

// Constructs declared SOURCE native DATA before the normal capture verifier;
// this is not installed/native execution evidence.
func sourceCurrentParentCapture(t *testing.T, d *firstTaskPublicDeliveryFixture, output model.ControllerOutputNativeReadback, input string) qualification.ControllerCapture {
	t.Helper()
	n := output.Data.ControllerOutput
	var published struct {
		Parents map[string]struct {
			SourceNativeSession struct{ Location struct{ Directory string } }
		}
	}
	raw, err := os.ReadFile(filepath.Join(d.root, "controller-provider-preexecution-source.json"))
	if err != nil || json.Unmarshal(raw, &published) != nil {
		t.Fatal("SOURCE native location", err)
	}
	directory := published.Parents[n.Admission.PreparedReceipt.PreparedTuple.Role].SourceNativeSession.Location.Directory
	if directory == "" {
		t.Fatal("SOURCE native directory absent")
	}
	capture := qualification.ControllerCapture{NativeOutput: output, NativeLog: make([]json.RawMessage, n.Current.LogCursor+1)}
	put := func(ref model.ControllerEventRef, data map[string]any) {
		data["sessionID"] = n.Lineage.SessionID
		capture.NativeLog[ref.Durable.Seq] = fixtureRaw(map[string]any{"id": ref.ID, "type": ref.Type, "created": ref.Created, "durable": ref.Durable, "data": data})
	}
	for seq := int64(0); seq <= n.Current.LogCursor; seq++ {
		ref := model.ControllerEventRef{ID: fmt.Sprintf("evt_source_accept_%d", seq), Type: "session.updated", Created: n.Current.ObservedAt}
		ref.Durable.AggregateID = n.Lineage.SessionID
		ref.Durable.Seq = seq
		ref.Durable.Version = 1
		data := map[string]any{}
		switch seq {
		case 0:
			ref.Type = "session.created"
			data = map[string]any{"projectID": n.Admission.PreparedReceipt.PreparedTuple.NativeRegistration.NativeProjectID, "location": map[string]any{"directory": directory, "workspaceID": nil}, "parentID": nil, "agent": n.Lineage.Agent, "model": n.Lineage.Model}
		case 1:
			ref.Type = "session.controller.registered"
			data["identity"] = n.Identity
		case 2:
			ref.Type = "session.controller.prepared"
			data["receipt"] = n.Admission.PreparedReceipt
		}
		put(ref, data)
	}
	put(n.Events.Enqueued, map[string]any{"inboxID": n.Lineage.InputID, "item": map[string]any{"type": "user", "payload": map[string]any{"text": input, "controllerBinding": n.Admission, "guard": map[string]any{"formatVersion": 3, "contextSeq": n.Current.ContextSeq}}}})
	put(n.Events.ExecutionStarted, map[string]any{})
	put(n.Events.Delivered, map[string]any{"inboxID": n.Lineage.InputID})
	for _, ref := range n.Events.StepStarted {
		put(ref, map[string]any{"assistantMessageID": n.Lineage.AssistantMessageID, "agent": n.Lineage.Agent, "model": n.Lineage.Model})
	}
	if len(n.Events.TextParts) != 1 {
		t.Fatal("SOURCE accept requires one exact output part")
	}
	for _, part := range n.Events.TextParts {
		put(part.Started, map[string]any{"assistantMessageID": n.Lineage.AssistantMessageID, "ordinal": part.Ordinal})
		put(part.Ended, map[string]any{"assistantMessageID": n.Lineage.AssistantMessageID, "ordinal": part.Ordinal, "text": n.Output.Text})
	}
	put(n.Events.StepEnded, map[string]any{"assistantMessageID": n.Lineage.AssistantMessageID, "finish": "stop"})
	put(n.Events.Terminal, map[string]any{})
	if _, err = capture.Verify(input, n.Identity, n.Admission); err != nil {
		t.Fatal("SOURCE acceptance DATA rejected by owning capture verifier", err)
	}
	return capture
}
