package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Fixed revision13 routes from F1 §8. Each call reuses node authentication,
// separate exact-manager lease and original idempotency. No retries/scheduler,
// arbitrary prepare body, native prompt or synthetic readiness is introduced.
func (c Client) managerIntentCall(ctx context.Context, method, handle, suffix, definition, key, lease string, call, result any) error {
	c = c.paidDomainClient()
	if !managedServiceIDPattern.MatchString(handle) || !validControllerLease(lease) {
		return errors.New("manager intent transport refused")
	}
	var raw json.RawMessage
	if err := c.requestWithWorkflowLease(ctx, method, controllerBridgePath+"manager-intents/"+handle+suffix, c.NodeToken, call, &raw, true, key, lease); err != nil {
		return err
	}
	return model.DecodeManagerContract(definition, raw, result)
}

func (c Client) ManagerIntent(ctx context.Context, op model.ControllerOutputOperation, receipt model.IntentPairReceipt, member, lease string) (model.IntentHandle, error) {
	var handle model.IntentHandle
	selected, err := op.ManagerIntentSelection(receipt, member)
	if err != nil {
		return handle, err
	}
	decision := receipt.First
	if member == "second" {
		decision = receipt.Second
	}
	return c.currentManagerIntent(ctx, op, selected, decision, receipt.AssociationDigest, lease)
}

func (c Client) ManagerAcceptedIntent(ctx context.Context, op model.ControllerOutputOperation, receipt model.ManagerActionReceipt, member, lease string) (model.IntentHandle, error) {
	selected, err := receipt.Select(op, member)
	if err != nil {
		return model.IntentHandle{}, err
	}
	decision, err := receipt.Decision(member)
	if err != nil {
		return model.IntentHandle{}, err
	}
	return c.currentManagerIntent(ctx, op, selected, decision, receipt.AssociationDigest(), lease)
}

func (c Client) currentManagerIntent(ctx context.Context, op model.ControllerOutputOperation, selected model.ManagerIntentSelection, decision model.IntentAcceptance, associationDigest, lease string) (model.IntentHandle, error) {
	var handle model.IntentHandle
	if decision.Handle == nil {
		return handle, errors.New("manager accepted handle missing")
	}
	err := c.managerIntentCall(ctx, http.MethodGet, *decision.Handle, "", "intentHandle", "", lease, nil, &handle)
	if err != nil {
		return handle, err
	}
	before, err := time.Parse(time.RFC3339Nano, handle.NotAfter)
	if err != nil || !time.Now().Before(before) || handle.HandleID != *decision.Handle || handle.Intent != selected.Ref || handle.Owner != selected.Owner ||
		handle.AllocationID != selected.AllocationID || handle.ContextID != op.Context.ContextID || handle.OperationID != op.OperationID ||
		handle.AssociationDigest != associationDigest || handle.RoleBindingID != op.RoleBindingID || handle.RoleBindingRevision != op.RoleBindingRevision {
		return model.IntentHandle{}, errors.New("manager intent current association conflict")
	}
	raw, _ := json.Marshal(handle)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "handleDigest")
	if model.WorkspaceDigest(fields) != handle.HandleDigest {
		return model.IntentHandle{}, errors.New("manager intent digest conflict")
	}
	return handle, nil
}

func (c Client) PrepareManagerIntent(ctx context.Context, handle model.IntentHandle, selected model.ManagerIntentSelection, lease string) (model.IntentPreparationReference, error) {
	var result model.IntentPreparationReference
	if handle.Intent != selected.Ref || handle.Owner != selected.Owner || handle.AllocationID != selected.AllocationID {
		return result, errors.New("manager intent selection conflict")
	}
	call := model.IntentPrepareRequest{FormatVersion: 1, RequestID: selected.PrepareRequestID, HandleID: handle.HandleID, ExpectedAdmissionRevision: selected.ExpectedAdmissionRevision}
	raw, _ := json.Marshal(call)
	if workflowcontract.Validate(workflowcontract.Manager, "intentPrepareRequest", raw) != nil {
		return result, errors.New("closed intent prepare refused")
	}
	err := c.managerIntentCall(ctx, http.MethodPost, handle.HandleID, "/preparations", "intentPreparationReference", call.RequestID, lease, call, &result)
	if err == nil && (result.HandleID != handle.HandleID || result.Intent != selected.Ref || result.LifecycleRequestDigest != selected.LifecycleRequestDigest) {
		return model.IntentPreparationReference{}, errors.New("intent preparation reference conflict")
	}
	return result, err // Pending reference, never a prepared/ready observation.
}

func (c Client) ManagerPreparedAssociation(ctx context.Context, handle model.IntentHandle, pending model.IntentPreparationReference, lease string) (model.ActualPreparationAssociation, error) {
	var result model.ActualPreparationAssociation
	err := c.managerIntentCall(ctx, http.MethodGet, handle.HandleID, "/prepared-association", "actualPreparationAssociation", "", lease, nil, &result)
	if err == nil && (result.HandleID != handle.HandleID || result.Intent != handle.Intent || pending.Intent != handle.Intent || pending.HandleID != handle.HandleID || result.PreparationID != pending.PreparationID) {
		return model.ActualPreparationAssociation{}, errors.New("actual preparation association conflict")
	}
	if err == nil && result.ValidateIntegrity() != nil {
		return model.ActualPreparationAssociation{}, errors.New("actual prepared receipt integrity conflict")
	}
	return result, err // Existing authenticated reporter must supply the receipt.
}

func (c Client) AssignManagerIntent(ctx context.Context, handle model.IntentHandle, selected model.ManagerIntentSelection, prepared model.ActualPreparationAssociation, entry model.CellServiceV3, lease string) (json.RawMessage, error) {
	if !validControllerLease(lease) || prepared.ValidateIntegrity() != nil || prepared.HandleID != handle.HandleID || prepared.Intent != selected.Ref || handle.Intent != selected.Ref || prepared.PreparationID != entry.PreparationID ||
		prepared.PreparedReceipt.ValidateFor(entry) != nil || workflowcontract.Validate(workflowcontract.Domain, "assignmentRequest", prepared.AssignmentBody) != nil {
		return nil, errors.New("actual intent preparation required before assignment")
	}
	var body struct {
		RequestID string          `json:"requestId"`
		Binding   json.RawMessage `json:"binding"`
	}
	var binding struct {
		ExecutionID     string `json:"executionId"`
		PreparationID   string `json:"preparationId"`
		NativeSessionID string `json:"nativeSessionId"`
	}
	if json.Unmarshal(prepared.AssignmentBody, &body) != nil || json.Unmarshal(prepared.Binding, &binding) != nil || !managedServiceIDPattern.MatchString(binding.ExecutionID) ||
		binding.PreparationID != entry.PreparationID || binding.NativeSessionID != entry.NativeSessionID || body.RequestID != selected.AssignmentRequestID || model.WorkspaceDigest(body.Binding) != model.WorkspaceDigest(prepared.Binding) {
		return nil, errors.New("current assignment binding conflict")
	}
	var result json.RawMessage
	err := c.requestWithWorkflowLease(ctx, http.MethodPost, controllerBridgePath+"executions/"+binding.ExecutionID+"/workflow-assignment", c.NodeToken, prepared.AssignmentBody, &result, true, body.RequestID, lease)
	if err != nil {
		return nil, err
	}
	if workflowcontract.Validate(workflowcontract.Domain, "assignmentReceipt", result) != nil {
		return nil, errors.New("closed assignment receipt refused")
	}
	var assignment struct {
		ExecutionID string          `json:"executionId"`
		Purpose     string          `json:"purpose"`
		Plan        json.RawMessage `json:"plan"`
		Target      json.RawMessage `json:"target"`
	}
	var request struct {
		Purpose string          `json:"purpose"`
		Plan    json.RawMessage `json:"plan"`
		Target  json.RawMessage `json:"target"`
	}
	_ = json.Unmarshal(result, &assignment)
	_ = json.Unmarshal(prepared.AssignmentBody, &request)
	if assignment.ExecutionID != binding.ExecutionID || assignment.Purpose != request.Purpose || model.WorkspaceDigest(assignment.Plan) != model.WorkspaceDigest(request.Plan) || model.WorkspaceDigest(assignment.Target) != model.WorkspaceDigest(request.Target) {
		return nil, errors.New("assignment receipt conflict")
	}
	return result, nil
}

func (c Client) GrantManagerIntent(ctx context.Context, handle model.IntentHandle, selected model.ManagerIntentSelection, prepared model.ActualPreparationAssociation, assignment json.RawMessage, productPolicyDigest, lease string) (model.ChildAdmissionAssociation, error) {
	var result model.ChildAdmissionAssociation
	if prepared.ValidateIntegrity() != nil || prepared.HandleID != handle.HandleID || prepared.Intent != selected.Ref || selected.Ref != handle.Intent {
		return result, errors.New("intent grant association conflict")
	}
	if workflowcontract.Validate(workflowcontract.Domain, "assignmentReceipt", assignment) != nil {
		return result, errors.New("actual assignment required before intent grant")
	}
	var assigned struct {
		AssignmentDigest string `json:"assignmentDigest"`
		ExecutionID      string `json:"executionId"`
	}
	if json.Unmarshal(assignment, &assigned) != nil {
		return result, errors.New("assignment refused")
	}
	var binding struct {
		ExecutionID     string `json:"executionId"`
		NativeSessionID string `json:"nativeSessionId"`
	}
	_ = json.Unmarshal(prepared.Binding, &binding)
	if assigned.ExecutionID != binding.ExecutionID {
		return result, errors.New("assignment execution conflict")
	}
	call := model.IntentGrantRequest{FormatVersion: 1, RequestID: selected.GrantRequestID, HandleID: handle.HandleID,
		PreparedReceiptDigest: prepared.PreparedReceipt.PreparedReceiptDigest, AssignmentDigest: assigned.AssignmentDigest, ProductPolicyDigest: productPolicyDigest}
	raw, _ := json.Marshal(call)
	if workflowcontract.Validate(workflowcontract.Manager, "intentGrantRequest", raw) != nil {
		return result, errors.New("closed intent grant refused")
	}
	err := c.managerIntentCall(ctx, http.MethodPost, handle.HandleID, "/grants", "childAdmissionAssociation", call.RequestID, lease, call, &result)
	if err == nil && result.ValidateIntegrity() != nil {
		return model.ChildAdmissionAssociation{}, errors.New("published child association digest conflict")
	}
	if err == nil && (result.HandleID != handle.HandleID || result.PreparationAssociationDigest != prepared.AssociationDigest || result.AllocationID != selected.AllocationID ||
		result.PolicyDigest != productPolicyDigest || model.WorkspaceDigest(result.Assignment) != model.WorkspaceDigest(assignment) ||
		result.Grant.PreparedReceiptDigest != call.PreparedReceiptDigest || result.Grant.SessionID != binding.NativeSessionID || result.Grant.OperationID != prepared.PreparedReceipt.PreparedTuple.OperationID ||
		result.Grant.CredentialBindingDigest != model.WorkspaceDigest(prepared.PreparedReceipt.PreparedTuple.CredentialBinding)) {
		return model.ChildAdmissionAssociation{}, errors.New("published child admission conflict")
	}
	return result, err
}
