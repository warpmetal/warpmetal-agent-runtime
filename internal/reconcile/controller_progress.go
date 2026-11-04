package reconcile

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// READ ONLY consumers for workflow's observation of normal-owned progression.
// No prepare/complete call, helper/native effect, context construction or new
// relay action. Missing original always remains pending.
func (r *Reconciler) readControllerParentApprovedInputLocked(ctx context.Context, id string) (controllerApprovedInput, error) {
	var empty controllerApprovedInput
	if r.Store == nil {
		return empty, ErrControllerActivityPending
	}
	raw, err := r.Store.ControllerActivityStage(ctx, id, state.ControllerNativePrepared)
	if err != nil {
		return empty, err
	}
	if len(raw) == 0 {
		return empty, ErrControllerFirstTaskPending
	}
	var prepared model.ControllerPreparedEnvelope
	if json.Unmarshal(raw, &prepared) != nil {
		return empty, state.ErrControllerActivityConflict
	}
	raw, err = r.Store.ControllerActivityStage(ctx, id, state.ControllerApprovedContext)
	if err != nil {
		return empty, err
	}
	if len(raw) == 0 {
		return empty, ErrControllerFirstTaskPending
	}
	var original controllerApprovedInput
	if json.Unmarshal(raw, &original) != nil || original.Context.PreparationID != id || original.Context.InputID != prepared.Payload.PreparedTuple.InputID || !exactControllerText(original.InputText, prepared.Payload.PreparedTuple.InputDigest) {
		return empty, state.ErrControllerActivityConflict
	}
	raw, err = r.Store.ControllerActivityStage(ctx, id, state.ControllerInstalledApplicability)
	if err != nil {
		return empty, err
	}
	if len(raw) == 0 {
		return empty, ErrControllerFirstTaskPending
	}
	var installed qualification.Applicability
	if json.Unmarshal(raw, &installed) != nil {
		return empty, state.ErrControllerActivityConflict
	}
	w, err := r.controllerActivityCurrentWitness(ctx, prepared.Payload.PreparedTuple.ServiceRegistrationID, installed, false)
	if err != nil {
		return empty, err
	}
	if w.Parent.Parent.Owner != prepared.Payload.PreparedTuple.Owner || w.Parent.Report.NativeRegistration == nil || !reflect.DeepEqual(*w.Parent.Report.NativeRegistration, prepared.Payload.PreparedTuple.NativeRegistration) {
		return empty, state.ErrControllerActivityConflict
	}
	policyRaw, err := r.Store.ControllerActivityStage(ctx, id, state.ControllerPolicyVerified)
	if err != nil {
		return empty, err
	}
	if len(policyRaw) == 0 {
		if original.Context.FormatVersion >= 3 || prepared.Payload.Validate() != nil || w.Parent.Parent.ConfigDigest != prepared.Payload.PreparedTuple.ConfigDigest {
			return empty, state.ErrControllerActivityConflict
		}
	} else {
		var policy qualification.ControllerPolicy
		if json.Unmarshal(policyRaw, &policy) != nil || policy.FormatVersion != 6 || model.WorkspaceDigest(json.RawMessage(policyRaw)) != original.Context.PolicyDigest || policy.ValidateContext(original.Context) != nil || policy.ValidatePreparedReceipt(prepared.Payload) != nil || !reflect.DeepEqual(policy.ApplicationIdentity(), w.Installed.Identity) || !reflect.DeepEqual(policy.Applicability, installed) {
			return empty, state.ErrControllerActivityConflict
		}
		native, e := w.Installed.Identity.DeriveWM8NativeIdentity()
		app := w.Installed.Application
		if e != nil || policy.IdentityAssociation.ValidateAccepted(w.ApplicationOperation, app.ApplicationID, app.ReceiptDigest, w.Installed.WorkspaceMaterializerDigest, native) != nil {
			return empty, state.ErrControllerActivityConflict
		}
	}
	return original, nil
}

func (r *Reconciler) ReadControllerParentApprovedInput(ctx context.Context, id string) (model.ControllerApprovedInputContext, string, error) {
	if err := r.lockControllerOriginalRead(ctx); err != nil {
		return model.ControllerApprovedInputContext{}, "", err
	}
	defer r.mu.Unlock()
	original, err := r.readControllerParentApprovedInputLocked(ctx, id)
	return original.Context, original.InputText, err
}

func (r *Reconciler) ReadControllerParentActionReceipt(ctx context.Context, id string) (json.RawMessage, error) {
	if err := r.lockControllerOriginalRead(ctx); err != nil {
		return nil, err
	}
	defer r.mu.Unlock()
	return r.readControllerParentActionReceiptLocked(ctx, id)
}

func (r *Reconciler) readControllerParentActionReceiptLocked(ctx context.Context, id string) (json.RawMessage, error) {
	original, err := r.readControllerParentApprovedInputLocked(ctx, id)
	if err != nil {
		return nil, err
	}
	raw, err := r.readControllerCompletionOriginal(ctx, id, state.ControllerOutputOperation, "parent-output-operation")
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, ErrControllerFirstTaskPending
	}
	var operation model.ControllerOutputOperation
	if json.Unmarshal(raw, &operation) != nil || !reflect.DeepEqual(operation.Context, original.Context) {
		return nil, state.ErrControllerActivityConflict
	}
	raw, err = r.Store.ControllerActivityStage(ctx, id, state.ControllerOutputEnvelope)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, ErrControllerFirstTaskPending
	}
	var envelope model.ControllerOutputEnvelope
	if json.Unmarshal(raw, &envelope) != nil || envelope.Payload.OperationID != operation.OperationID || envelope.Payload.OperationDigest != operation.OperationDigest {
		return nil, state.ErrControllerActivityConflict
	}
	receipt, err := r.readControllerCompletionOriginal(ctx, id, state.ControllerActionReceipt, "parent-output-action")
	if err != nil {
		return nil, err
	}
	if len(receipt) == 0 {
		return nil, ErrControllerFirstTaskPending
	}
	if original.Context.Target.Kind == "advice" && workflowcontract.Validate(workflowcontract.Domain, "adviceReceipt", receipt) != nil {
		return nil, state.ErrControllerActivityConflict
	}
	if original.Context.Target.Kind == "advice" {
		var accepted struct {
			Plan model.ControllerPlan `json:"plan"`
		}
		if json.Unmarshal(receipt, &accepted) != nil || !reflect.DeepEqual(accepted.Plan, original.Context.Plan) {
			return nil, state.ErrControllerActivityConflict
		}
	}
	if original.Context.Target.Kind == "manager_work_intents" && workflowcontract.Validate(workflowcontract.Manager, "intentPairReceipt", receipt) != nil {
		return nil, state.ErrControllerActivityConflict
	}
	if original.Context.Target.Kind == "manager_work_intents" {
		var accepted struct {
			ContextID   string `json:"contextId"`
			OperationID string `json:"operationId"`
		}
		if json.Unmarshal(receipt, &accepted) != nil || accepted.ContextID != original.Context.ContextID || accepted.OperationID != operation.OperationID {
			return nil, state.ErrControllerActivityConflict
		}
	}
	if original.Context.Target.Kind == "manager_work_intent" || original.Context.Target.Kind == "manager_intent" {
		var accepted model.ManagerActionReceipt
		if json.Unmarshal(receipt, &accepted) != nil || accepted.ValidateOutput(operation, envelope) != nil {
			return nil, state.ErrControllerActivityConflict
		}
	}
	return json.RawMessage(receipt), nil
}

// Lost owning ACK is UNKNOWN, never another expected-absence poll. A crash after
// durable completion but before the stage pin still exposes the exact result.
func (r *Reconciler) readControllerCompletionOriginal(ctx context.Context, id string, stage state.ControllerActivityStage, step string) ([]byte, error) {
	raw, err := r.Store.ControllerActivityStage(ctx, id, stage)
	if err != nil {
		return nil, err
	}
	claim, err := r.Store.OwnedContinuationClaim(ctx, id, step)
	if err != nil {
		return nil, err
	}
	if len(claim) == 0 {
		return raw, nil
	}
	result, err := r.Store.OwnedContinuationResult(ctx, id, step, claim)
	if err != nil {
		return nil, err
	}
	if len(raw) != 0 && model.WorkspaceDigest(json.RawMessage(raw)) != model.WorkspaceDigest(json.RawMessage(result)) {
		return nil, state.ErrControllerActivityConflict
	}
	return result, nil
}

// Select the ACTUAL normal caller's preparation, not owner status.preparationId,
// a caller-chosen preparation, or a new preparation attempt.
func (r *Reconciler) ReadControllerFirstTaskParentPreparation(ctx context.Context, taskID, serviceID string) (model.ControllerPreparedReceipt, error) {
	if err := r.lockControllerOriginalRead(ctx); err != nil {
		return model.ControllerPreparedReceipt{}, err
	}
	defer r.mu.Unlock()
	return r.readControllerFirstTaskParentPreparationLocked(ctx, taskID, serviceID)
}

// No observer scheduling/cutoff is chosen here. Honor the caller's existing I/O
// deadline even while an owning pass holds r.mu; contention is NOT SupplierPending.
func (r *Reconciler) lockControllerOriginalRead(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.mu.TryLock() {
			if err := ctx.Err(); err != nil {
				r.mu.Unlock()
				return err
			}
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (r *Reconciler) readControllerFirstTaskParentPreparationLocked(ctx context.Context, taskID, serviceID string) (model.ControllerPreparedReceipt, error) {
	var empty model.ControllerPreparedReceipt
	if r.Store == nil {
		return empty, state.ErrControllerActivityConflict
	}
	var parent *model.ControllerParentIntent
	for _, p := range r.currentAuthorityManifest().ParentServices {
		if p.ServiceRegistrationID == serviceID {
			if parent != nil || p.DesiredState != "active" || (p.Role != "manager" && p.Role != "orchestrator") {
				return empty, state.ErrControllerActivityConflict
			}
			copy := p
			parent = &copy
		}
	}
	if parent == nil {
		return empty, state.ErrControllerActivityConflict
	}
	claim, err := r.Store.OwnedContinuationClaim(ctx, taskID, "owner-original")
	if err != nil {
		return empty, err
	}
	if len(claim) == 0 {
		return empty, ErrControllerFirstTaskPending
	}
	raw, err := r.Store.OwnedContinuationResult(ctx, taskID, "owner-original", claim)
	if err != nil {
		return empty, err
	}
	var owner api.OwnerFirstTaskOriginal
	if workflowcontract.ValidateOwnerFirstTask("ownerFirstTaskOriginal", raw) != nil || json.Unmarshal(raw, &owner) != nil || owner.FirstTaskID != taskID || model.WorkspaceDigest(owner) != model.WorkspaceDigest(json.RawMessage(claim)) {
		return empty, state.ErrControllerActivityConflict
	}
	app, err := r.Store.WorkspaceApplication(ctx, owner.ApplicationOperationID)
	if err != nil {
		return empty, err
	}
	if app == nil || !app.Applied || app.ApplicationID != owner.ApplicationID || app.Operation.OperationDigest != owner.ApplicationOperationDigest || app.Operation.SetupIntentID != owner.SetupIntentID || app.Operation.ConfigurationID != owner.ConfigurationID || app.Operation.ConfigurationRevision != owner.ConfigurationRevision || app.Operation.ConfigurationDigest != owner.ConfigurationDigest || app.Operation.TargetRuntimeRevision != r.currentAuthorityManifest().DesiredRevision {
		return empty, state.ErrControllerActivityConflict
	}
	if parent.Owner != owner.Owner || parent.ApplicationOperationID != owner.ApplicationOperationID {
		return empty, state.ErrControllerActivityConflict
	}
	step, input, digest, request := "parent-prepare", owner.ParentActivityRequest.InputID, owner.ParentActivityRequest.InputDigest, owner.ParentActivityRequest.RequestID
	var decision controllerInitialDecisionOriginal
	if parent.Role == "manager" {
		if serviceID == owner.Parent.ServiceRegistrationID {
			return empty, state.ErrControllerActivityConflict
		}
		claim, err = r.Store.OwnedContinuationClaim(ctx, taskID, "initial-decision-original")
		if err != nil {
			return empty, err
		}
		if len(claim) == 0 {
			return empty, ErrControllerFirstTaskPending
		}
		raw, err = r.Store.OwnedContinuationResult(ctx, taskID, "initial-decision-original", claim)
		if err != nil {
			return empty, err
		}
		var declared qualification.ControllerDeclaredInput
		if json.Unmarshal(claim, &decision) != nil || json.Unmarshal(raw, &declared) != nil || !reflect.DeepEqual(decision.DeclaredInput, declared) || !reflect.DeepEqual(decision.OwnerOriginal, owner) || decision.Manager != *parent {
			return empty, state.ErrControllerActivityConflict
		}
		advicePrepared, err := r.readControllerFirstTaskParentPreparationLocked(ctx, taskID, owner.Parent.ServiceRegistrationID)
		if err != nil {
			return empty, err
		}
		advice, err := r.readControllerParentActionReceiptLocked(ctx, advicePrepared.PreparationID)
		if err != nil {
			return empty, err
		}
		if model.WorkspaceDigest(advice) != model.WorkspaceDigest(decision.Advice) {
			return empty, state.ErrControllerActivityConflict
		}
		step, input, digest, request = "initial-decision-prepare", declared.InputID, model.ControllerTextDigest(declared.InputText), declared.WorkflowRequestID
	} else if serviceID != owner.Parent.ServiceRegistrationID || parent.ConfigDigest != owner.Parent.ConfigDigest || parent.ServiceGeneration != owner.Parent.ServiceGeneration || parent.DesiredRevision != owner.Parent.DesiredRevision {
		return empty, state.ErrControllerActivityConflict
	}
	raw, err = r.Store.OwnedContinuationResult(ctx, taskID, step, claim)
	if err != nil {
		return empty, err
	}
	if len(raw) == 0 {
		return empty, ErrControllerFirstTaskPending
	}
	var prepared model.ControllerPreparedReceipt
	if json.Unmarshal(raw, &prepared) != nil || prepared.PreparedTuple.Owner != owner.Owner || prepared.PreparedTuple.ServiceRegistrationID != serviceID || prepared.PreparedTuple.Role != parent.Role || prepared.PreparedTuple.InputID != input || prepared.PreparedTuple.InputDigest != digest {
		return empty, state.ErrControllerActivityConflict
	}
	dependency, err := app.Operation.ParentDependency(*parent)
	if err != nil || dependency.Projection.ModelSelection == nil || dependency.Projection.ModelSelection.CredentialBinding == nil || prepared.PreparedTuple.ConfigurationDigest != owner.ConfigurationDigest || prepared.PreparedTuple.Authority != dependency.Projection.ModelSelection.Authority || prepared.PreparedTuple.CredentialBinding != *dependency.Projection.ModelSelection.CredentialBinding {
		return empty, state.ErrControllerActivityConflict
	}
	if parent.Role == "orchestrator" && prepared.PreparedTuple.NativeRegistration != owner.Parent.NativeRegistration {
		return empty, state.ErrControllerActivityConflict
	}
	approved, err := r.readControllerParentApprovedInputLocked(ctx, prepared.PreparationID)
	if err != nil {
		return empty, err
	}
	nativeRaw, err := r.Store.ControllerActivityStage(ctx, prepared.PreparationID, state.ControllerNativePrepared)
	if err != nil {
		return empty, err
	}
	var native model.ControllerPreparedEnvelope
	if json.Unmarshal(nativeRaw, &native) != nil || !reflect.DeepEqual(native.Payload, prepared) {
		return empty, state.ErrControllerActivityConflict
	}
	if approved.Context.WorkflowRequestID != request {
		return empty, state.ErrControllerActivityConflict
	}
	if parent.Role == "orchestrator" && (approved.Context.Target.Kind != "advice" || approved.Context.Target.Role != "orchestrator") {
		return empty, state.ErrControllerActivityConflict
	}
	if parent.Role == "manager" && !decision.DeclaredInput.MatchesContext(approved.Context) {
		return empty, state.ErrControllerActivityConflict
	}
	return prepared, nil
}
