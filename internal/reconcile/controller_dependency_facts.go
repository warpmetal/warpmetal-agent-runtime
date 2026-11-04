package reconcile

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type completedChildFactsRuntime interface {
	AttestCompletedCellWorkflowFacts(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.WorkflowFactsRequest, model.WorkflowFactsOperation, workspacecatalog.RegisteredProject, json.RawMessage, model.WorkflowFactsEnvelope) (model.WorkflowFactsEnvelope, error)
}
type completedFactsRefresh struct {
	Cause any
	First model.WorkflowFactsEnvelope
}

func (r *Reconciler) retainedStageChildrenLocked(ctx context.Context, appID, name string) (controllerStageOriginal, controllerStageChildResult, error) {
	var stage controllerStageOriginal
	var children controllerStageChildResult
	claim, err := r.Store.OwnedContinuationClaim(ctx, appID, "controller-stage-"+name)
	if err != nil {
		return stage, children, err
	}
	if len(claim) == 0 {
		return stage, children, ErrControllerFirstTaskPending
	}
	raw, err := r.Store.OwnedContinuationResult(ctx, appID, "controller-stage-"+name, claim)
	if err != nil {
		return stage, children, err
	}
	if len(raw) == 0 {
		return stage, children, state.ErrOwnedContinuationUnknown
	}
	if model.DecodePhysicalClosed(raw, &stage) != nil || stage.Readout.AllocationName != name {
		return stage, children, state.ErrControllerActivityConflict
	}
	id := controllerStageID(stage)
	claim, err = r.Store.OwnedContinuationClaim(ctx, id, "children")
	if err != nil {
		return stage, children, err
	}
	if len(claim) == 0 {
		return stage, children, ErrControllerFirstTaskPending
	}
	raw, err = r.Store.OwnedContinuationResult(ctx, id, "children", claim)
	if err != nil {
		return stage, children, err
	}
	if len(raw) == 0 {
		return stage, children, state.ErrOwnedContinuationUnknown
	}
	if model.DecodePhysicalClosed(raw, &children) != nil || !reflect.DeepEqual(children.Stage, stage) || children.Progress.State != "completed" || len(children.Progress.Children) != 1 {
		return stage, children, state.ErrControllerActivityConflict
	}
	return stage, children, nil
}

// Called only after independent protected declaration matching, in both the
// before-parent and accepted-child phases. A new causal stage may observe fresh
// facts; an expired/replayed same phase never allocates a clock-based identity.
func (r *Reconciler) refreshControllerDependenciesLocked(ctx context.Context, stage controllerStageOriginal, phase string) error {
	name := stage.Readout.AllocationName
	if name != "manager_integrate" && name != "manager_review" && name != "manager_accept" {
		return nil
	}
	if phase != "before_parent" && phase != "accepted_child" {
		return state.ErrControllerActivityConflict
	}
	var selected struct {
		Intent                                   struct{ Target, TargetReceipt, Candidate json.RawMessage }
		Result, ResultReceipt, Candidate, Review json.RawMessage
	}
	if json.Unmarshal(mustWorkflowJSON(stage.Declared.Target), &selected) != nil {
		return state.ErrControllerActivityConflict
	}
	target, receipt, candidate := selected.Intent.Target, selected.Intent.TargetReceipt, selected.Intent.Candidate
	if name == "manager_accept" {
		target, receipt, candidate = selected.Result, selected.ResultReceipt, selected.Candidate
	}
	var result struct {
		ResultID, ResultDigest, ExecutionID string
		ResultRevision                      int64
	}
	if json.Unmarshal(receipt, &result) != nil || result.ExecutionID == "" || model.WorkspaceDigest(target) != model.WorkspaceDigest(map[string]any{"resultId": result.ResultID, "resultRevision": result.ResultRevision, "resultDigest": result.ResultDigest}) {
		return state.ErrControllerActivityConflict
	}
	author, err := r.completedOriginForExecutionLocked(ctx, result.ExecutionID)
	if err != nil {
		return err
	}
	if author.Application.ApplicationOperationID != stage.Readout.ApplicationOperationID || author.Application.ApplicationOperationDigest != stage.Readout.ApplicationOperationDigest {
		return state.ErrControllerActivityConflict
	}
	if ok, e := r.completedChildResultHistoryLocked(ctx, author.Application, author.Child, author.Entry); e != nil {
		return e
	} else if !ok {
		return ErrControllerFirstTaskPending
	}
	claim, err := r.Store.OwnedContinuationClaim(ctx, author.Entry.PreparationID, "completion-result")
	if err != nil {
		return err
	}
	ack, err := r.Store.OwnedContinuationResult(ctx, author.Entry.PreparationID, "completion-result", claim)
	if err != nil {
		return err
	}
	if model.WorkspaceDigest(json.RawMessage(ack)) != model.WorkspaceDigest(receipt) {
		return state.ErrControllerActivityConflict
	}
	cause := map[string]any{"caseManifestDigest": stage.Readout.CaseManifestDigest, "allocationId": stage.Declared.AllocationID, "serviceRegistrationId": stage.Readout.ServiceRegistrationID, "declarationItemDigest": stage.Readout.DeclarationItemDigest, "phase": phase, "targetReceipt": json.RawMessage(receipt), "candidate": json.RawMessage(candidate)}
	refresh := func(d completedChildOriginal, integration *completedChildIntegration) error {
		first, e := r.firstCompletedFactsLocked(ctx, d)
		if e != nil {
			return e
		}
		_, e = r.ensureChildFactsForConsumerLocked(ctx, d.Application, d.Child, d.Entry, integration, &completedFactsRefresh{cause, first})
		return e
	}
	if err = refresh(author, nil); err != nil {
		return err
	}
	if name == "manager_integrate" {
		return nil
	}
	priorStage, children, err := r.retainedStageChildrenLocked(ctx, stage.Readout.ApplicationOperationID, "manager_integrate")
	if err != nil {
		return err
	}
	if priorStage.Readout.CaseManifestDigest != stage.Readout.CaseManifestDigest || priorStage.Readout.ServiceRegistrationID != stage.Readout.ServiceRegistrationID {
		return state.ErrControllerActivityConflict
	}
	child := children.Progress.Children[0]
	integrator, err := r.completedOriginForExecutionLocked(ctx, child.ExecutionID)
	if err != nil {
		return err
	}
	claim, err = r.Store.OwnedContinuationClaim(ctx, controllerStageID(priorStage), "integration-complete")
	if err != nil {
		return err
	}
	raw, err := r.Store.OwnedContinuationResult(ctx, controllerStageID(priorStage), "integration-complete", claim)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return ErrControllerFirstTaskPending
	}
	var original completedControllerIntegration
	if model.DecodePhysicalClosed(raw, &original) != nil || original.Candidate.Proof.Validate() != nil || original.Candidate.Receipt.ProofDigest != model.WorkspaceDigest(original.Candidate.Proof) {
		return state.ErrControllerActivityConflict
	}
	var request struct {
		Binding     json.RawMessage
		Observation struct {
			Target, Artifacts json.RawMessage
			AfterDigest       string
		}
	}
	if json.Unmarshal(original.Integration.Proof.Payload.Request, &request) != nil || model.WorkspaceDigest(request.Binding) != model.WorkspaceDigest(child.Binding) || model.WorkspaceDigest(request.Observation.Target) != model.WorkspaceDigest(target) {
		return state.ErrControllerActivityConflict
	}
	expected := map[string]any{"integration": model.WorkflowReceiptRef{ReceiptID: original.Integration.Receipt.ReceiptID, ReceiptDigest: original.Integration.Receipt.ReceiptDigest}, "afterDigest": request.Observation.AfterDigest, "manifestDigest": model.WorkspaceDigest(request.Observation.Artifacts)}
	if model.WorkspaceDigest(candidate) != model.WorkspaceDigest(expected) {
		return state.ErrControllerActivityConflict
	}
	if err = refresh(integrator, nil); err != nil {
		return err
	}
	if err = refresh(integrator, &original.Integration); err != nil {
		return err
	}
	if name != "manager_accept" {
		return nil
	}
	reviewStage, reviews, err := r.retainedStageChildrenLocked(ctx, stage.Readout.ApplicationOperationID, "manager_review")
	if err != nil {
		return err
	}
	if reviewStage.Readout.CaseManifestDigest != stage.Readout.CaseManifestDigest || reviewStage.Readout.ServiceRegistrationID != stage.Readout.ServiceRegistrationID {
		return state.ErrControllerActivityConflict
	}
	reviewer, err := r.completedOriginForExecutionLocked(ctx, reviews.Progress.Children[0].ExecutionID)
	if err != nil {
		return err
	}
	claim, err = r.Store.OwnedContinuationClaim(ctx, controllerStageID(reviewStage), "review-complete")
	if err != nil {
		return err
	}
	raw, err = r.Store.OwnedContinuationResult(ctx, controllerStageID(reviewStage), "review-complete", claim)
	if err != nil {
		return err
	}
	var reviewed completedControllerReview
	if model.DecodePhysicalClosed(raw, &reviewed) != nil || validateCompletedReview(reviewed, reviewer.Child.Binding) != nil || model.WorkspaceDigest(reviewed.Receipt) != model.WorkspaceDigest(selected.Review) {
		return state.ErrControllerActivityConflict
	}
	return refresh(reviewer, nil)
}
