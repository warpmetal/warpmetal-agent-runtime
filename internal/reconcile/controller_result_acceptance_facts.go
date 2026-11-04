package reconcile

import (
	"context"
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type childWorkflowFactsRuntime interface {
	AttestCellWorkflowFacts(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.WorkflowFactsRequest, model.WorkflowFactsOperation, workspacecatalog.RegisteredProject, json.RawMessage) (model.WorkflowFactsEnvelope, error)
}
type childWorkflowFactsControl interface {
	WorkflowFactsOperation(context.Context, model.WorkflowFactsRequest, int64) (model.WorkflowFactsOperation, error)
	ReportWorkflowFacts(context.Context, model.WorkflowFactsEnvelope) (model.WorkflowFactsReceipt, error)
}

type completedChildSettlement struct {
	Proof   model.WorkflowFactsEnvelope
	Receipt model.WorkflowFactsReceipt
}

func (r *Reconciler) ensureCompletedChildSettlementLocked(ctx context.Context, owner controllerChildApplication, child ControllerFirstTaskChildResult, entry model.CellServiceV3) (*completedChildSettlement, error) {
	return r.ensureCompletedChildFactsLocked(ctx, owner, child, entry, nil)
}

// The integration candidate is a separate node fact referring to the FIRST
// acknowledged integration observation. It never creates another result.
func (r *Reconciler) ensureCompletedChildFactsLocked(ctx context.Context, owner controllerChildApplication, child ControllerFirstTaskChildResult, entry model.CellServiceV3, integration *completedChildIntegration) (*completedChildSettlement, error) {
	return r.ensureChildFactsForConsumerLocked(ctx, owner, child, entry, integration, nil)
}

func (r *Reconciler) ensureChildFactsForConsumerLocked(ctx context.Context, owner controllerChildApplication, child ControllerFirstTaskChildResult, entry model.CellServiceV3, integration *completedChildIntegration, refresh *completedFactsRefresh) (*completedChildSettlement, error) {
	runtime, ok := r.ManagedRuntime.(childWorkflowFactsRuntime)
	if !ok && refresh == nil {
		return nil, nil
	} // Older adapters cannot supply settlement or results.
	var completedRuntime completedChildFactsRuntime
	if refresh != nil {
		var capable bool
		completedRuntime, capable = r.ManagedRuntime.(completedChildFactsRuntime)
		if !capable {
			return nil, ErrControllerFirstTaskAuthorityPending
		}
	} // Missing local capability must not create a dispatched/UNKNOWN claim.
	control, ok := r.ManagedControl.(childWorkflowFactsControl)
	if !ok {
		return nil, ErrControllerFirstTaskAuthorityPending
	}
	view, err := r.currentCompletedChildAuthority(ctx, owner, child, entry)
	if err != nil {
		return nil, err
	}
	if view.Fresh.NativeReport.Child == nil || view.Fresh.NativeReport.Child.Outcome == nil || *view.Fresh.NativeReport.Child.Outcome != "succeeded" {
		return nil, state.ErrControllerActivityConflict
	}
	prefix := "completion-settlement-"
	selector := model.WorkflowFactsSelector{Kind: "execution_settlement"}
	requestPrefix := "wfsettle_req_"
	if integration != nil {
		prefix, requestPrefix = "completion-candidate-", "wfcandidate_req_"
		selector = model.WorkflowFactsSelector{Kind: "integration_candidate", Receipt: &model.WorkflowReceiptRef{ReceiptID: integration.Receipt.ReceiptID, ReceiptDigest: integration.Receipt.ReceiptDigest}}
	}
	if refresh != nil {
		prefix = "completion-refresh-"
	}
	pending, err := r.Store.HasPendingOwnedContinuation(ctx, entry.PreparationID, prefix)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, state.ErrOwnedContinuationUnknown
	}
	snapshot := view.Fresh.BackendSnapshot
	candidateDigest := ""
	if integration != nil {
		snapshot, candidateDigest, err = controllerIntegrationCandidateSnapshot(snapshot, child.Binding, *integration)
		if err != nil {
			return nil, err
		}
	}
	digest := model.WorkspaceDigest(snapshot)
	stage := prefix + digest[7:]
	call := model.WorkflowFactsRequest{FormatVersion: 1, RequestID: requestPrefix + model.WorkspaceDigest(map[string]any{"binding": child.Binding, "snapshotDigest": digest})[7:], Binding: child.Binding, Operation: selector}
	if refresh != nil {
		identity := model.WorkspaceDigest(map[string]any{"cause": refresh.Cause, "binding": child.Binding, "kind": selector, "snapshotDigest": digest})
		stage = prefix + identity[7:]
		call.RequestID = "wffacts_" + identity[7:]
	}
	if call.Validate() != nil {
		return nil, state.ErrControllerActivityConflict
	}
	var op model.WorkflowFactsOperation
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-operation", call, func() (any, error) { return control.WorkflowFactsOperation(ctx, call, view.Manifest.DesiredRevision) }, &op); err != nil {
		return nil, err
	}
	if op.ValidateFor(call, view.Application.Operation.Producer.NodeTokenHash, view.Manifest.DesiredRevision, r.now()) != nil || !op.MatchesCurrentSnapshot(snapshot) {
		return nil, state.ErrControllerActivityConflict
	}
	var proof model.WorkflowFactsEnvelope
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-proof", op, func() (any, error) {
		if refresh != nil {
			return completedRuntime.AttestCompletedCellWorkflowFacts(ctx, view.Sandbox, entry, view.Manifest, view.Input, call, op, view.Root, view.Fresh.BackendSnapshot, refresh.First)
		}
		return runtime.AttestCellWorkflowFacts(ctx, view.Sandbox, entry, view.Manifest, view.Input, call, op, view.Root, snapshot)
	}, &proof); err != nil {
		return nil, err
	}
	var observed struct {
		NativeSessionID, NativeRole, SnapshotDigest, NativeReceiptDigest, CandidateDigest string
		Quiescent, EffectsComplete, DescendantsComplete                                   bool
	}
	expires, timeErr := time.Parse(time.RFC3339Nano, proof.Payload.NotAfter)
	limit, limitErr := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if proof.Validate() != nil || json.Unmarshal(proof.Payload.Readback, &observed) != nil || proof.KeyID != view.Application.Operation.Producer.KeyID || proof.Payload.OperationID != op.OperationID || proof.Payload.OperationDigest != op.OperationDigest || proof.Payload.NodeTokenHash != op.NodeTokenHash || model.WorkspaceDigest(proof.Payload.Binding) != model.WorkspaceDigest(call.Binding) || observed.NativeSessionID != entry.NativeSessionID || observed.NativeRole != entry.Role || observed.SnapshotDigest != digest || (integration == nil && (!observed.Quiescent || !observed.EffectsComplete || !observed.DescendantsComplete)) || (integration != nil && observed.CandidateDigest != candidateDigest) || timeErr != nil || limitErr != nil || !r.now().Before(expires) || expires.After(limit) {
		return nil, state.ErrControllerActivityConflict
	}
	again, err := r.currentCompletedChildAuthority(ctx, owner, child, entry)
	if err != nil {
		return nil, err
	}
	if !sameCompletedChildAuthority(view, again) {
		return nil, state.ErrControllerActivityConflict
	}
	var receipt model.WorkflowFactsReceipt
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-report", proof, func() (any, error) { return control.ReportWorkflowFacts(ctx, proof) }, &receipt); err != nil {
		return nil, err
	}
	if err = receipt.ValidateFor(proof, r.now()); err != nil {
		return nil, err
	}
	return &completedChildSettlement{Proof: proof, Receipt: receipt}, nil
}
