package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type childIntegrationCompletionRuntime interface {
	ObserveCellProductIntegration(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, workspacecatalog.RegisteredProject, json.RawMessage) (json.RawMessage, error)
	AttestCellProductIntegration(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.WorkflowCaptureRequest, model.WorkflowCaptureOperation, workspacecatalog.RegisteredProject, json.RawMessage) (model.WorkflowObservationEnvelope, error)
	RetainCellProductObservationReceipt(context.Context, model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error
}
type completedChildIntegration struct {
	Proof   model.WorkflowObservationEnvelope
	Receipt model.WorkflowObservationReceipt
}
type completedControllerIntegration struct {
	Integration completedChildIntegration
	Candidate   completedChildSettlement
}

// Integrator completion is node/current-execution authority. The independent
// observation and candidate refer to the original implement result; no second
// result, artifact upload or manager decision is emitted here.
func (r *Reconciler) reconcileControllerIntegrationLocked(ctx context.Context, id string, result controllerStageChildResult) error {
	if result.Stage.Readout.AllocationName != "manager_integrate" || result.Stage.Declared.Target.Kind != "manager_intent" || result.Progress.State != "completed" || len(result.Progress.Children) != 1 {
		return ErrControllerLaterChildPending
	}
	child := result.Progress.Children[0]
	claim := child
	claim.BackendSnapshot = nil
	rawClaim, _ := model.WorkspaceCanonicalJSON(claim)
	retained, err := r.Store.OwnedContinuationResult(ctx, id, "integration-complete", rawClaim)
	if err != nil {
		return err
	}
	if len(retained) != 0 {
		var prior completedControllerIntegration
		if model.DecodePhysicalClosed(retained, &prior) != nil || prior.Candidate.Proof.Validate() != nil || prior.Candidate.Receipt.ProofDigest != model.WorkspaceDigest(prior.Candidate.Proof) || model.WorkspaceDigest(prior.Candidate.Proof.Payload.Binding) != model.WorkspaceDigest(child.Binding) {
			return state.ErrControllerActivityConflict
		}
		_, _, err = controllerIntegrationCandidateSnapshot(child.BackendSnapshot, child.Binding, prior.Integration)
		return err // Immutable acknowledged history grants no fresh effect.
	}
	var entry *model.CellServiceV3
	for _, v := range r.currentAuthorityManifest().CellEntriesV3 {
		if v.PreparationID == child.PreparationAssociation.PreparationID {
			if entry != nil {
				return state.ErrControllerActivityConflict
			}
			copy := v
			entry = &copy
		}
	}
	if entry == nil {
		return ErrControllerLaterChildPending
	}
	if pending, e := r.Store.HasPendingOwnedContinuation(ctx, entry.PreparationID, "completion-"); e != nil {
		return e
	} else if pending {
		return state.ErrOwnedContinuationUnknown
	}
	settlement, err := r.ensureCompletedChildSettlementLocked(ctx, result.Application, child, *entry)
	if err != nil {
		return fmt.Errorf("integrator settlement: %w", err)
	}
	if settlement == nil {
		return ErrControllerFirstTaskAuthorityPending
	}
	integration, err := r.ensureCompletedChildIntegrationLocked(ctx, result.Application, child, *entry)
	if err != nil {
		return fmt.Errorf("integrator observation: %w", err)
	}
	candidate, err := r.ensureCompletedChildFactsLocked(ctx, result.Application, child, *entry, &integration)
	if err != nil {
		return fmt.Errorf("integrator candidate: %w", err)
	}
	if candidate == nil {
		return ErrControllerFirstTaskAuthorityPending
	}
	var complete completedControllerIntegration
	return r.ownedContinuationOnce(ctx, id, "integration-complete", claim, func() (any, error) { return completedControllerIntegration{integration, *candidate}, nil }, &complete)
}

// Reconstruct the expected candidate extension from the retained acknowledged
// observation. Never copy candidate fields from the operation's own snapshot.
func controllerIntegrationCandidateSnapshot(base, binding json.RawMessage, original completedChildIntegration) (json.RawMessage, string, error) {
	bad := state.ErrControllerActivityConflict
	var request struct {
		Binding     json.RawMessage `json:"binding"`
		Reconciles  json.RawMessage `json:"reconciles"`
		Observation json.RawMessage `json:"observation"`
	}
	var observed map[string]json.RawMessage
	var snapshot map[string]json.RawMessage
	var b struct{ ExecutionID string }
	if original.Proof.Validate() != nil || model.DecodePhysicalClosed(original.Proof.Payload.Request, &request) != nil || model.WorkspaceDigest(request.Binding) != model.WorkspaceDigest(binding) || string(request.Reconciles) != "null" || workflowcontract.Validate(workflowcontract.Domain, "observation", request.Observation) != nil || json.Unmarshal(request.Observation, &observed) != nil || json.Unmarshal(binding, &b) != nil || model.DecodePhysicalClosed(base, &snapshot) != nil || snapshot == nil {
		return nil, "", bad
	}
	text := func(k string) string { var v string; _ = json.Unmarshal(observed[k], &v); return v }
	receiptRaw, _ := model.WorkspaceCanonicalJSON(original.Receipt)
	outer := model.WorkflowObservationRequest{FormatVersion: 1, RequestID: original.Proof.Payload.RequestID, Binding: request.Binding, Reconciles: request.Reconciles, Observation: request.Observation}
	if text("type") != "integration" || text("status") != "settled" || text("outcome") != "succeeded" || workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", receiptRaw) != nil || original.Receipt.ExecutionID != b.ExecutionID || original.Receipt.Type != "integration" || original.Receipt.Status != "settled" || original.Receipt.ReceiptDigest != model.WorkspaceDigest(outer) {
		return nil, "", bad
	}
	ref := model.WorkflowReceiptRef{ReceiptID: original.Receipt.ReceiptID, ReceiptDigest: original.Receipt.ReceiptDigest}
	snapshot["candidate"] = mustWorkflowJSON(map[string]any{"receipt": ref, "target": observed["target"], "targetBinding": observed["targetBinding"], "artifacts": observed["artifacts"], "afterDigest": text("afterDigest"), "changedPaths": observed["changedPaths"]})
	raw, err := model.WorkspaceCanonicalJSON(snapshot)
	return raw, text("afterDigest"), err
}

func (r *Reconciler) ensureCompletedChildIntegrationLocked(ctx context.Context, owner controllerChildApplication, child ControllerFirstTaskChildResult, entry model.CellServiceV3) (completedChildIntegration, error) {
	var empty completedChildIntegration
	runtime, ok := r.ManagedRuntime.(childIntegrationCompletionRuntime)
	control, cok := r.ManagedControl.(childEffectObservationControl)
	if !ok || !cok {
		return empty, ErrControllerFirstTaskAuthorityPending
	}
	view, err := r.currentCompletedChildAuthority(ctx, owner, child, entry)
	if err != nil {
		return empty, err
	}
	observation, err := runtime.ObserveCellProductIntegration(ctx, view.Sandbox, entry, view.Manifest, view.Input, view.Root, view.Fresh.BackendSnapshot)
	if err != nil {
		return empty, err
	}
	var observed struct{ Type, Status, Outcome string }
	if workflowcontract.Validate(workflowcontract.Domain, "observation", observation) != nil || json.Unmarshal(observation, &observed) != nil || observed.Type != "integration" || observed.Status != "settled" || observed.Outcome != "succeeded" {
		return empty, state.ErrControllerActivityConflict
	}
	call := model.WorkflowCaptureRequest{FormatVersion: 1, RequestID: "wfintegration_" + model.WorkspaceDigest(map[string]any{"binding": child.Binding, "observation": observation})[7:], Binding: child.Binding, Operation: model.WorkflowCapture{Kind: "observation", Reconciles: json.RawMessage("null"), Observation: observation}}
	var op model.WorkflowCaptureOperation
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-integration-operation", call, func() (any, error) {
		return control.WorkflowObservationOperation(ctx, call, view.Manifest.DesiredRevision)
	}, &op); err != nil {
		return empty, err
	}
	var proof model.WorkflowObservationEnvelope
	opRaw, _ := model.WorkspaceCanonicalJSON(op)
	prior, err := r.Store.OwnedContinuationResult(ctx, entry.PreparationID, "completion-integration-proof", opRaw)
	if err != nil {
		return empty, err
	}
	if len(prior) != 0 && model.DecodePhysicalClosed(prior, &proof) != nil {
		return empty, state.ErrControllerActivityConflict
	}
	var receipt model.WorkflowObservationReceipt
	var ack []byte
	if len(prior) != 0 {
		proofRaw, _ := model.WorkspaceCanonicalJSON(proof)
		ack, err = r.Store.OwnedContinuationResult(ctx, entry.PreparationID, "completion-integration-ack", proofRaw)
		if err != nil {
			return empty, err
		}
		if len(ack) != 0 && model.DecodePhysicalClosed(ack, &receipt) != nil {
			return empty, state.ErrControllerActivityConflict
		}
	}
	if len(ack) == 0 {
		if op.ValidateFor(call, view.Application.Operation.Producer.NodeTokenHash, view.Manifest.DesiredRevision, r.now()) != nil || !op.MatchesCurrentSnapshot(view.Fresh.BackendSnapshot) {
			return empty, state.ErrControllerActivityConflict
		}
		if err = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-integration-proof", op, func() (any, error) {
			return runtime.AttestCellProductIntegration(ctx, view.Sandbox, entry, view.Manifest, view.Input, call, op, view.Root, view.Fresh.BackendSnapshot)
		}, &proof); err != nil {
			return empty, err
		}
		expiry, e1 := time.Parse(time.RFC3339Nano, proof.Payload.NotAfter)
		limit, e2 := time.Parse(time.RFC3339Nano, op.ExpiresAt)
		if proof.Validate() != nil || proof.KeyID != view.Application.Operation.Producer.KeyID || proof.Payload.OperationID != op.OperationID || proof.Payload.OperationDigest != op.OperationDigest || proof.Payload.NodeTokenHash != op.NodeTokenHash || e1 != nil || e2 != nil || !r.now().Before(expiry) || expiry.After(limit) {
			return empty, state.ErrControllerActivityConflict
		}
		expected := map[string]any{"binding": call.Binding, "reconciles": call.Operation.Reconciles, "observation": call.Operation.Observation}
		if proof.Payload.RequestID != call.RequestID || model.WorkspaceDigest(proof.Payload.Request) != model.WorkspaceDigest(expected) {
			return empty, state.ErrControllerActivityConflict
		}
		again, e := r.currentCompletedChildAuthority(ctx, owner, child, entry)
		if e != nil {
			return empty, e
		}
		if !sameCompletedChildAuthority(view, again) {
			return empty, state.ErrControllerActivityConflict
		}
		if err = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-integration-ack", proof, func() (any, error) { return control.ReportWorkflowObservation(ctx, proof) }, &receipt); err != nil {
			return empty, err
		}
	}
	original := completedChildIntegration{proof, receipt}
	if _, _, err = controllerIntegrationCandidateSnapshot(view.Fresh.BackendSnapshot, child.Binding, original); err != nil {
		return empty, err
	}
	var retained bool
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-integration-private-ack", original, func() (any, error) { return true, runtime.RetainCellProductObservationReceipt(ctx, proof, receipt) }, &retained); err != nil {
		return empty, err
	}
	if !retained {
		return empty, state.ErrControllerActivityConflict
	}
	return original, nil
}
