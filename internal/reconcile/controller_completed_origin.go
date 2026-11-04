package reconcile

import (
	"context"
	"encoding/json"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// A locator to the first canonical child result, never a second snapshot or
// authority. Current tuple and original claims are checked whenever it is used.
type completedChildOrigin struct {
	Kind          string `json:"kind"`
	SourceID      string `json:"sourceId"`
	PreparationID string `json:"preparationId"`
	BindingDigest string `json:"bindingDigest"`
}
type completedChildOriginal struct {
	Origin      completedChildOrigin
	Application controllerChildApplication
	Child       ControllerFirstTaskChildResult
	Entry       model.CellServiceV3
}

func (r *Reconciler) retainCompletedChildOriginLocked(ctx context.Context, kind, id string, owner controllerChildApplication, child ControllerFirstTaskChildResult, entry model.CellServiceV3) error {
	if _, err := r.currentCompletedChildAuthority(ctx, owner, child, entry); err != nil {
		return err
	}
	o := completedChildOrigin{kind, id, entry.PreparationID, model.WorkspaceDigest(child.Binding)}
	// Resolve from the canonical record before appending the immutable locator.
	if _, err := r.resolveCompletedChildOriginLocked(ctx, o, entry); err != nil {
		return err
	}
	var original completedChildOrigin
	return r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-origin", o, func() (any, error) { return o, nil }, &original)
}

func (r *Reconciler) resolveCompletedChildOriginLocked(ctx context.Context, o completedChildOrigin, entry model.CellServiceV3) (completedChildOriginal, error) {
	var out completedChildOriginal
	if o.PreparationID != entry.PreparationID || o.SourceID == "" || !model.PhysicalDigestValid(o.BindingDigest) {
		return out, state.ErrControllerActivityConflict
	}
	var owner controllerChildApplication
	var children []ControllerFirstTaskChildResult
	switch o.Kind {
	case "first_task":
		result, err := r.readControllerFirstTaskResultLocked(ctx, o.SourceID)
		if err != nil {
			return out, err
		}
		if result.State != "completed" {
			return out, ErrControllerFirstTaskPending
		}
		owner, children = controllerChildApplicationFromFirstTask(result.Owner), result.Children
	case "controller_stage":
		claim, err := r.Store.OwnedContinuationClaim(ctx, o.SourceID, "children")
		if err != nil {
			return out, err
		}
		if len(claim) == 0 {
			return out, ErrControllerFirstTaskPending
		}
		raw, err := r.Store.OwnedContinuationResult(ctx, o.SourceID, "children", claim)
		if err != nil {
			return out, err
		}
		if len(raw) == 0 {
			return out, state.ErrOwnedContinuationUnknown
		}
		var result controllerStageChildResult
		if model.DecodePhysicalClosed(raw, &result) != nil || controllerStageID(result.Stage) != o.SourceID || result.Progress.State != "completed" {
			return out, state.ErrControllerActivityConflict
		}
		compare := result
		compare.Progress.Children = append([]ControllerFirstTaskChildResult(nil), result.Progress.Children...)
		for i := range compare.Progress.Children {
			compare.Progress.Children[i].BackendSnapshot = nil
		}
		if model.WorkspaceDigest(compare) != model.WorkspaceDigest(json.RawMessage(claim)) {
			return out, state.ErrControllerActivityConflict
		}
		owner, children = result.Application, result.Progress.Children
	default:
		return out, state.ErrControllerActivityConflict
	}
	found := false
	for _, child := range children {
		if child.PreparationAssociation.PreparationID == entry.PreparationID {
			if found || model.WorkspaceDigest(child.Binding) != o.BindingDigest {
				return out, state.ErrControllerActivityConflict
			}
			out = completedChildOriginal{o, owner, child, entry}
			found = true
		}
	}
	if !found {
		return out, ErrControllerFirstTaskPending
	}
	return out, nil
}

func (r *Reconciler) completedOriginForExecutionLocked(ctx context.Context, executionID string) (completedChildOriginal, error) {
	var out completedChildOriginal
	found := false
	for _, entry := range r.currentAuthorityManifest().CellEntriesV3 {
		claim, err := r.Store.OwnedContinuationClaim(ctx, entry.PreparationID, "completion-origin")
		if err != nil {
			return out, err
		}
		if len(claim) == 0 {
			continue
		}
		raw, err := r.Store.OwnedContinuationResult(ctx, entry.PreparationID, "completion-origin", claim)
		if err != nil {
			return out, err
		}
		if len(raw) == 0 {
			return out, state.ErrOwnedContinuationUnknown
		}
		var origin completedChildOrigin
		if model.DecodePhysicalClosed(raw, &origin) != nil || model.WorkspaceDigest(origin) != model.WorkspaceDigest(json.RawMessage(claim)) {
			return out, state.ErrControllerActivityConflict
		}
		resolved, err := r.resolveCompletedChildOriginLocked(ctx, origin, entry)
		if err != nil {
			return out, err
		}
		if resolved.Child.ExecutionID == executionID {
			if found {
				return out, state.ErrControllerActivityConflict
			}
			out = resolved
			found = true
		}
	}
	if !found {
		return out, ErrControllerFirstTaskPending
	}
	return out, nil
}

func (r *Reconciler) firstCompletedFactsLocked(ctx context.Context, d completedChildOriginal) (model.WorkflowFactsEnvelope, error) {
	var out model.WorkflowFactsEnvelope
	stage := "completion-settlement-" + model.WorkspaceDigest(d.Child.BackendSnapshot)[7:]
	claim, err := r.Store.OwnedContinuationClaim(ctx, d.Entry.PreparationID, stage+"-proof")
	if err != nil {
		return out, err
	}
	if len(claim) == 0 {
		return out, ErrControllerFirstTaskPending
	}
	raw, err := r.Store.OwnedContinuationResult(ctx, d.Entry.PreparationID, stage+"-proof", claim)
	if err != nil {
		return out, err
	}
	if len(raw) == 0 {
		return out, state.ErrOwnedContinuationUnknown
	}
	var op model.WorkflowFactsOperation
	if model.DecodePhysicalClosed(raw, &out) != nil || out.Validate() != nil || model.DecodePhysicalClosed(claim, &op) != nil || out.Payload.OperationID != op.OperationID || out.Payload.OperationDigest != op.OperationDigest || model.WorkspaceDigest(out.Payload.Binding) != d.Origin.BindingDigest || !op.MatchesCurrentSnapshot(d.Child.BackendSnapshot) {
		return out, state.ErrControllerActivityConflict
	}
	ack, err := r.Store.OwnedContinuationResult(ctx, d.Entry.PreparationID, stage+"-report", raw)
	if err != nil {
		return out, err
	}
	if len(ack) == 0 {
		return out, state.ErrOwnedContinuationUnknown
	}
	var receipt model.WorkflowFactsReceipt
	if model.DecodePhysicalClosed(ack, &receipt) != nil || receipt.ProofDigest != model.WorkspaceDigest(out) || receipt.ExpiresAt != out.Payload.NotAfter {
		return out, state.ErrControllerActivityConflict
	}
	return out, nil
}

// Completed lifecycle records remain history even when their old dispatch
// authority expires. Current report, tuple, fence and UNKNOWN still gate replay.
func (r *Reconciler) controllerStageChildrenHistoryLocked(ctx context.Context, id string, stage controllerStageOriginal, owner controllerChildApplication) (controllerStageChildResult, bool, error) {
	var out controllerStageChildResult
	claim, err := r.Store.OwnedContinuationClaim(ctx, id, "children")
	if err != nil || len(claim) == 0 {
		return out, false, err
	}
	raw, err := r.Store.OwnedContinuationResult(ctx, id, "children", claim)
	if err != nil {
		return out, false, err
	}
	if len(raw) == 0 {
		return out, false, state.ErrOwnedContinuationUnknown
	}
	if model.DecodePhysicalClosed(raw, &out) != nil || model.WorkspaceDigest(out.Stage) != model.WorkspaceDigest(stage) || out.Application != owner || out.Progress.State != "completed" || len(out.Progress.Children) != 1 {
		return out, false, state.ErrControllerActivityConflict
	}
	child := out.Progress.Children[0]
	var selected *model.CellServiceV3
	for _, entry := range r.currentAuthorityManifest().CellEntriesV3 {
		if entry.PreparationID == child.PreparationAssociation.PreparationID {
			if selected != nil {
				return out, false, state.ErrControllerActivityConflict
			}
			copy := entry
			selected = &copy
		}
	}
	if selected == nil {
		return out, false, ErrControllerFirstTaskPending
	}
	origin := completedChildOrigin{"controller_stage", id, selected.PreparationID, model.WorkspaceDigest(child.Binding)}
	if _, err = r.resolveCompletedChildOriginLocked(ctx, origin, *selected); err != nil {
		return out, false, err
	}
	if pending, e := r.Store.HasPendingOwnedContinuation(ctx, selected.PreparationID, "completion-"); e != nil {
		return out, false, e
	} else if pending {
		return out, false, state.ErrOwnedContinuationUnknown
	}
	if _, err = r.currentCompletedChildAuthority(ctx, owner, child, *selected); err != nil {
		return out, false, err
	}
	if err = r.retainCompletedChildOriginLocked(ctx, "controller_stage", id, owner, child, *selected); err != nil {
		return out, false, err
	}
	return out, true, nil
}
