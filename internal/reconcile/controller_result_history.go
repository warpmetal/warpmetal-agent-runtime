package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Accepted effects are immutable history, not permission to repeat admission.
// Current authenticated terminal/report/fence/UNKNOWN checks remain mandatory;
// current artifact contents and expired role/fact leases are not that history.
func (r *Reconciler) completedChildResultHistoryLocked(ctx context.Context, owner controllerChildApplication, child ControllerFirstTaskChildResult, entry model.CellServiceV3) (bool, error) {
	claim, err := r.Store.OwnedContinuationClaim(ctx, entry.PreparationID, "completion-result")
	if err != nil || len(claim) == 0 {
		return false, err
	}
	pending, err := r.Store.HasPendingOwnedContinuation(ctx, entry.PreparationID, "completion-")
	if err != nil {
		return false, err
	}
	if pending {
		return false, state.ErrOwnedContinuationUnknown
	}
	raw, err := r.Store.OwnedContinuationResult(ctx, entry.PreparationID, "completion-result", claim)
	if err != nil {
		return false, err
	}
	if len(raw) == 0 {
		return false, state.ErrOwnedContinuationUnknown
	}
	view, err := r.currentCompletedChildAuthority(ctx, owner, child, entry)
	if err != nil {
		return false, err
	}
	var call struct {
		Binding      json.RawMessage
		AssignmentID string
		Result       struct{ Outputs []json.RawMessage }
	}
	var receipt struct{ ExecutionID, AssignmentID, ResultDigest string }
	var assignment struct{ AssignmentID, ExecutionID, Purpose string }
	if workflowcontract.Validate(workflowcontract.Domain, "resultRequest", claim) != nil || workflowcontract.Validate(workflowcontract.Domain, "resultReceipt", raw) != nil || json.Unmarshal(claim, &call) != nil || json.Unmarshal(raw, &receipt) != nil || json.Unmarshal(child.AdmissionAssociation.Assignment, &assignment) != nil || assignment.Purpose != "implement" || assignment.ExecutionID != child.ExecutionID || call.AssignmentID != assignment.AssignmentID || receipt.AssignmentID != call.AssignmentID || receipt.ExecutionID != child.ExecutionID || model.WorkspaceDigest(call.Binding) != model.WorkspaceDigest(child.Binding) || len(call.Result.Outputs) != 1 {
		return false, state.ErrControllerActivityConflict
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(claim, &fields) != nil || receipt.ResultDigest != model.WorkspaceDigest(map[string]any{"binding": call.Binding, "assignmentId": call.AssignmentID, "result": fields["result"]}) {
		return false, state.ErrControllerActivityConflict
	}
	artifactClaim, err := r.Store.OwnedContinuationClaim(ctx, entry.PreparationID, "completion-artifact-outcome")
	if err != nil || len(artifactClaim) == 0 {
		return false, state.ErrControllerActivityConflict
	}
	data, err := r.Store.OwnedContinuationResult(ctx, entry.PreparationID, "completion-artifact-outcome", artifactClaim)
	var outcome qualification.ChildWorkflowNativeCapture
	if err != nil || model.DecodePhysicalClosed(data, &outcome) != nil || outcome.Result == nil || outcome.Integration != nil || outcome.Reviewer != nil || entry.ExecutionGrant == nil {
		return false, state.ErrControllerActivityConflict
	}
	capture := *outcome.Result
	if capture.ValidateFor(entry, capture.GenerationDigest, child.Binding, entry.ExecutionGrant.InputID, model.RawPhysicalDigest(view.Input)) != nil {
		return false, state.ErrControllerActivityConflict
	}
	metadata, err := childDocumentFromNative(capture.Terminal.Text, outcome.ApprovedSourceReferences)
	if err != nil || model.WorkspaceDigest(json.RawMessage(artifactClaim)) != model.WorkspaceDigest(completedChildArtifactClaim(child.Binding, capture, metadata)) {
		return false, state.ErrControllerActivityConflict
	}
	data, err = r.Store.OwnedContinuationResult(ctx, entry.PreparationID, "completion-artifact", artifactClaim)
	var upload model.WorkflowArtifactReceipt
	if err != nil || model.DecodePhysicalClosed(data, &upload) != nil || workflowcontract.Validate(workflowcontract.Domain, "artifactReceipt", data) != nil || upload.ExecutionID != child.ExecutionID || upload.Purpose != metadata.Type || upload.Digest != capture.Artifact.Digest || upload.ByteCount != capture.Artifact.ByteCount || upload.SourcePath != capture.Artifact.SourcePath {
		return false, state.ErrControllerActivityConflict
	}
	output := map[string]any{"type": metadata.Type, "sourceRefs": metadata.SourceRefs, "method": metadata.Method, "output": map[string]any{"artifactId": upload.ArtifactID, "digest": upload.Digest, "byteCount": upload.ByteCount, "contentType": upload.ContentType}}
	if model.WorkspaceDigest(call.Result.Outputs[0]) != model.WorkspaceDigest(output) {
		return false, state.ErrControllerActivityConflict
	}
	return true, nil
}

func (r *Reconciler) completedFirstTaskHistoryLocked(ctx context.Context, owner api.OwnerFirstTaskOriginal) (bool, error) {
	result, err := r.readControllerFirstTaskResultLocked(ctx, owner.FirstTaskID)
	if errors.Is(err, ErrControllerFirstTaskPending) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !reflect.DeepEqual(result.Owner, owner) {
		return false, state.ErrControllerActivityConflict
	}
	if result.State != "completed" {
		return false, nil
	}
	for _, child := range result.Children {
		var entry *model.CellServiceV3
		for _, actual := range r.currentAuthorityManifest().CellEntriesV3 {
			if actual.PreparationID == child.PreparationAssociation.PreparationID {
				if entry != nil {
					return false, state.ErrControllerActivityConflict
				}
				copy := actual
				entry = &copy
			}
		}
		if entry == nil {
			return false, ErrControllerFirstTaskPending
		}
		found, err := r.completedChildResultHistoryLocked(ctx, controllerChildApplicationFromFirstTask(owner), child, *entry)
		if err != nil || !found {
			return false, err
		}
		if err = r.retainCompletedChildOriginLocked(ctx, "first_task", owner.FirstTaskID, controllerChildApplicationFromFirstTask(owner), child, *entry); err != nil {
			return false, err
		}
	}
	return true, nil
}
