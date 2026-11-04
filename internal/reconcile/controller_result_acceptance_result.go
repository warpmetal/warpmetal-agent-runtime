package reconcile

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type childWorkflowResultControl interface {
	ReportWorkflowResult(context.Context, json.RawMessage, string) (json.RawMessage, error)
}
type childOwnSourceReceiptRuntime interface {
	ReadCellProductSourceReceipts(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte) ([]qualification.ChildSourceReadOriginal, error)
}

// This bounded implement result is separate from integrator observations and
// reviewer assessments. Final business acceptance still belongs to the manager.
func (r *Reconciler) ensureCompletedChildResultLocked(ctx context.Context, owner controllerChildApplication, child ControllerFirstTaskChildResult, entry model.CellServiceV3, role model.WorkflowRoleEnrollment, settlement *completedChildSettlement, artifact *completedChildArtifact) error {
	runtime, supported := r.ManagedRuntime.(childOwnSourceReceiptRuntime)
	if !supported {
		return nil
	} // Earlier adapters cannot claim consumed sources/results.
	control, ok := r.ManagedControl.(childWorkflowResultControl)
	if !ok || settlement == nil || artifact == nil || artifact.Outcome.Result == nil {
		return ErrControllerFirstTaskAuthorityPending
	}
	view, err := r.currentCompletedChildAuthority(ctx, owner, child, entry)
	if err != nil {
		return err
	}
	var input struct {
		FormatVersion int
		Kind          string
		Content       struct{ WorkflowPacket json.RawMessage }
	}
	if json.Unmarshal(view.Input, &input) != nil || input.FormatVersion != 1 || input.Kind != "workspace_workflow_packet" || workflowcontract.Validate(workflowcontract.Manager, "workflowPacket", input.Content.WorkflowPacket) != nil {
		return errors.New("worker result original workflow packet unavailable")
	}
	var packet struct {
		PlanRef  model.ControllerPlanReference
		Specimen struct {
			Applicability            string
			References, ConsumerRefs []model.ControllerPlanReference
			States                   []string
		}
		Dependencies []string
	}
	if json.Unmarshal(input.Content.WorkflowPacket, &packet) != nil || packet.Specimen.Applicability != "not_applicable" || len(packet.Specimen.States) != 0 || len(packet.Dependencies) != 0 {
		return errors.New("worker result state/dependency evidence unavailable")
	}
	var assignment struct {
		AssignmentID, ExecutionID, Purpose string
		Plan                               struct{ PlanRef model.ControllerPlanReference }
	}
	if json.Unmarshal(child.AdmissionAssociation.Assignment, &assignment) != nil || assignment.ExecutionID != child.ExecutionID || assignment.Purpose != "implement" || assignment.Plan.PlanRef != packet.PlanRef {
		return errors.New("worker result assignment conflict")
	}
	originals, err := runtime.ReadCellProductSourceReceipts(ctx, view.Sandbox, entry, view.Manifest, view.Input)
	if err != nil {
		return err
	}
	consumed := []any{}
	seen := map[string]bool{}
	for _, original := range originals {
		var request struct {
			Binding     json.RawMessage
			Observation struct {
				Type           string
				Reference      model.ControllerPlanReference
				ObservedDigest string
				ByteCount      int
			}
		}
		p, n, ack := original.Envelope.Payload, original.Envelope.Payload.NativeReceipt, original.Receipt
		if original.Envelope.Validate() != nil || json.Unmarshal(p.Request, &request) != nil || original.Envelope.KeyID != view.Application.Operation.Producer.KeyID || p.NodeTokenHash != view.Application.Operation.Producer.NodeTokenHash || model.WorkspaceDigest(request.Binding) != model.WorkspaceDigest(child.Binding) || n.Role != "worker" || n.NativeSessionID != entry.NativeSessionID || request.Observation.Type != "source_read" || request.Observation.ObservedDigest != request.Observation.Reference.SourceDigest || request.Observation.ByteCount < 1 || ack.Type != "source_read" || ack.Status != "settled" || ack.ExecutionID != child.ExecutionID || workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", mustWorkflowJSON(ack)) != nil {
			return errors.New("worker result own read acknowledgement conflict")
		}
		key := model.WorkspaceDigest(request.Observation.Reference)
		if seen[key] {
			return errors.New("worker result duplicate source acknowledgement")
		}
		seen[key] = true
		consumed = append(consumed, map[string]any{"reference": request.Observation.Reference, "readReceipt": model.WorkflowReceiptRef{ReceiptID: ack.ReceiptID, ReceiptDigest: ack.ReceiptDigest}})
	}
	required := append([]model.ControllerPlanReference{packet.PlanRef}, packet.Specimen.References...)
	required = append(required, packet.Specimen.ConsumerRefs...)
	for _, ref := range append(required, artifact.Metadata.SourceRefs...) {
		if !seen[model.WorkspaceDigest(ref)] {
			return errors.New("worker result own required source acknowledgement missing")
		}
	}
	upload := artifact.Upload
	if upload.ExecutionID != child.ExecutionID || upload.Purpose != artifact.Metadata.Type || upload.Digest != artifact.Outcome.Result.Artifact.Digest || upload.ByteCount != artifact.Outcome.Result.Artifact.ByteCount || upload.SourcePath != artifact.Outcome.Result.Artifact.SourcePath {
		return errors.New("worker result actual uploaded artifact conflict")
	}
	output := map[string]any{"type": artifact.Metadata.Type, "sourceRefs": artifact.Metadata.SourceRefs, "method": artifact.Metadata.Method, "output": map[string]any{"artifactId": upload.ArtifactID, "digest": upload.Digest, "byteCount": upload.ByteCount, "contentType": upload.ContentType}}
	result := map[string]any{"outcome": "completed", "consumedRefs": consumed, "mismatches": []any{}, "stateEvidence": []any{}, "outputs": []any{output}, "effectReceipts": []any{}, "remainingWork": []string{}}
	identity := map[string]any{"binding": child.Binding, "assignmentId": assignment.AssignmentID, "result": result}
	body := mustWorkflowJSON(map[string]any{"formatVersion": 1, "requestId": "wfresult_" + model.WorkspaceDigest(identity)[7:], "binding": child.Binding, "assignmentId": assignment.AssignmentID, "result": result})
	if workflowcontract.Validate(workflowcontract.Domain, "resultRequest", body) != nil {
		return errors.New("worker result closed request refused")
	}
	prior, err := r.Store.OwnedContinuationResult(ctx, entry.PreparationID, "completion-result", body)
	if err != nil {
		return err
	}
	if len(prior) != 0 {
		return workflowcontract.Validate(workflowcontract.Domain, "resultReceipt", prior)
	}
	// Empty state/effect arrays are a supported current task shape, never a
	// guessed successful assessment or omission of required external effects.
	var snapshot struct{ Effects, Children []json.RawMessage }
	if json.Unmarshal(view.Fresh.BackendSnapshot, &snapshot) != nil || snapshot.Effects == nil || snapshot.Children == nil || len(snapshot.Effects) != 0 || len(snapshot.Children) != 0 || settlement.Receipt.ValidateFor(settlement.Proof, r.now()) != nil {
		return errors.New("worker result effects/settlement evidence unavailable")
	}
	var settled struct {
		SnapshotDigest                                  string
		Quiescent, EffectsComplete, DescendantsComplete bool
	}
	if json.Unmarshal(settlement.Proof.Payload.Readback, &settled) != nil || settled.SnapshotDigest != model.WorkspaceDigest(view.Fresh.BackendSnapshot) || !settled.Quiescent || !settled.EffectsComplete || !settled.DescendantsComplete {
		return errors.New("worker result current settlement changed")
	}
	again, err := r.currentCompletedChildAuthority(ctx, owner, child, entry)
	if err != nil || !sameCompletedChildAuthority(view, again) {
		return errors.New("worker result current authority changed")
	}
	var receipt json.RawMessage
	return r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-result", body, func() (any, error) { return control.ReportWorkflowResult(ctx, body, role.Lease) }, &receipt)
}
