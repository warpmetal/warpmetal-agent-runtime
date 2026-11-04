package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type childWorkflowReviewControl interface {
	ReportWorkflowReview(context.Context, json.RawMessage, string) (json.RawMessage, error)
}
type reviewerAssessment struct {
	Disposition string          `json:"disposition"`
	Findings    json.RawMessage `json:"findings"`
}
type completedControllerReview struct {
	Request  json.RawMessage
	Receipt  json.RawMessage
	Evidence model.WorkflowArtifactReceipt
}

// The model supplies only these two semantic fields. Original evidence bytes
// stay untouched; all identity, target and consumed-source fields come from
// independently retained current authority and first acknowledgements.
func parseReviewerAssessment(raw []byte) (reviewerAssessment, error) {
	var a reviewerAssessment
	bad := errors.New("reviewer assessment must be one closed disposition/findings JSON object")
	var fields map[string]json.RawMessage
	if len(raw) < 1 || len(raw) > 16384 || !utf8.Valid(raw) || model.DecodePhysicalClosed(raw, &a) != nil || json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || fields["disposition"] == nil || fields["findings"] == nil {
		return a, bad
	}
	if workflowcontract.Validate(workflowcontract.Domain, "reviewRequest/properties/disposition", fields["disposition"]) != nil || workflowcontract.Validate(workflowcontract.Domain, "reviewRequest/properties/findings", fields["findings"]) != nil {
		return a, bad
	}
	var findings []json.RawMessage
	if json.Unmarshal(a.Findings, &findings) != nil || findings == nil || (a.Disposition == "approve" && len(findings) != 0) {
		return a, bad
	}
	return a, nil
}

func (r *Reconciler) reconcileControllerReviewLocked(ctx context.Context, id string, result controllerStageChildResult) error {
	if result.Stage.Readout.AllocationName != "manager_review" || result.Progress.State != "completed" || len(result.Progress.Children) != 1 {
		return ErrControllerLaterChildPending
	}
	child := result.Progress.Children[0]
	claim := child
	claim.BackendSnapshot = nil
	prior, e := r.Store.OwnedContinuationResult(ctx, id, "review-complete", mustWorkflowJSON(claim))
	if e != nil {
		return e
	}
	if len(prior) != 0 {
		var old completedControllerReview
		if model.DecodePhysicalClosed(prior, &old) != nil || validateCompletedReview(old, child.Binding) != nil {
			return state.ErrControllerActivityConflict
		}
		return nil
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
	if entry == nil || entry.Role != "reviewer" || entry.ExecutionGrant == nil {
		return ErrControllerLaterChildPending
	}
	if pending, e := r.Store.HasPendingOwnedContinuation(ctx, entry.PreparationID, "completion-"); e != nil {
		return e
	} else if pending {
		return state.ErrOwnedContinuationUnknown
	}
	runtime, ok := r.ManagedRuntime.(childWorkflowOutcomeRuntime)
	control, cok := r.ManagedControl.(childWorkflowReviewControl)
	if !ok || !cok {
		return ErrControllerFirstTaskAuthorityPending
	}
	view, e := r.currentCompletedChildAuthority(ctx, result.Application, child, *entry)
	if e != nil {
		return e
	}
	native, e := runtime.ObserveCellWorkflowOutcome(ctx, view.Sandbox, *entry, view.Manifest, view.Input, view.Root)
	if e != nil {
		return e
	}
	if native.Reviewer == nil || native.Result != nil || native.Integration != nil {
		return state.ErrControllerActivityConflict
	}
	captured := native.Reviewer
	if captured.ValidateFor(*entry, captured.GenerationDigest, child.Binding, entry.ExecutionGrant.InputID, model.RawPhysicalDigest(view.Input), captured.AssessmentPath) != nil {
		return state.ErrControllerActivityConflict
	}
	assessment, e := captured.Assessment()
	if e != nil {
		return e
	}
	parsed, e := parseReviewerAssessment(assessment)
	if e != nil {
		return e
	} // No enrollment, upload, review, or inferred approval on malformed output.
	role, reads, e := r.completedReviewerOriginals(ctx, view, child, *entry, *captured)
	if e != nil {
		return e
	}
	target, integration, artifacts, e := r.reviewedIntegrationOriginal(ctx, result)
	if e != nil {
		return e
	}
	consumed, e := reviewerConsumedReferences(reads, view, child, *entry)
	if e != nil {
		return e
	}
	var assignment struct {
		AssignmentID, ExecutionID, Purpose string
		Target                             json.RawMessage
	}
	if json.Unmarshal(child.AdmissionAssociation.Assignment, &assignment) != nil || assignment.Purpose != "review" || assignment.ExecutionID != child.ExecutionID || model.WorkspaceDigest(assignment.Target) != model.WorkspaceDigest(target) {
		return state.ErrControllerActivityConflict
	}
	// Retain the actual first terminal assessment before independent facts/read/upload.
	outcomeClaim := map[string]any{"binding": child.Binding, "generationDigest": captured.GenerationDigest, "inputId": captured.InputID, "inputDigest": captured.InputDigest, "terminalSeq": captured.TerminalSeq, "assessmentPath": captured.AssessmentPath, "assessmentDigest": captured.AssessmentDigest}
	var original model.ChildNativeReviewerCapture
	if e = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-review-outcome", outcomeClaim, func() (any, error) { return *captured, nil }, &original); e != nil {
		return e
	}
	if first, e := original.Assessment(); e != nil || string(first) != string(assessment) {
		return state.ErrControllerActivityConflict
	}
	settled, e := r.ensureCompletedChildSettlementLocked(ctx, result.Application, child, *entry)
	if e != nil {
		return e
	}
	if settled == nil {
		return ErrControllerFirstTaskAuthorityPending
	}
	call := model.WorkflowCaptureRequest{FormatVersion: 1, RequestID: "wfreview_evidence_" + model.WorkspaceDigest(outcomeClaim)[7:], Binding: child.Binding, Operation: model.WorkflowCapture{Kind: "observation", Reconciles: json.RawMessage("null"), Observation: mustWorkflowJSON(map[string]any{"type": "artifact_read", "sourcePath": captured.AssessmentPath, "digest": captured.AssessmentDigest, "byteCount": len(assessment)})}}
	var upload model.WorkflowArtifactReceipt
	if e = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-review-evidence", outcomeClaim, func() (any, error) {
		return r.readUploadApprovedChildArtifact(ctx, *entry, call, "review_evidence", "application/json", func(ctx context.Context, current model.CellServiceV3) (json.RawMessage, error) {
			v, e := r.currentCompletedChildAuthority(ctx, result.Application, child, current)
			return v.Fresh.BackendSnapshot, e
		}, entry.PreparationID)
	}, &upload); e != nil {
		return e
	}
	if upload.ExecutionID != child.ExecutionID || upload.Purpose != "review_evidence" || upload.SourcePath != captured.AssessmentPath || upload.Digest != captured.AssessmentDigest || upload.ByteCount != len(assessment) || upload.ContentType != "application/json" {
		return state.ErrControllerActivityConflict
	}
	evidence := map[string]any{"artifactId": upload.ArtifactID, "digest": upload.Digest, "byteCount": upload.ByteCount, "contentType": upload.ContentType}
	body := map[string]any{"formatVersion": 1, "binding": child.Binding, "assignmentId": assignment.AssignmentID, "target": target, "integration": integration, "reviewedArtifacts": artifacts, "consumedRefs": consumed, "disposition": parsed.Disposition, "findings": parsed.Findings, "evidence": []any{evidence}}
	body["requestId"] = "wfreview_" + model.WorkspaceDigest(body)[7:]
	raw := mustWorkflowJSON(body)
	if workflowcontract.Validate(workflowcontract.Domain, "reviewRequest", raw) != nil {
		return state.ErrControllerActivityConflict
	}
	again, e := r.currentCompletedChildAuthority(ctx, result.Application, child, *entry)
	if e != nil {
		return e
	}
	if !sameCompletedChildAuthority(view, again) {
		return state.ErrControllerActivityConflict
	}
	var facts struct {
		SnapshotDigest                                  string
		Quiescent, EffectsComplete, DescendantsComplete bool
	}
	if settled.Receipt.ValidateFor(settled.Proof, r.now()) != nil || json.Unmarshal(settled.Proof.Payload.Readback, &facts) != nil || facts.SnapshotDigest != model.WorkspaceDigest(view.Fresh.BackendSnapshot) || !facts.Quiescent || !facts.EffectsComplete || !facts.DescendantsComplete {
		return state.ErrControllerActivityConflict
	}
	var receipt json.RawMessage
	if e = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-review-report", raw, func() (any, error) { return control.ReportWorkflowReview(ctx, raw, role.Lease) }, &receipt); e != nil {
		return e
	}
	complete := completedControllerReview{raw, receipt, upload}
	if e = validateCompletedReview(complete, child.Binding); e != nil {
		return e
	}
	var retained completedControllerReview
	return r.ownedContinuationOnce(ctx, id, "review-complete", claim, func() (any, error) { return complete, nil }, &retained)
}

func validateCompletedReview(value completedControllerReview, binding json.RawMessage) error {
	bad := state.ErrControllerActivityConflict
	if workflowcontract.Validate(workflowcontract.Domain, "reviewRequest", value.Request) != nil || workflowcontract.Validate(workflowcontract.Domain, "reviewReceipt", value.Receipt) != nil {
		return bad
	}
	var request map[string]json.RawMessage
	var receipt struct {
		ReviewDigest, ReviewerExecutionID, Disposition string
		Target, Integration                            json.RawMessage
	}
	var b struct{ ExecutionID string }
	if json.Unmarshal(value.Request, &request) != nil || json.Unmarshal(value.Receipt, &receipt) != nil || json.Unmarshal(binding, &b) != nil || model.WorkspaceDigest(request["binding"]) != model.WorkspaceDigest(binding) {
		return bad
	}
	delete(request, "requestId")
	var disposition string
	_ = json.Unmarshal(request["disposition"], &disposition)
	if receipt.ReviewDigest != model.WorkspaceDigest(request) || receipt.ReviewerExecutionID != b.ExecutionID || receipt.Disposition != disposition || model.WorkspaceDigest(receipt.Target) != model.WorkspaceDigest(request["target"]) || model.WorkspaceDigest(receipt.Integration) != model.WorkspaceDigest(request["integration"]) {
		return bad
	}
	return nil
}

// Reads the first preprompt locator and its existing proof/enrollment/read
// originals. Missing or partial custody cannot trigger a replacement binding.
func (r *Reconciler) completedReviewerOriginals(ctx context.Context, view completedChildAuthority, child ControllerFirstTaskChildResult, entry model.CellServiceV3, capture model.ChildNativeReviewerCapture) (model.WorkflowRoleEnrollment, qualification.ReviewerReadOriginals, error) {
	var role model.WorkflowRoleEnrollment
	var reads qualification.ReviewerReadOriginals
	bad := state.ErrControllerActivityConflict
	raw, e := r.Store.OwnedContinuationClaim(ctx, entry.PreparationID, "reviewer-source-original")
	if e != nil {
		return role, reads, e
	}
	if len(raw) == 0 {
		return role, reads, ErrControllerFirstTaskAuthorityPending
	}
	var claim reviewerSourceClaim
	var index reviewerSourceOriginalIndex
	if model.DecodePhysicalClosed(raw, &claim) != nil || !reflect.DeepEqual(claim.Entry, entry) || claim.GenerationDigest != capture.GenerationDigest || claim.InputDigest != model.RawPhysicalDigest(view.Input) {
		return role, reads, bad
	}
	get := func(step string, basis any, out any) error {
		v, e := r.Store.OwnedContinuationResult(ctx, entry.PreparationID, step, mustWorkflowJSON(basis))
		if e != nil {
			return e
		}
		if len(v) == 0 {
			return state.ErrOwnedContinuationUnknown
		}
		return model.DecodePhysicalClosed(v, out)
	}
	if e = get("reviewer-source-original", claim, &index); e != nil {
		return role, reads, e
	}
	if index.Base != claim.base() || index.ClaimDigest != model.WorkspaceDigest(claim) {
		return role, reads, bad
	}
	if e = get(index.Base+"-complete", claim, &reads); e != nil {
		return role, reads, e
	}
	var op model.WorkflowRoleOperation
	var proof model.WorkflowRoleEnvelope
	basis, e := r.Store.OwnedContinuationClaim(ctx, entry.PreparationID, index.Base+"-role-operation")
	if e != nil {
		return role, reads, e
	}
	if len(basis) == 0 {
		return role, reads, state.ErrOwnedContinuationUnknown
	}
	if e = get(index.Base+"-role-operation", json.RawMessage(basis), &op); e != nil {
		return role, reads, e
	}
	if e = get(index.Base+"-role-proof", op, &proof); e != nil {
		return role, reads, e
	}
	if e = get(index.Base+"-role-enroll", proof, &role); e != nil {
		return role, reads, e
	}
	var b struct{ WorkID, ExecutionID string }
	var snap struct{ ManagedServiceReceiptDigest, NativeContextDigest string }
	_ = json.Unmarshal(child.Binding, &b)
	_ = json.Unmarshal(view.Fresh.BackendSnapshot, &snap)
	s := op.Subject
	p := view.Application.Operation.Producer
	if op.Validate() != nil || proof.Validate() != nil || role.Validate() != nil || s.AccountID != view.Application.Operation.AccountID || s.TaskID != view.Application.Operation.TaskID || s.Role != "reviewer" || s.ServiceRegistrationID != entry.ServiceRegistrationID || s.ServiceGeneration != entry.ServiceGeneration || s.NativeSessionID != entry.NativeSessionID || s.WorkID == nil || *s.WorkID != b.WorkID || s.ExecutionID == nil || *s.ExecutionID != b.ExecutionID || s.ServerID != view.Manifest.ServerID || s.SandboxID != entry.SandboxID || s.SandboxGeneration != entry.SandboxGeneration || s.CellID != entry.OwnerCellID || s.ControllerID != entry.ControllerID || s.ControllerRevision != entry.ControllerRevision || s.AuthorityRevision != entry.AuthorityRevision || op.NodeTokenHash != p.NodeTokenHash || proof.KeyID != p.KeyID || proof.Payload.OperationDigest != op.OperationDigest || proof.Payload.OperationID != op.OperationID || !reflect.DeepEqual(proof.Payload.Subject, s) || proof.Payload.NodeTokenHash != p.NodeTokenHash || op.ManagedServiceReceiptDigest != snap.ManagedServiceReceiptDigest || op.NativeContextDigest != snap.NativeContextDigest || proof.Payload.ManagedServiceReceiptDigest != op.ManagedServiceReceiptDigest || proof.Payload.NativeContextDigest != op.NativeContextDigest {
		return role, reads, bad
	}
	deadline, e1 := time.Parse(time.RFC3339Nano, role.ExpiresAt)
	limit, e2 := time.Parse(time.RFC3339Nano, proof.Payload.NotAfter)
	oplimit, e3 := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || !r.now().Before(deadline) || deadline.After(limit) || limit.After(oplimit) {
		return role, reads, ErrWorkflowRoleExpired
	}
	if len(reads.Physical) != len(claim.Selection.Physical) {
		return role, reads, bad
	}
	for i, read := range append(append([]qualification.ChildSourceReadOriginal{}, reads.Physical...), reads.Artifact) {
		expected := claim.Selection.Artifact
		if i < len(claim.Selection.Physical) {
			expected = claim.Selection.Physical[i]
		}
		var request struct {
			Observation struct {
				Reference model.ControllerPlanReference
				ByteCount int
			}
		}
		if json.Unmarshal(read.Envelope.Payload.Request, &request) != nil || request.Observation.Reference != expected.Reference || request.Observation.ByteCount != expected.ByteCount {
			return role, reads, bad
		}
	}
	return role, reads, nil
}

func reviewerConsumedReferences(reads qualification.ReviewerReadOriginals, view completedChildAuthority, child ControllerFirstTaskChildResult, entry model.CellServiceV3) ([]any, error) {
	out := []any{}
	seen := map[string]bool{}
	for _, read := range append(append([]qualification.ChildSourceReadOriginal{}, reads.Physical...), reads.Artifact) {
		p, n, ack := read.Envelope.Payload, read.Envelope.Payload.NativeReceipt, read.Receipt
		var call struct {
			Binding, Reconciles json.RawMessage
			Observation         struct {
				Type           string
				Reference      model.ControllerPlanReference
				ObservedDigest string
				ByteCount      int
			}
		}
		if read.Envelope.Validate() != nil || json.Unmarshal(p.Request, &call) != nil || read.Envelope.KeyID != view.Application.Operation.Producer.KeyID || p.NodeTokenHash != view.Application.Operation.Producer.NodeTokenHash || model.WorkspaceDigest(call.Binding) != model.WorkspaceDigest(child.Binding) || string(call.Reconciles) != "null" || n.Role != "reviewer" || n.NativeSessionID != entry.NativeSessionID || n.ServiceRegistrationID != entry.ServiceRegistrationID || n.ServiceGeneration != entry.ServiceGeneration || call.Observation.Type != "source_read" || call.Observation.ObservedDigest != call.Observation.Reference.SourceDigest || ack.ExecutionID != child.ExecutionID || ack.Type != "source_read" || ack.Status != "settled" {
			return nil, state.ErrControllerActivityConflict
		}
		outer := model.WorkflowObservationRequest{FormatVersion: 1, RequestID: p.RequestID, Binding: call.Binding, Reconciles: call.Reconciles, Observation: mustWorkflowJSON(call.Observation)}
		// Preserve lower-case owning observation field names for its receipt digest.
		var exact map[string]json.RawMessage
		_ = json.Unmarshal(p.Request, &exact)
		outer.Observation = exact["observation"]
		if workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", mustWorkflowJSON(ack)) != nil || ack.ReceiptDigest != model.WorkspaceDigest(outer) {
			return nil, state.ErrControllerActivityConflict
		}
		key := model.WorkspaceDigest(call.Observation.Reference)
		if seen[key] {
			return nil, state.ErrControllerActivityConflict
		}
		seen[key] = true
		out = append(out, map[string]any{"reference": call.Observation.Reference, "readReceipt": model.WorkflowReceiptRef{ReceiptID: ack.ReceiptID, ReceiptDigest: ack.ReceiptDigest}})
	}
	return out, nil
}

// The normal integration stage owns the original target manifest and first
// candidate receipt. A review targets that same implement result, never a new one.
func (r *Reconciler) reviewedIntegrationOriginal(ctx context.Context, result controllerStageChildResult) (json.RawMessage, model.WorkflowReceiptRef, json.RawMessage, error) {
	var zero model.WorkflowReceiptRef
	bad := state.ErrControllerActivityConflict
	var selected struct {
		Intent struct {
			Target    json.RawMessage
			Candidate struct {
				Integration                 model.WorkflowReceiptRef
				AfterDigest, ManifestDigest string
			}
		}
	}
	if json.Unmarshal(mustWorkflowJSON(result.Stage.Declared.Target), &selected) != nil {
		return nil, zero, nil, bad
	}
	claim, e := r.Store.OwnedContinuationClaim(ctx, result.Application.ApplicationOperationID, "controller-stage-manager_integrate")
	if e != nil {
		return nil, zero, nil, e
	}
	raw, e := r.Store.OwnedContinuationResult(ctx, result.Application.ApplicationOperationID, "controller-stage-manager_integrate", claim)
	var stage controllerStageOriginal
	if e != nil || model.DecodePhysicalClosed(raw, &stage) != nil || stage.Readout.AllocationName != "manager_integrate" || stage.Readout.ApplicationOperationDigest != result.Application.ApplicationOperationDigest || stage.Readout.CaseManifestDigest != result.Stage.Readout.CaseManifestDigest || stage.Readout.ServiceRegistrationID != result.Stage.Readout.ServiceRegistrationID {
		return nil, zero, nil, bad
	}
	id := controllerStageID(stage)
	basis, e := r.Store.OwnedContinuationClaim(ctx, id, "integration-complete")
	if e != nil {
		return nil, zero, nil, e
	}
	raw, e = r.Store.OwnedContinuationResult(ctx, id, "integration-complete", basis)
	var first completedControllerIntegration
	if e != nil || model.DecodePhysicalClosed(raw, &first) != nil || first.Integration.Proof.Validate() != nil || first.Candidate.Proof.Validate() != nil || first.Candidate.Receipt.ProofDigest != model.WorkspaceDigest(first.Candidate.Proof) {
		return nil, zero, nil, bad
	}
	var request struct{ Binding, Reconciles, Observation json.RawMessage }
	var observed struct {
		Target, Artifacts json.RawMessage
		AfterDigest       string
	}
	if json.Unmarshal(first.Integration.Proof.Payload.Request, &request) != nil || json.Unmarshal(request.Observation, &observed) != nil {
		return nil, zero, nil, bad
	}
	if _, _, e = controllerIntegrationCandidateSnapshot(mustWorkflowJSON(map[string]any{}), request.Binding, first.Integration); e != nil {
		return nil, zero, nil, e
	}
	ref := model.WorkflowReceiptRef{ReceiptID: first.Integration.Receipt.ReceiptID, ReceiptDigest: first.Integration.Receipt.ReceiptDigest}
	if ref != selected.Intent.Candidate.Integration || observed.AfterDigest != selected.Intent.Candidate.AfterDigest || model.WorkspaceDigest(observed.Target) != model.WorkspaceDigest(selected.Intent.Target) || model.WorkspaceDigest(observed.Artifacts) != selected.Intent.Candidate.ManifestDigest {
		return nil, zero, nil, bad
	}
	return selected.Intent.Target, ref, observed.Artifacts, nil
}
