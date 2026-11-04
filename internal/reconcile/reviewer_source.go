package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

type reviewerSourceRuntime interface {
	ReadCellProductSource(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, qualification.TrustedWorkspace, model.ChildProductDelivery, model.WorkflowCaptureRequest, model.WorkflowCaptureOperation, json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error)
	RetainCellProductObservationReceipt(context.Context, model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error
	RetainCellProductReviewerRead(context.Context, model.CellServiceV3, model.Manifest, []byte, model.ChildProductDelivery, model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, model.WorkflowObservationReceipt) error
}

// One separate actual reviewer-bound ROOT read/report. No author-read credit,
// input append, sourcefile staging, second reviewer/model call or native selector
// adoption. Missing independent normal root/snapshot suppliers deny BEFORE reads.
func (r *Reconciler) ReadApprovedReviewerSource(ctx context.Context, entry model.CellServiceV3, call model.WorkflowCaptureRequest) (model.ReviewReadWitness, error) {
	var empty model.ReviewReadWitness
	control, ok := r.ManagedControl.(childEffectObservationControl)
	deliveryControl, dok := r.ManagedControl.(cellProductTransport)
	runtime, rok := r.ManagedRuntime.(reviewerSourceRuntime)
	owner, sok := r.currentChildSnapshotOwner()
	if !ok || !dok || !rok || !sok || r.Store == nil {
		return empty, errors.New("reviewer current ROOT/snapshot supplier pending")
	}
	current := r.currentAuthorityManifest()
	found := false
	for _, actual := range current.CellEntriesV3 {
		if reflect.DeepEqual(actual, entry) {
			found = true
		}
	}
	if !found || entry.LifecyclePhase != "execute" || entry.DesiredState != "active" {
		return empty, errors.New("reviewer current preparation changed")
	}
	box, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return empty, err
	}
	if box == nil || box.ObservedState != "running" || box.ObservedGeneration != entry.SandboxGeneration {
		return empty, errors.New("reviewer Sandbox changed")
	}
	snapshot, err := owner.CurrentCellProductWorkflowSnapshot(ctx, entry)
	if err != nil {
		return empty, err
	}
	delivery, err := deliveryControl.ChildProductControl(ctx, entry.PreparationID)
	if err != nil {
		return empty, err
	}
	text, err := r.fetchCellFirstText(ctx, cellV2View(entry))
	if err != nil {
		return empty, err
	}
	if err = r.exportCurrentChildProductFacts(ctx, entry, current, []byte(text), delivery.GenerationDigest()); err != nil {
		return empty, err
	}
	root, err := r.resolveApprovedProductSourceRoot(ctx, entry, delivery, call)
	if err != nil {
		return empty, err
	}
	op, err := control.WorkflowObservationOperation(ctx, call, current.DesiredRevision)
	if err != nil {
		return empty, err
	}
	if !op.MatchesCurrentSnapshot(snapshot) {
		return empty, errors.New("reviewer current workflow snapshot conflict")
	}
	envelope, read, err := runtime.ReadCellProductSource(ctx, model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ImageDigest: box.ImageDigest, Cell: true}, entry, current, []byte(text), root, delivery, call, op, snapshot)
	if err != nil {
		return empty, err
	}
	again, err := owner.CurrentCellProductWorkflowSnapshot(ctx, entry)
	if err != nil || model.WorkspaceDigest(again) != model.WorkspaceDigest(snapshot) || r.currentAuthorityManifest().DesiredRevision != current.DesiredRevision {
		return empty, errors.New("reviewer authority moved during read")
	}
	currentRoot, err := r.resolveApprovedProductSourceRoot(ctx, entry, delivery, call)
	if err != nil || currentRoot != root {
		return empty, errors.New("reviewer registered root moved during read")
	}
	receipt, err := control.ReportWorkflowObservation(ctx, envelope)
	if err != nil {
		return empty, err
	}
	if err = runtime.RetainCellProductObservationReceipt(ctx, envelope, receipt); err != nil {
		return empty, err
	}
	if err = runtime.RetainCellProductReviewerRead(ctx, entry, current, []byte(text), delivery, envelope, read, receipt); err != nil {
		return empty, err
	}
	// Recover the exact grant from signed delivery, already verified by the
	// operation-specific Runtime reader. It is not installed/root authority here.
	var wire struct {
		Generation struct {
			Policy struct {
				Payload struct {
					SourceReads []qualification.ChildSourceReadScope `json:"sourceReads"`
				} `json:"payload"`
			} `json:"policy"`
		} `json:"generation"`
	}
	var observed struct {
		Reference json.RawMessage `json:"reference"`
	}
	if json.Unmarshal(delivery.Bytes(), &wire) != nil || json.Unmarshal(call.Operation.Observation, &observed) != nil {
		return empty, errors.New("reviewer signed source scope conflict")
	}
	var grant json.RawMessage
	for _, scope := range wire.Generation.Policy.Payload.SourceReads {
		var fields struct {
			Reference json.RawMessage `json:"reference"`
		}
		_ = json.Unmarshal(scope.Grant, &fields)
		if model.WorkspaceDigest(fields.Reference) == model.WorkspaceDigest(observed.Reference) {
			if grant != nil {
				return empty, errors.New("reviewer duplicate source scope")
			}
			grant = scope.Grant
		}
	}
	if grant == nil {
		return empty, errors.New("reviewer source scope absent")
	}
	native, _ := json.Marshal(envelope.Payload.NativeReceipt)
	ack, _ := json.Marshal(receipt)
	return model.ReviewReadWitness{Bytes: read.Bytes, SourceGrant: grant, NativeReceipt: native, ReadReceipt: ack}, nil
}
