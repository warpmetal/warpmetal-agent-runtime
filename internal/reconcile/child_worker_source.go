package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type workerSourceRuntime interface {
	ApprovedCellProductSourceReads(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte) ([]qualification.ChildApprovedSourceRead, error)
	ReadCellProductApprovedSource(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, qualification.TrustedWorkspace, model.WorkflowCaptureRequest, model.WorkflowCaptureOperation, json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error)
	RetainCellProductSourceRead(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, model.WorkflowObservationReceipt) error
	ReadCellProductSourceReceipts(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte) ([]qualification.ChildSourceReadOriginal, error)
}

type workerSourceCaptureOriginal struct {
	Envelope model.WorkflowObservationEnvelope
	Read     qualification.WorkflowSourceCapture
}

// Called only after normal PRODUCT execute adoption. Preparation and
// qualification keep their existing path. The protected selector owns the
// distinction between a valid other workload and invalid worker authority.
func (r *Reconciler) ensurePublishedWorkerSourceReads(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, delivery model.ChildProductDelivery, input []byte) error {
	if entry.LifecyclePhase != "execute" {
		return nil
	}
	runtime, ok := r.ManagedRuntime.(workerSourceRuntime)
	if !ok {
		return errors.New("published worker source custody unavailable")
	}
	reads, err := runtime.ApprovedCellProductSourceReads(ctx, box, entry, current, input)
	if errors.Is(err, qualification.ErrWorkerSourceNotApplicable) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(reads) > 64 {
		return errors.New("published worker source scope exceeded")
	}
	_, ok = r.ManagedControl.(childEffectObservationControl)
	_, owned := r.currentChildSnapshotOwner()
	if !ok || !owned || r.Store == nil {
		return errors.New("published worker source observation unavailable")
	}
	// A changed source/snapshot must not evade an already dispatched uncertain
	// read/report. Recovery must resolve that first immutable claim separately.
	pending, err := r.Store.HasPendingOwnedContinuation(ctx, entry.PreparationID, "worker-source-")
	if err != nil {
		return err
	}
	if pending {
		return state.ErrOwnedContinuationUnknown
	}
	var wire struct {
		Generation struct {
			Policy struct {
				Payload struct{ Binding json.RawMessage }
			}
		}
	}
	if json.Unmarshal(delivery.Bytes(), &wire) != nil || len(wire.Generation.Policy.Payload.Binding) == 0 {
		return errors.New("published worker binding absent")
	}
	var retained []qualification.ChildSourceReadOriginal
	seen := map[string]bool{}
	for _, read := range reads {
		key := model.WorkspaceDigest(read.Reference)
		if seen[key] || read.ByteCount < 1 || read.ByteCount > 16384 {
			return errors.New("published worker source scope ambiguous")
		}
		seen[key] = true
		identity := model.WorkspaceDigest(map[string]any{"entry": entry, "generation": delivery.GenerationDigest(), "reference": read.Reference})[7:]
		stage := "worker-source-" + identity
		call := model.WorkflowCaptureRequest{FormatVersion: 1, RequestID: "wfsrc_" + identity, Binding: wire.Generation.Policy.Payload.Binding, Operation: model.WorkflowCapture{Kind: "observation", Reconciles: json.RawMessage("null"), Observation: mustWorkflowJSON(map[string]any{"type": "source_read", "reference": read.Reference, "observedDigest": read.Reference.SourceDigest, "byteCount": read.ByteCount})}}
		// A complete first own read is history. A later workflow snapshot is not
		// permission to replace its operation/proof/ACK or repeat the source read.
		prior, complete, err := r.retainedWorkerSourceRead(ctx, entry.PreparationID, stage, call)
		if err != nil {
			return err
		}
		if complete {
			retained = append(retained, prior)
			continue
		}
		original, err := r.ensurePublishedSourceRead(ctx, entry, current, delivery, read, stage, call,
			func(root qualification.TrustedWorkspace, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
				return runtime.ReadCellProductApprovedSource(ctx, box, entry, current, input, root, call, op, snapshot)
			},
			func(envelope model.WorkflowObservationEnvelope, read qualification.WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
				return runtime.RetainCellProductSourceRead(ctx, box, entry, current, input, envelope, read, receipt)
			})
		if err != nil {
			return err
		}
		retained = append(retained, original)
	}
	// The private getter revalidates current control, full original input, first
	// signed envelope and first ACK. Metadata and successful file reads alone
	// never grant consumption credit or permission to dispatch.
	originals, err := runtime.ReadCellProductSourceReceipts(ctx, box, entry, current, input)
	if err != nil || len(originals) != len(retained) || model.WorkspaceDigest(r.currentAuthorityManifest()) != model.WorkspaceDigest(current) {
		return errors.New("worker source first own acknowledgements unavailable")
	}
	for i := range originals {
		if !reflect.DeepEqual(originals[i], retained[i]) {
			return errors.New("worker source first own acknowledgement changed")
		}
	}
	return nil
}

// Read-only existing journal join. Missing stages remain work, incomplete
// dispatched stages remain UNKNOWN, and only all four first originals qualify
// for the protected current receipt getter above. No expiry is extended.
func (r *Reconciler) retainedWorkerSourceRead(ctx context.Context, id, stage string, call model.WorkflowCaptureRequest) (qualification.ChildSourceReadOriginal, bool, error) {
	var empty qualification.ChildSourceReadOriginal
	var op model.WorkflowCaptureOperation
	var original workerSourceCaptureOriginal
	var receipt model.WorkflowObservationReceipt
	var acknowledged bool
	steps := []struct {
		name  string
		claim any
		out   any
	}{
		{"operation", call, &op},
		{"read", &op, &original},
		{"ack", &original.Envelope, &receipt},
		{"private-ack", &receipt, &acknowledged},
	}
	for _, step := range steps {
		claim, err := model.WorkspaceCanonicalJSON(step.claim)
		if err != nil {
			return empty, false, err
		}
		raw, err := r.Store.OwnedContinuationResult(ctx, id, stage+"-"+step.name, claim)
		if err != nil || len(raw) == 0 {
			return empty, false, err
		}
		if err = json.Unmarshal(raw, step.out); err != nil {
			return empty, false, err
		}
	}
	if !acknowledged {
		return empty, false, errors.New("worker source retained private acknowledgement absent")
	}
	return qualification.ChildSourceReadOriginal{Envelope: original.Envelope, Receipt: receipt}, true, nil
}

// Shared mechanics only: selection, staging and sealing remain purpose-owned.
// The fixed readers validate their own current signed scope and full input.
func (r *Reconciler) ensurePublishedSourceRead(ctx context.Context, entry model.CellServiceV3, current model.Manifest, delivery model.ChildProductDelivery, read qualification.ChildApprovedSourceRead, stage string, call model.WorkflowCaptureRequest,
	readSource func(qualification.TrustedWorkspace, model.WorkflowCaptureRequest, model.WorkflowCaptureOperation, json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error),
	retainSource func(model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, model.WorkflowObservationReceipt) error) (qualification.ChildSourceReadOriginal, error) {
	var empty qualification.ChildSourceReadOriginal
	control, ok := r.ManagedControl.(childEffectObservationControl)
	owner, owned := r.currentChildSnapshotOwner()
	if !ok || !owned || r.Store == nil || readSource == nil || retainSource == nil {
		return empty, errors.New("published source observation unavailable")
	}
	root, err := r.resolveApprovedProductSourceRoot(ctx, entry, delivery, call)
	if err != nil {
		return empty, err
	}
	snapshot, err := owner.CurrentCellProductWorkflowSnapshot(ctx, entry)
	if err != nil {
		return empty, err
	}
	var op model.WorkflowCaptureOperation
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-operation", call, func() (any, error) { return control.WorkflowObservationOperation(ctx, call, current.DesiredRevision) }, &op); err != nil {
		return empty, err
	}
	if !op.MatchesCurrentSnapshot(snapshot) {
		return empty, errors.New("worker source current snapshot changed")
	}
	var original workerSourceCaptureOriginal
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-read", op, func() (any, error) {
		envelope, source, err := readSource(root, call, op, snapshot)
		return workerSourceCaptureOriginal{envelope, source}, err
	}, &original); err != nil {
		return empty, err
	}
	if len(original.Read.Bytes) != read.ByteCount || model.RawPhysicalDigest(original.Read.Bytes) != read.Reference.SourceDigest {
		return empty, errors.New("worker source original bytes changed")
	}
	again, err := owner.CurrentCellProductWorkflowSnapshot(ctx, entry)
	if err != nil || model.WorkspaceDigest(again) != model.WorkspaceDigest(snapshot) || model.WorkspaceDigest(r.currentAuthorityManifest()) != model.WorkspaceDigest(current) {
		return empty, errors.New("worker source authority changed during read")
	}
	currentRoot, err := r.resolveApprovedProductSourceRoot(ctx, entry, delivery, call)
	if err != nil || currentRoot != root {
		return empty, errors.New("worker source root changed during read")
	}
	var receipt model.WorkflowObservationReceipt
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-ack", original.Envelope, func() (any, error) { return control.ReportWorkflowObservation(ctx, original.Envelope) }, &receipt); err != nil {
		return empty, err
	}
	var acknowledged bool
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-private-ack", receipt, func() (any, error) {
		return true, retainSource(original.Envelope, original.Read, receipt)
	}, &acknowledged); err != nil {
		return empty, err
	}
	if !acknowledged {
		return empty, errors.New("worker source private acknowledgement absent")
	}
	return qualification.ChildSourceReadOriginal{Envelope: original.Envelope, Receipt: receipt}, nil
}
