package qualification

import (
	"context"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"time"
)

// Private original compiler record, captured from the normal ORIGINAL intent and
// immutable instruction owner at prepare. Not rebuilt from policy/reviewDelivery.
type reviewerCompilationRecord struct {
	PreparationID             string                       `json:"preparationId"`
	TupleDigest               string                       `json:"tupleDigest"`
	PreparationEnvelopeDigest string                       `json:"preparationEnvelopeDigest"`
	IntentDigest              string                       `json:"intentDigest"`
	Compilation               model.ReviewInputCompilation `json:"compilation"`
}

func reviewerCompilationOriginal(w ChildProductWitness) (reviewerCompilationRecord, error) {
	var r reviewerCompilationRecord
	raw := childFields(w.Intent)["reviewInput"]
	if decode(raw, &r.Compilation) != nil || workflowcontract.Validate(workflowcontract.Manager, "reviewInputCompilation", raw) != nil ||
		r.Compilation.InputID != w.Instructions.InputID || r.Compilation.InputDigest != Digest(w.Input) || r.Compilation.InputByteCount != len(w.Input) {
		return r, ErrUntrusted
	}
	r.PreparationID = w.Preparation.PreparationID
	r.TupleDigest = w.Preparation.PreparedTupleDigest
	r.PreparationEnvelopeDigest = CanonicalDigest(w.AcceptedPreparationEnvelope)
	r.IntentDigest = CanonicalDigest(w.Intent)
	return r, nil
}

func (p *Producer) retainReviewerCompilation(w ChildProductWitness) error {
	if w.InstalledInputs == nil || w.InstalledInputs.Workload.Kind != "review1" {
		return nil
	}
	original, err := reviewerCompilationOriginal(w)
	if err != nil {
		return err
	}
	name := "reviewer-input-" + w.Preparation.PreparationID + ".json"
	if w.Entry.LifecyclePhase == "prepare" {
		return p.append(name, canonicalBytes(original))
	}
	retained, err := p.read(name, 65536)
	if err != nil || string(retained) != string(canonicalBytes(original)) {
		return ErrUntrusted
	}
	return nil
}

// No native selector publication or admission. Existing actual installed checks
// remain mandatory; only the final ROOT-read credit check is not yet applicable.
func (p *Producer) ChildProductSourceReadWitness(ctx context.Context, entry model.CellServiceV3, current model.Manifest, input []byte) (ChildProductWitness, error) {
	var empty ChildProductWitness
	if p == nil {
		return empty, ErrUntrusted
	}
	w, _, err := assembleChildProductOwnerFacts(ctx, entry, input, p.read, time.Now())
	if err != nil || p.retainReviewerCompilation(w) != nil || p.verifyChildProductCurrentInstallation(ctx, w, entry, current, input) != nil {
		return empty, ErrUntrusted
	}
	if w.InstalledInputs.Workload.Kind == "review1" {
		raw, err := p.read("reviewer-input-"+entry.PreparationID+".json", 65536)
		var r reviewerCompilationRecord
		if err != nil || decode(raw, &r) != nil || !bytesCanonical(raw, r) {
			return empty, ErrUntrusted
		}
		w.ReviewCompilation = &r.Compilation
		// The provisional reader never credits a previous lifecycle's read fields.
		w.ReviewReads = nil
		w.ArtifactReviewReads = nil
	}
	return w, nil
}

func verifyReviewerFinalFacts(w ChildProductWitness, now time.Time) error {
	if w.Entry.LifecyclePhase != "execute" || w.InstalledInputs == nil || w.InstalledInputs.Workload.Kind != "review1" {
		return nil
	}
	plan := w.InstalledInputs.ReviewDelivery
	if plan == nil || w.ReviewCompilation == nil || !sameProduct(plan.Binding, w.Binding) || !sameProduct(plan.Assignment, w.Assignment) ||
		!sameProduct(*w.ReviewCompilation, childFields(w.Intent)["reviewInput"]) || model.VerifyReviewerDeliveryOriginals(*w.ReviewCompilation, *plan, string(w.Input), w.ReviewReads, w.ArtifactReviewReads, now) != nil {
		return ErrUntrusted
	}
	return nil
}

// Link selects original protected operation/read/ACK records only. No supplied
// witness is accepted at final assembly; every byte is reread from these owners.
type reviewerNativeLink struct {
	EntryDigest      string `json:"entryDigest"`
	GenerationDigest string `json:"generationDigest"`
	OperationID      string `json:"operationId"`
	ReceiptID        string `json:"receiptId"`
	ScopeDigest      string `json:"scopeDigest"`
}

func (p *Producer) RetainReviewerSourceRead(ctx context.Context, w ChildProductWitness, delivery model.ChildProductDelivery, scope ChildSourceReadScope, envelope model.WorkflowObservationEnvelope, read WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
	if ctx.Err() != nil || w.InstalledInputs == nil || w.InstalledInputs.Workload.Kind != "review1" || w.Entry.LifecyclePhase != "execute" || delivery.Phase() != "execute" || delivery.PreparationID() != w.Preparation.PreparationID ||
		read.OperationDigest != envelope.Payload.OperationDigest || read.ScopeDigest != CanonicalDigest(scope) || p.RetainChildObservationReceipt(envelope, receipt) != nil {
		return ErrUntrusted
	}
	raw, err := p.read("workflow-observation-"+envelope.Payload.OperationID+"-read.json", 65536)
	if err != nil || string(raw) != string(canonicalBytes(read)) {
		return ErrUntrusted
	}
	found := false
	for _, owned := range w.InstalledInputs.SourceReads {
		if sameProduct(owned, scope) {
			found = true
		}
	}
	if !found {
		return ErrUntrusted
	}
	link := reviewerNativeLink{EntryDigest: CanonicalDigest(w.Entry), GenerationDigest: delivery.GenerationDigest(), OperationID: envelope.Payload.OperationID, ReceiptID: receipt.ReceiptID, ScopeDigest: CanonicalDigest(scope)}
	return p.append("reviewer-native-"+w.Preparation.PreparationID+"-"+CanonicalDigest(scope.Grant)[7:]+".json", canonicalBytes(link))
}

func (p *Producer) reviewerOriginalRead(w ChildProductWitness, delivery model.ChildProductDelivery, scope ChildSourceReadScope, now time.Time) (model.ReviewReadWitness, error) {
	return loadReviewerNativeRead(w, delivery.GenerationDigest(), scope, now, p.read, p.verifyChildObservationReceipt)
}

// Private SOURCE journal seam only. Production uses protected Producer reads
// and original ACK/signature verification, never caller-supplied witness bytes.
func loadReviewerNativeRead(w ChildProductWitness, generationDigest string, scope ChildSourceReadScope, now time.Time, load func(string, int) ([]byte, error), verifyACK func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error) (model.ReviewReadWitness, error) {
	var empty model.ReviewReadWitness
	raw, err := load("reviewer-native-"+w.Preparation.PreparationID+"-"+CanonicalDigest(scope.Grant)[7:]+".json", 65536)
	var link reviewerNativeLink
	if err != nil || decode(raw, &link) != nil || !bytesCanonical(raw, link) || link.EntryDigest != CanonicalDigest(w.Entry) || link.GenerationDigest != generationDigest || link.ScopeDigest != CanonicalDigest(scope) || !safeID.MatchString(link.OperationID) || !safeID.MatchString(link.ReceiptID) {
		return empty, ErrUntrusted
	}
	raw, err = load("workflow-observation-receipt-"+link.ReceiptID+".json", 65536)
	var ack struct {
		Envelope model.WorkflowObservationEnvelope `json:"envelope"`
		Receipt  model.WorkflowObservationReceipt  `json:"receipt"`
	}
	if err != nil || decode(raw, &ack) != nil || !bytesCanonical(raw, ack) || ack.Envelope.Payload.OperationID != link.OperationID || verifyACK(ack.Envelope, ack.Receipt) != nil || ack.Receipt.ReceiptID != link.ReceiptID {
		return empty, ErrUntrusted
	}
	// Rehydrate only a FIRST independently acknowledged observation. Its short
	// capture window governs when the original read occurred, not how long the
	// receipt remains usable. Owning callers still verify current signed policy,
	// assignment and grant at now before entering this private reader.
	observed, observedErr := time.Parse(time.RFC3339Nano, ack.Envelope.Payload.NativeReceipt.ObservedAt)
	issued, issuedErr := time.Parse(time.RFC3339Nano, ack.Envelope.Payload.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, ack.Envelope.Payload.NotAfter)
	if observedErr != nil || issuedErr != nil || expiresErr != nil || observed.Before(issued) || !observed.Before(expires) || observed.After(now) {
		return empty, ErrUntrusted
	}
	raw, err = load("workflow-observation-"+link.OperationID+"-read.json", 65536)
	var capture WorkflowSourceCapture
	if err != nil || decode(raw, &capture) != nil || !bytesCanonical(raw, capture) || capture.OperationDigest != ack.Envelope.Payload.OperationDigest || capture.ScopeDigest != CanonicalDigest(scope) || capture.RootDevice == 0 || capture.RootInode == 0 || capture.SourceDevice == 0 || capture.SourceInode == 0 || capture.ObservedAt != ack.Envelope.Payload.NativeReceipt.ObservedAt {
		return empty, ErrUntrusted
	}
	fence, err := load("workflow-observation-"+link.OperationID+"-fence.json", 16384)
	expected := canonicalBytes(map[string]any{"operationDigest": capture.OperationDigest, "scopeDigest": capture.ScopeDigest, "rootDevice": capture.RootDevice, "rootInode": capture.RootInode})
	if err != nil || string(fence) != string(expected) {
		return empty, ErrUntrusted
	}
	return model.ReviewReadWitness{Bytes: capture.Bytes, SourceGrant: scope.Grant, NativeReceipt: canonicalBytes(ack.Envelope.Payload.NativeReceipt), ReadReceipt: canonicalBytes(ack.Receipt)}, nil
}

func (p *Producer) EnrichReviewerLifecycle(ctx context.Context, entry model.CellServiceV3, current model.Manifest, input []byte, store Store, box model.Sandbox, delivery model.ChildProductDelivery) error {
	w, err := p.ChildProductSourceReadWitness(ctx, entry, current, input)
	if err != nil {
		return err
	}
	if w.InstalledInputs.Workload.Kind != "review1" || entry.LifecyclePhase != "execute" {
		return nil
	}
	if _, err = store.ChildProductSourceReadPolicy(box, delivery, w, time.Now()); err != nil {
		return err
	}
	plan := w.InstalledInputs.ReviewDelivery
	if plan == nil {
		return ErrUntrusted
	}
	for _, span := range plan.Spans {
		if plan.FormatVersion == 2 && span.Kind == "target_artifact" {
			var c ChildProductControl
			if decode(delivery.Bytes(), &c) != nil || len(w.ArtifactReviewReads) != 0 {
				return ErrUntrusted
			}
			read, _, err := loadReviewerArtifactOriginal(ctx, w, c, producerReviewerArtifactJournal{producerPlanJournal{p}}, p.verifyChildObservationReceipt)
			if err != nil {
				return err
			}
			w.ArtifactReviewReads = append(w.ArtifactReviewReads, read)
			continue
		}
		var selected *ChildSourceReadScope
		for i := range w.InstalledInputs.SourceReads {
			scope := &w.InstalledInputs.SourceReads[i]
			grant := childFields(scope.Grant)
			if sameProduct(grant["reference"], span.Reference) && childString(grant, "rootGrantDigest") == span.RootGrantDigest {
				if selected != nil {
					return ErrUntrusted
				}
				selected = scope
			}
		}
		if selected == nil {
			return ErrUntrusted
		}
		read, err := p.reviewerOriginalRead(w, delivery, *selected, time.Now())
		if err != nil {
			return err
		}
		w.ReviewReads = append(w.ReviewReads, read)
	}
	if verifyReviewerFinalFacts(w, time.Now()) != nil || ctx.Err() != nil {
		return ErrUntrusted
	}
	raw, err := p.read("child-product-lifecycle-"+entry.PreparationID+".json", 512*1024)
	var life ChildProductLifecycleFacts
	if err != nil || decode(raw, &life) != nil {
		return ErrUntrusted
	}
	life.ReviewReads = w.ReviewReads
	life.ArtifactReviewReads = w.ArtifactReviewReads
	life.ReviewCompilation = w.ReviewCompilation
	if err = p.exportChildLifecycleFacts(ctx, entry, life); err != nil {
		return err
	}
	if plan.FormatVersion == 2 {
		return p.publishReviewerOriginals(ctx, store, box, w, current, delivery)
	}
	return nil
}
