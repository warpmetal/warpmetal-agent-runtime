package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Read selection is metadata only. Original envelopes below are the sole source
// of receipt credit; caller-created receipt references are never accepted.
type ReviewerSourceSelection struct {
	Physical []ChildApprovedSourceRead
	Artifact ChildApprovedSourceRead
}
type ReviewerReadOriginals struct {
	Physical []ChildSourceReadOriginal
	Artifact ChildSourceReadOriginal
}

// Existing authenticated target GETs only. The native custody owner selects
// each exact target/artifact/execution from current signed reviewer authority.
type ReviewerArtifactTransport interface {
	ReadWorkflowResult(context.Context, json.RawMessage, string) (json.RawMessage, error)
	FetchWorkflowArtifact(context.Context, string, json.RawMessage, string) ([]byte, error)
}

func (c ChildProductControl) ReviewerSources() (ReviewerSourceSelection, error) {
	var out ReviewerSourceSelection
	if c.Generation.Policy == nil || c.Generation.Policy.Payload.FormatVersion != 4 || c.Generation.FormatVersion != 5 || c.Generation.Phase != "execute" {
		return out, ErrUntrusted
	}
	q := c.Generation.Policy.Payload
	if q.Purpose != "reviewer" || len(q.ArtifactReads) != 1 || len(q.SourceReads) > 64 {
		return out, ErrUntrusted
	}
	seen := map[string]bool{}
	selectRead := func(reference json.RawMessage, count int64) (ChildApprovedSourceRead, error) {
		var r ChildApprovedSourceRead
		if workflowcontract.Validate(workflowcontract.Domain, "reference", reference) != nil || json.Unmarshal(reference, &r.Reference) != nil || r.Reference.Status != "accepted" || count < 0 || count > 16384 || seen[CanonicalDigest(reference)] {
			return r, ErrUntrusted
		}
		seen[CanonicalDigest(reference)] = true
		r.ByteCount = int(count)
		return r, nil
	}
	for _, s := range q.SourceReads {
		g := childFields(s.Grant)
		r, err := selectRead(g["reference"], childInteger(g, "byteCount"))
		if err != nil {
			return out, err
		}
		out.Physical = append(out.Physical, r)
	}
	a := childFields(q.ArtifactReads[0])
	r, err := selectRead(a["reference"], childInteger(childFields(a["artifact"]), "byteCount"))
	if err != nil {
		return out, err
	}
	out.Artifact = r
	return out, nil
}

func (p *Producer) ReadReviewerTargetArtifact(ctx context.Context, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, w ChildWorkflowObservationWitness, fetch func(context.Context, json.RawMessage, json.RawMessage, string) (json.RawMessage, []byte, error)) (model.WorkflowObservationEnvelope, ReviewerArtifactCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var noRead ReviewerArtifactCapture
	q, err := p.childObservationPolicy(call, op, w)
	if err != nil || w.SourceReadDelivery == nil || q.FormatVersion != 4 || q.Purpose != "reviewer" || w.Workspace.WorkspaceDigest != q.Root.Workspace.RootAttestation {
		return empty, noRead, ErrUntrusted
	}
	var c ChildProductControl
	if decode(w.SourceReadDelivery.Bytes(), &c) != nil || !sameProduct(c.Generation.Policy.Payload, q) {
		return empty, noRead, ErrUntrusted
	}
	root, err := confinedRoot(w.Workspace.HostRoot, w.Workspace.Device, w.Workspace.Inode)
	if err != nil {
		return empty, noRead, err
	}
	root.Close()
	j := producerReviewerArtifactJournal{producerPlanJournal{p}}
	prior, found, err := p.replayChildObservation(op, w)
	if err != nil {
		return empty, noRead, err
	}
	if !found {
		if _, err = os.Lstat(filepath.Join(p.config.EvidenceRoot, reviewerArtifactName(w.Product, c, op)+"-read.json")); !errors.Is(err, os.ErrNotExist) {
			return empty, noRead, ErrUntrusted
		}
	}
	read, err := captureReviewerArtifact(ctx, op, w.Product, c, fetch, j)
	if err != nil {
		return empty, noRead, err
	}
	if found {
		if prior.Payload.NativeReceipt.ObservedAt != read.ObservedAt {
			return empty, noRead, ErrUntrusted
		}
		return prior, read, nil
	}
	if _, err = p.childObservationPolicy(call, op, w); err != nil || ctx.Err() != nil {
		return empty, noRead, ErrUntrusted
	}
	envelope, err := p.sealChildObservation(call, op, w, read.ObservedAt)
	return envelope, read, err
}

func (p *Producer) RetainReviewerArtifactRead(ctx context.Context, w ChildProductWitness, c ChildProductControl, envelope model.WorkflowObservationEnvelope, read ReviewerArtifactCapture, receipt model.WorkflowObservationReceipt) error {
	if ctx.Err() != nil || p.RetainChildObservationReceipt(envelope, receipt) != nil {
		return ErrUntrusted
	}
	return retainReviewerArtifactOriginal(w, c, read, ChildSourceReadOriginal{Envelope: envelope, Receipt: receipt}, producerReviewerArtifactJournal{producerPlanJournal{p}}, p.verifyChildObservationReceipt)
}

func (p *Producer) ReadReviewerReceipts(ctx context.Context, w ChildProductWitness, c ChildProductControl) (ReviewerReadOriginals, error) {
	var out ReviewerReadOriginals
	if _, err := c.ReviewerSources(); err != nil {
		return out, err
	}
	for _, scope := range c.Generation.Policy.Payload.SourceReads {
		// Existing physical first originals remain their own custody chain. This
		// load performs no new ACK retention, signature or physical source read.
		read, err := loadReviewerNativeRead(w, c.Descriptor.GenerationDigest, scope, time.Now(), p.read, p.verifyChildObservationReceipt)
		if err != nil {
			return out, err
		}
		var receipt model.WorkflowObservationReceipt
		if decode(read.ReadReceipt, &receipt) != nil {
			return out, ErrUntrusted
		}
		raw, err := p.read("workflow-observation-receipt-"+receipt.ReceiptID+".json", 65536)
		var original ChildSourceReadOriginal
		if err != nil || decode(raw, &original) != nil || p.verifyChildObservationReceipt(original.Envelope, original.Receipt) != nil {
			return out, ErrUntrusted
		}
		out.Physical = append(out.Physical, original)
	}
	_, own, err := loadReviewerArtifactOriginal(ctx, w, c, producerReviewerArtifactJournal{producerPlanJournal{p}}, p.verifyChildObservationReceipt)
	if err != nil {
		return out, err
	}
	out.Artifact = own
	return out, nil
}
