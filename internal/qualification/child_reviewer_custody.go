package qualification

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// A fixed transport of FIRST originals, not new authority. Private cache/file
// identity remains the Producer's responsibility before exporting these proofs.
type childReviewerCustody struct {
	GenerationDigest   string                    `json:"generationDigest"`
	EntryDigest        string                    `json:"entryDigest"`
	InputID            string                    `json:"inputId"`
	InputDigest        string                    `json:"inputDigest"`
	DeliveryPlanDigest string                    `json:"deliveryPlanDigest"`
	SourceReads        []ChildSourceReadOriginal `json:"sourceReads"`
	ArtifactReads      []ChildSourceReadOriginal `json:"artifactReads"`
}

func reviewerCustodyOriginals(w ChildProductWitness, c ChildProductControl, own ReviewerReadOriginals) (childReviewerCustody, error) {
	var out childReviewerCustody
	if c.Generation.Policy == nil || c.Generation.FormatVersion != 5 || c.Generation.Policy.Payload.FormatVersion != 4 || verifyReviewerFinalFacts(w, time.Now()) != nil {
		return out, ErrUntrusted
	}
	d := c.Generation.Policy.Payload.ReviewDelivery
	if d == nil || len(own.Physical) != len(w.ReviewReads) || len(w.ArtifactReviewReads) != 1 {
		return out, ErrUntrusted
	}
	seen := map[string]bool{}
	for _, r := range own.Physical {
		found := false
		for _, read := range w.ReviewReads {
			if sameProduct(r.Envelope.Payload.NativeReceipt, read.NativeReceipt) && sameProduct(r.Receipt, read.ReadReceipt) {
				found = true
			}
		}
		if !found || seen[r.Receipt.ReceiptID] {
			return out, ErrUntrusted
		}
		seen[r.Receipt.ReceiptID] = true
	}
	if !sameProduct(own.Artifact.Envelope.Payload.NativeReceipt, w.ArtifactReviewReads[0].NativeReceipt) || !sameProduct(own.Artifact.Receipt, w.ArtifactReviewReads[0].ReadReceipt) {
		return out, ErrUntrusted
	}
	return childReviewerCustody{GenerationDigest: c.Descriptor.GenerationDigest, EntryDigest: CanonicalDigest(w.Entry), InputID: d.InputID, InputDigest: d.InputDigest, DeliveryPlanDigest: d.DeliveryPlanDigest, SourceReads: own.Physical, ArtifactReads: []ChildSourceReadOriginal{own.Artifact}}, nil
}
func (p *Producer) publishReviewerOriginals(ctx context.Context, store Store, box model.Sandbox, w ChildProductWitness, current model.Manifest, delivery model.ChildProductDelivery) error {
	var c ChildProductControl
	if decode(delivery.Bytes(), &c) != nil || p == nil || p.key == nil {
		return ErrUntrusted
	}
	// This getter reopens the full private artifact and physical original read,
	// fence and ACK records. No new source read, fetch, signature or credit.
	own, err := p.ReadReviewerReceipts(ctx, w, c)
	if err != nil {
		return err
	}
	bundle, err := reviewerCustodyOriginals(w, c, own)
	if err != nil {
		return err
	}
	raw := canonicalBytes(bundle)
	if len(raw) > 512*1024 || p.append("reviewer-custody-"+c.Descriptor.GenerationDigest[7:]+".json", raw) != nil {
		return ErrUntrusted
	}
	if p.verifyChildProductCurrentInstallation(ctx, w, w.Entry, current, w.Input) != nil {
		return ErrUntrusted
	}
	return store.publishReviewerCustody(ctx, box, w, delivery, raw)
}
func (s Store) publishReviewerCustody(ctx context.Context, box model.Sandbox, w ChildProductWitness, delivery model.ChildProductDelivery, raw []byte) error {
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return err
	}
	if _, err = s.ChildProductSourceReadPolicy(box, delivery, w, time.Now()); err != nil || ctx.Err() != nil {
		return ErrUntrusted
	}
	dir := filepath.Join(tree, "product", "reviewer")
	if s.childProductDirectory(dir, tree, key) != nil {
		return ErrUntrusted
	}
	name := filepath.Join(dir, delivery.GenerationDigest()[7:]+".json")
	if err = s.childProductFile(name, raw); errors.Is(err, os.ErrExist) {
		prior, e := s.read(name, tree, key, 512*1024)
		if e != nil || !bytes.Equal(prior, raw) {
			return ErrUntrusted
		}
	} else if err != nil {
		return err
	}
	if syncChildProductDirectory(dir) != nil {
		return ErrUntrusted
	}
	if _, err = s.ChildProductSourceReadPolicy(box, delivery, w, time.Now()); err != nil || ctx.Err() != nil {
		return ErrUntrusted
	}
	return nil
}
