package containers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Purpose selection is a protected descriptor, never a model/manifest option.
// Descriptor1 remains qualification. Missing PRODUCT adoption is not legacy
// fallback: independently installed current witnesses are needed before effects.
func (p Podman) NeedsCellProductControl(ctx context.Context, box model.Sandbox, entry model.CellServiceV3) (bool, error) {
	if p.QualificationRoot == "" {
		return false, nil
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return false, err
	}
	tree, _, err := store.Paths(box.ID)
	if err != nil {
		return false, err
	}
	name := filepath.Join(tree, "preparations", entry.PreparationID+".json")
	st, err := os.Lstat(name)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil || !st.Mode().IsRegular() || st.Size() > 65536 {
		return false, qualification.ErrUntrusted
	}
	// An unprotected/changed descriptor is subsequently denied by Store.Select
	// or ReadChildProduct; this branch only chooses the strict consumer family.
	raw, err := os.ReadFile(name)
	if err != nil {
		return false, err
	}
	var header struct {
		FormatVersion int `json:"formatVersion"`
	}
	if json.Unmarshal(raw, &header) != nil || (header.FormatVersion != 1 && header.FormatVersion != 2) {
		return false, qualification.ErrUntrusted
	}
	return header.FormatVersion == 2, nil
}

func (p Podman) AdoptCellProductControl(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, delivery model.ChildProductDelivery, input []byte) (string, error) {
	if p.verifyQualificationMounts(ctx, box.ID) != nil {
		return "", qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return "", err
	}
	// Normal backend native slots stay uncredited. Join ONLY separately retained
	// actual reviewer ROOT/native/ACK and prepare compiler originals before strict
	// final assembly/publication/admission. Missing old/wrong evidence refuses.
	if entry.LifecyclePhase == "execute" {
		store, err := p.qualificationStore(ctx)
		if err != nil {
			return "", err
		}
		if err = producer.EnrichReviewerLifecycle(ctx, entry, current, input, store, box, delivery); err != nil {
			return "", err
		}
	}
	w, err := producer.CurrentChildProductWitness(ctx, entry, current, input)
	if err != nil {
		// Assemble ONLY from separately enrolled owning facts. Complete installed
		// archive/self adoption remains mandatory; absence is not policy fallback.
		if err = producer.PublishCurrentChildProductWitness(ctx, entry, current, input); err != nil {
			return "", err
		}
		w, err = producer.CurrentChildProductWitness(ctx, entry, current, input)
		if err != nil {
			return "", err
		}
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return "", err
	}
	if len(w.SourceContinuation) != 0 {
		if err = p.enrollSourceContinuation(ctx, store, box, w.Case, w.SourceContinuation); err != nil {
			return "", err
		}
	}
	if entry.LifecyclePhase == "execute" {
		if p.PhysicalStore == nil {
			return "", qualification.ErrUntrusted
		}
		local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
		if err != nil || local == nil || local.Phase != "reported" || w.ActualReceipt == nil || qualification.CanonicalDigest(local.Receipt) != qualification.CanonicalDigest(*w.ActualReceipt) || local.Receipt.ValidateFor(entry) != nil {
			return "", qualification.ErrUntrusted
		}
	}
	if err = store.AdoptChildProduct(box, delivery, w, time.Now()); err != nil {
		return "", err
	}
	c, err := store.ReadChildProduct(box, entry.PreparationID, w, time.Now())
	if err != nil || c.Generation.Phase != entry.LifecyclePhase || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return "", qualification.ErrUntrusted
	}
	return c.Descriptor.GenerationDigest, nil
}

func (p Podman) AdoptCellProductEffectControl(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, delivery model.ChildProductEffectDelivery, input []byte) error {
	if delivery.PreparationID() != entry.PreparationID || entry.LifecyclePhase != "execute" || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	w, err := producer.CurrentChildProductWitness(ctx, entry, current, input)
	if err != nil {
		return err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return err
	}
	var previous *qualification.ChildEffectPredecessor
	if delivery.Ordinal() == 1 {
		var effect struct {
			Approval struct {
				PredecessorReceipt json.RawMessage `json:"predecessorReceipt"`
			} `json:"approval"`
		}
		if json.Unmarshal(delivery.Bytes(), &effect) != nil {
			return qualification.ErrUntrusted
		}
		own, err := producer.ChildEffectPredecessor(effect.Approval.PredecessorReceipt, w.Binding)
		if err != nil {
			return err
		}
		previous = &own
	}
	if store.AdoptChildProductEffect(box, delivery, w, previous, time.Now()) != nil || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return qualification.ErrUntrusted
	}
	return nil
}
