package reconcile

import (
	"context"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

type cellProductRuntime interface {
	NeedsCellProductControl(context.Context, model.Sandbox, model.CellServiceV3) (bool, error)
	AdoptCellProductControl(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, model.ChildProductDelivery, []byte) (string, error)
}
type cellProductTransport interface {
	ChildProductControl(context.Context, string) (model.ChildProductDelivery, error)
}

// This is the normal node-client projection seam, not SOURCE hook/socket input.
// Its external route/closed envelope are supplied by F1; no policy may implement
// it by extracting its own purported authority/installed/lifecycle facts.
type cellProductFactTransport interface {
	ChildProductFacts(context.Context, string) (model.ChildProductOriginalFacts, error)
}

type childFactExportRuntime interface {
	ExportCellProductFacts(context.Context, model.CellServiceV3, model.Manifest, qualification.ChildProductAuthorityFacts, qualification.ChildProductInstalledFacts, qualification.ChildProductLifecycleFacts, []byte) error
}

// Explicit manager continuation uses the SAME previously validated immutable
// Runtime authority, not a future parent/backend record or a manifest supplied
// by the caller. Ordinary reconcile continues to pass its own current snapshot.
func (r *Reconciler) verifyCurrentChildProductOrQualification(ctx context.Context, entry model.CellServiceV3) error {
	current := r.currentAuthorityManifest()
	found := false
	for _, actual := range current.CellEntriesV3 {
		if reflect.DeepEqual(actual, entry) {
			found = true
		}
	}
	if !found || entry.DesiredState != "active" || current.DesiredRevision < 1 {
		return errors.New("manager child current authority absent/changed")
	}
	if err := r.verifyCellProductOrQualification(ctx, entry, &current); err != nil {
		return err
	}
	if model.WorkspaceDigest(r.currentAuthorityManifest()) != model.WorkspaceDigest(current) || ctx.Err() != nil {
		return errors.New("manager child current authority moved during adoption")
	}
	return nil
}

func (r *Reconciler) exportCurrentChildProductFacts(ctx context.Context, entry model.CellServiceV3, current model.Manifest, input []byte, generationDigest string) error {
	control, ok := r.ManagedControl.(cellProductFactTransport)
	exporter, eok := r.ManagedRuntime.(childFactExportRuntime)
	if !ok || !eok {
		return errors.New("PRODUCT normal original fact projection/exporter unavailable")
	}
	facts, err := control.ChildProductFacts(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if facts.PreparationID() != entry.PreparationID || facts.Phase() != entry.LifecyclePhase || facts.GenerationDigest() != generationDigest {
		return errors.New("PRODUCT original projection/publication generation moved")
	}
	authority, installed, lifecycle, err := qualification.DecodeOriginalChildProductFacts(facts)
	if err != nil {
		return err
	}
	return exporter.ExportCellProductFacts(ctx, entry, current, authority, installed, lifecycle, input)
}

// This replaces ONLY PRODUCT's legacy qualification gate. It is at the real V3
// pre-credential/pre-worker boundary and always fetches fixed node control, exact
// immutable firstText, and independently current installed/qualification facts.
func (r *Reconciler) verifyCellProductOrQualification(ctx context.Context, entry model.CellServiceV3, current *model.Manifest) error {
	product, ok := r.ManagedRuntime.(cellProductRuntime)
	if !ok {
		return r.verifyCellQualification(ctx, entry)
	}
	local, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return err
	}
	if local == nil || local.Generation != entry.SandboxGeneration || local.ObservedGeneration != entry.SandboxGeneration || local.ImageDigest == "" {
		return errors.New("PRODUCT Sandbox missing/changed")
	}
	box := model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ImageDigest: local.ImageDigest, Cell: true}
	if current != nil {
		target, err := childSourceTransportTarget(entry, *current)
		if err != nil {
			return err
		}
		selected, err := r.adoptSourceTransportTarget(ctx, box, *current, target)
		if err != nil {
			return err
		}
		if selected {
			// Retain metadata, but do not replace the existing qualification/ROOT
			// gate with metadata alone. Local policy/grant admission still waits.
			return ErrSourceLocalGrantPending
		}
	}
	needed, err := product.NeedsCellProductControl(ctx, box, entry)
	if err != nil {
		return err
	}
	if !needed {
		if err := r.verifyCellQualification(ctx, entry); err != nil {
			return err
		}
		if current != nil {
			if err := r.ensurePaidCaseDomain(ctx, *current); err != nil {
				return err
			}
			if owner, ok := r.ManagedRuntime.(interface {
				PublishQualificationPhysicalAllocation(context.Context, model.CellServiceV3, model.Manifest) error
			}); ok {
				return owner.PublishQualificationPhysicalAllocation(ctx, entry, *current)
			}
		}
		return nil
	}
	if current == nil {
		return errors.New("PRODUCT requires independently observed current manifest")
	}
	if err := r.ensurePaidCaseDomain(ctx, *current); err != nil {
		return err
	}
	transport, ok := r.ManagedControl.(cellProductTransport)
	if !ok {
		return errors.New("PRODUCT node delivery unavailable")
	}
	delivery, err := transport.ChildProductControl(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	firstText, err := r.fetchCellFirstText(ctx, cellV2View(entry))
	if err != nil {
		return err
	}
	// Fixed signed delivery above is published already. Fetch the INDEPENDENT
	// original owner projection and export it before current assembly/adoption on
	// every ordinary admission/replay. Missing projection cannot reuse old files.
	if delivery.Phase() != entry.LifecyclePhase {
		return errors.New("PRODUCT published phase/current entry moved")
	}
	if err = r.exportCurrentChildProductFacts(ctx, entry, *current, []byte(firstText), delivery.GenerationDigest()); err != nil {
		return err
	}
	if err = r.ensurePreparedReviewerSources(ctx, box, entry, *current, delivery, []byte(firstText)); err != nil {
		return err
	}
	_, err = product.AdoptCellProductControl(ctx, box, entry, *current, delivery, []byte(firstText))
	if err != nil {
		return err
	}
	if err := r.ensurePublishedWorkerSourceReads(ctx, box, entry, *current, delivery, []byte(firstText)); err != nil {
		return err
	}
	return r.ensurePublishedIntegrationSource(ctx, box, entry, *current, delivery, []byte(firstText))
}
