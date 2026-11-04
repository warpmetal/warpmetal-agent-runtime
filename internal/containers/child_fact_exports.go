package containers

import (
	"context"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Called by ordinary node projection/admission AFTER committed publication, or
// by the test-only SOURCE hook. These are original owner facts, not PRODUCT extraction. The
// Runtime's own STATE must independently corroborate every execute receipt.
func (p Podman) ExportCellProductFacts(ctx context.Context, entry model.CellServiceV3, current model.Manifest, authority qualification.ChildProductAuthorityFacts, installed qualification.ChildProductInstalledFacts, lifecycle qualification.ChildProductLifecycleFacts, input []byte) error {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	if entry.LifecyclePhase == "execute" {
		if p.PhysicalStore == nil {
			return qualification.ErrUntrusted
		}
		local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
		if err != nil || local == nil || local.Phase != "reported" || lifecycle.ActualReceipt == nil || qualification.CanonicalDigest(local.Receipt) != qualification.CanonicalDigest(*lifecycle.ActualReceipt) || local.Receipt.ValidateFor(entry) != nil {
			return qualification.ErrUntrusted
		}
	}
	if err = producer.ExportOriginalChildProductFacts(ctx, entry, current, authority, installed, lifecycle, input, time.Now()); err != nil {
		return err
	}
	return p.publishMeasuredInstalledScriptRoots(ctx, entry, current, producer, input)
}
