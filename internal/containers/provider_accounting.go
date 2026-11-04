package containers

import (
	"context"
	"encoding/json"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func (p Podman) InitializeProviderAccounting(ctx context.Context, control qualification.ProviderOpeningControl) error {
	selected, err := qualification.ProviderAccountingSelected(p.QualificationProducer)
	if err != nil || !selected {
		return err
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	return producer.InitializeProviderAccounting(ctx, p.PhysicalStore, control)
}

func (p Podman) CommitProviderPhysicalSettlement(ctx context.Context, control qualification.ProviderSettlementControl, o state.PhysicalOperation, e model.PhysicalSettlement) error {
	if p.PhysicalStore == nil {
		return physicalgate.ErrPrerequisite
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	return producer.SettleProviderPhysical(ctx, p.PhysicalStore, control, o, e)
}

// Same protected opening and enrolled exact current capability; this observation
// cannot reserve a slot or authorize a provider request by itself.
func (p Podman) VerifyProviderAccessOpening(ctx context.Context, current model.Manifest, input model.QualificationAccessContext, capability []byte) error {
	if input.FormatVersion != 2 || p.PhysicalStore == nil || p.PhysicalAccess == nil {
		return physicalgate.ErrPrerequisite
	}
	b, err := p.PhysicalBaseline(ctx, current)
	if err != nil || b.ProviderCase == nil {
		return physicalgate.ErrPrerequisite
	}
	enrolled, err := p.PhysicalAccess.Enrollment(ctx, input.PreparationID)
	if err != nil || enrolled.Case != b.StoreCase(current.ServerID) || model.WorkspaceDigest(enrolled.Context) != model.WorkspaceDigest(input) || enrolled.CapabilityDigest != qualification.Digest(capability) {
		return physicalgate.ErrPrerequisite
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	return producer.VerifyPhysicalAccessAuthority(ctx, input, b)
}

func (p Podman) CollectProviderReadback(ctx context.Context, control qualification.ProviderCurrentControl) (json.RawMessage, error) {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return nil, err
	}
	return producer.CollectProviderReadback(ctx, p.PhysicalStore, control)
}
func (p Podman) BindCurrentProviderReservation(ctx context.Context, control qualification.ProviderCurrentControl, permit state.PhysicalPermit) (state.PhysicalPermit, error) {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return permit, err
	}
	return producer.BindCurrentProviderReservation(ctx, p.PhysicalStore, control, permit)
}
