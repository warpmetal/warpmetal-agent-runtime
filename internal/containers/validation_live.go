package containers

import (
	"context"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func (p Podman) AcceptValidationLiveReceipt(ctx context.Context, current model.Manifest, input model.QualificationAccessContext, capability, receipt []byte) error {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	return producer.AcceptValidationLiveReceipt(ctx, current, p.PhysicalStore, p.PhysicalAccess, input, capability, receipt)
}

func (p Podman) VerifyValidationLivePhysicalRequest(ctx context.Context, current model.Manifest, caller physicalgate.Caller, request model.PhysicalAdmitRequest, permit state.PhysicalPermit) error {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	return producer.VerifyValidationLivePhysicalRequest(ctx, current, p.PhysicalStore, caller, request, &permit)
}
