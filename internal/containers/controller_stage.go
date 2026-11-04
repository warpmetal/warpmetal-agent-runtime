package containers

import (
	"context"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

func (p Podman) ReadControllerDeclaredStage(ctx context.Context, current model.Manifest, parent model.ControllerParentIntent, readout model.ControllerStageReadout) (qualification.ControllerDeclaredInput, error) {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return qualification.ControllerDeclaredInput{}, err
	}
	return producer.ReadControllerDeclaredStage(ctx, current, parent, readout)
}
