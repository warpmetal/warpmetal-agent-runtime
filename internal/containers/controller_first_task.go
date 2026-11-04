package containers

import (
	"context"
	"encoding/json"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

func (p Podman) ReadControllerFirstTaskApplicability(ctx context.Context, current model.Manifest, w qualification.ControllerPolicyWitness) (qualification.Applicability, error) {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return qualification.Applicability{}, err
	}
	app, err := producer.ReadControllerFirstTaskApplicability(ctx, current, w)
	if err != nil {
		return qualification.Applicability{}, err
	}
	if err = p.verifyQualificationMounts(ctx, app.SandboxID); err != nil {
		return qualification.Applicability{}, err
	}
	if err = p.verifyQualificationImage(ctx, app.SandboxID, app.Sandbox.ConfigDigest); err != nil {
		return qualification.Applicability{}, err
	}
	return app, nil
}

func (p Podman) ReadControllerInitialDecision(ctx context.Context, current model.Manifest, parent model.ControllerParentIntent, adviceContext model.ControllerApprovedInputContext, advice json.RawMessage) (qualification.ControllerDeclaredInput, error) {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return qualification.ControllerDeclaredInput{}, err
	}
	return producer.ReadControllerInitialDecision(ctx, current, parent, adviceContext, advice)
}
