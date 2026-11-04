package containers

import (
	"context"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

func (p Podman) AttestWorkflowRole(ctx context.Context, op model.WorkflowRoleOperation, w qualification.WorkspaceApplicationWitness, registered model.WorkspaceRegisteredProducer) (model.WorkflowRoleEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return model.WorkflowRoleEnvelope{}, err
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return model.WorkflowRoleEnvelope{}, err
	}
	return producer.AttestWorkflowRole(op, w, registered, time.Now().UTC())
}
