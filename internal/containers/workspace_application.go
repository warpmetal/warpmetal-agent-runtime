package containers

import (
	"context"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Reuse the SAME registered host root producer; no worker key mount, new signer,
// node registration, operator permit or qualification ledger for metadata.
func (p Podman) AttestWorkspaceApplication(ctx context.Context, readback model.WorkspaceApplicationReadback, witnesses []qualification.WorkspaceApplicationWitness) (model.WorkspaceApplicationEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return model.WorkspaceApplicationEnvelope{}, err
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return model.WorkspaceApplicationEnvelope{}, err
	}
	return producer.AttestWorkspaceApplication(readback, witnesses, time.Now().UTC())
}
