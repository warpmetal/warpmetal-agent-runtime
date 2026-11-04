package containers

import (
	"context"
	"encoding/json"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

func (p Podman) enrollSourceContinuation(ctx context.Context, s qualification.Store, box model.Sandbox, c qualification.RealCase, expected []byte) error {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	authority, envelope, err := producer.CurrentSourceContinuationAuthority(ctx, c)
	if err != nil || len(expected) == 0 {
		return qualification.ErrUntrusted
	}
	var selected struct {
		SourceContinuation json.RawMessage `json:"sourceContinuation"`
	}
	if json.Unmarshal(authority, &selected) != nil || qualification.CanonicalDigest(selected.SourceContinuation) != qualification.CanonicalDigest(json.RawMessage(expected)) {
		return qualification.ErrUntrusted
	}
	return s.EnrollSourceContinuationAuthority(box, c, authority, envelope)
}
