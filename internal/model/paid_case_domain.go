package model

import (
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// r47 node-only bootstrap metadata. Neither body admits execution or carries
// paths/counters/trust overrides; signatures/current originals are verified by
// the owning producer independently of transport/schema validity.
type PaidCaseDomainAdoptionRequest struct {
	FormatVersion                   int             `json:"formatVersion"`
	CompleteInventoryEnvelopeDigest string          `json:"completeInventoryEnvelopeDigest"`
	DemandManifestDigest            string          `json:"demandManifestDigest"`
	RuntimeReadback                 json.RawMessage `json:"runtimeReadback"`
}

func (r PaidCaseDomainAdoptionRequest) Validate() error {
	raw, err := json.Marshal(r)
	if err != nil || workflowcontract.Validate(workflowcontract.PaidCaseDomainHandshake, "adoptionRequest", raw) != nil {
		return errors.New("invalid paid domain adoption request")
	}
	return nil
}

type PaidCaseDomainAcceptanceRequest struct {
	FormatVersion int             `json:"formatVersion"`
	Acceptance    json.RawMessage `json:"acceptance"`
}

func (r PaidCaseDomainAcceptanceRequest) Validate() error {
	raw, err := json.Marshal(r)
	if err != nil || workflowcontract.Validate(workflowcontract.PaidCaseDomainHandshake, "acceptanceRequest", raw) != nil {
		return errors.New("invalid paid domain acceptance request")
	}
	return nil
}
