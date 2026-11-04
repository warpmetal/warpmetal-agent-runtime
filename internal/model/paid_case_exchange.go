package model

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

const PaidObservationMaximum = 16 * 1024 * 1024
const PaidOriginalMaximum = 262144
const PaidOriginalCountMaximum = 128

type PaidCaseDomainOriginal struct {
	Digest        string `json:"digest"`
	ContentBase64 string `json:"contentBase64"`
}
type PaidCaseDomainObservationRequest struct {
	FormatVersion                   int                      `json:"formatVersion"`
	CompleteInventoryEnvelopeDigest string                   `json:"completeInventoryEnvelopeDigest"`
	DemandManifestDigest            string                   `json:"demandManifestDigest"`
	RuntimeReadback                 json.RawMessage          `json:"runtimeReadback"`
	Originals                       []PaidCaseDomainOriginal `json:"originals"`
}

// Wire/integrity checks only. Transitive ownership and trust are independent.
func (r PaidCaseDomainObservationRequest) Validate() error {
	bad := errors.New("paid domain observation wire refused")
	if len(r.Originals) > PaidOriginalCountMaximum {
		return bad
	}
	seen := map[string]bool{}
	for _, entry := range r.Originals {
		if !PhysicalDigestValid(entry.Digest) || seen[entry.Digest] || len(entry.ContentBase64) > 349528 {
			return bad
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(entry.ContentBase64)
		if err != nil || len(raw) > PaidOriginalMaximum || RawPhysicalDigest(raw) != entry.Digest || base64.StdEncoding.EncodeToString(raw) != entry.ContentBase64 {
			return bad
		}
		seen[entry.Digest] = true
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > PaidObservationMaximum || workflowcontract.ValidatePaidObservation(raw) != nil {
		return bad
	}
	return nil
}
