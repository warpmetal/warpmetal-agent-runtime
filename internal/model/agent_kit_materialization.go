package model

// WP-211B: verified in-cell agent-kit materialization audit record.
//
// One record is persisted per materialization identity (the WP-211 `akm_…` id
// derived from the configuration digest and the kit digest). The record holds
// the exact verified supervisor envelope, so a retry can prove idempotency
// without re-running the cell-side materializer and an audit can be replayed
// against the same digests. It grants no authority: no credential, tool, MCP,
// session or first-task effect is implied by it.

import (
	"encoding/json"
	"errors"
	"regexp"
)

var (
	agentKitDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	agentKitIDPattern     = regexp.MustCompile(`^akm_[a-f0-9]{32}$`)
	agentKitSafeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

const (
	AgentKitMaterializationFormatVersion = 1
	// AgentKitMaterializationEnvelopeMaximum is the supervised channel bound
	// (the supervisor wrapper receipt is capped at 64 KiB).
	AgentKitMaterializationEnvelopeMaximum = 64 * 1024
)

// AgentKitMaterialization is the local verified-receipt audit record.
type AgentKitMaterialization struct {
	FormatVersion                int               `json:"formatVersion"`
	MaterializationID            string            `json:"materializationId"`
	ApplicationOperationID       string            `json:"applicationOperationId"`
	SandboxID                    string            `json:"sandboxId"`
	SandboxGeneration            int64             `json:"sandboxGeneration"`
	ConfigurationID              string            `json:"configurationId"`
	ConfigurationRevision        int64             `json:"configurationRevision"`
	ConfigurationDigest          string            `json:"configurationDigest"`
	KitDigest                    string            `json:"kitDigest"`
	AdoptionID                   string            `json:"adoptionId"`
	Venue                        string            `json:"venue"`
	ClosureDigest                string            `json:"closureDigest"`
	EnvelopeDigest               string            `json:"envelopeDigest"`
	MaterializationReceiptDigest string            `json:"materializationReceiptDigest"`
	InstructionDigest            string            `json:"instructionDigest"`
	SkillContentDigests          map[string]string `json:"skillContentDigests"`
	EnvelopeJSON                 json.RawMessage   `json:"-"`
	VerifiedAt                   string            `json:"verifiedAt"`
}

// Validate is a closed re-check of a persisted record before it is stored or
// returned; it never proves cell activity by itself.
func (r AgentKitMaterialization) Validate() error {
	bad := errors.New("invalid agent kit materialization record")
	if r.FormatVersion != AgentKitMaterializationFormatVersion ||
		!agentKitIDPattern.MatchString(r.MaterializationID) ||
		!agentKitSafeIDPattern.MatchString(r.ApplicationOperationID) ||
		!agentKitSafeIDPattern.MatchString(r.SandboxID) ||
		r.SandboxGeneration < 1 ||
		!agentKitSafeIDPattern.MatchString(r.ConfigurationID) ||
		r.ConfigurationRevision < 1 ||
		!agentKitSafeIDPattern.MatchString(r.AdoptionID) ||
		len(r.Venue) == 0 || len(r.Venue) > 64 ||
		r.VerifiedAt == "" {
		return bad
	}
	for _, digest := range []string{
		r.ConfigurationDigest, r.KitDigest, r.ClosureDigest, r.EnvelopeDigest,
		r.MaterializationReceiptDigest, r.InstructionDigest,
	} {
		if !agentKitDigestPattern.MatchString(digest) {
			return bad
		}
	}
	for skillID, digest := range r.SkillContentDigests {
		if !agentKitSafeIDPattern.MatchString(skillID) || !agentKitDigestPattern.MatchString(digest) {
			return bad
		}
	}
	if len(r.EnvelopeJSON) == 0 || len(r.EnvelopeJSON) > AgentKitMaterializationEnvelopeMaximum {
		return bad
	}
	if !json.Valid(r.EnvelopeJSON) {
		return bad
	}
	return nil
}
