package model

import (
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"time"
)

// Secret-free independent node context. Not signed authority/enrollment/admission.
type QualificationAccessContext struct {
	FormatVersion        int             `json:"formatVersion"`
	ProviderPolicyDigest string          `json:"providerPolicyDigest,omitempty"`
	AccountingVersion    int             `json:"accountingVersion,omitempty"`
	QualificationID      string          `json:"qualificationId"`
	PreparationID        string          `json:"preparationId"`
	PreparedTupleDigest  string          `json:"preparedTupleDigest"`
	ReservationID        string          `json:"reservationId"`
	TupleDigest          string          `json:"tupleDigest"`
	AuthorityDigest      string          `json:"authorityDigest"`
	DemandManifestDigest string          `json:"demandManifestDigest"`
	Allocation           json.RawMessage `json:"allocation"`
	Accounting           json.RawMessage `json:"accounting"`
	Request              struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"request"`
	ExpiresAt string `json:"expiresAt"`
}

func (c QualificationAccessContext) Validate(id string, now time.Time) error {
	expiry, e := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	expectedURL := "https://api.openai.com/v1/models/gpt-4.1-mini-2025-04-14"
	if c.FormatVersion == 2 {
		raw, _ := json.Marshal(c)
		if workflowcontract.ValidateQualificationAccessProvider(raw) != nil {
			return ErrPhysicalWire
		}
		expectedURL = providerpolicy.Flash().Access.URL
	} else if c.FormatVersion != 1 || c.ProviderPolicyDigest != "" || c.AccountingVersion != 0 {
		return ErrPhysicalWire
	}
	if c.QualificationID != id || !PhysicalIDValid(id) || !PhysicalIDValid(c.PreparationID) || !PhysicalIDValid(c.ReservationID) || !PhysicalDigestValid(c.PreparedTupleDigest) || !PhysicalDigestValid(c.TupleDigest) || !PhysicalDigestValid(c.AuthorityDigest) || !PhysicalDigestValid(c.DemandManifestDigest) || e != nil || !now.Before(expiry) || c.Request.Method != "GET" || c.Request.URL != expectedURL {
		return ErrPhysicalWire
	}
	var allocation, accounting map[string]json.RawMessage
	if DecodePhysicalClosed(c.Allocation, &allocation) != nil || allocation == nil || DecodePhysicalClosed(c.Accounting, &accounting) != nil || accounting == nil {
		return ErrPhysicalWire
	}
	return nil
}
