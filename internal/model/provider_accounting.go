package model

import (
	"encoding/json"
	"errors"
)

// Only the authenticated opening GET's exact absence response selects recovery
// of an already retained first contribution. It never grants admission.
var ErrProviderOpeningAbsent = errors.New("provider accounting opening absent")

// Owner-authored accounting2 records. These are not fields in the native RPC.
type ProviderReservation struct {
	ParticipantID              string  `json:"participantId,omitempty"`
	ParticipantInventoryDigest string  `json:"participantInventoryDigest,omitempty"`
	FormatVersion              int     `json:"formatVersion"`
	AccountingVersion          int     `json:"accountingVersion"`
	LedgerID                   string  `json:"ledgerId"`
	ProviderPolicyDigest       string  `json:"providerPolicyDigest"`
	AuthorityDigest            string  `json:"authorityDigest"`
	DemandManifestDigest       string  `json:"demandManifestDigest"`
	OpeningDigest              string  `json:"openingDigest"`
	PhysicalID                 string  `json:"physicalId"`
	AllocationID               string  `json:"allocationId"`
	ReservationID              string  `json:"reservationId"`
	SubjectID                  string  `json:"subjectId"`
	ScopeDigest                string  `json:"scopeDigest"`
	PhysicalIndex              int     `json:"physicalIndex"`
	ModelRequestIndex          *int    `json:"modelRequestIndex"`
	PreparationOrdinal         int     `json:"preparationOrdinal"`
	Kind                       string  `json:"kind"`
	ReservedUsdMicros          int64   `json:"reservedUsdMicros"`
	NativeSessionID            *string `json:"nativeSessionId"`
	NativeInputID              *string `json:"nativeInputId"`
}
type ProviderAccountingPrefix struct {
	ParticipantInventoryDigest string            `json:"participantInventoryDigest,omitempty"`
	FormatVersion              int               `json:"formatVersion"`
	AuthorityDigest            string            `json:"authorityDigest"`
	Opening                    json.RawMessage   `json:"opening"`
	Reservations               []json.RawMessage `json:"reservations"`
	Settlements                []json.RawMessage `json:"settlements"`
	Snapshot                   json.RawMessage   `json:"snapshot"`
}
