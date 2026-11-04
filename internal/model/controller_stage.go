package model

import "encoding/json"

// Node discovery metadata is not execution authority. The exact item must also
// match the independent protected operator declaration before parent preparation.
type ControllerStageReadout struct {
	FormatVersion              int             `json:"formatVersion"`
	ApplicationOperationID     string          `json:"applicationOperationId"`
	ApplicationOperationDigest string          `json:"applicationOperationDigest"`
	ServiceRegistrationID      string          `json:"serviceRegistrationId"`
	ServiceGeneration          int64           `json:"serviceGeneration"`
	CaseID                     string          `json:"caseId"`
	CaseManifestDigest         string          `json:"caseManifestDigest"`
	DemandManifestDigest       string          `json:"demandManifestDigest"`
	AllocationName             string          `json:"allocationName"`
	Item                       json.RawMessage `json:"item"`
	DeclarationItemDigest      string          `json:"declarationItemDigest"`
}
