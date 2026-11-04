package qualification

import (
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Initial private adoption history, not an installed:true flag/current grant.
// No credentials, original reviewer source bytes or private read receipts cross
// into this record. Its complete generation was validated before publication.
type ChildProductNativeRecord struct {
	FormatVersion      int                   `json:"formatVersion"`
	GenerationDigest   string                `json:"generationDigest"`
	Entry              model.CellServiceV3   `json:"entry"`
	Applicability      Applicability         `json:"applicability"`
	Qualification      ChildQualificationPin `json:"qualification"`
	Root               ChildRootScope        `json:"root"`
	AuthorizedUntil    string                `json:"authorizedUntil"`
	SourceContinuation json.RawMessage       `json:"sourceContinuation,omitempty"`
}
