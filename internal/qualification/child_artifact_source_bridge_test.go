package qualification

import (
	"encoding/json"
)

// Test-only bridge to the actual artifact scope owner. No signer, UID override,
// authority factory or production export. A not-yet-supported capture member
// cannot satisfy the current predicate; the signed Store remains independently
// selected by that predicate when the corresponding purpose is supported.
func SourceChildIntegrationArtifactAllowedForTest(w ChildWorkflowObservationWitness, q ChildProductPolicy, capture json.RawMessage, path, digest string, count int64) bool {
	wire, err := json.Marshal(map[string]json.RawMessage{"OriginalIntegration": capture})
	if err != nil || json.Unmarshal(wire, &w) != nil {
		return false
	}
	return childResultArtifactAllowed(w, q, path, digest, count)
}
