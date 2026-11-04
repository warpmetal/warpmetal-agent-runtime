package providerpolicy

import (
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
)

const ParticipantDigest = "sha256:e3020419b9841fb1e39c9dca0ff262c8761c19438263187c90b86b89976e9657"

//go:embed deepseek-flash-responses-e2-v3.json
var participantBytes []byte

// Select accepts only the two exact immutable descriptors. It never upgrades
// an old case or derives prices/limits from a model response.
func Select(digest string) (Descriptor, bool) {
	if digest == FlashDigest {
		return Flash(), true
	}
	if digest != ParticipantDigest {
		return Descriptor{}, false
	}
	if fmt.Sprintf("sha256:%x", sha256.Sum256(participantBytes)) != ParticipantDigest {
		panic("participant provider descriptor pin mismatch")
	}
	var d Descriptor
	if json.Unmarshal(participantBytes, &d) != nil {
		panic("participant provider descriptor invalid")
	}
	return d, true
}
