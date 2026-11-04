// Package providerpolicy reads the immutable, owner-authored provider policy.
// Matching a transport here is not qualification, credentials or execution authority.
package providerpolicy

import (
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
)

const FlashDigest = "sha256:3082b57ec287f3b32451a970104bd0b170c2b5873f9efbe91380bc3b4212281f"

//go:embed deepseek-flash-responses-e2-v2.json
var flashBytes []byte

type Descriptor struct {
	ProviderID string `json:"providerId"`
	ModelID    string `json:"modelId"`
	AuthMode   string `json:"authMode"`
	Access     struct {
		Method          string `json:"method"`
		URL             string `json:"url"`
		ExpectedModelID string `json:"expectedModelId"`
	} `json:"access"`
	Transport struct {
		URL      string `json:"url"`
		Method   string `json:"method"`
		Protocol string `json:"protocol"`
	} `json:"transport"`
	Accounting struct {
		Version                int    `json:"version"`
		LedgerID               string `json:"ledgerId"`
		MaximumExposureMicros  int64  `json:"maximumExposureMicros"`
		PhysicalRequestLimit   int    `json:"physicalRequestLimit"`
		RequestReserveMicros   int64  `json:"requestReserveMicros"`
		InputMicrosPerMillion  int64  `json:"inputMicrosPerMillion"`
		OutputMicrosPerMillion int64  `json:"outputMicrosPerMillion"`
	} `json:"accounting"`
	Request struct {
		InputTokenUpperBound int `json:"inputTokenUpperBound"`
		MaxOutputTokens      int `json:"max_output_tokens"`
		DeadlineSeconds      int `json:"deadlineSeconds"`
	} `json:"request"`
}

func Flash() Descriptor {
	if fmt.Sprintf("sha256:%x", sha256.Sum256(flashBytes)) != FlashDigest {
		panic("embedded provider descriptor pin mismatch")
	}
	var value Descriptor
	if err := json.Unmarshal(flashBytes, &value); err != nil {
		panic("embedded provider descriptor invalid")
	}
	return value
}

func FlashPricingDigest() string {
	p := Flash()
	raw, _ := json.Marshal(map[string]any{"modelId": p.ModelID, "inputMicrosPerMillion": p.Accounting.InputMicrosPerMillion, "cachedInputMicrosPerMillion": p.Accounting.InputMicrosPerMillion, "outputMicrosPerMillion": p.Accounting.OutputMicrosPerMillion})
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
}
