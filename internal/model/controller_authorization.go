package model

type ControllerAuthorizationObservation struct {
	FormatVersion         int    `json:"formatVersion"`
	TargetKind            string `json:"targetKind"`
	PreparationID         string `json:"preparationId"`
	PreparedReceiptDigest string `json:"preparedReceiptDigest"`
	AuthorizationSHA256   string `json:"authorizationSha256"`
}
type ControllerAuthorizationEnvelope struct {
	Payload   ControllerAuthorizationObservation `json:"payload"`
	KeyID     string                             `json:"keyId"`
	Signature string                             `json:"signature"`
}
