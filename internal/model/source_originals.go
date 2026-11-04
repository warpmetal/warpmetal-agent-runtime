package model

import "encoding/json"

// Additive private SOURCE originals; neither these references nor their
// signatures are admission, financial retention or terminal release authority.
type SourceRegisteredProcess struct {
	SandboxID            string `json:"sandboxId"`
	SandboxGeneration    int64  `json:"sandboxGeneration"`
	NativeInstance       string `json:"nativeInstance"`
	NativeIdentityDigest string `json:"nativeIdentityDigest"`
	RegistrationDigest   string `json:"registrationDigest"`
}
type SourceProcessObservationRequest struct {
	FormatVersion      int             `json:"formatVersion"`
	Observation        json.RawMessage `json:"observation"`
	RegistrationBase64 string          `json:"registrationBase64"`
}
type SourceCurrentControlResponse struct {
	Observation   json.RawMessage `json:"observation"`
	ControlBase64 string          `json:"controlBase64"`
}
type SourceControlOriginal struct {
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	OperationID           string `json:"operationId"`
	DesiredRevision       int64  `json:"desiredRevision"`
	ActionRevision        int64  `json:"actionRevision"`
	ControlRevision       int64  `json:"controlRevision"`
	ConfigDigest          string `json:"configDigest"`
	DesiredState          string `json:"desiredState"`
}
type SourceCurrentControl struct {
	SourceControlOriginal
	ControlDigest string `json:"controlDigest"`
	ObservedAt    string `json:"observedAt"`
	ExpiresAt     string `json:"expiresAt"`
}
type SourceRegisteredProcessObservation struct {
	FormatVersion            int                     `json:"formatVersion"`
	Purpose                  string                  `json:"purpose"`
	Scope                    ControllerOwner         `json:"scope"`
	CandidateInventoryDigest string                  `json:"candidateInventoryDigest"`
	TargetKind               string                  `json:"targetKind"`
	PreparationID            string                  `json:"preparationId"`
	RegisteredProcess        SourceRegisteredProcess `json:"registeredProcess"`
	ObservedAt               string                  `json:"observedAt"`
	ExpiresAt                string                  `json:"expiresAt"`
}
type SourceCurrentControlObservation struct {
	FormatVersion            int                     `json:"formatVersion"`
	Purpose                  string                  `json:"purpose"`
	Scope                    ControllerOwner         `json:"scope"`
	CandidateInventoryDigest string                  `json:"candidateInventoryDigest"`
	TargetKind               string                  `json:"targetKind"`
	PreparationID            string                  `json:"preparationId"`
	RegisteredProcess        SourceRegisteredProcess `json:"registeredProcess"`
	CurrentControl           SourceCurrentControl    `json:"currentControl"`
}
