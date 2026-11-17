package boxcredentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
)

const (
	// maxRawEnvelopeBytes bounds one delivered envelope exactly as the platform
	// bounds its canonical form (plus encoding whitespace), before any base64
	// payload is decoded. Nothing larger can be a valid sealed credential.
	maxRawEnvelopeBytes = 128 << 10
	// maxEnvelopeFieldChars matches the platform's per-field base64url ceiling.
	maxEnvelopeFieldChars = 64 << 10
)

var (
	fingerprintPattern  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	credentialIDPattern = regexp.MustCompile(`^conn_[A-Za-z0-9_-]{16,88}$`)
	providerIDPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	boxIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	envelopeIDPattern   = regexp.MustCompile(`^env_[A-Za-z0-9_-]{8,96}$`)
	base64URLPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// requiredEnvelopeFields is the exact envelope key set the platform validates
// before sealing. Any missing or additional field means the item is not a
// canonical tool-provider-credential envelope and must not enter the store.
var requiredEnvelopeFields = []string{
	"formatVersion",
	"algorithm",
	"boxId",
	"keyFingerprint",
	"envelopeId",
	"purpose",
	"wrappedKey",
	"iv",
	"ciphertext",
	"createdAt",
}

type envelope struct {
	FormatVersion  int    `json:"formatVersion"`
	Algorithm      string `json:"algorithm"`
	BoxID          string `json:"boxId"`
	KeyFingerprint string `json:"keyFingerprint"`
	EnvelopeID     string `json:"envelopeId"`
	Purpose        string `json:"purpose"`
	WrappedKey     string `json:"wrappedKey"`
	IV             string `json:"iv"`
	Ciphertext     string `json:"ciphertext"`
	CreatedAt      string `json:"createdAt"`
}

// validateCredential validates one delivered item against this Box's identity
// and current key. It returns the exact wire bytes to persist; it never decodes
// the wrapped key or ciphertext and never includes their values in errors.
func validateCredential(
	delivery control.ToolProviderCredentialDelivery,
	boxID, fingerprint string,
) (storedCredential, error) {
	if !credentialIDPattern.MatchString(delivery.CredentialID) {
		return storedCredential{}, errors.New("credential id is invalid")
	}
	if !providerIDPattern.MatchString(delivery.ProviderID) {
		return storedCredential{}, errors.New("provider id is invalid")
	}
	if delivery.KeyFingerprint != fingerprint || !fingerprintPattern.MatchString(delivery.KeyFingerprint) {
		return storedCredential{}, errors.New("credential is sealed to a different box key")
	}
	if err := validateEnvelopeRaw(delivery.Envelope, boxID, fingerprint); err != nil {
		return storedCredential{}, err
	}
	return storedCredential{
		CredentialID:   delivery.CredentialID,
		ProviderID:     delivery.ProviderID,
		KeyFingerprint: delivery.KeyFingerprint,
		Envelope:       append(json.RawMessage(nil), delivery.Envelope...),
	}, nil
}

// validateStoredCredential re-validates a record read back from the root-only
// envelope file, so a tampered local document cannot re-introduce an envelope
// that no longer belongs to this Box identity.
func validateStoredCredential(record storedCredential, boxID, fingerprint string) error {
	if !credentialIDPattern.MatchString(record.CredentialID) {
		return errors.New("credential id is invalid")
	}
	if !providerIDPattern.MatchString(record.ProviderID) {
		return errors.New("provider id is invalid")
	}
	if record.KeyFingerprint != fingerprint {
		return errors.New("credential is sealed to a different box key")
	}
	return validateEnvelopeRaw(record.Envelope, boxID, fingerprint)
}

func validateEnvelopeRaw(raw json.RawMessage, boxID, fingerprint string) error {
	if len(raw) == 0 || len(raw) > maxRawEnvelopeBytes {
		return errors.New("credential envelope is missing or too large")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return errors.New("credential envelope is not an object")
	}
	if len(fields) != len(requiredEnvelopeFields) {
		return errors.New("credential envelope field set is invalid")
	}
	for _, name := range requiredEnvelopeFields {
		if _, ok := fields[name]; !ok {
			return errors.New("credential envelope field set is invalid")
		}
	}
	var value envelope
	if err := json.Unmarshal(raw, &value); err != nil {
		return errors.New("credential envelope is not canonical")
	}
	if value.FormatVersion != 1 ||
		value.Algorithm != EnvelopeAlgorithm ||
		value.Purpose != Purpose ||
		value.BoxID != boxID ||
		value.KeyFingerprint != fingerprint {
		return errors.New("credential envelope identity does not match this box")
	}
	if !envelopeIDPattern.MatchString(value.EnvelopeID) {
		return errors.New("credential envelope id is invalid")
	}
	iv, err := decodeBase64URL(value.IV)
	if err != nil || len(iv) != 12 {
		return errors.New("credential envelope iv is invalid")
	}
	wrappedKey, err := decodeBase64URL(value.WrappedKey)
	if err != nil || len(wrappedKey) == 0 || len(wrappedKey) > maxEnvelopeFieldChars {
		return errors.New("credential envelope wrapped key is invalid")
	}
	ciphertext, err := decodeBase64URL(value.Ciphertext)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > maxEnvelopeFieldChars {
		return errors.New("credential envelope ciphertext is invalid")
	}
	if !strings.HasSuffix(value.CreatedAt, "Z") {
		return errors.New("credential envelope timestamp is invalid")
	}
	if _, err := time.Parse(time.RFC3339, value.CreatedAt); err != nil {
		return errors.New("credential envelope timestamp is invalid")
	}
	return nil
}

func decodeBase64URL(value string) ([]byte, error) {
	if value == "" || len(value) > maxEnvelopeFieldChars || !base64URLPattern.MatchString(value) {
		return nil, fmt.Errorf("invalid base64url value")
	}
	return base64URL.DecodeString(value)
}
