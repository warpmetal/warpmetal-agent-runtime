package boxcredentials

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// This file implements Phase P2's envelope-opening primitive
// (docs RUNTIME_BOX_CREDENTIAL_BRIDGE.md section 4): fail-closed, in-memory
// opening of one sealed tool-provider credential. It executes no provider tool,
// injects nothing into a process, and neither persists nor logs plaintext.
//
// The wire format implemented here is the one the platform actually seals with:
// worker/account/sealed-credentials.ts (`canonicalJson(metadata)` as AES-GCM
// AAD, canonical JSON payload) consumed by backend
// warpmetal/agent_manager/tool_credentials.py. Two details differ from the plan
// document's prose and follow the shipped implementation instead:
//
//   - AAD field list: the document names `issuedAt` and `expiresAt` too, but
//     those live only inside the encrypted payload and therefore cannot
//     participate in an AAD an opener must assemble before decryption. The
//     sealer authenticates exactly the six envelope metadata fields; the
//     payload's own issuedAt/expiresAt are authenticated by the GCM tag as part
//     of the ciphertext.
//   - Payload bindings: the sealed payload has no `envelopeId` field; it binds
//     accountId/connectionId/providerId and carries `purpose`. The envelopeId is
//     authenticated as AAD metadata, and the delivery's credentialId (the
//     platform connection) is checked against the payload connectionId.

const (
	// aesDataKeyBytes is the only data-key size the platform seals (AES-256).
	aesDataKeyBytes = 32
	// standardNonceBytes is the AES-GCM nonce size the platform seals.
	standardNonceBytes = 12
	// maxCredentialPayloadBytes bounds the decrypted canonical payload exactly
	// as the platform bounds it before sealing.
	maxCredentialPayloadBytes = 16 << 10
	// maxCredentialFieldBytes bounds one secret field value (platform ceiling).
	maxCredentialFieldBytes = 8192
	// credentialIssuedAtSkew tolerates a bounded clock difference between the
	// platform and the Box for the not-yet-valid check, mirroring the rotation
	// contract's skew allowance. Expired credentials get no allowance.
	credentialIssuedAtSkew = 5 * time.Minute
)

// OpenErrorCode is a stable, secret-free failure code. Callers can branch on it
// without parsing text; the accompanying message never contains envelope,
// ciphertext or plaintext values.
type OpenErrorCode string

const (
	// CodeInvalidEnvelope means the sealed envelope is not a canonical
	// tool-provider credential envelope (shape, field set, encoding).
	CodeInvalidEnvelope OpenErrorCode = "invalid_envelope"
	// CodeUnsupportedAlgorithm means the envelope names an algorithm this Box
	// does not support.
	CodeUnsupportedAlgorithm OpenErrorCode = "unsupported_algorithm"
	// CodeBoxMismatch means the envelope is bound to another Box id.
	CodeBoxMismatch OpenErrorCode = "box_mismatch"
	// CodeKeyFingerprintMismatch means the envelope is sealed to another key.
	CodeKeyFingerprintMismatch OpenErrorCode = "key_fingerprint_mismatch"
	// CodeInvalidWrappedKey means the RSA-OAEP data key could not be unwrapped.
	CodeInvalidWrappedKey OpenErrorCode = "invalid_wrapped_key"
	// CodeInvalidTag means AES-GCM authentication failed: the ciphertext or an
	// authenticated metadata field was tampered with, or the envelope was
	// reassembled from mismatched parts.
	CodeInvalidTag OpenErrorCode = "invalid_tag"
	// CodeInvalidPayload means the decrypted payload is not the canonical
	// credential payload object.
	CodeInvalidPayload OpenErrorCode = "invalid_payload"
	// CodePayloadBindingMismatch means an authenticated payload binding
	// (provider, connection or account) does not match the delivery or caller.
	CodePayloadBindingMismatch OpenErrorCode = "payload_binding_mismatch"
	// CodeCredentialExpired means the payload's expiresAt is null-or-future rule
	// is violated.
	CodeCredentialExpired OpenErrorCode = "credential_expired"
	// CodeCredentialNotYetValid means the payload's issuedAt is in the future
	// beyond the allowed clock skew.
	CodeCredentialNotYetValid OpenErrorCode = "credential_not_yet_valid"
	// CodeCredentialNotFound means the bridge has no sealed record for the id.
	CodeCredentialNotFound OpenErrorCode = "credential_not_found"
	// CodeCredentialUnavailable means the bridge or its sealed store is not
	// available (for example the feature is disabled).
	CodeCredentialUnavailable OpenErrorCode = "credential_unavailable"
	// CodeKeyUnavailable means the root-only Box key could not be loaded.
	CodeKeyUnavailable OpenErrorCode = "key_unavailable"
)

var (
	// payloadIdentifierPattern is the platform's identifier grammar for the
	// authenticated payload bindings.
	payloadIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	// payloadTimestampPattern is the platform's timestamp grammar.
	payloadTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$`)
	// credentialFieldNamePattern is the platform's secret field-name grammar.
	credentialFieldNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
)

// requiredPayloadFields is the exact payload key set the platform seals. A
// different set is a hard failure: the opener never uses partial data.
var requiredPayloadFields = []string{
	"formatVersion",
	"purpose",
	"accountId",
	"connectionId",
	"providerId",
	"credential",
	"issuedAt",
	"expiresAt",
}

// requiredCredentialFields is the exact closed shape of the credential material.
var requiredCredentialFields = []string{"kind", "fields"}

// supportedCredentialKinds mirrors the platform's credential material kinds.
var supportedCredentialKinds = map[string]struct{}{
	"api_key":    {},
	"oauth2":     {},
	"github-app": {},
}

// OpenError is the only error type returning from the opening path. Its text is
// a fixed reason from a closed vocabulary: no envelope, ciphertext or plaintext
// value can reach it.
type OpenError struct {
	code   OpenErrorCode
	reason string
}

// Error implements error. The message is stable and secret-free.
func (e *OpenError) Error() string {
	return "boxcredentials: cannot open sealed credential: " + string(e.code) + " (" + e.reason + ")"
}

// Code returns the stable failure code.
func (e *OpenError) Code() OpenErrorCode {
	return e.code
}

// OpenErrorCodeOf extracts the stable failure code from an error returned by
// this package.
func OpenErrorCodeOf(err error) (OpenErrorCode, bool) {
	var openError *OpenError
	if errors.As(err, &openError) {
		return openError.code, true
	}
	return "", false
}

// IsOpenErrorCode reports whether err is an *OpenError with the given code.
func IsOpenErrorCode(err error, code OpenErrorCode) bool {
	found, ok := OpenErrorCodeOf(err)
	return ok && found == code
}

func newOpenError(code OpenErrorCode, reason string) *OpenError {
	return &OpenError{code: code, reason: reason}
}

// SealedCredential is one sealed tool-provider credential envelope exactly as
// delivered by the platform and persisted in the root-only local store. It
// contains ciphertext only; it is safe to keep at rest, never to log.
type SealedCredential struct {
	// CredentialID is the platform credential/connection id the envelope was
	// delivered under.
	CredentialID string
	// ProviderID is the tool provider the credential belongs to.
	ProviderID string
	// KeyFingerprint is the Box key fingerprint the platform sealed to.
	KeyFingerprint string
	// Envelope is the sealed envelope JSON, verbatim as delivered.
	Envelope json.RawMessage
}

// OpenExpectations carries the caller's additional binding expectations. Zero
// value means "use only the bindings the delivery and envelope provide".
type OpenExpectations struct {
	// AccountID, when non-empty, must equal the decrypted payload's accountId.
	// The gateway supplies it when the workspace's owner account is known.
	AccountID string
}

// Credential is one decrypted tool-provider credential held only in memory for
// the duration of a tool execution. Secret fields are never exported: String,
// GoString, fmt verbs and json.Marshal all render metadata only. Callers should
// call Destroy as soon as the credential is no longer needed.
type Credential struct {
	// ProviderID identifies the tool provider (metadata, not secret).
	ProviderID string `json:"providerId"`
	// ConnectionID is the owner account's platform connection id (metadata).
	ConnectionID string `json:"connectionId"`
	// AccountID is the owner account the credential belongs to (metadata).
	AccountID string `json:"accountId"`
	// Kind is the platform credential material kind (metadata).
	Kind string `json:"kind"`
	// IssuedAt is when the platform sealed the credential (metadata).
	IssuedAt time.Time `json:"issuedAt"`

	expiresAt    time.Time
	hasExpiresAt bool
	// fields stores secret values as byte slices so Destroy can zero them.
	fields    map[string][]byte
	destroyed bool
}

// ExpiresAt reports the optional hard expiry from the authenticated payload.
func (c *Credential) ExpiresAt() (time.Time, bool) {
	if c == nil || !c.hasExpiresAt {
		return time.Time{}, false
	}
	return c.expiresAt, true
}

// SecretFields returns a fresh map of field name to secret value. Each call
// allocates new strings, so a caller may mutate the returned map without
// affecting the credential or any other caller.
func (c *Credential) SecretFields() map[string]string {
	if c == nil || c.destroyed || len(c.fields) == 0 {
		return map[string]string{}
	}
	fields := make(map[string]string, len(c.fields))
	for name, value := range c.fields {
		fields[name] = string(value)
	}
	return fields
}

// Destroy best-effort zeroizes the stored secret values and forgets them.
// Go strings are immutable and the garbage collector may have copied data
// elsewhere, so this reduces but cannot eliminate residual copies in memory.
// It is idempotent.
func (c *Credential) Destroy() {
	if c == nil || c.destroyed {
		return
	}
	for name, value := range c.fields {
		zeroBytes(value)
		delete(c.fields, name)
	}
	c.fields = nil
	c.destroyed = true
}

// CredentialKind reports the non-secret credential material kind (for example
// "oauth2"). It is metadata only and is safe to log, render or hand to an
// external provider executor. It is the method form of the public Kind field.
func (c *Credential) CredentialKind() string {
	if c == nil {
		return ""
	}
	return c.Kind
}

// String renders metadata only. It never includes a secret value or field name.
func (c Credential) String() string {
	expiresAt := "none"
	if c.hasExpiresAt {
		expiresAt = c.expiresAt.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf(
		"boxcredentials.Credential{providerId=%s connectionId=%s accountId=%s kind=%s issuedAt=%s expiresAt=%s secretFields=%d destroyed=%t}",
		c.ProviderID, c.ConnectionID, c.AccountID, c.Kind,
		c.IssuedAt.UTC().Format(time.RFC3339), expiresAt, len(c.fields), c.destroyed,
	)
}

// GoString renders metadata only, for %#v.
func (c Credential) GoString() string {
	return c.String()
}

// Format implements fmt.Formatter so every verb renders metadata only. Without
// it, a verb that does not consult fmt.Stringer (for example %d) would make fmt
// reflect into the unexported secret fields.
func (c Credential) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(c.String()))
}

// OpenEnvelope opens one sealed tool-provider credential for this Box and
// returns a short-lived in-memory Credential. It verifies every binding and
// authenticity property before trusting any plaintext:
//
//   - envelope shape, formatVersion 1, algorithm, purpose and canonical encoding;
//   - boxId equals this Box's identity and keyFingerprint equals the current key;
//   - RSA-OAEP-SHA256 unwrap of the AES-256-GCM data key;
//   - AES-GCM open with the platform's canonical metadata AAD;
//   - exact payload object: provider/connection bindings equal the delivery,
//     optional caller account binding, expiresAt null-or-future and issuedAt
//     not in the future beyond the allowed skew.
//
// Any failure returns an *OpenError with a stable OpenErrorCode and no secret
// value in its text. The same envelope may be opened repeatedly; every call
// returns an independent Credential and independent secret copies.
func OpenEnvelope(key *Key, boxID string, sealed SealedCredential, expectations OpenExpectations) (*Credential, error) {
	return openEnvelopeAt(key, boxID, sealed, expectations, time.Now().UTC())
}

func openEnvelopeAt(
	key *Key,
	boxID string,
	sealed SealedCredential,
	expectations OpenExpectations,
	now time.Time,
) (*Credential, error) {
	if key == nil {
		return nil, newOpenError(CodeKeyUnavailable, "box encryption key is unavailable")
	}
	if !boxIDPattern.MatchString(boxID) {
		return nil, newOpenError(CodeBoxMismatch, "local box identity is invalid")
	}
	if !credentialIDPattern.MatchString(sealed.CredentialID) {
		return nil, newOpenError(CodeInvalidEnvelope, "delivery credential id is invalid")
	}
	if !providerIDPattern.MatchString(sealed.ProviderID) {
		return nil, newOpenError(CodeInvalidEnvelope, "delivery provider id is invalid")
	}
	if !fingerprintPattern.MatchString(sealed.KeyFingerprint) {
		return nil, newOpenError(CodeInvalidEnvelope, "delivery key fingerprint is invalid")
	}
	if sealed.KeyFingerprint != key.Fingerprint() {
		return nil, newOpenError(CodeKeyFingerprintMismatch, "delivery is sealed to a different box key")
	}
	decoded, openError := decodeSealedEnvelope(sealed.Envelope, boxID, key.Fingerprint())
	if openError != nil {
		return nil, openError
	}
	// The wrapped key and ciphertext are not plaintext, but they are the only
	// attacker-controllable intermediates; clear them once no longer needed.
	defer zeroBytes(decoded.wrappedKey)
	defer zeroBytes(decoded.ciphertext)

	aad, err := canonicalEnvelopeAAD(decoded.metadata)
	if err != nil {
		return nil, newOpenError(CodeInvalidEnvelope, "envelope metadata cannot be canonicalized")
	}
	dataKey, err := key.openDataKey(decoded.wrappedKey)
	if err != nil {
		return nil, newOpenError(CodeInvalidWrappedKey, "envelope data key cannot be unwrapped")
	}
	defer zeroBytes(dataKey)
	if len(dataKey) != aesDataKeyBytes {
		return nil, newOpenError(CodeInvalidWrappedKey, "envelope data key has an unsupported length")
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, newOpenError(CodeInvalidWrappedKey, "envelope data key is invalid")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, newOpenError(CodeInvalidEnvelope, "envelope nonce size is unsupported")
	}
	plaintext, err := gcm.Open(nil, decoded.iv, decoded.ciphertext, aad)
	if err != nil {
		return nil, newOpenError(CodeInvalidTag, "envelope ciphertext authentication failed")
	}
	defer zeroBytes(plaintext)
	payload, openError := decodeCredentialPayload(plaintext)
	if openError != nil {
		return nil, openError
	}
	if payload.providerID != sealed.ProviderID {
		return nil, newOpenError(CodePayloadBindingMismatch, "payload provider does not match the delivery")
	}
	if payload.connectionID != sealed.CredentialID {
		return nil, newOpenError(CodePayloadBindingMismatch, "payload connection does not match the delivery")
	}
	if expectations.AccountID != "" && payload.accountID != expectations.AccountID {
		return nil, newOpenError(CodePayloadBindingMismatch, "payload account does not match the expected account")
	}
	if payload.expiresAt != nil && !payload.expiresAt.After(now) {
		return nil, newOpenError(CodeCredentialExpired, "credential has expired")
	}
	if payload.issuedAt.After(now.Add(credentialIssuedAtSkew)) {
		return nil, newOpenError(CodeCredentialNotYetValid, "credential was issued in the future")
	}
	return buildCredential(payload), nil
}

// OpenCredential opens the sealed credential with the given platform
// credential/connection id that the bridge has already pulled and stashed in
// its root-only store. It reloads only the persisted key and ciphertext; no
// plaintext is stored and none is produced unless every check passes.
func (m *Manager) OpenCredential(credentialID string, expectations OpenExpectations) (*Credential, error) {
	if m == nil || !m.enabled || m.keyStore == nil || m.credentials == nil {
		return nil, newOpenError(CodeCredentialUnavailable, "box credential bridge is disabled")
	}
	if !credentialIDPattern.MatchString(credentialID) {
		return nil, newOpenError(CodeCredentialNotFound, "credential id is invalid")
	}
	key, err := m.keyStore.load()
	if err != nil {
		return nil, newOpenError(CodeKeyUnavailable, "box encryption key is unavailable")
	}
	stored, _, err := m.credentials.load(m.boxID, key.Fingerprint())
	if err != nil {
		return nil, newOpenError(CodeCredentialUnavailable, "sealed credential store is unavailable")
	}
	record, ok := stored[credentialID]
	if !ok {
		return nil, newOpenError(CodeCredentialNotFound, "no sealed credential for this box connection")
	}
	return OpenEnvelope(key, m.boxID, record.sealed(), expectations)
}

// sealed converts a validated store record into the public opening input.
func (c storedCredential) sealed() SealedCredential {
	return SealedCredential{
		CredentialID:   c.CredentialID,
		ProviderID:     c.ProviderID,
		KeyFingerprint: c.KeyFingerprint,
		Envelope:       append(json.RawMessage(nil), c.Envelope...),
	}
}

// decodedEnvelope is a shape-validated envelope plus its decoded binary fields.
type decodedEnvelope struct {
	metadata   envelope
	wrappedKey []byte
	iv         []byte
	ciphertext []byte
}

// decodeSealedEnvelope validates the envelope exactly as the platform defines
// it and returns the decoded pieces the opener needs. Identity mismatches get
// their specific stable code before any decryption is attempted.
func decodeSealedEnvelope(raw json.RawMessage, boxID, fingerprint string) (decodedEnvelope, *OpenError) {
	if len(raw) == 0 || len(raw) > maxRawEnvelopeBytes {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope is missing or too large")
	}
	entries, err := decodeJSONObjectEntries(raw)
	if err != nil {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope is not an object")
	}
	if _, err := exactJSONObject(entries, requiredEnvelopeFields); err != nil {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope field set is invalid")
	}
	var value envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope is not canonical")
	}
	if value.FormatVersion != 1 {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope format version is unsupported")
	}
	if value.Algorithm != EnvelopeAlgorithm {
		return decodedEnvelope{}, newOpenError(CodeUnsupportedAlgorithm, "envelope algorithm is unsupported")
	}
	if value.Purpose != Purpose {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope purpose does not match")
	}
	if value.BoxID != boxID {
		return decodedEnvelope{}, newOpenError(CodeBoxMismatch, "envelope is bound to a different box")
	}
	if value.KeyFingerprint != fingerprint || !fingerprintPattern.MatchString(value.KeyFingerprint) {
		return decodedEnvelope{}, newOpenError(CodeKeyFingerprintMismatch, "envelope is sealed to a different box key")
	}
	if !envelopeIDPattern.MatchString(value.EnvelopeID) {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope id is invalid")
	}
	iv, err := decodeBase64URL(value.IV)
	if err != nil || len(iv) != standardNonceBytes {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope iv is invalid")
	}
	wrappedKey, err := decodeBase64URL(value.WrappedKey)
	if err != nil || len(wrappedKey) == 0 {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope wrapped key is invalid")
	}
	ciphertext, err := decodeBase64URL(value.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope ciphertext is invalid")
	}
	// Defense in depth: the exact P1 canonical validation still has to accept
	// the envelope, so this phase cannot drift into accepting something the
	// pull path would have rejected.
	if err := validateEnvelopeRaw(raw, boxID, fingerprint); err != nil {
		return decodedEnvelope{}, newOpenError(CodeInvalidEnvelope, "envelope is not canonical")
	}
	return decodedEnvelope{
		metadata:   value,
		wrappedKey: wrappedKey,
		iv:         iv,
		ciphertext: ciphertext,
	}, nil
}

// canonicalEnvelopeAAD builds the AES-GCM additional authenticated data exactly
// as the platform seals it: canonical JSON of the envelope metadata (sorted
// keys, no whitespace, no HTML escaping). Only envelope-visible metadata can
// participate because the opener must build the AAD before it can decrypt.
func canonicalEnvelopeAAD(metadata envelope) ([]byte, error) {
	value := map[string]any{
		"algorithm":      metadata.Algorithm,
		"boxId":          metadata.BoxID,
		"envelopeId":     metadata.EnvelopeID,
		"formatVersion":  metadata.FormatVersion,
		"keyFingerprint": metadata.KeyFingerprint,
		"purpose":        metadata.Purpose,
	}
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

// decodedPayload is the validated authenticated payload.
type decodedPayload struct {
	formatVersion int
	purpose       string
	accountID     string
	connectionID  string
	providerID    string
	kind          string
	fields        map[string]string
	issuedAt      time.Time
	expiresAt     *time.Time
}

// decodeCredentialPayload parses the decrypted plaintext as the exact canonical
// credential payload object. It never returns partial data.
func decodeCredentialPayload(plaintext []byte) (*decodedPayload, *OpenError) {
	if len(plaintext) == 0 || len(plaintext) > maxCredentialPayloadBytes {
		return nil, newOpenError(CodeInvalidPayload, "payload size is invalid")
	}
	entries, err := decodeJSONObjectEntries(plaintext)
	if err != nil {
		return nil, newOpenError(CodeInvalidPayload, "payload is not an object")
	}
	object, err := exactJSONObject(entries, requiredPayloadFields)
	if err != nil {
		return nil, newOpenError(CodeInvalidPayload, "payload field set is invalid")
	}
	formatVersion, err := decodeJSONInteger(object["formatVersion"])
	if err != nil || formatVersion != 1 {
		return nil, newOpenError(CodeInvalidPayload, "payload format version is unsupported")
	}
	purpose, err := decodeJSONString(object["purpose"])
	if err != nil || purpose != Purpose {
		return nil, newOpenError(CodeInvalidPayload, "payload purpose does not match")
	}
	accountID, err := decodePayloadIdentifier(object["accountId"])
	if err != nil {
		return nil, newOpenError(CodeInvalidPayload, "payload account id is invalid")
	}
	connectionID, err := decodePayloadIdentifier(object["connectionId"])
	if err != nil {
		return nil, newOpenError(CodeInvalidPayload, "payload connection id is invalid")
	}
	providerID, err := decodePayloadIdentifier(object["providerId"])
	if err != nil || !providerIDPattern.MatchString(providerID) {
		return nil, newOpenError(CodeInvalidPayload, "payload provider id is invalid")
	}
	kind, fields, err := decodeCredentialMaterial(object["credential"])
	if err != nil {
		return nil, newOpenError(CodeInvalidPayload, "payload credential material is invalid")
	}
	issuedAt, err := decodePayloadTimestamp(object["issuedAt"])
	if err != nil {
		return nil, newOpenError(CodeInvalidPayload, "payload issuedAt is invalid")
	}
	expiresAt, err := decodeNullablePayloadTimestamp(object["expiresAt"])
	if err != nil {
		return nil, newOpenError(CodeInvalidPayload, "payload expiresAt is invalid")
	}
	return &decodedPayload{
		formatVersion: formatVersion,
		purpose:       purpose,
		accountID:     accountID,
		connectionID:  connectionID,
		providerID:    providerID,
		kind:          kind,
		fields:        fields,
		issuedAt:      issuedAt,
		expiresAt:     expiresAt,
	}, nil
}

// decodeCredentialMaterial validates the closed credential object.
func decodeCredentialMaterial(raw json.RawMessage) (string, map[string]string, error) {
	entries, err := decodeJSONObjectEntries(raw)
	if err != nil {
		return "", nil, err
	}
	object, err := exactJSONObject(entries, requiredCredentialFields)
	if err != nil {
		return "", nil, err
	}
	kind, err := decodeJSONString(object["kind"])
	if err != nil {
		return "", nil, errors.New("credential kind is invalid")
	}
	if _, ok := supportedCredentialKinds[kind]; !ok {
		return "", nil, errors.New("credential kind is unsupported")
	}
	fields, err := decodeCredentialFields(object["fields"])
	if err != nil {
		return "", nil, err
	}
	return kind, fields, nil
}

// decodeCredentialFields validates the secret field map without ever putting a
// value into an error.
func decodeCredentialFields(raw json.RawMessage) (map[string]string, error) {
	entries, err := decodeJSONObjectEntries(raw)
	if err != nil || len(entries) == 0 {
		return nil, errors.New("credential fields are invalid")
	}
	fields := make(map[string]string, len(entries))
	for _, entry := range entries {
		if !credentialFieldNamePattern.MatchString(entry.name) {
			return nil, errors.New("credential field name is invalid")
		}
		value, err := decodeJSONString(entry.value)
		if err != nil || value == "" || utf16CodeUnits(value) > maxCredentialFieldBytes {
			return nil, errors.New("credential field value is invalid")
		}
		fields[entry.name] = value
	}
	return fields, nil
}

// buildCredential copies the validated secret fields into byte storage so
// Destroy can zero them, then drops the intermediate parsed values.
func buildCredential(payload *decodedPayload) *Credential {
	credential := &Credential{
		ProviderID:   payload.providerID,
		ConnectionID: payload.connectionID,
		AccountID:    payload.accountID,
		Kind:         payload.kind,
		IssuedAt:     payload.issuedAt,
		fields:       make(map[string][]byte, len(payload.fields)),
	}
	if payload.expiresAt != nil {
		credential.expiresAt = *payload.expiresAt
		credential.hasExpiresAt = true
	}
	for name, value := range payload.fields {
		credential.fields[name] = []byte(value)
		// Drop the parser's immutable string reference as early as possible;
		// Go cannot zero string bytes, so this is best effort only.
		payload.fields[name] = ""
	}
	payload.fields = nil
	return credential
}

// rawObjectEntry is one decoded JSON object member.
type rawObjectEntry struct {
	name  string
	value json.RawMessage
}

// decodeJSONObjectEntries decodes a JSON object into its ordered members,
// rejecting duplicate keys and trailing data. The token-level decoder is used
// because encoding/json silently keeps the last duplicate key.
func decodeJSONObjectEntries(data []byte) ([]rawObjectEntry, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("value is not a JSON object")
	}
	entries := make([]rawObjectEntry, 0, 8)
	seen := make(map[string]struct{}, 8)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, errors.New("object contains a duplicate key")
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		entries = append(entries, rawObjectEntry{name: name, value: value})
	}
	token, err = decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return nil, errors.New("object is not closed")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after object")
	}
	return entries, nil
}

// exactJSONObject returns the member map and requires exactly the given names.
func exactJSONObject(entries []rawObjectEntry, required []string) (map[string]json.RawMessage, error) {
	if len(entries) != len(required) {
		return nil, errors.New("object field set is invalid")
	}
	object := make(map[string]json.RawMessage, len(entries))
	for _, entry := range entries {
		object[entry.name] = entry.value
	}
	for _, name := range required {
		if _, ok := object[name]; !ok {
			return nil, errors.New("object field set is invalid")
		}
	}
	return object, nil
}

func decodeJSONString(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", errors.New("value is not a string")
	}
	return value, nil
}

func decodeJSONInteger(raw json.RawMessage) (int, error) {
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, errors.New("value is not an integer")
	}
	return value, nil
}

func decodePayloadIdentifier(raw json.RawMessage) (string, error) {
	value, err := decodeJSONString(raw)
	if err != nil || !payloadIdentifierPattern.MatchString(value) {
		return "", errors.New("identifier is invalid")
	}
	return value, nil
}

func decodePayloadTimestamp(raw json.RawMessage) (time.Time, error) {
	value, err := decodeJSONString(raw)
	if err != nil || !payloadTimestampPattern.MatchString(value) {
		return time.Time{}, errors.New("timestamp is invalid")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, errors.New("timestamp is invalid")
	}
	return parsed.UTC(), nil
}

func decodeNullablePayloadTimestamp(raw json.RawMessage) (*time.Time, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	value, err := decodePayloadTimestamp(raw)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// utf16CodeUnits matches JavaScript string length, the platform's field-size
// unit, so an interoperable payload is not refused for a byte-length difference.
func utf16CodeUnits(value string) int {
	units := 0
	for _, character := range value {
		if character > 0xFFFF {
			units += 2
			continue
		}
		units++
	}
	return units
}

// zeroBytes overwrites a mutable byte slice in place. Go's garbage collector
// and immutable strings mean this is best-effort, not a guarantee: the compiler
// may have copied buffers, and aes.NewCipher's expanded key schedule cannot be
// addressed. It is still worth doing for the raw data key, ciphertext and
// decrypted payload buffers this package owns.
func zeroBytes(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
}
