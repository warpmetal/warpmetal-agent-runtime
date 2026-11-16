package boxcredentials

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
)

const (
	openTestEnvelopeID = "env_openTestEnvelope01"
	openTestAccountID  = "acct_open_test_0001"
	openTestSecret     = "ghp_open_test_secret_value"
	openTestIssuedAt   = "2026-11-16T00:00:00.000Z"
	openTestCreatedAt  = "2026-11-16T00:00:00Z"
)

var (
	openTestKeyOnce sync.Once
	openTestKey     *Key
	openTestKeyErr  error
)

// openTestBoxKey returns one shared 3072-bit fake Box key so the opening tests
// pay for RSA generation once instead of once per test.
func openTestBoxKey(t *testing.T) *Key {
	t.Helper()
	openTestKeyOnce.Do(func() {
		openTestKey, openTestKeyErr = generateKey(minimumKeyBits)
	})
	if openTestKeyErr != nil {
		t.Fatalf("generate test box key: %v", openTestKeyErr)
	}
	return openTestKey
}

// canonicalTestJSON renders deterministic JSON exactly like the platform's
// canonicalJson: map keys sorted at every depth, no whitespace, no HTML
// escaping. Test envelopes must be sealed with the platform's canonical form or
// the assertions do not mean anything.
func canonicalTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatalf("encode canonical test JSON: %v", err)
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
}

func validOpenTestPayload() map[string]any {
	return map[string]any{
		"formatVersion": 1,
		"purpose":       Purpose,
		"accountId":     openTestAccountID,
		"connectionId":  testCredID,
		"providerId":    "github",
		"credential": map[string]any{
			"kind":   "api_key",
			"fields": map[string]any{"token": openTestSecret},
		},
		"issuedAt":  openTestIssuedAt,
		"expiresAt": nil,
	}
}

// sealTestEnvelope seals plaintext to public exactly the way
// worker/account/sealed-credentials.ts does: a fresh AES-256-GCM data key,
// canonical envelope-metadata AAD, and RSA-OAEP-SHA256 key wrapping.
func sealTestEnvelope(
	t *testing.T,
	public *rsa.PublicKey,
	boxID, fingerprint, envelopeID string,
	plaintext []byte,
) json.RawMessage {
	t.Helper()
	dataKey := make([]byte, aesDataKeyBytes)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatalf("generate test data key: %v", err)
	}
	defer zeroBytes(dataKey)
	iv := make([]byte, standardNonceBytes)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("generate test iv: %v", err)
	}
	metadata := map[string]any{
		"algorithm":      EnvelopeAlgorithm,
		"boxId":          boxID,
		"envelopeId":     envelopeID,
		"formatVersion":  1,
		"keyFingerprint": fingerprint,
		"purpose":        Purpose,
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		t.Fatalf("create test aes cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("create test gcm: %v", err)
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, canonicalTestJSON(t, metadata))
	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, dataKey, nil)
	if err != nil {
		t.Fatalf("wrap test data key: %v", err)
	}
	return canonicalTestJSON(t, map[string]any{
		"formatVersion":  1,
		"algorithm":      EnvelopeAlgorithm,
		"boxId":          boxID,
		"keyFingerprint": fingerprint,
		"envelopeId":     envelopeID,
		"purpose":        Purpose,
		"wrappedKey":     base64URL.EncodeToString(wrappedKey),
		"iv":             base64URL.EncodeToString(iv),
		"ciphertext":     base64URL.EncodeToString(ciphertext),
		"createdAt":      openTestCreatedAt,
	})
}

// sealedOpenTestCredential is one valid delivery sealed to key.
func sealedOpenTestCredential(t *testing.T, key *Key) SealedCredential {
	t.Helper()
	return sealedOpenTestCredentialWithPayload(t, key, validOpenTestPayload())
}

func sealedOpenTestCredentialWithPayload(t *testing.T, key *Key, payload map[string]any) SealedCredential {
	t.Helper()
	return sealedOpenTestCredentialWithPlaintext(t, key, canonicalTestJSON(t, payload))
}

func sealedOpenTestCredentialWithPlaintext(t *testing.T, key *Key, plaintext []byte) SealedCredential {
	t.Helper()
	fingerprint := key.Fingerprint()
	return SealedCredential{
		CredentialID:   testCredID,
		ProviderID:     "github",
		KeyFingerprint: fingerprint,
		Envelope: sealTestEnvelope(
			t, &key.private.PublicKey, testBoxID, fingerprint, openTestEnvelopeID, plaintext,
		),
	}
}

// editEnvelope decodes the envelope JSON, applies edit and re-encodes it. The
// re-encoding is canonical, which is fine: the opener reads values, not bytes.
func editEnvelope(t *testing.T, sealed SealedCredential, edit func(map[string]any)) SealedCredential {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(sealed.Envelope, &object); err != nil {
		t.Fatalf("decode test envelope: %v", err)
	}
	edit(object)
	sealed.Envelope = canonicalTestJSON(t, object)
	return sealed
}

func envelopeString(t *testing.T, sealed SealedCredential, name string) string {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(sealed.Envelope, &object); err != nil {
		t.Fatalf("decode test envelope: %v", err)
	}
	value, _ := object[name].(string)
	return value
}

func decodeTestBase64URL(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64URL.DecodeString(value)
	if err != nil {
		t.Fatalf("decode test base64url value: %v", err)
	}
	return decoded
}

func TestCanonicalEnvelopeAADMatchesPlatformCanonicalization(t *testing.T) {
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	aad, err := canonicalEnvelopeAAD(envelope{
		FormatVersion:  1,
		Algorithm:      EnvelopeAlgorithm,
		BoxID:          testBoxID,
		KeyFingerprint: fingerprint,
		EnvelopeID:     openTestEnvelopeID,
		Purpose:        Purpose,
	})
	if err != nil {
		t.Fatalf("canonicalEnvelopeAAD() error = %v", err)
	}
	expected := `{"algorithm":"RSA-OAEP-256+A256GCM","boxId":"` + testBoxID +
		`","envelopeId":"` + openTestEnvelopeID + `","formatVersion":1,"keyFingerprint":"` +
		fingerprint + `","purpose":"tool-provider-credential"}`
	if string(aad) != expected {
		t.Fatalf("AAD mismatch:\n got: %s\nwant: %s", aad, expected)
	}
	if bytes.ContainsAny(aad, " \t\n\r") {
		t.Fatalf("AAD contains whitespace: %q", aad)
	}
}

func TestOpenEnvelopeReturnsBoundCredential(t *testing.T) {
	key := openTestBoxKey(t)
	payload := validOpenTestPayload()
	payload["expiresAt"] = "2099-01-01T00:00:00.000Z"
	sealed := sealedOpenTestCredentialWithPayload(t, key, payload)

	credential, err := OpenEnvelope(key, testBoxID, sealed, OpenExpectations{AccountID: openTestAccountID})
	if err != nil {
		t.Fatalf("OpenEnvelope() error = %v", err)
	}
	if credential.ProviderID != "github" || credential.ConnectionID != testCredID || credential.AccountID != openTestAccountID {
		t.Fatalf("credential metadata = %s, want payload bindings", credential)
	}
	if credential.Kind != "api_key" {
		t.Fatalf("credential kind = %q, want api_key", credential.Kind)
	}
	if credential.IssuedAt.UTC().Format(time.RFC3339) != "2026-11-16T00:00:00Z" {
		t.Fatalf("credential issuedAt = %s", credential.IssuedAt)
	}
	expiresAt, hasExpiry := credential.ExpiresAt()
	if !hasExpiry || expiresAt.UTC().Format(time.RFC3339) != "2099-01-01T00:00:00Z" {
		t.Fatalf("credential expiresAt = (%s, %t), want 2099-01-01", expiresAt, hasExpiry)
	}
	fields := credential.SecretFields()
	if len(fields) != 1 || fields["token"] != openTestSecret {
		t.Fatalf("secret fields = %d field(s), want the sealed token", len(fields))
	}
	if rendered := fmt.Sprintf("%v", credential); strings.Contains(rendered, openTestSecret) {
		t.Fatalf("credential rendering leaked the secret: %s", rendered)
	}
	credential.Destroy()
}

func TestOpenEnvelopeEnforcesValidityWindow(t *testing.T) {
	key := openTestBoxKey(t)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	timestamp := func(moment time.Time) string { return moment.UTC().Format(time.RFC3339) }

	payload := validOpenTestPayload()
	payload["issuedAt"] = timestamp(now.Add(-time.Minute))
	payload["expiresAt"] = timestamp(now.Add(time.Hour))
	sealed := sealedOpenTestCredentialWithPayload(t, key, payload)
	if _, err := openEnvelopeAt(key, testBoxID, sealed, OpenExpectations{}, now); err != nil {
		t.Fatalf("open inside validity window error = %v", err)
	}

	payload["expiresAt"] = timestamp(now)
	sealed = sealedOpenTestCredentialWithPayload(t, key, payload)
	if _, err := openEnvelopeAt(key, testBoxID, sealed, OpenExpectations{}, now); !IsOpenErrorCode(err, CodeCredentialExpired) {
		t.Fatalf("open at expiresAt error = %v, want %s", err, CodeCredentialExpired)
	}

	payload = validOpenTestPayload()
	payload["issuedAt"] = timestamp(now.Add(credentialIssuedAtSkew + time.Second))
	sealed = sealedOpenTestCredentialWithPayload(t, key, payload)
	if _, err := openEnvelopeAt(key, testBoxID, sealed, OpenExpectations{}, now); !IsOpenErrorCode(err, CodeCredentialNotYetValid) {
		t.Fatalf("open of future-issued credential error = %v, want %s", err, CodeCredentialNotYetValid)
	}

	payload["issuedAt"] = timestamp(now.Add(credentialIssuedAtSkew - time.Second))
	sealed = sealedOpenTestCredentialWithPayload(t, key, payload)
	if _, err := openEnvelopeAt(key, testBoxID, sealed, OpenExpectations{}, now); err != nil {
		t.Fatalf("open inside issuedAt skew error = %v", err)
	}
}

func TestOpenEnvelopeFailsClosed(t *testing.T) {
	key := openTestBoxKey(t)
	otherFingerprint := "sha256:" + strings.Repeat("b", 64)
	otherWrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other wrapping key: %v", err)
	}
	foreignWrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &otherWrappingKey.PublicKey, make([]byte, aesDataKeyBytes), nil)
	if err != nil {
		t.Fatalf("wrap foreign data key: %v", err)
	}
	valid := func() SealedCredential { return sealedOpenTestCredential(t, key) }
	withPayload := func(edit func(map[string]any)) SealedCredential {
		payload := validOpenTestPayload()
		edit(payload)
		return sealedOpenTestCredentialWithPayload(t, key, payload)
	}

	cases := []struct {
		name         string
		sealed       func() SealedCredential
		expectations OpenExpectations
		wantCode     OpenErrorCode
	}{
		{
			name: "delivery key fingerprint does not match",
			sealed: func() SealedCredential {
				sealed := valid()
				sealed.KeyFingerprint = otherFingerprint
				return sealed
			},
			wantCode: CodeKeyFingerprintMismatch,
		},
		{
			name: "envelope key fingerprint does not match",
			sealed: func() SealedCredential {
				return editEnvelope(t, valid(), func(object map[string]any) {
					object["keyFingerprint"] = otherFingerprint
				})
			},
			wantCode: CodeKeyFingerprintMismatch,
		},
		{
			name: "envelope bound to another box",
			sealed: func() SealedCredential {
				return editEnvelope(t, valid(), func(object map[string]any) {
					object["boxId"] = "srv_otherbox00002"
				})
			},
			wantCode: CodeBoxMismatch,
		},
		{
			name: "unsupported algorithm",
			sealed: func() SealedCredential {
				return editEnvelope(t, valid(), func(object map[string]any) {
					object["algorithm"] = "RSA-OAEP-256"
				})
			},
			wantCode: CodeUnsupportedAlgorithm,
		},
		{
			name: "unsupported format version",
			sealed: func() SealedCredential {
				return editEnvelope(t, valid(), func(object map[string]any) {
					object["formatVersion"] = 2
				})
			},
			wantCode: CodeInvalidEnvelope,
		},
		{
			name: "unknown envelope field",
			sealed: func() SealedCredential {
				return editEnvelope(t, valid(), func(object map[string]any) {
					object["unexpected"] = true
				})
			},
			wantCode: CodeInvalidEnvelope,
		},
		{
			name: "malformed ciphertext base64",
			sealed: func() SealedCredential {
				return editEnvelope(t, valid(), func(object map[string]any) {
					object["ciphertext"] = "not base64!"
				})
			},
			wantCode: CodeInvalidEnvelope,
		},
		{
			name: "short iv",
			sealed: func() SealedCredential {
				return editEnvelope(t, valid(), func(object map[string]any) {
					object["iv"] = base64URL.EncodeToString([]byte("short"))
				})
			},
			wantCode: CodeInvalidEnvelope,
		},
		{
			name: "tampered ciphertext",
			sealed: func() SealedCredential {
				sealed := valid()
				ciphertext := decodeTestBase64URL(t, envelopeString(t, sealed, "ciphertext"))
				ciphertext[len(ciphertext)-1] ^= 0xff
				return editEnvelope(t, sealed, func(object map[string]any) {
					object["ciphertext"] = base64URL.EncodeToString(ciphertext)
				})
			},
			wantCode: CodeInvalidTag,
		},
		{
			name: "tampered authenticated metadata",
			sealed: func() SealedCredential {
				return editEnvelope(t, valid(), func(object map[string]any) {
					object["envelopeId"] = "env_tamperedEnvelope01"
				})
			},
			wantCode: CodeInvalidTag,
		},
		{
			name: "wrapped key cannot be unwrapped",
			sealed: func() SealedCredential {
				return editEnvelope(t, valid(), func(object map[string]any) {
					object["wrappedKey"] = base64URL.EncodeToString(foreignWrappedKey)
				})
			},
			wantCode: CodeInvalidWrappedKey,
		},
		{
			name: "payload provider does not match delivery",
			sealed: func() SealedCredential {
				sealed := valid()
				sealed.ProviderID = "slack"
				return sealed
			},
			wantCode: CodePayloadBindingMismatch,
		},
		{
			name: "payload connection does not match delivery",
			sealed: func() SealedCredential {
				sealed := valid()
				sealed.CredentialID = "conn_bbbbbbbbbbbbbbbbbbbbbbbb"
				return sealed
			},
			wantCode: CodePayloadBindingMismatch,
		},
		{
			name:         "payload account does not match expectation",
			sealed:       valid,
			expectations: OpenExpectations{AccountID: "acct_someone_else"},
			wantCode:     CodePayloadBindingMismatch,
		},
		{
			name: "payload is expired",
			sealed: func() SealedCredential {
				return withPayload(func(payload map[string]any) {
					payload["expiresAt"] = "2020-01-01T00:00:00.000Z"
				})
			},
			wantCode: CodeCredentialExpired,
		},
		{
			name: "payload is issued in the future",
			sealed: func() SealedCredential {
				return withPayload(func(payload map[string]any) {
					payload["issuedAt"] = "2999-01-01T00:00:00.000Z"
				})
			},
			wantCode: CodeCredentialNotYetValid,
		},
		{
			name: "payload has an extra field",
			sealed: func() SealedCredential {
				return withPayload(func(payload map[string]any) {
					payload["envelopeId"] = openTestEnvelopeID
				})
			},
			wantCode: CodeInvalidPayload,
		},
		{
			name: "payload is missing a field",
			sealed: func() SealedCredential {
				return withPayload(func(payload map[string]any) {
					delete(payload, "purpose")
				})
			},
			wantCode: CodeInvalidPayload,
		},
		{
			name: "payload format version is unsupported",
			sealed: func() SealedCredential {
				return withPayload(func(payload map[string]any) {
					payload["formatVersion"] = 2
				})
			},
			wantCode: CodeInvalidPayload,
		},
		{
			name: "credential kind is unsupported",
			sealed: func() SealedCredential {
				return withPayload(func(payload map[string]any) {
					payload["credential"] = map[string]any{
						"kind":   "bearer",
						"fields": map[string]any{"token": openTestSecret},
					}
				})
			},
			wantCode: CodeInvalidPayload,
		},
		{
			name: "credential has no fields",
			sealed: func() SealedCredential {
				return withPayload(func(payload map[string]any) {
					payload["credential"] = map[string]any{"kind": "api_key", "fields": map[string]any{}}
				})
			},
			wantCode: CodeInvalidPayload,
		},
		{
			name: "credential has an unknown member",
			sealed: func() SealedCredential {
				return withPayload(func(payload map[string]any) {
					payload["credential"] = map[string]any{
						"kind":    "api_key",
						"fields":  map[string]any{"token": openTestSecret},
						"headers": map[string]any{"authorization": openTestSecret},
					}
				})
			},
			wantCode: CodeInvalidPayload,
		},
		{
			name: "credential field is empty",
			sealed: func() SealedCredential {
				return withPayload(func(payload map[string]any) {
					payload["credential"] = map[string]any{
						"kind":   "api_key",
						"fields": map[string]any{"token": ""},
					}
				})
			},
			wantCode: CodeInvalidPayload,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sealed := testCase.sealed()
			credential, err := OpenEnvelope(key, testBoxID, sealed, testCase.expectations)
			if err == nil {
				credential.Destroy()
				t.Fatalf("OpenEnvelope() succeeded, want %s", testCase.wantCode)
			}
			code, ok := OpenErrorCodeOf(err)
			if !ok {
				t.Fatalf("OpenEnvelope() error = %v, want an *OpenError with code %s", err, testCase.wantCode)
			}
			if code != testCase.wantCode {
				t.Fatalf("OpenEnvelope() code = %s, want %s (error %v)", code, testCase.wantCode, err)
			}
			message := err.Error()
			forbidden := []string{openTestSecret, "PRIVATE KEY"}
			for _, name := range []string{"ciphertext", "wrappedKey"} {
				forbidden = append(forbidden, envelopeString(t, sealed, name))
			}
			for _, value := range forbidden {
				if value != "" && strings.Contains(message, value) {
					t.Fatalf("error text leaked envelope or secret material %q: %s", value, message)
				}
			}
		})
	}
}

func TestOpenedCredentialCopiesAreIndependentAndDestroyable(t *testing.T) {
	key := openTestBoxKey(t)
	sealed := sealedOpenTestCredential(t, key)

	first, err := OpenEnvelope(key, testBoxID, sealed, OpenExpectations{})
	if err != nil {
		t.Fatalf("first OpenEnvelope() error = %v", err)
	}
	second, err := OpenEnvelope(key, testBoxID, sealed, OpenExpectations{})
	if err != nil {
		t.Fatalf("second OpenEnvelope() error = %v", err)
	}
	defer second.Destroy()

	fields := first.SecretFields()
	fields["token"] = "mutated"
	fields["injected"] = "should-not-stick"
	if got := first.SecretFields()["token"]; got != openTestSecret {
		t.Fatalf("mutating a returned map changed the credential: %q", got)
	}
	if _, ok := first.SecretFields()["injected"]; ok {
		t.Fatal("mutating a returned map added a field to the credential")
	}
	if got := second.SecretFields()["token"]; got != openTestSecret {
		t.Fatalf("mutating one credential changed another: %q", got)
	}

	storedBytes := first.fields["token"]
	first.Destroy()
	for index, value := range storedBytes {
		if value != 0 {
			t.Fatalf("Destroy() left secret byte %d set", index)
		}
	}
	if len(first.SecretFields()) != 0 {
		t.Fatal("Destroy() left secret fields readable")
	}
	if got := second.SecretFields()["token"]; got != openTestSecret {
		t.Fatalf("destroying one credential changed another: %q", got)
	}

	for _, rendered := range []string{
		fmt.Sprintf("%v", *second),
		fmt.Sprintf("%+v", *second),
		fmt.Sprintf("%#v", *second),
		fmt.Sprintf("%s", second),
		fmt.Sprintf("%q", second),
		fmt.Sprintf("%d", *second),
		fmt.Sprintf("%x", second),
		fmt.Sprintf("%p", second),
		second.String(),
		second.GoString(),
	} {
		if strings.Contains(rendered, openTestSecret) || strings.Contains(rendered, "token") {
			t.Fatalf("credential rendering leaked secret material: %s", rendered)
		}
	}
	if rendered := fmt.Sprintf("%d", *second); rendered != second.String() {
		t.Fatalf("non-string fmt verb did not render the redacted form: %s", rendered)
	}
	if rendered := fmt.Sprintf("%x", second); rendered != second.String() {
		t.Fatalf("hex fmt verb did not render the redacted form: %s", rendered)
	}
	marshaled, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	if strings.Contains(string(marshaled), openTestSecret) || strings.Contains(string(marshaled), "fields") {
		t.Fatalf("credential JSON leaked secret material: %s", marshaled)
	}
}

// TestFakeBoxJourneyOpensPulledCredential extends the P1 fake-Box journey: the
// platform seals a credential to the Box key that the fake Box persists, the
// bridge registers and pulls it into the root-only store, and the opening
// primitive turns the stored ciphertext into an in-memory credential without
// writing any plaintext to disk.
func TestFakeBoxJourneyOpensPulledCredential(t *testing.T) {
	platform := newFakePlatform(t)
	stateRoot := t.TempDir()

	keyStore := newKeyStore(stateRoot, minimumKeyBits)
	key, generated, err := keyStore.loadOrCreate()
	if err != nil {
		t.Fatalf("prepare fake Box key: %v", err)
	}
	if !generated {
		t.Fatal("fake Box key was not generated")
	}
	payload := validOpenTestPayload()
	sealedEnvelope := sealTestEnvelope(
		t, &key.private.PublicKey, testBoxID, key.Fingerprint(), openTestEnvelopeID,
		canonicalTestJSON(t, payload),
	)
	platform.pullItems = func(fingerprint string) []control.ToolProviderCredentialDelivery {
		if fingerprint != key.Fingerprint() {
			return nil
		}
		return []control.ToolProviderCredentialDelivery{{
			CredentialID:   testCredID,
			ProviderID:     "github",
			KeyFingerprint: fingerprint,
			Envelope:       sealedEnvelope,
		}}
	}
	var logBuffer bytes.Buffer
	manager := newTestManager(t, defaultTestOptions(platform, stateRoot, log.New(&logBuffer, "", 0)))
	cancel := startManager(t, manager)
	waitForStatus(t, manager, 15*time.Second, func(status Status) bool {
		return status.ActiveEnvelopeCount == 1 && !status.LastPullAt.IsZero()
	})
	stopManager(t, manager, cancel)

	credential, err := manager.OpenCredential(testCredID, OpenExpectations{AccountID: openTestAccountID})
	if err != nil {
		t.Fatalf("OpenCredential() error = %v", err)
	}
	if credential.ProviderID != "github" || credential.ConnectionID != testCredID || credential.AccountID != openTestAccountID {
		t.Fatalf("opened credential metadata = %s", credential)
	}
	if got := credential.SecretFields()["token"]; got != openTestSecret {
		t.Fatalf("opened credential secret field = %q, want the sealed value", got)
	}
	credential.Destroy()

	if _, err := manager.OpenCredential("conn_cccccccccccccccccccccccc", OpenExpectations{}); !IsOpenErrorCode(err, CodeCredentialNotFound) {
		t.Fatalf("OpenCredential(unknown) error = %v, want %s", err, CodeCredentialNotFound)
	}
	if _, err := manager.OpenCredential(testCredID, OpenExpectations{AccountID: "acct_someone_else"}); !IsOpenErrorCode(err, CodePayloadBindingMismatch) {
		t.Fatalf("OpenCredential(wrong account) error = %v, want %s", err, CodePayloadBindingMismatch)
	}

	if strings.Contains(logBuffer.String(), openTestSecret) {
		t.Fatalf("bridge logs leaked the plaintext credential: %s", logBuffer.String())
	}
	if strings.Contains(manager.Status().String(), openTestSecret) {
		t.Fatalf("bridge status leaked the plaintext credential: %s", manager.Status())
	}
	statusJSON, err := json.Marshal(manager.Status())
	if err != nil {
		t.Fatalf("marshal bridge status: %v", err)
	}
	if strings.Contains(string(statusJSON), openTestSecret) {
		t.Fatalf("bridge status JSON leaked the plaintext credential: %s", statusJSON)
	}
	// No persisted file may contain plaintext: only the root-only key PEM and
	// the sealed envelope document (ciphertext) are allowed at rest.
	walkErr := filepath.WalkDir(stateRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if bytes.Contains(content, []byte(openTestSecret)) {
			t.Errorf("plaintext credential was persisted at %s", filepath.Base(path))
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk state directory: %v", walkErr)
	}
}

func TestOpenCredentialFailsClosedWithoutEnabledBridgeOrKey(t *testing.T) {
	disabled, err := New(Options{Enabled: false})
	if err != nil {
		t.Fatalf("New(disabled) error = %v", err)
	}
	if _, err := disabled.OpenCredential(testCredID, OpenExpectations{}); !IsOpenErrorCode(err, CodeCredentialUnavailable) {
		t.Fatalf("disabled OpenCredential() error = %v, want %s", err, CodeCredentialUnavailable)
	}

	platform := newFakePlatform(t)
	enabled := newTestManager(t, defaultTestOptions(platform, t.TempDir(), discardLogger()))
	if _, err := enabled.OpenCredential(testCredID, OpenExpectations{}); !IsOpenErrorCode(err, CodeKeyUnavailable) {
		t.Fatalf("keyless OpenCredential() error = %v, want %s", err, CodeKeyUnavailable)
	}
	if registers, pulls := platform.counts(); registers != 0 || pulls != 0 {
		t.Fatalf("opening without a run loop made control-plane calls: registers=%d pulls=%d", registers, pulls)
	}
}
