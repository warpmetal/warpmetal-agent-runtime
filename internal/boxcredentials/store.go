package boxcredentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	credentialStoreVersion  = 1
	credentialStoreFileName = "tool-provider-credentials.json"
	maxCredentialStoreSize  = 8 << 20
)

// storedCredential is one validated sealed envelope keyed by credential id.
// The envelope bytes are kept verbatim; no plaintext, wrapped key material or
// decryption result is ever derived here.
type storedCredential struct {
	CredentialID   string          `json:"credentialId"`
	ProviderID     string          `json:"providerId"`
	KeyFingerprint string          `json:"keyFingerprint"`
	Envelope       json.RawMessage `json:"envelope"`
}

type credentialDocument struct {
	Version     int                         `json:"version"`
	UpdatedAt   time.Time                   `json:"updatedAt"`
	Credentials map[string]storedCredential `json:"credentials"`
}

// credentialStore owns the root-only sealed envelope file. The platform pull
// response is the complete active set, so every successful pull atomically
// replaces this file: revoked or reconnection-required envelopes disappear
// locally instead of lingering in the cache.
type credentialStore struct {
	path string
}

func newCredentialStore(stateRoot string) *credentialStore {
	return &credentialStore{
		path: filepath.Join(stateRoot, stateDirectoryName, credentialStoreFileName),
	}
}

// load restores the last persisted active set for this Box key. Records that no
// longer validate against the local key or identity are dropped and counted;
// the file itself is never rewritten by a read.
func (s *credentialStore) load(boxID, fingerprint string) (map[string]storedCredential, int, error) {
	content, err := readPrivateFile(s.path, maxCredentialStoreSize)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]storedCredential{}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	var document credentialDocument
	if err := json.Unmarshal(content, &document); err != nil {
		return nil, 0, errors.New("sealed credential store is not valid JSON")
	}
	if document.Version != credentialStoreVersion {
		return nil, 0, fmt.Errorf("sealed credential store version %d is unsupported", document.Version)
	}
	accepted := make(map[string]storedCredential, len(document.Credentials))
	rejected := 0
	for credentialID, record := range document.Credentials {
		if credentialID != record.CredentialID || validateStoredCredential(record, boxID, fingerprint) != nil {
			rejected++
			continue
		}
		accepted[credentialID] = record
	}
	return accepted, rejected, nil
}

// replace atomically persists the active set with root-only permissions.
func (s *credentialStore) replace(credentials map[string]storedCredential) error {
	if credentials == nil {
		credentials = map[string]storedCredential{}
	}
	document := credentialDocument{
		Version:     credentialStoreVersion,
		UpdatedAt:   time.Now().UTC(),
		Credentials: credentials,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return err
	}
	return atomicWriteFile(s.path, encoded, 0o600)
}
