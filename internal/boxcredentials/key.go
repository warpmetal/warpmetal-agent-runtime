package boxcredentials

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

const (
	// Algorithms are the exact wire values pinned by the platform for the Box
	// encryption key and for sealed tool-provider credential envelopes.
	Algorithm         = "RSA-OAEP-256"
	EnvelopeAlgorithm = "RSA-OAEP-256+A256GCM"
	// Purpose is the envelope purpose accepted for tool-provider credentials.
	Purpose = "tool-provider-credential"

	// productionKeyBits is the only key size generated for a production Box
	// (the platform floor is 3072 bits).
	productionKeyBits = 4096
	// minimumKeyBits mirrors the platform's own public-key floor; a persisted
	// key below it is refused rather than pinned.
	minimumKeyBits = 3072

	stateDirectoryName    = "box-credentials"
	privateKeyFileName    = "box-encryption-key.pem"
	maxPrivateKeyFileSize = 64 << 10
)

var base64URL = base64.RawURLEncoding

// Key is the Box's RSA-OAEP encryption key. The private half is deliberately
// unexported: nothing outside this package can serialize, log or return it.
type Key struct {
	private     *rsa.PrivateKey
	fingerprint string
	jwk         map[string]any
}

func generateKey(bits int) (*Key, error) {
	if bits < minimumKeyBits {
		return nil, fmt.Errorf("box encryption key size %d is below the platform minimum", bits)
	}
	private, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, errors.New("generate box encryption key")
	}
	return newKey(private)
}

func newKey(private *rsa.PrivateKey) (*Key, error) {
	if private == nil || private.N == nil || private.PublicKey.E != 65537 {
		return nil, errors.New("box encryption key is invalid")
	}
	if private.N.BitLen() < minimumKeyBits {
		return nil, errors.New("box encryption key is below the platform minimum")
	}
	if err := private.Validate(); err != nil {
		return nil, errors.New("box encryption key is invalid")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, errors.New("encode box encryption public key")
	}
	digest := sha256.Sum256(publicDER)
	jwk := map[string]any{
		"kty": "RSA",
		"n":   base64URL.EncodeToString(private.N.Bytes()),
		"e":   base64URL.EncodeToString(big.NewInt(int64(private.E)).Bytes()),
		"alg": Algorithm,
		"ext": true,
	}
	return &Key{
		private:     private,
		fingerprint: "sha256:" + hex.EncodeToString(digest[:]),
		jwk:         jwk,
	}, nil
}

// PublicJWK returns a copy of the only key material that may leave the Box.
func (k *Key) PublicJWK() map[string]any {
	clone := make(map[string]any, len(k.jwk))
	for name, value := range k.jwk {
		clone[name] = value
	}
	return clone
}

// Fingerprint is the sha256 over the SPKI DER public key, formatted as
// "sha256:<lowercase hex>", the exact encoding the platform pins.
func (k *Key) Fingerprint() string {
	return k.fingerprint
}

// String and GoString keep accidental formatting of the key from dumping the
// private components into a log line or crash report.
func (k *Key) String() string {
	return "boxcredentials.Key{fingerprint:" + k.fingerprint + "}"
}

func (k *Key) GoString() string {
	return k.String()
}

// openDataKey unwraps one RSA-OAEP-SHA256 sealed AES data key with the Box
// private key. The returned bytes are secret: the caller must zero them after
// the envelope is opened and must never log, persist or return them. Keeping
// the operation unexported means no caller can obtain or serialize the private
// key half from outside this package.
func (k *Key) openDataKey(wrappedKey []byte) ([]byte, error) {
	if k == nil || k.private == nil {
		return nil, errors.New("box encryption key is unavailable")
	}
	dataKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, k.private, wrappedKey, nil)
	if err != nil {
		return nil, errors.New("box encryption key cannot unwrap the envelope data key")
	}
	return dataKey, nil
}

func (k *Key) marshalPrivateKey() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.private)
	if err != nil {
		return nil, errors.New("encode box encryption private key")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func loadKey(path string) (*Key, error) {
	content, err := readPrivateFile(path, maxPrivateKeyFileSize)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("box encryption key file is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("box encryption key file is invalid")
	}
	private, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("box encryption key file is not an RSA key")
	}
	return newKey(private)
}

// keyStore owns the root-only Box identity directory under the Runtime state
// root. It never regenerates a key over an unreadable or malformed existing
// file: losing that key would silently change the Box identity.
type keyStore struct {
	directory string
	keyBits   int
}

func newKeyStore(stateRoot string, keyBits int) *keyStore {
	return &keyStore{
		directory: filepath.Join(stateRoot, stateDirectoryName),
		keyBits:   keyBits,
	}
}

func (s *keyStore) privateKeyPath() string {
	return filepath.Join(s.directory, privateKeyFileName)
}

func (s *keyStore) ensureDirectory() error {
	if err := ensurePrivateDirectory(s.directory); err != nil {
		return fmt.Errorf("prepare box credential state directory: %w", err)
	}
	return nil
}

// load returns the already-persisted Box key. Unlike loadOrCreate it never
// generates a key, so opening a credential fails closed instead of silently
// adopting a new Box identity.
func (s *keyStore) load() (*Key, error) {
	return loadKey(s.privateKeyPath())
}

// loadOrCreate returns the existing Box key, or generates and persists exactly
// one 4096-bit RSA-OAEP keypair on first use. It reports whether a key was
// generated on this call.
func (s *keyStore) loadOrCreate() (*Key, bool, error) {
	if err := s.ensureDirectory(); err != nil {
		return nil, false, err
	}
	key, err := loadKey(s.privateKeyPath())
	if err == nil {
		return key, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("load box encryption key: %w", err)
	}
	bits := s.keyBits
	if bits <= 0 {
		bits = productionKeyBits
	}
	generated, err := generateKey(bits)
	if err != nil {
		return nil, false, err
	}
	encoded, err := generated.marshalPrivateKey()
	if err != nil {
		return nil, false, err
	}
	if err := atomicWriteFile(s.privateKeyPath(), encoded, 0o600); err != nil {
		return nil, false, fmt.Errorf("persist box encryption key: %w", err)
	}
	return generated, true, nil
}
