package qualification

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// Test-build-only root ownership detachment. The actual private/public key
// identity still matches the independently enrolled backend fixture exactly.
func SourceAccountingProducerForTest(config ProducerConfig) (*Producer, error) {
	raw, err := os.ReadFile(config.KeyPath)
	if err != nil {
		return nil, ErrUntrusted
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 {
		return nil, ErrUntrusted
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrUntrusted
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().Name != "P-256" {
		return nil, ErrUntrusted
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, ErrUntrusted
	}
	if Digest(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})) != config.KeySHA256 {
		return nil, ErrUntrusted
	}
	return &Producer{config: config, key: key}, nil
}
