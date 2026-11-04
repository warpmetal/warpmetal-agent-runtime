package config

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/setupsource"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	APIOrigin             string                        `json:"apiOrigin"`
	ServerID              string                        `json:"serverId"`
	NodeToken             string                        `json:"nodeToken"`
	NodeTokenExpiresAt    time.Time                     `json:"nodeTokenExpiresAt"`
	QualificationRoot     string                        `json:"qualificationRoot,omitempty"`
	QualificationProducer *qualification.ProducerConfig `json:"qualificationProducer,omitempty"`
	// SetupTestSource is operator-only test-venue configuration. It is never
	// projected from a manifest or setup operation; a production runtime
	// leaves it absent so the setup runner keeps its strict SSRF guard. When
	// enabled it requires an exact-URL allowlist and the Runtime forwards the
	// gate only to this instance's setup executions.
	SetupTestSource *setupsource.Config `json:"setupTestSource,omitempty"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var value Config
	if err := json.Unmarshal(data, &value); err != nil {
		return Config{}, err
	}
	if !strings.HasPrefix(value.APIOrigin, "https://") || !strings.HasPrefix(value.ServerID, "srv_") ||
		!strings.HasPrefix(value.NodeToken, "rtn_") {
		return Config{}, errors.New("runtime configuration is invalid")
	}
	// Fail closed at startup: the workspace-application attestor is the
	// registered host root producer. A config without an exactly matching
	// producer pin must refuse to start instead of silently refusing every
	// application receipt with ErrUntrusted at runtime (R-WP111-1).
	if err := value.QualificationProducer.Validate(value.ServerID,
		fmt.Sprintf("%x", sha256.Sum256([]byte(value.NodeToken)))); err != nil {
		return Config{}, fmt.Errorf("qualification producer: %w", err)
	}
	// Fail closed at startup: a test source requested without a usable exact
	// URL allowlist must never let the daemon start and silently widen the
	// setup runner's source guard.
	if err := value.SetupTestSource.Validate(); err != nil {
		return Config{}, fmt.Errorf("setup test source: %w", err)
	}
	return value, nil
}

func Save(path string, value Config) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
