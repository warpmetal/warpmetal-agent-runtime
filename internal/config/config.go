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
	// ToolCredentialBridge opts the Runtime into Phase P1 of the sealed
	// tool-provider credential bridge. Every existing config omits it, so a
	// production Runtime keeps today's behavior exactly: no Box encryption key
	// is generated and no credential endpoint is called.
	ToolCredentialBridge *ToolCredentialBridgeConfig `json:"toolCredentialBridge,omitempty"`
}

// ToolCredentialBridgeConfig is the explicit opt-in for the Runtime Box
// credential bridge. The bridge only generates/registers a Box encryption key
// and stores sealed tool-provider credential envelopes; it does not decrypt,
// inject or execute provider tools in this phase.
type ToolCredentialBridgeConfig struct {
	Enabled bool `json:"enabled"`
	// PollIntervalSeconds bounds the credential pull cadence. Zero selects
	// DefaultToolCredentialBridgePollInterval; explicit values must be between
	// MinToolCredentialBridgePollInterval and MaxToolCredentialBridgePollInterval
	// so an operator can neither hammer the platform nor leave credentials
	// undelivered indefinitely.
	PollIntervalSeconds int `json:"pollIntervalSeconds,omitempty"`
}

const (
	// DefaultToolCredentialBridgePollInterval is the pull cadence used when the
	// operator enables the bridge without choosing an interval.
	DefaultToolCredentialBridgePollInterval = time.Minute
	// MinToolCredentialBridgePollInterval bounds how frequently an enabled
	// Runtime may poll the credential delivery endpoint.
	MinToolCredentialBridgePollInterval = 10 * time.Second
	// MaxToolCredentialBridgePollInterval bounds the longest accepted interval.
	MaxToolCredentialBridgePollInterval = time.Hour
)

// Validate refuses an enabled bridge with an unbounded or nonsensical poll
// cadence. A disabled or absent bridge is always valid so existing configs
// cannot be affected by the new field.
func (c *ToolCredentialBridgeConfig) Validate() error {
	if c == nil || !c.Enabled || c.PollIntervalSeconds == 0 {
		return nil
	}
	interval := time.Duration(c.PollIntervalSeconds) * time.Second
	if interval < MinToolCredentialBridgePollInterval || interval > MaxToolCredentialBridgePollInterval {
		return fmt.Errorf(
			"toolCredentialBridge.pollIntervalSeconds must be between %d and %d",
			int(MinToolCredentialBridgePollInterval/time.Second),
			int(MaxToolCredentialBridgePollInterval/time.Second),
		)
	}
	return nil
}

// PollInterval is the effective pull cadence for an enabled bridge. It is
// nil-safe and applies the documented default for an unset value.
func (c *ToolCredentialBridgeConfig) PollInterval() time.Duration {
	if c == nil || c.PollIntervalSeconds == 0 {
		return DefaultToolCredentialBridgePollInterval
	}
	return time.Duration(c.PollIntervalSeconds) * time.Second
}

// ToolCredentialBridgeEnabled reports whether the opt-in bridge is configured.
func (c Config) ToolCredentialBridgeEnabled() bool {
	return c.ToolCredentialBridge != nil && c.ToolCredentialBridge.Enabled
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
	// An explicitly enabled credential bridge must have a bounded pull cadence;
	// an absent/disabled bridge validates exactly like before this field existed.
	if err := value.ToolCredentialBridge.Validate(); err != nil {
		return Config{}, fmt.Errorf("tool credential bridge: %w", err)
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
