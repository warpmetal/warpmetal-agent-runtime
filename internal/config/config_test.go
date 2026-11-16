package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

func validBaseConfig(t *testing.T) Config {
	t.Helper()
	nodeToken := "rtn_config_test_token"
	digest := sha256.Sum256([]byte(nodeToken))
	return Config{
		APIOrigin:          "https://api.example.com",
		ServerID:           "srv_configtest001",
		NodeToken:          nodeToken,
		NodeTokenExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		QualificationProducer: &qualification.ProducerConfig{
			KeyID:         "qualification-key-1",
			KeyPath:       "/var/lib/warpmetal/qualification.key",
			KeySHA256:     "sha256:" + strings.Repeat("a", 64),
			EvidenceRoot:  "/var/lib/warpmetal/evidence",
			ServerID:      "srv_configtest001",
			NodeTokenHash: hex.EncodeToString(digest[:]),
		},
	}
}

func saveAndLoadConfig(t *testing.T, value Config) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := Save(path, value); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("config mode = %o, want 600", mode)
	}
	return Load(path)
}

func TestLegacyConfigWithoutCredentialBridgeIsUnchanged(t *testing.T) {
	base := validBaseConfig(t)
	loaded, err := saveAndLoadConfig(t, base)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.ToolCredentialBridge != nil {
		t.Fatalf("toolCredentialBridge = %#v, want absent", loaded.ToolCredentialBridge)
	}
	if loaded.ToolCredentialBridgeEnabled() {
		t.Fatal("absent tool credential bridge reported as enabled")
	}
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := Save(path, base); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if strings.Contains(string(content), "toolCredentialBridge") {
		t.Fatalf("disabled config gained the opt-in field: %s", content)
	}
}

func TestLoadValidatesEnabledCredentialBridge(t *testing.T) {
	tests := []struct {
		name        string
		bridge      *ToolCredentialBridgeConfig
		wantErr     bool
		wantPoll    time.Duration
		wantEnabled bool
	}{
		{
			name:     "absent",
			bridge:   nil,
			wantPoll: 0,
		},
		{
			name:        "enabled default interval",
			bridge:      &ToolCredentialBridgeConfig{Enabled: true},
			wantPoll:    DefaultToolCredentialBridgePollInterval,
			wantEnabled: true,
		},
		{
			name:        "enabled minimum interval",
			bridge:      &ToolCredentialBridgeConfig{Enabled: true, PollIntervalSeconds: int(MinToolCredentialBridgePollInterval / time.Second)},
			wantPoll:    MinToolCredentialBridgePollInterval,
			wantEnabled: true,
		},
		{
			name:        "enabled maximum interval",
			bridge:      &ToolCredentialBridgeConfig{Enabled: true, PollIntervalSeconds: int(MaxToolCredentialBridgePollInterval / time.Second)},
			wantPoll:    MaxToolCredentialBridgePollInterval,
			wantEnabled: true,
		},
		{
			name:    "enabled interval too small",
			bridge:  &ToolCredentialBridgeConfig{Enabled: true, PollIntervalSeconds: int(MinToolCredentialBridgePollInterval/time.Second) - 1},
			wantErr: true,
		},
		{
			name:    "enabled interval too large",
			bridge:  &ToolCredentialBridgeConfig{Enabled: true, PollIntervalSeconds: int(MaxToolCredentialBridgePollInterval/time.Second) + 1},
			wantErr: true,
		},
		{
			name:     "disabled ignores unset interval",
			bridge:   &ToolCredentialBridgeConfig{Enabled: false},
			wantPoll: DefaultToolCredentialBridgePollInterval,
		},
		{
			name:     "disabled ignores invalid interval",
			bridge:   &ToolCredentialBridgeConfig{Enabled: false, PollIntervalSeconds: 1},
			wantPoll: time.Second,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validBaseConfig(t)
			value.ToolCredentialBridge = test.bridge
			loaded, err := saveAndLoadConfig(t, value)
			if test.wantErr {
				if err == nil {
					t.Fatal("Load() accepted an unbounded credential bridge cadence")
				}
				if !strings.Contains(err.Error(), "tool credential bridge") {
					t.Fatalf("Load() error = %v, want a tool credential bridge validation error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if loaded.ToolCredentialBridgeEnabled() != test.wantEnabled {
				t.Fatalf("enabled = %t, want %t", loaded.ToolCredentialBridgeEnabled(), test.wantEnabled)
			}
			if test.bridge == nil {
				if loaded.ToolCredentialBridge != nil {
					t.Fatalf("bridge = %#v, want nil", loaded.ToolCredentialBridge)
				}
				return
			}
			if got := loaded.ToolCredentialBridge.PollInterval(); got != test.wantPoll {
				t.Fatalf("PollInterval() = %s, want %s", got, test.wantPoll)
			}
		})
	}
}
