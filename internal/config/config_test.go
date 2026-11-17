package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerexec"
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

func TestLoadValidatesProviderExecutorConfiguration(t *testing.T) {
	validCommand := "/usr/local/lib/warpmetal/provider-exec"
	tests := []struct {
		name     string
		executor *providerexec.Config
		wantErr  bool
	}{
		{
			name:     "absent executor keeps the P2d fail-closed configuration",
			executor: nil,
		},
		{
			name:     "valid executor with defaults",
			executor: &providerexec.Config{Command: validCommand},
		},
		{
			name: "valid executor with explicit bounds",
			executor: &providerexec.Config{
				Command:          validCommand,
				Args:             []string{"--mode", "reviewed"},
				TimeoutSeconds:   120,
				MaxResponseBytes: 2 << 20,
			},
		},
		{
			name:     "relative command",
			executor: &providerexec.Config{Command: "provider-exec"},
			wantErr:  true,
		},
		{
			name:     "empty command object",
			executor: &providerexec.Config{},
			wantErr:  true,
		},
		{
			name:     "non-clean command path",
			executor: &providerexec.Config{Command: "/usr/local/../local/bin/provider-exec"},
			wantErr:  true,
		},
		{
			name:     "command path with control character",
			executor: &providerexec.Config{Command: "/usr/local/bin/provider\nexec"},
			wantErr:  true,
		},
		{
			name:     "negative timeout",
			executor: &providerexec.Config{Command: validCommand, TimeoutSeconds: -1},
			wantErr:  true,
		},
		{
			name:     "timeout above the bound",
			executor: &providerexec.Config{Command: validCommand, TimeoutSeconds: int(providerexec.MaxTimeout/time.Second) + 1},
			wantErr:  true,
		},
		{
			name:     "timeout at the bound",
			executor: &providerexec.Config{Command: validCommand, TimeoutSeconds: int(providerexec.MaxTimeout / time.Second)},
		},
		{
			name:     "response limit below the bound",
			executor: &providerexec.Config{Command: validCommand, MaxResponseBytes: providerexec.MinMaxResponseBytes - 1},
			wantErr:  true,
		},
		{
			name:     "response limit above the bound",
			executor: &providerexec.Config{Command: validCommand, MaxResponseBytes: providerexec.MaxMaxResponseBytes + 1},
			wantErr:  true,
		},
		{
			name:     "response limit at the bound",
			executor: &providerexec.Config{Command: validCommand, MaxResponseBytes: providerexec.MaxMaxResponseBytes},
		},
		{
			name: "too many arguments",
			executor: &providerexec.Config{
				Command: validCommand,
				Args:    make([]string, providerexec.MaxArgs+1),
			},
			wantErr: true,
		},
		{
			name: "argument too long",
			executor: &providerexec.Config{
				Command: validCommand,
				Args:    []string{strings.Repeat("a", providerexec.MaxArgBytes+1)},
			},
			wantErr: true,
		},
		{
			name: "argument with a control character",
			executor: &providerexec.Config{
				Command: validCommand,
				Args:    []string{"a\x00b"},
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validBaseConfig(t)
			value.ToolCredentialBridge = &ToolCredentialBridgeConfig{
				Enabled:          true,
				ProviderExecutor: test.executor,
			}
			loaded, err := saveAndLoadConfig(t, value)
			if test.wantErr {
				if err == nil {
					t.Fatal("Load() accepted an invalid provider executor configuration")
				}
				if !strings.Contains(err.Error(), "providerExecutor") {
					t.Fatalf("Load() error = %v, want a providerExecutor validation error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if test.executor == nil {
				if loaded.ToolCredentialBridge.ProviderExecutor != nil {
					t.Fatalf("providerExecutor = %#v, want absent", loaded.ToolCredentialBridge.ProviderExecutor)
				}
				if loaded.ToolCredentialBridge.ProviderExecutorConfigured() {
					t.Fatal("absent provider executor reported as configured")
				}
				return
			}
			if !loaded.ToolCredentialBridge.ProviderExecutorConfigured() {
				t.Fatal("valid provider executor was not reported as configured")
			}
			if got := loaded.ToolCredentialBridge.ProviderExecutor.Timeout(); got != test.executor.Timeout() {
				t.Fatalf("Timeout() = %s, want %s", got, test.executor.Timeout())
			}
			if got := loaded.ToolCredentialBridge.ProviderExecutor.ResponseLimit(); got != test.executor.ResponseLimit() {
				t.Fatalf("ResponseLimit() = %d, want %d", got, test.executor.ResponseLimit())
			}
		})
	}
}

func TestLoadIgnoresProviderExecutorOnDisabledBridge(t *testing.T) {
	value := validBaseConfig(t)
	value.ToolCredentialBridge = &ToolCredentialBridgeConfig{
		Enabled:          false,
		ProviderExecutor: &providerexec.Config{Command: "relative-and-invalid"},
	}
	if _, err := saveAndLoadConfig(t, value); err != nil {
		t.Fatalf("Load() rejected an executor on a disabled bridge: %v", err)
	}
	if value.ToolCredentialBridge.ProviderExecutorConfigured() {
		t.Fatal("disabled bridge reported a configured provider executor")
	}
}
