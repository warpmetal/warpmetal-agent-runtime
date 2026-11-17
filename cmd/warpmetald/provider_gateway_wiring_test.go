package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/boxcredentials"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/config"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerexec"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providergateway"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/reconcile"
)

type wiringTestExecutor struct{ calls int }

func (executor *wiringTestExecutor) CallTool(
	context.Context,
	providergateway.ToolCall,
) (providergateway.ToolResult, error) {
	executor.calls++
	return providergateway.ToolResult{Text: "unused"}, nil
}

func TestConfigureProviderGatewaysDisabledIsInert(t *testing.T) {
	runtimeReconciler := &reconcile.Reconciler{}
	stop := configureProviderGateways(runtimeReconciler, nil, nil)
	stop()
	if runtimeReconciler.ProviderGateways != nil {
		t.Fatal("disabled provider gateways constructed a lifecycle manager")
	}
	if runtimeReconciler.ProviderCredentials != nil {
		t.Fatal("disabled provider gateways constructed a credential opener")
	}
	if runtimeReconciler.ProviderExecutor != nil {
		t.Fatal("disabled provider gateways wired a tool executor")
	}
}

func TestConfigureProviderGatewaysEnabledWiresLifecycleDependencies(t *testing.T) {
	bridge, err := boxcredentials.New(boxcredentials.Options{
		Enabled:  true,
		StateDir: t.TempDir(),
		Client: control.Client{
			Origin:    "https://api.warpmetal.example",
			NodeToken: "rtn_provider_wiring0001",
		},
		BoxID: "srv_wiring0001",
	})
	if err != nil {
		t.Fatalf("construct credential bridge: %v", err)
	}
	executor := &wiringTestExecutor{}
	runtimeReconciler := &reconcile.Reconciler{}
	stop := configureProviderGateways(runtimeReconciler, bridge, executor)
	defer stop()
	gateways, ok := runtimeReconciler.ProviderGateways.(reconcile.ProviderGateways)
	if !ok || gateways.Manager == nil {
		t.Fatalf("provider gateway manager was not wired: %#v", runtimeReconciler.ProviderGateways)
	}
	opener, ok := runtimeReconciler.ProviderCredentials.(reconcile.BoxCredentialOpener)
	if !ok || opener.Manager != bridge {
		t.Fatalf("credential opener was not wired to the enabled bridge: %#v", runtimeReconciler.ProviderCredentials)
	}
	if runtimeReconciler.ProviderExecutor != executor {
		t.Fatal("configured executor was not passed into the reconciler")
	}
	if gateways.Manager.Has("sbx_wiring0001", "run_wiring0001") {
		t.Fatal("freshly constructed manager already reports a running gateway")
	}
}

func TestConfigureProviderGatewaysEnabledWithoutExecutorFailsClosed(t *testing.T) {
	bridge, err := boxcredentials.New(boxcredentials.Options{
		Enabled:  true,
		StateDir: t.TempDir(),
		Client: control.Client{
			Origin:    "https://api.warpmetal.example",
			NodeToken: "rtn_provider_wiring0002",
		},
		BoxID: "srv_wiring0002",
	})
	if err != nil {
		t.Fatalf("construct credential bridge: %v", err)
	}
	runtimeReconciler := &reconcile.Reconciler{}
	stop := configureProviderGateways(runtimeReconciler, bridge, nil)
	defer stop()
	if runtimeReconciler.ProviderGateways == nil || runtimeReconciler.ProviderCredentials == nil {
		t.Fatal("enabled credential bridge did not wire the gateway lifecycle")
	}
	// P2d production wiring deliberately leaves the executor nil: no real
	// provider calls are enabled, so a manifest requiring gateways fails closed.
	if runtimeReconciler.ProviderExecutor != nil {
		t.Fatal("P2d wiring configured a production provider executor")
	}
}

// writeWiringTestExecutor writes an executable fake provider executor for the
// wiring tests. It is a shell script, but it is only ever executed by a test
// that needs the startup executable-file check to pass.
func writeWiringTestExecutor(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provider-exec")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake provider executor: %v", err)
	}
	return path
}

func TestNewProviderExecutorAbsentKeepsFailClosed(t *testing.T) {
	// No bridge at all: identical to the P2d configuration.
	executor, err := newProviderExecutor(config.Config{})
	if err != nil {
		t.Fatalf("newProviderExecutor() error = %v", err)
	}
	if executor != nil {
		t.Fatalf("absent bridge constructed an executor: %#v", executor)
	}
	// Enabled bridge without a providerExecutor: still the P2d fail-closed
	// configuration, no executor is constructed.
	executor, err = newProviderExecutor(config.Config{
		ToolCredentialBridge: &config.ToolCredentialBridgeConfig{Enabled: true},
	})
	if err != nil {
		t.Fatalf("newProviderExecutor() error = %v", err)
	}
	if executor != nil {
		t.Fatalf("enabled bridge without providerExecutor constructed an executor: %#v", executor)
	}
}

func TestNewProviderExecutorDisabledBridgeIsInert(t *testing.T) {
	// A disabled bridge ignores providerExecutor exactly as it ignores an
	// invalid poll interval: the configuration is inert by construction.
	executor, err := newProviderExecutor(config.Config{
		ToolCredentialBridge: &config.ToolCredentialBridgeConfig{
			Enabled: false,
			ProviderExecutor: &providerexec.Config{
				Command:        "relative-and-invalid",
				TimeoutSeconds: 100000,
			},
		},
	})
	if err != nil {
		t.Fatalf("newProviderExecutor() error = %v", err)
	}
	if executor != nil {
		t.Fatal("disabled bridge constructed an executor")
	}
}

func TestNewProviderExecutorConfiguredConstructsExecutor(t *testing.T) {
	command := writeWiringTestExecutor(t)
	executor, err := newProviderExecutor(config.Config{
		ToolCredentialBridge: &config.ToolCredentialBridgeConfig{
			Enabled: true,
			ProviderExecutor: &providerexec.Config{
				Command:        command,
				Args:           []string{"--mode", "reviewed"},
				TimeoutSeconds: 45,
			},
		},
	})
	if err != nil {
		t.Fatalf("newProviderExecutor() error = %v", err)
	}
	if executor == nil {
		t.Fatal("configured provider executor was not constructed")
	}
	timeoutProvider, ok := executor.(providergateway.ToolTimeoutProvider)
	if !ok {
		t.Fatal("provider executor does not declare its per-call timeout")
	}
	if got := timeoutProvider.ToolTimeout(); got != 45*time.Second {
		t.Fatalf("provider executor timeout = %s, want 45s", got)
	}
}

func TestNewProviderExecutorRejectsInvalidCommand(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := newProviderExecutor(config.Config{
		ToolCredentialBridge: &config.ToolCredentialBridgeConfig{
			Enabled:          true,
			ProviderExecutor: &providerexec.Config{Command: missing},
		},
	}); err == nil {
		t.Fatal("newProviderExecutor() accepted a missing command")
	}
	// A regular but non-executable file is also refused at startup.
	notExecutable := filepath.Join(t.TempDir(), "provider-exec")
	if err := os.WriteFile(notExecutable, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatalf("write non-executable file: %v", err)
	}
	if _, err := newProviderExecutor(config.Config{
		ToolCredentialBridge: &config.ToolCredentialBridgeConfig{
			Enabled:          true,
			ProviderExecutor: &providerexec.Config{Command: notExecutable},
		},
	}); err == nil {
		t.Fatal("newProviderExecutor() accepted a non-executable command")
	}
}
