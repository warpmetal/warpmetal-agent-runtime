package main

import (
	"context"
	"testing"

	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/boxcredentials"
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
