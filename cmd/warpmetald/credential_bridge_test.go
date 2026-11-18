package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/config"
)

func TestToolCredentialBridgeDisabledConfigIsInert(t *testing.T) {
	tests := []struct {
		name   string
		bridge *config.ToolCredentialBridgeConfig
	}{
		{name: "absent config field"},
		{name: "explicitly disabled", bridge: &config.ToolCredentialBridgeConfig{Enabled: false}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			defer server.Close()
			stateRoot := t.TempDir()
			settings := config.Config{
				APIOrigin:            "https://api.example.com",
				ServerID:             "srv_disabled_bridge",
				NodeToken:            "rtn_disabled_bridge",
				ToolCredentialBridge: test.bridge,
			}
			client := control.Client{Origin: server.URL, NodeToken: settings.NodeToken, HTTP: server.Client()}
			bridge, stop, err := startToolCredentialBridge(context.Background(), settings, client, stateRoot, nil)
			if err != nil {
				t.Fatalf("startToolCredentialBridge() error = %v", err)
			}
			if bridge != nil {
				t.Fatal("disabled credential bridge constructed a manager")
			}
			time.Sleep(50 * time.Millisecond)
			stop()
			if requests.Load() != 0 {
				t.Fatalf("disabled credential bridge made %d control-plane requests", requests.Load())
			}
			entries, err := os.ReadDir(stateRoot)
			if err != nil {
				t.Fatalf("read state root: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf("disabled credential bridge created state entries: %v", entries)
			}
		})
	}
}

func TestToolCredentialBridgeEnabledConfigRequiresUsableOptions(t *testing.T) {
	settings := config.Config{
		APIOrigin:            "https://api.example.com",
		ServerID:             "srv_enabled_bridge",
		NodeToken:            "rtn_enabled_bridge",
		ToolCredentialBridge: &config.ToolCredentialBridgeConfig{Enabled: true},
	}
	client := control.Client{Origin: "https://api.example.com", NodeToken: settings.NodeToken}
	if _, _, err := startToolCredentialBridge(context.Background(), settings, client, "", nil); err == nil {
		t.Fatal("enabled credential bridge accepted an empty state directory")
	}
}
