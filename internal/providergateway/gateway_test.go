package providergateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestProviderGatewayServesDeclaredToolsOverUnixSocket is the end-to-end
// journey: a real client dials the real Unix socket and exercises the whole MCP
// subset, the tool allowlist, redaction and the credential lifetime.
func TestProviderGatewayServesDeclaredToolsOverUnixSocket(t *testing.T) {
	root := testTempDir(t)
	socketPath := filepath.Join(root, "gateway.sock")
	fixture := newGatewayFixture(socketPath, root)
	running := startGateway(t, fixture.config)

	requireMode(t, socketPath, 0o600)
	requireMode(t, root, 0o700)

	client := dialRPC(t, socketPath)

	// initialize: a supported version is echoed, only the tools capability is
	// advertised, and the server identifies itself.
	initializeResponse := client.request(initializeMethod, map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "pgw-test-client", "version": "1"},
	})
	var initialized struct {
		ProtocolVersion string                     `json:"protocolVersion"`
		Capabilities    map[string]json.RawMessage `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(initializeResponse.Result, &initialized); err != nil {
		t.Fatalf("decode initialize result: %v", err)
	}
	if initialized.ProtocolVersion != "2025-03-26" {
		t.Fatalf("protocolVersion = %q, want the supported requested version", initialized.ProtocolVersion)
	}
	if len(initialized.Capabilities) != 1 {
		t.Fatalf("capabilities = %v, want only tools", initialized.Capabilities)
	}
	if _, ok := initialized.Capabilities["tools"]; !ok {
		t.Fatalf("capabilities = %v, want a tools entry", initialized.Capabilities)
	}
	if initialized.ServerInfo.Name != ServerName || initialized.ServerInfo.Version != ServerVersion {
		t.Fatalf("serverInfo = %+v", initialized.ServerInfo)
	}

	// notifications/initialized must not be answered: the next line read must be
	// the ping response, not a stray response with another id.
	client.notify(initializedNotificationMethod, nil)
	pingResult := decodeResult[map[string]json.RawMessage](t, client.request(pingMethod, nil))
	if len(pingResult) != 0 {
		t.Fatalf("ping result = %v, want an empty object", pingResult)
	}

	// tools/list must be exactly the declared tools, with their schemas.
	listResult := decodeResult[toolsListResult](t, client.request(toolsListMethod, nil))
	if !reflect.DeepEqual(listResult.Tools, fixture.config.Tools) {
		t.Fatalf("tools/list = %+v, want exactly the declared tools %+v", listResult.Tools, fixture.config.Tools)
	}

	// tools/call reaches the fake provider; the result carries only non-secret
	// metadata and the marker, and the argument canary is never logged.
	argumentCanary := "argument-canary-2c94"
	readResult := decodeToolCallResult(t, client.callTool(fakeReadToolName, map[string]any{
		"path": "/canary/" + argumentCanary,
	}))
	requireContains(t, readResult.Content[0].Text, fakeProviderID, "fake_read result")
	requireContains(t, readResult.Content[0].Text, fakeConnectionID, "fake_read result")
	requireContains(t, readResult.Content[0].Text, fakeReadMarker, "fake_read result")
	requireNotContains(t, readResult.Content[0].Text, fakeSecret, "fake_read result")
	if readResult.IsError {
		t.Fatalf("fake_read result unexpectedly isError")
	}

	writeResult := decodeToolCallResult(t, client.callTool(fakeWriteToolName, map[string]any{
		"value": "write-canary-8a1f",
	}))
	requireContains(t, writeResult.Content[0].Text, fakeWriteMarker, "fake_write result")
	requireNotContains(t, writeResult.Content[0].Text, fakeSecret, "fake_write result")
	if writeResult.IsError {
		t.Fatalf("fake_write result unexpectedly isError")
	}
	if calls := fixture.provider.callCount(); calls != 2 {
		t.Fatalf("executor call count = %d, want 2", calls)
	}

	// Unknown methods and unknown tool names are rejected without reaching the
	// executor.
	requireRPCError(t, client.request("tools/delete", nil), codeMethodNotFound)
	unknownToolResponse := client.callTool("fake_admin", map[string]any{})
	unknownToolError := requireRPCError(t, unknownToolResponse, codeInvalidParams)
	requireContains(t, unknownToolError.Message, "unknown tool", "unknown tool error")
	if calls := fixture.provider.callCount(); calls != 2 {
		t.Fatalf("executor was invoked for an undeclared tool: call count %d", calls)
	}

	// A client asking for an unsupported version gets the default instead of an
	// error.
	unsupportedClient := dialRPC(t, socketPath)
	unsupported := unsupportedClient.initialize("9999-01-01")
	if unsupported.ProtocolVersion != DefaultProtocolVersion {
		t.Fatalf("unsupported protocolVersion negotiated to %q, want %q", unsupported.ProtocolVersion, DefaultProtocolVersion)
	}

	// Nothing sensitive or argument/result-shaped may reach the log.
	logs := fixture.logs.String()
	requireContains(t, logs, fakeProviderID, "gateway log")
	requireNotContains(t, logs, fakeSecret, "gateway log")
	requireNotContains(t, logs, argumentCanary, "gateway log")
	requireNotContains(t, logs, "write-canary-8a1f", "gateway log")
	requireNotContains(t, logs, fakeReadMarker, "gateway log")

	// Close: Serve returns cleanly, the socket disappears, no further
	// connections are accepted and the credential is destroyed exactly once.
	running.stop()
	requireSocketGone(t, socketPath)
	requireDialFails(t, socketPath)
	if destroys := fixture.credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d, want 1", destroys)
	}
}

// TestProviderGatewayCloseLifecycle covers Close before Serve, idempotent Close,
// Serve being single-use, active connections being closed, and context
// cancellation as the alternative stop signal.
func TestProviderGatewayCloseLifecycle(t *testing.T) {
	t.Run("close before serve destroys credential and closes gateway", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "gateway.sock")
		fixture := newGatewayFixture(socketPath, root)
		gateway, err := New(fixture.config)
		if err != nil {
			t.Fatalf("new gateway: %v", err)
		}
		if err := gateway.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if err := gateway.Close(); err != nil {
			t.Fatalf("second close: %v", err)
		}
		if destroys := fixture.credential.destroys(); destroys != 1 {
			t.Fatalf("credential destroy count = %d, want 1", destroys)
		}
		if err := gateway.Serve(context.Background()); !errors.Is(err, errGatewayClosed) {
			t.Fatalf("Serve after Close error = %v, want errGatewayClosed", err)
		}
		requireSocketGone(t, socketPath)
		if destroys := fixture.credential.destroys(); destroys != 1 {
			t.Fatalf("credential destroy count = %d after Serve, want 1", destroys)
		}
	})

	t.Run("close closes active connections and removes socket", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "gateway.sock")
		fixture := newGatewayFixture(socketPath, root)
		running := startGateway(t, fixture.config)

		conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
		if err != nil {
			t.Fatalf("dial gateway: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")); err != nil {
			t.Fatalf("write ping: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		buffer := make([]byte, 256)
		if _, err := conn.Read(buffer); err != nil {
			t.Fatalf("read ping response: %v", err)
		}

		running.stop()
		requireSocketGone(t, socketPath)
		requireDialFails(t, socketPath)
		if destroys := fixture.credential.destroys(); destroys != 1 {
			t.Fatalf("credential destroy count = %d, want 1", destroys)
		}

		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		if _, err := conn.Read(buffer); err == nil {
			t.Fatalf("active connection still returned data after Close")
		}
	})

	t.Run("close cancels in-flight executor calls", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "gateway.sock")
		blocking := newBlockingExecutor()
		fixture := newGatewayFixture(socketPath, root)
		fixture.config.Executor = blocking
		fixture.config.ToolTimeout = time.Minute
		running := startGateway(t, fixture.config)

		conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
		if err != nil {
			t.Fatalf("dial gateway: %v", err)
		}
		defer conn.Close()
		request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + fakeReadToolName + `","arguments":{}}}` + "\n"
		if _, err := conn.Write([]byte(request)); err != nil {
			t.Fatalf("write tool call: %v", err)
		}
		select {
		case <-blocking.started:
		case <-time.After(5 * time.Second):
			t.Fatalf("executor was never invoked")
		}

		running.stop()
		select {
		case <-blocking.finished:
		case <-time.After(2 * time.Second):
			t.Fatalf("in-flight executor call was not cancelled by Close")
		}
	})

	t.Run("serve is single use", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "gateway.sock")
		fixture := newGatewayFixture(socketPath, root)
		running := startGateway(t, fixture.config)
		if err := running.gateway.Serve(context.Background()); !errors.Is(err, errServeCalled) {
			t.Fatalf("second Serve error = %v, want errServeCalled", err)
		}
	})

	t.Run("context cancellation stops serve and destroys credential", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "gateway.sock")
		fixture := newGatewayFixture(socketPath, root)
		gateway, err := New(fixture.config)
		if err != nil {
			t.Fatalf("new gateway: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- gateway.Serve(ctx) }()
		waitForSocket(t, socketPath)

		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Fatalf("Serve after context cancellation: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Serve did not return after context cancellation")
		}
		requireSocketGone(t, socketPath)
		requireDialFails(t, socketPath)
		if destroys := fixture.credential.destroys(); destroys != 1 {
			t.Fatalf("credential destroy count = %d, want 1", destroys)
		}
		if err := gateway.Close(); err != nil {
			t.Fatalf("Close after cancelled Serve: %v", err)
		}
		if destroys := fixture.credential.destroys(); destroys != 1 {
			t.Fatalf("credential destroy count = %d after Close, want 1", destroys)
		}
	})
}

// TestProviderGatewayRefusesSecondServerOnSameSocket proves a second gateway
// cannot hijack a live socket, and that the first gateway keeps serving.
func TestProviderGatewayRefusesSecondServerOnSameSocket(t *testing.T) {
	root := testTempDir(t)
	socketPath := filepath.Join(root, "gateway.sock")
	first := newGatewayFixture(socketPath, root)
	startGateway(t, first.config)

	second := newGatewayFixture(socketPath, root)
	secondGateway, err := New(second.config)
	if err != nil {
		t.Fatalf("new second gateway: %v", err)
	}
	err = secondGateway.Serve(context.Background())
	if err == nil {
		t.Fatalf("second Serve on a live socket path succeeded")
	}
	requireContains(t, err.Error(), "already in use", "second Serve error")
	if destroys := second.credential.destroys(); destroys != 1 {
		t.Fatalf("second credential destroy count = %d, want 1", destroys)
	}
	if err := secondGateway.Serve(context.Background()); !errors.Is(err, errGatewayClosed) {
		t.Fatalf("second Serve retry error = %v, want errGatewayClosed", err)
	}

	// The first gateway still owns and serves the socket.
	client := dialRPC(t, socketPath)
	decodeResult[map[string]json.RawMessage](t, client.request(pingMethod, nil))
	if first.credential.destroys() != 0 {
		t.Fatalf("first credential was destroyed by the failed second server")
	}
}

// TestProviderGatewaySocketGuardrails covers directory creation, permissions,
// existing-path refusal, symlink handling, root containment and stale socket
// replacement.
func TestProviderGatewaySocketGuardrails(t *testing.T) {
	t.Run("creates owner-only directories and a 0600 socket", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "runtime", "provider", "gateway.sock")
		fixture := newGatewayFixture(socketPath, root)
		startGateway(t, fixture.config)
		requireMode(t, filepath.Join(root, "runtime"), 0o700)
		requireMode(t, filepath.Join(root, "runtime", "provider"), 0o700)
		requireMode(t, socketPath, 0o600)
	})

	t.Run("refuses to overwrite an existing non-socket path", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "gateway.sock")
		if err := os.WriteFile(socketPath, []byte("keep me"), 0o600); err != nil {
			t.Fatalf("write existing file: %v", err)
		}
		fixture := newGatewayFixture(socketPath, root)
		gateway, err := New(fixture.config)
		if err != nil {
			t.Fatalf("new gateway: %v", err)
		}
		err = gateway.Serve(context.Background())
		if err == nil {
			t.Fatalf("Serve overwrote an existing regular file")
		}
		requireContains(t, err.Error(), "refusing to overwrite existing non-socket", "Serve error")
		content, readErr := os.ReadFile(socketPath)
		if readErr != nil {
			t.Fatalf("read existing file after refused Serve: %v", readErr)
		}
		if string(content) != "keep me" {
			t.Fatalf("existing file content = %q, want it untouched", content)
		}
		if destroys := fixture.credential.destroys(); destroys != 1 {
			t.Fatalf("credential destroy count = %d, want 1", destroys)
		}
	})

	t.Run("refuses a symlink at the socket path", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "gateway.sock")
		target := filepath.Join(root, "target")
		if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
			t.Fatalf("write symlink target: %v", err)
		}
		if err := os.Symlink(target, socketPath); err != nil {
			t.Fatalf("symlink socket path: %v", err)
		}
		fixture := newGatewayFixture(socketPath, root)
		gateway, _ := New(fixture.config)
		err := gateway.Serve(context.Background())
		if err == nil {
			t.Fatalf("Serve accepted a symlinked socket path")
		}
		requireContains(t, err.Error(), "symlink", "Serve error")
	})

	t.Run("refuses a symlinked socket directory", func(t *testing.T) {
		root := testTempDir(t)
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatalf("create real directory: %v", err)
		}
		linkDirectory := filepath.Join(root, "link")
		if err := os.Symlink(realDirectory, linkDirectory); err != nil {
			t.Fatalf("symlink socket directory: %v", err)
		}
		socketPath := filepath.Join(linkDirectory, "gateway.sock")
		fixture := newGatewayFixture(socketPath, root)
		gateway, _ := New(fixture.config)
		err := gateway.Serve(context.Background())
		if err == nil {
			t.Fatalf("Serve accepted a symlinked socket directory")
		}
		requireContains(t, err.Error(), "symlink", "Serve error")
	})

	t.Run("refuses a symlink escape from the allowed root", func(t *testing.T) {
		root := testTempDir(t)
		outside := testTempDir(t)
		escape := filepath.Join(root, "escape")
		if err := os.Symlink(outside, escape); err != nil {
			t.Fatalf("symlink escape: %v", err)
		}
		socketPath := filepath.Join(escape, "nested", "gateway.sock")
		fixture := newGatewayFixture(socketPath, root)
		gateway, _ := New(fixture.config)
		err := gateway.Serve(context.Background())
		if err == nil {
			t.Fatalf("Serve accepted a socket path escaping the allowed root")
		}
		requireContains(t, err.Error(), "outside the allowed root", "Serve error")
		if _, statErr := os.Lstat(filepath.Join(outside, "nested")); !os.IsNotExist(statErr) {
			t.Fatalf("gateway created directories outside the allowed root: %v", statErr)
		}
	})

	t.Run("refuses a group-accessible socket directory", func(t *testing.T) {
		root := testTempDir(t)
		runDirectory := filepath.Join(root, "run")
		if err := os.Mkdir(runDirectory, 0o750); err != nil {
			t.Fatalf("create run directory: %v", err)
		}
		if err := os.Chmod(runDirectory, 0o750); err != nil {
			t.Fatalf("chmod run directory: %v", err)
		}
		socketPath := filepath.Join(runDirectory, "gateway.sock")
		fixture := newGatewayFixture(socketPath, root)
		gateway, _ := New(fixture.config)
		err := gateway.Serve(context.Background())
		if err == nil {
			t.Fatalf("Serve accepted a group-accessible socket directory")
		}
		requireContains(t, err.Error(), "owner-only", "Serve error")
	})

	t.Run("refuses a missing allowed root", func(t *testing.T) {
		root := testTempDir(t)
		missingRoot := filepath.Join(root, "missing")
		socketPath := filepath.Join(missingRoot, "gateway.sock")
		fixture := newGatewayFixture(socketPath, missingRoot)
		gateway, _ := New(fixture.config)
		err := gateway.Serve(context.Background())
		if err == nil {
			t.Fatalf("Serve accepted a missing allowed root")
		}
		requireContains(t, err.Error(), "allowed root", "Serve error")
	})

	t.Run("replaces a stale socket from a crashed server", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "gateway.sock")
		staleListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
		if err != nil {
			t.Fatalf("create stale socket: %v", err)
		}
		staleListener.SetUnlinkOnClose(false)
		if err := staleListener.Close(); err != nil {
			t.Fatalf("close stale listener: %v", err)
		}
		if info, err := os.Lstat(socketPath); err != nil || info.Mode()&os.ModeSocket == 0 {
			t.Fatalf("stale socket file missing: %v", err)
		}

		fixture := newGatewayFixture(socketPath, root)
		startGateway(t, fixture.config)
		client := dialRPC(t, socketPath)
		decodeResult[map[string]json.RawMessage](t, client.request(pingMethod, nil))
	})
}

// TestProviderGatewayConfigValidation covers the static Config contract. It
// needs no I/O: New never touches the filesystem.
func TestProviderGatewayConfigValidation(t *testing.T) {
	validConfig := func() Config {
		return Config{
			SocketPath:   "/run/warpmetal/provider/gateway.sock",
			RootDir:      "/run/warpmetal/provider",
			ProviderID:   fakeProviderID,
			ConnectionID: fakeConnectionID,
			Tools:        fakeTools(),
			Executor:     newFakeProvider(),
		}
	}
	if _, err := New(validConfig()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "missing socket path", mutate: func(c *Config) { c.SocketPath = "" }, want: "socket path is required"},
		{name: "relative socket path", mutate: func(c *Config) { c.SocketPath = "gateway.sock" }, want: "must be absolute"},
		{name: "unclean socket path", mutate: func(c *Config) { c.SocketPath = "/run/warpmetal/../gateway.sock" }, want: "clean path"},
		{name: "relative root", mutate: func(c *Config) { c.RootDir = "run" }, want: "root directory must be absolute"},
		{name: "unclean root", mutate: func(c *Config) { c.RootDir = "/run/../run" }, want: "root directory must be a clean path"},
		{name: "missing provider id", mutate: func(c *Config) { c.ProviderID = "" }, want: "provider id is required"},
		{name: "provider id with whitespace", mutate: func(c *Config) { c.ProviderID = "git hub" }, want: "must not contain whitespace"},
		{name: "missing connection id", mutate: func(c *Config) { c.ConnectionID = "" }, want: "connection id is required"},
		{name: "nil executor", mutate: func(c *Config) { c.Executor = nil }, want: "executor is required"},
		{name: "no declared tools", mutate: func(c *Config) { c.Tools = nil }, want: "at least one declared tool"},
		{name: "duplicate tool names", mutate: func(c *Config) {
			c.Tools = append(c.Tools, c.Tools[0])
		}, want: "duplicate declared tool"},
		{name: "invalid tool name", mutate: func(c *Config) {
			c.Tools = []Tool{{Name: "bad name", InputSchema: json.RawMessage(`{"type":"object"}`)}}
		}, want: "invalid name"},
		{name: "missing input schema", mutate: func(c *Config) {
			c.Tools = []Tool{{Name: "tool"}}
		}, want: "no input schema"},
		{name: "invalid schema JSON", mutate: func(c *Config) {
			c.Tools = []Tool{{Name: "tool", InputSchema: json.RawMessage(`{not json`)}}
		}, want: "not valid JSON"},
		{name: "non-object schema", mutate: func(c *Config) {
			c.Tools = []Tool{{Name: "tool", InputSchema: json.RawMessage(`[1,2,3]`)}}
		}, want: "must be a JSON object"},
		{name: "null schema", mutate: func(c *Config) {
			c.Tools = []Tool{{Name: "tool", InputSchema: json.RawMessage(`null`)}}
		}, want: "must be a JSON object"},
		{name: "too many tools", mutate: func(c *Config) {
			tools := make([]Tool, 0, maxDeclaredTools+1)
			for index := 0; index <= maxDeclaredTools; index++ {
				tools = append(tools, Tool{
					Name:        fmt.Sprintf("tool_%03d", index),
					InputSchema: json.RawMessage(`{"type":"object"}`),
				})
			}
			c.Tools = tools
		}, want: "at most"},
		{name: "oversized schema", mutate: func(c *Config) {
			c.Tools = []Tool{{
				Name:        "tool",
				InputSchema: json.RawMessage(`{"type":"object","description":"` + strings.Repeat("a", maxToolSchemaBytes) + `"}`),
			}}
		}, want: "schema is too large"},
		{name: "negative tool timeout", mutate: func(c *Config) { c.ToolTimeout = -time.Second }, want: "must not be negative"},
		{name: "huge tool timeout", mutate: func(c *Config) { c.ToolTimeout = maxToolTimeout + time.Second }, want: "must not exceed"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := validConfig()
			testCase.mutate(&config)
			_, err := New(config)
			if err == nil {
				t.Fatalf("New accepted invalid config")
			}
			requireContains(t, err.Error(), testCase.want, "New error")
		})
	}

	// Config renders only non-secret metadata, so it is safe to log.
	config := validConfig()
	config.Credential = newFakeCredential(fakeSecret)
	rendered := fmt.Sprintf("%v %#v %+v %s %d", config, config, config, config, config)
	requireNotContains(t, rendered, fakeSecret, "rendered Config")
	requireContains(t, rendered, fakeProviderID, "rendered Config")
}
