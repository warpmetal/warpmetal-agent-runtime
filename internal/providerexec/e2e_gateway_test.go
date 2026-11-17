package providerexec_test

// This file is the Phase P4a end-to-end boundary test: a real Unix-socket
// provider gateway serves a real MCP client, delegates declared tool calls to a
// fake external executor command through internal/providerexec, and never lets an
// undeclared tool reach the executor. The fake command is a shell script, so no
// network and no real provider is involved.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerexec"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providergateway"
)

const (
	e2eSecret         = "e2e-gateway-secret-canary-4f81"
	e2eProviderID     = "github"
	e2eConnectionID   = "conn_e2e0000000000000001"
	e2eAccountID      = "acct_e2e0000000000000001"
	e2eToolName       = "echo"
	e2eCredentialKind = "oauth2"
)

// e2eCredential is a destroy-observable credential double with the same contract
// as *boxcredentials.Credential, including the optional material-kind extension.
type e2eCredential struct {
	mu           sync.Mutex
	destroyCount int
}

func (c *e2eCredential) SecretFields() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.destroyCount > 0 {
		return map[string]string{}
	}
	return map[string]string{"token": e2eSecret}
}

func (c *e2eCredential) Destroy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.destroyCount++
}

// CredentialKind implements providergateway.CredentialDescription.
func (c *e2eCredential) CredentialKind() string {
	return e2eCredentialKind
}

func (c *e2eCredential) destroys() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.destroyCount
}

// e2eLogBuffer is a concurrency-safe log sink.
type e2eLogBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *e2eLogBuffer) Write(payload []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(payload)
}

func (b *e2eLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

// e2eTempDir returns a short owner-only directory: Unix socket paths are
// length-limited on Darwin.
func e2eTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "pex-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

// writeE2ECommand writes an executable fake external provider executor.
func writeE2ECommand(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(e2eTempDir(t), "provider-exec")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write fake provider executor: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod fake provider executor: %v", err)
	}
	return path
}

// e2eGateway bundles one running gateway and its assertions handles.
type e2eGateway struct {
	t          *testing.T
	gateway    *providergateway.Gateway
	socketPath string
	credential *e2eCredential
	logs       *e2eLogBuffer
	cancel     context.CancelFunc
	serveDone  chan error
}

func startE2EGateway(t *testing.T, command string, args []string, toolTimeout time.Duration) *e2eGateway {
	t.Helper()
	logs := &e2eLogBuffer{}
	executor, err := providerexec.New(
		providerexec.Config{Command: command, Args: args, TimeoutSeconds: int(toolTimeout / time.Second)},
		log.New(logs, "", 0),
	)
	if err != nil {
		t.Fatalf("construct provider executor: %v", err)
	}
	root := e2eTempDir(t)
	socketPath := filepath.Join(root, "gateway.sock")
	credential := &e2eCredential{}
	gateway, err := providergateway.New(providergateway.Config{
		SocketPath:   socketPath,
		ProviderID:   e2eProviderID,
		ConnectionID: e2eConnectionID,
		AccountID:    e2eAccountID,
		Tools: []providergateway.Tool{{
			Name:        e2eToolName,
			Description: "Echo one fake provider value.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`),
		}},
		Executor:    executor,
		Credential:  credential,
		Logger:      log.New(logs, "", 0),
		ToolTimeout: toolTimeout,
	})
	if err != nil {
		t.Fatalf("construct provider gateway: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	running := &e2eGateway{
		t:          t,
		gateway:    gateway,
		socketPath: socketPath,
		credential: credential,
		logs:       logs,
		cancel:     cancel,
		serveDone:  make(chan error, 1),
	}
	go func() { running.serveDone <- gateway.Serve(ctx) }()
	waitForE2ESocket(t, socketPath)
	t.Cleanup(running.stop)
	return running
}

// stop tears the gateway down once and verifies Serve returned cleanly.
func (g *e2eGateway) stop() {
	if g.cancel == nil {
		return
	}
	g.cancel()
	g.cancel = nil
	_ = g.gateway.Close()
	select {
	case err := <-g.serveDone:
		if err != nil {
			g.t.Errorf("provider gateway Serve returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		g.t.Errorf("provider gateway Serve did not return after teardown")
	}
}

func waitForE2ESocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("gateway socket %q did not become ready", path)
}

// e2eClient is a minimal newline-delimited JSON-RPC client.
type e2eClient struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
}

func dialE2E(t *testing.T, socketPath string) *e2eClient {
	t.Helper()
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		t.Fatalf("dial provider gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &e2eClient{t: t, conn: conn, reader: bufio.NewReader(conn)}
}

func (c *e2eClient) request(id int64, method string, params any) map[string]json.RawMessage {
	c.t.Helper()
	payload := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		payload["params"] = params
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		c.t.Fatalf("encode request: %v", err)
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		c.t.Fatalf("set write deadline: %v", err)
	}
	if _, err := c.conn.Write(append(encoded, '\n')); err != nil {
		c.t.Fatalf("write request: %v", err)
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		c.t.Fatalf("set read deadline: %v", err)
	}
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("read response: %v", err)
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(line), &response); err != nil {
		c.t.Fatalf("decode response %q: %v", line, err)
	}
	return response
}

// callTool performs one tools/call and returns its MCP result or JSON-RPC error.
func (c *e2eClient) callTool(id int64, name string) (text string, isError bool, rpcMessage string) {
	c.t.Helper()
	response := c.request(id, "tools/call", map[string]any{
		"name":      name,
		"arguments": map[string]any{"q": "hello"},
	})
	if raw, ok := response["error"]; ok {
		var rpcError struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(raw, &rpcError); err != nil {
			c.t.Fatalf("decode JSON-RPC error: %v", err)
		}
		return "", false, rpcError.Message
	}
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(response["result"], &result); err != nil {
		c.t.Fatalf("decode tool result: %v", err)
	}
	if len(result.Content) != 1 || result.Content[0].Type != "text" {
		c.t.Fatalf("unexpected tool content: %+v", result.Content)
	}
	return result.Content[0].Text, result.IsError, ""
}

func waitForE2EFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("file %q did not appear", path)
}

func waitForE2EPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data))); parseErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pid file %q did not appear", path)
	return 0
}

func requireE2EProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child process %d survived gateway teardown", pid)
}

// TestProviderGatewayDelegatesToolsToExternalExecutor is the P4a end-to-end
// journey: a real Unix-socket MCP client lists and calls a declared tool, the
// gateway delegates to the configured external command, the command receives the
// per-call credential through stdin only, an undeclared tool never reaches the
// command, and the credential is destroyed exactly once at teardown.
func TestProviderGatewayDelegatesToolsToExternalExecutor(t *testing.T) {
	counter := filepath.Join(e2eTempDir(t), "invocations")
	command := writeE2ECommand(t, `request="$(cat)"
printf 'invoked\n' >> "$1"
result="echo-missing-credential"
case "$request" in
  *'"kind":"`+e2eCredentialKind+`"'*)
    case "$request" in
      *'"token":"`+e2eSecret+`"'*) result="echo-ok" ;;
    esac
    ;;
esac
printf '{"formatVersion":1,"content":[{"type":"text","text":"%s"}],"isError":false}\n' "$result"
`)
	running := startE2EGateway(t, command, []string{counter}, 30*time.Second)
	client := dialE2E(t, running.socketPath)

	// tools/list advertises the declared tool through the real MCP surface.
	listResponse := client.request(1, "tools/list", nil)
	var listResult struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(listResponse["result"], &listResult); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	if len(listResult.Tools) != 1 || listResult.Tools[0].Name != e2eToolName {
		t.Fatalf("tools/list = %+v, want just %q", listResult.Tools, e2eToolName)
	}

	// A declared tool call reaches the external command, which proves it saw the
	// per-call credential snapshot.
	text, isError, _ := client.callTool(2, e2eToolName)
	if isError {
		t.Fatalf("declared tool call returned isError: %q", text)
	}
	if text != "echo-ok" {
		t.Fatalf("external executor result = %q, want %q", text, "echo-ok")
	}

	// An undeclared tool is rejected by the gateway and never reaches the
	// external command.
	_, _, rpcMessage := client.callTool(3, "admin")
	if !strings.Contains(rpcMessage, "unknown tool") {
		t.Fatalf("undeclared tool JSON-RPC error = %q, want an unknown-tool error", rpcMessage)
	}
	invocations, err := os.ReadFile(counter)
	if err != nil {
		t.Fatalf("read invocation counter: %v", err)
	}
	if got := strings.Count(string(invocations), "invoked"); got != 1 {
		t.Fatalf("external executor invocations = %d, want 1", got)
	}

	// Nothing sensitive may appear in a response or a gateway/executor log.
	requireE2ENoSecret(t, "gateway response", text)
	requireE2ENoSecret(t, "gateway logs", running.logs.String())

	// Teardown destroys the opened credential exactly once.
	running.stop()
	if destroys := running.credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d, want 1", destroys)
	}
}

// TestProviderGatewayTeardownCancelsInFlightExternalCall proves Runtime shutdown
// cancels external executor calls: the whole child process group is killed and
// the credential is still destroyed exactly once.
func TestProviderGatewayTeardownCancelsInFlightExternalCall(t *testing.T) {
	base := filepath.Join(e2eTempDir(t), "slow")
	command := writeE2ECommand(t, `: > "$1"
echo $$ > "$1.pid"
sleep 60
`)
	running := startE2EGateway(t, command, []string{base}, 30*time.Second)
	client := dialE2E(t, running.socketPath)
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + e2eToolName + `","arguments":{}}}` + "\n")
	if err := client.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := client.conn.Write(payload); err != nil {
		t.Fatalf("write tool call: %v", err)
	}
	waitForE2EFile(t, base)
	pid := waitForE2EPID(t, base+".pid")

	// Shutdown: the Serve context is cancelled, which cancels the in-flight
	// executor call and kills the external command's process group.
	running.stop()
	requireE2EProcessGone(t, pid)
	if destroys := running.credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d, want 1", destroys)
	}
}

func requireE2ENoSecret(t *testing.T, label, payload string) {
	t.Helper()
	if strings.Contains(payload, e2eSecret) {
		t.Fatalf("%s leaked the credential secret", label)
	}
}
