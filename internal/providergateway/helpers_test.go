package providergateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// gatewayFixture bundles the usual valid gateway inputs plus a captured log
// sink, so tests can assert on secret-free logging.
type gatewayFixture struct {
	config     Config
	logs       *logBuffer
	provider   *fakeProvider
	credential *fakeCredential
}

func newGatewayFixture(socketPath, rootDir string) *gatewayFixture {
	logs := &logBuffer{}
	provider := newFakeProvider()
	credential := newFakeCredential(fakeSecret)
	return &gatewayFixture{
		config: Config{
			SocketPath:   socketPath,
			RootDir:      rootDir,
			ProviderID:   fakeProviderID,
			ConnectionID: fakeConnectionID,
			Tools:        fakeTools(),
			Executor:     provider,
			Credential:   credential,
			Logger:       log.New(logs, "", 0),
		},
		logs:       logs,
		provider:   provider,
		credential: credential,
	}
}

// runningGateway is a gateway whose Serve call runs in the background. Every
// test that starts one must let stop run (normally via t.Cleanup).
type runningGateway struct {
	t          *testing.T
	gateway    *Gateway
	socketPath string
	cancel     context.CancelFunc
	serveDone  chan error

	mu       sync.Mutex
	stopped  bool
	serveErr error
}

// startGateway runs Serve in the background and waits until the socket is
// ready. Cleanup stops it and fails the test if Serve returned an error.
func startGateway(t *testing.T, config Config) *runningGateway {
	t.Helper()
	gateway, err := New(config)
	if err != nil {
		t.Fatalf("new provider gateway: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	running := &runningGateway{
		t:          t,
		gateway:    gateway,
		socketPath: config.SocketPath,
		cancel:     cancel,
		serveDone:  make(chan error, 1),
	}
	go func() { running.serveDone <- gateway.Serve(ctx) }()
	t.Cleanup(running.stop)
	waitForSocket(t, config.SocketPath)
	return running
}

// stop cancels Serve, closes the gateway and waits for Serve to return. It is
// idempotent so cleanup can call it after a test already stopped the gateway.
func (r *runningGateway) stop() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	r.mu.Unlock()

	r.cancel()
	_ = r.gateway.Close()
	select {
	case err := <-r.serveDone:
		if err != nil {
			r.t.Errorf("provider gateway Serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		r.t.Fatalf("provider gateway Serve did not return after Close")
	}
}

// testTempDir returns a short, owner-only temporary directory. The path is kept
// short because Unix socket paths are length-limited on Darwin.
func testTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "pgw-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

// waitForSocket waits until the gateway socket exists with its final 0600 mode.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == socketPermissions {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("socket %q did not become ready", path)
}

// requireSocketGone asserts the socket file was removed.
func requireSocketGone(t *testing.T, path string) {
	t.Helper()
	if info, err := os.Lstat(path); err == nil {
		t.Fatalf("socket %q still exists (mode %v)", path, info.Mode())
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat socket %q: %v", path, err)
	}
}

// requireDialFails asserts no live server answers at path.
func requireDialFails(t *testing.T, path string) {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("expected a connection to %q to fail", path)
	}
}

// requireMode asserts a path's permission bits.
func requireMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%q permissions = %04o, want %04o", path, got, want)
	}
}

// rpcClient is a newline-delimited JSON-RPC client over a real Unix socket. It
// is used from the test goroutine only; the concurrency test speaks the
// protocol directly so it can report errors through channels.
type rpcClient struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
	nextID int64
}

func dialRPC(t *testing.T, socketPath string) *rpcClient {
	t.Helper()
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial provider gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &rpcClient{t: t, conn: conn, reader: bufio.NewReader(conn)}
}

func (c *rpcClient) sendLine(line string) {
	c.t.Helper()
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	if _, err := io.WriteString(c.conn, line); err != nil {
		c.t.Fatalf("write request: %v", err)
	}
}

func (c *rpcClient) readLine(timeout time.Duration) []byte {
	c.t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		c.t.Fatalf("set read deadline: %v", err)
	}
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("read response: %v", err)
	}
	return bytes.TrimSuffix(line, []byte{'\n'})
}

func (c *rpcClient) request(method string, params any) rpcResponse {
	c.t.Helper()
	c.nextID++
	id := c.nextID
	payload := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		payload["params"] = params
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		c.t.Fatalf("encode request: %v", err)
	}
	c.sendLine(string(encoded))
	response := decodeRPCResponse(c.t, c.readLine(5*time.Second))
	var responseID int64
	if err := json.Unmarshal(response.ID, &responseID); err != nil || responseID != id {
		c.t.Fatalf("response id = %s, want %d", response.ID, id)
	}
	return response
}

func (c *rpcClient) notify(method string, params any) {
	c.t.Helper()
	payload := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		payload["params"] = params
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		c.t.Fatalf("encode notification: %v", err)
	}
	c.sendLine(string(encoded))
}

func (c *rpcClient) callTool(name string, arguments any) rpcResponse {
	c.t.Helper()
	params := map[string]any{"name": name}
	if arguments != nil {
		params["arguments"] = arguments
	}
	return c.request(toolsCallMethod, params)
}

func (c *rpcClient) initialize(protocolVersion string) initializeResult {
	c.t.Helper()
	return decodeResult[initializeResult](c.t, c.request(initializeMethod, map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "pgw-test-client", "version": "1"},
	}))
}

// rpcResponse is the wire response shape used by test assertions.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

func decodeRPCResponse(t *testing.T, line []byte) rpcResponse {
	t.Helper()
	var response rpcResponse
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatalf("decode response %q: %v", line, err)
	}
	if response.JSONRPC != jsonRPCVersion {
		t.Fatalf("response jsonrpc = %q, want %q", response.JSONRPC, jsonRPCVersion)
	}
	return response
}

func decodeResult[T any](t *testing.T, response rpcResponse) T {
	t.Helper()
	if response.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: code=%d message=%q", response.Error.Code, response.Error.Message)
	}
	var result T
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("decode result %s: %v", response.Result, err)
	}
	return result
}

func decodeToolCallResult(t *testing.T, response rpcResponse) toolCallResult {
	t.Helper()
	result := decodeResult[toolCallResult](t, response)
	if len(result.Content) != 1 {
		t.Fatalf("tool result content length = %d, want 1", len(result.Content))
	}
	content := result.Content[0]
	if content.Type != "text" {
		t.Fatalf("tool result content type = %q, want text", content.Type)
	}
	return result
}

func requireRPCError(t *testing.T, response rpcResponse, wantCode int) rpcError {
	t.Helper()
	if response.Error == nil {
		t.Fatalf("expected JSON-RPC error %d, got result %s", wantCode, response.Result)
	}
	if response.Error.Code != wantCode {
		t.Fatalf("JSON-RPC error code = %d, want %d (message %q)", response.Error.Code, wantCode, response.Error.Message)
	}
	return *response.Error
}

func requireContains(t *testing.T, haystack, needle, label string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("%s does not contain %q: %q", label, needle, haystack)
	}
}

func requireNotContains(t *testing.T, haystack, needle, label string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Fatalf("%s must not contain %q: %q", label, needle, haystack)
	}
}

// concurrentCall performs one initialize + one fake_read call over a fresh
// connection and validates both responses. It returns errors instead of calling
// t.Fatalf so it is safe to run from goroutines.
func concurrentCall(socketPath string) error {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + fakeReadToolName + `","arguments":{}}}`
	if _, err := io.WriteString(conn, initialize+"\n"+call+"\n"); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	reader := bufio.NewReader(conn)
	for _, wantID := range []int{1, 2} {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("read response %d: %w", wantID, err)
		}
		var response struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   *rpcError       `json:"error"`
		}
		if err := json.Unmarshal(line, &response); err != nil {
			return fmt.Errorf("decode response %d: %w", wantID, err)
		}
		if response.JSONRPC != "2.0" {
			return fmt.Errorf("response %d jsonrpc = %q", wantID, response.JSONRPC)
		}
		var id int
		if err := json.Unmarshal(response.ID, &id); err != nil || id != wantID {
			return fmt.Errorf("response %d id = %s", wantID, response.ID)
		}
		if response.Error != nil {
			return fmt.Errorf("response %d error: %d %s", wantID, response.Error.Code, response.Error.Message)
		}
		if wantID == 2 {
			var result toolCallResult
			if err := json.Unmarshal(response.Result, &result); err != nil {
				return fmt.Errorf("decode tool result: %w", err)
			}
			if len(result.Content) != 1 || !strings.Contains(result.Content[0].Text, fakeReadMarker) {
				return fmt.Errorf("unexpected tool result: %+v", result)
			}
			if result.IsError {
				return fmt.Errorf("tool result unexpectedly isError")
			}
		}
	}
	return nil
}
