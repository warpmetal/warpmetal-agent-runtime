package providergateway

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestProviderGatewayRejectsMalformedAndOversizedRequests covers JSON-RPC
// framing and bounding errors, and proves the connection stays usable after
// each rejected request.
func TestProviderGatewayRejectsMalformedAndOversizedRequests(t *testing.T) {
	root := testTempDir(t)
	socketPath := filepath.Join(root, "gateway.sock")
	fixture := newGatewayFixture(socketPath, root)
	startGateway(t, fixture.config)

	client := dialRPC(t, socketPath)

	// Invalid JSON is a parse error with a null id.
	client.sendLine(`{"jsonrpc":"2.0","id":1,`)
	parseError := decodeRPCResponse(t, client.readLine(5*time.Second))
	if string(parseError.ID) != "null" {
		t.Fatalf("parse error id = %s, want null", parseError.ID)
	}
	requireRPCError(t, parseError, codeParseError)

	// The connection remains usable after a rejected line.
	ping := decodeResult[map[string]json.RawMessage](t, client.request(pingMethod, nil))
	if len(ping) != 0 {
		t.Fatalf("ping result = %v, want empty object", ping)
	}

	// Valid JSON that is not a single request object is an invalid request.
	for _, line := range []string{
		`[{"jsonrpc":"2.0","id":2,"method":"ping"}]`,
		`"hello"`,
		`42`,
		`null`,
	} {
		client.sendLine(line)
		response := decodeRPCResponse(t, client.readLine(5*time.Second))
		requireRPCError(t, response, codeInvalidRequest)
	}

	// A wrong JSON-RPC version or a missing method is an invalid request, while
	// the id is preserved when it is valid.
	client.sendLine(`{"jsonrpc":"1.0","id":3,"method":"ping"}`)
	badVersion := decodeRPCResponse(t, client.readLine(5*time.Second))
	requireRPCError(t, badVersion, codeInvalidRequest)
	if string(badVersion.ID) != "3" {
		t.Fatalf("invalid request id = %s, want 3", badVersion.ID)
	}
	client.sendLine(`{"jsonrpc":"2.0","id":4}`)
	missingMethod := decodeRPCResponse(t, client.readLine(5*time.Second))
	requireRPCError(t, missingMethod, codeInvalidRequest)

	// Invalid shapes for the known methods are invalid params.
	requireRPCError(t, client.request(toolsCallMethod, []any{}), codeInvalidParams)
	requireRPCError(t, client.request(toolsCallMethod, map[string]any{"arguments": map[string]any{}}), codeInvalidParams)
	requireRPCError(t, client.callTool(fakeReadToolName, "not-an-object"), codeInvalidParams)

	// A request line over the size cap is rejected and drained, not buffered.
	client.sendLine(strings.Repeat("a", maxRequestBytes+1))
	oversized := decodeRPCResponse(t, client.readLine(10*time.Second))
	if string(oversized.ID) != "null" {
		t.Fatalf("oversized request id = %s, want null", oversized.ID)
	}
	oversizedError := requireRPCError(t, oversized, codeInvalidRequest)
	requireContains(t, oversizedError.Message, "too large", "oversized error message")

	// The connection recovers after an oversized line.
	ping = decodeResult[map[string]json.RawMessage](t, client.request(pingMethod, nil))
	if len(ping) != 0 {
		t.Fatalf("ping after oversized request = %v, want empty object", ping)
	}

	if fixture.provider.callCount() != 0 {
		t.Fatalf("executor was invoked by rejected requests")
	}
}

// TestProviderGatewayToolScoping proves the declared allowlist is enforced
// before the Executor: an Executor that would happily handle an undeclared tool
// is never consulted.
func TestProviderGatewayToolScoping(t *testing.T) {
	root := testTempDir(t)
	socketPath := filepath.Join(root, "gateway.sock")
	fixture := newGatewayFixture(socketPath, root)
	fixture.config.Tools = fakeTools()[:1] // declare only fake_read
	fixture.provider.allowUndeclared = true
	startGateway(t, fixture.config)

	client := dialRPC(t, socketPath)
	listResult := decodeResult[toolsListResult](t, client.request(toolsListMethod, nil))
	if len(listResult.Tools) != 1 || listResult.Tools[0].Name != fakeReadToolName {
		t.Fatalf("tools/list = %+v, want only %q", listResult.Tools, fakeReadToolName)
	}

	decodeToolCallResult(t, client.callTool(fakeReadToolName, map[string]any{}))
	if calls := fixture.provider.callCount(); calls != 1 {
		t.Fatalf("executor call count = %d, want 1", calls)
	}

	response := client.callTool(fakeWriteToolName, map[string]any{"value": "x"})
	unknownTool := requireRPCError(t, response, codeInvalidParams)
	requireContains(t, unknownTool.Message, "unknown tool", "unknown tool error")
	if calls := fixture.provider.callNames(); len(calls) != 1 || calls[0] != fakeReadToolName {
		t.Fatalf("executor saw undeclared tool calls: %v", calls)
	}
}

// TestProviderGatewayConcurrentCalls runs independent sessions in parallel over
// the real socket. With -race this also covers the shared gateway state.
func TestProviderGatewayConcurrentCalls(t *testing.T) {
	root := testTempDir(t)
	socketPath := filepath.Join(root, "gateway.sock")
	fixture := newGatewayFixture(socketPath, root)
	fixture.provider.readDelay = 10 * time.Millisecond
	startGateway(t, fixture.config)

	const clients = 16
	errorsByClient := make([]error, clients)
	var waitGroup sync.WaitGroup
	for index := 0; index < clients; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			errorsByClient[index] = concurrentCall(socketPath)
		}(index)
	}
	waitGroup.Wait()

	for index, err := range errorsByClient {
		if err != nil {
			t.Fatalf("concurrent client %d: %v", index, err)
		}
	}
	if calls := fixture.provider.callCount(); calls != clients {
		t.Fatalf("executor call count = %d, want %d", calls, clients)
	}
}

// TestProviderGatewayToolTimeout proves a hung executor call is bounded by
// Config.ToolTimeout and reported as a tool-level failure.
func TestProviderGatewayToolTimeout(t *testing.T) {
	root := testTempDir(t)
	socketPath := filepath.Join(root, "gateway.sock")
	blocking := newBlockingExecutor()
	fixture := newGatewayFixture(socketPath, root)
	fixture.config.Executor = blocking
	fixture.config.ToolTimeout = 100 * time.Millisecond
	startGateway(t, fixture.config)

	client := dialRPC(t, socketPath)
	startedAt := time.Now()
	result := decodeToolCallResult(t, client.callTool(fakeReadToolName, map[string]any{}))
	elapsed := time.Since(startedAt)

	select {
	case <-blocking.started:
	default:
		t.Fatalf("executor was never invoked")
	}
	if !result.IsError {
		t.Fatalf("timed out tool result isError = false")
	}
	requireContains(t, result.Content[0].Text, "timed out", "timeout result")
	if elapsed < 80*time.Millisecond {
		t.Fatalf("tool call returned after %s, before the configured timeout", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("tool call took %s, not bounded by the configured timeout", elapsed)
	}
}

// TestProviderGatewayTruncatesLargeResults proves oversized tool output is
// truncated and cannot produce an unbounded response line.
func TestProviderGatewayTruncatesLargeResults(t *testing.T) {
	root := testTempDir(t)
	socketPath := filepath.Join(root, "gateway.sock")
	fixture := newGatewayFixture(socketPath, root)
	fixture.config.Executor = hugeExecutor{text: strings.Repeat("x", 2*maxToolResultBytes)}
	startGateway(t, fixture.config)

	client := dialRPC(t, socketPath)
	response := client.callTool(fakeReadToolName, map[string]any{})
	result := decodeToolCallResult(t, response)
	text := result.Content[0].Text
	if len(text) > maxToolResultBytes+len(truncationMarker) {
		t.Fatalf("tool result text length = %d, want at most %d", len(text), maxToolResultBytes+len(truncationMarker))
	}
	requireContains(t, text, truncationMarker, "truncated tool result")
	if len(response.Result) > maxResponseBytes {
		t.Fatalf("response result length = %d, exceeds wire ceiling", len(response.Result))
	}
}

// TestProviderGatewayRedactsCredentialMaterial uses an adversarial executor that
// returns the credential secret as output and inside an error. The gateway must
// redact it everywhere: content, JSON-RPC errors, panic handling and logs. A
// permitted Executor cannot obtain the secret at all (see fakeProvider), so this
// is a stronger-than-necessary leak test.
func TestProviderGatewayRedactsCredentialMaterial(t *testing.T) {
	t.Run("secret in result and error text is redacted", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "gateway.sock")
		fixture := newGatewayFixture(socketPath, root)
		fixture.config.Executor = leakyExecutor{secret: fakeSecret}
		startGateway(t, fixture.config)

		client := dialRPC(t, socketPath)

		readResult := decodeToolCallResult(t, client.callTool(fakeReadToolName, map[string]any{}))
		requireContains(t, readResult.Content[0].Text, redactedMarker, "redacted tool result")
		requireNotContains(t, readResult.Content[0].Text, fakeSecret, "redacted tool result")

		writeResult := decodeToolCallResult(t, client.callTool(fakeWriteToolName, map[string]any{}))
		if !writeResult.IsError {
			t.Fatalf("failing tool result isError = false")
		}
		requireContains(t, writeResult.Content[0].Text, redactedMarker, "redacted executor error")
		requireNotContains(t, writeResult.Content[0].Text, fakeSecret, "redacted executor error")

		logs := fixture.logs.String()
		requireContains(t, logs, "fake_write", "gateway log")
		requireContains(t, logs, redactedMarker, "gateway log")
		requireNotContains(t, logs, fakeSecret, "gateway log")
	})

	t.Run("panic value is never surfaced or logged", func(t *testing.T) {
		root := testTempDir(t)
		socketPath := filepath.Join(root, "gateway.sock")
		fixture := newGatewayFixture(socketPath, root)
		fixture.config.Executor = panicExecutor{sentinel: fakeSecret}
		startGateway(t, fixture.config)

		client := dialRPC(t, socketPath)
		result := decodeToolCallResult(t, client.callTool(fakeReadToolName, map[string]any{}))
		if !result.IsError {
			t.Fatalf("panicking tool result isError = false")
		}
		requireContains(t, result.Content[0].Text, "failed", "panic result")
		requireNotContains(t, result.Content[0].Text, fakeSecret, "panic result")
		requireNotContains(t, fixture.logs.String(), fakeSecret, "gateway log")
	})
}

// TestProviderGatewayExecutorErrorsAreToolResults also checks the JSON-RPC
// envelope: executor failures are MCP tool results, not JSON-RPC errors, so the
// session remains usable for the next call.
func TestProviderGatewayExecutorErrorsStayToolLevel(t *testing.T) {
	root := testTempDir(t)
	socketPath := filepath.Join(root, "gateway.sock")
	fixture := newGatewayFixture(socketPath, root)
	fixture.config.Executor = leakyExecutor{secret: fakeSecret}
	startGateway(t, fixture.config)

	client := dialRPC(t, socketPath)
	failing := client.callTool(fakeWriteToolName, map[string]any{})
	if failing.Error != nil {
		t.Fatalf("executor failure became a JSON-RPC error: %+v", failing.Error)
	}
	if result := decodeToolCallResult(t, failing); !result.IsError {
		t.Fatalf("executor failure did not set isError")
	}
	// Same session keeps working.
	ping := decodeResult[map[string]json.RawMessage](t, client.request(pingMethod, nil))
	if len(ping) != 0 {
		t.Fatalf("ping after executor failure = %v, want empty object", ping)
	}
}
