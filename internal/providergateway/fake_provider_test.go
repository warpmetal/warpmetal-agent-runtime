package providergateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Non-secret test metadata for the fake provider. The secret sentinel below is
// only ever placed in the fake credential; no permitted Executor path can see
// it, so its absence from responses and logs is the leak assertion.
const (
	fakeProviderID    = "github"
	fakeConnectionID  = "conn_fakeconnection0001"
	fakeReadToolName  = "fake_read"
	fakeWriteToolName = "fake_write"
	fakeSecret        = "pgw-test-secret-canary-6f3a9d"
	fakeReadMarker    = "fake-read-marker"
	fakeWriteMarker   = "fake-write-marker"
)

// fakeTools is the declared tool list the fake provider implements: one read
// and one write. The gateway is configured with exactly these in tests.
func fakeTools() []Tool {
	return []Tool{
		{
			Name:        fakeReadToolName,
			Description: "Read fake provider data for gateway tests.",
			InputSchema: json.RawMessage(
				`{"type":"object","properties":{"path":{"type":"string"}},"additionalProperties":false}`,
			),
		},
		{
			Name:        fakeWriteToolName,
			Description: "Write fake provider data for gateway tests.",
			InputSchema: json.RawMessage(
				`{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}`,
			),
		},
	}
}

// fakeProvider is the test double for a real provider client. It is built from
// non-secret metadata only and receives no credential from the gateway: the
// Executor interface has no credential parameter, so a fake_read result can
// never contain credential material. Its results carry only the provider id,
// the connection id and a fixed marker.
type fakeProvider struct {
	providerID   string
	connectionID string
	readDelay    time.Duration
	// allowUndeclared makes the provider implement names it was not declared
	// with, so tests can prove the gateway rejects them without invoking the
	// provider at all.
	allowUndeclared bool

	mu    sync.Mutex
	calls []string
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{providerID: fakeProviderID, connectionID: fakeConnectionID}
}

// CallTool implements Executor.
func (f *fakeProvider) CallTool(ctx context.Context, call ToolCall) (ToolResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, call.Name)
	f.mu.Unlock()

	if f.readDelay > 0 {
		timer := time.NewTimer(f.readDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ToolResult{}, ctx.Err()
		case <-timer.C:
		}
	}

	switch call.Name {
	case fakeReadToolName:
		return ToolResult{
			Text: "provider=" + f.providerID + " connection=" + f.connectionID + " marker=" + fakeReadMarker,
		}, nil
	case fakeWriteToolName:
		return ToolResult{Text: "marker=" + fakeWriteMarker}, nil
	}
	if f.allowUndeclared {
		return ToolResult{Text: "marker=" + fakeReadMarker}, nil
	}
	return ToolResult{}, fmt.Errorf("fake provider does not implement tool %q", call.Name)
}

func (f *fakeProvider) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeProvider) callNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// fakeCredential is the destroy-observable credential double. The real
// *boxcredentials.Credential cannot be constructed outside its package with
// secret material, so tests use this to hold a known sentinel and count Destroy.
type fakeCredential struct {
	mu           sync.Mutex
	secret       string
	destroyCount int
}

func newFakeCredential(secret string) *fakeCredential {
	return &fakeCredential{secret: secret}
}

// SecretFields implements Credential.
func (c *fakeCredential) SecretFields() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.destroyCount > 0 {
		return map[string]string{}
	}
	return map[string]string{"token": c.secret}
}

// Destroy implements Credential.
func (c *fakeCredential) Destroy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.destroyCount++
	c.secret = ""
}

func (c *fakeCredential) destroys() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.destroyCount
}

// leakyExecutor deliberately returns the credential secret both as tool output
// and inside an error. It is strictly worse than any real provider (which has
// no way to obtain the secret through the Executor interface); the gateway must
// still redact it from responses and logs.
type leakyExecutor struct {
	secret string
}

// CallTool implements Executor.
func (l leakyExecutor) CallTool(_ context.Context, call ToolCall) (ToolResult, error) {
	switch call.Name {
	case fakeReadToolName:
		return ToolResult{Text: "result token=" + l.secret}, nil
	case fakeWriteToolName:
		return ToolResult{}, fmt.Errorf("upstream rejected token %s", l.secret)
	default:
		return ToolResult{}, fmt.Errorf("leaky executor does not implement tool %q", call.Name)
	}
}

// blockingExecutor blocks until its context is cancelled, which is how the
// gateway's per-call timeout and shutdown cancellation are exercised.
type blockingExecutor struct {
	started  chan struct{}
	finished chan struct{}
	once     sync.Once
}

func newBlockingExecutor() *blockingExecutor {
	return &blockingExecutor{started: make(chan struct{}), finished: make(chan struct{})}
}

// CallTool implements Executor.
func (b *blockingExecutor) CallTool(ctx context.Context, _ ToolCall) (ToolResult, error) {
	defer close(b.finished)
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return ToolResult{}, ctx.Err()
}

// hugeExecutor returns more text than the gateway allows through, to prove that
// results are truncated and responses stay bounded.
type hugeExecutor struct {
	text string
}

// CallTool implements Executor.
func (h hugeExecutor) CallTool(context.Context, ToolCall) (ToolResult, error) {
	return ToolResult{Text: h.text}, nil
}

// panicExecutor panics with the credential-like sentinel to prove the gateway
// neither forwards nor logs recovered panic values.
type panicExecutor struct {
	sentinel string
}

// CallTool implements Executor.
func (p panicExecutor) CallTool(context.Context, ToolCall) (ToolResult, error) {
	panic(p.sentinel)
}

// logBuffer is a concurrency-safe log sink for assertions about log content.
type logBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *logBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}
