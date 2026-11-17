package providergateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	managerSandboxID = "sbx_manager0001"
	managerRunID     = "run_manager0001"
	managerAccountID = "acct_manager0001"
)

// managerTempDir returns a short workspace root. The gateway socket path adds
// the fixed .warpmetal/provider-gateways prefix plus the run id, and Unix socket
// paths are limited to 104 bytes on Darwin, so a manager test workspace root
// must stay shorter than the default temp directory.
func managerTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "pgm-")
	if err != nil {
		t.Fatalf("create short temp workspace root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

// newManagerRequest builds a valid manager request for one workspace.
func newManagerRequest(workspaceRoot, sandboxID, runID string) Request {
	return Request{
		SandboxID:         sandboxID,
		RunID:             runID,
		WorkspaceHostRoot: workspaceRoot,
		ProviderID:        fakeProviderID,
		ConnectionID:      fakeConnectionID,
		AccountID:         managerAccountID,
		Tools:             fakeTools(),
		Executor:          newFakeProvider(),
		Credential:        newFakeCredential(fakeSecret),
	}
}

type managerFixture struct {
	t             *testing.T
	manager       *Manager
	logs          *logBuffer
	workspaceRoot string
}

func newManagerFixture(t *testing.T) *managerFixture {
	t.Helper()
	logs := &logBuffer{}
	fixture := &managerFixture{
		t:             t,
		manager:       NewManager(log.New(logs, "", 0)),
		logs:          logs,
		workspaceRoot: managerTempDir(t),
	}
	t.Cleanup(func() {
		if err := fixture.manager.Close(context.Background()); err != nil {
			t.Errorf("close provider gateway manager: %v", err)
		}
	})
	return fixture
}

func (f *managerFixture) request(runID string) Request {
	return newManagerRequest(f.workspaceRoot, managerSandboxID, runID)
}

type startedGateway struct {
	handle     *Handle
	provider   *fakeProvider
	credential *fakeCredential
}

func (f *managerFixture) start(request Request) startedGateway {
	f.t.Helper()
	handle, err := f.manager.Start(context.Background(), request)
	if err != nil {
		f.t.Fatalf("start provider gateway: %v", err)
	}
	started := startedGateway{handle: handle}
	started.provider, _ = request.Executor.(*fakeProvider)
	started.credential, _ = request.Credential.(*fakeCredential)
	return started
}

// startFor starts a gateway for an explicit sandbox and run id.
func (f *managerFixture) startFor(workspaceRoot, sandboxID, runID string) startedGateway {
	f.t.Helper()
	return f.start(newManagerRequest(workspaceRoot, sandboxID, runID))
}

func waitHandleDone(t *testing.T, handle *Handle) {
	t.Helper()
	select {
	case <-handle.Done():
	case <-time.After(5 * time.Second):
		t.Fatalf("provider gateway handle did not finish cleanup")
	}
}

func requireGatewayDirGone(t *testing.T, workspaceRoot string) {
	t.Helper()
	path := filepath.Join(workspaceRoot, gatewayRelativeDir)
	if info, err := os.Lstat(path); err == nil {
		t.Fatalf("gateway directory %q still exists after close (mode %v)", path, info.Mode())
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat gateway directory %q: %v", path, err)
	}
}

func requireBoundedError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error")
	}
	if len(err.Error()) > 1024 {
		t.Fatalf("error is not bounded: %d bytes", len(err.Error()))
	}
	requireNotContains(t, err.Error(), fakeSecret, "error")
}

// requireStartRejected asserts a Start call failed safely: an error, an optional
// message fragment, a bounded and secret-free error, and a credential destroyed
// exactly once.
func requireStartRejected(t *testing.T, handle *Handle, err error, request Request, wantContains string) {
	t.Helper()
	if handle != nil {
		t.Fatalf("Start returned a handle together with an error")
	}
	if err == nil {
		t.Fatalf("Start accepted an invalid request")
	}
	requireBoundedError(t, err)
	if wantContains != "" {
		requireContains(t, err.Error(), wantContains, "start error")
	}
	if credential, ok := request.Credential.(*fakeCredential); ok {
		if destroys := credential.destroys(); destroys != 1 {
			t.Fatalf("credential destroy count = %d, want 1", destroys)
		}
	}
}

// requireNoLeakedGoroutines waits for the goroutine count to return to the
// baseline captured before the test started any gateway. The gateway cleanup is
// asynchronous by design (a serve supervisor still has to close Done), so this
// polls briefly instead of asserting an immediate count.
func requireNoLeakedGoroutines(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if current := runtime.NumGoroutine(); current <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine count = %d after teardown, want <= baseline %d", runtime.NumGoroutine(), baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// dialAndPing proves the gateway socket is live and answers one JSON-RPC
// request.
func dialAndPing(t *testing.T, socketPath string) {
	t.Helper()
	client := dialRPC(t, socketPath)
	decodeResult[map[string]json.RawMessage](t, client.request(pingMethod, nil))
}

// TestManagerStartsGatewayOverDeterministicUnixSocket is the manager's end-to-end
// journey: a real Unix socket under the sandbox workspace, the declared fake
// tools served to a real client, secret-free logs/diagnostics, and Close
// removing the socket and the owned run directory while destroying the
// credential exactly once.
func TestManagerStartsGatewayOverDeterministicUnixSocket(t *testing.T) {
	baseline := runtime.NumGoroutine()
	fixture := newManagerFixture(t)
	started := fixture.start(fixture.request(managerRunID))
	handle := started.handle

	wantSandboxSocket := filepath.Join(
		fixture.workspaceRoot, ".warpmetal", "provider-gateways", managerRunID+".sock",
	)
	if got := handle.SandboxSocketPath(); got != wantSandboxSocket {
		t.Fatalf("SandboxSocketPath() = %q, want %q", got, wantSandboxSocket)
	}
	wantContainerSocket := "/home/agent/.warpmetal/provider-gateways/" + managerRunID + ".sock"
	if got := handle.ContainerSocketPath(); got != wantContainerSocket {
		t.Fatalf("ContainerSocketPath() = %q, want %q (default container root)", got, wantContainerSocket)
	}
	if !strings.HasPrefix(wantSandboxSocket, fixture.workspaceRoot+string(filepath.Separator)) {
		t.Fatalf("socket path %q is not inside the workspace %q", wantSandboxSocket, fixture.workspaceRoot)
	}
	requireMode(t, wantSandboxSocket, 0o600)
	requireMode(t, filepath.Dir(wantSandboxSocket), 0o700)

	client := dialRPC(t, wantSandboxSocket)
	tools := decodeResult[toolsListResult](t, client.request(toolsListMethod, nil))
	if !reflect.DeepEqual(tools.Tools, fakeTools()) {
		t.Fatalf("tools/list = %+v, want exactly the declared tools", tools.Tools)
	}
	argumentCanary := "manager-argument-canary-3b7d"
	readResult := decodeToolCallResult(t, client.callTool(fakeReadToolName, map[string]any{
		"path": "/canary/" + argumentCanary,
	}))
	requireContains(t, readResult.Content[0].Text, fakeReadMarker, "fake_read result")
	requireNotContains(t, readResult.Content[0].Text, fakeSecret, "fake_read result")
	writeResult := decodeToolCallResult(t, client.callTool(fakeWriteToolName, map[string]any{
		"value": "manager-write-canary",
	}))
	requireContains(t, writeResult.Content[0].Text, fakeWriteMarker, "fake_write result")
	if started.provider.callCount() != 2 {
		t.Fatalf("executor call count = %d, want 2", started.provider.callCount())
	}

	// Diagnostics render non-secret metadata only.
	rendered := fmt.Sprintf("%v %s %+v %#v", handle, handle, handle, handle)
	requireContains(t, rendered, managerRunID, "rendered handle")
	requireNotContains(t, rendered, fakeSecret, "rendered handle")

	logs := fixture.logs.String()
	requireContains(t, logs, managerSandboxID, "manager log")
	requireContains(t, logs, managerRunID, "manager log")
	requireContains(t, logs, fakeProviderID, "manager log")
	requireNotContains(t, logs, fakeSecret, "manager log")
	requireNotContains(t, logs, argumentCanary, "manager log")
	requireNotContains(t, logs, "manager-write-canary", "manager log")
	requireNotContains(t, logs, fakeReadMarker, "manager log")
	requireNotContains(t, logs, fakeWriteMarker, "manager log")

	if err := handle.Close(context.Background()); err != nil {
		t.Fatalf("close handle: %v", err)
	}
	waitHandleDone(t, handle)
	requireSocketGone(t, wantSandboxSocket)
	requireDialFails(t, wantSandboxSocket)
	requireGatewayDirGone(t, fixture.workspaceRoot)
	if destroys := started.credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d, want 1", destroys)
	}
	// Repeated Close is safe and does not destroy the credential again.
	if err := handle.Close(context.Background()); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if destroys := started.credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d after second close, want 1", destroys)
	}
	// The manager detached the finished handle: closing everything is a no-op.
	if err := fixture.manager.CloseAll(context.Background()); err != nil {
		t.Fatalf("close all after handle close: %v", err)
	}
	requireNoLeakedGoroutines(t, baseline)
}

// TestManagerRefusesDuplicateAndTracksIndependentRuns covers duplicate refusal,
// coexisting run ids, per-handle close, CloseAll, and Manager.Close refusing new
// starts.
func TestManagerRefusesDuplicateAndTracksIndependentRuns(t *testing.T) {
	baseline := runtime.NumGoroutine()
	fixture := newManagerFixture(t)

	first := fixture.start(fixture.request(managerRunID))

	duplicateRequest := fixture.request(managerRunID)
	handle, err := fixture.manager.Start(context.Background(), duplicateRequest)
	requireStartRejected(t, handle, err, duplicateRequest, managerRunID)
	if !errors.Is(err, ErrGatewayAlreadyStarted) {
		t.Fatalf("duplicate error = %v, want ErrGatewayAlreadyStarted", err)
	}
	// The first gateway is unaffected.
	dialAndPing(t, first.handle.SandboxSocketPath())

	second := fixture.start(fixture.request("run_second0001"))
	dialAndPing(t, second.handle.SandboxSocketPath())

	// Closing one run leaves the other serving.
	if err := first.handle.Close(context.Background()); err != nil {
		t.Fatalf("close first handle: %v", err)
	}
	waitHandleDone(t, first.handle)
	requireSocketGone(t, first.handle.SandboxSocketPath())
	if first.credential.destroys() != 1 {
		t.Fatalf("first credential destroy count = %d, want 1", first.credential.destroys())
	}
	dialAndPing(t, second.handle.SandboxSocketPath())

	// CloseAll closes every tracked handle and removes the shared owned run
	// directory only after the last handle stops.
	if err := fixture.manager.CloseAll(context.Background()); err != nil {
		t.Fatalf("close all: %v", err)
	}
	waitHandleDone(t, second.handle)
	requireSocketGone(t, second.handle.SandboxSocketPath())
	if second.credential.destroys() != 1 {
		t.Fatalf("second credential destroy count = %d, want 1", second.credential.destroys())
	}
	requireGatewayDirGone(t, fixture.workspaceRoot)

	// CloseAll does not close the manager.
	third := fixture.start(fixture.request("run_third0001"))
	dialAndPing(t, third.handle.SandboxSocketPath())

	if err := fixture.manager.Close(context.Background()); err != nil {
		t.Fatalf("close manager: %v", err)
	}
	waitHandleDone(t, third.handle)
	requireSocketGone(t, third.handle.SandboxSocketPath())
	if third.credential.destroys() != 1 {
		t.Fatalf("third credential destroy count = %d, want 1", third.credential.destroys())
	}

	refusedRequest := fixture.request("run_fourth0001")
	handle, err = fixture.manager.Start(context.Background(), refusedRequest)
	requireStartRejected(t, handle, err, refusedRequest, "")
	if !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("post-close start error = %v, want ErrManagerClosed", err)
	}
	// CloseAll keeps working after Close, and Close is idempotent.
	if err := fixture.manager.Close(context.Background()); err != nil {
		t.Fatalf("second manager close: %v", err)
	}
	if err := fixture.manager.CloseAll(context.Background()); err != nil {
		t.Fatalf("close all after manager close: %v", err)
	}
	requireNoLeakedGoroutines(t, baseline)
}

// TestManagerCallerContextCancellationCleansUpAndDetaches covers the caller
// context as the gateway lifetime: cancellation tears the gateway down, removes
// the socket, destroys the credential exactly once and detaches the handle so
// the same (sandbox, run) can be started again.
func TestManagerCallerContextCancellationCleansUpAndDetaches(t *testing.T) {
	baseline := runtime.NumGoroutine()
	fixture := newManagerFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	request := fixture.request(managerRunID)
	handle, err := fixture.manager.Start(ctx, request)
	if err != nil {
		t.Fatalf("start provider gateway: %v", err)
	}
	credential := request.Credential.(*fakeCredential)
	sandboxSocketPath := handle.SandboxSocketPath()
	dialAndPing(t, sandboxSocketPath)

	cancel()
	waitHandleDone(t, handle)
	requireSocketGone(t, sandboxSocketPath)
	requireDialFails(t, sandboxSocketPath)
	requireGatewayDirGone(t, fixture.workspaceRoot)
	if destroys := credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d, want 1", destroys)
	}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatalf("close stopped handle: %v", err)
	}
	if destroys := credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d after close, want 1", destroys)
	}
	requireContains(t, handle.String(), "state=stopped", "stopped handle")

	// The handle detached itself, so the same sandbox/run pair can start again.
	restarted := fixture.start(fixture.request(managerRunID))
	dialAndPing(t, restarted.handle.SandboxSocketPath())
	if err := restarted.handle.Close(context.Background()); err != nil {
		t.Fatalf("close restarted handle: %v", err)
	}
	waitHandleDone(t, restarted.handle)
	if destroys := restarted.credential.destroys(); destroys != 1 {
		t.Fatalf("restarted credential destroy count = %d, want 1", destroys)
	}
	requireNoLeakedGoroutines(t, baseline)
}

// TestManagerStartCancelledBeforeStartDestroysCredential covers a caller context
// that is already cancelled.
func TestManagerStartCancelledBeforeStartDestroysCredential(t *testing.T) {
	baseline := runtime.NumGoroutine()
	fixture := newManagerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	request := fixture.request(managerRunID)
	handle, err := fixture.manager.Start(ctx, request)
	requireStartRejected(t, handle, err, request, "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("start error = %v, want context.Canceled", err)
	}
	if _, statErr := os.Lstat(filepath.Join(fixture.workspaceRoot, ".warpmetal")); !os.IsNotExist(statErr) {
		t.Fatalf("cancelled start created workspace state: %v", statErr)
	}
	requireNoLeakedGoroutines(t, baseline)
}

// TestManagerStartFailureCleansUp covers a gateway listener that cannot bind:
// Start returns a bounded error, destroys the credential exactly once, leaves
// pre-existing files untouched and never leaks a goroutine or socket.
func TestManagerStartFailureCleansUp(t *testing.T) {
	baseline := runtime.NumGoroutine()
	fixture := newManagerFixture(t)

	gatewayDir := filepath.Join(fixture.workspaceRoot, gatewayRelativeDir)
	if err := os.MkdirAll(gatewayDir, 0o700); err != nil {
		t.Fatalf("create gateway directory: %v", err)
	}
	blockedSocketPath := filepath.Join(gatewayDir, managerRunID+".sock")
	if err := os.WriteFile(blockedSocketPath, []byte("keep me"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}

	request := fixture.request(managerRunID)
	handle, err := fixture.manager.Start(context.Background(), request)
	requireStartRejected(t, handle, err, request, "refusing to overwrite existing non-socket")
	if len(err.Error()) > 1024 {
		t.Fatalf("listener failure error is not bounded: %d bytes", len(err.Error()))
	}
	if content, readErr := os.ReadFile(blockedSocketPath); readErr != nil || string(content) != "keep me" {
		t.Fatalf("blocking file was modified: content=%q err=%v", content, readErr)
	}
	// The gateway directory pre-existed, so the manager must never remove it.
	if info, statErr := os.Lstat(gatewayDir); statErr != nil || !info.IsDir() {
		t.Fatalf("pre-existing gateway directory was removed: %v", statErr)
	}
	// A failed start does not poison the manager for other runs.
	recovered := fixture.startFor(fixture.workspaceRoot, managerSandboxID, "run_recovered0001")
	if err := recovered.handle.Close(context.Background()); err != nil {
		t.Fatalf("close recovered handle: %v", err)
	}
	waitHandleDone(t, recovered.handle)
	if destroys := recovered.credential.destroys(); destroys != 1 {
		t.Fatalf("recovered credential destroy count = %d, want 1", destroys)
	}
	requireNoLeakedGoroutines(t, baseline)
}

// TestManagerLeavesPreExistingGatewayDirectory covers a successful start whose
// run directory already existed before the manager touched it: the socket is
// removed on close, the directory is not.
func TestManagerLeavesPreExistingGatewayDirectory(t *testing.T) {
	fixture := newManagerFixture(t)
	gatewayDir := filepath.Join(fixture.workspaceRoot, gatewayRelativeDir)
	if err := os.MkdirAll(gatewayDir, 0o700); err != nil {
		t.Fatalf("create gateway directory: %v", err)
	}
	started := fixture.start(fixture.request(managerRunID))
	socketPath := started.handle.SandboxSocketPath()
	dialAndPing(t, socketPath)
	if err := started.handle.Close(context.Background()); err != nil {
		t.Fatalf("close handle: %v", err)
	}
	waitHandleDone(t, started.handle)
	requireSocketGone(t, socketPath)
	if info, err := os.Lstat(gatewayDir); err != nil || !info.IsDir() {
		t.Fatalf("pre-existing gateway directory was removed: %v", err)
	}
	if destroys := started.credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d, want 1", destroys)
	}
}

// TestManagerRefusesUnsafeWorkspaceAndRequests covers request validation and the
// workspace-directory guardrails: unsafe run ids, invalid metadata, unsafe
// workspace roots, symlinked gateway paths, a group-accessible run directory and
// invalid container roots.
func TestManagerRefusesUnsafeWorkspaceAndRequests(t *testing.T) {
	baseline := runtime.NumGoroutine()
	fixture := newManagerFixture(t)

	t.Run("unsafe run ids", func(t *testing.T) {
		runIDs := []string{
			"",
			"../escape",
			"run/../escape",
			"run/other",
			".hidden",
			"run id",
			"run.id",
			strings.Repeat("a", maxRunIDBytes+1),
			"run\x00id",
		}
		for _, runID := range runIDs {
			request := fixture.request(runID)
			handle, err := fixture.manager.Start(context.Background(), request)
			requireStartRejected(t, handle, err, request, "run id")
			if _, statErr := os.Lstat(filepath.Join(fixture.workspaceRoot, ".warpmetal")); !os.IsNotExist(statErr) {
				t.Fatalf("unsafe run id %q created workspace state: %v", runID, statErr)
			}
		}
	})

	t.Run("invalid metadata", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*Request)
			want   string
		}{
			{name: "missing sandbox id", mutate: func(r *Request) { r.SandboxID = "" }, want: "sandbox id is required"},
			{name: "sandbox id whitespace", mutate: func(r *Request) { r.SandboxID = "sbx one" }, want: "whitespace"},
			{name: "missing provider id", mutate: func(r *Request) { r.ProviderID = "" }, want: "provider id is required"},
			{name: "missing connection id", mutate: func(r *Request) { r.ConnectionID = "" }, want: "connection id is required"},
			{name: "account id control character", mutate: func(r *Request) { r.AccountID = "acct\n1" }, want: "control"},
			{name: "too-long sandbox id", mutate: func(r *Request) { r.SandboxID = strings.Repeat("s", maxMetadataBytes+1) }, want: "too long"},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				request := fixture.request(managerRunID)
				testCase.mutate(&request)
				handle, err := fixture.manager.Start(context.Background(), request)
				requireStartRejected(t, handle, err, request, testCase.want)
			})
		}
	})

	t.Run("workspace root guardrails", func(t *testing.T) {
		workspaceFile := filepath.Join(fixture.workspaceRoot, "regular-file")
		if err := os.WriteFile(workspaceFile, []byte("x"), 0o600); err != nil {
			t.Fatalf("write regular file: %v", err)
		}
		workspaceSymlink := filepath.Join(fixture.workspaceRoot, "symlink-root")
		if err := os.Symlink(fixture.workspaceRoot, workspaceSymlink); err != nil {
			t.Fatalf("symlink workspace root: %v", err)
		}
		cases := []struct {
			name string
			root string
			want string
		}{
			{name: "empty", root: "", want: "workspace host root is required"},
			{name: "relative", root: "relative/workspace", want: "must be absolute"},
			{name: "unclean", root: fixture.workspaceRoot + "/../elsewhere", want: "clean path"},
			{name: "missing", root: filepath.Join(fixture.workspaceRoot, "missing"), want: "workspace root"},
			{name: "regular file", root: workspaceFile, want: "is not a directory"},
			{name: "symlink", root: workspaceSymlink, want: "must not be a symlink"},
			{name: "NUL byte", root: fixture.workspaceRoot + "/\x00", want: "NUL"},
			{name: "socket path too long", root: filepath.Join(fixture.workspaceRoot, strings.Repeat("w", 90)), want: "socket path is too long"},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				request := fixture.request(managerRunID)
				request.WorkspaceHostRoot = testCase.root
				handle, err := fixture.manager.Start(context.Background(), request)
				requireStartRejected(t, handle, err, request, testCase.want)
			})
		}
	})

	t.Run("symlinked gateway paths", func(t *testing.T) {
		t.Run("warpmetal directory symlink escape", func(t *testing.T) {
			workspace := managerTempDir(t)
			outside := managerTempDir(t)
			if err := os.Symlink(outside, filepath.Join(workspace, ".warpmetal")); err != nil {
				t.Fatalf("symlink .warpmetal: %v", err)
			}
			request := newManagerRequest(workspace, managerSandboxID, managerRunID)
			handle, err := fixture.manager.Start(context.Background(), request)
			requireStartRejected(t, handle, err, request, "must not be a symlink")
			entries, readErr := os.ReadDir(outside)
			if readErr != nil {
				t.Fatalf("read outside directory: %v", readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("manager created entries outside the workspace: %v", entries)
			}
		})
		t.Run("provider gateways directory symlink escape", func(t *testing.T) {
			workspace := managerTempDir(t)
			outside := managerTempDir(t)
			if err := os.MkdirAll(filepath.Join(workspace, ".warpmetal"), 0o700); err != nil {
				t.Fatalf("create .warpmetal: %v", err)
			}
			if err := os.Symlink(outside, filepath.Join(workspace, gatewayRelativeDir)); err != nil {
				t.Fatalf("symlink provider-gateways: %v", err)
			}
			request := newManagerRequest(workspace, managerSandboxID, managerRunID)
			handle, err := fixture.manager.Start(context.Background(), request)
			requireStartRejected(t, handle, err, request, "must not be a symlink")
			entries, readErr := os.ReadDir(outside)
			if readErr != nil {
				t.Fatalf("read outside directory: %v", readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("manager created entries outside the workspace: %v", entries)
			}
		})
	})

	t.Run("gateway directory guardrails", func(t *testing.T) {
		t.Run("group accessible run directory", func(t *testing.T) {
			workspace := managerTempDir(t)
			runDirectory := filepath.Join(workspace, gatewayRelativeDir)
			if err := os.MkdirAll(runDirectory, 0o750); err != nil {
				t.Fatalf("create run directory: %v", err)
			}
			if err := os.Chmod(runDirectory, 0o750); err != nil {
				t.Fatalf("chmod run directory: %v", err)
			}
			request := newManagerRequest(workspace, managerSandboxID, managerRunID)
			handle, err := fixture.manager.Start(context.Background(), request)
			requireStartRejected(t, handle, err, request, "owner-only")
			if info, statErr := os.Lstat(runDirectory); statErr != nil || !info.IsDir() {
				t.Fatalf("refused run directory was removed: %v", statErr)
			}
		})
		t.Run("run directory is a regular file", func(t *testing.T) {
			workspace := managerTempDir(t)
			if err := os.MkdirAll(filepath.Join(workspace, ".warpmetal"), 0o700); err != nil {
				t.Fatalf("create .warpmetal: %v", err)
			}
			if err := os.WriteFile(filepath.Join(workspace, gatewayRelativeDir), []byte("x"), 0o600); err != nil {
				t.Fatalf("write run directory file: %v", err)
			}
			request := newManagerRequest(workspace, managerSandboxID, managerRunID)
			handle, err := fixture.manager.Start(context.Background(), request)
			requireStartRejected(t, handle, err, request, "not a directory")
		})
	})

	t.Run("container root guardrails", func(t *testing.T) {
		cases := []struct {
			name string
			root string
			want string
		}{
			{name: "relative", root: "home/agent", want: "must be absolute"},
			{name: "unclean", root: "/home/../agent", want: "clean path"},
			{name: "NUL byte", root: "/home/agent\x00", want: "NUL"},
			{name: "container socket path too long", root: "/" + strings.Repeat("c", 64), want: "container socket path is too long"},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				request := fixture.request(managerRunID)
				request.ContainerRoot = testCase.root
				handle, err := fixture.manager.Start(context.Background(), request)
				requireStartRejected(t, handle, err, request, testCase.want)
			})
		}
	})

	t.Run("invalid gateway configuration cleans up", func(t *testing.T) {
		request := fixture.request(managerRunID)
		request.Executor = nil
		handle, err := fixture.manager.Start(context.Background(), request)
		requireStartRejected(t, handle, err, request, "executor is required")
		requireGatewayDirGone(t, fixture.workspaceRoot)
	})

	// The manager is still healthy after every rejected request.
	recovered := fixture.start(fixture.request(managerRunID))
	dialAndPing(t, recovered.handle.SandboxSocketPath())
	if err := recovered.handle.Close(context.Background()); err != nil {
		t.Fatalf("close recovered handle: %v", err)
	}
	waitHandleDone(t, recovered.handle)
	requireNoLeakedGoroutines(t, baseline)
}

// TestManagerCloseSandboxIsolatesSandboxes covers closing one sandbox's
// gateways while another sandbox keeps serving.
func TestManagerCloseSandboxIsolatesSandboxes(t *testing.T) {
	baseline := runtime.NumGoroutine()
	fixture := newManagerFixture(t)
	secondWorkspace := managerTempDir(t)

	firstSandboxRunOne := fixture.startFor(fixture.workspaceRoot, "sbx_one", "run_one0001")
	firstSandboxRunTwo := fixture.startFor(fixture.workspaceRoot, "sbx_one", "run_one0002")
	secondSandbox := fixture.startFor(secondWorkspace, "sbx_two", "run_two0001")
	dialAndPing(t, secondSandbox.handle.SandboxSocketPath())

	if err := fixture.manager.CloseSandbox(context.Background(), "sbx_one"); err != nil {
		t.Fatalf("close sandbox: %v", err)
	}
	waitHandleDone(t, firstSandboxRunOne.handle)
	waitHandleDone(t, firstSandboxRunTwo.handle)
	requireSocketGone(t, firstSandboxRunOne.handle.SandboxSocketPath())
	requireSocketGone(t, firstSandboxRunTwo.handle.SandboxSocketPath())
	requireGatewayDirGone(t, fixture.workspaceRoot)
	if firstSandboxRunOne.credential.destroys() != 1 {
		t.Fatalf("run one credential destroy count = %d, want 1", firstSandboxRunOne.credential.destroys())
	}
	if firstSandboxRunTwo.credential.destroys() != 1 {
		t.Fatalf("run two credential destroy count = %d, want 1", firstSandboxRunTwo.credential.destroys())
	}
	// The other sandbox is untouched.
	dialAndPing(t, secondSandbox.handle.SandboxSocketPath())
	if destroys := secondSandbox.credential.destroys(); destroys != 0 {
		t.Fatalf("second sandbox credential destroy count = %d after isolated close, want 0", destroys)
	}

	// Unknown and empty sandbox ids close nothing.
	if err := fixture.manager.CloseSandbox(context.Background(), "sbx_unknown"); err != nil {
		t.Fatalf("close unknown sandbox: %v", err)
	}
	if err := fixture.manager.CloseSandbox(context.Background(), ""); err != nil {
		t.Fatalf("close empty sandbox: %v", err)
	}
	dialAndPing(t, secondSandbox.handle.SandboxSocketPath())

	if err := secondSandbox.handle.Close(context.Background()); err != nil {
		t.Fatalf("close second sandbox handle: %v", err)
	}
	waitHandleDone(t, secondSandbox.handle)
	if destroys := secondSandbox.credential.destroys(); destroys != 1 {
		t.Fatalf("second sandbox credential destroy count = %d, want 1", destroys)
	}
	requireGatewayDirGone(t, secondWorkspace)
	requireNoLeakedGoroutines(t, baseline)
}

// TestManagerCustomContainerRoot covers an explicit container mount point: the
// returned container socket path is deterministic and follows ContainerRoot.
func TestManagerCustomContainerRoot(t *testing.T) {
	fixture := newManagerFixture(t)
	request := fixture.request(managerRunID)
	request.ContainerRoot = "/home/agent/projects/team_alpha"
	started := fixture.start(request)

	wantContainerSocket := "/home/agent/projects/team_alpha/.warpmetal/provider-gateways/" +
		managerRunID + ".sock"
	if got := started.handle.ContainerSocketPath(); got != wantContainerSocket {
		t.Fatalf("ContainerSocketPath() = %q, want %q", got, wantContainerSocket)
	}
	if want := filepath.Join(fixture.workspaceRoot, gatewayRelativeDir, managerRunID+".sock"); started.handle.SandboxSocketPath() != want {
		t.Fatalf("SandboxSocketPath() = %q, want %q", started.handle.SandboxSocketPath(), want)
	}
	dialAndPing(t, started.handle.SandboxSocketPath())
	if err := started.handle.Close(context.Background()); err != nil {
		t.Fatalf("close handle: %v", err)
	}
	waitHandleDone(t, started.handle)
	if destroys := started.credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d, want 1", destroys)
	}
}

// TestManagerHandleCloseIsIdempotentUnderConcurrency proves concurrent Close
// calls tear the gateway down once: no error, one credential destruction, no
// socket and no goroutine behind.
func TestManagerHandleCloseIsIdempotentUnderConcurrency(t *testing.T) {
	baseline := runtime.NumGoroutine()
	fixture := newManagerFixture(t)
	started := fixture.start(fixture.request(managerRunID))
	socketPath := started.handle.SandboxSocketPath()
	dialAndPing(t, socketPath)

	const closers = 4
	var waitGroup sync.WaitGroup
	errs := make(chan error, closers)
	for index := 0; index < closers; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			errs <- started.handle.Close(context.Background())
		}()
	}
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent close: %v", err)
		}
	}
	waitHandleDone(t, started.handle)
	requireSocketGone(t, socketPath)
	requireGatewayDirGone(t, fixture.workspaceRoot)
	if destroys := started.credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d, want 1", destroys)
	}
	requireNoLeakedGoroutines(t, baseline)
}

// TestManagerServerExitCleansUpAndDetaches covers the server stopping on its own
// (here by closing the gateway directly, which is what an accept failure does):
// the supervisor still removes the socket and owned directory, destroys the
// credential once, closes Done and detaches the handle.
func TestManagerServerExitCleansUpAndDetaches(t *testing.T) {
	baseline := runtime.NumGoroutine()
	fixture := newManagerFixture(t)
	started := fixture.start(fixture.request(managerRunID))
	socketPath := started.handle.SandboxSocketPath()
	dialAndPing(t, socketPath)

	if err := started.handle.gateway.Close(); err != nil {
		t.Fatalf("close gateway server: %v", err)
	}
	waitHandleDone(t, started.handle)
	requireSocketGone(t, socketPath)
	requireDialFails(t, socketPath)
	requireGatewayDirGone(t, fixture.workspaceRoot)
	if destroys := started.credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d, want 1", destroys)
	}
	// Close is still safe on the stopped handle and does not destroy again.
	if err := started.handle.Close(context.Background()); err != nil {
		t.Fatalf("close stopped handle: %v", err)
	}
	if destroys := started.credential.destroys(); destroys != 1 {
		t.Fatalf("credential destroy count = %d after Close, want 1", destroys)
	}

	// The detached handle no longer blocks the same (sandbox, run) pair.
	restarted := fixture.start(fixture.request(managerRunID))
	dialAndPing(t, restarted.handle.SandboxSocketPath())
	if err := restarted.handle.Close(context.Background()); err != nil {
		t.Fatalf("close restarted handle: %v", err)
	}
	waitHandleDone(t, restarted.handle)
	requireNoLeakedGoroutines(t, baseline)
}
