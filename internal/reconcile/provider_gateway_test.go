package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providergateway"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

const (
	providerGatewaySandboxID      = "sbx_gateway0001"
	providerGatewayServerID       = "srv_test12345"
	providerGatewaySecretSentinel = "pgw-reconcile-secret-canary-91d7f2"
)

// providerGatewayTestRequirement builds one valid manifest requirement.
func providerGatewayTestRequirement(
	runID, credentialID, providerID string,
	toolNames ...string,
) model.ProviderGatewayRequirement {
	tools := make([]model.ProviderGatewayTool, len(toolNames))
	for index, name := range toolNames {
		tools[index] = model.ProviderGatewayTool{
			Name:        name,
			Description: "Declared test tool " + name + ".",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`),
		}
	}
	return model.ProviderGatewayRequirement{
		RunID:        runID,
		CredentialID: credentialID,
		ProviderID:   providerID,
		Tools:        tools,
	}
}

// providerGatewayTestManifest builds a valid one-sandbox manifest.
func providerGatewayTestManifest(
	revision int64,
	desiredState string,
	generation int64,
	requirements []model.ProviderGatewayRequirement,
) model.Manifest {
	digest := "registry.example/sandbox@sha256:" + strings.Repeat("a", 64)
	return model.Manifest{
		ServerID:        providerGatewayServerID,
		DesiredRevision: revision,
		ImageDigest:     digest,
		Capacity:        model.Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []model.Sandbox{{
			ID:   providerGatewaySandboxID,
			Name: "main",
			Size: "small",
			Resources: model.Resources{
				CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256,
			},
			Lifetime:         "persistent",
			DesiredState:     desiredState,
			Generation:       generation,
			ProviderGateways: requirements,
		}},
	}
}

// providerGatewayTestWorkspaces is the workspace anchor seam: it returns a real
// temporary directory so the production gateway manager adapter can create the
// socket directory when a test uses it.
type providerGatewayTestWorkspaces struct {
	anchor     string
	ensureErr  error
	destroyErr error
	ensured    int
	destroyed  int
}

func (workspaces *providerGatewayTestWorkspaces) Ensure(context.Context, string, int) (string, error) {
	workspaces.ensured++
	if workspaces.ensureErr != nil {
		return "", workspaces.ensureErr
	}
	return workspaces.anchor, nil
}

func (workspaces *providerGatewayTestWorkspaces) Destroy(context.Context, string) error {
	workspaces.destroyed++
	return workspaces.destroyErr
}

// fakeProviderGatewayCredential is a destroy-observable credential double with
// the same idempotent Destroy contract as *boxcredentials.Credential.
type fakeProviderGatewayCredential struct {
	mu        sync.Mutex
	secret    string
	destroys  int
	destroyed bool
}

func newFakeProviderGatewayCredential(secret string) *fakeProviderGatewayCredential {
	return &fakeProviderGatewayCredential{secret: secret}
}

func (credential *fakeProviderGatewayCredential) SecretFields() map[string]string {
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.destroyed {
		return map[string]string{}
	}
	return map[string]string{"token": credential.secret}
}

func (credential *fakeProviderGatewayCredential) Destroy() {
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.destroyed {
		return
	}
	credential.destroyed = true
	credential.destroys++
	credential.secret = ""
}

func (credential *fakeProviderGatewayCredential) isDestroyed() bool {
	credential.mu.Lock()
	defer credential.mu.Unlock()
	return credential.destroyed
}

// fakeProviderGatewayHandle is one started gateway double. Close is idempotent,
// detaches from the fake manager and destroys the opened credential exactly like
// the production handle.
type fakeProviderGatewayHandle struct {
	manager    *fakeProviderGatewayManager
	sandboxID  string
	runID      string
	credential *fakeProviderGatewayCredential

	mu         sync.Mutex
	closeCalls int
	closeErr   error
	closed     bool
}

func (handle *fakeProviderGatewayHandle) Close(context.Context) error {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	handle.closeCalls++
	if handle.closeErr != nil {
		return handle.closeErr
	}
	if handle.closed {
		return nil
	}
	handle.closed = true
	handle.manager.detach(handle.sandboxID, handle.runID)
	if handle.credential != nil {
		handle.credential.Destroy()
	}
	return nil
}

func (handle *fakeProviderGatewayHandle) closeCount() int {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.closeCalls
}

// fakeProviderGatewayManager is a start/close-observable manager double. It
// mirrors the production ownership contract: Start takes ownership of the
// credential, a failed Start destroys it, and a started handle destroys it once
// on Close.
type fakeProviderGatewayManager struct {
	mu         sync.Mutex
	requests   []providergateway.Request
	handles    map[string]*fakeProviderGatewayHandle
	startErr   error
	closeErr   error
	closeCalls []string
}

func newFakeProviderGatewayManager() *fakeProviderGatewayManager {
	return &fakeProviderGatewayManager{handles: make(map[string]*fakeProviderGatewayHandle)}
}

func fakeProviderGatewayKey(sandboxID, runID string) string {
	return sandboxID + "\x00" + runID
}

func (manager *fakeProviderGatewayManager) Start(
	_ context.Context,
	request providergateway.Request,
) (ProviderGatewayHandle, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.requests = append(manager.requests, request)
	credential, _ := request.Credential.(*fakeProviderGatewayCredential)
	if manager.startErr != nil {
		// Mirror the production manager: a refused Start destroys the credential.
		if request.Credential != nil {
			request.Credential.Destroy()
		}
		return nil, manager.startErr
	}
	handle := &fakeProviderGatewayHandle{
		manager:    manager,
		sandboxID:  request.SandboxID,
		runID:      request.RunID,
		credential: credential,
	}
	manager.handles[fakeProviderGatewayKey(request.SandboxID, request.RunID)] = handle
	return handle, nil
}

func (manager *fakeProviderGatewayManager) Has(sandboxID, runID string) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.handles[fakeProviderGatewayKey(sandboxID, runID)] != nil
}

func (manager *fakeProviderGatewayManager) CloseSandbox(
	ctx context.Context,
	sandboxID string,
) error {
	manager.mu.Lock()
	manager.closeCalls = append(manager.closeCalls, sandboxID)
	handles := make([]*fakeProviderGatewayHandle, 0)
	for _, handle := range manager.handles {
		if handle.sandboxID == sandboxID {
			handles = append(handles, handle)
		}
	}
	closeErr := manager.closeErr
	manager.mu.Unlock()
	var errs []error
	for _, handle := range handles {
		if err := handle.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if closeErr != nil {
		errs = append(errs, closeErr)
	}
	return errors.Join(errs...)
}

func (manager *fakeProviderGatewayManager) detach(sandboxID, runID string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	delete(manager.handles, fakeProviderGatewayKey(sandboxID, runID))
}

func (manager *fakeProviderGatewayManager) startCount() int {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return len(manager.requests)
}

func (manager *fakeProviderGatewayManager) starts() []providergateway.Request {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return append([]providergateway.Request(nil), manager.requests...)
}

func (manager *fakeProviderGatewayManager) handle(sandboxID, runID string) *fakeProviderGatewayHandle {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.handles[fakeProviderGatewayKey(sandboxID, runID)]
}

func (manager *fakeProviderGatewayManager) closeSandboxCalls() []string {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return append([]string(nil), manager.closeCalls...)
}

// fakeProviderGatewayOpener is the credential opener double. Every OpenCredential
// call returns a fresh credential (like the real bridge) and every issued
// credential is retained so tests can assert destruction.
type fakeProviderGatewayOpener struct {
	mu          sync.Mutex
	secrets     map[string]string
	opened      []string
	credentials map[string][]*fakeProviderGatewayCredential
	openErr     error
}

func newFakeProviderGatewayOpener(secrets map[string]string) *fakeProviderGatewayOpener {
	return &fakeProviderGatewayOpener{
		secrets:     secrets,
		credentials: make(map[string][]*fakeProviderGatewayCredential),
	}
}

func (opener *fakeProviderGatewayOpener) OpenCredential(
	credentialID string,
) (providergateway.Credential, error) {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	opener.opened = append(opener.opened, credentialID)
	if opener.openErr != nil {
		return nil, opener.openErr
	}
	secret, ok := opener.secrets[credentialID]
	if !ok {
		return nil, fmt.Errorf("fake credential opener: unknown credential")
	}
	credential := newFakeProviderGatewayCredential(secret)
	opener.credentials[credentialID] = append(opener.credentials[credentialID], credential)
	return credential, nil
}

func (opener *fakeProviderGatewayOpener) openCount() int {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return len(opener.opened)
}

func (opener *fakeProviderGatewayOpener) openedIDs() []string {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return append([]string(nil), opener.opened...)
}

func (opener *fakeProviderGatewayOpener) issued(credentialID string) []*fakeProviderGatewayCredential {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return append([]*fakeProviderGatewayCredential(nil), opener.credentials[credentialID]...)
}

// fakeProviderGatewayExecutor is the pluggable P2d executor seam. The
// reconciler must wire it into every gateway request; production P2d leaves it
// nil so no provider call is ever made. An optional toolTimeout mirrors the
// external executor's ToolTimeoutProvider extension.
type fakeProviderGatewayExecutor struct {
	mu          sync.Mutex
	calls       int
	toolTimeout time.Duration
}

func (executor *fakeProviderGatewayExecutor) CallTool(
	context.Context,
	providergateway.ToolCall,
) (providergateway.ToolResult, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	executor.calls++
	return providergateway.ToolResult{Text: "unused"}, nil
}

// ToolTimeout implements providergateway.ToolTimeoutProvider.
func (executor *fakeProviderGatewayExecutor) ToolTimeout() time.Duration {
	return executor.toolTimeout
}

func (executor *fakeProviderGatewayExecutor) callCount() int {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.calls
}

type providerGatewayTestFixture struct {
	reconciler *Reconciler
	store      *state.Store
	workspaces *providerGatewayTestWorkspaces
	engine     *fakeEngine
}

func newProviderGatewayTestReconciler(
	t *testing.T,
	manager ProviderGatewayManager,
	opener ProviderCredentialOpener,
	executor providergateway.Executor,
) *providerGatewayTestFixture {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fixture := &providerGatewayTestFixture{
		store:      store,
		workspaces: &providerGatewayTestWorkspaces{anchor: t.TempDir()},
		engine:     &fakeEngine{},
	}
	fixture.reconciler = &Reconciler{
		Store:               store,
		Engine:              fixture.engine,
		Workspaces:          fixture.workspaces,
		Access:              access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		Sessions:            &fakeSessions{},
		HostCapacity:        model.Resources{CPUMillicores: 2000, MemoryMiB: 4096, WorkspaceDiskGiB: 40},
		ServerID:            providerGatewayServerID,
		ProviderGateways:    manager,
		ProviderCredentials: opener,
		ProviderExecutor:    executor,
	}
	return fixture
}

func (fixture *providerGatewayTestFixture) reconcile(t *testing.T, manifest model.Manifest) error {
	t.Helper()
	return fixture.reconciler.Reconcile(context.Background(), manifest)
}

func (fixture *providerGatewayTestFixture) localSandbox(t *testing.T) *state.LocalSandbox {
	t.Helper()
	local, err := fixture.store.Sandbox(context.Background(), providerGatewaySandboxID)
	if err != nil {
		t.Fatal(err)
	}
	return local
}

func requireProviderGatewayRequest(
	t *testing.T,
	request providergateway.Request,
	workspace, runID, providerID, connectionID string,
	toolNames ...string,
) {
	t.Helper()
	if request.SandboxID != providerGatewaySandboxID {
		t.Fatalf("gateway sandbox id = %q", request.SandboxID)
	}
	if request.RunID != runID {
		t.Fatalf("gateway run id = %q, want %q", request.RunID, runID)
	}
	if request.WorkspaceHostRoot != workspace {
		t.Fatalf("gateway workspace root = %q, want %q", request.WorkspaceHostRoot, workspace)
	}
	if request.ContainerRoot != providergateway.DefaultContainerRoot {
		t.Fatalf("gateway container root = %q, want %q", request.ContainerRoot, providergateway.DefaultContainerRoot)
	}
	if request.ProviderID != providerID || request.ConnectionID != connectionID {
		t.Fatalf(
			"gateway metadata = provider %q connection %q, want %q/%q",
			request.ProviderID, request.ConnectionID, providerID, connectionID,
		)
	}
	if request.Credential == nil {
		t.Fatal("gateway request carried no opened credential")
	}
	if len(request.Tools) != len(toolNames) {
		t.Fatalf("gateway tools = %#v, want %v", request.Tools, toolNames)
	}
	for index, name := range toolNames {
		if request.Tools[index].Name != name {
			t.Fatalf("gateway tool %d = %q, want %q", index, request.Tools[index].Name, name)
		}
		if len(request.Tools[index].InputSchema) == 0 {
			t.Fatalf("gateway tool %d has no input schema", index)
		}
	}
}

func TestReconcileStartsOneProviderGatewayPerRequirement(t *testing.T) {
	manager := newFakeProviderGatewayManager()
	opener := newFakeProviderGatewayOpener(map[string]string{
		"conn_github0000000000000001": providerGatewaySecretSentinel,
		"conn_google0000000000000002": "google-secret-canary",
	})
	executor := &fakeProviderGatewayExecutor{toolTimeout: 45 * time.Second}
	fixture := newProviderGatewayTestReconciler(t, manager, opener, executor)
	requirements := []model.ProviderGatewayRequirement{
		providerGatewayTestRequirement(
			"run_github_0001", "conn_github0000000000000001", "github", "list_repositories", "read_file",
		),
		providerGatewayTestRequirement(
			"run_google_0002", "conn_google0000000000000002", "google", "read_document",
		),
	}
	manifest := providerGatewayTestManifest(1, "running", 1, requirements)
	if err := fixture.reconcile(t, manifest); err != nil {
		t.Fatalf("reconcile with provider gateways: %v", err)
	}
	starts := manager.starts()
	if len(starts) != len(requirements) {
		t.Fatalf("started %d gateways, want %d", len(starts), len(requirements))
	}
	requireProviderGatewayRequest(
		t, starts[0], fixture.workspaces.anchor,
		"run_github_0001", "github", "conn_github0000000000000001",
		"list_repositories", "read_file",
	)
	requireProviderGatewayRequest(
		t, starts[1], fixture.workspaces.anchor,
		"run_google_0002", "google", "conn_google0000000000000002",
		"read_document",
	)
	for _, request := range starts {
		if request.Executor != executor {
			t.Fatal("gateway request did not carry the configured executor")
		}
		// An executor that declares its own per-call bound (the P4a external
		// provider executor does) sets the gateway's call deadline to it.
		if request.ToolTimeout != executor.toolTimeout {
			t.Fatalf("gateway tool timeout = %s, want the executor's %s", request.ToolTimeout, executor.toolTimeout)
		}
	}
	if got := opener.openedIDs(); len(got) != 2 ||
		got[0] != "conn_github0000000000000001" || got[1] != "conn_google0000000000000002" {
		t.Fatalf("opened credentials = %v", got)
	}
	for _, credentialID := range []string{"conn_github0000000000000001", "conn_google0000000000000002"} {
		issued := opener.issued(credentialID)
		if len(issued) != 1 || issued[0].isDestroyed() {
			t.Fatalf("live gateway credential %s was destroyed or reopened", credentialID)
		}
	}
	local := fixture.localSandbox(t)
	if local == nil || local.ObservedState != "running" || local.ObservedGeneration != 1 {
		t.Fatalf("sandbox was not committed running: %#v", local)
	}
	if !model.SameProviderGatewayRequirements(local.ProviderGateways, requirements) {
		t.Fatalf("stored provider gateways = %#v, want %#v", local.ProviderGateways, requirements)
	}
	if executor.callCount() != 0 {
		t.Fatalf("P2d reconcile executed %d provider tool calls, want 0", executor.callCount())
	}

	// A second identical pass must be idempotent: no duplicate gateway, no
	// re-opened credential, no extra handle.
	second := providerGatewayTestManifest(2, "running", 1, requirements)
	if err := fixture.reconcile(t, second); err != nil {
		t.Fatalf("second reconcile pass: %v", err)
	}
	if manager.startCount() != 2 {
		t.Fatalf("second pass started %d gateways, want no additional starts", manager.startCount()-2)
	}
	if opener.openCount() != 2 {
		t.Fatalf("second pass opened %d credentials, want no additional opens", opener.openCount()-2)
	}
}

func TestReconcileClosesProviderGatewayForRemovedRequirement(t *testing.T) {
	manager := newFakeProviderGatewayManager()
	opener := newFakeProviderGatewayOpener(map[string]string{
		"conn_github0000000000000001": providerGatewaySecretSentinel,
		"conn_google0000000000000002": "google-secret-canary",
	})
	fixture := newProviderGatewayTestReconciler(t, manager, opener, &fakeProviderGatewayExecutor{})
	first := []model.ProviderGatewayRequirement{
		providerGatewayTestRequirement(
			"run_github_0001", "conn_github0000000000000001", "github", "list_repositories",
		),
		providerGatewayTestRequirement(
			"run_google_0002", "conn_google0000000000000002", "google", "read_document",
		),
	}
	if err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, first)); err != nil {
		t.Fatalf("first reconcile pass: %v", err)
	}
	removedHandle := manager.handle(providerGatewaySandboxID, "run_google_0002")
	keptHandle := manager.handle(providerGatewaySandboxID, "run_github_0001")
	removedCredential := opener.issued("conn_google0000000000000002")[0]
	keptCredential := opener.issued("conn_github0000000000000001")[0]
	second := []model.ProviderGatewayRequirement{first[0]}
	if err := fixture.reconcile(t, providerGatewayTestManifest(2, "running", 1, second)); err != nil {
		t.Fatalf("second reconcile pass: %v", err)
	}
	if manager.startCount() != 2 {
		t.Fatalf("removing a requirement restarted gateways: starts = %d, want 2", manager.startCount())
	}
	if opener.openCount() != 2 {
		t.Fatalf("removing a requirement reopened credentials: opens = %d, want 2", opener.openCount())
	}
	if removedHandle == nil || removedHandle.closeCount() == 0 {
		t.Fatal("removed requirement's gateway was not closed")
	}
	if !removedCredential.isDestroyed() {
		t.Fatal("removed requirement's credential was not destroyed")
	}
	if manager.Has(providerGatewaySandboxID, "run_google_0002") {
		t.Fatal("removed requirement's gateway is still tracked")
	}
	if keptHandle == nil || keptHandle.closeCount() != 0 || keptCredential.isDestroyed() {
		t.Fatal("unchanged requirement's gateway was restarted")
	}
	if manager.handle(providerGatewaySandboxID, "run_github_0001") != keptHandle {
		t.Fatal("unchanged requirement lost its gateway")
	}
	local := fixture.localSandbox(t)
	if local == nil || len(local.ProviderGateways) != 1 || local.ProviderGateways[0].RunID != "run_github_0001" {
		t.Fatalf("state did not record the removed requirement: %#v", local)
	}
}

func TestReconcileReplacesChangedProviderGatewayRequirement(t *testing.T) {
	manager := newFakeProviderGatewayManager()
	opener := newFakeProviderGatewayOpener(map[string]string{
		"conn_github0000000000000001": providerGatewaySecretSentinel,
	})
	fixture := newProviderGatewayTestReconciler(t, manager, opener, &fakeProviderGatewayExecutor{})
	first := []model.ProviderGatewayRequirement{
		providerGatewayTestRequirement(
			"run_github_0001", "conn_github0000000000000001", "github", "list_repositories",
		),
	}
	if err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, first)); err != nil {
		t.Fatalf("first reconcile pass: %v", err)
	}
	firstHandle := manager.handle(providerGatewaySandboxID, "run_github_0001")
	firstCredential := opener.issued("conn_github0000000000000001")[0]
	second := []model.ProviderGatewayRequirement{
		providerGatewayTestRequirement(
			"run_github_0001", "conn_github0000000000000001", "github", "write_file",
		),
	}
	if err := fixture.reconcile(t, providerGatewayTestManifest(2, "running", 1, second)); err != nil {
		t.Fatalf("second reconcile pass: %v", err)
	}
	starts := manager.starts()
	if len(starts) != 2 {
		t.Fatalf("replaced requirement starts = %d, want 2", len(starts))
	}
	if got := starts[1].Tools[0].Name; got != "write_file" {
		t.Fatalf("replacement gateway tool = %q, want write_file", got)
	}
	if firstHandle == nil || firstHandle.closeCount() == 0 {
		t.Fatal("replaced requirement's gateway was not closed")
	}
	if !firstCredential.isDestroyed() {
		t.Fatal("replaced requirement's credential was not destroyed")
	}
}

func TestReconcileClosesProviderGatewaysOnStopDeleteAndGenerationChange(t *testing.T) {
	requirement := providerGatewayTestRequirement(
		"run_github_0001", "conn_github0000000000000001", "github", "list_repositories",
	)
	t.Run("stopped", func(t *testing.T) {
		manager := newFakeProviderGatewayManager()
		opener := newFakeProviderGatewayOpener(map[string]string{
			"conn_github0000000000000001": providerGatewaySecretSentinel,
		})
		fixture := newProviderGatewayTestReconciler(t, manager, opener, &fakeProviderGatewayExecutor{})
		if err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
			t.Fatalf("first reconcile pass: %v", err)
		}
		handle := manager.handle(providerGatewaySandboxID, "run_github_0001")
		credential := opener.issued("conn_github0000000000000001")[0]
		if err := fixture.reconcile(t, providerGatewayTestManifest(2, "stopped", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
			t.Fatalf("stopped reconcile pass: %v", err)
		}
		if handle == nil || handle.closeCount() == 0 {
			t.Fatal("stopping the sandbox did not close its provider gateway")
		}
		if !credential.isDestroyed() {
			t.Fatal("stopping the sandbox did not destroy the opened credential")
		}
		if manager.Has(providerGatewaySandboxID, "run_github_0001") {
			t.Fatal("stopped sandbox still tracks a provider gateway")
		}
		local := fixture.localSandbox(t)
		if local == nil || local.ObservedState != "stopped" {
			t.Fatalf("sandbox state after stop = %#v", local)
		}
	})

	t.Run("deleted", func(t *testing.T) {
		manager := newFakeProviderGatewayManager()
		opener := newFakeProviderGatewayOpener(map[string]string{
			"conn_github0000000000000001": providerGatewaySecretSentinel,
		})
		fixture := newProviderGatewayTestReconciler(t, manager, opener, &fakeProviderGatewayExecutor{})
		if err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
			t.Fatalf("first reconcile pass: %v", err)
		}
		credential := opener.issued("conn_github0000000000000001")[0]
		if err := fixture.reconcile(t, providerGatewayTestManifest(2, "deleted", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
			t.Fatalf("deleted reconcile pass: %v", err)
		}
		if manager.Has(providerGatewaySandboxID, "run_github_0001") {
			t.Fatal("deleted sandbox still tracks a provider gateway")
		}
		if !credential.isDestroyed() {
			t.Fatal("deleting the sandbox did not destroy the opened credential")
		}
		if fixture.engine.removed != 1 {
			t.Fatalf("container removals = %d, want 1", fixture.engine.removed)
		}
		local := fixture.localSandbox(t)
		if local == nil || local.ObservedState != "deleted" {
			t.Fatalf("sandbox state after delete = %#v", local)
		}
	})

	t.Run("omitted from manifest", func(t *testing.T) {
		manager := newFakeProviderGatewayManager()
		opener := newFakeProviderGatewayOpener(map[string]string{
			"conn_github0000000000000001": providerGatewaySecretSentinel,
		})
		fixture := newProviderGatewayTestReconciler(t, manager, opener, &fakeProviderGatewayExecutor{})
		if err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
			t.Fatalf("first reconcile pass: %v", err)
		}
		credential := opener.issued("conn_github0000000000000001")[0]
		omitted := providerGatewayTestManifest(2, "running", 1, nil)
		omitted.Sandboxes = nil
		if err := fixture.reconcile(t, omitted); err != nil {
			t.Fatalf("omitted-sandbox reconcile pass: %v", err)
		}
		if manager.Has(providerGatewaySandboxID, "run_github_0001") {
			t.Fatal("omitted sandbox still tracks a provider gateway")
		}
		if !credential.isDestroyed() {
			t.Fatal("omitting the sandbox did not destroy the opened credential")
		}
		if local := fixture.localSandbox(t); local != nil {
			t.Fatalf("omitted sandbox tombstone was not pruned: %#v", local)
		}
	})

	t.Run("generation change", func(t *testing.T) {
		manager := newFakeProviderGatewayManager()
		opener := newFakeProviderGatewayOpener(map[string]string{
			"conn_github0000000000000001": providerGatewaySecretSentinel,
		})
		fixture := newProviderGatewayTestReconciler(t, manager, opener, &fakeProviderGatewayExecutor{})
		if err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
			t.Fatalf("first reconcile pass: %v", err)
		}
		firstHandle := manager.handle(providerGatewaySandboxID, "run_github_0001")
		firstCredential := opener.issued("conn_github0000000000000001")[0]
		if err := fixture.reconcile(t, providerGatewayTestManifest(2, "running", 2, []model.ProviderGatewayRequirement{requirement})); err != nil {
			t.Fatalf("generation-change reconcile pass: %v", err)
		}
		starts := manager.starts()
		if len(starts) != 2 {
			t.Fatalf("generation change starts = %d, want 2", len(starts))
		}
		if firstHandle == nil || firstHandle.closeCount() == 0 {
			t.Fatal("generation change did not close the previous gateway")
		}
		if !firstCredential.isDestroyed() {
			t.Fatal("generation change did not destroy the previous credential")
		}
		secondCredentials := opener.issued("conn_github0000000000000001")
		if len(secondCredentials) != 2 || secondCredentials[1].isDestroyed() {
			t.Fatal("generation change did not open a fresh live credential")
		}
		if fixture.engine.restarted != 1 {
			t.Fatalf("container restarts = %d, want 1", fixture.engine.restarted)
		}
		local := fixture.localSandbox(t)
		if local == nil || local.ObservedState != "running" || local.ObservedGeneration != 2 {
			t.Fatalf("sandbox was not committed at generation 2: %#v", local)
		}
	})
}

func TestReconcileFailsClosedWhenProviderGatewayDependenciesMissing(t *testing.T) {
	requirement := providerGatewayTestRequirement(
		"run_github_0001", "conn_github0000000000000001", "github", "list_repositories",
	)
	tests := []struct {
		name     string
		manager  ProviderGatewayManager
		opener   ProviderCredentialOpener
		executor providergateway.Executor
		want     string
	}{
		{
			name:     "manager missing",
			opener:   newFakeProviderGatewayOpener(map[string]string{"conn_github0000000000000001": providerGatewaySecretSentinel}),
			executor: &fakeProviderGatewayExecutor{},
			want:     "lifecycle manager is not configured",
		},
		{
			name:     "credential opener missing",
			manager:  newFakeProviderGatewayManager(),
			executor: &fakeProviderGatewayExecutor{},
			want:     "box credential opener is not configured",
		},
		{
			name:    "executor missing",
			manager: newFakeProviderGatewayManager(),
			opener:  newFakeProviderGatewayOpener(map[string]string{"conn_github0000000000000001": providerGatewaySecretSentinel}),
			want:    "tool executor is not configured",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProviderGatewayTestReconciler(t, test.manager, test.opener, test.executor)
			err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, []model.ProviderGatewayRequirement{requirement}))
			if err == nil {
				t.Fatal("reconcile claimed a sandbox with unconfigured provider gateways")
			}
			if !errors.Is(err, errProviderGatewayNotEnabled) {
				t.Fatalf("reconcile error = %v, want the feature-not-enabled sentinel", err)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("reconcile error = %v, want %q", err, test.want)
			}
			if len(err.Error()) > 1024 {
				t.Fatalf("reconcile error is not bounded: %d bytes", len(err.Error()))
			}
			if strings.Contains(err.Error(), providerGatewaySecretSentinel) {
				t.Fatal("reconcile error leaked a credential secret")
			}
			if manager, ok := test.manager.(*fakeProviderGatewayManager); ok && manager.startCount() != 0 {
				t.Fatalf("unconfigured feature started %d gateways", manager.startCount())
			}
			local := fixture.localSandbox(t)
			if local == nil || local.ObservedState == "running" {
				t.Fatalf("sandbox was claimed ready despite the missing feature: %#v", local)
			}
			if local.ErrorCode != "provider_gateway_not_enabled" {
				t.Fatalf("sandbox error code = %q, want provider_gateway_not_enabled", local.ErrorCode)
			}
		})
	}
}

func TestReconcileDoesNotStartProviderGatewayBeforeWorkspaceIsReady(t *testing.T) {
	manager := newFakeProviderGatewayManager()
	opener := newFakeProviderGatewayOpener(map[string]string{
		"conn_github0000000000000001": providerGatewaySecretSentinel,
	})
	fixture := newProviderGatewayTestReconciler(t, manager, opener, &fakeProviderGatewayExecutor{})
	fixture.workspaces.ensureErr = errors.New("workspace mount unavailable")
	requirement := providerGatewayTestRequirement(
		"run_github_0001", "conn_github0000000000000001", "github", "list_repositories",
	)
	err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, []model.ProviderGatewayRequirement{requirement}))
	if err == nil {
		t.Fatal("reconcile succeeded without a workspace")
	}
	if manager.startCount() != 0 || opener.openCount() != 0 {
		t.Fatalf("gateway started before the workspace was ready: starts=%d opens=%d", manager.startCount(), opener.openCount())
	}
	local := fixture.localSandbox(t)
	if local == nil || local.ObservedState == "running" {
		t.Fatalf("sandbox was claimed ready without a workspace: %#v", local)
	}
}

func TestReconcileDestroysCredentialWhenGatewayStartFails(t *testing.T) {
	manager := newFakeProviderGatewayManager()
	manager.startErr = errors.New("listener unavailable")
	opener := newFakeProviderGatewayOpener(map[string]string{
		"conn_github0000000000000001": providerGatewaySecretSentinel,
	})
	fixture := newProviderGatewayTestReconciler(t, manager, opener, &fakeProviderGatewayExecutor{})
	requirement := providerGatewayTestRequirement(
		"run_github_0001", "conn_github0000000000000001", "github", "list_repositories",
	)
	err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, []model.ProviderGatewayRequirement{requirement}))
	if err == nil {
		t.Fatal("reconcile succeeded after the gateway start failed")
	}
	if !strings.Contains(err.Error(), "gateway unavailable") && !strings.Contains(err.Error(), "listener unavailable") {
		t.Fatalf("reconcile error = %v", err)
	}
	credentials := opener.issued("conn_github0000000000000001")
	if len(credentials) != 1 || !credentials[0].isDestroyed() {
		t.Fatal("failed gateway start leaked a live credential")
	}
	if manager.Has(providerGatewaySandboxID, "run_github_0001") {
		t.Fatal("failed gateway start left a tracked gateway")
	}
	local := fixture.localSandbox(t)
	if local == nil || local.ObservedState == "running" {
		t.Fatalf("sandbox was claimed ready after gateway start failure: %#v", local)
	}
	if local.ErrorCode != "provider_gateway_start_failed" {
		t.Fatalf("sandbox error code = %q, want provider_gateway_start_failed", local.ErrorCode)
	}
}

// providerGatewayLogBuffer is a concurrency-safe log sink.
type providerGatewayLogBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (sink *providerGatewayLogBuffer) Write(payload []byte) (int, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.buffer.Write(payload)
}

func (sink *providerGatewayLogBuffer) String() string {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.buffer.String()
}

// TestReconcileRunsRealProviderGatewayManager proves the production manager
// adapter boundary end to end with a fake executor/credential: start, idempotent
// re-use, teardown on stop, credential destruction and secret-free logs, state
// and report.
func TestReconcileRunsRealProviderGatewayManager(t *testing.T) {
	workspaceRoot, err := os.MkdirTemp("/tmp", "pgr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workspaceRoot) })
	logs := &providerGatewayLogBuffer{}
	manager := providergateway.NewManager(log.New(logs, "", 0))
	t.Cleanup(func() { _ = manager.Close(context.Background()) })
	opener := newFakeProviderGatewayOpener(map[string]string{
		"conn_github0000000000000001": providerGatewaySecretSentinel,
	})
	executor := &fakeProviderGatewayExecutor{}
	fixture := newProviderGatewayTestReconciler(
		t, ProviderGateways{Manager: manager}, opener, executor,
	)
	fixture.workspaces.anchor = workspaceRoot
	requirement := providerGatewayTestRequirement(
		"run_github_0001", "conn_github0000000000000001", "github", "list_repositories",
	)
	manifest := providerGatewayTestManifest(1, "running", 1, []model.ProviderGatewayRequirement{requirement})
	if err := fixture.reconcile(t, manifest); err != nil {
		t.Fatalf("reconcile with the production manager: %v", err)
	}
	if !manager.Has(providerGatewaySandboxID, "run_github_0001") {
		t.Fatal("production manager did not report the started gateway")
	}
	socketPath := filepath.Join(
		workspaceRoot, ".warpmetal", "provider-gateways", "run_github_0001.sock",
	)
	if _, err := os.Lstat(socketPath); err != nil {
		t.Fatalf("gateway socket %q: %v", socketPath, err)
	}
	credentials := opener.issued("conn_github0000000000000001")
	if len(credentials) != 1 || credentials[0].isDestroyed() {
		t.Fatal("running gateway credential is missing or already destroyed")
	}
	if err := fixture.reconcile(t, providerGatewayTestManifest(2, "running", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
		t.Fatalf("idempotent second pass: %v", err)
	}
	if opener.openCount() != 1 {
		t.Fatalf("idempotent pass reopened the credential: opens=%d", opener.openCount())
	}
	if !manager.Has(providerGatewaySandboxID, "run_github_0001") {
		t.Fatal("idempotent pass lost the running gateway")
	}

	report, err := fixture.reconciler.Report(context.Background(), providerGatewayServerID, "test")
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	reportPayload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	local := fixture.localSandbox(t)
	if local == nil {
		t.Fatal("sandbox state missing")
	}
	statePayload, err := json.Marshal(local)
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{
		"report": reportPayload,
		"state":  statePayload,
		"logs":   []byte(logs.String()),
	} {
		if strings.Contains(string(payload), providerGatewaySecretSentinel) {
			t.Fatalf("%s leaked the credential secret", name)
		}
	}
	if executor.callCount() != 0 {
		t.Fatalf("tool calls = %d, want 0", executor.callCount())
	}

	if err := fixture.reconcile(t, providerGatewayTestManifest(3, "stopped", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
		t.Fatalf("stopped pass: %v", err)
	}
	if manager.Has(providerGatewaySandboxID, "run_github_0001") {
		t.Fatal("stopped sandbox still tracks the production gateway")
	}
	if !credentials[0].isDestroyed() {
		t.Fatal("stopping the sandbox did not destroy the opened credential")
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("gateway socket still exists after teardown: %v", err)
	}
}

func TestReconcileRetriesProviderGatewayAfterStartFailure(t *testing.T) {
	manager := newFakeProviderGatewayManager()
	manager.startErr = errors.New("listener unavailable")
	opener := newFakeProviderGatewayOpener(map[string]string{
		"conn_github0000000000000001": providerGatewaySecretSentinel,
	})
	fixture := newProviderGatewayTestReconciler(t, manager, opener, &fakeProviderGatewayExecutor{})
	requirement := providerGatewayTestRequirement(
		"run_github_0001", "conn_github0000000000000001", "github", "list_repositories",
	)
	if err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, []model.ProviderGatewayRequirement{requirement})); err == nil {
		t.Fatal("reconcile succeeded while the gateway start failed")
	}
	// The retry is idempotent on the failure path: the failed attempt left no
	// handle and no live credential, so a healthy manager starts exactly once.
	manager.mu.Lock()
	manager.startErr = nil
	manager.mu.Unlock()
	if err := fixture.reconcile(t, providerGatewayTestManifest(2, "running", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
		t.Fatalf("retried reconcile pass: %v", err)
	}
	if manager.startCount() != 2 {
		t.Fatalf("start attempts = %d, want the failed attempt plus one retry", manager.startCount())
	}
	if !manager.Has(providerGatewaySandboxID, "run_github_0001") {
		t.Fatal("retried pass did not leave a running gateway")
	}
	local := fixture.localSandbox(t)
	if local == nil || local.ObservedState != "running" {
		t.Fatalf("retried sandbox was not committed running: %#v", local)
	}
}

func TestReconcileRetriesProviderGatewayTeardown(t *testing.T) {
	manager := newFakeProviderGatewayManager()
	opener := newFakeProviderGatewayOpener(map[string]string{
		"conn_github0000000000000001": providerGatewaySecretSentinel,
	})
	fixture := newProviderGatewayTestReconciler(t, manager, opener, &fakeProviderGatewayExecutor{})
	requirement := providerGatewayTestRequirement(
		"run_github_0001", "conn_github0000000000000001", "github", "list_repositories",
	)
	if err := fixture.reconcile(t, providerGatewayTestManifest(1, "running", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
		t.Fatalf("first reconcile pass: %v", err)
	}
	credential := opener.issued("conn_github0000000000000001")[0]
	manager.mu.Lock()
	manager.closeErr = errors.New("teardown busy")
	manager.mu.Unlock()
	err := fixture.reconcile(t, providerGatewayTestManifest(2, "stopped", 1, []model.ProviderGatewayRequirement{requirement}))
	if err == nil {
		t.Fatal("reconcile succeeded although gateway teardown failed")
	}
	local := fixture.localSandbox(t)
	if local == nil || local.ErrorCode != "provider_gateway_close_failed" {
		t.Fatalf("failed teardown did not fail the sandbox closed: %#v", local)
	}
	if !credential.isDestroyed() {
		t.Fatal("failed teardown leaked the opened credential")
	}
	// The next pass retries the teardown and then completes the stop.
	manager.mu.Lock()
	manager.closeErr = nil
	manager.mu.Unlock()
	if err := fixture.reconcile(t, providerGatewayTestManifest(3, "stopped", 1, []model.ProviderGatewayRequirement{requirement})); err != nil {
		t.Fatalf("retried stop pass: %v", err)
	}
	local = fixture.localSandbox(t)
	if local == nil || local.ObservedState != "stopped" {
		t.Fatalf("retried stop pass did not complete: %#v", local)
	}
	if manager.Has(providerGatewaySandboxID, "run_github_0001") {
		t.Fatal("retried stop pass left a provider gateway running")
	}
}
