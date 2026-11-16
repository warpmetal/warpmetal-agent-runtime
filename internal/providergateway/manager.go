package providergateway

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultContainerRoot is where the sandbox workspace is mounted inside the
	// container. The agent runs as UID 1000 with the workspace mounted at
	// /home/agent, so the container-side socket path is deterministic.
	DefaultContainerRoot = "/home/agent"

	// gatewayRelativeDir is where sandbox-facing provider gateway sockets live,
	// relative to the workspace root. The same relative layout exists on the
	// host and inside the container.
	gatewayRelativeDir = ".warpmetal/provider-gateways"
	// socketFileSuffix is appended to the run id to name a gateway socket.
	socketFileSuffix = ".sock"

	// startReadyTimeout bounds how long Start waits for the gateway to accept
	// connections before declaring startup failed and cleaning up.
	startReadyTimeout = 5 * time.Second
	// startReadyPoll is how often Start probes the listener while waiting.
	startReadyPoll = 2 * time.Millisecond
	// startReadyDialTimeout bounds one readiness probe.
	startReadyDialTimeout = 250 * time.Millisecond
	// closeTimeout bounds Handle.Close waiting for the serve goroutine to
	// return, independent of any caller deadline.
	closeTimeout = 5 * time.Second

	// maxUnixSocketPathBytes is a conservative ceiling for a Unix socket path.
	// sockaddr_un allows 104 bytes on Darwin (including the NUL terminator) and
	// 108 on Linux; going beyond that fails at bind time with an unhelpful
	// platform error, so the manager rejects it deterministically.
	maxUnixSocketPathBytes = 100
	// maxRunIDBytes is the maximum run id length accepted by runIDPattern.
	maxRunIDBytes = 128
)

var (
	// ErrManagerClosed is returned by Start once Manager.Close has been called.
	// It does not affect handles that are already running: Manager.Close closes
	// those before returning, and CloseAll/CloseSandbox remain usable.
	ErrManagerClosed = errors.New("providergateway: manager is closed")
	// ErrGatewayAlreadyStarted is returned when a gateway already exists for the
	// same (SandboxID, RunID) pair.
	ErrGatewayAlreadyStarted = errors.New("providergateway: gateway already started for sandbox and run")

	// runIDPattern is the bounded, traversal-free run identifier shape. A run id
	// is used as a file name, so anything but letters, digits, '_' and '-' is
	// refused.
	runIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
)

// gatewayPathComponents are the fixed directory components below the workspace
// root. They never come from caller input.
var gatewayPathComponents = []string{".warpmetal", "provider-gateways"}

// Request describes one sandbox-facing provider gateway to start. It carries
// only non-secret platform metadata; the opened Credential is the sole secret
// input and it is never logged, rendered or returned.
type Request struct {
	// SandboxID is the sandbox the gateway belongs to (non-secret metadata).
	// Required.
	SandboxID string
	// RunID is the bounded safe identifier of the run that owns the gateway. It
	// names the socket file, so it must match ^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$.
	// Required.
	RunID string
	// WorkspaceHostRoot is the host path of the sandbox workspace the gateway
	// socket is created under. It must already exist as a regular directory.
	// Required.
	WorkspaceHostRoot string
	// ContainerRoot is where the workspace is mounted inside the container.
	// Empty uses DefaultContainerRoot (/home/agent).
	ContainerRoot string
	// ProviderID is the non-secret tool provider identifier. Required.
	ProviderID string
	// ConnectionID is the non-secret platform account connection identifier.
	// Required.
	ConnectionID string
	// AccountID is the non-secret owner account the credential belongs to.
	// Optional.
	AccountID string
	// Tools is the template-declared tool allowlist. Exactly these tools are
	// advertised and callable. Required, at least one.
	Tools []Tool
	// Executor executes declared tool calls. Required.
	Executor Executor
	// Credential is the opened provider credential. The manager takes ownership
	// of it for every Start call: a successful Start destroys it exactly once
	// when the returned Handle is closed, and a failed Start destroys it before
	// returning. Nil means the gateway runs without a credential.
	Credential Credential
	// ToolTimeout optionally bounds one executor call. Zero uses the gateway
	// default.
	ToolTimeout time.Duration
}

// Manager owns the lifecycle of every scoped provider gateway in this runtime
// process. It tracks the running handles of all sandboxes, refuses duplicate
// (SandboxID, RunID) starts, and guarantees teardown: listener, live
// connections, credential, socket file and an owned socket directory.
//
// A Manager is safe for concurrent use. Start serializes its short filesystem
// preparation and duplicate check, and each started gateway then serves
// independently. Close marks the manager closed, waits for in-flight starts and
// closes every handle; CloseAll and CloseSandbox close running handles without
// closing the manager.
type Manager struct {
	logger *log.Logger

	mu          sync.Mutex
	handles     map[string]*Handle
	gatewayDirs map[string]*gatewayDirectoryState
	closed      bool
	starts      sync.WaitGroup
}

// gatewayDirectoryState tracks one resolved gateway directory across all its
// handles. The directory is removed when its last handle stops, and only when
// this manager created it: a directory that already existed is always left in
// place.
type gatewayDirectoryState struct {
	created bool
	handles int
}

// NewManager creates a Manager. A nil logger uses log.Default(); the manager
// never logs tool arguments, tool results or credential material.
func NewManager(logger *log.Logger) *Manager {
	if logger == nil {
		logger = log.Default()
	}
	return &Manager{
		logger:      logger,
		handles:     make(map[string]*Handle),
		gatewayDirs: make(map[string]*gatewayDirectoryState),
	}
}

// Start prepares the sandbox workspace gateway directory, starts the provider
// gateway server on the deterministic Unix socket and waits until the listener
// accepts connections. It returns a Handle whose Close tears the gateway down.
//
// Start is refused when the manager is closed (ErrManagerClosed) or when a
// gateway already exists for the same (SandboxID, RunID) pair
// (ErrGatewayAlreadyStarted). The refused request's credential is destroyed
// before the error is returned.
//
// The supplied context bounds the gateway lifetime: when it is cancelled the
// gateway stops, its cleanup runs and the handle detaches itself from the
// manager.
func (m *Manager) Start(ctx context.Context, request Request) (handle *Handle, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if validateErr := request.validate(); validateErr != nil {
		// Start takes ownership of the credential on every path, including a
		// rejected request, so a failed call never leaks an opened credential.
		request.destroyCredential()
		return nil, validateErr
	}
	defer func() {
		if err != nil {
			m.logger.Printf(
				"provider gateway manager: start failed sandboxId=%q runId=%q: %s",
				request.SandboxID, request.RunID, logSafe(err.Error()),
			)
		}
	}()
	if ctxErr := ctx.Err(); ctxErr != nil {
		request.destroyCredential()
		return nil, fmt.Errorf("providergateway: start: %w", ctxErr)
	}

	handle, err = m.reserve(request)
	if err != nil {
		request.destroyCredential()
		return nil, err
	}
	defer m.starts.Done()

	gateway, newErr := New(Config{
		SocketPath:   handle.sandboxSocketPath,
		RootDir:      request.WorkspaceHostRoot,
		ProviderID:   request.ProviderID,
		ConnectionID: request.ConnectionID,
		Tools:        request.Tools,
		Executor:     request.Executor,
		Credential:   request.Credential,
		Logger:       m.logger,
		ToolTimeout:  request.ToolTimeout,
	})
	if newErr != nil {
		// New does not take ownership of the credential when it fails.
		request.destroyCredential()
		m.detach(handle)
		handle.releaseGatewayDir()
		return nil, fmt.Errorf("providergateway: start: %w", newErr)
	}

	serveCtx, cancel := context.WithCancel(ctx)
	handle.gateway = gateway
	handle.cancel = cancel
	handle.serveExit = make(chan error, 1)
	go func() { handle.serveExit <- gateway.Serve(serveCtx) }()
	go handle.supervise()
	handle.mu.Lock()
	handle.launched = true
	handle.mu.Unlock()

	if readyErr := handle.waitReady(ctx); readyErr != nil {
		_ = handle.Close(context.Background())
		return nil, readyErr
	}
	// The context can cancel in the readiness window; do not hand back a
	// gateway that is already on its way out.
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = handle.Close(context.Background())
		return nil, fmt.Errorf("providergateway: start: %w", ctxErr)
	}

	// A start that raced Manager.Close must not escape as a live handle.
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		_ = handle.Close(context.Background())
		return nil, ErrManagerClosed
	}

	m.logger.Printf(
		"provider gateway manager: gateway ready sandboxId=%q runId=%q providerId=%q connectionId=%q accountId=%q socket=%q containerSocket=%q",
		request.SandboxID, request.RunID, request.ProviderID, request.ConnectionID,
		request.AccountID, handle.sandboxSocketPath, handle.containerSocketPath,
	)
	return handle, nil
}

// CloseAll closes every gateway the manager currently tracks and waits for
// their teardown. The manager stays open, so Start remains available. A Start
// that is still preparing when CloseAll runs is left to finish; it owns its own
// cleanup if that preparation fails.
func (m *Manager) CloseAll(ctx context.Context) error {
	return m.closeHandles(ctx, nil)
}

// CloseSandbox closes every gateway that belongs to sandboxID and waits for
// their teardown. Other sandboxes are untouched. An unknown or empty sandbox id
// closes nothing and returns nil.
func (m *Manager) CloseSandbox(ctx context.Context, sandboxID string) error {
	if sandboxID == "" {
		return nil
	}
	return m.closeHandles(ctx, func(handle *Handle) bool { return handle.sandboxID == sandboxID })
}

// Close marks the manager closed, waits for in-flight Start calls to finish and
// closes every gateway. After Close returns, Start fails with ErrManagerClosed.
// Close is idempotent.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.starts.Wait()
	return m.closeHandles(ctx, nil)
}

// reserve validates the request against the manager state, prepares the owned
// gateway directory and inserts a starting handle. It runs under the manager
// lock so the duplicate check, the directory ownership bookkeeping and the
// Start WaitGroup accounting are atomic with respect to Manager.Close.
func (m *Manager) reserve(request Request) (*Handle, error) {
	key := request.SandboxID + "\x00" + request.RunID
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrManagerClosed
	}
	if _, exists := m.handles[key]; exists {
		return nil, fmt.Errorf(
			"%w: sandbox %q run %q",
			ErrGatewayAlreadyStarted, request.SandboxID, request.RunID,
		)
	}
	directory, err := prepareGatewayDirectory(request.WorkspaceHostRoot)
	if err != nil {
		return nil, err
	}
	state := m.gatewayDirs[directory.resolved]
	if state == nil {
		state = &gatewayDirectoryState{created: directory.created}
		m.gatewayDirs[directory.resolved] = state
	}
	state.handles++
	handle := &Handle{
		manager:             m,
		key:                 key,
		sandboxID:           request.SandboxID,
		runID:               request.RunID,
		providerID:          request.ProviderID,
		connectionID:        request.ConnectionID,
		accountID:           request.AccountID,
		gatewaysDir:         directory.path,
		resolvedGatewaysDir: directory.resolved,
		sandboxSocketPath:   filepath.Join(directory.path, request.RunID+socketFileSuffix),
		containerSocketPath: filepath.Join(request.containerRoot(), gatewayRelativeDir, request.RunID+socketFileSuffix),
		done:                make(chan struct{}),
	}
	m.handles[key] = handle
	m.starts.Add(1)
	return handle, nil
}

// detach forgets a handle. It is idempotent and safe to call from the serve
// supervisor and from Start failure paths.
func (m *Manager) detach(handle *Handle) {
	handle.detachOnce.Do(func() {
		m.mu.Lock()
		if m.handles[handle.key] == handle {
			delete(m.handles, handle.key)
		}
		m.mu.Unlock()
	})
}

// releaseGatewayDir drops one reference to a gateway directory and removes the
// directory when it was created by this manager and its last handle is gone.
// The removal happens under the manager lock so a concurrent Start can never
// observe an existing directory that is about to disappear (which would leave
// an untracked directory behind).
func (m *Manager) releaseGatewayDir(resolved string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.gatewayDirs[resolved]
	if state == nil {
		return
	}
	state.handles--
	if state.handles > 0 {
		return
	}
	delete(m.gatewayDirs, resolved)
	if state.created {
		// os.Remove (never RemoveAll) leaves the directory alone if another
		// process added an entry in the meantime.
		_ = os.Remove(resolved)
	}
}

// closeHandles snapshots the matching handles and closes them. The snapshot is
// taken before any close so a handle detaching itself during teardown is still
// closed exactly once (Close is idempotent).
func (m *Manager) closeHandles(ctx context.Context, match func(*Handle) bool) error {
	m.mu.Lock()
	handles := make([]*Handle, 0, len(m.handles))
	for _, handle := range m.handles {
		if match == nil || match(handle) {
			handles = append(handles, handle)
		}
	}
	m.mu.Unlock()

	var errs []error
	for _, handle := range handles {
		if err := handle.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// validate checks everything about a Request that can be checked without
// touching the filesystem. The workspace root directory itself is verified by
// prepareGatewayDirectory.
func (r Request) validate() error {
	if !runIDPattern.MatchString(r.RunID) {
		return fmt.Errorf(
			"providergateway: run id must be a safe identifier (letters, digits, '_' or '-', at most %d bytes)",
			maxRunIDBytes,
		)
	}
	if err := validateMetadata("sandbox id", r.SandboxID); err != nil {
		return err
	}
	if err := validateMetadata("provider id", r.ProviderID); err != nil {
		return err
	}
	if err := validateMetadata("connection id", r.ConnectionID); err != nil {
		return err
	}
	if r.AccountID != "" {
		if err := validateMetadata("account id", r.AccountID); err != nil {
			return err
		}
	}
	if err := validateWorkspaceRoot(r.WorkspaceHostRoot); err != nil {
		return err
	}
	if err := validateContainerRoot(r.containerRoot()); err != nil {
		return err
	}
	hostSocketPath, containerSocketPath := r.socketPaths()
	if len(hostSocketPath) > maxUnixSocketPathBytes {
		return fmt.Errorf(
			"providergateway: host socket path is too long (%d bytes, limit %d)",
			len(hostSocketPath), maxUnixSocketPathBytes,
		)
	}
	if len(containerSocketPath) > maxUnixSocketPathBytes {
		return fmt.Errorf(
			"providergateway: container socket path is too long (%d bytes, limit %d)",
			len(containerSocketPath), maxUnixSocketPathBytes,
		)
	}
	return nil
}

// containerRoot returns the effective container root for the request.
func (r Request) containerRoot() string {
	if r.ContainerRoot == "" {
		return DefaultContainerRoot
	}
	return r.ContainerRoot
}

// socketPaths returns the deterministic host and container socket paths for the
// request. RunID, WorkspaceHostRoot and ContainerRoot must already be valid.
func (r Request) socketPaths() (hostSocketPath, containerSocketPath string) {
	relative := filepath.Join(gatewayRelativeDir, r.RunID+socketFileSuffix)
	return filepath.Join(r.WorkspaceHostRoot, relative), filepath.Join(r.containerRoot(), relative)
}

// destroyCredential destroys the request's credential, if any. It is called
// only on paths where the gateway never took ownership, because the gateway
// destroys the credential exactly once itself.
func (r Request) destroyCredential() {
	if r.Credential != nil {
		r.Credential.Destroy()
	}
}

func validateWorkspaceRoot(root string) error {
	if strings.TrimSpace(root) == "" {
		return errors.New("providergateway: workspace host root is required")
	}
	if strings.ContainsRune(root, 0) {
		return errors.New("providergateway: workspace host root contains a NUL byte")
	}
	if !filepath.IsAbs(root) {
		return errors.New("providergateway: workspace host root must be absolute")
	}
	if filepath.Clean(root) != root {
		return errors.New("providergateway: workspace host root must be a clean path")
	}
	return nil
}

func validateContainerRoot(root string) error {
	if strings.ContainsRune(root, 0) {
		return errors.New("providergateway: container root contains a NUL byte")
	}
	if !filepath.IsAbs(root) {
		return errors.New("providergateway: container root must be absolute")
	}
	if filepath.Clean(root) != root {
		return errors.New("providergateway: container root must be a clean path")
	}
	return nil
}

// gatewayDirectory is the prepared socket directory for one workspace.
type gatewayDirectory struct {
	// path is the workspace-relative spelling used to build the host socket
	// path that the caller is told about.
	path string
	// resolved is the symlink-resolved path used for ownership bookkeeping.
	resolved string
	// created reports whether this call created the directory.
	created bool
}

// prepareGatewayDirectory validates the workspace root and prepares
// <root>/.warpmetal/provider-gateways as an owner-only directory. The workspace
// root must already exist as a regular directory (not a symlink). Existing
// gateway path components must not be symlinks, so a planted link cannot move
// the socket outside the workspace, and an existing provider-gateways directory
// must already be owner-only. The resolved directory is verified to stay inside
// the resolved workspace root.
func prepareGatewayDirectory(workspaceRoot string) (gatewayDirectory, error) {
	directory := filepath.Join(workspaceRoot, gatewayRelativeDir)
	rootInfo, err := os.Lstat(workspaceRoot)
	if err != nil {
		return gatewayDirectory{}, fmt.Errorf("providergateway: workspace root %q: %w", workspaceRoot, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return gatewayDirectory{}, fmt.Errorf("providergateway: workspace root %q must not be a symlink", workspaceRoot)
	}
	if !rootInfo.IsDir() {
		return gatewayDirectory{}, fmt.Errorf("providergateway: workspace root %q is not a directory", workspaceRoot)
	}
	resolvedRoot, err := filepath.EvalSymlinks(workspaceRoot)
	if err != nil {
		return gatewayDirectory{}, fmt.Errorf("providergateway: resolve workspace root %q: %w", workspaceRoot, err)
	}

	created := false
	current := workspaceRoot
	for index, component := range gatewayPathComponents {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, fs.ErrNotExist) {
			if mkdirErr := os.MkdirAll(directory, socketDirectoryPermissions); mkdirErr != nil {
				return gatewayDirectory{}, fmt.Errorf("providergateway: create gateway directory %q: %w", directory, mkdirErr)
			}
			created = true
			break
		}
		if statErr != nil {
			return gatewayDirectory{}, fmt.Errorf("providergateway: inspect gateway path %q: %w", current, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return gatewayDirectory{}, fmt.Errorf("providergateway: gateway path %q must not be a symlink", current)
		}
		if !info.IsDir() {
			return gatewayDirectory{}, fmt.Errorf("providergateway: gateway path %q is not a directory", current)
		}
		// Only the final provider-gateways directory protects the socket, so
		// only it must already be owner-only. A pre-existing .warpmetal may be
		// shared with other workspace tooling.
		if index == len(gatewayPathComponents)-1 && info.Mode().Perm()&0o077 != 0 {
			return gatewayDirectory{}, fmt.Errorf(
				"providergateway: gateway directory %q must be owner-only (found mode %04o)",
				current, info.Mode().Perm(),
			)
		}
	}
	if created {
		// MkdirAll applies the process umask; tighten explicitly so the run
		// directory is always 0700.
		if chmodErr := os.Chmod(directory, socketDirectoryPermissions); chmodErr != nil {
			_ = os.Remove(directory)
			return gatewayDirectory{}, fmt.Errorf("providergateway: set gateway directory permissions: %w", chmodErr)
		}
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		if created {
			_ = os.Remove(directory)
		}
		return gatewayDirectory{}, fmt.Errorf("providergateway: resolve gateway directory %q: %w", directory, err)
	}
	if !pathWithin(resolvedDirectory, resolvedRoot) {
		if created {
			_ = os.Remove(directory)
		}
		return gatewayDirectory{}, fmt.Errorf(
			"providergateway: gateway directory %q resolves outside workspace root %q",
			directory, workspaceRoot,
		)
	}
	return gatewayDirectory{path: directory, resolved: resolvedDirectory, created: created}, nil
}
