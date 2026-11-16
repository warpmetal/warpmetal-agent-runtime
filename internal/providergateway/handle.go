package providergateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Handle is one running sandbox-facing provider gateway. It is returned by
// Manager.Start once the Unix listener accepts connections.
//
// The handle exposes the deterministic socket paths the caller needs: the host
// path the runtime dials or forwards and the container path the agent's MCP
// entry (socat) dials. Close tears the gateway down. The handle also detaches
// itself and runs its cleanup when the Serve context is cancelled or the server
// exits, so no listener, socket file or goroutine outlives the gateway.
type Handle struct {
	manager *Manager

	key          string
	sandboxID    string
	runID        string
	providerID   string
	connectionID string
	accountID    string

	gatewaysDir         string
	resolvedGatewaysDir string
	sandboxSocketPath   string
	containerSocketPath string

	// gateway, cancel and serveExit are written once by Start before the
	// server goroutines are launched. They are immutable afterwards.
	gateway   *Gateway
	cancel    context.CancelFunc
	serveExit chan error

	mu       sync.Mutex
	launched bool
	serveErr error

	// done is closed by the supervisor once the server returned, the handle is
	// detached and the owned directory has been released.
	done chan struct{}

	closeOnce      sync.Once
	closeErr       error
	detachOnce     sync.Once
	releaseDirOnce sync.Once
}

// SandboxSocketPath returns the host path of the gateway's Unix socket:
// <WorkspaceHostRoot>/.warpmetal/provider-gateways/<RunID>.sock.
func (h *Handle) SandboxSocketPath() string {
	return h.sandboxSocketPath
}

// ContainerSocketPath returns the socket path as seen inside the sandbox
// container: <ContainerRoot>/.warpmetal/provider-gateways/<RunID>.sock, with
// ContainerRoot defaulting to /home/agent.
func (h *Handle) ContainerSocketPath() string {
	return h.containerSocketPath
}

// Done returns a channel that is closed once the gateway has stopped and its
// cleanup (detach, owned directory release, socket removal) has finished. It is
// the explicit signal a caller can wait on to prove no gateway goroutine is
// left behind.
func (h *Handle) Done() <-chan struct{} {
	return h.done
}

// Close stops the gateway and waits for its teardown: it cancels Serve, closes
// the listener and live connections, removes the socket file when it is still
// this gateway's, destroys the credential exactly once and releases the
// workspace gateway directory when this manager created it.
//
// Close is idempotent and bounded: it waits at most until ctx is done or the
// internal close timeout expires, whichever is earlier. It returns nil on a
// completed teardown. It is safe to call after the gateway stopped by itself
// (server error or cancelled Start context).
func (h *Handle) Close(ctx context.Context) error {
	// A handle can be observed by a concurrent CloseAll while Start is still
	// preparing it. Leave that handle to Start, which owns its cleanup, rather
	// than consuming the one-shot close.
	h.mu.Lock()
	launched := h.launched
	h.mu.Unlock()
	if !launched {
		return nil
	}
	h.closeOnce.Do(func() {
		h.mu.Lock()
		cancel := h.cancel
		gateway := h.gateway
		h.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if gateway != nil {
			_ = gateway.Close()
		}
		if ctx == nil {
			ctx = context.Background()
		}
		waitCtx, waitCancel := context.WithTimeout(ctx, closeTimeout)
		defer waitCancel()
		select {
		case <-h.done:
		default:
			// Only wait when cleanup has not finished yet, so an already
			// cancelled caller context cannot turn a completed teardown into a
			// spurious timeout error.
			select {
			case <-h.done:
			case <-waitCtx.Done():
				h.closeErr = fmt.Errorf("providergateway: close did not finish: %w", waitCtx.Err())
			}
		}
	})
	return h.closeErr
}

// String renders non-secret lifecycle metadata for diagnostics. Credential
// material, tool arguments and tool results are never part of a Handle.
func (h *Handle) String() string {
	h.mu.Lock()
	launched := h.launched
	serveErr := h.serveErr
	h.mu.Unlock()

	state := "starting"
	if launched {
		state = "running"
		select {
		case <-h.done:
			if serveErr != nil {
				state = "failed"
			} else {
				state = "stopped"
			}
		default:
		}
	}
	return fmt.Sprintf(
		"providergateway.Handle{sandboxId=%q runId=%q providerId=%q connectionId=%q accountId=%q socket=%q containerSocket=%q state=%s}",
		h.sandboxID, h.runID, h.providerID, h.connectionID, h.accountID,
		h.sandboxSocketPath, h.containerSocketPath, state,
	)
}

// GoString renders the same non-secret form for %#v.
func (h *Handle) GoString() string {
	return h.String()
}

// supervise owns the post-serve cleanup. It runs until Serve returns: it
// records the server outcome, detaches the handle from the manager, releases the
// owned workspace directory and only then closes Done. Every exit path from
// Serve therefore ends with a detached handle and no socket left behind.
func (h *Handle) supervise() {
	serveErr := <-h.serveExit
	h.mu.Lock()
	h.serveErr = serveErr
	h.mu.Unlock()

	h.manager.detach(h)
	h.releaseGatewayDir()
	if serveErr != nil {
		h.manager.logger.Printf(
			"provider gateway manager: gateway exited sandboxId=%q runId=%q: %s",
			h.sandboxID, h.runID, logSafe(serveErr.Error()),
		)
	} else {
		h.manager.logger.Printf(
			"provider gateway manager: gateway stopped sandboxId=%q runId=%q socket=%q",
			h.sandboxID, h.runID, h.sandboxSocketPath,
		)
	}
	close(h.done)
}

// releaseGatewayDir drops this handle's reference to its gateway directory. It
// is idempotent.
func (h *Handle) releaseGatewayDir() {
	h.releaseDirOnce.Do(func() {
		h.manager.releaseGatewayDir(h.resolvedGatewaysDir)
	})
}

// waitReady waits until the Unix listener accepts a probe connection, a bounded
// readiness window expires, the start context is cancelled or the server exits.
func (h *Handle) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(startReadyTimeout)
	ticker := time.NewTicker(startReadyPoll)
	defer ticker.Stop()
	for {
		conn, dialErr := net.DialTimeout("unix", h.sandboxSocketPath, startReadyDialTimeout)
		if dialErr == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-h.done:
			return h.startExitError(ctx)
		case <-ctx.Done():
			return fmt.Errorf("providergateway: start: %w", ctx.Err())
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf(
					"providergateway: gateway did not accept connections within %s",
					startReadyTimeout,
				)
			}
		}
	}
}

// startExitError renders the bounded, secret-free reason a server exited before
// it became ready. The serve error may name workspace paths but never tool data
// or credential material; it is sanitized and truncated before being surfaced.
func (h *Handle) startExitError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("providergateway: start: %w", err)
	}
	h.mu.Lock()
	serveErr := h.serveErr
	h.mu.Unlock()
	if serveErr != nil {
		return fmt.Errorf("providergateway: gateway exited before becoming ready: %s", logSafe(serveErr.Error()))
	}
	return errors.New("providergateway: gateway exited before becoming ready")
}
