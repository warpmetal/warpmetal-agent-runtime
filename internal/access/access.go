package access

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

var grantID = regexp.MustCompile(`^grant_[A-Za-z0-9_-]{8,60}$`)

type Renderer struct {
	Path    string
	Gateway string
}

func (r Renderer) Write(grants []state.LocalGrant) error {
	var lines []string
	for _, grant := range grants {
		if grant.DesiredState != "active" {
			continue
		}
		if !grantID.MatchString(grant.ID) {
			return fmt.Errorf("invalid grant ID %q", grant.ID)
		}
		key, err := normalizePublicKey(grant.SSHPublicKey)
		if err != nil {
			return fmt.Errorf("grant %s: %w", grant.ID, err)
		}
		gateway := r.Gateway
		if gateway == "" {
			gateway = "/usr/libexec/warpmetal-sandbox-gateway"
		}
		options := fmt.Sprintf(
			`command="%s %s",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc`,
			gateway,
			grant.ID,
		)
		lines = append(lines, options+" "+key)
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	return atomicWrite(r.Path, []byte(content), 0640)
}

func normalizePublicKey(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") || strings.Contains(value, "PRIVATE KEY") {
		return "", errors.New("invalid SSH public key")
	}
	parts := strings.Fields(value)
	if len(parts) < 2 {
		return "", errors.New("invalid SSH public key")
	}
	allowed := strings.HasPrefix(parts[0], "ssh-") || strings.HasPrefix(parts[0], "ecdsa-sha2-")
	if !allowed {
		return "", errors.New("unsupported SSH public key")
	}
	if _, err := base64.StdEncoding.DecodeString(parts[1]); err != nil {
		return "", errors.New("invalid SSH public key material")
	}
	return parts[0] + " " + parts[1], nil
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".authorized_keys-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

type Gateway struct {
	Store  *state.Store
	Engine containers.Engine

	mu       sync.Mutex
	sessions map[string]map[uint64]trackedSession
	nextID   uint64
}

type trackedSession struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type gatewayRequest struct {
	GrantID string `json:"grantId"`
	Command string `json:"command"`
	TTY     bool   `json:"tty"`
}

type gatewayResponse struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	ExitMarker string `json:"exitMarker,omitempty"`
}

func (g *Gateway) Serve(ctx context.Context, socketPath string) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0660); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go g.serveConnection(ctx, connection)
	}
}

func (g *Gateway) serveConnection(parent context.Context, connection net.Conn) {
	defer connection.Close()
	decoder := json.NewDecoder(io.LimitReader(connection, 12*1024))
	var request gatewayRequest
	if err := decoder.Decode(&request); err != nil || !grantID.MatchString(request.GrantID) ||
		len(request.Command) > 8192 {
		writeGatewayResponse(connection, gatewayResponse{Error: "invalid_request"})
		return
	}
	grant, err := g.Store.Grant(parent, request.GrantID)
	if err != nil || grant == nil || grant.DesiredState != "active" ||
		grant.ObservedState != "applied" {
		writeGatewayResponse(connection, gatewayResponse{Error: "access_grant_unavailable"})
		return
	}
	sandbox, err := g.Store.Sandbox(parent, grant.SandboxID)
	if err != nil || sandbox == nil || sandbox.ObservedState != "running" ||
		sandbox.DesiredState != "running" {
		writeGatewayResponse(connection, gatewayResponse{Error: "sandbox_stopped"})
		return
	}
	ctx, cancel := context.WithCancel(parent)
	sessionID := g.addSession(grant.ID, cancel)
	defer func() {
		cancel()
		g.finishSession(grant.ID, sessionID)
	}()
	exitMarker, err := newExitMarker()
	if err != nil {
		writeGatewayResponse(connection, gatewayResponse{Error: "sandbox_gateway_unavailable"})
		return
	}
	if err := writeGatewayResponse(connection, gatewayResponse{OK: true, ExitMarker: exitMarker}); err != nil {
		return
	}
	execError := g.Engine.Exec(
		ctx,
		sandbox.ID,
		request.Command,
		request.TTY,
		connection,
		connection,
		connection,
	)
	_, _ = fmt.Fprintf(connection, "\x00warpmetal-exit:%s:%d\n", exitMarker, sessionExitCode(execError))
}

func newExitMarker() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func sessionExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit interface{ ExitCode() int }
	if errors.As(err, &exit) {
		code := exit.ExitCode()
		if code > 0 && code <= 255 {
			return code
		}
	}
	return 1
}

func (g *Gateway) TerminateGrant(ctx context.Context, id string) error {
	g.mu.Lock()
	tracked := make([]trackedSession, 0, len(g.sessions[id]))
	for _, session := range g.sessions[id] {
		tracked = append(tracked, session)
		session.cancel()
	}
	g.mu.Unlock()
	for _, session := range tracked {
		select {
		case <-session.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (g *Gateway) TerminateSandbox(ctx context.Context, sandboxID string) error {
	grants, err := g.Store.Grants(ctx)
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if grant.SandboxID == sandboxID {
			if err := g.TerminateGrant(ctx, grant.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *Gateway) addSession(id string, cancel context.CancelFunc) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sessions == nil {
		g.sessions = map[string]map[uint64]trackedSession{}
	}
	if g.sessions[id] == nil {
		g.sessions[id] = map[uint64]trackedSession{}
	}
	g.nextID++
	g.sessions[id][g.nextID] = trackedSession{cancel: cancel, done: make(chan struct{})}
	return g.nextID
}

func (g *Gateway) finishSession(id string, sessionID uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if session, ok := g.sessions[id][sessionID]; ok {
		close(session.done)
	}
	delete(g.sessions[id], sessionID)
	if len(g.sessions[id]) == 0 {
		delete(g.sessions, id)
	}
}

func writeGatewayResponse(writer io.Writer, value gatewayResponse) error {
	buffered := bufio.NewWriter(writer)
	if err := json.NewEncoder(buffered).Encode(value); err != nil {
		return err
	}
	return buffered.Flush()
}
