package access

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type testExitError struct{ code int }

func (e testExitError) Error() string { return "test exit" }
func (e testExitError) ExitCode() int { return e.code }

func TestRendererForcesOneGrantAndStripsComment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	renderer := Renderer{Path: path}
	err := renderer.Write([]state.LocalGrant{
		{
			ID:           "grant_test12345",
			SandboxID:    "sbx_test12345",
			SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA agent-comment",
			DesiredState: "active",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, required := range []string{
		`command="/usr/libexec/warpmetal-sandbox-gateway grant_test12345"`,
		"no-agent-forwarding",
		"no-port-forwarding",
		"no-X11-forwarding",
		"no-user-rc",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("authorized key omitted %s: %s", required, text)
		}
	}
	if strings.Contains(text, "agent-comment") {
		t.Fatal("untrusted public-key comment was retained")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("authorized keys mode = %o, want 640", info.Mode().Perm())
	}
}

func TestRendererRejectsOptionInjection(t *testing.T) {
	renderer := Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")}
	err := renderer.Write([]state.LocalGrant{
		{
			ID:           "grant_test12345",
			SSHPublicKey: "command=host-shell ssh-ed25519 AAAA\nssh-ed25519 AAAA",
			DesiredState: "active",
		},
	})
	if err == nil {
		t.Fatal("expected injected key rejection")
	}
}

func TestRendererPublishesOnlyActiveGrantKeysThroughTheForcedGateway(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	renderer := Renderer{Path: path}
	err := renderer.Write([]state.LocalGrant{
		{
			ID:           "grant_active123",
			SandboxID:    "sbx_assigned123",
			SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA active",
			DesiredState: "active",
		},
		{
			ID:           "grant_revoked123",
			SandboxID:    "sbx_assigned123",
			SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB revoked",
			DesiredState: "revoked",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if strings.Count(text, "command=\"") != 1 ||
		!strings.Contains(text, `command="/usr/libexec/warpmetal-sandbox-gateway grant_active123"`) ||
		strings.Contains(text, "grant_revoked123") || strings.Contains(text, "BBBBBBBB") {
		t.Fatalf("authorized keys did not expose exactly the active forced grant: %s", text)
	}
}

type gatewayExecCall struct {
	sandboxID string
	command   string
	tty       bool
}

type gatewayTestEngine struct {
	calls               chan gatewayExecCall
	waitForCancellation bool
	executionEnded      chan struct{}
}

func (e *gatewayTestEngine) Ensure(context.Context, model.Sandbox, string, string) error {
	return nil
}

func (e *gatewayTestEngine) Replace(context.Context, model.Sandbox, string, string, bool) error {
	return nil
}

func (e *gatewayTestEngine) Start(context.Context, string) error   { return nil }
func (e *gatewayTestEngine) Stop(context.Context, string) error    { return nil }
func (e *gatewayTestEngine) Restart(context.Context, string) error { return nil }
func (e *gatewayTestEngine) Remove(context.Context, string) error  { return nil }

func (e *gatewayTestEngine) Exec(
	ctx context.Context,
	sandboxID string,
	command string,
	tty bool,
	_ containers.SessionInput,
	_ io.Writer,
	_ io.Writer,
) error {
	e.calls <- gatewayExecCall{sandboxID: sandboxID, command: command, tty: tty}
	if !e.waitForCancellation {
		return nil
	}
	<-ctx.Done()
	close(e.executionEnded)
	return ctx.Err()
}

type gatewayTestSessionInput struct {
	io.Reader
}

func (gatewayTestSessionInput) InterruptRead() error { return nil }

func gatewayTestStore(t *testing.T, grants ...state.LocalGrant) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.PutSandbox(context.Background(), state.LocalSandbox{
		ID:            "sbx_assigned123",
		Name:          "assigned",
		DesiredState:  "running",
		ObservedState: "running",
		Lifetime:      "persistent",
	}); err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		if err := store.PutGrant(context.Background(), grant); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func startGatewayRequest(
	t *testing.T,
	gateway *Gateway,
	request gatewayRequest,
) (gatewayResponse, *bufio.Reader, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	go gateway.serveConnection(
		context.Background(),
		server,
		gatewayTestSessionInput{Reader: server},
	)
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	var response gatewayResponse
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		t.Fatal(err)
	}
	return response, reader, client
}

func TestUnixSessionInputInterruptReadPreservesWriteHalf(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "warpmetal-access-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	address := &net.UnixAddr{Name: filepath.Join(directory, "session.sock"), Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, err := net.DialUnix("unix", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	input := unixSessionInput{connection: server}
	readStarted := make(chan struct{})
	readReturned := make(chan struct{})
	go func() {
		close(readStarted)
		var buffer [1]byte
		_, _ = input.Read(buffer[:])
		close(readReturned)
	}()
	<-readStarted
	if err := input.InterruptRead(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-readReturned:
	case <-time.After(time.Second):
		t.Fatal("CloseRead did not interrupt the session input read")
	}

	if _, err := server.Write([]byte("trailer")); err != nil {
		t.Fatalf("write half was closed with the read half: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	trailer := make([]byte, len("trailer"))
	if _, err := io.ReadFull(client, trailer); err != nil {
		t.Fatal(err)
	}
	if string(trailer) != "trailer" {
		t.Fatalf("trailer = %q, want trailer", trailer)
	}
}

func TestUnixSessionInputCloseReadFailureFallsBackToFullClose(t *testing.T) {
	closeReadError := errors.New("close read failed")
	connection := newCloseReadFailureConnection(closeReadError)
	t.Cleanup(func() { _ = connection.Close() })
	input := unixSessionInput{connection: connection}
	readReturned := make(chan struct{})
	go func() {
		var buffer [1]byte
		_, _ = input.Read(buffer[:])
		close(readReturned)
	}()
	<-connection.readStarted

	err := input.InterruptRead()
	if !errors.Is(err, closeReadError) {
		t.Fatalf("interrupt error = %v, want %v", err, closeReadError)
	}
	if !connection.fullCloseCalled() {
		t.Fatal("CloseRead failure did not fall back to full Close")
	}
	select {
	case <-readReturned:
	case <-time.After(time.Second):
		t.Fatal("full Close did not unblock the session input read")
	}
}

type closeReadFailureConnection struct {
	closeReadError error
	readStarted    chan struct{}
	closed         chan struct{}
	readOnce       sync.Once
	closeOnce      sync.Once
}

func newCloseReadFailureConnection(closeReadError error) *closeReadFailureConnection {
	return &closeReadFailureConnection{
		closeReadError: closeReadError,
		readStarted:    make(chan struct{}),
		closed:         make(chan struct{}),
	}
}

func (c *closeReadFailureConnection) Read(_ []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *closeReadFailureConnection) CloseRead() error {
	return c.closeReadError
}

func (c *closeReadFailureConnection) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *closeReadFailureConnection) fullCloseCalled() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func TestGatewayRoutesInteractiveExecAndSubsystemRequestsOnlyToAssignedSandbox(t *testing.T) {
	grant := state.LocalGrant{
		ID:            "grant_active123",
		SandboxID:     "sbx_assigned123",
		SSHPublicKey:  "ssh-ed25519 fixture",
		DesiredState:  "active",
		ObservedState: "applied",
	}
	engine := &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)}
	gateway := &Gateway{Store: gatewayTestStore(t, grant), Engine: engine}
	tests := []struct {
		name    string
		command string
		tty     bool
	}{
		{name: "interactive empty command", command: "", tty: true},
		{name: "one-shot command", command: "printf assigned", tty: false},
		{name: "SFTP subsystem", command: "internal-sftp", tty: false},
		{name: "OpenSSH SFTP server", command: "/usr/lib/openssh/sftp-server", tty: false},
		{name: "SCP sink", command: "scp -t /home/agent/workspace", tty: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, reader, connection := startGatewayRequest(t, gateway, gatewayRequest{
				GrantID: grant.ID,
				Command: test.command,
				TTY:     test.tty,
			})
			defer connection.Close()
			if !response.OK || response.Error != "" || response.ExitMarker == "" {
				t.Fatalf("gateway rejected assigned request: %#v", response)
			}
			call := <-engine.calls
			if call != (gatewayExecCall{
				sandboxID: "sbx_assigned123",
				command:   test.command,
				tty:       test.tty,
			}) {
				t.Fatalf("request escaped or changed assigned sandbox: %#v", call)
			}
			if _, err := io.ReadAll(reader); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGatewayDeniesUnknownAndRevokedGrantsBeforeContainerExec(t *testing.T) {
	revoked := state.LocalGrant{
		ID:            "grant_revoked123",
		SandboxID:     "sbx_assigned123",
		SSHPublicKey:  "ssh-ed25519 fixture",
		DesiredState:  "revoked",
		ObservedState: "revoked",
	}
	engine := &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)}
	gateway := &Gateway{Store: gatewayTestStore(t, revoked), Engine: engine}
	for _, grantID := range []string{"grant_unknown123", revoked.ID} {
		response, reader, connection := startGatewayRequest(t, gateway, gatewayRequest{
			GrantID: grantID,
			Command: "id",
		})
		if response.OK || response.Error != "access_grant_unavailable" || response.ExitMarker != "" {
			connection.Close()
			t.Fatalf("unavailable grant was not denied: %#v", response)
		}
		if _, err := io.ReadAll(reader); err != nil {
			connection.Close()
			t.Fatal(err)
		}
		connection.Close()
		select {
		case call := <-engine.calls:
			t.Fatalf("unavailable grant reached container exec: %#v", call)
		default:
		}
	}
}

func TestActiveGatewaySessionTerminationWaitsForExecToEndAndBlocksReplay(t *testing.T) {
	grant := state.LocalGrant{
		ID:            "grant_active123",
		SandboxID:     "sbx_assigned123",
		SSHPublicKey:  "ssh-ed25519 fixture",
		DesiredState:  "active",
		ObservedState: "applied",
	}
	store := gatewayTestStore(t, grant)
	engine := &gatewayTestEngine{
		calls:               make(chan gatewayExecCall, 1),
		waitForCancellation: true,
		executionEnded:      make(chan struct{}),
	}
	gateway := &Gateway{Store: store, Engine: engine}
	response, reader, connection := startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grant.ID,
		Command: "long-running",
	})
	defer connection.Close()
	if !response.OK {
		t.Fatalf("active session was rejected: %#v", response)
	}
	if call := <-engine.calls; call.sandboxID != "sbx_assigned123" {
		t.Fatalf("active session reached wrong sandbox: %#v", call)
	}
	grant.DesiredState = "revoked"
	grant.ObservedState = "revoking"
	if err := store.PutGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	streamEnded := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(reader)
		streamEnded <- err
	}()
	terminated := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		terminated <- gateway.TerminateGrant(ctx, grant.ID)
	}()
	select {
	case <-engine.executionEnded:
	case <-time.After(time.Second):
		t.Fatal("revocation did not cancel active container execution")
	}
	if err := <-streamEnded; err != nil {
		t.Fatal(err)
	}
	if err := <-terminated; err != nil {
		t.Fatal(err)
	}

	replay, replayReader, replayConnection := startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grant.ID,
		Command: "replay",
	})
	defer replayConnection.Close()
	if replay.OK || replay.Error != "access_grant_unavailable" {
		t.Fatalf("revoked grant replay was not denied: %#v", replay)
	}
	if _, err := io.ReadAll(replayReader); err != nil {
		t.Fatal(err)
	}
}

func TestGrantTerminationWaitsForTheTrackedSession(t *testing.T) {
	gateway := &Gateway{}
	sessionContext, cancel := context.WithCancel(context.Background())
	sessionID := gateway.addSession("grant_test12345", cancel)
	terminated := make(chan error, 1)
	go func() {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		terminated <- gateway.TerminateGrant(ctx, "grant_test12345")
	}()
	select {
	case <-sessionContext.Done():
	case <-time.After(time.Second):
		t.Fatal("tracked session was not cancelled")
	}
	select {
	case err := <-terminated:
		t.Fatalf("termination returned before the session exited: %v", err)
	default:
	}
	gateway.finishSession("grant_test12345", sessionID)
	if err := <-terminated; err != nil {
		t.Fatal(err)
	}
}

func TestSessionExitCodePreservesWrappedContainerStatus(t *testing.T) {
	if got := sessionExitCode(nil); got != 0 {
		t.Fatalf("nil status = %d, want 0", got)
	}
	if got := sessionExitCode(fmt.Errorf("wrapped: %w", testExitError{code: 42})); got != 42 {
		t.Fatalf("wrapped status = %d, want 42", got)
	}
	if got := sessionExitCode(errors.New("transport failed")); got != 1 {
		t.Fatalf("transport status = %d, want 1", got)
	}
}

func TestNewExitMarkerIsUnpredictableHex(t *testing.T) {
	first, err := newExitMarker()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newExitMarker()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || len(second) != 32 || first == second {
		t.Fatalf("invalid exit markers %q and %q", first, second)
	}
}

func TestPackagedSSHMatchBlockReturnsToGlobalScope(t *testing.T) {
	content, err := os.ReadFile("../../packaging/sshd/warpmetal-sandbox.conf")
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.Contains(text, "DisableForwarding yes") ||
		!strings.HasSuffix(strings.TrimSpace(text), "Match all") {
		t.Fatalf("SSH match block is not closed or fully restricted: %s", text)
	}
	matchStart := strings.Index(text, "Match User warpmetal-sandbox")
	matchEnd := strings.Index(text, "Match all")
	permitUserEnvironment := strings.Index(text, "PermitUserEnvironment no")
	if permitUserEnvironment == -1 || matchStart == -1 || matchEnd == -1 ||
		permitUserEnvironment > matchStart || matchStart > matchEnd {
		t.Fatalf("PermitUserEnvironment must be global, before the sandbox Match block: %s", text)
	}
}

func TestPackagedSSHBoundaryDeniesPasswordsForwardingAndHostSubsystemBypass(t *testing.T) {
	content, err := os.ReadFile("../../packaging/sshd/warpmetal-sandbox.conf")
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, directive := range []string{
		"Match User warpmetal-sandbox",
		"AuthorizedKeysFile /etc/ssh/warpmetal-runtime/authorized_keys",
		"AuthenticationMethods publickey",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"DisableForwarding yes",
		"AllowAgentForwarding no",
		"AllowTcpForwarding no",
		"AllowStreamLocalForwarding no",
		"PermitTunnel no",
		"GatewayPorts no",
		"X11Forwarding no",
		"PermitUserRC no",
		"PermitTTY yes",
	} {
		if strings.Count(text, directive) != 1 {
			t.Fatalf("SSH boundary must contain exactly one %q: %s", directive, text)
		}
	}
	for _, forbidden := range []string{
		"PasswordAuthentication yes",
		"KbdInteractiveAuthentication yes",
		"AllowAgentForwarding yes",
		"AllowTcpForwarding yes",
		"AllowStreamLocalForwarding yes",
		"PermitTunnel yes",
		"GatewayPorts yes",
		"X11Forwarding yes",
		"ForceCommand internal-sftp",
		"Subsystem sftp",
		"TrustedUserCAKeys",
		"AuthorizedPrincipalsFile",
		"HostbasedAuthentication yes",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("SSH boundary introduced alternate access %q: %s", forbidden, text)
		}
	}
}
