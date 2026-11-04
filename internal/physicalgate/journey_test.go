package physicalgate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Existing native SOURCE boundaries remain distinct: real subprocess/Unix RPC,
// host-private SQLite and local HTTP with separate homes; installed process,
// signed authority/baseline and native/plugin identities are explicit synthetic
// suppliers. No providers, qualification fixture, installed native or ROOT credit.
func TestPhysicalGateLocalTerminalStatusCannotBecomeSettlement(t *testing.T) {
	if os.Getenv("WARPMETAL_RUNTIME_GATE_SOURCE_EVIDENCE") == "" {
		t.Skip("requires retained SOURCE evidence")
	}
	root, err := os.MkdirTemp("/private/var/folders/ln/3pk8bkxd7f72yhhjwpwpb56m0000gn/T/opencode", "g-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE_SOCKET_ARTIFACTS", root)
	for index, action := range []string{"status", "settle"} {
		path := filepath.Join(root, fmt.Sprintf("%d.sock", index))
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		l.SetUnlinkOnClose(false)
		done := make(chan error, 1)
		go func() {
			c, err := l.Accept()
			if err != nil {
				done <- err
				return
			}
			defer c.Close()
			_, err = readFrame(c)
			if err != nil {
				done <- err
				return
			}
			// Explicit synthetic wire supplier; no owning terminal or store proof.
			_, err = c.Write([]byte("{\"formatVersion\":1,\"operationId\":\"source_operation\",\"status\":\"local-terminal\",\"error\":null}\n"))
			done <- err
		}()
		body := json.RawMessage(`{}`)
		if action == "settle" {
			body, _ = json.Marshal(model.PhysicalSettlement{RequestDigest: model.WorkspaceDigest("request"), ResponseDigest: model.WorkspaceDigest("response"), ResponseByteCount: 1, HTTPStatus: 200, UsageUsdMicros: 0, EvidenceDigest: model.WorkspaceDigest("evidence")})
		}
		reply, err := Call(context.Background(), path, model.PhysicalRPCRequest{FormatVersion: 1, Action: action, OperationID: "source_operation", Body: body})
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		_ = l.Close()
		if action == "status" {
			if err != nil || reply.Status != "local-terminal" {
				t.Fatal("owning local terminal status unreadable", err)
			}
		} else if err == nil {
			t.Fatal("local terminal accepted as paid settlement acknowledgement")
		}
	}
	t.Run("owning_listener_verified_terminal", testOwnedSourceOfflineTerminal)
}

func TestRuntimePhysicalGateCrossHomeUnknownRestart(t *testing.T) {
	base := os.Getenv("WARPMETAL_RUNTIME_GATE_SOURCE_EVIDENCE")
	if base == "" {
		t.Skip("requires approved retained SOURCE evidence root")
	}
	root, err := os.MkdirTemp(base, "runtime-physical-gate-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE_PRIVATE_ARTIFACTS", root)
	store, err := state.Open(filepath.Join(root, "runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	case_ := state.PhysicalCase{TaskID: "synthetic_task", ServerID: "synthetic_server", CaseDigest: model.WorkspaceDigest("synthetic_case"), BaselineDigest: model.WorkspaceDigest("explicit_known_empty_SOURCE_baseline"), Requests: 4, Preparations: 2, ModelRequests: 4, AccessRequests: 0, UsdMicros: 1684000}
	if err = store.AdoptPhysicalLedger(context.Background(), case_, nil); err != nil {
		t.Fatal(err)
	}
	auth := &sourceProcessAuthority{callers: map[int]Caller{}, case_: case_, evidence: map[string]model.PhysicalSettlement{}}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	var mu sync.Mutex
	httpCalls, active, maximum := 0, 0, 0
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		httpCalls++
		active++
		if active > maximum {
			maximum = active
		}
		ordinal := httpCalls
		mu.Unlock()
		if ordinal == 1 {
			started <- struct{}{}
			<-release
		}
		status := 200
		if ordinal == 2 {
			status = 400
		}
		raw := []byte(fmt.Sprintf(`{"sourceRequest":%d,"originalBodyDigest":%q}`, ordinal, model.WorkspaceDigest(json.RawMessage(body))))
		meta := model.PhysicalSettlement{RequestDigest: model.WorkspaceDigest(json.RawMessage(body)), ResponseDigest: model.RawPhysicalDigest(raw), ResponseByteCount: len(raw), HTTPStatus: status, UsageUsdMicros: 7, EvidenceDigest: model.WorkspaceDigest(map[string]any{"body": json.RawMessage(body), "response": string(raw), "status": status})}
		auth.mu.Lock()
		auth.evidence[meta.RequestDigest] = meta
		auth.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write(raw)
		mu.Lock()
		active--
		mu.Unlock()
	}))
	defer local.Close()
	// AF_UNIX paths have a kernel byte limit; keep a separately retained short
	// endpoint directory under the approved harness root, not a symlink/cleanup.
	endpointRoot, err := os.MkdirTemp("/private/var/folders/ln/3pk8bkxd7f72yhhjwpwpb56m0000gn/T/opencode", "g-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE_SOCKET_ARTIFACTS", endpointRoot)
	socket := filepath.Join(endpointRoot, "1.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	server := Server{Store: store, Authority: auth}
	// Test-only response transport drops the ACK after the actual commit. There
	// is no production option/wire/env hook for substituting this supplier.
	go server.Serve(sourceACKDroppingListener{listener})
	children := []*sourceChild{}
	for _, name := range []string{"a", "b"} {
		home := filepath.Join(root, "home-"+name)
		if err = os.Mkdir(home, 0700); err != nil {
			t.Fatal(err)
		}
		child := startSourceChild(t, home, socket, local.URL, name)
		children = append(children, child)
		auth.mu.Lock()
		auth.callers[child.command.Process.Pid] = Caller{SandboxID: "source_box_" + name, SandboxGeneration: 1, NativeInstance: "source_native_" + name, NativeIdentityDigest: model.WorkspaceDigest("synthetic_native_" + name)}
		auth.mu.Unlock()
	}
	defer func() {
		releaseOnce.Do(func() { close(release) })
		for _, c := range children {
			c.stop(t)
		}
		_ = listener.Close()
		_ = store.Close()
	}()
	a, b := children[0], children[1]
	a.send(t, sourceInstruction{Socket: socket, Operation: "source_first", Index: 1, RequestIndex: 1, Preparation: 1, Mode: "request"})
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("first actual local request absent")
	}
	b.send(t, sourceInstruction{Socket: socket, Operation: "source_contended", Index: 2, RequestIndex: 1, Preparation: 2, Mode: "request"})
	if got := b.receive(t); got != "refused" {
		t.Fatal("cross-home contention", got)
	}
	releaseOnce.Do(func() { close(release) })
	if got := a.receive(t); got != "settled:200" {
		t.Fatal("first completion", got)
	}
	b.send(t, sourceInstruction{Socket: socket, Operation: "source_second", Index: 2, RequestIndex: 1, Preparation: 2, Mode: "request"})
	if got := b.receive(t); got != "settled:400" {
		t.Fatal("definite failed HTTP did not retain/release", got)
	}
	// Both actual children are still alive; their own writes are isolated.
	for _, c := range children {
		if _, err = os.ReadFile(filepath.Join(c.home, "own-write.txt")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = os.Stat(filepath.Join(a.home, "b-write.txt")); !os.IsNotExist(err) {
		t.Fatal("shared home")
	}
	a.send(t, sourceInstruction{Socket: socket, Operation: "source_lost_ack", Index: 3, RequestIndex: 2, Preparation: 1, Mode: "request"})
	if got := a.receive(t); got != "unknown" {
		t.Fatal("lost admission ACK", got)
	}
	_ = listener.Close()
	_ = store.Close()
	store, err = state.Open(filepath.Join(root, "runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	socket2 := filepath.Join(endpointRoot, "2.sock")
	listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: socket2, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	server = Server{Store: store, Authority: auth}
	go server.Serve(listener)
	b.send(t, sourceInstruction{Socket: socket2, Operation: "source_after_restart", Index: 4, RequestIndex: 2, Preparation: 2, Mode: "request"})
	if got := b.receive(t); got != "refused" {
		t.Fatal("restart expired/cleared unknown", got)
	}
	a.send(t, sourceInstruction{Socket: socket2, Operation: "source_lost_ack", Mode: "status"})
	if got := a.receive(t); got != "unknown" {
		t.Fatal("status granted/released unknown", got)
	}
	a.send(t, sourceInstruction{Socket: socket2, Operation: "source_lost_ack", Index: 3, RequestIndex: 2, Preparation: 1, Mode: "request"})
	if got := a.receive(t); got != "refused" {
		t.Fatal("exact lost-ACK replay redispatched", got)
	}
	rows, err := store.PhysicalHistory(context.Background(), case_)
	if err != nil || len(rows) != 3 {
		t.Fatal("durable prefix", len(rows), err)
	}
	if rows[2].Phase != "unknown" || rows[0].ReservedUsdMicros != 421000 || rows[1].ReservedUsdMicros != 421000 || rows[2].ReservedUsdMicros != 421000 || rows[1].Settlement == nil || rows[1].Settlement.HTTPStatus != 400 {
		t.Fatal("failed/unknown reservation/history lost")
	}
	mu.Lock()
	defer mu.Unlock()
	if httpCalls != 2 || maximum != 1 {
		t.Fatal("physical requests/cap", httpCalls, maximum)
	}
	t.Log("SOURCE physical local HTTP=2, overlapping actual child processes=2, maximum physical concurrency=1; installed authority synthetic; failed+unknown reserve retained1263000")
}

type sourceInstruction struct {
	Socket                           string
	Operation                        string
	Index, RequestIndex, Preparation int
	Mode                             string
}
type sourceACKDroppingListener struct{ *net.UnixListener }
type sourceACKDroppingConn struct{ *net.UnixConn }

func (l sourceACKDroppingListener) Accept() (net.Conn, error) {
	c, err := l.AcceptUnix()
	if err != nil {
		return nil, err
	}
	return sourceACKDroppingConn{c}, nil
}
func (c sourceACKDroppingConn) Write(raw []byte) (int, error) {
	var r model.PhysicalRPCResponse
	if json.Unmarshal(bytes.TrimSpace(raw), &r) == nil && r.OperationID == "source_lost_ack" && r.Status == "admitted" {
		_ = c.Close()
		return 0, io.EOF
	}
	return c.UnixConn.Write(raw)
}

type sourceChild struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
	home    string
	log     *os.File
}

func startSourceChild(t *testing.T, home, socket, url, name string) *sourceChild {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestPhysicalGateChildSource$")
	command.Env = append(os.Environ(), "WARPMETAL_GATE_CHILD_TEST=1", "WARPMETAL_GATE_CHILD_HOME="+home, "WARPMETAL_GATE_CHILD_URL="+url, "WARPMETAL_GATE_CHILD_NAME="+name)
	input, _ := command.StdinPipe()
	out, _ := command.StdoutPipe()
	log, err := os.OpenFile(filepath.Join(home, "child-stderr.txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = log
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	c := &sourceChild{command, input, bufio.NewScanner(out), home, log}
	if c.receive(t) != "ready" {
		t.Fatal("child startup")
	}
	return c
}
func (c *sourceChild) send(t *testing.T, in sourceInstruction) {
	t.Helper()
	raw, _ := json.Marshal(in)
	if _, err := c.input.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
}
func (c *sourceChild) receive(t *testing.T) string {
	t.Helper()
	line := make(chan string, 1)
	go func() {
		if c.output.Scan() {
			line <- c.output.Text()
		} else {
			line <- "closed"
		}
	}()
	select {
	case text := <-line:
		return text
	case <-time.After(10 * time.Second):
		t.Fatal("child response timeout")
		return ""
	}
}
func (c *sourceChild) stop(t *testing.T) {
	t.Helper()
	_ = c.input.Close()
	if err := c.command.Wait(); err != nil {
		t.Errorf("source child exit: %v", err)
	}
	_ = c.log.Close()
}

// Only this TEST subprocess entry consumes these environment variables. Neither
// Server nor a production caller/authentication path has an env supplier switch.
func TestPhysicalGateChildSource(t *testing.T) {
	if os.Getenv("WARPMETAL_GATE_CHILD_TEST") != "1" {
		t.Skip("SOURCE subprocess only")
	}
	home, name, url := os.Getenv("WARPMETAL_GATE_CHILD_HOME"), os.Getenv("WARPMETAL_GATE_CHILD_NAME"), os.Getenv("WARPMETAL_GATE_CHILD_URL")
	_ = os.WriteFile(filepath.Join(home, "own-write.txt"), []byte(name), 0600)
	fmt.Println("ready")
	for scanner := bufio.NewScanner(os.Stdin); scanner.Scan(); {
		var in sourceInstruction
		if json.Unmarshal(scanner.Bytes(), &in) != nil {
			t.Fatal("instruction")
		}
		body := []byte(fmt.Sprintf(`{"child":%q,"request":%d}`, name, in.RequestIndex))
		call := model.PhysicalRPCRequest{FormatVersion: 1, Action: "admit", OperationID: in.Operation}
		admit := model.PhysicalAdmitRequest{Consumer: "product", PreparationID: fmt.Sprintf("source_prep_%d", in.Preparation), RequestIndex: in.RequestIndex, OuterPhysicalIndex: in.Index, AuthorityDigest: model.WorkspaceDigest("synthetic_authority"), RequestDigest: model.WorkspaceDigest(json.RawMessage(body))}
		call.Body, _ = json.Marshal(admit)
		if in.Mode == "status" {
			call.Action = "status"
			call.Body = json.RawMessage(`{}`)
		}
		reply, err := Call(context.Background(), in.Socket, call)
		if err != nil {
			fmt.Println("unknown")
			continue
		}
		if in.Mode == "status" {
			fmt.Println(reply.Status)
			continue
		}
		if reply.Status != "admitted" {
			fmt.Println("refused")
			continue
		}
		response, err := http.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Println("unknown")
			continue
		}
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		meta := model.PhysicalSettlement{RequestDigest: admit.RequestDigest, ResponseDigest: model.RawPhysicalDigest(raw), ResponseByteCount: len(raw), HTTPStatus: response.StatusCode, UsageUsdMicros: 7, EvidenceDigest: model.WorkspaceDigest(map[string]any{"body": json.RawMessage(body), "response": string(raw), "status": response.StatusCode})}
		call.Action = "settle"
		call.Body, _ = json.Marshal(meta)
		reply, err = Call(context.Background(), in.Socket, call)
		if err != nil || reply.Status != "settled" {
			fmt.Println("unknown")
			continue
		}
		fmt.Printf("settled:%d\n", response.StatusCode)
	}
}

type sourceProcessAuthority struct {
	mu       sync.Mutex
	callers  map[int]Caller
	case_    state.PhysicalCase
	evidence map[string]model.PhysicalSettlement
}

func (a *sourceProcessAuthority) Authenticate(_ context.Context, peer Peer) (Caller, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.callers[peer.PID]
	if !ok {
		return Caller{}, ErrPrerequisite
	}
	return c, nil
}
func (a *sourceProcessAuthority) AuthorizeAdmission(_ context.Context, c Caller, call model.PhysicalAdmitRequest) (state.PhysicalPermit, error) {
	if call.Consumer != "product" || call.AuthorityDigest != model.WorkspaceDigest("synthetic_authority") {
		return state.PhysicalPermit{}, ErrPrerequisite
	}
	ordinal := 1
	if strings.HasSuffix(c.SandboxID, "_b") {
		ordinal = 2
	}
	if call.PreparationID != fmt.Sprintf("source_prep_%d", ordinal) {
		return state.PhysicalPermit{}, ErrPrerequisite
	}
	return state.PhysicalPermit{Case: a.case_, Caller: c.Subject(), Request: call, PreparationOrdinal: ordinal, AllocationID: fmt.Sprintf("source_allocation_%d", ordinal)}, nil
}
func (a *sourceProcessAuthority) VerifySettlement(_ context.Context, c Caller, own state.PhysicalOperation, received model.PhysicalSettlement) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	actual, ok := a.evidence[received.RequestDigest]
	if !ok || actual != received || own.Permit.Caller != c.Subject() {
		return ErrPrerequisite
	}
	return nil
}
