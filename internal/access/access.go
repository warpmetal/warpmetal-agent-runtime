package access

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

var grantID = regexp.MustCompile(`^grant_[A-Za-z0-9_-]{8,60}$`)

const sessionHandoffCommand = "warpmetal-team-control"

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

// ControllerPrepareEngine is the exact supervisor helper boundary used to issue
// the controller-activity prepare for a Foreman chat handoff. It is the same
// ExecManagedSupervisor surface worker prompts use; no shell path is added.
type ControllerPrepareEngine interface {
	ExecManagedSupervisor(context.Context, string, containers.ManagedSupervisorAction, []byte) ([]byte, []byte, error)
}

// ControllerParentCredentialSource delivers the pinned provider connection
// material for one ready controller parent. It is backend-contract authority,
// not caller input.
type ControllerParentCredentialSource interface {
	ControllerParentCredential(context.Context, string) (api.ControllerCredential, error)
}

type Gateway struct {
	Store                *state.Store
	Engine               containers.Engine
	SessionHandoffEngine containers.SessionHandoffEngine
	// ControllerPrepare issues ONLY the controller-activity prepare for chat.
	// Nil fails the chat handoff closed before any bridge process exists.
	ControllerPrepare ControllerPrepareEngine
	// ControllerCredential is the pinned parent credential source. Nil fails
	// closed; no synthetic or cached credential is ever substituted.
	ControllerCredential ControllerParentCredentialSource
	HostKeyFingerprint   string
	// ForemanChatQualification is the optional venue-scoped qualification
	// client configuration. When nil, Foreman chat refuses before SSH; it is
	// never a product default and never owner-controlled.
	ForemanChatQualification *containers.ForemanChatQualificationV1
	Now                      func() time.Time

	mu       sync.Mutex
	sessions map[string]map[uint64]trackedSession
	nextID   uint64
}

type trackedSession struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// handoffDiagnosticLimit bounds the bridge diagnostics retained per handoff.
const handoffDiagnosticLimit = 4 << 10

// handoffDiagnosticSink retains the most recent bounded bridge diagnostics.
// Handoff stderr must never share the framed protocol connection: the sink is a
// distinct writer that cannot interleave with, consume, reorder, or
// backpressure the connection stream, and overflow drops the oldest bytes.
type handoffDiagnosticSink struct {
	mu       sync.Mutex
	retained []byte
}

func (s *handoffDiagnosticSink) Write(payload []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(payload) >= handoffDiagnosticLimit {
		s.retained = append(s.retained[:0], payload[len(payload)-handoffDiagnosticLimit:]...)
		return len(payload), nil
	}
	s.retained = append(s.retained, payload...)
	if len(s.retained) > handoffDiagnosticLimit {
		s.retained = append(s.retained[:0], s.retained[len(s.retained)-handoffDiagnosticLimit:]...)
	}
	return len(payload), nil
}

// String returns the retained diagnostics, most recent last.
func (s *handoffDiagnosticSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.retained)
}

type gatewayRequest struct {
	GrantID             string                      `json:"grantId"`
	Command             string                      `json:"command"`
	TTY                 bool                        `json:"tty"`
	SessionHandoff      *model.SessionHandoffV1     `json:"sessionHandoff,omitempty"`
	SessionHandoffChat  *model.ForemanChatHandoffV1 `json:"sessionHandoffChat,omitempty"`
	SessionHandoffHello []byte                      `json:"sessionHandoffHello,omitempty"`
}

type gatewayResponse struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	ExitMarker string `json:"exitMarker,omitempty"`
}

type unixSessionConnection interface {
	io.Reader
	CloseRead() error
	Close() error
}

type unixSessionInput struct {
	connection unixSessionConnection
}

type prefixedGatewayInput struct {
	io.Reader
	input containers.SessionInput
}

func (i prefixedGatewayInput) InterruptRead() error { return i.input.InterruptRead() }

func (i unixSessionInput) Read(value []byte) (int, error) {
	return i.connection.Read(value)
}

func (i unixSessionInput) InterruptRead() error {
	if err := i.connection.CloseRead(); err != nil {
		return errors.Join(err, i.connection.Close())
	}
	return nil
}

func (g *Gateway) Serve(ctx context.Context, socketPath string) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return err
	}
	// Never steal a live gateway socket. A second `warpmetald` start must fail
	// closed instead of unlinking the path a running supervisor is serving on
	// (D-WP20-2); only a stale, unconnectable path may be removed.
	if connection, dialErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond); dialErr == nil {
		_ = connection.Close()
		return fmt.Errorf("supervisor socket %s is already in use", socketPath)
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
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
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go g.serveConnection(ctx, connection, unixSessionInput{connection: connection})
	}
}

func (g *Gateway) serveConnection(
	parent context.Context,
	connection net.Conn,
	input containers.SessionInput,
) {
	defer connection.Close()
	decoder := json.NewDecoder(io.LimitReader(connection, 128*1024))
	decoder.DisallowUnknownFields()
	var request gatewayRequest
	if err := decoder.Decode(&request); err != nil || !grantID.MatchString(request.GrantID) ||
		len(request.Command) > 8192 || len(request.SessionHandoffHello) > 64*1024 {
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
	parsedHandoff, parsedChat, handoffCode := decodeSessionHandoffHello(request.SessionHandoffHello)
	if handoffCode != "" {
		writeGatewayResponse(connection, gatewayResponse{Error: handoffCode})
		return
	}
	if parsedHandoff == nil && request.SessionHandoff != nil ||
		parsedChat == nil && request.SessionHandoffChat != nil {
		writeGatewayResponse(connection, gatewayResponse{Error: "handoff_invalid"})
		return
	}
	if parsedHandoff != nil && request.SessionHandoff == nil || parsedChat != nil && request.SessionHandoffChat == nil {
		writeGatewayResponse(connection, gatewayResponse{Error: "handoff_invalid"})
		return
	}
	if parsedHandoff != nil && parsedChat != nil {
		writeGatewayResponse(connection, gatewayResponse{Error: "handoff_invalid"})
		return
	}
	if len(request.SessionHandoffHello) != 0 && request.Command != sessionHandoffCommand ||
		request.Command == sessionHandoffCommand && len(request.SessionHandoffHello) == 0 {
		writeGatewayResponse(connection, gatewayResponse{Error: "handoff_invalid"})
		return
	}
	if parsedHandoff != nil {
		parsedJSON, _ := json.Marshal(parsedHandoff)
		privateJSON, _ := json.Marshal(request.SessionHandoff)
		if !bytes.Equal(parsedJSON, privateJSON) || request.Command != sessionHandoffCommand {
			writeGatewayResponse(connection, gatewayResponse{Error: "handoff_invalid"})
			return
		}
	}
	if parsedChat != nil {
		parsedJSON, _ := json.Marshal(parsedChat)
		privateJSON, _ := json.Marshal(request.SessionHandoffChat)
		if !bytes.Equal(parsedJSON, privateJSON) || request.Command != sessionHandoffCommand {
			writeGatewayResponse(connection, gatewayResponse{Error: "handoff_invalid"})
			return
		}
	}
	var handoffLaunch containers.SessionHandoffLaunch
	if parsedHandoff != nil || parsedChat != nil {
		foremanChatTracef("preface chat=%t hello_bytes=%d hello_sha=%s", parsedChat != nil,
			len(request.SessionHandoffHello), frameDigest(request.SessionHandoffHello))
		if g.SessionHandoffEngine == nil {
			writeGatewayResponse(connection, gatewayResponse{Error: "handoff_not_ready"})
			return
		}
		var code string
		if parsedChat != nil {
			handoffLaunch, code = g.validateForemanChatHandoff(parent, *grant, *sandbox, *parsedChat, request.SessionHandoffHello)
		} else {
			handoffLaunch, code = g.validateSessionHandoff(parent, *grant, *sandbox, *parsedHandoff, request.SessionHandoffHello)
		}
		if code != "" {
			log.Printf("foreman chat handoff refused: %s", code)
			writeGatewayResponse(connection, gatewayResponse{Error: code})
			return
		}
		if parsedChat != nil {
			foremanChatTracef("launch hello_bytes=%d hello_sha=%s grant=%s handoff=%s",
				len(handoffLaunch.HelloFrame), frameDigest(handoffLaunch.HelloFrame),
				handoffLaunch.Grant.GrantID, parsedChat.HandoffID)
		}
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
	var execError error
	if parsedHandoff != nil || parsedChat != nil {
		// The framed bridge protocol owns the connection byte stream, so bridge
		// diagnostics go to a distinct bounded sink instead.
		diagnostics := &handoffDiagnosticSink{}
		tracedInput := &inputTraceReader{input: input}
		tracedOutput := &frameTraceWriter{writer: connection}
		execError = g.SessionHandoffEngine.ExecSessionHandoff(
			ctx, sandbox.ID, handoffLaunch, tracedInput, tracedOutput, diagnostics,
		)
		foremanChatTracef("exec returned error=%v", execError)
		if diagnostics.String() != "" {
			log.Printf("foreman chat bridge diagnostics: %s", diagnostics.String())
		}
	} else {
		ordinaryInput := input
		if len(request.SessionHandoffHello) != 0 {
			ordinaryInput = prefixedGatewayInput{
				Reader: io.MultiReader(bytes.NewReader(request.SessionHandoffHello), input), input: input,
			}
		}
		execError = g.Engine.Exec(
			ctx, sandbox.ID, request.Command, request.TTY, ordinaryInput, connection, connection,
		)
	}
	_, _ = fmt.Fprintf(connection, "\x00warpmetal-exit:%s:%d\n", exitMarker, sessionExitCode(execError))
}

func decodeSessionHandoffHello(frame []byte) (*model.SessionHandoffV1, *model.ForemanChatHandoffV1, string) {
	if len(frame) == 0 {
		return nil, nil, ""
	}
	if len(frame) < 5 || len(frame) > 64*1024 || int(binary.BigEndian.Uint32(frame[:4])) != len(frame)-4 || frame[4] != 0x01 {
		return nil, nil, "handoff_invalid"
	}
	var envelope struct {
		Protocol string          `json:"protocol"`
		Handoff  json.RawMessage `json:"handoff"`
	}
	if err := json.Unmarshal(frame[5:], &envelope); err != nil || envelope.Protocol != "wm-team-control/1" {
		return nil, nil, "handoff_invalid"
	}
	if len(envelope.Handoff) == 0 || bytes.Equal(envelope.Handoff, []byte("null")) {
		return nil, nil, ""
	}
	var action struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(envelope.Handoff, &action); err != nil {
		return nil, nil, "handoff_invalid"
	}
	if action.Action == "chat_session" {
		target, code := decodeForemanChatHandoff(envelope.Handoff)
		return nil, target, code
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Handoff))
	decoder.DisallowUnknownFields()
	var target model.SessionHandoffV1
	if err := decoder.Decode(&target); err != nil {
		return nil, nil, "handoff_invalid"
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, "handoff_invalid"
	}
	return &target, nil, ""
}

func decodeForemanChatHandoff(value []byte) (*model.ForemanChatHandoffV1, string) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var target model.ForemanChatHandoffV1
	if err := decoder.Decode(&target); err != nil {
		return nil, "handoff_invalid"
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, "handoff_invalid"
	}
	return &target, ""
}

func (g *Gateway) validateSessionHandoff(
	ctx context.Context,
	grant state.LocalGrant,
	sandbox state.LocalSandbox,
	target model.SessionHandoffV1,
	hello []byte,
) (containers.SessionHandoffLaunch, string) {
	now := time.Now().UTC()
	if g.Now != nil {
		now = g.Now().UTC()
	}
	if err := model.ValidateSessionHandoffV1(target, now); err != nil {
		if !target.ExpiresAt.IsZero() && !now.Before(target.ExpiresAt) || !target.IssuedAt.IsZero() && now.Before(target.IssuedAt) ||
			!target.IssuedAt.IsZero() && !target.ExpiresAt.IsZero() && target.ExpiresAt.Sub(target.IssuedAt) > 120*time.Second {
			return containers.SessionHandoffLaunch{}, "handoff_expired"
		}
		return containers.SessionHandoffLaunch{}, "handoff_invalid"
	}
	identity := target.Identity
	sourceRef := target.Source
	if grant.SandboxID != identity.SandboxID || sandbox.ID != identity.SandboxID ||
		sandbox.Generation != identity.SandboxGeneration || sandbox.ObservedGeneration != identity.SandboxGeneration {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	service, err := g.Store.ManagedService(ctx, identity.ServiceRegistrationID)
	if err != nil || service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" ||
		service.Report.NativeRegistration == nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	// The trusted run mapping, not the descriptor role, selects the manager
	// validation path. Only the store's authoritative not-found result may fall
	// through to the ordinary exact-session gates.
	run, runErr := g.Store.ManagerRunBySource(ctx, sourceRef.RegisteredSourceID)
	if runErr != nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	if run != nil {
		return g.validateManagerSessionHandoff(ctx, grant, sandbox, service, target, hello)
	}
	manifest := service.Manifest
	native := service.Report.NativeRegistration
	mapping, mappingErr := g.Store.ContinuationHandoffBySource(ctx, sourceRef.RegisteredSourceID)
	if mappingErr != nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	mapped := mapping != nil
	if manifest.Identity.ServerID != identity.ServerID || manifest.Identity.TeamID != identity.TeamID ||
		manifest.Identity.MemberID != identity.MemberID || manifest.Identity.SandboxID != identity.SandboxID ||
		manifest.Identity.SandboxGeneration != identity.SandboxGeneration ||
		manifest.Identity.ServiceRegistrationID != identity.ServiceRegistrationID ||
		manifest.Identity.Instance != identity.Instance || manifest.Identity.Role != identity.Role ||
		service.ServiceGeneration != identity.ServiceGeneration || service.Report.ServiceGeneration != identity.ServiceGeneration ||
		service.Report.Identity != manifest.Identity || !service.Report.InstructionApplied ||
		service.Report.InstructionRevision != identity.InstructionRevision ||
		service.Report.InstructionDigest != identity.InstructionDigest ||
		service.ProcessInstance != model.ManagedServiceProcessInstance(identity.Instance, identity.ServiceGeneration) || service.Port < 1 ||
		manifest.Profile.ProfileID != identity.ProfileID || manifest.Profile.ProfileRevision != identity.ProfileRevision ||
		manifest.Profile.ProfileDigest != identity.ProfileDigest ||
		manifest.Instructions.InstructionRevision != identity.InstructionRevision ||
		manifest.Instructions.InstructionDigest != identity.InstructionDigest {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	if !mapped && (manifest.Workspace.ProjectID != identity.ProjectID || manifest.Workspace.WorkspaceEpoch != identity.WorkspaceEpoch ||
		native.RegisteredSourceID != sourceRef.RegisteredSourceID || native.WorkspaceEpoch != identity.WorkspaceEpoch ||
		native.NativeSessionID != sourceRef.NativeSessionID || native.NativeProjectID != sourceRef.NativeProjectID ||
		native.NativeLocationDigest != sourceRef.NativeLocationDigest) {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	if mapped {
		if mapping.Report == nil || mapping.Report.Status != "ready" || mapping.Report.Session == nil || mapping.Report.TargetWorkspace == nil ||
			mapping.Manifest.TargetPolicy.TeamID != identity.TeamID || mapping.Manifest.TargetPolicy.MemberID != identity.MemberID ||
			mapping.Manifest.TargetPolicy.SandboxID != identity.SandboxID ||
			mapping.Manifest.TargetPolicy.SandboxGeneration != identity.SandboxGeneration ||
			mapping.Manifest.TargetPolicy.ServiceRegistrationID != identity.ServiceRegistrationID ||
			mapping.Manifest.TargetPolicy.ServiceGeneration != identity.ServiceGeneration ||
			mapping.Manifest.TargetPolicy.Role != identity.Role || mapping.Manifest.TargetPolicy.ProfileID != identity.ProfileID ||
			mapping.Manifest.TargetPolicy.ProfileRevision != identity.ProfileRevision ||
			mapping.Manifest.TargetPolicy.ProfileDigest != identity.ProfileDigest ||
			mapping.Manifest.TargetPolicy.InstructionRevision != identity.InstructionRevision ||
			mapping.Manifest.TargetPolicy.InstructionDigest != identity.InstructionDigest ||
			mapping.Report.TargetWorkspace.ProjectID != identity.ProjectID ||
			mapping.Report.TargetWorkspace.WorkspaceEpoch != identity.WorkspaceEpoch ||
			mapping.Report.Session.RegisteredSourceID != sourceRef.RegisteredSourceID ||
			mapping.Report.Session.NativeSessionID != sourceRef.NativeSessionID ||
			mapping.Report.Session.NativeProjectID != sourceRef.NativeProjectID ||
			mapping.Report.Session.NativeLocationDigest != sourceRef.NativeLocationDigest {
			return containers.SessionHandoffLaunch{}, "handoff_target_changed"
		}
	}
	projects, err := g.Store.ManagedProjects(ctx)
	if err != nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	var project *state.LocalManagedProject
	for index := range projects {
		candidate := &projects[index]
		if candidate.Report.ProjectID == identity.ProjectID && candidate.Report.WorkspaceEpoch == identity.WorkspaceEpoch {
			if project != nil {
				return containers.SessionHandoffLaunch{}, "handoff_not_ready"
			}
			project = candidate
		}
	}
	if project == nil || project.Phase != "ready" || project.Report.Availability != "available" ||
		project.ServerID != identity.ServerID || project.Report.SandboxID != identity.SandboxID ||
		project.Report.SandboxGeneration != identity.SandboxGeneration {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	expectedScope := manifest.Workspace.ScopeRevision
	if mapped {
		expectedScope = mapping.Report.TargetWorkspace.ScopeRevision
		if project.Report.RootAttestation != mapping.Report.TargetWorkspace.RootAttestation ||
			project.Report.SelectionID != mapping.Report.TargetWorkspace.SelectionID {
			return containers.SessionHandoffLaunch{}, "handoff_target_changed"
		}
		switch mapping.Manifest.HandoffKind {
		case "reviewer":
			if project.Report.Designation != "continuity-handoff" || project.TeamID != identity.TeamID ||
				project.MemberID != identity.MemberID || project.Report.ServiceRegistrationID == nil ||
				*project.Report.ServiceRegistrationID != identity.ServiceRegistrationID {
				return containers.SessionHandoffLaunch{}, "handoff_target_changed"
			}
		case "restored_target":
			if project.Report.Designation != "continuity-materialization" || project.Report.ServiceRegistrationID != nil {
				return containers.SessionHandoffLaunch{}, "handoff_target_changed"
			}
		default:
			return containers.SessionHandoffLaunch{}, "handoff_target_changed"
		}
	} else if project.TeamID != identity.TeamID || project.MemberID != identity.MemberID ||
		project.Report.ServiceRegistrationID == nil || *project.Report.ServiceRegistrationID != identity.ServiceRegistrationID ||
		project.Report.RootAttestation != manifest.Workspace.RootAttestation || project.Report.SelectionID != manifest.Workspace.SelectionID {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	source, err := g.Store.ContinuitySource(ctx, sourceRef.RegisteredSourceID)
	if err != nil || source == nil || source.Report.Availability != "available" || source.Lifecycle != "running" ||
		source.Instance != identity.Instance || source.Report.ServiceRegistrationID != identity.ServiceRegistrationID ||
		source.Report.ServiceGeneration != identity.ServiceGeneration || source.Report.ProjectID != identity.ProjectID ||
		source.Report.SandboxID != identity.SandboxID || source.Report.SandboxGeneration != identity.SandboxGeneration ||
		source.Report.WorkspaceEpoch != identity.WorkspaceEpoch || source.Report.NativeSessionID != sourceRef.NativeSessionID ||
		source.Report.NativeProjectID != sourceRef.NativeProjectID || source.Report.NativeLocationDigest != sourceRef.NativeLocationDigest ||
		source.Report.Role != identity.Role || source.Report.ProfileRevision != identity.ProfileRevision ||
		source.Report.InstructionRevision != identity.InstructionRevision ||
		source.Report.RegisteredSourceID != sourceRef.RegisteredSourceID || source.Root != project.HostRoot ||
		source.Report.ScopeRevision != expectedScope {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	if target.Work != nil {
		work := target.Work
		registration, lookupErr := g.Store.ContinuityRegistration(ctx, work.BindingID)
		if lookupErr != nil || registration == nil || registration.ObservedStatus != "verified" ||
			registration.Manifest.DesiredState != "active" || !registration.Manifest.ContinuityEnabled ||
			registration.ServiceGeneration != identity.ServiceGeneration || registration.Manifest.Identity.WorkID != work.WorkID ||
			registration.Manifest.Identity.ProjectID != identity.ProjectID || registration.Manifest.Identity.SandboxID != identity.SandboxID ||
			registration.Manifest.Identity.SandboxGeneration != identity.SandboxGeneration ||
			registration.Manifest.Identity.WorkspaceEpoch != identity.WorkspaceEpoch ||
			registration.Manifest.Identity.ExpectedRevision != work.ExpectedRevision ||
			registration.Manifest.ScopeRevision != expectedScope ||
			registration.Manifest.Binding.BindingID != work.BindingID ||
			registration.Manifest.Binding.BindingRevision != work.BindingRevision ||
			registration.Manifest.Binding.RegisteredSourceID != sourceRef.RegisteredSourceID ||
			registration.Manifest.Binding.ServiceRegistrationID != identity.ServiceRegistrationID ||
			registration.Manifest.Binding.NativeSessionID != sourceRef.NativeSessionID ||
			registration.Manifest.Binding.NativeProjectID != sourceRef.NativeProjectID ||
			registration.Manifest.Binding.NativeLocationDigest != sourceRef.NativeLocationDigest {
			return containers.SessionHandoffLaunch{}, "handoff_target_changed"
		}
		if mapped && (mapping.Manifest.TargetWorkID != work.WorkID || mapping.Manifest.TargetWorkID != registration.Manifest.Identity.WorkID ||
			mapping.Report.Session.RegisteredSourceID != registration.Manifest.Binding.RegisteredSourceID) {
			return containers.SessionHandoffLaunch{}, "handoff_target_changed"
		}
	}
	if !strings.HasPrefix(g.HostKeyFingerprint, "SHA256:") {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	digest := sha256.Sum256([]byte(grant.ID + "\x00" + target.HandoffID))
	return containers.SessionHandoffLaunch{
		Grant: containers.SessionBridgeGrantV1{
			SchemaVersion: 1, GrantID: "grt_" + hex.EncodeToString(digest[:12]),
			ServerID: identity.ServerID, SandboxID: identity.SandboxID,
			Generation: identity.SandboxGeneration, Instance: identity.Instance,
			ProfileID: identity.ProfileID, ProfileDigest: identity.ProfileDigest,
			HostKeyFingerprint: g.HostKeyFingerprint,
			Engine:             containers.SessionBridgeEngineV1{Host: "127.0.0.1", Port: service.Port},
			AllowedPaths:       []string{"/api"},
			AllowedMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			IssuedAt:           target.IssuedAt, ExpiresAt: target.ExpiresAt,
		},
		HelloFrame: append([]byte(nil), hello...),
	}, ""
}

// validateForemanChatHandoff re-resolves the exact Foreman native session and
// builds the additive chat bridge grant. The owner descriptor is consent, not
// execution authority: the Runtime store must still show the exact ready
// managed service, the exact available orchestrator continuity source and the
// exact managed project for this sandbox generation. Manager/worker/reviewer
// sources, a changed target, a stale grant and a non-Foreman label are refused
// before any bridge process exists.
// validateControllerParentChatHandoff is the controller-parent sibling of the
// managed-service chat path. Controller parents publish managedServices and a
// signed parent receipt, not a legacy managed service or continuity source, so
// the legacy gate always refused them. The parent record is the same exact
// signed authority; state.json supplies the already-running native port.
// foremanChatAdvisory derives the closed read-only admission scope from the
// already-validated exact Foreman identity. It is not caller input: the same
// signed controller-parent receipt, role binding and handoff that authorize the
// chat grant supply every field, so a different server, sandbox, generation,
// instance, session, service, role or handoff cannot inherit it. The expiry is
// the exact 120-second chat consent, and the capability is only read-only chat.
func foremanChatAdvisory(
	grant state.LocalGrant,
	target model.ForemanChatHandoffV1,
	identity model.ForemanChatIdentityV1,
	instance string,
	projection *model.ControllerRoleProjection,
	roleAgentDigest string,
	preparedReceiptDigest string,
	_ *containers.ForemanChatQualificationV1,
) *containers.ForemanChatAdvisoryV1 {
	digest := sha256.Sum256([]byte(
		"foreman-chat-read-only\x00" + grant.ID + "\x00" + target.HandoffID + "\x00" +
			identity.RoleBindingID + "\x00" + preparedReceiptDigest))
	return &containers.ForemanChatAdvisoryV1{
		FormatVersion:         1,
		Capability:            containers.ForemanChatAdvisoryCapability,
		AdmissionID:           "fca_" + hex.EncodeToString(digest[:16]),
		ServerID:              identity.ServerID,
		SandboxID:             identity.SandboxID,
		SandboxGeneration:     identity.SandboxGeneration,
		Instance:              instance,
		NativeSessionID:       target.Source.NativeSessionID,
		ServiceRegistrationID: identity.ServiceRegistrationID,
		ServiceGeneration:     identity.ServiceGeneration,
		Role:                  identity.Role,
		RoleBindingID:         identity.RoleBindingID,
		HandoffID:             target.HandoffID,
		IssuedAt:              target.IssuedAt,
		ExpiresAt:             target.ExpiresAt,
		Projection:            projection,
		RoleAgentDigest:       roleAgentDigest,
	}
}

func (g *Gateway) validateControllerParentChatHandoff(
	ctx context.Context,
	grant state.LocalGrant,
	sandbox state.LocalSandbox,
	target model.ForemanChatHandoffV1,
	now time.Time,
	hello []byte,
) (containers.SessionHandoffLaunch, string) {
	identity, sourceRef := target.Identity, target.Source
	parent, err := g.Store.ControllerParent(ctx, identity.ServiceRegistrationID)
	if err != nil || parent == nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	intent, report := parent.Intent, parent.Report
	if intent.Role != "orchestrator" || report.Role != "orchestrator" ||
		report.NativeRoleReadback == nil || report.NativeRoleReadback.Role != "orchestrator" {
		return containers.SessionHandoffLaunch{}, "foreman_chat_role_denied"
	}
	if report.ObservedState != "ready" || !report.InstructionApplied ||
		report.ProfileStatus != "ready" || report.WorkspaceStatus != "ready" ||
		report.NativeRegistration == nil || report.LastError != nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	native := report.NativeRegistration
	if intent.ServiceRegistrationID != identity.ServiceRegistrationID ||
		intent.ServiceGeneration != identity.ServiceGeneration ||
		report.ServiceGeneration != identity.ServiceGeneration ||
		intent.Owner.ServerID != identity.ServerID ||
		intent.Owner.SandboxID != identity.SandboxID ||
		intent.Owner.SandboxGeneration != identity.SandboxGeneration ||
		intent.Profile.ProfileRevision != identity.ProfileRevision ||
		report.InstructionRevision != identity.InstructionRevision ||
		intent.Workspace.ProjectID != identity.ProjectID ||
		intent.Workspace.WorkspaceEpoch != identity.WorkspaceEpoch ||
		native.RegisteredSourceID != sourceRef.RegisteredSourceID ||
		native.NativeSessionID != sourceRef.NativeSessionID ||
		native.NativeProjectID != sourceRef.NativeProjectID ||
		native.NativeLocationDigest != sourceRef.NativeLocationDigest {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	run, runErr := g.Store.ManagerRunBySource(ctx, sourceRef.RegisteredSourceID)
	if runErr != nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	if run != nil {
		return containers.SessionHandoffLaunch{}, "foreman_chat_role_denied"
	}
	projects, err := g.Store.ManagedProjects(ctx)
	if err != nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	var project *state.LocalManagedProject
	for index := range projects {
		candidate := &projects[index]
		if candidate.Report.ProjectID == identity.ProjectID &&
			candidate.Report.WorkspaceEpoch == identity.WorkspaceEpoch {
			if project != nil {
				return containers.SessionHandoffLaunch{}, "handoff_not_ready"
			}
			project = candidate
		}
	}
	if project == nil || project.Phase != "ready" ||
		project.Report.Availability != "available" ||
		project.ServerID != identity.ServerID ||
		project.Report.SandboxID != identity.SandboxID ||
		project.Report.SandboxGeneration != identity.SandboxGeneration ||
		intent.Workspace.RootAttestation != project.Report.RootAttestation ||
		!strings.HasPrefix(g.HostKeyFingerprint, "SHA256:") {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	projection, roleAgentDigest, code := g.controllerParentChatProjection(ctx, intent)
	if code != "" {
		return containers.SessionHandoffLaunch{}, code
	}
	statePath := filepath.Join(project.Anchor, ".warpmetal", "opencode", "instances",
		intent.Instance, "state.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	var local struct {
		Phase                string `json:"phase"`
		Port                 int    `json:"port"`
		Instance             string `json:"instance"`
		SessionID            string `json:"sessionId"`
		NativeSessionID      string `json:"nativeSessionId"`
		NativeProjectID      string `json:"nativeProjectId"`
		NativeLocationDigest string `json:"nativeLocationDigest"`
		InstructionApplied   bool   `json:"instructionApplied"`
		ProfileRevision      int64  `json:"profileRevision"`
		InstructionRevision  int64  `json:"instructionRevision"`
	}
	if err = json.Unmarshal(raw, &local); err != nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	if local.Phase != "running" || !local.InstructionApplied ||
		local.Instance != intent.Instance || local.Port < 1 || local.Port > 65535 ||
		local.SessionID != sourceRef.NativeSessionID ||
		local.NativeProjectID != sourceRef.NativeProjectID ||
		local.NativeLocationDigest != sourceRef.NativeLocationDigest ||
		local.ProfileRevision != identity.ProfileRevision ||
		local.InstructionRevision != identity.InstructionRevision {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	prepared, code := g.prepareControllerParentChat(ctx, grant, target, intent, projection)
	if code != "" {
		return containers.SessionHandoffLaunch{}, code
	}
	digest := sha256.Sum256([]byte(grant.ID + "\x00" + target.HandoffID))
	return containers.SessionHandoffLaunch{
		Grant: containers.SessionBridgeGrantV1{
			SchemaVersion: 1, GrantID: "grt_" + hex.EncodeToString(digest[:12]),
			ServerID: identity.ServerID, SandboxID: identity.SandboxID,
			Generation: identity.SandboxGeneration, Instance: intent.Instance,
			ProfileID: "opencode", ProfileDigest: intent.Profile.ProfileDigest,
			HostKeyFingerprint: g.HostKeyFingerprint,
			Engine:             containers.SessionBridgeEngineV1{Host: "127.0.0.1", Port: local.Port},
			AllowedPaths:       []string{"/api"},
			AllowedMethods:     []string{"GET", "POST"},
			IssuedAt:           target.IssuedAt, ExpiresAt: target.ExpiresAt,
			Capability: containers.ForemanChatCapability,
			Chat: &containers.SessionBridgeChatV1{
				Protocol:              containers.ForemanChatProtocol,
				MaxQuestionBytes:      containers.ForemanChatQuestionBytes,
				MaxReplyBytes:         containers.ForemanChatReplyBytes,
				MaxQuestionsPerMinute: containers.ForemanChatQuestionsPerMinute,
				MaxConcurrent:         containers.ForemanChatMaxConcurrent,
				HandoffID:             target.HandoffID,
				NativeSessionID:       sourceRef.NativeSessionID,
				ServiceRegistrationID: identity.ServiceRegistrationID,
				ServiceGeneration:     identity.ServiceGeneration,
				ProjectID:             identity.ProjectID,
				WorkspaceEpoch:        identity.WorkspaceEpoch,
				Qualification:         g.ForemanChatQualification,
				Advisory:              foremanChatAdvisory(grant, target, identity, intent.Instance, projection, roleAgentDigest, prepared.PreparedReceiptDigest, g.ForemanChatQualification),
			},
		},
		HelloFrame: append([]byte(nil), hello...),
	}, ""
}

// prepareControllerParentChat issues the SAME supervisor controller-activity
// prepare worker prompts use, but scoped to the exact Foreman chat handoff. It
// first reads the native controller identity from the supervisor (the only
// authority that owns the exact persisted intent/projection/source), fetches
// the pinned provider connection material for that exact ready parent, builds
// the closed prepared tuple from the OBSERVED native identity, and lets the
// supervisor adopt the credential and bind it to the Foreman native session
// BEFORE the chat bridge process exists. A valid bound receipt for the same
// native session/credential is reused, so only the first handoff pays the
// bounded prepare cost.
//
// The prepared input id/digest are an advisory sentinel, never a question: no
// model text exists at handoff time, and the sentinel is never submitted to the
// native prompt route. The returned receipt is the Runtime-issued authority
// whose digest is bound into the chat advisory admission id; it contains no
// prompt, tool, approval or mutation capability.
func (g *Gateway) prepareControllerParentChat(
	ctx context.Context,
	grant state.LocalGrant,
	target model.ForemanChatHandoffV1,
	intent model.ControllerParentIntent,
	projection *model.ControllerRoleProjection,
) (model.ControllerPreparedReceipt, string) {
	if g.ControllerPrepare == nil || g.ControllerCredential == nil ||
		g.ForemanChatQualification == nil || projection == nil ||
		projection.ModelSelection == nil || projection.ModelSelection.CredentialBinding == nil {
		return model.ControllerPreparedReceipt{}, "foreman_chat_prepare_unavailable"
	}
	statusRequest := map[string]any{
		"schemaVersion": 1,
		"sandboxId":     intent.Owner.SandboxID,
		"instance":      intent.Instance,
		"profileId":     intent.Profile.ProfileID,
		"probe":         true,
	}
	payload, err := json.Marshal(statusRequest)
	if err != nil {
		return model.ControllerPreparedReceipt{}, "foreman_chat_prepare_unavailable"
	}
	raw, _, statusErr := g.ControllerPrepare.ExecManagedSupervisor(
		ctx, intent.Owner.SandboxID, containers.ManagedSupervisorStatus, payload)
	var status struct {
		Binding json.RawMessage `json:"binding"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &status) != nil || len(status.Binding) == 0 {
		return model.ControllerPreparedReceipt{}, "foreman_chat_prepare_unavailable"
	}
	if statusErr != nil {
		return model.ControllerPreparedReceipt{}, "foreman_chat_prepare_unavailable"
	}
	// The status receipt carries the EXACT native identity. Decode only the
	// closed fields this prepare consumes; the native intent is the authority
	// that owns the persisted configDigest/roleAgentDigest values, which can
	// differ from the Runtime's local start-request projection.
	type nativeIdentity struct {
		Intent struct {
			ConfigDigest          string                `json:"configDigest"`
			RoleAgentDigest       string                `json:"roleAgentDigest"`
			Role                  string                `json:"role"`
			ServiceRegistrationID string                `json:"serviceRegistrationId"`
			ServiceGeneration     int64                 `json:"serviceGeneration"`
			Instance              string                `json:"instance"`
			Owner                 model.ControllerOwner `json:"owner"`
			Workspace             struct {
				WorkspaceEpoch string `json:"workspaceEpoch"`
			} `json:"workspace"`
		} `json:"intent"`
		Projection model.ControllerRoleProjection `json:"projection"`
		Source     struct {
			Source struct {
				RegisteredSourceID   string `json:"registeredSourceId"`
				NativeSessionID      string `json:"nativeSessionId"`
				NativeProjectID      string `json:"nativeProjectId"`
				NativeLocationDigest string `json:"nativeLocationDigest"`
			} `json:"source"`
		} `json:"source"`
	}
	var observed struct {
		Identity        nativeIdentity                   `json:"identity"`
		State           string                           `json:"state"`
		PreparedReceipt *model.ControllerPreparedReceipt `json:"preparedReceipt"`
	}
	if json.Unmarshal(status.Binding, &observed) != nil || observed.Identity.Intent.Role != "orchestrator" ||
		observed.Identity.Intent.ServiceRegistrationID != intent.ServiceRegistrationID ||
		observed.Identity.Intent.ServiceGeneration != intent.ServiceGeneration ||
		observed.Identity.Intent.Instance != intent.Instance ||
		observed.Identity.Intent.Owner.ServerID != intent.Owner.ServerID ||
		observed.Identity.Intent.Owner.SandboxID != intent.Owner.SandboxID ||
		observed.Identity.Intent.Owner.SandboxGeneration != intent.Owner.SandboxGeneration ||
		observed.Identity.Source.Source.NativeSessionID != target.Source.NativeSessionID ||
		observed.Identity.Source.Source.NativeProjectID != target.Source.NativeProjectID ||
		observed.Identity.Source.Source.NativeLocationDigest != target.Source.NativeLocationDigest ||
		observed.Identity.Projection.ModelSelection == nil ||
		observed.Identity.Projection.ModelSelection.CredentialBinding == nil {
		return model.ControllerPreparedReceipt{}, "foreman_chat_prepare_refused"
	}
	native := observed.Identity
	selected := native.Projection.ModelSelection.Authority
	binding := native.Projection.ModelSelection.CredentialBinding
	if selected != projection.ModelSelection.Authority ||
		*binding != *projection.ModelSelection.CredentialBinding ||
		selected != (model.CellPreparedAuthorityV3{ProviderID: "openai", ModelID: containers.ForemanChatAdvisoryModelID, AuthMode: "api_key"}) {
		return model.ControllerPreparedReceipt{}, "foreman_chat_model_unaligned"
	}
	// A previously prepared binding for this exact native session and this exact
	// pinned credential is already the Runtime-issued admission. Reuse it: the
	// chat bridge re-prepares one question-bound receipt per advisory prompt.
	if observed.State == "bound" && observed.PreparedReceipt != nil &&
		observed.PreparedReceipt.Validate() == nil &&
		observed.PreparedReceipt.PreparedTuple.NativeRegistration.NativeSessionID == target.Source.NativeSessionID &&
		observed.PreparedReceipt.PreparedTuple.NativeRegistration.NativeLocationDigest == target.Source.NativeLocationDigest &&
		observed.PreparedReceipt.PreparedTuple.CredentialBinding == *binding &&
		observed.PreparedReceipt.PreparedTuple.Authority == selected {
		return *observed.PreparedReceipt, ""
	}
	credential, err := g.ControllerCredential.ControllerParentCredential(ctx, intent.ServiceRegistrationID)
	if err != nil {
		return model.ControllerPreparedReceipt{}, "foreman_chat_credential_unavailable"
	}
	if credential.ConnectionID != binding.ConnectionID ||
		credential.ConnectionRevision != binding.ConnectionRevision ||
		credential.ProviderID != selected.ProviderID ||
		credential.AuthMode != selected.AuthMode {
		return model.ControllerPreparedReceipt{}, "foreman_chat_credential_unavailable"
	}
	var material struct {
		Type string `json:"type"`
		Key  string `json:"key"`
	}
	if json.Unmarshal(credential.Material, &material) != nil || material.Type != "key" ||
		strings.TrimSpace(material.Key) == "" || len(material.Key) > 4096 {
		return model.ControllerPreparedReceipt{}, "foreman_chat_credential_unavailable"
	}
	// The advisory sentinel binds this prepare to the exact grant/handoff/session
	// and is never a model question. A stable pair means a replayed handoff
	// re-uses the SAME preparation identity instead of minting a new one.
	prepDigest := sha256.Sum256([]byte(
		"foreman-chat-prepare\x00" + grant.ID + "\x00" + target.HandoffID + "\x00" +
			target.Source.NativeSessionID + "\x00" + intent.ServiceRegistrationID))
	preparationID := "prep_" + hex.EncodeToString(prepDigest[:12])
	inputID := "msg_" + hex.EncodeToString(prepDigest[12:24])
	inputDigest := sha256.Sum256([]byte("foreman-chat-advisory\x00" + target.HandoffID + "\x00" + target.Source.NativeSessionID))
	preparedRegistration := model.ManagedNativeRegistrationV1{
		RegisteredSourceID:   native.Source.Source.RegisteredSourceID,
		NativeSessionID:      native.Source.Source.NativeSessionID,
		NativeProjectID:      native.Source.Source.NativeProjectID,
		NativeLocationDigest: native.Source.Source.NativeLocationDigest,
		WorkspaceEpoch:       native.Intent.Workspace.WorkspaceEpoch,
	}
	tuple := model.ControllerPreparedTuple{
		Owner:                 native.Intent.Owner,
		Role:                  native.Intent.Role,
		ServiceRegistrationID: native.Intent.ServiceRegistrationID,
		ServiceGeneration:     native.Intent.ServiceGeneration,
		NativeRegistration:    preparedRegistration,
		RoleAgentDigest:       native.Intent.RoleAgentDigest,
		ConfigurationDigest:   native.Intent.ConfigDigest,
		ConfigDigest:          native.Intent.ConfigDigest,
		InputID:               inputID,
		InputDigest:           "sha256:" + hex.EncodeToString(inputDigest[:]),
		Authority:             selected,
		CredentialBinding:     *binding,
	}
	request := map[string]any{
		"schemaVersion": 1,
		"sandboxId":     intent.Owner.SandboxID,
		"instance":      intent.Instance,
		"profileId":     intent.Profile.ProfileID,
		"preparationId": preparationID,
		"preparedTuple": tuple,
		"credential":    credential,
		"policyDigest":  g.ForemanChatQualification.PolicyDigest,
	}
	payload, err = json.Marshal(request)
	if err != nil {
		return model.ControllerPreparedReceipt{}, "foreman_chat_prepare_unavailable"
	}
	raw, _, execErr := g.ControllerPrepare.ExecManagedSupervisor(
		ctx, intent.Owner.SandboxID, containers.ManagedSupervisorControllerPrepare, payload)
	if len(raw) == 0 {
		return model.ControllerPreparedReceipt{}, "foreman_chat_prepare_unavailable"
	}
	var receipt struct {
		SchemaVersion   int                             `json:"schemaVersion"`
		Command         string                          `json:"command"`
		Status          string                          `json:"status"`
		PreparedReceipt model.ControllerPreparedReceipt `json:"preparedReceipt"`
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return model.ControllerPreparedReceipt{}, "foreman_chat_prepare_refused"
	}
	if receipt.SchemaVersion != 1 || receipt.Command != string(containers.ManagedSupervisorControllerPrepare) ||
		receipt.Status != "prepared" || receipt.PreparedReceipt.Validate() != nil ||
		receipt.PreparedReceipt.PreparationID != preparationID ||
		receipt.PreparedReceipt.PreparedTuple != tuple ||
		receipt.PreparedReceipt.PreparedTuple.NativeRegistration.NativeSessionID != target.Source.NativeSessionID ||
		receipt.PreparedReceipt.PreparedTuple.NativeRegistration.NativeProjectID != target.Source.NativeProjectID ||
		receipt.PreparedReceipt.PreparedTuple.NativeRegistration.NativeLocationDigest != target.Source.NativeLocationDigest ||
		receipt.PreparedReceipt.PreparedTuple.ServiceRegistrationID != intent.ServiceRegistrationID ||
		receipt.PreparedReceipt.PreparedTuple.Role != "orchestrator" {
		return model.ControllerPreparedReceipt{}, "foreman_chat_prepare_refused"
	}
	// The packaged supervisor emits a complete typed success receipt but exits
	// nonzero for controller-prepare (its _EXIT_OK set does not include
	// "prepared"). The validated receipt is authoritative; a nonzero exit is not
	// a refusal once every closed field above matched. Failures emit a typed
	// error receipt that fails those checks.
	_ = execErr
	return receipt.PreparedReceipt, ""
}

func (g *Gateway) validateForemanChatHandoff(
	ctx context.Context,
	grant state.LocalGrant,
	sandbox state.LocalSandbox,
	target model.ForemanChatHandoffV1,
	hello []byte,
) (containers.SessionHandoffLaunch, string) {
	// WP-196: the controller-parent Foreman chat path is the qualification
	// client. The handoff identity names the parent service, so dispatch there
	// first when this Runtime actually holds that parent. The legacy
	// managed-service sibling predates controller-parent qualification authority
	// and keeps its closed fail-before-SSH refusal.
	if parent, err := g.Store.ControllerParent(ctx, target.Identity.ServiceRegistrationID); err == nil && parent != nil {
		now := time.Now()
		if g.Now != nil {
			now = g.Now()
		}
		return g.validateControllerParentChatHandoff(ctx, grant, sandbox, target, now, hello)
	}
	_ = ctx
	_ = grant
	_ = sandbox
	_ = target
	_ = hello
	if g.ForemanChatQualification == nil {
		return containers.SessionHandoffLaunch{}, "foreman_chat_qualification_unconfigured"
	}
	return containers.SessionHandoffLaunch{}, "foreman_chat_qualification_unavailable"
}

// controllerParentChatProjection resolves the exact adopted projection for the
// Foreman parent. Foreman chat is a qualification client: without the venue
// configuration, an applied controller application, or the plugin-pinned model
// authority it refuses before any bridge process or SSH session exists.
func (g *Gateway) controllerParentChatProjection(ctx context.Context, intent model.ControllerParentIntent) (*model.ControllerRoleProjection, string, string) {
	if g.ForemanChatQualification == nil {
		return nil, "", "foreman_chat_qualification_unconfigured"
	}
	application, err := g.Store.WorkspaceApplication(ctx, intent.ApplicationOperationID)
	if err != nil || application == nil || !application.Applied || application.Operation.OperationID != intent.ApplicationOperationID {
		return nil, "", "foreman_chat_qualification_unavailable"
	}
	var projection *model.ControllerRoleProjection
	for index := range application.Operation.Dependencies.Roles {
		role := &application.Operation.Dependencies.Roles[index]
		if role.Binding.ServiceRegistrationID == intent.ServiceRegistrationID && role.Binding.Role == "orchestrator" {
			candidate := role.Projection
			projection = &candidate
		}
	}
	if projection == nil || projection.ModelSelection == nil ||
		projection.ModelSelection.Authority != (model.CellPreparedAuthorityV3{ProviderID: "openai", ModelID: containers.ForemanChatAdvisoryModelID, AuthMode: "api_key"}) {
		return nil, "", "foreman_chat_model_unaligned"
	}
	// The native controller identity, the signed policy and the chat advisory
	// all use the retained six-field projection. The optional version-1
	// tool-closure binding is a Runtime-side closure field carried only by the
	// parent's seven-field launch wire, so the parent intent's roleAgentDigest
	// is the digest of the WITH-closure projection while the advisory digest is
	// the digest WITHOUT it. WP-196: verify both views explicitly instead of
	// comparing the six-field advisory digest to the seven-field intent digest
	// (which misreported an aligned tuple as foreman_chat_model_unaligned).
	advisory := *projection
	wireDigest := model.WorkspaceDigest(advisory)
	advisory.ToolClosureDigest = ""
	roleAgentDigest := model.WorkspaceDigest(advisory)
	if wireDigest != intent.RoleAgentDigest || roleAgentDigest != model.WorkspaceDigest(advisory) {
		return nil, "", "foreman_chat_model_unaligned"
	}
	return &advisory, roleAgentDigest, ""
}

// managerInspectableTerminalState reports the valid proposal-bearing terminal
// outcomes whose completed manager session may be opened read-only through the
// exact handoff mapping. It admits no worker input, guidance delivery or any
// other mutating permission.
func managerInspectableTerminalState(state string) bool {
	switch state {
	case "recommended", "no_action", "needs_owner":
		return true
	}
	return false
}

func (g *Gateway) validateManagerSessionHandoff(
	ctx context.Context,
	grant state.LocalGrant,
	sandbox state.LocalSandbox,
	service *state.LocalManagedService,
	target model.SessionHandoffV1,
	hello []byte,
) (containers.SessionHandoffLaunch, string) {
	identity, sourceRef := target.Identity, target.Source
	run, err := g.Store.ManagerRunBySource(ctx, sourceRef.RegisteredSourceID)
	if err != nil || run == nil || run.Report == nil || run.Report.Proposal == nil || run.ManagerSession == nil ||
		run.Phase != run.Report.State || !managerInspectableTerminalState(run.Phase) ||
		run.ManagerRegisteredSourceID != sourceRef.RegisteredSourceID {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	session := run.ManagerSession
	manifest := service.Manifest
	if run.Manifest.Target.TeamID != identity.TeamID || run.Manifest.Target.MemberID != identity.MemberID ||
		run.Manifest.Source.ServiceRegistrationID != identity.ServiceRegistrationID ||
		run.Manifest.Source.ServiceGeneration != identity.ServiceGeneration ||
		run.Manifest.Source.SandboxGeneration != identity.SandboxGeneration ||
		run.Manifest.Source.WorkspaceEpoch != identity.WorkspaceEpoch ||
		session.NativeSessionID != sourceRef.NativeSessionID || session.NativeProjectID != sourceRef.NativeProjectID ||
		session.NativeLocationDigest != sourceRef.NativeLocationDigest ||
		session.ServiceRegistrationID != identity.ServiceRegistrationID || session.ServiceGeneration != identity.ServiceGeneration ||
		session.ProviderRouteDigest != run.Manifest.ProviderRouteDigest || session.ManagerProfile != run.Manifest.ManagerProfile ||
		manifest.Identity.ServerID != identity.ServerID || manifest.Identity.TeamID != identity.TeamID ||
		manifest.Identity.MemberID != identity.MemberID || manifest.Identity.SandboxID != identity.SandboxID ||
		manifest.Identity.SandboxGeneration != identity.SandboxGeneration ||
		manifest.Identity.ServiceRegistrationID != identity.ServiceRegistrationID ||
		manifest.Identity.Instance != identity.Instance ||
		service.ProcessInstance != model.ManagedServiceProcessInstance(identity.Instance, identity.ServiceGeneration) ||
		service.ServiceGeneration != identity.ServiceGeneration || service.Report.ServiceGeneration != identity.ServiceGeneration ||
		service.Report.Identity != manifest.Identity || service.Report.ObservedState != "ready" || !service.Report.InstructionApplied ||
		manifest.Workspace.ProjectID != identity.ProjectID || manifest.Workspace.WorkspaceEpoch != identity.WorkspaceEpoch ||
		manifest.Profile.ProfileID != identity.ProfileID || manifest.Profile.ProfileRevision != identity.ProfileRevision ||
		manifest.Profile.ProfileDigest != identity.ProfileDigest ||
		manifest.Instructions.InstructionRevision != identity.InstructionRevision ||
		manifest.Instructions.InstructionDigest != identity.InstructionDigest ||
		service.Report.InstructionRevision != identity.InstructionRevision || service.Report.InstructionDigest != identity.InstructionDigest ||
		!managerHandoffTargetMatches(run.Manifest.Target, target.Task, target.Work) {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	capability, err := g.Store.ManagerCapability(ctx, run.Manifest.Source.RegisteredSourceID)
	if err != nil || capability == nil || !capability.Available || capability.ProviderRouteDigest != run.Manifest.ProviderRouteDigest ||
		capability.ManagerProfile != run.Manifest.ManagerProfile || capability.ServiceGeneration != identity.ServiceGeneration ||
		capability.WorkspaceEpoch != identity.WorkspaceEpoch || capability.NativeSessionID != run.Manifest.Source.NativeSessionID ||
		capability.ProfileRevision != run.Manifest.Source.ProfileRevision || capability.InstructionRevision != run.Manifest.Source.InstructionRevision {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	primary, err := g.Store.ContinuitySource(ctx, run.Manifest.Source.RegisteredSourceID)
	if err != nil || primary == nil || primary.Report.Availability != "available" || primary.Lifecycle != "running" ||
		primary.Instance != identity.Instance || primary.Report.ServiceRegistrationID != identity.ServiceRegistrationID ||
		primary.Report.ServiceGeneration != identity.ServiceGeneration || primary.Report.ProjectID != identity.ProjectID ||
		primary.Report.SandboxID != identity.SandboxID || primary.Report.SandboxGeneration != identity.SandboxGeneration ||
		primary.Report.WorkspaceEpoch != identity.WorkspaceEpoch || primary.Report.NativeSessionID != run.Manifest.Source.NativeSessionID ||
		primary.Report.ProfileRevision != identity.ProfileRevision || primary.Report.InstructionRevision != identity.InstructionRevision {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	projects, err := g.Store.ManagedProjects(ctx)
	if err != nil {
		return containers.SessionHandoffLaunch{}, "handoff_not_ready"
	}
	var project *state.LocalManagedProject
	for index := range projects {
		candidate := &projects[index]
		if candidate.Report.ProjectID == identity.ProjectID && candidate.Report.WorkspaceEpoch == identity.WorkspaceEpoch {
			if project != nil {
				return containers.SessionHandoffLaunch{}, "handoff_not_ready"
			}
			project = candidate
		}
	}
	if project == nil || project.Phase != "ready" || project.Report.Availability != "available" ||
		project.ServerID != identity.ServerID || project.TeamID != identity.TeamID || project.MemberID != identity.MemberID ||
		project.Report.SandboxID != identity.SandboxID || project.Report.SandboxGeneration != identity.SandboxGeneration ||
		project.Report.SelectionID != manifest.Workspace.SelectionID || project.Report.RootAttestation != manifest.Workspace.RootAttestation ||
		primary.Root != project.HostRoot || grant.SandboxID != identity.SandboxID || sandbox.ID != identity.SandboxID ||
		sandbox.Generation != identity.SandboxGeneration || sandbox.ObservedGeneration != identity.SandboxGeneration ||
		!strings.HasPrefix(g.HostKeyFingerprint, "SHA256:") {
		return containers.SessionHandoffLaunch{}, "handoff_target_changed"
	}
	digest := sha256.Sum256([]byte(grant.ID + "\x00" + target.HandoffID))
	return containers.SessionHandoffLaunch{
		Grant: containers.SessionBridgeGrantV1{
			SchemaVersion: 1, GrantID: "grt_" + hex.EncodeToString(digest[:12]),
			ServerID: identity.ServerID, SandboxID: identity.SandboxID, Generation: identity.SandboxGeneration,
			Instance: identity.Instance, ProfileID: identity.ProfileID, ProfileDigest: identity.ProfileDigest,
			HostKeyFingerprint: g.HostKeyFingerprint, Engine: containers.SessionBridgeEngineV1{Host: "127.0.0.1", Port: service.Port},
			AllowedPaths: []string{"/api"}, AllowedMethods: []string{"GET", "OPTIONS"},
			IssuedAt: target.IssuedAt, ExpiresAt: target.ExpiresAt,
		},
		HelloFrame: append([]byte(nil), hello...),
	}, ""
}

func managerHandoffTargetMatches(target model.InsightsManagerTargetV1, task *model.SessionHandoffTaskV1, work *model.SessionHandoffWorkV1) bool {
	if (target.TaskID == nil) != (task == nil) || (target.WorkID == nil) != (work == nil) {
		return false
	}
	if task != nil && (*target.TaskID != task.TaskID || *target.TaskAttempt != task.TaskAttempt) {
		return false
	}
	return work == nil || *target.WorkID == work.WorkID && *target.WorkRevision == work.ExpectedRevision &&
		*target.BindingID == work.BindingID && *target.BindingRevision == work.BindingRevision
}

func Ed25519HostKeyFingerprint(keys []model.HostKey) (string, error) {
	for _, key := range keys {
		fields := strings.Fields(key.PublicKey)
		if len(fields) != 2 || fields[0] != "ssh-ed25519" {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil || len(blob) != 51 || binary.BigEndian.Uint32(blob[:4]) != 11 || string(blob[4:15]) != "ssh-ed25519" {
			return "", errors.New("invalid Ed25519 host public key")
		}
		digest := sha256.Sum256(blob)
		return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]), nil
	}
	return "", errors.New("Ed25519 host public key is required for session handoff")
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
