package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type gatewayBackendHandoffFixture struct {
	Finding struct {
		Handoff model.SessionHandoffV1 `json:"handoff"`
	} `json:"finding"`
	Work struct {
		Handoff model.SessionHandoffV1 `json:"handoff"`
	} `json:"work"`
}

type gatewayS2BHandoffFixture struct {
	ReviewerManifest   model.ContinuationHandoffManifestV1 `json:"reviewerManifest"`
	ReviewerReport     model.ContinuationHandoffReportV1   `json:"reviewerReport"`
	TargetRegistration model.ContinuityRegistrationV1      `json:"reviewerTargetRegistration"`
	SessionHandoff     struct {
		Handoff model.SessionHandoffV1 `json:"handoff"`
	} `json:"reviewerSessionHandoffAfterRegistration"`
}

type handoffBridgeCall struct {
	SandboxID string
	Launch    containers.SessionHandoffLaunch
}

type handoffTestEngine struct {
	calls chan handoffBridgeCall
}

func (e *handoffTestEngine) ExecSessionHandoff(
	_ context.Context,
	sandboxID string,
	launch containers.SessionHandoffLaunch,
	_ containers.SessionInput,
	_, _ io.Writer,
) error {
	e.calls <- handoffBridgeCall{SandboxID: sandboxID, Launch: launch}
	return nil
}

// handoffStreamingEngine models the packaged bridge: it logs deterministic
// diagnostics to stderr before and after writing framed protocol bytes to
// stdout, then exits.
type handoffStreamingEngine struct {
	stderrBefore []byte
	stdout       []byte
	stderrAfter  []byte
	err          error
	streams      chan handoffStreamWriters
}

type handoffStreamWriters struct {
	stdout io.Writer
	stderr io.Writer
}

func (e *handoffStreamingEngine) ExecSessionHandoff(
	_ context.Context, _ string, _ containers.SessionHandoffLaunch, _ containers.SessionInput,
	stdout, stderr io.Writer,
) error {
	if len(e.stderrBefore) != 0 {
		if _, err := stderr.Write(e.stderrBefore); err != nil {
			return err
		}
	}
	if len(e.stdout) != 0 {
		if _, err := stdout.Write(e.stdout); err != nil {
			return err
		}
	}
	if len(e.stderrAfter) != 0 {
		if _, err := stderr.Write(e.stderrAfter); err != nil {
			return err
		}
	}
	e.streams <- handoffStreamWriters{stdout: stdout, stderr: stderr}
	return e.err
}

// runGatewayStreamRequest drives one real serveConnection request and returns
// the raw connection bytes after the JSON response line, so framed protocol
// purity can be asserted byte for byte.
func runGatewayStreamRequest(t *testing.T, gateway *Gateway, request gatewayRequest) (gatewayResponse, []byte) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		gateway.serveConnection(context.Background(), server, gatewayTestSessionInput{Reader: server})
		close(done)
	}()
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(client)
	_ = client.Close()
	if err != nil {
		t.Fatalf("read gateway stream: %v", err)
	}
	<-done
	index := bytes.IndexByte(raw, '\n')
	if index < 0 {
		t.Fatalf("gateway response is not newline terminated: %q", raw)
	}
	var response gatewayResponse
	if err := json.Unmarshal(raw[:index], &response); err != nil {
		t.Fatalf("gateway response %q: %v", raw[:index], err)
	}
	return response, raw[index+1:]
}

func gatewayStreamHandoffGateway(t *testing.T, store *state.Store, engine containers.SessionHandoffEngine, target model.SessionHandoffV1) *Gateway {
	t.Helper()
	return &Gateway{
		Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
		SessionHandoffEngine: engine,
		HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
	}
}

func loadGatewayBackendHandoffFixture(t *testing.T) gatewayBackendHandoffFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("testdata", "agent-session-handoff-v1.backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture gatewayBackendHandoffFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func loadGatewayS2BHandoffFixture(t *testing.T) gatewayS2BHandoffFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "api", "testdata", "agent-continuation-handoff-v1.backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture gatewayS2BHandoffFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func encodeGatewayHandoffHello(t *testing.T, target model.SessionHandoffV1) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"protocol": "wm-team-control/1",
		"handoff":  target,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(1+len(payload)))
	frame[4] = 0x01
	copy(frame[5:], payload)
	return frame
}

// seedSessionHandoffAuthority seeds the production-shaped supervisor process
// instance exactly as the reconciliation writer derives it.
func seedSessionHandoffAuthority(t *testing.T, target model.SessionHandoffV1) (*state.Store, string) {
	t.Helper()
	return seedSessionHandoffAuthorityForProcessInstance(t, target,
		model.ManagedServiceProcessInstance(target.Identity.Instance, target.Identity.ServiceGeneration))
}

func seedSessionHandoffAuthorityForProcessInstance(t *testing.T, target model.SessionHandoffV1, processInstance string) (*state.Store, string) {
	t.Helper()
	return seedSessionHandoffAuthorityForProcessInstanceAtPath(t, filepath.Join(t.TempDir(), "runtime.sqlite3"), target, processInstance)
}

func seedSessionHandoffAuthorityForProcessInstanceAtPath(t *testing.T, path string, target model.SessionHandoffV1, processInstance string) (*state.Store, string) {
	t.Helper()
	ctx := context.Background()
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	grantID := "grant_handoff123"
	if err := store.PutSandbox(ctx, state.LocalSandbox{
		ID: target.Identity.SandboxID, Name: "managed", DesiredState: "running",
		ObservedState: "running", Generation: target.Identity.SandboxGeneration,
		ObservedGeneration: target.Identity.SandboxGeneration, Lifetime: "persistent",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutGrant(ctx, state.LocalGrant{
		ID: grantID, SandboxID: target.Identity.SandboxID,
		SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		DesiredState: "active", ObservedState: "applied",
	}); err != nil {
		t.Fatal(err)
	}
	serviceID := target.Identity.ServiceRegistrationID
	selectionID := "selection_handoff_exact"
	serviceManifest := model.ManagedServiceV1{
		FormatVersion: 1, OperationID: "operation_handoff_service", ActionRevision: 1,
		DesiredRevision: 1, ConfigDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		DesiredState: "active", SessionMode: "lookup_only",
		Identity: model.ManagedServiceIdentityV1{
			ServerID: target.Identity.ServerID, TeamID: target.Identity.TeamID,
			MemberID: target.Identity.MemberID, SandboxID: target.Identity.SandboxID,
			SandboxGeneration:         target.Identity.SandboxGeneration,
			ServiceRegistrationID:     serviceID,
			ExpectedServiceGeneration: target.Identity.ServiceGeneration,
			Instance:                  target.Identity.Instance, Role: target.Identity.Role,
		},
		Profile: model.ManagedServiceProfileV1{
			SetupOperationID: "setup_handoff", ProfileID: target.Identity.ProfileID,
			ProfileRevision: target.Identity.ProfileRevision, ProfileDigest: target.Identity.ProfileDigest,
		},
		Instructions: model.ManagedServiceInstructionsV1{
			InstructionRevision: target.Identity.InstructionRevision,
			InstructionDigest:   target.Identity.InstructionDigest,
		},
		Workspace: model.ManagedServiceWorkspaceV1{
			SelectionID: selectionID, ProjectID: target.Identity.ProjectID,
			WorkspaceEpoch: target.Identity.WorkspaceEpoch, ScopeRevision: 1,
			Designation:     "team_project",
			RootAttestation: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		},
	}
	serviceReport := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: serviceManifest.OperationID, ActionRevision: 1,
		ObservedDesiredRevision: 1, ConfigDigest: serviceManifest.ConfigDigest,
		ObservedState: "ready", Identity: serviceManifest.Identity,
		ServiceGeneration: target.Identity.ServiceGeneration,
		ProfileStatus:     "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready",
		WorkerStatus: "ready", InstructionApplied: true,
		InstructionRevision: target.Identity.InstructionRevision,
		InstructionDigest:   target.Identity.InstructionDigest,
		NativeRegistration: &model.ManagedNativeRegistrationV1{
			RegisteredSourceID:   target.Source.RegisteredSourceID,
			WorkspaceEpoch:       target.Identity.WorkspaceEpoch,
			NativeSessionID:      target.Source.NativeSessionID,
			NativeProjectID:      target.Source.NativeProjectID,
			NativeLocationDigest: target.Source.NativeLocationDigest,
		},
		ReceiptDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	if err := store.PutManagedServiceIntent(ctx, state.LocalManagedService{
		Manifest: serviceManifest, Phase: "pending", ProcessInstance: processInstance,
		Port: 18443, ServiceGeneration: target.Identity.ServiceGeneration,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateManagedService(ctx, serviceID, "ready", &serviceReport, ""); err != nil {
		t.Fatal(err)
	}
	serviceIDPointer := serviceID
	if err := store.PutManagedProject(ctx, state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: selectionID, ProjectID: target.Identity.ProjectID,
			WorkspaceEpoch: target.Identity.WorkspaceEpoch, SandboxID: target.Identity.SandboxID,
			SandboxGeneration:     target.Identity.SandboxGeneration,
			ServiceRegistrationID: &serviceIDPointer, Designation: "team_project", Label: "team",
			Availability: "available", RootAttestation: serviceManifest.Workspace.RootAttestation,
			LastObservedAt: target.IssuedAt,
		},
		ServerID: target.Identity.ServerID, TeamID: target.Identity.TeamID,
		MemberID: target.Identity.MemberID, AllocationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ConfigDigest: serviceManifest.ConfigDigest, Anchor: "/host/workspaces", HostRoot: "/host/workspaces/team",
		ContainerRoot: "/home/agent/projects/team", Phase: "ready", ScopeRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	sourceReport := model.ContinuitySourceReportV1{
		FormatVersion: 1, RegisteredSourceID: target.Source.RegisteredSourceID,
		ServiceRegistrationID: serviceID, ServiceGeneration: target.Identity.ServiceGeneration,
		ProjectID: target.Identity.ProjectID, SandboxID: target.Identity.SandboxID,
		SandboxGeneration: target.Identity.SandboxGeneration, WorkspaceEpoch: target.Identity.WorkspaceEpoch,
		NativeSessionID: target.Source.NativeSessionID, NativeProjectID: target.Source.NativeProjectID,
		NativeLocationDigest: target.Source.NativeLocationDigest, ScopeRevision: 1,
		Role: target.Identity.Role, ProfileRevision: target.Identity.ProfileRevision,
		InstructionRevision: target.Identity.InstructionRevision, Availability: "available",
		LastObservedAt: target.IssuedAt,
	}
	if err := store.PutContinuitySource(ctx, state.LocalContinuitySource{
		Report: sourceReport, Root: "/host/workspaces/team", Instance: target.Identity.Instance,
		Lifecycle: "running", LifecycleRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if target.Work != nil {
		if err := store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
			Manifest: model.ContinuityRegistrationV1{
				FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: 1,
				Identity: model.ContinuityIdentityV1{
					WorkID: target.Work.WorkID, ProjectID: target.Identity.ProjectID,
					SandboxID: target.Identity.SandboxID, WorkspaceEpoch: target.Identity.WorkspaceEpoch,
					SandboxGeneration: target.Identity.SandboxGeneration,
					ExpectedRevision:  target.Work.ExpectedRevision,
				},
				Binding: model.ContinuityBindingV1{
					BindingID: target.Work.BindingID, BindingRevision: target.Work.BindingRevision,
					RegisteredSourceID:    target.Source.RegisteredSourceID,
					ServiceRegistrationID: serviceID, NativeSessionID: target.Source.NativeSessionID,
					NativeProjectID:      target.Source.NativeProjectID,
					NativeLocationDigest: target.Source.NativeLocationDigest,
				},
			},
			ObservedStatus: "verified", ServiceGeneration: target.Identity.ServiceGeneration,
			ReceiptDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		}); err != nil {
			t.Fatal(err)
		}
	}
	return store, grantID
}

func TestGatewayValidatesActualBackendFindingAndWorkBeforeFixedBridge(t *testing.T) {
	fixture := loadGatewayBackendHandoffFixture(t)
	for name, target := range map[string]model.SessionHandoffV1{
		"finding": fixture.Finding.Handoff,
		"work":    fixture.Work.Handoff,
	} {
		t.Run(name, func(t *testing.T) {
			store, grantID := seedSessionHandoffAuthority(t, target)
			ordinary := &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)}
			bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
			frame := encodeGatewayHandoffHello(t, target)
			gateway := &Gateway{
				Store: store, Engine: ordinary, SessionHandoffEngine: bridge,
				HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				Now:                func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
			}
			response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
				GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
				SessionHandoff: &target, SessionHandoffHello: frame,
			})
			_ = client.Close()
			if !response.OK {
				t.Fatalf("exact backend handoff was rejected: %s", response.Error)
			}
			select {
			case call := <-bridge.calls:
				if call.SandboxID != target.Identity.SandboxID || call.Launch.Grant.Instance != target.Identity.Instance ||
					call.Launch.Grant.Engine.Port != 18443 || !bytes.Equal(call.Launch.HelloFrame, frame) ||
					call.Launch.Grant.ExpiresAt != target.ExpiresAt {
					t.Fatalf("fixed launch did not preserve host authority: %+v", call)
				}
			case <-time.After(time.Second):
				t.Fatal("fixed handoff bridge was not launched")
			}
			select {
			case call := <-ordinary.calls:
				t.Fatalf("handoff reached arbitrary command execution: %+v", call)
			default:
			}
		})
	}
}

// A service stored with the writer's derived supervisor process instance
// (wmsup-default-0003 for this fixture) must pass the pre-launch gate for both
// the ordinary and manager branches; the raw logical instance is not the
// stored identity.
// An ordinary Team manager Work/session has no ManagerRun mapping. The run
// mapping, not the descriptor role, must select the manager validation path.
func TestGatewayAdmitsOrdinaryManagerSessionWithoutRunMapping(t *testing.T) {
	target := loadGatewayBackendHandoffFixture(t).Work.Handoff
	target.Identity.Role = "manager"
	store, grantID := seedSessionHandoffAuthority(t, target)
	runs, err := store.ManagerRuns(context.Background())
	if err != nil || len(runs) != 0 {
		t.Fatalf("seeded manager runs = %#v, %v", runs, err)
	}
	bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
	gateway := &Gateway{
		Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
		SessionHandoffEngine: bridge,
		HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
	}
	response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
	})
	_ = client.Close()
	if !response.OK {
		t.Fatalf("ordinary manager session without run mapping was rejected: %+v", response)
	}
	select {
	case call := <-bridge.calls:
		if call.SandboxID != target.Identity.SandboxID || call.Launch.Grant.Instance != target.Identity.Instance {
			t.Fatalf("ordinary manager launch changed: %+v", call)
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary manager session did not reach the fixed bridge")
	}
}

func TestGatewayAcceptsProductionDerivedProcessInstance(t *testing.T) {
	target := loadGatewayBackendHandoffFixture(t).Finding.Handoff
	store, grantID := seedSessionHandoffAuthority(t, target)
	service, err := store.ManagedService(context.Background(), target.Identity.ServiceRegistrationID)
	if err != nil || service == nil {
		t.Fatalf("seeded service = %#v, %v", service, err)
	}
	if want := "wmsup-default-0003"; service.ProcessInstance != want {
		t.Fatalf("seeded process instance = %q, want %q", service.ProcessInstance, want)
	}
	bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
	gateway := &Gateway{
		Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
		SessionHandoffEngine: bridge,
		HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
	}
	response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
	})
	_ = client.Close()
	if !response.OK {
		t.Fatalf("production-derived process instance was rejected: %+v", response)
	}
	select {
	case call := <-bridge.calls:
		if call.SandboxID != target.Identity.SandboxID {
			t.Fatalf("launch changed: %+v", call)
		}
	case <-time.After(time.Second):
		t.Fatal("accepted handoff did not reach the fixed bridge")
	}
}

func TestGatewayRefusesNonProductionProcessInstance(t *testing.T) {
	target := loadGatewayBackendHandoffFixture(t).Finding.Handoff
	mutations := map[string]string{
		"wrong instance":   "wmsup-other-0003",
		"wrong generation": "wmsup-default-0002",
	}
	for name, processInstance := range mutations {
		t.Run(name, func(t *testing.T) {
			store, grantID := seedSessionHandoffAuthorityForProcessInstance(t, target, processInstance)
			bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
			gateway := &Gateway{
				Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
				SessionHandoffEngine: bridge,
				HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
			}
			response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
				GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
				SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
			})
			_ = client.Close()
			if response.OK || response.Error != "handoff_target_changed" {
				t.Fatalf("mismatched process instance returned %+v", response)
			}
			select {
			case call := <-bridge.calls:
				t.Fatalf("mismatched process instance reached bridge: %+v", call)
			default:
			}
		})
	}
}

func handoffStreamSink(t *testing.T, engine *handoffStreamingEngine) interface{ String() string } {
	t.Helper()
	var writers handoffStreamWriters
	select {
	case writers = <-engine.streams:
	case <-time.After(time.Second):
		t.Fatal("handoff bridge was not executed")
	}
	if writers.stdout == writers.stderr {
		t.Fatal("handoff bridge stderr was routed into the framed connection stream")
	}
	sink, ok := writers.stderr.(interface{ String() string })
	if !ok {
		t.Fatalf("handoff bridge stderr sink = %T, want bounded diagnostics", writers.stderr)
	}
	return sink
}

func TestGatewayHandoffKeepsBridgeStderrOutOfFramedStream(t *testing.T) {
	target := loadGatewayBackendHandoffFixture(t).Finding.Handoff
	store, grantID := seedSessionHandoffAuthority(t, target)
	ack := []byte{0x00, 0x00, 0x00, 0x0d, 0x02, 'h', 'e', 'l', 'l', 'o', '-', 'a', 'c', 'k', 0x00}
	before := []byte("[team-bridge-helper] ready instance=default engine=127.0.0.1:18443\n")
	after := []byte("[team-bridge-helper] attached session=ses_bridge0001\n")
	engine := &handoffStreamingEngine{
		stderrBefore: before, stdout: ack, stderrAfter: after,
		streams: make(chan handoffStreamWriters, 1),
	}
	response, stream := runGatewayStreamRequest(t, gatewayStreamHandoffGateway(t, store, engine, target), gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
	})
	if !response.OK {
		t.Fatalf("handoff was rejected: %+v", response)
	}
	want := append(append([]byte{}, ack...), []byte(fmt.Sprintf("\x00warpmetal-exit:%s:0\n", response.ExitMarker))...)
	if !bytes.Equal(stream, want) {
		t.Fatalf("connection stream = %q, want framed bytes only %q", stream, want)
	}
	sink := handoffStreamSink(t, engine)
	wantDiagnostics := string(append(append([]byte{}, before...), after...))
	if got := sink.String(); got != wantDiagnostics {
		t.Fatalf("diagnostic sink = %q, want %q", got, wantDiagnostics)
	}
}

func TestGatewayHandoffDiagnosticSinkBoundsLargeStderr(t *testing.T) {
	target := loadGatewayBackendHandoffFixture(t).Finding.Handoff
	store, grantID := seedSessionHandoffAuthority(t, target)
	ack := []byte{0x00, 0x00, 0x00, 0x05, 0x02, 'p', 'i', 'n', 'g', 0x00}
	tail := []byte("[team-bridge-helper] most recent line\n")
	large := append(bytes.Repeat([]byte{'d'}, 64*1024), tail...)
	engine := &handoffStreamingEngine{
		stderrBefore: large, stdout: ack,
		streams: make(chan handoffStreamWriters, 1),
	}
	response, stream := runGatewayStreamRequest(t, gatewayStreamHandoffGateway(t, store, engine, target), gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
	})
	if !response.OK {
		t.Fatalf("handoff was rejected: %+v", response)
	}
	want := append(append([]byte{}, ack...), []byte(fmt.Sprintf("\x00warpmetal-exit:%s:0\n", response.ExitMarker))...)
	if !bytes.Equal(stream, want) {
		t.Fatalf("connection stream = %q, want framed bytes only %q", stream, want)
	}
	retained := handoffStreamSink(t, engine).String()
	if len(retained) == 0 || len(retained) >= len(large) {
		t.Fatalf("diagnostic sink did not bound large stderr: %d bytes", len(retained))
	}
	if len(retained) > 64*1024 {
		t.Fatalf("diagnostic sink retained too much: %d bytes", len(retained))
	}
	if !strings.HasSuffix(retained, string(tail)) {
		t.Fatalf("diagnostic sink dropped the most recent stderr: %q", retained)
	}
}

func TestGatewayHandoffBridgeErrorAfterStderrKeepsCleanExitFrame(t *testing.T) {
	target := loadGatewayBackendHandoffFixture(t).Finding.Handoff
	store, grantID := seedSessionHandoffAuthority(t, target)
	ack := []byte{0x00, 0x00, 0x00, 0x08, 0x02, 'c', 'l', 'o', 's', 'e', 'd', 0x00}
	diagnostics := []byte("[team-bridge-helper] session failed: closed\n")
	engine := &handoffStreamingEngine{
		stderrBefore: diagnostics, stdout: ack, err: errors.New("bridge exited after logging"),
		streams: make(chan handoffStreamWriters, 1),
	}
	response, stream := runGatewayStreamRequest(t, gatewayStreamHandoffGateway(t, store, engine, target), gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
	})
	if !response.OK {
		t.Fatalf("handoff was rejected: %+v", response)
	}
	want := append(append([]byte{}, ack...), []byte(fmt.Sprintf("\x00warpmetal-exit:%s:1\n", response.ExitMarker))...)
	if !bytes.Equal(stream, want) {
		t.Fatalf("connection stream = %q, want framed bytes only %q", stream, want)
	}
	if got := handoffStreamSink(t, engine).String(); got != string(diagnostics) {
		t.Fatalf("diagnostic sink = %q, want %q", got, diagnostics)
	}
}

func TestGatewayRefusesEveryStaleHostTupleBeforeContainerExecution(t *testing.T) {
	fixture := loadGatewayBackendHandoffFixture(t)
	original := fixture.Work.Handoff
	mutations := map[string]func(*model.SessionHandoffV1){
		"sandbox_generation": func(v *model.SessionHandoffV1) { v.Identity.SandboxGeneration++ },
		"service_generation": func(v *model.SessionHandoffV1) { v.Identity.ServiceGeneration++ },
		"profile_digest": func(v *model.SessionHandoffV1) {
			v.Identity.ProfileDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"instruction_revision": func(v *model.SessionHandoffV1) { v.Identity.InstructionRevision++ },
		"project":              func(v *model.SessionHandoffV1) { v.Identity.ProjectID += "_stale" },
		"workspace_epoch":      func(v *model.SessionHandoffV1) { v.Identity.WorkspaceEpoch += "_stale" },
		"registered_source":    func(v *model.SessionHandoffV1) { v.Source.RegisteredSourceID += "_stale" },
		"native_session":       func(v *model.SessionHandoffV1) { v.Source.NativeSessionID += "_stale" },
		"native_project":       func(v *model.SessionHandoffV1) { v.Source.NativeProjectID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		"native_location": func(v *model.SessionHandoffV1) {
			v.Source.NativeLocationDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"work_revision":    func(v *model.SessionHandoffV1) { v.Work.ExpectedRevision++ },
		"binding_revision": func(v *model.SessionHandoffV1) { v.Work.BindingRevision++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			store, grantID := seedSessionHandoffAuthority(t, original)
			stale := original
			work := *original.Work
			stale.Work = &work
			mutate(&stale)
			bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
			gateway := &Gateway{
				Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
				SessionHandoffEngine: bridge,
				HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				Now:                  func() time.Time { return original.IssuedAt.Add(30 * time.Second) },
			}
			response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
				GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
				SessionHandoff: &stale, SessionHandoffHello: encodeGatewayHandoffHello(t, stale),
			})
			_ = client.Close()
			if response.OK || response.Error != "handoff_target_changed" {
				t.Fatalf("stale tuple returned %+v", response)
			}
			select {
			case call := <-bridge.calls:
				t.Fatalf("stale tuple reached bridge: %+v", call)
			default:
			}
		})
	}
}

func TestGatewayRefusesExpiredHandoffWithoutMutatingAuthority(t *testing.T) {
	target := loadGatewayBackendHandoffFixture(t).Finding.Handoff
	store, grantID := seedSessionHandoffAuthority(t, target)
	beforeSources, _ := store.ContinuitySources(context.Background())
	beforeProjects, _ := store.ManagedProjects(context.Background())
	beforeServices, _ := store.ManagedServices(context.Background())
	bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
	gateway := &Gateway{
		Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
		SessionHandoffEngine: bridge,
		HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Now:                  func() time.Time { return target.ExpiresAt.Add(time.Nanosecond) },
	}
	response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
	})
	_ = client.Close()
	if response.OK || response.Error != "handoff_expired" {
		t.Fatalf("expired handoff returned %+v", response)
	}
	afterSources, _ := store.ContinuitySources(context.Background())
	afterProjects, _ := store.ManagedProjects(context.Background())
	afterServices, _ := store.ManagedServices(context.Background())
	if len(afterSources) != len(beforeSources) || len(afterProjects) != len(beforeProjects) || len(afterServices) != len(beforeServices) {
		t.Fatal("handoff validation mutated host authority")
	}
}

func seedMappedS2BHandoffAuthority(
	t *testing.T,
	fixture gatewayS2BHandoffFixture,
) (*state.Store, string, model.SessionHandoffV1) {
	t.Helper()
	target := fixture.SessionHandoff.Handoff
	primary := target
	primary.Identity.ProjectID = "project_s2b_primary0001"
	primary.Identity.WorkspaceEpoch = "epoch_s2b_primary0001"
	primary.Source.RegisteredSourceID = "source_s2b_primary0001"
	primary.Source.NativeSessionID = "ses_s2b_primary0001"
	primary.Source.NativeProjectID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	primary.Source.NativeLocationDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	primary.Work = nil
	store, grantID := seedSessionHandoffAuthority(t, primary)

	serviceID := target.Identity.ServiceRegistrationID
	if err := store.PutManagedProject(context.Background(), state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: fixture.ReviewerReport.TargetWorkspace.SelectionID,
			ProjectID: target.Identity.ProjectID, WorkspaceEpoch: target.Identity.WorkspaceEpoch,
			SandboxID: target.Identity.SandboxID, SandboxGeneration: target.Identity.SandboxGeneration,
			ServiceRegistrationID: &serviceID, Designation: "continuity-handoff", Label: "reviewer",
			Availability: "available", RootAttestation: fixture.ReviewerReport.TargetWorkspace.RootAttestation,
			LastObservedAt: target.IssuedAt,
		},
		ServerID: target.Identity.ServerID, TeamID: target.Identity.TeamID, MemberID: target.Identity.MemberID,
		AllocationDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ConfigDigest:     "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Anchor:           "/host/workspaces", HostRoot: "/host/workspaces/reviewer",
		ContainerRoot: "/home/agent/projects/reviewer", Phase: "ready",
		ScopeRevision: fixture.ReviewerReport.TargetWorkspace.ScopeRevision,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuitySource(context.Background(), state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: target.Source.RegisteredSourceID,
			ServiceRegistrationID: target.Identity.ServiceRegistrationID,
			ServiceGeneration:     target.Identity.ServiceGeneration, ProjectID: target.Identity.ProjectID,
			SandboxID: target.Identity.SandboxID, SandboxGeneration: target.Identity.SandboxGeneration,
			WorkspaceEpoch: target.Identity.WorkspaceEpoch, NativeSessionID: target.Source.NativeSessionID,
			NativeProjectID: target.Source.NativeProjectID, NativeLocationDigest: target.Source.NativeLocationDigest,
			ScopeRevision: fixture.ReviewerReport.TargetWorkspace.ScopeRevision, Role: target.Identity.Role,
			ProfileRevision: target.Identity.ProfileRevision, InstructionRevision: target.Identity.InstructionRevision,
			Availability: "available", LastObservedAt: target.IssuedAt,
		},
		Root: "/host/workspaces/reviewer", Instance: target.Identity.Instance,
		Lifecycle: "running", LifecycleRevision: fixture.ReviewerReport.DesiredRevision,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuityRegistration(context.Background(), state.LocalContinuityRegistration{
		Manifest: fixture.TargetRegistration, ObservedStatus: "verified",
		ServiceGeneration: target.Identity.ServiceGeneration,
		ReceiptDigest:     "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuationHandoffPreparation(context.Background(), state.LocalContinuationHandoffPreparation{
		Manifest: fixture.ReviewerManifest, Phase: "allocating",
		TargetSelectionID: fixture.ReviewerReport.TargetWorkspace.SelectionID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationHandoffPreparation(
		context.Background(), fixture.ReviewerManifest.OperationID,
		fixture.ReviewerReport.TargetWorkspace.SelectionID, fixture.ReviewerReport,
	); err != nil {
		t.Fatal(err)
	}
	return store, grantID, primary
}

func TestGatewayAcceptsOnlyVerifiedS2BAdditionalMapping(t *testing.T) {
	fixture := loadGatewayS2BHandoffFixture(t)
	target := fixture.SessionHandoff.Handoff

	t.Run("exact additional mapping", func(t *testing.T) {
		store, grantID, _ := seedMappedS2BHandoffAuthority(t, fixture)
		bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
		gateway := &Gateway{
			Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
			SessionHandoffEngine: bridge,
			HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
		}
		response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
			GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
			SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
		})
		_ = client.Close()
		if !response.OK {
			t.Fatalf("verified mapped session was rejected: %+v", response)
		}
		select {
		case call := <-bridge.calls:
			if call.Launch.Grant.Instance != target.Identity.Instance ||
				!bytes.Equal(call.Launch.HelloFrame, encodeGatewayHandoffHello(t, target)) {
				t.Fatalf("mapped launch changed: %+v", call)
			}
		case <-time.After(time.Second):
			t.Fatal("mapped session did not reach fixed bridge")
		}
	})

	t.Run("primary source cannot substitute for mapped Work", func(t *testing.T) {
		store, grantID, primary := seedMappedS2BHandoffAuthority(t, fixture)
		substituted := target
		substituted.Source = primary.Source
		bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
		gateway := &Gateway{
			Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
			SessionHandoffEngine: bridge,
			HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
		}
		response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
			GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
			SessionHandoff: &substituted, SessionHandoffHello: encodeGatewayHandoffHello(t, substituted),
		})
		_ = client.Close()
		if response.OK || response.Error != "handoff_target_changed" {
			t.Fatalf("primary source substitution returned %+v", response)
		}
		select {
		case call := <-bridge.calls:
			t.Fatalf("substitution reached bridge: %+v", call)
		default:
		}
	})
}

func TestGatewayPreservesLegacyTeamHelloWithoutHandoff(t *testing.T) {
	target := loadGatewayBackendHandoffFixture(t).Finding.Handoff
	store, grantID := seedSessionHandoffAuthority(t, target)
	payload := []byte(`{"protocol":"wm-team-control/1"}`)
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(1+len(payload)))
	frame[4] = 0x01
	copy(frame[5:], payload)
	ordinary := &gatewayTestEngine{
		calls: make(chan gatewayExecCall, 1), readInputBytes: len(frame), inputBytes: make(chan []byte, 1),
	}
	gateway := &Gateway{
		Store: store, Engine: ordinary,
		SessionHandoffEngine: &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)},
		HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
	}
	response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: nil, SessionHandoffHello: frame,
	})
	_ = client.Close()
	if !response.OK {
		t.Fatalf("legacy Team session was rejected: %s", response.Error)
	}
	select {
	case got := <-ordinary.inputBytes:
		if !bytes.Equal(got, frame) {
			t.Fatalf("legacy HELLO changed: %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("legacy Team HELLO did not reach the existing command path")
	}
}

func TestGatewayRefusesPrivateDescriptorThatDiffersFromExactHello(t *testing.T) {
	target := loadGatewayBackendHandoffFixture(t).Finding.Handoff
	store, grantID := seedSessionHandoffAuthority(t, target)
	frame := encodeGatewayHandoffHello(t, target)
	changed := target
	changed.Identity.WorkspaceEpoch += "_different"
	bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
	gateway := &Gateway{
		Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
		SessionHandoffEngine: bridge,
		HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
	}
	response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &changed, SessionHandoffHello: frame,
	})
	_ = client.Close()
	if response.OK || response.Error != "handoff_invalid" {
		t.Fatalf("mismatched private descriptor returned %+v", response)
	}
	select {
	case call := <-bridge.calls:
		t.Fatalf("mismatched descriptor reached helper: %+v", call)
	default:
	}
}

func TestSessionHandoffHostPinDerivesFromDaemonEd25519Key(t *testing.T) {
	blob := make([]byte, 0, 51)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], 11)
	blob = append(blob, length[:]...)
	blob = append(blob, "ssh-ed25519"...)
	binary.BigEndian.PutUint32(length[:], 32)
	blob = append(blob, length[:]...)
	blob = append(blob, make([]byte, 32)...)
	fingerprint, err := Ed25519HostKeyFingerprint([]model.HostKey{{
		PublicKey: "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob),
	}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(blob)
	want := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	if fingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", fingerprint, want)
	}
	if _, err := Ed25519HostKeyFingerprint([]model.HostKey{{
		PublicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==",
	}}); err == nil {
		t.Fatal("non-Ed25519 daemon key was accepted for the bridge host pin")
	}
}
