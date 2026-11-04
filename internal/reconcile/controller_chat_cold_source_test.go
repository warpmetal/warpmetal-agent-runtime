package reconcile

// Current A7/N6 app comes from the same accepted-app TLS/SQLite constructor.
// Public Access.Gateway.Serve consumes the actual owner HELLO framing over a
// Unix socket. No old sentinel preparation, fake admission or signing broker.
import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type currentChatColdSource struct {
	native                                     *parentSourceRuntime
	bridge, credentials, preparations, prompts int
}

func (s *currentChatColdSource) ExecManagedSupervisor(ctx context.Context, box string, action containers.ManagedSupervisorAction, raw []byte) ([]byte, []byte, error) {
	if action == containers.ManagedSupervisorControllerPrepare {
		s.preparations++
		return nil, nil, errors.New("cold HELLO must not prepare")
	}
	if action == containers.ManagedSupervisorControllerPrompt {
		s.prompts++
		return nil, nil, errors.New("cold HELLO must not prompt")
	}
	return s.native.ExecManagedSupervisor(ctx, box, action, raw)
}
func (s *currentChatColdSource) ControllerParentCredential(context.Context, string) (api.ControllerCredential, error) {
	s.credentials++
	return api.ControllerCredential{}, errors.New("cold HELLO must not lease a credential")
}
func (s *currentChatColdSource) ExecSessionHandoff(_ context.Context, _ string, launch containers.SessionHandoffLaunch, _ containers.SessionInput, out, _ io.Writer) error {
	s.bridge++
	// Only current Access framing/launch is supplied here. The separate owning
	// Podman/S subprocess journey must verify the actual packaged bridge.
	raw := fixtureRaw(map[string]any{"v": 1, "protocol": "wm-team-control/1", "source": "SOURCE bridge boundary"})
	frame := make([]byte, len(raw)+5)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(raw)+1))
	frame[4] = 0x81
	copy(frame[5:], raw)
	_, e := out.Write(frame)
	return e
}
func TestCurrentForemanChatColdOpenThroughAccess(t *testing.T) {
	packetPath := os.Getenv("WARPMETAL_CURRENT_CHAT_PACKET")
	if packetPath == "" {
		t.Skip("explicit current SOURCE packet destination")
	}
	t.Setenv("WARPMETAL_CHILD_COMPLETION_SOURCE", "1")
	runControllerProviderPreExecutionSourceFixtureExport(t, func(j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, published map[string]any) {
		ctx := context.Background()
		now := j.reconciler.now()
		published = publicDeliveryMap(published)
		var app model.WorkspaceApplicationOperation
		publicDeliveryDecode(t, published["application"], &app)
		var envelope qualification.ChildEnvelope[qualification.ControllerPolicy]
		publicDeliveryDecode(t, sourceObject(sourceObject(published["parents"])["orchestrator"])["policy"], &envelope)
		policy := envelope.Payload
		a, n := policy.ApplicationIdentity(), policy.NativeIdentity()
		parent := a.Intent
		derived, e := a.DeriveWM8NativeIdentity()
		if e != nil || model.WorkspaceDigest(derived) != model.WorkspaceDigest(n) || policy.IdentityAssociation.ValidateAccepted(app, policy.ApplicationReference().ApplicationID, policy.ApplicationReference().ReceiptDigest, app.MaterializerDigest, derived) != nil {
			t.Fatal("current SOURCE A7/N6 accepted app boundary", e)
		}
		local, e := j.reconciler.Store.ControllerParent(ctx, parent.ServiceRegistrationID)
		if e != nil || local == nil || local.Report.NativeRegistration == nil {
			t.Fatal(e)
		}
		project, e := j.reconciler.Store.ManagedProject(ctx, parent.Workspace.ProjectID)
		if e != nil || project == nil {
			projects, pe := j.reconciler.Store.ManagedProjects(ctx)
			if pe != nil {
				t.Fatal(pe)
			}
			for i := range projects {
				if projects[i].Report.ProjectID == parent.Workspace.ProjectID {
					v := projects[i]
					project = &v
				}
			}
		}
		if project == nil || project.ServerID != parent.Owner.ServerID || project.Report.RootAttestation != parent.Workspace.RootAttestation {
			t.Fatal("SOURCE current project identity unavailable")
		}
		project.Report.Availability = "available"
		if e = j.reconciler.Store.PutManagedProject(ctx, *project); e != nil {
			t.Fatal(e)
		}
		reg := local.Report.NativeRegistration
		target := model.ForemanChatHandoffV1{FormatVersion: 1, Action: "chat_session", HandoffID: "handoff_current_source_chat", IssuedAt: now, ExpiresAt: now.Add(120 * time.Second), Identity: model.ForemanChatIdentityV1{ServerID: parent.Owner.ServerID, SandboxID: parent.Owner.SandboxID, SandboxGeneration: parent.Owner.SandboxGeneration, Role: "orchestrator", RoleLabel: "foreman", ProjectID: parent.Workspace.ProjectID, WorkspaceEpoch: parent.Workspace.WorkspaceEpoch, ServiceRegistrationID: parent.ServiceRegistrationID, ServiceGeneration: parent.ServiceGeneration, ProfileRevision: parent.Profile.ProfileRevision, InstructionRevision: parent.Instructions.InstructionRevision, RoleBindingID: "wrole_source_chat", RoleBindingRevision: 1}, Source: model.SessionHandoffSourceV1{RegisteredSourceID: reg.RegisteredSourceID, NativeSessionID: reg.NativeSessionID, NativeProjectID: reg.NativeProjectID, NativeLocationDigest: reg.NativeLocationDigest}}
		if e = model.ValidateForemanChatHandoffV1(target, now); e != nil {
			t.Fatal("SOURCE cold owner handoff", e)
		}
		statePath := filepath.Join(project.Anchor, ".warpmetal/opencode/instances", parent.Instance, "state.json")
		if e = os.MkdirAll(filepath.Dir(statePath), 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(statePath, fixtureRaw(map[string]any{"phase": "running", "port": 18445, "instance": parent.Instance, "sessionId": reg.NativeSessionID, "nativeSessionId": reg.NativeSessionID, "nativeProjectId": reg.NativeProjectID, "nativeLocationDigest": reg.NativeLocationDigest, "instructionApplied": true, "profileRevision": parent.Profile.ProfileRevision, "instructionRevision": parent.Instructions.InstructionRevision}), 0600); e != nil {
			t.Fatal(e)
		}
		grant := state.LocalGrant{ID: "grant_current_source_chat", SandboxID: parent.Owner.SandboxID, DesiredState: "active", ObservedState: "applied"}
		if e = j.reconciler.Store.PutGrant(ctx, grant); e != nil {
			t.Fatal(e)
		}
		raw := fixtureRaw(map[string]any{"v": 1, "protocol": "wm-team-control/1", "handoff": target})
		hello := make([]byte, len(raw)+5)
		binary.BigEndian.PutUint32(hello[:4], uint32(len(raw)+1))
		hello[4] = 1
		copy(hello[5:], raw)
		source := &currentChatColdSource{native: native}
		gateway := &access.Gateway{Store: j.reconciler.Store, SessionHandoffEngine: source, ControllerPrepare: source, ControllerCredential: source, HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Now: func() time.Time { return now }, ForemanChatQualification: &containers.ForemanChatQualificationV1{FormatVersion: 1, Tree: d.tree, Key: d.key, PolicyDigest: model.WorkspaceDigest(policy), Broker: filepath.Join(d.root, "unavailable-advisory.sock")}}
		dir, e := os.MkdirTemp("/tmp", "wm-chat-cold-")
		if e != nil {
			t.Fatal(e)
		}
		socket := filepath.Join(dir, "gateway.sock")
		serveCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- gateway.Serve(serveCtx, socket) }()
		var conn net.Conn
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			conn, e = net.DialTimeout("unix", socket, 30*time.Millisecond)
			if e == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if e != nil {
			t.Fatal("SOURCE gateway socket", e)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if e = json.NewEncoder(conn).Encode(map[string]any{"grantId": grant.ID, "command": "warpmetal-team-control", "tty": false, "sessionHandoffChat": target, "sessionHandoffHello": hello}); e != nil {
			t.Fatal(e)
		}
		reader := bufio.NewReader(conn)
		line, e := reader.ReadBytes('\n')
		if e != nil {
			t.Fatal(e)
		}
		var response struct {
			OK    bool
			Error string
		}
		if json.Unmarshal(line, &response) != nil {
			t.Fatal("SOURCE gateway response")
		}
		cancel()
		<-done
		observation := map[string]any{"classification": "SOURCE current accepted app/A7N6/native state/owner consent; actual normal Access Unix HELLO. No successor execution authority or native/ROOT/provider.", "application": app, "policy": envelope, "target": target, "hello": hello, "sourceState": json.RawMessage(fixtureRaw(local.Report)), "response": response, "bridgeLaunches": source.bridge, "coldPreparations": source.preparations, "coldCredentials": source.credentials, "coldPrompts": source.prompts, "providerRequests": 0, "nativeExecutables": 0, "rootRuns": 0}
		d.writeOriginal(t, packetPath, fixtureRaw(observation), 0600)
		if source.preparations != 0 || source.credentials != 0 || source.prompts != 0 {
			t.Fatal("cold HELLO consumed authority", source.preparations, source.credentials, source.prompts)
		}
		if !response.OK || source.bridge != 1 {
			t.Fatalf("current DeepSeek cold-open rejected before fixed bridge: code=%s bridge=%d prep=%d prompt=%d", response.Error, source.bridge, source.preparations, source.prompts)
		}
	})
}
