package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

func foremanChatProjection() *model.ControllerRoleProjection {
	return &model.ControllerRoleProjection{
		NativeAgentID:   "warpmetal-controller-orchestrator",
		SystemDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ApprovedProfile: model.ApprovedExpertiseProfile{ProfileID: "profile", ProfileRevision: 1, ProfileDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", BundleDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		ModelSelection: &model.WorkspaceModelSelection{
			Authority:         model.CellPreparedAuthorityV3{ProviderID: "openai", ModelID: ForemanChatAdvisoryModelID, AuthMode: "api_key"},
			CredentialBinding: &model.CellCredentialBindingV3{ConnectionID: "conn_runtime_chat", ConnectionRevision: 1, ProviderID: "openai", AuthMode: "api_key"},
		},
		ToolsDisabled: true, MCPDisabled: true,
	}
}

func foremanChatGrant(now time.Time) SessionBridgeGrantV1 {
	projection := foremanChatProjection()
	return SessionBridgeGrantV1{
		SchemaVersion: 1, GrantID: "grt_runtime_chat_1234", ServerID: "srv_handoff",
		SandboxID: "sbx_handoff1234", Generation: 3, Instance: "foreman-1",
		ProfileID:          "opencode",
		ProfileDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		HostKeyFingerprint: "SHA256:gV3XbFCV8d8Fqo2V7Ws6yptwLtxWcH5c3u3N2kLbc04",
		Engine:             SessionBridgeEngineV1{Host: "127.0.0.1", Port: 18443},
		AllowedPaths:       []string{"/api"},
		AllowedMethods:     []string{"GET", "POST"},
		IssuedAt:           now, ExpiresAt: now.Add(2 * time.Minute),
		Capability: ForemanChatCapability,
		Chat: &SessionBridgeChatV1{
			Protocol: ForemanChatProtocol, MaxQuestionBytes: ForemanChatQuestionBytes,
			MaxReplyBytes: ForemanChatReplyBytes, MaxQuestionsPerMinute: ForemanChatQuestionsPerMinute,
			MaxConcurrent: ForemanChatMaxConcurrent, HandoffID: "handoff_runtime_chat_1234",
			NativeSessionID: "ses_runtime_chat_1234", ServiceRegistrationID: "service_runtime_chat",
			ServiceGeneration: 2, ProjectID: "project_runtime_chat", WorkspaceEpoch: "epoch_runtime_chat",
			Advisory: &ForemanChatAdvisoryV1{
				FormatVersion: 1, Capability: ForemanChatAdvisoryCapability,
				AdmissionID: "fca_0123456789abcdef01234567", ServerID: "srv_handoff",
				SandboxID: "sbx_handoff1234", SandboxGeneration: 3, Instance: "foreman-1",
				NativeSessionID: "ses_runtime_chat_1234", ServiceRegistrationID: "service_runtime_chat",
				ServiceGeneration: 2, Role: "orchestrator", RoleBindingID: "wrole_runtime_chat_1",
				HandoffID: "handoff_runtime_chat_1234", IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute),
				Projection: projection, RoleAgentDigest: model.WorkspaceDigest(*projection),
			},
			Qualification: &ForemanChatQualificationV1{
				FormatVersion: ForemanChatQualificationFormat, Tree: "/etc/warpmetal/qualification",
				Key:          "/etc/warpmetal/qualification-public-key.pem",
				PolicyDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				Broker:       "/run/warpmetal/qualification-admission.sock",
			},
		},
	}
}

func TestPodmanForemanChatUsesTheSameFixedPackagedBridge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	hello := []byte{0, 0, 0, 3, 0x01, '{', '}'}
	launch := SessionHandoffLaunch{Grant: foremanChatGrant(now), HelloFrame: hello}
	var args []string
	var input []byte
	podman := Podman{runStreamCommand: func(
		_ context.Context, _ bool, stdin SessionInput, _, _ io.Writer, gotArgs ...string,
	) error {
		args = append([]string(nil), gotArgs...)
		var err error
		input, err = io.ReadAll(stdin)
		return err
	}}
	if err := podman.ExecSessionHandoff(
		context.Background(), "sbx_handoff1234", launch,
		&eofSessionInput{Reader: strings.NewReader("question-frames")}, io.Discard, io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, append(append([]byte{}, hello...), []byte("question-frames")...)) {
		t.Fatalf("chat bridge stdin changed: %x", input)
	}
	wantSuffix := []string{
		"warpmetal-sbx_handoff1234", capabilityLauncherPath, "/usr/bin/python3",
		"/usr/local/libexec/warpmetal-agent-teams/warpmetal_team_bridge.py", "helper",
	}
	if len(args) < len(wantSuffix) || !equalStrings(args[len(args)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("chat did not use the fixed packaged helper: %#v", args)
	}
	var grantArgument string
	for index := range args {
		if args[index] == "--env" && index+1 < len(args) && strings.HasPrefix(args[index+1], "WM_TEAM_BRIDGE_GRANT=") {
			grantArgument = strings.TrimPrefix(args[index+1], "WM_TEAM_BRIDGE_GRANT=")
		}
	}
	var got SessionBridgeGrantV1
	decoder := json.NewDecoder(strings.NewReader(grantArgument))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Capability != ForemanChatCapability || got.Chat == nil ||
		got.Chat.NativeSessionID != "ses_runtime_chat_1234" ||
		got.Chat.MaxReplyBytes != ForemanChatReplyBytes {
		t.Fatalf("host chat grant changed: %+v", got)
	}
}

func TestPodmanForemanChatRejectsWidenedOrInconsistentPolicyBeforeExecution(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for name, mutate := range map[string]func(*SessionBridgeGrantV1){
		"foreign_capability": func(grant *SessionBridgeGrantV1) { grant.Capability = "shell" },
		"missing_chat":       func(grant *SessionBridgeGrantV1) { grant.Chat = nil },
		"widened_reply": func(grant *SessionBridgeGrantV1) {
			grant.Chat.MaxReplyBytes = 8 * 1024 * 1024
		},
		"widened_question": func(grant *SessionBridgeGrantV1) {
			grant.Chat.MaxQuestionBytes = 1024 * 1024
		},
		"widened_rate": func(grant *SessionBridgeGrantV1) {
			grant.Chat.MaxQuestionsPerMinute = 600
		},
		"widened_concurrency": func(grant *SessionBridgeGrantV1) { grant.Chat.MaxConcurrent = 8 },
		"mutation_methods": func(grant *SessionBridgeGrantV1) {
			grant.AllowedMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
		},
		"foreign_protocol": func(grant *SessionBridgeGrantV1) { grant.Chat.Protocol = "wm-team-control/2" },
		"missing_session":  func(grant *SessionBridgeGrantV1) { grant.Chat.NativeSessionID = "" },
		"missing_advisory": func(grant *SessionBridgeGrantV1) { grant.Chat.Advisory = nil },
		"foreign_advisory_session": func(grant *SessionBridgeGrantV1) {
			grant.Chat.Advisory.NativeSessionID = "ses_other_chat_1234"
		},
		"widened_advisory": func(grant *SessionBridgeGrantV1) {
			grant.Chat.Advisory.Capability = "foreman_chat_control"
		},
	} {
		t.Run(name, func(t *testing.T) {
			grant := foremanChatGrant(now)
			mutate(&grant)
			called := false
			podman := Podman{runStreamCommand: func(context.Context, bool, SessionInput, io.Writer, io.Writer, ...string) error {
				called = true
				return nil
			}}
			err := podman.ExecSessionHandoff(
				context.Background(), "sbx_handoff1234",
				SessionHandoffLaunch{Grant: grant, HelloFrame: []byte{0, 0, 0, 3, 0x01, '{', '}'}},
				&eofSessionInput{Reader: strings.NewReader("")}, io.Discard, io.Discard,
			)
			if err == nil || called {
				t.Fatalf("widened chat grant accepted: err=%v called=%v", err, called)
			}
		})
	}
}

func TestLegacySessionGrantOmitsTheChatCapabilityBytes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	grant := SessionBridgeGrantV1{
		SchemaVersion: 1, GrantID: "grt_runtime_handoff_1234", ServerID: "srv_handoff",
		SandboxID: "sbx_handoff1234", Generation: 3, Instance: "worker-1",
		ProfileID:          "opencode",
		ProfileDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		HostKeyFingerprint: "SHA256:gV3XbFCV8d8Fqo2V7Ws6yptwLtxWcH5c3u3N2kLbc04",
		Engine:             SessionBridgeEngineV1{Host: "127.0.0.1", Port: 18443},
		AllowedPaths:       []string{"/api"},
		AllowedMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		IssuedAt:           now, ExpiresAt: now.Add(2 * time.Minute),
	}
	encoded, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"capability", "chat"} {
		if bytes.Contains(encoded, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("legacy grant gained the %q field: %s", forbidden, encoded)
		}
	}
}

func TestForemanChatQualificationRefusesUnalignedProjectionAndMissingTreeConfig(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for name, mutate := range map[string]func(*SessionBridgeGrantV1){
		"unaligned_model": func(grant *SessionBridgeGrantV1) {
			grant.Chat.Advisory.Projection.ModelSelection.Authority.ModelID = "gpt-4o-mini"
			grant.Chat.Advisory.RoleAgentDigest = model.WorkspaceDigest(*grant.Chat.Advisory.Projection)
		},
		"inconsistent_digest": func(grant *SessionBridgeGrantV1) {
			grant.Chat.Advisory.RoleAgentDigest = "sha256:" + strings.Repeat("e", 64)
		},
		"missing_qualification": func(grant *SessionBridgeGrantV1) { grant.Chat.Qualification = nil },
		"key_inside_tree": func(grant *SessionBridgeGrantV1) {
			grant.Chat.Qualification.Key = grant.Chat.Qualification.Tree + "/key.pem"
		},
		"relative_broker": func(grant *SessionBridgeGrantV1) { grant.Chat.Qualification.Broker = "broker.sock" },
		"widened_policy_digest": func(grant *SessionBridgeGrantV1) {
			grant.Chat.Qualification.PolicyDigest = "sha256:xyz"
		},
	} {
		t.Run(name, func(t *testing.T) {
			grant := foremanChatGrant(now)
			mutate(&grant)
			launch := SessionHandoffLaunch{Grant: grant, HelloFrame: []byte{0, 0, 0, 3, 0x01, '{', '}'}}
			podman := Podman{runStreamCommand: func(context.Context, bool, SessionInput, io.Writer, io.Writer, ...string) error {
				t.Fatal("an unaligned or unconfigured Foreman chat reached container execution")
				return nil
			}}
			if err := podman.ExecSessionHandoff(context.Background(), grant.SandboxID, launch,
				&eofSessionInput{Reader: strings.NewReader("")}, io.Discard, io.Discard); err == nil {
				t.Fatal("unaligned Foreman chat launch was accepted")
			}
		})
	}
}

func TestForemanChatQualificationEnvIsClosedAndOptional(t *testing.T) {
	if value, err := ForemanChatQualificationFromEnv(""); err != nil || value != nil {
		t.Fatalf("empty qualification env changed: %+v %v", value, err)
	}
	valid := `{"formatVersion":1,"tree":"/etc/warpmetal/qualification","key":"/etc/warpmetal/qualification-public-key.pem","policyDigest":"sha256:` + strings.Repeat("a", 64) + `","broker":"/run/warpmetal/qualification-admission.sock"}`
	if value, err := ForemanChatQualificationFromEnv(valid); err != nil || value == nil || value.FormatVersion != 1 {
		t.Fatalf("valid qualification env refused: %+v %v", value, err)
	}
	for _, raw := range []string{
		`{"formatVersion":1}`,
		`{"formatVersion":1,"tree":"/etc/warpmetal/qualification","key":"/etc/warpmetal/qualification-public-key.pem","policyDigest":"sha256:` + strings.Repeat("a", 64) + `","broker":"/run/warpmetal/broker.sock","extra":true}`,
	} {
		if _, err := ForemanChatQualificationFromEnv(raw); err == nil {
			t.Fatalf("invalid qualification env accepted: %s", raw)
		}
	}
}

// Extends the recovered fixed-launch journey with the SAME fresh current
// accepted app/A7-N6 originals emitted by the public Access cold-open journey.
// The host transport callback is SOURCE; no container/SSH/native process runs.
func TestPodmanCurrentForemanColdOpenUsesExactIdentity(t *testing.T) {
	path := os.Getenv("WARPMETAL_CURRENT_CHAT_PACKET")
	if path == "" {
		t.Skip("current SOURCE cold-open originals required")
	}
	var packet struct {
		Application model.WorkspaceApplicationOperation
		Policy      qualification.ChildEnvelope[qualification.ControllerPolicy]
		Target      model.ForemanChatHandoffV1
		Hello       []byte
	}
	raw, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(raw, &packet) != nil {
		t.Fatal("current SOURCE packet", e)
	}
	p := packet.Policy.Payload
	a, n := p.ApplicationIdentity(), p.NativeIdentity()
	derived, e := a.DeriveWM8NativeIdentity()
	if e != nil || model.WorkspaceDigest(n) != model.WorkspaceDigest(derived) || p.IdentityAssociation.ValidateAccepted(packet.Application, p.ApplicationReference().ApplicationID, p.ApplicationReference().ReceiptDigest, packet.Application.MaterializerDigest, derived) != nil {
		t.Fatal("current A7/N6 source join", e)
	}
	target := packet.Target
	grant := foremanChatGrant(target.IssuedAt)
	grant.ServerID = target.Identity.ServerID
	grant.SandboxID = target.Identity.SandboxID
	grant.Generation = target.Identity.SandboxGeneration
	grant.Instance = a.Intent.Instance
	grant.ProfileDigest = a.Intent.Profile.ProfileDigest
	grant.ExpiresAt = target.ExpiresAt
	chat := grant.Chat
	chat.HandoffID = target.HandoffID
	chat.NativeSessionID = target.Source.NativeSessionID
	chat.ServiceRegistrationID = target.Identity.ServiceRegistrationID
	chat.ServiceGeneration = target.Identity.ServiceGeneration
	chat.ProjectID = target.Identity.ProjectID
	chat.WorkspaceEpoch = target.Identity.WorkspaceEpoch
	chat.Qualification.PolicyDigest = model.WorkspaceDigest(p)
	advisory := chat.Advisory
	advisory.ServerID = grant.ServerID
	advisory.SandboxID = grant.SandboxID
	advisory.SandboxGeneration = grant.Generation
	advisory.Instance = grant.Instance
	advisory.NativeSessionID = chat.NativeSessionID
	advisory.ServiceRegistrationID = chat.ServiceRegistrationID
	advisory.ServiceGeneration = chat.ServiceGeneration
	advisory.RoleBindingID = target.Identity.RoleBindingID
	advisory.HandoffID = target.HandoffID
	advisory.ExpiresAt = target.ExpiresAt
	advisory.Projection = &n.Projection
	advisory.RoleAgentDigest = model.WorkspaceDigest(n.Projection)
	calls := 0
	podman := Podman{runStreamCommand: func(_ context.Context, _ bool, input SessionInput, _, _ io.Writer, args ...string) error {
		calls++
		got, e := io.ReadAll(input)
		if e != nil || !bytes.Equal(got, packet.Hello) {
			t.Fatal("cold framing changed", e)
		}
		return nil
	}}
	err := podman.ExecSessionHandoff(context.Background(), grant.SandboxID, SessionHandoffLaunch{Grant: grant, HelloFrame: packet.Hello}, &eofSessionInput{Reader: strings.NewReader("")}, io.Discard, io.Discard)
	out, _ := json.Marshal(map[string]any{"classification": "same current SOURCE A7/N6 originals, actual fixed Podman launch validator, stream transport detached; no prep/prompt/provider", "error": func() any {
		if err != nil {
			return err.Error()
		}
		return nil
	}(), "launches": calls, "coldPreparations": 0, "coldPrompts": 0, "providerRequests": 0})
	if e = os.WriteFile(path+".podman.json", append(out, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	if err != nil || calls != 1 {
		t.Fatalf("current DeepSeek cold-open refused by fixed Podman launch: error=%v calls=%d", err, calls)
	}
}
