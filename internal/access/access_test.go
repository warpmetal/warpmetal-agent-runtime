package access

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

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
}
