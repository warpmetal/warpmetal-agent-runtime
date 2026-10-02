package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPodmanSessionHandoffUsesOnlyFixedPackagedBridge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	hello := []byte{0, 0, 0, 3, 0x01, '{', '}'}
	tail := []byte("following-bridge-frame")
	launch := SessionHandoffLaunch{
		Grant: SessionBridgeGrantV1{
			SchemaVersion: 1, GrantID: "grt_runtime_handoff_1234", ServerID: "srv_handoff",
			SandboxID: "sbx_handoff1234", Generation: 3, Instance: "worker-1",
			ProfileID:          "opencode",
			ProfileDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			HostKeyFingerprint: "SHA256:gV3XbFCV8d8Fqo2V7Ws6yptwLtxWcH5c3u3N2kLbc04",
			Engine:             SessionBridgeEngineV1{Host: "127.0.0.1", Port: 18443},
			AllowedPaths:       []string{"/api"},
			AllowedMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			IssuedAt:           now, ExpiresAt: now.Add(2 * time.Minute),
		},
		HelloFrame: hello,
	}
	var remote bool
	var args []string
	var input []byte
	podman := Podman{runStreamCommand: func(
		_ context.Context,
		gotRemote bool,
		stdin SessionInput,
		_, _ io.Writer,
		gotArgs ...string,
	) error {
		remote = gotRemote
		args = append([]string(nil), gotArgs...)
		var err error
		input, err = io.ReadAll(stdin)
		return err
	}}
	err := podman.ExecSessionHandoff(
		context.Background(), "sbx_handoff1234", launch,
		&eofSessionInput{Reader: strings.NewReader(string(tail))}, io.Discard, io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !remote {
		t.Fatal("handoff bypassed the delegated private Podman service")
	}
	if !bytes.Equal(input, append(append([]byte{}, hello...), tail...)) {
		t.Fatalf("bridge stdin changed: %x", input)
	}
	wantSuffix := []string{
		"warpmetal-sbx_handoff1234", capabilityLauncherPath, "/usr/bin/python3",
		"/usr/local/libexec/warpmetal-agent-teams/warpmetal_team_bridge.py", "helper",
	}
	if len(args) < len(wantSuffix) || !equalStrings(args[len(args)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("handoff did not use the fixed packaged helper: %#v", args)
	}
	joined := strings.Join(args, " ")
	for _, forbidden := range []string{"/bin/sh", "SSH_ORIGINAL_COMMAND"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("handoff argv contains owner/shell input %q: %#v", forbidden, args)
		}
	}
	for _, argument := range args {
		if argument == "-c" || argument == "-lc" {
			t.Fatalf("handoff argv contains shell mode %q: %#v", argument, args)
		}
	}
	var grantArgument string
	for index := range args {
		if args[index] == "--env" && index+1 < len(args) && strings.HasPrefix(args[index+1], "WM_TEAM_BRIDGE_GRANT=") {
			grantArgument = strings.TrimPrefix(args[index+1], "WM_TEAM_BRIDGE_GRANT=")
			break
		}
	}
	if grantArgument == "" {
		t.Fatalf("fixed helper did not receive the host-generated grant: %#v", args)
	}
	var got SessionBridgeGrantV1
	decoder := json.NewDecoder(strings.NewReader(grantArgument))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&got); err != nil || !reflect.DeepEqual(got, launch.Grant) {
		t.Fatalf("host bridge grant changed: got=%+v err=%v", got, err)
	}
}

func TestPodmanSessionHandoffRejectsOversizedHelloBeforeExecution(t *testing.T) {
	called := false
	podman := Podman{runStreamCommand: func(context.Context, bool, SessionInput, io.Writer, io.Writer, ...string) error {
		called = true
		return nil
	}}
	launch := SessionHandoffLaunch{
		Grant:      SessionBridgeGrantV1{SchemaVersion: 1},
		HelloFrame: make([]byte, 64*1024+1),
	}
	err := podman.ExecSessionHandoff(
		context.Background(), "sbx_handoff1234", launch,
		&eofSessionInput{Reader: strings.NewReader("")}, io.Discard, io.Discard,
	)
	if err == nil || called {
		t.Fatalf("oversized HELLO result: err=%v called=%v", err, called)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
