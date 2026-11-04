package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// SOURCE transport/config journey: the real command parser, normal API client,
// TLS and atomic config writer execute. Only the public host-key observation and
// server response are test suppliers; no registered producer or host is claimed.
func TestRegistrationCommandTLSAndConfig(t *testing.T) {
	for _, selected := range []struct{ name, image string }{
		{"legacy_image_omitted", ""},
		{"candidate_image_transmitted", "sha256:" + strings.Repeat("a", 64)},
	} {
		t.Run(selected.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "runtime.json")
			keys := []model.HostKey{{PublicKey: "ssh-ed25519 c291cmNlLXB1YmxpYy1ob3N0LWtleQ=="}}
			var calls int
			var body map[string]json.RawMessage
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/internal/runtime/register" || r.Header.Get("Authorization") != "Bearer rtb_source_registration" {
					t.Errorf("unexpected registration request method, path or SOURCE bearer")
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("registration body: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"serverId":"srv_source_registration","nodeToken":"rtn_source_registration","expiresAt":"2099-01-01T00:00:00Z"}`)
			}))
			defer server.Close()
			keyReads := 0
			args := []string{"--api", server.URL, "--server", "srv_source_registration", "--config", configPath}
			if selected.image != "" {
				args = append(args, "--image-digest", selected.image)
			}
			err := registerWithInputs(args,
				strings.NewReader("rtb_source_registration\n"), func() ([]model.HostKey, error) { keyReads++; return keys, nil }, server.Client())
			if err != nil {
				t.Fatalf("register command: %v", err)
			}
			wantFields := 3
			if selected.image != "" {
				wantFields++
			}
			if calls != 1 || keyReads != 1 || len(body) != wantFields {
				t.Fatalf("registration changed: HTTP=%d publicKeyReads=%d fields=%d", calls, keyReads, len(body))
			}
			if selected.image == "" && body["imageDigest"] != nil {
				t.Fatal("ordinary registration must omit the image field")
			}
			if selected.image != "" {
				var gotImage string
				if json.Unmarshal(body["imageDigest"], &gotImage) != nil || gotImage != selected.image {
					t.Fatal("selected candidate image digest was not transmitted exactly")
				}
			}
			var gotServer, gotVersion string
			var gotKeys []model.HostKey
			if json.Unmarshal(body["serverId"], &gotServer) != nil || json.Unmarshal(body["supervisorVersion"], &gotVersion) != nil ||
				json.Unmarshal(body["hostKeys"], &gotKeys) != nil || gotServer != "srv_source_registration" || gotVersion != version || !reflect.DeepEqual(gotKeys, keys) {
				t.Fatal("registration public identity changed")
			}
			raw, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			var saved map[string]any
			if json.Unmarshal(raw, &saved) != nil || !reflect.DeepEqual(saved, map[string]any{
				"apiOrigin": server.URL, "serverId": "srv_source_registration", "nodeToken": "rtn_source_registration", "nodeTokenExpiresAt": "2099-01-01T00:00:00Z",
			}) {
				t.Fatal("actual registration response was not retained exactly")
			}
			info, err := os.Stat(configPath)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("registration config must be private")
			}
		})
	}

	for _, kind := range []string{"existing_config", "malformed_config", "symlink_config"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "runtime.json")
			original := []byte(`{"apiOrigin":"https://original.invalid","serverId":"srv_original","nodeToken":"rtn_source_old","qualificationProducer":{"keyId":"source_original"}}`)
			if kind == "malformed_config" {
				original = []byte("{truncated SOURCE config\n")
			}
			retainedPath := configPath
			if kind == "symlink_config" {
				retainedPath = filepath.Join(dir, "original.json")
			}
			if err := os.WriteFile(retainedPath, original, 0640); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink_config" {
				if err := os.Symlink(retainedPath, configPath); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(configPath)
			if err != nil {
				t.Fatal(err)
			}
			calls, keyReads := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"serverId":"srv_source_registration","nodeToken":"rtn_source_registration","expiresAt":"2099-01-01T00:00:00Z"}`)
			}))
			defer server.Close()
			stdin := &registrationCountedInput{reader: strings.NewReader("rtb_source_registration\n")}
			err = registerWithInputs([]string{"--api", server.URL, "--server", "srv_source_registration", "--config", configPath}, stdin,
				func() ([]model.HostKey, error) {
					keyReads++
					return []model.HostKey{{PublicKey: "ssh-ed25519 c291cmNl"}}, nil
				}, server.Client())
			if err == nil || err.Error() != "runtime_registration_config_exists" || stdin.reads != 0 || keyReads != 0 || calls != 0 {
				t.Errorf("existing config did not refuse before external inputs: err=%v stdinReads=%d publicKeyReads=%d HTTP=%d", err, stdin.reads, keyReads, calls)
			}
			after, statErr := os.Lstat(configPath)
			current, readErr := os.ReadFile(retainedPath)
			if statErr != nil || readErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || !bytes.Equal(current, original) {
				t.Error("existing config identity, mode or original bytes changed")
			}
			if kind == "symlink_config" {
				if target, err := os.Readlink(configPath); err != nil || target != retainedPath {
					t.Error("existing config symlink changed")
				}
			}
		})
	}

	t.Run("invalid_image_refused_before_inputs", func(t *testing.T) {
		stdin := &registrationCountedInput{reader: strings.NewReader("rtb_source_registration\n")}
		keys := 0
		err := registerWithInputs([]string{"--server", "srv_source_registration", "--config", filepath.Join(t.TempDir(), "runtime.json"), "--image-digest", "sha256:" + strings.Repeat("A", 64)}, stdin,
			func() ([]model.HostKey, error) { keys++; return nil, nil }, nil)
		if err == nil || err.Error() != "a valid --image-digest is required" || stdin.reads != 0 || keys != 0 {
			t.Fatalf("invalid image reached command inputs: err=%v stdin=%d publicKeys=%d", err, stdin.reads, keys)
		}
	})
}

type registrationCountedInput struct {
	reader *strings.Reader
	reads  int
}

func (r *registrationCountedInput) Read(p []byte) (int, error) { r.reads++; return r.reader.Read(p) }
