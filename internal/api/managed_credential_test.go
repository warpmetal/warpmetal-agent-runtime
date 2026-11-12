package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// TestClientManagedServiceCredentialUsesClosedRoute pins the exact protected
// managed-credential request the Runtime sends for a DeepSeek managed service:
// the same node-auth/request helper as the cell credential, one closed body
// field, and the complete account-connection identity in the result.
func TestClientManagedServiceCredentialUsesClosedRoute(t *testing.T) {
	var method, path, authorization string
	var body map[string]string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		method, path, authorization = request.Method, request.URL.Path, request.Header.Get("Authorization")
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("managed credential request body = %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"credentialId":"cred_managed0001","apiKey":"sk-managed-000000000000","connectionId":"connection_managed0001","connectionRevision":4,"providerId":"deepseek","modelId":"deepseek-flash","authMode":"api_key","keyFingerprint":"sha256:keyfingerprint"}`))
	}))
	defer server.Close()

	client := Client{Origin: server.URL, NodeToken: "rtn_credential", HTTP: server.Client()}
	result, err := client.ManagedServiceCredential(context.Background(), "service_managed0001")
	if err != nil {
		t.Fatalf("ManagedServiceCredential() error = %v", err)
	}
	if method != http.MethodPost || path != "/internal/runtime/managed-credential" {
		t.Fatalf("managed credential route = %s %s", method, path)
	}
	if authorization != "Bearer rtn_credential" {
		t.Fatalf("managed credential authorization = %q", authorization)
	}
	if !reflect.DeepEqual(body, map[string]string{"serviceRegistrationId": "service_managed0001"}) {
		t.Fatalf("managed credential request body = %#v", body)
	}
	want := ManagedCredentialResult{
		CredentialID: "cred_managed0001", APIKey: "sk-managed-000000000000",
		ConnectionID: "connection_managed0001", ConnectionRevision: 4,
		ProviderID: "deepseek", ModelID: "deepseek-flash", AuthMode: "api_key",
		KeyFingerprint: "sha256:keyfingerprint",
	}
	if result != want {
		t.Fatalf("managed credential result = %#v", result)
	}
}

// TestClientManagedServiceCredentialSurfacesMissingProviderConnection proves
// the documented 404 provider_credential_missing response remains a typed
// control-plane error the reconciler maps to its stable service failure code.
func TestClientManagedServiceCredentialSurfacesMissingProviderConnection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusNotFound)
		_, _ = writer.Write([]byte(`{"error":{"code":"provider_credential_missing"}}`))
	}))
	defer server.Close()

	client := Client{Origin: server.URL, NodeToken: "rtn_credential", HTTP: server.Client()}
	_, err := client.ManagedServiceCredential(context.Background(), "service_managed0001")
	var response *ResponseError
	if !errors.As(err, &response) || response.Status != http.StatusNotFound || response.Code != "provider_credential_missing" {
		t.Fatalf("managed credential missing connection error = %#v", err)
	}
	if ErrorCode(err) != "provider_credential_missing" {
		t.Fatalf("managed credential error code = %q", ErrorCode(err))
	}
}

// TestClientManagedServiceCredentialRefusesIncompleteIdentity proves a response
// without the immutable connection lease identity is never forwarded to the
// supervisor, so a partial body cannot write an unbound credential file.
func TestClientManagedServiceCredentialRefusesIncompleteIdentity(t *testing.T) {
	for name, payload := range map[string]string{
		"no credential":          `{"apiKey":"sk-managed-000000000000","connectionId":"connection_managed0001","connectionRevision":4}`,
		"no key":                 `{"credentialId":"cred_managed0001","connectionId":"connection_managed0001","connectionRevision":4}`,
		"no connection":          `{"credentialId":"cred_managed0001","apiKey":"sk-managed-000000000000","connectionRevision":4}`,
		"no connection revision": `{"credentialId":"cred_managed0001","apiKey":"sk-managed-000000000000","connectionId":"connection_managed0001"}`,
	} {
		name, payload := name, payload
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(payload))
			}))
			defer server.Close()
			client := Client{Origin: server.URL, NodeToken: "rtn_credential", HTTP: server.Client()}
			if _, err := client.ManagedServiceCredential(context.Background(), "service_managed0001"); err == nil {
				t.Fatal("incomplete managed credential response was accepted")
			}
		})
	}
}
