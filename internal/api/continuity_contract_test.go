package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

func TestClientConsumesFrozenContinuityManifestFixtureWithoutLosingClosedFields(t *testing.T) {
	fixtureBytes, err := os.ReadFile("testdata/agent-continuity-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"serverId":        "srv_continuity0001",
		"desiredRevision": 1,
		"imageDigest": "registry.example/sandbox@sha256:" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"capacity": map[string]any{
			"cpuMillicores": 1000, "memoryMiB": 2048, "workspaceDiskGiB": 20, "pids": 256,
		},
		"sandboxes": []any{map[string]any{
			"id": "sbx_continuity000000000001", "name": "continuity-worker", "size": "small",
			"resources": map[string]any{
				"cpuMillicores": 500, "memoryMiB": 1024, "workspaceDiskGiB": 10, "pids": 256,
			},
			"lifetime": "persistent", "expiresInSeconds": nil, "startedAt": nil, "expiresAt": nil,
			"desiredState": "running", "generation": 4,
		}},
		"accessGrants":            []any{},
		"setupOperations":         []any{},
		"continuityRegistrations": []json.RawMessage{fixture["registrationManifest"]},
		"continuityOperations":    []json.RawMessage{fixture["operationManifest"]},
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/internal/runtime/manifest" {
			http.Error(writer, "unexpected request", http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(payload)
	}))
	defer server.Close()

	client := Client{Origin: server.URL, NodeToken: "rtn_test", HTTP: server.Client()}
	decoded, err := client.Manifest(context.Background())
	if err != nil {
		t.Fatalf("frozen continuity manifest was rejected: %v", err)
	}
	roundTrip, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(roundTrip, &document); err != nil {
		t.Fatal(err)
	}
	for field, fixtureField := range map[string]string{
		"continuityRegistrations": "registrationManifest",
		"continuityOperations":    "operationManifest",
	} {
		var values []json.RawMessage
		if err := json.Unmarshal(document[field], &values); err != nil || len(values) != 1 {
			t.Fatalf("%s was not preserved as one closed record: %s (%v)", field, document[field], err)
		}
		var got, want any
		if err := json.Unmarshal(values[0], &got); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(fixture[fixtureField], &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s drifted from frozen fixture:\n got %s\nwant %s", field, values[0], fixture[fixtureField])
		}
	}
}
