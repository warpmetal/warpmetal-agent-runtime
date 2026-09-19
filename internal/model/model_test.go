package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func testImageDigest(value string) string {
	return "registry.example/sandbox@sha256:" + strings.Repeat(value, 64)
}

func TestValidateManifestAcceptsFixedTemporarySandbox(t *testing.T) {
	seconds := 900
	manifest := Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: 1,
		ImageDigest:     testImageDigest("a"),
		Capacity:        Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []Sandbox{
			{
				ID:               "sbx_test12345",
				Name:             "reviewer",
				Size:             "small",
				Resources:        Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
				Lifetime:         "temporary",
				ExpiresInSeconds: &seconds,
				DesiredState:     "running",
				Generation:       1,
			},
		},
	}
	if err := ValidateManifest(manifest, "srv_test12345", 0); err != nil {
		t.Fatal(err)
	}
}

func TestValidateManifestRejectsWrongServerOverCapacityAndDuplicateKey(t *testing.T) {
	manifest := Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: 2,
		ImageDigest:     testImageDigest("a"),
		Capacity:        Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10},
		Sandboxes: []Sandbox{
			{
				ID:           "sbx_test12345",
				Name:         "main",
				Resources:    Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20, PIDs: 256},
				Lifetime:     "persistent",
				DesiredState: "running",
				Generation:   1,
			},
		},
	}
	if err := ValidateManifest(manifest, "srv_other12345", 1); err == nil {
		t.Fatal("expected server identity rejection")
	}
	if err := ValidateManifest(manifest, manifest.ServerID, 1); err == nil {
		t.Fatal("expected capacity rejection")
	}
}

func TestValidateManifestRejectsMutableImageReference(t *testing.T) {
	manifest := Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: 1,
		ImageDigest:     "registry.example/sandbox:latest",
		Capacity:        Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10},
	}
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err == nil {
		t.Fatal("expected mutable image reference rejection")
	}
}

func TestValidateManifestRejectsMutablePerSandboxImageReference(t *testing.T) {
	manifest := Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: 1,
		ImageDigest:     testImageDigest("a"),
		Capacity:        Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10},
		Sandboxes: []Sandbox{{
			ID: "sbx_test12345", Name: "main",
			Resources:   Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			ImageDigest: "registry.example/sandbox:latest",
			Lifetime:    "persistent", DesiredState: "running", Generation: 1,
		}},
	}
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err == nil {
		t.Fatal("expected mutable per-sandbox image to be rejected")
	}
}

func TestManifestPreservesSetupOperationsOnTheWire(t *testing.T) {
	payload := []byte(`{
		"serverId":"srv_test12345",
		"desiredRevision":1,
		"imageDigest":"registry.example/sandbox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"capacity":{"cpuMillicores":1500,"memoryMiB":3072,"workspaceDiskGiB":30,"pids":512},
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
			"materializer":{"kind":"archive","artifacts":[]}
		}]
	}`)

	var manifest Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	operations, exists := roundTrip["setupOperations"]
	if !exists || string(operations) == "null" || string(operations) == "[]" {
		t.Fatalf("setupOperations were discarded from the manifest wire contract: %s", encoded)
	}
}

func TestValidateManifestRejectsMoreThanThirtyTwoSetupOperations(t *testing.T) {
	operations := make([]map[string]any, 33)
	for index := range operations {
		operations[index] = map[string]any{
			"id":                fmt.Sprintf("setup-test%03d", index),
			"schemaVersion":     1,
			"sandboxId":         "sbx_test12345",
			"sandboxGeneration": 1,
			"profileId":         "profile-test12345",
			"profileRevision":   1,
			"profileDigest":     "sha256:" + strings.Repeat("b", 64),
			"materializer":      map[string]any{"kind": "archive", "artifacts": []any{}},
		}
	}
	wire := map[string]any{
		"serverId":        "srv_test12345",
		"desiredRevision": 1,
		"imageDigest":     testImageDigest("a"),
		"capacity":        Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30, PIDs: 512},
		"sandboxes":       []Sandbox{},
		"accessGrants":    []AccessGrant{},
		"setupOperations": operations,
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err == nil {
		t.Fatal("expected more than 32 setup operations to be rejected")
	}
}

func TestValidateManifestRejectsMalformedSetupOperation(t *testing.T) {
	sandbox := Sandbox{
		ID:           "sbx_test12345",
		Name:         "main",
		Resources:    Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
		Lifetime:     "persistent",
		DesiredState: "running",
		Generation:   1,
	}
	wire := map[string]any{
		"serverId":        "srv_test12345",
		"desiredRevision": 1,
		"imageDigest":     testImageDigest("a"),
		"capacity":        Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30, PIDs: 512},
		"sandboxes":       []Sandbox{sandbox},
		"accessGrants":    []AccessGrant{},
		"setupOperations": []map[string]any{{
			"id":                "setup-test12345",
			"schemaVersion":     1,
			"sandboxId":         sandbox.ID,
			"sandboxGeneration": sandbox.Generation,
			"profileId":         "profile-test12345",
			"profileRevision":   1,
			"profileDigest":     "sha256:not-a-digest",
			"materializer":      map[string]any{"kind": "archive", "artifacts": []any{}},
		}},
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err == nil {
		t.Fatal("expected a malformed setup operation to be rejected")
	}
}

func npmPackageSetManifest(t *testing.T) Manifest {
	t.Helper()
	payload := []byte(`{
		"serverId":"srv_test12345", "desiredRevision":1,
		"imageDigest":"registry.example/sandbox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"capacity":{"cpuMillicores":1500,"memoryMiB":3072,"workspaceDiskGiB":30,"pids":512},
		"sandboxes":[{"id":"sbx_test12345","name":"main","resources":{"cpuMillicores":500,"memoryMiB":1024,"workspaceDiskGiB":10,"pids":256},"lifetime":"persistent","desiredState":"running","generation":1}],
		"accessGrants":[], "setupOperations":[{
			"id":"setup-test12345", "schemaVersion":1, "sandboxId":"sbx_test12345", "sandboxGeneration":1,
			"profileId":"profile-test12345", "profileRevision":1,
			"profileDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"materializer":{"kind":"npm-package-set","artifacts":[{
				"id":"codex-wrapper", "source":"https://registry.npmjs.org/@openai/codex/-/codex-0.156.0-alpha.3.tgz",
				"sha256":"sha256:ad521f01018cef9b7975c13a6e3092c9bfd3b4ae27867af3d921686cebe92e2e",
				"format":"npm-tgz", "sizeBytes":4911, "packageName":"@openai/codex",
				"packageVersion":"0.156.0-alpha.3", "installAs":"@openai/codex"}], "bins":["codex"]}
		}]
	}`)
	var manifest Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestValidateManifestAcceptsClosedNPMPackageSetSetupOperation(t *testing.T) {
	manifest := npmPackageSetManifest(t)
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err != nil {
		t.Fatalf("valid npm-package-set setup operation was rejected: %v", err)
	}
}

func TestValidateManifestRejectsNPMPackageSetOperationViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"absent bins", func(operation map[string]any) { delete(operation["materializer"].(map[string]any), "bins") }},
		{"tag version", func(operation map[string]any) {
			operation["materializer"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)["packageVersion"] = "latest"
		}},
		{"range version", func(operation map[string]any) {
			operation["materializer"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)["packageVersion"] = "^0.156.0"
		}},
		{"malformed package name", func(operation map[string]any) {
			operation["materializer"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)["packageName"] = "@OpenAI/codex"
		}},
		{"malformed install alias", func(operation map[string]any) {
			operation["materializer"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)["installAs"] = "codex alias"
		}},
		{"duplicate alias", func(operation map[string]any) {
			artifact := operation["materializer"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)
			copy := map[string]any{}
			for k, v := range artifact {
				copy[k] = v
			}
			copy["id"] = "codex-payload"
			operation["materializer"].(map[string]any)["artifacts"] = append(operation["materializer"].(map[string]any)["artifacts"].([]any), copy)
		}},
		{"duplicate bin", func(operation map[string]any) {
			operation["materializer"].(map[string]any)["bins"] = []any{"codex", "codex"}
		}},
		{"aggregate over two gib", func(operation map[string]any) {
			artifact := operation["materializer"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)
			copy := map[string]any{}
			for k, v := range artifact {
				copy[k] = v
			}
			copy["id"] = "codex-payload"
			copy["installAs"] = "@openai/codex-linux-x64"
			copy["sizeBytes"] = int64(2147483648)
			operation["materializer"].(map[string]any)["artifacts"] = append(operation["materializer"].(map[string]any)["artifacts"].([]any), copy)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := npmPackageSetManifest(t)
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatal(err)
			}
			test.mutate(wire["setupOperations"].([]any)[0].(map[string]any))
			payload, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			var mutated Manifest
			if err := json.Unmarshal(payload, &mutated); err != nil {
				t.Fatal(err)
			}
			if err := ValidateManifest(mutated, mutated.ServerID, 0); err == nil {
				t.Fatal("expected invalid npm-package-set operation to be rejected")
			}
		})
	}
}
