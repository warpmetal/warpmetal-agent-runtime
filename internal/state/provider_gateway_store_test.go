package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func providerGatewayStoreSandbox(requirements []model.ProviderGatewayRequirement) LocalSandbox {
	return LocalSandbox{
		ID:                 "sbx_test12345",
		Name:               "worker",
		DesiredState:       "running",
		ObservedState:      "running",
		Generation:         1,
		ObservedGeneration: 1,
		Lifetime:           "persistent",
		Resources:          model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
		ImageDigest:        "sha256:test",
		ProviderGateways:   requirements,
	}
}

func providerGatewayStoreRequirements() []model.ProviderGatewayRequirement {
	return []model.ProviderGatewayRequirement{
		{
			RunID:        "run_github_0001",
			CredentialID: "conn_0123456789abcdefghijkl",
			ProviderID:   "github",
			Tools: []model.ProviderGatewayTool{{
				Name:        "list_repositories",
				Description: "List repositories.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"owner":{"type":"string"}}}`),
			}},
		},
		{
			RunID:        "run_google_0002",
			CredentialID: "conn_zyxwvutsrqponmlkjihg",
			ProviderID:   "google",
			ConnectionID: "conn_explicit_connection",
			Tools: []model.ProviderGatewayTool{{
				Name:        "read_document",
				InputSchema: json.RawMessage(`{"type":"object"}`),
			}},
		},
	}
}

func TestStoreRoundTripsProviderGatewayRequirements(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.PutSandbox(ctx, providerGatewayStoreSandbox(nil)); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Sandbox(ctx, "sbx_test12345")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.ProviderGateways != nil {
		t.Fatalf("sandbox without provider gateways loaded as non-empty: %#v", loaded)
	}
	var stored string
	if err := store.db.QueryRowContext(
		ctx, `SELECT provider_gateways FROM sandboxes WHERE id = ?`, "sbx_test12345",
	).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("no-requirement row stored %q, want empty string", stored)
	}

	requirements := providerGatewayStoreRequirements()
	if err := store.PutSandbox(ctx, providerGatewayStoreSandbox(requirements)); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Sandbox(ctx, "sbx_test12345")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || !reflect.DeepEqual(loaded.ProviderGateways, requirements) {
		t.Fatalf("provider gateways did not round-trip:\n got %#v\nwant %#v", loaded, requirements)
	}
	values, err := store.Sandboxes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || !reflect.DeepEqual(values[0].ProviderGateways, requirements) {
		t.Fatalf("Sandboxes lost provider gateways: %#v", values)
	}
	if err := store.db.QueryRowContext(
		ctx, `SELECT provider_gateways FROM sandboxes WHERE id = ?`, "sbx_test12345",
	).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var decoded []model.ProviderGatewayRequirement
	if err := json.Unmarshal([]byte(stored), &decoded); err != nil || !reflect.DeepEqual(decoded, requirements) {
		t.Fatalf("stored provider gateways column is not the requirement JSON: %q (%v)", stored, err)
	}

	// Clearing the requirements is a real removal, and the empty value means
	// none on the next read.
	if err := store.PutSandbox(ctx, providerGatewayStoreSandbox(nil)); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Sandbox(ctx, "sbx_test12345")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.ProviderGateways != nil {
		t.Fatalf("cleared provider gateways were not removed: %#v", loaded)
	}
}

func TestStoreUpgradesLegacySandboxAndPersistsProviderGateways(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`CREATE TABLE sandboxes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  desired_state TEXT NOT NULL,
  observed_state TEXT NOT NULL,
  generation INTEGER NOT NULL,
  observed_generation INTEGER NOT NULL,
  lifetime TEXT NOT NULL,
  expires_in_seconds INTEGER,
  started_at TEXT,
  expires_at TEXT,
  cpu_millicores INTEGER NOT NULL,
  memory_mib INTEGER NOT NULL,
  workspace_disk_gib INTEGER NOT NULL,
  pids_limit INTEGER NOT NULL,
  image_digest TEXT NOT NULL,
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
INSERT INTO sandboxes(
  id, name, desired_state, observed_state, generation, observed_generation,
  lifetime, cpu_millicores, memory_mib, workspace_disk_gib, pids_limit,
  image_digest, updated_at
) VALUES(
  'sbx_legacy0001', 'main', 'running', 'running', 1, 1,
  'persistent', 500, 1024, 10, 256, 'sha256:test', '` + time.Now().UTC().Format(time.RFC3339Nano) + `'
);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	loaded, err := store.Sandbox(ctx, "sbx_legacy0001")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.ProviderGateways != nil {
		t.Fatalf("legacy sandbox row did not upgrade to empty provider gateways: %#v", loaded)
	}
	upgraded := providerGatewayStoreSandbox(providerGatewayStoreRequirements())
	upgraded.ID = "sbx_legacy0001"
	if err := store.PutSandbox(ctx, upgraded); err != nil {
		t.Fatalf("upgraded database cannot persist provider gateways: %v", err)
	}
	loaded, err = store.Sandbox(ctx, "sbx_legacy0001")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || !reflect.DeepEqual(loaded.ProviderGateways, upgraded.ProviderGateways) {
		t.Fatalf("upgraded database lost provider gateways: %#v", loaded)
	}
}

func TestStoreRejectsInvalidProviderGateways(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	invalid := providerGatewayStoreRequirements()
	invalid[0].RunID = "../escape"
	sandbox := providerGatewayStoreSandbox(invalid)
	if err := store.PutSandbox(ctx, sandbox); err == nil {
		t.Fatal("invalid provider gateways were persisted")
	}
	if loaded, err := store.Sandbox(ctx, sandbox.ID); err != nil || loaded != nil {
		t.Fatalf("failed insert left state behind: %#v %v", loaded, err)
	}
}

func TestStoreFailsClosedOnCorruptProviderGatewayColumn(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.PutSandbox(ctx, providerGatewayStoreSandbox(providerGatewayStoreRequirements())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(
		ctx, `UPDATE sandboxes SET provider_gateways = '{"not":"a list"}' WHERE id = ?`, "sbx_test12345",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Sandbox(ctx, "sbx_test12345"); err == nil {
		t.Fatal("corrupt stored provider gateways were silently accepted")
	}
	if _, err := store.db.ExecContext(
		ctx, `UPDATE sandboxes SET provider_gateways = '[{"runId":"../escape"}]' WHERE id = ?`, "sbx_test12345",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Sandbox(ctx, "sbx_test12345"); err == nil {
		t.Fatal("stored provider gateways that violate the manifest contract were accepted")
	}
}
