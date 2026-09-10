package state

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func TestStorePersistsTemporaryClockAndGrant(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	seconds := 900
	started := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	expires := started.Add(900 * time.Second)
	sandbox := LocalSandbox{
		ID:                 "sbx_test12345",
		Name:               "reviewer",
		DesiredState:       "running",
		ObservedState:      "running",
		Generation:         1,
		ObservedGeneration: 1,
		Lifetime:           "temporary",
		ExpiresInSeconds:   &seconds,
		StartedAt:          &started,
		ExpiresAt:          &expires,
		Resources:          model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
		ImageDigest:        "sha256:test",
	}
	if err := store.PutSandbox(ctx, sandbox); err != nil {
		t.Fatal(err)
	}
	if err := store.PutGrant(ctx, LocalGrant{
		ID:            "grant_test12345",
		SandboxID:     sandbox.ID,
		SSHPublicKey:  "ssh-ed25519 AAAA",
		DesiredState:  "active",
		ObservedState: "applied",
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Sandbox(ctx, sandbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.ExpiresAt == nil || !loaded.ExpiresAt.Equal(expires) {
		t.Fatalf("expiration was not durable: %#v", loaded)
	}
	if loaded.ObservedState != "running" || loaded.ObservedGeneration != 1 ||
		loaded.ImageDigest != sandbox.ImageDigest {
		t.Fatalf("sandbox state was not durable: %#v", loaded)
	}
	grant, err := store.Grant(ctx, "grant_test12345")
	if err != nil || grant == nil || grant.SandboxID != sandbox.ID {
		t.Fatalf("grant was not durable: %#v %v", grant, err)
	}
}

func TestStoreOpensLegacySandboxRowsWithoutToolColumns(t *testing.T) {
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
  'sbx_test12345', 'main', 'running', 'running', 1, 1,
  'persistent', 500, 1024, 10, 256, 'sha256:test', '2026-09-06T00:00:00Z'
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
	loaded, err := store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.ObservedState != "running" ||
		loaded.ImageDigest != "sha256:test" {
		t.Fatalf("legacy sandbox state was not loaded: %#v", loaded)
	}
}
