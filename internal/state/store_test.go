package state

import (
	"context"
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
	grant, err := store.Grant(ctx, "grant_test12345")
	if err != nil || grant == nil || grant.SandboxID != sandbox.ID {
		t.Fatalf("grant was not durable: %#v %v", grant, err)
	}
}
