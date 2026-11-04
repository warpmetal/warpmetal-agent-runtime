package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func agentKitFixtureRecord() model.AgentKitMaterialization {
	return model.AgentKitMaterialization{
		FormatVersion:                model.AgentKitMaterializationFormatVersion,
		MaterializationID:            "akm_" + strings.Repeat("a", 32),
		ApplicationOperationID:       "wfapp_store_test",
		SandboxID:                    "sbx_store_test0001",
		SandboxGeneration:            1,
		ConfigurationID:              "cfg_store_test",
		ConfigurationRevision:        3,
		ConfigurationDigest:          "sha256:" + strings.Repeat("b", 64),
		KitDigest:                    "sha256:" + strings.Repeat("c", 64),
		AdoptionID:                   "WP211A-MAT-ADOPT-1",
		Venue:                        "TEST-wp211a-installed-a",
		ClosureDigest:                "sha256:" + strings.Repeat("d", 64),
		EnvelopeDigest:               "sha256:" + strings.Repeat("e", 64),
		MaterializationReceiptDigest: "sha256:" + strings.Repeat("f", 64),
		InstructionDigest:            "sha256:" + strings.Repeat("1", 64),
		SkillContentDigests:          map[string]string{"warpmetal-agent-sandbox": "sha256:" + strings.Repeat("2", 64)},
		EnvelopeJSON:                 json.RawMessage(`{"schemaVersion":1,"command":"materialize-agent-kit","status":"ready","ready":true}`),
		VerifiedAt:                   "2026-10-26T18:00:00Z",
	}
}

func TestAgentKitMaterializationStoreIsIdempotentAndImmutable(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	ctx := context.Background()
	record := agentKitFixtureRecord()
	created, err := store.PutAgentKitMaterialization(ctx, record)
	if err != nil || !created {
		t.Fatalf("first put: created=%t err=%v", created, err)
	}
	retained, err := store.AgentKitMaterialization(ctx, record.MaterializationID, record.SandboxID, record.SandboxGeneration)
	if err != nil || retained == nil {
		t.Fatalf("read retained: %v", err)
	}
	if retained.EnvelopeDigest != record.EnvelopeDigest || retained.InstructionDigest != record.InstructionDigest ||
		retained.SkillContentDigests["warpmetal-agent-sandbox"] != record.SkillContentDigests["warpmetal-agent-sandbox"] ||
		string(retained.EnvelopeJSON) != string(record.EnvelopeJSON) {
		t.Fatalf("retained record drifted: %+v", retained)
	}
	// Same record retry: no duplicate row, reports not-created.
	created, err = store.PutAgentKitMaterialization(ctx, record)
	if err != nil || created {
		t.Fatalf("retry put: created=%t err=%v", created, err)
	}
	// A different verified receipt with the same identity fails closed.
	conflicted := record
	conflicted.EnvelopeDigest = "sha256:" + strings.Repeat("9", 64)
	if _, err := store.PutAgentKitMaterialization(ctx, conflicted); err != ErrAgentKitMaterializationConflict {
		t.Fatalf("conflict must fail closed, got %v", err)
	}
	// Invalid records are refused before storage.
	invalid := record
	invalid.MaterializationID = "not-an-id"
	if _, err := store.PutAgentKitMaterialization(ctx, invalid); err == nil {
		t.Fatal("invalid record must be refused")
	}
	if missing, err := store.AgentKitMaterialization(ctx, "akm_"+strings.Repeat("0", 32), record.SandboxID, record.SandboxGeneration); err != nil || missing != nil {
		t.Fatalf("unknown id must be nil,nil: %v %v", missing, err)
	}
}

// TestAgentKitMaterializationIsWorkspaceScoped proves the multi-workspace fix:
// two cells on one node that share one account configuration/kit (hence the
// same deterministic materialization identity) keep separate verified rows and
// can never read each other's retained envelope. It also proves restart safety
// and continued same-workspace idempotency.
func TestAgentKitMaterializationIsWorkspaceScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	ctx := context.Background()
	first := agentKitFixtureRecord()
	second := first
	second.SandboxID = "sbx_store_test0002"
	second.ApplicationOperationID = "wfapp_store_test_2"
	// Same materialization identity + same configuration/kit is the collision
	// case: distinct rows are keyed by workspace.
	created, err := store.PutAgentKitMaterialization(ctx, first)
	if err != nil || !created {
		t.Fatalf("first put: created=%t err=%v", created, err)
	}
	created, err = store.PutAgentKitMaterialization(ctx, second)
	if err != nil || !created {
		t.Fatalf("second workspace put: created=%t err=%v", created, err)
	}
	for _, record := range []model.AgentKitMaterialization{first, second} {
		retained, err := store.AgentKitMaterialization(ctx, record.MaterializationID, record.SandboxID, record.SandboxGeneration)
		if err != nil || retained == nil || retained.SandboxID != record.SandboxID || retained.ApplicationOperationID != record.ApplicationOperationID {
			t.Fatalf("workspace-scoped read %s: %#v %v", record.SandboxID, retained, err)
		}
	}
	// A third workspace with the same identity has no retained evidence.
	if missing, err := store.AgentKitMaterialization(ctx, first.MaterializationID, "sbx_store_test0003", 1); err != nil || missing != nil {
		t.Fatalf("unrelated workspace must be nil,nil: %v %v", missing, err)
	}
	// Same-workspace retry remains idempotent after a restart.
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if created, err := reopened.PutAgentKitMaterialization(ctx, first); err != nil || created {
		t.Fatalf("idempotent retry after restart: created=%t err=%v", created, err)
	}
	all, err := reopened.AgentKitMaterializations(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("retained rows after restart: %d %v", len(all), err)
	}
}

// TestOpenMigratesLegacySingleKeyAgentKitMaterializations proves the additive
// upgrade: a legacy table with the single-column primary key is rebuilt in place,
// every row is preserved under its own sandbox/generation, and a second
// workspace can then persist the same materialization identity.
func TestOpenMigratesLegacySingleKeyAgentKitMaterializations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	const legacy = `CREATE TABLE agent_kit_materializations (
  materialization_id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL,
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK(sandbox_generation > 0),
  configuration_id TEXT NOT NULL,
  configuration_revision INTEGER NOT NULL CHECK(configuration_revision > 0),
  configuration_digest TEXT NOT NULL,
  kit_digest TEXT NOT NULL,
  adoption_id TEXT NOT NULL,
  venue TEXT NOT NULL,
  closure_digest TEXT NOT NULL,
  envelope_digest TEXT NOT NULL,
  receipt_digest TEXT NOT NULL,
  instruction_digest TEXT NOT NULL,
  skill_content_digests_json BLOB NOT NULL,
  envelope_json BLOB NOT NULL,
  verified_at TEXT NOT NULL
)`
	if _, err := raw.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	legacyRecord := agentKitFixtureRecord()
	source, _ := json.Marshal(legacyRecord.EnvelopeJSON)
	_ = source
	if _, err := raw.Exec(`INSERT INTO agent_kit_materializations(
materialization_id,operation_id,sandbox_id,sandbox_generation,configuration_id,configuration_revision,
configuration_digest,kit_digest,adoption_id,venue,closure_digest,envelope_digest,receipt_digest,
instruction_digest,skill_content_digests_json,envelope_json,verified_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		legacyRecord.MaterializationID, legacyRecord.ApplicationOperationID, legacyRecord.SandboxID,
		legacyRecord.SandboxGeneration, legacyRecord.ConfigurationID, legacyRecord.ConfigurationRevision,
		legacyRecord.ConfigurationDigest, legacyRecord.KitDigest, legacyRecord.AdoptionID, legacyRecord.Venue,
		legacyRecord.ClosureDigest, legacyRecord.EnvelopeDigest, legacyRecord.MaterializationReceiptDigest,
		legacyRecord.InstructionDigest, []byte(`{"warpmetal-agent-sandbox":"sha256:`+strings.Repeat("2", 64)+`"}`),
		[]byte(legacyRecord.EnvelopeJSON), legacyRecord.VerifiedAt); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open and migrate legacy agent kit table: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	preserved, err := store.AgentKitMaterialization(ctx, legacyRecord.MaterializationID, legacyRecord.SandboxID, legacyRecord.SandboxGeneration)
	if err != nil || preserved == nil || preserved.EnvelopeDigest != legacyRecord.EnvelopeDigest {
		t.Fatalf("migration lost the legacy row: %#v %v", preserved, err)
	}
	second := legacyRecord
	second.SandboxID = "sbx_store_migrated02"
	second.ApplicationOperationID = "wfapp_store_migrated_2"
	if created, err := store.PutAgentKitMaterialization(ctx, second); err != nil || !created {
		t.Fatalf("second workspace after migration: created=%t err=%v", created, err)
	}
}
