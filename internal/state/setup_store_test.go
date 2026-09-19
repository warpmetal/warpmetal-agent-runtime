package state

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func TestSetupOperationFenceAndOutcomeSurviveStoreRestart(t *testing.T) {
	database := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.PutSandbox(ctx, LocalSandbox{
		ID: "sbx_test12345", Name: "main", DesiredState: "running", ObservedState: "running",
		Generation: 1, ObservedGeneration: 1, Lifetime: "persistent",
		Resources: model.Resources{
			CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256,
		},
		ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
	}); err != nil {
		t.Fatal(err)
	}

	wantColumns := []string{
		"id", "sandbox_id", "sandbox_generation", "profile_id", "profile_revision",
		"profile_digest", "desired_revision", "body_digest", "request_json", "state",
		"receipt_json", "receipt_digest", "error_code", "error_message", "updated_at",
	}
	rows, err := store.db.QueryContext(ctx, `PRAGMA table_info(setup_operations)`)
	if err != nil {
		t.Fatal(err)
	}
	columns := map[string]bool{}
	for rows.Next() {
		var ordinal, notNull, primaryKey int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&ordinal, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range wantColumns {
		if !columns[name] {
			t.Fatalf("durable setup_operations column %q is missing; columns=%#v", name, columns)
		}
	}

	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	request := `{"id":"setup-test12345","sandboxId":"sbx_test12345"}`
	receipt := `{"id":"setup-test12345","status":"failed"}`
	_, err = store.db.ExecContext(ctx, `INSERT INTO setup_operations(
id, sandbox_id, sandbox_generation, profile_id, profile_revision, profile_digest,
desired_revision, body_digest, request_json, state, receipt_json, receipt_digest,
error_code, error_message, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"setup-test12345", "sbx_test12345", 1, "openai-codex", 1, digestA,
		7, digestB, request, "failed", receipt, digestB,
		"setup_self_test_failed", "bounded diagnostic", "2026-09-18T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("persist setup fence: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var sandboxID, profileDigest, state, errorCode string
	var generation, desiredRevision int64
	err = reopened.db.QueryRowContext(ctx, `SELECT sandbox_id, sandbox_generation,
profile_digest, desired_revision, state, error_code FROM setup_operations WHERE id = ?`,
		"setup-test12345",
	).Scan(&sandboxID, &generation, &profileDigest, &desiredRevision, &state, &errorCode)
	if err != nil {
		t.Fatal(err)
	}
	if sandboxID != "sbx_test12345" || generation != 1 || profileDigest != digestA ||
		desiredRevision != 7 || state != "failed" || errorCode != "setup_self_test_failed" {
		t.Fatalf("setup fence/outcome changed across restart: %q %d %q %d %q %q",
			sandboxID, generation, profileDigest, desiredRevision, state, errorCode)
	}
}

func TestSetupOperationStateDomainIsClosed(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var schema string
	err = store.db.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'setup_operations'`,
	).Scan(&schema)
	if err != nil {
		t.Fatalf("setup_operations schema is missing: %v", err)
	}
	compact := strings.ToLower(strings.Join(strings.Fields(schema), " "))
	for _, state := range []string{"pending", "applying", "ready", "failed", "cancelled"} {
		if !strings.Contains(compact, "'"+state+"'") {
			t.Fatalf("setup state %q is not constrained by the durable schema: %s", state, schema)
		}
	}
}

func transitionSetupOperation(
	t *testing.T,
	store *Store,
	id string,
	status string,
	receipt []byte,
	errorCode string,
	errorMessage string,
) error {
	t.Helper()
	method := reflect.ValueOf(store).MethodByName("TransitionSetupOperation")
	if !method.IsValid() {
		t.Fatal("Store.TransitionSetupOperation is missing")
	}
	typ := method.Type()
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	bytesType := reflect.TypeOf([]byte(nil))
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if typ.NumIn() != 6 || typ.In(0) != contextType || typ.In(1).Kind() != reflect.String ||
		typ.In(2).Kind() != reflect.String || typ.In(3) != bytesType ||
		typ.In(4).Kind() != reflect.String || typ.In(5).Kind() != reflect.String ||
		typ.NumOut() != 1 || typ.Out(0) != errorType {
		t.Fatalf("TransitionSetupOperation has unexpected signature: %s", typ)
	}
	results := method.Call([]reflect.Value{
		reflect.ValueOf(context.Background()), reflect.ValueOf(id), reflect.ValueOf(status),
		reflect.ValueOf(receipt), reflect.ValueOf(errorCode), reflect.ValueOf(errorMessage),
	})
	if results[0].IsNil() {
		return nil
	}
	return results[0].Interface().(error)
}

func TestSetupOperationTransitionsRejectSkippedAndTerminalEdges(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.PutSandbox(ctx, LocalSandbox{
		ID: "sbx_test12345", Name: "main", DesiredState: "running", ObservedState: "running",
		Generation: 1, ObservedGeneration: 1, Lifetime: "persistent",
		Resources: model.Resources{
			CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256,
		},
		ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
	}); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	insert := func(id string) {
		t.Helper()
		_, err := store.db.ExecContext(ctx, `INSERT INTO setup_operations(
id, sandbox_id, sandbox_generation, profile_id, profile_revision, profile_digest,
desired_revision, body_digest, request_json, state, error_code, error_message, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?)`, id, "sbx_test12345", 1,
			"openai-codex", 1, digest, 1, digest, `{}`, "pending", "2026-09-18T12:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("setup-ready-path")
	if err := transitionSetupOperation(t, store, "setup-ready-path", "ready", []byte(`{}`), "", ""); err == nil {
		t.Fatal("pending -> ready skipped the applying fence")
	}
	if err := transitionSetupOperation(t, store, "setup-ready-path", "applying", nil, "", ""); err != nil {
		t.Fatalf("pending -> applying: %v", err)
	}
	if err := transitionSetupOperation(t, store, "setup-ready-path", "ready", []byte(`{}`), "", ""); err != nil {
		t.Fatalf("applying -> ready: %v", err)
	}
	if err := transitionSetupOperation(t, store, "setup-ready-path", "failed", nil, "late", "late"); err == nil {
		t.Fatal("terminal ready operation changed to failed")
	}

	insert("setup-cancel-path")
	if err := transitionSetupOperation(t, store, "setup-cancel-path", "cancelled", nil, "", ""); err != nil {
		t.Fatalf("pending -> cancelled: %v", err)
	}
	if err := transitionSetupOperation(t, store, "setup-cancel-path", "applying", nil, "", ""); err == nil {
		t.Fatal("terminal cancelled operation returned to applying")
	}
}
