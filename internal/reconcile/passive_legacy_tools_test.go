package reconcile

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	_ "modernc.org/sqlite"
)

const contractToolReport = `[
  {"id":"codex","status":"available","version":"legacy"},
  {"id":"claude","status":"available","version":"legacy"}
]`

type contractEngine struct {
	ensured     int
	started     int
	stopped     int
	restarted   int
	replaced    int
	removed     int
	toolReports int
}

func (e *contractEngine) Ensure(context.Context, model.Sandbox, string, string) error {
	e.ensured++
	return nil
}

func (e *contractEngine) Replace(
	context.Context,
	model.Sandbox,
	string,
	string,
	bool,
) error {
	e.replaced++
	return nil
}

func (e *contractEngine) Start(context.Context, string) error {
	e.started++
	return nil
}

func (e *contractEngine) Stop(context.Context, string) error {
	e.stopped++
	return nil
}

func (e *contractEngine) Restart(context.Context, string) error {
	e.restarted++
	return nil
}

func (e *contractEngine) Remove(context.Context, string) error {
	e.removed++
	return nil
}

func (e *contractEngine) Exec(
	context.Context,
	string,
	string,
	bool,
	containers.SessionInput,
	io.Writer,
	io.Writer,
) error {
	return nil
}

// ToolReport deliberately remains an extra method after the production Engine
// stops exposing this legacy boundary. Any call records an observable contract
// violation without making the fixture itself unavailable to current Runtime.
func (e *contractEngine) ToolReport(_ context.Context, _ string, stdout io.Writer) error {
	e.toolReports++
	_, err := io.WriteString(stdout, contractToolReport)
	return err
}

type contractWorkspaces struct {
	destroyed int
}

func (w *contractWorkspaces) Ensure(context.Context, string, int) (string, error) {
	return "/workspace", nil
}

func (w *contractWorkspaces) Destroy(context.Context, string) error {
	w.destroyed++
	return nil
}

type contractSessions struct {
	grants    int
	sandboxes int
}

func (s *contractSessions) TerminateGrant(context.Context, string) error {
	s.grants++
	return nil
}

func (s *contractSessions) TerminateSandbox(context.Context, string) error {
	s.sandboxes++
	return nil
}

type legacyToolColumns struct {
	desired    string
	observed   string
	generation int64
}

func TestLegacyToolManifestAndDatabaseStateRemainPassive(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	seedLegacyToolDatabase(t, databasePath)
	wantLegacyColumns := readLegacyToolColumns(t, databasePath)

	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatalf("open database containing legacy tool columns: %v", err)
	}
	engine := &contractEngine{}
	workspaces := &contractWorkspaces{}
	sessions := &contractSessions{}
	reconciler := contractReconciler(t, store, engine, workspaces, sessions)
	manifest := decodeContractManifest(t, 2, 2, "running", "", true)

	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		_ = store.Close()
		t.Fatalf("reconcile manifest containing legacy cliTools: %v", err)
	}
	report, err := reconciler.Report(context.Background(), manifest.ServerID, "test")
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	local, err := store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	grant, err := store.Grant(context.Background(), "grant_test12345")
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if engine.toolReports != 0 {
		t.Errorf("legacy cliTools invoked the image reporter %d time(s)", engine.toolReports)
	}
	if engine.restarted != 1 || engine.ensured != 0 || engine.started != 0 ||
		engine.stopped != 0 || engine.replaced != 0 || engine.removed != 0 {
		t.Errorf("ordinary generation restart changed lifecycle path: %#v", engine)
	}
	if local == nil || local.ObservedState != "running" || local.ObservedGeneration != 2 ||
		local.ImageDigest != contractImageDigest("a") || local.StartedAt == nil {
		t.Errorf("legacy state did not preserve the running sandbox and image pin: %#v", local)
	}
	if grant == nil || grant.ObservedState != "applied" || grant.DesiredState != "active" {
		t.Errorf("legacy state did not preserve the access grant: %#v", grant)
	}
	assertReportOmitsCLITools(t, report)
	if got := readLegacyToolColumns(t, databasePath); !reflect.DeepEqual(got, wantLegacyColumns) {
		t.Errorf("legacy tool columns were actively mutated: got %#v, want %#v", got, wantLegacyColumns)
	}
}

func TestCapacityLifecycleRemainsIndependentOfToolReporting(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &contractEngine{}
	workspaces := &contractWorkspaces{}
	sessions := &contractSessions{}
	reconciler := contractReconciler(t, store, engine, workspaces, sessions)

	steps := []struct {
		revision   int64
		generation int64
		state      string
		image      string
	}{
		{revision: 1, generation: 1, state: "running"},
		{revision: 2, generation: 2, state: "stopped"},
		{revision: 3, generation: 3, state: "running"},
		{revision: 4, generation: 4, state: "running"},
		{revision: 5, generation: 5, state: "running", image: contractImageDigest("b")},
	}
	for _, step := range steps {
		manifest := decodeContractManifest(
			t,
			step.revision,
			step.generation,
			step.state,
			step.image,
			false,
		)
		if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
			t.Fatalf("reconcile revision %d: %v", step.revision, err)
		}
	}

	wantEngine := contractEngine{ensured: 1, started: 1, stopped: 1, restarted: 1, replaced: 1}
	if !reflect.DeepEqual(*engine, wantEngine) {
		t.Fatalf("capacity lifecycle calls changed: got %#v, want %#v", *engine, wantEngine)
	}
	if workspaces.destroyed != 0 {
		t.Fatalf("capacity lifecycle destroyed the workspace %d time(s)", workspaces.destroyed)
	}

	report, err := reconciler.Report(context.Background(), "srv_test12345", "test")
	if err != nil {
		t.Fatal(err)
	}
	assertReportOmitsCLITools(t, report)
	if len(report.Sandboxes) != 1 || report.Sandboxes[0].ObservedState != "running" ||
		report.Sandboxes[0].ObservedGeneration != 5 ||
		report.Sandboxes[0].ImageDigest != contractImageDigest("b") {
		t.Fatalf("capacity lifecycle report changed: %#v", report)
	}
	if len(report.AccessGrants) != 1 || report.AccessGrants[0].ObservedState != "applied" {
		t.Fatalf("access grant report changed: %#v", report.AccessGrants)
	}
}

func contractReconciler(
	t *testing.T,
	store *state.Store,
	engine *contractEngine,
	workspaces *contractWorkspaces,
	sessions *contractSessions,
) *Reconciler {
	t.Helper()
	return &Reconciler{
		Store:      store,
		Engine:     engine,
		Workspaces: workspaces,
		Access: access.Renderer{
			Path: filepath.Join(t.TempDir(), "authorized_keys"),
		},
		Sessions: sessions,
		HostCapacity: model.Resources{
			CPUMillicores:    4000,
			MemoryMiB:        8192,
			WorkspaceDiskGiB: 80,
		},
		ServerID: "srv_test12345",
	}
}

func decodeContractManifest(
	t *testing.T,
	revision int64,
	generation int64,
	desiredState string,
	sandboxImage string,
	legacyTools bool,
) model.Manifest {
	t.Helper()
	imageField := ""
	if sandboxImage != "" {
		imageField = fmt.Sprintf(`,"imageDigest":%q`, sandboxImage)
	}
	toolField := ""
	if legacyTools {
		toolField = `,"cliTools":["codex"]`
	}
	payload := fmt.Sprintf(`{
  "serverId":"srv_test12345",
  "desiredRevision":%d,
  "imageDigest":%q,
  "capacity":{"cpuMillicores":1500,"memoryMiB":3072,"workspaceDiskGiB":30,"pids":512},
  "sandboxes":[{
    "id":"sbx_test12345","name":"main","size":"small",
    "resources":{"cpuMillicores":500,"memoryMiB":1024,"workspaceDiskGiB":10,"pids":256},
    "lifetime":"persistent","desiredState":%q,"generation":%d%s%s
  }],
  "accessGrants":[{
    "id":"grant_test12345","sandboxId":"sbx_test12345",
    "sshPublicKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBsdWm8Pqyk0JnYWt0lYSdPUgk7DcBLBnISfcYHiL+s",
    "sshFingerprint":"SHA256:test","desiredState":"active"
  }]
}`, revision, contractImageDigest("a"), desiredState, generation, imageField, toolField)
	var manifest model.Manifest
	if err := json.Unmarshal([]byte(payload), &manifest); err != nil {
		t.Fatalf("decode manifest fixture: %v", err)
	}
	return manifest
}

func assertReportOmitsCLITools(t *testing.T, report model.Report) {
	t.Helper()
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(`"cliTools"`)) {
		t.Errorf("outgoing report contains legacy cliTools: %s", payload)
	}
}

func seedLegacyToolDatabase(t *testing.T, path string) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = database.Exec(fmt.Sprintf(`
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE sandboxes (
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
  cli_tools TEXT NOT NULL DEFAULT '[]',
  observed_cli_tools TEXT NOT NULL DEFAULT '[]',
  cli_tools_generation INTEGER NOT NULL DEFAULT 0,
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE TABLE grants (
  id TEXT PRIMARY KEY,
  sandbox_id TEXT NOT NULL REFERENCES sandboxes(id) ON DELETE CASCADE,
  ssh_public_key TEXT NOT NULL,
  desired_state TEXT NOT NULL,
  observed_state TEXT NOT NULL,
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
INSERT INTO metadata(key, value) VALUES('desired_revision', '1');
INSERT INTO sandboxes(
  id, name, desired_state, observed_state, generation, observed_generation,
  lifetime, started_at, cpu_millicores, memory_mib, workspace_disk_gib,
  pids_limit, image_digest, cli_tools, observed_cli_tools,
  cli_tools_generation, updated_at
) VALUES(
  'sbx_test12345', 'main', 'running', 'running', 1, 1, 'persistent',
  '2026-09-01T00:00:00Z', 500, 1024, 10, 256, %q,
  '["claude"]', '[{"id":"claude","status":"available","version":"legacy"}]',
  1, '2026-09-01T00:00:00Z'
);
INSERT INTO grants(
  id, sandbox_id, ssh_public_key, desired_state, observed_state, updated_at
) VALUES(
  'grant_test12345', 'sbx_test12345',
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBsdWm8Pqyk0JnYWt0lYSdPUgk7DcBLBnISfcYHiL+s',
  'active', 'applied', '2026-09-01T00:00:00Z'
);`, contractImageDigest("a")))
	if err != nil {
		t.Fatalf("seed legacy database: %v", err)
	}
}

func readLegacyToolColumns(t *testing.T, path string) legacyToolColumns {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var value legacyToolColumns
	if err := database.QueryRow(`
SELECT cli_tools, observed_cli_tools, cli_tools_generation
FROM sandboxes WHERE id = 'sbx_test12345'
`).Scan(&value.desired, &value.observed, &value.generation); err != nil {
		t.Fatalf("read legacy tool columns: %v", err)
	}
	return value
}

func contractImageDigest(character string) string {
	return "registry.example/sandbox@sha256:" + strings.Repeat(character, 64)
}
