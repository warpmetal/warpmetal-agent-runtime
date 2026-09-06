package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type fakeEngine struct {
	created        int
	replaced       int
	restarted      int
	removed        int
	images         []string
	replaceRunning bool
	replaceErr     error
	execOutput     string
	execErr        error
	execCommands   []string
}

func (f *fakeEngine) Replace(
	_ context.Context,
	_ model.Sandbox,
	_ string,
	image string,
	running bool,
) error {
	f.replaced++
	f.images = append(f.images, image)
	f.replaceRunning = running
	return f.replaceErr
}

func (f *fakeEngine) Ensure(
	_ context.Context,
	_ model.Sandbox,
	_ string,
	image string,
) error {
	f.created++
	f.images = append(f.images, image)
	return nil
}
func (f *fakeEngine) Start(context.Context, string) error   { return nil }
func (f *fakeEngine) Stop(context.Context, string) error    { return nil }
func (f *fakeEngine) Restart(context.Context, string) error { f.restarted++; return nil }
func (f *fakeEngine) Remove(context.Context, string) error  { f.removed++; return nil }
func (f *fakeEngine) Exec(
	_ context.Context,
	_ string,
	command string,
	_ bool,
	_ io.Reader,
	stdout io.Writer,
	_ io.Writer,
) error {
	f.execCommands = append(f.execCommands, command)
	_, _ = io.WriteString(stdout, f.execOutput)
	return f.execErr
}

type fakeWorkspaces struct{ destroyed int }

func (f *fakeWorkspaces) Ensure(context.Context, string, int) (string, error) {
	return "/workspace", nil
}
func (f *fakeWorkspaces) Destroy(context.Context, string) error { f.destroyed++; return nil }

type fakeSessions struct{ terminated int }

func (f *fakeSessions) TerminateGrant(context.Context, string) error {
	f.terminated++
	return nil
}
func (f *fakeSessions) TerminateSandbox(context.Context, string) error {
	f.terminated++
	return nil
}

func TestEmptyReportUsesArraysOnTheWire(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reconciler := &Reconciler{Store: store}
	report, err := reconciler.Report(context.Background(), "srv_test12345", "test")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(payload)
	if !strings.Contains(encoded, `"sandboxes":[]`) ||
		!strings.Contains(encoded, `"accessGrants":[]`) {
		t.Fatalf("empty report collections must be JSON arrays: %s", encoded)
	}
}

func TestTemporarySandboxExpiresLocallyDuringControlPlaneOutage(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{}
	workspaces := &fakeWorkspaces{}
	sessions := &fakeSessions{}
	current := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	reconciler := &Reconciler{
		Store:        store,
		Engine:       engine,
		Workspaces:   workspaces,
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		Sessions:     sessions,
		HostCapacity: model.Resources{CPUMillicores: 4000, MemoryMiB: 8192, WorkspaceDiskGiB: 80},
		ServerID:     "srv_test12345",
		Now:          func() time.Time { return current },
	}
	seconds := 900
	originalImage := "registry.example/sandbox@sha256:" + strings.Repeat("a", 64)
	newImage := "registry.example/sandbox@sha256:" + strings.Repeat("b", 64)
	manifest := model.Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: 1,
		ImageDigest:     originalImage,
		Capacity:        model.Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []model.Sandbox{
			{
				ID:               "sbx_test12345",
				Name:             "reviewer",
				Size:             "small",
				Resources:        model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
				Lifetime:         "temporary",
				ExpiresInSeconds: &seconds,
				DesiredState:     "running",
				Generation:       1,
			},
		},
	}
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	local, err := store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil || local == nil || local.ExpiresAt == nil {
		t.Fatalf("temporary clock was not persisted: %#v %v", local, err)
	}
	report, err := reconciler.Report(context.Background(), manifest.ServerID, "test")
	if err != nil || len(report.Sandboxes) != 1 || report.Sandboxes[0].StartedAt == nil ||
		report.Sandboxes[0].ExpiresAt == nil {
		t.Fatalf("authoritative local timestamps were not reported: %#v %v", report, err)
	}
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if engine.created != 2 {
		t.Fatalf("running container drift was not reconciled: %#v", engine)
	}
	manifest.DesiredRevision = 2
	manifest.ImageDigest = newImage
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	local, err = store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil || local == nil ||
		local.ImageDigest != originalImage {
		t.Fatalf("existing sandbox did not retain its creation image: %#v %v", local, err)
	}
	if engine.images[len(engine.images)-1] != originalImage {
		t.Fatalf("existing container was reconciled with a new default image: %#v", engine.images)
	}
	if engine.replaced != 0 {
		t.Fatalf("a global default change replaced an existing sandbox: %#v", engine)
	}
	current = current.Add(901 * time.Second)
	if err := reconciler.Expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	local, err = store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil || local.ObservedState != "deleted" {
		t.Fatalf("sandbox was not deleted: %#v %v", local, err)
	}
	if engine.removed != 1 || workspaces.destroyed != 1 || sessions.terminated == 0 {
		t.Fatalf("cleanup was incomplete: %#v %#v %#v", engine, workspaces, sessions)
	}
	manifest.DesiredRevision = 3
	manifest.Sandboxes = nil
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	local, err = store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil || local != nil {
		t.Fatalf("confirmed local tombstone was not pruned: %#v %v", local, err)
	}
}

func TestExplicitSandboxImageRefreshPreservesWorkspaceAndLifetime(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{}
	workspaces := &fakeWorkspaces{}
	sessions := &fakeSessions{}
	current := time.Date(2026, 9, 5, 6, 0, 0, 0, time.UTC)
	reconciler := &Reconciler{
		Store: store, Engine: engine, Workspaces: workspaces, Sessions: sessions,
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		HostCapacity: model.Resources{CPUMillicores: 4000, MemoryMiB: 8192, WorkspaceDiskGiB: 80},
		ServerID:     "srv_test12345", Now: func() time.Time { return current },
	}
	originalImage := "registry.example/sandbox@sha256:" + strings.Repeat("a", 64)
	newImage := "registry.example/sandbox@sha256:" + strings.Repeat("b", 64)
	manifest := model.Manifest{
		ServerID: "srv_test12345", DesiredRevision: 1, ImageDigest: originalImage,
		Capacity: model.Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []model.Sandbox{{
			ID: "sbx_test12345", Name: "reviewer", Size: "small",
			Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			Lifetime:  "persistent", DesiredState: "running", Generation: 1,
		}},
	}
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	before, err := store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil || before == nil || before.StartedAt == nil {
		t.Fatalf("initial sandbox missing: %#v %v", before, err)
	}
	startedAt := *before.StartedAt
	manifest.DesiredRevision = 2
	manifest.Sandboxes[0].Generation = 2
	manifest.Sandboxes[0].ImageDigest = newImage
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	after, err := store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil || after == nil {
		t.Fatalf("refreshed sandbox missing: %#v %v", after, err)
	}
	if after.ImageDigest != newImage || after.ObservedGeneration != 2 ||
		after.ObservedState != "running" || after.StartedAt == nil ||
		!after.StartedAt.Equal(startedAt) {
		t.Fatalf("refresh changed persistent identity or did not converge: %#v", after)
	}
	if engine.replaced != 1 || !engine.replaceRunning || sessions.terminated != 1 ||
		workspaces.destroyed != 0 {
		t.Fatalf("refresh boundaries were not honored: %#v %#v %#v", engine, sessions, workspaces)
	}
}

func TestSandboxImageRefreshFailureKeepsPinnedDigest(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{replaceErr: containers.ErrImagePullFailed}
	reconciler := &Reconciler{
		Store: store, Engine: engine, Workspaces: &fakeWorkspaces{}, Sessions: &fakeSessions{},
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		HostCapacity: model.Resources{CPUMillicores: 4000, MemoryMiB: 8192, WorkspaceDiskGiB: 80},
		ServerID:     "srv_test12345",
	}
	originalImage := "registry.example/sandbox@sha256:" + strings.Repeat("a", 64)
	newImage := "registry.example/sandbox@sha256:" + strings.Repeat("b", 64)
	manifest := model.Manifest{
		ServerID: "srv_test12345", DesiredRevision: 1, ImageDigest: originalImage,
		Capacity: model.Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []model.Sandbox{{
			ID: "sbx_test12345", Name: "reviewer", Size: "small",
			Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			Lifetime:  "persistent", DesiredState: "running", Generation: 1,
		}},
	}
	engine.replaceErr = nil
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	engine.replaceErr = containers.ErrImagePullFailed
	manifest.DesiredRevision = 2
	manifest.Sandboxes[0].Generation = 2
	manifest.Sandboxes[0].ImageDigest = newImage
	if err := reconciler.Reconcile(context.Background(), manifest); err == nil {
		t.Fatal("expected image pull failure")
	}
	local, err := store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil || local == nil || local.ImageDigest != originalImage ||
		local.ErrorCode != "sandbox_image_pull_failed" || local.ObservedGeneration != 1 {
		t.Fatalf("failed refresh advanced pinned state: %#v %v", local, err)
	}
}

func TestStoppedSandboxImageRefreshPreservesStoppedState(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{}
	workspaces := &fakeWorkspaces{}
	reconciler := &Reconciler{
		Store: store, Engine: engine, Workspaces: workspaces, Sessions: &fakeSessions{},
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		HostCapacity: model.Resources{CPUMillicores: 4000, MemoryMiB: 8192, WorkspaceDiskGiB: 80},
		ServerID:     "srv_test12345",
	}
	originalImage := "registry.example/sandbox@sha256:" + strings.Repeat("a", 64)
	newImage := "registry.example/sandbox@sha256:" + strings.Repeat("b", 64)
	manifest := model.Manifest{
		ServerID: "srv_test12345", DesiredRevision: 1, ImageDigest: originalImage,
		Capacity: model.Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []model.Sandbox{{
			ID: "sbx_test12345", Name: "reviewer", Size: "small",
			Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			Lifetime:  "persistent", DesiredState: "running", Generation: 1,
		}},
	}
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	manifest.DesiredRevision = 2
	manifest.Sandboxes[0].DesiredState = "stopped"
	manifest.Sandboxes[0].Generation = 2
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	manifest.DesiredRevision = 3
	manifest.Sandboxes[0].Generation = 3
	manifest.Sandboxes[0].ImageDigest = newImage
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	local, err := store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil || local == nil || local.ObservedState != "stopped" ||
		local.ObservedGeneration != 3 || local.ImageDigest != newImage {
		t.Fatalf("stopped refresh did not converge: %#v %v", local, err)
	}
	if engine.replaced != 1 || engine.replaceRunning || workspaces.destroyed != 0 {
		t.Fatalf("stopped refresh changed lifecycle or workspace: %#v %#v", engine, workspaces)
	}
}

func TestSandboxImageRefreshRollbackFailureIsDistinct(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{}
	reconciler := &Reconciler{
		Store: store, Engine: engine, Workspaces: &fakeWorkspaces{}, Sessions: &fakeSessions{},
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		HostCapacity: model.Resources{CPUMillicores: 4000, MemoryMiB: 8192, WorkspaceDiskGiB: 80},
		ServerID:     "srv_test12345",
	}
	originalImage := "registry.example/sandbox@sha256:" + strings.Repeat("a", 64)
	newImage := "registry.example/sandbox@sha256:" + strings.Repeat("b", 64)
	manifest := model.Manifest{
		ServerID: "srv_test12345", DesiredRevision: 1, ImageDigest: originalImage,
		Capacity: model.Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []model.Sandbox{{
			ID: "sbx_test12345", Name: "reviewer", Size: "small",
			Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			Lifetime:  "persistent", DesiredState: "running", Generation: 1,
		}},
	}
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	engine.replaceErr = containers.ErrImageRollbackFailed
	manifest.DesiredRevision = 2
	manifest.Sandboxes[0].Generation = 2
	manifest.Sandboxes[0].ImageDigest = newImage
	if err := reconciler.Reconcile(context.Background(), manifest); err == nil {
		t.Fatal("expected rollback failure")
	}
	local, err := store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil || local == nil || local.ImageDigest != originalImage ||
		local.ErrorCode != "container_image_rollback_failed" || local.ObservedGeneration != 1 {
		t.Fatalf("rollback failure was not preserved distinctly: %#v %v", local, err)
	}
}

const successfulToolReport = `[
  {"id":"codex","status":"available","version":"0.153.4"},
  {"id":"claude","status":"available","version":"2.1.263"},
  {"id":"cursor","status":"available","version":"2026.09.02-c22c1a3"}
]`

func TestSelectedCLIToolsAreGenerationBoundAndReportedExactly(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{execOutput: successfulToolReport}
	reconciler := testReconciler(t, store, engine)
	manifest := testManifest([]string{"cursor", "codex"})
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	report, err := reconciler.Report(context.Background(), manifest.ServerID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Sandboxes) != 1 || report.Sandboxes[0].ObservedGeneration != 1 ||
		len(report.Sandboxes[0].CLITools) != 2 ||
		report.Sandboxes[0].CLITools[0].ID != "cursor" ||
		report.Sandboxes[0].CLITools[1].ID != "codex" {
		t.Fatalf("selected CLI tools were not reported exactly: %#v", report)
	}
	if len(engine.execCommands) != 1 ||
		engine.execCommands[0] != "/usr/local/bin/warpmetal-agent-tool-report" {
		t.Fatalf("runtime executed an unexpected command: %#v", engine.execCommands)
	}
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if len(engine.execCommands) != 1 {
		t.Fatalf("unchanged generation was probed again: %#v", engine.execCommands)
	}
}

func TestCLIToolSelectionChangeRequiresGenerationAdvance(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{execOutput: successfulToolReport}
	reconciler := testReconciler(t, store, engine)
	manifest := testManifest([]string{"codex"})
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	manifest.DesiredRevision = 2
	manifest.Sandboxes[0].CLITools = []string{"claude", "cursor"}
	if err := reconciler.Reconcile(context.Background(), manifest); err == nil ||
		!strings.Contains(err.Error(), "generation advance") {
		t.Fatalf("same-generation selection change was not rejected: %v", err)
	}
	manifest.Sandboxes[0].Generation = 2
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	report, err := reconciler.Report(context.Background(), manifest.ServerID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if report.Sandboxes[0].ObservedGeneration != 2 ||
		len(report.Sandboxes[0].CLITools) != 2 ||
		report.Sandboxes[0].CLITools[0].ID != "claude" ||
		len(engine.execCommands) != 2 {
		t.Fatalf("advanced selection did not replace observations: %#v %#v", report, engine)
	}
}

func TestCLIToolProbeFailurePreservesRunningSandboxAndPersistsSafeStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	engine := &fakeEngine{execErr: errors.New("secret child stderr")}
	reconciler := testReconciler(t, store, engine)
	manifest := testManifest([]string{"codex", "claude"})
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatalf("tool failure failed the sandbox lifecycle: %v", err)
	}
	local, err := store.Sandbox(context.Background(), "sbx_test12345")
	if err != nil {
		t.Fatal(err)
	}
	if local == nil || local.ObservedState != "running" || local.ObservedGeneration != 1 ||
		local.ErrorCode != "" || len(local.ObservedCLITools) != 2 ||
		local.ObservedCLITools[0].Status != "failed" ||
		local.ObservedCLITools[0].LastError == nil ||
		strings.Contains(local.ObservedCLITools[0].LastError.Message, "secret") {
		t.Fatalf("tool failure corrupted or leaked into sandbox state: %#v", local)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reconciler.Store = store
	report, err := reconciler.Report(context.Background(), manifest.ServerID, "test")
	if err != nil || len(report.Sandboxes) != 1 ||
		len(report.Sandboxes[0].CLITools) != 2 || report.Sandboxes[0].LastError != nil {
		t.Fatalf("safe tool failure was not durable: %#v %v", report, err)
	}
}

func TestReportOmitsStaleCLIToolObservations(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.PutSandbox(context.Background(), state.LocalSandbox{
		ID: "sbx_test12345", Name: "main", DesiredState: "running", ObservedState: "running",
		Generation: 2, ObservedGeneration: 2, Lifetime: "persistent",
		Resources:   model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
		ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
		CLITools:    []string{"codex"}, ObservedCLITools: []model.CLIToolReport{{ID: "codex", Status: "available"}},
		CLIToolsGeneration: 1,
	}); err != nil {
		t.Fatal(err)
	}
	report, err := (&Reconciler{Store: store}).Report(context.Background(), "srv_test12345", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Sandboxes[0].CLITools) != 0 {
		t.Fatalf("stale tool observations were reported: %#v", report)
	}
}

func testManifest(cliTools []string) model.Manifest {
	return model.Manifest{
		ServerID: "srv_test12345", DesiredRevision: 1,
		ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
		Capacity:    model.Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []model.Sandbox{{
			ID: "sbx_test12345", Name: "main", Size: "small",
			Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			Lifetime:  "persistent", DesiredState: "running", Generation: 1,
			CLITools: append([]string(nil), cliTools...),
		}},
	}
}

func testReconciler(t *testing.T, store *state.Store, engine *fakeEngine) *Reconciler {
	t.Helper()
	return &Reconciler{
		Store: store, Engine: engine, Workspaces: &fakeWorkspaces{},
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		HostCapacity: model.Resources{CPUMillicores: 4000, MemoryMiB: 8192, WorkspaceDiskGiB: 80},
		ServerID:     "srv_test12345",
	}
}
