package reconcile

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type fakeEngine struct {
	created   int
	restarted int
	removed   int
	images    []string
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
	context.Context,
	string,
	string,
	bool,
	io.Reader,
	io.Writer,
	io.Writer,
) error {
	return nil
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
