package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type fakeContinuityRecovery struct {
	called int
	err    error
}

func (f *fakeContinuityRecovery) Recover(context.Context) error {
	f.called++
	return f.err
}

func (f *fakeContinuityRecovery) RecoverLocalSafety(context.Context) error {
	return nil
}

func (f *fakeContinuityRecovery) RecoverCurrent(ctx context.Context, _ model.Manifest) error {
	return f.Recover(ctx)
}

func TestReconcileRecoversDurableContinuityOperationsBeforeLifecycleActions(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	recovery := &fakeContinuityRecovery{err: errors.New("owned pause state is unknown")}
	engine := &fakeEngine{}
	r := &Reconciler{
		Store: store, Engine: engine, Workspaces: &fakeWorkspaces{},
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		Sessions:     &fakeSessions{},
		HostCapacity: model.Resources{CPUMillicores: 2000, MemoryMiB: 4096, WorkspaceDiskGiB: 40},
		ServerID:     "srv_test12345",
		Continuity:   recovery,
	}
	manifest := model.Manifest{
		ServerID: "srv_test12345", DesiredRevision: 1,
		ImageDigest: "registry.example/sandbox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Capacity:    model.Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20},
		Sandboxes: []model.Sandbox{{
			ID: "sbx_test12345", Name: "worker", Size: "small",
			Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			Lifetime:  "persistent", DesiredState: "running", Generation: 1,
		}},
	}
	if err := r.Reconcile(context.Background(), manifest); err == nil {
		t.Fatal("lifecycle reconciliation continued through uncertain continuity recovery")
	}
	if recovery.called != 1 || engine.created != 0 {
		t.Fatalf("continuity recovery/lifecycle calls = %d/%d, want 1/0", recovery.called, engine.created)
	}
}
