package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type fakeCheckpointLifecycle struct {
	calls int
	err   error
}

func (f *fakeCheckpointLifecycle) Run(context.Context) error {
	f.calls++
	return f.err
}

func TestExpireRunsBoundedCheckpointLifecycleWithoutManifest(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lifecycle := &fakeCheckpointLifecycle{}
	reconciler := &Reconciler{Store: store, ContinuityLifecycle: lifecycle}
	if err := reconciler.Expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lifecycle.calls != 1 {
		t.Fatalf("checkpoint lifecycle calls = %d, want 1", lifecycle.calls)
	}
	lifecycle.err = errors.New("collection failed closed")
	if err := reconciler.Expire(context.Background()); !errors.Is(err, lifecycle.err) {
		t.Fatalf("collector failure = %v", err)
	}
}
