package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func TestOrdinaryRuntimeConstructorWiresContinuityRegistryObjectsEngineAndRecovery(t *testing.T) {
	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reconciler := newRuntimeReconciler(store, containers.Podman{}, filepath.Join(root, "workspaces"), filepath.Join(root, "authorized_keys"), nil, model.Resources{}, "srv_constructor0001", root, api.Client{}, context.Background())
	if reconciler.Continuity == nil || reconciler.ContinuityControl == nil || reconciler.ContinuityLifecycle == nil {
		t.Fatalf("ordinary constructor omitted continuity recovery/control: %#v", reconciler)
	}
	report, err := reconciler.Report(t.Context(), "srv_constructor0001", "test")
	if err != nil {
		t.Fatal(err)
	}
	if report.ContinuitySources == nil || report.ContinuityRegistrations == nil || report.ContinuityOperations == nil {
		t.Fatalf("ordinary constructor did not publish closed continuity arrays: %#v", report)
	}
}

func TestOrdinaryRuntimeConstructorWiresContinuationRestoreRecovery(t *testing.T) {
	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reconciler := newRuntimeReconciler(store, containers.Podman{}, filepath.Join(root, "workspaces"), filepath.Join(root, "authorized_keys"), nil, model.Resources{}, "srv_constructor0001", root, api.Client{}, context.Background())
	if reconciler.ContinuationRestore == nil {
		t.Fatal("ordinary constructor omitted S2 continuation/restore recovery")
	}
	report, err := reconciler.Report(t.Context(), "srv_constructor0001", "test")
	if err != nil {
		t.Fatal(err)
	}
	if report.ContinuityContinuations == nil || report.ContinuityRestores == nil {
		t.Fatalf("ordinary constructor did not publish closed S2 arrays: %#v", report)
	}
}
