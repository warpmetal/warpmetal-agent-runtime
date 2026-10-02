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

func TestOrdinaryRuntimeConstructorWiresDurableInsightsCollector(t *testing.T) {
	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	control := api.Client{Origin: "https://api.warpmetal.example", NodeToken: "rtn_test"}
	reconciler := newRuntimeReconciler(store, containers.Podman{}, filepath.Join(root, "workspaces"), filepath.Join(root, "authorized_keys"), nil, model.Resources{}, "srv_insights0001", root, control, context.Background())
	if reconciler.Insights == nil {
		t.Fatal("ordinary runtime omitted policy fetch, durable outbox, and fixed monitor collector")
	}
}
