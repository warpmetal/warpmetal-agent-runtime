package workspacecatalog

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func TestAllocateHandoffCreatesOneDurableExclusiveLeafAndReplaysAfterRestart(t *testing.T) {
	root := t.TempDir()
	anchor := filepath.Join(root, "workspace")
	if err := os.Mkdir(anchor, 0700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, "runtime.sqlite3")
	store, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	request := HandoffProjectRequest{
		OperationID: "op_handoff_catalog0001", Anchor: anchor, ServerID: "srv_handoffcatalog0001",
		SandboxID: "sbx_handoffcatalog0001", SandboxGeneration: 3,
		ServiceRegistrationID: "service_handoffcatalog0001",
	}
	allocated, err := (Catalog{State: store}).AllocateHandoff(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(allocated.HostRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("new handoff leaf was not empty: entries=%v err=%v", entries, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	replayed, err := (Catalog{State: reopened}).AllocateHandoff(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Report.SelectionID != allocated.Report.SelectionID || replayed.HostRoot != allocated.HostRoot ||
		replayed.ContainerRoot != allocated.ContainerRoot {
		t.Fatalf("replay allocated another target: first=%+v replay=%+v", allocated, replayed)
	}
	if err := os.WriteFile(filepath.Join(replayed.HostRoot, "materialized.txt"), []byte("checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	ready, err := (Catalog{State: reopened}).CompleteHandoff(context.Background(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Report.Availability != "available" || ready.Report.Designation != "continuity-handoff" ||
		ready.Report.ServiceRegistrationID == nil || *ready.Report.ServiceRegistrationID != request.ServiceRegistrationID {
		t.Fatalf("handoff target was not safely published: %+v", ready)
	}
}
