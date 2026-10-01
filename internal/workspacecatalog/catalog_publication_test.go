package workspacecatalog

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// TestReportsWithholdPreAttestationAllocationIntents pins the publication rule
// for the two materialization allocations: the durable pre-attestation intent
// exists for recovery, but only an attested record may be published, and the
// ordinary Allocate call resumes the exact same target.
func TestReportsWithholdPreAttestationAllocationIntents(t *testing.T) {
	root := t.TempDir()
	anchor := filepath.Join(root, "workspace")
	if err := os.Mkdir(anchor, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(root, "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	catalog := Catalog{State: store}
	handoff := HandoffProjectRequest{
		OperationID: "op_handoff_publication0001", Anchor: anchor, ServerID: "srv_publication0001",
		SandboxID: "sbx_publication0001", SandboxGeneration: 1,
		ServiceRegistrationID: "service_publication0001",
	}
	restore := RestoreProjectRequest{
		OperationID: "op_restore_publication0001", Anchor: anchor, ServerID: "srv_publication0001",
		SandboxID: "sbx_publication0001", SandboxGeneration: 1,
	}

	beginHandoff, err := catalog.BeginHandoffAllocation(context.Background(), handoff)
	if err != nil {
		t.Fatal(err)
	}
	beginRestore, err := catalog.BeginRestoreAllocation(context.Background(), restore)
	if err != nil {
		t.Fatal(err)
	}
	if beginHandoff.Report.RootAttestation != "" || beginRestore.Report.RootAttestation != "" {
		t.Fatal("pre-attestation intents must not carry a root attestation")
	}
	pending, err := catalog.Reports(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pre-attestation allocation intents were published: %+v", pending)
	}

	allocatedHandoff, err := catalog.AllocateHandoff(context.Background(), handoff)
	if err != nil {
		t.Fatal(err)
	}
	allocatedRestore, err := catalog.AllocateRestore(context.Background(), restore)
	if err != nil {
		t.Fatal(err)
	}
	if allocatedHandoff.Report.SelectionID != beginHandoff.Report.SelectionID ||
		allocatedRestore.Report.SelectionID != beginRestore.Report.SelectionID {
		t.Fatal("allocation resume changed the durable target identity")
	}
	published, err := catalog.Reports(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(published) != 2 {
		t.Fatalf("attested materializations were withheld: %+v", published)
	}
	for _, report := range published {
		if report.RootAttestation == "" {
			t.Fatalf("published materialization has no attested root: %+v", report)
		}
		if report.Reason == nil || *report.Reason != "materialization_pending" {
			t.Fatalf("published materialization lost its pending reason: %+v", report)
		}
	}
}
