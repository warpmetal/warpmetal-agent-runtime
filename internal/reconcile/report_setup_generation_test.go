package reconcile

import (
	"context"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// After an owner redrive supersedes a failed setup operation and creates a new
// immutable generation, the local store still carries the old row. A report that
// includes the superseded tuple can never be accepted by the backend ("Setup
// tuple conflicts."), so the Runtime must report only the current manifest's
// setup operations and adopt the new generation on the same reconcile pass.
func TestReportEmitsOnlyCurrentManifestSetupGeneration(t *testing.T) {
	reconciler := cellReadyReconciler(t, &fakeEngine{cellReady: true})
	if err := reconciler.Reconcile(context.Background(), cellReadyManifest(1)); err != nil {
		t.Fatal(err)
	}
	put := func(id string) {
		t.Helper()
		if err := reconciler.Store.PutSetupOperation(context.Background(), state.LocalSetupOperation{
			ID: id, SandboxID: setupSandboxID, SandboxGeneration: 1,
			ProfileID: "opencode", ProfileRevision: 4,
			ProfileDigest:   "sha256:" + "a" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			DesiredRevision: 4, State: "pending", BodyDigest: "sha256:" + "b" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			RequestJSON: []byte(`{}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("setup_superseded0000001")
	put("setup_currentgeneration01")
	manifest := cellReadyManifest(4)
	manifest.SetupOperations = []model.SetupOperation{{
		ID: "setup_currentgeneration01", SandboxID: setupSandboxID, SandboxGeneration: 1,
		ProfileID: "opencode", ProfileRevision: 4,
		ProfileDigest: "sha256:" + "a" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}
	reconciler.currentAuthority = &manifest
	report, err := reconciler.Report(context.Background(), "srv_test12345", "0.1.52")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SetupOperations) != 1 || report.SetupOperations[0].ID != "setup_currentgeneration01" {
		t.Fatalf("report setup operations = %+v, want only the current generation", report.SetupOperations)
	}
	// A manifest with no setup operations keeps the legacy report shape.
	legacy := cellReadyManifest(5)
	reconciler.currentAuthority = &legacy
	report, err = reconciler.Report(context.Background(), "srv_test12345", "0.1.52")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SetupOperations) != 2 {
		t.Fatalf("legacy report setup operations = %d, want 2", len(report.SetupOperations))
	}
}
