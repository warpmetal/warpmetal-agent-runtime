package reconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// Same normal accepted-result journey, including its original role/facts/file
// transport and SAME SQLite reopen. Only this SOURCE clock advances; no signed
// original or authority is rewritten and no real native time is simulated.
func runCompletedFactExpirySource(t *testing.T, f *firstTaskChildTerminalFixture, j *managerPolicyJourney) {
	t.Helper()
	ctx := context.Background()
	s := f.completion
	if s == nil || s.result == nil || s.results != 1 || s.facts.reports != 1 {
		t.Fatal("expiry requires original accepted result and current snapshot facts")
	}
	claim, e := j.reconciler.Store.OwnedContinuationClaim(ctx, f.entry.PreparationID, "completion-result")
	if e != nil || len(claim) == 0 {
		t.Fatal(e)
	}
	original, e := j.reconciler.Store.OwnedContinuationResult(ctx, f.entry.PreparationID, "completion-result", claim)
	if e != nil || len(original) == 0 {
		t.Fatal(e)
	}
	expires, e := time.Parse(time.RFC3339Nano, s.facts.op.ExpiresAt)
	if e != nil {
		t.Fatal(e)
	}
	roleEnd, e := time.Parse(time.RFC3339Nano, s.op.ExpiresAt)
	if e != nil {
		t.Fatal(e)
	}
	advanced := expires.Add(time.Second)
	if !advanced.Before(roleEnd) {
		t.Fatal("fact-only expiry fixture unexpectedly expires role")
	}
	app, e := j.reconciler.Store.WorkspaceApplication(ctx, s.runtime.parents[0].ApplicationOperationID)
	if e != nil || app == nil {
		t.Fatal(e)
	}
	appEnd, e := time.Parse(time.RFC3339Nano, app.Operation.ExpiresAt)
	if e != nil || !advanced.Before(appEnd) {
		t.Fatal("fact-only expiry fixture unexpectedly expires accepted application")
	}
	// Reopen the same journal before the clock-only observation. No changed
	// effect snapshot is introduced merely to give an expired proof a new key.
	if err := j.reconciler.Store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(j.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	j.reconciler.Store = reopened
	j.reconciler.ManagedCatalog.(*workspacecatalog.Catalog).State = reopened
	s.runtime.parentSourceRuntime.store = reopened
	beforeSnapshot := model.WorkspaceDigest(f.currentSnapshot())
	priorNow := j.reconciler.Now
	defer func() { j.reconciler.Now = priorNow }()
	j.reconciler.Now = func() time.Time { return advanced }
	err = j.reconciler.Reconcile(ctx, j.manifest)
	retained, e := j.reconciler.Store.OwnedContinuationResult(ctx, f.entry.PreparationID, "completion-result", claim)
	if e != nil || string(retained) != string(original) || model.WorkspaceDigest(f.currentSnapshot()) != beforeSnapshot || s.results != 1 || s.artifact.uploads != 1 || s.operations != 1 || s.enrollments != 1 {
		t.Fatal("expiry changed completed effect/history", e)
	}
	root, e := os.MkdirTemp(os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE"), "completed-facts-expiry-")
	if e != nil {
		t.Fatal(e)
	}
	errorText := ""
	if err != nil {
		errorText = err.Error()
	}
	raw := fixtureRaw(map[string]any{"classification": "normal first-task accepted-result SOURCE replay at expired first fact; current snapshot/role/app unchanged, no ROOT/native/backend acceptance claim", "firstResultRequest": json.RawMessage(claim), "firstResultReceipt": json.RawMessage(original), "expiredFactsOperation": s.facts.op, "observedNow": advanced.Format(time.RFC3339Nano), "stillCurrentRoleExpires": roleEnd.Format(time.RFC3339Nano), "stillCurrentApplicationExpires": appEnd.Format(time.RFC3339Nano), "snapshotDigest": beforeSnapshot, "roleOperations": s.operations, "enrollments": s.enrollments, "artifactUploads": s.artifact.uploads, "resultPOSTs": s.results, "factPOSTs": s.facts.reports, "error": errorText, "providers": 0, "nativeRuns": 0, "rootRuns": 0})
	if e = os.WriteFile(filepath.Join(root, "expired-facts-replay.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	t.Log("retained completed facts expiry SOURCE boundary", root)
	if err != nil {
		t.Fatalf("accepted original result replay re-admitted expired first facts despite unchanged current snapshot: %v", err)
	}
}
