package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// TestReconcileKeepsHistoricalHandoffAbsentFromCurrentIntentNonFatal pins the
// architecture 800/804 current-authority rule inside the existing
// reconcile/S2 fixture path: the complete fresh manifest owns one fully
// validated immutable current authority before any action recovery, recovery
// and reporting are scoped to that authority, and a retained ready handoff the
// current intent no longer carries is closed as current-unknown without being
// recovered, reported, probed, mutated or stopped. Independent current work
// still completes and the global revision closes on the validated manifest.
//
// The ready handoff and its registration rows are explicit preset fixture
// state (an honest unit preset, not a producer derivation); the real prior
// backend-acceptance provenance is the live r795/r798 evidence, which cannot
// be reset safely for repeatability.
func TestReconcileKeepsHistoricalHandoffAbsentFromCurrentIntentNonFatal(t *testing.T) {
	// The production Coordinator legitimately skips registration provisioning
	// when the environment has no managed-service row for the binding
	// ("Environments without a managed catalog cannot be provisioned here"),
	// so the acknowledged successor tuple itself is what this regression
	// advances and pins.
	setup := seedHandoffIsolationState(t, handoffIsolationOptions{skipSourceService: true})
	ctx := context.Background()

	// Honest unit preset completion: the retained handoff's source sandbox is
	// running at the stored generation, exactly as the live r795 source was.
	if err := setup.store.PutSandbox(ctx, state.LocalSandbox{
		ID: handoffIsolationSourceSandbox, Name: "source", DesiredState: "running", ObservedState: "running",
		Generation: setup.manifest.Identity.SandboxGeneration, ObservedGeneration: setup.manifest.Identity.SandboxGeneration,
		Lifetime: "persistent",
	}); err != nil {
		t.Fatal(err)
	}

	stored, err := setup.store.ContinuityRegistration(ctx, setup.manifest.Binding.BindingID)
	if err != nil || stored == nil {
		t.Fatalf("stored registration = %#v, %v", stored, err)
	}
	if stored.Manifest.Binding.BindingRevision != setup.manifest.Binding.BindingRevision {
		t.Fatalf("fixture registration revision = %d, want %d",
			stored.Manifest.Binding.BindingRevision, setup.manifest.Binding.BindingRevision)
	}

	// Legitimate higher binding revision, same scope: the acknowledged
	// successor tuple still matches the fresh source row exactly, so the real
	// Coordinator durably applies it without touching any handoff history.
	successor := stored.Manifest
	successor.Binding.BindingRevision = stored.Manifest.Binding.BindingRevision + 1
	coordinator := &continuity.Coordinator{
		Store: setup.store, Registry: continuity.StateRegistry{Store: setup.store},
		Now: func() time.Time { return time.Now().UTC() },
	}
	advance := isolationDesiredManifest()
	advance.ContinuityRegistrations = []model.ContinuityRegistrationV1{successor}
	if err := coordinator.Acknowledge(ctx, advance); err != nil {
		t.Fatalf("legitimate same-scope binding revision advance was refused: %v", err)
	}
	advanced, err := setup.store.ContinuityRegistration(ctx, setup.manifest.Binding.BindingID)
	if err != nil || advanced == nil ||
		advanced.Manifest.Binding.BindingRevision != successor.Binding.BindingRevision ||
		advanced.Manifest.ScopeRevision != stored.Manifest.ScopeRevision ||
		advanced.ObservedStatus != "verified" {
		t.Fatalf("successor registration did not durably verify: %#v, %v", advanced, err)
	}

	before := isolationPreparationState(t, setup.path, setup.manifest.OperationID)
	beforeHash := handoffPreparationDigest(before)

	engine := &fakeEngine{}
	reconciler := isolationReconciler(t, setup, engine)
	if err := reconciler.Reconcile(ctx, isolationDesiredManifest()); err != nil {
		t.Fatalf("retained historical handoff absent from the current intent aborted the pass: %v", err)
	}

	// Durable history stays byte-identical and the last validated successor
	// registration is untouched by the current-only recovery/report.
	after := isolationPreparationState(t, setup.path, setup.manifest.OperationID)
	if !reflect.DeepEqual(before, after) || handoffPreparationDigest(after) != beforeHash {
		t.Fatalf("current-only pass moved retained history: before=%#v after=%#v", before, after)
	}
	retained, err := setup.store.ContinuityRegistration(ctx, setup.manifest.Binding.BindingID)
	if err != nil || retained == nil ||
		retained.Manifest.Binding.BindingRevision != successor.Binding.BindingRevision ||
		retained.Manifest.ScopeRevision != successor.ScopeRevision ||
		retained.ObservedStatus != "verified" {
		t.Fatalf("current-only pass moved the validated owner registration: %#v, %v", retained, err)
	}
	if setup.supervisor.calls != 0 {
		t.Fatalf("historical absence reached a supervisor probe/stop: calls=%d", setup.supervisor.calls)
	}

	// Independent current work still completes and the global revision closes
	// on the fully validated manifest.
	if engine.created != 1 {
		t.Fatalf("historical absence blocked the manifest apply: created=%d", engine.created)
	}
	if applied, err := setup.store.Revision(ctx); err != nil || applied != isolationDesiredManifest().DesiredRevision {
		t.Fatalf("historical absence blocked the applied revision: %d, %v", applied, err)
	}
}

func handoffPreparationDigest(row isolationPreparationRow) string {
	sum := sha256.Sum256([]byte(row.Manifest + "\x00" + row.Phase + "\x00" + row.Selection + "\x00" + row.Report + "\x00" + row.UpdatedAt))
	return "sha256:" + hex.EncodeToString(sum[:])
}
