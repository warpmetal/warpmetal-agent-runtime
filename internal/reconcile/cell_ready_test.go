package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// cellReadyManifest returns a running cell-sandbox manifest with no setup
// operations (so the nested preflight never runs against the fake engine).
func cellReadyManifest(revision int64) model.Manifest {
	digest := "sha256:" + strings.Repeat("a", 64)
	return model.Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: revision,
		ImageDigest:     "registry.example/sandbox@" + digest,
		Capacity:        model.Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []model.Sandbox{{
			ID: setupSandboxID, Name: "cell", Size: "small",
			Resources:    model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			Lifetime:     "persistent",
			DesiredState: "running",
			Generation:   1,
			Cell:         true,
		}},
	}
}

func cellReadyReconciler(t *testing.T, engine *fakeEngine) *Reconciler {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return cellReadyReconcilerOn(t, store, engine)
}

// cellReadyReconcilerOn builds a fresh Reconciler over a retained store, which
// models a daemon restart re-observing the same durable sandbox rows.
func cellReadyReconcilerOn(t *testing.T, store *state.Store, engine *fakeEngine) *Reconciler {
	t.Helper()
	return &Reconciler{
		Store: store, Engine: engine, Workspaces: &fakeWorkspaces{}, Sessions: &fakeSessions{},
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		HostCapacity: model.Resources{CPUMillicores: 4000, MemoryMiB: 8192, WorkspaceDiskGiB: 80},
		ServerID:     "srv_test12345",
	}
}

// TestCellSandboxObservedWitnessReadinessIsPersistedAndReported proves the
// Runtime only reports cell readiness from the Engine's real witness
// observation, persists it on the local sandbox, and emits it on the report.
func TestCellSandboxObservedWitnessReadinessIsPersistedAndReported(t *testing.T) {
	engine := &fakeEngine{cellReady: true}
	reconciler := cellReadyReconciler(t, engine)
	if err := reconciler.Reconcile(context.Background(), cellReadyManifest(1)); err != nil {
		t.Fatal(err)
	}
	if engine.cellObserved != 1 {
		t.Fatalf("cell witness observed %d times, want 1", engine.cellObserved)
	}
	// The create path is unchanged: exactly one create, no transition
	// recreation, and readiness comes from the live observation.
	if engine.created != 1 || engine.recreated != 0 || engine.replaced != 0 {
		t.Fatalf("create path mutated the container lifecycle: %#v", engine)
	}
	local, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || local == nil {
		t.Fatalf("sandbox missing: %#v %v", local, err)
	}
	if !local.CellReady {
		t.Fatalf("observed cell readiness was not persisted: %#v", local)
	}
	report, err := reconciler.Report(context.Background(), "srv_test12345", "0.1.47")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Sandboxes) != 1 {
		t.Fatalf("report sandboxes = %d, want 1", len(report.Sandboxes))
	}
	if !report.Sandboxes[0].CellReady {
		t.Fatalf("report did not carry observed cell readiness: %#v", report.Sandboxes[0])
	}
	// The wire must serialize the exact `cellReady` boolean the backend gate
	// consumes.
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"cellReady":true`) {
		t.Fatalf("serialized report missing cellReady=true: %s", payload)
	}
}

// TestCellSandboxUnobservedWitnessFailsClosed proves an absent/replaced witness
// keeps cell readiness false (never derived from the desired cell flag) and the
// report omits the flag, so the backend clears observed_cell_ready.
func TestCellSandboxUnobservedWitnessFailsClosed(t *testing.T) {
	engine := &fakeEngine{cellReady: false}
	reconciler := cellReadyReconciler(t, engine)
	if err := reconciler.Reconcile(context.Background(), cellReadyManifest(1)); err != nil {
		t.Fatal(err)
	}
	if engine.cellObserved != 1 {
		t.Fatalf("cell witness observed %d times, want 1", engine.cellObserved)
	}
	local, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || local == nil {
		t.Fatalf("sandbox missing: %#v %v", local, err)
	}
	if local.CellReady {
		t.Fatalf("unobserved witness was reported ready: %#v", local)
	}
	report, err := reconciler.Report(context.Background(), "srv_test12345", "0.1.47")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "cellReady") {
		t.Fatalf("report must omit cellReady when not ready: %s", payload)
	}
}

// TestLegacySandboxNeverObservesOrReportsCellReadiness proves a non-cell
// sandbox neither triggers the witness observation nor reports readiness.
func TestLegacySandboxNeverObservesOrReportsCellReadiness(t *testing.T) {
	engine := &fakeEngine{cellReady: true}
	reconciler := cellReadyReconciler(t, engine)
	manifest := cellReadyManifest(1)
	manifest.Sandboxes[0].Cell = false
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if engine.cellObserved != 0 {
		t.Fatalf("legacy sandbox triggered witness observation %d times", engine.cellObserved)
	}
	local, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || local == nil {
		t.Fatalf("sandbox missing: %#v %v", local, err)
	}
	if local.CellReady {
		t.Fatalf("legacy sandbox reported cell readiness: %#v", local)
	}
}

// TestLegacySandboxCellTransitionRecreatesContainerWithWitness proves a legacy
// box enabled as a cell (same generation, same image) is re-created through the
// controlled Recreate path so the SA9 witness hook is applied, and the observed
// readiness is then persisted and reported. This is the concrete lifecycle
// semantics for the late-enable path (no silently stuck not-ready state).
func TestLegacySandboxCellTransitionRecreatesContainerWithWitness(t *testing.T) {
	engine := &fakeEngine{cellReady: true}
	reconciler := cellReadyReconciler(t, engine)

	legacy := cellReadyManifest(1)
	legacy.Sandboxes[0].Cell = false
	if err := reconciler.Reconcile(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	before, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || before == nil || before.Cell || before.CellReady {
		t.Fatalf("legacy sandbox was not established as non-cell: %#v %v", before, err)
	}
	if engine.recreated != 0 {
		t.Fatalf("legacy sandbox triggered a recreation: %#v", engine)
	}

	enabled := cellReadyManifest(2)
	if err := reconciler.Reconcile(context.Background(), enabled); err != nil {
		t.Fatal(err)
	}
	after, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || after == nil {
		t.Fatalf("cell-enabled sandbox missing: %#v %v", after, err)
	}
	if engine.recreated != 1 {
		t.Fatalf("cell transition did not recreate the container exactly once: %#v", engine)
	}
	if !after.Cell || !after.CellReady {
		t.Fatalf("cell transition did not converge to ready: %#v", after)
	}

	// A re-reconcile of the already-cell sandbox must NOT recreate again.
	if err := reconciler.Reconcile(context.Background(), enabled); err != nil {
		t.Fatal(err)
	}
	if engine.recreated != 1 {
		t.Fatalf("already-cell sandbox re-triggered recreation: %#v", engine)
	}
}

// TestLegacySandboxCellTransitionFailsClosedOnRecreateFailure proves a failed
// controlled replacement keeps the cell not-ready (fail closed) and surfaces an
// explicit failed state rather than silently admitting a witness-less container.
func TestLegacySandboxCellTransitionFailsClosedOnRecreateFailure(t *testing.T) {
	engine := &fakeEngine{cellReady: true, replaceErr: errors.New("recreate failed")}
	reconciler := cellReadyReconciler(t, engine)
	legacy := cellReadyManifest(1)
	legacy.Sandboxes[0].Cell = false
	if err := reconciler.Reconcile(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	enabled := cellReadyManifest(2)
	if err := reconciler.Reconcile(context.Background(), enabled); err == nil {
		t.Fatal("cell transition reported success after recreate failed")
	}
	after, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || after == nil {
		t.Fatalf("sandbox missing after failed recreate: %#v %v", after, err)
	}
	if after.CellReady {
		t.Fatalf("failed recreate was reported ready: %#v", after)
	}
	if after.ObservedState != "failed" {
		t.Fatalf("failed recreate did not surface an explicit failed state: %#v", after)
	}
}

// TestCellReadyClearedOnStopTransition proves a previously-ready sandbox clears
// its readiness when stopped (never retains a stale true into a non-running
// state), and the report omits the flag.
func TestCellReadyClearedOnStopTransition(t *testing.T) {
	engine := &fakeEngine{cellReady: true}
	reconciler := cellReadyReconciler(t, engine)
	if err := reconciler.Reconcile(context.Background(), cellReadyManifest(1)); err != nil {
		t.Fatal(err)
	}
	ready, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || ready == nil || !ready.CellReady {
		t.Fatalf("sandbox not established ready: %#v %v", ready, err)
	}
	stopped := cellReadyManifest(2)
	stopped.Sandboxes[0].DesiredState = "stopped"
	if err := reconciler.Reconcile(context.Background(), stopped); err != nil {
		t.Fatal(err)
	}
	after, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || after == nil || after.CellReady {
		t.Fatalf("stopped sandbox retained readiness: %#v %v", after, err)
	}
	report, err := reconciler.Report(context.Background(), "srv_test12345", "0.1.47")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "cellReady") {
		t.Fatalf("report emitted cellReady for a stopped sandbox: %s", payload)
	}
}

// TestCellTransitionRetriesAfterRecreationFailure proves a failed transition
// does not consume the cell flag, so a later replay of the same desired
// authority retries the recreation exactly once and converges.
func TestCellTransitionRetriesAfterRecreationFailure(t *testing.T) {
	engine := &fakeEngine{cellReady: true, replaceErr: errors.New("recreate failed")}
	reconciler := cellReadyReconciler(t, engine)
	legacy := cellReadyManifest(1)
	legacy.Sandboxes[0].Cell = false
	if err := reconciler.Reconcile(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	enabled := cellReadyManifest(2)
	if err := reconciler.Reconcile(context.Background(), enabled); err == nil {
		t.Fatal("cell transition reported success after recreate failed")
	}
	failed, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || failed == nil || failed.Cell {
		t.Fatalf("transition was consumed despite failed recreation: %#v %v", failed, err)
	}
	// Repair and replay the SAME desired authority.
	engine.replaceErr = nil
	if err := reconciler.Reconcile(context.Background(), enabled); err != nil {
		t.Fatal(err)
	}
	// One failed recreation attempt (rolled back) plus one successful attempt.
	if engine.recreated != 2 {
		t.Fatalf("recreate count = %d, want 2 (one failed + one success)", engine.recreated)
	}
	after, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || after == nil || !after.Cell || !after.CellReady {
		t.Fatalf("transition did not converge after retry: %#v %v", after, err)
	}
	// A further reconcile must not recreate again.
	if err := reconciler.Reconcile(context.Background(), enabled); err != nil {
		t.Fatal(err)
	}
	if engine.recreated != 2 {
		t.Fatalf("converged transition re-triggered recreation: %#v", engine)
	}
}

// TestStoppedSandboxCellTransitionAppliesOnStart proves enabling cell while a
// legacy box is stopped does not recreate while stopped, but applies the
// controlled recreation with the witness when the box is later started.
func TestStoppedSandboxCellTransitionAppliesOnStart(t *testing.T) {
	engine := &fakeEngine{cellReady: true}
	reconciler := cellReadyReconciler(t, engine)

	legacy := cellReadyManifest(1)
	legacy.Sandboxes[0].Cell = false
	if err := reconciler.Reconcile(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	stopped := cellReadyManifest(2)
	stopped.Sandboxes[0].Cell = false
	stopped.Sandboxes[0].DesiredState = "stopped"
	if err := reconciler.Reconcile(context.Background(), stopped); err != nil {
		t.Fatal(err)
	}

	enableStopped := cellReadyManifest(3)
	enableStopped.Sandboxes[0].DesiredState = "stopped"
	if err := reconciler.Reconcile(context.Background(), enableStopped); err != nil {
		t.Fatal(err)
	}
	if engine.recreated != 0 {
		t.Fatalf("stopped transition recreated the container: %#v", engine)
	}

	start := cellReadyManifest(4)
	if err := reconciler.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if engine.recreated != 1 {
		t.Fatalf("start after stopped transition did not recreate exactly once: %#v", engine)
	}
	after, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || after == nil || !after.Cell || !after.CellReady {
		t.Fatalf("stopped->cell->start did not converge to ready: %#v %v", after, err)
	}
}

// TestCellTransitionHoldsOnActiveCellExecution proves the legacy->cell
// transition does NOT stop/rename/recreate the container while an authoritative
// cell execution is running/pending/unknown. It surfaces an explicit hold
// reason and leaves the cell flag uncommitted (so a later drain retries).
func TestCellTransitionHoldsOnActiveCellExecution(t *testing.T) {
	engine := &fakeEngine{cellReady: true}
	reconciler := cellReadyReconciler(t, engine)

	legacy := cellReadyManifest(1)
	legacy.Sandboxes[0].Cell = false
	if err := reconciler.Reconcile(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	// Seed an authoritative pending (non-terminal) cell execution for this box.
	if err := reconciler.Store.PutCellOperation(context.Background(), state.LocalCellOperation{
		Entry: model.ManagedServiceV2{OperationID: "op_cellactive01", SandboxID: setupSandboxID},
		Phase: "pending",
	}); err != nil {
		t.Fatal(err)
	}

	enabled := cellReadyManifest(2)
	if err := reconciler.Reconcile(context.Background(), enabled); err != nil {
		t.Fatal(err)
	}
	// No container mutation: no recreate/stop/remove/ensure.
	if engine.recreated != 0 || engine.stopped != 0 || engine.removed != 0 || engine.created != 1 {
		t.Fatalf("held transition mutated the container: %#v", engine)
	}
	after, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || after == nil {
		t.Fatalf("sandbox missing: %#v %v", after, err)
	}
	if after.ErrorCode != "cell_transition_work_pending" || after.ErrorMessage == "" {
		t.Fatalf("hold did not surface the explicit reason: %#v", after)
	}
	if after.Cell || after.CellReady {
		t.Fatalf("held transition committed cell or readiness: %#v", after)
	}
}

// TestCellTransitionHoldsOnBusyManagedWorker proves the drain fence also holds
// for a legacy Team worker that is busy with a task (authoritative managed task
// authority), not only for a cell execution.
func TestCellTransitionHoldsOnBusyManagedWorker(t *testing.T) {
	engine := &fakeEngine{cellReady: true}
	reconciler := cellReadyReconciler(t, engine)

	legacy := cellReadyManifest(1)
	legacy.Sandboxes[0].Cell = false
	if err := reconciler.Reconcile(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	// Seed a busy legacy Team worker authority for this sandbox's service.
	taskID := "task_active0001"
	attempt := int64(3)
	if err := reconciler.Store.PutManagedTaskAuthority(context.Background(), state.LocalManagedTaskAuthority{
		ServiceRegistrationID: "svc_legacyworker01",
		ServiceGeneration:     1,
		SandboxGeneration:     1,
		TaskID:                &taskID,
		TaskAttempt:           &attempt,
		Busy:                  true,
		ObservedAt:            time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	// A matching managed service row carries the sandbox identity.
	if err := reconciler.Store.PutManagedServiceIntent(context.Background(), state.LocalManagedService{
		Manifest: model.ManagedServiceV1{
			Identity: model.ManagedServiceIdentityV1{
				SandboxID: setupSandboxID, SandboxGeneration: 1,
				ServiceRegistrationID:     "svc_legacyworker01",
				ExpectedServiceGeneration: 1,
				Instance:                  "default",
				Role:                      "worker",
			},
			ConfigDigest:    "sha256:" + strings.Repeat("a", 64),
			OperationID:     "op_legacyworker01",
			ActionRevision:  1,
			DesiredRevision: 1,
			DesiredState:    "active",
			SessionMode:     "create_initial",
			Profile:         model.ManagedServiceProfileV1{ProfileDigest: "sha256:" + strings.Repeat("a", 64)},
			Instructions:    model.ManagedServiceInstructionsV1{InstructionRevision: 1, InstructionDigest: "sha256:" + strings.Repeat("a", 64)},
			Workspace:       model.ManagedServiceWorkspaceV1{Designation: "team_project"},
		},
		Phase:             "ready",
		ProcessInstance:   "wmsup-default-0001",
		Port:              18443,
		ServiceGeneration: 1,
	}); err != nil {
		t.Fatal(err)
	}

	enabled := cellReadyManifest(2)
	if err := reconciler.Reconcile(context.Background(), enabled); err != nil {
		t.Fatal(err)
	}
	if engine.recreated != 0 || engine.stopped != 0 {
		t.Fatalf("held transition mutated the container: %#v", engine)
	}
	after, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || after == nil || after.ErrorCode != "cell_transition_work_pending" {
		t.Fatalf("busy-worker hold did not surface the reason: %#v %v", after, err)
	}
}

// TestAdoptedRunningCellWitnessIsObservedInPlace proves the Runtime re-observes
// an already-running container when the cell authority arrives late (daemon
// restart / desired_revision bump / venue adoption) and commits readiness from
// that live witness without destroying the container. This is the defect WP-52
// step 8 hit: the container carried the reviewed SA9 witness, but the Runtime
// only ever observed readiness on a create/transition pass, so a valid adopted
// cell stayed cellReady=0. A busy sandbox must adopt too: adoption mutates
// nothing, so the drain fence that guards a destructive recreate does not apply.
func TestAdoptedRunningCellWitnessIsObservedInPlace(t *testing.T) {
	for name, active := range map[string]bool{
		"quiescent":        false,
		"active-cell-work": true,
	} {
		t.Run(name, func(t *testing.T) {
			engine := &fakeEngine{cellReady: true}
			reconciler := cellReadyReconciler(t, engine)
			// 1. The Runtime created this sandbox as a LEGACY box: no cell
			// authority had arrived yet, so the stored cell flag is false.
			legacy := cellReadyManifest(1)
			legacy.Sandboxes[0].Cell = false
			if err := reconciler.Reconcile(context.Background(), legacy); err != nil {
				t.Fatal(err)
			}
			before, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
			if err != nil || before == nil || before.Cell || before.CellReady {
				t.Fatalf("legacy container was not established as non-cell: %#v %v", before, err)
			}
			// 2. The SAME running container is now a valid SA9 cell (the venue
			// re-created it with the reviewed precreate hook, or a previous
			// Runtime process created it before the local cell flag settled).
			// No Runtime create/recreate owns this witness.
			engine.cellContainer = true
			if active {
				if err := reconciler.Store.PutCellOperation(context.Background(), state.LocalCellOperation{
					Entry: model.ManagedServiceV2{OperationID: "op_adoptedcell01", SandboxID: setupSandboxID},
					Phase: "pending",
				}); err != nil {
					t.Fatal(err)
				}
			}
			// 3. A desired_revision bump delivers the cell authority.
			enabled := cellReadyManifest(2)
			if err := reconciler.Reconcile(context.Background(), enabled); err != nil {
				t.Fatal(err)
			}
			after, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
			if err != nil || after == nil {
				t.Fatalf("sandbox missing after cell authority: %#v %v", after, err)
			}
			if !after.Cell || !after.CellReady {
				t.Fatalf("adopted running cell witness was not observed and committed: %#v", after)
			}
			if after.ObservedState != "running" || after.ErrorCode != "" {
				t.Fatalf("adoption left the sandbox in a held/failed state: %#v", after)
			}
			// Adoption is in place: the witnessed mount namespace is preserved.
			if engine.recreated != 0 || engine.stopped != 0 || engine.removed != 0 {
				t.Fatalf("adoption mutated the running container: %#v", engine)
			}
			if engine.lifecycleVerified == 0 {
				t.Fatal("adoption did not re-run the fail-closed cell-lifecycle verification")
			}
			if engine.cellObserved == 0 {
				t.Fatal("adoption did not re-observe the SA9 witness")
			}
			// The wire carries the exact observed readiness the backend gate
			// consumes, so observed_cell_ready can become true.
			report, err := reconciler.Report(context.Background(), "srv_test12345", "0.1.52")
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(payload), `"cellReady":true`) {
				t.Fatalf("adopted cell report omitted cellReady=true: %s", payload)
			}
		})
	}
}

// TestAdoptedRunningCellWitnessFailsClosed proves an adopted running container
// whose SA9 witness is missing or tampered with is never admitted: the Runtime
// does not adopt it, still runs the controlled cell recreation, and commits
// readiness only from the live observation (false here).
func TestAdoptedRunningCellWitnessFailsClosed(t *testing.T) {
	for name, state := range map[string]struct {
		container bool
		ready     bool
	}{
		"missing-witness":  {container: false, ready: false},
		"tampered-witness": {container: true, ready: false},
	} {
		t.Run(name, func(t *testing.T) {
			engine := &fakeEngine{cellReady: state.ready}
			reconciler := cellReadyReconciler(t, engine)
			legacy := cellReadyManifest(1)
			legacy.Sandboxes[0].Cell = false
			if err := reconciler.Reconcile(context.Background(), legacy); err != nil {
				t.Fatal(err)
			}
			engine.cellContainer = state.container
			enabled := cellReadyManifest(2)
			if err := reconciler.Reconcile(context.Background(), enabled); err != nil {
				t.Fatal(err)
			}
			after, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
			if err != nil || after == nil {
				t.Fatalf("sandbox missing: %#v %v", after, err)
			}
			if after.CellReady {
				t.Fatalf("missing/tampered witness was admitted as ready: %#v", after)
			}
			if engine.cellObserved == 0 {
				t.Fatal("the transition never observed the existing container")
			}
			// Without an adoptable witness the controlled replacement still
			// runs, so the fail-closed path is unchanged.
			if engine.recreated != 1 {
				t.Fatalf("witness-less transition bypassed the controlled recreate: %#v", engine)
			}
			report, err := reconciler.Report(context.Background(), "srv_test12345", "0.1.52")
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(payload), "cellReady") {
				t.Fatalf("witness-less report emitted cellReady: %s", payload)
			}
		})
	}
}

// TestCellRevisionBumpReobservesAdoptedRunningCell proves a daemon restart and
// every later desired_revision bump re-observe the already-running cell
// container rather than trusting a stored flag: a witness that disappears
// clears readiness (fail closed) and a restored witness re-admits it.
func TestCellRevisionBumpReobservesAdoptedRunningCell(t *testing.T) {
	engine := &fakeEngine{cellReady: true}
	reconciler := cellReadyReconciler(t, engine)
	if err := reconciler.Reconcile(context.Background(), cellReadyManifest(1)); err != nil {
		t.Fatal(err)
	}
	ready, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || ready == nil || !ready.CellReady {
		t.Fatalf("cell container was not established ready: %#v %v", ready, err)
	}
	// Daemon restart: a fresh Reconciler process over the same durable rows.
	restarted := cellReadyReconcilerOn(t, reconciler.Store, engine)
	// The witness is gone/replaced in the current mount namespace.
	engine.cellReady = false
	observedBefore := engine.cellObserved
	if err := restarted.Reconcile(context.Background(), cellReadyManifest(1)); err != nil {
		t.Fatal(err)
	}
	if engine.cellObserved != observedBefore+1 {
		t.Fatalf("restart reconcile observed the witness %d times, want 1", engine.cellObserved-observedBefore)
	}
	tampered, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || tampered == nil || tampered.CellReady {
		t.Fatalf("restart kept a stale ready flag for an unobserved witness: %#v %v", tampered, err)
	}
	// A desired_revision bump re-observes again and re-admits the restored
	// witness on the SAME adopted running container (no recreation).
	engine.cellReady = true
	observedBefore = engine.cellObserved
	enabled := cellReadyManifest(2)
	if err := restarted.Reconcile(context.Background(), enabled); err != nil {
		t.Fatal(err)
	}
	if engine.cellObserved != observedBefore+1 {
		t.Fatalf("revision bump observed the witness %d times, want 1", engine.cellObserved-observedBefore)
	}
	after, err := reconciler.Store.Sandbox(context.Background(), setupSandboxID)
	if err != nil || after == nil || !after.Cell || !after.CellReady {
		t.Fatalf("revision bump did not re-observe the adopted cell: %#v %v", after, err)
	}
	if engine.recreated != 0 || engine.replaced != 0 {
		t.Fatalf("re-observation replaced an already-cell container: %#v", engine)
	}
}
