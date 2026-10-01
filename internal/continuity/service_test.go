package continuity

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
)

type registrySequence struct {
	workspaces []RegisteredWorkspace
	calls      int
}

func (r *registrySequence) Resolve(_ context.Context, identity model.ContinuityIdentityV1) (RegisteredWorkspace, error) {
	if r.calls >= len(r.workspaces) {
		return RegisteredWorkspace{}, errors.New("unexpected registry lookup")
	}
	workspace := r.workspaces[r.calls]
	r.calls++
	if workspace.Identity.WorkID != identity.WorkID || workspace.Identity.ProjectID != identity.ProjectID ||
		workspace.Identity.WorkspaceEpoch != identity.WorkspaceEpoch || workspace.Identity.SandboxID != identity.SandboxID {
		return RegisteredWorkspace{}, ErrTargetChanged
	}
	return workspace, nil
}

type fakeCaptureEngine struct {
	states       []containers.ContainerState
	pauseErr     error
	pauseCalls   int
	unpauseCalls int
	events       *[]string
	unpauseCtx   error
}

func (f *fakeCaptureEngine) InspectState(context.Context, string) (containers.ContainerState, error) {
	if len(f.states) == 0 {
		return "", errors.New("missing fake state")
	}
	state := f.states[0]
	if len(f.states) > 1 {
		f.states = f.states[1:]
	}
	return state, nil
}

func (f *fakeCaptureEngine) Pause(context.Context, string) error {
	f.pauseCalls++
	if f.events != nil {
		*f.events = append(*f.events, "engine.pause")
	}
	return f.pauseErr
}

func (f *fakeCaptureEngine) Unpause(ctx context.Context, _ string) error {
	f.unpauseCalls++
	f.unpauseCtx = ctx.Err()
	if f.events != nil {
		*f.events = append(*f.events, "engine.unpause")
	}
	return nil
}

type fakeObjects struct {
	capture            storage.DurableCapture
	captureErr         error
	verifyErr          error
	materialize        storage.MaterializeReceipt
	materializeRequest storage.MaterializeRequest
	events             *[]string
	captureHook        func()
}

func (f *fakeObjects) Capture(ctx context.Context, request storage.CaptureRequest) (storage.DurableCapture, error) {
	if f.captureHook != nil {
		f.captureHook()
	}
	if f.events != nil {
		*f.events = append(*f.events, "objects.capture")
	}
	if f.captureErr != nil {
		<-ctx.Done()
		return storage.DurableCapture{}, f.captureErr
	}
	return f.capture, nil
}

func (f *fakeObjects) Verify(context.Context, string) (storage.DurableCapture, error) {
	if f.verifyErr != nil {
		return storage.DurableCapture{}, f.verifyErr
	}
	return f.capture, nil
}

func (f *fakeObjects) Materialize(_ context.Context, request storage.MaterializeRequest) (storage.MaterializeReceipt, error) {
	f.materializeRequest = request
	return f.materialize, nil
}

func testIdentity(epoch string, generation int64) model.ContinuityIdentityV1 {
	taskID := "task_test12345"
	taskAttempt := int64(2)
	return model.ContinuityIdentityV1{
		WorkID: "work_test12345", ProjectID: "project_test12345", SandboxID: "sbx_test12345",
		WorkspaceEpoch: epoch, SandboxGeneration: generation, TaskID: &taskID,
		TaskAttempt: &taskAttempt, ExpectedRevision: 9,
	}
}

func testBoundaryBinding() BoundaryBindingV1 {
	return BoundaryBindingV1{
		BindingID: "binding_test12345", BindingRevision: 6,
		RegisteredSourceID: "source_test12345", ServiceRegistrationID: "service_test12345",
		NativeSessionID: "session_test12345", NativeProjectID: "native_project12345",
		NativeLocationDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666",
	}
}

func testWorkspace(identity model.ContinuityIdentityV1, root, lifecycle string) RegisteredWorkspace {
	return RegisteredWorkspace{
		Identity: identity, Root: root, Lifecycle: lifecycle, LifecycleRevision: 12,
		BoundaryBinding: testBoundaryBinding(),
	}
}

func openContinuityStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testCapture(identity model.ContinuityIdentityV1) storage.DurableCapture {
	return storage.DurableCapture{
		ID: "capture_test12345", ObjectID: "object_test12345",
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Manifest:       storage.CheckpointManifestV1{FormatVersion: 1, Identity: identity},
		Bytes:          42, ObjectCount: 3,
	}
}

func safeBoundary(identity model.ContinuityIdentityV1) SafeBoundaryReceiptV1 {
	return SafeBoundaryReceiptV1{
		ID: "boundary_test12345", Kind: "task", AcknowledgedAt: time.Date(2026, 9, 27, 16, 0, 0, 0, time.UTC),
		WorkID: identity.WorkID, WorkspaceEpoch: identity.WorkspaceEpoch,
		SandboxGeneration: identity.SandboxGeneration, TaskID: identity.TaskID, TaskAttempt: identity.TaskAttempt,
		Binding: testBoundaryBinding(),
	}
}

func TestCapturePersistsPauseIntentAndOwnershipBeforeFilesystemRead(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	root := t.TempDir()
	workspace := testWorkspace(identity, root, "running")
	events := []string{}
	engine := &fakeCaptureEngine{states: []containers.ContainerState{containers.ContainerRunning, containers.ContainerPaused}, events: &events}
	objects := &fakeObjects{capture: testCapture(identity), events: &events}
	store := openContinuityStore(t)
	service := Service{
		State: store, Objects: objects, Engine: engine,
		Registry:      &registrySequence{workspaces: []RegisteredWorkspace{workspace, workspace}},
		FreezeTimeout: 15 * time.Second,
		OnTransition:  func(state string) { events = append(events, "state."+state) },
	}
	receipt, err := service.Capture(context.Background(), CaptureRequestV1{
		OperationID: "continuity_op_12345", RequestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Identity: identity, SafeBoundary: safeBoundary(identity),
	})
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{"state.pausing", "engine.pause", "state.paused", "objects.capture", "engine.unpause"}
	positions := make([]int, len(wantOrder))
	for index, event := range wantOrder {
		positions[index] = -1
		for candidate, actual := range events {
			if actual == event {
				positions[index] = candidate
				break
			}
		}
	}
	for index := 1; index < len(positions); index++ {
		if positions[index-1] < 0 || positions[index] <= positions[index-1] {
			t.Fatalf("capture ordering = %#v, want ordered %#v", events, wantOrder)
		}
	}
	if receipt.CaptureID != objects.capture.ID || receipt.ManifestDigest != objects.capture.ManifestDigest {
		t.Fatalf("capture receipt = %#v", receipt)
	}
	operation, err := store.ContinuityOperation(context.Background(), "continuity_op_12345")
	if err != nil || operation == nil || operation.State != "captured" || operation.PauseOwned {
		t.Fatalf("completed capture operation = %#v %v", operation, err)
	}
	if accepted, err := store.AcceptedCheckpoint(context.Background(), identity.WorkID); err != nil || accepted != nil {
		t.Fatalf("capture advanced checkpoint pointer before Checkpoint: %#v %v", accepted, err)
	}
}

func TestCheckpointNamesDurableCaptureAndAdvancesPointerOnlyAfterVerification(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	store := openContinuityStore(t)
	capture := testCapture(identity)
	if err := store.PutContinuityCapture(context.Background(), state.LocalContinuityCapture{
		ID: capture.ID, Identity: identity, ObjectID: capture.ObjectID, ManifestDigest: capture.ManifestDigest,
		Bytes: capture.Bytes, ObjectCount: capture.ObjectCount, Verified: true,
	}); err != nil {
		t.Fatal(err)
	}
	objects := &fakeObjects{capture: capture}
	service := Service{State: store, Objects: objects}
	receipt, err := service.Checkpoint(context.Background(), CheckpointRequestV1{
		OperationID: "continuity_checkpoint_12345", RequestDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Identity: identity, CaptureID: capture.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.CaptureID != capture.ID || receipt.CheckpointID == "" || receipt.ManifestDigest != capture.ManifestDigest {
		t.Fatalf("checkpoint receipt = %#v", receipt)
	}
	accepted, err := store.AcceptedCheckpoint(context.Background(), identity.WorkID)
	if err != nil || accepted == nil || accepted.CaptureID != capture.ID || accepted.ID != receipt.CheckpointID {
		t.Fatalf("accepted pointer = %#v %v", accepted, err)
	}
	replayed, err := service.Checkpoint(context.Background(), CheckpointRequestV1{
		OperationID: "continuity_checkpoint_12345", RequestDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Identity: identity, CaptureID: capture.ID,
	})
	if err != nil || replayed.FormatVersion != receipt.FormatVersion ||
		replayed.OperationID != receipt.OperationID || replayed.CheckpointID != receipt.CheckpointID ||
		replayed.CaptureID != receipt.CaptureID || replayed.ManifestDigest != receipt.ManifestDigest ||
		!replayed.Identity.Equal(receipt.Identity) || replayed.Outcome != receipt.Outcome {
		t.Fatalf("idempotent checkpoint replay = %#v, %v; want %#v", replayed, err, receipt)
	}

	previousID := accepted.ID
	objects.verifyErr = errors.New("manifest object digest mismatch")
	_, err = service.Checkpoint(context.Background(), CheckpointRequestV1{
		OperationID: "continuity_checkpoint_67890", RequestDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		Identity: identity, CaptureID: capture.ID,
	})
	if err == nil {
		t.Fatal("corrupt capture was accepted")
	}
	accepted, _ = store.AcceptedCheckpoint(context.Background(), identity.WorkID)
	if accepted == nil || accepted.ID != previousID {
		t.Fatalf("failed verification changed prior pointer: %#v", accepted)
	}
}

func TestStoppedCaptureUsesAcceptedExecutionWithoutPausing(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	workspace := testWorkspace(identity, t.TempDir(), "stopped")
	engine := &fakeCaptureEngine{}
	objects := &fakeObjects{capture: testCapture(identity)}
	service := Service{
		State: openContinuityStore(t), Objects: objects, Engine: engine,
		Registry:      &registrySequence{workspaces: []RegisteredWorkspace{workspace}},
		FreezeTimeout: 15 * time.Second,
	}
	boundary := safeBoundary(identity)
	boundary.Kind = "stopped"
	executionID := "execution_test12345"
	boundary.LastAcceptedExecutionID = &executionID
	if _, err := service.Capture(context.Background(), CaptureRequestV1{
		OperationID: "continuity_op_stopped", RequestDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		Identity: identity, SafeBoundary: boundary,
	}); err != nil {
		t.Fatal(err)
	}
	if engine.pauseCalls != 0 || engine.unpauseCalls != 0 {
		t.Fatalf("stopped capture used pause lifecycle: %#v", engine)
	}
}

func TestInitialCaptureUsesNullTaskOnlyWithNoAdmittedExecutionProof(t *testing.T) {
	identity := testIdentity("epoch_initial123", 1)
	identity.TaskID = nil
	identity.TaskAttempt = nil
	workspace := testWorkspace(identity, t.TempDir(), "stopped")
	workspace.NoAdmittedExecution = true
	boundary := safeBoundary(identity)
	boundary.Kind = "initial"
	objects := &fakeObjects{capture: testCapture(identity)}
	service := Service{
		State: openContinuityStore(t), Objects: objects, Engine: &fakeCaptureEngine{},
		Registry: &registrySequence{workspaces: []RegisteredWorkspace{workspace}},
	}
	if _, err := service.Capture(context.Background(), CaptureRequestV1{
		OperationID: "continuity_op_initial", RequestDigest: "sha256:abababababababababababababababababababababababababababababababab",
		Identity: identity, SafeBoundary: boundary,
	}); err != nil {
		t.Fatal(err)
	}

	workspace.NoAdmittedExecution = false
	service = Service{
		State: openContinuityStore(t), Objects: objects, Engine: &fakeCaptureEngine{},
		Registry: &registrySequence{workspaces: []RegisteredWorkspace{workspace}},
	}
	_, err := service.Capture(context.Background(), CaptureRequestV1{
		OperationID: "continuity_op_initial_rejected", RequestDigest: "sha256:bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc",
		Identity: identity, SafeBoundary: boundary,
	})
	if !errors.Is(err, ErrSafeBoundaryRequired) {
		t.Fatalf("initial capture without no-execution proof = %v", err)
	}
}

func TestCaptureTimeoutUsesIndependentThawContext(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	workspace := testWorkspace(identity, t.TempDir(), "running")
	engine := &fakeCaptureEngine{states: []containers.ContainerState{containers.ContainerRunning, containers.ContainerPaused}}
	objects := &fakeObjects{captureErr: context.DeadlineExceeded}
	service := Service{
		State: openContinuityStore(t), Objects: objects, Engine: engine,
		Registry:      &registrySequence{workspaces: []RegisteredWorkspace{workspace, workspace}},
		FreezeTimeout: 5 * time.Millisecond, WatchdogTimeout: time.Second,
	}
	_, err := service.Capture(context.Background(), CaptureRequestV1{
		OperationID: "continuity_op_timeout", RequestDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		Identity: identity, SafeBoundary: safeBoundary(identity),
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capture error = %v", err)
	}
	if engine.unpauseCalls != 1 || engine.unpauseCtx != nil {
		t.Fatalf("watchdog thaw used cancelled capture context: calls=%d ctx=%v", engine.unpauseCalls, engine.unpauseCtx)
	}
}

func TestCaptureNeverThawsPreExistingOperatorPause(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	workspace := testWorkspace(identity, t.TempDir(), "running")
	engine := &fakeCaptureEngine{states: []containers.ContainerState{containers.ContainerPaused}}
	service := Service{
		State: openContinuityStore(t), Objects: &fakeObjects{capture: testCapture(identity)}, Engine: engine,
		Registry: &registrySequence{workspaces: []RegisteredWorkspace{workspace}}, FreezeTimeout: time.Second,
	}
	_, err := service.Capture(context.Background(), CaptureRequestV1{
		OperationID: "continuity_op_prepaused", RequestDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666",
		Identity: identity, SafeBoundary: safeBoundary(identity),
	})
	if !errors.Is(err, ErrPauseNotOwned) {
		t.Fatalf("pre-existing pause error = %v", err)
	}
	if engine.pauseCalls != 0 || engine.unpauseCalls != 0 {
		t.Fatalf("pre-existing pause was changed: %#v", engine)
	}
}

func TestRecoverAfterRestartThawsOnlyDurablyOwnedPause(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	database := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	operation := state.LocalContinuityOperation{
		ID: "continuity_op_restart", Kind: "capture", Identity: identity,
		RequestDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
		State:         "pending", Deadline: time.Now().UTC().Add(-time.Second),
	}
	if err := store.PutContinuityOperation(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(context.Background(), operation.ID, state.ContinuityTransition{
		From: "pending", To: "pausing",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(context.Background(), operation.ID, state.ContinuityTransition{
		From: "pausing", To: "paused", PauseOwned: true, PauseGeneration: identity.SandboxGeneration,
		PauseLifecycleRevision: 12,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	workspace := testWorkspace(identity, t.TempDir(), "running")
	engine := &fakeCaptureEngine{states: []containers.ContainerState{containers.ContainerPaused}}
	service := Service{
		State: reopened, Engine: engine,
		Registry:        &registrySequence{workspaces: []RegisteredWorkspace{workspace}},
		WatchdogTimeout: time.Second,
	}
	if err := service.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if engine.unpauseCalls != 1 || engine.unpauseCtx != nil {
		t.Fatalf("restart watchdog did not independently thaw owned pause: %#v", engine)
	}
	recovered, err := reopened.ContinuityOperation(context.Background(), operation.ID)
	if err != nil || recovered == nil || recovered.State != "failed" || recovered.PauseOwned ||
		recovered.ErrorCode != "capture_interrupted" {
		t.Fatalf("restart recovery outcome = %#v, %v", recovered, err)
	}
}

func TestRecoverLeavesAmbiguousPreOwnershipPauseFailClosed(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	store := openContinuityStore(t)
	operation := state.LocalContinuityOperation{
		ID: "continuity_op_ambiguous_restart", Kind: "capture", Identity: identity,
		RequestDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
		State:         "pending", Deadline: time.Now().UTC().Add(-time.Second),
	}
	if err := store.PutContinuityOperation(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(context.Background(), operation.ID, state.ContinuityTransition{
		From: "pending", To: "pausing",
	}); err != nil {
		t.Fatal(err)
	}
	engine := &fakeCaptureEngine{states: []containers.ContainerState{containers.ContainerPaused}}
	service := Service{State: store, Engine: engine, WatchdogTimeout: time.Second}
	if err := service.Recover(context.Background()); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("ambiguous recovery error = %v", err)
	}
	if engine.unpauseCalls != 0 {
		t.Fatal("restart recovery thawed a pause without durable ownership")
	}
	recovered, err := store.ContinuityOperation(context.Background(), operation.ID)
	if err != nil || recovered == nil || recovered.State != "recovery_required" || recovered.PauseOwned {
		t.Fatalf("ambiguous restart outcome = %#v, %v", recovered, err)
	}
}

func TestRecoverCompletesCheckpointVerificationWithoutRecapture(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	capture := testCapture(identity)
	store := openContinuityStore(t)
	if err := store.PutContinuityCapture(context.Background(), state.LocalContinuityCapture{
		ID: capture.ID, Identity: identity, ObjectID: capture.ObjectID,
		ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes,
		ObjectCount: capture.ObjectCount, Verified: true,
	}); err != nil {
		t.Fatal(err)
	}
	operation := state.LocalContinuityOperation{
		ID: "continuity_checkpoint_restart", Kind: "checkpoint", Identity: identity,
		RequestDigest: "sha256:8888888888888888888888888888888888888888888888888888888888888888",
		State:         "pending", Deadline: time.Now().UTC().Add(-time.Second),
	}
	if err := store.PutContinuityOperation(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(context.Background(), operation.ID, state.ContinuityTransition{
		From: "pending", To: "verifying", CaptureID: capture.ID,
	}); err != nil {
		t.Fatal(err)
	}
	checkpointID := stableID("checkpoint", operation.ID, capture.ID, capture.ManifestDigest)
	if err := store.AcceptCheckpoint(context.Background(), state.LocalCheckpoint{
		ID: checkpointID, CaptureID: capture.ID, Identity: identity,
		ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes, ObjectCount: capture.ObjectCount,
	}); err != nil {
		t.Fatal(err)
	}
	service := Service{State: store, Objects: &fakeObjects{capture: capture}}
	if err := service.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.ContinuityOperation(context.Background(), operation.ID)
	if err != nil || recovered == nil || recovered.State != "succeeded" || recovered.CheckpointID == "" {
		t.Fatalf("checkpoint recovery = %#v, %v", recovered, err)
	}
	accepted, err := store.AcceptedCheckpoint(context.Background(), identity.WorkID)
	if err != nil || accepted == nil || accepted.CaptureID != capture.ID {
		t.Fatalf("recovered accepted pointer = %#v, %v", accepted, err)
	}
}

func TestRecoverDoesNotReplayStoppedCaptureOrAmbiguousMaterialization(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	t.Run("stopped capture", func(t *testing.T) {
		store := openContinuityStore(t)
		operation := state.LocalContinuityOperation{
			ID: "continuity_stopped_restart", Kind: "capture", Identity: identity,
			RequestDigest: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
			State:         "pending", Deadline: time.Now().UTC().Add(-time.Second),
		}
		if err := store.PutContinuityOperation(context.Background(), operation); err != nil {
			t.Fatal(err)
		}
		if err := store.TransitionContinuityOperation(context.Background(), operation.ID, state.ContinuityTransition{
			From: "pending", To: "capturing",
		}); err != nil {
			t.Fatal(err)
		}
		service := Service{State: store, Objects: &fakeObjects{capture: testCapture(identity)}}
		if err := service.Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		recovered, _ := store.ContinuityOperation(context.Background(), operation.ID)
		if recovered == nil || recovered.State != "failed" || recovered.ErrorCode != "capture_interrupted" {
			t.Fatalf("stopped capture recovery = %#v", recovered)
		}
	})
	t.Run("materialization", func(t *testing.T) {
		store := openContinuityStore(t)
		operation := state.LocalContinuityOperation{
			ID: "continuity_materialize_restart", Kind: "materialize", Identity: identity,
			RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
			State:         "pending", Deadline: time.Now().UTC().Add(-time.Second),
		}
		if err := store.PutContinuityOperation(context.Background(), operation); err != nil {
			t.Fatal(err)
		}
		if err := store.TransitionContinuityOperation(context.Background(), operation.ID, state.ContinuityTransition{
			From: "pending", To: "materializing", CheckpointID: "checkpoint_test12345",
		}); err != nil {
			t.Fatal(err)
		}
		service := Service{State: store}
		if err := service.Recover(context.Background()); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("materialization recovery error = %v", err)
		}
		recovered, _ := store.ContinuityOperation(context.Background(), operation.ID)
		if recovered == nil || recovered.State != "recovery_required" || recovered.CheckpointID != "checkpoint_test12345" {
			t.Fatalf("materialization recovery = %#v", recovered)
		}
	})
}

func TestCaptureFailsClosedOnAmbiguousPauseOrLifecycleRevisionChange(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	workspace := testWorkspace(identity, t.TempDir(), "running")
	t.Run("ambiguous pause", func(t *testing.T) {
		engine := &fakeCaptureEngine{states: []containers.ContainerState{containers.ContainerRunning}, pauseErr: ErrPauseOutcomeUnknown}
		store := openContinuityStore(t)
		service := Service{State: store, Objects: &fakeObjects{capture: testCapture(identity)}, Engine: engine,
			Registry: &registrySequence{workspaces: []RegisteredWorkspace{workspace}}, FreezeTimeout: time.Second}
		_, err := service.Capture(context.Background(), CaptureRequestV1{
			OperationID: "continuity_op_ambiguous", RequestDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Identity: identity, SafeBoundary: safeBoundary(identity),
		})
		if !errors.Is(err, ErrPauseOutcomeUnknown) {
			t.Fatalf("capture error = %v", err)
		}
		if engine.unpauseCalls != 0 {
			t.Fatal("ambiguous pause response was thawed")
		}
	})
	t.Run("generation changed", func(t *testing.T) {
		changed := workspace
		changed.Identity.SandboxGeneration = 5
		engine := &fakeCaptureEngine{states: []containers.ContainerState{containers.ContainerRunning, containers.ContainerPaused}}
		store := openContinuityStore(t)
		service := Service{State: store, Objects: &fakeObjects{capture: testCapture(identity)}, Engine: engine,
			Registry: &registrySequence{workspaces: []RegisteredWorkspace{workspace, changed}}, FreezeTimeout: time.Second}
		_, err := service.Capture(context.Background(), CaptureRequestV1{
			OperationID: "continuity_op_changed", RequestDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			Identity: identity, SafeBoundary: safeBoundary(identity),
		})
		if !errors.Is(err, ErrTargetChanged) {
			t.Fatalf("capture error = %v", err)
		}
		if engine.unpauseCalls != 0 {
			t.Fatal("changed sandbox generation was thawed")
		}
	})
	t.Run("lifecycle revision changed", func(t *testing.T) {
		changed := workspace
		changed.LifecycleRevision++
		engine := &fakeCaptureEngine{states: []containers.ContainerState{containers.ContainerRunning, containers.ContainerPaused}}
		store := openContinuityStore(t)
		service := Service{State: store, Objects: &fakeObjects{capture: testCapture(identity)}, Engine: engine,
			Registry: &registrySequence{workspaces: []RegisteredWorkspace{workspace, changed}}, FreezeTimeout: time.Second}
		_, err := service.Capture(context.Background(), CaptureRequestV1{
			OperationID: "continuity_op_lifecycle_changed", RequestDigest: "sha256:2323232323232323232323232323232323232323232323232323232323232323",
			Identity: identity, SafeBoundary: safeBoundary(identity),
		})
		if !errors.Is(err, ErrTargetChanged) {
			t.Fatalf("capture error = %v", err)
		}
		if engine.unpauseCalls != 0 {
			t.Fatal("changed lifecycle revision was thawed")
		}
	})
}

func TestMaterializeRequiresNewRegistryDesignatedDestination(t *testing.T) {
	source := testIdentity("epoch_source123", 4)
	destination := testIdentity("epoch_destination123", 1)
	destination.WorkID = source.WorkID
	destination.ProjectID = source.ProjectID
	capture := testCapture(source)
	store := openContinuityStore(t)
	if err := store.PutContinuityCapture(context.Background(), state.LocalContinuityCapture{
		ID: capture.ID, Identity: source, ObjectID: capture.ObjectID, ManifestDigest: capture.ManifestDigest,
		Bytes: capture.Bytes, ObjectCount: capture.ObjectCount, Verified: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptCheckpoint(context.Background(), state.LocalCheckpoint{
		ID: "checkpoint_test12345", CaptureID: capture.ID, Identity: source,
		ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes, ObjectCount: capture.ObjectCount,
	}); err != nil {
		t.Fatal(err)
	}
	service := Service{
		State: store, Objects: &fakeObjects{capture: capture},
		Registry: &registrySequence{workspaces: []RegisteredWorkspace{{
			Identity: destination, Root: t.TempDir(), Lifecycle: "stopped", Fresh: true,
			Designation: "ordinary-workspace",
		}}},
	}
	_, err := service.Materialize(context.Background(), MaterializeRequestV1{
		OperationID: "continuity_materialize_12345", RequestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		SourceIdentity: source, DestinationIdentity: destination, CheckpointID: "checkpoint_test12345",
	})
	if !errors.Is(err, ErrDestinationNotDesignated) {
		t.Fatalf("arbitrary fresh workspace error = %v, want ErrDestinationNotDesignated", err)
	}
}

func TestMaterializePassesOnlyRegistryOwnedDestinationToObjectStore(t *testing.T) {
	source := testIdentity("epoch_source123", 4)
	destination := testIdentity("epoch_destination123", 1)
	capture := testCapture(source)
	store := openContinuityStore(t)
	if err := store.PutContinuityCapture(context.Background(), state.LocalContinuityCapture{
		ID: capture.ID, Identity: source, ObjectID: capture.ObjectID, ManifestDigest: capture.ManifestDigest,
		Bytes: capture.Bytes, ObjectCount: capture.ObjectCount, Verified: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptCheckpoint(context.Background(), state.LocalCheckpoint{
		ID: "checkpoint_test12345", CaptureID: capture.ID, Identity: source,
		ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes, ObjectCount: capture.ObjectCount,
	}); err != nil {
		t.Fatal(err)
	}
	destinationRoot := t.TempDir()
	objects := &fakeObjects{
		capture: capture,
		materialize: storage.MaterializeReceipt{
			ManifestDigest: capture.ManifestDigest, DestinationIdentity: destination,
			Bytes: capture.Bytes, ObjectCount: capture.ObjectCount,
		},
	}
	service := Service{
		State: store, Objects: objects,
		Registry: &registrySequence{workspaces: []RegisteredWorkspace{{
			Identity: destination, Root: destinationRoot, Lifecycle: "stopped", Fresh: true,
			Designation: MaterializeDesignation,
		}}},
	}
	receipt, err := service.Materialize(context.Background(), MaterializeRequestV1{
		OperationID: "continuity_materialize_67890", RequestDigest: "sha256:7777777777777777777777777777777777777777777777777777777777777777",
		SourceIdentity: source, DestinationIdentity: destination, CheckpointID: "checkpoint_test12345",
	})
	if err != nil {
		t.Fatal(err)
	}
	if objects.materializeRequest.DestinationRoot != destinationRoot ||
		!objects.materializeRequest.DestinationIdentity.Equal(destination) ||
		!objects.materializeRequest.SourceIdentity.Equal(source) {
		t.Fatalf("materialize escaped registry mapping: %#v", objects.materializeRequest)
	}
	if receipt.ManifestDigest != capture.ManifestDigest || !receipt.DestinationIdentity.Equal(destination) {
		t.Fatalf("materialize receipt = %#v", receipt)
	}
}

func TestContinuityReceiptsUseClosedCamelCaseJSON(t *testing.T) {
	receipt := CheckpointReceiptV1{
		FormatVersion: 1, OperationID: "continuity_checkpoint_12345", CheckpointID: "checkpoint_test12345",
		CaptureID: "capture_test12345", ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Identity: testIdentity("epoch_source123", 4), Outcome: "succeeded",
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"formatVersion", "operationId", "checkpointId", "captureId", "manifestDigest", "identity", "outcome"}
	gotKeys := make([]string, 0, len(decoded))
	for key := range decoded {
		gotKeys = append(gotKeys, key)
	}
	for _, key := range wantKeys {
		if _, exists := decoded[key]; !exists {
			t.Fatalf("receipt missing camelCase field %q: %s", key, payload)
		}
	}
	if len(gotKeys) != len(wantKeys) {
		t.Fatalf("receipt exposed unknown fields: %s", payload)
	}
	identity, ok := decoded["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity shape = %#v", decoded["identity"])
	}
	wantIdentityKeys := []string{"workId", "projectId", "sandboxId", "workspaceEpoch", "sandboxGeneration", "taskId", "taskAttempt", "expectedRevision"}
	actualIdentityKeys := make([]string, 0, len(identity))
	for key := range identity {
		actualIdentityKeys = append(actualIdentityKeys, key)
	}
	if len(actualIdentityKeys) != len(wantIdentityKeys) {
		t.Fatalf("identity exposed unknown fields: %s", payload)
	}
	for _, key := range wantIdentityKeys {
		if _, exists := identity[key]; !exists {
			t.Fatalf("identity missing %q: %s", key, payload)
		}
	}
}

func TestSafeBoundaryInitialReceiptUsesExactBindingAndNullTaskPair(t *testing.T) {
	identity := testIdentity("epoch_source123", 4)
	identity.TaskID = nil
	identity.TaskAttempt = nil
	receipt := safeBoundary(identity)
	receipt.Kind = "initial"
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{
		"id", "kind", "acknowledgedAt", "workId", "workspaceEpoch", "sandboxGeneration",
		"taskId", "taskAttempt", "lastAcceptedExecutionId", "binding",
	}
	if len(decoded) != len(wantKeys) {
		t.Fatalf("safe boundary exposed unknown fields: %s", payload)
	}
	for _, key := range wantKeys {
		if _, exists := decoded[key]; !exists {
			t.Fatalf("safe boundary missing %q: %s", key, payload)
		}
	}
	if decoded["taskId"] != nil || decoded["taskAttempt"] != nil || decoded["lastAcceptedExecutionId"] != nil {
		t.Fatalf("initial safe boundary invented execution identity: %s", payload)
	}
	binding, ok := decoded["binding"].(map[string]any)
	if !ok {
		t.Fatalf("safe boundary binding = %#v", decoded["binding"])
	}
	wantBindingKeys := []string{
		"bindingId", "bindingRevision", "registeredSourceId", "serviceRegistrationId",
		"nativeSessionId", "nativeProjectId", "nativeLocationDigest",
	}
	if len(binding) != len(wantBindingKeys) {
		t.Fatalf("safe boundary binding exposed unknown fields: %s", payload)
	}
	for _, key := range wantBindingKeys {
		if _, exists := binding[key]; !exists {
			t.Fatalf("safe boundary binding missing %q: %s", key, payload)
		}
	}
}
