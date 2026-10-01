package continuity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
)

type s3ReleasedPreparationFixture struct {
	ContinuationManifest        model.ContinuationManifestV1               `json:"continuationManifest"`
	ContinuationReport          model.ContinuationReportV1                 `json:"continuationReport"`
	ContinuationReleaseManifest model.ContinuationReleaseManifestV1        `json:"continuationReleaseManifest"`
	ContinuationReleaseReport   model.ContinuationReleaseReportV1          `json:"continuationReleaseReport"`
	HandoffManifest             model.ContinuationHandoffManifestV1        `json:"restoredTargetManifest"`
	HandoffReport               model.ContinuationHandoffReportV1          `json:"restoredTargetReport"`
	HandoffReleaseManifest      model.ContinuationHandoffReleaseManifestV1 `json:"handoffReleaseManifest"`
	HandoffReleaseReport        model.ContinuationHandoffReleaseReportV1   `json:"handoffReleaseReport"`
}

func s3ReleasedPreparationFixtures(t *testing.T) s3ReleasedPreparationFixture {
	t.Helper()
	var fixture s3ReleasedPreparationFixture
	ordinary, err := os.ReadFile(filepath.Join("..", "api", "testdata", "agent-continuation-v1.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ordinary, &fixture); err != nil {
		t.Fatal(err)
	}
	handoff, err := os.ReadFile(filepath.Join("..", "api", "testdata", "agent-continuation-handoff-v1.backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(handoff, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func s3ContinuationIdentity(checkpoint state.LocalCheckpoint) model.ContinuationIdentityV1 {
	return model.ContinuationIdentityV1{
		WorkID: checkpoint.Identity.WorkID, ProjectID: checkpoint.Identity.ProjectID,
		SandboxID: checkpoint.Identity.SandboxID, WorkspaceEpoch: checkpoint.Identity.WorkspaceEpoch,
		SandboxGeneration: checkpoint.Identity.SandboxGeneration, ExpectedRevision: checkpoint.Identity.ExpectedRevision,
	}
}

func s3CheckpointReference(checkpoint state.LocalCheckpoint) model.ContinuationCheckpointRefV1 {
	return model.ContinuationCheckpointRefV1{
		OperationID: "capture_" + checkpoint.ID, CheckpointID: checkpoint.ID,
		ManifestDigest: checkpoint.ManifestDigest, Bytes: checkpoint.Bytes, ObjectCount: checkpoint.ObjectCount,
	}
}

func s3GitRepository(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.txt"), []byte("initial\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"init", "-b", "main"}, {"config", "user.name", "Runtime Test"},
		{"config", "user.email", "runtime@example.invalid"}, {"add", "state.txt"}, {"commit", "-m", "initial"},
	} {
		command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s: %v", arguments, output, err)
		}
	}
	return root
}

func s3Identity(workID, sandboxID string) model.ContinuityIdentityV1 {
	taskID, attempt := "task_"+workID, int64(1)
	return model.ContinuityIdentityV1{
		WorkID: workID, ProjectID: "project_" + workID, SandboxID: sandboxID,
		WorkspaceEpoch: "epoch_" + workID, SandboxGeneration: 1,
		TaskID: &taskID, TaskAttempt: &attempt, ExpectedRevision: 1,
	}
}

func s3SaveCheckpoint(t *testing.T, ctx context.Context, objects *storage.CheckpointStore, store *state.Store,
	root string, identity model.ContinuityIdentityV1, name string, createdAt time.Time, pinned bool,
) state.LocalCheckpoint {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "state.txt"), []byte(name+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	objects.Now = func() time.Time { return createdAt }
	capture, err := objects.Capture(ctx, storage.CaptureRequest{
		OperationID: "capture_op_" + name, Identity: identity, WorkspaceRoot: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuityCapture(ctx, state.LocalContinuityCapture{
		ID: capture.ID, Identity: identity, ObjectID: capture.ObjectID, ManifestDigest: capture.ManifestDigest,
		Bytes: capture.Bytes, ObjectCount: capture.ObjectCount, Verified: true, CreatedAt: createdAt,
	}); err != nil {
		t.Fatal(err)
	}
	checkpoint := state.LocalCheckpoint{
		ID: "checkpoint_" + name, CaptureID: capture.ID, Identity: identity, ManifestDigest: capture.ManifestDigest,
		Bytes: capture.Bytes, ObjectCount: capture.ObjectCount, Pinned: pinned, CreatedAt: createdAt,
	}
	if err := store.AcceptCheckpoint(ctx, checkpoint); err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func TestCheckpointLifecycleCollectsBoxHistoryAndRecoversDeletingIntent(t *testing.T) {
	ctx := context.Background()
	database := filepath.Join(t.TempDir(), "runtime.sqlite3")
	objects := &storage.CheckpointStore{Root: filepath.Join(t.TempDir(), "objects")}
	repository := s3GitRepository(t)
	store, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	sandboxID := "sbx_s3lifecycle0001"
	if err := store.SetCheckpointPolicy(ctx, sandboxID, state.CheckpointPolicy{
		MaxBytes: 1 << 30, MaxPerBox: 10, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	workA, workB, workC := s3Identity("work_s3alpha0001", sandboxID), s3Identity("work_s3bravo0001", sandboxID), s3Identity("work_s3charlie01", sandboxID)
	a1 := s3SaveCheckpoint(t, ctx, objects, store, repository, workA, "a1", base, false)
	a2 := s3SaveCheckpoint(t, ctx, objects, store, repository, workA, "a2", base.Add(time.Hour), false)
	b1 := s3SaveCheckpoint(t, ctx, objects, store, repository, workB, "b1", base, true)
	c1 := s3SaveCheckpoint(t, ctx, objects, store, repository, workC, "c1", base, false)
	c2 := s3SaveCheckpoint(t, ctx, objects, store, repository, workC, "c2", base.Add(time.Hour), false)
	if err := store.PutContinuityOperation(ctx, state.LocalContinuityOperation{
		ID: "materialize_s3_inflight", Kind: "materialize", Identity: c1.Identity,
		RequestDigest: "sha256:" + strings.Repeat("a", 64), State: "pending", Deadline: base.Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(ctx, "materialize_s3_inflight", state.ContinuityTransition{
		From: "pending", To: "materializing", CheckpointID: c1.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCheckpointPolicy(ctx, sandboxID, state.CheckpointPolicy{
		MaxBytes: 1 << 30, MaxPerBox: 4, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	planAt := base.Add(40 * 24 * time.Hour)
	lifecycle := &CheckpointLifecycle{
		State: store, Objects: *objects, Now: func() time.Time { return planAt }, GracePeriod: time.Hour, MaxPerPass: 32,
	}
	if err := lifecycle.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Verify(ctx, a1.CaptureID); err != nil {
		t.Fatalf("planning removed before grace: %v", err)
	}
	intents, err := store.CheckpointGCIntents(ctx)
	if err != nil || len(intents) != 1 || intents[0].CaptureID != a1.CaptureID || intents[0].Phase != "planned" {
		t.Fatalf("planned collection = %#v, %v", intents, err)
	}
	injected := errors.New("injected crash after durable delete fence")
	lifecycle.Now = func() time.Time { return planAt.Add(2 * time.Hour) }
	lifecycle.BeforeCollect = func(intent state.CheckpointGCIntent) error { return injected }
	if err := lifecycle.Run(ctx); !errors.Is(err, injected) {
		t.Fatalf("collection interruption = %v", err)
	}
	intents, err = store.CheckpointGCIntents(ctx)
	if err != nil || len(intents) != 1 || intents[0].Phase != "deleting" {
		t.Fatalf("durable delete fence = %#v, %v", intents, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered := &CheckpointLifecycle{
		State: reopened, Objects: *objects, Now: func() time.Time { return planAt.Add(3 * time.Hour) }, GracePeriod: time.Hour, MaxPerPass: 32,
	}
	if err := recovered.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Verify(ctx, a1.CaptureID); !errors.Is(err, storage.ErrCheckpointUnavailable) {
		t.Fatalf("eligible physical object still available: %v", err)
	}
	for _, protected := range []state.LocalCheckpoint{a2, b1, c1, c2} {
		if _, err := objects.Verify(ctx, protected.CaptureID); err != nil {
			t.Fatalf("protected %s removed: %v", protected.ID, err)
		}
	}
	if err := reopened.AcceptCheckpoint(ctx, a1); !errors.Is(err, state.ErrCheckpointUnavailable) {
		t.Fatalf("historical checkpoint resurrected: %v", err)
	}
	accepted, err := reopened.AcceptedCheckpoint(ctx, workA.WorkID)
	if err != nil || accepted == nil || accepted.ID != a2.ID {
		t.Fatalf("collection moved current pointer: %#v, %v", accepted, err)
	}
	// The four protected checkpoints consume the box count across three Work
	// records. A fourth Work may publish a capture, but checkpoint acceptance
	// fails atomically and cannot move an existing pointer.
	delta := s3Identity("work_s3delta0001", sandboxID)
	if err := os.WriteFile(filepath.Join(repository, "state.txt"), []byte("d1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	objects.Now = func() time.Time { return planAt }
	deltaCapture, err := objects.Capture(ctx, storage.CaptureRequest{
		OperationID: "capture_op_d1", Identity: delta, WorkspaceRoot: repository,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.PutContinuityCapture(ctx, state.LocalContinuityCapture{
		ID: deltaCapture.ID, Identity: delta, ObjectID: deltaCapture.ObjectID,
		ManifestDigest: deltaCapture.ManifestDigest, Bytes: deltaCapture.Bytes,
		ObjectCount: deltaCapture.ObjectCount, Verified: true, CreatedAt: planAt,
	}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.AcceptCheckpoint(ctx, state.LocalCheckpoint{
		ID: "checkpoint_d1", CaptureID: deltaCapture.ID, Identity: delta,
		ManifestDigest: deltaCapture.ManifestDigest, Bytes: deltaCapture.Bytes,
		ObjectCount: deltaCapture.ObjectCount, CreatedAt: planAt,
	}); !errors.Is(err, state.ErrCheckpointQuota) {
		t.Fatalf("box count quota = %v", err)
	}
	accepted, err = reopened.AcceptedCheckpoint(ctx, workA.WorkID)
	if err != nil || accepted == nil || accepted.ID != a2.ID {
		t.Fatalf("quota failure moved prior pointer: %#v, %v", accepted, err)
	}
}

func TestCheckpointLifecycleRetiresExactlyReleasedContinuationAndHandoffRoots(t *testing.T) {
	ctx := context.Background()
	database := filepath.Join(t.TempDir(), "runtime.sqlite3")
	objects := &storage.CheckpointStore{Root: filepath.Join(t.TempDir(), "objects")}
	repository := s3GitRepository(t)
	store, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	sandboxID := "sbx_s3releasedroot0001"
	if err := store.SetCheckpointPolicy(ctx, sandboxID, state.CheckpointPolicy{
		MaxBytes: 1 << 30, MaxPerBox: 10, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	source := s3Identity("work_s3releasedsource0001", sandboxID)
	inflight := s3Identity("work_s3releasepending001", sandboxID)
	a := s3SaveCheckpoint(t, ctx, objects, store, repository, source, "released_a", base, false)
	b := s3SaveCheckpoint(t, ctx, objects, store, repository, source, "current_b", base.Add(time.Hour), false)
	c := s3SaveCheckpoint(t, ctx, objects, store, repository, inflight, "inflight_c", base, false)
	d := s3SaveCheckpoint(t, ctx, objects, store, repository, inflight, "current_d", base.Add(time.Hour), false)
	failedIdentity := s3Identity("work_s3releasefailed0001", sandboxID)
	e := s3SaveCheckpoint(t, ctx, objects, store, repository, failedIdentity, "failed_e", base, false)
	f := s3SaveCheckpoint(t, ctx, objects, store, repository, failedIdentity, "current_f", base.Add(time.Hour), false)
	foreignIdentity := s3Identity("work_s3releaseforeign001", sandboxID)
	g := s3SaveCheckpoint(t, ctx, objects, store, repository, foreignIdentity, "foreign_g", base, false)
	h := s3SaveCheckpoint(t, ctx, objects, store, repository, foreignIdentity, "current_h", base.Add(time.Hour), false)
	fixture := s3ReleasedPreparationFixtures(t)

	ordinary := fixture.ContinuationManifest
	ordinary.OperationID = "op_s3_release_ordinary0001"
	ordinary.DesiredRevision = 40
	ordinary.Identity = s3ContinuationIdentity(a)
	ordinary.Checkpoint = s3CheckpointReference(a)
	ordinaryReport := fixture.ContinuationReport
	ordinaryReport.OperationID = ordinary.OperationID
	ordinaryReport.DesiredRevision = ordinary.DesiredRevision
	ordinaryReport.Identity = ordinary.Identity
	ordinaryReport.Binding = ordinary.Binding
	ordinaryReport.Checkpoint = ordinary.Checkpoint
	ordinaryReport.Target = ordinary.Target
	ordinaryReport.ContextDigest = ordinary.Context.Digest
	if err := store.PutContinuationPreparation(ctx, state.LocalContinuationPreparation{Manifest: ordinary, Phase: "preparing"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationPreparation(ctx, ordinary.OperationID, ordinaryReport); err != nil {
		t.Fatal(err)
	}
	ordinaryRelease := fixture.ContinuationReleaseManifest
	ordinaryRelease.OperationID = ordinary.OperationID
	ordinaryRelease.DesiredRevision = ordinary.DesiredRevision + 1
	ordinaryRelease.Identity = ordinary.Identity
	ordinaryRelease.Binding = ordinary.Binding
	ordinaryRelease.Checkpoint = ordinary.Checkpoint
	ordinaryRelease.Target = ordinary.Target
	ordinaryRelease.Context = ordinary.Context
	ordinaryReleaseReport := fixture.ContinuationReleaseReport
	ordinaryReleaseReport.OperationID = ordinaryRelease.OperationID
	ordinaryReleaseReport.DesiredRevision = ordinaryRelease.DesiredRevision
	ordinaryReleaseReport.Identity = ordinaryRelease.Identity
	ordinaryReleaseReport.Binding = ordinaryRelease.Binding
	ordinaryReleaseReport.Checkpoint = ordinaryRelease.Checkpoint
	ordinaryReleaseReport.Target = ordinaryRelease.Target
	ordinaryReleaseReport.Context = ordinaryRelease.Context
	ordinaryReleaseReport.Reason = ordinaryRelease.Reason
	if err := store.PutContinuationRelease(ctx, state.LocalContinuationRelease{Manifest: ordinaryRelease, Phase: "releasing"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationRelease(ctx, ordinaryRelease.OperationID, ordinaryReleaseReport); err != nil {
		t.Fatal(err)
	}

	handoff := fixture.HandoffManifest
	handoff.OperationID = "op_s3_release_handoff_prepare0001"
	handoff.DesiredRevision = 50
	handoff.Identity = s3ContinuationIdentity(a)
	handoff.Checkpoint = s3CheckpointReference(a)
	handoff.Lineage.CheckpointOperationID = handoff.Checkpoint.OperationID
	handoffReport := fixture.HandoffReport
	handoffReport.OperationID = handoff.OperationID
	handoffReport.DesiredRevision = handoff.DesiredRevision
	handoffReport.Identity = handoff.Identity
	handoffReport.Binding = handoff.Binding
	handoffReport.Checkpoint = handoff.Checkpoint
	handoffReport.Lineage = handoff.Lineage
	handoffReport.TargetPolicy = handoff.TargetPolicy
	handoffReport.WorkspaceRequest = handoff.Workspace
	handoffReport.ContextDigest = handoff.Context.Digest
	if err := store.PutContinuationHandoffPreparation(ctx, state.LocalContinuationHandoffPreparation{Manifest: handoff, Phase: "allocating"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationHandoffPreparation(ctx, handoff.OperationID,
		handoffReport.TargetWorkspace.SelectionID, handoffReport); err != nil {
		t.Fatal(err)
	}
	handoffRelease := fixture.HandoffReleaseManifest
	handoffRelease.OperationID = "op_s3_release_handoff0001"
	handoffRelease.DesiredRevision = handoff.DesiredRevision + 1
	handoffRelease.PrepareDesiredRevision = handoff.DesiredRevision
	handoffRelease.HandoffKind = handoff.HandoffKind
	handoffRelease.SessionMode = handoff.SessionMode
	handoffRelease.TargetWorkID = handoff.TargetWorkID
	handoffRelease.MappingID = handoff.MappingID
	handoffRelease.Identity = handoff.Identity
	handoffRelease.Binding = handoff.Binding
	handoffRelease.Checkpoint = handoff.Checkpoint
	handoffRelease.Lineage = handoff.Lineage
	handoffRelease.TargetPolicy = handoff.TargetPolicy
	handoffRelease.Workspace = handoff.Workspace
	handoffRelease.Context = handoff.Context
	handoffReleaseReport := fixture.HandoffReleaseReport
	handoffReleaseReport.ContinuationHandoffReleaseManifestV1 = handoffRelease
	if err := store.PutContinuationHandoffRelease(ctx, state.LocalContinuationHandoffRelease{Manifest: handoffRelease, Phase: "releasing"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationHandoffRelease(ctx, handoffRelease.OperationID, handoffReleaseReport); err != nil {
		t.Fatal(err)
	}

	pending := ordinary
	pending.OperationID = "op_s3_release_uncertain0001"
	pending.DesiredRevision = 60
	pending.Identity = s3ContinuationIdentity(c)
	pending.Checkpoint = s3CheckpointReference(c)
	pendingReport := ordinaryReport
	pendingReport.OperationID = pending.OperationID
	pendingReport.DesiredRevision = pending.DesiredRevision
	pendingReport.Identity = pending.Identity
	pendingReport.Checkpoint = pending.Checkpoint
	if err := store.PutContinuationPreparation(ctx, state.LocalContinuationPreparation{Manifest: pending, Phase: "preparing"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationPreparation(ctx, pending.OperationID, pendingReport); err != nil {
		t.Fatal(err)
	}
	pendingRelease := ordinaryRelease
	pendingRelease.OperationID = pending.OperationID
	pendingRelease.DesiredRevision = pending.DesiredRevision + 1
	pendingRelease.Identity = pending.Identity
	pendingRelease.Checkpoint = pending.Checkpoint
	if err := store.PutContinuationRelease(ctx, state.LocalContinuationRelease{Manifest: pendingRelease, Phase: "releasing"}); err != nil {
		t.Fatal(err)
	}
	failed := ordinary
	failed.OperationID = "op_s3_release_failed0001"
	failed.DesiredRevision = 70
	failed.Identity = s3ContinuationIdentity(e)
	failed.Checkpoint = s3CheckpointReference(e)
	failedReport := ordinaryReport
	failedReport.OperationID = failed.OperationID
	failedReport.DesiredRevision = failed.DesiredRevision
	failedReport.Identity = failed.Identity
	failedReport.Checkpoint = failed.Checkpoint
	if err := store.PutContinuationPreparation(ctx, state.LocalContinuationPreparation{Manifest: failed, Phase: "preparing"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationPreparation(ctx, failed.OperationID, failedReport); err != nil {
		t.Fatal(err)
	}
	failedRelease := ordinaryRelease
	failedRelease.OperationID = failed.OperationID
	failedRelease.DesiredRevision = failed.DesiredRevision + 1
	failedRelease.Identity = failed.Identity
	failedRelease.Checkpoint = failed.Checkpoint
	failedReleaseReport := ordinaryReleaseReport
	failedReleaseReport.OperationID = failedRelease.OperationID
	failedReleaseReport.DesiredRevision = failedRelease.DesiredRevision
	failedReleaseReport.Identity = failedRelease.Identity
	failedReleaseReport.Checkpoint = failedRelease.Checkpoint
	failedReleaseReport.Status = "failed"
	failedCode := "release_refused"
	failedReleaseReport.ErrorCode = &failedCode
	if err := store.PutContinuationRelease(ctx, state.LocalContinuationRelease{Manifest: failedRelease, Phase: "releasing"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationRelease(ctx, failedRelease.OperationID, failedReleaseReport); err != nil {
		t.Fatal(err)
	}

	foreign := ordinary
	foreign.OperationID = "op_s3_release_foreign0001"
	foreign.DesiredRevision = 80
	foreign.Identity = s3ContinuationIdentity(g)
	foreign.Checkpoint = s3CheckpointReference(g)
	foreignReport := ordinaryReport
	foreignReport.OperationID = foreign.OperationID
	foreignReport.DesiredRevision = foreign.DesiredRevision
	foreignReport.Identity = foreign.Identity
	foreignReport.Checkpoint = foreign.Checkpoint
	if err := store.PutContinuationPreparation(ctx, state.LocalContinuationPreparation{Manifest: foreign, Phase: "preparing"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationPreparation(ctx, foreign.OperationID, foreignReport); err != nil {
		t.Fatal(err)
	}
	foreignRelease := ordinaryRelease
	foreignRelease.OperationID = foreign.OperationID
	foreignRelease.DesiredRevision = foreign.DesiredRevision + 1
	foreignRelease.Identity = foreign.Identity
	foreignRelease.Checkpoint = foreign.Checkpoint
	foreignRelease.Binding = foreign.Binding
	foreignRelease.Binding.ServiceGeneration++
	foreignReleaseReport := ordinaryReleaseReport
	foreignReleaseReport.OperationID = foreignRelease.OperationID
	foreignReleaseReport.DesiredRevision = foreignRelease.DesiredRevision
	foreignReleaseReport.Identity = foreignRelease.Identity
	foreignReleaseReport.Checkpoint = foreignRelease.Checkpoint
	foreignReleaseReport.Binding = foreignRelease.Binding
	if err := store.PutContinuationRelease(ctx, state.LocalContinuationRelease{Manifest: foreignRelease, Phase: "releasing"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationRelease(ctx, foreignRelease.OperationID, foreignReleaseReport); err != nil {
		t.Fatal(err)
	}

	if err := store.SetCheckpointPolicy(ctx, sandboxID, state.CheckpointPolicy{
		MaxBytes: 1 << 30, MaxPerBox: 7, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	planAt := base.Add(40 * 24 * time.Hour)
	lifecycle := &CheckpointLifecycle{
		State: store, Objects: *objects, Now: func() time.Time { return planAt }, GracePeriod: time.Hour, MaxPerPass: 32,
	}
	if err := lifecycle.Run(ctx); err != nil {
		t.Fatal(err)
	}
	intents, err := store.CheckpointGCIntents(ctx)
	if err != nil || len(intents) != 1 || intents[0].CheckpointID != a.ID || intents[0].Phase != "planned" {
		t.Fatalf("released root collection plan = %#v, %v", intents, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered := &CheckpointLifecycle{
		State: reopened, Objects: *objects, Now: func() time.Time { return planAt.Add(2 * time.Hour) }, GracePeriod: time.Hour, MaxPerPass: 32,
	}
	if err := recovered.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Verify(ctx, a.CaptureID); !errors.Is(err, storage.ErrCheckpointUnavailable) {
		t.Fatalf("exactly released checkpoint remained available: %v", err)
	}
	for _, protected := range []state.LocalCheckpoint{b, c, d, e, f, g, h} {
		if _, err := objects.Verify(ctx, protected.CaptureID); err != nil {
			t.Fatalf("protected checkpoint %s was collected: %v", protected.ID, err)
		}
	}
	if err := reopened.PutContinuationPreparation(ctx, state.LocalContinuationPreparation{Manifest: ordinary, Phase: "preparing"}); err != nil {
		t.Fatalf("identical historical preparation replay = %v", err)
	}
	if err := reopened.CompleteContinuationRelease(ctx, ordinaryRelease.OperationID, ordinaryReleaseReport); err != nil {
		t.Fatalf("identical terminal release replay = %v", err)
	}
	if err := reopened.CompleteContinuationHandoffRelease(ctx, handoffRelease.OperationID, handoffReleaseReport); err != nil {
		t.Fatalf("identical handoff release replay = %v", err)
	}
	if err := reopened.AcceptCheckpoint(ctx, a); !errors.Is(err, state.ErrCheckpointUnavailable) {
		t.Fatalf("historical release replay resurrected checkpoint: %v", err)
	}
}
