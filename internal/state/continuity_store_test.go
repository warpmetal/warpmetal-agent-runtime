package state

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func continuityIdentity() model.ContinuityIdentityV1 {
	taskID := "task_test12345"
	taskAttempt := int64(3)
	return model.ContinuityIdentityV1{
		WorkID:            "work_test12345",
		ProjectID:         "project_test12345",
		SandboxID:         "sbx_test12345",
		WorkspaceEpoch:    "epoch_test12345",
		SandboxGeneration: 7,
		TaskID:            &taskID,
		TaskAttempt:       &taskAttempt,
		ExpectedRevision:  11,
	}
}

func TestContinuityOperationPauseOwnershipSurvivesStoreRestart(t *testing.T) {
	database := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Date(2026, 9, 27, 16, 30, 0, 0, time.UTC)
	operation := LocalContinuityOperation{
		ID:            "continuity_op_12345",
		Kind:          "checkpoint",
		Identity:      continuityIdentity(),
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		State:         "pending",
		Deadline:      deadline,
	}
	if err := store.PutContinuityOperation(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(context.Background(), operation.ID, ContinuityTransition{
		From: "pending", To: "pausing",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(context.Background(), operation.ID, ContinuityTransition{
		From: "pausing", To: "paused", PauseOwned: true, PauseGeneration: 7,
		PauseLifecycleRevision: 12,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.ContinuityOperation(context.Background(), operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.State != "paused" || !got.PauseOwned || got.PauseGeneration != 7 ||
		got.PauseLifecycleRevision != 12 ||
		!got.Deadline.Equal(deadline) || !got.Identity.Equal(operation.Identity) {
		t.Fatalf("durable pause ownership changed across restart: %#v", got)
	}
}

func TestAcceptCheckpointIsAtomicAndPreservesPriorPointerOnQuotaFailure(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	identity := continuityIdentity()
	if err := store.SetCheckpointPolicy(ctx, identity.SandboxID, CheckpointPolicy{
		MaxBytes: 64, MaxPerBox: 2, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	first := LocalCheckpoint{
		ID: "checkpoint_first", CaptureID: "capture_first", Identity: identity,
		ManifestDigest: "sha256:first", Bytes: 32, ObjectCount: 2, Pinned: true,
	}
	if err := store.PutContinuityCapture(ctx, LocalContinuityCapture{
		ID: first.CaptureID, Identity: identity, ObjectID: "object_first",
		ManifestDigest: first.ManifestDigest, Bytes: first.Bytes, ObjectCount: first.ObjectCount,
		Verified: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptCheckpoint(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := LocalCheckpoint{
		ID: "checkpoint_second", CaptureID: "capture_second", Identity: identity,
		ManifestDigest: "sha256:second", Bytes: 40, ObjectCount: 1,
	}
	err = store.PutContinuityCapture(ctx, LocalContinuityCapture{
		ID: second.CaptureID, Identity: identity, ObjectID: "object_second",
		ManifestDigest: second.ManifestDigest, Bytes: second.Bytes, ObjectCount: second.ObjectCount,
		Verified: true,
	})
	if !errors.Is(err, ErrCheckpointQuota) {
		t.Fatalf("quota failure = %v, want ErrCheckpointQuota", err)
	}
	accepted, err := store.AcceptedCheckpoint(ctx, identity.WorkID)
	if err != nil {
		t.Fatal(err)
	}
	if accepted == nil || accepted.ID != first.ID {
		t.Fatalf("quota failure advanced accepted checkpoint: %#v", accepted)
	}
	if stored, err := store.Checkpoint(ctx, second.ID); err != nil || stored != nil {
		t.Fatalf("failed checkpoint was partially committed: %#v %v", stored, err)
	}
	if capture, err := store.ContinuityCapture(ctx, second.CaptureID); err != nil || capture != nil {
		t.Fatalf("over-quota capture was partially committed: %#v %v", capture, err)
	}
}

func TestCheckpointRetentionIsPerBoxAndPreservesPins(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	identity := continuityIdentity()
	if err := store.SetCheckpointPolicy(ctx, identity.SandboxID, CheckpointPolicy{
		MaxBytes: 1 << 30, MaxPerBox: 3, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	for index, id := range []string{"first", "second", "third"} {
		capture := LocalContinuityCapture{
			ID: "capture_" + id, Identity: identity, ObjectID: "object_" + id,
			ManifestDigest: "sha256:" + id, Bytes: 8, ObjectCount: 1, Verified: true,
		}
		if err := store.PutContinuityCapture(ctx, capture); err != nil {
			t.Fatal(err)
		}
		if err := store.AcceptCheckpoint(ctx, LocalCheckpoint{
			ID: "checkpoint_" + id, CaptureID: capture.ID, Identity: identity,
			ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes, ObjectCount: 1,
			Pinned: index == 0,
		}); err != nil {
			t.Fatal(err)
		}
	}
	retained, err := store.CheckpointsForWork(ctx, identity.WorkID)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 3 {
		t.Fatalf("acceptance evicted history before explicit retention: %#v", retained)
	}
	if err := store.SetCheckpointPolicy(ctx, identity.SandboxID, CheckpointPolicy{
		MaxBytes: 1 << 30, MaxPerBox: 2, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	removed, err := store.ApplyCheckpointRetention(ctx, identity.SandboxID, time.Now().UTC().Add(31*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0].Pinned || removed[0].ID != "checkpoint_second" {
		t.Fatalf("retention did not preserve pinned checkpoint: %#v", removed)
	}
	retained, err = store.CheckpointsForWork(ctx, identity.WorkID)
	if err != nil || len(retained) != 2 || !retained[0].Pinned || retained[1].ID != "checkpoint_third" {
		t.Fatalf("retained checkpoints = %#v, %v", retained, err)
	}
}

func TestCheckpointByteQuotaCoversAllWorkInSandbox(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	first := continuityIdentity()
	second := continuityIdentity()
	second.WorkID = "work_other12345"
	otherTaskID := "task_other12345"
	second.TaskID = &otherTaskID
	if err := store.SetCheckpointPolicy(ctx, first.SandboxID, CheckpointPolicy{
		MaxBytes: 64, MaxPerBox: 20, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuityCapture(ctx, LocalContinuityCapture{
		ID: "capture_first_work", Identity: first, ObjectID: "object_first_work",
		ManifestDigest: "sha256:first-work", Bytes: 48, ObjectCount: 1, Verified: true,
	}); err != nil {
		t.Fatal(err)
	}
	err = store.PutContinuityCapture(ctx, LocalContinuityCapture{
		ID: "capture_second_work", Identity: second, ObjectID: "object_second_work",
		ManifestDigest: "sha256:second-work", Bytes: 17, ObjectCount: 1, Verified: true,
	})
	if !errors.Is(err, ErrCheckpointQuota) {
		t.Fatalf("cross-work sandbox quota error = %v", err)
	}
	remaining, err := store.CheckpointBudget(ctx, first.SandboxID)
	if err != nil || remaining != 16 {
		t.Fatalf("remaining sandbox budget = %d, %v; want 16", remaining, err)
	}
}

func TestContinuityOperationIdentityAndRequestDigestAreImmutable(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	value := LocalContinuityOperation{
		ID: "continuity_op_12345", Kind: "checkpoint", Identity: continuityIdentity(),
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		State:         "pending", Deadline: time.Now().UTC().Add(time.Minute),
	}
	if err := store.PutContinuityOperation(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	changed := value
	changedAttempt := *changed.Identity.TaskAttempt + 1
	changed.Identity.TaskAttempt = &changedAttempt
	if err := store.PutContinuityOperation(context.Background(), changed); err == nil {
		t.Fatal("operation ID was reused with a different task attempt")
	}
	changed = value
	changed.RequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := store.PutContinuityOperation(context.Background(), changed); err == nil {
		t.Fatal("operation ID was reused with a different request digest")
	}
}

func TestCheckpointCollectionRechecksRootsAndFencesLateReferences(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	identity := continuityIdentity()
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if err := store.SetCheckpointPolicy(ctx, identity.SandboxID, CheckpointPolicy{
		MaxBytes: 1 << 20, MaxPerBox: 2, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	var first LocalCheckpoint
	for index, name := range []string{"old", "current"} {
		capture := LocalContinuityCapture{
			ID: "capture_" + name, Identity: identity, ObjectID: "object_" + name,
			ManifestDigest: "sha256:" + name, Bytes: 8, ObjectCount: 1,
			Verified: true, CreatedAt: base.Add(time.Duration(index) * time.Hour),
		}
		if err := store.PutContinuityCapture(ctx, capture); err != nil {
			t.Fatal(err)
		}
		checkpoint := LocalCheckpoint{
			ID: "checkpoint_" + name, CaptureID: capture.ID, Identity: identity,
			ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes,
			ObjectCount: capture.ObjectCount, CreatedAt: capture.CreatedAt,
		}
		if err := store.AcceptCheckpoint(ctx, checkpoint); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			first = checkpoint
		}
	}
	if err := store.SetCheckpointPolicy(ctx, identity.SandboxID, CheckpointPolicy{
		MaxBytes: 1 << 20, MaxPerBox: 1, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	now := base.Add(40 * 24 * time.Hour)
	intents, err := store.PlanCheckpointCollection(ctx, now, time.Hour, 32)
	if err != nil || len(intents) != 1 || intents[0].CheckpointID != first.ID {
		t.Fatalf("initial collection plan = %#v, %v", intents, err)
	}
	operation := LocalContinuityOperation{
		ID: "materialize_late_root", Kind: "materialize", Identity: identity,
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		State:         "pending", Deadline: now.Add(time.Hour),
	}
	if err := store.PutContinuityOperation(ctx, operation); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(ctx, operation.ID, ContinuityTransition{
		From: "pending", To: "materializing", CheckpointID: first.ID,
	}); err != nil {
		t.Fatal(err)
	}
	confirmed, err := store.ConfirmCheckpointCollection(ctx, intents[0])
	if err != nil || confirmed {
		t.Fatalf("new root did not cancel collection: confirmed=%v err=%v", confirmed, err)
	}
	if err := store.TransitionContinuityOperation(ctx, operation.ID, ContinuityTransition{
		From: "materializing", To: "failed", CheckpointID: first.ID,
	}); err != nil {
		t.Fatal(err)
	}
	intents, err = store.PlanCheckpointCollection(ctx, now.Add(2*time.Hour), 0, 32)
	if err != nil || len(intents) != 1 {
		t.Fatalf("replacement collection plan = %#v, %v", intents, err)
	}
	confirmed, err = store.ConfirmCheckpointCollection(ctx, intents[0])
	if err != nil || !confirmed {
		t.Fatalf("durable delete fence = %v, %v", confirmed, err)
	}
	if err := store.AcceptCheckpoint(ctx, first); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatalf("historical replay after delete fence = %v", err)
	}
	restore := LocalRestoreOperation{
		Manifest: model.RestoreManifestV1{
			OperationID: "restore_late_reference",
			Checkpoint:  model.ContinuationCheckpointRefV1{CheckpointID: first.ID},
		},
		Phase: "allocating",
	}
	if err := store.PutRestoreOperation(ctx, restore); err == nil {
		t.Fatal("restore established a reference after the durable delete fence")
	}
}

func TestCheckpointCollectionProtectsEveryInflightAuthorityRoot(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	identity := continuityIdentity()
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if err := store.SetCheckpointPolicy(ctx, identity.SandboxID, CheckpointPolicy{
		MaxBytes: 1 << 20, MaxPerBox: 20, MaxAge: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	names := []string{"operation", "continue", "release", "handoff", "handoff_release", "restore", "unrooted", "current"}
	checkpoints := map[string]LocalCheckpoint{}
	for index, name := range names {
		capture := LocalContinuityCapture{
			ID: "capture_" + name, Identity: identity, ObjectID: "object_" + name,
			ManifestDigest: "sha256:" + name, Bytes: 8, ObjectCount: 1,
			Verified: true, CreatedAt: base.Add(time.Duration(index) * time.Minute),
		}
		if err := store.PutContinuityCapture(ctx, capture); err != nil {
			t.Fatal(err)
		}
		checkpoint := LocalCheckpoint{
			ID: "checkpoint_" + name, CaptureID: capture.ID, Identity: identity,
			ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes,
			ObjectCount: capture.ObjectCount, CreatedAt: capture.CreatedAt,
		}
		if err := store.AcceptCheckpoint(ctx, checkpoint); err != nil {
			t.Fatal(err)
		}
		checkpoints[name] = checkpoint
	}
	operation := LocalContinuityOperation{
		ID: "materialize_root", Kind: "materialize", Identity: identity,
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		State:         "pending", Deadline: base.Add(90 * 24 * time.Hour),
	}
	if err := store.PutContinuityOperation(ctx, operation); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(ctx, operation.ID, ContinuityTransition{
		From: "pending", To: "materializing", CheckpointID: checkpoints["operation"].ID,
	}); err != nil {
		t.Fatal(err)
	}
	updated := base.Format(time.RFC3339Nano)
	manifest := func(name string) []byte {
		return []byte(`{"checkpoint":{"checkpointId":"` + checkpoints[name].ID + `"}}`)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO continuation_preparations(operation_id,manifest_json,phase,report_json,updated_at) VALUES(?,?,'preparing',NULL,?)`, []any{"continue_root", manifest("continue"), updated}},
		{`INSERT INTO continuation_releases(operation_id,manifest_json,phase,report_json,updated_at) VALUES(?,?,'releasing',NULL,?)`, []any{"release_root", manifest("release"), updated}},
		{`INSERT INTO continuation_handoff_preparations(operation_id,manifest_json,phase,target_selection_id,mapped_source_id,report_json,updated_at) VALUES(?,?,'allocating','','',NULL,?)`, []any{"handoff_root", manifest("handoff"), updated}},
		{`INSERT INTO continuation_handoff_releases(operation_id,manifest_json,phase,report_json,updated_at) VALUES(?,?,'releasing',NULL,?)`, []any{"handoff_release_root", manifest("handoff_release"), updated}},
		{`INSERT INTO restore_operations(operation_id,manifest_json,phase,report_json,updated_at) VALUES(?,?,'allocating',NULL,?)`, []any{"restore_root", manifest("restore"), updated}},
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	orphanRoot := LocalContinuityCapture{
		ID: "capture_orphan_root", Identity: identity, ObjectID: "object_orphan_root",
		ManifestDigest: "sha256:orphan-root", Bytes: 8, ObjectCount: 1,
		Verified: true, CreatedAt: base,
	}
	unrootedOrphan := LocalContinuityCapture{
		ID: "capture_orphan_unrooted", Identity: identity, ObjectID: "object_orphan_unrooted",
		ManifestDigest: "sha256:orphan-unrooted", Bytes: 8, ObjectCount: 1,
		Verified: true, CreatedAt: base,
	}
	for _, capture := range []LocalContinuityCapture{orphanRoot, unrootedOrphan} {
		if err := store.PutContinuityCapture(ctx, capture); err != nil {
			t.Fatal(err)
		}
	}
	captureOperation := LocalContinuityOperation{
		ID: "capture_root", Kind: "capture", Identity: identity,
		RequestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		State:         "pending", Deadline: base.Add(90 * 24 * time.Hour),
	}
	if err := store.PutContinuityOperation(ctx, captureOperation); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(ctx, captureOperation.ID, ContinuityTransition{
		From: "pending", To: "capturing", CaptureID: orphanRoot.ID,
	}); err != nil {
		t.Fatal(err)
	}
	intents, err := store.PlanCheckpointCollection(ctx, base.Add(40*24*time.Hour), time.Hour, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 2 {
		t.Fatalf("collection planned protected roots: %#v", intents)
	}
	got := map[string]bool{}
	for _, intent := range intents {
		got[intent.CaptureID] = true
	}
	if !got[checkpoints["unrooted"].CaptureID] || !got[unrootedOrphan.ID] {
		t.Fatalf("eligible unrooted objects not planned: %#v", intents)
	}
}
