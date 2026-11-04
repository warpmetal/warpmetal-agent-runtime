package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func newReportSyncTest(t *testing.T, post func(context.Context, model.Report) (ReportAck, error),
	manifest func(context.Context) (model.Manifest, error)) (*ReportSync, *state.Store, *[]model.Report) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	sent := &[]model.Report{}
	wrapped := func(ctx context.Context, report model.Report) (ReportAck, error) {
		*sent = append(*sent, report)
		return post(ctx, report)
	}
	sync := &ReportSync{
		Post: wrapped, Manifest: manifest, Store: store,
		Now:   func() time.Time { return time.Unix(1_790_000_000, 0) },
		Sleep: func(context.Context, time.Duration) bool { return true },
		Rand:  func() float64 { return 0.5 },
	}
	return sync, store, sent
}

func conflictsFor(count int) func(context.Context, model.Report) (ReportAck, error) {
	calls := 0
	return func(context.Context, model.Report) (ReportAck, error) {
		calls++
		if calls > count {
			return ReportAck{ReportEpoch: int64(calls)}, nil
		}
		return ReportAck{}, &api.ResponseError{
			Status: 409, Code: "runtime_report_conflict",
			Detail: map[string]any{"resyncGeneration": float64(1), "reportEpoch": float64(0)},
		}
	}
}

func manifestAt(revision int64) func(context.Context) (model.Manifest, error) {
	return func(context.Context) (model.Manifest, error) {
		return model.Manifest{DesiredRevision: revision}, nil
	}
}

func TestReportSyncAcceptedPersistsSequence(t *testing.T) {
	sync, store, sent := newReportSyncTest(t,
		func(context.Context, model.Report) (ReportAck, error) {
			return ReportAck{ReportEpoch: 1}, nil
		}, manifestAt(4))
	if err := sync.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 || (*sent)[0].ReportSequence != 1 ||
		(*sent)[0].ReportDigest == "" {
		t.Fatalf("unexpected sent report: %+v", *sent)
	}
	persisted, err := store.ReportSyncState(context.Background())
	if err != nil || persisted.Sequence != 1 || persisted.LastEpoch != 1 ||
		persisted.BlockedCode != "" {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
}

func TestReportSyncConflictResyncsWithCurrentEpoch(t *testing.T) {
	posts := 0
	post := func(context.Context, model.Report) (ReportAck, error) {
		posts++
		if posts == 1 {
			return ReportAck{}, &api.ResponseError{
				Status: 409, Code: "runtime_report_conflict",
				Detail: map[string]any{"resyncGeneration": float64(1), "reportEpoch": float64(0)},
			}
		}
		return ReportAck{ReportEpoch: 1}, nil
	}
	sync, store, sent := newReportSyncTest(t, post, manifestAt(5))
	if err := sync.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 {
		t.Fatalf("expected one resync retry, got %d", len(*sent))
	}
	if (*sent)[1].ObservedDesiredRevision != 5 || (*sent)[1].ReportSequence != 2 {
		t.Fatalf("resync report body: %+v", (*sent)[1])
	}
	persisted, _ := store.ReportSyncState(context.Background())
	if persisted.BlockedCode != "" || persisted.Sequence != 2 {
		t.Fatalf("persisted=%+v", persisted)
	}
}

func TestReportSyncExhaustionPersistsTypedBlockAndRestartStaysBlocked(t *testing.T) {
	sync, store, sent := newReportSyncTest(t, conflictsFor(1000), manifestAt(4))
	sync.MaxAttempts = 3
	if err := sync.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
	if len(*sent) < 3 || len(*sent) > 4 {
		t.Fatalf("bounded attempts expected ~3, got %d", len(*sent))
	}
	persisted, _ := store.ReportSyncState(context.Background())
	if persisted.BlockedCode != "runtime_report_conflict" ||
		persisted.BlockedDesiredRevision != 4 ||
		persisted.Sequence != int64(len(*sent)) {
		t.Fatalf("persisted=%+v", persisted)
	}
	// Restart: a new sync instance over the same store must not spin while the
	// manifest desired revision is unchanged.
	post := func(context.Context, model.Report) (ReportAck, error) {
		t.Fatal("blocked report must not be retried")
		return ReportAck{}, nil
	}
	restarted, _, _ := newReportSyncTest(t, post, manifestAt(4))
	restarted.Store = store
	if err := restarted.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
}

func TestReportSyncAutoRecoversWhenManifestDesiredAdvances(t *testing.T) {
	sync, store, sent := newReportSyncTest(t, conflictsFor(1000), manifestAt(4))
	sync.MaxAttempts = 2
	if err := sync.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
	if len(*sent) < 2 || len(*sent) > 3 {
		t.Fatalf("expected initial bounded attempts, got %d", len(*sent))
	}
	// Owner redrive bumps desired revision: the next pass clears the block and
	// applies the fresh report.
	post := func(context.Context, model.Report) (ReportAck, error) {
		return ReportAck{ReportEpoch: 1}, nil
	}
	recovered, _, recoveredSent := newReportSyncTest(t, post, manifestAt(6))
	recovered.Store = store
	if err := recovered.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
	if len(*recoveredSent) != 1 {
		t.Fatalf("expected one recovered report, got %d", len(*recoveredSent))
	}
	persisted, _ := store.ReportSyncState(context.Background())
	if persisted.BlockedCode != "" || persisted.LastEpoch != 1 {
		t.Fatalf("persisted=%+v", persisted)
	}
}

func TestReportSyncNonReconciliationErrorRetriesBounded(t *testing.T) {
	sync, store, sent := newReportSyncTest(t,
		func(context.Context, model.Report) (ReportAck, error) {
			return ReportAck{}, errors.New("control-plane request failed")
		}, manifestAt(4))
	sync.MaxAttempts = 2
	if err := sync.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 {
		t.Fatalf("expected bounded retries, got %d", len(*sent))
	}
	persisted, _ := store.ReportSyncState(context.Background())
	if persisted.BlockedCode != "report_retry_exhausted" {
		t.Fatalf("persisted=%+v", persisted)
	}
}

// A superseded setup generation (owner redrive) replaces the operation tuple the
// report must carry. The first body is stale by construction, so the sync must
// re-derive it from the fresh manifest instead of replaying stale bytes until the
// bounded block; the rebuilt body is then accepted and the sequence persisted.
func TestReportSyncRebuildsReportOnSupersededSetupGeneration(t *testing.T) {
	posts := 0
	post := func(_ context.Context, report model.Report) (ReportAck, error) {
		posts++
		if posts == 1 {
			return ReportAck{}, &api.ResponseError{
				Status: 409, Code: "runtime_report_conflict",
				Detail: map[string]any{
					"conflictCodes":   []any{"setup_generation_superseded"},
					"desiredRevision": float64(4), "reportEpoch": float64(1),
				},
			}
		}
		if len(report.SetupOperations) != 1 || report.SetupOperations[0].ID != "setup_newgen0001" {
			t.Fatalf("rebuilt report still carries the stale setup tuple: %+v", report.SetupOperations)
		}
		return ReportAck{ReportEpoch: 2}, nil
	}
	sync, store, sent := newReportSyncTest(t, post, manifestAt(4))
	rebuilds := 0
	sync.Rebuild = func(_ context.Context, manifest model.Manifest) (*model.Report, error) {
		rebuilds++
		if manifest.DesiredRevision != 4 {
			t.Fatalf("rebuild manifest revision: %d", manifest.DesiredRevision)
		}
		rebuilt := &model.Report{SetupOperations: []model.SetupOperationReport{{
			ID: "setup_newgen0001", SandboxID: "sbx_test00001", SandboxGeneration: 1,
			ProfileID: "opencode", ProfileRevision: 4, ProfileDigest: "sha256:aa", Status: "ready",
		}}}
		return rebuilt, nil
	}
	stale := &model.Report{SetupOperations: []model.SetupOperationReport{{
		ID: "setup_oldgen0001", SandboxID: "sbx_test00001", SandboxGeneration: 1,
		ProfileID: "opencode", ProfileRevision: 4, ProfileDigest: "sha256:aa", Status: "failed",
	}}}
	if err := sync.Send(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	if rebuilds != 1 {
		t.Fatalf("expected exactly one rebuild, got %d", rebuilds)
	}
	if len(*sent) != 2 || (*sent)[1].ReportSequence != 2 || (*sent)[1].ObservedDesiredRevision != 4 {
		t.Fatalf("unexpected sent reports: %+v", *sent)
	}
	persisted, _ := store.ReportSyncState(context.Background())
	if persisted.BlockedCode != "" || persisted.Sequence != 2 || persisted.LastEpoch != 2 {
		t.Fatalf("persisted=%+v", persisted)
	}
}

// Rebuilds are bounded inside one Send: a conflict that persists even after the
// fresh manifest was applied still ends in the existing typed terminal block,
// never an infinite rebuild loop.
func TestReportSyncRebuildBoundedThenTypedBlock(t *testing.T) {
	post := func(context.Context, model.Report) (ReportAck, error) {
		return ReportAck{}, &api.ResponseError{
			Status: 409, Code: "runtime_report_conflict",
			Detail: map[string]any{"conflictCodes": []any{"setup_generation_superseded"}},
		}
	}
	sync, store, sent := newReportSyncTest(t, post, manifestAt(4))
	sync.MaxAttempts = 5
	sync.MaxRebuilds = 2
	rebuilds := 0
	sync.Rebuild = func(context.Context, model.Manifest) (*model.Report, error) {
		rebuilds++
		return &model.Report{}, nil
	}
	if err := sync.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
	if rebuilds > 2 {
		t.Fatalf("rebuild bound exceeded: %d", rebuilds)
	}
	if len(*sent) < 5 || len(*sent) > 6 {
		t.Fatalf("expected bounded attempts, got %d", len(*sent))
	}
	persisted, _ := store.ReportSyncState(context.Background())
	if persisted.BlockedCode != "runtime_report_conflict" || persisted.BlockedDesiredRevision != 4 {
		t.Fatalf("persisted=%+v", persisted)
	}
}

// A rebuild failure keeps the ordinary bounded retry/typed-block behaviour.
func TestReportSyncRebuildErrorFallsBackToBoundedTypedBlock(t *testing.T) {
	sync, store, sent := newReportSyncTest(t, conflictsFor(1000), manifestAt(4))
	sync.MaxAttempts = 3
	sync.Rebuild = func(context.Context, model.Manifest) (*model.Report, error) {
		return nil, errors.New("fresh manifest reconcile failed")
	}
	if err := sync.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
	if len(*sent) < 3 || len(*sent) > 4 {
		t.Fatalf("expected bounded attempts, got %d", len(*sent))
	}
	persisted, _ := store.ReportSyncState(context.Background())
	if persisted.BlockedCode != "runtime_report_conflict" {
		t.Fatalf("persisted=%+v", persisted)
	}
}

// The rebuilt report's accepted sequence is persisted, so a daemon restart can
// neither duplicate it nor replay the stale generation.
func TestReportSyncRebuildAcceptanceIsRestartSafe(t *testing.T) {
	posts := 0
	post := func(_ context.Context, report model.Report) (ReportAck, error) {
		posts++
		if posts == 1 {
			return ReportAck{}, &api.ResponseError{
				Status: 409, Code: "runtime_report_conflict",
				Detail: map[string]any{"conflictCodes": []any{"setup_generation_superseded"}},
			}
		}
		return ReportAck{ReportEpoch: 7}, nil
	}
	sync, store, _ := newReportSyncTest(t, post, manifestAt(4))
	sync.Rebuild = func(context.Context, model.Manifest) (*model.Report, error) {
		return &model.Report{SetupOperations: []model.SetupOperationReport{{ID: "setup_newgen0001"}}}, nil
	}
	if err := sync.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
	persisted, _ := store.ReportSyncState(context.Background())
	if persisted.Sequence != 2 || persisted.LastEpoch != 7 {
		t.Fatalf("persisted=%+v", persisted)
	}
	// Restart: fresh instance over the same store resumes from the persisted
	// sequence and accepts a new report without replaying the old body.
	restartedPost := func(_ context.Context, report model.Report) (ReportAck, error) {
		if report.ReportSequence != persisted.Sequence+1 {
			t.Fatalf("restart sequence: %d", report.ReportSequence)
		}
		return ReportAck{ReportEpoch: 8}, nil
	}
	restarted, _, _ := newReportSyncTest(t, restartedPost, manifestAt(5))
	restarted.Store = store
	if err := restarted.Send(context.Background(), &model.Report{}); err != nil {
		t.Fatal(err)
	}
	final, _ := store.ReportSyncState(context.Background())
	if final.Sequence != persisted.Sequence+1 || final.LastEpoch != 8 {
		t.Fatalf("final=%+v", final)
	}
}
