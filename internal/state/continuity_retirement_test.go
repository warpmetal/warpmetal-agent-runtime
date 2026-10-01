package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func retirementTestReport(operationID, status string) model.ContinuityOperationReportV1 {
	report := model.ContinuityOperationReportV1{
		FormatVersion: 1, OperationID: operationID, Action: "capture_checkpoint",
		ScopeRevision: 2, BoundaryKind: "initial",
		Identity: model.ContinuityIdentityV1{
			WorkID: "work_retirement0001", ProjectID: "project_retirement0001",
			SandboxID: "sbx_retirement00000001", WorkspaceEpoch: "epoch_retirement0001",
			SandboxGeneration: 4, ExpectedRevision: 3,
		},
		Binding: model.ContinuityBindingV1{
			BindingID: "binding_retirement0001", BindingRevision: 1,
			RegisteredSourceID: "source_retirement0001", ServiceRegistrationID: "service_retirement0001",
			NativeSessionID: "ses_retirement0001", NativeProjectID: "native_project_retirement1",
			NativeLocationDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
		RequestDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
	}
	switch status {
	case "accepted":
		report.Status = "accepted"
		report.CheckpointID = "checkpoint_retirement0000000000000001"
		report.CaptureID = "capture_retirement00000000000000000001"
		report.ManifestDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		report.Bytes = 128
		report.ObjectCount = 2
		report.ReceiptDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	case "failed":
		report.Status = "failed"
		report.LastError = &model.ItemError{Code: "capture_failed"}
	case "outcome_unknown":
		report.Status = "outcome_unknown"
		report.LastError = &model.ItemError{Code: "boundary_outcome_unknown"}
	default:
		report.Status = status
	}
	return report
}

func TestContinuityOperationRetirementIsAtomicIdempotentAndConflictFailClosed(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	accepted := retirementTestReport("op_retirement_accepted1", "accepted")
	failed := retirementTestReport("op_retirement_failed001", "failed")
	applying := retirementTestReport("op_retirement_applying1", "applying")
	held := retirementTestReport("op_retirement_held0001", "accepted")
	for _, report := range []model.ContinuityOperationReportV1{accepted, failed, applying, held} {
		if err := store.PutContinuityOperationReport(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PutContinuityBarrier(ctx, held.OperationID, []byte(`{"owner":"capture"}`), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	eligible := func(candidate ContinuityOperationCandidate) (bool, error) {
		switch candidate.Report.Status {
		case "accepted", "failed", "outcome_unknown":
			return !candidate.BarrierPresent && !candidate.LocalOperationLive, nil
		default:
			return false, nil
		}
	}
	retired, err := store.RetireContinuityOperationReports(ctx, eligible, "manifest_absent_terminal_acknowledged")
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 2 || retired[0].OperationID != accepted.OperationID || retired[1].OperationID != failed.OperationID {
		t.Fatalf("first retirement = %#v", retired)
	}
	pending, err := store.ContinuityOperationReports(ctx)
	if err != nil || len(pending) != 2 {
		t.Fatalf("outbox after retirement = %#v %v", pending, err)
	}
	for _, report := range pending {
		if report.OperationID != applying.OperationID && report.OperationID != held.OperationID {
			t.Fatalf("unexpected retained row %#v", report)
		}
	}
	retirements, err := store.ContinuityOperationRetirements(ctx)
	if err != nil || len(retirements) != 2 {
		t.Fatalf("retirements = %#v %v", retirements, err)
	}
	for _, retirement := range retirements {
		if retirement.Reason != "manifest_absent_terminal_acknowledged" || retirement.RetiredAt.IsZero() {
			t.Fatalf("retirement tombstone = %#v", retirement)
		}
		want := accepted
		if retirement.Report.OperationID == failed.OperationID {
			want = failed
		}
		if !reflect.DeepEqual(retirement.Report, want) {
			t.Fatalf("retired receipt drifted:\n got %#v\nwant %#v", retirement.Report, want)
		}
	}

	// Reopen: the outbox and tombstone state is durable, and a second
	// acknowledgement retires nothing.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.RetireContinuityOperationReports(ctx, eligible, "manifest_absent_terminal_acknowledged"); err != nil {
		t.Fatal(err)
	}
	if retirements, err := store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != 2 {
		t.Fatalf("replayed retirement duplicated tombstones: %#v %v", retirements, err)
	}

	// A conflicting duplicate of an already-retired operation ID stays
	// fail-closed: the retained receipt is immutable and the conflicting outbox
	// row is never retired.
	conflicting := accepted
	conflicting.Bytes = accepted.Bytes + 1
	if err := store.PutContinuityOperationReport(ctx, conflicting); err != nil {
		t.Fatal(err)
	}
	retired, err = store.RetireContinuityOperationReports(ctx, eligible, "manifest_absent_terminal_acknowledged")
	if err != nil || len(retired) != 0 {
		t.Fatalf("conflicting duplicate was retired: %#v %v", retired, err)
	}
	pending, err = store.ContinuityOperationReports(ctx)
	if err != nil || len(pending) != 3 {
		t.Fatalf("conflicting duplicate outbox state = %#v %v", pending, err)
	}
	retirements, err = store.ContinuityOperationRetirements(ctx)
	if err != nil || len(retirements) != 2 {
		t.Fatalf("conflicting duplicate changed tombstones: %#v %v", retirements, err)
	}
	for _, retirement := range retirements {
		if retirement.Report.OperationID == accepted.OperationID && !reflect.DeepEqual(retirement.Report, accepted) {
			t.Fatalf("conflicting duplicate rewrote the retained receipt: %#v", retirement.Report)
		}
	}

	// The byte-identical duplicate is idempotent: it is retired again without
	// touching the retained receipt.
	if err := store.PutContinuityOperationReport(ctx, accepted); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RetireContinuityOperationReports(ctx, eligible, "manifest_absent_terminal_acknowledged"); err != nil {
		t.Fatal(err)
	}
	pending, err = store.ContinuityOperationReports(ctx)
	if err != nil || len(pending) != 2 {
		t.Fatalf("identical duplicate replay = %#v %v", pending, err)
	}
	if retirements, err := store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != 2 {
		t.Fatalf("identical duplicate replay duplicated tombstones: %#v %v", retirements, err)
	}
}

func TestContinuityOperationRetirementRollsBackOnPartialFailure(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first := retirementTestReport("op_retirement_rollback01", "accepted")
	second := retirementTestReport("op_retirement_rollback02", "failed")
	for _, report := range []model.ContinuityOperationReportV1{first, second} {
		if err := store.PutContinuityOperationReport(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	injected := errors.New("injected partial acknowledgement failure")
	_, err = store.RetireContinuityOperationReports(ctx, func(ContinuityOperationCandidate) (bool, error) {
		calls++
		if calls == 2 {
			return false, injected
		}
		return true, nil
	}, "manifest_absent_terminal_acknowledged")
	if !errors.Is(err, injected) {
		t.Fatalf("partial acknowledgement error = %v, want injected failure", err)
	}
	pending, err := store.ContinuityOperationReports(ctx)
	if err != nil || len(pending) != 2 {
		t.Fatalf("partial acknowledgement lost an outbox receipt: %#v %v", pending, err)
	}
	if retirements, err := store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != 0 {
		t.Fatalf("partial acknowledgement wrote tombstones: %#v %v", retirements, err)
	}
	// The same batch succeeds once the injected failure is gone.
	if _, err := store.RetireContinuityOperationReports(ctx, func(ContinuityOperationCandidate) (bool, error) {
		return true, nil
	}, "manifest_absent_terminal_acknowledged"); err != nil {
		t.Fatal(err)
	}
	pending, err = store.ContinuityOperationReports(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("completed acknowledgement outbox = %#v %v", pending, err)
	}
	if retirements, err := store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != 2 {
		t.Fatalf("completed acknowledgement tombstones = %#v %v", retirements, err)
	}
}

func TestContinuityOperationRetirementKeepsUnaddressableLiveAndBarrierRows(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// A stored JSON payload whose embedded operation ID does not match its
	// primary key, and an unparseable payload, are never offered to the
	// predicate and never retired.
	mismatch := retirementTestReport("op_retirement_jsonother1", "accepted")
	mismatchPayload, _ := json.Marshal(mismatch)
	if _, err := store.db.ExecContext(ctx, `INSERT INTO continuity_remote_operations(operation_id, request_digest, report_json, updated_at)
VALUES(?,?,?,?)`, "op_retirement_keyother1", mismatch.RequestDigest, mismatchPayload,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO continuity_remote_operations(operation_id, request_digest, report_json, updated_at)
VALUES(?,?,?,?)`, "op_retirement_badjson1", "sha256:5555555555555555555555555555555555555555555555555555555555555555",
		[]byte("{not-json"), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	// A live local continuity operation and a live barrier must reach the
	// predicate as the exact fences the store read.
	live := retirementTestReport("op_retirement_liveop001", "accepted")
	if err := store.PutContinuityOperationReport(ctx, live); err != nil {
		t.Fatal(err)
	}
	operation := LocalContinuityOperation{
		ID: live.OperationID + "_checkpoint", Kind: "checkpoint", Identity: live.Identity,
		RequestDigest: live.RequestDigest, State: "pending", Deadline: time.Now().UTC().Add(time.Minute),
	}
	if err := store.PutContinuityOperation(ctx, operation); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionContinuityOperation(ctx, operation.ID, ContinuityTransition{From: "pending", To: "verifying"}); err != nil {
		t.Fatal(err)
	}
	held := retirementTestReport("op_retirement_barrier001", "accepted")
	if err := store.PutContinuityOperationReport(ctx, held); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuityBarrier(ctx, held.OperationID, []byte(`{"owner":"capture"}`), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}

	seen := map[string]ContinuityOperationCandidate{}
	predicateCalls := 0
	_, err = store.RetireContinuityOperationReports(ctx, func(candidate ContinuityOperationCandidate) (bool, error) {
		predicateCalls++
		seen[candidate.Report.OperationID] = candidate
		return false, nil
	}, "manifest_absent_terminal_acknowledged")
	if err != nil {
		t.Fatal(err)
	}
	if predicateCalls != 2 {
		t.Fatalf("predicate calls = %d, want only the two structurally addressable rows", predicateCalls)
	}
	if _, ok := seen["op_retirement_keyother1"]; ok {
		t.Fatal("key-mismatched row was offered to the predicate")
	}
	if _, ok := seen["op_retirement_jsonother1"]; ok {
		t.Fatal("row whose JSON operation ID does not match its key was offered to the predicate")
	}
	if _, ok := seen["op_retirement_badjson1"]; ok {
		t.Fatal("unparseable row was offered to the predicate")
	}
	if candidate, ok := seen[live.OperationID]; !ok || !candidate.LocalOperationLive || candidate.BarrierPresent {
		t.Fatalf("live local operation fence = %#v", candidate)
	}
	if candidate, ok := seen[held.OperationID]; !ok || !candidate.BarrierPresent || candidate.LocalOperationLive {
		t.Fatalf("barrier fence = %#v", candidate)
	}
	// ContinuityOperationReports is deliberately strict about unparseable
	// payloads, so the fail-closed row count is proven at the table boundary.
	var storedCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM continuity_remote_operations`).Scan(&storedCount); err != nil {
		t.Fatal(err)
	}
	if storedCount != 4 {
		t.Fatalf("fail-closed row count = %d, want 4", storedCount)
	}
	if retirements, err := store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != 0 {
		t.Fatalf("fail-closed rows retired: %#v %v", retirements, err)
	}
}

func TestContinuityOperationRetirementLookupFindsOnlyRetiredRows(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if retired, err := store.ContinuityOperationRetirement(ctx, "op_retirement_missing01"); err != nil || retired != nil {
		t.Fatalf("missing tombstone = %#v %v", retired, err)
	}
	report := retirementTestReport("op_retirement_lookup001", "accepted")
	if err := store.PutContinuityOperationReport(ctx, report); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RetireContinuityOperationReports(ctx, func(ContinuityOperationCandidate) (bool, error) {
		return true, nil
	}, "manifest_absent_terminal_acknowledged"); err != nil {
		t.Fatal(err)
	}
	retired, err := store.ContinuityOperationRetirement(ctx, report.OperationID)
	if err != nil || retired == nil || retired.Reason != "manifest_absent_terminal_acknowledged" ||
		retired.RetiredAt.IsZero() || !reflect.DeepEqual(retired.Report, report) {
		t.Fatalf("retired lookup = %#v %v", retired, err)
	}
}

func TestContinuityOperationRetirementRejectsUnboundedRequests(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.RetireContinuityOperationReports(ctx, nil, "reason"); err == nil {
		t.Fatal("nil predicate was accepted")
	}
	if _, err := store.RetireContinuityOperationReports(ctx, func(ContinuityOperationCandidate) (bool, error) {
		return true, nil
	}, ""); err == nil {
		t.Fatal("empty reason was accepted")
	}
	if _, err := store.RetireContinuityOperationReports(ctx, func(ContinuityOperationCandidate) (bool, error) {
		return true, nil
	}, fmt.Sprintf("%200s", "x")); err == nil {
		t.Fatal("unbounded reason was accepted")
	}
}
