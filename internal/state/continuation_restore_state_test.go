package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type continuationStateFixture struct {
	ContinuationManifest        model.ContinuationManifestV1        `json:"continuationManifest"`
	ContinuationReport          model.ContinuationReportV1          `json:"continuationReport"`
	ContinuationReleaseManifest model.ContinuationReleaseManifestV1 `json:"continuationReleaseManifest"`
	ContinuationReleaseReport   model.ContinuationReleaseReportV1   `json:"continuationReleaseReport"`
	RestoreManifest             model.RestoreManifestV1             `json:"restoreManifest"`
	RestoreReport               model.RestoreReportV1               `json:"restoreReport"`
}

func TestContinuationReleaseIntentAndTerminalReceiptSurviveSQLiteReopen(t *testing.T) {
	fixture := readContinuationStateFixture(t)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuationRelease(context.Background(), LocalContinuationRelease{Manifest: fixture.ContinuationReleaseManifest, Phase: "releasing"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pending, err := reopened.ContinuationRelease(context.Background(), fixture.ContinuationReleaseManifest.OperationID)
	if err != nil || pending == nil || pending.Phase != "releasing" || !reflect.DeepEqual(pending.Manifest, fixture.ContinuationReleaseManifest) {
		t.Fatalf("reopened release intent = %#v, %v", pending, err)
	}
	if err := reopened.CompleteContinuationRelease(context.Background(), fixture.ContinuationReleaseManifest.OperationID, fixture.ContinuationReleaseReport); err != nil {
		t.Fatal(err)
	}
	if err := reopened.CompleteContinuationRelease(context.Background(), fixture.ContinuationReleaseManifest.OperationID, fixture.ContinuationReleaseReport); err != nil {
		t.Fatalf("identical release replay failed: %v", err)
	}
	changed := fixture.ContinuationReleaseReport
	changed.DesiredRevision++
	if err := reopened.CompleteContinuationRelease(context.Background(), fixture.ContinuationReleaseManifest.OperationID, changed); !errors.Is(err, ErrContinuationConflict) {
		t.Fatalf("changed release receipt error = %v, want ErrContinuationConflict", err)
	}
}

func readContinuationStateFixture(t *testing.T) continuationStateFixture {
	t.Helper()
	payload, err := os.ReadFile("../api/testdata/agent-continuation-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture continuationStateFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestContinuationPreparingIntentAndExactBaselineSurviveSQLiteReopen(t *testing.T) {
	fixture := readContinuationStateFixture(t)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	intent := LocalContinuationPreparation{Manifest: fixture.ContinuationManifest, Phase: "preparing"}
	if err := store.PutContinuationPreparation(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.ContinuationPreparation(context.Background(), fixture.ContinuationManifest.OperationID)
	if err != nil || got == nil || got.Phase != "preparing" || !reflect.DeepEqual(got.Manifest, fixture.ContinuationManifest) {
		t.Fatalf("reopened continuation intent = %#v, %v", got, err)
	}
	if err := reopened.CompleteContinuationPreparation(context.Background(), fixture.ContinuationManifest.OperationID, fixture.ContinuationReport); err != nil {
		t.Fatal(err)
	}
	ready, err := reopened.ContinuationPreparation(context.Background(), fixture.ContinuationManifest.OperationID)
	if err != nil || ready == nil || ready.Phase != "ready" || ready.Report == nil ||
		!reflect.DeepEqual(*ready.Report, fixture.ContinuationReport) {
		t.Fatalf("durable exact baseline = %#v, %v", ready, err)
	}
	conflict := fixture.ContinuationManifest
	conflict.Binding.ServiceGeneration++
	if err := reopened.PutContinuationPreparation(context.Background(), LocalContinuationPreparation{Manifest: conflict, Phase: "preparing"}); !errors.Is(err, ErrContinuationConflict) {
		t.Fatalf("changed baseline tuple error = %v, want ErrContinuationConflict", err)
	}
}

func TestContinuationFailureRequiresNullBaselineAndBoundedError(t *testing.T) {
	fixture := readContinuationStateFixture(t)
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.PutContinuationPreparation(context.Background(), LocalContinuationPreparation{Manifest: fixture.ContinuationManifest, Phase: "preparing"}); err != nil {
		t.Fatal(err)
	}
	code := "workspace_changed"
	failed := fixture.ContinuationReport
	failed.Status = "failed"
	failed.ErrorCode = &code
	if err := store.CompleteContinuationPreparation(context.Background(), fixture.ContinuationManifest.OperationID, failed); !errors.Is(err, ErrContinuationConflict) {
		t.Fatalf("failed report with fabricated baseline error = %v, want ErrContinuationConflict", err)
	}
	failed.Baseline = nil
	if err := store.CompleteContinuationPreparation(context.Background(), fixture.ContinuationManifest.OperationID, failed); err != nil {
		t.Fatal(err)
	}
	got, err := store.ContinuationPreparation(context.Background(), fixture.ContinuationManifest.OperationID)
	if err != nil || got == nil || got.Report == nil || got.Report.Baseline != nil || got.Report.ErrorCode == nil || *got.Report.ErrorCode != code {
		t.Fatalf("durable failed continuation report = %#v, %v", got, err)
	}
}

func TestRestoreAllocationIntentSurvivesReopenAndTerminalReceiptIsImmutable(t *testing.T) {
	fixture := readContinuationStateFixture(t)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	intent := LocalRestoreOperation{Manifest: fixture.RestoreManifest, Phase: "allocating"}
	if err := store.PutRestoreOperation(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.RestoreOperation(context.Background(), fixture.RestoreManifest.OperationID)
	if err != nil || got == nil || got.Phase != "allocating" || !reflect.DeepEqual(got.Manifest, fixture.RestoreManifest) {
		t.Fatalf("reopened restore intent = %#v, %v", got, err)
	}
	if err := reopened.CompleteRestoreOperation(context.Background(), fixture.RestoreManifest.OperationID, fixture.RestoreReport); err != nil {
		t.Fatal(err)
	}
	changed := fixture.RestoreReport
	changed.Target.ProjectID = "project_changed0001"
	if err := reopened.CompleteRestoreOperation(context.Background(), fixture.RestoreManifest.OperationID, changed); !errors.Is(err, ErrRestoreConflict) {
		t.Fatalf("changed terminal restore error = %v, want ErrRestoreConflict", err)
	}
}
