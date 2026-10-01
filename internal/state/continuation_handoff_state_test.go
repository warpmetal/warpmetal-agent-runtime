package state

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type stateS2BFixture struct {
	ReviewerManifest model.ContinuationHandoffManifestV1        `json:"reviewerManifest"`
	ReviewerReport   model.ContinuationHandoffReportV1          `json:"reviewerReport"`
	ReleaseManifest  model.ContinuationHandoffReleaseManifestV1 `json:"handoffReleaseManifest"`
	ReleaseReport    model.ContinuationHandoffReleaseReportV1   `json:"handoffReleaseReport"`
}

func loadStateS2BFixture(t *testing.T) stateS2BFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "api", "testdata", "agent-continuation-handoff-v1.backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture stateS2BFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestContinuationHandoffStateReopensExactMappingAndRelease(t *testing.T) {
	fixture := loadStateS2BFixture(t)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	intent := LocalContinuationHandoffPreparation{Manifest: fixture.ReviewerManifest, Phase: "allocating"}
	if err := store.PutContinuationHandoffPreparation(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationHandoffPreparation(ctx, fixture.ReviewerManifest.OperationID,
		fixture.ReviewerReport.TargetWorkspace.SelectionID, fixture.ReviewerReport); err != nil {
		t.Fatal(err)
	}
	preparation := LocalContinuationHandoffPreparation{
		Manifest: fixture.ReviewerManifest, Phase: "ready",
		TargetSelectionID: fixture.ReviewerReport.TargetWorkspace.SelectionID, Report: &fixture.ReviewerReport,
	}
	releaseIntent := LocalContinuationHandoffRelease{Manifest: fixture.ReleaseManifest, Phase: "releasing"}
	if err := store.PutContinuationHandoffRelease(ctx, releaseIntent); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationHandoffRelease(ctx, fixture.ReleaseManifest.OperationID, fixture.ReleaseReport); err != nil {
		t.Fatal(err)
	}
	release := LocalContinuationHandoffRelease{Manifest: fixture.ReleaseManifest, Phase: "released", Report: &fixture.ReleaseReport}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	gotPreparation, err := reopened.ContinuationHandoffPreparation(ctx, fixture.ReviewerManifest.OperationID)
	if err != nil || !reflect.DeepEqual(gotPreparation, &preparation) {
		t.Fatalf("reopened preparation = %#v, %v", gotPreparation, err)
	}
	gotBySource, err := reopened.ContinuationHandoffBySource(ctx, fixture.ReviewerReport.Session.RegisteredSourceID)
	if err != nil || !reflect.DeepEqual(gotBySource, &preparation) {
		t.Fatalf("source mapping = %#v, %v", gotBySource, err)
	}
	gotRelease, err := reopened.ContinuationHandoffRelease(ctx, fixture.ReleaseManifest.OperationID)
	if err != nil || !reflect.DeepEqual(gotRelease, &release) {
		t.Fatalf("reopened release = %#v, %v", gotRelease, err)
	}
}

func TestContinuationHandoffStateRejectsChangedReplayAndSourceReuse(t *testing.T) {
	fixture := loadStateS2BFixture(t)
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	value := LocalContinuationHandoffPreparation{Manifest: fixture.ReviewerManifest, Phase: "allocating"}
	if err := store.PutContinuationHandoffPreparation(ctx, value); err != nil {
		t.Fatal(err)
	}
	changed := value
	changed.Manifest.MappingID += "_changed"
	if err := store.PutContinuationHandoffPreparation(ctx, changed); err != ErrContinuationHandoffConflict {
		t.Fatalf("changed replay error = %v", err)
	}
	foreign := value
	foreign.Manifest.OperationID += "_foreign"
	foreign.Manifest.MappingID += "_foreign"
	if err := store.PutContinuationHandoffPreparation(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	foreignReport := fixture.ReviewerReport
	foreignReport.OperationID = foreign.Manifest.OperationID
	foreignReport.MappingID = foreign.Manifest.MappingID
	if err := store.CompleteContinuationHandoffPreparation(ctx, foreign.Manifest.OperationID,
		foreignReport.TargetWorkspace.SelectionID, foreignReport); err != ErrContinuationHandoffConflict {
		t.Fatalf("mapped source reuse error = %v", err)
	}
}
