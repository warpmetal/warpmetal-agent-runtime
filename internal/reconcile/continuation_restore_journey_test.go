package reconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type frozenContinuationRestoreFixture struct {
	ContinuationManifest        model.ContinuationManifestV1        `json:"continuationManifest"`
	ContinuationReport          model.ContinuationReportV1          `json:"continuationReport"`
	ContinuationReleaseManifest model.ContinuationReleaseManifestV1 `json:"continuationReleaseManifest"`
	ContinuationReleaseReport   model.ContinuationReleaseReportV1   `json:"continuationReleaseReport"`
	RestoreManifest             model.RestoreManifestV1             `json:"restoreManifest"`
	RestoreReport               model.RestoreReportV1               `json:"restoreReport"`
}

type recordingContinuationRestoreControl struct {
	recoveries    int
	continuations []model.ContinuationManifestV1
	releases      []model.ContinuationReleaseManifestV1
	restores      []model.RestoreManifestV1
	fixture       frozenContinuationRestoreFixture
}

func (c *recordingContinuationRestoreControl) ApplyReleases(_ context.Context, releases []model.ContinuationReleaseManifestV1) error {
	c.releases = append(c.releases, releases...)
	return nil
}

func (c *recordingContinuationRestoreControl) Recover(context.Context) error {
	c.recoveries++
	return nil
}

func (c *recordingContinuationRestoreControl) Apply(_ context.Context, continuations []model.ContinuationManifestV1, restores []model.RestoreManifestV1) error {
	c.continuations = append(c.continuations, continuations...)
	c.restores = append(c.restores, restores...)
	return nil
}

func (c *recordingContinuationRestoreControl) Reports(context.Context) ([]model.ContinuationReportV1, []model.RestoreReportV1, error) {
	return []model.ContinuationReportV1{c.fixture.ContinuationReport}, []model.RestoreReportV1{c.fixture.RestoreReport}, nil
}

func (c *recordingContinuationRestoreControl) ReleaseReports(context.Context) ([]model.ContinuationReleaseReportV1, error) {
	return []model.ContinuationReleaseReportV1{c.fixture.ContinuationReleaseReport}, nil
}

func readFrozenContinuationRestoreFixture(t *testing.T) frozenContinuationRestoreFixture {
	t.Helper()
	payload, err := os.ReadFile("../api/testdata/agent-continuation-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture frozenContinuationRestoreFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestReconcileConsumesAndReportsExactContinuationRestoreRecords(t *testing.T) {
	fixture := readFrozenContinuationRestoreFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	control := &recordingContinuationRestoreControl{fixture: fixture}
	r := &Reconciler{
		Store: store, Engine: &contractEngine{}, Workspaces: &contractWorkspaces{},
		Access: access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")}, Sessions: &contractSessions{},
		HostCapacity: model.Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20},
		ServerID:     "srv_continuation0001", ContinuationRestore: control,
	}
	manifest := model.Manifest{
		ContinuityContinuations:        []model.ContinuationManifestV1{fixture.ContinuationManifest},
		ContinuityContinuationReleases: []model.ContinuationReleaseManifestV1{fixture.ContinuationReleaseManifest},
		ContinuityRestores:             []model.RestoreManifestV1{fixture.RestoreManifest},
	}
	if err := r.reconcileContinuationRestore(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if control.recoveries != 1 || !reflect.DeepEqual(control.continuations, manifest.ContinuityContinuations) ||
		!reflect.DeepEqual(control.releases, manifest.ContinuityContinuationReleases) || !reflect.DeepEqual(control.restores, manifest.ContinuityRestores) {
		t.Fatalf("continuation/restore apply drifted: %#v", control)
	}
	report, err := r.Report(context.Background(), r.ServerID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.ContinuityContinuations, []model.ContinuationReportV1{fixture.ContinuationReport}) ||
		!reflect.DeepEqual(report.ContinuityContinuationReleases, []model.ContinuationReleaseReportV1{fixture.ContinuationReleaseReport}) ||
		!reflect.DeepEqual(report.ContinuityRestores, []model.RestoreReportV1{fixture.RestoreReport}) {
		t.Fatalf("continuation/restore report drifted: %#v", report)
	}
}

func TestFreshRuntimePublishesClosedContinuationRestoreArrays(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r := &Reconciler{
		Store: store, Engine: &contractEngine{}, Workspaces: &contractWorkspaces{},
		Access: access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")}, Sessions: &contractSessions{},
		HostCapacity: model.Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20}, ServerID: "srv_continuation0001",
	}
	report, err := r.Report(context.Background(), r.ServerID, "test")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"continuityContinuations", "continuityContinuationReleases", "continuityRestores"} {
		if string(document[field]) != "[]" {
			t.Fatalf("fresh Runtime report %s = %s, want closed empty array", field, document[field])
		}
	}
}
