package reconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type frozenContinuityFixture struct {
	SourceReport         model.ContinuitySourceReportV1       `json:"sourceReport"`
	RegistrationManifest model.ContinuityRegistrationV1       `json:"registrationManifest"`
	RegistrationReport   model.ContinuityRegistrationReportV1 `json:"registrationReport"`
	OperationManifest    model.ContinuityOperationV1          `json:"operationManifest"`
	OperationReport      model.ContinuityOperationReportV1    `json:"operationReport"`
}

type recordingContinuityControl struct {
	applied   []model.ContinuityOperationV1
	recovered int
	fixture   frozenContinuityFixture
}

func (c *recordingContinuityControl) Recover(context.Context) error {
	c.recovered++
	return nil
}

func (c *recordingContinuityControl) RecoverLocalSafety(context.Context) error {
	return nil
}

func (c *recordingContinuityControl) RecoverCurrent(ctx context.Context, _ model.Manifest) error {
	return c.Recover(ctx)
}

func (c *recordingContinuityControl) ReportsCurrent(ctx context.Context, _ model.Manifest) ([]model.ContinuitySourceReportV1, []model.ContinuityRegistrationReportV1, []model.ContinuityOperationReportV1, error) {
	return c.Reports(ctx)
}

func (c *recordingContinuityControl) Apply(_ context.Context, manifest model.Manifest) error {
	c.applied = append(c.applied, manifest.ContinuityOperations...)
	return nil
}

func (c *recordingContinuityControl) Acknowledge(context.Context, model.Manifest) error { return nil }

func (c *recordingContinuityControl) Reports(context.Context) ([]model.ContinuitySourceReportV1, []model.ContinuityRegistrationReportV1, []model.ContinuityOperationReportV1, error) {
	return []model.ContinuitySourceReportV1{c.fixture.SourceReport}, []model.ContinuityRegistrationReportV1{c.fixture.RegistrationReport}, []model.ContinuityOperationReportV1{c.fixture.OperationReport}, nil
}

func TestRuntimeReportPublishesClosedContinuityArraysOnlyFromHostState(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reconciler := &Reconciler{
		Store: store, Engine: &contractEngine{}, Workspaces: &contractWorkspaces{},
		Access:   access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		Sessions: &contractSessions{}, HostCapacity: model.Resources{
			CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20,
		},
		ServerID: "srv_continuity0001",
	}
	report, err := reconciler.Report(context.Background(), "srv_continuity0001", "test")
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
	for _, field := range []string{"continuitySources", "continuityRegistrations", "continuityOperations"} {
		if string(document[field]) != "[]" {
			t.Errorf("fresh Runtime report %s = %s, want explicit closed empty array", field, document[field])
		}
	}
}

func TestReconcileConsumesFrozenContinuityManifestThenReportsExactHostRecords(t *testing.T) {
	payload, err := os.ReadFile("../api/testdata/agent-continuity-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture frozenContinuityFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	control := &recordingContinuityControl{fixture: fixture}
	reconciler := &Reconciler{
		Store: store, Engine: &contractEngine{}, Workspaces: &contractWorkspaces{},
		Access: access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")}, Sessions: &contractSessions{},
		HostCapacity: model.Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20}, ServerID: "srv_continuity0001", Continuity: control, ContinuityControl: control,
	}
	// The backend fixture registration carries Work revision 1 while the server
	// manifest has already advanced to an unrelated revision (live run22 observed
	// 30). These are separate domains and must not be compared.
	manifest := model.Manifest{ServerID: "srv_continuity0001", DesiredRevision: 30, ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64), Capacity: model.Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20}, Sandboxes: []model.Sandbox{{ID: fixture.OperationManifest.Identity.SandboxID, Name: "continuity-worker", Size: "small", Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256}, Lifetime: "persistent", DesiredState: "running", Generation: fixture.OperationManifest.Identity.SandboxGeneration}}, ContinuityRegistrations: []model.ContinuityRegistrationV1{fixture.RegistrationManifest}, ContinuityOperations: []model.ContinuityOperationV1{fixture.OperationManifest}}
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if control.recovered != 1 || !reflect.DeepEqual(control.applied, manifest.ContinuityOperations) {
		t.Fatalf("recovery/apply=%d %#v", control.recovered, control.applied)
	}
	report, err := reconciler.Report(context.Background(), manifest.ServerID, "test")
	if err != nil {
		t.Fatal(err)
	}
	// The frozen observation is far outside the shared freshness contract, so
	// the report-time derivation publishes that source as unavailable with the
	// fail-closed reason while preserving the authentic observation timestamp
	// and every identity field exactly. The registration and operation records
	// stay byte-exact.
	derivedSource := fixture.SourceReport
	reason := "source_unavailable"
	derivedSource.Availability = "unavailable"
	derivedSource.Reason = &reason
	if !reflect.DeepEqual(report.ContinuitySources, []model.ContinuitySourceReportV1{derivedSource}) || !reflect.DeepEqual(report.ContinuityRegistrations, []model.ContinuityRegistrationReportV1{fixture.RegistrationReport}) || !reflect.DeepEqual(report.ContinuityOperations, []model.ContinuityOperationReportV1{fixture.OperationReport}) {
		t.Fatalf("frozen reports drifted: %#v", report)
	}
}
