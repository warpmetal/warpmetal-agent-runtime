package api

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type continuationRestoreFixture struct {
	ContinuationManifest        model.ContinuationManifestV1        `json:"continuationManifest"`
	ContinuationReport          model.ContinuationReportV1          `json:"continuationReport"`
	ContinuationReleaseManifest model.ContinuationReleaseManifestV1 `json:"continuationReleaseManifest"`
	ContinuationReleaseReport   model.ContinuationReleaseReportV1   `json:"continuationReleaseReport"`
	RestoreManifest             model.RestoreManifestV1             `json:"restoreManifest"`
	RestoreReport               model.RestoreReportV1               `json:"restoreReport"`
}

type continuationBackendWireFixture struct {
	FormatVersion              int                                   `json:"formatVersion"`
	ContinuationManifest       model.ContinuationManifestV1          `json:"continuationManifest"`
	ContinuationReport         model.ContinuationReportV1            `json:"continuationReport"`
	ContinuationBaseline       model.ContinuationBaselineAuthorityV1 `json:"continuationBaseline"`
	ReleaseManifest            model.ContinuationReleaseManifestV1   `json:"releaseManifest"`
	ReleasePreparationManifest model.ContinuationManifestV1          `json:"releasePreparationManifest"`
	ReleaseReport              model.ContinuationReleaseReportV1     `json:"releaseReport"`
	FailedContinuationReport   model.ContinuationReportV1            `json:"failedContinuationReport"`
	RestoreManifest            model.RestoreManifestV1               `json:"restoreManifest"`
	RestoreReport              model.RestoreReportV1                 `json:"restoreReport"`
}

func loadContinuationRestoreFixture(t *testing.T) continuationRestoreFixture {
	t.Helper()
	payload, err := os.ReadFile("testdata/agent-continuation-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture continuationRestoreFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestClientConsumesExactContinuationAndRestoreWire(t *testing.T) {
	fixture := loadContinuationRestoreFixture(t)
	manifestPayload, err := json.Marshal(model.Manifest{
		ContinuityContinuations:        []model.ContinuationManifestV1{fixture.ContinuationManifest},
		ContinuityContinuationReleases: []model.ContinuationReleaseManifestV1{fixture.ContinuationReleaseManifest},
		ContinuityRestores:             []model.RestoreManifestV1{fixture.RestoreManifest},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.Manifest
	if err := json.Unmarshal(manifestPayload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.ContinuityContinuations, []model.ContinuationManifestV1{fixture.ContinuationManifest}) ||
		!reflect.DeepEqual(decoded.ContinuityContinuationReleases, []model.ContinuationReleaseManifestV1{fixture.ContinuationReleaseManifest}) ||
		!reflect.DeepEqual(decoded.ContinuityRestores, []model.RestoreManifestV1{fixture.RestoreManifest}) {
		t.Fatalf("continuation manifest tuple drifted: %#v", decoded)
	}

	reportPayload, err := json.Marshal(model.Report{
		ContinuityContinuations:        []model.ContinuationReportV1{fixture.ContinuationReport},
		ContinuityContinuationReleases: []model.ContinuationReleaseReportV1{fixture.ContinuationReleaseReport},
		ContinuityRestores:             []model.RestoreReportV1{fixture.RestoreReport},
	})
	if err != nil {
		t.Fatal(err)
	}
	var reportDocument map[string]json.RawMessage
	if err := json.Unmarshal(reportPayload, &reportDocument); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"continuityContinuations", "continuityContinuationReleases", "continuityRestores"} {
		if _, ok := reportDocument[field]; !ok {
			t.Fatalf("Runtime report omitted closed %s array: %s", field, reportPayload)
		}
	}
	if _, exists := reportDocument["context"]; exists {
		t.Fatalf("Runtime report leaked continuation context: %s", reportPayload)
	}
}

func TestContinuationWireUsesDedicatedIdentityWithoutCaptureTaskFields(t *testing.T) {
	fixture := loadContinuationRestoreFixture(t)
	payload, err := json.Marshal(fixture.ContinuationManifest.Identity)
	if err != nil {
		t.Fatal(err)
	}
	var identity map[string]json.RawMessage
	if err := json.Unmarshal(payload, &identity); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"taskId", "taskAttempt"} {
		if _, exists := identity[forbidden]; exists {
			t.Fatalf("continuation identity exposed capture-only %s: %s", forbidden, payload)
		}
	}
	if len(identity) != 6 {
		t.Fatalf("continuation identity is not the exact closed six-field tuple: %s", payload)
	}
}

func TestRuntimeConsumesBackendGeneratedContinuationRestoreFixtureVerbatim(t *testing.T) {
	payload, err := os.ReadFile("testdata/agent-continuation-v1.backend-wire.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture continuationBackendWireFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.FormatVersion != 1 || fixture.ContinuationManifest.OperationID != fixture.ContinuationReport.OperationID ||
		fixture.ContinuationManifest.OperationID != fixture.ContinuationBaseline.OperationID ||
		fixture.ContinuationManifest.DesiredRevision != fixture.ContinuationBaseline.DesiredRevision ||
		fixture.ContinuationManifest.Context.Digest != fixture.ContinuationBaseline.ContextDigest ||
		fixture.ContinuationReport.Baseline == nil || fixture.ContinuationReport.Baseline.BaselineID != fixture.ContinuationBaseline.BaselineID ||
		fixture.ContinuationReport.ReceiptDigest != fixture.ContinuationBaseline.ReceiptDigest ||
		fixture.ContinuationManifest.Binding.ServiceRegistrationID != fixture.ContinuationBaseline.ServiceRegistrationID ||
		fixture.ReleaseManifest.OperationID != fixture.ReleasePreparationManifest.OperationID ||
		fixture.ReleaseManifest.DesiredRevision <= fixture.ReleasePreparationManifest.DesiredRevision ||
		fixture.ReleaseReport.DesiredRevision != fixture.ReleaseManifest.DesiredRevision || fixture.ReleaseReport.Status != "released" ||
		fixture.FailedContinuationReport.Status != "failed" || fixture.FailedContinuationReport.Baseline != nil ||
		fixture.FailedContinuationReport.ErrorCode == nil ||
		fixture.RestoreManifest.OperationID != fixture.RestoreReport.OperationID {
		t.Fatalf("backend generated S2 tuple drifted: %#v", fixture)
	}
}
