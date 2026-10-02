package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type s2bBackendWireFixture struct {
	ReviewerManifest       ContinuationHandoffManifestV1        `json:"reviewerManifest"`
	ReviewerReport         ContinuationHandoffReportV1          `json:"reviewerReport"`
	RestoredTargetManifest ContinuationHandoffManifestV1        `json:"restoredTargetManifest"`
	RestoredTargetReport   ContinuationHandoffReportV1          `json:"restoredTargetReport"`
	ReleaseManifest        ContinuationHandoffReleaseManifestV1 `json:"handoffReleaseManifest"`
	ReleaseReport          ContinuationHandoffReleaseReportV1   `json:"handoffReleaseReport"`
	TargetRegistration     ContinuityRegistrationV1             `json:"reviewerTargetRegistration"`
	SessionHandoff         struct {
		Handoff SessionHandoffV1 `json:"handoff"`
	} `json:"reviewerSessionHandoffAfterRegistration"`
}

func readS2BBackendWireFixture(t *testing.T) s2bBackendWireFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "api", "testdata", "agent-continuation-handoff-v1.backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture s2bBackendWireFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestActualBackendContinuationHandoffFixturePreservesReviewerAndRestoreModes(t *testing.T) {
	fixture := readS2BBackendWireFixture(t)
	if err := validateContinuationHandoffManifest(fixture.ReviewerManifest, map[string]int64{
		fixture.ReviewerManifest.Identity.SandboxID:     fixture.ReviewerManifest.Identity.SandboxGeneration,
		fixture.ReviewerManifest.TargetPolicy.SandboxID: fixture.ReviewerManifest.TargetPolicy.SandboxGeneration,
	}); err != nil {
		t.Fatalf("reviewer manifest: %v", err)
	}
	if err := validateContinuationHandoffManifest(fixture.RestoredTargetManifest, map[string]int64{
		fixture.RestoredTargetManifest.Identity.SandboxID:     fixture.RestoredTargetManifest.Identity.SandboxGeneration,
		fixture.RestoredTargetManifest.TargetPolicy.SandboxID: fixture.RestoredTargetManifest.TargetPolicy.SandboxGeneration,
	}); err != nil {
		t.Fatalf("restored target manifest: %v", err)
	}
	if fixture.ReviewerManifest.Workspace.Mode != "allocate_and_materialize" ||
		fixture.ReviewerManifest.Workspace.SelectionID != nil ||
		fixture.ReviewerManifest.Lineage.RestoreOperationID != nil {
		t.Fatalf("reviewer workspace projection changed: %+v", fixture.ReviewerManifest.Workspace)
	}
	if fixture.RestoredTargetManifest.Workspace.Mode != "accepted_restore" ||
		fixture.RestoredTargetManifest.Workspace.SelectionID == nil ||
		fixture.RestoredTargetManifest.Lineage.RestoreOperationID == nil {
		t.Fatalf("restored workspace projection changed: %+v", fixture.RestoredTargetManifest.Workspace)
	}
	if !validContinuationHandoffReadyReport(fixture.ReviewerManifest, fixture.ReviewerReport) ||
		!validContinuationHandoffReadyReport(fixture.RestoredTargetManifest, fixture.RestoredTargetReport) {
		t.Fatal("actual helper-shaped ready report did not match its manifest")
	}
	if fixture.ReviewerReport.Session.NativeSessionID == fixture.ReviewerManifest.Binding.NativeSessionID ||
		fixture.ReviewerReport.Session.RegisteredSourceID == fixture.ReviewerManifest.Binding.RegisteredSourceID {
		t.Fatal("separate-session report reused the primary source")
	}
	if !validContinuationHandoffRelease(fixture.ReleaseManifest, fixture.ReleaseReport) {
		t.Fatal("actual release report did not match its explicit release manifest")
	}
	if fixture.TargetRegistration.Binding.NativeSessionID != fixture.ReviewerReport.Session.NativeSessionID ||
		fixture.SessionHandoff.Handoff.Source.NativeSessionID != fixture.ReviewerReport.Session.NativeSessionID {
		t.Fatal("target registration and owner handoff do not preserve the mapped session")
	}
}

func TestManifestAndReportExposeContinuationHandoffArrays(t *testing.T) {
	fixture := readS2BBackendWireFixture(t)
	manifest := Manifest{
		ContinuityHandoffs:        []ContinuationHandoffManifestV1{fixture.ReviewerManifest},
		ContinuityHandoffReleases: []ContinuationHandoffReleaseManifestV1{fixture.ReleaseManifest},
	}
	report := Report{
		ContinuityHandoffs:        []ContinuationHandoffReportV1{fixture.ReviewerReport},
		ContinuityHandoffReleases: []ContinuationHandoffReleaseReportV1{fixture.ReleaseReport},
	}
	encodedManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	encodedReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{"manifest": encodedManifest, "report": encodedReport} {
		if !json.Valid(encoded) || !containsJSONKey(encoded, "continuityHandoffs") ||
			!containsJSONKey(encoded, "continuityHandoffReleases") {
			t.Fatalf("%s omitted S2.B arrays: %s", name, encoded)
		}
	}
}

func containsJSONKey(payload []byte, key string) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(payload, &object) == nil && object[key] != nil
}
