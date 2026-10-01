package model

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type managerBackendFixture struct {
	PolicyManifest       InsightsManagerPolicyManifestV1 `json:"managerPolicyManifest"`
	ManualReviewManifest InsightsManagerReviewManifestV1 `json:"manualReviewManifest"`
	TakeoverManifest     InsightsTakeoverManifestV1      `json:"takeoverManifest"`
	TakeoverReport       InsightsTakeoverReportV1        `json:"takeoverReadyReport"`
	ManagerHandoff       struct {
		Handoff SessionHandoffV1 `json:"handoff"`
	} `json:"managerSessionHandoff"`
}

func TestManagerBackendWireModelsAreClosedAndManifestReportArraysValidate(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "manager", "testdata", "backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture managerBackendFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInsightsManagerPolicyManifest(fixture.PolicyManifest); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInsightsManagerReviewManifest(fixture.ManualReviewManifest); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInsightsTakeoverManifest(fixture.TakeoverManifest); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
		ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
		Capacity:    Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20},
		Sandboxes: []Sandbox{{ID: fixture.PolicyManifest.SandboxID, Name: "manager-review", Size: "small",
			Resources: Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			Lifetime:  "persistent", DesiredState: "running", Generation: fixture.PolicyManifest.SandboxGeneration}},
		InsightsManagerPolicies: []InsightsManagerPolicyManifestV1{fixture.PolicyManifest},
		InsightsManagerReviews:  []InsightsManagerReviewManifestV1{fixture.ManualReviewManifest},
		InsightsTakeovers:       []InsightsTakeoverManifestV1{fixture.TakeoverManifest},
	}
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err != nil {
		t.Fatal(err)
	}
	report := Report{
		ServerID: manifest.ServerID, AppliedRevision: 1, SupervisorVersion: "test",
		InsightsManagerPolicies: []InsightsManagerPolicyReportV1{},
		InsightsManagerReviews:  []InsightsManagerRunReportV1{},
		InsightsTakeovers:       []InsightsTakeoverReportV1{fixture.TakeoverReport},
	}
	encoded, err := json.Marshal(report)
	if err != nil || !json.Valid(encoded) {
		t.Fatalf("manager report = %s, %v", encoded, err)
	}
}

func TestManagerReviewAcceptsIndependentNullableTaskAndWorkTuplesButRejectsPartialGroups(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "manager", "testdata", "backend.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var canonical struct {
		Review json.RawMessage `json:"reviewManifest"`
	}
	if err := json.Unmarshal(payload, &canonical); err != nil {
		t.Fatal(err)
	}
	decode := func(t *testing.T, mutate func(map[string]any)) InsightsManagerReviewManifestV1 {
		t.Helper()
		var raw map[string]any
		if err := json.Unmarshal(canonical.Review, &raw); err != nil {
			t.Fatal(err)
		}
		mutate(raw["target"].(map[string]any))
		encoded, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		var value InsightsManagerReviewManifestV1
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	workOnly := decode(t, func(target map[string]any) {
		target["taskId"], target["taskAttempt"] = nil, nil
		target["workId"], target["workRevision"] = "work_manager0001", 4
		target["bindingId"], target["bindingRevision"] = "binding_manager0001", 2
	})
	if err := ValidateInsightsManagerReviewManifest(workOnly); err != nil {
		t.Fatalf("independent Work tuple rejected: %v", err)
	}
	taskOnly := decode(t, func(target map[string]any) {
		target["workId"], target["workRevision"] = nil, nil
		target["bindingId"], target["bindingRevision"] = nil, nil
	})
	if err := ValidateInsightsManagerReviewManifest(taskOnly); err != nil {
		t.Fatalf("independent task tuple rejected: %v", err)
	}
	partialTask := decode(t, func(target map[string]any) { target["taskAttempt"] = nil })
	if err := ValidateInsightsManagerReviewManifest(partialTask); err == nil {
		t.Fatal("partial task tuple accepted")
	}
	partialWork := decode(t, func(target map[string]any) {
		target["taskId"], target["taskAttempt"] = nil, nil
		target["workId"], target["workRevision"] = "work_manager0001", 4
		target["bindingId"], target["bindingRevision"] = nil, nil
	})
	if err := ValidateInsightsManagerReviewManifest(partialWork); err == nil {
		t.Fatal("partial Work/binding tuple accepted")
	}
}
