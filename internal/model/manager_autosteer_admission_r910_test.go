package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// r910 decision909 A: a saved auto_steer policy is admitted when its
// AutoSteerPolicy is the legacy nil form or the explicit non-executable
// unavailable form {formatVersion:1, available:false, qualifiedTuple:null,
// reason in native_guard_unqualified|runtime_unavailable|source_unavailable}.
// available:true requires the full valid tuple and a nil reason. Everything
// else stays invalid. The execution gates in internal/manager/guidance.go
// (reviewPolicyModeValid, autoSteerQualified) remain byte-unchanged, so an
// unavailable policy means zero reservation/start/provider/guidance effects.
func TestManagerSavedAutoSteerUnavailableFormsAdmittedNonExecutable(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "manager", "testdata", "backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture managerBackendFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	base := fixture.PolicyManifest
	base.Mode = "auto_steer"
	base.AutoSteerAvailable = false
	base.AutoSteerPolicy = nil

	validTuple := &InsightsManagerAutoSteerTupleV1{
		NativeGuardVersion: "warpmetal.atomic-input.v1", CustomNativeVersion: "1.0.0",
		NativeSourceRevision: "rev_managerpolicy0001",
		PatchDigest:          "sha256:" + strings.Repeat("a", 64),
		ArtifactSHA256:       "sha256:" + strings.Repeat("b", 64),
		BinarySHA256:         "sha256:" + strings.Repeat("c", 64),
		ImageDigest:          "sha256:" + strings.Repeat("d", 64),
		ManagerProfileDigest: "sha256:" + strings.Repeat("e", 64),
		ManagerPluginDigest:  "sha256:" + strings.Repeat("f", 64),
	}
	reason := func(value string) *string { return &value }

	cases := []struct {
		name    string
		mutate  func(*InsightsManagerPolicyManifestV1)
		wantErr bool
	}{
		{"legacy nil admitted non-executable", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = nil
		}, false},
		{"unavailable native_guard_unqualified admitted", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = &InsightsManagerAutoSteerPolicyV1{FormatVersion: 1, Reason: reason("native_guard_unqualified")}
		}, false},
		{"unavailable runtime_unavailable admitted", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = &InsightsManagerAutoSteerPolicyV1{FormatVersion: 1, Reason: reason("runtime_unavailable")}
		}, false},
		{"unavailable source_unavailable admitted", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = &InsightsManagerAutoSteerPolicyV1{FormatVersion: 1, Reason: reason("source_unavailable")}
		}, false},
		{"available false without reason stays invalid", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = &InsightsManagerAutoSteerPolicyV1{FormatVersion: 1}
		}, true},
		{"available false with tuple stays invalid", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = &InsightsManagerAutoSteerPolicyV1{FormatVersion: 1, QualifiedTuple: validTuple}
		}, true},
		{"available true without tuple stays invalid", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = &InsightsManagerAutoSteerPolicyV1{FormatVersion: 1, Available: true}
		}, true},
		{"available true with reason stays invalid", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = &InsightsManagerAutoSteerPolicyV1{
				FormatVersion: 1, Available: true, Reason: reason("native_guard_unqualified"), QualifiedTuple: validTuple,
			}
		}, true},
		{"format two stays invalid", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = &InsightsManagerAutoSteerPolicyV1{FormatVersion: 2, Reason: reason("native_guard_unqualified")}
		}, true},
		{"unknown reason stays invalid", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = &InsightsManagerAutoSteerPolicyV1{FormatVersion: 1, Reason: reason("foreign_reason")}
		}, true},
		{"qualified available true admitted", func(policy *InsightsManagerPolicyManifestV1) {
			policy.AutoSteerPolicy = &InsightsManagerAutoSteerPolicyV1{FormatVersion: 1, Available: true, QualifiedTuple: validTuple}
		}, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := base
			policy.AutoSteerPolicy = nil
			testCase.mutate(&policy)
			err := ValidateInsightsManagerPolicyManifest(policy)
			if testCase.wantErr != (err != nil) {
				t.Fatalf("validate error = %v, wantErr %v", err, testCase.wantErr)
			}
		})
	}
}
