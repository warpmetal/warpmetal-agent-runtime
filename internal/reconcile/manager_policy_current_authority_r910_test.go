package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// r910 decision909 B: outgoing manager policy reports are scoped to the
// current validated authority identity
// (sandboxId, sandboxGeneration, policyRevision, runGeneration). The lease
// validUntil and capability-driven AutoSteerPolicy drift never grant identity.
// Reviews, takeovers and guidance settlement paths stay unfiltered, and
// current policy status/revision reports keep their existing capability/stale
// derivation.
func TestManagerPolicyReportsScopedToCurrentAuthorityIdentity(t *testing.T) {
	ctx := context.Background()
	journey := newManagerPolicyJourney(t)
	journey.control.enrollErr = errors.New("managed workspace is unavailable")
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err == nil {
		t.Fatal("ordinary pass unexpectedly completed")
	}
	type policyKey struct {
		sandboxID         string
		sandboxGeneration int64
		policyRevision    int64
		runGeneration     int64
	}
	keyOf := func(policy model.InsightsManagerPolicyReportV1) policyKey {
		return policyKey{policy.SandboxID, policy.SandboxGeneration, policy.PolicyRevision, policy.RunGeneration}
	}

	before, err := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if err != nil {
		t.Fatalf("report construction failed: %v", err)
	}
	if len(before.InsightsManagerPolicies) == 0 {
		t.Fatal("setup: fixture stored no policy rows to report")
	}

	// Stale authority: every current policy identity moves by +2 run
	// generations, so the stored rows are no longer current. No policy report
	// may be emitted (the stored capability/source rows must not leak).
	stale := journey.manifest
	stale.InsightsManagerPolicies = append([]model.InsightsManagerPolicyManifestV1(nil), journey.manifest.InsightsManagerPolicies...)
	for index := range stale.InsightsManagerPolicies {
		stale.InsightsManagerPolicies[index].RunGeneration += 2
	}
	journey.reconciler.setCurrentAuthority(stale)
	report, err := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if err != nil {
		t.Fatalf("stale-authority report construction failed: %v", err)
	}
	if len(report.InsightsManagerPolicies) != 0 {
		t.Fatalf("stale authority emitted %d manager policy reports: %#v", len(report.InsightsManagerPolicies), report.InsightsManagerPolicies)
	}

	// Current authority keeps the exact current policy report.
	journey.reconciler.setCurrentAuthority(journey.manifest)
	current, err := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if err != nil {
		t.Fatalf("current-authority report construction failed: %v", err)
	}
	allowed := map[policyKey]bool{}
	for _, policy := range journey.manifest.InsightsManagerPolicies {
		allowed[policyKey{policy.SandboxID, policy.SandboxGeneration, policy.PolicyRevision, policy.RunGeneration}] = true
	}
	found := false
	for _, policy := range current.InsightsManagerPolicies {
		if !allowed[keyOf(policy)] {
			t.Fatalf("current report emitted a noncurrent policy tuple: %#v", policy)
		}
		found = true
	}
	if !found {
		t.Fatalf("current authority dropped the current policy report: %#v", current.InsightsManagerPolicies)
	}
}
