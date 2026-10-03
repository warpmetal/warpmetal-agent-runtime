package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// r928 decision909 B exact clause: manager policy capability items survive only
// when all eight InsightsManagerSourceV1 identity fields match a source
// serialized in the SAME report. Absent or mismatched items are omitted while
// the current policy report itself is retained, with the existing rollup/digest
// recomputation and 120s fail-closed derivation for included stale sources.
func TestManagerPolicyCapabilitiesProjectSameReportSources(t *testing.T) {
	ctx := context.Background()
	journey := newManagerPolicyJourney(t)
	journey.control.enrollErr = errors.New("managed workspace is unavailable")
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err == nil {
		t.Fatal("ordinary pass unexpectedly completed")
	}
	hasCapability := func(report model.Report) bool {
		for _, policy := range report.InsightsManagerPolicies {
			for _, capability := range policy.RecommendCapabilities {
				if capability.Source.RegisteredSourceID == "source_managerpolicy0001" {
					return true
				}
			}
		}
		return false
	}
	baseline, err := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if err != nil {
		t.Fatalf("report construction failed: %v", err)
	}
	if len(baseline.InsightsManagerPolicies) == 0 {
		t.Fatal("setup: no current policy report")
	}
	if !hasCapability(baseline) {
		t.Fatal("setup: baseline capability missing for the matching same-report source")
	}

	// The cached capability's source is no longer serialized with the same
	// eight-field identity: the offending capability item must be omitted while
	// the current policy report stays in place.
	source, err := journey.store.ContinuitySource(ctx, "source_managerpolicy0001")
	if err != nil || source == nil {
		t.Fatalf("stored source = %#v, %v", source, err)
	}
	changed := *source
	changed.Report.NativeSessionID = "ses_managerpolicy0002"
	if err := journey.store.PutContinuitySource(ctx, changed); err != nil {
		t.Fatal(err)
	}
	report, err := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if err != nil {
		t.Fatalf("report construction failed: %v", err)
	}
	if len(report.InsightsManagerPolicies) == 0 {
		t.Fatal("current policy report was dropped")
	}
	if hasCapability(report) {
		t.Fatal("capability with a non-serialized source identity was not omitted")
	}
}
