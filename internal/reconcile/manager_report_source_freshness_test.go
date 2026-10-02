package reconcile

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

const managerPolicySourceID = "source_managerpolicy0001"

// storedSource reads the journey's authentic stored continuity source row.
func (journey *managerPolicyJourney) storedSource(t *testing.T) state.LocalContinuitySource {
	t.Helper()
	source, err := journey.store.ContinuitySource(context.Background(), managerPolicySourceID)
	if err != nil || source == nil {
		t.Fatalf("stored continuity source = %#v, %v", source, err)
	}
	return *source
}

// setSourceObservation writes the authentic stored observation the report must
// serialize. It changes only the observation itself: the ordinary available
// reporting state and running lifecycle a stalled observation loop leaves
// behind, with the caller's exact stored timestamp.
func (journey *managerPolicyJourney) setSourceObservation(t *testing.T, observedAt time.Time) {
	t.Helper()
	source := journey.storedSource(t)
	source.Report.Availability = "available"
	source.Report.Reason = nil
	source.Report.LastObservedAt = observedAt
	source.Lifecycle = "running"
	if err := journey.store.PutContinuitySource(context.Background(), source); err != nil {
		t.Fatal(err)
	}
}

// managerPolicyReportJourney drives the real pass and report construction: the
// pass fails at managed-service enrollment after the sandbox is observed, then
// the stored source observation is rewritten to the caller's observation age
// and the ordinary end-of-pass report is built.
func managerPolicyReportJourney(t *testing.T, age time.Duration) (*managerPolicyJourney, model.Report) {
	t.Helper()
	journey := newManagerPolicyJourney(t)
	ctx := context.Background()
	journey.control.enrollErr = errors.New("managed workspace is unavailable")
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err == nil {
		t.Fatal("ordinary pass unexpectedly completed")
	}
	journey.setSourceObservation(t, journey.reconciler.Now().Add(-age))
	report, err := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if err != nil {
		t.Fatalf("report construction failed: %v", err)
	}
	return journey, report
}

// managerSourceItem returns the report's continuity source item for the given
// registered source.
func managerSourceItem(t *testing.T, report model.Report, registeredSourceID string) model.ContinuitySourceReportV1 {
	t.Helper()
	for _, item := range report.ContinuitySources {
		if item.RegisteredSourceID == registeredSourceID {
			return item
		}
	}
	t.Fatalf("report carries no item for %s: %#v", registeredSourceID, report.ContinuitySources)
	return model.ContinuitySourceReportV1{}
}

// managerCapabilityItem returns the policy report's capability item for the
// given registered source.
func managerCapabilityItem(t *testing.T, report model.Report, registeredSourceID string) model.InsightsManagerRecommendCapabilityV1 {
	t.Helper()
	if len(report.InsightsManagerPolicies) != 1 {
		t.Fatalf("manager policy reports = %#v", report.InsightsManagerPolicies)
	}
	for _, item := range report.InsightsManagerPolicies[0].RecommendCapabilities {
		if item.Source.RegisteredSourceID == registeredSourceID {
			return item
		}
	}
	t.Fatalf("policy report carries no capability for %s: %#v", registeredSourceID, report.InsightsManagerPolicies[0].RecommendCapabilities)
	return model.InsightsManagerRecommendCapabilityV1{}
}

// TestReconcileReportDerivesStaleSourceAsFailClosedUnavailable is the A19R
// journey. A continuity source whose authentic stored observation is older than
// the shared freshness contract is reported as unavailable with its real
// observation timestamp and identity preserved, and the manager capability item
// that references it derives the fail-closed pair the node API documents for a
// stale source: available=false with reason source_unavailable. The whole
// report then follows that documented admission path instead of looping on a
// refusal that no ordinary report can ever clear.
func TestReconcileReportDerivesStaleSourceAsFailClosedUnavailable(t *testing.T) {
	journey, report := managerPolicyReportJourney(t, 121*time.Second)
	stored := journey.storedSource(t)

	item := managerSourceItem(t, report, managerPolicySourceID)
	if !item.LastObservedAt.Equal(stored.Report.LastObservedAt) {
		t.Errorf("stale source observation timestamp was not preserved: got %s, stored %s", item.LastObservedAt, stored.Report.LastObservedAt)
	}
	wantReason := "source_unavailable"
	want := stored.Report
	want.Availability = "unavailable"
	want.Reason = &wantReason
	if !reflect.DeepEqual(item, want) {
		t.Errorf("stale source serialization drifted from the authentic stored observation:\n got %#v\nwant %#v", item, want)
	}

	capability := managerCapabilityItem(t, report, managerPolicySourceID)
	if capability.Source != (model.InsightsManagerSourceV1{
		RegisteredSourceID: stored.Report.RegisteredSourceID, WorkspaceEpoch: stored.Report.WorkspaceEpoch,
		NativeSessionID: stored.Report.NativeSessionID, ServiceRegistrationID: stored.Report.ServiceRegistrationID,
		ServiceGeneration: stored.Report.ServiceGeneration, SandboxGeneration: stored.Report.SandboxGeneration,
		ProfileRevision: stored.Report.ProfileRevision, InstructionRevision: stored.Report.InstructionRevision,
	}) {
		t.Errorf("capability source identity drifted: %#v", capability.Source)
	}
	if capability.Available || capability.Reason == nil || *capability.Reason != "source_unavailable" {
		t.Errorf("stale-referencing capability did not derive the documented fail-closed pair: %#v", capability)
	}
}

// TestReconcileReportDerivesStaleUnavailableSourceCapability covers the same
// single decision applied to a source that was already reported unavailable:
// the stale source item keeps its authentic reason and timestamp untouched,
// while every capability item that references it is still derived as the
// fail-closed pair, because the node API admits a stale source only through
// that pair and would otherwise refuse on the capability's own reason.
func TestReconcileReportDerivesStaleUnavailableSourceCapability(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	ctx := context.Background()
	// Clone the journey authority into a second registered source that is
	// already unavailable and has carried its own unavailability reason since
	// registration; capabilities are immutable per generation, so this state is
	// seeded before the pass rather than rewritten after it.
	observedAt := journey.reconciler.Now().Add(-time.Hour)
	secondSourceID := "source_managerpolicy0002"
	secondServiceID := "service_managerpolicy0002"
	source := journey.storedSource(t)
	source.Report.RegisteredSourceID = secondSourceID
	source.Report.ServiceRegistrationID = secondServiceID
	source.Report.WorkspaceEpoch = "epoch_managerpolicy0002"
	source.Report.NativeSessionID = "ses_managerpolicy0002"
	source.Report.Availability = "unavailable"
	sourceReason := "service_failed"
	source.Report.Reason = &sourceReason
	source.Report.LastObservedAt = observedAt
	source.Lifecycle = "running"
	if err := journey.store.PutContinuitySource(ctx, source); err != nil {
		t.Fatal(err)
	}
	capability, err := journey.store.ManagerCapability(ctx, managerPolicySourceID)
	if err != nil || capability == nil {
		t.Fatalf("stored manager capability = %#v, %v", capability, err)
	}
	secondCapability := *capability
	secondCapability.RegisteredSourceID = secondSourceID
	secondCapability.ServiceRegistrationID = secondServiceID
	secondCapability.WorkspaceEpoch = source.Report.WorkspaceEpoch
	secondCapability.NativeSessionID = source.Report.NativeSessionID
	secondCapability.Available = false
	secondCapability.Reason = "native_guard_unqualified"
	if err := journey.store.PutManagerCapability(ctx, secondCapability); err != nil {
		t.Fatal(err)
	}
	journey.control.enrollErr = errors.New("managed workspace is unavailable")
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err == nil {
		t.Fatal("ordinary pass unexpectedly completed")
	}
	report, err := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if err != nil {
		t.Fatalf("report construction failed: %v", err)
	}
	item := managerSourceItem(t, report, secondSourceID)
	if !reflect.DeepEqual(item, source.Report) {
		t.Fatalf("already-unavailable stale source serialization drifted:\n got %#v\nwant %#v", item, source.Report)
	}
	capabilityItem := managerCapabilityItem(t, report, secondSourceID)
	if capabilityItem.Available || capabilityItem.Reason == nil || *capabilityItem.Reason != "source_unavailable" {
		t.Fatalf("stale-referencing capability did not derive the documented fail-closed pair: %#v", capabilityItem)
	}
}

// TestReconcileReportPreservesFreshSourceAvailability proves the other side of
// the same single decision: an observation on or inside the existing
// 120-second contract is never downgraded, so a genuine re-observation restores
// ordinary available reporting for both the source item and its capability.
func TestReconcileReportPreservesFreshSourceAvailability(t *testing.T) {
	for _, testCase := range []struct {
		name string
		age  time.Duration
	}{
		{"fresh re-observation restores ordinary reporting", 30 * time.Second},
		{"observation exactly on the freshness boundary is not downgraded", continuity.SourceFreshness},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			journey, report := managerPolicyReportJourney(t, testCase.age)
			stored := journey.storedSource(t)
			item := managerSourceItem(t, report, managerPolicySourceID)
			if !reflect.DeepEqual(item, stored.Report) {
				t.Fatalf("fresh source serialization drifted:\n got %#v\nwant %#v", item, stored.Report)
			}
			if item.Availability != "available" || item.Reason != nil {
				t.Fatalf("fresh source was downgraded: %#v", item)
			}
			capability := managerCapabilityItem(t, report, managerPolicySourceID)
			if !capability.Available || capability.Reason != nil {
				t.Fatalf("fresh-referencing capability was downgraded: %#v", capability)
			}
			if !report.InsightsManagerPolicies[0].Recommend.Available || report.InsightsManagerPolicies[0].Recommend.Reason != nil {
				t.Fatalf("fresh policy rollup was downgraded: %#v", report.InsightsManagerPolicies[0].Recommend)
			}
		})
	}
}
