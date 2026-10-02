package manager

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type intakeJourney struct {
	fixture     managerCoordinatorFixture
	policy      model.InsightsManagerPolicyManifestV1
	store       *state.Store
	control     *fakeManagerControl
	coordinator *Coordinator
	finding     model.InsightFindingV1
	batch       model.InsightBatchV1
	receipt     model.InsightBatchReceiptV1
	review      model.InsightsManagerReviewManifestV1
}

func newIntakeJourney(t *testing.T, batchPolicyRevision int64) *intakeJourney {
	t.Helper()
	fixture := loadManagerCoordinatorFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	authority := fixture
	authority.Policy = fixture.RecommendTakeoverPolicy
	authority.Review.Source = fixture.RecommendTakeover.Source
	authority.Review.Target = fixture.RecommendTakeover.Target
	authority.Review.PolicyRevision = fixture.RecommendTakeover.PolicyRevision
	authority.Review.FindingRevision = fixture.RecommendTakeover.FindingRevision
	authority.Review.ValidUntil = fixture.RecommendTakeover.ValidUntil
	seedManagerCoordinatorAuthority(t, store, authority)
	policy := fixture.RecommendTakeoverPolicy
	policy.Mode = "recommend"
	policy.AllowedRules = []string{fixture.Review.RuleID}
	now := policy.ValidUntil.Add(-30 * time.Second)
	control := &fakeManagerControl{}
	coordinator := &Coordinator{Store: store, Control: control, Helper: &fakeManagerHelper{}, Now: func() time.Time { return now }}
	ctx := context.Background()
	if err := coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}); err != nil {
		t.Fatal(err)
	}
	source := fixture.RecommendTakeover.Source
	target := model.InsightsManagerTargetV1{TeamID: fixture.RecommendTakeover.Target.TeamID, MemberID: fixture.RecommendTakeover.Target.MemberID}
	finding := model.InsightFindingV1{
		FindingID: "finding_intake0001", RuleID: fixture.Review.RuleID, State: "open", Revision: 1,
		FirstSequence: 10, LastSequence: 14, Count: 4, Threshold: 4, MatchedCallIDs: []string{"call_intake0001"},
		FirstObservedAt: now.Add(-time.Minute), LastObservedAt: now, Coverage: "complete", ToolCategory: "shell", Phase: "tool",
	}
	if batchPolicyRevision == 0 {
		// 0 selects the manager policy's own revision for the matching-domain case.
		batchPolicyRevision = policy.PolicyRevision
	}
	batch := model.InsightBatchV1{
		FormatVersion: 1, BatchID: "batch_intake0001", SandboxID: fixture.RecommendTakeoverPolicy.SandboxID,
		SandboxGeneration: source.SandboxGeneration, PolicyRevision: batchPolicyRevision,
		RegisteredSourceID: source.RegisteredSourceID, ServiceRegistrationID: source.ServiceRegistrationID,
		ServiceGeneration: source.ServiceGeneration, WorkspaceEpoch: source.WorkspaceEpoch, NativeSessionID: source.NativeSessionID,
		JournalGeneration: "journal_intake0001", ThroughSequence: 14, ObservedAt: now, Status: "streaming",
		Findings: []model.InsightFindingV1{finding},
	}
	receipt := model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: len(batch.Findings), ThroughSequence: batch.ThroughSequence}
	review := model.InsightsManagerReviewManifestV1{
		FormatVersion: 1, ReservationID: "reservation_intake0001", RunID: "run_intake0001", Manual: true,
		FindingID: finding.FindingID, FindingRevision: finding.Revision, PolicyRevision: policy.PolicyRevision,
		RuleID: finding.RuleID, RecipeID: fixture.Review.RecipeID,
		ProviderRouteDigest: fixture.Review.ProviderRouteDigest, ManagerProfile: fixture.Review.ManagerProfile,
		Source: source, Target: target, Budget: model.InsightsManagerBudgetV1{ModelRequests: 1, InputTokens: 1, OutputTokens: 1},
		ValidUntil: now.Add(time.Minute),
	}
	// A prior run for the same finding keeps the automatic path ineligible, so the
	// journey observes the intake alone: no reservation, run, or provider action.
	prior := review
	prior.ReservationID = "reservation_intake0000"
	prior.RunID = "run_intake0000"
	if err := store.PutManagerRun(ctx, state.LocalManagerRun{Manifest: prior, Phase: "recommended", StartedAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return &intakeJourney{fixture: fixture, policy: policy, store: store, control: control, coordinator: coordinator,
		finding: finding, batch: batch, receipt: receipt, review: review}
}

// TestManagerIntakeKeepsManagerPolicyRevisionDomain is the paired .41 -> .42
// journey: the insights batch carries the insights/monitor policy revision,
// which is an independent counter from the manager policy revision. On .41 the
// intake silently skipped (no local acknowledged finding) and the review was
// refused with "manager finding authority changed"; on .42 the finding is
// intaken with the manager-domain revision and the same review passes.
func TestManagerIntakeKeepsManagerPolicyRevisionDomain(t *testing.T) {
	journey := newIntakeJourney(t, 4)
	ctx := context.Background()
	if err := journey.coordinator.ObserveAcknowledgedInsightBatch(ctx, journey.batch, journey.receipt); err != nil {
		t.Fatalf("intake returned error: %v", err)
	}
	stored, err := journey.store.ManagerFinding(ctx, journey.finding.FindingID)
	if err != nil || stored == nil {
		_, _, authorityErr := journey.coordinator.reviewAuthority(ctx, journey.review, true)
		t.Fatalf("finding was not intaken (RED on .41): %#v %v; review authority: %v", stored, err, authorityErr)
	}
	if !stored.Acknowledged || stored.PolicyRevision != journey.policy.PolicyRevision || stored.Source != journey.review.Source ||
		stored.JournalGeneration != journey.batch.JournalGeneration || !reflect.DeepEqual(stored.Finding, journey.finding) {
		t.Fatalf("intaken finding domain = %#v", stored)
	}
	if runs, err := journey.store.ManagerRuns(ctx); err != nil || len(runs) != 1 {
		t.Fatalf("intake changed runs: %#v %v", runs, err)
	}
	if reservations, err := journey.store.ManagerReservations(ctx); err != nil || len(reservations) != 0 {
		t.Fatalf("intake created reservations: %#v %v", reservations, err)
	}
	if len(journey.control.reservations) != 0 || len(journey.control.reports) != 0 {
		t.Fatalf("intake performed a control/provider action: %#v %#v", journey.control.reservations, journey.control.reports)
	}
	capability, finding, err := journey.coordinator.reviewAuthority(ctx, journey.review, true)
	if err != nil || capability == nil || finding == nil {
		t.Fatalf("review authority after intake (RED on .41: manager finding authority changed): %v", err)
	}
}

func TestManagerIntakeFailClosedNegatives(t *testing.T) {
	t.Run("matching revision domains still intake", func(t *testing.T) {
		journey := newIntakeJourney(t, 0) // the batch carries the manager policy's own revision
		if err := journey.coordinator.ObserveAcknowledgedInsightBatch(context.Background(), journey.batch, journey.receipt); err != nil {
			t.Fatal(err)
		}
		stored, err := journey.store.ManagerFinding(context.Background(), journey.finding.FindingID)
		if err != nil || stored == nil || stored.PolicyRevision != journey.policy.PolicyRevision {
			t.Fatalf("matching-domain intake = %#v %v", stored, err)
		}
	})

	t.Run("stale or non-current manager policy declines the intake", func(t *testing.T) {
		for name, mutate := range map[string]func(*model.InsightsManagerPolicyManifestV1){
			"off": func(policy *model.InsightsManagerPolicyManifestV1) { policy.Mode = "off"; policy.AllowedRules = nil },
			"out of window": func(policy *model.InsightsManagerPolicyManifestV1) {
				policy.ValidUntil = policy.ValidUntil.Add(3 * time.Hour)
			},
		} {
			t.Run(name, func(t *testing.T) {
				journey := newIntakeJourney(t, 4)
				policy := journey.policy
				mutate(&policy)
				if err := journey.coordinator.Apply(context.Background(), model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}); err != nil {
					t.Fatal(err)
				}
				if err := journey.coordinator.ObserveAcknowledgedInsightBatch(context.Background(), journey.batch, journey.receipt); err != nil {
					t.Fatal(err)
				}
				if stored, err := journey.store.ManagerFinding(context.Background(), journey.finding.FindingID); err != nil || stored != nil {
					t.Fatalf("intake wrote under a non-current policy: %#v %v", stored, err)
				}
				if len(journey.control.reservations) != 0 || len(journey.control.reports) != 0 {
					t.Fatalf("declined intake performed a control action: %#v %#v", journey.control.reservations, journey.control.reports)
				}
			})
		}
	})

	t.Run("a disallowed rule is not intaken", func(t *testing.T) {
		journey := newIntakeJourney(t, 4)
		policy := journey.policy
		disallowed := "suspected_stall@1"
		if disallowed == journey.finding.RuleID {
			disallowed = "repeated_identical_call@1"
		}
		policy.AllowedRules = []string{disallowed}
		if err := journey.coordinator.Apply(context.Background(), model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}); err != nil {
			t.Fatal(err)
		}
		if err := journey.coordinator.ObserveAcknowledgedInsightBatch(context.Background(), journey.batch, journey.receipt); err != nil {
			t.Fatal(err)
		}
		if stored, err := journey.store.ManagerFinding(context.Background(), journey.finding.FindingID); err != nil || stored != nil {
			t.Fatalf("disallowed-rule finding was intaken: %#v %v", stored, err)
		}
	})

	t.Run("receipt mismatches still error", func(t *testing.T) {
		journey := newIntakeJourney(t, 4)
		for name, corrupt := range map[string]func(*model.InsightBatchReceiptV1){
			"accepted":        func(receipt *model.InsightBatchReceiptV1) { receipt.Accepted = 2 },
			"throughSequence": func(receipt *model.InsightBatchReceiptV1) { receipt.ThroughSequence = 15 },
		} {
			t.Run(name, func(t *testing.T) {
				receipt := journey.receipt
				corrupt(&receipt)
				if err := journey.coordinator.ObserveAcknowledgedInsightBatch(context.Background(), journey.batch, receipt); err == nil {
					t.Fatal("mismatched receipt was accepted")
				}
				if stored, err := journey.store.ManagerFinding(context.Background(), journey.finding.FindingID); err != nil || stored != nil {
					t.Fatalf("mismatched receipt wrote a finding: %#v %v", stored, err)
				}
			})
		}
	})

	t.Run("a mismatched review is still refused", func(t *testing.T) {
		journey := newIntakeJourney(t, 4)
		ctx := context.Background()
		if err := journey.coordinator.ObserveAcknowledgedInsightBatch(ctx, journey.batch, journey.receipt); err != nil {
			t.Fatal(err)
		}
		review := journey.review
		review.PolicyRevision = 4
		if _, _, err := journey.coordinator.reviewAuthority(ctx, review, true); err == nil {
			t.Fatal("review with a foreign policy revision was accepted")
		}
	})
}
