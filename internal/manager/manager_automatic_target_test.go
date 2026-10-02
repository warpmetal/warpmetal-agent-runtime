package manager

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type automaticTargetJourney struct {
	fixture     managerCoordinatorFixture
	policy      model.InsightsManagerPolicyManifestV1
	source      model.InsightsManagerSourceV1
	sandboxID   string
	store       *state.Store
	control     *fakeManagerControl
	coordinator *Coordinator
	finding     model.InsightFindingV1
	batch       model.InsightBatchV1
	receipt     model.InsightBatchReceiptV1
	expected    model.InsightsManagerTargetV1
	minimal     model.InsightsManagerTargetV1
}

func stringPointer(value string) *string { return &value }
func intPointer(value int64) *int64      { return &value }

func (journey *automaticTargetJourney) setRegistration(t *testing.T, observed string) {
	t.Helper()
	registration := state.LocalContinuityRegistration{
		Manifest: model.ContinuityRegistrationV1{
			FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: 1,
			Identity: model.ContinuityIdentityV1{
				WorkID: "work_live_manager_insights_20260929l9a", ProjectID: "project_manager0001",
				SandboxID: journey.sandboxID, WorkspaceEpoch: journey.source.WorkspaceEpoch,
				SandboxGeneration: journey.source.SandboxGeneration, ExpectedRevision: 1,
			},
			Binding: model.ContinuityBindingV1{
				BindingID: "binding_live_manager_20260929l9a", BindingRevision: 1,
				RegisteredSourceID: journey.source.RegisteredSourceID, ServiceRegistrationID: journey.source.ServiceRegistrationID,
				NativeSessionID: journey.source.NativeSessionID, NativeProjectID: strings.Repeat("0", 40),
				NativeLocationDigest: "sha256:" + strings.Repeat("e", 64),
			},
		},
		ObservedStatus: observed, ServiceGeneration: journey.source.ServiceGeneration,
	}
	if err := journey.store.PutContinuityRegistration(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
}

func (journey *automaticTargetJourney) complete(t *testing.T) {
	t.Helper()
	// The dispatch itself is allowed to fail (the helper is a stub); the
	// reservation request recorded by the control is what this journey proves.
	_ = journey.coordinator.ObserveAcknowledgedInsightBatch(context.Background(), journey.batch, journey.receipt)
}

func newAutomaticTargetJourney(t *testing.T) *automaticTargetJourney {
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
	control := &fakeManagerControl{dynamic: true}
	control.reservation = model.InsightsManagerReservationV1{
		ExpiresAt: now.Add(30 * time.Second),
		Execution: model.InsightsManagerReservationExecutionV1{
			ManagerProfile: fixture.Review.ManagerProfile, ProviderRouteDigest: fixture.Review.ProviderRouteDigest,
		},
		Remaining: model.InsightsManagerRemainingV1{
			SandboxDailyRuns: 10, SandboxHourlyRuns: 5, SandboxDailyInputTokens: 100000,
			SandboxDailyOutputTokens: 10000, SessionRuns24h: 1, ServerConcurrentRuns: 1, ServerHourlyStarts: 5,
		},
	}
	coordinator := &Coordinator{Store: store, Control: control, Helper: &fakeManagerHelper{}, Now: func() time.Time { return now }}
	ctx := context.Background()
	if err := coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}); err != nil {
		t.Fatal(err)
	}
	source := fixture.RecommendTakeover.Source
	sandboxID := fixture.RecommendTakeoverPolicy.SandboxID
	finding := model.InsightFindingV1{
		FindingID: "finding_auto0001", RuleID: fixture.Review.RuleID, State: "open", Revision: 1,
		FirstSequence: 1, LastSequence: 4, Count: 4, Threshold: 4, MatchedCallIDs: []string{"call_auto0001"},
		FirstObservedAt: now.Add(-time.Minute), LastObservedAt: now, Coverage: "complete", ToolCategory: "shell", Phase: "tool",
	}
	batch := model.InsightBatchV1{
		FormatVersion: 1, BatchID: "batch_auto0001", SandboxID: sandboxID,
		SandboxGeneration: source.SandboxGeneration, PolicyRevision: 4,
		RegisteredSourceID: source.RegisteredSourceID, ServiceRegistrationID: source.ServiceRegistrationID,
		ServiceGeneration: source.ServiceGeneration, WorkspaceEpoch: source.WorkspaceEpoch,
		NativeSessionID: source.NativeSessionID, JournalGeneration: "journal_auto0001",
		ThroughSequence: 4, ObservedAt: now, Status: "streaming", Findings: []model.InsightFindingV1{finding},
	}
	return &automaticTargetJourney{
		fixture: fixture, policy: policy, source: source, sandboxID: sandboxID, store: store, control: control,
		coordinator: coordinator, finding: finding, batch: batch,
		receipt: model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: 1, ThroughSequence: batch.ThroughSequence},
		expected: model.InsightsManagerTargetV1{
			TeamID: fixture.RecommendTakeover.Target.TeamID, MemberID: fixture.RecommendTakeover.Target.MemberID,
			WorkID: stringPointer("work_live_manager_insights_20260929l9a"), WorkRevision: intPointer(1),
			BindingID: stringPointer("binding_live_manager_20260929l9a"), BindingRevision: intPointer(1),
		},
		minimal: model.InsightsManagerTargetV1{
			TeamID: fixture.RecommendTakeover.Target.TeamID, MemberID: fixture.RecommendTakeover.Target.MemberID,
		},
	}
}

// TestManagerAutomaticTargetMatchesDescriptorWorkBinding is the paired .42 ->
// .43 journey: the automatic reservation target must carry the exact verified
// Work binding fields the backend descriptor derives from the same continuity
// registration, fall back to the minimal descriptor target when no verified
// binding exists, and re-derive a pending reservation created before the
// correction without clearing or migration.
func TestManagerAutomaticTargetMatchesDescriptorWorkBinding(t *testing.T) {
	t.Run("verified binding yields the descriptor target", func(t *testing.T) {
		journey := newAutomaticTargetJourney(t)
		journey.setRegistration(t, "verified")
		journey.complete(t)
		if len(journey.control.reservations) != 1 {
			t.Fatalf("automatic reservations = %#v", journey.control.reservations)
		}
		got := journey.control.reservations[0]
		if got.Manual || got.FindingID != journey.finding.FindingID || !reflectTargetEqual(got.Target, journey.expected) {
			t.Fatalf("automatic target = %#v, want %#v", got.Target, journey.expected)
		}
	})
	t.Run("a verified binding for another source is ignored", func(t *testing.T) {
		journey := newAutomaticTargetJourney(t)
		registration := state.LocalContinuityRegistration{
			Manifest: model.ContinuityRegistrationV1{
				FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: 1,
				Identity: model.ContinuityIdentityV1{
					WorkID: "work_other0001", ProjectID: "project_other0001", SandboxID: journey.sandboxID,
					WorkspaceEpoch: journey.source.WorkspaceEpoch, SandboxGeneration: journey.source.SandboxGeneration,
					ExpectedRevision: 1,
				},
				Binding: model.ContinuityBindingV1{
					BindingID: "binding_other0001", BindingRevision: 1,
					RegisteredSourceID: "source_other0001", ServiceRegistrationID: journey.source.ServiceRegistrationID,
					NativeSessionID: journey.source.NativeSessionID, NativeProjectID: strings.Repeat("0", 40),
					NativeLocationDigest: "sha256:" + strings.Repeat("e", 64),
				},
			},
			ObservedStatus: "verified", ServiceGeneration: journey.source.ServiceGeneration,
		}
		if err := journey.store.PutContinuityRegistration(context.Background(), registration); err != nil {
			t.Fatal(err)
		}
		journey.complete(t)
		if len(journey.control.reservations) != 1 || !reflectTargetEqual(journey.control.reservations[0].Target, journey.minimal) {
			t.Fatalf("foreign binding target = %#v", journey.control.reservations)
		}
	})
	t.Run("no binding falls back to the minimal target", func(t *testing.T) {
		journey := newAutomaticTargetJourney(t)
		journey.complete(t)
		if len(journey.control.reservations) != 1 || !reflectTargetEqual(journey.control.reservations[0].Target, journey.minimal) {
			t.Fatalf("unbound target = %#v", journey.control.reservations)
		}
	})
	t.Run("a pending pre-correction reservation recovers with the descriptor target", func(t *testing.T) {
		journey := newAutomaticTargetJourney(t)
		journey.setRegistration(t, "verified")
		control := journey.control
		request := model.InsightsManagerReservationRequestV1{
			FormatVersion: 1, ReservationID: "reservation_auto0001", RequestID: "req_manager_auto0001",
			Manual: false, FindingID: journey.finding.FindingID, FindingRevision: journey.finding.Revision,
			PolicyRevision: journey.policy.PolicyRevision, RuleID: journey.finding.RuleID,
			RecipeID: journey.fixture.Review.RecipeID, ProviderRouteDigest: journey.fixture.Review.ProviderRouteDigest,
			Source: journey.source, Target: journey.minimal,
			Budget: model.InsightsManagerBudgetV1{ModelRequests: 1, InputTokens: 1, OutputTokens: 1}, ExpiresInSeconds: 60,
		}
		if err := journey.store.PutManagerReservation(context.Background(), state.LocalManagerReservation{Request: request, Phase: "pending"}); err != nil {
			t.Fatal(err)
		}
		if err := journey.coordinator.Recover(context.Background()); err != nil {
			t.Fatalf("recover re-derivation failed: %v", err)
		}
		if len(control.reservations) != 1 {
			t.Fatalf("recovered reservations = %#v", control.reservations)
		}
		if !reflectTargetEqual(control.reservations[0].Target, journey.expected) {
			t.Fatalf("recovered target = %#v, want %#v", control.reservations[0].Target, journey.expected)
		}
	})
}

func reflectTargetEqual(left, right model.InsightsManagerTargetV1) bool {
	equal := func(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	equalInt := func(a, b *int64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	return left.TeamID == right.TeamID && left.MemberID == right.MemberID && equal(left.TaskID, right.TaskID) &&
		equalInt(left.TaskAttempt, right.TaskAttempt) && equal(left.WorkID, right.WorkID) && equalInt(left.WorkRevision, right.WorkRevision) &&
		equal(left.BindingID, right.BindingID) && equalInt(left.BindingRevision, right.BindingRevision)
}
