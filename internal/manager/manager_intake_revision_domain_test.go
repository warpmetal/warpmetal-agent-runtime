package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
	control.canonical = model.InsightsManagerTargetEnvelopeV1{FormatVersion: 1, FindingID: review.FindingID,
		FindingRevision: review.FindingRevision, Source: review.Source, Target: review.Target}
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
	capability, evidence, err := journey.coordinator.reviewAuthority(ctx, journey.review, true)
	if err != nil || capability == nil || evidence == nil {
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

	// C1 r13 requirement-backed maintenance: an exact ACKed observation is
	// retained regardless of the current Off/not-current policy, while
	// automatic execution stays at zero. The previous oracle required the
	// observation itself to be discarded.
	t.Run("stale or non-current manager policy retains the observation with zero automatic execution", func(t *testing.T) {
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
				stored, err := journey.store.ManagerFinding(context.Background(), journey.finding.FindingID)
				if err != nil || stored == nil || !stored.Acknowledged || !reflect.DeepEqual(stored.Finding, journey.finding) {
					t.Fatalf("non-current observation was not retained: %#v %v", stored, err)
				}
				if len(journey.control.reservations) != 0 || len(journey.control.reports) != 0 {
					t.Fatalf("non-current observation performed an automatic action: %#v %#v", journey.control.reservations, journey.control.reports)
				}
			})
		}
	})

	// C1 r13 requirement-backed maintenance: allowed-rule eligibility gates
	// automatic execution only; the acknowledged observation is retained.
	t.Run("a disallowed rule is retained with zero automatic execution", func(t *testing.T) {
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
		stored, err := journey.store.ManagerFinding(context.Background(), journey.finding.FindingID)
		if err != nil || stored == nil || !stored.Acknowledged {
			t.Fatalf("disallowed-rule observation was not retained: %#v %v", stored, err)
		}
		if len(journey.control.reservations) != 0 || len(journey.control.reports) != 0 {
			t.Fatalf("disallowed rule started automatic work: %#v %#v", journey.control.reservations, journey.control.reports)
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

// TestManagerIntakeRetainsOffObservationForCurrentPolicyRecheck is the A0-6
// paired journey: an open finding acknowledged while the manager is Off is
// retained as observation evidence whose policy revision is provenance only,
// and a later manual recheck under the current Recommend policy is admitted
// without demanding that the historical observation policy equal the current
// execution policy. Automatic execution stays at zero while the observation is
// Off, and fresh effect authority is still required for the manual recheck.
func TestManagerIntakeRetainsOffObservationForCurrentPolicyRecheck(t *testing.T) {
	journey := newIntakeJourney(t, 4)
	ctx := context.Background()
	offPolicy := journey.policy
	offPolicy.Mode = "off"
	offPolicy.AllowedRules = nil
	offPolicy.PolicyRevision++
	offPolicy.RunGeneration++
	if err := journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{offPolicy}}); err != nil {
		t.Fatal(err)
	}
	if err := journey.coordinator.ObserveAcknowledgedInsightBatch(ctx, journey.batch, journey.receipt); err != nil {
		t.Fatal(err)
	}
	stored, err := journey.store.ManagerFinding(ctx, journey.finding.FindingID)
	if err != nil || stored == nil || !stored.Acknowledged || !reflect.DeepEqual(stored.Finding, journey.finding) {
		t.Fatalf("Off acknowledgement was not retained as observation evidence: %#v %v", stored, err)
	}
	if len(journey.control.reservations) != 0 || len(journey.control.reports) != 0 {
		t.Fatalf("Off acknowledgement performed an automatic action: %#v %#v", journey.control.reservations, journey.control.reports)
	}
	recommendPolicy := offPolicy
	recommendPolicy.Mode = "recommend"
	recommendPolicy.AllowedRules = []string{journey.finding.RuleID}
	recommendPolicy.PolicyRevision++
	recommendPolicy.RunGeneration++
	if err := journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{recommendPolicy}}); err != nil {
		t.Fatal(err)
	}
	review := journey.review
	review.PolicyRevision = recommendPolicy.PolicyRevision
	review.ValidUntil = recommendPolicy.ValidUntil
	capability, evidence, err := journey.coordinator.reviewAuthority(ctx, review, true)
	if err != nil || capability == nil || evidence == nil {
		t.Fatalf("current Recommend manual recheck refused historical Off evidence: %v", err)
	}
	if evidence["findingId"] != journey.finding.FindingID || evidence["findingRevision"] != journey.finding.Revision ||
		evidence["ruleId"] != journey.finding.RuleID {
		t.Fatalf("manual recheck used changed finding evidence: %#v", evidence)
	}
	// Fresh effect authority is preserved: the same retained evidence under an
	// Off current policy still fails before any control or helper action.
	guarded := recommendPolicy
	guarded.Mode = "off"
	guarded.AllowedRules = nil
	guarded.PolicyRevision++
	guarded.RunGeneration++
	if err := journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{guarded}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journey.coordinator.reviewAuthority(ctx, review, true); err == nil {
		t.Fatal("Off current policy admitted a manual review")
	}
	if len(journey.control.reservations) != 0 || len(journey.control.reports) != 0 {
		t.Fatalf("manual recheck admission performed a control action: %#v %#v", journey.control.reservations, journey.control.reports)
	}
}

// TestManagerReviewManifestCarriesCanonicalFindingEvidence is the optional
// paired-wire RED: the backend review manifest may carry the canonical 14-field
// Sandbox findingEvidence snapshot for an already-ACKed finding whose local
// batch record no longer exists. The strict manifest decoder must admit the
// optional field (today it refuses it as unknown), and the descriptor must keep
// the existing helper evidence shape.
func TestManagerReviewManifestCarriesCanonicalFindingEvidence(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	payload, err := os.ReadFile(filepath.Join("testdata", "sandbox.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sandbox struct {
		FindingEvidence map[string]any `json:"findingEvidence"`
	}
	if err := json.Unmarshal(payload, &sandbox); err != nil {
		t.Fatal(err)
	}
	if len(sandbox.FindingEvidence) != 14 {
		t.Fatalf("canonical findingEvidence shape changed: %d fields", len(sandbox.FindingEvidence))
	}
	existing := managerFindingEvidence(state.LocalManagerFinding{})
	existingKeys, manifestKeys := make([]string, 0, len(existing)), make([]string, 0, len(sandbox.FindingEvidence))
	for key := range existing {
		existingKeys = append(existingKeys, key)
	}
	for key := range sandbox.FindingEvidence {
		manifestKeys = append(manifestKeys, key)
	}
	sort.Strings(existingKeys)
	sort.Strings(manifestKeys)
	if !reflect.DeepEqual(existingKeys, manifestKeys) {
		t.Fatalf("canonical findingEvidence differs from the helper evidence shape: %#v %#v", existingKeys, manifestKeys)
	}
	evidenceFinding := model.InsightFindingV1{FindingID: fixture.Review.FindingID, RuleID: fixture.Review.RuleID, State: "open",
		Revision: fixture.Review.FindingRevision, FirstSequence: 1, LastSequence: 8, Count: 4, Threshold: 3,
		MatchedCallIDs: []string{"call_manager0001"}, FirstObservedAt: fixture.Review.ValidUntil.Add(-time.Minute),
		LastObservedAt: fixture.Review.ValidUntil.Add(-time.Minute), Coverage: "complete", ToolCategory: "shell", Phase: "tool"}
	canonical := managerFindingEvidence(state.LocalManagerFinding{Finding: evidenceFinding, Source: fixture.Review.Source,
		JournalGeneration: "journal_manager0001"})
	encodedReview, err := json.Marshal(fixture.Review)
	if err != nil {
		t.Fatal(err)
	}
	review := map[string]any{}
	if err := json.Unmarshal(encodedReview, &review); err != nil {
		t.Fatal(err)
	}
	review["findingEvidence"] = canonical
	manifestJSON, err := json.Marshal(map[string]any{"desiredRevision": 1, "insightsManagerReviews": []any{review}})
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestJSON))
	decoder.DisallowUnknownFields()
	var manifest model.Manifest
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("canonical optional findingEvidence was refused by the strict manifest decoder: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("canonical manifest decode trailing data: %v", err)
	}
	// The decoded authenticated manifest is consumed directly: the backend
	// snapshot is the reservation evidence, no local finding row exists, and
	// no batch/ACK history is manufactured.
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	seedManagerCoordinatorPrerequisites(t, store, fixture)
	helper := &fakeManagerHelper{reviewOutput: managerReviewReceipt(t, fixture, "start_review")}
	control := &fakeManagerControl{runForReport: managerRequestForReview(fixture.Review)}
	requireManagerStartReportBeforeHelper(t, helper, control)
	now := fixture.Review.ValidUntil.Add(-30 * time.Second)
	coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
	manifest.InsightsManagerPolicies = []model.InsightsManagerPolicyManifestV1{fixture.Policy}
	if err := coordinator.Apply(ctx, manifest); err != nil {
		t.Fatalf("findingEvidence manifest was refused by the coordinator: %v", err)
	}
	if len(helper.calls) != 1 || helper.calls[0].Payload["action"] != "start_review" {
		t.Fatalf("findingEvidence review helper calls = %#v", helper.calls)
	}
	actualJSON, err := json.Marshal(helper.calls[0].Payload["finding"])
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]any
	if err := json.Unmarshal(actualJSON, &actual); err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]any
	if err := json.Unmarshal(expectedJSON, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("canonical findingEvidence did not pass through exactly: %#v", actual)
	}
	if len(control.reports) != 2 || control.reports[0].State != "reviewing" || control.reports[1].State != "recommended" {
		t.Fatalf("findingEvidence review reports = %#v", control.reports)
	}
	if finding, err := store.ManagerFinding(ctx, fixture.Review.FindingID); err != nil || finding != nil {
		t.Fatalf("findingEvidence review manufactured local ACK history: %#v %v", finding, err)
	}
	if reservations, err := store.ManagerReservations(ctx); err != nil || len(reservations) != 0 {
		t.Fatalf("findingEvidence review created a reservation: %#v %v", reservations, err)
	}
}
