package manager

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
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
	helper      *fakeManagerHelper
	finding     model.InsightFindingV1
	batch       model.InsightBatchV1
	receipt     model.InsightBatchReceiptV1
	expected    model.InsightsManagerTargetV1
	minimal     model.InsightsManagerTargetV1
	now         time.Time
}

func stringPointer(value string) *string { return &value }
func intPointer(value int64) *int64      { return &value }

func (journey *automaticTargetJourney) setRegistration(t *testing.T, observed string) {
	t.Helper()
	journey.putRegistration(t, observed, nil, nil, 1)
}

// putRegistration seeds the verified Work registration with explicit provenance
// task fields and expected revision so a journey can model the real Task3
// shape (a registration verified before the task with taskId/taskAttempt
// null), a registration refreshed to a new work revision, or stale provenance
// task fields that must not veto the canonical target.
func (journey *automaticTargetJourney) putRegistration(t *testing.T, observed string, taskID *string, taskAttempt *int64, expectedRevision int64) {
	t.Helper()
	registration := state.LocalContinuityRegistration{
		Manifest: model.ContinuityRegistrationV1{
			FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: 1,
			Identity: model.ContinuityIdentityV1{
				WorkID: "work_live_manager_insights_20260929l9a", ProjectID: "project_manager0001",
				SandboxID: journey.sandboxID, WorkspaceEpoch: journey.source.WorkspaceEpoch,
				SandboxGeneration: journey.source.SandboxGeneration, ExpectedRevision: expectedRevision,
				TaskID: taskID, TaskAttempt: taskAttempt,
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

// putTaskAuthorityValue seeds the live member-task authority exactly as the
// managed worker status activeTask observation persists it.
func (journey *automaticTargetJourney) putTaskAuthorityValue(t *testing.T, value state.LocalManagedTaskAuthority) {
	t.Helper()
	if err := journey.store.PutManagedTaskAuthority(context.Background(), value); err != nil {
		t.Fatal(err)
	}
}

// putLiveTaskAuthority seeds a fresh Busy authority with an exact active
// task/attempt, or an idle authority when taskID is empty.
func (journey *automaticTargetJourney) putLiveTaskAuthority(t *testing.T, taskID string, attempt int64, busy bool, observedAt time.Time) {
	t.Helper()
	value := state.LocalManagedTaskAuthority{
		ServiceRegistrationID: journey.source.ServiceRegistrationID,
		ServiceGeneration:     journey.source.ServiceGeneration,
		SandboxGeneration:     journey.source.SandboxGeneration,
		ObservedAt:            observedAt,
	}
	if taskID != "" {
		value.TaskID = stringPointer(taskID)
		value.TaskAttempt = intPointer(attempt)
	}
	value.Busy = busy
	journey.putTaskAuthorityValue(t, value)
}

// setCanonical pins the canonical descriptor envelope the node-authorized
// target read returns for this journey.
func (journey *automaticTargetJourney) setCanonical(t *testing.T, target model.InsightsManagerTargetV1) {
	t.Helper()
	journey.control.canonical = model.InsightsManagerTargetEnvelopeV1{
		FormatVersion: 1, FindingID: journey.finding.FindingID, FindingRevision: journey.finding.Revision,
		Source: journey.source, Target: target,
	}
}

// canonicalWithTask returns the journey Work target plus the canonical
// active/waiting task pair.
func (journey *automaticTargetJourney) canonicalWithTask(taskID string, attempt int64) model.InsightsManagerTargetV1 {
	target := journey.expected
	target.TaskID, target.TaskAttempt = stringPointer(taskID), intPointer(attempt)
	return target
}

func (journey *automaticTargetJourney) observe(t *testing.T) {
	t.Helper()
	// Observation persists the durable anchor and performs only the bounded
	// read-only canonical capture; every effect is owned by the end-of-pass Apply.
	_ = journey.coordinator.ObserveAcknowledgedInsightBatch(context.Background(), journey.batch, journey.receipt)
}

func (journey *automaticTargetJourney) complete(t *testing.T) {
	t.Helper()
	// The full production order for one pass: observation, then the real
	// end-of-pass manager boundary. The dispatch itself may fail (helper stub).
	journey.observe(t)
	_ = journey.coordinator.Apply(context.Background(), model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{journey.policy}})
}

// seedAcknowledgedFinding records the exact acknowledged finding so recovery
// paths can reach the post-ACK canonical guard without an intake observation.
func (journey *automaticTargetJourney) seedAcknowledgedFinding(t *testing.T) {
	t.Helper()
	if err := journey.store.PutManagerFinding(context.Background(), state.LocalManagerFinding{
		Finding: journey.finding, Source: journey.source, PolicyRevision: journey.policy.PolicyRevision,
		JournalGeneration: journey.batch.JournalGeneration, Acknowledged: true,
	}); err != nil {
		t.Fatal(err)
	}
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
	helper := &fakeManagerHelper{}
	coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
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
	journey := &automaticTargetJourney{
		fixture: fixture, policy: policy, source: source, sandboxID: sandboxID, store: store, control: control,
		coordinator: coordinator, finding: finding, batch: batch, now: now, helper: helper,
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
	journey.setCanonical(t, journey.expected)
	return journey
}

// TestManagerAutomaticTargetMatchesDescriptorWorkBinding is the consolidated
// canonical r1370 journey: the automatic reservation target is the fresh
// node-authorized descriptor, accepted for an active task with a matching
// Busy worker and for a waiting task with an idle worker, rejected when the
// canonical read is missing, when the local Busy task contradicts canonical,
// or when the Work revision projection has not caught up; an existing pending
// reservation is replayed from its persisted body without a canonical read.
func TestManagerAutomaticTargetMatchesDescriptorWorkBinding(t *testing.T) {
	t.Run("canonical active and waiting targets post exactly", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			taskID string
			busy   bool
		}{
			{name: "active", taskID: "task_canon0001", busy: true},
			{name: "waiting", taskID: "task_canon0002"},
		} {
			t.Run(test.name, func(t *testing.T) {
				journey := newAutomaticTargetJourney(t)
				journey.setRegistration(t, "verified")
				canonical := journey.canonicalWithTask(test.taskID, 1)
				journey.setCanonical(t, canonical)
				if test.busy {
					journey.putLiveTaskAuthority(t, test.taskID, 1, true, journey.now)
				} else {
					journey.putLiveTaskAuthority(t, "", 0, false, journey.now)
				}
				journey.complete(t)
				if len(journey.control.reservations) != 1 {
					t.Fatalf("automatic reservations = %#v", journey.control.reservations)
				}
				if got := journey.control.reservations[0].Target; !reflectTargetEqual(got, canonical) {
					t.Fatalf("canonical target = %#v, want %#v", got, canonical)
				}
				if len(journey.control.events) < 3 || journey.control.events[0] != "canonical" || journey.control.events[1] != "canonical" || journey.control.events[2] != "reserve" {
					t.Fatalf("canonical/reserve ordering = %#v", journey.control.events)
				}
				if len(journey.helper.calls) == 0 {
					t.Fatal("canonical match did not reach the dispatch path")
				}
				runs, err := journey.store.ManagerRuns(context.Background())
				if err != nil || len(runs) != 1 || !reflectTargetEqual(runs[0].Manifest.Target, canonical) {
					t.Fatalf("admitted run target = %#v, %v, want %#v", runs, err, canonical)
				}
			})
		}
	})
	t.Run("a missing canonical descriptor rejects without a reservation", func(t *testing.T) {
		journey := newAutomaticTargetJourney(t)
		journey.setRegistration(t, "verified")
		journey.control.canonicalErr = errors.New("injected target read unknown")
		journey.complete(t)
		if len(journey.control.reservations) != 0 {
			t.Fatalf("missing canonical descriptor posted = %#v", journey.control.reservations)
		}
		if len(journey.control.events) != 1 || journey.control.events[0] != "canonical" {
			t.Fatalf("missing canonical ordering = %#v", journey.control.events)
		}
	})
	t.Run("a Busy contradiction rejects without a reservation", func(t *testing.T) {
		journey := newAutomaticTargetJourney(t)
		journey.setRegistration(t, "verified")
		journey.setCanonical(t, journey.canonicalWithTask("task_canon0001", 1))
		journey.putLiveTaskAuthority(t, "task_canon0002", 1, true, journey.now)
		journey.complete(t)
		if len(journey.control.reservations) != 0 {
			t.Fatalf("Busy contradiction posted = %#v", journey.control.reservations)
		}
		if len(journey.control.events) != 2 || journey.control.events[0] != "canonical" || journey.control.events[1] != "canonical" {
			t.Fatalf("Busy contradiction ordering = %#v", journey.control.events)
		}
	})
	t.Run("a Busy task against a null canonical target rejects without a reservation", func(t *testing.T) {
		journey := newAutomaticTargetJourney(t)
		journey.setRegistration(t, "verified")
		journey.setCanonical(t, journey.expected)
		journey.putLiveTaskAuthority(t, "task_canon0001", 1, true, journey.now)
		journey.complete(t)
		if len(journey.control.reservations) != 0 {
			t.Fatalf("Busy mismatch against a null canonical target posted = %#v", journey.control.reservations)
		}
		if len(journey.control.events) != 2 || journey.control.events[0] != "canonical" || journey.control.events[1] != "canonical" {
			t.Fatalf("Busy/null mismatch ordering = %#v", journey.control.events)
		}
	})
	t.Run("a Work revision projection mismatch fails closed", func(t *testing.T) {
		journey := newAutomaticTargetJourney(t)
		journey.setRegistration(t, "verified")
		canonical := journey.expected
		canonical.WorkRevision, canonical.BindingRevision = intPointer(2), intPointer(2)
		journey.setCanonical(t, canonical)
		journey.complete(t)
		if len(journey.control.reservations) != 0 {
			t.Fatalf("projection mismatch posted = %#v", journey.control.reservations)
		}
		if len(journey.control.events) != 2 || journey.control.events[0] != "canonical" || journey.control.events[1] != "canonical" {
			t.Fatalf("projection mismatch ordering = %#v", journey.control.events)
		}
	})
	t.Run("an existing pending reservation replays its persisted body without recomputation", func(t *testing.T) {
		journey := newAutomaticTargetJourney(t)
		journey.setRegistration(t, "verified")
		journey.seedAcknowledgedFinding(t)
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
		journey.setCanonical(t, journey.canonicalWithTask("task_canon0001", 1))
		if err := journey.coordinator.Recover(context.Background()); err != nil {
			t.Fatalf("recover failed: %v", err)
		}
		if len(control.reservations) != 1 {
			t.Fatalf("recovered reservations = %#v", control.reservations)
		}
		if got := control.reservations[0]; !reflect.DeepEqual(got, request) {
			t.Fatalf("recovery recomputed the persisted body = %#v, want %#v", got, request)
		}
		// The persisted reservation replay must happen before any canonical
		// read; after the ACK a fresh canonical comparison is required before
		// any paid/native effect, and a mismatch must not dispatch or mutate
		// the stored request.
		if len(control.events) < 2 || control.events[0] != "reserve" || control.events[1] != "canonical" {
			t.Fatalf("reserve/canonical ordering = %#v", control.events)
		}
		if len(journey.helper.calls) != 0 {
			t.Fatalf("canonical mismatch dispatched provider work: %#v", journey.helper.calls)
		}
		stored, err := journey.store.ManagerReservation(context.Background(), request.ReservationID)
		if err != nil || stored == nil || !reflect.DeepEqual(stored.Request, request) {
			t.Fatalf("canonical mismatch mutated the persisted request = %#v %v", stored, err)
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

// TestManagerDeferredAdmissionRecoversAfterTransientPolicyGateWithoutNewBatch
// is the r1497 RED for the evidenced primary-path liveness blocker: an accepted
// finding whose automatic admission is blocked by a controlled transient gate
// must still admit exactly one reservation and run for the original task once
// the gate clears and Recover runs, without a new batch.
//
// The gate used here is an expired-then-renewed policy lease. It is a
// deliberate fixture choice and does not claim to be the historical Task4
// cause (the at-batch values were not retained). The Task4 task identity is
// used for the bound canonical target.
func TestManagerDeferredAdmissionRecoversAfterTransientPolicyGateWithoutNewBatch(t *testing.T) {
	const taskID = "task_mUQ6klDxlPEnqIRpkLw8teCW"
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	journey.setRegistration(t, "verified")
	journey.putLiveTaskAuthority(t, taskID, 1, true, journey.now)
	journey.finding.FindingID = "finding_e9f2069895184350fa2dc9d0"
	journey.batch.Findings[0].FindingID = journey.finding.FindingID
	canonical := journey.canonicalWithTask(taskID, 1)
	journey.setCanonical(t, canonical)

	storedPolicy, err := journey.store.ManagerPolicy(ctx, journey.sandboxID)
	if err != nil || storedPolicy == nil {
		t.Fatalf("stored policy = %#v %v", storedPolicy, err)
	}
	expired := *storedPolicy
	expired.Manifest.ValidUntil = journey.now.Add(-time.Second)
	if err := journey.store.PutManagerPolicy(ctx, expired); err != nil {
		t.Fatal(err)
	}

	journey.observe(t) // accepted batch; the controlled transient gate blocks admission
	if reservations, err := journey.store.ManagerReservations(ctx); err != nil || len(reservations) != 0 {
		t.Fatalf("transient gate persisted reservations = %#v %v", reservations, err)
	}
	accepted, err := journey.store.ManagerFinding(ctx, journey.finding.FindingID)
	if err != nil || accepted == nil || !accepted.Acknowledged {
		t.Fatalf("accepted finding = %#v %v", accepted, err)
	}

	// The gate clears (policy lease renewed) with no new batch. Reconsideration
	// runs at the real end-of-pass manager boundary (Apply).
	renewed := *storedPolicy
	renewed.Manifest.ValidUntil = journey.now.Add(30 * time.Second)
	if err := journey.store.PutManagerPolicy(ctx, renewed); err != nil {
		t.Fatal(err)
	}
	journey.helper.reviewOutput = managerReviewReceipt(t, journey.fixture, "start_review")
	manifest := model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{renewed.Manifest}}
	// The stub native dispatch may fail after admission (same contract as the
	// journey's complete helper); the durable reservation/run are the oracle.
	_ = journey.coordinator.Apply(ctx, manifest)
	if len(journey.control.reservations) != 1 {
		t.Fatalf("deferred admission reservations = %#v, want exactly one", journey.control.reservations)
	}
	if got := journey.control.reservations[0].Target; !reflectTargetEqual(got, canonical) {
		t.Fatalf("deferred admission target = %#v, want %#v", got, canonical)
	}
	runs, err := journey.store.ManagerRuns(ctx)
	if err != nil || len(runs) != 1 || !reflectTargetEqual(runs[0].Manifest.Target, canonical) {
		t.Fatalf("deferred admission runs = %#v %v, want exactly one for the original task", runs, err)
	}
	if err := journey.coordinator.Apply(ctx, manifest); err != nil || len(journey.control.reservations) != 1 {
		t.Fatalf("second apply duplicated admission = %#v %v", journey.control.reservations, err)
	}
}

// TestManagerDeferredAdmissionNeverRetargetsChangedOrNullTask guards the new
// deferred path: a deferred admission anchored to the original canonical task
// must never resolve to a later task or to a null task.
func TestManagerDeferredAdmissionNeverRetargetsChangedOrNullTask(t *testing.T) {
	const taskA = "task_mUQ6klDxlPEnqIRpkLw8teCW"
	const taskB = "task_other0001"
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	journey.setRegistration(t, "verified")
	journey.putLiveTaskAuthority(t, taskA, 1, true, journey.now)
	journey.setCanonical(t, journey.canonicalWithTask(taskA, 1))

	storedPolicy, err := journey.store.ManagerPolicy(ctx, journey.sandboxID)
	if err != nil || storedPolicy == nil {
		t.Fatalf("stored policy = %#v %v", storedPolicy, err)
	}
	expired := *storedPolicy
	expired.Manifest.ValidUntil = journey.now.Add(-time.Second)
	if err := journey.store.PutManagerPolicy(ctx, expired); err != nil {
		t.Fatal(err)
	}
	journey.observe(t)

	renewed := *storedPolicy
	renewed.Manifest.ValidUntil = journey.now.Add(30 * time.Second)
	manifest := model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{renewed.Manifest}}

	// The canonical task changed before admission: refuse, never retarget.
	journey.setCanonical(t, journey.canonicalWithTask(taskB, 1))
	if err := journey.coordinator.Apply(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if len(journey.control.reservations) != 0 {
		t.Fatalf("changed task was retargeted = %#v", journey.control.reservations)
	}
	// A null canonical pair must not be admitted for the anchored task either.
	journey.setCanonical(t, journey.expected)
	if err := journey.coordinator.Apply(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if len(journey.control.reservations) != 0 {
		t.Fatalf("null task was retargeted = %#v", journey.control.reservations)
	}
}

// TestManagerDeferredAdmissionRetiresOnOffOrLineageChange guards that a
// deferred admission is retired by Off or by a changed policy lineage and is
// never revived by a later opt-in.
func TestManagerDeferredAdmissionRetiresOnOffOrLineageChange(t *testing.T) {
	const taskA = "task_mUQ6klDxlPEnqIRpkLw8teCW"
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	journey.setRegistration(t, "verified")
	journey.putLiveTaskAuthority(t, taskA, 1, true, journey.now)
	journey.setCanonical(t, journey.canonicalWithTask(taskA, 1))

	storedPolicy, err := journey.store.ManagerPolicy(ctx, journey.sandboxID)
	if err != nil || storedPolicy == nil {
		t.Fatalf("stored policy = %#v %v", storedPolicy, err)
	}
	expired := *storedPolicy
	expired.Manifest.ValidUntil = journey.now.Add(-time.Second)
	if err := journey.store.PutManagerPolicy(ctx, expired); err != nil {
		t.Fatal(err)
	}
	journey.observe(t)

	off := journey.policy
	off.Mode = "off"
	off.AllowedRules = []string{}
	off.PolicyRevision++
	off.RunGeneration++
	off.ValidUntil = journey.now.Add(30 * time.Second)
	if err := journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{off}}); err != nil {
		t.Fatal(err)
	}
	if len(journey.control.reservations) != 0 {
		t.Fatalf("off lineage admitted = %#v", journey.control.reservations)
	}

	// A later opt-in with a fresh lineage must not revive the retired finding.
	fresh := journey.policy
	fresh.PolicyRevision += 2
	fresh.RunGeneration += 2
	fresh.ValidUntil = journey.now.Add(30 * time.Second)
	if err := journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fresh}}); err != nil {
		t.Fatal(err)
	}
	if len(journey.control.reservations) != 0 {
		t.Fatalf("later opt-in revived a retired admission = %#v", journey.control.reservations)
	}
}

// TestManagerApplyLeavesLegacyAcknowledgedFindingsInert guards that findings
// acknowledged before the admission mechanism (no admission marker) are never
// backfilled or retriggered by the end-of-pass apply.
func TestManagerApplyLeavesLegacyAcknowledgedFindingsInert(t *testing.T) {
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	seedManagerFinding(t, journey.store, journey.fixture)
	legacy, err := journey.store.ManagerFinding(ctx, journey.fixture.Review.FindingID)
	if err != nil || legacy == nil || !legacy.Acknowledged {
		t.Fatalf("legacy acknowledged finding = %#v %v", legacy, err)
	}
	if err := journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{journey.policy}}); err != nil {
		t.Fatal(err)
	}
	if len(journey.control.reservations) != 0 || journey.control.canonicalCalls != 0 {
		t.Fatalf("legacy finding was backfilled = %#v canonical=%d", journey.control.reservations, journey.control.canonicalCalls)
	}
}

// TestManagerDeferredAdmissionDefersTransientAutoSteerQualification (r1507-f1)
// guards that a temporarily unqualified auto_steer pair is deferred, not
// terminal-declined, and never produces an effect before qualification.
func TestManagerDeferredAdmissionDefersTransientAutoSteerQualification(t *testing.T) {
	const taskA = "task_mUQ6klDxlPEnqIRpkLw8teCW"
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	// Seed the qualified pair capability at the next generation so the only
	// transient readiness transition in this oracle is the policy tuple.
	capability, err := journey.store.ManagerCapability(ctx, journey.source.RegisteredSourceID)
	if err != nil || capability == nil {
		t.Fatalf("capability = %#v %v", capability, err)
	}
	qualified := q2MergeQualifiedCapability(t, *capability)
	newGeneration := journey.source.ServiceGeneration + 1
	qualified.ServiceGeneration = newGeneration
	qualified.NativeVersion = q2CustomVersion
	qualified.NativeSourceRevision = q2SourceRevision
	qualified.ManagerPluginDigest = q2PluginDigest
	if err := journey.store.PutManagerCapability(ctx, qualified); err != nil {
		t.Fatal(err)
	}
	continuity, err := journey.store.ContinuitySource(ctx, journey.source.RegisteredSourceID)
	if err != nil || continuity == nil {
		t.Fatalf("continuity source = %#v %v", continuity, err)
	}
	continuity.Report.ServiceGeneration = newGeneration
	if err := journey.store.PutContinuitySource(ctx, *continuity); err != nil {
		t.Fatal(err)
	}
	journey.source.ServiceGeneration = newGeneration
	journey.batch.ServiceGeneration = newGeneration
	journey.setRegistration(t, "verified")
	journey.putLiveTaskAuthority(t, taskA, 1, true, journey.now)
	journey.setCanonical(t, journey.canonicalWithTask(taskA, 1))
	storedPolicy, err := journey.store.ManagerPolicy(ctx, journey.sandboxID)
	if err != nil || storedPolicy == nil {
		t.Fatalf("stored policy = %#v %v", storedPolicy, err)
	}
	auto := *storedPolicy
	auto.Manifest.Mode = "auto_steer"
	auto.Manifest.AutoSteerPolicy = nil
	if err := journey.store.PutManagerPolicy(ctx, auto); err != nil {
		t.Fatal(err)
	}
	journey.observe(t)
	stored, err := journey.store.ManagerFinding(ctx, journey.finding.FindingID)
	if err != nil || stored == nil || stored.Admission == nil {
		t.Fatalf("admission anchor = %#v %v", stored, err)
	}
	if stored.Admission.State == "declined" {
		t.Fatalf("transient qualification declined permanently: %#v", stored.Admission)
	}
	_ = journey.coordinator.Apply(ctx, model.Manifest{})
	if len(journey.control.reservations) != 0 {
		t.Fatalf("unqualified auto_steer admitted = %#v", journey.control.reservations)
	}
	stored, _ = journey.store.ManagerFinding(ctx, journey.finding.FindingID)
	if stored.Admission.State != "deferred" || stored.Admission.Reason != "qualification" {
		t.Fatalf("qualification deferral = %#v", stored.Admission)
	}
	// The pair becomes qualified with no new batch and no lineage change:
	// exactly one reservation/run for the original task, then no duplicate.
	qualifiedPolicy := q2MergeQualifiedPolicy(t, auto.Manifest, journey.fixture.Review.ManagerProfile.ProfileDigest)
	if err := journey.store.PutManagerPolicy(ctx, state.LocalManagerPolicy{Manifest: qualifiedPolicy, Report: auto.Report}); err != nil {
		t.Fatal(err)
	}
	journey.helper.reviewOutput = managerReviewReceipt(t, journey.fixture, "start_review")
	_ = journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{qualifiedPolicy}})
	if len(journey.control.reservations) != 1 {
		t.Fatalf("qualified auto_steer reservations = %#v, want exactly one", journey.control.reservations)
	}
	if got := journey.control.reservations[0].Target; !reflectTargetEqual(got, journey.canonicalWithTask(taskA, 1)) {
		t.Fatalf("qualified target = %#v", got)
	}
	runs, err := journey.store.ManagerRuns(ctx)
	if err != nil || len(runs) != 1 {
		t.Fatalf("qualified runs = %#v %v, want exactly one", runs, err)
	}
	_ = journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{qualifiedPolicy}})
	if len(journey.control.reservations) != 1 {
		t.Fatalf("second apply duplicated the qualified admission = %#v", journey.control.reservations)
	}
}

// TestManagerDeferredAdmissionAdmitsAdvancedWorkRevision (r1507-f3) guards that
// the anchor freezes only team/member/task/attempt and admits the current
// canonical Work/binding revision once the verified registration advances.
func TestManagerDeferredAdmissionAdmitsAdvancedWorkRevision(t *testing.T) {
	const taskA = "task_mUQ6klDxlPEnqIRpkLw8teCW"
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	journey.setRegistration(t, "verified")
	journey.putLiveTaskAuthority(t, taskA, 1, true, journey.now)
	journey.setCanonical(t, journey.canonicalWithTask(taskA, 1))
	storedPolicy, err := journey.store.ManagerPolicy(ctx, journey.sandboxID)
	if err != nil || storedPolicy == nil {
		t.Fatalf("stored policy = %#v %v", storedPolicy, err)
	}
	expired := *storedPolicy
	expired.Manifest.ValidUntil = journey.now.Add(-time.Second)
	if err := journey.store.PutManagerPolicy(ctx, expired); err != nil {
		t.Fatal(err)
	}
	journey.observe(t)

	advanced := journey.canonicalWithTask(taskA, 1)
	advanced.WorkRevision = intPointer(2)
	journey.setCanonical(t, advanced)
	journey.putRegistration(t, "verified", nil, nil, 2)
	renewed := *storedPolicy
	renewed.Manifest.ValidUntil = journey.now.Add(30 * time.Second)
	_ = journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{renewed.Manifest}})
	if len(journey.control.reservations) != 1 {
		t.Fatalf("advanced Work revision reservations = %#v, want exactly one", journey.control.reservations)
	}
	if got := journey.control.reservations[0].Target; got.WorkRevision == nil || *got.WorkRevision != 2 {
		t.Fatalf("advanced Work revision target = %#v, want revision 2", got)
	}
}

// TestManagerDeferredEpisodeDedupeIncludesLegacyIdentity (r1507-f4) guards the
// auto_steer stable-findingId episode against a legacy batch-derived automatic
// reservation: no fresh canonical read and no second attempt, and Recover
// replays the stored request byte-identical.
func TestManagerDeferredEpisodeDedupeIncludesLegacyIdentity(t *testing.T) {
	const taskA = "task_mUQ6klDxlPEnqIRpkLw8teCW"
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	journey.setRegistration(t, "verified")
	journey.putLiveTaskAuthority(t, taskA, 1, true, journey.now)
	journey.setCanonical(t, journey.canonicalWithTask(taskA, 1))
	storedPolicy, err := journey.store.ManagerPolicy(ctx, journey.sandboxID)
	if err != nil || storedPolicy == nil {
		t.Fatalf("stored policy = %#v %v", storedPolicy, err)
	}
	auto := *storedPolicy
	auto.Manifest.Mode = "auto_steer"
	auto.Manifest.AutoSteerPolicy = nil
	// The retained episode predates the current policy lineage: the backend
	// episode lookup has no policy-revision filter, so the runtime must dedupe
	// across revisions too.
	auto.Manifest.PolicyRevision++
	auto.Manifest.RunGeneration++
	request := seedPendingReservation(t, journey, false, "pending", "reservation_legacy0001")
	if request.PolicyRevision == auto.Manifest.PolicyRevision {
		t.Fatalf("legacy reservation must carry the older policy revision")
	}
	if err := journey.store.PutManagerPolicy(ctx, auto); err != nil {
		t.Fatal(err)
	}
	journey.observe(t)
	if journey.control.canonicalCalls != 0 {
		t.Fatalf("episode dedupe did not precede canonical capture: %d calls", journey.control.canonicalCalls)
	}
	// A later count/revision update under the same stable findingId must stay
	// revision-immune for auto_steer.
	journey.batch.BatchID = "batch_episode0002"
	journey.receipt.BatchID = "batch_episode0002"
	journey.batch.Findings[0].Revision = 2
	journey.finding.Revision = 2
	journey.setCanonical(t, journey.canonicalWithTask(taskA, 1))
	journey.observe(t)
	if journey.control.canonicalCalls != 0 {
		t.Fatalf("revision update escaped auto_steer episode dedupe: %d calls", journey.control.canonicalCalls)
	}
	_ = journey.coordinator.Apply(ctx, model.Manifest{})
	if len(journey.control.reservations) != 0 {
		t.Fatalf("second episode attempt = %#v", journey.control.reservations)
	}
	// Immutable Recover is unchanged: a retained request whose policy revision
	// no longer matches the stored authority fails the existing authority check
	// without issuing a new request or a fresh canonical read.
	if err := journey.coordinator.Recover(ctx); err == nil {
		t.Fatal("stale-revision replay unexpectedly succeeded")
	}
	if len(journey.control.reservations) != 0 || journey.control.canonicalCalls != 0 {
		t.Fatalf("stale-revision replay crossed the lookup boundary: reservations=%#v canonical=%d", journey.control.reservations, journey.control.canonicalCalls)
	}
}

// TestManagerRecommendAdmitsLaterRevisionAfterAdmitted (r1511-f1) guards the
// recommend per-revision compatibility: an admitted revision-1 anchor must not
// block a legitimate revision-2 admission with a distinct batch identity.
func TestManagerRecommendAdmitsLaterRevisionAfterAdmitted(t *testing.T) {
	const taskA = "task_mUQ6klDxlPEnqIRpkLw8teCW"
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	journey.setRegistration(t, "verified")
	journey.putLiveTaskAuthority(t, taskA, 1, true, journey.now)
	journey.setCanonical(t, journey.canonicalWithTask(taskA, 1))
	policy := journey.policy
	policy.DailyRunLimit = 2
	policy.DailyInputTokenLimit = 64000
	policy.DailyOutputTokenLimit = 8000
	policy.ValidUntil = journey.now.Add(30 * time.Second)
	journey.policy = policy
	manifest := model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}
	_ = journey.coordinator.Apply(ctx, manifest)
	journey.observe(t)
	_ = journey.coordinator.Apply(ctx, manifest)
	if len(journey.control.reservations) != 1 {
		t.Fatalf("recommend revision1 admission = %#v", journey.control.reservations)
	}
	first := journey.control.reservations[0]

	advance := journey.now.Add(310 * time.Second)
	journey.now = advance
	journey.coordinator.Now = func() time.Time { return advance }
	journey.putLiveTaskAuthority(t, taskA, 1, true, advance)
	renewed := policy
	renewed.ValidUntil = advance.Add(30 * time.Second)
	journey.batch.BatchID = "batch_recommend_rev2"
	journey.receipt.BatchID = "batch_recommend_rev2"
	journey.batch.Findings[0].Revision = 2
	journey.batch.Findings[0].Count = 5
	journey.finding.Revision = 2
	journey.setCanonical(t, journey.canonicalWithTask(taskA, 1))
	journey.observe(t)
	_ = journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{renewed}})
	if len(journey.control.reservations) != 2 {
		t.Fatalf("recommend revision2 admission = %#v, want two distinct attempts", journey.control.reservations)
	}
	if journey.control.reservations[1].ReservationID == first.ReservationID {
		t.Fatalf("revision2 reused the revision1 identity: %#v", journey.control.reservations[1])
	}
	if journey.control.reservations[1].FindingRevision != 2 {
		t.Fatalf("revision2 request = %#v, want finding revision 2", journey.control.reservations[1])
	}
}

// TestManagerAbsentInitialPolicyNeverRevives (r1511-f3) guards the 1498
// decision: an initial truly absent policy declines explicitly and a later
// opt-in never revives it.
func TestManagerAbsentInitialPolicyNeverRevives(t *testing.T) {
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	const absentSandbox = "sbx_absentpolicy0001"
	source, err := journey.store.ContinuitySource(ctx, journey.source.RegisteredSourceID)
	if err != nil || source == nil {
		t.Fatalf("continuity source = %#v %v", source, err)
	}
	source.Report.SandboxID = absentSandbox
	if err := journey.store.PutContinuitySource(ctx, *source); err != nil {
		t.Fatal(err)
	}
	journey.batch.SandboxID = absentSandbox
	journey.setCanonical(t, journey.expected)
	journey.observe(t)
	stored, err := journey.store.ManagerFinding(ctx, journey.finding.FindingID)
	if err != nil || stored == nil || stored.Admission == nil {
		t.Fatalf("admission anchor = %#v %v", stored, err)
	}
	if stored.Admission.State != "declined" || stored.Admission.Reason != "policy_absent" {
		t.Fatalf("absent policy anchor = %#v", stored.Admission)
	}
	if journey.control.canonicalCalls != 0 {
		t.Fatalf("absent policy captured canonical: %d", journey.control.canonicalCalls)
	}
	fresh := journey.policy
	fresh.SandboxID = absentSandbox
	fresh.ValidUntil = journey.now.Add(30 * time.Second)
	if err := journey.store.PutManagerPolicy(ctx, state.LocalManagerPolicy{Manifest: fresh, Report: state.LocalManagerPolicy{}.Report}); err != nil {
		t.Fatal(err)
	}
	_ = journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fresh}})
	stored, err = journey.store.ManagerFinding(ctx, journey.finding.FindingID)
	if err != nil || stored == nil || stored.Admission == nil || stored.Admission.State != "declined" {
		t.Fatalf("later opt-in revived absent policy = %#v %v", stored, err)
	}
	if len(journey.control.reservations) != 0 {
		t.Fatalf("later opt-in admitted = %#v", journey.control.reservations)
	}
}

// TestManagerReobservationUpdatesProvenance (r1507-f5) guards that a genuine
// re-observation refreshes the current finding revision/count while the
// recommend-mode episode keeps its per-revision identity, and that legacy rows
// without an anchor stay legacy.
func TestManagerReobservationUpdatesProvenance(t *testing.T) {
	const taskA = "task_mUQ6klDxlPEnqIRpkLw8teCW"
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	journey.setRegistration(t, "verified")
	journey.putLiveTaskAuthority(t, taskA, 1, true, journey.now)
	journey.setCanonical(t, journey.canonicalWithTask(taskA, 1))
	storedPolicy, err := journey.store.ManagerPolicy(ctx, journey.sandboxID)
	if err != nil || storedPolicy == nil {
		t.Fatalf("stored policy = %#v %v", storedPolicy, err)
	}
	expired := *storedPolicy
	expired.Manifest.ValidUntil = journey.now.Add(-time.Second)
	if err := journey.store.PutManagerPolicy(ctx, expired); err != nil {
		t.Fatal(err)
	}
	journey.observe(t)

	journey.batch.BatchID = "batch_episode0002"
	journey.receipt.BatchID = "batch_episode0002"
	journey.batch.Findings[0].Revision = 2
	journey.batch.Findings[0].Count = 5
	journey.finding.Revision = 2
	journey.setCanonical(t, journey.canonicalWithTask(taskA, 1))
	journey.observe(t)
	stored, err := journey.store.ManagerFinding(ctx, journey.finding.FindingID)
	if err != nil || stored == nil || stored.Finding.Revision != 2 || stored.Finding.Count != 5 {
		t.Fatalf("provenance refresh = %#v %v", stored, err)
	}
	renewed := *storedPolicy
	renewed.Manifest.ValidUntil = journey.now.Add(30 * time.Second)
	_ = journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{renewed.Manifest}})
	if len(journey.control.reservations) != 1 {
		t.Fatalf("recommend revision-2 admission = %#v, want exactly one", journey.control.reservations)
	}
}

// TestManagerReobservationLeavesLegacyRowsNil (r1507-f5) guards that a legacy
// finding without an admission anchor is never backfilled on re-observation.
func TestManagerReobservationLeavesLegacyRowsNil(t *testing.T) {
	ctx := context.Background()
	journey := newAutomaticTargetJourney(t)
	seedManagerFinding(t, journey.store, journey.fixture)
	journey.finding.FindingID = journey.fixture.Review.FindingID
	journey.batch.Findings[0].FindingID = journey.finding.FindingID
	journey.setCanonical(t, journey.expected)
	journey.observe(t)
	_ = journey.coordinator.Apply(ctx, model.Manifest{})
	stored, err := journey.store.ManagerFinding(ctx, journey.fixture.Review.FindingID)
	if err != nil || stored == nil {
		t.Fatalf("legacy finding = %#v %v", stored, err)
	}
	if stored.Admission != nil {
		t.Fatalf("legacy row was re-anchored = %#v", stored.Admission)
	}
	if len(journey.control.reservations) != 0 {
		t.Fatalf("legacy row was attempted = %#v", journey.control.reservations)
	}
}
