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

func (journey *automaticTargetJourney) complete(t *testing.T) {
	t.Helper()
	// The dispatch itself is allowed to fail (the helper is a stub); the
	// reservation request recorded by the control is what this journey proves.
	_ = journey.coordinator.ObserveAcknowledgedInsightBatch(context.Background(), journey.batch, journey.receipt)
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
				if len(journey.control.events) < 3 || journey.control.events[0] != "canonical" || journey.control.events[1] != "reserve" || journey.control.events[2] != "canonical" {
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
		if len(journey.control.events) != 1 || journey.control.events[0] != "canonical" {
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
		if len(journey.control.events) != 1 || journey.control.events[0] != "canonical" {
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
		if len(journey.control.events) != 1 || journey.control.events[0] != "canonical" {
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
