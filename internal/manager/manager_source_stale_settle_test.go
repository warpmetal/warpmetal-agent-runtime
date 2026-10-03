package manager

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type sourceStaleControl struct {
	reserveErr error
	reserves   int
	reports    int
}

// GetInsightsManagerTarget pins the canonical read expectation. The recovery
// journeys below only exercise persisted requests, which must never refetch
// the canonical target; returning an error here makes any recomputation on the
// recovery path fail closed instead of settling.
func (control *sourceStaleControl) GetInsightsManagerTarget(context.Context, string, string) (model.InsightsManagerTargetEnvelopeV1, error) {
	return model.InsightsManagerTargetEnvelopeV1{}, errors.New("stub has no canonical target read")
}

func (control *sourceStaleControl) ReserveInsightsManagerReview(context.Context, model.InsightsManagerReservationRequestV1) (model.InsightsManagerReservationV1, error) {
	control.reserves++
	return model.InsightsManagerReservationV1{}, control.reserveErr
}

func (control *sourceStaleControl) SubmitInsightsManagerRunReport(context.Context, model.InsightsManagerRunReportV1) (model.InsightsManagerActivityV1, error) {
	control.reports++
	return model.InsightsManagerActivityV1{}, errors.New("stub has no report authority")
}

func seedPendingReservation(t *testing.T, journey *automaticTargetJourney, manual bool, phase, reservationID string) model.InsightsManagerReservationRequestV1 {
	t.Helper()
	request := model.InsightsManagerReservationRequestV1{
		FormatVersion: 1, ReservationID: reservationID, RequestID: "req_manager_stale0001",
		Manual: manual, FindingID: journey.finding.FindingID, FindingRevision: journey.finding.Revision,
		PolicyRevision: journey.policy.PolicyRevision, RuleID: journey.finding.RuleID,
		RecipeID: journey.fixture.Review.RecipeID, ProviderRouteDigest: journey.fixture.Review.ProviderRouteDigest,
		Source: journey.source, Target: journey.expected,
		Budget: model.InsightsManagerBudgetV1{ModelRequests: 1, InputTokens: 1, OutputTokens: 1}, ExpiresInSeconds: 60,
	}
	if err := journey.store.PutManagerReservation(context.Background(), state.LocalManagerReservation{Request: request, Phase: phase}); err != nil {
		t.Fatal(err)
	}
	return request
}

func journeyWithStaleControl(t *testing.T, control *sourceStaleControl) *automaticTargetJourney {
	t.Helper()
	journey := newAutomaticTargetJourney(t)
	journey.setRegistration(t, "verified")
	journey.coordinator.Control = control
	return journey
}

// TestManagerSourceStaleRefusalSettlesOnlyUnreservedAutomaticPending is the
// .44 journey: only a PENDING AUTOMATIC reservation refused with a typed stale
// condition (source or target), with no backend reservation, no local run and
// no provider execution, settles honestly through the terminal "unused" phase;
// every other case keeps the original refusal (fail closed).
func TestManagerSourceStaleRefusalSettlesOnlyUnreservedAutomaticPending(t *testing.T) {
	staleRefusal := func() error { return &api.ResponseError{Status: 409, Code: "manager_source_stale"} }

	t.Run("a pending automatic reservation refused for stale source settles unused", func(t *testing.T) {
		control := &sourceStaleControl{reserveErr: staleRefusal()}
		journey := journeyWithStaleControl(t, control)
		request := seedPendingReservation(t, journey, false, "pending", "reservation_stale0001")
		if err := journey.coordinator.Recover(context.Background()); err != nil {
			t.Fatalf("recover did not settle: %v", err)
		}
		stored, err := journey.store.ManagerReservation(context.Background(), request.ReservationID)
		if err != nil || stored == nil || stored.Phase != "unused" || !reflect.DeepEqual(stored.Request, request) {
			t.Fatalf("settled intent = %#v %v", stored, err)
		}
		if control.reserves != 1 || control.reports != 0 {
			t.Fatalf("control calls = reserves %d reports %d", control.reserves, control.reports)
		}
		if runs, err := journey.store.ManagerRuns(context.Background()); err != nil || len(runs) != 0 {
			t.Fatalf("runs created: %#v %v", runs, err)
		}
	})
	t.Run("manual intents keep the refusal", func(t *testing.T) {
		control := &sourceStaleControl{reserveErr: staleRefusal()}
		journey := journeyWithStaleControl(t, control)
		request := seedPendingReservation(t, journey, true, "pending", "reservation_stale0002")
		if err := journey.coordinator.Recover(context.Background()); err == nil {
			t.Fatal("manual intent was settled")
		}
		stored, _ := journey.store.ManagerReservation(context.Background(), request.ReservationID)
		if stored == nil || stored.Phase != "pending" {
			t.Fatalf("manual intent phase = %#v", stored)
		}
	})
	t.Run("a pending unreserved automatic reservation refused for a stale target settles unused", func(t *testing.T) {
		control := &sourceStaleControl{reserveErr: &api.ResponseError{Status: 409, Code: "manager_target_stale"}}
		journey := journeyWithStaleControl(t, control)
		request := seedPendingReservation(t, journey, false, "pending", "reservation_stale0003")
		if err := journey.coordinator.Recover(context.Background()); err != nil {
			t.Fatalf("recover did not contain the target-stale refusal: %v", err)
		}
		stored, err := journey.store.ManagerReservation(context.Background(), request.ReservationID)
		if err != nil || stored == nil || stored.Phase != "unused" || !reflect.DeepEqual(stored.Request, request) {
			t.Fatalf("contained intent = %#v %v", stored, err)
		}
		if control.reserves != 1 || control.reports != 0 {
			t.Fatalf("control calls = reserves %d reports %d", control.reserves, control.reports)
		}
		if runs, err := journey.store.ManagerRuns(context.Background()); err != nil || len(runs) != 0 {
			t.Fatalf("runs created: %#v %v", runs, err)
		}
		if err := journey.coordinator.Recover(context.Background()); err != nil || control.reserves != 1 {
			t.Fatalf("retired intent replayed: reserves %d err %v", control.reserves, err)
		}
	})
	t.Run("unrecognized refusals keep the refusal", func(t *testing.T) {
		control := &sourceStaleControl{reserveErr: &api.ResponseError{Status: 409, Code: "manager_capability_stale"}}
		journey := journeyWithStaleControl(t, control)
		request := seedPendingReservation(t, journey, false, "pending", "reservation_stale0006")
		if err := journey.coordinator.Recover(context.Background()); err == nil {
			t.Fatal("unrecognized refusal was settled")
		}
		stored, _ := journey.store.ManagerReservation(context.Background(), request.ReservationID)
		if stored == nil || stored.Phase != "pending" {
			t.Fatalf("unrecognized phase = %#v", stored)
		}
	})
	t.Run("transport-unknown refusals keep the refusal", func(t *testing.T) {
		control := &sourceStaleControl{reserveErr: errors.New("injected transport unknown")}
		journey := journeyWithStaleControl(t, control)
		request := seedPendingReservation(t, journey, false, "pending", "reservation_stale0007")
		if err := journey.coordinator.Recover(context.Background()); err == nil {
			t.Fatal("transport-unknown refusal was settled")
		}
		stored, _ := journey.store.ManagerReservation(context.Background(), request.ReservationID)
		if stored == nil || stored.Phase != "pending" {
			t.Fatalf("transport-unknown phase = %#v", stored)
		}
	})
	t.Run("target-stale guards keep manual and run-bearing refusals strict", func(t *testing.T) {
		targetStale := func() error { return &api.ResponseError{Status: 409, Code: "manager_target_stale"} }
		t.Run("manual intents keep the refusal", func(t *testing.T) {
			control := &sourceStaleControl{reserveErr: targetStale()}
			journey := journeyWithStaleControl(t, control)
			request := seedPendingReservation(t, journey, true, "pending", "reservation_stale0008")
			if err := journey.coordinator.Recover(context.Background()); err == nil {
				t.Fatal("manual target-stale intent was settled")
			}
			stored, _ := journey.store.ManagerReservation(context.Background(), request.ReservationID)
			if stored == nil || stored.Phase != "pending" {
				t.Fatalf("manual target-stale phase = %#v", stored)
			}
		})
		t.Run("an existing local run keeps the refusal", func(t *testing.T) {
			control := &sourceStaleControl{reserveErr: targetStale()}
			journey := journeyWithStaleControl(t, control)
			request := seedPendingReservation(t, journey, false, "pending", "reservation_stale0009")
			if err := journey.store.PutManagerRun(context.Background(), runForReservation(journey, request, "run_stale0009")); err != nil {
				t.Fatal(err)
			}
			if err := journey.coordinator.Recover(context.Background()); err == nil {
				t.Fatal("run-bearing target-stale intent was settled")
			}
			stored, _ := journey.store.ManagerReservation(context.Background(), request.ReservationID)
			if stored == nil || stored.Phase != "pending" {
				t.Fatalf("run-bearing target-stale phase = %#v", stored)
			}
		})
	})
	t.Run("an existing local run keeps the refusal", func(t *testing.T) {
		control := &sourceStaleControl{reserveErr: staleRefusal()}
		journey := journeyWithStaleControl(t, control)
		request := seedPendingReservation(t, journey, false, "pending", "reservation_stale0004")
		run := state.LocalManagerRun{
			Manifest: model.InsightsManagerReviewManifestV1{
				FormatVersion: 1, ReservationID: request.ReservationID, RunID: "run_stale0004", Manual: false,
				FindingID: request.FindingID, FindingRevision: request.FindingRevision, PolicyRevision: request.PolicyRevision,
				RuleID: request.RuleID, RecipeID: request.RecipeID, ProviderRouteDigest: request.ProviderRouteDigest,
				ManagerProfile: journey.fixture.Review.ManagerProfile, Source: request.Source, Target: request.Target,
				Budget: request.Budget, ValidUntil: journey.policy.ValidUntil,
			},
			Phase: "dispatching",
		}
		if err := journey.store.PutManagerRun(context.Background(), run); err != nil {
			t.Fatal(err)
		}
		if err := journey.coordinator.Recover(context.Background()); err == nil {
			t.Fatal("existing-run refusal was settled")
		}
		stored, _ := journey.store.ManagerReservation(context.Background(), request.ReservationID)
		if stored == nil || stored.Phase != "pending" {
			t.Fatalf("existing-run phase = %#v", stored)
		}
		if control.reports != 0 {
			t.Fatalf("settle submitted a report: %d", control.reports)
		}
	})
	t.Run("terminal intents are skipped", func(t *testing.T) {
		control := &sourceStaleControl{reserveErr: staleRefusal()}
		journey := journeyWithStaleControl(t, control)
		seedPendingReservation(t, journey, false, "unused", "reservation_stale0005")
		if err := journey.coordinator.Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		if control.reserves != 0 {
			t.Fatalf("terminal intent retried: %d", control.reserves)
		}
	})
}

func runForReservation(journey *automaticTargetJourney, request model.InsightsManagerReservationRequestV1, runID string) state.LocalManagerRun {
	return state.LocalManagerRun{
		Manifest: model.InsightsManagerReviewManifestV1{
			FormatVersion: 1, ReservationID: request.ReservationID, RunID: runID, Manual: false,
			FindingID: request.FindingID, FindingRevision: request.FindingRevision, PolicyRevision: request.PolicyRevision,
			RuleID: request.RuleID, RecipeID: request.RecipeID, ProviderRouteDigest: request.ProviderRouteDigest,
			ManagerProfile: journey.fixture.Review.ManagerProfile, Source: request.Source, Target: request.Target,
			Budget: request.Budget, ValidUntil: journey.policy.ValidUntil,
		},
		Phase: "dispatching",
	}
}

// TestManagerReservationRequestImmutableAcrossUnknownRecovery is the RED
// journey for the ambiguous reservation POST: a persisted request that may
// already have reached the backend must be replayed exactly under the same
// reservation/request identity, even when the canonical descriptor and the
// verified Work registration both move on. A changed descriptor must not
// prevent reconciliation of the possibly-accepted old reservation, and only a
// definite typed stale refusal may retire the intent and let a fresh
// observation mint a new intent identity.
func TestManagerReservationRequestImmutableAcrossUnknownRecovery(t *testing.T) {
	journey := newAutomaticTargetJourney(t)
	journey.setRegistration(t, "verified")
	journey.seedAcknowledgedFinding(t)
	request := seedPendingReservation(t, journey, false, "pending", "reservation_immutable0001")
	journey.setCanonical(t, journey.canonicalWithTask("task_canon0001", 1))
	journey.control.loseReserve = true
	if err := journey.coordinator.Recover(context.Background()); err == nil {
		t.Fatal("ambiguous reservation outcome returned success")
	}
	if len(journey.control.events) != 1 || journey.control.events[0] != "reserve" {
		t.Fatalf("ambiguous attempt events = %#v", journey.control.events)
	}
	if len(journey.control.reservations) != 1 {
		t.Fatalf("ambiguous attempts = %#v", journey.control.reservations)
	}
	first := journey.control.reservations[0]
	stored, err := journey.store.ManagerReservation(context.Background(), request.ReservationID)
	if err != nil || stored == nil || stored.Phase != "pending" || !reflect.DeepEqual(stored.Request, first) {
		t.Fatalf("ambiguous attempt mutated the persisted request = %#v %v", stored, err)
	}
	// A source refresh and a new canonical descriptor land between the
	// ambiguous attempt and the recovery. The persisted request must be
	// replayed before any fresh canonical read, the request identity must not
	// drift, and the changed descriptor must not allow a provider dispatch.
	journey.setCanonical(t, journey.canonicalWithTask("task_canon0002", 1))
	journey.putRegistration(t, "verified", nil, nil, 2)
	if err := journey.coordinator.Recover(context.Background()); err != nil {
		t.Fatalf("recovery after unknown failed: %v", err)
	}
	if len(journey.control.reservations) != 2 {
		t.Fatalf("recovery attempts = %#v", journey.control.reservations)
	}
	second := journey.control.reservations[1]
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("recovery changed the request under the same identity:\nfirst  %#v\nsecond %#v", first, second)
	}
	if len(journey.control.events) < 3 || journey.control.events[0] != "reserve" || journey.control.events[1] != "reserve" || journey.control.events[2] != "canonical" {
		t.Fatalf("recovery ordering = %#v", journey.control.events)
	}
	if len(journey.helper.calls) != 0 {
		t.Fatalf("changed canonical descriptor dispatched provider work: %#v", journey.helper.calls)
	}
	stored, err = journey.store.ManagerReservation(context.Background(), request.ReservationID)
	if err != nil || stored == nil || !reflect.DeepEqual(stored.Request, first) {
		t.Fatalf("recovery mutated the persisted request = %#v %v", stored, err)
	}
}
