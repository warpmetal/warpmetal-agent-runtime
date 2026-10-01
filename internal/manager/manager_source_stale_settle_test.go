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
// .44 journey: only a PENDING AUTOMATIC reservation refused with the typed
// source-stale condition, with no backend reservation, no local run and no
// provider execution, settles honestly through the terminal "unused" phase;
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
	t.Run("non-source-stale refusals keep the refusal", func(t *testing.T) {
		control := &sourceStaleControl{reserveErr: &api.ResponseError{Status: 409, Code: "manager_target_stale"}}
		journey := journeyWithStaleControl(t, control)
		request := seedPendingReservation(t, journey, false, "pending", "reservation_stale0003")
		if err := journey.coordinator.Recover(context.Background()); err == nil {
			t.Fatal("non-source-stale refusal was settled")
		}
		stored, _ := journey.store.ManagerReservation(context.Background(), request.ReservationID)
		if stored == nil || stored.Phase != "pending" {
			t.Fatalf("non-source-stale phase = %#v", stored)
		}
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
