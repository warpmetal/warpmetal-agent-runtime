package manager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type managerCoordinatorFixture struct {
	Policy                  model.InsightsManagerPolicyManifestV1 `json:"managerPolicyManifest"`
	Review                  model.InsightsManagerReviewManifestV1 `json:"manualReviewManifest"`
	AutomaticReservation    model.InsightsManagerReservationV1    `json:"automaticReservation"`
	Takeover                model.InsightsTakeoverManifestV1      `json:"takeoverManifest"`
	RecommendTakeoverPolicy model.InsightsManagerPolicyManifestV1 `json:"recommendTakeoverPolicy"`
	RecommendTakeover       model.InsightsTakeoverManifestV1      `json:"recommendTakeoverManifest"`
	RecommendResumePolicy   model.InsightsManagerPolicyManifestV1 `json:"recommendResumePolicy"`
	RecommendResume         model.InsightsTakeoverManifestV1      `json:"recommendResumeManifest"`
	Handoff                 struct {
		Handoff model.SessionHandoffV1 `json:"handoff"`
	} `json:"managerSessionHandoff"`
}

func TestCoordinatorAppliesBackendRecommendResumeAndRecoversLostReleaseLookupOnly(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	authority := fixture
	authority.Policy = fixture.RecommendTakeoverPolicy
	authority.Review.Source = fixture.RecommendTakeover.Source
	authority.Review.Target = fixture.RecommendTakeover.Target
	authority.Review.PolicyRevision = fixture.RecommendTakeover.PolicyRevision
	authority.Review.FindingRevision = fixture.RecommendTakeover.FindingRevision
	authority.Review.ValidUntil = fixture.RecommendTakeover.ValidUntil
	seedManagerCoordinatorAuthority(t, store, authority)
	if err := store.PutManagedTaskAuthority(context.Background(), state.LocalManagedTaskAuthority{
		ServiceRegistrationID: fixture.RecommendTakeover.Source.ServiceRegistrationID,
		ServiceGeneration:     fixture.RecommendTakeover.Source.ServiceGeneration,
		SandboxGeneration:     fixture.RecommendTakeover.Source.SandboxGeneration,
		TaskID:                fixture.RecommendTakeover.Target.TaskID, TaskAttempt: fixture.RecommendTakeover.Target.TaskAttempt,
		Busy: true, ObservedAt: fixture.RecommendTakeover.ValidUntil.Add(-30 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	helper := &fakeManagerHelper{outputs: map[string][]byte{
		"acquire_intervention_hold":   managerHoldReceipt(t, fixture.RecommendTakeover, "acquire_intervention_hold", "active", "none_pending"),
		"reconcile_intervention_hold": managerHoldReceipt(t, fixture.RecommendResume, "reconcile_intervention_hold", "released", "none_pending"),
	}, loseActions: map[string]bool{"release_intervention_hold": true}}
	now := fixture.RecommendTakeover.ValidUntil.Add(-30 * time.Second)
	coordinator := &Coordinator{Store: store, Control: &fakeManagerControl{}, Helper: helper, Now: func() time.Time { return now }}
	if err := coordinator.Apply(context.Background(), model.Manifest{
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.RecommendTakeoverPolicy},
		InsightsTakeovers:       []model.InsightsTakeoverManifestV1{fixture.RecommendTakeover},
	}); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Apply(context.Background(), model.Manifest{
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.RecommendResumePolicy},
		InsightsTakeovers:       []model.InsightsTakeoverManifestV1{fixture.RecommendResume},
	}); err == nil || !strings.Contains(err.Error(), "injected ambiguous release_intervention_hold response") {
		t.Fatalf("Recommend Resume did not reach the release helper: %v", err)
	}
	pending, err := store.ManagerTakeover(context.Background(), fixture.RecommendResume.OperationID)
	if err != nil || pending == nil || pending.Phase != "release_unknown" {
		t.Fatalf("durable Recommend Resume intent = %#v, %v", pending, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	coordinator = &Coordinator{Store: store, Control: &fakeManagerControl{}, Helper: helper, Now: func() time.Time { return now }}
	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(helper.calls) != 3 || helper.calls[0].Payload["action"] != "acquire_intervention_hold" ||
		helper.calls[1].Payload["action"] != "release_intervention_hold" || helper.calls[2].Payload["action"] != "reconcile_intervention_hold" {
		t.Fatalf("Recommend Resume helper sequence = %#v", helper.calls)
	}
	released, err := store.ManagerTakeover(context.Background(), fixture.RecommendResume.OperationID)
	if err != nil || released == nil || released.Phase != "released" || released.Report == nil || released.Report.Status != "ready" {
		t.Fatalf("Recommend Resume report = %#v, %v", released, err)
	}
}

type managerHelperCall struct {
	SandboxID string
	Payload   map[string]any
}

type fakeManagerHelper struct {
	calls        []managerHelperCall
	loseStart    bool
	reviewOutput []byte
	outputs      map[string][]byte
	loseActions  map[string]bool
	beforeCall   func(map[string]any) error
}

func (helper *fakeManagerHelper) ExecManager(_ context.Context, sandboxID string, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	if helper.beforeCall != nil {
		if err := helper.beforeCall(request); err != nil {
			return nil, nil, err
		}
	}
	helper.calls = append(helper.calls, managerHelperCall{SandboxID: sandboxID, Payload: request})
	action, _ := request["action"].(string)
	if action == "start_review" && helper.loseStart {
		helper.loseStart = false
		return nil, nil, errors.New("injected ambiguous start response")
	}
	if helper.loseActions[action] {
		delete(helper.loseActions, action)
		return nil, nil, errors.New("injected ambiguous " + action + " response")
	}
	if output := helper.outputs[action]; output != nil {
		return append([]byte(nil), output...), nil, nil
	}
	output := append([]byte(nil), helper.reviewOutput...)
	if action == "start_review" {
		authority, _ := request["authority"].(map[string]any)
		var receipt map[string]any
		if json.Unmarshal(output, &receipt) == nil && authority != nil {
			receipt["reservationId"], receipt["runId"] = authority["reservationId"], authority["runId"]
			if runID, ok := authority["runId"].(string); ok {
				receipt["managerRegisteredSourceId"] = managerSourceID(runID)
			}
			output, _ = json.Marshal(receipt)
		}
	}
	return output, nil, nil
}

type fakeManagerControl struct {
	reservations     []model.InsightsManagerReservationRequestV1
	reservation      model.InsightsManagerReservationV1
	reports          []model.InsightsManagerRunReportV1
	dynamic          bool
	loseReserve      bool
	runForReport     *model.InsightsManagerReservationRequestV1
	startReportError error
	startACKChange   func(*model.InsightsManagerActivityV1)
	// startReportLoseOnce models a reviewing report that the backend accepted
	// but whose reply was lost: the report was recorded, the caller sees an
	// error, and the retry must re-send the same idempotent report instead of
	// treating the run as helper execution_unknown.
	startReportLoseOnce bool
}

func (control *fakeManagerControl) ReserveInsightsManagerReview(_ context.Context, request model.InsightsManagerReservationRequestV1) (model.InsightsManagerReservationV1, error) {
	control.reservations = append(control.reservations, request)
	control.runForReport = &request
	if control.loseReserve {
		control.loseReserve = false
		return model.InsightsManagerReservationV1{}, errors.New("injected ambiguous reservation response")
	}
	if control.dynamic {
		value := control.reservation
		value.FormatVersion, value.ReservationID, value.RequestID, value.Manual = 1, request.ReservationID, request.RequestID, request.Manual
		if value.RunID == "" {
			value.RunID = opaqueID("run_", request.RequestID)
		}
		value.State, value.FindingID, value.FindingRevision, value.PolicyRevision = "reserved", request.FindingID, request.FindingRevision, request.PolicyRevision
		value.Source, value.Target, value.ReservedBudget = request.Source, request.Target, request.Budget
		value.Execution.ProviderRouteDigest = request.ProviderRouteDigest
		if value.ExpiresAt.IsZero() {
			value.ExpiresAt = time.Now().UTC().Add(time.Minute)
		}
		return value, nil
	}
	return control.reservation, nil
}

func (control *fakeManagerControl) SubmitInsightsManagerRunReport(_ context.Context, report model.InsightsManagerRunReportV1) (model.InsightsManagerActivityV1, error) {
	control.reports = append(control.reports, report)
	if report.State == "reviewing" && control.startReportError != nil {
		return model.InsightsManagerActivityV1{}, control.startReportError
	}
	if report.State == "reviewing" && control.startReportLoseOnce {
		control.startReportLoseOnce = false
		return model.InsightsManagerActivityV1{}, errors.New("injected lost reviewing report reply")
	}
	rationale := (*string)(nil)
	if report.Proposal != nil {
		value := report.Proposal.RationaleCode
		rationale = &value
	}
	requestID, findingID, ruleID, recipeID := "req_manual_runtime0001", "", "", ""
	if run := control.runForReport; run != nil {
		requestID, findingID, ruleID, recipeID = run.RequestID, run.FindingID, run.RuleID, run.RecipeID
	}
	activity := model.InsightsManagerActivityV1{RunID: report.RunID, ReservationID: report.ReservationID, RequestID: requestID,
		Manual: report.Manual, FindingID: findingID, RuleID: ruleID, RecipeID: recipeID, Source: report.Source, Target: report.Target,
		State: report.State, RationaleCode: rationale, ModelRequests: report.Usage.ModelRequests, InputTokens: report.Usage.InputTokens,
		OutputTokens: report.Usage.OutputTokens, ManagerSession: model.InsightsManagerActivitySessionV1{Capability: "exact_session"},
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if report.State == "reviewing" && control.startACKChange != nil {
		control.startACKChange(&activity)
	}
	return activity, nil
}

func TestCoordinatorPersistsBeforeDispatchAndReconcilesLostStartAfterSQLiteReopen(t *testing.T) {
	t.Run("accepted start then ambiguous helper and reopen", func(t *testing.T) {
		fixture := loadManagerCoordinatorFixture(t)
		databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
		store, err := state.Open(databasePath)
		if err != nil {
			t.Fatal(err)
		}
		seedManagerCoordinatorAuthority(t, store, fixture)
		helper := &fakeManagerHelper{loseStart: true, reviewOutput: managerReviewReceipt(t, fixture, "reconcile_review")}
		control := &fakeManagerControl{runForReport: managerRequestForReview(fixture.Review)}
		requireManagerStartReportBeforeHelper(t, helper, control)
		now := func() time.Time { return fixture.Review.ValidUntil.Add(-30 * time.Second) }
		coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: now}
		manifest := model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
			InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.Policy},
			InsightsManagerReviews:  []model.InsightsManagerReviewManifestV1{fixture.Review}}
		if err := coordinator.Apply(context.Background(), manifest); err == nil {
			t.Fatal("lost start response returned success")
		}
		persisted, err := store.ManagerRun(context.Background(), fixture.Review.RunID)
		if err != nil || persisted == nil || persisted.Phase != "execution_unknown" || !persisted.DispatchStarted || persisted.Report != nil {
			t.Fatalf("durable pre-dispatch intent = %#v, %v", persisted, err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		store, err = state.Open(databasePath)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		coordinator = &Coordinator{Store: store, Control: control, Helper: helper, Now: now}
		if err := coordinator.Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(helper.calls) != 2 || helper.calls[0].Payload["action"] != "start_review" || helper.calls[1].Payload["action"] != "reconcile_review" {
			t.Fatalf("lost response replayed native work: %#v", helper.calls)
		}
		if len(control.reports) != 2 || control.reports[0].State != "reviewing" || control.reports[1].State != "recommended" {
			t.Fatalf("restart replayed or omitted start report: %#v", control.reports)
		}
		policyReports, runReports, takeoverReports, err := coordinator.Reports(context.Background(), nil)
		if err != nil || len(policyReports) != 1 || len(runReports) != 1 || len(takeoverReports) != 0 || runReports[0].State != "recommended" {
			t.Fatalf("recovered reports = %#v/%#v/%#v, %v", policyReports, runReports, takeoverReports, err)
		}
		mapped, err := store.ManagerRunBySource(context.Background(), managerSourceID(fixture.Review.RunID))
		if err != nil || mapped == nil || mapped.Manifest.RunID != fixture.Review.RunID || mapped.ManagerSession == nil ||
			mapped.ManagerSession.NativeSessionID != fixture.Handoff.Handoff.Source.NativeSessionID {
			t.Fatalf("manager session mapping = %#v, %v", mapped, err)
		}
	})
	for _, refusal := range []string{"report refused", "run ACK changed", "finding ACK changed"} {
		t.Run(refusal+" before helper and after reopen", func(t *testing.T) {
			fixture := loadManagerCoordinatorFixture(t)
			databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
			store, err := state.Open(databasePath)
			if err != nil {
				t.Fatal(err)
			}
			seedManagerCoordinatorAuthority(t, store, fixture)
			helper := &fakeManagerHelper{reviewOutput: managerReviewReceipt(t, fixture, "start_review")}
			control := &fakeManagerControl{runForReport: managerRequestForReview(fixture.Review)}
			if refusal == "report refused" {
				control.startReportError = errors.New("injected start report refusal")
			} else {
				control.startACKChange = func(activity *model.InsightsManagerActivityV1) {
					if refusal == "run ACK changed" {
						activity.RunID += "_foreign"
					} else {
						activity.FindingID += "_foreign"
					}
				}
			}
			now := fixture.Review.ValidUntil.Add(-30 * time.Second)
			coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
			manifest := model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.Policy},
				InsightsManagerReviews: []model.InsightsManagerReviewManifestV1{fixture.Review}}
			err = coordinator.Apply(context.Background(), manifest)
			if err == nil || len(helper.calls) != 0 {
				t.Fatalf("unacknowledged review reached helper: helperCalls=%d error=%v", len(helper.calls), err)
			}
			pending, err := store.ManagerRun(context.Background(), fixture.Review.RunID)
			if err != nil || pending == nil || !reflect.DeepEqual(pending.Manifest, fixture.Review) {
				t.Fatalf("unacknowledged review intent was not preserved: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = state.Open(databasePath)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			coordinator.Store = store
			err = coordinator.Recover(context.Background())
			if err == nil || len(helper.calls) != 0 {
				t.Fatalf("unacknowledged reopened review reached helper: helperCalls=%d error=%v", len(helper.calls), err)
			}
			control.startReportError, control.startACKChange = nil, nil
			if err := coordinator.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(helper.calls) != 1 || helper.calls[0].Payload["action"] != "start_review" {
				t.Fatalf("fresh acknowledged recovery did not start exactly once: %#v", helper.calls)
			}
		})
	}
	t.Run("lost reviewing reply retries the same idempotent report before helper", func(t *testing.T) {
		fixture := loadManagerCoordinatorFixture(t)
		databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
		store, err := state.Open(databasePath)
		if err != nil {
			t.Fatal(err)
		}
		seedManagerCoordinatorAuthority(t, store, fixture)
		helper := &fakeManagerHelper{reviewOutput: managerReviewReceipt(t, fixture, "start_review")}
		control := &fakeManagerControl{runForReport: managerRequestForReview(fixture.Review), startReportLoseOnce: true}
		now := fixture.Review.ValidUntil.Add(-30 * time.Second)
		coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
		manifest := model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
			InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.Policy},
			InsightsManagerReviews:  []model.InsightsManagerReviewManifestV1{fixture.Review}}
		// The backend accepted the reviewing report but the reply was lost: the
		// run must stay a non-dispatched start_ack_pending intent, never helper
		// execution_unknown, and the helper must see zero work.
		if err := coordinator.Apply(context.Background(), manifest); err == nil || len(helper.calls) != 0 {
			t.Fatalf("lost reviewing reply returned success or reached helper: calls=%d err=%v", len(helper.calls), err)
		}
		if len(control.reports) != 1 || control.reports[0].State != "reviewing" {
			t.Fatalf("lost reviewing report trace = %#v", control.reports)
		}
		pending, err := store.ManagerRun(context.Background(), fixture.Review.RunID)
		if err != nil || pending == nil || pending.Phase != "start_ack_pending" || pending.DispatchStarted || pending.Report != nil {
			t.Fatalf("lost reviewing reply intent = %#v, %v", pending, err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		store, err = state.Open(databasePath)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		coordinator.Store = store
		if err := coordinator.Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(control.reports) != 3 || control.reports[0].State != "reviewing" || control.reports[1].State != "reviewing" ||
			control.reports[2].State != "recommended" || !reflect.DeepEqual(control.reports[0], control.reports[1]) {
			t.Fatalf("lost reviewing reply was not retried idempotently: %#v", control.reports)
		}
		if len(helper.calls) != 1 || helper.calls[0].Payload["action"] != "start_review" {
			t.Fatalf("lost reviewing reply recovery started %d helper calls: %#v", len(helper.calls), helper.calls)
		}
		settled, err := store.ManagerRun(context.Background(), fixture.Review.RunID)
		if err != nil || settled == nil || settled.Phase != "recommended" || settled.Report == nil {
			t.Fatalf("lost reviewing reply recovery settlement = %#v, %v", settled, err)
		}
	})
	for _, loss := range []string{"pending ACK expires", "pending ACK source unavailable", "ACK latency expires"} {
		t.Run(loss+" settles zero native work", func(t *testing.T) {
			fixture := loadManagerCoordinatorFixture(t)
			databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
			store, err := state.Open(databasePath)
			if err != nil {
				t.Fatal(err)
			}
			seedManagerCoordinatorAuthority(t, store, fixture)
			helper := &fakeManagerHelper{reviewOutput: managerReviewReceipt(t, fixture, "start_review")}
			control := &fakeManagerControl{runForReport: managerRequestForReview(fixture.Review)}
			now := fixture.Review.ValidUntil.Add(-30 * time.Second)
			if loss == "ACK latency expires" {
				control.startACKChange = func(*model.InsightsManagerActivityV1) { now = fixture.Review.ValidUntil.Add(time.Second) }
			} else {
				control.startReportError = errors.New("injected start report refusal")
			}
			coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
			err = coordinator.Apply(context.Background(), model.Manifest{
				InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.Policy},
				InsightsManagerReviews:  []model.InsightsManagerReviewManifestV1{fixture.Review},
			})
			if len(helper.calls) != 0 || (loss != "ACK latency expires" && err == nil) {
				t.Fatalf("unacknowledged/expired start reached helper: calls=%d err=%v", len(helper.calls), err)
			}
			if loss != "ACK latency expires" {
				pending, err := store.ManagerRun(context.Background(), fixture.Review.RunID)
				if err != nil || pending == nil || pending.Phase != "start_ack_pending" || pending.DispatchStarted {
					t.Fatalf("unstarted ACK intent changed: %#v %v", pending, err)
				}
				if loss == "pending ACK expires" {
					now = fixture.Review.ValidUntil.Add(time.Second)
				} else {
					source, err := store.ContinuitySource(context.Background(), fixture.Review.Source.RegisteredSourceID)
					if err != nil {
						t.Fatal(err)
					}
					source.Report.Availability = "unavailable"
					if err := store.PutContinuitySource(context.Background(), *source); err != nil {
						t.Fatal(err)
					}
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				store, err = state.Open(databasePath)
				if err != nil {
					t.Fatal(err)
				}
				coordinator.Store = store
				if err := coordinator.Recover(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			defer store.Close()
			settled, err := store.ManagerRun(context.Background(), fixture.Review.RunID)
			if err != nil || settled == nil || settled.Phase != "failed" || settled.DispatchStarted || settled.Report == nil ||
				!settled.Report.Usage.UsageCertain || settled.Report.Usage.UnusedProof != "trusted_zero_start" ||
				settled.Report.Usage.ModelRequests != 0 || settled.Report.Usage.InputTokens != 0 || settled.Report.Usage.OutputTokens != 0 || len(helper.calls) != 0 {
				t.Fatalf("unstarted review did not settle unused: %#v %v", settled, err)
			}
		})
	}
}

// TestCoordinatorReportsActualTerminalProposalOutcomes is the paired strict
// terminal-semantics journey: the helper receipt's nullable proposal carries
// the actual closed outcome/rationale/citation bounds, and Runtime must report
// no_action as no_action instead of relabeling it, preserving the actual
// negative proposal summary and manager session. The report is asserted through
// its JSON shape so this journey does not depend on production structs that the
// C1 implementation changes.
func TestCoordinatorReportsActualTerminalProposalOutcomes(t *testing.T) {
	for _, terminal := range []struct {
		status  string
		outcome string
	}{
		{status: "no_action", outcome: "no_action"},
		{status: "needs_owner", outcome: "needs_owner"},
	} {
		t.Run(terminal.status+" keeps the actual proposal summary", func(t *testing.T) {
			fixture := loadManagerCoordinatorFixture(t)
			databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
			store, err := state.Open(databasePath)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			seedManagerCoordinatorAuthority(t, store, fixture)
			helper := &fakeManagerHelper{reviewOutput: managerTerminalReceipt(t, fixture, terminal.status, terminal.outcome)}
			control := &fakeManagerControl{runForReport: managerRequestForReview(fixture.Review)}
			now := fixture.Review.ValidUntil.Add(-30 * time.Second)
			coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
			manifest := model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
				InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.Policy},
				InsightsManagerReviews:  []model.InsightsManagerReviewManifestV1{fixture.Review}}
			if err := coordinator.Apply(context.Background(), manifest); err != nil {
				t.Fatalf("actual terminal %s receipt was refused: %v", terminal.status, err)
			}
			stored, err := store.ManagerRun(context.Background(), fixture.Review.RunID)
			if err != nil || stored == nil || stored.Phase != terminal.status || stored.Report == nil {
				t.Fatalf("terminal %s run = %#v, %v", terminal.status, stored, err)
			}
			report := managerReportJSON(t, stored.Report)
			if report["state"] != terminal.status {
				t.Fatalf("terminal report state changed: %#v", report["state"])
			}
			proposal, ok := report["proposal"].(map[string]any)
			// The receipt's actual citation bounds 3..5 differ from the seeded
			// finding window 1..8: a synthesized finding window is a failure.
			if !ok || proposal["outcome"] != terminal.outcome || proposal["rationaleCode"] != "unchanged_failure_repeated" ||
				proposal["recipeId"] != fixture.Review.RecipeID || proposal["guidanceDigest"] != nil ||
				proposal["firstSequence"] != float64(3) || proposal["lastSequence"] != float64(5) {
				t.Fatalf("actual terminal proposal summary changed: %#v", report["proposal"])
			}
			if report["managerSession"] == nil {
				t.Fatalf("terminal negative result dropped the manager session: %#v", report)
			}
			if len(helper.calls) != 1 || helper.calls[0].Payload["action"] != "start_review" {
				t.Fatalf("terminal outcome repeated native work: %#v", helper.calls)
			}
		})
	}
}

func managerTerminalReceipt(t *testing.T, fixture managerCoordinatorFixture, status, outcome string) []byte {
	t.Helper()
	payload := managerReviewReceipt(t, fixture, "start_review")
	var receipt map[string]any
	if err := json.Unmarshal(payload, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt["status"] = status
	receipt["proposal"] = map[string]any{"recipeId": fixture.Review.RecipeID, "outcome": outcome,
		"rationaleCode": "unchanged_failure_repeated", "firstSequence": 3, "lastSequence": 5, "guidanceDigest": nil}
	// A null-guidance negative proposal requires the guidance receipt digest to
	// be null too; the seeded positive fixture is not coherent negative output.
	if guidance, ok := receipt["guidanceReceipt"].(map[string]any); ok {
		guidance["guidanceDigest"] = nil
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func managerReportJSON(t *testing.T, report *model.InsightsManagerRunReportV1) map[string]any {
	t.Helper()
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

// Standalone journey guard: the actual cross-repository producer independently
// checks the committed PostgreSQL state. Here existing helper dispatch tests
// also enforce exact wire authority and zero start usage before their fixtures.
func requireManagerStartReportBeforeHelper(t *testing.T, helper *fakeManagerHelper, control *fakeManagerControl) {
	t.Helper()
	helper.beforeCall = func(request map[string]any) error {
		if request["action"] != "start_review" {
			return nil
		}
		var review model.InsightsManagerReviewManifestV1
		payload, err := json.Marshal(request["authority"])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(payload, &review); err != nil {
			return err
		}
		if len(control.reports) != 1 {
			t.Fatalf("reviewing report must precede helper: reports=%d", len(control.reports))
		}
		report := control.reports[0]
		if report.FormatVersion != 1 || report.State != "reviewing" || report.RunID != review.RunID ||
			report.ReservationID != review.ReservationID || report.Manual != review.Manual || report.PolicyRevision != review.PolicyRevision ||
			report.Source != review.Source || !reflect.DeepEqual(report.Target, review.Target) ||
			report.Proposal != nil || report.ManagerSession != nil || report.ErrorCode != nil || !digestPattern.MatchString(report.ReceiptDigest) ||
			report.Usage.ModelRequests != 0 || report.Usage.InputTokens != 0 || report.Usage.OutputTokens != 0 ||
			report.Usage.UsageCertain || report.Usage.UnusedProof != "none" {
			t.Fatalf("start report changed authority or charged before helper: state=%s run=%s", report.State, report.RunID)
		}
		return nil
	}
}

func TestCoordinatorContinuesDurableReviewingRunWithoutRestartingIt(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedManagerCoordinatorAuthority(t, store, fixture)
	reviewing := managerReviewReceipt(t, fixture, "start_review")
	var progress map[string]any
	if err := json.Unmarshal(reviewing, &progress); err != nil {
		t.Fatal(err)
	}
	progress["status"] = "reviewing"
	reviewing, _ = json.Marshal(progress)
	helper := &fakeManagerHelper{outputs: map[string][]byte{
		"start_review":    reviewing,
		"continue_review": managerReviewReceipt(t, fixture, "continue_review"),
	}}
	control := &fakeManagerControl{runForReport: managerRequestForReview(fixture.Review)}
	requireManagerStartReportBeforeHelper(t, helper, control)
	coordinator := &Coordinator{Store: store, Control: control, Helper: helper,
		Now: func() time.Time { return fixture.Review.ValidUntil.Add(-30 * time.Second) }}
	manifest := model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.Policy},
		InsightsManagerReviews:  []model.InsightsManagerReviewManifestV1{fixture.Review}}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	run, err := store.ManagerRun(context.Background(), fixture.Review.RunID)
	if err != nil || run == nil || run.Phase != "reviewing" || run.Report != nil {
		t.Fatalf("reviewing run = %#v, %v", run, err)
	}
	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(control.reports) != 2 || control.reports[0].State != "reviewing" || control.reports[1].State != "recommended" {
		t.Fatalf("continued review replayed or omitted start report: %#v", control.reports)
	}
	if len(helper.calls) != 2 || helper.calls[0].Payload["action"] != "start_review" || helper.calls[1].Payload["action"] != "continue_review" {
		t.Fatalf("review continuation calls = %#v", helper.calls)
	}
}

func TestCoordinatorAutomaticReviewStartsOnceAfterACKAndEnforcesCooldown(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	policy := fixture.Policy
	policy.PolicyRevision = fixture.AutomaticReservation.PolicyRevision
	policy.RunGeneration = 2
	policy.ValidUntil = fixture.AutomaticReservation.ExpiresAt
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedManagerCoordinatorAuthority(t, store, fixture)
	helper := &fakeManagerHelper{reviewOutput: automaticManagerReviewReceipt(t, fixture)}
	control := &fakeManagerControl{reservation: fixture.AutomaticReservation, dynamic: true}
	requireManagerStartReportBeforeHelper(t, helper, control)
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
	manifest := model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	batch := managerInsightBatch(fixture, fixture.AutomaticReservation.PolicyRevision, "batch_manager_ack0001")
	receipt := model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: len(batch.Findings), ThroughSequence: batch.ThroughSequence}
	if err := coordinator.ObserveAcknowledgedInsightBatch(context.Background(), batch, receipt); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.ObserveAcknowledgedInsightBatch(context.Background(), batch, receipt); err != nil {
		t.Fatal(err)
	}
	if len(control.reservations) != 1 || len(helper.calls) != 1 || helper.calls[0].Payload["action"] != "start_review" {
		t.Fatalf("automatic episode was duplicated: reservations=%#v helper=%#v", control.reservations, helper.calls)
	}

	cooldown := managerInsightBatch(fixture, fixture.AutomaticReservation.PolicyRevision, "batch_manager_ack0002")
	cooldown.Findings[0].FindingID = "finding_insights0002"
	cooldown.Findings[0].Revision = 1
	if err := coordinator.ObserveAcknowledgedInsightBatch(context.Background(), cooldown,
		model.InsightBatchReceiptV1{BatchID: cooldown.BatchID, Accepted: 1, ThroughSequence: cooldown.ThroughSequence}); err != nil {
		t.Fatal(err)
	}
	if len(control.reservations) != 1 || len(helper.calls) != 1 {
		t.Fatalf("session cooldown did not charge completed run: reservations=%d helper=%d", len(control.reservations), len(helper.calls))
	}

	off := policy
	off.PolicyRevision++
	off.RunGeneration++
	off.Mode = "off"
	off.AllowedRules = []string{}
	manifest.DesiredRevision++
	manifest.InsightsManagerPolicies = []model.InsightsManagerPolicyManifestV1{off}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	offBatch := managerInsightBatch(fixture, off.PolicyRevision, "batch_manager_off0001")
	offBatch.Findings[0].FindingID = "finding_insights0003"
	if err := coordinator.ObserveAcknowledgedInsightBatch(context.Background(), offBatch,
		model.InsightBatchReceiptV1{BatchID: offBatch.BatchID, Accepted: 1, ThroughSequence: offBatch.ThroughSequence}); err != nil {
		t.Fatal(err)
	}
	if len(control.reservations) != 1 || len(helper.calls) != 1 {
		t.Fatalf("Off policy admitted review: reservations=%d helper=%d", len(control.reservations), len(helper.calls))
	}

	expired := policy
	expired.PolicyRevision += 2
	expired.RunGeneration += 2
	manifest.DesiredRevision++
	manifest.InsightsManagerPolicies = []model.InsightsManagerPolicyManifestV1{expired}
	coordinator.Now = func() time.Time { return expired.ValidUntil.Add(time.Second) }
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	expiredBatch := managerInsightBatch(fixture, expired.PolicyRevision, "batch_manager_expired0001")
	expiredBatch.Findings[0].FindingID = "finding_insights0004"
	if err := coordinator.ObserveAcknowledgedInsightBatch(context.Background(), expiredBatch,
		model.InsightBatchReceiptV1{BatchID: expiredBatch.BatchID, Accepted: 1, ThroughSequence: expiredBatch.ThroughSequence}); err != nil {
		t.Fatal(err)
	}
	if len(control.reservations) != 1 || len(helper.calls) != 1 {
		t.Fatalf("expired policy admitted review: reservations=%d helper=%d", len(control.reservations), len(helper.calls))
	}
}

func TestCoordinatorReplaysExactPersistedReservationAfterLostReplyAndReopen(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	policy := fixture.Policy
	policy.PolicyRevision = fixture.AutomaticReservation.PolicyRevision
	policy.RunGeneration = 2
	policy.ValidUntil = fixture.AutomaticReservation.ExpiresAt
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	seedManagerCoordinatorAuthority(t, store, fixture)
	helper := &fakeManagerHelper{reviewOutput: automaticManagerReviewReceipt(t, fixture)}
	control := &fakeManagerControl{reservation: fixture.AutomaticReservation, dynamic: true, loseReserve: true}
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
	if err := coordinator.Apply(context.Background(), model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}); err != nil {
		t.Fatal(err)
	}
	batch := managerInsightBatch(fixture, policy.PolicyRevision, "batch_manager_reservation_lost0001")
	if err := coordinator.ObserveAcknowledgedInsightBatch(context.Background(), batch,
		model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: 1, ThroughSequence: batch.ThroughSequence}); err == nil {
		t.Fatal("lost reservation response returned success")
	}
	if len(helper.calls) != 0 {
		t.Fatalf("ambiguous reservation reached helper: %#v", helper.calls)
	}
	intents, err := store.ManagerReservations(context.Background())
	if err != nil || len(intents) != 1 || intents[0].Phase != "pending" || intents[0].Reservation != nil {
		t.Fatalf("reservation intent = %#v, %v", intents, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	coordinator = &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(control.reservations) != 2 || !reflect.DeepEqual(control.reservations[0], control.reservations[1]) || len(helper.calls) != 1 {
		t.Fatalf("reservation replay changed intent: requests=%#v helper=%#v", control.reservations, helper.calls)
	}
}

func TestCoordinatorOffExpiredAndManagerSourceNeverReserve(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	cases := []struct {
		name   string
		policy func(model.InsightsManagerPolicyManifestV1) model.InsightsManagerPolicyManifestV1
		batch  func(model.InsightBatchV1) model.InsightBatchV1
		now    func(model.InsightsManagerPolicyManifestV1) time.Time
	}{
		{name: "off", policy: func(value model.InsightsManagerPolicyManifestV1) model.InsightsManagerPolicyManifestV1 {
			value.Mode, value.AllowedRules = "off", []string{}
			return value
		}, batch: func(value model.InsightBatchV1) model.InsightBatchV1 { return value },
			now: func(value model.InsightsManagerPolicyManifestV1) time.Time { return value.ValidUntil.Add(-time.Second) }},
		{name: "expired", policy: func(value model.InsightsManagerPolicyManifestV1) model.InsightsManagerPolicyManifestV1 { return value },
			batch: func(value model.InsightBatchV1) model.InsightBatchV1 { return value },
			now:   func(value model.InsightsManagerPolicyManifestV1) time.Time { return value.ValidUntil.Add(time.Second) }},
		{name: "manager source recursion", policy: func(value model.InsightsManagerPolicyManifestV1) model.InsightsManagerPolicyManifestV1 { return value },
			batch: func(value model.InsightBatchV1) model.InsightBatchV1 {
				value.RegisteredSourceID = fixture.Handoff.Handoff.Source.RegisteredSourceID
				value.NativeSessionID = fixture.Handoff.Handoff.Source.NativeSessionID
				return value
			}, now: func(value model.InsightsManagerPolicyManifestV1) time.Time { return value.ValidUntil.Add(-time.Second) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			seedManagerCoordinatorAuthority(t, store, fixture)
			policy := test.policy(fixture.Policy)
			control := &fakeManagerControl{reservation: fixture.AutomaticReservation, dynamic: true}
			helper := &fakeManagerHelper{reviewOutput: automaticManagerReviewReceipt(t, fixture)}
			coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return test.now(policy) }}
			if err := coordinator.Apply(context.Background(), model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
				InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}); err != nil {
				t.Fatal(err)
			}
			batch := test.batch(managerInsightBatch(fixture, policy.PolicyRevision, "batch_manager_denied0001"))
			if err := coordinator.ObserveAcknowledgedInsightBatch(context.Background(), batch,
				model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: 1, ThroughSequence: batch.ThroughSequence}); err != nil {
				t.Fatal(err)
			}
			if len(control.reservations) != 0 || len(helper.calls) != 0 {
				t.Fatalf("denied manager episode crossed boundary: reservations=%#v helper=%#v", control.reservations, helper.calls)
			}
		})
	}
}

func TestCoordinatorChargesLocalConcurrentAndFailedRunCooldownBeforeBackendReservation(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedManagerCoordinatorAuthority(t, store, fixture)
	now := fixture.Review.ValidUntil.Add(-30 * time.Second)
	for index, phase := range []string{"execution_unknown", "failed"} {
		run := fixture.Review
		run.RunID = "run_manager_localcap000" + string(rune('1'+index))
		run.ReservationID = "reservation_manager_localcap000" + string(rune('1'+index))
		if err := store.PutManagerRun(context.Background(), state.LocalManagerRun{Manifest: run, Phase: phase, DispatchStarted: true, StartedAt: now.Add(-time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	control := &fakeManagerControl{reservation: fixture.AutomaticReservation, dynamic: true}
	helper := &fakeManagerHelper{reviewOutput: automaticManagerReviewReceipt(t, fixture)}
	coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
	if err := coordinator.Apply(context.Background(), model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.Policy}}); err != nil {
		t.Fatal(err)
	}
	batch := managerInsightBatch(fixture, fixture.Policy.PolicyRevision, "batch_manager_localcap0001")
	if err := coordinator.ObserveAcknowledgedInsightBatch(context.Background(), batch,
		model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: 1, ThroughSequence: batch.ThroughSequence}); err != nil {
		t.Fatal(err)
	}
	if len(control.reservations) != 0 || len(helper.calls) != 0 {
		t.Fatalf("local cap/cooldown crossed backend/helper boundary: reservations=%#v helper=%#v", control.reservations, helper.calls)
	}
}

func TestCoordinatorPersistsTakeoverAndLostResumeBeforeLookupOnlyRecovery(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	seedManagerCoordinatorAuthority(t, store, fixture)
	policy := fixture.Policy
	policy.Mode, policy.AllowedRules = "off", []string{}
	takeover := fixture.Takeover
	takeover.PolicyRevision, takeover.RunGeneration = policy.PolicyRevision, policy.RunGeneration
	takeover.Source, takeover.Target = fixture.Review.Source, fixture.Review.Target
	takeover.ValidUntil = fixture.Review.ValidUntil
	help := &fakeManagerHelper{outputs: map[string][]byte{
		"acquire_intervention_hold":   managerHoldReceipt(t, takeover, "acquire_intervention_hold", "active", "none_pending"),
		"reconcile_intervention_hold": managerHoldReceipt(t, managerResumeManifest(t, takeover), "reconcile_intervention_hold", "released", "none_pending"),
	}, loseActions: map[string]bool{"release_intervention_hold": true}}
	now := func() time.Time { return takeover.ValidUntil.Add(-30 * time.Second) }
	coordinator := &Coordinator{Store: store, Control: &fakeManagerControl{}, Helper: help, Now: now}
	manifest := model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}, InsightsTakeovers: []model.InsightsTakeoverManifestV1{takeover}}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	renewed := takeover
	renewed.ValidUntil = renewed.ValidUntil.Add(15 * time.Second)
	help.outputs["acquire_intervention_hold"] = managerHoldReceipt(t, renewed, "acquire_intervention_hold", "active", "none_pending")
	manifest.DesiredRevision++
	manifest.InsightsTakeovers = []model.InsightsTakeoverManifestV1{renewed}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	takeover = renewed
	resume := managerResumeManifest(t, takeover)
	resumePolicy := policy
	resumePolicy.PolicyRevision, resumePolicy.RunGeneration = resume.PolicyRevision, resume.RunGeneration
	resumePolicy.ValidUntil = resume.ValidUntil
	help.outputs["reconcile_intervention_hold"] = managerHoldReceipt(t, resume, "reconcile_intervention_hold", "released", "none_pending")
	manifest.DesiredRevision++
	manifest.InsightsManagerPolicies = []model.InsightsManagerPolicyManifestV1{resumePolicy}
	manifest.InsightsTakeovers = []model.InsightsTakeoverManifestV1{resume}
	if err := coordinator.Apply(context.Background(), manifest); err == nil {
		t.Fatal("lost release response returned success")
	}
	pending, err := store.ManagerTakeover(context.Background(), resume.OperationID)
	if err != nil || pending == nil || pending.Phase != "release_unknown" || !pending.DispatchStarted || pending.Report != nil {
		t.Fatalf("durable release intent = %#v, %v", pending, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	coordinator = &Coordinator{Store: store, Control: &fakeManagerControl{}, Helper: help, Now: now}
	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	var actions []any
	for _, call := range help.calls {
		actions = append(actions, call.Payload["action"])
	}
	want := []any{"acquire_intervention_hold", "acquire_intervention_hold", "release_intervention_hold", "reconcile_intervention_hold"}
	if !reflect.DeepEqual(actions, want) {
		t.Fatalf("takeover recovery replayed a hold mutation: got %#v want %#v", actions, want)
	}
	_, _, takeoverReports, err := coordinator.Reports(context.Background(), nil)
	if err != nil || len(takeoverReports) != 1 {
		t.Fatalf("recovered takeover reports = %#v, %v", takeoverReports, err)
	}
	foundResume := false
	for _, report := range takeoverReports {
		if report.OperationID == resume.OperationID && report.Status == "ready" {
			foundResume = true
		}
	}
	if !foundResume {
		t.Fatalf("released takeover report missing: %#v", takeoverReports)
	}
	retained, err := store.ManagerTakeovers(context.Background())
	if err != nil || len(retained) != 2 {
		t.Fatalf("takeover history was discarded: %#v, %v", retained, err)
	}
	released, err := store.ManagerTakeover(context.Background(), resume.OperationID)
	if err != nil || released == nil || released.Phase != "released" || released.Report == nil || released.Report.Status != "ready" {
		t.Fatalf("local released phase or wire completion changed: %#v, %v", released, err)
	}
}

func TestCoordinatorPreservesUnsettledUnknownHoldAndRefusesResume(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedManagerCoordinatorAuthority(t, store, fixture)
	policy := fixture.Policy
	policy.Mode, policy.AllowedRules = "off", []string{}
	takeover := fixture.Takeover
	takeover.PolicyRevision, takeover.RunGeneration = policy.PolicyRevision, policy.RunGeneration
	takeover.Source, takeover.Target, takeover.ValidUntil = fixture.Review.Source, fixture.Review.Target, fixture.Review.ValidUntil
	helper := &fakeManagerHelper{outputs: map[string][]byte{
		"acquire_intervention_hold": managerHoldReceipt(t, takeover, "acquire_intervention_hold", "unsettled", "unknown"),
	}}
	coordinator := &Coordinator{Store: store, Control: &fakeManagerControl{}, Helper: helper,
		Now: func() time.Time { return takeover.ValidUntil.Add(-30 * time.Second) }}
	manifest := model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy},
		InsightsTakeovers: []model.InsightsTakeoverManifestV1{takeover}}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	resume := managerResumeManifest(t, takeover)
	manifest.InsightsTakeovers = []model.InsightsTakeoverManifestV1{resume}
	if err := coordinator.Apply(context.Background(), manifest); err == nil {
		t.Fatal("unknown pending-input hold was released")
	}
	if len(helper.calls) != 1 {
		t.Fatalf("unknown hold reached release helper: %#v", helper.calls)
	}
	stored, err := store.ManagerTakeover(context.Background(), takeover.OperationID)
	if err != nil || stored == nil || stored.Phase != "unsettled" || stored.Report == nil || stored.Report.PendingInput.State != "unknown" {
		t.Fatalf("unsettled hold = %#v, %v", stored, err)
	}
	// A newer policy cannot erase an unresolved hold from report assembly.
	policy.PolicyRevision, policy.RunGeneration = resume.PolicyRevision, resume.RunGeneration
	if err := coordinator.ApplyPolicies(context.Background(), model.Manifest{
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy},
	}); err != nil {
		t.Fatal(err)
	}
	_, _, reports, err := coordinator.Reports(context.Background(), nil)
	if err != nil || len(reports) != 1 || reports[0].OperationID != takeover.OperationID || reports[0].Status != "unsettled" {
		t.Fatalf("unresolved hold disappeared after authority advanced: %#v, %v", reports, err)
	}
}

func TestCoordinatorRefusesEveryStaleCriticalSourceFenceBeforeHelper(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	mutations := map[string]func(*model.InsightsManagerReviewManifestV1){
		"workspace epoch":      func(value *model.InsightsManagerReviewManifestV1) { value.Source.WorkspaceEpoch += "_stale" },
		"native session":       func(value *model.InsightsManagerReviewManifestV1) { value.Source.NativeSessionID += "_stale" },
		"service generation":   func(value *model.InsightsManagerReviewManifestV1) { value.Source.ServiceGeneration++ },
		"sandbox generation":   func(value *model.InsightsManagerReviewManifestV1) { value.Source.SandboxGeneration++ },
		"profile revision":     func(value *model.InsightsManagerReviewManifestV1) { value.Source.ProfileRevision++ },
		"instruction revision": func(value *model.InsightsManagerReviewManifestV1) { value.Source.InstructionRevision++ },
		"provider route digest": func(value *model.InsightsManagerReviewManifestV1) {
			value.ProviderRouteDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			seedManagerCoordinatorAuthority(t, store, fixture)
			review := fixture.Review
			mutate(&review)
			helper := &fakeManagerHelper{reviewOutput: managerReviewReceipt(t, fixture, "start_review")}
			coordinator := &Coordinator{Store: store, Control: &fakeManagerControl{}, Helper: helper,
				Now: func() time.Time { return fixture.Review.ValidUntil.Add(-30 * time.Second) }}
			manifest := model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
				InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.Policy},
				InsightsManagerReviews:  []model.InsightsManagerReviewManifestV1{review}}
			if err := coordinator.Apply(context.Background(), manifest); err == nil {
				t.Fatal("stale review reached helper")
			}
			if len(helper.calls) != 0 {
				t.Fatalf("stale review helper calls = %#v", helper.calls)
			}
		})
	}
}

func TestCoordinatorRequiresFreshExactHostTaskLeaseForTaskOnlyReview(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	for _, test := range []struct {
		name       string
		attemptGap int64
		wantCalls  int
	}{
		{name: "exact current task", wantCalls: 1},
		{name: "stale attempt", attemptGap: 1, wantCalls: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			seedManagerCoordinatorAuthority(t, store, fixture)
			review := fixture.Review
			review.Target.TaskID = fixture.Takeover.Target.TaskID
			review.Target.TaskAttempt = fixture.Takeover.Target.TaskAttempt
			now := review.ValidUntil.Add(-30 * time.Second)
			observedAttempt := *review.Target.TaskAttempt + test.attemptGap
			if err := store.PutManagedTaskAuthority(context.Background(), state.LocalManagedTaskAuthority{
				ServiceRegistrationID: review.Source.ServiceRegistrationID, ServiceGeneration: review.Source.ServiceGeneration,
				SandboxGeneration: review.Source.SandboxGeneration, TaskID: review.Target.TaskID, TaskAttempt: &observedAttempt,
				Busy: true, ObservedAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			helper := &fakeManagerHelper{reviewOutput: managerReviewReceipt(t, fixture, "start_review")}
			control := &fakeManagerControl{runForReport: managerRequestForReview(review)}
			coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
			manifest := model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
				InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fixture.Policy},
				InsightsManagerReviews:  []model.InsightsManagerReviewManifestV1{review}}
			err = coordinator.Apply(context.Background(), manifest)
			if (err == nil) != (test.wantCalls == 1) || len(helper.calls) != test.wantCalls {
				t.Fatalf("task lease result err=%v helper calls=%#v", err, helper.calls)
			}
		})
	}
}

func TestCoordinatorRejectsConflictingReusedRunIDWithoutChangingPersistedReport(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	for _, phase := range []string{"recommended", "reviewing", "execution_unknown"} {
		t.Run(phase, func(t *testing.T) {
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			helper := &fakeManagerHelper{}
			coordinator := &Coordinator{Store: store, Control: &fakeManagerControl{}, Helper: helper,
				Now: func() time.Time { return fixture.Review.ValidUntil.Add(-30 * time.Second) }}
			original := state.LocalManagerRun{Manifest: fixture.Review, Phase: phase, DispatchStarted: true,
				StartedAt: fixture.Review.ValidUntil.Add(-time.Minute)}
			if phase == "recommended" {
				report := fixtureReportForReview(fixture.Review)
				original.Report = &report
			}
			if err := store.PutManagerRun(context.Background(), original); err != nil {
				t.Fatal(err)
			}
			conflict := fixture.Review
			conflict.ReservationID = "reservation_manager_conflict0001"
			err = coordinator.Apply(context.Background(), model.Manifest{InsightsManagerReviews: []model.InsightsManagerReviewManifestV1{conflict}})
			if !errors.Is(err, state.ErrManagerConflict) {
				t.Fatalf("conflicting reused run ID error = %v", err)
			}
			persisted, lookupErr := store.ManagerRun(context.Background(), fixture.Review.RunID)
			if lookupErr != nil || !reflect.DeepEqual(persisted, &original) || len(helper.calls) != 0 {
				t.Fatalf("conflicting replay changed state/helper: persisted=%#v helper=%#v err=%v", persisted, helper.calls, lookupErr)
			}
		})
	}
}

func TestCoordinatorPersistsExactLeaseOnlyRenewalWithoutRepeatingWork(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	for _, phase := range []string{"recommended", "reviewing", "execution_unknown"} {
		t.Run(phase, func(t *testing.T) {
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			helper := &fakeManagerHelper{}
			coordinator := &Coordinator{Store: store, Control: &fakeManagerControl{}, Helper: helper,
				Now: func() time.Time { return fixture.Review.ValidUntil.Add(-30 * time.Second) }}
			original := state.LocalManagerRun{Manifest: fixture.Review, Phase: phase, DispatchStarted: true,
				StartedAt: fixture.Review.ValidUntil.Add(-time.Minute)}
			if phase == "recommended" {
				report := fixtureReportForReview(fixture.Review)
				original.Report = &report
			}
			if err := store.PutManagerRun(context.Background(), original); err != nil {
				t.Fatal(err)
			}
			if err := coordinator.Apply(context.Background(), model.Manifest{InsightsManagerReviews: []model.InsightsManagerReviewManifestV1{fixture.Review}}); err != nil {
				t.Fatalf("exact replay rejected: %v", err)
			}
			renewed := fixture.Review
			renewed.ValidUntil = renewed.ValidUntil.Add(15 * time.Second)
			if err := coordinator.Apply(context.Background(), model.Manifest{InsightsManagerReviews: []model.InsightsManagerReviewManifestV1{renewed}}); err != nil {
				t.Fatalf("lease-only renewal rejected: %v", err)
			}
			afterRenewal, err := store.ManagerRun(context.Background(), fixture.Review.RunID)
			if err != nil || afterRenewal == nil || !afterRenewal.Manifest.ValidUntil.Equal(renewed.ValidUntil) ||
				!reflect.DeepEqual(afterRenewal.Report, original.Report) {
				t.Fatalf("lease-only renewal = %#v, %v", afterRenewal, err)
			}
			if len(helper.calls) != 0 {
				t.Fatalf("lease-only renewal repeated helper work: %#v", helper.calls)
			}
		})
	}
}

func fixtureReportForReview(review model.InsightsManagerReviewManifestV1) model.InsightsManagerRunReportV1 {
	return model.InsightsManagerRunReportV1{FormatVersion: 1, ReservationID: review.ReservationID, RunID: review.RunID,
		Manual: review.Manual, State: "recommended", PolicyRevision: review.PolicyRevision, Source: review.Source,
		Target: review.Target, Usage: model.InsightsManagerUsageV1{UnusedProof: "none"},
		ReceiptDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}

func loadManagerCoordinatorFixture(t *testing.T) managerCoordinatorFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("testdata", "backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture managerCoordinatorFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// seedManagerCoordinatorPrerequisites seeds the local sandbox, managed service,
// continuity source and manager capability. An optional explicit capability
// lets a caller seed one full initial capability through the same validated
// store boundary; ordinary calls keep the controlled default literal unchanged.
func seedManagerCoordinatorPrerequisites(t *testing.T, store *state.Store, fixture managerCoordinatorFixture, explicit ...state.LocalManagerCapability) {
	t.Helper()
	if len(explicit) > 1 {
		t.Fatal("seedManagerCoordinatorPrerequisites accepts at most one explicit capability")
	}
	ctx := context.Background()
	source := fixture.Review.Source
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: fixture.Policy.SandboxID, DesiredState: "running", ObservedState: "running",
		Generation: source.SandboxGeneration, ObservedGeneration: source.SandboxGeneration, Lifetime: "persistent",
		ImageDigest: q2TestImageDigest()}); err != nil {
		t.Fatal(err)
	}
	serviceManifest := model.ManagedServiceV1{FormatVersion: 1, OperationID: "op_manager_service0001", ActionRevision: 1, DesiredRevision: 1,
		ConfigDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DesiredState: "active", SessionMode: "lookup_only",
		Identity: model.ManagedServiceIdentityV1{ServerID: "srv_p2c_managerreview", TeamID: fixture.Review.Target.TeamID,
			MemberID: fixture.Review.Target.MemberID, SandboxID: fixture.Policy.SandboxID, SandboxGeneration: source.SandboxGeneration,
			ServiceRegistrationID: source.ServiceRegistrationID, ExpectedServiceGeneration: source.ServiceGeneration, Instance: "default", Role: "worker"},
		Profile: model.ManagedServiceProfileV1{SetupOperationID: "setup_manager0001", ProfileID: "opencode", ProfileRevision: source.ProfileRevision,
			ProfileDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		Instructions: model.ManagedServiceInstructionsV1{InstructionRevision: source.InstructionRevision,
			InstructionDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		Workspace: model.ManagedServiceWorkspaceV1{SelectionID: "selection_manager0001", ProjectID: "project_managerreview",
			WorkspaceEpoch: source.WorkspaceEpoch, ScopeRevision: 1, Designation: "team_project",
			RootAttestation: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}
	if err := store.PutManagedServiceIntent(ctx, state.LocalManagedService{Manifest: serviceManifest, Phase: "ready", ProcessInstance: "default",
		Port: 18443, CreationDispatched: true, ServiceGeneration: source.ServiceGeneration}); err != nil {
		t.Fatal(err)
	}
	native := &model.ManagedNativeRegistrationV1{RegisteredSourceID: source.RegisteredSourceID, WorkspaceEpoch: source.WorkspaceEpoch,
		NativeSessionID: source.NativeSessionID, NativeProjectID: "0123456789abcdef0123456789abcdef01234567",
		NativeLocationDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
	serviceReport := model.ManagedServiceReportV1{FormatVersion: 1, OperationID: serviceManifest.OperationID, ActionRevision: 1,
		ObservedDesiredRevision: 1, ConfigDigest: serviceManifest.ConfigDigest, ObservedState: "ready", Identity: serviceManifest.Identity,
		ServiceGeneration: source.ServiceGeneration, ProfileStatus: "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "ready",
		InstructionApplied: true, InstructionRevision: source.InstructionRevision, InstructionDigest: serviceManifest.Instructions.InstructionDigest,
		NativeRegistration: native, ReceiptDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
	if err := store.UpdateManagedService(ctx, source.ServiceRegistrationID, "ready", &serviceReport, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuitySource(ctx, state.LocalContinuitySource{Report: model.ContinuitySourceReportV1{FormatVersion: 1,
		RegisteredSourceID: source.RegisteredSourceID, ServiceRegistrationID: source.ServiceRegistrationID, ServiceGeneration: source.ServiceGeneration,
		ProjectID: serviceManifest.Workspace.ProjectID, SandboxID: fixture.Policy.SandboxID, SandboxGeneration: source.SandboxGeneration,
		WorkspaceEpoch: source.WorkspaceEpoch, NativeSessionID: source.NativeSessionID, NativeProjectID: native.NativeProjectID,
		NativeLocationDigest: native.NativeLocationDigest, ScopeRevision: 1, Role: "worker", ProfileRevision: source.ProfileRevision,
		InstructionRevision: source.InstructionRevision, Availability: "available", LastObservedAt: fixture.Review.ValidUntil.Add(-time.Minute)},
		Root: t.TempDir(), Instance: "default", Lifecycle: "running", LifecycleRevision: 1}); err != nil {
		t.Fatal(err)
	}
	capability := state.LocalManagerCapability{RegisteredSourceID: source.RegisteredSourceID, ServiceRegistrationID: source.ServiceRegistrationID,
		ServiceGeneration: source.ServiceGeneration, WorkspaceEpoch: source.WorkspaceEpoch, NativeSessionID: source.NativeSessionID,
		SandboxID: fixture.Policy.SandboxID, SandboxGeneration: source.SandboxGeneration, ProfileRevision: source.ProfileRevision,
		InstructionRevision: source.InstructionRevision, ProviderID: "deepseek", ModelID: "deepseek-chat", NativeProtocol: "openai_chat",
		Protocol: "opencode-supervisor/1", ProviderRouteDigest: fixture.Review.ProviderRouteDigest, ManagerProfile: fixture.Review.ManagerProfile,
		RecipeIDs: []string{fixture.Review.RecipeID}, MaxInputTokens: 8000, MaxOutputTokens: 1000, Available: true}
	if len(explicit) == 1 {
		capability = explicit[0]
	}
	if err := store.PutManagerCapability(ctx, capability); err != nil {
		t.Fatal(err)
	}
}

func seedManagerCoordinatorAuthority(t *testing.T, store *state.Store, fixture managerCoordinatorFixture) {
	t.Helper()
	seedManagerCoordinatorPrerequisites(t, store, fixture)
	ctx := context.Background()
	source := fixture.Review.Source
	finding := model.InsightFindingV1{FindingID: fixture.Review.FindingID, RuleID: fixture.Review.RuleID, State: "open",
		Revision: fixture.Review.FindingRevision, FirstSequence: 1, LastSequence: 8, Count: 4, Threshold: 3,
		MatchedCallIDs: []string{"call_manager0001"}, FirstObservedAt: fixture.Review.ValidUntil.Add(-time.Minute),
		LastObservedAt: fixture.Review.ValidUntil.Add(-time.Minute), Coverage: "complete", ToolCategory: "shell", Phase: "tool"}
	if err := store.PutManagerFinding(ctx, state.LocalManagerFinding{Finding: finding, Source: source, PolicyRevision: fixture.Review.PolicyRevision, JournalGeneration: "journal_manager0001",
		Acknowledged: true}); err != nil {
		t.Fatal(err)
	}
}

func TestCoordinatorRederivesSourceUnavailableAtReport(t *testing.T) {
	fixture := loadManagerCoordinatorFixture(t)
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
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
	now := policy.ValidUntil.Add(-30 * time.Second)
	coordinator := &Coordinator{Store: store, Control: &fakeManagerControl{}, Helper: &fakeManagerHelper{}, Now: func() time.Time { return now }}
	ctx := context.Background()
	if err := coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}); err != nil {
		t.Fatal(err)
	}
	reportsFor := func() model.InsightsManagerPolicyReportV1 {
		t.Helper()
		policies, _, _, reportErr := coordinator.Reports(ctx, nil)
		if reportErr != nil || len(policies) != 1 {
			t.Fatalf("reports = %#v, %v", policies, reportErr)
		}
		return policies[0]
	}
	report := reportsFor()
	if !report.Recommend.Available || len(report.RecommendCapabilities) != 1 || !report.RecommendCapabilities[0].Available {
		t.Fatalf("available source report = %#v", report)
	}
	// The exact source turns unavailable after the policy apply: every native
	// report cycle re-derives the truthful fail-closed state instead of
	// replaying the availability cached at apply.
	source, err := store.ContinuitySource(ctx, authority.Review.Source.RegisteredSourceID)
	if err != nil || source == nil {
		t.Fatalf("source = %#v, %v", source, err)
	}
	source.Report.Availability = "unavailable"
	if err := store.PutContinuitySource(ctx, *source); err != nil {
		t.Fatal(err)
	}
	report = reportsFor()
	if report.Recommend.Available || report.Recommend.Reason == nil || *report.Recommend.Reason != "source_unavailable" {
		t.Fatalf("unavailable source recommend = %#v", report.Recommend)
	}
	capabilityReport := report.RecommendCapabilities[0]
	if capabilityReport.Available || capabilityReport.Reason == nil || *capabilityReport.Reason != "source_unavailable" {
		t.Fatalf("unavailable source capability = %#v", capabilityReport)
	}
	// Restoring the source restores the unchanged available behavior.
	source.Report.Availability = "available"
	if err := store.PutContinuitySource(ctx, *source); err != nil {
		t.Fatal(err)
	}
	report = reportsFor()
	if !report.Recommend.Available || report.Recommend.Reason != nil || !report.RecommendCapabilities[0].Available || report.RecommendCapabilities[0].Reason != nil {
		t.Fatalf("restored source report = %#v", report)
	}
	// Precedence negatives: policy_off and policy_expired win over the source
	// state; the capability's own reason wins over runtime fallbacks.
	offPolicy := policy
	offPolicy.Mode = "off"
	if err := coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{offPolicy}}); err != nil {
		t.Fatal(err)
	}
	report = reportsFor()
	if report.Recommend.Available || report.Recommend.Reason == nil || *report.Recommend.Reason != "policy_off" ||
		report.RecommendCapabilities[0].Reason == nil || *report.RecommendCapabilities[0].Reason != "policy_off" {
		t.Fatalf("policy off report = %#v", report)
	}
	expiredPolicy := policy
	expiredPolicy.ValidUntil = now.Add(-time.Second)
	if err := coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{expiredPolicy}}); err != nil {
		t.Fatal(err)
	}
	report = reportsFor()
	if report.Recommend.Reason == nil || *report.Recommend.Reason != "policy_expired" ||
		report.RecommendCapabilities[0].Reason == nil || *report.RecommendCapabilities[0].Reason != "policy_expired" {
		t.Fatalf("policy expired report = %#v", report)
	}
	// The capability's own reason branch is unchanged from .39 (the store keeps
	// the capability immutable, so it is fixed at seed time and its precedence
	// over the runtime fallback is covered by the unchanged code path).
}

func managerReviewReceipt(t *testing.T, fixture managerCoordinatorFixture, action string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("testdata", "sandbox.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		Receipt map[string]any `json:"reviewReceipt"`
	}
	if err := json.Unmarshal(payload, &source); err != nil {
		t.Fatal(err)
	}
	receipt := source.Receipt
	receipt["action"] = action
	receipt["reservationId"] = fixture.Review.ReservationID
	receipt["runId"] = fixture.Review.RunID
	receipt["managerRegisteredSourceId"] = managerSourceID(fixture.Review.RunID)
	session := receipt["managerSession"].(map[string]any)
	session["nativeSessionId"] = fixture.Handoff.Handoff.Source.NativeSessionID
	session["nativeProjectId"] = fixture.Handoff.Handoff.Source.NativeProjectID
	session["nativeLocationDigest"] = fixture.Handoff.Handoff.Source.NativeLocationDigest
	session["serviceRegistrationId"] = fixture.Review.Source.ServiceRegistrationID
	session["serviceGeneration"] = float64(fixture.Review.Source.ServiceGeneration)
	session["providerRouteDigest"] = fixture.Review.ProviderRouteDigest
	profile, err := json.Marshal(fixture.Review.ManagerProfile)
	if err != nil {
		t.Fatal(err)
	}
	var profileMap map[string]any
	if err := json.Unmarshal(profile, &profileMap); err != nil {
		t.Fatal(err)
	}
	session["managerProfile"] = profileMap
	// The paired receipt carries the actual six-key proposal. The controlled
	// local factory derives its recommendation bounds from the seeded finding
	// (firstSequence 1, lastSequence 8) and keeps the digest coherent with the
	// guidance receipt; terminal-negative journeys override both.
	guidance := receipt["guidanceReceipt"].(map[string]any)
	receipt["proposal"] = map[string]any{"recipeId": fixture.Review.RecipeID, "outcome": "recommendation",
		"rationaleCode": "unchanged_failure_repeated", "firstSequence": 1, "lastSequence": 8,
		"guidanceDigest": guidance["guidanceDigest"]}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func managerRequestForReview(review model.InsightsManagerReviewManifestV1) *model.InsightsManagerReservationRequestV1 {
	return &model.InsightsManagerReservationRequestV1{RequestID: "req_manual_runtime0001", FindingID: review.FindingID,
		RuleID: review.RuleID, RecipeID: review.RecipeID}
}

func managerInsightBatch(fixture managerCoordinatorFixture, policyRevision int64, batchID string) model.InsightBatchV1 {
	source := fixture.Review.Source
	finding := model.InsightFindingV1{FindingID: fixture.Review.FindingID, RuleID: fixture.Review.RuleID, State: "open",
		Revision: fixture.Review.FindingRevision, FirstSequence: 1, LastSequence: 8, Count: 4, Threshold: 3,
		MatchedCallIDs: []string{"call_manager0001"}, FirstObservedAt: fixture.Review.ValidUntil.Add(-time.Minute),
		LastObservedAt: fixture.Review.ValidUntil.Add(-time.Minute), Coverage: "complete", ToolCategory: "shell", Phase: "tool"}
	return model.InsightBatchV1{FormatVersion: 1, BatchID: batchID, SandboxID: fixture.Policy.SandboxID,
		SandboxGeneration: source.SandboxGeneration, PolicyRevision: policyRevision, RegisteredSourceID: source.RegisteredSourceID,
		ServiceRegistrationID: source.ServiceRegistrationID, ServiceGeneration: source.ServiceGeneration, WorkspaceEpoch: source.WorkspaceEpoch,
		NativeSessionID: source.NativeSessionID, JournalGeneration: "journal_manager0001", ThroughSequence: 8,
		ObservedAt: fixture.Review.ValidUntil.Add(-time.Minute), Status: "ready", Findings: []model.InsightFindingV1{finding}}
}

func automaticManagerReviewReceipt(t *testing.T, fixture managerCoordinatorFixture) []byte {
	t.Helper()
	receipt := managerReviewReceipt(t, fixture, "start_review")
	var value map[string]any
	if err := json.Unmarshal(receipt, &value); err != nil {
		t.Fatal(err)
	}
	value["reservationId"] = fixture.AutomaticReservation.ReservationID
	value["runId"] = fixture.AutomaticReservation.RunID
	value["managerRegisteredSourceId"] = managerSourceID(fixture.AutomaticReservation.RunID)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func managerResumeManifest(t *testing.T, takeover model.InsightsTakeoverManifestV1) model.InsightsTakeoverManifestV1 {
	t.Helper()
	payload, err := json.Marshal(takeover)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	raw["operationId"] = "resume_manager_runtime0001"
	raw["predecessorOperationId"] = takeover.OperationID
	raw["action"] = "resume_manager_and_release_member"
	raw["holdRevision"] = float64(takeover.HoldRevision + 1)
	raw["holdState"] = "released"
	raw["policyRevision"] = float64(takeover.PolicyRevision + 1)
	raw["runGeneration"] = float64(takeover.RunGeneration + 1)
	payload, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var resume model.InsightsTakeoverManifestV1
	if err := json.Unmarshal(payload, &resume); err != nil {
		t.Fatal(err)
	}
	return resume
}

func managerHoldReceipt(t *testing.T, manifest model.InsightsTakeoverManifestV1, action, status, pendingState string) []byte {
	t.Helper()
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(payload, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt["action"] = action
	receipt["status"] = status
	receipt["pendingInput"] = map[string]any{"state": pendingState, "alreadyConsumed": false}
	receipt["receiptDigest"] = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	receipt["errorCode"] = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

var _ Control = (*fakeManagerControl)(nil)
var _ Helper = (*fakeManagerHelper)(nil)

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Q2 paired guidance boundary tests (root revisions 178/180/186). The legacy
// Recommend journey remains a zero-dispatch control. The qualified automatic
// origin is seeded through existing store types with the tuple facts held as
// JSON-shaped test-local seams, so the expected RED is behavioral (missing
// qualified admission/dispatch/observation/cancellation), never a missing-type
// compile error.
// ---------------------------------------------------------------------------

func q2ActionCalls(calls []managerHelperCall, action string) []managerHelperCall {
	var matched []managerHelperCall
	for _, call := range calls {
		if call.Payload["action"] == action {
			matched = append(matched, call)
		}
	}
	return matched
}

// q2CanonicalDigest is the r178/r180 canonical digest: sha256 over UTF-8 compact
// sorted-key JSON excluding the digest field itself.
func q2CanonicalDigest(t *testing.T, value map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("sha256:%x", sum)
}

func q2BindingDigest(t *testing.T, authority map[string]any, reservationID, runID string) string {
	t.Helper()
	source, _ := authority["source"].(map[string]any)
	binding := map[string]any{
		"bindingVersion":        1,
		"guardId":               opaqueID("guard_", runID),
		"instructionRevision":   source["instructionRevision"],
		"nativeSessionId":       source["nativeSessionId"],
		"pendingInputId":        opaqueID("msg_", runID),
		"profileRevision":       source["profileRevision"],
		"registeredSourceId":    source["registeredSourceId"],
		"reservationId":         reservationID,
		"runId":                 runID,
		"sandboxGeneration":     source["sandboxGeneration"],
		"serviceGeneration":     source["serviceGeneration"],
		"serviceRegistrationId": source["serviceRegistrationId"],
		"workspaceEpoch":        source["workspaceEpoch"],
	}
	return q2CanonicalDigest(t, binding)
}

// q2GuidanceReceipt builds the dispatch/observe/cancel helper receipt with the
// exact guidance snapshot keys, canonical receiptDigest and finite times taken
// from the fixture clock (never a fabricated future).
func q2GuidanceReceipt(t *testing.T, action, sandboxID string, authority map[string]any, guidanceDigest, state string, now time.Time) []byte {
	t.Helper()
	reservationID, _ := authority["reservationId"].(string)
	runID, _ := authority["runId"].(string)
	stamp := now.UTC().Format(time.RFC3339)
	snapshot := map[string]any{
		"formatVersion":  1,
		"sandboxId":      sandboxID,
		"reservationId":  reservationID,
		"runId":          runID,
		"revision":       1,
		"bindingDigest":  q2BindingDigest(t, authority, reservationID, runID),
		"guidanceDigest": guidanceDigest,
		"guardId":        opaqueID("guard_", runID),
		"pendingInputId": opaqueID("msg_", runID),
		"state":          state,
		"refusalCode":    nil,
		"logCursor":      nil,
		"observedAt":     stamp,
		"admittedAt":     now.Add(-2 * time.Second).UTC().Format(time.RFC3339),
		"availableAt":    nil,
		"settledAt":      nil,
	}
	switch state {
	case "available_to_worker":
		snapshot["availableAt"] = now.Add(-time.Second).UTC().Format(time.RFC3339)
		snapshot["settledAt"] = snapshot["availableAt"]
	case "cancelled", "refused":
		snapshot["settledAt"] = now.Add(-time.Second).UTC().Format(time.RFC3339)
	}
	snapshot["receiptDigest"] = q2CanonicalDigest(t, snapshot)
	receipt := map[string]any{
		"formatVersion": 1,
		"action":        action,
		"reservationId": reservationID,
		"runId":         runID,
		"guidance":      snapshot,
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// q2LegacyJourney is the existing legacy Recommend automatic journey: unqualified
// capability, mode recommend. It must produce zero native guidance.
func q2LegacyJourney(t *testing.T) (managerCoordinatorFixture, *state.Store, *fakeManagerControl, *fakeManagerHelper, *Coordinator, model.Manifest, model.InsightsManagerPolicyManifestV1) {
	t.Helper()
	fixture := loadManagerCoordinatorFixture(t)
	policy := fixture.Policy
	policy.PolicyRevision = fixture.AutomaticReservation.PolicyRevision
	policy.RunGeneration = 2
	policy.ValidUntil = fixture.AutomaticReservation.ExpiresAt
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedManagerCoordinatorAuthority(t, store, fixture)
	helper := &fakeManagerHelper{reviewOutput: automaticManagerReviewReceipt(t, fixture)}
	control := &fakeManagerControl{reservation: fixture.AutomaticReservation, dynamic: true}
	requireManagerStartReportBeforeHelper(t, helper, control)
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
	manifest := model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	batch := managerInsightBatch(fixture, fixture.AutomaticReservation.PolicyRevision, "batch_q2_legacy0001")
	receipt := model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: len(batch.Findings), ThroughSequence: batch.ThroughSequence}
	if err := coordinator.ObserveAcknowledgedInsightBatch(context.Background(), batch, receipt); err != nil {
		t.Fatal(err)
	}
	if len(control.reservations) != 1 || len(q2ActionCalls(helper.calls, "start_review")) != 1 {
		t.Fatalf("legacy journey precondition: reservations=%d start_review=%d", len(control.reservations), len(q2ActionCalls(helper.calls, "start_review")))
	}
	if len(control.reports) == 0 || control.reports[len(control.reports)-1].State != "recommended" {
		t.Fatalf("legacy journey precondition: terminal report ACK = %#v", control.reports)
	}
	return fixture, store, control, helper, coordinator, manifest, policy
}

// q2QualifiedJourney seeds the qualified automatic origin: mode auto_steer with
// the negotiated tuple seam, custom native version and exact plugin/profile/source
// capability, then runs the automatic review to a terminal recommended ACK.

// q2SeedManagerFinding seeds the acknowledged finding without re-running the
// default capability prerequisites (the qualified journey seeds its own
// capability explicitly).
func q2SeedManagerFinding(t *testing.T, store *state.Store, fixture managerCoordinatorFixture) {
	t.Helper()
	source := fixture.Review.Source
	finding := model.InsightFindingV1{FindingID: fixture.Review.FindingID, RuleID: fixture.Review.RuleID, State: "open",
		Revision: fixture.Review.FindingRevision, FirstSequence: 1, LastSequence: 8, Count: 4, Threshold: 3,
		MatchedCallIDs: []string{"call_manager0001"}, FirstObservedAt: fixture.Review.ValidUntil.Add(-time.Minute),
		LastObservedAt: fixture.Review.ValidUntil.Add(-time.Minute), Coverage: "complete", ToolCategory: "shell", Phase: "tool"}
	if err := store.PutManagerFinding(context.Background(), state.LocalManagerFinding{Finding: finding, Source: source,
		PolicyRevision: fixture.Review.PolicyRevision, JournalGeneration: "journal_manager0001", Acknowledged: true}); err != nil {
		t.Fatal(err)
	}
}

func q2QualifiedJourney(t *testing.T) (managerCoordinatorFixture, *state.Store, *fakeManagerControl, *fakeManagerHelper, *Coordinator, model.Manifest, model.InsightsManagerPolicyManifestV1, model.InsightsManagerRunReportV1, map[string]any, bool) {
	t.Helper()
	fixture := loadManagerCoordinatorFixture(t)
	policy := fixture.Policy
	policy.Mode = "auto_steer"
	policy.AutoSteerAvailable = false
	policy.PolicyRevision = fixture.AutomaticReservation.PolicyRevision
	policy.RunGeneration = 180
	policy.ValidUntil = fixture.AutomaticReservation.ExpiresAt
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	policy = q2MergeQualifiedPolicy(t, policy, fixture.Review.ManagerProfile.ProfileDigest)
	qualified := state.LocalManagerCapability{
		RegisteredSourceID: fixture.Review.Source.RegisteredSourceID, ServiceRegistrationID: fixture.Review.Source.ServiceRegistrationID,
		ServiceGeneration: fixture.Review.Source.ServiceGeneration, WorkspaceEpoch: fixture.Review.Source.WorkspaceEpoch,
		NativeSessionID: fixture.Review.Source.NativeSessionID, SandboxID: fixture.Policy.SandboxID, SandboxGeneration: fixture.Review.Source.SandboxGeneration,
		ProfileRevision: fixture.Review.Source.ProfileRevision, InstructionRevision: fixture.Review.Source.InstructionRevision,
		NativeVersion: "2.0.14-wm.1", NativeSourceRevision: "08462140ec0de1e4b17d4a353d8d5827f53cf7b0",
		Protocol: "opencode-supervisor/1", NativeProtocol: "openai_chat", ProviderID: "deepseek", ModelID: "deepseek-chat",
		ProviderRouteDigest: fixture.Review.ProviderRouteDigest, RecipeIDs: []string{fixture.Review.RecipeID},
		ManagerPluginDigest: "sha256:f7d9cec7e6bcfef134b0d27c5bd1526a0199859b5954c0dae523ff843eaf7a94",
		ManagerProfile:      fixture.Review.ManagerProfile, MaxInputTokens: 8000, MaxOutputTokens: 1000,
		FinalRequestMaxBytes: 7000, ToolsAllowed: false, MediaAllowed: false, HardOutputTokenLimit: true, Available: true,
	}
	qualified = q2MergeQualifiedCapability(t, qualified)
	seedManagerCoordinatorPrerequisites(t, store, fixture, qualified)
	q2SeedManagerFinding(t, store, fixture)
	report := model.InsightsManagerPolicyReportV1{FormatVersion: 1, SandboxID: policy.SandboxID,
		SandboxGeneration: fixture.Review.Source.SandboxGeneration, PolicyRevision: policy.PolicyRevision, RunGeneration: policy.RunGeneration,
		Status: "applied", Recommend: model.InsightsManagerCapabilityV1{Available: true},
		ReceiptDigest: "sha256:" + strings.Repeat("9", 64)}
	if err := store.PutManagerPolicy(context.Background(), state.LocalManagerPolicy{Manifest: policy, Report: report}); err != nil {
		t.Fatal(err)
	}
	helper := &fakeManagerHelper{reviewOutput: automaticManagerReviewReceipt(t, fixture)}
	control := &fakeManagerControl{reservation: fixture.AutomaticReservation, dynamic: true}
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return now }}
	manifest := model.Manifest{ServerID: "srv_p2c_managerreview", DesiredRevision: 1,
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}
	batch := managerInsightBatch(fixture, fixture.AutomaticReservation.PolicyRevision, "batch_q2_qualified0001")
	receipt := model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: len(batch.Findings), ThroughSequence: batch.ThroughSequence}
	_ = coordinator.ObserveAcknowledgedInsightBatch(context.Background(), batch, receipt)
	admitted := len(control.reservations) == 1 && len(q2ActionCalls(helper.calls, "start_review")) == 1 &&
		len(control.reports) > 0 && control.reports[len(control.reports)-1].State == "recommended"
	terminal := model.InsightsManagerRunReportV1{}
	if len(control.reports) > 0 {
		terminal = control.reports[len(control.reports)-1]
	}
	var authority map[string]any
	if starts := q2ActionCalls(helper.calls, "start_review"); len(starts) == 1 {
		authority, _ = starts[0].Payload["authority"].(map[string]any)
	}
	return fixture, store, control, helper, coordinator, manifest, policy, terminal, authority, admitted
}

func q2QualifiedPrereqs(t *testing.T, helper *fakeManagerHelper, authority map[string]any, terminal model.InsightsManagerRunReportV1, sandboxID string, now time.Time) string {
	t.Helper()
	if terminal.Proposal == nil || terminal.Proposal.GuidanceDigest == nil || *terminal.Proposal.GuidanceDigest == "" {
		t.Fatalf("qualified terminal recommended proposal omitted guidanceDigest: %#v", terminal.Proposal)
	}
	guidanceDigest := *terminal.Proposal.GuidanceDigest
	helper.outputs = map[string][]byte{
		"dispatch_guidance": q2GuidanceReceipt(t, "dispatch_guidance", sandboxID, authority, guidanceDigest, "pending", now),
		"observe_guidance":  q2GuidanceReceipt(t, "observe_guidance", sandboxID, authority, guidanceDigest, "available_to_worker", now),
		"cancel_guidance":   q2GuidanceReceipt(t, "cancel_guidance", sandboxID, authority, guidanceDigest, "cancelled", now),
	}
	return guidanceDigest
}

// TestQ2LegacyRecommendControlNeverDispatchesGuidance is the primary control:
// unqualified legacy Recommend must produce zero native guidance and no
// negotiation fields on any helper request.
func TestQ2LegacyRecommendControlNeverDispatchesGuidance(t *testing.T) {
	_, _, control, helper, coordinator, manifest, _ := q2LegacyJourney(t)
	reportsBefore, callsBefore := len(control.reports), len(helper.calls)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if dispatches := q2ActionCalls(helper.calls[callsBefore:], "dispatch_guidance"); len(dispatches) != 0 {
		t.Fatalf("R186: legacy Recommend must never admit native guidance: %#v", helper.calls[callsBefore:])
	}
	if len(control.reports) != reportsBefore {
		t.Fatalf("legacy Recommend guidance changed model reports: before=%d after=%d", reportsBefore, len(control.reports))
	}
	for _, call := range helper.calls[callsBefore:] {
		if _, ok := call.Payload["runtimeContractVersion"]; ok {
			t.Fatalf("legacy helper request carried negotiation fields: %#v", call.Payload)
		}
	}
}

// TestQ2QualifiedAutoSteerOriginDispatchesEndOfPassWithNegotiatedAuthority is the
// primary qualified RED: one negotiated dispatch_guidance at end-of-pass Apply
// after the terminal ACK, with exact request keys, origin runGeneration, real
// canonical binding digest and the terminal guidance digest.
func TestQ2QualifiedAutoSteerOriginDispatchesEndOfPassWithNegotiatedAuthority(t *testing.T) {
	fixture, store, control, helper, coordinator, manifest, policy, terminal, authority, admitted := q2QualifiedJourney(t)
	if !admitted {
		t.Fatalf("R186/R178: qualified auto_steer origin must admit exactly one automatic review before guidance (reservations=%d start_review=%d reports=%#v)",
			len(control.reservations), len(q2ActionCalls(helper.calls, "start_review")), control.reports)
	}
	capability, err := store.ManagerCapability(context.Background(), terminal.Source.RegisteredSourceID)
	if err != nil || capability == nil {
		t.Fatalf("qualified capability = %#v, %v", capability, err)
	}
	if authority["runGeneration"] != float64(policy.RunGeneration) {
		t.Fatalf("R194/R180: negotiated start-review authority must carry origin runGeneration: %#v", authority["runGeneration"])
	}
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	q2QualifiedPrereqs(t, helper, authority, terminal, capability.SandboxID, now)
	helper.beforeCall = func(request map[string]any) error {
		if request["action"] != "dispatch_guidance" {
			return nil
		}
		run, err := store.ManagerRun(context.Background(), terminal.RunID)
		if err != nil || run == nil {
			return fmt.Errorf("intent check read failed: %v", err)
		}
		if !run.GuidanceAttempted || run.Guidance != nil {
			return errors.New("durable attempt intent must exist before the helper POST")
		}
		return nil
	}
	reportsBefore, callsBefore := len(control.reports), len(helper.calls)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatalf("R186: qualified end-of-pass Apply must admit the negotiated guidance attempt: %v", err)
	}
	dispatches := q2ActionCalls(helper.calls[callsBefore:], "dispatch_guidance")
	if len(dispatches) != 1 {
		t.Fatalf("R178/R186: exactly one negotiated dispatch_guidance; got %#v", helper.calls[callsBefore:])
	}
	request := dispatches[0].Payload
	keys := []string{"formatVersion", "action", "instance", "runtimeContractVersion", "authority", "bindingDigest"}
	if len(request) != len(keys) {
		t.Fatalf("R178: dispatch_guidance keys must be exactly %v: %#v", keys, request)
	}
	for _, key := range keys {
		if _, ok := request[key]; !ok {
			t.Fatalf("R178: dispatch_guidance missing %s: %#v", key, request)
		}
	}
	if request["runtimeContractVersion"] != "0.1.32" {
		t.Fatalf("R180/R186: negotiated dispatch must carry exactly 0.1.32: %#v", request["runtimeContractVersion"])
	}
	dispatchAuthority, _ := request["authority"].(map[string]any)
	if dispatchAuthority["runGeneration"] != float64(policy.RunGeneration) {
		t.Fatalf("R180/R186: dispatch authority runGeneration = %#v want %d", dispatchAuthority["runGeneration"], policy.RunGeneration)
	}
	if dispatchAuthority["validUntil"] != authority["validUntil"] {
		t.Fatalf("R180: advice lifetime must not be renewed: dispatch=%#v start=%#v", dispatchAuthority["validUntil"], authority["validUntil"])
	}
	reservationID, _ := dispatchAuthority["reservationId"].(string)
	runID, _ := dispatchAuthority["runId"].(string)
	if request["bindingDigest"] != q2BindingDigest(t, dispatchAuthority, reservationID, runID) {
		t.Fatalf("R178/R180: dispatch bindingDigest is not the canonical digest: %#v", request["bindingDigest"])
	}
	if len(control.reports) != reportsBefore {
		t.Fatalf("R178: guidance dispatch must not create a model report: before=%d after=%d", reportsBefore, len(control.reports))
	}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if again := q2ActionCalls(helper.calls[callsBefore:], "dispatch_guidance"); len(again) != 1 {
		t.Fatalf("R178/R186: one automatic attempt per episode; second pass dispatched %d", len(again))
	}
}

// TestQ2QualifiedOriginRecoverObservesUnknownGetOnly is the recovery RED: after
// an unknown negotiated dispatch, Recover observes GET-only exactly once and
// never initiates another attempt or model review.
func TestQ2QualifiedOriginRecoverObservesUnknownGetOnly(t *testing.T) {
	fixture, store, control, helper, coordinator, manifest, _, terminal, authority, admitted := q2QualifiedJourney(t)
	if !admitted {
		t.Fatalf("R186/R178: qualified auto_steer origin must admit exactly one automatic review before recovery (reports=%#v)", control.reports)
	}
	capability, err := store.ManagerCapability(context.Background(), terminal.Source.RegisteredSourceID)
	if err != nil || capability == nil {
		t.Fatalf("qualified capability = %#v, %v", capability, err)
	}
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	q2QualifiedPrereqs(t, helper, authority, terminal, capability.SandboxID, now)
	helper.loseActions = map[string]bool{"dispatch_guidance": true}
	callsBefore := len(helper.calls)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Logf("unknown qualified dispatch surfaced: %v", err)
	}
	if dispatches := q2ActionCalls(helper.calls[callsBefore:], "dispatch_guidance"); len(dispatches) != 1 {
		t.Fatalf("R186 precondition: exactly one attempted negotiated guidance before recovery; got %#v", helper.calls[callsBefore:])
	}
	recoverBefore := len(helper.calls)
	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := helper.calls[recoverBefore:]
	if again := q2ActionCalls(after, "dispatch_guidance"); len(again) != 0 {
		t.Fatalf("R178/R186: Recover must never initiate another guidance attempt: %#v", after)
	}
	if started := q2ActionCalls(after, "start_review"); len(started) != 0 {
		t.Fatalf("R178: Recover must never start a new model review: %#v", after)
	}
	observed := q2ActionCalls(after, "observe_guidance")
	if len(observed) != 1 {
		t.Fatalf("R178/R186: Recover must reconcile unknown guidance GET-only via observe_guidance: %#v", after)
	}
	observeKeys := []string{"formatVersion", "action", "instance", "runtimeContractVersion", "reservationId", "runId", "bindingDigest"}
	if len(observed[0].Payload) != len(observeKeys) {
		t.Fatalf("R178: observe_guidance keys must be exactly %v: %#v", observeKeys, observed[0].Payload)
	}
	if observed[0].Payload["runtimeContractVersion"] != "0.1.32" {
		t.Fatalf("R180: observe_guidance must carry exactly 0.1.32: %#v", observed[0].Payload["runtimeContractVersion"])
	}
}

// TestQ2QualifiedOriginOffCancelsPendingWithTruthfulAck is the Off RED: Off
// fences new attempts and cancels known pending guidance through the existing
// DELETE path with exact identity keys.
func TestQ2QualifiedOriginOffCancelsPendingWithTruthfulAck(t *testing.T) {
	fixture, store, control, helper, coordinator, manifest, policy, terminal, authority, admitted := q2QualifiedJourney(t)
	if !admitted {
		t.Fatalf("R186/R178: qualified auto_steer origin must admit exactly one automatic review before Off (reports=%#v)", control.reports)
	}
	capability, err := store.ManagerCapability(context.Background(), terminal.Source.RegisteredSourceID)
	if err != nil || capability == nil {
		t.Fatalf("qualified capability = %#v, %v", capability, err)
	}
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	q2QualifiedPrereqs(t, helper, authority, terminal, capability.SandboxID, now)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatalf("R186: qualified guidance attempt required before Off: %v", err)
	}
	if dispatches := q2ActionCalls(helper.calls, "dispatch_guidance"); len(dispatches) != 1 {
		t.Fatalf("R186 precondition: pending qualified guidance attempt required before Off; got %#v", helper.calls)
	}
	off := policy
	off.PolicyRevision++
	off.RunGeneration++
	off.Mode = "off"
	off.AllowedRules = []string{}
	manifest.DesiredRevision++
	manifest.InsightsManagerPolicies = []model.InsightsManagerPolicyManifestV1{off}
	callsBefore := len(helper.calls)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	after := helper.calls[callsBefore:]
	cancels := q2ActionCalls(after, "cancel_guidance")
	if len(cancels) != 1 {
		t.Fatalf("R178/R186: Off must cancel known pending guidance via the existing DELETE path; got %#v", after)
	}
	cancelKeys := []string{"formatVersion", "action", "instance", "runtimeContractVersion", "reservationId", "runId", "bindingDigest"}
	if len(cancels[0].Payload) != len(cancelKeys) {
		t.Fatalf("R178: cancel_guidance keys must be exactly %v: %#v", cancelKeys, cancels[0].Payload)
	}
	if cancels[0].Payload["runtimeContractVersion"] != "0.1.32" {
		t.Fatalf("R180: cancel_guidance must carry exactly 0.1.32: %#v", cancels[0].Payload["runtimeContractVersion"])
	}
	if again := q2ActionCalls(helper.calls, "dispatch_guidance"); len(again) != 1 {
		t.Fatalf("R186: Off must fence new attempts; dispatches=%d", len(again))
	}
	storedPolicy, err := store.ManagerPolicy(context.Background(), policy.SandboxID)
	if err != nil || storedPolicy == nil || storedPolicy.Report.Status != "applied" {
		t.Fatalf("R194: Off applied only after known pending guidance settled: %#v, %v", storedPolicy, err)
	}
}

// TestQ2UnknownGuidanceKeepsOffAckUnsettled proves unknown guidance stays
// protective: Off must not cancel it, must not claim applied, and later
// recovery remains GET-only.
func TestQ2UnknownGuidanceKeepsOffAckUnsettled(t *testing.T) {
	fixture, store, control, helper, coordinator, manifest, policy, terminal, authority, admitted := q2QualifiedJourney(t)
	if !admitted {
		t.Fatalf("qualified origin not admitted: %#v", control.reports)
	}
	capability, err := store.ManagerCapability(context.Background(), terminal.Source.RegisteredSourceID)
	if err != nil || capability == nil {
		t.Fatalf("capability = %#v, %v", capability, err)
	}
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	q2QualifiedPrereqs(t, helper, authority, terminal, capability.SandboxID, now)
	helper.loseActions = map[string]bool{"dispatch_guidance": true}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Logf("unknown dispatch surfaced: %v", err)
	}
	if len(q2ActionCalls(helper.calls, "dispatch_guidance")) != 1 {
		t.Fatalf("expected one attempted dispatch before Off: %#v", helper.calls)
	}
	off := policy
	off.PolicyRevision++
	off.RunGeneration++
	off.Mode = "off"
	off.AllowedRules = []string{}
	manifest.DesiredRevision++
	manifest.InsightsManagerPolicies = []model.InsightsManagerPolicyManifestV1{off}
	callsBefore := len(helper.calls)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if cancels := q2ActionCalls(helper.calls[callsBefore:], "cancel_guidance"); len(cancels) != 0 {
		t.Fatalf("R194: Off must not cancel unknown guidance: %#v", cancels)
	}
	storedPolicy, err := store.ManagerPolicy(context.Background(), policy.SandboxID)
	if err != nil || storedPolicy == nil || storedPolicy.Report.Status == "applied" {
		t.Fatalf("R194: Off must not claim applied while unknown guidance unsettled: %#v, %v", storedPolicy, err)
	}
	recoverBefore := len(helper.calls)
	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := helper.calls[recoverBefore:]
	if len(q2ActionCalls(after, "dispatch_guidance")) != 0 || len(q2ActionCalls(after, "start_review")) != 0 {
		t.Fatalf("R194: recovery after unknown must be GET-only: %#v", after)
	}
	if len(q2ActionCalls(after, "observe_guidance")) != 1 {
		t.Fatalf("R194: unknown guidance recovery must observe exactly once: %#v", after)
	}
}

// TestQ2AttemptIntentWithoutSnapshotRecoversGetOnly proves a crash between the
// durable intent and any result recovers without a second attempt.
func TestQ2AttemptIntentWithoutSnapshotRecoversGetOnly(t *testing.T) {
	fixture, store, control, helper, coordinator, _, _, terminal, authority, admitted := q2QualifiedJourney(t)
	if !admitted {
		t.Fatalf("qualified origin not admitted: %#v", control.reports)
	}
	capability, err := store.ManagerCapability(context.Background(), terminal.Source.RegisteredSourceID)
	if err != nil || capability == nil {
		t.Fatalf("capability = %#v, %v", capability, err)
	}
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	q2QualifiedPrereqs(t, helper, authority, terminal, capability.SandboxID, now)
	run, err := store.ManagerRun(context.Background(), terminal.RunID)
	if err != nil || run == nil {
		t.Fatalf("run = %#v, %v", run, err)
	}
	run.GuidanceAttempted = true
	run.Guidance = nil
	if err := store.PutManagerRun(context.Background(), *run); err != nil {
		t.Fatal(err)
	}
	callsBefore := len(helper.calls)
	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := helper.calls[callsBefore:]
	if len(q2ActionCalls(after, "dispatch_guidance")) != 0 {
		t.Fatalf("R194: recovery must never dispatch a second attempt: %#v", after)
	}
	if observed := q2ActionCalls(after, "observe_guidance"); len(observed) != 1 {
		t.Fatalf("R194: attempted-without-snapshot must recover GET-only: %#v", after)
	}
	reloaded, err := store.ManagerRun(context.Background(), terminal.RunID)
	if err != nil || reloaded == nil || reloaded.Guidance == nil || reloaded.Guidance.GuidanceDigest != *terminal.Proposal.GuidanceDigest {
		t.Fatalf("R194: recovered snapshot must keep the original proposal digest: %#v, %v", reloaded, err)
	}
}

func q2TestArtifactDigest() string { return "sha256:" + strings.Repeat("4e", 32) }
func q2TestBinaryDigest() string   { return "sha256:" + strings.Repeat("ef", 32) }
func q2TestImageDigest() string    { return "sha256:" + strings.Repeat("1a", 32) }

const (
	q2GuardVersion    = "warpmetal.atomic-input.v1"
	q2CustomVersion   = "2.0.14-wm.1"
	q2SourceRevision  = "08462140ec0de1e4b17d4a353d8d5827f53cf7b0"
	q2PatchDigest     = "sha256:5bcf0104d17a31d5141d9ad773b7ca7fbeddeb71a4a36689d5baee9f72f0f47b"
	q2ProfileDigest   = "sha256:4ea596774c5b66bfc395bda3f6c00765d4e89e22f270235a327872b3760e5e17"
	q2PluginDigest    = "sha256:f7d9cec7e6bcfef134b0d27c5bd1526a0199859b5954c0dae523ff843eaf7a94"
	q2ContractVersion = "0.1.32"
)

// q2MergedJSON overlays an exact extra JSON object onto an existing typed value
// and returns the merged bytes, so fields the current types do not know are
// still authored and will be captured by future typed fields via the same
// json.Unmarshal path.
func q2MergedJSON(t *testing.T, base any, extra string) []byte {
	t.Helper()
	payload, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var merged map[string]any
	if err := json.Unmarshal(payload, &merged); err != nil {
		t.Fatal(err)
	}
	var overlay map[string]any
	if err := json.Unmarshal([]byte(extra), &overlay); err != nil {
		t.Fatal(err)
	}
	for key, value := range overlay {
		merged[key] = value
	}
	out, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func q2QualifiedPolicyExtra(profileDigest string) string {
	return fmt.Sprintf(`{"autoSteerPolicy":{"formatVersion":1,"available":true,"reason":null,"qualifiedTuple":{"nativeGuardVersion":%q,"customNativeVersion":%q,"nativeSourceRevision":%q,"patchDigest":%q,"artifactSha256":%q,"binarySha256":%q,"imageDigest":%q,"managerProfileDigest":%q,"managerPluginDigest":%q}}}`,
		q2GuardVersion, q2CustomVersion, q2SourceRevision, q2PatchDigest, q2TestArtifactDigest(), q2TestBinaryDigest(),
		q2TestImageDigest(), profileDigest, q2PluginDigest)
}

func q2QualifiedCapabilityExtra() string {
	return fmt.Sprintf(`{"nativeGuard":{"guardVersion":%q,"customVersion":%q,"sourceRevision":%q,"patchDigest":%q,"artifactSha256":%q,"binarySha256":%q}}`,
		q2GuardVersion, q2CustomVersion, q2SourceRevision, q2PatchDigest, q2TestArtifactDigest(), q2TestBinaryDigest())
}

func q2MergeQualifiedPolicy(t *testing.T, policy model.InsightsManagerPolicyManifestV1, profileDigest string) model.InsightsManagerPolicyManifestV1 {
	t.Helper()
	var merged model.InsightsManagerPolicyManifestV1
	if err := json.Unmarshal(q2MergedJSON(t, policy, q2QualifiedPolicyExtra(profileDigest)), &merged); err != nil {
		t.Fatal(err)
	}
	return merged
}

func q2MergeQualifiedCapability(t *testing.T, capability state.LocalManagerCapability) state.LocalManagerCapability {
	t.Helper()
	var merged state.LocalManagerCapability
	if err := json.Unmarshal(q2MergedJSON(t, capability, q2QualifiedCapabilityExtra()), &merged); err != nil {
		t.Fatal(err)
	}
	return merged
}

// TestQ2QualifiedWireRoundTripRetainsNegotiatedObjects is the named wire
// serialization assertion: a valid32 policy, capability and managed service must
// survive a JSON round trip with their qualified objects intact.
func TestQ2QualifiedWireRoundTripRetainsNegotiatedObjects(t *testing.T) {
	policyJSON := q2MergedJSON(t, model.InsightsManagerPolicyManifestV1{}, q2QualifiedPolicyExtra(q2ProfileDigest))
	var policy model.InsightsManagerPolicyManifestV1
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	capabilityJSON := q2MergedJSON(t, state.LocalManagerCapability{}, q2QualifiedCapabilityExtra())
	var capability state.LocalManagerCapability
	if err := json.Unmarshal(capabilityJSON, &capability); err != nil {
		t.Fatal(err)
	}
	serviceJSON := q2MergedJSON(t, model.ManagedServiceV1{FormatVersion: 1}, fmt.Sprintf(`{"runtimeContractVersion":%q,"image":{"digest":%q}}`, q2ContractVersion, q2TestImageDigest()))
	var service model.ManagedServiceV1
	if err := json.Unmarshal(serviceJSON, &service); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name  string
		value any
		key   string
	}{
		{"policy", policy, "autoSteerPolicy"},
		{"capability", capability, "nativeGuard"},
		{"managedService", service, "runtimeContractVersion"},
	} {
		payload, err := json.Marshal(item.value)
		if err != nil {
			t.Fatal(err)
		}
		var round map[string]any
		if err := json.Unmarshal(payload, &round); err != nil {
			t.Fatal(err)
		}
		if _, ok := round[item.key]; !ok {
			t.Fatalf("R189: %s JSON round trip lost %s; wire=%s", item.name, item.key, string(payload))
		}
	}
}

// TestQ2LegacyHelperCapabilityWireUnchangedAndNoNegotiationFields is the
// existing-shape control: the helper capability wire stays the exact legacy 17
// fields and the legacy policy manifest carries no negotiated extras.
func TestQ2LegacyHelperCapabilityWireUnchangedAndNoNegotiationFields(t *testing.T) {
	fixture, store, _, _, _, _, _ := q2LegacyJourney(t)
	capability, err := store.ManagerCapability(context.Background(), fixture.Review.Source.RegisteredSourceID)
	if err != nil || capability == nil {
		t.Fatalf("capability = %#v, %v", capability, err)
	}
	encoded, err := json.Marshal(managerCapabilityWire(*capability))
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire) != 17 {
		t.Fatalf("legacy helper capability wire changed width: %#v", wire)
	}
	for _, forbidden := range []string{"nativeGuard", "runtimeContractVersion", "autoSteerPolicy", "guidance"} {
		if _, ok := wire[forbidden]; ok {
			t.Fatalf("legacy helper capability wire must omit %s: %#v", forbidden, wire)
		}
	}
	policyEncoded, err := json.Marshal(fixture.Policy)
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := json.Unmarshal(policyEncoded, &policy); err != nil {
		t.Fatal(err)
	}
	if available, ok := policy["autoSteerAvailable"]; !ok || available != false {
		t.Fatalf("legacy autoSteerAvailable must stay present false: %#v", policy["autoSteerAvailable"])
	}
	if _, ok := policy["autoSteerPolicy"]; ok {
		t.Fatalf("legacy policy manifest must omit the negotiated autoSteerPolicy: %#v", policy)
	}
}

// q2RawGuidanceReceipt builds an SF-shaped raw receipt with fixed 3-digit
// millisecond timestamps and the helper digest over the raw closed map, before
// any Go time normalization.
func q2RawGuidanceReceipt(t *testing.T, action, sandboxID string, authority map[string]any, guidanceDigest, state string, now time.Time) []byte {
	t.Helper()
	reservationID, _ := authority["reservationId"].(string)
	runID, _ := authority["runId"].(string)
	observed := now.UTC().Truncate(time.Second).Add(30 * time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	admitted := now.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05.000Z")
	snapshot := map[string]any{
		"formatVersion": 1, "sandboxId": sandboxID, "reservationId": reservationID, "runId": runID,
		"revision": 1, "bindingDigest": q2BindingDigest(t, authority, reservationID, runID),
		"guidanceDigest": guidanceDigest, "guardId": opaqueID("guard_", runID), "pendingInputId": opaqueID("msg_", runID),
		"state": state, "refusalCode": nil, "logCursor": nil,
		"observedAt": observed, "admittedAt": admitted, "availableAt": nil, "settledAt": nil,
	}
	snapshot["receiptDigest"] = q2CanonicalDigest(t, snapshot)
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	receipt := map[string]any{"formatVersion": 1, "action": action, "reservationId": reservationID, "runId": runID, "guidance": json.RawMessage(snapshotJSON)}
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// TestQ2RawMillisecondReceiptCanonicalBeforeDecode proves the helper digest is
// validated over the original raw strings before decoding.
func TestQ2RawMillisecondReceiptCanonicalBeforeDecode(t *testing.T) {
	fixture, store, control, helper, coordinator, manifest, _, terminal, authority, admitted := q2QualifiedJourney(t)
	if !admitted {
		t.Fatalf("qualified origin not admitted: %#v", control.reports)
	}
	capability, err := store.ManagerCapability(context.Background(), terminal.Source.RegisteredSourceID)
	if err != nil || capability == nil {
		t.Fatalf("capability = %#v, %v", capability, err)
	}
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	helper.outputs = map[string][]byte{
		"dispatch_guidance": q2RawGuidanceReceipt(t, "dispatch_guidance", capability.SandboxID, authority, *terminal.Proposal.GuidanceDigest, "pending", now),
	}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatalf("R198-B1: raw millisecond receipt must validate before decode: %v", err)
	}
	run, err := store.ManagerRun(context.Background(), terminal.RunID)
	if err != nil || run == nil || run.Guidance == nil {
		t.Fatalf("published guidance = %#v, %v", run, err)
	}
	expected := now.UTC().Truncate(time.Second).Add(30 * time.Millisecond)
	if !run.Guidance.ObservedAt.Equal(expected) {
		t.Fatalf("R198-B1: observedAt lost the millisecond fraction: %s", run.Guidance.ObservedAt)
	}
	if run.Guidance.ReceiptDigest != canonicalGuidanceDigest(*run.Guidance) {
		t.Fatalf("R198-B1: Runtime publication digest must be canonical: %s", run.Guidance.ReceiptDigest)
	}
}

// q2AwaitingScenario drives the qualified unknown-guidance Off flow.
func q2AwaitingScenario(t *testing.T) (*Coordinator, *state.Store, *fakeManagerHelper, managerCoordinatorFixture, model.InsightsManagerPolicyManifestV1, map[string]any, model.InsightsManagerRunReportV1) {
	t.Helper()
	fixture, store, control, helper, coordinator, manifest, policy, terminal, authority, admitted := q2QualifiedJourney(t)
	if !admitted {
		t.Fatalf("qualified origin not admitted: %#v", control.reports)
	}
	capability, err := store.ManagerCapability(context.Background(), terminal.Source.RegisteredSourceID)
	if err != nil || capability == nil {
		t.Fatalf("capability = %#v, %v", capability, err)
	}
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	q2QualifiedPrereqs(t, helper, authority, terminal, capability.SandboxID, now)
	helper.loseActions = map[string]bool{"dispatch_guidance": true}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Logf("unknown qualified dispatch surfaced: %v", err)
	}
	off := policy
	off.PolicyRevision++
	off.RunGeneration++
	off.Mode = "off"
	off.AllowedRules = []string{}
	manifest.DesiredRevision++
	manifest.InsightsManagerPolicies = []model.InsightsManagerPolicyManifestV1{off}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	return coordinator, store, helper, fixture, off, authority, terminal
}

func q2FindPolicyReport(t *testing.T, reports []model.InsightsManagerPolicyReportV1, sandboxID string) model.InsightsManagerPolicyReportV1 {
	t.Helper()
	for _, report := range reports {
		if report.SandboxID == sandboxID {
			return report
		}
	}
	t.Fatalf("policy report for %s missing: %#v", sandboxID, reports)
	return model.InsightsManagerPolicyReportV1{}
}

// TestQ2ReportsAwaitingGuidanceAndHardwareCapability proves the closed
// awaiting_guidance status is derived in Reports and negotiated capability
// items carry real nativeGuard/plugin facts independent of desired Off.
func TestQ2ReportsAwaitingGuidanceAndHardwareCapability(t *testing.T) {
	coordinator, store, helper, fixture, off, authority, terminal := q2AwaitingScenario(t)
	capability, err := store.ManagerCapability(context.Background(), terminal.Source.RegisteredSourceID)
	if err != nil || capability == nil {
		t.Fatalf("capability = %#v, %v", capability, err)
	}
	reports, _, _, err := coordinator.Reports(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	report := q2FindPolicyReport(t, reports, off.SandboxID)
	if report.Status != "awaiting_guidance" {
		t.Fatalf("R198-B2: Reports must derive awaiting_guidance while unknown unsettled: %#v", report)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["status"] != "awaiting_guidance" {
		t.Fatalf("R198-B2: serialized status must be awaiting_guidance: %#v", wire["status"])
	}
	var negotiated *model.InsightsManagerRecommendCapabilityV1
	for index := range report.RecommendCapabilities {
		if report.RecommendCapabilities[index].NativeGuard != nil {
			negotiated = &report.RecommendCapabilities[index]
			break
		}
	}
	if negotiated == nil || negotiated.ManagerPluginDigest != capability.ManagerPluginDigest ||
		negotiated.NativeGuard.PatchDigest != capability.NativeGuard.PatchDigest ||
		negotiated.NativeGuard.BinarySHA256 != capability.NativeGuard.BinarySHA256 {
		t.Fatalf("R198-B3/B4: negotiated item must carry real nativeGuard/plugin facts: %#v", negotiated)
	}
	if !negotiated.Available || (negotiated.Reason != nil && *negotiated.Reason != "") {
		t.Fatalf("R198-B4: hardware capability must be available independent of desired Off/lease: %#v", negotiated)
	}
	if report.Recommend.Available || report.Recommend.Reason == nil || *report.Recommend.Reason != "policy_off" {
		t.Fatalf("R198-B4: policy rollup must remain mode fenced: %#v", report.Recommend)
	}
	now := fixture.AutomaticReservation.ExpiresAt.Add(-30 * time.Second)
	helper.outputs["observe_guidance"] = q2GuidanceReceipt(t, "observe_guidance", capability.SandboxID, authority, *terminal.Proposal.GuidanceDigest, "available_to_worker", now)
	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	settledReports, _, _, err := coordinator.Reports(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if settled := q2FindPolicyReport(t, settledReports, off.SandboxID); settled.Status != "applied" {
		t.Fatalf("R198-B2: settled guidance must derive applied: %#v", settled)
	}
}

// TestQ2WireExampleExport writes actual serialized Reports examples when
// Q2_WIRE_EXAMPLE is set.
func TestQ2WireExampleExport(t *testing.T) {
	path := os.Getenv("Q2_WIRE_EXAMPLE")
	if path == "" {
		t.Skip("Q2_WIRE_EXAMPLE not set")
	}
	coordinator, _, _, _, _, _, _ := q2AwaitingScenario(t)
	reports, _, _, err := coordinator.Reports(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	example := map[string]any{"formatVersion": 1, "reports": reports}
	payload, err := json.MarshalIndent(example, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
