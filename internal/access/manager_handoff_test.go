package access

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type managerGatewayFixture struct {
	ReservationRequest model.InsightsManagerReservationRequestV1 `json:"automaticReservationRequest"`
	Reservation        model.InsightsManagerReservationV1        `json:"automaticReservation"`
	Report             model.InsightsManagerRunReportV1          `json:"automaticReport"`
	Handoff            struct {
		Handoff model.SessionHandoffV1 `json:"handoff"`
	} `json:"managerSessionHandoff"`
}

func loadManagerGatewayFixture(t *testing.T) managerGatewayFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "manager", "testdata", "backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture managerGatewayFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func seedManagerGatewayAuthority(
	t *testing.T,
	fixture managerGatewayFixture,
	target model.SessionHandoffV1,
	processInstance string,
) (*state.Store, string, model.SessionHandoffV1) {
	t.Helper()
	return seedManagerGatewayAuthorityPhase(t, fixture, target, processInstance, "recommended")
}

func seedManagerGatewayAuthorityPhase(
	t *testing.T,
	fixture managerGatewayFixture,
	target model.SessionHandoffV1,
	processInstance string,
	phase string,
) (*state.Store, string, model.SessionHandoffV1) {
	t.Helper()
	review := model.InsightsManagerReviewManifestV1{
		FormatVersion: 1, ReservationID: fixture.Reservation.ReservationID, RunID: fixture.Reservation.RunID,
		Manual: false, FindingID: fixture.Reservation.FindingID, FindingRevision: fixture.Reservation.FindingRevision,
		PolicyRevision: fixture.Reservation.PolicyRevision, RuleID: fixture.ReservationRequest.RuleID,
		RecipeID: fixture.ReservationRequest.RecipeID, ProviderRouteDigest: fixture.Reservation.Execution.ProviderRouteDigest,
		ManagerProfile: fixture.Reservation.Execution.ManagerProfile, Source: fixture.Reservation.Source,
		Target: fixture.Reservation.Target, Budget: fixture.Reservation.ReservedBudget, ValidUntil: fixture.Reservation.ExpiresAt,
	}
	primary := target
	primary.Identity.Role = "worker"
	primary.Source.RegisteredSourceID = review.Source.RegisteredSourceID
	primary.Source.NativeSessionID = review.Source.NativeSessionID
	primary.Source.NativeProjectID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	primary.Source.NativeLocationDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	store, grantID := seedSessionHandoffAuthorityForProcessInstance(t, primary, processInstance)
	report := fixture.Report
	report.State = phase
	managerRun := state.LocalManagerRun{
		Manifest: review, Phase: phase, Report: &report,
		ManagerRegisteredSourceID: target.Source.RegisteredSourceID,
		ManagerSession: &model.InsightsManagerSessionV1{
			NativeSessionID: target.Source.NativeSessionID, NativeProjectID: target.Source.NativeProjectID,
			NativeLocationDigest:  target.Source.NativeLocationDigest,
			ServiceRegistrationID: target.Identity.ServiceRegistrationID,
			ServiceGeneration:     target.Identity.ServiceGeneration,
			ProviderRouteDigest:   review.ProviderRouteDigest,
			ManagerProfile:        review.ManagerProfile,
		},
	}
	if err := store.PutManagerRun(t.Context(), managerRun); err != nil {
		t.Fatal(err)
	}
	if err := store.PutManagerCapability(t.Context(), state.LocalManagerCapability{
		RegisteredSourceID: review.Source.RegisteredSourceID, ServiceRegistrationID: review.Source.ServiceRegistrationID,
		ServiceGeneration: review.Source.ServiceGeneration, WorkspaceEpoch: review.Source.WorkspaceEpoch,
		NativeSessionID: review.Source.NativeSessionID, SandboxID: target.Identity.SandboxID,
		SandboxGeneration: review.Source.SandboxGeneration, ProfileRevision: review.Source.ProfileRevision,
		InstructionRevision: review.Source.InstructionRevision, ProviderRouteDigest: review.ProviderRouteDigest,
		ManagerProfile: review.ManagerProfile, Available: true,
	}); err != nil {
		t.Fatal(err)
	}
	return store, grantID, primary
}

func TestGatewayRequiresExactManagerRunMappingRatherThanManagerRole(t *testing.T) {
	fixture := loadManagerGatewayFixture(t)
	target := fixture.Handoff.Handoff
	store, grantID, primary := seedManagerGatewayAuthority(t, fixture, target,
		model.ManagedServiceProcessInstance(target.Identity.Instance, target.Identity.ServiceGeneration))
	service, err := store.ManagedService(t.Context(), target.Identity.ServiceRegistrationID)
	if err != nil || service == nil {
		t.Fatalf("seeded manager service = %#v, %v", service, err)
	}
	if want := "wmsup-default-0003"; service.ProcessInstance != want {
		t.Fatalf("seeded process instance = %q, want %q", service.ProcessInstance, want)
	}
	bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
	gateway := &Gateway{
		Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
		SessionHandoffEngine: bridge,
		HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
	}
	frame := encodeGatewayHandoffHello(t, target)
	response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &target, SessionHandoffHello: frame,
	})
	_ = client.Close()
	if !response.OK {
		t.Fatalf("exact manager run handoff rejected: %+v", response)
	}
	select {
	case call := <-bridge.calls:
		if !bytes.Equal(call.Launch.HelloFrame, frame) || call.Launch.Grant.Instance != target.Identity.Instance {
			t.Fatalf("manager launch changed: %+v", call)
		}
	case <-time.After(time.Second):
		t.Fatal("manager run did not reach read-only fixed bridge")
	}

	roleOnly := target
	roleOnly.Source = primary.Source
	roleOnly.Identity.ProjectID = primary.Identity.ProjectID
	roleOnly.Identity.WorkspaceEpoch = primary.Identity.WorkspaceEpoch
	response, _, client = startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &roleOnly, SessionHandoffHello: encodeGatewayHandoffHello(t, roleOnly),
	})
	_ = client.Close()
	if response.OK || response.Error != "handoff_target_changed" {
		t.Fatalf("manager role without exact run mapping returned %+v", response)
	}
}

func TestGatewayRefusesManagerHandoffWithMismatchedProcessInstance(t *testing.T) {
	fixture := loadManagerGatewayFixture(t)
	target := fixture.Handoff.Handoff
	mutations := map[string]string{
		"wrong instance":   "wmsup-other-0003",
		"wrong generation": "wmsup-default-0002",
	}
	for name, processInstance := range mutations {
		t.Run(name, func(t *testing.T) {
			store, grantID, _ := seedManagerGatewayAuthority(t, fixture, target, processInstance)
			bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
			gateway := &Gateway{
				Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
				SessionHandoffEngine: bridge,
				HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
			}
			response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
				GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
				SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
			})
			_ = client.Close()
			if response.OK || response.Error != "handoff_target_changed" {
				t.Fatalf("mismatched manager process instance returned %+v", response)
			}
			select {
			case call := <-bridge.calls:
				t.Fatalf("mismatched manager process instance reached bridge: %+v", call)
			default:
			}
		})
	}
}

func TestGatewayRefusesManagerHandoffWithNonRecommendedRunPhase(t *testing.T) {
	fixture := loadManagerGatewayFixture(t)
	target := fixture.Handoff.Handoff
	store, grantID, _ := seedManagerGatewayAuthorityPhase(t, fixture, target,
		model.ManagedServiceProcessInstance(target.Identity.Instance, target.Identity.ServiceGeneration), "completed")
	bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
	gateway := &Gateway{
		Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
		SessionHandoffEngine: bridge,
		HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
	}
	response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
	})
	_ = client.Close()
	if response.OK || response.Error != "handoff_target_changed" {
		t.Fatalf("non-recommended manager run returned %+v", response)
	}
	select {
	case call := <-bridge.calls:
		t.Fatalf("non-recommended manager run reached bridge: %+v", call)
	default:
	}
}

// A manager run lookup that errors must fail closed; only the store's
// authoritative not-found result selects the ordinary path.
func TestGatewayFailsClosedWhenManagerRunLookupErrors(t *testing.T) {
	target := loadGatewayBackendHandoffFixture(t).Work.Handoff
	target.Identity.Role = "manager"
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, grantID := seedSessionHandoffAuthorityForProcessInstanceAtPath(t, path, target,
		model.ManagedServiceProcessInstance(target.Identity.Instance, target.Identity.ServiceGeneration))
	if _, err := store.ManagerRuns(t.Context()); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(t.Context(),
		`INSERT INTO manager_runs(run_id, manager_source_id, value_json, updated_at) VALUES(?,?,?,?)`,
		"run_corrupt033", target.Source.RegisteredSourceID, []byte("{"),
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	bridge := &handoffTestEngine{calls: make(chan handoffBridgeCall, 1)}
	gateway := &Gateway{
		Store: store, Engine: &gatewayTestEngine{calls: make(chan gatewayExecCall, 1)},
		SessionHandoffEngine: bridge,
		HostKeyFingerprint:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Now:                  func() time.Time { return target.IssuedAt.Add(30 * time.Second) },
	}
	response, _, client := startGatewayRequest(t, gateway, gatewayRequest{
		GrantID: grantID, Command: "warpmetal-team-control", TTY: true,
		SessionHandoff: &target, SessionHandoffHello: encodeGatewayHandoffHello(t, target),
	})
	_ = client.Close()
	if response.OK || response.Error != "handoff_not_ready" {
		t.Fatalf("manager run lookup error returned %+v, want handoff_not_ready", response)
	}
	select {
	case call := <-bridge.calls:
		t.Fatalf("manager run lookup error fell through to the ordinary path: %+v", call)
	default:
	}
}
