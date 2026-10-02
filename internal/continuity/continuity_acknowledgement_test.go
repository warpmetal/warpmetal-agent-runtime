package continuity

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// TestCoordinatorAcknowledgeHandlesInPlaceBindingRevisionSuccession reproduces
// the backend's activate_binding shape: one binding row whose revision advanced
// to 2, carried in the same manifest as its revoked revision-1 predecessor. The
// superseded owner must still be visible to retirement (from the pre-apply
// durable snapshot and from the manifest's own tuple), the durable outcome must
// be the active successor, and the report must carry the successor, regardless
// of manifest entry order.
func TestCoordinatorAcknowledgeHandlesInPlaceBindingRevisionSuccession(t *testing.T) {
	ctx := context.Background()
	fixture := readContinuityFixture(t)
	predecessor := fixture.RegistrationManifest
	predecessor.DesiredState = "revoked"
	successor := fixture.RegistrationManifest
	successor.Binding.BindingRevision = 2
	orders := []struct {
		name          string
		registrations []model.ContinuityRegistrationV1
	}{
		{name: "backend_order", registrations: []model.ContinuityRegistrationV1{predecessor, successor}},
		{name: "reversed_order", registrations: []model.ContinuityRegistrationV1{successor, predecessor}},
	}
	for _, order := range orders {
		t.Run(order.name, func(t *testing.T) {
			helper := &fakeBoundaryHelper{}
			coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}, helper)
			if err := coordinator.Apply(ctx, manifest); err != nil {
				t.Fatal(err)
			}
			accepted := fixture.OperationManifest
			acknowledged := manifest
			acknowledged.ContinuityRegistrations = order.registrations
			acknowledged.ContinuityOperations = nil
			if err := coordinator.Acknowledge(ctx, acknowledged); err != nil {
				t.Fatalf("in-place binding revision succession was not acknowledged: %v", err)
			}
			pending, err := store.ContinuityOperationReports(ctx)
			if err != nil || len(pending) != 0 {
				t.Fatalf("predecessor echo not retired: %#v %v", pending, err)
			}
			retirements, err := store.ContinuityOperationRetirements(ctx)
			if err != nil || len(retirements) != 1 || retirements[0].Report.OperationID != accepted.OperationID {
				t.Fatalf("predecessor retirement = %#v %v", retirements, err)
			}
			stored, err := store.ContinuityRegistration(ctx, fixture.RegistrationManifest.Binding.BindingID)
			if err != nil || stored == nil || stored.Manifest.Binding.BindingRevision != 2 ||
				stored.Manifest.DesiredState != "active" || stored.ObservedStatus != "verified" {
				t.Fatalf("durable successor outcome = %#v %v", stored, err)
			}
			_, registrations, operations, err := coordinator.Reports(ctx)
			if err != nil || len(registrations) != 1 || registrations[0].Binding.BindingRevision != 2 ||
				registrations[0].ObservedStatus != "verified" || len(operations) != 0 {
				t.Fatalf("successor report shape = %#v %#v %v", registrations, operations, err)
			}
			if len(helper.actions) != 2 {
				t.Fatalf("acknowledgement executed helper actions: %v", helper.actions)
			}
		})
	}
}

// TestCoordinatorKeepsRetiredOperationReplaysFailClosed proves the retirement
// tombstone is a production fence: a later manifest that re-carries a retired
// operation ID fails closed before any helper, barrier or capture work instead
// of re-executing the acknowledged operation.
func TestCoordinatorKeepsRetiredOperationReplaysFailClosed(t *testing.T) {
	ctx := context.Background()
	fixture := readContinuityFixture(t)
	helper := &fakeBoundaryHelper{}
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}, helper)
	if err := coordinator.Apply(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	actions := len(helper.actions)
	acknowledged := manifest
	acknowledged.ContinuityOperations = nil
	if err := coordinator.Acknowledge(ctx, acknowledged); err != nil {
		t.Fatal(err)
	}
	if retirements, err := store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != 1 {
		t.Fatalf("retirement before replay = %#v %v", retirements, err)
	}
	if err := coordinator.Apply(ctx, manifest); err == nil || !strings.Contains(err.Error(), "already acknowledged and retired") {
		t.Fatalf("retired operation replay was not fail-closed: %v", err)
	}
	if len(helper.actions) != actions {
		t.Fatalf("retired operation replay executed helper actions: %v", helper.actions)
	}
	if pending, err := store.ContinuityOperationReports(ctx); err != nil || len(pending) != 0 {
		t.Fatalf("retired operation replay rewrote the outbox: %#v %v", pending, err)
	}
	if barriers, err := store.ContinuityBarriers(ctx); err != nil || len(barriers) != 0 {
		t.Fatalf("retired operation replay acquired a barrier: %#v %v", barriers, err)
	}
}

// TestCoordinatorAcknowledgeRetiresAuthenticTerminalEchoes proves the
// pre-failure acknowledgement phase against rows produced by the ordinary
// operation path itself: an accepted report from a real boundary+capture+
// checkpoint cycle, and failed/outcome_unknown reports from the ordinary
// terminal writers. The phase must retire exactly the terminal rows the fresh
// manifest no longer carries, preserve their receipts byte-for-byte as local
// tombstones, and leave every present, live or foreign row untouched.
func TestCoordinatorAcknowledgeRetiresAuthenticTerminalEchoes(t *testing.T) {
	ctx := context.Background()
	fixture := readContinuityFixture(t)
	helper := &fakeBoundaryHelper{}
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}, helper)

	// The accepted row arrives through the real coordinator operation path.
	if err := coordinator.Apply(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	accepted := fixture.OperationManifest

	failed := accepted
	failed.OperationID = "op_acknowledge_failed0001"
	if err := coordinator.failOperation(ctx, failed, "capture_failed"); err != nil {
		t.Fatal(err)
	}
	unknown := accepted
	unknown.OperationID = "op_acknowledge_unknown0001"
	if err := coordinator.unknownOperation(ctx, unknown, "boundary_outcome_unknown"); err != nil {
		t.Fatal(err)
	}
	authentic := map[string]model.ContinuityOperationReportV1{}
	storedAuthentic, err := store.ContinuityOperationReports(ctx)
	if err != nil || len(storedAuthentic) != 3 {
		t.Fatalf("authentic terminal rows = %#v %v", storedAuthentic, err)
	}
	for _, report := range storedAuthentic {
		authentic[report.OperationID] = report
	}

	// A present operation is never acknowledged by omission, even though it is
	// terminal. All three authentic IDs are present in this fresh manifest.
	withOperations := manifest
	withOperations.ContinuityOperations = []model.ContinuityOperationV1{accepted, failed, unknown}
	if err := coordinator.Acknowledge(ctx, withOperations); err != nil {
		t.Fatal(err)
	}
	reports, err := store.ContinuityOperationReports(ctx)
	if err != nil || len(reports) != 3 {
		t.Fatalf("present terminal echoes retired: %#v %v", reports, err)
	}

	// A live barrier also keeps the row fail-closed.
	barrier := accepted
	barrier.OperationID = "op_acknowledge_barrier001"
	if err := coordinator.failOperation(ctx, barrier, "capture_failed"); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuityBarrier(ctx, barrier.OperationID, []byte(`{"owner":"capture"}`), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// A foreign binding is structurally exact but owned by no local
	// registration and stays untouched.
	foreign := accepted
	foreign.OperationID = "op_acknowledge_foreign001"
	foreign.Binding.BindingID = "binding_foreign_ack0001"
	foreign.Binding.RegisteredSourceID = "source_foreign_ack0001"
	if err := coordinator.failOperation(ctx, foreign, "capture_failed"); err != nil {
		t.Fatal(err)
	}
	// A nonterminal row is never inferred from absence.
	applying := accepted
	applying.OperationID = "op_acknowledge_applying01"
	if err := store.PutContinuityOperationReport(ctx, model.ContinuityOperationReportV1{
		FormatVersion: 1, OperationID: applying.OperationID, Action: "capture_checkpoint",
		ScopeRevision: applying.ScopeRevision, BoundaryKind: applying.BoundaryKind,
		Identity: applying.Identity, Binding: applying.Binding, RequestDigest: applying.RequestDigest,
		Status: "applying",
	}); err != nil {
		t.Fatal(err)
	}

	acknowledged := manifest
	acknowledged.ContinuityOperations = nil
	if err := coordinator.Acknowledge(ctx, acknowledged); err != nil {
		t.Fatal(err)
	}
	pending, err := store.ContinuityOperationReports(ctx)
	if err != nil || len(pending) != 3 {
		t.Fatalf("fail-closed echoes changed: %#v %v", pending, err)
	}
	present := map[string]bool{}
	for _, report := range pending {
		present[report.OperationID] = true
	}
	for _, retained := range []string{barrier.OperationID, foreign.OperationID, applying.OperationID} {
		if !present[retained] {
			t.Fatalf("fail-closed echo %s was retired", retained)
		}
	}
	retirements, err := store.ContinuityOperationRetirements(ctx)
	if err != nil || len(retirements) != 3 {
		t.Fatalf("authentic terminal retirements = %#v %v", retirements, err)
	}
	retired := map[string]model.ContinuityOperationReportV1{}
	for _, retirement := range retirements {
		if retirement.Reason != "manifest_absent_terminal_acknowledged" {
			t.Fatalf("retirement reason = %#v", retirement)
		}
		retired[retirement.Report.OperationID] = retirement.Report
	}
	for operationID, want := range authentic {
		retirement, ok := retired[operationID]
		if !ok {
			t.Fatalf("authentic echo %s was not retired", operationID)
		}
		if !reflect.DeepEqual(retirement, want) {
			t.Fatalf("retired receipt drifted:\n got %#v\nwant %#v", retirement, want)
		}
	}
	_, registrations, operations, err := coordinator.Reports(ctx)
	if err != nil || len(registrations) != 1 || registrations[0].ObservedStatus != "verified" || len(operations) != 3 {
		t.Fatalf("reports after acknowledgement = %#v %#v %v", registrations, operations, err)
	}

	// Registration adoption is part of the same pre-failure phase: an explicit
	// revocation in the same fresh manifest is applied without running any
	// operation.
	revoked := acknowledged
	revoked.ContinuityRegistrations = append([]model.ContinuityRegistrationV1(nil), acknowledged.ContinuityRegistrations...)
	revoked.ContinuityRegistrations[0].DesiredState = "revoked"
	revoked.ContinuityRegistrations[0].ContinuityEnabled = false
	if err := coordinator.Acknowledge(ctx, revoked); err != nil {
		t.Fatal(err)
	}
	stored, err := store.ContinuityRegistration(ctx, fixture.RegistrationManifest.Binding.BindingID)
	if err != nil || stored == nil || stored.ObservedStatus != "revoked" || stored.Manifest.DesiredState != "revoked" {
		t.Fatalf("revoked registration = %#v %v", stored, err)
	}
	if len(helper.actions) != 2 {
		t.Fatalf("acknowledgement executed helper actions: %v", helper.actions)
	}
}
