package continuity

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// continuityAcknowledgedPair builds the backend's in-place binding succession
// from the continuity fixture: the revoked/disabled predecessor and the active
// successor under the same binding ID, with an optional successor mutation.
func continuityAcknowledgedPair(fixture continuityFixture, mutate func(*model.ContinuityRegistrationV1)) (model.ContinuityRegistrationV1, model.ContinuityRegistrationV1) {
	predecessor := fixture.RegistrationManifest
	predecessor.DesiredState = "revoked"
	predecessor.ContinuityEnabled = false
	successor := fixture.RegistrationManifest
	successor.Binding.BindingRevision = 2
	if mutate != nil {
		mutate(&successor)
	}
	return predecessor, successor
}

// TestCoordinatorAcknowledgeKeepsTheVerifiedEffectiveSuccessorAcrossTheRelistedPair
// is the A46 acknowledgement-boundary proof. The fresh manifest re-lists the
// backend's pair: the revoked predecessor beside the active successor under one
// binding ID. Only the active successor is durable effective state, in either
// manifest order, and an already byte-for-field-equal verified successor is
// never re-evaluated against source freshness or service state: even after the
// stored source observation ages beyond the freshness contract, a re-apply
// preserves its authentic observed status, service generation, receipt and
// error fields byte-for-field.
func TestCoordinatorAcknowledgeKeepsTheVerifiedEffectiveSuccessorAcrossTheRelistedPair(t *testing.T) {
	ctx := context.Background()
	orders := []struct {
		name           string
		successorFirst bool
	}{
		{name: "backend_order"},
		{name: "reversed_order", successorFirst: true},
	}
	for _, order := range orders {
		t.Run(order.name, func(t *testing.T) {
			fixture := readContinuityFixture(t)
			helper := &fakeBoundaryHelper{}
			coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}, helper)
			if err := coordinator.Apply(ctx, manifest); err != nil {
				t.Fatal(err)
			}
			predecessor, successor := continuityAcknowledgedPair(fixture, nil)
			acknowledged := manifest
			acknowledged.ContinuityOperations = nil
			if order.successorFirst {
				acknowledged.ContinuityRegistrations = []model.ContinuityRegistrationV1{successor, predecessor}
			} else {
				acknowledged.ContinuityRegistrations = []model.ContinuityRegistrationV1{predecessor, successor}
			}
			if err := coordinator.Acknowledge(ctx, acknowledged); err != nil {
				t.Fatalf("effective succession was not acknowledged: %v", err)
			}
			first, err := store.ContinuityRegistration(ctx, fixture.RegistrationManifest.Binding.BindingID)
			if err != nil || first == nil || first.Manifest.Binding.BindingRevision != 2 ||
				first.Manifest.DesiredState != "active" || first.ObservedStatus != "verified" ||
				first.ReceiptDigest == "" || first.ServiceGeneration < 1 || first.ErrorCode != "" {
				t.Fatalf("effective successor outcome = %#v, %v", first, err)
			}
			// The stored source now ages past the freshness contract. A re-apply
			// that re-evaluated the equal successor would downgrade it; the
			// acknowledgement must preserve the authentic verified row.
			coordinator.Now = func() time.Time { return fixture.SourceReport.LastObservedAt.Add(10 * time.Minute) }
			if err := coordinator.Acknowledge(ctx, acknowledged); err != nil {
				t.Fatalf("repeated effective succession was not acknowledged: %v", err)
			}
			second, err := store.ContinuityRegistration(ctx, fixture.RegistrationManifest.Binding.BindingID)
			if err != nil || !reflect.DeepEqual(first, second) {
				t.Fatalf("stale re-apply changed the verified effective successor:\nfirst  %#v\nsecond %#v\n%v",
					first, second, err)
			}
		})
	}
}

// TestCoordinatorAcknowledgeRejectsUnsupportedDuplicateGroupsWithoutWrites is
// the A46 fail-closed half: only the exact pair admitted by the validated
// manifest semantics resolves; two active entries, two revoked entries, a
// revision jump, a reversed relation, an inconsistent fence or more than two
// entries abort the acknowledgement before any durable write.
func TestCoordinatorAcknowledgeRejectsUnsupportedDuplicateGroupsWithoutWrites(t *testing.T) {
	ctx := context.Background()
	fixture := readContinuityFixture(t)
	predecessor, successor := continuityAcknowledgedPair(fixture, nil)
	secondActive := successor
	secondActive.Binding.BindingRevision = 3
	secondActive.ScopeRevision = 3
	secondRevoked := predecessor
	secondRevoked.Binding.BindingRevision = 3
	revisionJump := successor
	revisionJump.Binding.BindingRevision = 3
	reversedPredecessor := predecessor
	reversedPredecessor.Binding.BindingRevision = 3
	foreignFence := successor
	foreignFence.Binding.NativeLocationDigest = "sha256:" + strings.Repeat("b", 64)
	thirdEntry := successor
	thirdEntry.Binding.BindingRevision = 3
	thirdEntry.ScopeRevision = 3
	cases := []struct {
		name          string
		registrations []model.ContinuityRegistrationV1
	}{
		{name: "two_active", registrations: []model.ContinuityRegistrationV1{successor, secondActive}},
		{name: "two_revoked", registrations: []model.ContinuityRegistrationV1{predecessor, secondRevoked}},
		{name: "revision_jump", registrations: []model.ContinuityRegistrationV1{predecessor, revisionJump}},
		{name: "reversed_relation", registrations: []model.ContinuityRegistrationV1{reversedPredecessor, successor}},
		{name: "inconsistent_fence", registrations: []model.ContinuityRegistrationV1{predecessor, foreignFence}},
		{name: "three_entries", registrations: []model.ContinuityRegistrationV1{predecessor, successor, thirdEntry}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			helper := &fakeBoundaryHelper{}
			coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}, helper)
			if err := coordinator.Apply(ctx, manifest); err != nil {
				t.Fatal(err)
			}
			before, err := store.ContinuityRegistrations(ctx)
			if err != nil {
				t.Fatal(err)
			}
			beforeReports, err := store.ContinuityOperationReports(ctx)
			if err != nil {
				t.Fatal(err)
			}
			acknowledged := manifest
			acknowledged.ContinuityOperations = nil
			acknowledged.ContinuityRegistrations = test.registrations
			err = coordinator.Acknowledge(ctx, acknowledged)
			if err == nil || !strings.Contains(err.Error(), "unsupported duplicate binding shape") {
				t.Fatalf("unsupported duplicate group did not fail closed: %v", err)
			}
			after, err := store.ContinuityRegistrations(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("unsupported duplicate group wrote registrations:\nbefore %#v\nafter  %#v", before, after)
			}
			afterReports, err := store.ContinuityOperationReports(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(beforeReports, afterReports) {
				t.Fatalf("unsupported duplicate group wrote operation reports:\nbefore %#v\nafter  %#v", beforeReports, afterReports)
			}
		})
	}
}
