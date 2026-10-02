package reconcile

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// TestReconcilerAppliesTheEffectiveSuccessorRegardlessOfManifestOrder is the
// A46 order-independence proof on the faithful real pair: the fresh manifest
// carries the active successor BEFORE the re-listed revoked predecessor, and
// the acknowledgement must still resolve only the effective successor. The
// ready handoff stays deferred and byte-identical, the durable successor stays
// byte-identical verified, A43 observes each active source exactly once, and
// the rebuilt report is accepted by the frozen backend v21.
func TestReconcilerAppliesTheEffectiveSuccessorRegardlessOfManifestOrder(t *testing.T) {
	ctx := context.Background()
	backend := loadFrozenBackendV21(t)
	journey, handoff := newHandoffSuccessionJourney(t)
	bindingID := journey.finish.registration.Binding.BindingID
	manifest := journey.manifest
	var successor model.ContinuityRegistrationV1
	haveSuccessor := false
	reordered := make([]model.ContinuityRegistrationV1, 0, len(manifest.ContinuityRegistrations))
	for _, registration := range manifest.ContinuityRegistrations {
		if registration.Binding.BindingID == bindingID && registration.DesiredState == "active" {
			successor = registration
			haveSuccessor = true
		}
	}
	if !haveSuccessor {
		t.Fatal("journey manifest has no active finish successor")
	}
	reordered = append(reordered, successor)
	for _, registration := range manifest.ContinuityRegistrations {
		if registration.Binding.BindingID == bindingID && registration.DesiredState == "active" {
			continue
		}
		reordered = append(reordered, registration)
	}
	manifest.ContinuityRegistrations = reordered
	beforeHandoff := journey.storedHandoff(t, handoff.manifest.OperationID)
	beforeFinish := journey.storedRegistrations(t)[bindingID]
	passErr := journey.reconciler.Reconcile(ctx, manifest)
	afterFinish := journey.storedRegistrations(t)[bindingID]
	t.Logf("reversed-order pass error: %v", passErr)
	t.Logf("reversed-order probes: %v finish registration: %s/%d/%q",
		journey.probeInstances, afterFinish.ObservedStatus, afterFinish.ServiceGeneration, afterFinish.ErrorCode)
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") ||
		!strings.Contains(passErr.Error(), "recover continuation handoffs:") {
		t.Fatalf("reversed-order pair was not deferred into the ordinary pass: %v", passErr)
	}
	if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b", "finish"}) {
		t.Fatalf("reversed-order probes = %v, want exactly the active ba1b and finish sources", journey.probeInstances)
	}
	if !reflect.DeepEqual(beforeFinish, afterFinish) || afterFinish.ObservedStatus != "verified" ||
		afterFinish.ServiceGeneration != 1 || afterFinish.ReceiptDigest == "" || afterFinish.ErrorCode != "" {
		t.Fatalf("reversed manifest order changed the verified successor:\nbefore %#v\nafter  %#v", beforeFinish, afterFinish)
	}
	if !reflect.DeepEqual(beforeHandoff, journey.storedHandoff(t, handoff.manifest.OperationID)) {
		t.Fatal("reversed manifest order changed the ready handoff record")
	}
	_, payload := journey.daemonReport(t, passErr)
	verdict, _ := backend.applyReport(
		t, payload, journey.backendV21Rows(t), journey.backendV21Sources(t),
		journey.now(), frozenBackendV21CurrentTokenHash,
	)
	if !verdict.Accepted {
		t.Fatalf("reversed-order report was rejected: HTTP %d %s: %s\n%s",
			verdict.Error.Status, verdict.Error.Code, verdict.Error.Message, payload)
	}
}
