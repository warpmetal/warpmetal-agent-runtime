package reconcile

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// backendV21RowsWithMappedTarget adds the exact active mapped handoff-target
// registration (owned by the ready preparation) to the frozen backend v21
// registration rows.
func backendV21RowsWithMappedTarget(t *testing.T, journey *acknowledgementJourney) map[string]frozenBackendV21RegistrationRow {
	t.Helper()
	rows := journey.backendV21Rows(t)
	var mapped model.ContinuityRegistrationV1
	for _, registration := range journey.manifest.ContinuityRegistrations {
		if registration.Binding.BindingID == successionHandoffMappedBinding {
			mapped = registration
		}
	}
	if mapped.Binding.BindingID == "" {
		t.Fatal("journey manifest carries no mapped handoff-target registration")
	}
	identity, binding := registrationWireMaps(t, mapped)
	rows[frozenRowKey(mapped.Binding.BindingID, 1)] = frozenBackendV21RegistrationRow{
		State: "pending", DesiredState: "active", ContinuityEnabled: true,
		ScopeRevision: float64(mapped.ScopeRevision), ServiceGeneration: 1,
		ReceiptDigest: "", ErrorCode: "", Current: true, Availability: "available",
		Identity: identity, Binding: binding,
	}
	return rows
}

// TestReconcilerKeepsHandoffTargetObservationFailClosed is the A49 mutation-blind
// negative matrix for the target-side observation: a refused, failed, malformed
// or changed reconcile_handoff response, and every changed session/project/
// location/baseline/workspace/policy/instruction/generation tuple, must fail
// the pass closed with the mapped row byte-unchanged, A43 never reached, the
// ready handoff history byte-identical, no allocation/materialization/admission,
// and no leaked session or location value.
func TestReconcilerKeepsHandoffTargetObservationFailClosed(t *testing.T) {
	ctx := context.Background()
	mutateSession := func(report *model.ContinuationHandoffReportV1) {
		report.Session.NativeSessionID = "ses_foreignmapped0001"
		report.Baseline.NativeSessionID = "ses_foreignmapped0001"
	}
	mutateProject := func(report *model.ContinuationHandoffReportV1) {
		report.Session.NativeProjectID = strings.Repeat("e", 40)
	}
	mutateLocation := func(report *model.ContinuationHandoffReportV1) {
		report.Session.NativeLocationDigest = "sha256:" + strings.Repeat("e", 64)
	}
	mutateBaseline := func(report *model.ContinuationHandoffReportV1) {
		report.Baseline.NativeSessionID = "ses_foreignbaseline0001"
	}
	mutateGeneration := func(report *model.ContinuationHandoffReportV1) {
		report.Baseline.ServiceGeneration = report.TargetPolicy.ServiceGeneration + 1
	}
	mutateWorkspace := func(report *model.ContinuationHandoffReportV1) {
		workspace := *report.TargetWorkspace
		workspace.ProjectID = "project_foreignworkspace0001"
		report.TargetWorkspace = &workspace
	}
	mutatePolicy := func(report *model.ContinuationHandoffReportV1) {
		report.TargetPolicy.Role = "foreign_role"
	}
	mutateInstructions := func(report *model.ContinuationHandoffReportV1) {
		report.Session.InstructionApplied = false
	}
	cases := []struct {
		name      string
		deferred  bool
		configure func(t *testing.T, journey *acknowledgementJourney, handoff *successionHandoffFixture)
		leak      string
	}{
		{name: "helper_refused", leak: "ses_foreignmapped0001", configure: func(t *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			handoff.setHelperRefusal(t, "handoff_target_refused")
		}},
		{name: "helper_transport_error", deferred: true, configure: func(_ *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			handoff.helper.failure = errors.New("supervisor transport failed")
		}},
		{name: "helper_malformed_response", configure: func(_ *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			handoff.helper.envelope = []byte(`{"formatVersion":1,"action":"reconcile_handoff"`)
		}},
		{name: "changed_session", leak: "ses_foreignmapped0001", configure: func(t *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			report := handoff.readyReport
			mutateSession(&report)
			handoff.setHelperReport(t, report)
		}},
		{name: "changed_project", leak: strings.Repeat("e", 40), configure: func(t *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			report := handoff.readyReport
			mutateProject(&report)
			handoff.setHelperReport(t, report)
		}},
		{name: "changed_location", leak: strings.Repeat("e", 64), configure: func(t *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			report := handoff.readyReport
			mutateLocation(&report)
			handoff.setHelperReport(t, report)
		}},
		{name: "changed_baseline", leak: "ses_foreignbaseline0001", configure: func(t *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			report := handoff.readyReport
			mutateBaseline(&report)
			handoff.setHelperReport(t, report)
		}},
		{name: "changed_service_generation", configure: func(t *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			report := handoff.readyReport
			mutateGeneration(&report)
			handoff.setHelperReport(t, report)
		}},
		{name: "changed_workspace", leak: "project_foreignworkspace0001", configure: func(t *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			report := handoff.readyReport
			mutateWorkspace(&report)
			handoff.setHelperReport(t, report)
		}},
		{name: "changed_policy", leak: "foreign_role", configure: func(t *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			report := handoff.readyReport
			mutatePolicy(&report)
			handoff.setHelperReport(t, report)
		}},
		{name: "changed_instructions", configure: func(t *testing.T, _ *acknowledgementJourney, handoff *successionHandoffFixture) {
			report := handoff.readyReport
			mutateInstructions(&report)
			handoff.setHelperReport(t, report)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			journey, handoff := newHandoffSuccessionJourney(t, withMappedTargetRegistration())
			operationID := handoff.manifest.OperationID
			test.configure(t, journey, handoff)
			beforeMapped := journey.storedSource(t, successionHandoffMappedSource)
			beforePrimary := journey.storedSource(t, successionHandoffPrimarySource)
			beforeHandoff := journey.storedHandoff(t, operationID)
			beforePreparations := journey.handoffPreparations(t)
			beforeMappedRegistration := journey.storedRegistrations(t)[successionHandoffMappedBinding]
			passErr := journey.reconciler.Reconcile(ctx, journey.manifest)
			t.Logf("target-side failure %s pass error: %v", test.name, passErr)
			if test.deferred {
				// The existing classified transport probe deferral: the mapped
				// row is still never written and the pass continues, while the
				// probe error stays visible alongside the ordinary failure.
				if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") ||
					!strings.Contains(passErr.Error(), "recover continuation handoffs:") {
					t.Fatalf("classified transport deferral did not continue the ordinary pass: %v", passErr)
				}
				if !reflect.DeepEqual(beforeMapped, journey.storedSource(t, successionHandoffMappedSource)) {
					t.Fatal("classified transport deferral wrote the mapped source row")
				}
				if !reflect.DeepEqual(beforeHandoff, journey.storedHandoff(t, operationID)) ||
					!reflect.DeepEqual(beforePreparations, journey.handoffPreparations(t)) {
					t.Fatal("classified transport deferral changed the ready handoff history")
				}
				if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b", "finish"}) {
					t.Fatalf("classified transport deferral did not leave A43 to the ordinary sources: %v", journey.probeInstances)
				}
				if applied := journey.appliedRevision(t); applied != 64 {
					t.Fatalf("classified transport deferral advanced the applied revision to %d", applied)
				}
				handoff.assertUntouched(t)
				return
			}
			if passErr == nil || !strings.Contains(passErr.Error(), "recover continuation handoffs:") {
				t.Fatalf("target-side failure did not fail the handoff recovery: %v", passErr)
			}
			if strings.Contains(passErr.Error(), "apply managed services:") {
				t.Fatalf("target-side failure was deferred into the ordinary pass: %v", passErr)
			}
			if test.leak != "" && strings.Contains(passErr.Error(), test.leak) {
				t.Fatalf("target-side failure leaked the changed value for %s", test.name)
			}
			if !reflect.DeepEqual(beforeMapped, journey.storedSource(t, successionHandoffMappedSource)) {
				t.Fatal("target-side failure wrote the mapped source row")
			}
			if !reflect.DeepEqual(observedSourceIdentityOf(beforePrimary), observedSourceIdentityOf(journey.storedSource(t, successionHandoffPrimarySource))) {
				t.Fatal("target-side failure changed the primary source identity")
			}
			if len(journey.probeInstances) != 0 {
				t.Fatalf("A43 ran after a target-side failure: %v", journey.probeInstances)
			}
			if !reflect.DeepEqual(beforeHandoff, journey.storedHandoff(t, operationID)) ||
				!reflect.DeepEqual(beforePreparations, journey.handoffPreparations(t)) {
				t.Fatal("target-side failure changed the ready handoff history")
			}
			if !reflect.DeepEqual(beforeMappedRegistration, journey.storedRegistrations(t)[successionHandoffMappedBinding]) {
				t.Fatal("target-side failure changed the owned mapped registration")
			}
			if applied := journey.appliedRevision(t); applied != 64 {
				t.Fatalf("target-side failure advanced the applied revision to %d", applied)
			}
			handoff.assertUntouched(t)
		})
	}
}

// TestReconcilerKeepsAmbiguousHandoffOwnershipFatal proves A43 fails closed when
// an active registration's source names a completed ready preparation but the
// ownership fence is contradictory: the phase must neither probe the source
// generically nor skip it into later sources, and no source/registration/
// handoff/revision state may move beyond the genuine target-side observation.
func TestReconcilerKeepsAmbiguousHandoffOwnershipFatal(t *testing.T) {
	ctx := context.Background()
	journey, handoff := newHandoffSuccessionJourney(t, withMappedTargetRegistration())
	operationID := handoff.manifest.OperationID
	source := journey.storedSource(t, successionHandoffMappedSource)
	source.Report.ProjectID = "project_foreignownership0001"
	if err := journey.store.PutContinuitySource(ctx, source); err != nil {
		t.Fatal(err)
	}
	beforeSources := journey.storedSources(t)
	beforeHandoff := journey.storedHandoff(t, operationID)
	beforePreparations := journey.handoffPreparations(t)
	beforeMappedRegistration := journey.storedRegistrations(t)[successionHandoffMappedBinding]
	passErr := journey.reconciler.Reconcile(ctx, journey.manifest)
	t.Logf("ambiguous ownership pass error: %v", passErr)
	if passErr == nil || !strings.Contains(passErr.Error(), "observe continuity sources:") {
		t.Fatalf("ambiguous handoff ownership did not fail the observation phase: %v", passErr)
	}
	if len(journey.probeInstances) != 0 {
		t.Fatalf("ambiguous ownership was probed or skipped into later sources: %v", journey.probeInstances)
	}
	for id, before := range beforeSources {
		after, ok := journey.storedSources(t)[id]
		if !ok || !reflect.DeepEqual(observedSourceIdentityOf(before), observedSourceIdentityOf(after)) {
			t.Fatalf("ambiguous ownership changed the source identity for %s", id)
		}
	}
	if !reflect.DeepEqual(beforeHandoff, journey.storedHandoff(t, operationID)) ||
		!reflect.DeepEqual(beforePreparations, journey.handoffPreparations(t)) {
		t.Fatal("ambiguous ownership changed the ready handoff history")
	}
	if !reflect.DeepEqual(beforeMappedRegistration, journey.storedRegistrations(t)[successionHandoffMappedBinding]) {
		t.Fatal("ambiguous ownership changed the owned mapped registration")
	}
	if applied := journey.appliedRevision(t); applied != 64 {
		t.Fatalf("ambiguous ownership advanced the applied revision to %d", applied)
	}
}

// TestReconcilerObservesHandoffTargetSessionsThroughTheirOwnBoundaries is the
// A49 RED/GREEN journey on the complete captured-live shape. RED (.56): the
// exact handoff-source succession defers before target re-observation, A43 then
// selects the mapped handoff-target registration first after ba1b, sends the
// generic target-service primary status probe for the mapped source, fails
// session_mismatch before the ordinary finish observation, leaves the
// mapped/finish rows stale and the frozen backend refuses 409 with the handoff
// byte-identical. GREEN: the succession deferral still re-observes the target
// side of the same ready preparation exactly once through its correct
// boundaries (target service primary status receipt, then the distinct mapped
// session's idempotent reconcile_handoff); A43 excludes the exactly owned
// mapped source and still probes ba1b and finish once each; every source
// identity is unchanged; the frozen backend accepts the rebuilt report; the
// ready handoff, baseline, history, registration receipts, six terminal rows
// and checkpoint stay byte-identical; and the next ordinary lifecycle with a
// genuine fresh selection reaches manager ready and applied==desired 67 with no
// bypass.
func TestReconcilerObservesHandoffTargetSessionsThroughTheirOwnBoundaries(t *testing.T) {
	ctx := context.Background()
	backend := loadFrozenBackendV21(t)
	journey, handoff := newHandoffSuccessionJourney(t, withMappedTargetRegistration())
	operationID := handoff.manifest.OperationID
	finishSourceID := journey.finish.registration.Binding.RegisteredSourceID
	ba1bSourceID := journey.ba1b.registration.Binding.RegisteredSourceID
	beforeHandoff := journey.storedHandoff(t, operationID)
	beforePreparations := journey.handoffPreparations(t)
	beforeMapped := journey.storedSource(t, successionHandoffMappedSource)
	beforePrimary := journey.storedSource(t, successionHandoffPrimarySource)
	beforeMappedRegistration := journey.storedRegistrations(t)[successionHandoffMappedBinding]

	passErr := journey.reconciler.Reconcile(ctx, journey.manifest)
	t.Logf("ordinary pass error: %v", passErr)
	t.Logf("source probe instances this pass: %v", journey.probeInstances)
	t.Logf("handoff supervisor calls: %d helper calls: %d reconciles: %d objects: %d catalog: %d admission: %d",
		handoff.supervisor.calls, handoff.helper.calls, handoff.helper.reconciles,
		handoff.objects.calls, handoff.catalog.calls, handoff.admission.calls)
	t.Logf("mapped source: availability=%s reason=%v lastObservedAt=%s",
		journey.storedSource(t, successionHandoffMappedSource).Report.Availability,
		stringValue(journey.storedSource(t, successionHandoffMappedSource).Report.Reason),
		journey.storedSource(t, successionHandoffMappedSource).Report.LastObservedAt)
	t.Logf("primary source: availability=%s lastObservedAt=%s",
		journey.storedSource(t, successionHandoffPrimarySource).Report.Availability,
		journey.storedSource(t, successionHandoffPrimarySource).Report.LastObservedAt)
	if _, payload := journey.daemonReport(t, passErr); payload != nil {
		verdict, _ := backend.applyReport(
			t, payload, backendV21RowsWithMappedTarget(t, journey), journey.backendV21Sources(t),
			journey.now(), frozenBackendV21CurrentTokenHash,
		)
		if verdict.Accepted {
			t.Logf("frozen backend verdict on this pass: accepted=true")
		} else {
			t.Logf("frozen backend verdict on this pass: accepted=false HTTP=%d code=%s message=%s",
				verdict.Error.Status, verdict.Error.Code, verdict.Error.Message)
		}
	}

	// GREEN: the pass still defers the ready handoff and fails the ordinary
	// managed-service enrollment, while the target side of the SAME preparation
	// is observed exactly once through each correct boundary.
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") ||
		!strings.Contains(passErr.Error(), "recover continuation handoffs:") {
		t.Fatalf("handoff-target succession did not continue into the ordinary pass: %v", passErr)
	}
	handoff.assertTargetObservedOnce(t)
	if !reflect.DeepEqual(beforeHandoff, journey.storedHandoff(t, operationID)) ||
		!reflect.DeepEqual(beforePreparations, journey.handoffPreparations(t)) {
		t.Fatal("ready handoff record or history changed across the deferral")
	}
	// A43 excludes the exactly owned mapped source and still observes ba1b and
	// finish once each; the mapped source is never probed by the generic
	// managed-service status surface.
	if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b", "finish"}) {
		t.Fatalf("A43 probes = %v, want exactly the ordinary ba1b and finish sources", journey.probeInstances)
	}
	mappedAfter := journey.storedSource(t, successionHandoffMappedSource)
	primaryAfter := journey.storedSource(t, successionHandoffPrimarySource)
	if mappedAfter.Report.Availability != "available" || mappedAfter.Report.Reason != nil ||
		!mappedAfter.Report.LastObservedAt.Equal(journey.now()) {
		t.Fatalf("mapped session was not observed through reconcile_handoff: %#v", mappedAfter.Report)
	}
	if primaryAfter.Report.Availability != "available" || primaryAfter.Report.Reason != nil ||
		!primaryAfter.Report.LastObservedAt.Equal(journey.now()) {
		t.Fatalf("target service primary session was not observed through its status surface: %#v", primaryAfter.Report)
	}
	if !reflect.DeepEqual(observedSourceIdentityOf(mappedAfter), observedSourceIdentityOf(beforeMapped)) ||
		!reflect.DeepEqual(observedSourceIdentityOf(primaryAfter), observedSourceIdentityOf(beforePrimary)) {
		t.Fatalf("mapped/primary source identity drifted:\nmapped got %#v want %#v\nprimary got %#v want %#v",
			observedSourceIdentityOf(mappedAfter), observedSourceIdentityOf(beforeMapped),
			observedSourceIdentityOf(primaryAfter), observedSourceIdentityOf(beforePrimary))
	}
	if !reflect.DeepEqual(beforeMappedRegistration, journey.storedRegistrations(t)[successionHandoffMappedBinding]) {
		t.Fatal("the owned mapped registration row changed across the pass")
	}
	service := journey.storedService(t, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if service == nil || service.Phase != "failed" || service.ErrorCode != "enrollment_unavailable" {
		t.Fatalf("manager failure was not preserved: %#v", service)
	}
	if applied := journey.appliedRevision(t); applied != 64 {
		t.Fatalf("applied revision = %d, want the unchanged 64", applied)
	}
	report, payload := journey.daemonReport(t, passErr)
	if report.LastError == nil || report.LastError.Code != "reconcile_failed" ||
		!strings.Contains(report.LastError.Message, "stale") ||
		!strings.Contains(report.LastError.Message, "handoff source registration") {
		t.Fatalf("deferred succession and stale-selection failure are not both visible: %#v", report.LastError)
	}
	if _, repeated := journey.daemonReport(t, passErr); !bytes.Equal(payload, repeated) {
		t.Fatal("report is not rebuilt deterministically from the durable rows")
	}
	verdict, sourcesAfter := backend.applyReport(
		t, payload, backendV21RowsWithMappedTarget(t, journey), journey.backendV21Sources(t),
		journey.now(), frozenBackendV21CurrentTokenHash,
	)
	if !verdict.Accepted {
		t.Fatalf("handoff-target report was rejected by frozen backend v21: HTTP %d %s: %s\n%s",
			verdict.Error.Status, verdict.Error.Code, verdict.Error.Message, payload)
	}
	if row := sourcesAfter[frozenSourceKey(mappedAfter.Report.SandboxID, successionHandoffMappedSource)]; row.NodeTokenHash != frozenBackendV21CurrentTokenHash ||
		!row.LastObservedAt.Equal(journey.now()) {
		t.Fatalf("accepted report did not carry the current mapped-source token/freshness: %#v", row)
	}

	// A repeated pass repeats the deferral and the two observations exactly,
	// with the mapped source excluded again and every registration byte-stable.
	settledHandoff := journey.storedHandoff(t, operationID)
	settledMapped := journey.storedSource(t, successionHandoffMappedSource)
	settledPrimary := journey.storedSource(t, successionHandoffPrimarySource)
	settledFinish := journey.storedSource(t, finishSourceID)
	settledBa1b := journey.storedSource(t, ba1bSourceID)
	probesBefore := len(journey.probeInstances)
	handoff.reset()
	passErr = journey.reconciler.Reconcile(ctx, journey.manifest)
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") {
		t.Fatalf("second handoff-target pass did not preserve the failure: %v", passErr)
	}
	handoff.assertTargetObservedOnce(t)
	if !reflect.DeepEqual(journey.probeInstances[probesBefore:], []string{"ba1b", "finish"}) {
		t.Fatalf("second handoff-target probes = %v", journey.probeInstances[probesBefore:])
	}
	if !reflect.DeepEqual(settledHandoff, journey.storedHandoff(t, operationID)) ||
		!reflect.DeepEqual(settledMapped, journey.storedSource(t, successionHandoffMappedSource)) ||
		!reflect.DeepEqual(settledPrimary, journey.storedSource(t, successionHandoffPrimarySource)) ||
		!reflect.DeepEqual(settledFinish, journey.storedSource(t, finishSourceID)) ||
		!reflect.DeepEqual(settledBa1b, journey.storedSource(t, ba1bSourceID)) {
		t.Fatal("second handoff-target pass changed a settled row")
	}

	// Reopen/restart: the same deterministic deferral, the same two target-side
	// observations and an accepted report.
	journey.restart(t)
	handoff.rebind(journey)
	journey.handoff = handoff.controller
	journey.reconciler = journey.newReconciler()
	handoff.reset()
	probesBefore = len(journey.probeInstances)
	passErr = journey.reconciler.Reconcile(ctx, journey.manifest)
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") {
		t.Fatalf("restarted handoff-target pass did not preserve the failure: %v", passErr)
	}
	handoff.assertTargetObservedOnce(t)
	if !reflect.DeepEqual(journey.probeInstances[probesBefore:], []string{"ba1b", "finish"}) {
		t.Fatalf("restarted handoff-target probes = %v", journey.probeInstances[probesBefore:])
	}
	if !reflect.DeepEqual(settledHandoff, journey.storedHandoff(t, operationID)) ||
		!reflect.DeepEqual(settledMapped, journey.storedSource(t, successionHandoffMappedSource)) ||
		!reflect.DeepEqual(settledPrimary, journey.storedSource(t, successionHandoffPrimarySource)) {
		t.Fatal("restart changed a settled handoff-target row")
	}
	_, restartedPayload := journey.daemonReport(t, passErr)
	restartedVerdict, _ := backend.applyReport(
		t, restartedPayload, backendV21RowsWithMappedTarget(t, journey), journey.backendV21Sources(t),
		journey.now(), frozenBackendV21CurrentTokenHash,
	)
	if !restartedVerdict.Accepted {
		t.Fatalf("restarted handoff-target report was rejected: HTTP %d %s: %s",
			restartedVerdict.Error.Status, restartedVerdict.Error.Code, restartedVerdict.Error.Message)
	}

	// The next ordinary lifecycle with a genuine fresh selection converges to
	// manager ready and applied==desired 67 without bypass or rewrite.
	journey.control.enrollErr = nil
	handoff.reset()
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
		t.Fatalf("ordinary convergence did not complete: %v", err)
	}
	if applied := journey.appliedRevision(t); applied != journey.manifest.DesiredRevision {
		t.Fatalf("converged applied revision = %d, want %d", applied, journey.manifest.DesiredRevision)
	}
	service = journey.storedService(t, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" || service.ErrorCode != "" {
		t.Fatalf("manager enrollment did not recover through the ordinary lifecycle: %#v", service)
	}
	if !reflect.DeepEqual(settledHandoff, journey.storedHandoff(t, operationID)) ||
		!reflect.DeepEqual(settledMapped, journey.storedSource(t, successionHandoffMappedSource)) ||
		!reflect.DeepEqual(settledPrimary, journey.storedSource(t, successionHandoffPrimarySource)) {
		t.Fatal("ordinary convergence rewrote a settled handoff-target row")
	}
	if retirements := len(journey.sourceObservationDurableState(t).retirements); retirements != len(journey.echoes) {
		t.Fatalf("terminal echo retirements drifted: %d", retirements)
	}
	t.Logf("convergence boundary counts: helper calls=%d reconciles=%d registrations=%d supervisor=%d objects=%d catalog=%d admission=%d",
		handoff.helper.calls, handoff.helper.reconciles, handoff.helper.registrations,
		handoff.supervisor.calls, handoff.objects.calls, handoff.catalog.calls, handoff.admission.calls)
}
