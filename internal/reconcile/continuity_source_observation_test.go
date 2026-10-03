package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

const (
	frozenBackendV21PriorTokenHash   = "tokenhash_prior0001"
	frozenBackendV21CurrentTokenHash = "tokenhash_current0001"
)

// sourceObservationHandoffStub models the post-.53 deferred handoff: the
// recover step returns the bounded probe-unknown deferral before any supervisor
// probe, and every apply step is recorded but never reached on a failing pass.
type sourceObservationHandoffStub struct {
	recoveries      int
	supervisorCalls int
	applies         int
}

func (stub *sourceObservationHandoffStub) RecoverHandoffs(context.Context) error {
	stub.recoveries++
	return continuity.ErrHandoffProbeUnknown
}

func (stub *sourceObservationHandoffStub) RecoverHandoffsCurrent(context.Context, model.Manifest) error {
	stub.recoveries++
	return continuity.ErrHandoffProbeUnknown
}

func (stub *sourceObservationHandoffStub) ApplyHandoffs(context.Context, []model.ContinuationHandoffManifestV1) error {
	stub.applies++
	return nil
}

func (stub *sourceObservationHandoffStub) ApplyHandoffTargetRegistrations(context.Context, []model.ContinuityRegistrationV1) error {
	stub.applies++
	return nil
}

func (stub *sourceObservationHandoffStub) ApplyHandoffReleases(context.Context, []model.ContinuationHandoffReleaseManifestV1) error {
	stub.applies++
	return nil
}

func (stub *sourceObservationHandoffStub) HandoffReports(context.Context) ([]model.ContinuationHandoffReportV1, []model.ContinuationHandoffReleaseReportV1, error) {
	return nil, nil, nil
}

func (stub *sourceObservationHandoffStub) HandoffReportsCurrent(context.Context, model.Manifest) ([]model.ContinuationHandoffReportV1, []model.ContinuationHandoffReleaseReportV1, error) {
	return nil, nil, nil
}

// newSourceObservationJourney is the accepted post-.53 A43 state: the shared
// observed-source journey with the synthetic successor-only manifest the A43
// correction was validated against (the backend had dropped the revoked
// predecessor row), a deferred handoff, and a supervisor status probe that
// answers for the two active sources only. The real re-listed predecessor /
// active successor pair is exercised by the A45 journey.
func newSourceObservationJourney(t *testing.T) *acknowledgementJourney {
	t.Helper()
	journey := newObservedSourceJourney(t, 2)
	successorOnly := make([]model.ContinuityRegistrationV1, 0, len(journey.manifest.ContinuityRegistrations))
	for _, registration := range journey.manifest.ContinuityRegistrations {
		if registration.Binding.BindingID == journey.finish.registration.Binding.BindingID &&
			registration.DesiredState == "revoked" {
			continue
		}
		successorOnly = append(successorOnly, registration)
	}
	journey.manifest.ContinuityRegistrations = successorOnly
	journey.handoff = &sourceObservationHandoffStub{}
	journey.reconciler = journey.newReconciler()
	return journey
}

// newObservedSourceJourney is the shared observed-source state behind the A43
// source observation and A45 ready-handoff succession journeys: the A41/A42
// journey with the finish successor adopted at successorScope, the finish and
// ba1b sources backed by real managed-service rows, their authentic
// observations older than the 120 s freshness contract, and a supervisor
// status probe that answers for the two active sources only. The fresh
// authenticated manifest keeps the real re-listed pair - the verified
// predecessor re-listed revoked under the same binding ID plus the active
// successor - exactly like the backend's manifest_entries filter. The caller
// installs its handoff control and rebuilds the reconciler.
func newObservedSourceJourney(t *testing.T, successorScope int64) *acknowledgementJourney {
	t.Helper()
	journey := newAcknowledgementJourney(t)
	if successorScope != journey.replacement.registration.ScopeRevision {
		// The owner-authorized A41 apply moves the finish successor one
		// monotonic scope step (2 -> 3); the stored source observation was
		// recorded while the successor was adopted, so it carries the same
		// scope.
		journey.replacement.registration.ScopeRevision = successorScope
		journey.replacement.source.ScopeRevision = successorScope
		for index := range journey.manifest.ContinuityRegistrations {
			registration := &journey.manifest.ContinuityRegistrations[index]
			if registration.Binding.BindingID == journey.finish.registration.Binding.BindingID &&
				registration.DesiredState == "active" {
				registration.ScopeRevision = successorScope
			}
		}
		source := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID)
		source.Report.ScopeRevision = successorScope
		if err := journey.store.PutContinuitySource(context.Background(), source); err != nil {
			t.Fatal(err)
		}
	}
	// The proven post-.53 sequence: the finish successor was adopted while its
	// source observation was still fresh, and only later did the stored
	// observation age beyond the 120 s contract.
	if err := journey.reconciler.Reconcile(context.Background(), journey.manifest); err == nil ||
		!strings.Contains(err.Error(), "apply managed services:") {
		t.Fatalf("settling pass did not preserve the stale-selection failure: %v", err)
	}
	finishService := journey.seedObservedSourceService(t, journey.replacement, "finish", "worker")
	ba1bService := journey.seedObservedSourceService(t, journey.ba1b, "ba1b", "worker")
	finishSource := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID)
	ba1bSource := journey.storedSource(t, journey.ba1b.registration.Binding.RegisteredSourceID)
	journey.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
		switch request["instance"] {
		case "finish":
			return observedSourceStatusReceipt(finishSource, finishService), nil
		case "ba1b":
			return observedSourceStatusReceipt(ba1bSource, ba1bService), nil
		default:
			return nil, nil
		}
	}
	journey.reconciler = journey.newReconciler()
	return journey
}

// seedObservedSourceService backs a stored source observation with a real
// managed-service row and moves the stored observation older than the shared
// freshness contract, exactly like the proven post-.53 live state.
func (journey *acknowledgementJourney) seedObservedSourceService(
	t *testing.T,
	registration acknowledgementRegistration,
	instance string,
	role string,
) state.LocalManagedService {
	t.Helper()
	ctx := context.Background()
	source, err := journey.store.ContinuitySource(ctx, registration.registration.Binding.RegisteredSourceID)
	if err != nil || source == nil {
		t.Fatalf("source for %s = %#v, %v", instance, source, err)
	}
	source.Instance = instance
	source.Report.LastObservedAt = journey.now().Add(-10 * time.Minute)
	if err := journey.store.PutContinuitySource(ctx, *source); err != nil {
		t.Fatal(err)
	}
	selectionID := "selection_" + instance + "000001"
	service := state.LocalManagedService{
		Manifest: model.ManagedServiceV1{
			FormatVersion: 1, DesiredState: "active", SessionMode: "lookup_only",
			Identity: model.ManagedServiceIdentityV1{
				ServerID:                  journey.fixture.ServiceManifest.Identity.ServerID,
				TeamID:                    journey.fixture.ServiceManifest.Identity.TeamID,
				MemberID:                  journey.fixture.ServiceManifest.Identity.MemberID,
				SandboxID:                 registration.registration.Identity.SandboxID,
				SandboxGeneration:         registration.registration.Identity.SandboxGeneration,
				ServiceRegistrationID:     registration.registration.Binding.ServiceRegistrationID,
				ExpectedServiceGeneration: 1, Instance: instance, Role: role,
			},
			Profile: model.ManagedServiceProfileV1{
				SetupOperationID: journey.fixture.SetupManifest.ID,
				ProfileID:        "opencode",
				ProfileRevision:  1,
				ProfileDigest:    journey.fixture.SetupManifest.ProfileDigest,
			},
			Instructions: model.ManagedServiceInstructionsV1{
				InstructionRevision: registration.source.InstructionRevision,
				InstructionDigest:   acknowledgementDigest([]byte("source-instruction|" + registration.registration.Binding.ServiceRegistrationID)),
			},
			Workspace: model.ManagedServiceWorkspaceV1{
				SelectionID:    selectionID,
				ProjectID:      registration.registration.Identity.ProjectID,
				WorkspaceEpoch: registration.registration.Identity.WorkspaceEpoch,
				ScopeRevision:  registration.registration.ScopeRevision,
				Designation:    "team_project",
				RootAttestation: acknowledgementDigest(
					[]byte("root-attestation|" + instance),
				),
			},
		},
		Phase: "ready", ServiceGeneration: 1,
		ProcessInstance: "wmsup-" + instance + "-0001", Port: 18443,
	}
	if err := journey.store.PutManagedServiceIntent(ctx, service); err != nil {
		t.Fatal(err)
	}
	// The real project record the service was started on, so the ordinary
	// registration projection repair has its exact ready authority.
	serviceID := registration.registration.Binding.ServiceRegistrationID
	anchor := t.TempDir()
	if err := os.MkdirAll(filepath.Join(anchor, ".warpmetal", "opencode", "instances", instance), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := journey.store.PutManagedProject(ctx, state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: selectionID,
			ProjectID:             registration.registration.Identity.ProjectID,
			WorkspaceEpoch:        registration.registration.Identity.WorkspaceEpoch,
			SandboxID:             registration.registration.Identity.SandboxID,
			SandboxGeneration:     registration.registration.Identity.SandboxGeneration,
			ServiceRegistrationID: &serviceID,
			Designation:           "team_project", Label: "label_" + instance,
			Availability:    "available",
			RootAttestation: acknowledgementDigest([]byte("project-attestation|" + instance)),
			LastObservedAt:  journey.now(),
		},
		ServerID: journey.fixture.ServiceManifest.Identity.ServerID,
		TeamID:   journey.fixture.ServiceManifest.Identity.TeamID,
		MemberID: journey.fixture.ServiceManifest.Identity.MemberID,
		Anchor:   anchor, HostRoot: source.Root, ContainerRoot: "/home/agent/projects/" + instance,
		Phase: "ready",
	}); err != nil {
		t.Fatal(err)
	}
	return service
}

func (journey *acknowledgementJourney) storedSource(t *testing.T, registeredSourceID string) state.LocalContinuitySource {
	t.Helper()
	source, err := journey.store.ContinuitySource(context.Background(), registeredSourceID)
	if err != nil || source == nil {
		t.Fatalf("stored source %s = %#v, %v", registeredSourceID, source, err)
	}
	return *source
}

func (journey *acknowledgementJourney) storedService(t *testing.T, serviceID string) *state.LocalManagedService {
	t.Helper()
	service, err := journey.store.ManagedService(context.Background(), serviceID)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func observedSourceStatusReceipt(source state.LocalContinuitySource, service state.LocalManagedService) []byte {
	payload, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "command": "status", "status": "running", "phase": "running", "ready": true,
		"instance": service.Manifest.Identity.Instance, "sandboxId": source.Report.SandboxID,
		"profileId": service.Manifest.Profile.ProfileID, "profileDigest": service.Manifest.Profile.ProfileDigest,
		"profileRevision": service.Manifest.Profile.ProfileRevision,
		"sessionId":       source.Report.NativeSessionID, "nativeProjectId": source.Report.NativeProjectID,
		"nativeLocationDigest": source.Report.NativeLocationDigest,
		"instructionRevision":  service.Manifest.Instructions.InstructionRevision,
		"instructionDigest":    service.Manifest.Instructions.InstructionDigest,
		"instructionApplied":   true,
	})
	return payload
}

func stoppedSourceStatusReceipt(reason string) []byte {
	payload, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "command": "status", "status": "stopped", "phase": "stopped", "ready": false,
		"reason": reason,
	})
	return payload
}

// observedSourceIdentity is the complete authentic observation content a probe
// must preserve; only availability, reason and lastObservedAt may move.
type observedSourceIdentity struct {
	Report              model.ContinuitySourceReportV1
	Root                string
	Instance            string
	Lifecycle           string
	LifecycleRevision   int64
	NoAdmittedExecution bool
}

func observedSourceIdentityOf(source state.LocalContinuitySource) observedSourceIdentity {
	report := source.Report
	report.Availability = ""
	report.Reason = nil
	report.LastObservedAt = time.Time{}
	return observedSourceIdentity{
		Report: report, Root: source.Root, Instance: source.Instance,
		Lifecycle: source.Lifecycle, LifecycleRevision: source.LifecycleRevision,
		NoAdmittedExecution: source.NoAdmittedExecution,
	}
}

// sourceObservationDurableState snapshots every durable row the observation
// phase must never touch.
type sourceObservationDurableState struct {
	revision      int64
	registrations []state.LocalContinuityRegistration
	sources       []state.LocalContinuitySource
	operations    []model.ContinuityOperationReportV1
	retirements   []state.ContinuityOperationRetirement
	service       *state.LocalManagedService
}

func (value sourceObservationDurableState) withoutSources() sourceObservationDurableState {
	value.sources = nil
	return value
}

func (journey *acknowledgementJourney) sourceObservationDurableState(t *testing.T) sourceObservationDurableState {
	t.Helper()
	ctx := context.Background()
	value := sourceObservationDurableState{}
	var err error
	if value.revision, err = journey.store.Revision(ctx); err != nil {
		t.Fatal(err)
	}
	if value.registrations, err = journey.store.ContinuityRegistrations(ctx); err != nil {
		t.Fatal(err)
	}
	if value.sources, err = journey.store.ContinuitySources(ctx); err != nil {
		t.Fatal(err)
	}
	if value.operations, err = journey.store.ContinuityOperationReports(ctx); err != nil {
		t.Fatal(err)
	}
	if value.retirements, err = journey.store.ContinuityOperationRetirements(ctx); err != nil {
		t.Fatal(err)
	}
	if value.service, err = journey.store.ManagedService(ctx, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID); err != nil {
		t.Fatal(err)
	}
	return value
}

func (journey *acknowledgementJourney) backendV21Sources(t *testing.T) map[string]frozenBackendV21SourceRow {
	t.Helper()
	sources, err := journey.store.ContinuitySources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]frozenBackendV21SourceRow{}
	for _, source := range sources {
		rows[frozenSourceKey(source.Report.SandboxID, source.Report.RegisteredSourceID)] = frozenBackendV21SourceRow{
			Availability:        source.Report.Availability,
			Reason:              stringValue(source.Report.Reason),
			LastObservedAt:      source.Report.LastObservedAt,
			NodeTokenHash:       frozenBackendV21PriorTokenHash,
			ServiceGeneration:   int64(source.Report.ServiceGeneration),
			ScopeRevision:       source.Report.ScopeRevision,
			ProfileRevision:     source.Report.ProfileRevision,
			InstructionRevision: source.Report.InstructionRevision,
		}
	}
	return rows
}

// TestReconcilerObservesContinuitySourcesBeforeManagedServiceFailure is the
// A43 RED/GREEN journey. RED: the ordinary pass aborts at the failure-prone
// managed-service enrollment before any later source re-observation, the
// deferred handoff never probes, the report is rebuilt from the unchanged
// stale observation and the frozen backend v21 refuses it with 409
// "Registration is no longer current and admissible.". GREEN: the pre-failure
// observation phase records a complete fresh observation for the active
// finish/ba1b sources despite the still-failing manager enrollment and the
// deferred handoff, the rebuilt report is accepted at the serialized boundary
// with applied still 64, and the next ordinary pass with a fresh selection
// recovers the manager and reaches desired 67.
func TestReconcilerObservesContinuitySourcesBeforeManagedServiceFailure(t *testing.T) {
	ctx := context.Background()
	backend := loadFrozenBackendV21(t)
	journey := newSourceObservationJourney(t)
	handoff := journey.handoff.(*sourceObservationHandoffStub)
	finishSourceID := journey.finish.registration.Binding.RegisteredSourceID
	ba1bSourceID := journey.ba1b.registration.Binding.RegisteredSourceID
	beforePassFinish := journey.storedSource(t, finishSourceID)
	beforePassBa1b := journey.storedSource(t, ba1bSourceID)
	beforeMeasured := journey.storedRegistrations(t)[journey.finish.registration.Binding.BindingID]
	t.Logf("finish registration before the measured pass: status=%s revision=%d error=%s",
		beforeMeasured.ObservedStatus, beforeMeasured.Manifest.Binding.BindingRevision, beforeMeasured.ErrorCode)
	passErr := journey.reconciler.Reconcile(ctx, journey.manifest)
	t.Logf("ordinary pass error: %v", passErr)
	t.Logf("source probe instances this pass: %v", journey.probeInstances)
	t.Logf("stored finish source before the pass: availability=%s reason=%v lastObservedAt=%s",
		beforePassFinish.Report.Availability, stringValue(beforePassFinish.Report.Reason), beforePassFinish.Report.LastObservedAt)
	t.Logf("stored finish source after the pass: availability=%s reason=%v lastObservedAt=%s",
		journey.storedSource(t, finishSourceID).Report.Availability,
		stringValue(journey.storedSource(t, finishSourceID).Report.Reason),
		journey.storedSource(t, finishSourceID).Report.LastObservedAt)
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") {
		t.Fatalf("stale-selection managed-service failure was not preserved: %v", passErr)
	}
	if handoff.recoveries != 1 || handoff.supervisorCalls != 0 || handoff.applies != 0 {
		t.Fatalf("deferred handoff probing = recoveries %d supervisor %d applies %d, want 1/0/0",
			handoff.recoveries, handoff.supervisorCalls, handoff.applies)
	}
	report, payload := journey.daemonReport(t, passErr)
	if _, repeated := journey.daemonReport(t, passErr); !bytes.Equal(payload, repeated) {
		t.Fatal("report is not rebuilt deterministically from the durable rows")
	}
	verdict, sourcesAfter := backend.applyReport(
		t, payload, journey.backendV21Rows(t), journey.backendV21Sources(t),
		journey.now(), frozenBackendV21CurrentTokenHash,
	)
	if !verdict.Accepted {
		t.Fatalf("post-.53 report was rejected by frozen backend v21: HTTP %d %s: %s\n%s",
			verdict.Error.Status, verdict.Error.Code, verdict.Error.Message, payload)
	}
	t.Logf("frozen backend v21 verdict: accepted the post-.53 report")

	// Exactly the two unique active sources are probed once each, in
	// deterministic source order; the revoked manager is never probed.
	if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b", "finish"}) {
		t.Fatalf("source probes = %v, want exactly the active ba1b and finish sources", journey.probeInstances)
	}
	finishObserved := journey.storedSource(t, finishSourceID)
	ba1bObserved := journey.storedSource(t, ba1bSourceID)
	for _, observed := range []state.LocalContinuitySource{finishObserved, ba1bObserved} {
		if observed.Report.Availability != "available" || observed.Report.Reason != nil ||
			!observed.Report.LastObservedAt.Equal(journey.now()) {
			t.Fatalf("source %s was not re-observed completely: %#v", observed.Report.RegisteredSourceID, observed)
		}
	}
	if !reflect.DeepEqual(observedSourceIdentityOf(finishObserved), observedSourceIdentityOf(beforePassFinish)) ||
		!reflect.DeepEqual(observedSourceIdentityOf(ba1bObserved), observedSourceIdentityOf(beforePassBa1b)) {
		t.Fatalf("observation content drifted:\nfinish got %#v want %#v\nba1b got %#v want %#v",
			observedSourceIdentityOf(finishObserved), observedSourceIdentityOf(beforePassFinish),
			observedSourceIdentityOf(ba1bObserved), observedSourceIdentityOf(beforePassBa1b))
	}
	finishRow, ok := sourcesAfter[frozenSourceKey(finishObserved.Report.SandboxID, finishObserved.Report.RegisteredSourceID)]
	if !ok || finishRow.NodeTokenHash != frozenBackendV21CurrentTokenHash ||
		!finishRow.LastObservedAt.Equal(journey.now()) {
		t.Fatalf("accepted report did not refresh the backend token/freshness: %#v", finishRow)
	}
	if applied, err := journey.store.Revision(ctx); err != nil || applied != 64 {
		t.Fatalf("applied revision = %d, %v; want the unchanged 64", applied, err)
	}
	service := journey.storedService(t, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if service == nil || service.Phase != "failed" || service.ErrorCode != "enrollment_unavailable" {
		t.Fatalf("manager failure was not preserved: %#v", service)
	}
	if report.LastError == nil || report.LastError.Code != "reconcile_failed" ||
		!strings.Contains(report.LastError.Message, "stale") {
		t.Fatalf("stale-selection reconcile_failed marker was not visible: %#v", report.LastError)
	}
	if len(report.ContinuityRegistrations) != 2 ||
		report.ContinuityRegistrations[0].Binding.BindingID != journey.ba1b.registration.Binding.BindingID ||
		report.ContinuityRegistrations[1].Binding.BindingID != journey.finish.registration.Binding.BindingID {
		t.Fatalf("report registration shape drifted: %#v", report.ContinuityRegistrations)
	}
	for _, observation := range report.ContinuityRegistrations {
		if observation.Binding.BindingID == journey.manager.registration.Binding.BindingID {
			t.Fatalf("revoked manager tuple was serialized: %#v", observation)
		}
	}
	if len(report.ContinuityOperations) != 0 {
		t.Fatalf("retired operation echoes were serialized: %#v", report.ContinuityOperations)
	}

	// A second ordinary pass is net-idempotent: only the genuine observations
	// are re-written (identically under the fixed clock); every registration,
	// operation, tombstone, service row and revision stays byte-identical.
	settled := journey.sourceObservationDurableState(t)
	settledFinish := journey.storedSource(t, finishSourceID)
	settledBa1b := journey.storedSource(t, ba1bSourceID)
	probesBefore := len(journey.probeInstances)
	passErr = journey.reconciler.Reconcile(ctx, journey.manifest)
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") {
		t.Fatalf("second stale-selection pass did not preserve the failure: %v", passErr)
	}
	if !reflect.DeepEqual(journey.probeInstances[probesBefore:], []string{"ba1b", "finish"}) {
		t.Fatalf("second pass probes = %v", journey.probeInstances[probesBefore:])
	}
	settledAgain := journey.sourceObservationDurableState(t)
	if !reflect.DeepEqual(settled.withoutSources(), settledAgain.withoutSources()) {
		t.Fatalf("observation phase touched unrelated durable state:\nbefore %#v\nafter  %#v",
			settled.withoutSources(), settledAgain.withoutSources())
	}
	if !reflect.DeepEqual(journey.storedSource(t, finishSourceID), settledFinish) ||
		!reflect.DeepEqual(journey.storedSource(t, ba1bSourceID), settledBa1b) {
		t.Fatal("second pass changed the genuine observations")
	}
	if handoff.recoveries != 2 || handoff.supervisorCalls != 0 || handoff.applies != 0 {
		t.Fatalf("handoff state moved across passes: %#v", handoff)
	}

	// Reopen/restart: deterministic re-observation and an accepted report.
	journey.restart(t)
	probesBefore = len(journey.probeInstances)
	passErr = journey.reconciler.Reconcile(ctx, journey.manifest)
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") {
		t.Fatalf("restarted stale-selection pass did not preserve the failure: %v", passErr)
	}
	if !reflect.DeepEqual(journey.probeInstances[probesBefore:], []string{"ba1b", "finish"}) {
		t.Fatalf("restarted pass probes = %v", journey.probeInstances[probesBefore:])
	}
	if !reflect.DeepEqual(journey.storedSource(t, finishSourceID), settledFinish) ||
		!reflect.DeepEqual(journey.storedSource(t, ba1bSourceID), settledBa1b) {
		t.Fatal("restart changed the genuine observations")
	}
	_, restartedPayload := journey.daemonReport(t, passErr)
	restartedVerdict, restartedSources := backend.applyReport(
		t, restartedPayload, journey.backendV21Rows(t), journey.backendV21Sources(t),
		journey.now(), frozenBackendV21CurrentTokenHash,
	)
	if !restartedVerdict.Accepted {
		t.Fatalf("restarted report was rejected: HTTP %d %s: %s",
			restartedVerdict.Error.Status, restartedVerdict.Error.Code, restartedVerdict.Error.Message)
	}
	if row := restartedSources[frozenSourceKey(settledFinish.Report.SandboxID, finishSourceID)]; row.NodeTokenHash != frozenBackendV21CurrentTokenHash {
		t.Fatalf("restarted report did not carry the current token hash: %#v", row)
	}

	// Fresh selection: the next ordinary pass completes enrollment with no
	// bypass and reaches applied==desired 67.
	journey.control.enrollErr = nil
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
		t.Fatalf("fresh-selection pass did not complete: %v", err)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != journey.manifest.DesiredRevision {
		t.Fatalf("converged applied revision = %d, %v; want %d", revision, err, journey.manifest.DesiredRevision)
	}
	service = journey.storedService(t, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" ||
		service.Manifest.Identity.Role != "manager" {
		t.Fatalf("manager enrollment did not recover through the ordinary lifecycle: %#v", service)
	}
	if !reflect.DeepEqual(journey.storedSource(t, finishSourceID), settledFinish) ||
		!reflect.DeepEqual(journey.storedSource(t, ba1bSourceID), settledBa1b) {
		t.Fatal("convergence changed the genuine observations")
	}
}

// TestReconcilerSourceObservationKeepsOnlyGenuineFreshObservations is the
// mutation-blind negative matrix for the observation phase: genuine
// unavailability is persisted truthfully, ambiguous/foreign/malformed probes
// and preconditions fail closed without writes, dedup is exact, and a partial
// failure never fabricates freshness or touches unrelated state.
func TestReconcilerSourceObservationKeepsOnlyGenuineFreshObservations(t *testing.T) {
	ctx := context.Background()
	backend := loadFrozenBackendV21(t)

	failingPass := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "apply managed services:") {
			t.Fatalf("stale-selection managed-service failure was not preserved: %v", err)
		}
	}

	t.Run("genuine_unavailable_is_persisted_and_still_refused", func(t *testing.T) {
		journey := newSourceObservationJourney(t)
		base := journey.statusProbe
		journey.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
			if request["instance"] == "finish" {
				return stoppedSourceStatusReceipt("service_stopped"), nil
			}
			return base(sandboxID, request)
		}
		journey.reconciler = journey.newReconciler()
		passErr := journey.reconciler.Reconcile(ctx, journey.manifest)
		failingPass(t, passErr)
		source := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID)
		if source.Report.Availability != "unavailable" || source.Report.Reason == nil ||
			*source.Report.Reason != "service_stopped" || !source.Report.LastObservedAt.Equal(journey.now()) {
			t.Fatalf("genuine unavailability was not persisted visibly: %#v", source.Report)
		}
		_, payload := journey.daemonReport(t, passErr)
		verdict, _ := backend.applyReport(
			t, payload, journey.backendV21Rows(t), journey.backendV21Sources(t),
			journey.now(), frozenBackendV21CurrentTokenHash,
		)
		if verdict.Accepted || verdict.Error.Status != 409 ||
			verdict.Error.Message != "Registration is no longer current and admissible." {
			t.Fatalf("unavailable source registration verdict = %#v", verdict)
		}
	})

	closed := []struct {
		name     string
		override func(journey *acknowledgementJourney)
	}{
		{name: "probe_error_fails_closed", override: func(journey *acknowledgementJourney) {
			base := journey.statusProbe
			journey.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
				if request["instance"] == "finish" {
					return nil, errors.New("supervisor status transport failed")
				}
				return base(sandboxID, request)
			}
		}},
		{name: "malformed_receipt_fails_closed", override: func(journey *acknowledgementJourney) {
			base := journey.statusProbe
			journey.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
				if request["instance"] == "finish" {
					return []byte(`{"schemaVersion":1,"command":"status","status":"running"`), nil
				}
				return base(sandboxID, request)
			}
		}},
		{name: "identity_mismatch_fails_closed", override: func(journey *acknowledgementJourney) {
			base := journey.statusProbe
			journey.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
				if request["instance"] == "finish" {
					return []byte(`{"schemaVersion":1,"command":"status","status":"running","phase":"running","ready":true,` +
						`"instance":"finish","sandboxId":"sbx_managedservice00000001","profileId":"opencode",` +
						`"profileDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","profileRevision":1,` +
						`"sessionId":"ses_foreign_source0001","nativeProjectId":"0123456789abcdef0123456789abcdef01234567",` +
						`"nativeLocationDigest":"sha256:2222222222222222222222222222222222222222222222222222222222222222",` +
						`"instructionRevision":1,"instructionDigest":"sha256:3333333333333333333333333333333333333333333333333333333333333333",` +
						`"instructionApplied":true}`), nil
				}
				return base(sandboxID, request)
			}
		}},
	}
	for _, test := range closed {
		t.Run(test.name, func(t *testing.T) {
			journey := newSourceObservationJourney(t)
			test.override(journey)
			journey.reconciler = journey.newReconciler()
			before := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID)
			beforeService := journey.storedService(t, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
			err := journey.reconciler.Reconcile(ctx, journey.manifest)
			if err == nil || !strings.Contains(err.Error(), "observe continuity sources") {
				t.Fatalf("ambiguous probe did not fail closed: %v", err)
			}
			after := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("ambiguous probe changed the stored observation:\nbefore %#v\nafter  %#v", before, after)
			}
			if !reflect.DeepEqual(journey.storedService(t, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID), beforeService) {
				t.Fatal("fail-closed probe mutated the managed service")
			}
			if revision, err := journey.store.Revision(ctx); err != nil || revision != 64 {
				t.Fatalf("fail-closed probe changed the applied revision: %d %v", revision, err)
			}
		})
	}

	t.Run("foreign_or_unowned_source_is_not_probed", func(t *testing.T) {
		journey := newSourceObservationJourney(t)
		source := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID)
		source.Report.ScopeRevision = 999
		if err := journey.store.PutContinuitySource(ctx, source); err != nil {
			t.Fatal(err)
		}
		journey.reconciler = journey.newReconciler()
		failingPass(t, journey.reconciler.Reconcile(ctx, journey.manifest))
		if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b"}) {
			t.Fatalf("foreign source probes = %v, want only ba1b", journey.probeInstances)
		}
		if stored := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID); stored.Report.ScopeRevision != 999 {
			t.Fatalf("foreign source row was mutated: %#v", stored.Report)
		}
	})

	t.Run("revoked_manager_is_never_probed", func(t *testing.T) {
		journey := newSourceObservationJourney(t)
		// A durable revoked row that still carries a positive service generation
		// and a fully matching service/source tuple: only the active/enabled
		// selection may keep it unprobed.
		manager, err := journey.store.ContinuityRegistration(ctx, journey.manager.registration.Binding.BindingID)
		if err != nil || manager == nil {
			t.Fatalf("manager registration = %#v %v", manager, err)
		}
		manager.ServiceGeneration = 1
		if err := journey.store.PutContinuityRegistration(ctx, *manager); err != nil {
			t.Fatal(err)
		}
		journey.seedObservedSourceService(t, journey.manager, "manager", "manager")
		failingPass(t, journey.reconciler.Reconcile(ctx, journey.manifest))
		for _, instance := range journey.probeInstances {
			if instance == "manager" || instance == "default" {
				t.Fatalf("revoked manager source was probed: %v", journey.probeInstances)
			}
		}
	})

	t.Run("same_source_multiple_registrations_probes_once", func(t *testing.T) {
		journey := newSourceObservationJourney(t)
		shared := journey.finish.registration
		shared.Binding.BindingID = "binding_finish_shared00001"
		// A durable verified local row for the second registration, so the
		// duplicate is locally valid and only dedup keeps the probe count at one.
		if err := journey.store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
			Manifest: shared, ObservedStatus: "verified", ServiceGeneration: 1,
			ReceiptDigest: acknowledgementRegistrationReceiptDigest(shared, journey.finish.source),
		}); err != nil {
			t.Fatal(err)
		}
		manifest := journey.manifest
		manifest.ContinuityRegistrations = append(
			append([]model.ContinuityRegistrationV1(nil), journey.manifest.ContinuityRegistrations...), shared,
		)
		failingPass(t, journey.reconciler.Reconcile(ctx, manifest))
		if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b", "finish"}) {
			t.Fatalf("shared source probes = %v, want one probe per unique source", journey.probeInstances)
		}
	})

	t.Run("atomic_failure_keeps_only_genuine_observations", func(t *testing.T) {
		journey := newSourceObservationJourney(t)
		failingPass(t, journey.reconciler.Reconcile(ctx, journey.manifest))
		settledFinish := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID)
		settledBa1b := journey.storedSource(t, journey.ba1b.registration.Binding.RegisteredSourceID)
		settledService := journey.storedService(t, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
		base := journey.statusProbe
		journey.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
			if request["instance"] == "finish" {
				return nil, errors.New("finish probe transport failed")
			}
			return base(sandboxID, request)
		}
		journey.reconciler = journey.newReconciler()
		err := journey.reconciler.Reconcile(ctx, journey.manifest)
		if err == nil || !strings.Contains(err.Error(), "observe continuity sources") {
			t.Fatalf("partial probe failure was not fail-closed: %v", err)
		}
		if !reflect.DeepEqual(journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID), settledFinish) ||
			!reflect.DeepEqual(journey.storedSource(t, journey.ba1b.registration.Binding.RegisteredSourceID), settledBa1b) {
			t.Fatal("partial failure changed a genuine observation")
		}
		if !reflect.DeepEqual(journey.storedService(t, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID), settledService) {
			t.Fatal("partial failure mutated the managed service")
		}
		if revision, err := journey.store.Revision(ctx); err != nil || revision != 64 {
			t.Fatalf("partial failure advanced the applied revision: %d %v", revision, err)
		}
	})

	t.Run("unavailable_observation_is_refreshed_available", func(t *testing.T) {
		journey := newSourceObservationJourney(t)
		source := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID)
		reason := "service_stopped"
		source.Report.Availability = "unavailable"
		source.Report.Reason = &reason
		if err := journey.store.PutContinuitySource(ctx, source); err != nil {
			t.Fatal(err)
		}
		journey.reconciler = journey.newReconciler()
		failingPass(t, journey.reconciler.Reconcile(ctx, journey.manifest))
		refreshed := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID)
		if refreshed.Report.Availability != "available" || refreshed.Report.Reason != nil ||
			!refreshed.Report.LastObservedAt.Equal(journey.now()) {
			t.Fatalf("unavailable observation was not refreshed by the real probe: %#v", refreshed.Report)
		}
	})

	t.Run("local_succession_outcome_mismatch_is_not_probed", func(t *testing.T) {
		journey := newSourceObservationJourney(t)
		local, err := journey.store.ContinuityRegistration(ctx, journey.finish.registration.Binding.BindingID)
		if err != nil || local == nil {
			t.Fatalf("local registration = %#v %v", local, err)
		}
		local.Manifest.Identity.ExpectedRevision = 2
		if err := journey.store.PutContinuityRegistration(ctx, *local); err != nil {
			t.Fatal(err)
		}
		if err := journey.reconciler.observeContinuitySources(ctx, journey.manifest); err != nil {
			t.Fatalf("local mismatch did not fail closed explicitly: %v", err)
		}
		if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b"}) {
			t.Fatalf("locally unmatched registration probes = %v, want only ba1b", journey.probeInstances)
		}
	})

	t.Run("malformed_registration_manifest_is_not_probed", func(t *testing.T) {
		journey := newSourceObservationJourney(t)
		local, err := journey.store.ContinuityRegistration(ctx, journey.finish.registration.Binding.BindingID)
		if err != nil || local == nil {
			t.Fatalf("local registration = %#v %v", local, err)
		}
		local.Manifest.Binding.BindingRevision = 0
		if err := journey.store.PutContinuityRegistration(ctx, *local); err != nil {
			t.Fatal(err)
		}
		manifest := journey.manifest
		manifest.ContinuityRegistrations = append([]model.ContinuityRegistrationV1(nil), journey.manifest.ContinuityRegistrations...)
		for index := range manifest.ContinuityRegistrations {
			if manifest.ContinuityRegistrations[index].Binding.BindingID == journey.finish.registration.Binding.BindingID {
				manifest.ContinuityRegistrations[index].Binding.BindingRevision = 0
			}
		}
		if err := journey.reconciler.observeContinuitySources(ctx, manifest); err != nil {
			t.Fatalf("malformed manifest did not fail closed explicitly: %v", err)
		}
		if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b"}) {
			t.Fatalf("malformed registration probes = %v, want only ba1b", journey.probeInstances)
		}
	})

	t.Run("stale_observation_is_refused_even_with_the_current_token", func(t *testing.T) {
		journey := newSourceObservationJourney(t)
		source := journey.storedSource(t, journey.finish.registration.Binding.RegisteredSourceID)
		item := model.ContinuityRegistrationReportV1{
			ContinuityRegistrationV1: journey.replacement.registration,
			ObservedStatus:           "verified",
			ServiceGeneration:        1,
			ReceiptDigest:            acknowledgementRegistrationReceiptDigest(journey.replacement.registration, journey.finish.source),
		}
		payload, err := json.Marshal(map[string]any{
			"continuitySources":       []model.ContinuitySourceReportV1{source.Report},
			"continuityRegistrations": []model.ContinuityRegistrationReportV1{item},
		})
		if err != nil {
			t.Fatal(err)
		}
		verdict, _ := backend.applyReport(
			t, payload, journey.backendV21Rows(t), journey.backendV21Sources(t),
			journey.now(), frozenBackendV21CurrentTokenHash,
		)
		if verdict.Accepted || verdict.Error.Status != 409 ||
			verdict.Error.Message != "Registration is no longer current and admissible." {
			t.Fatalf("stale observation verdict = %#v", verdict)
		}
		fresh := source.Report
		fresh.LastObservedAt = journey.now()
		fresh.Availability = "available"
		fresh.Reason = nil
		payload, err = json.Marshal(map[string]any{
			"continuitySources":       []model.ContinuitySourceReportV1{fresh},
			"continuityRegistrations": []model.ContinuityRegistrationReportV1{item},
		})
		if err != nil {
			t.Fatal(err)
		}
		verdict, sourcesAfter := backend.applyReport(
			t, payload, journey.backendV21Rows(t), journey.backendV21Sources(t),
			journey.now(), frozenBackendV21CurrentTokenHash,
		)
		if !verdict.Accepted {
			t.Fatalf("fresh observation was refused: HTTP %d %s: %s",
				verdict.Error.Status, verdict.Error.Code, verdict.Error.Message)
		}
		row := sourcesAfter[frozenSourceKey(source.Report.SandboxID, source.Report.RegisteredSourceID)]
		if row.NodeTokenHash != frozenBackendV21CurrentTokenHash || !row.LastObservedAt.Equal(journey.now()) {
			t.Fatalf("fresh observation did not refresh the token/freshness: %#v", row)
		}
	})
}
