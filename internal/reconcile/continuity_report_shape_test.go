package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// reportWriteSnapshot captures every durable row the report path reads, so a
// report construction can be proven to perform zero local writes.
type reportWriteSnapshot struct {
	revision      int64
	registrations []state.LocalContinuityRegistration
	sources       []state.LocalContinuitySource
	operations    []model.ContinuityOperationReportV1
	retirements   []state.ContinuityOperationRetirement
	service       *state.LocalManagedService
	sandboxes     []state.LocalSandbox
}

func (journey *acknowledgementJourney) reportWriteSnapshot(t *testing.T) reportWriteSnapshot {
	t.Helper()
	ctx := context.Background()
	snapshot := reportWriteSnapshot{}
	var err error
	if snapshot.revision, err = journey.store.Revision(ctx); err != nil {
		t.Fatal(err)
	}
	if snapshot.registrations, err = journey.store.ContinuityRegistrations(ctx); err != nil {
		t.Fatal(err)
	}
	if snapshot.sources, err = journey.store.ContinuitySources(ctx); err != nil {
		t.Fatal(err)
	}
	if snapshot.operations, err = journey.store.ContinuityOperationReports(ctx); err != nil {
		t.Fatal(err)
	}
	if snapshot.retirements, err = journey.store.ContinuityOperationRetirements(ctx); err != nil {
		t.Fatal(err)
	}
	if snapshot.service, err = journey.store.ManagedService(ctx, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID); err != nil {
		t.Fatal(err)
	}
	if snapshot.sandboxes, err = journey.store.Sandboxes(ctx); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func frozenRowKey(bindingID string, revision int64) string {
	return bindingID + "#" + strconv.FormatInt(revision, 10)
}

func registrationWireMaps(t *testing.T, registration model.ContinuityRegistrationV1) (map[string]any, map[string]any) {
	t.Helper()
	payload, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	identity, _ := document["identity"].(map[string]any)
	binding, _ := document["binding"].(map[string]any)
	return identity, binding
}

// backendV21Rows is the frozen backend durable registration table the
// serialized report is applied against: the revoked manager rev-1 row (state
// verified, receipt none), the pending active finish rev-2 successor and the
// verified ba1b rev-1 row.
func (journey *acknowledgementJourney) backendV21Rows(t *testing.T) map[string]frozenBackendV21RegistrationRow {
	t.Helper()
	rows := map[string]frozenBackendV21RegistrationRow{}
	managerIdentity, managerBinding := registrationWireMaps(t, revokedTuple(journey.manager.registration))
	rows[frozenRowKey(journey.manager.registration.Binding.BindingID, 1)] = frozenBackendV21RegistrationRow{
		State: "verified", DesiredState: "revoked", ContinuityEnabled: false,
		ScopeRevision: 2, ServiceGeneration: 1, ReceiptDigest: "", ErrorCode: "",
		Current: false, Availability: "unavailable",
		Identity: managerIdentity, Binding: managerBinding,
	}
	finishIdentity, finishBinding := registrationWireMaps(t, journey.replacement.registration)
	rows[frozenRowKey(journey.finish.registration.Binding.BindingID, 2)] = frozenBackendV21RegistrationRow{
		State: "pending", DesiredState: "active", ContinuityEnabled: true,
		ScopeRevision: float64(journey.replacement.registration.ScopeRevision), ServiceGeneration: 1, ReceiptDigest: "", ErrorCode: "",
		Current: true, Availability: "available",
		Identity: finishIdentity, Binding: finishBinding,
	}
	ba1bIdentity, ba1bBinding := registrationWireMaps(t, journey.ba1b.registration)
	rows[frozenRowKey(journey.ba1b.registration.Binding.BindingID, 1)] = frozenBackendV21RegistrationRow{
		State: "verified", DesiredState: "active", ContinuityEnabled: true,
		ScopeRevision: 1, ServiceGeneration: 1,
		ReceiptDigest: acknowledgementRegistrationReceiptDigest(journey.ba1b.registration, journey.ba1b.source),
		Current:       true, Availability: "available",
		Identity: ba1bIdentity, Binding: ba1bBinding,
	}
	return rows
}

// daemonReport derives the report exactly like the daemon loop does, including
// the reconcile_failed marker and the pinned image digest.
func (journey *acknowledgementJourney) daemonReport(t *testing.T, passError error) (model.Report, []byte) {
	t.Helper()
	report, err := journey.reconciler.Report(context.Background(), journey.manifest.ServerID, "test")
	if err != nil {
		t.Fatalf("report construction failed: %v", err)
	}
	report.ImageDigest = journey.manifest.ImageDigest
	if passError != nil {
		report.LastError = &model.ItemError{Code: "reconcile_failed", Message: passError.Error()}
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return report, payload
}

// TestReconcilerPostAcknowledgementReportPassesBackendV21 is the A42 RED/GREEN
// journey at the serialized boundary. RED: the first post-acknowledgement
// report serializes the locally retained revoked/disabled manager tuple with an
// empty receipt digest and the frozen backend v21 rejects it with HTTP 400
// invalid_runtime_report; a synthetic digest would instead reach the
// verified-row revocation conflict. GREEN: the report carries only the active
// finish rev-2 successor and the unchanged ba1b row, passes the frozen schema
// and apply rules, leaves applied=64 with the stale-selection failure visible,
// performs zero local writes, is identical across reopen/restart, and the next
// ordinary Reconcile pass completes enrollment and reaches desired 67.
func TestReconcilerPostAcknowledgementReportPassesBackendV21(t *testing.T) {
	ctx := context.Background()
	backend := loadFrozenBackendV21(t)
	journey := newAcknowledgementJourney(t)
	passErr := journey.reconciler.Reconcile(ctx, journey.manifest)
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") ||
		!strings.Contains(passErr.Error(), "stale") {
		t.Fatalf("stale-selection managed-service failure was not preserved: %v", passErr)
	}
	managerBindingID := journey.manager.registration.Binding.BindingID
	managerLocal := journey.storedRegistrations(t)[managerBindingID]
	if managerLocal.Manifest.DesiredState != "revoked" || managerLocal.Manifest.ContinuityEnabled ||
		managerLocal.ObservedStatus != "revoked" || managerLocal.ReceiptDigest != "" || managerLocal.ErrorCode != "" {
		t.Fatalf("revoked manager row did not match the live shape: %#v", managerLocal)
	}

	before := journey.reportWriteSnapshot(t)
	report, payload := journey.daemonReport(t, passErr)
	verdict := backend.applyRegistrationReport(t, payload, journey.backendV21Rows(t))
	if !verdict.Accepted {
		t.Fatalf("first post-acknowledgement report was rejected by frozen backend v21: HTTP %d %s: %s\n%s",
			verdict.Error.Status, verdict.Error.Code, verdict.Error.Message, payload)
	}
	t.Logf("frozen backend v21 verdict: accepted the first post-acknowledgement report (%d registration observations, applied %d)",
		len(report.ContinuityRegistrations), report.AppliedRevision)
	if report.AppliedRevision != 64 {
		t.Fatalf("report applied revision = %d, want the unchanged 64", report.AppliedRevision)
	}
	if report.LastError == nil || report.LastError.Code != "reconcile_failed" ||
		!strings.Contains(report.LastError.Message, "stale") {
		t.Fatalf("stale-selection reconcile_failed marker was not visible: %#v", report.LastError)
	}
	if len(report.ManagedServices) != 1 || report.ManagedServices[0].ObservedState != "failed" ||
		report.ManagedServices[0].LastError == nil || report.ManagedServices[0].LastError.Code != "enrollment_unavailable" ||
		report.ManagedServices[0].Identity.Role != "manager" {
		t.Fatalf("deferred manager enrollment was not visible: %#v", report.ManagedServices)
	}
	if len(report.ContinuityRegistrations) != 2 {
		t.Fatalf("report registration count = %d, want the two current desired-active rows: %#v",
			len(report.ContinuityRegistrations), report.ContinuityRegistrations)
	}
	if report.ContinuityRegistrations[0].Binding.BindingID != journey.ba1b.registration.Binding.BindingID ||
		report.ContinuityRegistrations[1].Binding.BindingID != journey.finish.registration.Binding.BindingID {
		t.Fatalf("report registration order drifted: %#v", report.ContinuityRegistrations)
	}
	finishObserved := report.ContinuityRegistrations[1]
	if finishObserved.Binding.BindingRevision != 2 || finishObserved.ObservedStatus != "verified" ||
		finishObserved.Binding.BindingID != journey.finish.registration.Binding.BindingID ||
		!reflect.DeepEqual(finishObserved.ContinuityRegistrationV1, journey.replacement.registration) ||
		finishObserved.ReceiptDigest != acknowledgementRegistrationReceiptDigest(journey.replacement.registration, journey.finish.source) {
		t.Fatalf("finish rev-2 successor observation drifted: %#v", finishObserved)
	}
	for _, observation := range report.ContinuityRegistrations {
		if observation.Binding.BindingID == managerBindingID {
			t.Fatalf("revoked manager tuple was serialized: %#v", observation)
		}
	}
	if len(report.ContinuityOperations) != 0 {
		t.Fatalf("retired operation echoes were serialized: %#v", report.ContinuityOperations)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	if string(document["continuityOperations"]) != "[]" {
		t.Fatalf("continuityOperations wire shape = %s, want []", document["continuityOperations"])
	}
	for _, echo := range journey.echoes {
		if bytes.Contains(payload, []byte(echo.OperationID)) {
			t.Fatalf("retired operation echo %s reappeared on the wire", echo.OperationID)
		}
	}
	if len(report.ContinuitySources) != 3 || len(report.Sandboxes) != 1 || report.Sandboxes[0].ObservedState != "running" ||
		len(report.SetupOperations) != 1 || report.SetupOperations[0].Status != "ready" ||
		len(report.AccessGrants) != 0 || len(report.ManagedWorkspaceSelections) != 1 {
		t.Fatalf("unrelated report sections drifted: %#v", report)
	}
	after := journey.reportWriteSnapshot(t)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("report performed local writes:\nbefore %#v\nafter  %#v", before, after)
	}

	// Reopen/restart: identical payload, still accepted, and the revoked local
	// row is byte-identical.
	journey.restart(t)
	_, restartPayload := journey.daemonReport(t, passErr)
	if !bytes.Equal(payload, restartPayload) {
		t.Fatalf("report changed across reopen/restart:\nfirst %s\nrestart %s", payload, restartPayload)
	}
	if verdict := backend.applyRegistrationReport(t, restartPayload, journey.backendV21Rows(t)); !verdict.Accepted {
		t.Fatalf("restarted report was rejected: HTTP %d %s: %s", verdict.Error.Status, verdict.Error.Code, verdict.Error.Message)
	} else {
		t.Logf("frozen backend v21 verdict: accepted the restarted report")
	}
	if restarted := journey.storedRegistrations(t)[managerBindingID]; !reflect.DeepEqual(restarted, managerLocal) {
		t.Fatalf("reopen/restart changed the revoked local row: %#v", restarted)
	}

	// The next ordinary Reconcile pass, with a fresh selection, completes
	// enrollment and reaches desired 67.
	journey.control.enrollErr = nil
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
		t.Fatalf("fresh-selection pass did not complete: %v", err)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != journey.manifest.DesiredRevision {
		t.Fatalf("converged applied revision = %d, %v; want %d", revision, err, journey.manifest.DesiredRevision)
	}
	service, err := journey.store.ManagedService(ctx, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if err != nil || service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" ||
		service.Manifest.Identity.Role != "manager" {
		t.Fatalf("manager enrollment did not complete through the ordinary lifecycle: %#v %v", service, err)
	}
	convergedReport, convergedPayload := journey.daemonReport(t, nil)
	if convergedReport.LastError != nil || len(convergedReport.ManagedServices) != 1 ||
		convergedReport.ManagedServices[0].ObservedState != "ready" {
		t.Fatalf("converged manager report = %#v", convergedReport)
	}
	if verdict := backend.applyRegistrationReport(t, convergedPayload, journey.backendV21Rows(t)); !verdict.Accepted {
		t.Fatalf("converged report was rejected: HTTP %d %s: %s", verdict.Error.Status, verdict.Error.Code, verdict.Error.Message)
	} else {
		t.Logf("frozen backend v21 verdict: accepted the converged report with the manager service ready")
	}
	if stored := journey.storedRegistrations(t)[managerBindingID]; !reflect.DeepEqual(stored, managerLocal) {
		t.Fatalf("reporting/convergence changed the revoked local row: %#v", stored)
	}

	// The revoked local row can only change through a later valid manifest
	// acknowledgement: the manager binding advances in place to revision 2.
	managerSuccessor := journey.manager.registration
	managerSuccessor.Binding.BindingRevision = 2
	changed := journey.manifest
	changed.ContinuityRegistrations = []model.ContinuityRegistrationV1{
		revokedTuple(journey.finish.registration), journey.replacement.registration,
		revokedTuple(journey.manager.registration), managerSuccessor,
		journey.ba1b.registration,
	}
	if err := journey.reconciler.Reconcile(ctx, changed); err != nil {
		t.Fatalf("later manager acknowledgement did not apply: %v", err)
	}
	managerNow := journey.storedRegistrations(t)[managerBindingID]
	if managerNow.Manifest.Binding.BindingRevision != 2 || managerNow.ObservedStatus != "verified" ||
		!reflect.DeepEqual(managerNow.Manifest, managerSuccessor) {
		t.Fatalf("later manager acknowledgement did not advance the revoked row: %#v", managerNow)
	}
	rows := journey.backendV21Rows(t)
	managerIdentity, managerBinding := registrationWireMaps(t, managerSuccessor)
	rows[frozenRowKey(managerBindingID, 2)] = frozenBackendV21RegistrationRow{
		State: "pending", DesiredState: "active", ContinuityEnabled: true,
		ScopeRevision: 2, ServiceGeneration: journey.manager.source.ServiceGeneration,
		ReceiptDigest: "", ErrorCode: "", Current: true, Availability: "available",
		Identity: managerIdentity, Binding: managerBinding,
	}
	nowReport, nowPayload := journey.daemonReport(t, nil)
	if verdict := backend.applyRegistrationReport(t, nowPayload, rows); !verdict.Accepted {
		t.Fatalf("advanced manager report was rejected: HTTP %d %s: %s", verdict.Error.Status, verdict.Error.Code, verdict.Error.Message)
	} else {
		t.Logf("frozen backend v21 verdict: accepted the later acknowledged manager successor report")
	}
	found := false
	for _, observation := range nowReport.ContinuityRegistrations {
		if observation.Binding.BindingID == managerBindingID && observation.Binding.BindingRevision == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("advanced manager tuple is not reportable: %#v", nowReport.ContinuityRegistrations)
	}
}

// TestReconcilerReportProjectionKeepsOnlyCurrentDesiredActiveRegistrations is
// the mutation-blind negative matrix for the report projection: active current
// observations (including failed ones) are emitted unchanged, the exact
// revoked/disabled row is omitted without store writes, and every malformed or
// contradictory local manifest fails report construction closed. The frozen
// backend proof pins both the live empty-digest 400 and the synthetic-digest
// verified-row revocation conflict.
func TestReconcilerReportProjectionKeepsOnlyCurrentDesiredActiveRegistrations(t *testing.T) {
	ctx := context.Background()
	backend := loadFrozenBackendV21(t)

	settled := func(t *testing.T) *acknowledgementJourney {
		t.Helper()
		journey := newAcknowledgementJourney(t)
		if err := journey.reconciler.Reconcile(ctx, journey.manifest); err == nil ||
			!strings.Contains(err.Error(), "apply managed services:") {
			t.Fatalf("stale-selection failure was not preserved: %v", err)
		}
		return journey
	}

	t.Run("extra_active_failed_observation_is_emitted", func(t *testing.T) {
		journey := settled(t)
		extra := acknowledgementRegistrationFixture("extra_active_0000001", "worker", 2)
		extra.registration.ContinuityEnabled = true
		if err := journey.store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
			Manifest: extra.registration, ObservedStatus: "failed", ErrorCode: "source_unavailable",
		}); err != nil {
			t.Fatal(err)
		}
		report, err := journey.reconciler.Report(ctx, journey.manifest.ServerID, "test")
		if err != nil {
			t.Fatalf("active failed observation failed report construction: %v", err)
		}
		var found *model.ContinuityRegistrationReportV1
		for index := range report.ContinuityRegistrations {
			if report.ContinuityRegistrations[index].Binding.BindingID == extra.registration.Binding.BindingID {
				found = &report.ContinuityRegistrations[index]
			}
		}
		if found == nil {
			t.Fatalf("active current failed observation was dropped: %#v", report.ContinuityRegistrations)
		}
		if found.ObservedStatus != "failed" || found.LastError == nil || found.LastError.Code != "source_unavailable" ||
			found.ServiceGeneration != 0 || found.ReceiptDigest != "" ||
			!reflect.DeepEqual(found.ContinuityRegistrationV1, extra.registration) {
			t.Fatalf("emitted failed observation drifted: %#v", found)
		}
	})

	t.Run("revoked_disabled_row_is_omitted_without_writes", func(t *testing.T) {
		journey := settled(t)
		managerBindingID := journey.manager.registration.Binding.BindingID
		before := journey.storedRegistrations(t)[managerBindingID]
		report, err := journey.reconciler.Report(ctx, journey.manifest.ServerID, "test")
		if err != nil {
			t.Fatal(err)
		}
		for _, observation := range report.ContinuityRegistrations {
			if observation.Binding.BindingID == managerBindingID {
				t.Fatalf("revoked/disabled row was serialized: %#v", observation)
			}
		}
		after := journey.storedRegistrations(t)[managerBindingID]
		if !reflect.DeepEqual(before, after) || after.ReceiptDigest != "" || after.Manifest.DesiredState != "revoked" ||
			after.Manifest.ContinuityEnabled {
			t.Fatalf("revoked/disabled row changed across report construction: %#v", after)
		}
	})

	contradictions := []struct {
		name   string
		mutate func(value *state.LocalContinuityRegistration)
	}{
		{name: "revoked_enabled_fails_closed", mutate: func(value *state.LocalContinuityRegistration) {
			value.Manifest.ContinuityEnabled = true
		}},
		{name: "active_disabled_fails_closed", mutate: func(value *state.LocalContinuityRegistration) {
			value.Manifest.DesiredState = "active"
			value.Manifest.ContinuityEnabled = false
		}},
		{name: "unknown_desired_state_fails_closed", mutate: func(value *state.LocalContinuityRegistration) {
			value.Manifest.DesiredState = "paused"
		}},
		{name: "invalid_binding_fails_closed", mutate: func(value *state.LocalContinuityRegistration) {
			value.Manifest.Binding.BindingRevision = 0
		}},
		{name: "invalid_scope_revision_fails_closed", mutate: func(value *state.LocalContinuityRegistration) {
			value.Manifest.ScopeRevision = 0
		}},
		{name: "invalid_identity_fails_closed", mutate: func(value *state.LocalContinuityRegistration) {
			value.Manifest.Identity.SandboxGeneration = 0
		}},
	}
	for _, test := range contradictions {
		t.Run(test.name, func(t *testing.T) {
			journey := settled(t)
			managerBindingID := journey.manager.registration.Binding.BindingID
			value := journey.storedRegistrations(t)[managerBindingID]
			test.mutate(&value)
			if err := journey.store.PutContinuityRegistration(ctx, value); err != nil {
				t.Fatal(err)
			}
			if _, err := journey.reconciler.Report(ctx, journey.manifest.ServerID, "test"); err == nil {
				t.Fatalf("contradictory local manifest was silently omitted instead of failing closed: %#v", value)
			}
		})
	}

	t.Run("local_revoked_row_empty_digest_is_invalid", func(t *testing.T) {
		journey := settled(t)
		item := model.ContinuityRegistrationReportV1{
			ContinuityRegistrationV1: revokedTuple(journey.manager.registration),
			ObservedStatus:           "revoked",
		}
		payload, err := json.Marshal(map[string]any{"continuityRegistrations": []model.ContinuityRegistrationReportV1{item}})
		if err != nil {
			t.Fatal(err)
		}
		verdict := backend.applyRegistrationReport(t, payload, journey.backendV21Rows(t))
		if verdict.Error != nil {
			t.Logf("frozen backend v21 verdict for the empty receipt digest: HTTP %d %s: %s",
				verdict.Error.Status, verdict.Error.Code, verdict.Error.Message)
		}
		if verdict.Accepted || verdict.Error.Status != 400 || verdict.Error.Code != "invalid_runtime_report" ||
			verdict.Error.Message != "Runtime report is invalid." {
			t.Fatalf("empty receipt digest verdict = %#v", verdict)
		}
	})
	t.Run("synthetic_revoked_digest_still_conflicts", func(t *testing.T) {
		journey := settled(t)
		item := model.ContinuityRegistrationReportV1{
			ContinuityRegistrationV1: revokedTuple(journey.manager.registration),
			ObservedStatus:           "revoked",
			ServiceGeneration:        1,
			ReceiptDigest:            "sha256:" + strings.Repeat("a", 64),
		}
		payload, err := json.Marshal(map[string]any{"continuityRegistrations": []model.ContinuityRegistrationReportV1{item}})
		if err != nil {
			t.Fatal(err)
		}
		verdict := backend.applyRegistrationReport(t, payload, journey.backendV21Rows(t))
		if verdict.Error != nil {
			t.Logf("frozen backend v21 verdict for the synthetic receipt digest: HTTP %d %s: %s",
				verdict.Error.Status, verdict.Error.Code, verdict.Error.Message)
		}
		if verdict.Accepted || verdict.Error.Status != 409 || verdict.Error.Code != "runtime_report_conflict" ||
			verdict.Error.Message != "Registration terminal receipt changed." {
			t.Fatalf("synthetic receipt digest verdict = %#v", verdict)
		}
	})
}
