package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// acknowledgementRegistration is one durable rev-1 continuity registration
// plus the exact host source observation it was verified against.
type acknowledgementRegistration struct {
	registration model.ContinuityRegistrationV1
	source       model.ContinuitySourceReportV1
}

// acknowledgementJourney reproduces the proven post-v21 live state at the real
// Reconciler boundary (owner decision A41):
//
//   - the local store holds rev-1 continuity registrations (finish scope 2,
//     manager scope 2, ba1b scope 1) all observed verified/active;
//   - the local continuity outbox holds six authentic terminal operation rows
//     (2 accepted, 3 failed, 1 outcome_unknown) for the finish binding that the
//     backend already terminalized and that the fresh manifest no longer
//     carries;
//   - applied revision is 64 while the fresh desired manifest is 67 and
//     carries the ordinary revocation/replacement state (finish rev 1 revoked,
//     a finish replacement registration pending, manager rev 1 revoked, ba1b
//     unchanged active);
//   - the manifest's managed service cannot enroll only because its workspace
//     selection is stale, so the ordinary pre-A41 pass aborts before the
//     end-of-pass continuity apply.
type acknowledgementJourney struct {
	fixture      producerFixture
	now          func() time.Time
	databasePath string
	accessPath   string
	store        *state.Store
	catalog      *workspacecatalog.Catalog
	control      *fakeManagedControl
	runtime      *fakeManagedRuntime
	coordinator  *continuity.Coordinator
	reconciler   *Reconciler
	manifest     model.Manifest
	finish       acknowledgementRegistration
	replacement  acknowledgementRegistration
	manager      acknowledgementRegistration
	ba1b         acknowledgementRegistration
	echoes       []model.ContinuityOperationReportV1
	// A43 source-observation wiring: an optional handoff control (so a deferred
	// handoff can be proven not to suppress the observation phase) and an
	// optional supervisor status probe hook with its recorded instances.
	handoff        ContinuationHandoffControl
	statusProbe    func(sandboxID string, request map[string]any) ([]byte, error)
	probeInstances []string
}

func acknowledgementDigest(payload []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}

// acknowledgementRegistrationFixture derives one complete registration tuple
// from a stable fixture name so every field stays inside the same identity and
// binding fence the live records used.
func acknowledgementRegistrationFixture(name, role string, scopeRevision int64) acknowledgementRegistration {
	workID := "work_" + name
	projectID := "project_" + name
	epoch := "epoch_" + name
	serviceID := "service_" + name
	sourceID := "source_" + name
	sessionID := "ses_" + name
	nativeSum := sha256.Sum256([]byte("native|" + name))
	nativeProjectID := hex.EncodeToString(nativeSum[:20])
	locationDigest := acknowledgementDigest([]byte("native-location|" + name))
	binding := model.ContinuityBindingV1{
		BindingID: "binding_" + name, BindingRevision: 1,
		RegisteredSourceID: sourceID, ServiceRegistrationID: serviceID,
		NativeSessionID: sessionID, NativeProjectID: nativeProjectID, NativeLocationDigest: locationDigest,
	}
	identity := model.ContinuityIdentityV1{
		WorkID: workID, ProjectID: projectID, SandboxID: "sbx_managedservice00000001",
		WorkspaceEpoch: epoch, SandboxGeneration: 2, ExpectedRevision: 1,
	}
	return acknowledgementRegistration{
		registration: model.ContinuityRegistrationV1{
			FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true,
			ScopeRevision: scopeRevision, Identity: identity, Binding: binding,
		},
		source: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: sourceID, ServiceRegistrationID: serviceID,
			ServiceGeneration: 1, ProjectID: projectID, SandboxID: identity.SandboxID,
			SandboxGeneration: identity.SandboxGeneration, WorkspaceEpoch: epoch,
			NativeSessionID: sessionID, NativeProjectID: nativeProjectID, NativeLocationDigest: locationDigest,
			ScopeRevision: scopeRevision, Role: role, ProfileRevision: 1, InstructionRevision: 1,
			Availability: "available", LastObservedAt: time.Date(2026, 9, 27, 17, 0, 0, 0, time.UTC),
		},
	}
}

// acknowledgementRegistrationReceiptDigest mirrors the receipt the ordinary
// Coordinator.Apply writes for a verified registration: the digest of the
// registration tuple paired with the exact source observation.
func acknowledgementRegistrationReceiptDigest(registration model.ContinuityRegistrationV1, source model.ContinuitySourceReportV1) string {
	payload, _ := json.Marshal(struct {
		Registration model.ContinuityRegistrationV1 `json:"registration"`
		Source       model.ContinuitySourceReportV1 `json:"source"`
	}{Registration: registration, Source: source})
	return acknowledgementDigest(payload)
}

func seedAcknowledgementRegistration(t *testing.T, store *state.Store, value acknowledgementRegistration) {
	t.Helper()
	ctx := context.Background()
	if err := store.PutContinuitySource(ctx, state.LocalContinuitySource{
		Report: value.source, Root: t.TempDir(), Instance: "default",
		Lifecycle: "stopped", LifecycleRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
		Manifest: value.registration, ObservedStatus: "verified", ServiceGeneration: value.source.ServiceGeneration,
		ReceiptDigest: acknowledgementRegistrationReceiptDigest(value.registration, value.source),
	}); err != nil {
		t.Fatal(err)
	}
}

// acknowledgementEchoes builds the six authentic terminal outbox rows of the
// proven live state. The accepted rows carry the exact receipt digest the
// ordinary operation path computes over its own report payload.
func acknowledgementEchoes(finish acknowledgementRegistration) []model.ContinuityOperationReportV1 {
	reports := make([]model.ContinuityOperationReportV1, 0, 6)
	for index := 1; index <= 6; index++ {
		report := model.ContinuityOperationReportV1{
			FormatVersion: 1, OperationID: fmt.Sprintf("op_finish_echo%04d", index),
			Action: "capture_checkpoint", ScopeRevision: finish.registration.ScopeRevision,
			BoundaryKind: "initial", Identity: finish.registration.Identity, Binding: finish.registration.Binding,
			RequestDigest: acknowledgementDigest([]byte(fmt.Sprintf("echo-request-%d", index))),
		}
		switch {
		case index <= 2:
			report.Status = "accepted"
			report.CheckpointID = fmt.Sprintf("checkpoint_%032x", index)
			report.CaptureID = fmt.Sprintf("capture_%032x", index)
			report.ManifestDigest = acknowledgementDigest([]byte(fmt.Sprintf("echo-manifest-%d", index)))
			report.Bytes = int64(index) * 1024
			report.ObjectCount = index
			report.ReceiptDigest = acknowledgementDigest(mustMarshalReport(report))
		case index <= 5:
			report.Status = "failed"
			report.LastError = &model.ItemError{Code: "capture_failed"}
		default:
			report.Status = "outcome_unknown"
			report.LastError = &model.ItemError{Code: "boundary_outcome_unknown"}
		}
		reports = append(reports, report)
	}
	return reports
}

func mustMarshalReport(report model.ContinuityOperationReportV1) []byte {
	payload, err := json.Marshal(report)
	if err != nil {
		panic(err)
	}
	return payload
}

func seedAcknowledgementEchoes(t *testing.T, store *state.Store, reports []model.ContinuityOperationReportV1) {
	t.Helper()
	for _, report := range reports {
		if err := store.PutContinuityOperationReport(context.Background(), report); err != nil {
			t.Fatal(err)
		}
	}
}

func newAcknowledgementJourney(t *testing.T) *acknowledgementJourney {
	t.Helper()
	fixture := loadProducerFixture(t)
	fixture.ServiceManifest.Identity.Role = "manager"
	fixture.ServiceManifest.Identity.SandboxGeneration = 2
	fixture.SetupManifest.SandboxGeneration = 2
	fixture.InstructionRequest.SandboxGeneration = 2
	fixture.EnrollmentRequest.SandboxGeneration = 2
	now := func() time.Time { return time.Date(2026, 9, 27, 17, 0, 30, 0, time.UTC) }
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	finish := acknowledgementRegistrationFixture("finish_rev1_00001", "worker", 2)
	// The backend's activate_binding keeps one binding row and advances its
	// revision: the successor shares the binding ID, the registered source and
	// every other binding field, and only the revision moves to 2.
	successor := finish
	successor.registration.Binding.BindingRevision = 2
	journey := &acknowledgementJourney{
		fixture: fixture, now: now, databasePath: databasePath,
		accessPath:  filepath.Join(t.TempDir(), "authorized_keys"),
		store:       store,
		manager:     acknowledgementRegistrationFixture("manager_rev1_0001", "manager", 2),
		ba1b:        acknowledgementRegistrationFixture("ba1b_rev1_0000001", "worker", 1),
		finish:      finish,
		replacement: successor,
	}
	t.Cleanup(func() { _ = journey.store.Close() })
	seedReadyProfile(t, store, fixture.SetupManifest)
	// The documented Workspaces.Ensure layout: a real backing image file next
	// to the mountpoint anchor the catalog attests.
	sandboxDirectory := t.TempDir()
	imagePath := filepath.Join(sandboxDirectory, "workspace.ext4")
	if err := os.WriteFile(imagePath, []byte("workspace image fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(sandboxDirectory, "workspace")
	if err := os.Mkdir(anchor, 0700); err != nil {
		t.Fatal(err)
	}
	catalog := &workspacecatalog.Catalog{State: store, Now: now}
	workspace, err := catalog.EnsureDefault(context.Background(), workspacecatalog.DefaultProjectRequest{
		Anchor: anchor, ServerID: fixture.ServiceManifest.Identity.ServerID,
		TeamID: fixture.ServiceManifest.Identity.TeamID, MemberID: fixture.ServiceManifest.Identity.MemberID,
		SandboxID: fixture.ServiceManifest.Identity.SandboxID, SandboxGeneration: 2,
		ServiceRegistrationID: fixture.ServiceManifest.Identity.ServiceRegistrationID,
		AllocationDigest:      fixture.WorkspaceRequestManifest.AllocationDigest,
		ConfigDigest:          fixture.ServiceManifest.ConfigDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.ServiceManifest.Workspace.SelectionID = workspace.Report.SelectionID
	fixture.ServiceManifest.Workspace.ProjectID = workspace.Report.ProjectID
	fixture.ServiceManifest.Workspace.WorkspaceEpoch = workspace.Report.WorkspaceEpoch
	fixture.ServiceManifest.Workspace.RootAttestation = workspace.Report.RootAttestation
	journey.catalog = catalog
	seedAcknowledgementRegistration(t, store, journey.finish)
	seedAcknowledgementRegistration(t, store, journey.manager)
	seedAcknowledgementRegistration(t, store, journey.ba1b)
	journey.echoes = acknowledgementEchoes(journey.finish)
	seedAcknowledgementEchoes(t, store, journey.echoes)
	if err := store.SetRevision(context.Background(), 64); err != nil {
		t.Fatal(err)
	}
	finishRevoked := revokedTuple(journey.finish.registration)
	managerRevoked := revokedTuple(journey.manager.registration)
	hostCapacity := model.Resources{CPUMillicores: 2000, MemoryMiB: 4096, WorkspaceDiskGiB: 20, PIDs: 128}
	journey.manifest = model.Manifest{
		ServerID: fixture.ServiceManifest.Identity.ServerID, DesiredRevision: 67, Capacity: hostCapacity,
		ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
		Sandboxes: []model.Sandbox{{
			ID: fixture.ServiceManifest.Identity.SandboxID, Name: "managed-service",
			DesiredState: "running", Generation: 2, Lifetime: "persistent",
			Resources: model.Resources{CPUMillicores: 1000, MemoryMiB: 1024, WorkspaceDiskGiB: 2, PIDs: 64},
		}},
		SetupOperations: []model.SetupOperation{fixture.SetupManifest},
		ManagedServices: []model.ManagedServiceV1{fixture.ServiceManifest},
		ContinuityRegistrations: []model.ContinuityRegistrationV1{
			finishRevoked, journey.replacement.registration, managerRevoked, journey.ba1b.registration,
		},
	}
	journey.control = &fakeManagedControl{fixture: fixture}
	journey.control.enrollErr = errors.New("managed workspace selection received_at is stale")
	journey.runtime = &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture}
	journey.coordinator = &continuity.Coordinator{
		Store: store, Registry: continuity.StateRegistry{Store: store, Now: now}, Now: now,
	}
	journey.reconciler = journey.newReconciler()
	return journey
}

func (journey *acknowledgementJourney) newReconciler() *Reconciler {
	journey.catalog = &workspacecatalog.Catalog{State: journey.store, Now: journey.now}
	journey.coordinator = &continuity.Coordinator{
		Store: journey.store, Registry: continuity.StateRegistry{Store: journey.store, Now: journey.now}, Now: journey.now,
	}
	journey.runtime = &fakeManagedRuntime{
		store: journey.store, serviceID: journey.fixture.ServiceManifest.Identity.ServiceRegistrationID,
		fixture: journey.fixture,
	}
	if journey.statusProbe != nil {
		journey.runtime.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
			instance, _ := request["instance"].(string)
			journey.probeInstances = append(journey.probeInstances, instance)
			return journey.statusProbe(sandboxID, request)
		}
	}
	return &Reconciler{
		Store: journey.store, Engine: &contractEngine{}, Workspaces: &contractWorkspaces{},
		Access:       access.Renderer{Path: journey.accessPath},
		HostCapacity: journey.manifest.Capacity, ServerID: journey.fixture.ServiceManifest.Identity.ServerID, Now: journey.now,
		ContinuityControl: journey.coordinator,
		ManagedCatalog:    journey.catalog, ManagedControl: journey.control, ManagedRuntime: journey.runtime,
		ContinuationHandoff: journey.handoff,
	}
}

// restart closes and reopens the durable store and rebuilds the real
// Reconciler/continuity wiring, so every acknowledgement claim is proven across
// a process boundary rather than in-memory state.
func (journey *acknowledgementJourney) restart(t *testing.T) {
	t.Helper()
	if err := journey.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(journey.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	journey.store = store
	journey.reconciler = journey.newReconciler()
}

func (journey *acknowledgementJourney) storedRegistrations(t *testing.T) map[string]state.LocalContinuityRegistration {
	t.Helper()
	values, err := journey.store.ContinuityRegistrations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]state.LocalContinuityRegistration, len(values))
	for _, value := range values {
		result[value.Manifest.Binding.BindingID] = value
	}
	return result
}

func (journey *acknowledgementJourney) outbox(t *testing.T) []model.ContinuityOperationReportV1 {
	t.Helper()
	values, err := journey.store.ContinuityOperationReports(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return values
}

// wantRegistrationReports is the registration observation set the fresh
// manifest must yield exactly once, constructed independently of the stored
// rows so a stale post-failure report can never compare equal to itself. The
// locally retained revoked/disabled manager tuple is deliberately absent: the
// backend already revoked it and its exact local form is not a reportable
// current desired-active registration.
func (journey *acknowledgementJourney) wantRegistrationReports(t *testing.T) []model.ContinuityRegistrationReportV1 {
	t.Helper()
	want := []model.ContinuityRegistrationReportV1{
		{
			ContinuityRegistrationV1: journey.replacement.registration,
			ObservedStatus:           "verified",
			ServiceGeneration:        journey.finish.source.ServiceGeneration,
			ReceiptDigest:            acknowledgementRegistrationReceiptDigest(journey.replacement.registration, journey.finish.source),
		},
		{
			ContinuityRegistrationV1: journey.ba1b.registration,
			ObservedStatus:           "verified",
			ServiceGeneration:        journey.ba1b.source.ServiceGeneration,
			ReceiptDigest:            acknowledgementRegistrationReceiptDigest(journey.ba1b.registration, journey.ba1b.source),
		},
	}
	sort.Slice(want, func(left, right int) bool {
		return want[left].Binding.BindingID < want[right].Binding.BindingID
	})
	return want
}

// assertPostFailureCurrentState proves the managed-service failure stayed
// visible while every current registration was adopted or revoked exactly once
// and every acknowledged terminal echo was retired exactly once, without any
// helper execution or applied-revision advance.
func (journey *acknowledgementJourney) assertPostFailureCurrentState(t *testing.T, passError error) {
	t.Helper()
	serviceID := journey.fixture.ServiceManifest.Identity.ServiceRegistrationID
	if passError == nil || !strings.Contains(passError.Error(), "apply managed services: managed service "+serviceID) ||
		!strings.Contains(passError.Error(), "stale") {
		t.Errorf("stale-selection managed-service failure was not preserved: %v", passError)
	}
	revision, err := journey.store.Revision(context.Background())
	if err != nil || revision != 64 {
		t.Errorf("failed pass applied revision = %d, %v; want the unchanged 64", revision, err)
	}
	service, err := journey.store.ManagedService(context.Background(), serviceID)
	if err != nil || service == nil || service.Phase != "failed" || service.ErrorCode != "enrollment_unavailable" {
		t.Errorf("failed managed service = %#v, %v; want visible enrollment_unavailable", service, err)
	}
	registrations := journey.storedRegistrations(t)
	if len(registrations) != 3 {
		t.Errorf("stored registrations = %d %#v, want the three current manifest bindings", len(registrations), registrations)
	}
	finish := registrations[journey.finish.registration.Binding.BindingID]
	if finish.ObservedStatus != "verified" || finish.Manifest.DesiredState != "active" ||
		finish.Manifest.Binding.BindingRevision != journey.replacement.registration.Binding.BindingRevision ||
		!reflect.DeepEqual(finish.Manifest, journey.replacement.registration) ||
		finish.ReceiptDigest != acknowledgementRegistrationReceiptDigest(journey.replacement.registration, journey.finish.source) {
		t.Errorf("in-place binding revision successor was not the durable outcome: %#v", finish)
	}
	if finish.Manifest.Binding.BindingID != journey.finish.registration.Binding.BindingID {
		t.Errorf("binding revision succession moved the binding ID: %#v", finish.Manifest.Binding)
	}
	manager := registrations[journey.manager.registration.Binding.BindingID]
	if manager.ObservedStatus != "revoked" || manager.Manifest.DesiredState != "revoked" ||
		!reflect.DeepEqual(manager.Manifest, revokedTuple(journey.manager.registration)) {
		t.Errorf("revoked manager rev-1 registration = %#v", manager)
	}
	ba1b := registrations[journey.ba1b.registration.Binding.BindingID]
	if ba1b.ObservedStatus != "verified" || !reflect.DeepEqual(ba1b.Manifest, journey.ba1b.registration) ||
		ba1b.ReceiptDigest != acknowledgementRegistrationReceiptDigest(journey.ba1b.registration, journey.ba1b.source) {
		t.Errorf("unchanged ba1b rev-1 registration = %#v", ba1b)
	}
	if pending := journey.outbox(t); len(pending) != 0 {
		t.Errorf("acknowledged terminal echoes still in the outbox: %d %#v", len(pending), pending)
	}
	retirements, err := journey.store.ContinuityOperationRetirements(context.Background())
	if err != nil || len(retirements) != len(journey.echoes) {
		t.Errorf("terminal echo retirements = %#v, %v; want all six", retirements, err)
	} else {
		retired := map[string]state.ContinuityOperationRetirement{}
		for _, retirement := range retirements {
			retired[retirement.Report.OperationID] = retirement
		}
		for _, echo := range journey.echoes {
			retirement, ok := retired[echo.OperationID]
			if !ok {
				t.Errorf("echo %s was not retained as an acknowledged retirement", echo.OperationID)
				continue
			}
			if retirement.Report.RequestDigest != echo.RequestDigest ||
				!bytes.Equal(mustMarshalReport(retirement.Report), mustMarshalReport(echo)) {
				t.Errorf("retained echo %s drifted from its byte-equal receipt:\n got %s\nwant %s",
					echo.OperationID, mustMarshalReport(retirement.Report), mustMarshalReport(echo))
			}
		}
	}
	if len(journey.runtime.invocations) != 0 || journey.runtime.enrollmentCalls != 0 || journey.runtime.startCalls != 0 {
		t.Errorf("registration acknowledgement or retirement executed helpers/actions: %#v", journey.runtime.invocations)
	}
	// The first current report must be the conflict-free shape the control
	// plane accepts: exactly the current registration observations, every one
	// byte-equal to its fresh manifest tuple, and no acknowledged terminal echo.
	report, err := journey.reconciler.Report(context.Background(), journey.manifest.ServerID, "test")
	if err != nil {
		t.Fatalf("report derivation failed: %v", err)
	}
	if report.AppliedRevision != 64 {
		t.Errorf("report applied revision = %d, want 64", report.AppliedRevision)
	}
	want := journey.wantRegistrationReports(t)
	got := append([]model.ContinuityRegistrationReportV1(nil), report.ContinuityRegistrations...)
	sort.Slice(got, func(left, right int) bool { return got[left].Binding.BindingID < got[right].Binding.BindingID })
	if !reflect.DeepEqual(got, want) {
		t.Errorf("current registration report shape drifted:\n got %#v\nwant %#v", got, want)
	}
	for _, observation := range report.ContinuityRegistrations {
		if observation.Binding.BindingID == journey.manager.registration.Binding.BindingID {
			t.Errorf("locally retained revoked manager tuple was serialized: %#v", observation)
		}
	}
	if len(report.ContinuityOperations) != 0 {
		t.Errorf("report re-emitted acknowledged terminal echoes: %d %#v", len(report.ContinuityOperations), report.ContinuityOperations)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	if string(document["continuityOperations"]) != "[]" || string(document["continuityRegistrations"]) == "[]" {
		t.Errorf("report wire shape is not the current closed shape: %s", payload)
	}
}

func revokedTuple(registration model.ContinuityRegistrationV1) model.ContinuityRegistrationV1 {
	// The backend revocation writes both fields: desiredState revoked and
	// continuityEnabled false. A revoked+enabled or active+disabled tuple is
	// contradictory and must never be treated as a valid local manifest.
	revoked := registration
	revoked.DesiredState = "revoked"
	revoked.ContinuityEnabled = false
	return revoked
}

// TestReconcileAcknowledgesCurrentManifestBeforeManagedServiceFailure is the
// A41 RED/GREEN journey. RED: the failure-prone managed-service enrollment
// aborts the pass before the end-of-pass continuity apply, so the next report
// re-emits revoked rev-1 registrations and all six terminal echoes. GREEN: the
// pre-failure acknowledgement phase adopts/revokes exactly the manifest
// registrations and retires exactly the acknowledged terminal echoes, while
// the pass still fails, the applied revision stays 64, and the report carries
// only current observations. A fresh-selection pass then converges through the
// ordinary lifecycle to desired revision 67.
func TestReconcileAcknowledgesCurrentManifestBeforeManagedServiceFailure(t *testing.T) {
	ctx := context.Background()
	journey := newAcknowledgementJourney(t)
	err := journey.reconciler.Reconcile(ctx, journey.manifest)
	journey.assertPostFailureCurrentState(t, err)

	// Reopen/restart: the acknowledged state is durable, adoption and
	// retirement are idempotent, and the same stale-selection failure stays
	// visible without duplicating any tuple or receipt.
	journey.restart(t)
	err = journey.reconciler.Reconcile(ctx, journey.manifest)
	journey.assertPostFailureCurrentState(t, err)

	// The next naturally successful pass must converge through the ordinary
	// end-of-pass lifecycle, not a special bypass.
	journey.control.enrollErr = nil
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
		t.Fatalf("fresh-selection pass did not complete: %v", err)
	}
	revision, err := journey.store.Revision(ctx)
	if err != nil || revision != journey.manifest.DesiredRevision {
		t.Fatalf("converged applied revision = %d, %v; want %d", revision, err, journey.manifest.DesiredRevision)
	}
	service, err := journey.store.ManagedService(ctx, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if err != nil || service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" {
		t.Fatalf("enrollment did not complete through the ordinary lifecycle: %#v %v", service, err)
	}
	registrations := journey.storedRegistrations(t)
	if len(registrations) != 3 ||
		registrations[journey.finish.registration.Binding.BindingID].Manifest.Binding.BindingRevision != 2 ||
		registrations[journey.finish.registration.Binding.BindingID].ObservedStatus != "verified" ||
		registrations[journey.manager.registration.Binding.BindingID].ObservedStatus != "revoked" {
		t.Fatalf("successful pass changed the adopted registration observations: %#v", registrations)
	}
	if pending := journey.outbox(t); len(pending) != 0 {
		t.Fatalf("successful pass re-created acknowledged echoes: %#v", pending)
	}
	retirements, err := journey.store.ContinuityOperationRetirements(ctx)
	if err != nil || len(retirements) != len(journey.echoes) {
		t.Fatalf("successful pass changed the retirement history: %#v %v", retirements, err)
	}
	if len(journey.runtime.invocations) == 0 {
		t.Fatal("successful pass skipped the ordinary managed-service lifecycle")
	}
	// A restart after convergence replays the same current shape exactly once.
	journey.restart(t)
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
		t.Fatalf("post-convergence restart pass did not replay: %v", err)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != 67 {
		t.Fatalf("post-convergence replay revision = %d, %v; want 67", revision, err)
	}
	if retirements, err := journey.store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != 6 {
		t.Fatalf("post-convergence replay duplicated retirements: %#v %v", retirements, err)
	}
}

// TestReconcileKeepsRegressedManifestFailClosedBeforeAcknowledgement proves the
// phase never runs behind a stale or regressed manifest: the existing
// manifest/server/revision gate refuses the pass before any registration or
// outbox write.
func TestReconcileKeepsRegressedManifestFailClosedBeforeAcknowledgement(t *testing.T) {
	ctx := context.Background()
	journey := newAcknowledgementJourney(t)
	regressed := journey.manifest
	regressed.DesiredRevision = 63
	err := journey.reconciler.Reconcile(ctx, regressed)
	if err == nil || !strings.Contains(err.Error(), "manifest revision moved backwards") {
		t.Fatalf("regressed manifest was not refused before acknowledgement: %v", err)
	}
	registrations := journey.storedRegistrations(t)
	finish := registrations[journey.finish.registration.Binding.BindingID]
	if len(registrations) != 3 || finish.ObservedStatus != "verified" || finish.Manifest.DesiredState != "active" {
		t.Fatalf("regressed manifest changed registrations: %#v", registrations)
	}
	if pending := journey.outbox(t); len(pending) != len(journey.echoes) {
		t.Fatalf("regressed manifest retired terminal echoes: %#v", pending)
	}
	if retirements, err := journey.store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != 0 {
		t.Fatalf("regressed manifest wrote retirements: %#v %v", retirements, err)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != 64 {
		t.Fatalf("regressed manifest changed the applied revision: %d %v", revision, err)
	}
}

// TestReconcileKeepsAmbiguousBindingSuccessionFailClosed proves the manifest
// gate accepts only the exact backend revision-succession shape. Equal
// revisions, a revision jump, an inconsistent binding tuple, an inconsistent
// work fence and a scope regression are all refused before any registration or
// outbox write.
func TestReconcileKeepsAmbiguousBindingSuccessionFailClosed(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		mutate func(journey *acknowledgementJourney) model.ContinuityRegistrationV1
	}{
		{name: "equal_revision", mutate: func(journey *acknowledgementJourney) model.ContinuityRegistrationV1 {
			successor := journey.replacement.registration
			successor.Binding.BindingRevision = journey.finish.registration.Binding.BindingRevision
			return successor
		}},
		{name: "revision_jump", mutate: func(journey *acknowledgementJourney) model.ContinuityRegistrationV1 {
			successor := journey.replacement.registration
			successor.Binding.BindingRevision = journey.finish.registration.Binding.BindingRevision + 2
			return successor
		}},
		{name: "inconsistent_binding_tuple", mutate: func(journey *acknowledgementJourney) model.ContinuityRegistrationV1 {
			successor := journey.replacement.registration
			successor.Binding.RegisteredSourceID = "source_ambiguoussuccess01"
			return successor
		}},
		{name: "inconsistent_work_fence", mutate: func(journey *acknowledgementJourney) model.ContinuityRegistrationV1 {
			successor := journey.replacement.registration
			successor.Identity.WorkID = "work_ambiguoussuccess001"
			return successor
		}},
		{name: "scope_regression", mutate: func(journey *acknowledgementJourney) model.ContinuityRegistrationV1 {
			successor := journey.replacement.registration
			successor.ScopeRevision = journey.finish.registration.ScopeRevision - 1
			return successor
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			journey := newAcknowledgementJourney(t)
			manifest := journey.manifest
			manifest.ContinuityRegistrations = append([]model.ContinuityRegistrationV1(nil), journey.manifest.ContinuityRegistrations...)
			manifest.ContinuityRegistrations[1] = test.mutate(journey)
			err := journey.reconciler.Reconcile(ctx, manifest)
			if err == nil || !strings.Contains(err.Error(), "duplicate continuity registration") {
				t.Fatalf("ambiguous binding succession was not refused: %v", err)
			}
			registrations := journey.storedRegistrations(t)
			finish := registrations[journey.finish.registration.Binding.BindingID]
			if len(registrations) != 3 || finish.ObservedStatus != "verified" ||
				!reflect.DeepEqual(finish.Manifest, journey.finish.registration) {
				t.Fatalf("refused succession changed registrations: %#v", registrations)
			}
			if pending := journey.outbox(t); len(pending) != len(journey.echoes) {
				t.Fatalf("refused succession retired echoes: %#v", pending)
			}
			if retirements, err := journey.store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != 0 {
				t.Fatalf("refused succession wrote retirements: %#v %v", retirements, err)
			}
			if revision, err := journey.store.Revision(ctx); err != nil || revision != 64 {
				t.Fatalf("refused succession changed the applied revision: %d %v", revision, err)
			}
		})
	}
}

// TestReconcileAdoptsTheActiveSuccessorRegardlessOfManifestOrder proves the
// in-place binding revision is applied in revision order: a manifest that
// lists the active successor before its revoked predecessor still ends on the
// successor, and the revoked predecessor still owns the six terminal echoes.
func TestReconcileAdoptsTheActiveSuccessorRegardlessOfManifestOrder(t *testing.T) {
	ctx := context.Background()
	journey := newAcknowledgementJourney(t)
	manifest := journey.manifest
	manifest.ContinuityRegistrations = []model.ContinuityRegistrationV1{
		journey.replacement.registration,
		revokedTuple(journey.finish.registration),
		revokedTuple(journey.manager.registration),
		journey.ba1b.registration,
	}
	err := journey.reconciler.Reconcile(ctx, manifest)
	if err == nil || !strings.Contains(err.Error(), "apply managed services:") {
		t.Fatalf("stale-selection service failure was not preserved: %v", err)
	}
	registrations := journey.storedRegistrations(t)
	finish := registrations[journey.finish.registration.Binding.BindingID]
	if len(registrations) != 3 || finish.Manifest.Binding.BindingRevision != 2 ||
		finish.ObservedStatus != "verified" || !reflect.DeepEqual(finish.Manifest, journey.replacement.registration) {
		t.Fatalf("reversed manifest order lost the active successor: %#v", finish)
	}
	if pending := journey.outbox(t); len(pending) != 0 {
		t.Fatalf("reversed manifest order did not retire the revoked predecessor's echoes: %#v", pending)
	}
}

// TestReconcileRetiresAcknowledgedEchoesForAnOmittedRegistration proves the
// durable local ownership half of the retirement fence: a terminal echo whose
// registration the current manifest no longer carries is still owned by the
// durable registration row read before the manifest applied.
func TestReconcileRetiresAcknowledgedEchoesForAnOmittedRegistration(t *testing.T) {
	ctx := context.Background()
	journey := newAcknowledgementJourney(t)
	manifest := journey.manifest
	manifest.ContinuityRegistrations = []model.ContinuityRegistrationV1{
		revokedTuple(journey.manager.registration),
		journey.ba1b.registration,
	}
	err := journey.reconciler.Reconcile(ctx, manifest)
	if err == nil || !strings.Contains(err.Error(), "apply managed services:") {
		t.Fatalf("stale-selection service failure was not preserved: %v", err)
	}
	registrations := journey.storedRegistrations(t)
	finish := registrations[journey.finish.registration.Binding.BindingID]
	if len(registrations) != 3 || finish.ObservedStatus != "verified" ||
		!reflect.DeepEqual(finish.Manifest, journey.finish.registration) {
		t.Fatalf("omitted registration row changed: %#v", registrations)
	}
	if pending := journey.outbox(t); len(pending) != 0 {
		t.Fatalf("locally owned acknowledged echoes were not retired: %#v", pending)
	}
	if retirements, err := journey.store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != len(journey.echoes) {
		t.Fatalf("locally owned retirements = %#v %v", retirements, err)
	}
}

// TestReconcileRetiresAcknowledgedEchoesForTheRevokedPredecessorAfterReapply
// reproduces a crash between the registration apply and the retirement: a
// previous pass already replaced the local row with the active successor, so
// only the same fresh manifest's revoked predecessor still names the owner of
// the six terminal echoes. The acknowledgement phase must still retire them
// and keep the successor as the durable outcome.
func TestReconcileRetiresAcknowledgedEchoesForTheRevokedPredecessorAfterReapply(t *testing.T) {
	ctx := context.Background()
	journey := newAcknowledgementJourney(t)
	// The previous pass applied the real succession without the retirement.
	if err := journey.coordinator.Apply(ctx, journey.manifest); err != nil {
		t.Fatal(err)
	}
	stored := journey.storedRegistrations(t)
	if finish := stored[journey.finish.registration.Binding.BindingID]; finish.Manifest.Binding.BindingRevision != 2 {
		t.Fatalf("reapply did not reach the active successor: %#v", finish)
	}
	if pending := journey.outbox(t); len(pending) != len(journey.echoes) {
		t.Fatalf("pre-acknowledgement outbox = %d, want the six echoes", len(pending))
	}
	err := journey.reconciler.Reconcile(ctx, journey.manifest)
	if err == nil || !strings.Contains(err.Error(), "apply managed services:") {
		t.Fatalf("stale-selection service failure was not preserved: %v", err)
	}
	if pending := journey.outbox(t); len(pending) != 0 {
		t.Fatalf("revoked predecessor no longer owned its acknowledged echoes: %#v", pending)
	}
	if retirements, err := journey.store.ContinuityOperationRetirements(ctx); err != nil || len(retirements) != len(journey.echoes) {
		t.Fatalf("reapplied acknowledgement retirements = %#v %v", retirements, err)
	}
	stored = journey.storedRegistrations(t)
	if finish := stored[journey.finish.registration.Binding.BindingID]; finish.Manifest.Binding.BindingRevision != 2 ||
		!reflect.DeepEqual(finish.Manifest, journey.replacement.registration) {
		t.Fatalf("reapplied acknowledgement lost the active successor: %#v", finish)
	}
}

// acknowledgementNegativeCase seeds one ineligible terminal outbox row next to
// a positive control row. The positive control proves the acknowledgement
// phase ran; the ineligible row proves the exact predicate under test fails
// closed and leaves the row untouched.
type acknowledgementNegativeCase struct {
	name  string
	build func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(t *testing.T, journey *acknowledgementJourney) error)
}

func acknowledgementEchoTemplate(journey *acknowledgementJourney, operationID string) model.ContinuityOperationReportV1 {
	base := acknowledgementEchoes(journey.finish)[0]
	base.OperationID = operationID
	base.ReceiptDigest = acknowledgementDigest(mustMarshalReport(base))
	return base
}

func acknowledgementPositiveControl(journey *acknowledgementJourney) model.ContinuityOperationReportV1 {
	control := acknowledgementEchoTemplate(journey, "op_ack_control0001")
	control.CheckpointID = fmt.Sprintf("checkpoint_%032x", 99)
	control.CaptureID = fmt.Sprintf("capture_%032x", 99)
	control.ManifestDigest = acknowledgementDigest([]byte("ack-control-manifest"))
	control.ReceiptDigest = acknowledgementDigest(mustMarshalReport(control))
	return control
}

func TestReconcileRetiresOnlyAcknowledgedTerminalEchoes(t *testing.T) {
	ctx := context.Background()
	cases := []acknowledgementNegativeCase{
		{name: "applying_row_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_applying0001")
			row.Status = "applying"
			row.CheckpointID, row.CaptureID, row.ManifestDigest, row.ReceiptDigest = "", "", "", ""
			return row, nil
		}},
		{name: "unknown_status_row_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_registered0001")
			row.Status = "registered"
			row.CheckpointID, row.CaptureID, row.ManifestDigest, row.ReceiptDigest = "", "", "", ""
			return row, nil
		}},
		{name: "present_operation_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_present000001")
			journey.manifest.ContinuityOperations = []model.ContinuityOperationV1{{
				FormatVersion: 1, OperationID: row.OperationID, Action: "capture_checkpoint",
				RequestDigest: acknowledgementDigest([]byte("present-operation")),
				ScopeRevision: journey.ba1b.registration.ScopeRevision, BoundaryKind: "initial",
				Identity: journey.ba1b.registration.Identity, Binding: journey.ba1b.registration.Binding,
			}}
			return row, nil
		}},
		{name: "barrier_row_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(t *testing.T, journey *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_barrier0000001")
			return row, func(t *testing.T, journey *acknowledgementJourney) error {
				if err := journey.store.PutContinuityBarrier(context.Background(), row.OperationID, []byte(`{"owner":"capture"}`), []byte(`{}`)); err != nil {
					return err
				}
				return nil
			}
		}},
		{name: "live_local_operation_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(t *testing.T, journey *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_live0000000001")
			return row, func(t *testing.T, journey *acknowledgementJourney) error {
				ctx := context.Background()
				operation := state.LocalContinuityOperation{
					ID: row.OperationID + "_checkpoint", Kind: "checkpoint",
					Identity: row.Identity, RequestDigest: row.RequestDigest, State: "pending",
					Deadline: time.Now().UTC().Add(time.Minute),
				}
				if err := journey.store.PutContinuityOperation(ctx, operation); err != nil {
					return err
				}
				return journey.store.TransitionContinuityOperation(ctx, operation.ID, state.ContinuityTransition{From: "pending", To: "verifying"})
			}
		}},
		{name: "malformed_format_version_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_format00000001")
			row.FormatVersion = 0
			return row, nil
		}},
		{name: "malformed_request_digest_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_digest00000001")
			row.RequestDigest = "not-a-digest"
			return row, nil
		}},
		{name: "accepted_without_receipt_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_noreceipt000001")
			row.ReceiptDigest = ""
			return row, nil
		}},
		{name: "failed_without_error_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_noerror00000001")
			row.Status = "failed"
			row.CheckpointID, row.CaptureID, row.ManifestDigest, row.ReceiptDigest = "", "", "", ""
			row.LastError = nil
			return row, nil
		}},
		{name: "task_pair_mismatch_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_taskpair0000001")
			taskID := "task_ack000000000000001"
			row.Identity.TaskID = &taskID
			return row, nil
		}},
		{name: "foreign_binding_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_foreignbinding1")
			// The Work-level identity and scope still match the durable local
			// registration exactly; only the binding is foreign. The binding
			// fence alone must keep the row fail-closed.
			row.Binding.BindingID = "binding_ackforeign000001"
			row.Binding.RegisteredSourceID = "source_ackforeign000001"
			row.Binding.NativeSessionID = "ses_ackforeign000001"
			return row, nil
		}},
		{name: "foreign_work_identity_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_foreignidentity")
			row.Identity.WorkID = "work_ack_foreign000001"
			return row, nil
		}},
		{name: "scope_mismatch_retained", build: func(journey *acknowledgementJourney) (model.ContinuityOperationReportV1, func(*testing.T, *acknowledgementJourney) error) {
			row := acknowledgementEchoTemplate(journey, "op_ack_scopemismatch01")
			row.ScopeRevision = journey.finish.registration.ScopeRevision + 1
			return row, nil
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			journey := newAcknowledgementJourney(t)
			row, prepare := test.build(journey)
			if prepare != nil {
				if err := prepare(t, journey); err != nil {
					t.Fatal(err)
				}
			}
			control := acknowledgementPositiveControl(journey)
			if err := journey.store.PutContinuityOperationReport(ctx, row); err != nil {
				t.Fatal(err)
			}
			if err := journey.store.PutContinuityOperationReport(ctx, control); err != nil {
				t.Fatal(err)
			}
			err := journey.reconciler.Reconcile(ctx, journey.manifest)
			if err == nil || !strings.Contains(err.Error(), "apply managed services:") {
				t.Fatalf("stale-selection service failure was not preserved: %v", err)
			}
			pending, readErr := journey.store.ContinuityOperationReports(ctx)
			if readErr != nil {
				t.Fatal(readErr)
			}
			present := map[string]bool{}
			for _, report := range pending {
				present[report.OperationID] = true
			}
			if present[control.OperationID] {
				t.Fatalf("positive control %s was not retired; acknowledgement phase did not run", control.OperationID)
			}
			if !present[row.OperationID] {
				t.Fatalf("ineligible row %s was retired despite %s", row.OperationID, test.name)
			}
			retirements, readErr := journey.store.ContinuityOperationRetirements(ctx)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, retirement := range retirements {
				if retirement.Report.OperationID == row.OperationID {
					t.Fatalf("ineligible row %s was retained as a retirement despite %s", row.OperationID, test.name)
				}
			}
			if len(retirements) != len(journey.echoes)+1 {
				t.Fatalf("retirements = %d, want the six echoes plus the positive control", len(retirements))
			}
		})
	}
}

// TestReconcileKeepsAcknowledgedEchoesWithoutManifestAuthority is covered by
// the journey test itself: RED (no pre-failure phase) re-emits the revoked
// rev-1 tuples and all six terminal echoes, which the journey's post-failure
// assertions reject.
