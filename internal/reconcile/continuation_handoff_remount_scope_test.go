package reconcile

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// The registered primary session and native tuple the ordinary managed-service
// start/status receipts of the producer journey preserve (fakeManagedRuntime),
// so the pre-ratification source row below is exactly the row the ordinary
// continuity source observation leaves before the ratified A22 remount
// adoption advances its workspace scope.
const (
	a27SourceSessionID     = "ses_managedservice0001"
	a27SourceNativeProject = "0123456789abcdef0123456789abcdef01234567"
	a27SourceLocation      = "sha256:d9cf96858af585c5acc19643dfba975c35894edd0b85f88e96e82f88988beab6"
)

// a27RemountHandoff is the live A26 shape at the reconcile boundary: the source
// managed service has been driven through the backend-ratified A5/A22 remount
// adoption (workspace scope advanced exactly one, current root, retained
// superseded provenance, nonzero durable image identity), the ordinary
// continuity source observation has advanced the source row to that ratified
// scope, and the ready handoff still carries the binding it was prepared with.
type a27RemountHandoff struct {
	journey    *managerPolicyJourney
	remount    remountedManagedProject
	before     state.LocalManagedService
	incoming   model.ManagedServiceV1
	record     state.LocalManagedProject
	manifest   model.ContinuationHandoffManifestV1
	report     model.ContinuationHandoffReportV1
	ratified   model.Manifest
	controller *continuity.S2Controller
	runtime    *probeHandoffRuntime
	objects    *probeHandoffObjects
	probeNow   time.Time
	sourceID   string
	serviceID  string
}

// seedA27RatifiedRemountHandoff builds that shape from the deployed pre-remount
// rows the existing A22P journey seeds: it re-observes the documented remount,
// seeds the pre-ratification ordinary source observation, then runs the
// backend-ratified manifest through the real reconcile pass, where the store
// adoption advances the service workspace scope and the ordinary
// reconcileManagedServiceActive path rewrites the source observation at the
// ratified scope.
func seedA27RatifiedRemountHandoff(t *testing.T) *a27RemountHandoff {
	t.Helper()
	ctx := context.Background()
	journey, remount, before, incoming, record := registeredRemountJourney(t)
	serviceID := before.Manifest.Identity.ServiceRegistrationID
	sourceID := managedSourceID(serviceID)

	// The ordinary continuity source observation as the pre-remount service
	// left it: the registered primary at the stored binding scope and session.
	if err := journey.store.PutContinuitySource(ctx, state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: sourceID,
			ServiceRegistrationID: serviceID, ServiceGeneration: before.Manifest.Identity.ExpectedServiceGeneration,
			ProjectID: before.Manifest.Workspace.ProjectID, SandboxID: before.Manifest.Identity.SandboxID,
			SandboxGeneration: before.Manifest.Identity.SandboxGeneration,
			WorkspaceEpoch:    before.Manifest.Workspace.WorkspaceEpoch,
			NativeSessionID:   a27SourceSessionID, NativeProjectID: a27SourceNativeProject,
			NativeLocationDigest: a27SourceLocation,
			ScopeRevision:        before.Manifest.Workspace.ScopeRevision, Role: before.Manifest.Identity.Role,
			ProfileRevision:     before.Manifest.Profile.ProfileRevision,
			InstructionRevision: before.Manifest.Instructions.InstructionRevision,
			Availability:        "unavailable", Reason: probeReason(), LastObservedAt: journey.reconciler.Now().Add(-10 * time.Minute),
		},
		Root: record.HostRoot, Instance: before.Manifest.Identity.Instance, Lifecycle: "running",
		LifecycleRevision: before.Manifest.ActionRevision,
	}); err != nil {
		t.Fatal(err)
	}

	// The ready handoff the source advanced under: every stored tuple keeps the
	// pre-remount binding, session and scope.
	fixture := readS2BWorkerFixture(t)
	manifest := fixture.ReviewerManifest
	manifest.Identity = model.ContinuationIdentityV1{
		WorkID: "work_statehandoffreviewer0001", ProjectID: before.Manifest.Workspace.ProjectID,
		SandboxID: before.Manifest.Identity.SandboxID, WorkspaceEpoch: before.Manifest.Workspace.WorkspaceEpoch,
		SandboxGeneration: before.Manifest.Identity.SandboxGeneration, ExpectedRevision: 1,
	}
	manifest.Binding = model.ContinuationBindingRefV1{
		BindingID: "binding_statehandoffreviewer0001", BindingRevision: 1,
		RegisteredSourceID: sourceID, ServiceRegistrationID: serviceID,
		NativeSessionID: a27SourceSessionID, NativeProjectID: a27SourceNativeProject,
		NativeLocationDigest: a27SourceLocation,
		ServiceGeneration:    before.Manifest.Identity.ExpectedServiceGeneration,
		ScopeRevision:        before.Manifest.Workspace.ScopeRevision,
	}
	manifest.Lineage.SourceWorkID = manifest.Identity.WorkID
	manifest.Lineage.SourceRevision = manifest.Identity.ExpectedRevision
	manifest.Lineage.CheckpointOperationID = manifest.Checkpoint.OperationID
	report := fixture.ReviewerReport
	report.Identity, report.Binding, report.Checkpoint = manifest.Identity, manifest.Binding, manifest.Checkpoint
	report.Lineage, report.TargetPolicy, report.WorkspaceRequest = manifest.Lineage, manifest.TargetPolicy, manifest.Workspace
	report.ContextDigest = manifest.Context.Digest
	report.Status = "ready"
	report.ErrorCode = nil

	if err := journey.store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
		Manifest: model.ContinuityRegistrationV1{
			FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: manifest.Binding.ScopeRevision,
			Identity: model.ContinuityIdentityV1{
				WorkID: manifest.Identity.WorkID, ProjectID: manifest.Identity.ProjectID, SandboxID: manifest.Identity.SandboxID,
				WorkspaceEpoch: manifest.Identity.WorkspaceEpoch, SandboxGeneration: manifest.Identity.SandboxGeneration,
				ExpectedRevision: manifest.Identity.ExpectedRevision,
			},
			Binding: model.ContinuityBindingV1{
				BindingID: manifest.Binding.BindingID, BindingRevision: manifest.Binding.BindingRevision,
				RegisteredSourceID: manifest.Binding.RegisteredSourceID, ServiceRegistrationID: manifest.Binding.ServiceRegistrationID,
				NativeSessionID: manifest.Binding.NativeSessionID, NativeProjectID: manifest.Binding.NativeProjectID,
				NativeLocationDigest: manifest.Binding.NativeLocationDigest,
			},
		},
		ObservedStatus: "verified", ServiceGeneration: manifest.Binding.ServiceGeneration,
		ReceiptDigest: probeDigest("2"),
	}); err != nil {
		t.Fatal(err)
	}
	targetSandbox, _, _ := seedProbeHandoffTargetSide(t, journey.store, journey.reconciler.ServerID, journey.reconciler.Now, manifest, report)
	targetService, err := journey.store.ManagedService(ctx, manifest.TargetPolicy.ServiceRegistrationID)
	if err != nil || targetService == nil || targetService.Report.NativeRegistration == nil {
		t.Fatalf("target service = %#v, %v", targetService, err)
	}

	envelope, err := json.Marshal(map[string]any{
		"formatVersion": 1, "action": "reconcile_handoff", "status": "ready", "state": "prepared",
		"report": report, "consumption": nil, "release": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	handoff := &a27RemountHandoff{
		journey: journey, remount: remount, before: before, incoming: incoming, record: record,
		manifest: manifest, report: report, sourceID: sourceID, serviceID: serviceID,
		probeNow: journey.reconciler.Now(),
		objects:  &probeHandoffObjects{},
	}
	handoff.runtime = &probeHandoffRuntime{
		statusReceipts: map[string]map[string]any{
			manifest.Identity.SandboxID: {
				"schemaVersion": 1, "command": "status", "status": "running", "ready": true,
				"sessionId": a27SourceSessionID, "nativeProjectId": a27SourceNativeProject,
				"nativeLocationDigest": a27SourceLocation,
				"instructionRevision":  before.Manifest.Instructions.InstructionRevision,
				"instructionDigest":    before.Manifest.Instructions.InstructionDigest,
				"instructionApplied":   true,
			},
			targetSandbox: {
				"schemaVersion": 1, "command": "status", "status": "running", "ready": true,
				"sessionId":            targetService.Report.NativeRegistration.NativeSessionID,
				"nativeProjectId":      targetService.Report.NativeRegistration.NativeProjectID,
				"nativeLocationDigest": targetService.Report.NativeRegistration.NativeLocationDigest,
				"instructionRevision":  targetService.Manifest.Instructions.InstructionRevision,
				"instructionDigest":    targetService.Manifest.Instructions.InstructionDigest,
				"instructionApplied":   true,
			},
		},
		statusFailures: map[string]string{},
		reconcile:      envelope,
	}
	handoff.controller = &continuity.S2Controller{
		Store: journey.store, ServerID: journey.reconciler.ServerID, Objects: handoff.objects,
		Catalog: &workspacecatalog.Catalog{State: journey.store}, Helper: handoff.runtime,
		HandoffSupervisor: handoff.runtime,
		Now:               func() time.Time { return handoff.probeNow },
	}
	journey.reconciler.ContinuationHandoff = handoff.controller

	// The backend-ratified manifest keeps the stored handoff intent so the pass
	// validates and replays it, and keeps the target box in the desired set.
	ratified := journey.manifest
	ratified.ManagedServices = []model.ManagedServiceV1{incoming}
	ratified.ContinuityHandoffs = []model.ContinuationHandoffManifestV1{manifest}
	ratified.Sandboxes = append(append([]model.Sandbox(nil), journey.manifest.Sandboxes...),
		model.Sandbox{
			ID: manifest.TargetPolicy.SandboxID, Name: "a27-handoff-target", Size: "small",
			Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 9, PIDs: 32},
			Lifetime:  "persistent", DesiredState: "running", Generation: manifest.TargetPolicy.SandboxGeneration,
		})
	handoff.ratified = ratified

	if err := journey.reconciler.Reconcile(ctx, ratified); err != nil {
		t.Fatalf("ratified remount pass aborted: %v", err)
	}
	advanced, err := journey.store.ContinuitySource(ctx, sourceID)
	if err != nil || advanced == nil {
		t.Fatalf("ratified source observation = %#v, %v", advanced, err)
	}
	if advanced.Report.ScopeRevision != manifest.Binding.ScopeRevision+1 ||
		advanced.Report.NativeSessionID != a27SourceSessionID || advanced.Root != record.HostRoot {
		t.Fatalf("ordinary observation did not advance the source row to the ratified scope: %#v", advanced.Report)
	}
	// The journey precondition: the store adoption moved only the two ratified
	// workspace fields on the retained service, and the re-observed project
	// still carries the complete A5/A25 remount authority the +1 proof needs.
	adopted, err := journey.store.ManagedService(ctx, serviceID)
	if err != nil || adopted == nil ||
		adopted.Manifest.Workspace.ScopeRevision != manifest.Binding.ScopeRevision+1 ||
		adopted.Manifest.Workspace.RootAttestation != record.Report.RootAttestation ||
		adopted.ServiceGeneration != before.ServiceGeneration {
		t.Fatalf("source service did not adopt the ratified remount authority: %#v, %v", adopted, err)
	}
	recordNow := storedManagedProjectRecord(t, journey.store, record.Report.SelectionID)
	if recordNow.Phase != "ready" || recordNow.Report.Availability != "available" ||
		recordNow.Report.Designation != "team_project" || recordNow.SupersededRootAttestation == "" ||
		recordNow.ImageIdentity.Device == 0 || recordNow.ImageIdentity.Inode == 0 || recordNow.ImageIdentity.Size == 0 ||
		recordNow.AnchorDevice == 0 || recordNow.AnchorDevice != recordNow.RootDevice {
		t.Fatalf("journey project is not the complete remount authority: %#v", recordNow)
	}
	handoff.runtime.actions = nil
	handoff.runtime.requests = nil
	return handoff
}

// a27Exec runs one raw statement against the journey's real SQLite file. The
// boundary journeys use it to move a durable row exactly as an external writer
// could, without any store admission path repairing or rejecting the move.
func a27Exec(t *testing.T, path, query string, args ...any) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func a27MutateSource(t *testing.T, fixture *a27RemountHandoff, mutate func(*state.LocalContinuitySource)) {
	t.Helper()
	row, err := fixture.journey.store.ContinuitySource(context.Background(), fixture.sourceID)
	if err != nil || row == nil {
		t.Fatalf("ratified source row = %#v, %v", row, err)
	}
	mutate(row)
	if err := fixture.journey.store.PutContinuitySource(context.Background(), *row); err != nil {
		t.Fatal(err)
	}
}

func a27MutateRegistration(t *testing.T, fixture *a27RemountHandoff, mutate func(*state.LocalContinuityRegistration)) {
	t.Helper()
	registration, err := fixture.journey.store.ContinuityRegistration(context.Background(), fixture.manifest.Binding.BindingID)
	if err != nil || registration == nil {
		t.Fatalf("ratified registration = %#v, %v", registration, err)
	}
	mutate(registration)
	if err := fixture.journey.store.PutContinuityRegistration(context.Background(), *registration); err != nil {
		t.Fatal(err)
	}
}

func a27MutateServiceManifest(t *testing.T, fixture *a27RemountHandoff, mutate func(*model.ManagedServiceV1)) {
	t.Helper()
	row := storedManagedServiceRow(t, fixture.journey.store, fixture.serviceID)
	if row == nil {
		t.Fatal("ratified service row is missing")
	}
	manifest := row.Manifest
	mutate(&manifest)
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	a27Exec(t, fixture.journey.databasePath,
		`UPDATE managed_services SET manifest_json=? WHERE service_registration_id=?`, payload, fixture.serviceID)
}

func a27MutateServiceReport(t *testing.T, fixture *a27RemountHandoff, mutate func(*model.ManagedServiceReportV1)) {
	t.Helper()
	row := storedManagedServiceRow(t, fixture.journey.store, fixture.serviceID)
	if row == nil {
		t.Fatal("ratified service row is missing")
	}
	report := row.Report
	mutate(&report)
	if err := fixture.journey.store.UpdateManagedService(context.Background(), fixture.serviceID, row.Phase, &report, row.ErrorCode); err != nil {
		t.Fatal(err)
	}
}

func a27MutateProject(t *testing.T, fixture *a27RemountHandoff, mutate func(*state.LocalManagedProject)) {
	t.Helper()
	record := storedManagedProjectRecord(t, fixture.journey.store, fixture.record.Report.SelectionID)
	mutate(&record)
	private, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	a27Exec(t, fixture.journey.databasePath,
		`UPDATE managed_workspace_projects SET private_json=? WHERE selection_id=?`, private, record.Report.SelectionID)
}

// a27RawSourceColumns reads the retained source row exactly as stored,
// including the ordinary write timestamp, so a fail-closed recovery can be
// proven to leave it byte-identical.
func a27RawSourceColumns(t *testing.T, path, sourceID string) map[string]string {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var report, root, instance, lifecycle, updatedAt string
	var revision, noExecution int64
	if err := database.QueryRowContext(context.Background(),
		`SELECT report_json,workspace_root,instance,lifecycle,lifecycle_revision,no_admitted_execution,updated_at
		 FROM continuity_sources WHERE registered_source_id=?`, sourceID).
		Scan(&report, &root, &instance, &lifecycle, &revision, &noExecution, &updatedAt); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"report_json": report, "workspace_root": root, "instance": instance, "lifecycle": lifecycle,
		"lifecycle_revision": fmt.Sprint(revision), "no_admitted_execution": fmt.Sprint(noExecution),
		"updated_at": updatedAt,
	}
}

func assertA27SourceUnchanged(t *testing.T, fixture *a27RemountHandoff, before map[string]string) {
	t.Helper()
	if after := a27RawSourceColumns(t, fixture.journey.databasePath, fixture.sourceID); !reflect.DeepEqual(before, after) {
		t.Fatalf("fail-closed recovery moved the source row: before=%v after=%v", before, after)
	}
}

// a27HistoryCounts counts the durable operation, preparation, release,
// checkpoint and capture history rows the recovery must never create, replace
// or prune.
func a27HistoryCounts(t *testing.T, path string) map[string]int {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	counts := map[string]int{}
	for _, table := range []string{
		"continuation_handoff_preparations", "continuation_handoff_releases",
		"continuity_operations", "checkpoints", "continuity_captures",
	} {
		var count int
		if err := database.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		counts[table] = count
	}
	return counts
}

// TestReconcileRecoversReadyHandoffAfterTheRatifiedRemountAdvancesTheSourceScope
// is the A26/A27 journey. The source service reaches the backend-ratified A5/A22
// remount authority and the ordinary observation moves the source row one scope
// step beyond the stored handoff binding. The ready replay must probe the exact
// preserved native session through the durable current-record proof, complete
// the ordinary ready-publish path, and move nothing else: no recreation or
// rebind of the handoff, no replacement of the retained native session, no
// rewrite of the operation/session/report/preparation/checkpoint history and no
// change to any service process fact.
func TestReconcileRecoversReadyHandoffAfterTheRatifiedRemountAdvancesTheSourceScope(t *testing.T) {
	fixture := seedA27RatifiedRemountHandoff(t)
	ctx := context.Background()
	sourceBefore, err := fixture.journey.store.ContinuitySource(ctx, fixture.sourceID)
	if err != nil || sourceBefore == nil {
		t.Fatalf("ratified source row = %#v, %v", sourceBefore, err)
	}
	if sourceBefore.Report.ScopeRevision != fixture.manifest.Binding.ScopeRevision+1 {
		t.Fatalf("journey source row is not one step beyond the binding: %#v", sourceBefore.Report)
	}
	preparationBefore := isolationPreparationState(t, fixture.journey.databasePath, fixture.manifest.OperationID)
	registrationBefore, err := fixture.journey.store.ContinuityRegistration(ctx, fixture.manifest.Binding.BindingID)
	if err != nil || registrationBefore == nil {
		t.Fatalf("ratified registration = %#v, %v", registrationBefore, err)
	}
	serviceBefore := rawManagedServiceColumns(t, fixture.journey, fixture.serviceID)
	mappedSourceID := fixture.report.Session.RegisteredSourceID
	mappedBefore, err := fixture.journey.store.ContinuitySource(ctx, mappedSourceID)
	if err != nil || mappedBefore == nil {
		t.Fatalf("mapped handoff source = %#v, %v", mappedBefore, err)
	}
	historyBefore := a27HistoryCounts(t, fixture.journey.databasePath)
	fixture.probeNow = fixture.journey.reconciler.Now().Add(5 * time.Minute)

	if err := fixture.controller.RecoverHandoffs(ctx); err != nil {
		t.Fatalf("ratified remount scope advance refused ready recovery: %v", err)
	}

	// The ready replay probes the exact preserved native session and the target
	// service primary through the supervisor status boundary, then re-proves the
	// target session through the ordinary reconcile_handoff request.
	if !reflect.DeepEqual(fixture.runtime.actions, []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus), "reconcile_handoff",
	}) {
		t.Fatalf("ready replay actions = %v", fixture.runtime.actions)
	}
	sourceProbe := fixture.runtime.requests[0]
	if sourceProbe["sandboxId"] != fixture.manifest.Identity.SandboxID || sourceProbe["instance"] != "default" ||
		sourceProbe["profileId"] != fixture.serviceManifestProfileID(t) || sourceProbe["probe"] != true ||
		sourceProbe["schemaVersion"] != float64(1) || sourceProbe["requestTimeoutSeconds"] != float64(30) {
		t.Fatalf("source status probe payload = %#v", sourceProbe)
	}
	targetProbe := fixture.runtime.requests[1]
	if targetProbe["sandboxId"] != fixture.manifest.TargetPolicy.SandboxID || targetProbe["probe"] != true {
		t.Fatalf("target status probe payload = %#v", targetProbe)
	}

	// The ordinary observation moves exactly its three observation fields and
	// nothing else on the source row.
	sourceAfter, err := fixture.journey.store.ContinuitySource(ctx, fixture.sourceID)
	if err != nil || sourceAfter == nil {
		t.Fatalf("recovered source row = %#v, %v", sourceAfter, err)
	}
	if sourceAfter.Report.Availability != "available" || sourceAfter.Report.Reason != nil ||
		!sourceAfter.Report.LastObservedAt.Equal(fixture.probeNow) {
		t.Fatalf("recovery did not truthfully refresh the source observation: %#v", sourceAfter.Report)
	}
	expectedSource := *sourceBefore
	expectedSource.Report.Availability = "available"
	expectedSource.Report.Reason = nil
	expectedSource.Report.LastObservedAt = fixture.probeNow
	if !reflect.DeepEqual(expectedSource, *sourceAfter) {
		t.Fatalf("recovery moved more than the observation fields: before=%#v after=%#v", sourceBefore, sourceAfter)
	}

	// No recreation or rebind: the handoff operation, session, report,
	// preparation and binding stay byte-identical.
	if after := isolationPreparationState(t, fixture.journey.databasePath, fixture.manifest.OperationID); !reflect.DeepEqual(preparationBefore, after) {
		t.Fatalf("recovery rewrote the handoff preparation: before=%v after=%v", preparationBefore, after)
	}
	preparations, err := fixture.journey.store.ContinuationHandoffPreparations(ctx)
	if err != nil || len(preparations) != 1 || preparations[0].Manifest.OperationID != fixture.manifest.OperationID ||
		preparations[0].Report == nil || !reflect.DeepEqual(*preparations[0].Report, fixture.report) {
		t.Fatalf("recovery recreated the handoff operation: %#v, %v", preparations, err)
	}
	registrationAfter, err := fixture.journey.store.ContinuityRegistration(ctx, fixture.manifest.Binding.BindingID)
	if err != nil || !reflect.DeepEqual(registrationBefore, registrationAfter) {
		t.Fatalf("recovery moved the source registration: before=%#v after=%#v", registrationBefore, registrationAfter)
	}

	// All retained service process facts are preserved: the ready replay never
	// touches the managed service row or its native registration.
	if after := rawManagedServiceColumns(t, fixture.journey, fixture.serviceID); !reflect.DeepEqual(serviceBefore, after) {
		t.Fatalf("ready replay moved the retained service row: before=%v after=%v", serviceBefore, after)
	}
	service, err := fixture.journey.store.ManagedService(ctx, fixture.serviceID)
	if err != nil || service == nil || service.Report.NativeRegistration == nil ||
		service.Report.NativeRegistration.NativeSessionID != a27SourceSessionID ||
		service.Manifest.Workspace.ScopeRevision != fixture.incoming.Workspace.ScopeRevision {
		t.Fatalf("recovery replaced the retained native session: %#v, %v", service, err)
	}

	// The mapped target session source likewise moves only its observation.
	mappedAfter, err := fixture.journey.store.ContinuitySource(ctx, mappedSourceID)
	if err != nil || mappedAfter == nil {
		t.Fatalf("recovered mapped source = %#v, %v", mappedAfter, err)
	}
	expectedMapped := *mappedBefore
	expectedMapped.Report.Availability = "available"
	expectedMapped.Report.Reason = nil
	expectedMapped.Report.LastObservedAt = fixture.probeNow
	if !reflect.DeepEqual(expectedMapped, *mappedAfter) {
		t.Fatalf("recovery moved more than the mapped observation: before=%#v after=%#v", mappedBefore, mappedAfter)
	}
	if after := a27HistoryCounts(t, fixture.journey.databasePath); !reflect.DeepEqual(historyBefore, after) {
		t.Fatalf("recovery created or replaced durable history: before=%v after=%v", historyBefore, after)
	}

	// The wedge is cleared at the pass boundary too: the same ratified manifest
	// now reconciles end to end and still repeats no side effect.
	if err := fixture.journey.reconciler.Reconcile(ctx, fixture.ratified); err != nil {
		t.Fatalf("recovered pass was not admitted: %v", err)
	}
	replayed, err := fixture.journey.store.ContinuationHandoffPreparations(ctx)
	if err != nil || len(replayed) != 1 || !reflect.DeepEqual(replayed[0].Report, preparations[0].Report) {
		t.Fatalf("recovered pass rewrote the handoff report: %#v, %v", replayed, err)
	}
	if after := a27HistoryCounts(t, fixture.journey.databasePath); !reflect.DeepEqual(historyBefore, after) {
		t.Fatalf("recovered pass created or replaced durable history: before=%v after=%v", historyBefore, after)
	}
	serviceAfterPass := rawManagedServiceColumns(t, fixture.journey, fixture.serviceID)
	for _, field := range []string{"manifest_json", "phase", "report_json", "error_code", "process_instance", "port", "creation_dispatched", "service_generation"} {
		if serviceAfterPass[field] != serviceBefore[field] {
			t.Fatalf("recovered pass moved service field %s: before=%q after=%q", field, serviceBefore[field], serviceAfterPass[field])
		}
	}
	if revision, err := fixture.journey.store.Revision(ctx); err != nil || revision != fixture.ratified.DesiredRevision {
		t.Fatalf("recovered pass did not advance the applied revision to %d: %d, %v", fixture.ratified.DesiredRevision, revision, err)
	}
}

// serviceManifestProfileID reads the stored source service profile id for the
// probe-payload assertion.
func (fixture *a27RemountHandoff) serviceManifestProfileID(t *testing.T) string {
	t.Helper()
	row := storedManagedServiceRow(t, fixture.journey.store, fixture.serviceID)
	if row == nil {
		t.Fatal("ratified service row is missing")
	}
	return row.Manifest.Profile.ProfileID
}

// TestReconcileKeepsEveryUnprovenHandoffSourceScopeAdvanceFatal is the
// fail-closed boundary matrix for the guarded one-step advance: every mutated
// durable clause must refuse recovery with the documented reason, and the
// source row must stay byte-identical, including its write timestamp.
func TestReconcileKeepsEveryUnprovenHandoffSourceScopeAdvanceFatal(t *testing.T) {
	cases := []struct {
		name string
		// authorityChanged is true when the refusal must carry
		// ErrS2AuthorityChanged; false means the existing documented
		// ErrS2RecoveryUnknown tuple refusal.
		authorityChanged bool
		mutate           func(*testing.T, *a27RemountHandoff)
	}{
		{"source scope jump beyond one", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateSource(t, fixture, func(source *state.LocalContinuitySource) { source.Report.ScopeRevision += 2 })
		}},
		{"source scope regression", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateSource(t, fixture, func(source *state.LocalContinuitySource) {
				source.Report.ScopeRevision = fixture.manifest.Binding.ScopeRevision - 1
			})
		}},
		{"source role drift", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateSource(t, fixture, func(source *state.LocalContinuitySource) { source.Report.Role = "reviewer" })
		}},
		{"source native session drift", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateSource(t, fixture, func(source *state.LocalContinuitySource) {
				source.Report.NativeSessionID = "ses_foreign0000000001"
			})
		}},
		{"source service generation drift", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateSource(t, fixture, func(source *state.LocalContinuitySource) { source.Report.ServiceGeneration++ })
		}},
		{"registration scope drift", false, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateRegistration(t, fixture, func(registration *state.LocalContinuityRegistration) {
				registration.Manifest.ScopeRevision++
			})
		}},
		{"service report generation drift", false, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateServiceReport(t, fixture, func(report *model.ManagedServiceReportV1) { report.ServiceGeneration++ })
		}},
		{"service identity drift", false, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateServiceManifest(t, fixture, func(manifest *model.ManagedServiceV1) {
				manifest.Identity.SandboxGeneration++
			})
		}},
		{"service workspace scope not advanced", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateServiceManifest(t, fixture, func(manifest *model.ManagedServiceV1) {
				manifest.Workspace.ScopeRevision = fixture.manifest.Binding.ScopeRevision
			})
		}},
		{"service workspace scope advanced twice", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateServiceManifest(t, fixture, func(manifest *model.ManagedServiceV1) {
				manifest.Workspace.ScopeRevision = fixture.manifest.Binding.ScopeRevision + 2
			})
		}},
		{"service workspace project mismatch", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateServiceManifest(t, fixture, func(manifest *model.ManagedServiceV1) {
				manifest.Workspace.ProjectID = "project_foreign0000000001"
			})
		}},
		{"service workspace epoch mismatch", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateServiceManifest(t, fixture, func(manifest *model.ManagedServiceV1) {
				manifest.Workspace.WorkspaceEpoch = "epoch_foreign0000000001"
			})
		}},
		{"service and project moved to a consistent foreign tuple", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateServiceManifest(t, fixture, func(manifest *model.ManagedServiceV1) {
				manifest.Workspace.ProjectID = "project_foreign0000000001"
				manifest.Workspace.WorkspaceEpoch = "epoch_foreign0000000001"
			})
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) {
				record.Report.ProjectID = "project_foreign0000000001"
				record.Report.WorkspaceEpoch = "epoch_foreign0000000001"
			})
		}},
		{"project missing", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27Exec(t, fixture.journey.databasePath, `DELETE FROM managed_workspace_projects WHERE selection_id=?`, fixture.record.Report.SelectionID)
		}},
		{"project not ready", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) { record.Phase = "allocated" })
		}},
		{"project unavailable", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) { record.Report.Availability = "unavailable" })
		}},
		{"project not a team project", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) { record.Report.Designation = "continuity-handoff" })
		}},
		{"project tuple mismatch", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) { record.Report.ProjectID = "project_foreign0000000001" })
		}},
		{"project root mismatch", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) { record.HostRoot = "/host/workspaces/foreign" })
		}},
		{"project root attestation drift", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) { record.Report.RootAttestation = probeDigest("8") })
		}},
		{"missing superseded root provenance", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) { record.SupersededRootAttestation = "" })
		}},
		{"zero durable image identity", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) {
				record.ImageIdentity = state.ManagedProjectImageIdentity{}
			})
		}},
		{"partially zero durable image identity", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) { record.ImageIdentity.Inode = 0 })
		}},
		{"anchor device fence", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) { record.AnchorDevice = 0 })
		}},
		{"root device fence", true, func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) { record.RootDevice = record.AnchorDevice + 1 })
		}},
		{"source sandbox not running", false, func(t *testing.T, fixture *a27RemountHandoff) {
			sandbox, err := fixture.journey.store.Sandbox(context.Background(), fixture.manifest.Identity.SandboxID)
			if err != nil || sandbox == nil {
				t.Fatalf("source sandbox = %#v, %v", sandbox, err)
			}
			sandbox.ObservedState = "stopped"
			if err := fixture.journey.store.PutSandbox(context.Background(), *sandbox); err != nil {
				t.Fatal(err)
			}
		}},
		{"supervisor receipt does not prove the session", false, func(t *testing.T, fixture *a27RemountHandoff) {
			fixture.runtime.statusReceipts[fixture.manifest.Identity.SandboxID]["sessionId"] = "ses_foreign0000000001"
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := seedA27RatifiedRemountHandoff(t)
			testCase.mutate(t, fixture)
			before := a27RawSourceColumns(t, fixture.journey.databasePath, fixture.sourceID)
			preparationBefore := isolationPreparationState(t, fixture.journey.databasePath, fixture.manifest.OperationID)

			err := fixture.controller.RecoverHandoffs(context.Background())
			if err == nil {
				t.Fatal("unproven scope advance was accepted")
			}
			if testCase.authorityChanged && !errors.Is(err, continuity.ErrS2AuthorityChanged) {
				t.Fatalf("refusal %v does not carry ErrS2AuthorityChanged", err)
			}
			if !testCase.authorityChanged && !errors.Is(err, continuity.ErrS2RecoveryUnknown) {
				t.Fatalf("refusal %v does not carry ErrS2RecoveryUnknown", err)
			}
			assertA27SourceUnchanged(t, fixture, before)
			if after := isolationPreparationState(t, fixture.journey.databasePath, fixture.manifest.OperationID); !reflect.DeepEqual(preparationBefore, after) {
				t.Fatalf("refusal rewrote the handoff preparation: before=%v after=%v", preparationBefore, after)
			}
		})
	}
}

// TestReconcileKeepsTheUnchangedExactSourceScopePath pins the other half of the
// boundary: the stored binding scope itself still recovers with no remount
// proof at all, exactly as before the A27 correction.
func TestReconcileKeepsTheUnchangedExactSourceScopePath(t *testing.T) {
	fixture := seedA27RatifiedRemountHandoff(t)
	ctx := context.Background()
	a27MutateSource(t, fixture, func(source *state.LocalContinuitySource) {
		source.Report.ScopeRevision = fixture.manifest.Binding.ScopeRevision
	})
	fixture.probeNow = fixture.journey.reconciler.Now().Add(9 * time.Minute)

	if err := fixture.controller.RecoverHandoffs(ctx); err != nil {
		t.Fatalf("exact stored scope path refused recovery: %v", err)
	}
	row, err := fixture.journey.store.ContinuitySource(ctx, fixture.sourceID)
	if err != nil || row == nil || row.Report.ScopeRevision != fixture.manifest.Binding.ScopeRevision ||
		row.Report.Availability != "available" || !row.Report.LastObservedAt.Equal(fixture.probeNow) {
		t.Fatalf("exact stored scope path did not refresh the observation: %#v, %v", row, err)
	}
	if !reflect.DeepEqual(fixture.runtime.actions, []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus), "reconcile_handoff",
	}) {
		t.Fatalf("exact stored scope replay actions = %v", fixture.runtime.actions)
	}
}

// TestReconcileKeepsADurableAuthorityChangeBeforeThePostProbeRecheckFatal is
// the race boundary: the complete durable authority the one-step advance rests
// on is re-read and re-proven after the external supervisor receipt, so a row
// that moves inside that window is refused and the source observation is never
// written. The second case moves only a source-row field the observation itself
// never owns, which only the source-row stability re-proof can see.
func TestReconcileKeepsADurableAuthorityChangeBeforeThePostProbeRecheckFatal(t *testing.T) {
	cases := []struct {
		name string
		// mutate moves durable state from inside the source supervisor status
		// probe, after the initial validation and before the re-proof.
		mutate func(*testing.T, *a27RemountHandoff)
	}{
		{"project authority moved during the probe", func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateProject(t, fixture, func(record *state.LocalManagedProject) {
				record.SupersededRootAttestation = ""
			})
		}},
		{"source row moved beyond its observation fields", func(t *testing.T, fixture *a27RemountHandoff) {
			a27MutateSource(t, fixture, func(source *state.LocalContinuitySource) {
				source.Instance = "foreign-instance"
			})
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := seedA27RatifiedRemountHandoff(t)
			ctx := context.Background()
			fixture.runtime.statusHook = func(sandboxID string) {
				if sandboxID != fixture.manifest.Identity.SandboxID {
					return
				}
				testCase.mutate(t, fixture)
			}
			fixture.probeNow = fixture.journey.reconciler.Now().Add(7 * time.Minute)
			before := a27RawSourceColumns(t, fixture.journey.databasePath, fixture.sourceID)

			err := fixture.controller.RecoverHandoffs(ctx)
			if err == nil || !errors.Is(err, continuity.ErrS2AuthorityChanged) {
				t.Fatalf("post-probe authority change was not refused with ErrS2AuthorityChanged: %v", err)
			}
			if testCase.name == "project authority moved during the probe" {
				assertA27SourceUnchanged(t, fixture, before)
			} else {
				// The probe-window source-row move is the test's own write; the
				// refusal must still never perform the recovery's observation
				// write on top of it.
				row, err := fixture.journey.store.ContinuitySource(ctx, fixture.sourceID)
				if err != nil || row == nil || row.Instance != "foreign-instance" ||
					row.Report.LastObservedAt.Equal(fixture.probeNow) {
					t.Fatalf("refused recovery wrote the source observation: %#v, %v", row, err)
				}
			}
			if !reflect.DeepEqual(fixture.runtime.actions, []string{string(containers.ManagedSupervisorStatus)}) {
				t.Fatalf("post-probe refusal reached a later probe: %v", fixture.runtime.actions)
			}
		})
	}
}
