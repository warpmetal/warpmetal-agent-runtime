package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// probeHandoffObjects is a deliberate tripwire: the ready report recovery path
// this journey exercises must never reach the object store.
type probeHandoffObjects struct{ calls int }

func (f *probeHandoffObjects) Verify(context.Context, string) (storage.DurableCapture, error) {
	f.calls++
	return storage.DurableCapture{}, errors.New("handoff probe journey must not verify objects")
}

func (f *probeHandoffObjects) VerifyWorkspace(context.Context, string, string) error {
	f.calls++
	return errors.New("handoff probe journey must not verify workspaces")
}

func (f *probeHandoffObjects) MaterializeNew(context.Context, storage.MaterializeNewRequest) (storage.MaterializeReceipt, error) {
	f.calls++
	return storage.MaterializeReceipt{}, errors.New("handoff probe journey must not materialize")
}

// probeHandoffRuntime is the handoff supervisor and helper boundary: status
// probes answer from per-sandbox receipts or fail with a bounded transport
// error, and the target session probe answers the ordinary reconcile_handoff
// ready envelope or a bounded refusal.
type probeHandoffRuntime struct {
	statusReceipts map[string]map[string]any
	statusFailures map[string]string
	actions        []string
	requests       []map[string]any
	reconcile      []byte
	reconcileErr   error
	refusal        string
	// statusHook runs inside the status probe boundary, after the action is
	// recorded and before the receipt answers. The durable-authority race
	// boundary uses it to move a store row between the observation's initial
	// validation and its post-probe re-proof.
	statusHook func(sandboxID string)
}

func (f *probeHandoffRuntime) ExecManagedSupervisor(_ context.Context, _ string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	if action != containers.ManagedSupervisorStatus {
		return nil, nil, errors.New("unexpected supervisor action " + string(action))
	}
	f.actions = append(f.actions, string(action))
	f.requests = append(f.requests, request)
	sandboxID, _ := request["sandboxId"].(string)
	if f.statusHook != nil {
		f.statusHook(sandboxID)
	}
	if failure, failed := f.statusFailures[sandboxID]; failed {
		return nil, []byte(failure), errors.New("exit status 125")
	}
	receipt, ok := f.statusReceipts[sandboxID]
	if !ok {
		return nil, nil, errors.New("no status receipt for sandbox " + sandboxID)
	}
	encoded, err := json.Marshal(receipt)
	return encoded, nil, err
}

func (f *probeHandoffRuntime) ExecContinuity(_ context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	action, _ := request["action"].(string)
	f.actions = append(f.actions, action)
	f.requests = append(f.requests, request)
	if f.reconcileErr != nil {
		err := f.reconcileErr
		f.reconcileErr = nil
		return nil, []byte("injected continuity transport failure"), err
	}
	if f.refusal != "" {
		payload, _ := json.Marshal(map[string]any{
			"formatVersion": 1, "action": "reconcile_handoff", "status": "refused",
			"error": f.refusal, "facts": map[string]any{},
		})
		return payload, []byte("injected reconcile refusal"), errors.New("exit status 1")
	}
	if action != "reconcile_handoff" || f.reconcile == nil {
		return nil, nil, errors.New("unexpected continuity action " + action)
	}
	return f.reconcile, nil, nil
}

type probeHandoffFixture struct {
	manifest      model.ContinuationHandoffManifestV1
	report        model.ContinuationHandoffReportV1
	controller    *continuity.S2Controller
	runtime       *probeHandoffRuntime
	sourceSandbox string
	targetSandbox string
	sourceID      string
	serviceID     string
	sessionID     string
	objects       *probeHandoffObjects
}

func probeDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func probeReason() *string {
	reason := "probe_stale"
	return &reason
}

func putProbeSandbox(t *testing.T, store *state.Store, id string, generation int64) {
	t.Helper()
	if err := store.PutSandbox(context.Background(), state.LocalSandbox{
		ID: id, Name: "probe-" + strings.TrimPrefix(id, "sbx_"), DesiredState: "running", ObservedState: "running",
		Generation: generation, ObservedGeneration: generation, Lifetime: "persistent",
	}); err != nil {
		t.Fatal(err)
	}
}

func putProbeSource(t *testing.T, store *state.Store, value state.LocalContinuitySource) {
	t.Helper()
	if err := store.PutContinuitySource(context.Background(), value); err != nil {
		t.Fatal(err)
	}
}

// seedProbeReadyHandoff builds the live ready-handoff shape at the reconcile
// boundary: a ready preparation whose exact source service, target service and
// three registered sources all prove their stored tuples, with the stored
// observations aged to unavailable so only a truthful probe can refresh them.
func seedProbeReadyHandoff(t *testing.T, store *state.Store, serverID string, now func() time.Time) *probeHandoffFixture {
	t.Helper()
	ctx := context.Background()
	fixture := readS2BWorkerFixture(t)
	manifest := fixture.ReviewerManifest
	report := fixture.ReviewerReport
	if report.TargetWorkspace == nil || report.Session == nil {
		t.Fatal("worker fixture lacks the ready target tuple")
	}
	stale := now().Add(-10 * time.Minute)

	if err := store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
		Manifest: model.ContinuityRegistrationV1{
			FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: manifest.Binding.ScopeRevision,
			Identity: model.ContinuityIdentityV1{
				WorkID: manifest.Identity.WorkID, ProjectID: manifest.Identity.ProjectID,
				SandboxID: manifest.Identity.SandboxID, WorkspaceEpoch: manifest.Identity.WorkspaceEpoch,
				SandboxGeneration: manifest.Identity.SandboxGeneration, ExpectedRevision: manifest.Identity.ExpectedRevision,
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
	putProbeSandbox(t, store, manifest.Identity.SandboxID, manifest.Identity.SandboxGeneration)

	sourceService := model.ManagedServiceV1{
		FormatVersion: 1, OperationID: "op_probehandoffsource0001", ActionRevision: 1, DesiredRevision: 1,
		ConfigDigest: probeDigest("3"), DesiredState: "active", SessionMode: "lookup_only",
		Identity: model.ManagedServiceIdentityV1{
			ServerID: serverID, TeamID: manifest.TargetPolicy.TeamID, MemberID: manifest.TargetPolicy.MemberID,
			SandboxID: manifest.Identity.SandboxID, SandboxGeneration: manifest.Identity.SandboxGeneration,
			ServiceRegistrationID:     manifest.Binding.ServiceRegistrationID,
			ExpectedServiceGeneration: manifest.Binding.ServiceGeneration, Instance: "default", Role: "worker",
		},
		Profile: model.ManagedServiceProfileV1{
			SetupOperationID: "setup_probehandoffsource0001", ProfileID: "opencode",
			ProfileRevision: 1, ProfileDigest: probeDigest("4"),
		},
		Instructions: model.ManagedServiceInstructionsV1{InstructionRevision: 1, InstructionDigest: probeDigest("5")},
		Workspace: model.ManagedServiceWorkspaceV1{
			SelectionID: "selection_probehandoffsource0001", ProjectID: manifest.Identity.ProjectID,
			WorkspaceEpoch: manifest.Identity.WorkspaceEpoch, ScopeRevision: 1, Designation: "team_project",
			RootAttestation: probeDigest("6"),
		},
	}
	sourceReport := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: sourceService.OperationID, ActionRevision: sourceService.ActionRevision,
		ObservedDesiredRevision: sourceService.DesiredRevision, ConfigDigest: sourceService.ConfigDigest,
		ObservedState: "ready", Identity: sourceService.Identity, ServiceGeneration: manifest.Binding.ServiceGeneration,
		ProfileStatus: "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "ready",
		InstructionApplied: true, InstructionRevision: 1, InstructionDigest: probeDigest("5"),
		NativeRegistration: &model.ManagedNativeRegistrationV1{
			RegisteredSourceID: manifest.Binding.RegisteredSourceID, WorkspaceEpoch: manifest.Identity.WorkspaceEpoch,
			NativeSessionID: manifest.Binding.NativeSessionID, NativeProjectID: manifest.Binding.NativeProjectID,
			NativeLocationDigest: manifest.Binding.NativeLocationDigest,
		},
		ReceiptDigest: probeDigest("7"),
	}
	if err := store.PutManagedServiceIntent(ctx, state.LocalManagedService{
		Manifest: sourceService, Phase: "ready",
		ProcessInstance: model.ManagedServiceProcessInstance("default", manifest.Binding.ServiceGeneration),
		Port:            18443, CreationDispatched: true, ServiceGeneration: manifest.Binding.ServiceGeneration,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateManagedService(ctx, manifest.Binding.ServiceRegistrationID, "ready", &sourceReport, ""); err != nil {
		t.Fatal(err)
	}
	putProbeSource(t, store, state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: manifest.Binding.RegisteredSourceID,
			ServiceRegistrationID: manifest.Binding.ServiceRegistrationID, ServiceGeneration: manifest.Binding.ServiceGeneration,
			ProjectID: manifest.Identity.ProjectID, SandboxID: manifest.Identity.SandboxID,
			SandboxGeneration: manifest.Identity.SandboxGeneration, WorkspaceEpoch: manifest.Identity.WorkspaceEpoch,
			NativeSessionID: manifest.Binding.NativeSessionID, NativeProjectID: manifest.Binding.NativeProjectID,
			NativeLocationDigest: manifest.Binding.NativeLocationDigest, ScopeRevision: manifest.Binding.ScopeRevision,
			Role: sourceService.Identity.Role, ProfileRevision: sourceService.Profile.ProfileRevision,
			InstructionRevision: sourceService.Instructions.InstructionRevision,
			Availability:        "unavailable", Reason: probeReason(), LastObservedAt: stale,
		},
		Root: "/host/workspaces/probehandoffsource", Instance: "default", Lifecycle: "running", LifecycleRevision: 1,
	})

	targetSandbox, serviceID, targetID := seedProbeHandoffTargetSide(t, store, serverID, now, manifest, report)
	targetService, err := store.ManagedService(ctx, manifest.TargetPolicy.ServiceRegistrationID)
	if err != nil || targetService == nil || targetService.Report.NativeRegistration == nil {
		t.Fatalf("target service = %#v, %v", targetService, err)
	}
	native := targetService.Report.NativeRegistration

	envelope, err := json.Marshal(map[string]any{
		"formatVersion": 1, "action": "reconcile_handoff", "status": "ready", "state": "prepared",
		"report": report, "consumption": nil, "release": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &probeHandoffRuntime{
		statusReceipts: map[string]map[string]any{
			manifest.Identity.SandboxID: {
				"schemaVersion": 1, "command": "status", "status": "running", "ready": true,
				"sessionId": manifest.Binding.NativeSessionID, "nativeProjectId": manifest.Binding.NativeProjectID,
				"nativeLocationDigest": manifest.Binding.NativeLocationDigest,
				"instructionRevision":  1, "instructionDigest": probeDigest("5"), "instructionApplied": true,
			},
			targetSandbox: {
				"schemaVersion": 1, "command": "status", "status": "running", "ready": true,
				"sessionId": native.NativeSessionID, "nativeProjectId": native.NativeProjectID,
				"nativeLocationDigest": native.NativeLocationDigest,
				"instructionRevision":  targetService.Manifest.Instructions.InstructionRevision,
				"instructionDigest":    targetService.Manifest.Instructions.InstructionDigest,
				"instructionApplied":   true,
			},
		},
		statusFailures: map[string]string{},
		reconcile:      envelope,
	}
	objects := &probeHandoffObjects{}
	controller := &continuity.S2Controller{
		Store: store, ServerID: serverID, Objects: objects,
		Catalog: &workspacecatalog.Catalog{State: store}, Helper: runtime, HandoffSupervisor: runtime, Now: now,
	}
	return &probeHandoffFixture{
		manifest: manifest, report: report, controller: controller, runtime: runtime,
		sourceSandbox: manifest.Identity.SandboxID, targetSandbox: targetSandbox,
		sourceID: manifest.Binding.RegisteredSourceID, serviceID: serviceID,
		sessionID: targetID, objects: objects,
	}
}

// seedProbeHandoffTargetSide seeds the complete target-side durable rows of one
// ready handoff: the target service and its registered primary source, the
// target handoff project, the ready preparation itself, and the mapped target
// session source. The caller owns the source side of the handoff.
func seedProbeHandoffTargetSide(
	t *testing.T, store *state.Store, serverID string, now func() time.Time,
	manifest model.ContinuationHandoffManifestV1, report model.ContinuationHandoffReportV1,
) (targetSandbox string, targetPrimarySourceID string, sessionSourceID string) {
	t.Helper()
	ctx := context.Background()
	stale := now().Add(-10 * time.Minute)
	targetPolicy := manifest.TargetPolicy
	primaryWorkspace := model.ManagedServiceWorkspaceV1{
		SelectionID: "selection_probehandofftargetprimary0001", ProjectID: "project_probehandofftargetprimary0001",
		WorkspaceEpoch: "epoch_probehandofftargetprimary0001", ScopeRevision: 1, Designation: "team_project",
		RootAttestation: probeDigest("9"),
	}
	targetService := model.ManagedServiceV1{
		FormatVersion: 1, OperationID: "op_probehandofftarget0001", ActionRevision: targetPolicy.ServiceActionRevision,
		DesiredRevision: targetPolicy.ServiceDesiredRevision, ConfigDigest: probeDigest("8"),
		DesiredState: "active", SessionMode: "lookup_only",
		Identity: model.ManagedServiceIdentityV1{
			ServerID: serverID, TeamID: targetPolicy.TeamID, MemberID: targetPolicy.MemberID,
			SandboxID: targetPolicy.SandboxID, SandboxGeneration: targetPolicy.SandboxGeneration,
			ServiceRegistrationID:     targetPolicy.ServiceRegistrationID,
			ExpectedServiceGeneration: targetPolicy.ServiceGeneration, Instance: "default", Role: targetPolicy.Role,
		},
		Profile: model.ManagedServiceProfileV1{
			SetupOperationID: "setup_probehandofftarget0001", ProfileID: targetPolicy.ProfileID,
			ProfileRevision: targetPolicy.ProfileRevision, ProfileDigest: targetPolicy.ProfileDigest,
		},
		Instructions: model.ManagedServiceInstructionsV1{
			InstructionRevision: targetPolicy.InstructionRevision, InstructionDigest: targetPolicy.InstructionDigest,
		},
		Workspace: primaryWorkspace,
	}
	native := &model.ManagedNativeRegistrationV1{
		RegisteredSourceID: "source_probehandofftargetprimary0001", WorkspaceEpoch: primaryWorkspace.WorkspaceEpoch,
		NativeSessionID: "ses_probehandofftargetprimary0001", NativeProjectID: strings.Repeat("a", 40),
		NativeLocationDigest: probeDigest("c"),
	}
	targetReport := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: targetService.OperationID, ActionRevision: targetService.ActionRevision,
		ObservedDesiredRevision: targetService.DesiredRevision, ConfigDigest: targetService.ConfigDigest,
		ObservedState: "ready", Identity: targetService.Identity, ServiceGeneration: targetPolicy.ServiceGeneration,
		ProfileStatus: "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "ready",
		InstructionApplied: true, InstructionRevision: targetPolicy.InstructionRevision,
		InstructionDigest: targetPolicy.InstructionDigest, NativeRegistration: native, ReceiptDigest: probeDigest("d"),
	}
	if err := store.PutManagedServiceIntent(ctx, state.LocalManagedService{
		Manifest: targetService, Phase: "ready",
		ProcessInstance: model.ManagedServiceProcessInstance("default", targetPolicy.ServiceGeneration),
		Port:            18443, CreationDispatched: true, ServiceGeneration: targetPolicy.ServiceGeneration,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateManagedService(ctx, targetPolicy.ServiceRegistrationID, "ready", &targetReport, ""); err != nil {
		t.Fatal(err)
	}
	putProbeSandbox(t, store, targetPolicy.SandboxID, targetPolicy.SandboxGeneration)
	primaryHostRoot := "/host/workspaces/probehandofftarget/primary"
	if err := store.PutManagedProject(ctx, state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: primaryWorkspace.SelectionID, ProjectID: primaryWorkspace.ProjectID,
			WorkspaceEpoch: primaryWorkspace.WorkspaceEpoch, SandboxID: targetPolicy.SandboxID,
			SandboxGeneration: targetPolicy.SandboxGeneration, ServiceRegistrationID: &targetPolicy.ServiceRegistrationID,
			Designation: "team_project", Label: "probe-target-primary", Availability: "available",
			RootAttestation: primaryWorkspace.RootAttestation, LastObservedAt: now(),
		},
		ServerID: serverID, TeamID: targetPolicy.TeamID, MemberID: targetPolicy.MemberID,
		AllocationDigest: probeDigest("a"), ConfigDigest: probeDigest("b"),
		Anchor: "/host/workspaces/probehandofftarget", HostRoot: primaryHostRoot,
		ContainerRoot: "/home/agent/projects/probehandofftarget", Phase: "ready", ScopeRevision: primaryWorkspace.ScopeRevision,
	}); err != nil {
		t.Fatal(err)
	}
	putProbeSource(t, store, state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: native.RegisteredSourceID,
			ServiceRegistrationID: targetPolicy.ServiceRegistrationID, ServiceGeneration: targetPolicy.ServiceGeneration,
			ProjectID: primaryWorkspace.ProjectID, SandboxID: targetPolicy.SandboxID,
			SandboxGeneration: targetPolicy.SandboxGeneration, WorkspaceEpoch: primaryWorkspace.WorkspaceEpoch,
			NativeSessionID: native.NativeSessionID, NativeProjectID: native.NativeProjectID,
			NativeLocationDigest: native.NativeLocationDigest, ScopeRevision: primaryWorkspace.ScopeRevision,
			Role: targetPolicy.Role, ProfileRevision: targetPolicy.ProfileRevision,
			InstructionRevision: targetPolicy.InstructionRevision,
			Availability:        "unavailable", Reason: probeReason(), LastObservedAt: stale,
		},
		Root: primaryHostRoot, Instance: "default", Lifecycle: "running", LifecycleRevision: 1,
	})

	target := *report.TargetWorkspace
	handoffHostRoot := "/host/workspaces/probehandoff/target"
	if err := store.PutManagedProject(ctx, state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: target.SelectionID, ProjectID: target.ProjectID,
			WorkspaceEpoch: target.WorkspaceEpoch, SandboxID: targetPolicy.SandboxID,
			SandboxGeneration: targetPolicy.SandboxGeneration, ServiceRegistrationID: &targetPolicy.ServiceRegistrationID,
			Designation: "continuity-handoff", Label: "probe-handoff", Availability: "available",
			RootAttestation: target.RootAttestation, LastObservedAt: now(),
		},
		ServerID: serverID, TeamID: targetPolicy.TeamID, MemberID: targetPolicy.MemberID,
		AllocationDigest: probeDigest("e"), ConfigDigest: probeDigest("f"),
		Anchor: "/host/workspaces/probehandoff", HostRoot: handoffHostRoot,
		ContainerRoot: "/home/agent/projects/probehandoff", Phase: "ready", ScopeRevision: target.ScopeRevision,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuationHandoffPreparation(ctx, state.LocalContinuationHandoffPreparation{
		Manifest: manifest, Phase: "allocating",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationHandoffPreparation(ctx, manifest.OperationID, target.SelectionID, report); err != nil {
		t.Fatal(err)
	}
	putProbeSource(t, store, state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: report.Session.RegisteredSourceID,
			ServiceRegistrationID: targetPolicy.ServiceRegistrationID, ServiceGeneration: targetPolicy.ServiceGeneration,
			ProjectID: target.ProjectID, SandboxID: targetPolicy.SandboxID, SandboxGeneration: targetPolicy.SandboxGeneration,
			WorkspaceEpoch: target.WorkspaceEpoch, NativeSessionID: report.Session.NativeSessionID,
			NativeProjectID: report.Session.NativeProjectID, NativeLocationDigest: report.Session.NativeLocationDigest,
			ScopeRevision: target.ScopeRevision, Role: targetPolicy.Role,
			ProfileRevision: targetPolicy.ProfileRevision, InstructionRevision: targetPolicy.InstructionRevision,
			Availability: "unavailable", Reason: probeReason(), LastObservedAt: stale,
		},
		Root: handoffHostRoot, Instance: "default", Lifecycle: "running",
		LifecycleRevision: manifest.DesiredRevision, NoAdmittedExecution: true,
	})
	return targetPolicy.SandboxID, native.RegisteredSourceID, report.Session.RegisteredSourceID
}

// probeHandoffManifest keeps both handoff boxes in the desired set so the
// sandbox loop reconciles them instead of pruning them, exactly like the live
// manifest keeps the handoff source and target boxes, and carries the stored
// handoff intent so manifest validation and ApplyHandoffs stay in the pass.
func probeHandoffManifest(journey *managerPolicyJourney, fixture *probeHandoffFixture) model.Manifest {
	manifest := journey.manifest
	manifest.ContinuityHandoffs = []model.ContinuationHandoffManifestV1{fixture.manifest}
	manifest.Sandboxes = append(append([]model.Sandbox(nil), journey.manifest.Sandboxes...),
		model.Sandbox{
			ID: fixture.sourceSandbox, Name: "probe-handoff-source", Size: "small",
			Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 9, PIDs: 32},
			Lifetime:  "persistent", DesiredState: "running", Generation: 1,
		},
		model.Sandbox{
			ID: fixture.targetSandbox, Name: "probe-handoff-target", Size: "small",
			Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 9, PIDs: 32},
			Lifetime:  "persistent", DesiredState: "running", Generation: 1,
		},
	)
	return manifest
}

func probePreparationRecord(t *testing.T, store *state.Store, operationID string) *state.LocalContinuationHandoffPreparation {
	t.Helper()
	record, err := store.ContinuationHandoffPreparation(context.Background(), operationID)
	if err != nil || record == nil {
		t.Fatalf("handoff preparation %s = %#v, %v", operationID, record, err)
	}
	return record
}

func assertProbeSourceStale(t *testing.T, store *state.Store, id string, observed time.Time) {
	t.Helper()
	row, err := store.ContinuitySource(context.Background(), id)
	if err != nil || row == nil {
		t.Fatalf("continuity source %s = %#v, %v", id, row, err)
	}
	if row.Report.Availability != "unavailable" || row.Report.Reason == nil || *row.Report.Reason != "probe_stale" ||
		!row.Report.LastObservedAt.Equal(observed) {
		t.Fatalf("continuity source %s was refreshed by a probe that did not complete: %#v", id, row.Report)
	}
}

func assertProbeSourceProbed(t *testing.T, store *state.Store, id string, observed time.Time) {
	t.Helper()
	row, err := store.ContinuitySource(context.Background(), id)
	if err != nil || row == nil {
		t.Fatalf("continuity source %s = %#v, %v", id, row, err)
	}
	if row.Report.Availability != "available" || row.Report.Reason != nil || !row.Report.LastObservedAt.Equal(observed) {
		t.Fatalf("continuity source %s was not truthfully refreshed: %#v", id, row.Report)
	}
}

// TestReconcileDefersHandoffProbeFailureAndStillAdvancesThePass reproduces the
// live circular wedge: a ready handoff whose source supervisor probe fails with
// a stale-process-class error must stay fail-closed and unadvanced, while the
// same pass still reconciles sandboxes, managed services, setup and the
// applied revision so the runtime can repair the probe precondition itself.
func TestReconcileDefersHandoffProbeFailureAndStillAdvancesThePass(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	probe := seedProbeReadyHandoff(t, journey.store, journey.reconciler.ServerID, journey.reconciler.Now)
	journey.reconciler.ContinuationHandoff = probe.controller
	probe.runtime.statusFailures[probe.sourceSandbox] =
		"Error: can only create exec sessions on running containers (error=stale_process)"
	manifest := probeHandoffManifest(journey, probe)
	ctx := context.Background()
	before := probePreparationRecord(t, journey.store, probe.manifest.OperationID)

	if err := journey.reconciler.Reconcile(ctx, manifest); err != nil {
		t.Fatalf("handoff probe failure aborted the whole reconcile: %v", err)
	}
	if after := probePreparationRecord(t, journey.store, probe.manifest.OperationID); !reflect.DeepEqual(before, after) {
		t.Fatalf("deferred handoff preparation changed: before=%#v after=%#v", before, after)
	}
	// The incomplete probe published nothing: every stored observation stays
	// unavailable with its original timestamp.
	stale := journey.reconciler.Now().Add(-10 * time.Minute)
	assertProbeSourceStale(t, journey.store, probe.sourceID, stale)
	assertProbeSourceStale(t, journey.store, probe.serviceID, stale)
	assertProbeSourceStale(t, journey.store, probe.sessionID, stale)
	if !reflect.DeepEqual(probe.runtime.actions, []string{string(containers.ManagedSupervisorStatus)}) {
		t.Fatalf("deferred probe reached more than the failing source probe: %v", probe.runtime.actions)
	}
	if probe.objects.calls != 0 {
		t.Fatalf("deferred probe reached the object store: %d", probe.objects.calls)
	}
	// The pass continued: every live box was reconciled (the stopped handoff
	// source box can be started by the runtime again), the managed service was
	// applied, and the applied revision advanced.
	engine, ok := journey.reconciler.Engine.(*contractEngine)
	if !ok || engine.ensured != 3 {
		t.Fatalf("sandbox loop did not reconcile every live box: %#v", journey.reconciler.Engine)
	}
	if len(journey.control.enrollments) != 1 {
		t.Fatalf("managed service was not reconciled in the deferred pass: enrollments=%d", len(journey.control.enrollments))
	}
	service, err := journey.store.ManagedService(ctx, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if err != nil || service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" {
		t.Fatalf("managed service did not reach ready: %#v, %v", service, err)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != manifest.DesiredRevision {
		t.Fatalf("deferred pass did not advance the applied revision to %d: %d, %v", manifest.DesiredRevision, revision, err)
	}
	report, err := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if err != nil {
		t.Fatal(err)
	}
	managedReady := false
	for _, service := range report.ManagedServices {
		if service.OperationID == journey.fixture.ServiceManifest.OperationID && service.ObservedState == "ready" {
			managedReady = true
		}
	}
	if report.AppliedRevision != manifest.DesiredRevision || len(report.Sandboxes) != 3 || !managedReady ||
		len(report.ContinuityHandoffs) != 1 || report.ContinuityHandoffs[0].Status != "ready" {
		t.Fatalf("deferred pass report content = %#v", report)
	}
	// The deferred probe error is returned only when nothing else in the pass
	// could proceed: an unrelated managed-service abort stays visible and
	// carries the probe failure alongside it.
	probe.runtime.actions = nil
	journey.control.enrollErr = errors.New("managed workspace is unavailable")
	err = journey.reconciler.Reconcile(ctx, manifest)
	if err == nil || !strings.Contains(err.Error(), "apply managed services:") ||
		!strings.Contains(err.Error(), "recover continuation handoffs:") {
		t.Fatalf("deferred probe error was not visible next to the unrelated abort: %v", err)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != manifest.DesiredRevision {
		t.Fatalf("failed pass moved the applied revision: %d, %v", revision, err)
	}
}

// TestReconcileResumesDeferredHandoffProbeOnceTheProbeSucceeds proves the other
// half of the invariant: after the sandbox loop reconciles the box whose
// container the probe could not reach, the next pass follows the ordinary
// re-observe path and truthfully refreshes all three registered sources.
func TestReconcileResumesDeferredHandoffProbeOnceTheProbeSucceeds(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	probe := seedProbeReadyHandoff(t, journey.store, journey.reconciler.ServerID, journey.reconciler.Now)
	journey.reconciler.ContinuationHandoff = probe.controller
	probe.runtime.statusFailures[probe.sourceSandbox] =
		"Error: can only create exec sessions on running containers (error=stale_process)"
	manifest := probeHandoffManifest(journey, probe)
	ctx := context.Background()

	if err := journey.reconciler.Reconcile(ctx, manifest); err != nil {
		t.Fatalf("handoff probe failure aborted the whole reconcile: %v", err)
	}
	engine, ok := journey.reconciler.Engine.(*contractEngine)
	if !ok || engine.ensured != 3 {
		t.Fatalf("sandbox loop did not reconcile every live box: %#v", journey.reconciler.Engine)
	}
	deferred := probePreparationRecord(t, journey.store, probe.manifest.OperationID)

	// The box reconcilers restored the probe precondition, so the ordinary
	// monitor fetch path answers again.
	delete(probe.runtime.statusFailures, probe.sourceSandbox)
	probe.runtime.actions = nil
	if err := journey.reconciler.Reconcile(ctx, manifest); err != nil {
		t.Fatalf("healed handoff probe did not follow the ordinary path: %v", err)
	}
	if !reflect.DeepEqual(probe.runtime.actions, []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus), "reconcile_handoff",
	}) {
		t.Fatalf("healed probe actions = %v", probe.runtime.actions)
	}
	observed := journey.reconciler.Now()
	assertProbeSourceProbed(t, journey.store, probe.sourceID, observed)
	assertProbeSourceProbed(t, journey.store, probe.serviceID, observed)
	assertProbeSourceProbed(t, journey.store, probe.sessionID, observed)
	// The ready report republishes conflict-free and byte-identically: the
	// deferral never advanced the record, and the healed pass did not either.
	if resumed := probePreparationRecord(t, journey.store, probe.manifest.OperationID); !reflect.DeepEqual(deferred, resumed) {
		t.Fatalf("resumed handoff preparation drifted: %#v -> %#v", deferred, resumed)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != manifest.DesiredRevision {
		t.Fatalf("healed pass did not advance the applied revision to %d: %d, %v", manifest.DesiredRevision, revision, err)
	}
}

// TestReconcileDefersUnreachableTargetHandoffProbe covers the target session
// probe: when the target sandbox cannot be exec'd, the handoff stays
// fail-closed but the pass still reconciles and advances.
func TestReconcileDefersUnreachableTargetHandoffProbe(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	probe := seedProbeReadyHandoff(t, journey.store, journey.reconciler.ServerID, journey.reconciler.Now)
	journey.reconciler.ContinuationHandoff = probe.controller
	probe.runtime.reconcileErr = errors.New("can only create exec sessions on running containers: exit status 125")
	manifest := probeHandoffManifest(journey, probe)
	ctx := context.Background()
	before := probePreparationRecord(t, journey.store, probe.manifest.OperationID)

	if err := journey.reconciler.Reconcile(ctx, manifest); err != nil {
		t.Fatalf("unreachable target handoff probe aborted the whole reconcile: %v", err)
	}
	if after := probePreparationRecord(t, journey.store, probe.manifest.OperationID); !reflect.DeepEqual(before, after) {
		t.Fatalf("deferred handoff preparation changed: before=%#v after=%#v", before, after)
	}
	// Both supervisor status probes completed and refreshed truthfully; only
	// the target session whose dispatch never ran stays stale.
	observed := journey.reconciler.Now()
	assertProbeSourceProbed(t, journey.store, probe.sourceID, observed)
	assertProbeSourceProbed(t, journey.store, probe.serviceID, observed)
	assertProbeSourceStale(t, journey.store, probe.sessionID, observed.Add(-10*time.Minute))
	if revision, err := journey.store.Revision(ctx); err != nil || revision != manifest.DesiredRevision {
		t.Fatalf("deferred pass did not advance the applied revision to %d: %d, %v", manifest.DesiredRevision, revision, err)
	}
}

// TestReconcileKeepsNonProbeHandoffFailuresFatalAndVisible pins the boundary of
// the probe deferral: a probe that answers with a receipt contradicting the
// stored tuple, and a probe that answers with a refusal, both remain fatal and
// abort the pass before any sandbox or managed-service work.
func TestReconcileKeepsNonProbeHandoffFailuresFatalAndVisible(t *testing.T) {
	cases := map[string]func(*probeHandoffFixture){
		"source status receipt does not prove the stored session": func(probe *probeHandoffFixture) {
			probe.runtime.statusReceipts[probe.sourceSandbox]["sessionId"] = "ses_probe_foreign0001"
		},
		"target reconcile refuses the ready session": func(probe *probeHandoffFixture) {
			probe.runtime.refusal = "handoff_identity_mismatch"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			journey := newManagerPolicyJourney(t)
			probe := seedProbeReadyHandoff(t, journey.store, journey.reconciler.ServerID, journey.reconciler.Now)
			journey.reconciler.ContinuationHandoff = probe.controller
			mutate(probe)
			manifest := probeHandoffManifest(journey, probe)
			ctx := context.Background()
			before := probePreparationRecord(t, journey.store, probe.manifest.OperationID)

			err := journey.reconciler.Reconcile(ctx, manifest)
			if err == nil || !strings.Contains(err.Error(), "recover continuation handoffs:") {
				t.Fatalf("non-probe handoff failure was skipped: %v", err)
			}
			if !errors.Is(err, continuity.ErrS2RecoveryUnknown) || errors.Is(err, continuity.ErrSourceServiceNotReady) ||
				errors.Is(err, continuity.ErrTargetServiceNotReady) {
				t.Fatalf("non-probe handoff failure classification = %v", err)
			}
			if after := probePreparationRecord(t, journey.store, probe.manifest.OperationID); !reflect.DeepEqual(before, after) {
				t.Fatalf("fatal handoff recovery changed the preparation: before=%#v after=%#v", before, after)
			}
			if revision, err := journey.store.Revision(ctx); err != nil || revision != 0 {
				t.Fatalf("failed pass advanced the applied revision: %d, %v", revision, err)
			}
			if engine, ok := journey.reconciler.Engine.(*contractEngine); !ok || engine.ensured != 0 {
				t.Fatalf("failed pass reached the sandbox loop: %#v", journey.reconciler.Engine)
			}
			if len(journey.control.enrollments) != 0 {
				t.Fatalf("failed pass reached managed services: %d", len(journey.control.enrollments))
			}
			if probe.objects.calls != 0 {
				t.Fatalf("failed pass reached the object store: %d", probe.objects.calls)
			}
		})
	}
}
