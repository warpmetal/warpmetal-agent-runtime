package reconcile

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

const (
	handoffIsolationServerID       = "srv_handoffisolation033"
	handoffIsolationSourceSandbox  = "sbx_033_source"
	handoffIsolationDesiredSandbox = "sbx_033_desired"
)

type isolationHandoffObjects struct{ calls int }

func (f *isolationHandoffObjects) Verify(context.Context, string) (storage.DurableCapture, error) {
	f.calls++
	return storage.DurableCapture{}, errors.New("handoff isolation must not verify objects")
}

func (f *isolationHandoffObjects) VerifyWorkspace(context.Context, string, string) error {
	f.calls++
	return errors.New("handoff isolation must not verify workspaces")
}

func (f *isolationHandoffObjects) MaterializeNew(context.Context, storage.MaterializeNewRequest) (storage.MaterializeReceipt, error) {
	f.calls++
	return storage.MaterializeReceipt{}, errors.New("handoff isolation must not materialize")
}

type isolationHandoffSupervisor struct{ calls int }

func (f *isolationHandoffSupervisor) ExecManagedSupervisor(context.Context, string, containers.ManagedSupervisorAction, []byte) ([]byte, []byte, error) {
	f.calls++
	return nil, nil, errors.New("handoff isolation must not probe the supervisor")
}

type isolationHandoffHelper struct {
	calls      int
	operations []string
	released   []byte
}

func (f *isolationHandoffHelper) ExecContinuity(_ context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	f.calls++
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	operationID, _ := request["operationId"].(string)
	f.operations = append(f.operations, operationID)
	return f.released, nil, nil
}

type isolationSourceService struct {
	manifest  model.ManagedServiceV1
	report    model.ManagedServiceReportV1
	phase     string
	errorCode string
}

type handoffIsolationOptions struct {
	skipSourceService    bool
	corruptSourceService bool
	mutateSourceService  func(*isolationSourceService)
}

type handoffIsolationState struct {
	store       *state.Store
	path        string
	manifest    model.ContinuationHandoffManifestV1
	releasePrep model.ContinuationHandoffManifestV1
	release     model.ContinuationHandoffReleaseManifestV1
	controller  *continuity.S2Controller
	helper      *isolationHandoffHelper
	supervisor  *isolationHandoffSupervisor
	objects     *isolationHandoffObjects
}

// seedHandoffIsolationState builds the live L7 shape: a ready handoff
// preparation whose exact-tuple source service is locally failed, an
// independent preparation with a pending release, and the target rows the
// production recovery path reads before any probe.
func seedHandoffIsolationState(t *testing.T, options handoffIsolationOptions) *handoffIsolationState {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fixture := readS2BWorkerFixture(t)

	manifest := fixture.ReviewerManifest
	manifest.OperationID = "op_handoff_033_failedsource"
	manifest.DesiredRevision = 1
	manifest.MappingID = "mapping_033_failedsource"
	manifest.TargetWorkID = "work_handoff_033_failedsource"
	manifest.Identity = model.ContinuationIdentityV1{
		WorkID: "work_033_source", ProjectID: "project_033_source", SandboxID: handoffIsolationSourceSandbox,
		WorkspaceEpoch: "epoch_033_source", SandboxGeneration: 1, ExpectedRevision: 1,
	}
	manifest.Binding = model.ContinuationBindingRefV1{
		BindingID: "binding_033_source", BindingRevision: 1, ScopeRevision: 1,
		ServiceRegistrationID: "service_033_source", ServiceGeneration: 1,
		RegisteredSourceID: "source_033_source", NativeSessionID: "ses_033_source",
		NativeProjectID: strings.Repeat("a", 40), NativeLocationDigest: "sha256:" + strings.Repeat("a", 64),
	}
	manifest.Checkpoint = model.ContinuationCheckpointRefV1{
		OperationID: "op_capture_033", CheckpointID: "checkpoint_033",
		ManifestDigest: "sha256:" + strings.Repeat("b", 64), Bytes: 8, ObjectCount: 1,
	}
	manifest.Lineage.SourceWorkID = manifest.Identity.WorkID
	manifest.Lineage.SourceRevision = manifest.Identity.ExpectedRevision
	manifest.Lineage.CheckpointOperationID = manifest.Checkpoint.OperationID
	prepSelection := "selection_033_failed"
	prepWorkspace := model.ContinuationHandoffTargetWorkspaceV1{
		SelectionID: prepSelection, ProjectID: manifest.Identity.ProjectID,
		WorkspaceEpoch: manifest.Identity.WorkspaceEpoch, ScopeRevision: 1,
		RootAttestation: "sha256:" + strings.Repeat("1", 64),
	}

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
				RegisteredSourceID:    manifest.Binding.RegisteredSourceID,
				ServiceRegistrationID: manifest.Binding.ServiceRegistrationID,
				NativeSessionID:       manifest.Binding.NativeSessionID,
				NativeProjectID:       manifest.Binding.NativeProjectID,
				NativeLocationDigest:  manifest.Binding.NativeLocationDigest,
			},
		},
		ObservedStatus: "verified", ServiceGeneration: manifest.Binding.ServiceGeneration,
		ReceiptDigest: "sha256:" + strings.Repeat("2", 64),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuitySource(ctx, state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: manifest.Binding.RegisteredSourceID,
			ServiceRegistrationID: manifest.Binding.ServiceRegistrationID, ServiceGeneration: manifest.Binding.ServiceGeneration,
			ProjectID: manifest.Identity.ProjectID, SandboxID: manifest.Identity.SandboxID,
			SandboxGeneration: manifest.Identity.SandboxGeneration, WorkspaceEpoch: manifest.Identity.WorkspaceEpoch,
			NativeSessionID: manifest.Binding.NativeSessionID, NativeProjectID: manifest.Binding.NativeProjectID,
			NativeLocationDigest: manifest.Binding.NativeLocationDigest, ScopeRevision: manifest.Binding.ScopeRevision,
			Role: "worker", ProfileRevision: 1, InstructionRevision: 1,
			Availability: "available", LastObservedAt: time.Now().UTC(),
		},
		Root: "/host/workspaces/033_source", Instance: "default", Lifecycle: "running", LifecycleRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	source := isolationSourceService{
		manifest: model.ManagedServiceV1{
			FormatVersion: 1, OperationID: "op_033_source_service", ActionRevision: 1, DesiredRevision: 1,
			ConfigDigest: "sha256:" + strings.Repeat("3", 64),
			DesiredState: "active", SessionMode: "lookup_only",
			Identity: model.ManagedServiceIdentityV1{
				ServerID: handoffIsolationServerID, TeamID: "team_033", MemberID: "tmem_033",
				SandboxID: manifest.Identity.SandboxID, SandboxGeneration: manifest.Identity.SandboxGeneration,
				ServiceRegistrationID:     manifest.Binding.ServiceRegistrationID,
				ExpectedServiceGeneration: manifest.Binding.ServiceGeneration,
				Instance:                  "default", Role: "worker",
			},
			Profile: model.ManagedServiceProfileV1{
				SetupOperationID: "setup_033_source", ProfileID: "opencode",
				ProfileRevision: 1, ProfileDigest: "sha256:" + strings.Repeat("4", 64),
			},
			Instructions: model.ManagedServiceInstructionsV1{
				InstructionRevision: 1, InstructionDigest: "sha256:" + strings.Repeat("5", 64),
			},
			Workspace: model.ManagedServiceWorkspaceV1{
				SelectionID: "selection_033_source_primary", ProjectID: manifest.Identity.ProjectID,
				WorkspaceEpoch: manifest.Identity.WorkspaceEpoch, ScopeRevision: 1, Designation: "team_project",
				RootAttestation: "sha256:" + strings.Repeat("6", 64),
			},
		},
		report: model.ManagedServiceReportV1{
			FormatVersion: 1, OperationID: "op_033_source_service", ActionRevision: 1,
			ObservedDesiredRevision: 1, ConfigDigest: "sha256:" + strings.Repeat("3", 64),
			ObservedState: "failed", ServiceGeneration: manifest.Binding.ServiceGeneration,
			InstructionApplied: false, InstructionRevision: 1, InstructionDigest: "sha256:" + strings.Repeat("5", 64),
			ReceiptDigest: "sha256:" + strings.Repeat("7", 64),
		},
		phase: "failed", errorCode: "enrollment_unavailable",
	}
	source.report.Identity = source.manifest.Identity
	if options.mutateSourceService != nil {
		options.mutateSourceService(&source)
	}
	if !options.skipSourceService {
		if err := store.PutManagedServiceIntent(ctx, state.LocalManagedService{
			Manifest: source.manifest, Phase: source.phase,
			ProcessInstance: model.ManagedServiceProcessInstance(source.manifest.Identity.Instance, source.manifest.Identity.ExpectedServiceGeneration),
			Port:            18443, CreationDispatched: true, ServiceGeneration: source.manifest.Identity.ExpectedServiceGeneration,
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.UpdateManagedService(ctx, source.manifest.Identity.ServiceRegistrationID, source.phase, &source.report, source.errorCode); err != nil {
			t.Fatal(err)
		}
		if options.corruptSourceService {
			corruptManagedService(t, path, source.manifest.Identity.ServiceRegistrationID)
		}
	}

	targetPolicy := manifest.TargetPolicy
	if err := store.PutManagedServiceIntent(ctx, state.LocalManagedService{
		Manifest: model.ManagedServiceV1{
			FormatVersion: 1, OperationID: "op_033_target_service", ActionRevision: targetPolicy.ServiceActionRevision,
			DesiredRevision: targetPolicy.ServiceDesiredRevision, ConfigDigest: "sha256:" + strings.Repeat("8", 64),
			DesiredState: "active", SessionMode: "lookup_only",
			Identity: model.ManagedServiceIdentityV1{
				ServerID: handoffIsolationServerID, TeamID: targetPolicy.TeamID, MemberID: targetPolicy.MemberID,
				SandboxID: targetPolicy.SandboxID, SandboxGeneration: targetPolicy.SandboxGeneration,
				ServiceRegistrationID:     targetPolicy.ServiceRegistrationID,
				ExpectedServiceGeneration: targetPolicy.ServiceGeneration,
				Instance:                  "default", Role: targetPolicy.Role,
			},
			Profile: model.ManagedServiceProfileV1{
				SetupOperationID: "setup_033_target", ProfileID: targetPolicy.ProfileID,
				ProfileRevision: targetPolicy.ProfileRevision, ProfileDigest: targetPolicy.ProfileDigest,
			},
			Instructions: model.ManagedServiceInstructionsV1{
				InstructionRevision: targetPolicy.InstructionRevision, InstructionDigest: targetPolicy.InstructionDigest,
			},
			Workspace: model.ManagedServiceWorkspaceV1{
				SelectionID: "selection_033_target_primary", ProjectID: "project_033_target_primary",
				WorkspaceEpoch: "epoch_033_target_primary", ScopeRevision: 1, Designation: "team_project",
				RootAttestation: "sha256:" + strings.Repeat("9", 64),
			},
		},
		Phase: "ready", ProcessInstance: model.ManagedServiceProcessInstance("default", targetPolicy.ServiceGeneration),
		Port: 18443, CreationDispatched: true, ServiceGeneration: targetPolicy.ServiceGeneration,
	}); err != nil {
		t.Fatal(err)
	}

	releasePrep := fixture.ReviewerManifest
	releasePrep.OperationID = "op_handoff_033_release"
	releasePrep.DesiredRevision = 1
	releasePrep.MappingID = "mapping_033_release"
	releasePrep.TargetWorkID = "work_handoff_033_release"
	releasePrep.Identity = manifest.Identity
	releasePrep.Binding = manifest.Binding
	releasePrep.Checkpoint = manifest.Checkpoint
	releasePrep.Lineage = manifest.Lineage
	releaseSelection := "selection_033_release"
	releaseWorkspace := model.ContinuationHandoffTargetWorkspaceV1{
		SelectionID: releaseSelection, ProjectID: "project_033_release",
		WorkspaceEpoch: "epoch_033_release", ScopeRevision: 1,
		RootAttestation: "sha256:" + strings.Repeat("a", 64),
	}
	releasePrepReport := isolationReadyReport(releasePrep, fixture.ReviewerReport, releaseWorkspace)
	releaseSession := *releasePrepReport.Session
	releaseSession.RegisteredSourceID = "source_033_release_session"
	releasePrepReport.Session = &releaseSession

	for _, record := range []struct {
		manifest  model.ContinuationHandoffManifestV1
		report    model.ContinuationHandoffReportV1
		selection string
		workspace model.ContinuationHandoffTargetWorkspaceV1
	}{
		{manifest: manifest, report: isolationReadyReport(manifest, fixture.ReviewerReport, prepWorkspace), selection: prepSelection, workspace: prepWorkspace},
		{manifest: releasePrep, report: releasePrepReport, selection: releaseSelection, workspace: releaseWorkspace},
	} {
		if err := store.PutContinuationHandoffPreparation(ctx, state.LocalContinuationHandoffPreparation{
			Manifest: record.manifest, Phase: "allocating",
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.CompleteContinuationHandoffPreparation(ctx, record.manifest.OperationID, record.selection, record.report); err != nil {
			t.Fatal(err)
		}
		if err := store.PutManagedProject(ctx, state.LocalManagedProject{
			Report: model.ProjectCatalogReportV1{
				FormatVersion: 1, SelectionID: record.selection, ProjectID: record.workspace.ProjectID,
				WorkspaceEpoch: record.workspace.WorkspaceEpoch, SandboxID: targetPolicy.SandboxID,
				SandboxGeneration: targetPolicy.SandboxGeneration, Designation: "continuity-handoff", Label: "033",
				Availability: "available", RootAttestation: record.workspace.RootAttestation,
				LastObservedAt: time.Now().UTC(),
			},
			ServerID: handoffIsolationServerID, TeamID: targetPolicy.TeamID, MemberID: targetPolicy.MemberID,
			AllocationDigest: "sha256:" + strings.Repeat("b", 64), ConfigDigest: "sha256:" + strings.Repeat("8", 64),
			Anchor: "/host/workspaces/033", HostRoot: "/host/workspaces/033/" + record.selection,
			ContainerRoot: "/home/agent/projects/033", Phase: "ready", ScopeRevision: record.workspace.ScopeRevision,
		}); err != nil {
			t.Fatal(err)
		}
	}

	release := fixture.ReleaseManifest
	release.OperationID = "op_release_033"
	release.PrepareDesiredRevision = releasePrep.DesiredRevision
	release.DesiredRevision = releasePrep.DesiredRevision + 1
	release.Reason = "superseded"
	release.HandoffKind = releasePrep.HandoffKind
	release.SessionMode = releasePrep.SessionMode
	release.TargetWorkID = releasePrep.TargetWorkID
	release.MappingID = releasePrep.MappingID
	release.Identity = releasePrep.Identity
	release.Binding = releasePrep.Binding
	release.Checkpoint = releasePrep.Checkpoint
	release.Lineage = releasePrep.Lineage
	release.TargetPolicy = releasePrep.TargetPolicy
	release.Workspace = releasePrep.Workspace
	release.Context = releasePrep.Context
	if err := store.PutContinuationHandoffRelease(ctx, state.LocalContinuationHandoffRelease{
		Manifest: release, Phase: "releasing",
	}); err != nil {
		t.Fatal(err)
	}
	releaseReport := fixture.ReleaseReport
	releaseReport.ContinuationHandoffReleaseManifestV1 = release
	releaseReport.Status = "released"
	releaseReport.ErrorCode = nil
	releaseReport.ReceiptDigest = "sha256:" + strings.Repeat("c", 64)
	envelope, err := json.Marshal(map[string]any{
		"formatVersion": 1, "action": "reconcile_handoff", "status": "released", "state": "released",
		"report": releasePrepReport, "consumption": nil, "release": releaseReport,
	})
	if err != nil {
		t.Fatal(err)
	}

	helper := &isolationHandoffHelper{released: envelope}
	supervisor := &isolationHandoffSupervisor{}
	objects := &isolationHandoffObjects{}
	controller := &continuity.S2Controller{
		Store: store, ServerID: handoffIsolationServerID, Objects: objects,
		Catalog: &workspacecatalog.Catalog{State: store}, Helper: helper,
		HandoffSupervisor: supervisor,
	}
	return &handoffIsolationState{
		store: store, path: path, manifest: manifest, releasePrep: releasePrep, release: release,
		controller: controller, helper: helper, supervisor: supervisor, objects: objects,
	}
}

func isolationReadyReport(
	manifest model.ContinuationHandoffManifestV1,
	base model.ContinuationHandoffReportV1,
	workspace model.ContinuationHandoffTargetWorkspaceV1,
) model.ContinuationHandoffReportV1 {
	report := base
	report.FormatVersion = 1
	report.OperationID = manifest.OperationID
	report.Action = manifest.Action
	report.DesiredRevision = manifest.DesiredRevision
	report.HandoffKind = manifest.HandoffKind
	report.SessionMode = manifest.SessionMode
	report.TargetWorkID = manifest.TargetWorkID
	report.MappingID = manifest.MappingID
	report.Identity = manifest.Identity
	report.Binding = manifest.Binding
	report.Checkpoint = manifest.Checkpoint
	report.Lineage = manifest.Lineage
	report.TargetPolicy = manifest.TargetPolicy
	report.WorkspaceRequest = manifest.Workspace
	report.ContextDigest = manifest.Context.Digest
	report.Status = "ready"
	report.ErrorCode = nil
	report.TargetWorkspace = &workspace
	return report
}

func isolationDesiredManifest() model.Manifest {
	return model.Manifest{
		ServerID: handoffIsolationServerID, DesiredRevision: 1,
		ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
		Capacity:    model.Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20},
		Sandboxes: []model.Sandbox{{
			ID: handoffIsolationDesiredSandbox, Name: "worker", Size: "small",
			Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			Lifetime:  "persistent", DesiredState: "running", Generation: 1,
		}},
	}
}

func isolationReconciler(t *testing.T, setup *handoffIsolationState, engine *fakeEngine) *Reconciler {
	t.Helper()
	return &Reconciler{
		Store: setup.store, Engine: engine, Workspaces: &fakeWorkspaces{},
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		Sessions:     &fakeSessions{},
		HostCapacity: model.Resources{CPUMillicores: 2000, MemoryMiB: 4096, WorkspaceDiskGiB: 40},
		ServerID:     handoffIsolationServerID, ContinuationHandoff: setup.controller,
	}
}

type isolationPreparationRow struct {
	Manifest  string
	Phase     string
	Selection string
	Report    string
	UpdatedAt string
}

func isolationPreparationState(t *testing.T, path, operationID string) isolationPreparationRow {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var row isolationPreparationRow
	if err := db.QueryRowContext(context.Background(),
		`SELECT manifest_json, phase, target_selection_id, COALESCE(report_json, ''), updated_at
		 FROM continuation_handoff_preparations WHERE operation_id = ?`, operationID).
		Scan(&row.Manifest, &row.Phase, &row.Selection, &row.Report, &row.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	return row
}

func isolationReleaseState(t *testing.T, setup *handoffIsolationState) *state.LocalContinuationHandoffRelease {
	t.Helper()
	release, err := setup.store.ContinuationHandoffRelease(context.Background(), setup.release.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	return release
}

func corruptManagedService(t *testing.T, path, serviceID string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(context.Background(),
		`UPDATE managed_services SET manifest_json = '{' WHERE service_registration_id = ?`, serviceID); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileIsolatesFailedSourceServiceHandoffRecovery(t *testing.T) {
	setup := seedHandoffIsolationState(t, handoffIsolationOptions{})
	ctx := context.Background()
	before := isolationPreparationState(t, setup.path, setup.manifest.OperationID)
	engine := &fakeEngine{}
	reconciler := isolationReconciler(t, setup, engine)
	if err := reconciler.Reconcile(ctx, isolationDesiredManifest()); err != nil {
		t.Fatalf("failed source service aborted the whole reconcile: %v", err)
	}
	after := isolationPreparationState(t, setup.path, setup.manifest.OperationID)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed preparation changed: before=%#v after=%#v", before, after)
	}
	if setup.supervisor.calls != 0 || setup.objects.calls != 0 {
		t.Fatalf("failed preparation was probed: supervisor=%d objects=%d", setup.supervisor.calls, setup.objects.calls)
	}
	if !reflect.DeepEqual(setup.helper.operations, []string{setup.releasePrep.OperationID}) {
		t.Fatalf("helper calls = %v, want only release preparation %s", setup.helper.operations, setup.releasePrep.OperationID)
	}
	release := isolationReleaseState(t, setup)
	if release == nil || release.Report == nil || release.Report.Status != "released" {
		t.Fatalf("independent release recovery did not continue: %#v", release)
	}
	if release.Report.ReceiptDigest != "sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("independent release report = %#v", release.Report)
	}
	if engine.created != 1 {
		t.Fatalf("manifest apply did not advance the desired sandbox: created=%d", engine.created)
	}
	local, err := setup.store.Sandbox(ctx, handoffIsolationDesiredSandbox)
	if err != nil || local == nil || local.ObservedState != "running" {
		t.Fatalf("desired sandbox did not reach running: %#v, %v", local, err)
	}
}

func TestReconcileKeepsStructuralSourceServiceFailuresFatal(t *testing.T) {
	cases := map[string]handoffIsolationOptions{
		"missing source service": {skipSourceService: true},
		"source service lookup error": {
			corruptSourceService: true,
		},
		"service generation drift": {
			mutateSourceService: func(s *isolationSourceService) { s.report.ServiceGeneration++ },
		},
		"service identity drift": {
			mutateSourceService: func(s *isolationSourceService) { s.manifest.Identity.SandboxGeneration++ },
		},
		"instruction revision drift on failed service": {
			mutateSourceService: func(s *isolationSourceService) { s.report.InstructionRevision++ },
		},
		"instruction digest drift on failed service": {
			mutateSourceService: func(s *isolationSourceService) {
				s.report.InstructionDigest = "sha256:" + strings.Repeat("d", 64)
			},
		},
		"ready service without instruction proof": {
			mutateSourceService: func(s *isolationSourceService) {
				s.phase = "ready"
				s.report.ObservedState = "ready"
				s.report.InstructionApplied = false
			},
		},
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			setup := seedHandoffIsolationState(t, options)
			before := isolationPreparationState(t, setup.path, setup.manifest.OperationID)
			engine := &fakeEngine{}
			reconciler := isolationReconciler(t, setup, engine)
			err := reconciler.Reconcile(context.Background(), isolationDesiredManifest())
			if err == nil {
				t.Fatal("structural source service failure was skipped")
			}
			if errors.Is(err, continuity.ErrSourceServiceNotReady) {
				t.Fatalf("structural source service failure returned the skip sentinel: %v", err)
			}
			after := isolationPreparationState(t, setup.path, setup.manifest.OperationID)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("fatal recovery changed the preparation: before=%#v after=%#v", before, after)
			}
			if release := isolationReleaseState(t, setup); release == nil || release.Report != nil {
				t.Fatalf("release recovery continued past a fatal source failure: %#v", release)
			}
			if engine.created != 0 {
				t.Fatalf("manifest apply continued past a fatal source failure: created=%d", engine.created)
			}
			if setup.supervisor.calls != 0 || setup.objects.calls != 0 {
				t.Fatalf("fatal source failure was probed: supervisor=%d objects=%d", setup.supervisor.calls, setup.objects.calls)
			}
		})
	}
}
