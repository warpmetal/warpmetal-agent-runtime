package continuity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type s2bControllerFixture struct {
	ReviewerManifest       model.ContinuationHandoffManifestV1        `json:"reviewerManifest"`
	RestoredTargetManifest model.ContinuationHandoffManifestV1        `json:"restoredTargetManifest"`
	ReleaseManifest        model.ContinuationHandoffReleaseManifestV1 `json:"handoffReleaseManifest"`
	TargetRegistration     model.ContinuityRegistrationV1             `json:"reviewerTargetRegistration"`
}

type s2bSandboxFixture struct {
	TargetRegistrationRequest model.ContinuationTargetRegistrationRequestV1 `json:"targetRegistrationRequest"`
	TargetRegistrationReceipt model.ContinuationTargetRegistrationReceiptV1 `json:"targetRegistrationReceipt"`
}

func readS2BControllerFixture(t *testing.T) s2bControllerFixture {
	t.Helper()
	payload, err := os.ReadFile("../api/testdata/agent-continuation-handoff-v1.backend-wire.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture s2bControllerFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func readS2BSandboxFixture(t *testing.T) s2bSandboxFixture {
	t.Helper()
	payload, err := os.ReadFile("testdata-agent-continuation-handoff-sandbox-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture s2bSandboxFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

type fakeS2BHandoffRuntime struct {
	actions            []string
	requests           []map[string]any
	prepared           bool
	losePrepare        bool
	prepareErr         error
	reconcileRefusal   string
	reconcilePayload   []byte
	reconcileErr       error
	statusReceipts     map[string]map[string]any
	statusErrors       map[string]error
	nativeCreateCount  int
	continuityResponse model.ContinuationHandoffReportV1
	targetReceipt      model.ContinuationTargetRegistrationReceiptV1
}

func (f *fakeS2BHandoffRuntime) ExecManagedSupervisor(
	_ context.Context, _ string, action containers.ManagedSupervisorAction, payload []byte,
) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	f.actions = append(f.actions, string(action))
	f.requests = append(f.requests, request)
	if action == containers.ManagedSupervisorStatus {
		sandboxID, _ := request["sandboxId"].(string)
		if err := f.statusErrors[sandboxID]; err != nil {
			return nil, []byte("injected status probe failure"), err
		}
		receipt, ok := f.statusReceipts[sandboxID]
		if !ok {
			return nil, nil, errors.New("no status receipt for sandbox " + sandboxID)
		}
		payload, err := json.Marshal(receipt)
		return payload, nil, err
	}
	registration := request["registration"].(map[string]any)
	receipt, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "command": "register-handoff-workspace", "status": "registered",
		"operationId": registration["operationId"], "mappingId": registration["mappingId"],
		"targetWorkId": registration["targetWorkId"], "targetWorkspace": registration["targetWorkspace"],
		"sandboxId": request["sandboxId"], "instance": request["instance"], "profileId": request["profileId"],
		"ready": false,
	})
	return receipt, nil, nil
}

func (f *fakeS2BHandoffRuntime) ExecContinuity(_ context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	action := request["action"].(string)
	f.actions = append(f.actions, action)
	f.requests = append(f.requests, request)
	switch action {
	case "prepare_handoff":
		if f.prepareErr != nil {
			err := f.prepareErr
			f.prepareErr = nil
			return nil, nil, err
		}
		f.prepared = true
		f.nativeCreateCount++
		if f.losePrepare {
			f.losePrepare = false
			return nil, nil, errors.New("injected lost prepare response")
		}
		response, err := json.Marshal(f.continuityResponse)
		return response, nil, err
	case "reconcile_handoff":
		if f.reconcilePayload != nil || f.reconcileErr != nil {
			return f.reconcilePayload, []byte("reconcile override"), f.reconcileErr
		}
		if !f.prepared {
			if f.reconcileRefusal != "" {
				refusal, marshalErr := json.Marshal(map[string]any{
					"formatVersion": 1, "action": action, "status": "refused",
					"error": f.reconcileRefusal, "facts": map[string]any{"operationId": request["operationId"]},
				})
				if marshalErr != nil {
					return nil, nil, marshalErr
				}
				return refusal, []byte("handoff session record missing"), errors.New("exit status 1")
			}
			return nil, nil, errors.New("handoff was never prepared")
		}
		response, err := json.Marshal(map[string]any{
			"formatVersion": 1, "action": action, "status": "ready", "state": "prepared",
			"report": f.continuityResponse, "consumption": nil, "release": nil,
		})
		return response, nil, err
	case "register_continuation_target":
		response, err := json.Marshal(f.targetReceipt)
		return response, nil, err
	default:
		return nil, nil, errors.New("unexpected S2.B helper action")
	}
}

type fakeS2BAdmission struct {
	operations []string
}

func (f *fakeS2BAdmission) ScheduleContinuationHandoff(
	_ context.Context, operationID string, _ model.ContinuationHandoffManifestV1,
	_ model.ContinuityRegistrationV1,
) error {
	f.operations = append(f.operations, operationID)
	return nil
}

func seedS2BTargetService(
	t *testing.T,
	store *state.Store,
	manifest model.ContinuationHandoffManifestV1,
	anchor string,
) workspacecatalog.RegisteredProject {
	t.Helper()
	ctx := context.Background()
	target := manifest.TargetPolicy
	if err := store.PutSandbox(ctx, state.LocalSandbox{
		ID: target.SandboxID, Name: "handoff-target", DesiredState: "running", ObservedState: "running",
		Generation: target.SandboxGeneration, ObservedGeneration: target.SandboxGeneration, Lifetime: "persistent",
	}); err != nil {
		t.Fatal(err)
	}
	project, err := (workspacecatalog.Catalog{State: store}).EnsureDefault(ctx, workspacecatalog.DefaultProjectRequest{
		Anchor: anchor, ServerID: "srv_s2controller0001", TeamID: target.TeamID, MemberID: target.MemberID,
		SandboxID: target.SandboxID, SandboxGeneration: target.SandboxGeneration,
		ServiceRegistrationID: target.ServiceRegistrationID,
		AllocationDigest:      "sha256:" + strings.Repeat("a", 64), ConfigDigest: "sha256:" + strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	serviceManifest := model.ManagedServiceV1{
		FormatVersion: 1, OperationID: "op_s2b_target_service", ActionRevision: target.ServiceActionRevision,
		DesiredRevision: target.ServiceDesiredRevision, ConfigDigest: "sha256:" + strings.Repeat("b", 64),
		DesiredState: "active", SessionMode: "lookup_only",
		Identity: model.ManagedServiceIdentityV1{
			ServerID: "srv_s2controller0001", TeamID: target.TeamID, MemberID: target.MemberID,
			SandboxID: target.SandboxID, SandboxGeneration: target.SandboxGeneration,
			ServiceRegistrationID:     target.ServiceRegistrationID,
			ExpectedServiceGeneration: target.ServiceGeneration, Instance: "default", Role: target.Role,
		},
		Profile: model.ManagedServiceProfileV1{
			SetupOperationID: "setup_s2b_target", ProfileID: target.ProfileID,
			ProfileRevision: target.ProfileRevision, ProfileDigest: target.ProfileDigest,
		},
		Instructions: model.ManagedServiceInstructionsV1{
			InstructionRevision: target.InstructionRevision, InstructionDigest: target.InstructionDigest,
		},
		Workspace: model.ManagedServiceWorkspaceV1{
			SelectionID: project.Report.SelectionID, ProjectID: project.Report.ProjectID,
			WorkspaceEpoch: project.Report.WorkspaceEpoch, ScopeRevision: project.ScopeRevision,
			Designation: "team_project", RootAttestation: project.Report.RootAttestation,
		},
	}
	if err := store.PutManagedServiceIntent(ctx, state.LocalManagedService{
		Manifest: serviceManifest, Phase: "ready", ProcessInstance: "default", Port: 18443,
		CreationDispatched: true, ServiceGeneration: target.ServiceGeneration,
	}); err != nil {
		t.Fatal(err)
	}
	primarySource := "source_primary_s2btarget"
	report := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: serviceManifest.OperationID, ActionRevision: target.ServiceActionRevision,
		ObservedDesiredRevision: target.ServiceDesiredRevision, ConfigDigest: serviceManifest.ConfigDigest,
		ObservedState: "ready", Identity: serviceManifest.Identity, ServiceGeneration: target.ServiceGeneration,
		ProfileStatus: "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "ready",
		InstructionApplied: true, InstructionRevision: target.InstructionRevision,
		InstructionDigest: target.InstructionDigest,
		NativeRegistration: &model.ManagedNativeRegistrationV1{
			RegisteredSourceID: primarySource, WorkspaceEpoch: project.Report.WorkspaceEpoch,
			NativeSessionID: "ses_primary_s2btarget", NativeProjectID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			NativeLocationDigest: "sha256:" + strings.Repeat("c", 64),
		},
		ReceiptDigest: "sha256:" + strings.Repeat("d", 64),
	}
	if err := store.UpdateManagedService(ctx, target.ServiceRegistrationID, "ready", &report, ""); err != nil {
		t.Fatal(err)
	}
	// The registered primary source row the backend's target-policy fence and
	// the ready-branch probe both read.
	if err := store.PutContinuitySource(ctx, state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: primarySource,
			ServiceRegistrationID: target.ServiceRegistrationID, ServiceGeneration: target.ServiceGeneration,
			ProjectID: project.Report.ProjectID, SandboxID: target.SandboxID, SandboxGeneration: target.SandboxGeneration,
			WorkspaceEpoch: project.Report.WorkspaceEpoch, NativeSessionID: "ses_primary_s2btarget",
			NativeProjectID:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			NativeLocationDigest: "sha256:" + strings.Repeat("c", 64),
			ScopeRevision:        project.ScopeRevision, Role: target.Role,
			ProfileRevision: target.ProfileRevision, InstructionRevision: target.InstructionRevision,
			Availability: "available", LastObservedAt: time.Now().UTC(),
		},
		Root: project.HostRoot, Instance: "default", Lifecycle: "running",
		LifecycleRevision: target.ServiceActionRevision,
	}); err != nil {
		t.Fatal(err)
	}
	return project
}

func handoffReadyReport(
	manifest model.ContinuationHandoffManifestV1,
	workspace model.ContinuationHandoffTargetWorkspaceV1,
) model.ContinuationHandoffReportV1 {
	return model.ContinuationHandoffReportV1{
		FormatVersion: 1, OperationID: manifest.OperationID, Action: manifest.Action,
		DesiredRevision: manifest.DesiredRevision, HandoffKind: manifest.HandoffKind,
		SessionMode: manifest.SessionMode, TargetWorkID: manifest.TargetWorkID, MappingID: manifest.MappingID,
		Identity: manifest.Identity, Binding: manifest.Binding, Checkpoint: manifest.Checkpoint,
		Lineage: manifest.Lineage, TargetPolicy: manifest.TargetPolicy, WorkspaceRequest: manifest.Workspace,
		ContextDigest: manifest.Context.Digest, Status: "ready", TargetWorkspace: &workspace,
		Session: &model.ContinuationHandoffSessionV1{
			MappingID: manifest.MappingID, RegisteredSourceID: "source_s2b_mapped_session",
			NativeSessionID: "ses_s2b_mapped_session", NativeProjectID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			NativeLocationDigest: "sha256:" + strings.Repeat("e", 64),
			InstructionRevision:  manifest.TargetPolicy.InstructionRevision,
			InstructionDigest:    manifest.TargetPolicy.InstructionDigest, InstructionApplied: true,
		},
		Baseline: &model.ContinuationBaselineV1{
			BaselineID: "baseline_s2b_mapped", BaselineDigest: "sha256:" + strings.Repeat("f", 64),
			NativeSessionID: "ses_s2b_mapped_session", ServiceGeneration: manifest.TargetPolicy.ServiceGeneration,
			ReadyAt: time.Date(2026, 9, 27, 22, 0, 0, 0, time.UTC),
		},
		ReceiptDigest: "sha256:" + strings.Repeat("1", 64),
	}
}

func TestS2BHandoffAllocatesMaterializesThenRecoversLostPrepareLookupOnly(t *testing.T) {
	fixture := readS2BControllerFixture(t)
	s2Fixture := readS2WireFixture(t)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	source := seedS2Authority(t, store, s2Fixture)
	manifest := fixture.ReviewerManifest
	manifest.Identity, manifest.Binding, manifest.Checkpoint = source.manifest.Identity, source.manifest.Binding, source.manifest.Checkpoint
	manifest.Lineage.SourceWorkID = manifest.Identity.WorkID
	manifest.Lineage.SourceRevision = manifest.Identity.ExpectedRevision
	manifest.Lineage.CheckpointOperationID = manifest.Checkpoint.OperationID
	targetAnchor := t.TempDir()
	seedS2BTargetService(t, store, manifest, targetAnchor)
	objects := &fakeS2Objects{capture: source.capture}
	runtime := &fakeS2BHandoffRuntime{losePrepare: true}
	admission := &fakeS2BAdmission{}
	controller := &S2Controller{
		Store: store, ServerID: "srv_s2controller0001", Objects: objects,
		Catalog: &workspacecatalog.Catalog{State: store}, Helper: runtime,
		HandoffSupervisor: runtime, HandoffAdmission: admission,
	}
	if err := controller.ApplyHandoffs(context.Background(), []model.ContinuationHandoffManifestV1{manifest}); err == nil {
		t.Fatal("lost prepare response was treated as ready")
	}
	if objects.materializeCalls != 1 || runtime.nativeCreateCount != 1 || len(admission.operations) != 0 {
		t.Fatalf("pre-recovery effects: materialize=%d creates=%d admissions=%v",
			objects.materializeCalls, runtime.nativeCreateCount, admission.operations)
	}
	records, err := store.ContinuationHandoffPreparations(context.Background())
	if err != nil || len(records) != 1 || records[0].Report != nil {
		t.Fatalf("durable lost-response intent = %#v, %v", records, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	record, err := reopened.ContinuationHandoffPreparation(context.Background(), manifest.OperationID)
	if err != nil || record == nil || record.TargetSelectionID == "" {
		t.Fatalf("reopened allocation = %#v, %v", record, err)
	}
	project, err := reopened.ManagedProject(context.Background(), record.TargetSelectionID)
	if err != nil || project == nil {
		t.Fatalf("reopened project = %#v, %v", project, err)
	}
	runtime.continuityResponse = handoffReadyReport(manifest, model.ContinuationHandoffTargetWorkspaceV1{
		SelectionID: project.Report.SelectionID, ProjectID: project.Report.ProjectID,
		WorkspaceEpoch: project.Report.WorkspaceEpoch, ScopeRevision: project.ScopeRevision,
		RootAttestation: project.Report.RootAttestation,
	})
	recovered := &S2Controller{
		Store: reopened, ServerID: "srv_s2controller0001", Objects: objects,
		Catalog: &workspacecatalog.Catalog{State: reopened}, Helper: runtime,
		HandoffSupervisor: runtime, HandoffAdmission: admission,
	}
	if err := recovered.RecoverHandoffs(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A later daemon pass re-probes both sources and republishes the already
	// accepted host mapping from SQLite without repeating native preparation or
	// conflicting on the observational timestamp.
	runtime.statusReceipts = prepareS2BReadyProbe(t, reopened, manifest)
	if err := recovered.RecoverHandoffs(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.nativeCreateCount != 1 || objects.materializeCalls != 1 ||
		!reflect.DeepEqual(runtime.actions, []string{
			"register-handoff-workspace", "prepare_handoff", "reconcile_handoff",
			string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus), "reconcile_handoff",
		}) {
		t.Fatalf("restart repeated a side effect: actions=%v create=%d materialize=%d",
			runtime.actions, runtime.nativeCreateCount, objects.materializeCalls)
	}
	mapped, err := reopened.ContinuitySource(context.Background(), runtime.continuityResponse.Session.RegisteredSourceID)
	if err != nil || mapped == nil || mapped.Report.NativeSessionID != runtime.continuityResponse.Session.NativeSessionID ||
		mapped.Root != project.HostRoot {
		t.Fatalf("mapped source = %#v, %v", mapped, err)
	}
	if len(admission.operations) != 0 {
		t.Fatal("worker started before backend target registration was verified and projected")
	}
}

// A preparation persisted in "materializing" has provably never dispatched
// workspace registration or prepare_handoff: both are ordered behind the
// workspace_registered phase write. Recovery may therefore resume the retained
// materialized target from its checkpoint even after the source authority has
// advanced past the stored manifest.
func TestS2BHandoffRecoversMaterializedTargetAfterSourceAuthorityDrift(t *testing.T) {
	fixture := readS2BControllerFixture(t)
	s2Fixture := readS2WireFixture(t)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	source := seedS2Authority(t, store, s2Fixture)
	manifest := fixture.ReviewerManifest
	manifest.Identity, manifest.Binding, manifest.Checkpoint = source.manifest.Identity, source.manifest.Binding, source.manifest.Checkpoint
	manifest.Lineage.SourceWorkID = manifest.Identity.WorkID
	manifest.Lineage.SourceRevision = manifest.Identity.ExpectedRevision
	manifest.Lineage.CheckpointOperationID = manifest.Checkpoint.OperationID
	seedS2BTargetService(t, store, manifest, t.TempDir())
	objects := &fakeS2Objects{capture: source.capture, materializeErr: errors.New("injected interruption after the handoff phase")}
	runtime := &fakeS2BHandoffRuntime{}
	admission := &fakeS2BAdmission{}
	controller := &S2Controller{
		Store: store, ServerID: "srv_s2controller0001", Objects: objects,
		Catalog: &workspacecatalog.Catalog{State: store}, Helper: runtime,
		HandoffSupervisor: runtime, HandoffAdmission: admission,
	}
	if err := controller.ApplyHandoffs(ctx, []model.ContinuationHandoffManifestV1{manifest}); err == nil {
		t.Fatal("interrupted materialization was treated as complete")
	}
	if len(runtime.actions) != 0 || runtime.nativeCreateCount != 0 || len(admission.operations) != 0 {
		t.Fatalf("interrupted handoff reached the native side: %v/%d/%v",
			runtime.actions, runtime.nativeCreateCount, admission.operations)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	record, err := reopened.ContinuationHandoffPreparation(ctx, manifest.OperationID)
	if err != nil || record == nil || record.Phase != "materializing" || record.TargetSelectionID == "" || record.Report != nil {
		t.Fatalf("interrupted preparation = %#v, %v", record, err)
	}
	project, err := reopened.ManagedProject(ctx, record.TargetSelectionID)
	if err != nil || project == nil || project.Report.Designation != "continuity-handoff" ||
		project.Phase != "handoff_allocated" || project.Report.RootAttestation == "" {
		t.Fatalf("materialized handoff target = %#v, %v", project, err)
	}
	// The source advanced after the preparation was persisted. The stored
	// manifest no longer matches the current source registration and scope.
	registration, err := reopened.ContinuityRegistration(ctx, manifest.Binding.BindingID)
	if err != nil || registration == nil {
		t.Fatalf("source registration = %#v, %v", registration, err)
	}
	registration.Manifest.ScopeRevision++
	if err := reopened.PutContinuityRegistration(ctx, *registration); err != nil {
		t.Fatal(err)
	}
	sourceRecord, err := reopened.ContinuitySource(ctx, manifest.Binding.RegisteredSourceID)
	if err != nil || sourceRecord == nil {
		t.Fatalf("source record = %#v, %v", sourceRecord, err)
	}
	sourceRecord.Report.ScopeRevision++
	if err := reopened.PutContinuitySource(ctx, *sourceRecord); err != nil {
		t.Fatal(err)
	}
	workspace := model.ContinuationHandoffTargetWorkspaceV1{
		SelectionID: project.Report.SelectionID, ProjectID: project.Report.ProjectID,
		WorkspaceEpoch: project.Report.WorkspaceEpoch, ScopeRevision: project.ScopeRevision,
		RootAttestation: project.Report.RootAttestation,
	}
	runtime.continuityResponse = handoffReadyReport(manifest, workspace)
	objects.materializeErr = nil
	recovered := &S2Controller{
		Store: reopened, ServerID: "srv_s2controller0001", Objects: objects,
		Catalog: &workspacecatalog.Catalog{State: reopened}, Helper: runtime,
		HandoffSupervisor: runtime, HandoffAdmission: admission,
	}
	if err := recovered.RecoverHandoffs(ctx); err != nil {
		t.Fatal(err)
	}
	final, err := reopened.ContinuationHandoffPreparation(ctx, manifest.OperationID)
	if err != nil || final == nil || final.Report == nil || final.Report.Status != "ready" ||
		final.Report.TargetWorkspace == nil || *final.Report.TargetWorkspace != workspace ||
		final.Report.Session == nil || final.Report.Baseline == nil {
		t.Fatalf("recovered preparation = %#v, %v", final, err)
	}
	if runtime.nativeCreateCount != 1 || !reflect.DeepEqual(runtime.actions, []string{"register-handoff-workspace", "prepare_handoff"}) ||
		objects.materializeCalls != 2 {
		t.Fatalf("recovery actions/calls = %v creates=%d materialize=%d",
			runtime.actions, runtime.nativeCreateCount, objects.materializeCalls)
	}
	projects, err := reopened.ManagedProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	handoffTargets := 0
	for _, candidate := range projects {
		if candidate.Report.Designation != "continuity-handoff" {
			continue
		}
		handoffTargets++
		if candidate.Report.SelectionID != record.TargetSelectionID {
			t.Fatalf("recovery created a second handoff target: %#v", candidate.Report)
		}
	}
	if handoffTargets != 1 {
		t.Fatalf("recovery handoff targets = %d", handoffTargets)
	}
	mapped, err := reopened.ContinuitySource(ctx, runtime.continuityResponse.Session.RegisteredSourceID)
	if err != nil || mapped == nil || mapped.Report.NativeSessionID != runtime.continuityResponse.Session.NativeSessionID ||
		mapped.Root != project.HostRoot {
		t.Fatalf("mapped source = %#v, %v", mapped, err)
	}
	// A later daemon pass re-probes both sources and republishes the accepted
	// mapping without repeating the native preparation or conflicting on the
	// observational timestamp.
	runtime.statusReceipts = prepareS2BReadyProbe(t, reopened, manifest)
	if err := recovered.RecoverHandoffs(ctx); err != nil {
		t.Fatal(err)
	}
	if runtime.nativeCreateCount != 1 || !reflect.DeepEqual(runtime.actions, []string{
		"register-handoff-workspace", "prepare_handoff",
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus), "reconcile_handoff",
	}) {
		t.Fatalf("recovery replay repeated a side effect: %v/%d", runtime.actions, runtime.nativeCreateCount)
	}
}

type s2bRecoveryRequiredFixture struct {
	store      *state.Store
	path       string
	objects    *fakeS2Objects
	runtime    *fakeS2BHandoffRuntime
	controller *S2Controller
	manifest   model.ContinuationHandoffManifestV1
	selection  string
}

// seedS2BRecoveryRequiredHandoff reproduces the live post-dispatch failure: the
// target workspace is materialized and ready, the single prepare_handoff
// dispatch failed without a native record (losePrepare models a lost response
// instead), and the source authority has since advanced past the manifest.
func seedS2BRecoveryRequiredHandoff(t *testing.T, losePrepare bool) s2bRecoveryRequiredFixture {
	return seedS2BRecoveryRequiredHandoffMode(t, losePrepare, true)
}

func seedS2BRecoveryRequiredHandoffMode(t *testing.T, losePrepare, driftSource bool) s2bRecoveryRequiredFixture {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	source := seedS2Authority(t, store, readS2WireFixture(t))
	manifest := readS2BControllerFixture(t).ReviewerManifest
	manifest.Identity, manifest.Binding, manifest.Checkpoint = source.manifest.Identity, source.manifest.Binding, source.manifest.Checkpoint
	manifest.Lineage.SourceWorkID = manifest.Identity.WorkID
	manifest.Lineage.SourceRevision = manifest.Identity.ExpectedRevision
	manifest.Lineage.CheckpointOperationID = manifest.Checkpoint.OperationID
	seedS2BTargetService(t, store, manifest, t.TempDir())
	objects := &fakeS2Objects{capture: source.capture}
	runtime := &fakeS2BHandoffRuntime{losePrepare: losePrepare}
	if !losePrepare {
		runtime.prepareErr = errors.New("injected prepare transport failure")
	}
	admission := &fakeS2BAdmission{}
	controller := &S2Controller{
		Store: store, ServerID: "srv_s2controller0001", Objects: objects,
		Catalog: &workspacecatalog.Catalog{State: store}, Helper: runtime,
		HandoffSupervisor: runtime, HandoffAdmission: admission,
	}
	if err := controller.ApplyHandoffs(ctx, []model.ContinuationHandoffManifestV1{manifest}); err == nil {
		t.Fatal("failed handoff preparation was treated as ready")
	}
	record, err := store.ContinuationHandoffPreparation(ctx, manifest.OperationID)
	if err != nil || record == nil || record.Phase != "recovery_required" || record.Report != nil || record.TargetSelectionID == "" {
		t.Fatalf("failed preparation state = %#v, %v", record, err)
	}
	project, err := store.ManagedProject(ctx, record.TargetSelectionID)
	if err != nil || project == nil || project.Phase != "ready" || project.Report.Designation != "continuity-handoff" {
		t.Fatalf("materialized handoff target = %#v, %v", project, err)
	}
	runtime.continuityResponse = handoffReadyReport(manifest, model.ContinuationHandoffTargetWorkspaceV1{
		SelectionID: project.Report.SelectionID, ProjectID: project.Report.ProjectID,
		WorkspaceEpoch: project.Report.WorkspaceEpoch, ScopeRevision: project.ScopeRevision,
		RootAttestation: project.Report.RootAttestation,
	})
	// The source advanced after the dispatch failed, exactly like the live box.
	if driftSource {
		registration, err := store.ContinuityRegistration(ctx, manifest.Binding.BindingID)
		if err != nil || registration == nil {
			t.Fatalf("source registration = %#v, %v", registration, err)
		}
		registration.Manifest.ScopeRevision++
		if err := store.PutContinuityRegistration(ctx, *registration); err != nil {
			t.Fatal(err)
		}
		sourceRecord, err := store.ContinuitySource(ctx, manifest.Binding.RegisteredSourceID)
		if err != nil || sourceRecord == nil {
			t.Fatalf("source record = %#v, %v", sourceRecord, err)
		}
		sourceRecord.Report.ScopeRevision++
		if err := store.PutContinuitySource(ctx, *sourceRecord); err != nil {
			t.Fatal(err)
		}
	}
	runtime.actions = nil
	runtime.requests = nil
	return s2bRecoveryRequiredFixture{
		store: store, path: path, objects: objects, runtime: runtime, controller: controller, manifest: manifest, selection: record.TargetSelectionID,
	}
}

func TestS2BHandoffRecoversMissingNativeSessionAfterSourceAuthorityDrift(t *testing.T) {
	fixture := seedS2BRecoveryRequiredHandoff(t, false)
	fixture.runtime.reconcileRefusal = "handoff_session_missing"
	if err := fixture.controller.RecoverHandoffs(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixture.runtime.actions, []string{"reconcile_handoff", "register-handoff-workspace", "prepare_handoff"}) ||
		fixture.runtime.nativeCreateCount != 1 {
		t.Fatalf("missing-session recovery actions = %v creates=%d", fixture.runtime.actions, fixture.runtime.nativeCreateCount)
	}
	record, err := fixture.store.ContinuationHandoffPreparation(context.Background(), fixture.manifest.OperationID)
	if err != nil || record == nil || record.Phase != "ready" || record.Report == nil || record.Report.Status != "ready" ||
		record.TargetSelectionID != fixture.selection {
		t.Fatalf("published preparation = %#v, %v", record, err)
	}
	mapped, err := fixture.store.ContinuitySource(context.Background(), record.Report.Session.RegisteredSourceID)
	if err != nil || mapped == nil || mapped.Report.NativeSessionID != record.Report.Session.NativeSessionID {
		t.Fatalf("mapped handoff source = %#v, %v", mapped, err)
	}
}

func TestS2BHandoffPublishesReconciledNativeSessionWithoutPrepare(t *testing.T) {
	fixture := seedS2BRecoveryRequiredHandoff(t, true)
	if fixture.runtime.nativeCreateCount != 1 {
		t.Fatalf("lost prepare dispatch count = %d", fixture.runtime.nativeCreateCount)
	}
	if err := fixture.controller.RecoverHandoffs(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixture.runtime.actions, []string{"reconcile_handoff"}) || fixture.runtime.nativeCreateCount != 1 {
		t.Fatalf("prepared reconcile repeated a side effect: %v creates=%d", fixture.runtime.actions, fixture.runtime.nativeCreateCount)
	}
	record, err := fixture.store.ContinuationHandoffPreparation(context.Background(), fixture.manifest.OperationID)
	if err != nil || record == nil || record.Phase != "ready" || record.Report == nil || record.Report.Status != "ready" {
		t.Fatalf("reconciled preparation = %#v, %v", record, err)
	}
}

func TestS2BHandoffLeavesPhaseUntouchedForNonMissingReconcileRefusal(t *testing.T) {
	fixture := seedS2BRecoveryRequiredHandoff(t, false)
	fixture.runtime.reconcileRefusal = "handoff_identity_mismatch"
	err := fixture.controller.RecoverHandoffs(context.Background())
	if !errors.Is(err, ErrS2RecoveryUnknown) {
		t.Fatalf("non-missing refusal error = %v, want ErrS2RecoveryUnknown", err)
	}
	if !reflect.DeepEqual(fixture.runtime.actions, []string{"reconcile_handoff"}) ||
		fixture.runtime.prepared || fixture.runtime.nativeCreateCount != 0 {
		t.Fatalf("non-missing refusal reached native preparation: %v", fixture.runtime.actions)
	}
	record, err := fixture.store.ContinuationHandoffPreparation(context.Background(), fixture.manifest.OperationID)
	if err != nil || record == nil || record.Phase != "recovery_required" || record.Report != nil {
		t.Fatalf("refused preparation changed phase = %#v, %v", record, err)
	}
}

func TestS2BHandoffReplayAfterMissingNativeSessionRecoveryDoesNotRepeatSideEffects(t *testing.T) {
	fixture := seedS2BRecoveryRequiredHandoff(t, false)
	fixture.runtime.reconcileRefusal = "handoff_session_missing"
	if err := fixture.controller.RecoverHandoffs(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.runtime.statusReceipts = prepareS2BReadyProbe(t, fixture.store, fixture.manifest)
	before := append([]string(nil), fixture.runtime.actions...)
	if err := fixture.controller.RecoverHandoffs(context.Background()); err != nil {
		t.Fatal(err)
	}
	replayed := fixture.runtime.actions[len(before):]
	if !reflect.DeepEqual(replayed, []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus), "reconcile_handoff",
	}) || fixture.runtime.nativeCreateCount != 1 {
		t.Fatalf("replay repeated side effects: %v creates=%d", fixture.runtime.actions, fixture.runtime.nativeCreateCount)
	}
}

// s2bStatusReceipt builds the exact supervisor status receipt for one managed
// service's registered primary native session.
func s2bStatusReceipt(t *testing.T, service *state.LocalManagedService) map[string]any {
	t.Helper()
	native := service.Report.NativeRegistration
	if native == nil {
		t.Fatalf("service %s has no native registration", service.Manifest.Identity.ServiceRegistrationID)
	}
	return map[string]any{
		"schemaVersion": 1, "command": "status", "status": "running", "ready": true,
		"sessionId":            native.NativeSessionID,
		"nativeProjectId":      native.NativeProjectID,
		"nativeLocationDigest": native.NativeLocationDigest,
		"instructionRevision":  service.Manifest.Instructions.InstructionRevision,
		"instructionDigest":    service.Manifest.Instructions.InstructionDigest,
		"instructionApplied":   true,
	}
}

// prepareS2BReadyProbe makes the stored primary sources probe-ready: it undoes
// any test-only scope drift, seeds the source sandbox row, and returns the
// exact status receipts for the source service and the target service keyed by
// their sandbox ids.
func prepareS2BReadyProbe(t *testing.T, store *state.Store, manifest model.ContinuationHandoffManifestV1) map[string]map[string]any {
	t.Helper()
	ctx := context.Background()
	registration, err := store.ContinuityRegistration(ctx, manifest.Binding.BindingID)
	if err != nil || registration == nil {
		t.Fatalf("source registration = %#v, %v", registration, err)
	}
	if registration.Manifest.ScopeRevision != manifest.Binding.ScopeRevision {
		registration.Manifest.ScopeRevision = manifest.Binding.ScopeRevision
		if err := store.PutContinuityRegistration(ctx, *registration); err != nil {
			t.Fatal(err)
		}
	}
	sourceRow, err := store.ContinuitySource(ctx, manifest.Binding.RegisteredSourceID)
	if err != nil || sourceRow == nil {
		t.Fatalf("source row = %#v, %v", sourceRow, err)
	}
	if sourceRow.Report.ScopeRevision != manifest.Binding.ScopeRevision {
		sourceRow.Report.ScopeRevision = manifest.Binding.ScopeRevision
		if err := store.PutContinuitySource(ctx, *sourceRow); err != nil {
			t.Fatal(err)
		}
	}
	sandbox, err := store.Sandbox(ctx, manifest.Identity.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sandbox == nil {
		if err := store.PutSandbox(ctx, state.LocalSandbox{
			ID: manifest.Identity.SandboxID, Name: "handoff-source", DesiredState: "running", ObservedState: "running",
			Generation: manifest.Identity.SandboxGeneration, ObservedGeneration: manifest.Identity.SandboxGeneration, Lifetime: "persistent",
		}); err != nil {
			t.Fatal(err)
		}
	}
	sourceService, err := store.ManagedService(ctx, manifest.Binding.ServiceRegistrationID)
	if err != nil || sourceService == nil {
		t.Fatalf("source service = %#v, %v", sourceService, err)
	}
	targetService, err := store.ManagedService(ctx, manifest.TargetPolicy.ServiceRegistrationID)
	if err != nil || targetService == nil {
		t.Fatalf("target service = %#v, %v", targetService, err)
	}
	return map[string]map[string]any{
		manifest.Identity.SandboxID:     s2bStatusReceipt(t, sourceService),
		manifest.TargetPolicy.SandboxID: s2bStatusReceipt(t, targetService),
	}
}

func assertS2BSourceProbed(t *testing.T, store *state.Store, id string, observed time.Time) {
	t.Helper()
	row, err := store.ContinuitySource(context.Background(), id)
	if err != nil || row == nil {
		t.Fatalf("continuity source %s = %#v, %v", id, row, err)
	}
	if row.Report.Availability != "available" || row.Report.Reason != nil || !row.Report.LastObservedAt.Equal(observed) {
		t.Fatalf("continuity source %s was not truthfully refreshed: %#v", id, row.Report)
	}
}

func assertS2BSourceStale(t *testing.T, store *state.Store, id string, observed time.Time) {
	t.Helper()
	row, err := store.ContinuitySource(context.Background(), id)
	if err != nil || row == nil {
		t.Fatalf("continuity source %s = %#v, %v", id, row, err)
	}
	if row.Report.Availability != "unavailable" || row.Report.Reason == nil || !row.Report.LastObservedAt.Equal(observed) {
		t.Fatalf("continuity source %s was refreshed by a failed probe: %#v", id, row.Report)
	}
}

type s2bReadyHandoffFixture struct {
	store      *state.Store
	path       string
	runtime    *fakeS2BHandoffRuntime
	controller *S2Controller
	manifest   model.ContinuationHandoffManifestV1
	sourceID   string
	serviceID  string
	targetID   string
	advance    func(time.Time)
}

// seedS2BReadyHandoff publishes a ready continuation handoff through the .28
// missing-session recovery, restores the probe-visible source authority, then
// ages all three source rows past SourceFreshness into an unavailable state so
// only truthful current probes can refresh them.
func seedS2BReadyHandoff(t *testing.T) s2bReadyHandoffFixture {
	t.Helper()
	ctx := context.Background()
	base := seedS2BRecoveryRequiredHandoffMode(t, false, false)
	base.runtime.reconcileRefusal = "handoff_session_missing"
	if err := base.controller.RecoverHandoffs(ctx); err != nil {
		t.Fatal(err)
	}
	base.runtime.reconcileRefusal = ""
	record, err := base.store.ContinuationHandoffPreparation(ctx, base.manifest.OperationID)
	if err != nil || record == nil || record.Report == nil || record.Report.Status != "ready" || record.Report.Session == nil {
		t.Fatalf("ready preparation = %#v, %v", record, err)
	}
	targetService, err := base.store.ManagedService(ctx, base.manifest.TargetPolicy.ServiceRegistrationID)
	if err != nil || targetService == nil || targetService.Report.NativeRegistration == nil {
		t.Fatalf("target service = %#v, %v", targetService, err)
	}
	statusReceipts := prepareS2BReadyProbe(t, base.store, base.manifest)
	now := time.Date(2026, 9, 29, 3, 0, 0, 0, time.UTC)
	stale := func(id string) {
		row, err := base.store.ContinuitySource(ctx, id)
		if err != nil || row == nil {
			t.Fatalf("continuity source %s = %#v, %v", id, row, err)
		}
		reason := "probe_stale"
		row.Report.Availability = "unavailable"
		row.Report.Reason = &reason
		row.Report.LastObservedAt = now.Add(-10 * time.Minute)
		if err := base.store.PutContinuitySource(ctx, *row); err != nil {
			t.Fatal(err)
		}
	}
	serviceID := targetService.Report.NativeRegistration.RegisteredSourceID
	targetID := record.Report.Session.RegisteredSourceID
	stale(base.manifest.Binding.RegisteredSourceID)
	stale(serviceID)
	stale(targetID)
	controller := &S2Controller{
		Store: base.store, ServerID: "srv_s2controller0001", Objects: base.objects,
		Catalog: &workspacecatalog.Catalog{State: base.store}, Helper: base.runtime,
		HandoffSupervisor: base.runtime, HandoffAdmission: &fakeS2BAdmission{},
		Now: func() time.Time { return now },
	}
	base.runtime.statusReceipts = statusReceipts
	base.runtime.actions = nil
	base.runtime.requests = nil
	return s2bReadyHandoffFixture{
		store: base.store, path: base.path, runtime: base.runtime, controller: controller, manifest: base.manifest,
		sourceID: base.manifest.Binding.RegisteredSourceID, serviceID: serviceID, targetID: targetID,
		advance: func(value time.Time) { now = value },
	}
}

func TestS2BHandoffReadyReobservesAllThreeSourcesBeforePublish(t *testing.T) {
	fixture := seedS2BReadyHandoff(t)
	first := time.Date(2026, 9, 29, 3, 5, 0, 0, time.UTC)
	fixture.advance(first)
	if err := fixture.controller.RecoverHandoffs(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertS2BSourceProbed(t, fixture.store, fixture.sourceID, first)
	assertS2BSourceProbed(t, fixture.store, fixture.serviceID, first)
	assertS2BSourceProbed(t, fixture.store, fixture.targetID, first)
	if !reflect.DeepEqual(fixture.runtime.actions, []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus), "reconcile_handoff",
	}) || fixture.runtime.nativeCreateCount != 1 {
		t.Fatalf("ready probe actions = %v creates=%d", fixture.runtime.actions, fixture.runtime.nativeCreateCount)
	}
	if len(fixture.runtime.requests) < 2 {
		t.Fatalf("ready probe requests = %#v", fixture.runtime.requests)
	}
	sourceProbe := fixture.runtime.requests[0]
	targetProbe := fixture.runtime.requests[1]
	if sourceProbe["sandboxId"] != fixture.manifest.Identity.SandboxID ||
		sourceProbe["instance"] != "default" || sourceProbe["profileId"] != "opencode" ||
		sourceProbe["schemaVersion"] != float64(1) || sourceProbe["probe"] != true ||
		sourceProbe["requestTimeoutSeconds"] != float64(30) {
		t.Fatalf("source status probe payload = %#v", sourceProbe)
	}
	if targetProbe["sandboxId"] != fixture.manifest.TargetPolicy.SandboxID ||
		targetProbe["instance"] != "default" || targetProbe["profileId"] != "opencode" ||
		targetProbe["schemaVersion"] != float64(1) || targetProbe["probe"] != true ||
		targetProbe["requestTimeoutSeconds"] != float64(30) {
		t.Fatalf("target service status probe payload = %#v", targetProbe)
	}
	// A second pass advances only the observation timestamps and stays
	// conflict-free with publishHandoffReady's deep equality.
	second := first.Add(30 * time.Second)
	fixture.advance(second)
	if err := fixture.controller.RecoverHandoffs(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertS2BSourceProbed(t, fixture.store, fixture.sourceID, second)
	assertS2BSourceProbed(t, fixture.store, fixture.serviceID, second)
	assertS2BSourceProbed(t, fixture.store, fixture.targetID, second)
	if len(fixture.runtime.actions) != 6 || fixture.runtime.nativeCreateCount != 1 {
		t.Fatalf("probe replay repeated side effects: %v creates=%d", fixture.runtime.actions, fixture.runtime.nativeCreateCount)
	}
}

func TestS2BHandoffRejectsMismatchedProbeReceipts(t *testing.T) {
	fixture := seedS2BReadyHandoff(t)
	ctx := context.Background()
	readRow := func(id string) *state.LocalContinuitySource {
		t.Helper()
		row, err := fixture.store.ContinuitySource(ctx, id)
		if err != nil || row == nil {
			t.Fatalf("stale source %s = %#v, %v", id, row, err)
		}
		return row
	}
	stalePrimary := readRow(fixture.sourceID)
	staleService := readRow(fixture.serviceID)
	staleTarget := readRow(fixture.targetID)
	sourceSandbox := fixture.manifest.Identity.SandboxID
	targetSandbox := fixture.manifest.TargetPolicy.SandboxID
	// (1) source Work primary receipt mismatch.
	fixture.runtime.statusReceipts[sourceSandbox]["sessionId"] = "ses_s2b_mismatched"
	if err := fixture.controller.RecoverHandoffs(ctx); !errors.Is(err, ErrS2RecoveryUnknown) {
		t.Fatalf("mismatched source receipt error = %v, want ErrS2RecoveryUnknown", err)
	}
	assertS2BSourceStale(t, fixture.store, fixture.sourceID, stalePrimary.Report.LastObservedAt)
	if !reflect.DeepEqual(fixture.runtime.actions, []string{string(containers.ManagedSupervisorStatus)}) {
		t.Fatalf("mismatched source probe reached a later probe: %v", fixture.runtime.actions)
	}
	// (2) target-service registered primary receipt mismatch.
	fixture.runtime.statusReceipts[sourceSandbox]["sessionId"] = stalePrimary.Report.NativeSessionID
	before := len(fixture.runtime.actions)
	fixture.runtime.statusReceipts[targetSandbox]["sessionId"] = "ses_s2b_mismatched"
	if err := fixture.controller.RecoverHandoffs(ctx); !errors.Is(err, ErrS2RecoveryUnknown) {
		t.Fatalf("mismatched target service receipt error = %v, want ErrS2RecoveryUnknown", err)
	}
	assertS2BSourceStale(t, fixture.store, fixture.serviceID, staleService.Report.LastObservedAt)
	assertS2BSourceStale(t, fixture.store, fixture.targetID, staleTarget.Report.LastObservedAt)
	if !reflect.DeepEqual(fixture.runtime.actions[before:], []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus),
	}) {
		t.Fatalf("mismatched target service probe reached the session reconcile: %v", fixture.runtime.actions[before:])
	}
	// (3) target handoff session reconcile refusal.
	fixture.runtime.statusReceipts[targetSandbox]["sessionId"] = staleService.Report.NativeSessionID
	before = len(fixture.runtime.actions)
	fixture.runtime.reconcilePayload = []byte(`{"formatVersion":1,"action":"reconcile_handoff","status":"refused","error":"handoff_identity_mismatch","facts":{}}`)
	fixture.runtime.reconcileErr = errors.New("exit status 1")
	if err := fixture.controller.RecoverHandoffs(ctx); !errors.Is(err, ErrS2RecoveryUnknown) {
		t.Fatalf("refused reconcile probe error = %v, want ErrS2RecoveryUnknown", err)
	}
	assertS2BSourceStale(t, fixture.store, fixture.targetID, staleTarget.Report.LastObservedAt)
	if !reflect.DeepEqual(fixture.runtime.actions[before:], []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus), "reconcile_handoff",
	}) {
		t.Fatalf("refused session probe actions = %v", fixture.runtime.actions[before:])
	}
	// (4) A valid-shaped envelope whose prepared session tuple drifted is
	// refused too.
	mismatched := fixture.runtime.continuityResponse
	mismatched.Session.NativeSessionID = "ses_s2b_mismatched"
	mismatched.Baseline.NativeSessionID = "ses_s2b_mismatched"
	envelope, err := json.Marshal(map[string]any{
		"formatVersion": 1, "action": "reconcile_handoff", "status": "ready", "state": "prepared",
		"report": mismatched, "consumption": nil, "release": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtime.reconcilePayload = envelope
	fixture.runtime.reconcileErr = nil
	if err := fixture.controller.RecoverHandoffs(ctx); !errors.Is(err, ErrS2RecoveryUnknown) {
		t.Fatalf("drifted session probe error = %v, want ErrS2RecoveryUnknown", err)
	}
	assertS2BSourceStale(t, fixture.store, fixture.targetID, staleTarget.Report.LastObservedAt)
}

func TestS2BHandoffProbeTransportErrorsNeverRefresh(t *testing.T) {
	fixture := seedS2BReadyHandoff(t)
	ctx := context.Background()
	readRow := func(id string) *state.LocalContinuitySource {
		t.Helper()
		row, err := fixture.store.ContinuitySource(ctx, id)
		if err != nil || row == nil {
			t.Fatalf("stale source %s = %#v, %v", id, row, err)
		}
		return row
	}
	stalePrimary := readRow(fixture.sourceID)
	staleService := readRow(fixture.serviceID)
	staleTarget := readRow(fixture.targetID)
	sourceSandbox := fixture.manifest.Identity.SandboxID
	targetSandbox := fixture.manifest.TargetPolicy.SandboxID
	// (1) source Work primary status transport error.
	fixture.runtime.statusErrors = map[string]error{sourceSandbox: errors.New("injected source status transport failure")}
	if err := fixture.controller.RecoverHandoffs(ctx); !errors.Is(err, ErrS2RecoveryUnknown) {
		t.Fatalf("source status transport error = %v, want ErrS2RecoveryUnknown", err)
	}
	assertS2BSourceStale(t, fixture.store, fixture.sourceID, stalePrimary.Report.LastObservedAt)
	// (2) target-service registered primary status transport error.
	fixture.runtime.statusErrors = map[string]error{targetSandbox: errors.New("injected target service status transport failure")}
	before := len(fixture.runtime.actions)
	if err := fixture.controller.RecoverHandoffs(ctx); !errors.Is(err, ErrS2RecoveryUnknown) {
		t.Fatalf("target service status transport error = %v, want ErrS2RecoveryUnknown", err)
	}
	assertS2BSourceStale(t, fixture.store, fixture.serviceID, staleService.Report.LastObservedAt)
	assertS2BSourceStale(t, fixture.store, fixture.targetID, staleTarget.Report.LastObservedAt)
	if !reflect.DeepEqual(fixture.runtime.actions[before:], []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus),
	}) {
		t.Fatalf("target service transport error reached the session reconcile: %v", fixture.runtime.actions[before:])
	}
	// (3) target handoff session reconcile transport error.
	fixture.runtime.statusErrors = nil
	fixture.runtime.reconcileErr = errors.New("injected reconcile transport failure")
	if err := fixture.controller.RecoverHandoffs(ctx); !errors.Is(err, ErrS2RecoveryUnknown) {
		t.Fatalf("reconcile transport error = %v, want ErrS2RecoveryUnknown", err)
	}
	assertS2BSourceStale(t, fixture.store, fixture.targetID, staleTarget.Report.LastObservedAt)
}

// A locally failed source service whose generation/identity/instruction tuple
// still matches must not abort recovery of the whole handoff set.
func TestS2BHandoffSkipsFailedSourceServiceWithoutTouchingTheRecord(t *testing.T) {
	fixture := seedS2BReadyHandoff(t)
	ctx := context.Background()
	service, err := fixture.store.ManagedService(ctx, fixture.manifest.Binding.ServiceRegistrationID)
	if err != nil || service == nil {
		t.Fatalf("source service = %#v, %v", service, err)
	}
	report := service.Report
	report.ObservedState = "failed"
	report.InstructionApplied = false
	if err := fixture.store.UpdateManagedService(ctx, fixture.manifest.Binding.ServiceRegistrationID, "failed", &report, "enrollment_unavailable"); err != nil {
		t.Fatal(err)
	}
	before, err := fixture.store.ContinuationHandoffPreparation(ctx, fixture.manifest.OperationID)
	if err != nil || before == nil {
		t.Fatalf("preparation = %#v, %v", before, err)
	}
	primaryBefore, err := fixture.store.ContinuitySource(ctx, fixture.sourceID)
	if err != nil || primaryBefore == nil {
		t.Fatalf("primary source = %#v, %v", primaryBefore, err)
	}
	targetBefore, err := fixture.store.ContinuitySource(ctx, fixture.targetID)
	if err != nil || targetBefore == nil {
		t.Fatalf("target source = %#v, %v", targetBefore, err)
	}
	if err := fixture.controller.RecoverHandoffs(ctx); err != nil {
		t.Fatalf("failed source service aborted recovery: %v", err)
	}
	after, err := fixture.store.ContinuationHandoffPreparation(ctx, fixture.manifest.OperationID)
	if err != nil || after == nil {
		t.Fatalf("preparation = %#v, %v", after, err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed source service changed the preparation: before=%#v after=%#v", before, after)
	}
	primaryAfter, err := fixture.store.ContinuitySource(ctx, fixture.sourceID)
	if err != nil || primaryAfter == nil {
		t.Fatalf("primary source = %#v, %v", primaryAfter, err)
	}
	targetAfter, err := fixture.store.ContinuitySource(ctx, fixture.targetID)
	if err != nil || targetAfter == nil {
		t.Fatalf("target source = %#v, %v", targetAfter, err)
	}
	if !reflect.DeepEqual(primaryBefore, primaryAfter) || !reflect.DeepEqual(targetBefore, targetAfter) {
		t.Fatalf("failed source service refreshed observations: primary=%#v target=%#v", primaryAfter, targetAfter)
	}
	if len(fixture.runtime.actions) != 0 {
		t.Fatalf("failed source service was probed: %v", fixture.runtime.actions)
	}
}

// Once the local source service is repaired in place, the retained
// preparation follows the existing re-observe/publish path without being
// recreated.
func TestS2BHandoffResumesFailedSourceServiceRecordWhenTheServiceRecovers(t *testing.T) {
	fixture := seedS2BReadyHandoff(t)
	ctx := context.Background()
	service, err := fixture.store.ManagedService(ctx, fixture.manifest.Binding.ServiceRegistrationID)
	if err != nil || service == nil {
		t.Fatalf("source service = %#v, %v", service, err)
	}
	report := service.Report
	report.ObservedState = "failed"
	report.InstructionApplied = false
	if err := fixture.store.UpdateManagedService(ctx, fixture.manifest.Binding.ServiceRegistrationID, "failed", &report, "enrollment_unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.controller.RecoverHandoffs(ctx); err != nil {
		t.Fatalf("failed source service aborted recovery: %v", err)
	}
	retained, err := fixture.store.ContinuationHandoffPreparation(ctx, fixture.manifest.OperationID)
	if err != nil || retained == nil || retained.Report == nil {
		t.Fatalf("retained preparation = %#v, %v", retained, err)
	}
	service, err = fixture.store.ManagedService(ctx, fixture.manifest.Binding.ServiceRegistrationID)
	if err != nil || service == nil {
		t.Fatalf("source service = %#v, %v", service, err)
	}
	report = service.Report
	report.ObservedState = "ready"
	report.InstructionApplied = true
	if err := fixture.store.UpdateManagedService(ctx, fixture.manifest.Binding.ServiceRegistrationID, "ready", &report, ""); err != nil {
		t.Fatal(err)
	}
	probeTime := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	fixture.advance(probeTime)
	if err := fixture.controller.RecoverHandoffs(ctx); err != nil {
		t.Fatalf("recovered source service did not resume the retained preparation: %v", err)
	}
	resumed, err := fixture.store.ContinuationHandoffPreparation(ctx, fixture.manifest.OperationID)
	if err != nil || resumed == nil {
		t.Fatalf("resumed preparation = %#v, %v", resumed, err)
	}
	if !reflect.DeepEqual(retained, resumed) {
		t.Fatalf("resumed preparation drifted: %#v -> %#v", retained, resumed)
	}
	records, err := fixture.store.ContinuationHandoffPreparations(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("retained preparation was recreated: %#v, %v", records, err)
	}
	assertS2BSourceProbed(t, fixture.store, fixture.sourceID, probeTime)
	assertS2BSourceProbed(t, fixture.store, fixture.serviceID, probeTime)
	assertS2BSourceProbed(t, fixture.store, fixture.targetID, probeTime)
	if !reflect.DeepEqual(fixture.runtime.actions, []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus), "reconcile_handoff",
	}) || fixture.runtime.nativeCreateCount != 1 {
		t.Fatalf("resumed probe actions = %v creates=%d", fixture.runtime.actions, fixture.runtime.nativeCreateCount)
	}
}

func TestS2BTargetWorkUsesFixedRegistrationActionBeforeWorkerAdmission(t *testing.T) {
	fixture := readS2BControllerFixture(t)
	sandboxFixture := readS2BSandboxFixture(t)
	s2Fixture := readS2WireFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	source := seedS2Authority(t, store, s2Fixture)
	manifest := fixture.ReviewerManifest
	manifest.Identity, manifest.Binding, manifest.Checkpoint = source.manifest.Identity, source.manifest.Binding, source.manifest.Checkpoint
	manifest.Lineage.SourceWorkID = manifest.Identity.WorkID
	manifest.Lineage.SourceRevision = manifest.Identity.ExpectedRevision
	manifest.Lineage.CheckpointOperationID = manifest.Checkpoint.OperationID
	project := seedS2BTargetService(t, store, manifest, t.TempDir())
	targetWorkspace := model.ContinuationHandoffTargetWorkspaceV1{
		SelectionID: project.Report.SelectionID, ProjectID: project.Report.ProjectID,
		WorkspaceEpoch: project.Report.WorkspaceEpoch, ScopeRevision: project.ScopeRevision,
		RootAttestation: project.Report.RootAttestation,
	}
	report := handoffReadyReport(manifest, targetWorkspace)
	if err := store.PutContinuationHandoffPreparation(context.Background(), state.LocalContinuationHandoffPreparation{
		Manifest: manifest, Phase: "allocating", TargetSelectionID: targetWorkspace.SelectionID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteContinuationHandoffPreparation(
		context.Background(), manifest.OperationID, targetWorkspace.SelectionID, report,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuitySource(context.Background(), state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: report.Session.RegisteredSourceID,
			ServiceRegistrationID: manifest.TargetPolicy.ServiceRegistrationID,
			ServiceGeneration:     manifest.TargetPolicy.ServiceGeneration, ProjectID: targetWorkspace.ProjectID,
			SandboxID: manifest.TargetPolicy.SandboxID, SandboxGeneration: manifest.TargetPolicy.SandboxGeneration,
			WorkspaceEpoch: targetWorkspace.WorkspaceEpoch, NativeSessionID: report.Session.NativeSessionID,
			NativeProjectID: report.Session.NativeProjectID, NativeLocationDigest: report.Session.NativeLocationDigest,
			ScopeRevision: targetWorkspace.ScopeRevision, Role: manifest.TargetPolicy.Role,
			ProfileRevision:     manifest.TargetPolicy.ProfileRevision,
			InstructionRevision: manifest.TargetPolicy.InstructionRevision,
			Availability:        "available", LastObservedAt: report.Baseline.ReadyAt,
		},
		Root: project.HostRoot, Instance: "default", Lifecycle: "running",
		LifecycleRevision: manifest.DesiredRevision,
	}); err != nil {
		t.Fatal(err)
	}
	registration := fixture.TargetRegistration
	registration.Identity.ProjectID = targetWorkspace.ProjectID
	registration.Identity.SandboxID = manifest.TargetPolicy.SandboxID
	registration.Identity.SandboxGeneration = manifest.TargetPolicy.SandboxGeneration
	registration.Identity.WorkspaceEpoch = targetWorkspace.WorkspaceEpoch
	registration.Binding.RegisteredSourceID = report.Session.RegisteredSourceID
	registration.Binding.ServiceRegistrationID = manifest.TargetPolicy.ServiceRegistrationID
	registration.Binding.NativeSessionID = report.Session.NativeSessionID
	registration.Binding.NativeProjectID = report.Session.NativeProjectID
	registration.Binding.NativeLocationDigest = report.Session.NativeLocationDigest
	runtime := &fakeS2BHandoffRuntime{targetReceipt: model.ContinuationTargetRegistrationReceiptV1{
		FormatVersion: 1, Action: "register_continuation_target", Status: "registered",
		OperationID: manifest.OperationID, WorkID: registration.Identity.WorkID,
		ExpectedRevision: registration.Identity.ExpectedRevision, Binding: registration.Binding,
		ReceiptDigest: "sha256:" + strings.Repeat("2", 64),
	}}
	admission := &fakeS2BAdmission{}
	controller := &S2Controller{
		Store: store, ServerID: "srv_s2controller0001", Objects: &fakeS2Objects{capture: source.capture},
		Catalog: &workspacecatalog.Catalog{State: store}, Helper: runtime,
		HandoffSupervisor: runtime, HandoffAdmission: admission,
	}
	if err := controller.ApplyHandoffTargetRegistrations(
		context.Background(), []model.ContinuityRegistrationV1{registration},
	); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runtime.actions, []string{"register_continuation_target"}) ||
		len(admission.operations) != 1 || admission.operations[0] != manifest.OperationID {
		t.Fatalf("target admission sequence actions=%v admissions=%v", runtime.actions, admission.operations)
	}
	requestPayload, err := json.Marshal(runtime.requests[0])
	if err != nil {
		t.Fatal(err)
	}
	var request model.ContinuationTargetRegistrationRequestV1
	if err := json.Unmarshal(requestPayload, &request); err != nil {
		t.Fatal(err)
	}
	if request.Action != sandboxFixture.TargetRegistrationRequest.Action || request.OperationID != manifest.OperationID ||
		request.PrepareDesiredRevision != manifest.DesiredRevision ||
		request.Registration.WorkID != registration.Identity.WorkID ||
		request.Registration.ProjectID != registration.Identity.ProjectID ||
		request.Registration.SandboxID != registration.Identity.SandboxID ||
		request.Registration.WorkspaceEpoch != registration.Identity.WorkspaceEpoch ||
		request.Registration.SandboxGeneration != registration.Identity.SandboxGeneration ||
		request.Registration.ExpectedRevision != registration.Identity.ExpectedRevision ||
		request.Registration.Binding != registration.Binding ||
		request.Registration.BackgroundWriterState != "idle" || request.Registration.TaskID != nil ||
		request.Registration.TaskAttempt != nil || request.Registration.LastAcceptedExecutionID != nil {
		t.Fatalf("fixed target registration request = %+v", request)
	}
	stored, err := store.ContinuityRegistration(context.Background(), registration.Binding.BindingID)
	if err != nil || stored == nil || stored.ObservedStatus != "verified" ||
		stored.ReceiptDigest != runtime.targetReceipt.ReceiptDigest {
		t.Fatalf("stored target registration = %#v, %v", stored, err)
	}
}

func TestS2BRestoredTargetUsesAcceptedWorkspaceWithoutAnotherMaterialization(t *testing.T) {
	fixture := readS2BControllerFixture(t)
	s2Fixture := readS2WireFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authority := seedS2Authority(t, store, s2Fixture)
	objects := &fakeS2Objects{capture: authority.capture}
	base := &S2Controller{
		Store: store, ServerID: "srv_s2controller0001", Objects: objects,
		Catalog: &workspacecatalog.Catalog{State: store}, Helper: &fakeS2Helper{},
	}
	if err := base.Apply(context.Background(), nil, []model.RestoreManifestV1{authority.restore}); err != nil {
		t.Fatal(err)
	}
	_, restoreReports, err := base.Reports(context.Background())
	if err != nil || len(restoreReports) != 1 || restoreReports[0].Target == nil {
		t.Fatalf("accepted restore = %#v, %v", restoreReports, err)
	}
	target := *restoreReports[0].Target
	manifest := fixture.RestoredTargetManifest
	manifest.Identity, manifest.Binding, manifest.Checkpoint = authority.manifest.Identity, authority.manifest.Binding, authority.manifest.Checkpoint
	manifest.TargetPolicy.SandboxID = authority.restore.Target.SandboxID
	manifest.TargetPolicy.SandboxGeneration = authority.restore.Target.SandboxGeneration
	manifest.Lineage.SourceWorkID = manifest.Identity.WorkID
	manifest.Lineage.SourceRevision = manifest.Identity.ExpectedRevision
	manifest.Lineage.CheckpointOperationID = manifest.Checkpoint.OperationID
	manifest.Lineage.RestoreOperationID = &authority.restore.OperationID
	manifest.Workspace.RestoreOperationID = &authority.restore.OperationID
	manifest.Workspace.SelectionID = &target.SelectionID
	manifest.Workspace.ProjectID = &target.ProjectID
	manifest.Workspace.WorkspaceEpoch = &target.WorkspaceEpoch
	manifest.Workspace.ScopeRevision = &target.ScopeRevision
	manifest.Workspace.RootAttestation = &target.RootAttestation
	seedS2BTargetService(t, store, manifest, t.TempDir())
	runtime := &fakeS2BHandoffRuntime{continuityResponse: handoffReadyReport(manifest, model.ContinuationHandoffTargetWorkspaceV1{
		SelectionID: target.SelectionID, ProjectID: target.ProjectID, WorkspaceEpoch: target.WorkspaceEpoch,
		ScopeRevision: target.ScopeRevision, RootAttestation: target.RootAttestation,
	})}
	controller := &S2Controller{
		Store: store, ServerID: "srv_s2controller0001", Objects: objects,
		Catalog: &workspacecatalog.Catalog{State: store}, Helper: runtime,
		HandoffSupervisor: runtime, HandoffAdmission: &fakeS2BAdmission{},
	}
	beforeMaterialize := objects.materializeCalls
	if err := controller.ApplyHandoffs(context.Background(), []model.ContinuationHandoffManifestV1{manifest}); err != nil {
		t.Fatal(err)
	}
	if objects.materializeCalls != beforeMaterialize || objects.workspaceChecks == 0 ||
		!reflect.DeepEqual(runtime.actions, []string{"register-handoff-workspace", "prepare_handoff"}) {
		t.Fatalf("accepted restore handoff materialize/check/actions = %d/%d/%v",
			objects.materializeCalls-beforeMaterialize, objects.workspaceChecks, runtime.actions)
	}
}

func TestS2BHandoffRefusesEveryStaleAuthorityBeforeNativeCreation(t *testing.T) {
	fixture := readS2BControllerFixture(t)
	s2Fixture := readS2WireFixture(t)
	mutations := map[string]func(*model.ContinuationHandoffManifestV1){
		"source binding": func(v *model.ContinuationHandoffManifestV1) { v.Binding.BindingRevision++ },
		"checkpoint": func(v *model.ContinuationHandoffManifestV1) {
			v.Checkpoint.ManifestDigest = "sha256:" + strings.Repeat("3", 64)
		},
		"target service generation": func(v *model.ContinuationHandoffManifestV1) {
			v.TargetPolicy.ServiceGeneration++
		},
		"target profile": func(v *model.ContinuationHandoffManifestV1) {
			v.TargetPolicy.ProfileDigest = "sha256:" + strings.Repeat("4", 64)
		},
		"target instructions": func(v *model.ContinuationHandoffManifestV1) {
			v.TargetPolicy.InstructionDigest = "sha256:" + strings.Repeat("5", 64)
		},
		"target workspace policy": func(v *model.ContinuationHandoffManifestV1) {
			v.TargetPolicy.SandboxGeneration++
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			authority := seedS2Authority(t, store, s2Fixture)
			manifest := fixture.ReviewerManifest
			manifest.Identity, manifest.Binding, manifest.Checkpoint = authority.manifest.Identity, authority.manifest.Binding, authority.manifest.Checkpoint
			manifest.Lineage.SourceWorkID = manifest.Identity.WorkID
			manifest.Lineage.SourceRevision = manifest.Identity.ExpectedRevision
			manifest.Lineage.CheckpointOperationID = manifest.Checkpoint.OperationID
			seedS2BTargetService(t, store, manifest, t.TempDir())
			mutate(&manifest)
			runtime := &fakeS2BHandoffRuntime{}
			objects := &fakeS2Objects{capture: authority.capture}
			controller := &S2Controller{
				Store: store, ServerID: "srv_s2controller0001", Objects: objects,
				Catalog: &workspacecatalog.Catalog{State: store}, Helper: runtime,
				HandoffSupervisor: runtime, HandoffAdmission: &fakeS2BAdmission{},
			}
			if err := controller.ApplyHandoffs(context.Background(), []model.ContinuationHandoffManifestV1{manifest}); err == nil {
				t.Fatal("stale authority was accepted")
			}
			if len(runtime.actions) != 0 || runtime.nativeCreateCount != 0 {
				t.Fatalf("stale authority reached native helper: %v/%d", runtime.actions, runtime.nativeCreateCount)
			}
		})
	}
}
