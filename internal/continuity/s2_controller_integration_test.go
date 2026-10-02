package continuity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type s2WireFixture struct {
	ContinuationManifest model.ContinuationManifestV1 `json:"continuationManifest"`
	ContinuationReport   model.ContinuationReportV1   `json:"continuationReport"`
	RestoreManifest      model.RestoreManifestV1      `json:"restoreManifest"`
}

type fakeS2Objects struct {
	capture          storage.DurableCapture
	verifyErr        error
	verifyCalls      int
	workspaceErr     error
	workspaceChecks  int
	materializeErr   error
	materializeCalls int
	lastMaterialize  storage.MaterializeNewRequest
}

func (f *fakeS2Objects) Verify(_ context.Context, checkpointID string) (storage.DurableCapture, error) {
	f.verifyCalls++
	if f.verifyErr != nil {
		return storage.DurableCapture{}, f.verifyErr
	}
	if checkpointID != f.capture.ID {
		return storage.DurableCapture{}, storage.ErrCheckpointCorrupt
	}
	return f.capture, nil
}

func (f *fakeS2Objects) VerifyWorkspace(_ context.Context, checkpointID, workspaceRoot string) error {
	f.workspaceChecks++
	if checkpointID != f.capture.ID || workspaceRoot == "" {
		return storage.ErrCheckpointCorrupt
	}
	return f.workspaceErr
}

func (f *fakeS2Objects) MaterializeNew(_ context.Context, request storage.MaterializeNewRequest) (storage.MaterializeReceipt, error) {
	f.materializeCalls++
	f.lastMaterialize = request
	if f.materializeErr != nil {
		return storage.MaterializeReceipt{}, f.materializeErr
	}
	command := exec.Command("git", "clone", "--no-hardlinks", "--", request.SourceRoot, request.DestinationRoot)
	if output, err := command.CombinedOutput(); err != nil {
		return storage.MaterializeReceipt{}, errors.New(string(output))
	}
	return storage.MaterializeReceipt{
		ManifestDigest: f.capture.ManifestDigest, DestinationIdentity: request.DestinationIdentity,
		Bytes: f.capture.Bytes, ObjectCount: f.capture.ObjectCount,
	}, nil
}

type fakeS2Helper struct {
	report      model.ContinuationReportV1
	actions     []string
	requests    []map[string]any
	losePrepare bool
	loseRelease bool
	prepared    bool
	released    bool
}

func (f *fakeS2Helper) ExecContinuity(_ context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	action, _ := request["action"].(string)
	f.actions = append(f.actions, action)
	f.requests = append(f.requests, request)
	switch action {
	case "prepare_continuation":
		f.prepared = true
		if f.losePrepare {
			f.losePrepare = false
			return nil, nil, errors.New("injected lost prepare response")
		}
		response, err := json.Marshal(f.report)
		return response, nil, err
	case "reconcile_continuation":
		if !f.prepared {
			return nil, nil, errors.New("baseline was never prepared")
		}
		if f.released {
			envelope := map[string]any{
				"formatVersion": 1, "action": action, "status": "released", "state": "released",
				"report": f.report, "consumption": nil,
				"release": map[string]any{"releasedAt": "2026-09-27T18:02:00Z"},
			}
			response, err := json.Marshal(envelope)
			return response, nil, err
		}
		envelope := map[string]any{
			"formatVersion": 1, "action": action, "status": "ready", "state": "prepared",
			"report": f.report, "consumption": nil, "release": nil,
		}
		response, err := json.Marshal(envelope)
		return response, nil, err
	case "release_continuation":
		if !f.prepared {
			return nil, nil, errors.New("baseline was never prepared")
		}
		f.released = true
		if f.loseRelease {
			f.loseRelease = false
			return nil, nil, errors.New("injected lost release response")
		}
		envelope := map[string]any{
			"formatVersion": 1, "action": action, "status": "released", "state": "released",
			"report": f.report, "consumption": nil,
			"release": map[string]any{"releasedAt": "2026-09-27T18:02:00Z"},
		}
		response, err := json.Marshal(envelope)
		return response, nil, err
	default:
		return nil, nil, errors.New("unexpected helper action")
	}
}

func readS2WireFixture(t *testing.T) s2WireFixture {
	t.Helper()
	payload, err := os.ReadFile("../api/testdata/agent-continuation-v1.backend-wire.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture s2WireFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

type s2Authority struct {
	manifest model.ContinuationManifestV1
	report   model.ContinuationReportV1
	restore  model.RestoreManifestV1
	anchor   string
	source   string
	capture  storage.DurableCapture
}

func seedS2Authority(t *testing.T, store *state.Store, fixture s2WireFixture) s2Authority {
	t.Helper()
	ctx := context.Background()
	anchor := t.TempDir()
	catalog := workspacecatalog.Catalog{State: store, Now: func() time.Time { return time.Date(2026, 9, 27, 20, 0, 0, 0, time.UTC) }}
	project, err := catalog.EnsureDefault(ctx, workspacecatalog.DefaultProjectRequest{
		Anchor: anchor, ServerID: "srv_s2controller0001", TeamID: fixture.ContinuationManifest.Target.TeamID,
		MemberID: fixture.ContinuationManifest.Target.MemberID, SandboxID: fixture.ContinuationManifest.Identity.SandboxID,
		SandboxGeneration:     fixture.ContinuationManifest.Identity.SandboxGeneration,
		ServiceRegistrationID: fixture.ContinuationManifest.Binding.ServiceRegistrationID,
		AllocationDigest:      "sha256:" + strings.Repeat("1", 64), ConfigDigest: "sha256:" + strings.Repeat("2", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := fixture.ContinuationManifest
	manifest.Identity.ProjectID, manifest.Identity.WorkspaceEpoch = project.Report.ProjectID, project.Report.WorkspaceEpoch
	manifest.Target.SelectionID, manifest.Target.ProjectID = project.Report.SelectionID, project.Report.ProjectID
	manifest.Target.WorkspaceEpoch, manifest.Target.RootAttestation = project.Report.WorkspaceEpoch, project.Report.RootAttestation
	restore := fixture.RestoreManifest
	restore.Identity = manifest.Identity
	restore.Binding = manifest.Binding
	report := fixture.ContinuationReport
	report.Identity, report.Binding, report.Checkpoint, report.Target = manifest.Identity, manifest.Binding, manifest.Checkpoint, manifest.Target
	report.ContextDigest = manifest.Context.Digest

	sourceIdentity := model.ContinuityIdentityV1{
		WorkID: manifest.Identity.WorkID, ProjectID: manifest.Identity.ProjectID, SandboxID: manifest.Identity.SandboxID,
		WorkspaceEpoch: manifest.Identity.WorkspaceEpoch, SandboxGeneration: manifest.Identity.SandboxGeneration,
		ExpectedRevision: manifest.Identity.ExpectedRevision,
	}
	captureID := manifest.Checkpoint.CheckpointID
	capture := storage.DurableCapture{
		ID: captureID, ObjectID: captureID, ManifestDigest: manifest.Checkpoint.ManifestDigest,
		Manifest: storage.CheckpointManifestV1{FormatVersion: 1, Identity: sourceIdentity},
		Bytes:    manifest.Checkpoint.Bytes, ObjectCount: manifest.Checkpoint.ObjectCount,
	}
	if err := store.PutContinuityCapture(ctx, state.LocalContinuityCapture{
		ID: captureID, Identity: sourceIdentity, ObjectID: captureID, ManifestDigest: capture.ManifestDigest,
		Bytes: capture.Bytes, ObjectCount: capture.ObjectCount, Verified: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptCheckpoint(ctx, state.LocalCheckpoint{
		ID: manifest.Checkpoint.CheckpointID, CaptureID: captureID, Identity: sourceIdentity,
		ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes, ObjectCount: capture.ObjectCount,
	}); err != nil {
		t.Fatal(err)
	}
	binding := model.ContinuityBindingV1{
		BindingID: manifest.Binding.BindingID, BindingRevision: manifest.Binding.BindingRevision,
		RegisteredSourceID: manifest.Binding.RegisteredSourceID, ServiceRegistrationID: manifest.Binding.ServiceRegistrationID,
		NativeSessionID: manifest.Binding.NativeSessionID, NativeProjectID: manifest.Binding.NativeProjectID,
		NativeLocationDigest: manifest.Binding.NativeLocationDigest,
	}
	if err := store.PutContinuityOperationReport(ctx, model.ContinuityOperationReportV1{
		FormatVersion: 1, OperationID: manifest.Checkpoint.OperationID, Action: "capture_checkpoint",
		ScopeRevision: manifest.Binding.ScopeRevision, BoundaryKind: "task", Identity: sourceIdentity, Binding: binding,
		Status: "accepted", CheckpointID: manifest.Checkpoint.CheckpointID, CaptureID: captureID,
		ManifestDigest: manifest.Checkpoint.ManifestDigest, Bytes: manifest.Checkpoint.Bytes, ObjectCount: manifest.Checkpoint.ObjectCount,
		ReceiptDigest: "sha256:" + strings.Repeat("5", 64), RequestDigest: "sha256:" + strings.Repeat("6", 64),
	}); err != nil {
		t.Fatal(err)
	}
	sourceReport := model.ContinuitySourceReportV1{
		FormatVersion: 1, RegisteredSourceID: binding.RegisteredSourceID, ServiceRegistrationID: binding.ServiceRegistrationID,
		ServiceGeneration: manifest.Binding.ServiceGeneration, ProjectID: manifest.Identity.ProjectID,
		SandboxID: manifest.Identity.SandboxID, SandboxGeneration: manifest.Identity.SandboxGeneration,
		WorkspaceEpoch: manifest.Identity.WorkspaceEpoch, NativeSessionID: binding.NativeSessionID,
		NativeProjectID: binding.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest,
		ScopeRevision: manifest.Binding.ScopeRevision, Role: manifest.Target.Role,
		ProfileRevision: manifest.Target.ProfileRevision, InstructionRevision: manifest.Target.InstructionRevision,
		Availability: "available", LastObservedAt: time.Now().UTC(),
	}
	if err := store.PutContinuitySource(ctx, state.LocalContinuitySource{
		Report: sourceReport, Root: project.HostRoot, Instance: "worker", Lifecycle: "running", LifecycleRevision: 3,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
		Manifest: model.ContinuityRegistrationV1{FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true,
			ScopeRevision: manifest.Binding.ScopeRevision, Identity: sourceIdentity, Binding: binding},
		ObservedStatus: "verified", ServiceGeneration: manifest.Binding.ServiceGeneration,
		ReceiptDigest: "sha256:" + strings.Repeat("3", 64),
	}); err != nil {
		t.Fatal(err)
	}
	serviceManifest := model.ManagedServiceV1{
		FormatVersion: 1, OperationID: "op_service_s2controller0001", ActionRevision: manifest.Target.ServiceActionRevision,
		DesiredRevision: manifest.Target.ServiceDesiredRevision, ConfigDigest: "sha256:" + strings.Repeat("2", 64),
		DesiredState: "active", SessionMode: "lookup_only",
		Identity: model.ManagedServiceIdentityV1{
			ServerID: "srv_s2controller0001", TeamID: manifest.Target.TeamID, MemberID: manifest.Target.MemberID,
			SandboxID: manifest.Target.SandboxID, SandboxGeneration: manifest.Target.SandboxGeneration,
			ServiceRegistrationID: manifest.Target.ServiceRegistrationID, ExpectedServiceGeneration: manifest.Target.ServiceGeneration,
			Instance: "default", Role: manifest.Target.Role,
		},
		Profile:      model.ManagedServiceProfileV1{SetupOperationID: "setup_s2controller0001", ProfileID: manifest.Target.ProfileID, ProfileRevision: manifest.Target.ProfileRevision, ProfileDigest: manifest.Target.ProfileDigest},
		Instructions: model.ManagedServiceInstructionsV1{InstructionRevision: manifest.Target.InstructionRevision, InstructionDigest: manifest.Target.InstructionDigest},
		Workspace:    model.ManagedServiceWorkspaceV1{SelectionID: manifest.Target.SelectionID, ProjectID: manifest.Target.ProjectID, WorkspaceEpoch: manifest.Target.WorkspaceEpoch, ScopeRevision: manifest.Target.ScopeRevision, Designation: "team_project", RootAttestation: manifest.Target.RootAttestation},
	}
	if err := store.PutManagedServiceIntent(ctx, state.LocalManagedService{Manifest: serviceManifest, Phase: "ready", ProcessInstance: "worker", Port: 4321, CreationDispatched: true, ServiceGeneration: manifest.Target.ServiceGeneration}); err != nil {
		t.Fatal(err)
	}
	serviceReport := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: serviceManifest.OperationID, ActionRevision: serviceManifest.ActionRevision,
		ObservedDesiredRevision: serviceManifest.DesiredRevision, ConfigDigest: serviceManifest.ConfigDigest, ObservedState: "ready",
		Identity: serviceManifest.Identity, ServiceGeneration: manifest.Target.ServiceGeneration, ProfileStatus: "ready", WorkspaceStatus: "ready",
		EnrollmentStatus: "ready", WorkerStatus: "ready", InstructionApplied: true,
		InstructionRevision: manifest.Target.InstructionRevision, InstructionDigest: manifest.Target.InstructionDigest,
		NativeRegistration: &model.ManagedNativeRegistrationV1{RegisteredSourceID: binding.RegisteredSourceID, WorkspaceEpoch: manifest.Identity.WorkspaceEpoch, NativeSessionID: binding.NativeSessionID, NativeProjectID: binding.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest},
		ReceiptDigest:      "sha256:" + strings.Repeat("4", 64),
	}
	if err := store.UpdateManagedService(ctx, serviceManifest.Identity.ServiceRegistrationID, "ready", &serviceReport, ""); err != nil {
		t.Fatal(err)
	}
	return s2Authority{manifest: manifest, report: report, restore: restore, anchor: anchor, source: project.HostRoot, capture: capture}
}

func TestS2ControllerRejectsEveryStaleAuthorityAndRecoversLostPrepareLookupOnly(t *testing.T) {
	fixture := readS2WireFixture(t)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	authority := seedS2Authority(t, store, fixture)
	objects := &fakeS2Objects{capture: authority.capture}
	helper := &fakeS2Helper{report: authority.report, losePrepare: true}
	controller := &S2Controller{Store: store, ServerID: "srv_s2controller0001", Objects: objects, Catalog: &workspacecatalog.Catalog{State: store}, Helper: helper}
	if err := controller.Apply(context.Background(), []model.ContinuationManifestV1{authority.manifest}, nil); err == nil {
		t.Fatal("lost prepare response was treated as ready")
	} else if len(helper.actions) == 0 {
		t.Fatalf("continuation refused before helper: %v", err)
	}
	if len(helper.actions) != 1 || helper.actions[0] != "prepare_continuation" {
		t.Fatalf("initial helper actions = %#v", helper.actions)
	}
	expectedPayload, err := json.Marshal(continuationHelperRequest{ContinuationManifestV1: authority.manifest, Instance: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	var expectedRequest map[string]any
	if err := json.Unmarshal(expectedPayload, &expectedRequest); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(helper.requests[0], expectedRequest) {
		t.Fatalf("prepare helper did not receive the exact manifest and registered instance\nwant: %#v\ngot:  %#v", expectedRequest, helper.requests[0])
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered := &S2Controller{Store: reopened, ServerID: "srv_s2controller0001", Objects: objects, Catalog: &workspacecatalog.Catalog{State: reopened}, Helper: helper}
	if err := recovered.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(helper.actions, []string{"prepare_continuation", "reconcile_continuation"}) {
		t.Fatalf("lost response recovery actions = %#v", helper.actions)
	}
	reports, _, err := recovered.Reports(context.Background())
	if err != nil || len(reports) != 1 || !reflect.DeepEqual(reports[0], authority.report) {
		t.Fatalf("recovered exact baseline report = %#v, %v", reports, err)
	}
	if err := recovered.Apply(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(helper.actions, []string{"prepare_continuation", "reconcile_continuation"}) {
		t.Fatalf("omitted prepared baseline was released: %#v", helper.actions)
	}

	baseCalls := len(helper.actions)
	mutations := map[string]func(*model.ContinuationManifestV1){
		"checkpoint": func(v *model.ContinuationManifestV1) {
			v.Checkpoint.ManifestDigest = "sha256:" + strings.Repeat("a", 64)
		},
		"binding":            func(v *model.ContinuationManifestV1) { v.Binding.BindingRevision++ },
		"service generation": func(v *model.ContinuationManifestV1) { v.Binding.ServiceGeneration++; v.Target.ServiceGeneration++ },
		"native session":     func(v *model.ContinuationManifestV1) { v.Binding.NativeSessionID = "ses_stale0001" },
		"member":             func(v *model.ContinuationManifestV1) { v.Target.MemberID = "tmem_stale0001" },
		"workspace": func(v *model.ContinuationManifestV1) {
			v.Identity.WorkspaceEpoch = "epoch_stale0001"
			v.Target.WorkspaceEpoch = "epoch_stale0001"
		},
		"root attestation": func(v *model.ContinuationManifestV1) { v.Target.RootAttestation = "sha256:" + strings.Repeat("b", 64) },
		"profile":          func(v *model.ContinuationManifestV1) { v.Target.ProfileDigest = "sha256:" + strings.Repeat("c", 64) },
		"instructions": func(v *model.ContinuationManifestV1) {
			v.Target.InstructionDigest = "sha256:" + strings.Repeat("d", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			stale := authority.manifest
			stale.OperationID = "op_stale_" + strings.ReplaceAll(name, " ", "_")
			mutate(&stale)
			if err := recovered.Apply(context.Background(), []model.ContinuationManifestV1{stale}, nil); err == nil {
				t.Fatal("stale tuple reached helper")
			}
			if len(helper.actions) != baseCalls {
				t.Fatalf("stale tuple dispatched helper: %#v", helper.actions[baseCalls:])
			}
		})
	}
	objects.verifyErr = storage.ErrCheckpointCorrupt
	fresh := authority.manifest
	fresh.OperationID = "op_continue_checkpointverify0001"
	if err := recovered.Apply(context.Background(), []model.ContinuationManifestV1{fresh}, nil); !errors.Is(err, storage.ErrCheckpointCorrupt) {
		t.Fatalf("current checkpoint verification error = %v", err)
	}
}

func TestS2ControllerRefusesChangedCurrentWorkspaceBeforePreparingContinuation(t *testing.T) {
	fixture := readS2WireFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authority := seedS2Authority(t, store, fixture)
	objects := &fakeS2Objects{capture: authority.capture, workspaceErr: storage.ErrWorkspaceChanged}
	helper := &fakeS2Helper{report: authority.report}
	controller := &S2Controller{Store: store, ServerID: "srv_s2controller0001", Objects: objects, Catalog: &workspacecatalog.Catalog{State: store}, Helper: helper}

	err = controller.Apply(context.Background(), []model.ContinuationManifestV1{authority.manifest}, nil)
	if err != nil {
		t.Fatalf("changed current workspace was not recorded as a terminal refusal: %v", err)
	}
	if objects.workspaceChecks != 1 || len(helper.actions) != 0 {
		t.Fatalf("changed workspace checks/helper actions = %d/%#v", objects.workspaceChecks, helper.actions)
	}
	reports, _, err := controller.Reports(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Status != "failed" || reports[0].Baseline != nil ||
		reports[0].ErrorCode == nil || *reports[0].ErrorCode != "workspace_changed" {
		t.Fatalf("changed workspace immutable failure report = %#v, %v", reports, err)
	}
	if err := controller.Apply(context.Background(), []model.ContinuationManifestV1{authority.manifest}, nil); err != nil {
		t.Fatal(err)
	}
	if objects.workspaceChecks != 1 || len(helper.actions) != 0 {
		t.Fatalf("failure replay repeated verification/helper = %d/%#v", objects.workspaceChecks, helper.actions)
	}
	releaseMap := continuationReleaseManifestMap(t, authority.manifest)
	releaseMap["reason"] = "failed"
	payload, err := json.Marshal(releaseMap)
	if err != nil {
		t.Fatal(err)
	}
	var release model.ContinuationReleaseManifestV1
	if err := json.Unmarshal(payload, &release); err != nil {
		t.Fatal(err)
	}
	if err := controller.ApplyReleases(context.Background(), []model.ContinuationReleaseManifestV1{release}); err != nil {
		t.Fatal(err)
	}
	releaseReports, err := controller.ReleaseReports(context.Background())
	if err != nil || len(releaseReports) != 1 || releaseReports[0].Status != "released" || releaseReports[0].ErrorCode != nil {
		t.Fatalf("pre-helper failure release = %#v, %v", releaseReports, err)
	}
	if len(helper.actions) != 0 {
		t.Fatalf("pre-helper failure fabricated a native baseline release: %#v", helper.actions)
	}
}

func TestS2ControllerExplicitReleaseUsesSavedPrepareTupleAndReplaysAcrossRestart(t *testing.T) {
	fixture := readS2WireFixture(t)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	authority := seedS2Authority(t, store, fixture)
	helper := &fakeS2Helper{report: authority.report}
	objects := &fakeS2Objects{capture: authority.capture}
	controller := &S2Controller{Store: store, ServerID: "srv_s2controller0001", Objects: objects, Catalog: &workspacecatalog.Catalog{State: store}, Helper: helper}
	if err := controller.Apply(context.Background(), []model.ContinuationManifestV1{authority.manifest}, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered := &S2Controller{Store: reopened, ServerID: "srv_s2controller0001", Objects: objects, Catalog: &workspacecatalog.Catalog{State: reopened}, Helper: helper}

	release := continuationReleaseManifestMap(t, authority.manifest)
	apply := reflect.ValueOf(recovered).MethodByName("ApplyReleases")
	if !apply.IsValid() {
		t.Fatal("S2Controller.ApplyReleases is unavailable for the explicit backend release intent")
	}
	if apply.Type().NumIn() != 2 {
		t.Fatalf("ApplyReleases signature = %s", apply.Type())
	}
	releases := reflect.New(apply.Type().In(1))
	payload, err := json.Marshal([]map[string]any{release})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, releases.Interface()); err != nil {
		t.Fatalf("canonical release manifest is outside the Runtime model: %v", err)
	}
	result := apply.Call([]reflect.Value{reflect.ValueOf(context.Background()), releases.Elem()})
	if len(result) != 1 || !result[0].IsNil() {
		t.Fatalf("explicit release failed: %#v", result)
	}
	if !helper.released || !reflect.DeepEqual(helper.actions, []string{"prepare_continuation", "release_continuation"}) {
		t.Fatalf("explicit release helper actions = %#v", helper.actions)
	}
	expectedRequestPayload, err := json.Marshal(continuationHelperRequest{ContinuationManifestV1: authority.manifest, Instance: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	var expectedRequest map[string]any
	if err := json.Unmarshal(expectedRequestPayload, &expectedRequest); err != nil {
		t.Fatal(err)
	}
	expectedRequest["action"] = "release_continuation"
	if !reflect.DeepEqual(helper.requests[1], expectedRequest) {
		t.Fatalf("helper release did not use the exact saved prepare tuple\nwant: %#v\ngot:  %#v", expectedRequest, helper.requests[1])
	}

	reportsMethod := reflect.ValueOf(recovered).MethodByName("ReleaseReports")
	if !reportsMethod.IsValid() {
		t.Fatal("S2Controller.ReleaseReports is unavailable")
	}
	reportResults := reportsMethod.Call([]reflect.Value{reflect.ValueOf(context.Background())})
	if len(reportResults) != 2 || !reportResults[1].IsNil() || reportResults[0].Len() != 1 {
		t.Fatalf("release reports = %#v", reportResults)
	}
	reportPayload, err := json.Marshal(reportResults[0].Index(0).Interface())
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(reportPayload, &report); err != nil {
		t.Fatal(err)
	}
	if report["status"] != "released" || report["errorCode"] != nil || report["reason"] != "superseded" ||
		report["desiredRevision"] != release["desiredRevision"] {
		t.Fatalf("release report did not echo the exact backend tuple: %#v", report)
	}
	beforeReplay := len(helper.actions)
	result = apply.Call([]reflect.Value{reflect.ValueOf(context.Background()), releases.Elem()})
	if len(result) != 1 || !result[0].IsNil() || len(helper.actions) != beforeReplay {
		t.Fatalf("terminal release replay called helper again: %#v / %#v", result, helper.actions)
	}
}

func TestS2ControllerRecoversLostReleaseResponseFromReleasedTombstone(t *testing.T) {
	fixture := readS2WireFixture(t)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	authority := seedS2Authority(t, store, fixture)
	helper := &fakeS2Helper{report: authority.report, loseRelease: true}
	objects := &fakeS2Objects{capture: authority.capture}
	controller := &S2Controller{Store: store, ServerID: "srv_s2controller0001", Objects: objects, Catalog: &workspacecatalog.Catalog{State: store}, Helper: helper}
	if err := controller.Apply(context.Background(), []model.ContinuationManifestV1{authority.manifest}, nil); err != nil {
		t.Fatal(err)
	}
	releaseMap := continuationReleaseManifestMap(t, authority.manifest)
	payload, err := json.Marshal(releaseMap)
	if err != nil {
		t.Fatal(err)
	}
	var release model.ContinuationReleaseManifestV1
	if err := json.Unmarshal(payload, &release); err != nil {
		t.Fatal(err)
	}
	if err := controller.ApplyReleases(context.Background(), []model.ContinuationReleaseManifestV1{release}); !errors.Is(err, ErrS2RecoveryUnknown) {
		t.Fatalf("lost release response error = %v, want ErrS2RecoveryUnknown", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered := &S2Controller{Store: reopened, ServerID: "srv_s2controller0001", Objects: objects, Catalog: &workspacecatalog.Catalog{State: reopened}, Helper: helper}
	if err := recovered.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(helper.actions, []string{"prepare_continuation", "release_continuation", "reconcile_continuation"}) {
		t.Fatalf("lost release recovery actions = %#v", helper.actions)
	}
	reports, err := recovered.ReleaseReports(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Status != "released" || reports[0].DesiredRevision != release.DesiredRevision {
		t.Fatalf("recovered release report = %#v, %v", reports, err)
	}

	foreign := release
	foreign.OperationID = "op_release_foreign0001"
	if err := recovered.ApplyReleases(context.Background(), []model.ContinuationReleaseManifestV1{foreign}); !errors.Is(err, ErrS2AuthorityChanged) {
		t.Fatalf("foreign release error = %v, want ErrS2AuthorityChanged", err)
	}
	if len(helper.actions) != 3 {
		t.Fatalf("foreign release reached helper: %#v", helper.actions)
	}
}

func continuationReleaseManifestMap(t *testing.T, prepared model.ContinuationManifestV1) map[string]any {
	t.Helper()
	payload, err := os.ReadFile("../api/testdata/agent-continuation-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var canonical struct {
		Release map[string]any `json:"continuationReleaseManifest"`
	}
	if err := json.Unmarshal(payload, &canonical); err != nil {
		t.Fatal(err)
	}
	preparedPayload, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal(preparedPayload, &saved); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"formatVersion", "operationId", "identity", "binding", "checkpoint", "target", "context"} {
		canonical.Release[field] = saved[field]
	}
	canonical.Release["desiredRevision"] = saved["desiredRevision"].(float64) + 1
	return canonical.Release
}

func TestS2RestoreControllerAllocatesMaterializesAndPublishesOneTargetAcrossRestart(t *testing.T) {
	fixture := readS2WireFixture(t)
	statePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	authority := seedS2Authority(t, store, fixture)
	objects := &fakeS2Objects{capture: authority.capture}
	helper := &fakeS2Helper{}
	controller := &S2Controller{Store: store, ServerID: "srv_s2controller0001", Objects: objects, Catalog: &workspacecatalog.Catalog{State: store}, Helper: helper}
	if err := controller.Apply(context.Background(), nil, []model.RestoreManifestV1{authority.restore}); err != nil {
		t.Fatal(err)
	}
	_, reports, err := controller.Reports(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Status != "accepted" || reports[0].Target == nil {
		t.Fatalf("restore report = %#v, %v", reports, err)
	}
	firstTarget := *reports[0].Target
	if objects.verifyCalls == 0 || objects.materializeCalls != 1 || len(helper.actions) != 0 {
		t.Fatalf("restore verify/materialize/helper = %d/%d/%#v", objects.verifyCalls, objects.materializeCalls, helper.actions)
	}
	services, err := store.ManagedServices(context.Background())
	if err != nil || len(services) != 1 {
		t.Fatalf("restore created a service: %d, %v", len(services), err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered := &S2Controller{Store: reopened, ServerID: "srv_s2controller0001", Objects: objects, Catalog: &workspacecatalog.Catalog{State: reopened}, Helper: helper}
	if err := recovered.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := recovered.Apply(context.Background(), nil, []model.RestoreManifestV1{authority.restore}); err != nil {
		t.Fatal(err)
	}
	_, reports, err = recovered.Reports(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Target == nil || !reflect.DeepEqual(*reports[0].Target, firstTarget) {
		t.Fatalf("reopened restore target drifted: %#v, %v", reports, err)
	}
	projects, err := reopened.ManagedProjects(context.Background())
	if err != nil || len(projects) != 2 || objects.materializeCalls != 1 {
		t.Fatalf("replay allocation/materialization = %d/%d, %v", len(projects), objects.materializeCalls, err)
	}
}

func initGitFixture(t *testing.T, root string) {
	t.Helper()
	for _, args := range [][]string{{"init", "--initial-branch=main"}, {"config", "user.name", "S2 Test"}, {"config", "user.email", "s2@example.invalid"}} {
		command := exec.Command("git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
}
