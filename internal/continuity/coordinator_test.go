package continuity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type fakeBoundaryHelper struct {
	actions               []string
	operations            []string
	failAction            string
	failCount             int
	refuseAction          string
	refuseCode            string
	refuseWithErrorAction string
	refuseWithErrorCode   string
	onAction              func(string)
	identity              model.ContinuityIdentityV1
	binding               model.ContinuityBindingV1
}

func (f *fakeBoundaryHelper) ExecContinuity(_ context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	action := request["action"].(string)
	f.actions = append(f.actions, action)
	f.operations = append(f.operations, request["operationId"].(string))
	if f.onAction != nil {
		f.onAction(action)
	}
	if action == f.failAction && f.failCount != 0 {
		if f.failCount > 0 {
			f.failCount--
		}
		return nil, nil, errors.New("injected helper failure")
	}
	if action == f.refuseAction {
		payload, err := json.Marshal(boundaryEnvelope{FormatVersion: 1, Action: action, Status: "refused", Error: f.refuseCode})
		return payload, nil, err
	}
	if action == f.refuseWithErrorAction {
		payload, err := json.Marshal(boundaryEnvelope{FormatVersion: 1, Action: action, Status: "refused", Error: f.refuseWithErrorCode})
		return payload, nil, errors.Join(err, errors.New("exit status 1"))
	}
	status := "acknowledged"
	if action == "release_boundary" {
		status = "released"
	}
	kind := "initial"
	if f.identity.TaskID != nil && f.identity.TaskAttempt != nil {
		kind = "task"
	}
	receipt := SafeBoundaryReceiptV1{ID: "boundary_fixture0001", Kind: kind, AcknowledgedAt: time.Now().UTC(), WorkID: f.identity.WorkID, WorkspaceEpoch: f.identity.WorkspaceEpoch, SandboxGeneration: f.identity.SandboxGeneration, TaskID: f.identity.TaskID, TaskAttempt: f.identity.TaskAttempt, Binding: f.binding}
	payload, err := json.Marshal(boundaryEnvelope{FormatVersion: 1, Action: action, Status: status, Receipt: receipt})
	return payload, nil, err
}

func seedFixtureSource(t *testing.T, store *state.Store, fixture continuityFixture, root string) {
	t.Helper()
	if err := store.PutContinuitySource(context.Background(), state.LocalContinuitySource{
		Report: fixture.SourceReport, Root: root, Instance: "worker", Lifecycle: "stopped",
		LifecycleRevision: 8, NoAdmittedExecution: true,
	}); err != nil {
		t.Fatal(err)
	}
}

// seedCoordinatorAuthority seeds one continuity fixture's source, managed
// project, instance directory, and managed service into an existing store.
func seedCoordinatorAuthority(t *testing.T, store *state.Store, fixture continuityFixture, root string) {
	t.Helper()
	seedFixtureSource(t, store, fixture, root)
	if err := os.MkdirAll(filepath.Join(root, ".warpmetal", "opencode", "instances", "worker"), 0o700); err != nil {
		t.Fatal(err)
	}
	serviceID := fixture.RegistrationManifest.Binding.ServiceRegistrationID
	generation := fixture.RegistrationManifest.Identity.SandboxGeneration
	attestation := "sha256:" + strings.Repeat("a", 64)
	if err := store.PutManagedProject(context.Background(), state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: "selection_continuity0001",
			ProjectID:      fixture.RegistrationManifest.Identity.ProjectID,
			WorkspaceEpoch: fixture.RegistrationManifest.Identity.WorkspaceEpoch,
			SandboxID:      fixture.RegistrationManifest.Identity.SandboxID, SandboxGeneration: generation,
			ServiceRegistrationID: &serviceID, Designation: "team_project", Label: "team_continuity0001",
			Availability: "available", RootAttestation: attestation, LastObservedAt: fixture.SourceReport.LastObservedAt,
		},
		Anchor: root, HostRoot: root, ContainerRoot: "/home/agent/projects/team_continuity0001", Phase: "ready",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutManagedServiceIntent(context.Background(), state.LocalManagedService{
		Manifest: model.ManagedServiceV1{
			FormatVersion: 1, DesiredState: "active", SessionMode: "lookup_only",
			Identity: model.ManagedServiceIdentityV1{
				ServerID: "srv_continuity0001", TeamID: "team_continuity0001", MemberID: "tmem_continuity0001",
				SandboxID: fixture.RegistrationManifest.Identity.SandboxID, SandboxGeneration: generation,
				ServiceRegistrationID: serviceID, ExpectedServiceGeneration: 3, Instance: "worker", Role: "worker",
			},
			Workspace: model.ManagedServiceWorkspaceV1{
				SelectionID:    "selection_continuity0001",
				ProjectID:      fixture.RegistrationManifest.Identity.ProjectID,
				WorkspaceEpoch: fixture.RegistrationManifest.Identity.WorkspaceEpoch,
				ScopeRevision:  2, Designation: "team_project", RootAttestation: attestation,
			},
		},
		Phase: "ready", ServiceGeneration: 3, ProcessInstance: "wmsup-worker-0003", Port: 18443,
	}); err != nil {
		t.Fatal(err)
	}
}

func fixtureCoordinator(t *testing.T, objects *fakeObjects, helper *fakeBoundaryHelper) (*Coordinator, *state.Store, model.Manifest) {
	t.Helper()
	fixture := readContinuityFixture(t)
	store := openContinuityStore(t)
	root := t.TempDir()
	seedCoordinatorAuthority(t, store, fixture, root)
	helper.identity, helper.binding = fixture.OperationManifest.Identity, fixture.OperationManifest.Binding
	registry := StateRegistry{Store: store, Now: func() time.Time { return fixture.SourceReport.LastObservedAt }}
	service := &Service{State: store, Objects: objects, Registry: registry}
	coordinator := &Coordinator{Store: store, Service: service, Helper: helper, Registry: registry, Now: func() time.Time { return fixture.SourceReport.LastObservedAt }}
	manifest := model.Manifest{ContinuityRegistrations: []model.ContinuityRegistrationV1{fixture.RegistrationManifest}, ContinuityOperations: []model.ContinuityOperationV1{fixture.OperationManifest}}
	return coordinator, store, manifest
}

type continuityFixture struct {
	SourceReport         model.ContinuitySourceReportV1 `json:"sourceReport"`
	RegistrationManifest model.ContinuityRegistrationV1 `json:"registrationManifest"`
	OperationManifest    model.ContinuityOperationV1    `json:"operationManifest"`
}

func TestCoordinatorPreservesVerifiedRegistrationReceiptAcrossSourceRefresh(t *testing.T) {
	fixture := readContinuityFixture(t)
	helper := &fakeBoundaryHelper{}
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{}, helper)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	first, err := store.ContinuityRegistration(context.Background(), fixture.RegistrationManifest.Binding.BindingID)
	if err != nil || first == nil {
		t.Fatalf("initial registration=%#v err=%v", first, err)
	}
	if first.ObservedStatus != "verified" || first.ReceiptDigest == "" {
		t.Fatalf("initial registration terminal receipt=%#v", first)
	}
	// A later observation of the same source tuple refreshes its timestamp.
	// Re-applying the unchanged manifest must not rewrite the verified
	// terminal receipt: the control plane rejects changed terminal receipts.
	refreshed := fixture.SourceReport
	refreshed.LastObservedAt = refreshed.LastObservedAt.Add(30 * time.Second)
	if err := store.PutContinuitySource(context.Background(), state.LocalContinuitySource{
		Report: refreshed, Root: t.TempDir(), Instance: "worker", Lifecycle: "stopped",
		LifecycleRevision: 8, NoAdmittedExecution: true,
	}); err != nil {
		t.Fatal(err)
	}
	coordinator.Now = func() time.Time { return refreshed.LastObservedAt }
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	second, err := store.ContinuityRegistration(context.Background(), fixture.RegistrationManifest.Binding.BindingID)
	if err != nil || second == nil {
		t.Fatalf("second registration=%#v err=%v", second, err)
	}
	if second.ObservedStatus != first.ObservedStatus || second.ReceiptDigest != first.ReceiptDigest {
		t.Fatalf("verified terminal receipt changed on re-apply: %#v -> %#v", first, second)
	}
}

func TestStateRegistryResolvesTaskBoundaryIdentityAgainstWorkFence(t *testing.T) {
	fixture := readContinuityFixture(t)
	helper := &fakeBoundaryHelper{}
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{}, helper)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	registry := StateRegistry{Store: store, Now: func() time.Time { return fixture.SourceReport.LastObservedAt }}
	identity := fixture.RegistrationManifest.Identity
	taskID := "task_boundary0001"
	attempt := int64(1)
	identity.TaskID = &taskID
	identity.TaskAttempt = &attempt
	workspace, err := registry.Resolve(context.Background(), identity)
	if err != nil {
		t.Fatalf("task-boundary identity did not resolve against the work fence: %v", err)
	}
	if workspace.Identity.TaskID == nil || *workspace.Identity.TaskID != taskID {
		t.Fatalf("resolved workspace lost the task boundary: %#v", workspace.Identity)
	}
}

func TestCoordinatorRecoversBoundaryMissingFromHelperRefusalDespiteExitError(t *testing.T) {
	fixture := readContinuityFixture(t)
	helper := &fakeBoundaryHelper{failAction: "acquire_boundary", failCount: 1}
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}, helper)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	barriers, err := store.ContinuityBarriers(context.Background())
	if err != nil || len(barriers) != 1 {
		t.Fatalf("barriers=%#v err=%v", barriers, err)
	}
	helper.refuseWithErrorAction = "reconcile_boundary"
	helper.refuseWithErrorCode = "boundary_missing"
	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatalf("recover with structured refusal error: %v", err)
	}
	barriers, err = store.ContinuityBarriers(context.Background())
	if err != nil || len(barriers) != 0 {
		t.Fatalf("boundary_missing refusal did not clear the barrier: %#v err=%v", barriers, err)
	}
}

func TestCoordinatorProvisionsExactContinuityRegistrationBeforeBoundary(t *testing.T) {
	fixture := readContinuityFixture(t)
	helper := &fakeBoundaryHelper{}
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}, helper)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	source, err := store.ContinuitySource(context.Background(), fixture.RegistrationManifest.Binding.RegisteredSourceID)
	if err != nil || source == nil {
		t.Fatalf("source=%#v err=%v", source, err)
	}
	path := filepath.Join(source.Root, ".warpmetal", "opencode", "instances", "worker", "continuity-registration.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("provisioned registration missing: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 14 || saved["workId"] != fixture.RegistrationManifest.Identity.WorkID ||
		saved["projectId"] != fixture.RegistrationManifest.Identity.ProjectID ||
		saved["workspaceEpoch"] != fixture.RegistrationManifest.Identity.WorkspaceEpoch ||
		saved["sandboxId"] != fixture.RegistrationManifest.Identity.SandboxID ||
		saved["expectedRevision"] != float64(fixture.RegistrationManifest.Identity.ExpectedRevision) ||
		saved["sandboxGeneration"] != float64(fixture.RegistrationManifest.Identity.SandboxGeneration) ||
		saved["instance"] != "worker" || saved["projectRoot"] != "/home/agent/projects/team_continuity0001" ||
		saved["backgroundWriterState"] != "idle" || saved["lastAcceptedExecutionId"] != nil ||
		saved["taskId"] != nil || saved["taskAttempt"] != nil {
		t.Fatalf("registration projection drifted: %#v", saved)
	}
	if info, err := os.Stat(path); err != nil || info.Mode()&0o077 != 0 {
		t.Fatalf("registration mode=%v err=%v", info, err)
	}
	_, _, reports, err := coordinator.Reports(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Status != "accepted" {
		t.Fatalf("operation after provisioning=%#v err=%v", reports, err)
	}
}

func projectionFilePath(source *state.LocalContinuitySource) string {
	return filepath.Join(source.Root, ".warpmetal", "opencode", "instances", "worker", "continuity-registration.json")
}

func projectionMetadata(info os.FileInfo) (uint32, uint32) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid, stat.Gid
	}
	return 0, 0
}

// An exact verified active registration with no continuity operation must
// naturally materialize its box-side projection, and an identical replay must
// be a true no-op.
func TestCoordinatorMaterializesVerifiedRegistrationProjectionWithoutOperation(t *testing.T) {
	fixture := readContinuityFixture(t)
	helper := &fakeBoundaryHelper{}
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{}, helper)
	manifest.ContinuityOperations = nil
	ctx := context.Background()
	source, err := store.ContinuitySource(ctx, fixture.RegistrationManifest.Binding.RegisteredSourceID)
	if err != nil || source == nil {
		t.Fatalf("source=%#v err=%v", source, err)
	}
	projectionPath := projectionFilePath(source)
	if _, err := os.Lstat(projectionPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("projection unexpectedly present before apply: %v", err)
	}
	if err := coordinator.Apply(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(projectionPath)
	if err != nil {
		t.Fatalf("verified registration projection missing: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	bindingPayload, err := json.Marshal(fixture.RegistrationManifest.Binding)
	if err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := json.Unmarshal(bindingPayload, &binding); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 14 || saved["workId"] != fixture.RegistrationManifest.Identity.WorkID ||
		saved["projectId"] != fixture.RegistrationManifest.Identity.ProjectID ||
		saved["workspaceEpoch"] != fixture.RegistrationManifest.Identity.WorkspaceEpoch ||
		saved["sandboxId"] != fixture.RegistrationManifest.Identity.SandboxID ||
		saved["sandboxGeneration"] != float64(fixture.RegistrationManifest.Identity.SandboxGeneration) ||
		saved["expectedRevision"] != float64(fixture.RegistrationManifest.Identity.ExpectedRevision) ||
		saved["instance"] != "worker" || saved["projectRoot"] != "/home/agent/projects/team_continuity0001" ||
		saved["backgroundWriterState"] != "idle" || saved["lastAcceptedExecutionId"] != nil ||
		saved["taskId"] != nil || saved["taskAttempt"] != nil || !reflect.DeepEqual(saved["binding"], binding) {
		t.Fatalf("registration-only projection drifted: %#v", saved)
	}
	if info, err := os.Stat(projectionPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("registration projection mode=%v err=%v", info, err)
	}
	if len(helper.actions) != 0 {
		t.Fatalf("registration-only apply invoked the helper: %v", helper.actions)
	}
	beforeInfo, err := os.Stat(projectionPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeUID, beforeGID := projectionMetadata(beforeInfo)
	registrationBefore, err := store.ContinuityRegistration(ctx, fixture.RegistrationManifest.Binding.BindingID)
	if err != nil || registrationBefore == nil {
		t.Fatalf("registration=%#v err=%v", registrationBefore, err)
	}
	sourceBefore, err := store.ContinuitySource(ctx, fixture.RegistrationManifest.Binding.RegisteredSourceID)
	if err != nil || sourceBefore == nil {
		t.Fatalf("source=%#v err=%v", sourceBefore, err)
	}
	if err := coordinator.Apply(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	afterRaw, err := os.ReadFile(projectionPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, afterRaw) {
		t.Fatalf("identical replay churned projection bytes: %q -> %q", raw, afterRaw)
	}
	afterInfo, err := os.Stat(projectionPath)
	if err != nil {
		t.Fatal(err)
	}
	afterUID, afterGID := projectionMetadata(afterInfo)
	if !afterInfo.ModTime().Equal(beforeInfo.ModTime()) || afterInfo.Mode() != beforeInfo.Mode() ||
		afterUID != beforeUID || afterGID != beforeGID {
		t.Fatalf("identical replay churned projection metadata: %#v -> %#v", beforeInfo, afterInfo)
	}
	registrationAfter, err := store.ContinuityRegistration(ctx, fixture.RegistrationManifest.Binding.BindingID)
	if err != nil || registrationAfter == nil {
		t.Fatalf("registration=%#v err=%v", registrationAfter, err)
	}
	sourceAfter, err := store.ContinuitySource(ctx, fixture.RegistrationManifest.Binding.RegisteredSourceID)
	if err != nil || sourceAfter == nil {
		t.Fatalf("source=%#v err=%v", sourceAfter, err)
	}
	if !reflect.DeepEqual(registrationBefore, registrationAfter) || !reflect.DeepEqual(sourceBefore, sourceAfter) {
		t.Fatalf("identical replay changed registration or source rows")
	}
	if len(helper.actions) != 0 {
		t.Fatalf("identical replay invoked the helper: %v", helper.actions)
	}
	if _, err := os.Lstat(projectionPath + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identical replay left a staging file: %v", err)
	}
}

// Stale or mismatched source authority must never create or refresh a
// projection for an otherwise verified terminal registration.
func TestCoordinatorNeverProjectsStaleOrMismatchedVerifiedRegistration(t *testing.T) {
	fixture := readContinuityFixture(t)
	cases := map[string]func(*model.ContinuitySourceReportV1){
		"stale": func(report *model.ContinuitySourceReportV1) {
			report.LastObservedAt = report.LastObservedAt.Add(-121 * time.Second)
		},
		"mismatched": func(report *model.ContinuitySourceReportV1) {
			report.NativeSessionID = "session_changed0001"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			helper := &fakeBoundaryHelper{}
			coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{}, helper)
			manifest.ContinuityOperations = nil
			ctx := context.Background()
			if err := store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
				Manifest: fixture.RegistrationManifest, ObservedStatus: "verified",
				ServiceGeneration: fixture.SourceReport.ServiceGeneration,
				ReceiptDigest:     "sha256:" + strings.Repeat("b", 64),
			}); err != nil {
				t.Fatal(err)
			}
			current, err := store.ContinuitySource(ctx, fixture.RegistrationManifest.Binding.RegisteredSourceID)
			if err != nil || current == nil {
				t.Fatalf("source=%#v err=%v", current, err)
			}
			report := fixture.SourceReport
			mutate(&report)
			if err := store.PutContinuitySource(ctx, state.LocalContinuitySource{
				Report: report, Root: current.Root, Instance: "worker", Lifecycle: "stopped",
				LifecycleRevision: 8, NoAdmittedExecution: true,
			}); err != nil {
				t.Fatal(err)
			}
			if err := coordinator.Apply(ctx, manifest); err != nil {
				t.Fatalf("stale/mismatched verified registration aborted apply: %v", err)
			}
			if _, err := os.Lstat(projectionFilePath(current)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stale/mismatched registration projected: %v", err)
			}
			if len(helper.actions) != 0 {
				t.Fatalf("stale/mismatched registration invoked the helper: %v", helper.actions)
			}
		})
	}
}

func TestCoordinatorNeverProjectsRevokedRegistration(t *testing.T) {
	fixture := readContinuityFixture(t)
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{}, &fakeBoundaryHelper{})
	manifest.ContinuityOperations = nil
	manifest.ContinuityRegistrations[0].DesiredState = "revoked"
	manifest.ContinuityRegistrations[0].ContinuityEnabled = false
	ctx := context.Background()
	if err := coordinator.Apply(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	source, err := store.ContinuitySource(ctx, fixture.RegistrationManifest.Binding.RegisteredSourceID)
	if err != nil || source == nil {
		t.Fatalf("source=%#v err=%v", source, err)
	}
	if _, err := os.Lstat(projectionFilePath(source)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoked registration projected: %v", err)
	}
	registration, err := store.ContinuityRegistration(ctx, fixture.RegistrationManifest.Binding.BindingID)
	if err != nil || registration == nil || registration.ObservedStatus != "revoked" {
		t.Fatalf("revoked registration=%#v err=%v", registration, err)
	}
}

// The operation path must still write the exact operation task pair immediately
// before a boundary action, even though a registration-only projection normally
// carries the null registration pair.
func TestCoordinatorWritesOperationTaskPairProjectionBeforeBoundary(t *testing.T) {
	fixture := readContinuityFixture(t)
	taskID := "task_boundary035"
	attempt := int64(2)
	operation := fixture.OperationManifest
	operation.Identity.TaskID, operation.Identity.TaskAttempt = &taskID, &attempt
	operation.BoundaryKind = "task"
	helper := &fakeBoundaryHelper{}
	objects := &fakeObjects{capture: testCapture(operation.Identity)}
	coordinator, store, manifest := fixtureCoordinator(t, objects, helper)
	coordinator.Service.Engine = &fakeCaptureEngine{states: []containers.ContainerState{
		containers.ContainerRunning, containers.ContainerPaused, containers.ContainerPaused,
	}}
	ctx := context.Background()
	source, err := store.ContinuitySource(ctx, fixture.RegistrationManifest.Binding.RegisteredSourceID)
	if err != nil || source == nil {
		t.Fatalf("source=%#v err=%v", source, err)
	}
	source.Lifecycle = "running"
	source.NoAdmittedExecution = false
	if err := store.PutContinuitySource(ctx, *source); err != nil {
		t.Fatal(err)
	}
	manifest.ContinuityOperations = []model.ContinuityOperationV1{operation}
	helper.identity = operation.Identity
	objects.capture = testCapture(operation.Identity)
	projectionPath := projectionFilePath(source)
	var observed map[string]any
	helper.onAction = func(action string) {
		if action != "acquire_boundary" {
			return
		}
		raw, err := os.ReadFile(projectionPath)
		if err != nil {
			t.Fatalf("projection missing at boundary: %v", err)
		}
		var saved map[string]any
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		observed = saved
	}
	if err := coordinator.Apply(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if observed == nil || observed["taskId"] != taskID || observed["taskAttempt"] != float64(attempt) {
		t.Fatalf("boundary projection task pair=%#v", observed)
	}
	_, _, reports, err := coordinator.Reports(ctx)
	if err != nil || len(reports) != 1 || reports[0].Status != "accepted" {
		code := ""
		if len(reports) == 1 && reports[0].LastError != nil {
			code = reports[0].LastError.Code
		}
		t.Fatalf("task boundary operation report status=%s code=%s err=%v", func() string {
			if len(reports) == 1 {
				return reports[0].Status
			}
			return "missing"
		}(), code, err)
	}
}

type coordinatorProjectionJourney struct {
	store                *state.Store
	path                 string
	mapped               model.ContinuityRegistrationV1
	manager              model.ContinuityRegistrationV1
	coordinator          *Coordinator
	helper               *fakeBoundaryHelper
	controller           *S2Controller
	runtime              *fakeS2BHandoffRuntime
	handoffOperationID   string
	targetServiceID      string
	targetServiceReport  model.ManagedServiceReportV1
	mappedProjectionPath string
	existingProjection   []byte
}

type coordinatorProjectionOptions struct {
	corruptPreparationReport []byte
	mutateRegistration       func(*model.ContinuityRegistrationV1)
	mutateRegistrationSource func(*state.LocalContinuitySource)
}

// seedCoordinatorProjectionJourney builds a real store with one exact ready
// mapped handoff-target registration (whose primary service project differs
// from the mapping target, like the live reviewer box) and one valid unmapped
// manager-style registration with no projection yet.
func seedCoordinatorProjectionJourney(t *testing.T, options coordinatorProjectionOptions) coordinatorProjectionJourney {
	t.Helper()
	ctx := context.Background()
	authority := readContinuityFixture(t)
	handoff := readS2BControllerFixture(t)
	ready := seedS2BReadyHandoff(t)
	store := ready.store
	now := time.Date(2026, 9, 29, 4, 0, 0, 0, time.UTC)
	ready.advance(now)
	record, err := store.ContinuationHandoffPreparation(ctx, ready.manifest.OperationID)
	if err != nil || record == nil || record.Report == nil || record.Report.Session == nil || record.Report.TargetWorkspace == nil {
		t.Fatalf("ready handoff preparation = %#v, %v", record, err)
	}
	mapped := handoff.TargetRegistration
	mapped.Identity.WorkID = record.Manifest.TargetWorkID
	mapped.Identity.ProjectID = record.Report.TargetWorkspace.ProjectID
	mapped.Identity.WorkspaceEpoch = record.Report.TargetWorkspace.WorkspaceEpoch
	mapped.Identity.SandboxID = record.Manifest.TargetPolicy.SandboxID
	mapped.Identity.SandboxGeneration = record.Manifest.TargetPolicy.SandboxGeneration
	mapped.Identity.TaskID, mapped.Identity.TaskAttempt = nil, nil
	mapped.ScopeRevision = record.Report.TargetWorkspace.ScopeRevision
	mapped.Binding.RegisteredSourceID = record.Report.Session.RegisteredSourceID
	mapped.Binding.ServiceRegistrationID = record.Manifest.TargetPolicy.ServiceRegistrationID
	mapped.Binding.NativeSessionID = record.Report.Session.NativeSessionID
	mapped.Binding.NativeProjectID = record.Report.Session.NativeProjectID
	mapped.Binding.NativeLocationDigest = record.Report.Session.NativeLocationDigest
	mapped.DesiredState, mapped.ContinuityEnabled = "active", true
	if options.mutateRegistration != nil {
		options.mutateRegistration(&mapped)
	}
	mappedSource, err := store.ContinuitySource(ctx, mapped.Binding.RegisteredSourceID)
	if err != nil || mappedSource == nil {
		t.Fatalf("mapped source = %#v, %v", mappedSource, err)
	}
	mappedSource.Report.Availability = "available"
	mappedSource.Report.Reason = nil
	mappedSource.Report.LastObservedAt = now
	if options.mutateRegistrationSource != nil {
		options.mutateRegistrationSource(mappedSource)
	}
	if err := store.PutContinuitySource(ctx, *mappedSource); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
		Manifest: mapped, ObservedStatus: "verified",
		ServiceGeneration: record.Manifest.TargetPolicy.ServiceGeneration,
		ReceiptDigest:     "sha256:" + strings.Repeat("d", 64),
	}); err != nil {
		t.Fatal(err)
	}
	if options.corruptPreparationReport != nil {
		db, err := sql.Open("sqlite", ready.path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.ExecContext(ctx,
			`UPDATE continuation_handoff_preparations SET report_json=? WHERE operation_id=?`,
			options.corruptPreparationReport, record.Manifest.OperationID); err != nil {
			t.Fatal(err)
		}
	}
	targetService, err := store.ManagedService(ctx, record.Manifest.TargetPolicy.ServiceRegistrationID)
	if err != nil || targetService == nil {
		t.Fatalf("target service = %#v, %v", targetService, err)
	}
	primary, err := store.ManagedProject(ctx, targetService.Manifest.Workspace.SelectionID)
	if err != nil || primary == nil || primary.Anchor == "" {
		t.Fatalf("primary target project = %#v, %v", primary, err)
	}
	mappedProjectionPath := filepath.Join(primary.Anchor, ".warpmetal", "opencode", "instances",
		targetService.Manifest.Identity.Instance, "continuity-registration.json")
	if err := os.MkdirAll(filepath.Dir(mappedProjectionPath), 0o700); err != nil {
		t.Fatal(err)
	}
	existingProjection := []byte("{\"formatVersion\":1,\"existing\":\"handoff-target-projection\"}\n")
	if err := os.WriteFile(mappedProjectionPath, existingProjection, 0o600); err != nil {
		t.Fatal(err)
	}
	seedCoordinatorAuthority(t, store, authority, t.TempDir())
	managerSource, err := store.ContinuitySource(ctx, authority.RegistrationManifest.Binding.RegisteredSourceID)
	if err != nil || managerSource == nil {
		t.Fatalf("manager source = %#v, %v", managerSource, err)
	}
	managerSource.Report.LastObservedAt = now
	if err := store.PutContinuitySource(ctx, *managerSource); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
		Manifest: authority.RegistrationManifest, ObservedStatus: "verified",
		ServiceGeneration: authority.SourceReport.ServiceGeneration,
		ReceiptDigest:     "sha256:" + strings.Repeat("e", 64),
	}); err != nil {
		t.Fatal(err)
	}
	registry := StateRegistry{Store: store, Now: func() time.Time { return now }}
	helper := &fakeBoundaryHelper{}
	coordinator := &Coordinator{
		Store: store, Service: &Service{State: store, Objects: &fakeObjects{}, Registry: registry},
		Helper: helper, Registry: registry, Now: func() time.Time { return now },
	}
	return coordinatorProjectionJourney{
		store: store, path: ready.path, mapped: mapped, manager: authority.RegistrationManifest,
		coordinator: coordinator, helper: helper, controller: ready.controller, runtime: ready.runtime,
		handoffOperationID: record.Manifest.OperationID, targetServiceID: record.Manifest.TargetPolicy.ServiceRegistrationID,
		targetServiceReport:  targetService.Report,
		mappedProjectionPath: mappedProjectionPath, existingProjection: existingProjection,
	}
}

// assertRegistrationProjection proves a ready box-side projection carries the
// exact work/binding tuple with the null registration task pair.
func assertRegistrationProjection(t *testing.T, store *state.Store, registration model.ContinuityRegistrationV1) {
	t.Helper()
	source, err := store.ContinuitySource(context.Background(), registration.Binding.RegisteredSourceID)
	if err != nil || source == nil {
		t.Fatalf("registration source = %#v, %v", source, err)
	}
	raw, err := os.ReadFile(projectionFilePath(source))
	if err != nil {
		t.Fatalf("registration projection missing: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	bindingPayload, err := json.Marshal(registration.Binding)
	if err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := json.Unmarshal(bindingPayload, &binding); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 14 || saved["workId"] != registration.Identity.WorkID ||
		saved["projectId"] != registration.Identity.ProjectID ||
		saved["workspaceEpoch"] != registration.Identity.WorkspaceEpoch ||
		saved["sandboxId"] != registration.Identity.SandboxID ||
		saved["sandboxGeneration"] != float64(registration.Identity.SandboxGeneration) ||
		saved["expectedRevision"] != float64(registration.Identity.ExpectedRevision) ||
		saved["taskId"] != nil || saved["taskAttempt"] != nil || !reflect.DeepEqual(saved["binding"], binding) {
		t.Fatalf("registration projection drifted: %#v", saved)
	}
}

func TestCoordinatorSkipsExactMappedHandoffRegistrationProjectionRepair(t *testing.T) {
	journey := seedCoordinatorProjectionJourney(t, coordinatorProjectionOptions{})
	ctx := context.Background()
	beforeProjection, err := os.ReadFile(journey.mappedProjectionPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(journey.mappedProjectionPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeReceipt, err := journey.store.ContinuityRegistration(ctx, journey.mapped.Binding.BindingID)
	if err != nil || beforeReceipt == nil {
		t.Fatalf("mapped registration = %#v, %v", beforeReceipt, err)
	}
	manifest := model.Manifest{ContinuityRegistrations: []model.ContinuityRegistrationV1{journey.mapped, journey.manager}}
	if err := journey.coordinator.Apply(ctx, manifest); err != nil {
		t.Fatalf("exact mapped handoff registration wedged the projection repair: %v", err)
	}
	afterProjection, err := os.ReadFile(journey.mappedProjectionPath)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(journey.mappedProjectionPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeProjection, afterProjection) || !bytes.Equal(afterProjection, journey.existingProjection) ||
		!afterInfo.ModTime().Equal(beforeInfo.ModTime()) || afterInfo.Mode() != beforeInfo.Mode() {
		t.Fatalf("exact mapped handoff projection changed: %q -> %q", beforeProjection, afterProjection)
	}
	afterReceipt, err := journey.store.ContinuityRegistration(ctx, journey.mapped.Binding.BindingID)
	if err != nil || afterReceipt == nil {
		t.Fatalf("mapped registration = %#v, %v", afterReceipt, err)
	}
	if !reflect.DeepEqual(beforeReceipt, afterReceipt) {
		t.Fatalf("mapped registration receipt changed: %#v -> %#v", beforeReceipt, afterReceipt)
	}
	managerSource, err := journey.store.ContinuitySource(ctx, journey.manager.Binding.RegisteredSourceID)
	if err != nil || managerSource == nil {
		t.Fatalf("manager source = %#v, %v", managerSource, err)
	}
	raw, err := os.ReadFile(projectionFilePath(managerSource))
	if err != nil {
		t.Fatalf("unmapped manager registration projection missing: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	bindingPayload, err := json.Marshal(journey.manager.Binding)
	if err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := json.Unmarshal(bindingPayload, &binding); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 14 || saved["workId"] != journey.manager.Identity.WorkID ||
		saved["projectId"] != journey.manager.Identity.ProjectID ||
		saved["workspaceEpoch"] != journey.manager.Identity.WorkspaceEpoch ||
		saved["sandboxId"] != journey.manager.Identity.SandboxID ||
		saved["sandboxGeneration"] != float64(journey.manager.Identity.SandboxGeneration) ||
		saved["expectedRevision"] != float64(journey.manager.Identity.ExpectedRevision) ||
		saved["instance"] != "worker" || saved["projectRoot"] != "/home/agent/projects/team_continuity0001" ||
		saved["taskId"] != nil || saved["taskAttempt"] != nil || !reflect.DeepEqual(saved["binding"], binding) {
		t.Fatalf("unmapped manager projection drifted: %#v", saved)
	}
	if len(journey.helper.actions) != 0 {
		t.Fatalf("projection repair invoked the helper: %v", journey.helper.actions)
	}
}

func TestCoordinatorRejectsInexactMappedHandoffRegistration(t *testing.T) {
	cases := map[string]coordinatorProjectionOptions{
		"non-ready preparation": {
			corruptPreparationReport: []byte(`{"formatVersion":1,"action":"prepare_handoff","status":"failed"}`),
		},
		"partial workspace": {
			mutateRegistration: func(registration *model.ContinuityRegistrationV1) {
				registration.Identity.WorkspaceEpoch += "_alt"
			},
			mutateRegistrationSource: func(source *state.LocalContinuitySource) {
				source.Report.WorkspaceEpoch += "_alt"
			},
		},
		"partial scope": {
			mutateRegistration:       func(registration *model.ContinuityRegistrationV1) { registration.ScopeRevision++ },
			mutateRegistrationSource: func(source *state.LocalContinuitySource) { source.Report.ScopeRevision++ },
		},
		"identity mismatch": {
			mutateRegistration: func(registration *model.ContinuityRegistrationV1) { registration.Identity.WorkID += "_alt" },
		},
		"binding mismatch": {
			mutateRegistration: func(registration *model.ContinuityRegistrationV1) {
				registration.Binding.NativeSessionID += "_alt"
			},
			mutateRegistrationSource: func(source *state.LocalContinuitySource) {
				source.Report.NativeSessionID += "_alt"
			},
		},
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			journey := seedCoordinatorProjectionJourney(t, options)
			ctx := context.Background()
			before, err := os.ReadFile(journey.mappedProjectionPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest := model.Manifest{ContinuityRegistrations: []model.ContinuityRegistrationV1{journey.mapped}}
			err = journey.coordinator.Apply(ctx, manifest)
			if err == nil || !strings.Contains(err.Error(), "continuity registration authority changed") {
				t.Fatalf("inexact mapped handoff registration error = %v", err)
			}
			after, err := os.ReadFile(journey.mappedProjectionPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("inexact mapped handoff registration changed its projection: %q -> %q", before, after)
			}
			if len(journey.helper.actions) != 0 {
				t.Fatalf("inexact mapped handoff registration invoked the helper: %v", journey.helper.actions)
			}
		})
	}
}

// The live deadlock shape: the ready preparation's exact target service row is
// transiently starting. The recovery step must defer so the same pass reaches
// the ordinary apply, and the next natural cycle completes the preparation.
func TestCoordinatorDefersStartingTargetServiceHandoffRecovery(t *testing.T) {
	journey := seedCoordinatorProjectionJourney(t, coordinatorProjectionOptions{})
	ctx := context.Background()
	if err := journey.store.UpdateManagedService(ctx, journey.targetServiceID, "starting", &journey.targetServiceReport, ""); err != nil {
		t.Fatal(err)
	}
	before, err := journey.store.ContinuationHandoffPreparation(ctx, journey.handoffOperationID)
	if err != nil || before == nil || before.Report == nil {
		t.Fatalf("ready preparation = %#v, %v", before, err)
	}
	if err := journey.controller.RecoverHandoffs(ctx); err != nil {
		t.Fatalf("starting target service aborted the handoff recovery step: %v", err)
	}
	manifest := model.Manifest{ContinuityRegistrations: []model.ContinuityRegistrationV1{journey.mapped, journey.manager}}
	if err := journey.coordinator.Apply(ctx, manifest); err != nil {
		t.Fatalf("same pass did not reach the ordinary registration apply: %v", err)
	}
	after, err := journey.store.ContinuationHandoffPreparation(ctx, journey.handoffOperationID)
	if err != nil || after == nil {
		t.Fatalf("preparation = %#v, %v", after, err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("deferred preparation changed: %#v -> %#v", before, after)
	}
	if !reflect.DeepEqual(journey.runtime.actions, []string{string(containers.ManagedSupervisorStatus)}) ||
		journey.runtime.nativeCreateCount != 1 {
		t.Fatalf("deferred pass actions = %v creates=%d", journey.runtime.actions, journey.runtime.nativeCreateCount)
	}
	if len(journey.helper.actions) != 0 {
		t.Fatalf("deferred pass invoked the boundary helper: %v", journey.helper.actions)
	}
	assertRegistrationProjection(t, journey.store, journey.manager)
	// The ordinary service apply advances the phase; the next natural cycle
	// completes the retained preparation without recreation.
	if err := journey.store.UpdateManagedService(ctx, journey.targetServiceID, "ready", &journey.targetServiceReport, ""); err != nil {
		t.Fatal(err)
	}
	if err := journey.controller.RecoverHandoffs(ctx); err != nil {
		t.Fatalf("recovered target service did not complete the retained handoff: %v", err)
	}
	final, err := journey.store.ContinuationHandoffPreparation(ctx, journey.handoffOperationID)
	if err != nil || final == nil {
		t.Fatalf("preparation = %#v, %v", final, err)
	}
	if !reflect.DeepEqual(before, final) {
		t.Fatalf("completed preparation drifted: %#v -> %#v", before, final)
	}
	records, err := journey.store.ContinuationHandoffPreparations(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("retained preparation was recreated: %#v, %v", records, err)
	}
	if !reflect.DeepEqual(journey.runtime.actions, []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus),
		string(containers.ManagedSupervisorStatus), "reconcile_handoff",
	}) || journey.runtime.nativeCreateCount != 1 {
		t.Fatalf("completed recovery actions = %v creates=%d", journey.runtime.actions, journey.runtime.nativeCreateCount)
	}
	assertRegistrationProjection(t, journey.store, journey.manager)
}

// Only the transient starting phase with an otherwise exact tuple may defer.
func TestCoordinatorKeepsNonStartingTargetServiceFailuresFatal(t *testing.T) {
	cases := map[string]struct {
		phase   string
		missing bool
		mutate  func(*model.ManagedServiceReportV1)
	}{
		"failed phase": {phase: "failed"},
		"missing service": {
			missing: true,
		},
		"starting authority mismatch": {
			phase: "starting",
			mutate: func(report *model.ManagedServiceReportV1) {
				report.InstructionDigest = "sha256:" + strings.Repeat("f", 64)
			},
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			journey := seedCoordinatorProjectionJourney(t, coordinatorProjectionOptions{})
			ctx := context.Background()
			report := journey.targetServiceReport
			if testCase.mutate != nil {
				testCase.mutate(&report)
			}
			if testCase.missing {
				db, err := sql.Open("sqlite", journey.path)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err := db.ExecContext(ctx,
					`DELETE FROM managed_services WHERE service_registration_id = ?`, journey.targetServiceID); err != nil {
					t.Fatal(err)
				}
			} else if err := journey.store.UpdateManagedService(ctx, journey.targetServiceID, testCase.phase, &report, ""); err != nil {
				t.Fatal(err)
			}
			err := journey.controller.RecoverHandoffs(ctx)
			if !errors.Is(err, ErrS2AuthorityChanged) {
				t.Fatalf("non-deferrable target service error = %v, want ErrS2AuthorityChanged", err)
			}
			if errors.Is(err, ErrTargetServiceNotReady) {
				t.Fatalf("non-deferrable target service returned the deferral sentinel: %v", err)
			}
			managerSource, err := journey.store.ContinuitySource(ctx, journey.manager.Binding.RegisteredSourceID)
			if err != nil || managerSource == nil {
				t.Fatalf("manager source = %#v, %v", managerSource, err)
			}
			if _, statErr := os.Lstat(projectionFilePath(managerSource)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("aborted pass repaired the manager projection: %v", statErr)
			}
		})
	}
}

// The live enrollment-retry wedge: the exact target service is failed with a
// supported enrollment proof. Recovery defers so the same pass can reach the
// enrollment retry in the ordinary service apply.
func assertCoordinatorDefersRetryableEnrollmentTarget(t *testing.T, code string) {
	t.Helper()
	journey := seedCoordinatorProjectionJourney(t, coordinatorProjectionOptions{})
	ctx := context.Background()
	failed := journey.targetServiceReport
	failed.ObservedState = "failed"
	failed.EnrollmentStatus = "failed"
	failed.WorkerStatus = "failed"
	failed.InstructionApplied = false
	failed.LastError = &model.ManagedServiceErrorV1{Code: code}
	if err := journey.store.UpdateManagedService(ctx, journey.targetServiceID, "failed", &failed, code); err != nil {
		t.Fatal(err)
	}
	before, err := journey.store.ContinuationHandoffPreparation(ctx, journey.handoffOperationID)
	if err != nil || before == nil || before.Report == nil {
		t.Fatalf("ready preparation = %#v, %v", before, err)
	}
	if err := journey.controller.RecoverHandoffs(ctx); err != nil {
		t.Fatalf("%s target service aborted the handoff recovery step: %v", code, err)
	}
	manifest := model.Manifest{ContinuityRegistrations: []model.ContinuityRegistrationV1{journey.mapped, journey.manager}}
	if err := journey.coordinator.Apply(ctx, manifest); err != nil {
		t.Fatalf("same pass did not reach the ordinary registration apply: %v", err)
	}
	after, err := journey.store.ContinuationHandoffPreparation(ctx, journey.handoffOperationID)
	if err != nil || after == nil {
		t.Fatalf("preparation = %#v, %v", after, err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("deferred preparation changed: %#v -> %#v", before, after)
	}
	if !reflect.DeepEqual(journey.runtime.actions, []string{string(containers.ManagedSupervisorStatus)}) ||
		journey.runtime.nativeCreateCount != 1 {
		t.Fatalf("deferred pass actions = %v creates=%d", journey.runtime.actions, journey.runtime.nativeCreateCount)
	}
	if len(journey.helper.actions) != 0 {
		t.Fatalf("deferred pass invoked the boundary helper: %v", journey.helper.actions)
	}
	assertRegistrationProjection(t, journey.store, journey.manager)
	// The enrollment retry advances the service; the next natural cycle
	// completes the retained preparation without recreation.
	if err := journey.store.UpdateManagedService(ctx, journey.targetServiceID, "ready", &journey.targetServiceReport, ""); err != nil {
		t.Fatal(err)
	}
	if err := journey.controller.RecoverHandoffs(ctx); err != nil {
		t.Fatalf("retried enrollment service did not complete the retained handoff: %v", err)
	}
	final, err := journey.store.ContinuationHandoffPreparation(ctx, journey.handoffOperationID)
	if err != nil || final == nil {
		t.Fatalf("preparation = %#v, %v", final, err)
	}
	if !reflect.DeepEqual(before, final) {
		t.Fatalf("completed preparation drifted: %#v -> %#v", before, final)
	}
	records, err := journey.store.ContinuationHandoffPreparations(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("retained preparation was recreated: %#v, %v", records, err)
	}
	if !reflect.DeepEqual(journey.runtime.actions, []string{
		string(containers.ManagedSupervisorStatus), string(containers.ManagedSupervisorStatus),
		string(containers.ManagedSupervisorStatus), "reconcile_handoff",
	}) || journey.runtime.nativeCreateCount != 1 {
		t.Fatalf("completed recovery actions = %v creates=%d", journey.runtime.actions, journey.runtime.nativeCreateCount)
	}
	assertRegistrationProjection(t, journey.store, journey.manager)
}

func TestCoordinatorDefersEnrollmentUnavailableTargetServiceHandoffRecovery(t *testing.T) {
	assertCoordinatorDefersRetryableEnrollmentTarget(t, "enrollment_unavailable")
}

// The live reviewer-handoff deadlock: the exact target service is failed with
// the durable/report enrollment_failed proof. Recovery defers so the same pass
// can reach the supported enrollment repair in the ordinary service apply.
func TestCoordinatorDefersEnrollmentFailedTargetServiceHandoffRecovery(t *testing.T) {
	assertCoordinatorDefersRetryableEnrollmentTarget(t, "enrollment_failed")
}

// Only the exact accepted enrollment proof may defer; every other failed
// code or partial/conflicting proof stays fail-closed.
func TestCoordinatorKeepsNonRetryableFailedTargetServiceFatal(t *testing.T) {
	enrollmentProof := func(report *model.ManagedServiceReportV1, code string) {
		report.ObservedState = "failed"
		report.LastError = &model.ManagedServiceErrorV1{Code: code}
	}
	cases := map[string]struct {
		durableCode  string
		phase        string
		mutateReport func(*model.ManagedServiceReportV1)
	}{
		"different failed code": {
			durableCode: "enrollment_rejected",
			mutateReport: func(report *model.ManagedServiceReportV1) {
				enrollmentProof(report, "enrollment_rejected")
			},
		},
		"durable proof without report proof": {
			durableCode: "enrollment_unavailable",
			mutateReport: func(report *model.ManagedServiceReportV1) {
				report.ObservedState = "failed"
				report.LastError = nil
			},
		},
		"report proof without durable code": {
			mutateReport: func(report *model.ManagedServiceReportV1) {
				enrollmentProof(report, "enrollment_unavailable")
			},
		},
		"stopped service": {
			phase: "stopped",
		},
		"enrollment with generation drift": {
			durableCode: "enrollment_unavailable",
			mutateReport: func(report *model.ManagedServiceReportV1) {
				enrollmentProof(report, "enrollment_unavailable")
				report.ServiceGeneration++
			},
		},
		"enrollment_failed with report mismatch": {
			durableCode: "enrollment_failed",
			mutateReport: func(report *model.ManagedServiceReportV1) {
				enrollmentProof(report, "enrollment_unavailable")
			},
		},
		"enrollment_failed with generation drift": {
			durableCode: "enrollment_failed",
			mutateReport: func(report *model.ManagedServiceReportV1) {
				enrollmentProof(report, "enrollment_failed")
				report.ServiceGeneration++
			},
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			journey := seedCoordinatorProjectionJourney(t, coordinatorProjectionOptions{})
			ctx := context.Background()
			report := journey.targetServiceReport
			if testCase.mutateReport != nil {
				testCase.mutateReport(&report)
			}
			phase := testCase.phase
			if phase == "" {
				phase = "failed"
			}
			if err := journey.store.UpdateManagedService(ctx, journey.targetServiceID, phase, &report, testCase.durableCode); err != nil {
				t.Fatal(err)
			}
			err := journey.controller.RecoverHandoffs(ctx)
			if !errors.Is(err, ErrS2AuthorityChanged) {
				t.Fatalf("non-retryable failed target service error = %v, want ErrS2AuthorityChanged", err)
			}
			if errors.Is(err, ErrTargetServiceNotReady) {
				t.Fatalf("non-retryable failed target service returned the deferral sentinel: %v", err)
			}
			managerSource, err := journey.store.ContinuitySource(ctx, journey.manager.Binding.RegisteredSourceID)
			if err != nil || managerSource == nil {
				t.Fatalf("manager source = %#v, %v", managerSource, err)
			}
			if _, statErr := os.Lstat(projectionFilePath(managerSource)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("aborted pass repaired the manager projection: %v", statErr)
			}
		})
	}
}

func TestCoordinatorFailsOperationWhenRegistrationProvisioningFails(t *testing.T) {
	fixture := readContinuityFixture(t)
	helper := &fakeBoundaryHelper{}
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}, helper)
	source, err := store.ContinuitySource(context.Background(), fixture.RegistrationManifest.Binding.RegisteredSourceID)
	if err != nil || source == nil {
		t.Fatalf("source=%#v err=%v", source, err)
	}
	if err := os.RemoveAll(filepath.Join(source.Root, ".warpmetal", "opencode", "instances", "worker")); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if len(helper.actions) != 0 {
		t.Fatalf("boundary helper ran without a provisioned registration: %v", helper.actions)
	}
	_, _, reports, err := coordinator.Reports(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Status != "failed" ||
		reports[0].LastError == nil || reports[0].LastError.Code != "registration_provision_failed" {
		t.Fatalf("provisioning failure report=%#v err=%v", reports, err)
	}
}

func TestCoordinatorReleasesExactOwnedBarrierAfterCaptureFailure(t *testing.T) {
	fixture := readContinuityFixture(t)
	corrupt := testCapture(fixture.OperationManifest.Identity)
	corrupt.Manifest.Identity.WorkspaceEpoch = "epoch_changed0001"
	helper := &fakeBoundaryHelper{}
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{capture: corrupt}, helper)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if len(helper.actions) != 2 || helper.actions[0] != "acquire_boundary" || helper.actions[1] != "release_boundary" {
		t.Fatalf("capture failure helper actions=%v", helper.actions)
	}
	if helper.operations[0] != manifest.ContinuityOperations[0].OperationID || helper.operations[1] != helper.operations[0] {
		t.Fatalf("release did not carry exact barrier owner: %v", helper.operations)
	}
	barriers, err := store.ContinuityBarriers(context.Background())
	if err != nil || len(barriers) != 0 {
		t.Fatalf("released failed capture barrier=%#v err=%v", barriers, err)
	}
	_, _, reports, err := coordinator.Reports(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Status != "failed" || reports[0].LastError == nil || reports[0].LastError.Code != "capture_failed" {
		t.Fatalf("capture failure report=%#v err=%v", reports, err)
	}
}

func TestCoordinatorRecoversUnknownReleaseWithoutDroppingSomeoneElsesBarrier(t *testing.T) {
	fixture := readContinuityFixture(t)
	helper := &fakeBoundaryHelper{failAction: "release_boundary", failCount: 1}
	coordinator, store, manifest := fixtureCoordinator(t, &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}, helper)
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	barriers, err := store.ContinuityBarriers(context.Background())
	if err != nil || len(barriers) != 1 {
		t.Fatalf("unknown release did not retain durable owner: %#v err=%v", barriers, err)
	}
	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	barriers, err = store.ContinuityBarriers(context.Background())
	if err != nil || len(barriers) != 0 {
		t.Fatalf("reconciled release retained barrier: %#v err=%v", barriers, err)
	}
	want := []string{"acquire_boundary", "release_boundary", "reconcile_boundary", "release_boundary"}
	if len(helper.actions) != len(want) {
		t.Fatalf("helper actions=%v want=%v", helper.actions, want)
	}
	for i := range want {
		if helper.actions[i] != want[i] || helper.operations[i] != manifest.ContinuityOperations[0].OperationID {
			t.Fatalf("helper call %d actions=%v owners=%v", i, helper.actions, helper.operations)
		}
	}

	// A reconcile response that cannot prove ownership must leave the durable
	// barrier in place and must not proceed to release it.
	secondHelper := &fakeBoundaryHelper{refuseAction: "reconcile_boundary", refuseCode: "boundary_owned"}
	second, secondStore, secondManifest := fixtureCoordinator(t, &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}, secondHelper)
	if err := secondStore.PutContinuityBarrier(context.Background(), secondManifest.ContinuityOperations[0].OperationID, barriersRequest(t, secondManifest.ContinuityOperations[0], "worker"), []byte{}); err != nil {
		t.Fatal(err)
	}
	if err := second.Recover(context.Background()); err == nil {
		t.Fatal("recovery released a barrier whose ownership was not acknowledged")
	}
	remaining, err := secondStore.ContinuityBarriers(context.Background())
	if err != nil || len(remaining) != 1 || len(secondHelper.actions) != 1 || secondHelper.actions[0] != "reconcile_boundary" {
		t.Fatalf("unproved owner recovery barriers=%#v actions=%v err=%v", remaining, secondHelper.actions, err)
	}
}

func barriersRequest(t *testing.T, operation model.ContinuityOperationV1, instance string) []byte {
	t.Helper()
	kind := operation.BoundaryKind
	payload, err := json.Marshal(map[string]any{"formatVersion": 1, "action": "acquire_boundary", "kind": kind, "operationId": operation.OperationID, "instance": instance, "workId": operation.Identity.WorkID, "projectId": operation.Identity.ProjectID, "sandboxId": operation.Identity.SandboxID, "workspaceEpoch": operation.Identity.WorkspaceEpoch, "sandboxGeneration": operation.Identity.SandboxGeneration, "taskId": operation.Identity.TaskID, "taskAttempt": operation.Identity.TaskAttempt, "expectedRevision": operation.Identity.ExpectedRevision, "binding": operation.Binding})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func readContinuityFixture(t *testing.T) continuityFixture {
	t.Helper()
	payload, err := os.ReadFile("../api/testdata/agent-continuity-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture continuityFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestCoordinatorConsumesFrozenShapePersistsBarrierAndReplaysAcceptedReport(t *testing.T) {
	now := time.Date(2026, 9, 27, 16, 0, 0, 0, time.UTC)
	fixture := readContinuityFixture(t)
	identity := fixture.OperationManifest.Identity
	binding := fixture.OperationManifest.Binding
	registration := fixture.RegistrationManifest
	operation := fixture.OperationManifest
	store := openContinuityStore(t)
	if err := store.PutContinuitySource(context.Background(), state.LocalContinuitySource{Report: fixture.SourceReport, Root: t.TempDir(), Instance: "worker", Lifecycle: "stopped", LifecycleRevision: 8, NoAdmittedExecution: true}); err != nil {
		t.Fatal(err)
	}
	helper := &fakeBoundaryHelper{identity: identity, binding: binding}
	objects := &fakeObjects{capture: testCapture(identity)}
	objects.captureHook = func() {
		barriers, err := store.ContinuityBarriers(context.Background())
		if err != nil || len(barriers) != 1 {
			t.Fatalf("capture ran before durable barrier ownership: %#v %v", barriers, err)
		}
	}
	registry := StateRegistry{Store: store, Now: func() time.Time { return now }}
	service := &Service{State: store, Objects: objects, Registry: registry}
	coordinator := &Coordinator{Store: store, Service: service, Helper: helper, Registry: registry, Now: func() time.Time { return now }}
	manifest := model.Manifest{ContinuityRegistrations: []model.ContinuityRegistrationV1{registration}, ContinuityOperations: []model.ContinuityOperationV1{operation}}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if got := helper.actions; len(got) != 2 || got[0] != "acquire_boundary" || got[1] != "release_boundary" {
		t.Fatalf("helper sequence=%v", got)
	}
	barriers, _ := store.ContinuityBarriers(context.Background())
	if len(barriers) != 0 {
		t.Fatalf("completed barrier retained: %#v", barriers)
	}
	_, registrations, reports, err := coordinator.Reports(context.Background())
	if err != nil || len(registrations) != 1 || registrations[0].ObservedStatus != "verified" || len(reports) != 1 || reports[0].Status != "accepted" {
		t.Fatalf("reports=%#v %#v %v", registrations, reports, err)
	}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if len(helper.actions) != 2 {
		t.Fatalf("accepted replay called helper again: %v", helper.actions)
	}
	conflict := manifest
	conflict.ContinuityOperations = append([]model.ContinuityOperationV1(nil), manifest.ContinuityOperations...)
	conflict.ContinuityOperations[0].RequestDigest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	if err := coordinator.Apply(context.Background(), conflict); err == nil {
		t.Fatal("conflicting request digest reused an accepted operation ID")
	}
}

func TestCoordinatorRefusesStaleSourceWithoutCallingHelper(t *testing.T) {
	now := time.Now().UTC()
	identity := testIdentity("epoch_source123", 4)
	binding := testBoundaryBinding()
	store := openContinuityStore(t)
	if err := store.PutContinuitySource(context.Background(), state.LocalContinuitySource{Report: model.ContinuitySourceReportV1{FormatVersion: 1, RegisteredSourceID: binding.RegisteredSourceID, ServiceRegistrationID: binding.ServiceRegistrationID, ServiceGeneration: 1, ProjectID: identity.ProjectID, SandboxID: identity.SandboxID, SandboxGeneration: identity.SandboxGeneration, WorkspaceEpoch: identity.WorkspaceEpoch, NativeSessionID: binding.NativeSessionID, NativeProjectID: binding.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest, ScopeRevision: 1, Availability: "available", LastObservedAt: now.Add(-121 * time.Second)}, Root: t.TempDir(), Instance: "worker", Lifecycle: "stopped", LifecycleRevision: 1}); err != nil {
		t.Fatal(err)
	}
	helper := &fakeBoundaryHelper{identity: identity, binding: binding}
	registry := StateRegistry{Store: store, Now: func() time.Time { return now }}
	service := &Service{State: store, Objects: &fakeObjects{}, Registry: registry}
	coordinator := &Coordinator{Store: store, Service: service, Helper: helper, Registry: registry, Now: func() time.Time { return now }}
	registration := model.ContinuityRegistrationV1{FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: 1, Identity: identity, Binding: binding}
	if err := coordinator.Apply(context.Background(), model.Manifest{ContinuityRegistrations: []model.ContinuityRegistrationV1{registration}}); err != nil {
		t.Fatal(err)
	}
	if len(helper.actions) != 0 {
		t.Fatalf("stale source invoked helper: %v", helper.actions)
	}
	_, registrations, _, _ := coordinator.Reports(context.Background())
	if registrations[0].ObservedStatus != "failed" {
		t.Fatalf("stale registration=%#v", registrations[0])
	}
}

func TestStateRegistryRejectsStaleBindingGenerationAndServiceRevision(t *testing.T) {
	fixture := readContinuityFixture(t)
	for name, mutate := range map[string]func(*model.ContinuitySourceReportV1){
		"binding":            func(report *model.ContinuitySourceReportV1) { report.NativeSessionID = "ses_changed0001" },
		"sandbox_generation": func(report *model.ContinuitySourceReportV1) { report.SandboxGeneration++ },
		"service_generation": func(report *model.ContinuitySourceReportV1) { report.ServiceGeneration++ },
		"future_observation": func(report *model.ContinuitySourceReportV1) {
			report.LastObservedAt = report.LastObservedAt.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := openContinuityStore(t)
			report := fixture.SourceReport
			mutate(&report)
			if err := store.PutContinuitySource(context.Background(), state.LocalContinuitySource{Report: report, Root: t.TempDir(), Instance: "worker", Lifecycle: "stopped", LifecycleRevision: 8, NoAdmittedExecution: true}); err != nil {
				t.Fatal(err)
			}
			if err := store.PutContinuityRegistration(context.Background(), state.LocalContinuityRegistration{Manifest: fixture.RegistrationManifest, ObservedStatus: "verified", ServiceGeneration: fixture.SourceReport.ServiceGeneration, ReceiptDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err != nil {
				t.Fatal(err)
			}
			registry := StateRegistry{Store: store, Now: func() time.Time { return fixture.SourceReport.LastObservedAt }}
			if _, err := registry.Resolve(context.Background(), fixture.OperationManifest.Identity); !errors.Is(err, ErrTargetChanged) {
				t.Fatalf("stale %s registry resolve=%v", name, err)
			}
		})
	}
}

func TestCoordinatorReleasesBoundaryWhenLifecycleFenceChangesAtAcquire(t *testing.T) {
	fixture := readContinuityFixture(t)
	objects := &fakeObjects{capture: testCapture(fixture.OperationManifest.Identity)}
	objects.captureHook = func() { t.Fatal("capture crossed a changed lifecycle fence") }
	helper := &fakeBoundaryHelper{}
	coordinator, store, manifest := fixtureCoordinator(t, objects, helper)
	helper.onAction = func(action string) {
		if action != "acquire_boundary" {
			return
		}
		if err := store.AdvanceContinuityLifecycle(context.Background(), fixture.SourceReport.RegisteredSourceID, 8, "running"); err != nil {
			t.Fatal(err)
		}
		if err := store.AdvanceContinuityLifecycle(context.Background(), fixture.SourceReport.RegisteredSourceID, 9, "stopped"); err != nil {
			t.Fatal(err)
		}
	}
	if err := coordinator.Apply(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if len(helper.actions) != 2 || helper.actions[0] != "acquire_boundary" || helper.actions[1] != "release_boundary" {
		t.Fatalf("lifecycle fence helper actions=%v", helper.actions)
	}
	_, _, reports, err := coordinator.Reports(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Status != "failed" || reports[0].LastError == nil || reports[0].LastError.Code != "target_changed" {
		t.Fatalf("lifecycle fence report=%#v err=%v", reports, err)
	}
	barriers, err := store.ContinuityBarriers(context.Background())
	if err != nil || len(barriers) != 0 {
		t.Fatalf("lifecycle fence barrier=%#v err=%v", barriers, err)
	}
}
