package reconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type s2bWorkerFixture struct {
	ReviewerManifest   model.ContinuationHandoffManifestV1        `json:"reviewerManifest"`
	ReviewerReport     model.ContinuationHandoffReportV1          `json:"reviewerReport"`
	TargetRegistration model.ContinuityRegistrationV1             `json:"reviewerTargetRegistration"`
	ReleaseManifest    model.ContinuationHandoffReleaseManifestV1 `json:"handoffReleaseManifest"`
	ReleaseReport      model.ContinuationHandoffReleaseReportV1   `json:"handoffReleaseReport"`
}

type blockingHandoffWorkerRuntime struct {
	mu       sync.Mutex
	requests []map[string]any
	started  chan struct{}
}

func (r *blockingHandoffWorkerRuntime) ExecManagedSupervisor(context.Context, string, containers.ManagedSupervisorAction, []byte) ([]byte, []byte, error) {
	panic("targeted worker scheduling must not invoke the supervisor")
}

func (r *blockingHandoffWorkerRuntime) ExecManagedWorker(ctx context.Context, _ string, action containers.ManagedWorkerAction, payload []byte) ([]byte, []byte, error) {
	if action != containers.ManagedWorkerExecute {
		panic("targeted worker scheduling must only invoke execute")
	}
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	r.mu.Lock()
	r.requests = append(r.requests, request)
	if len(r.requests) == 1 {
		close(r.started)
	}
	r.mu.Unlock()
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func (r *blockingHandoffWorkerRuntime) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

func readS2BWorkerFixture(t *testing.T) s2bWorkerFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "api", "testdata", "agent-continuation-handoff-v1.backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture s2bWorkerFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestTargetedContinuationWorkerUsesMappedProjectAndOneServiceExecution(t *testing.T) {
	fixture := readS2BWorkerFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manifest := fixture.ReviewerManifest
	registration := fixture.TargetRegistration
	target := manifest.TargetPolicy
	if err := store.PutSandbox(context.Background(), state.LocalSandbox{
		ID: target.SandboxID, Name: "target", DesiredState: "running", ObservedState: "running",
		Generation: target.SandboxGeneration, ObservedGeneration: target.SandboxGeneration, Lifetime: "persistent",
	}); err != nil {
		t.Fatal(err)
	}
	serviceManifest := model.ManagedServiceV1{
		FormatVersion: 1, OperationID: "op_s2b_worker_service", ActionRevision: target.ServiceActionRevision,
		DesiredRevision: target.ServiceDesiredRevision, ConfigDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DesiredState: "active", SessionMode: "lookup_only",
		Identity: model.ManagedServiceIdentityV1{
			ServerID: "srv_p2c_statehandoffreviewer", TeamID: target.TeamID, MemberID: target.MemberID,
			SandboxID: target.SandboxID, SandboxGeneration: target.SandboxGeneration,
			ServiceRegistrationID: target.ServiceRegistrationID, ExpectedServiceGeneration: target.ServiceGeneration,
			Instance: "default", Role: target.Role,
		},
		Profile: model.ManagedServiceProfileV1{
			SetupOperationID: "setup_s2b_worker", ProfileID: target.ProfileID,
			ProfileRevision: target.ProfileRevision, ProfileDigest: target.ProfileDigest,
		},
		Instructions: model.ManagedServiceInstructionsV1{
			InstructionRevision: target.InstructionRevision, InstructionDigest: target.InstructionDigest,
		},
		Workspace: model.ManagedServiceWorkspaceV1{
			SelectionID: "selection_s2b_primary", ProjectID: "project_s2b_primary",
			WorkspaceEpoch: "epoch_s2b_primary", ScopeRevision: 1, Designation: "team_project",
			RootAttestation: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}
	serviceReport := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: serviceManifest.OperationID, ActionRevision: target.ServiceActionRevision,
		ObservedDesiredRevision: target.ServiceDesiredRevision, ConfigDigest: serviceManifest.ConfigDigest,
		ObservedState: "ready", Identity: serviceManifest.Identity, ServiceGeneration: target.ServiceGeneration,
		ProfileStatus: "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "ready",
		InstructionApplied: true, InstructionRevision: target.InstructionRevision,
		InstructionDigest: target.InstructionDigest,
		NativeRegistration: &model.ManagedNativeRegistrationV1{
			RegisteredSourceID: "source_s2b_primary", WorkspaceEpoch: "epoch_s2b_primary",
			NativeSessionID: "ses_s2b_primary", NativeProjectID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			NativeLocationDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
		ReceiptDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
	if err := store.PutManagedServiceIntent(context.Background(), state.LocalManagedService{
		Manifest: serviceManifest, Phase: "ready", ProcessInstance: "default", Port: 18443,
		CreationDispatched: true, ServiceGeneration: target.ServiceGeneration,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateManagedService(context.Background(), target.ServiceRegistrationID, "ready", &serviceReport, ""); err != nil {
		t.Fatal(err)
	}
	serviceID := target.ServiceRegistrationID
	mappedRoot := "/home/agent/projects/reviewer-target"
	if err := store.PutManagedProject(context.Background(), state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: fixture.ReviewerReport.TargetWorkspace.SelectionID,
			ProjectID: registration.Identity.ProjectID, WorkspaceEpoch: registration.Identity.WorkspaceEpoch,
			SandboxID: registration.Identity.SandboxID, SandboxGeneration: registration.Identity.SandboxGeneration,
			ServiceRegistrationID: &serviceID, Designation: "continuity-handoff", Label: "reviewer",
			Availability: "available", RootAttestation: fixture.ReviewerReport.TargetWorkspace.RootAttestation,
		},
		ServerID: serviceManifest.Identity.ServerID, TeamID: target.TeamID, MemberID: target.MemberID,
		HostRoot: "/host/workspaces/reviewer-target", ContainerRoot: mappedRoot, Phase: "ready",
		ScopeRevision: fixture.ReviewerReport.TargetWorkspace.ScopeRevision,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuityRegistration(context.Background(), state.LocalContinuityRegistration{
		Manifest: registration, ObservedStatus: "verified", ServiceGeneration: target.ServiceGeneration,
		ReceiptDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &blockingHandoffWorkerRuntime{started: make(chan struct{})}
	lifecycle, cancel := context.WithCancel(context.Background())
	defer cancel()
	reconciler := &Reconciler{Store: store, ManagedRuntime: runtime, ManagedExecutionContext: lifecycle}
	if err := reconciler.ScheduleContinuationHandoff(context.Background(), manifest.OperationID, manifest, registration); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runtime.started:
	case <-time.After(time.Second):
		t.Fatal("targeted worker did not start")
	}
	if err := reconciler.ScheduleContinuationHandoff(context.Background(), manifest.OperationID, manifest, registration); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	if runtime.count() != 1 {
		t.Fatalf("one service launched %d targeted workers", runtime.count())
	}
	runtime.mu.Lock()
	request := runtime.requests[0]
	runtime.mu.Unlock()
	if request["continuationOperationId"] != manifest.OperationID || request["projectPath"] != mappedRoot ||
		request["root"] != "/home/agent" {
		t.Fatalf("targeted worker request = %#v", request)
	}
}
