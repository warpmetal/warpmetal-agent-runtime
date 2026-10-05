package reconcile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// isolatedServiceControl dispatches the existing per-service fake to the exact
// service registration, so one manifest can carry two independently owned
// active services without a new control framework.
type isolatedServiceControl struct {
	byService map[string]*fakeManagedControl
}

func (control *isolatedServiceControl) ManagedServiceEndpoint() string {
	return "https://api.warpmetal.example"
}

func (control *isolatedServiceControl) InsightPolicies(context.Context) (model.InsightPolicyEnvelopeV1, error) {
	return model.InsightPolicyEnvelopeV1{}, nil
}

func (control *isolatedServiceControl) ManagedServiceEnrollment(ctx context.Context, serviceID string, request model.ManagedServiceFetchRequestV1) (model.ManagedServiceEnrollmentV1, error) {
	inner, ok := control.byService[serviceID]
	if !ok {
		return model.ManagedServiceEnrollmentV1{}, errors.New("unexpected managed service enrollment")
	}
	return inner.ManagedServiceEnrollment(ctx, serviceID, request)
}

func (control *isolatedServiceControl) ManagedServiceInstructions(ctx context.Context, serviceID string, request model.ManagedServiceFetchRequestV1) (model.ManagedServiceInstructionV1, error) {
	inner, ok := control.byService[serviceID]
	if !ok {
		return model.ManagedServiceInstructionV1{}, errors.New("unexpected managed service instruction fetch")
	}
	return inner.ManagedServiceInstructions(ctx, serviceID, request)
}

// isolatedServiceRuntime dispatches the existing per-sandbox fake by the exact
// sandbox id, so later independent services reach the genuine fixture
// supervisor/native/source path.
type isolatedServiceRuntime struct {
	bySandbox map[string]*fakeManagedRuntime
}

func (runtime *isolatedServiceRuntime) ExecManagedSupervisor(ctx context.Context, sandboxID string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	inner, ok := runtime.bySandbox[sandboxID]
	if !ok {
		return nil, nil, errors.New("unexpected managed sandbox supervisor call")
	}
	return inner.ExecManagedSupervisor(ctx, sandboxID, action, payload)
}

func (runtime *isolatedServiceRuntime) ExecManagedWorker(ctx context.Context, sandboxID string, action containers.ManagedWorkerAction, payload []byte) ([]byte, []byte, error) {
	inner, ok := runtime.bySandbox[sandboxID]
	if !ok {
		return nil, nil, errors.New("unexpected managed sandbox worker call")
	}
	return inner.ExecManagedWorker(ctx, sandboxID, action, payload)
}

// independentActiveServiceFixture derives a second, fully valid active service
// from the existing packaged producer fixture: distinct service/sandbox/member
// and setup identities plus its own catalog workspace, reusing the same
// seedReadyProfile and EnsureDefault helpers as the established journeys.
func independentActiveServiceFixture(t *testing.T, store *state.Store, now func() time.Time) producerFixture {
	t.Helper()
	fixture := loadProducerFixture(t)
	fixture.ServiceManifest.Identity.SandboxGeneration = 2
	fixture.SetupManifest.SandboxGeneration = 2
	fixture.InstructionRequest.SandboxGeneration = 2
	fixture.EnrollmentRequest.SandboxGeneration = 2
	fixture.ServiceManifest.Identity.ServiceRegistrationID = "service_independent_active_second"
	fixture.ServiceManifest.Identity.SandboxID = "sbx_independent_active_second"
	fixture.ServiceManifest.Identity.MemberID = "member_independent_active_second"
	fixture.ServiceManifest.Profile.SetupOperationID = "setup-independent-active-second"
	fixture.SetupManifest.ID = "setup-independent-active-second"
	fixture.SetupManifest.SandboxID = "sbx_independent_active_second"
	seedReadyProfile(t, store, fixture.SetupManifest)

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
	return fixture
}

// TestManagedServicesContinueIndependentActiveStartAfterEarlierActiveEnrollmentFailure
// is the reviewed ordinary critical isolation regression: when an earlier active
// service fails enrollment, a later independently owned active service must
// still reconcile through its genuine supervisor/native/source path while the
// earlier failed receipt remains, the fatal cause is returned and the global
// applied revision does not advance.
func TestManagedServicesContinueIndependentActiveStartAfterEarlierActiveEnrollmentFailure(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	ctx := context.Background()
	second := independentActiveServiceFixture(t, journey.store, journey.reconciler.Now)
	firstID := journey.fixture.ServiceManifest.Identity.ServiceRegistrationID
	secondID := second.ServiceManifest.Identity.ServiceRegistrationID

	firstControl := journey.reconciler.ManagedControl.(*fakeManagedControl)
	firstRuntime := journey.reconciler.ManagedRuntime.(*fakeManagedRuntime)
	secondControl := &fakeManagedControl{fixture: second}
	secondRuntime := &fakeManagedRuntime{store: journey.store, serviceID: secondID, fixture: second}
	journey.reconciler.ManagedControl = &isolatedServiceControl{byService: map[string]*fakeManagedControl{
		firstID: firstControl, secondID: secondControl,
	}}
	journey.reconciler.ManagedRuntime = &isolatedServiceRuntime{bySandbox: map[string]*fakeManagedRuntime{
		journey.fixture.ServiceManifest.Identity.SandboxID: firstRuntime,
		second.ServiceManifest.Identity.SandboxID:          secondRuntime,
	}}
	firstControl.enrollErr = errors.New("earlier active enrollment unavailable")
	journey.manifest.ManagedServices = append(journey.manifest.ManagedServices, second.ServiceManifest)
	journey.manifest.SetupOperations = append(journey.manifest.SetupOperations, second.SetupManifest)
	journey.manifest.Sandboxes = append(journey.manifest.Sandboxes, model.Sandbox{
		ID: second.ServiceManifest.Identity.SandboxID, Name: "independent-active-service",
		DesiredState: "running", Generation: 2, Lifetime: "persistent",
		Resources: model.Resources{CPUMillicores: 1000, MemoryMiB: 1024, WorkspaceDiskGiB: 2, PIDs: 64},
	})

	err := journey.reconciler.Reconcile(ctx, journey.manifest)
	if err == nil || !strings.Contains(err.Error(), "apply managed services: managed service "+firstID) {
		t.Fatalf("earlier active enrollment failure was not preserved as the fatal cause: %v", err)
	}
	if !strings.Contains(err.Error(), "earlier active enrollment unavailable") {
		t.Fatalf("earlier active failure cause was not preserved: %v", err)
	}
	if prior, after := journey.revisions(t); after != prior {
		t.Fatalf("fatal pass advanced the global applied revision %d -> %d", prior, after)
	}
	firstStored, err := journey.store.ManagedService(ctx, firstID)
	if err != nil || firstStored == nil || firstStored.Phase != "failed" ||
		firstStored.Report.LastError == nil || firstStored.Report.LastError.Code != "enrollment_unavailable" {
		t.Fatalf("earlier failed service receipt did not remain closed and exact: %#v %v", firstStored, err)
	}
	if firstRuntime.startCalls != 0 {
		t.Fatalf("failed earlier service was not left closed: startCalls=%d", firstRuntime.startCalls)
	}
	if len(secondControl.enrollments) != 1 {
		t.Fatalf("later independent active service never reached enrollment (enrollments=%d)", len(secondControl.enrollments))
	}
	if secondRuntime.startCalls < 1 {
		t.Fatalf("later independent active service never reached the supervisor start (startCalls=%d)", secondRuntime.startCalls)
	}
	registered := false
	for _, invocation := range secondRuntime.invocations {
		if invocation.action == string(containers.ManagedSupervisorRegisterSource) {
			registered = true
		}
	}
	if !registered {
		t.Fatalf("later independent active service never reached source registration: %#v", secondRuntime.invocations)
	}
	secondStored, err := journey.store.ManagedService(ctx, secondID)
	if err != nil || secondStored == nil || secondStored.Phase != "ready" {
		t.Fatalf("later independent active service did not reconcile to ready: %#v %v", secondStored, err)
	}
}
