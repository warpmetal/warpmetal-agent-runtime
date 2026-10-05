package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// isolatedServiceControl dispatches the existing per-service fake to the exact
// service registration, so one manifest can carry two independently owned
// active services without a new control framework.
type isolatedServiceControl struct {
	byService map[string]*fakeManagedControl
	policies  model.InsightPolicyEnvelopeV1
}

func (control *isolatedServiceControl) ManagedServiceEndpoint() string {
	return "https://api.warpmetal.example"
}

func (control *isolatedServiceControl) InsightPolicies(context.Context) (model.InsightPolicyEnvelopeV1, error) {
	return control.policies, nil
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

// TestRetainedFailedStateRecoversWithEnabledMonitor is the retained failed-state
// (backward) recovery regression: it seeds the exact signed-44 persisted
// state (failed service row, native registration already overwritten, retained
// source stopped with availability available and Reason nil, exact tuple and
// session, fresh verified registration) and requires recovery under a fresh
// desired-active manifest. It is intentionally a seeded-state test, not a
// transient-injection test; TestTransientEnrollmentFailureRecoversWithEnabledMonitor
// below covers the real ready -> failure -> recovery transition.
func TestRetainedFailedStateRecoversWithEnabledMonitor(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	ctx := context.Background()
	second := independentActiveServiceFixture(t, journey.store, journey.reconciler.Now)
	first := journey.fixture.ServiceManifest
	firstID := first.Identity.ServiceRegistrationID
	secondID := second.ServiceManifest.Identity.ServiceRegistrationID

	firstControl := journey.reconciler.ManagedControl.(*fakeManagedControl)
	firstRuntime := journey.reconciler.ManagedRuntime.(*fakeManagedRuntime)
	secondControl := &fakeManagedControl{fixture: second}
	secondRuntime := &fakeManagedRuntime{store: journey.store, serviceID: secondID, fixture: second}
	journey.reconciler.ManagedControl = &isolatedServiceControl{byService: map[string]*fakeManagedControl{
		firstID: firstControl, secondID: secondControl,
	}}
	journey.reconciler.ManagedRuntime = &isolatedServiceRuntime{bySandbox: map[string]*fakeManagedRuntime{
		first.Identity.SandboxID:                  firstRuntime,
		second.ServiceManifest.Identity.SandboxID: secondRuntime,
	}}
	// Reuse the complete source-observation adapter so the actual probe sees the
	// exact retained tuple instead of a fixture-shaped mismatch.
	firstRuntime.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
		payload, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		// Delegate the original fake status behavior so managed capability
		// fields stay intact; the adapter only completes observation identity.
		original := firstRuntime.statusProbe
		firstRuntime.statusProbe = nil
		defaultReceipt, _, defaultErr := firstRuntime.ExecManagedSupervisor(
			context.Background(), sandboxID, containers.ManagedSupervisorStatus, payload,
		)
		firstRuntime.statusProbe = original
		if defaultErr != nil {
			return nil, defaultErr
		}
		currentSource, err := journey.store.ContinuitySource(ctx, managedSourceID(firstID))
		if err != nil {
			return nil, err
		}
		if currentSource == nil {
			return defaultReceipt, nil
		}
		currentService, err := journey.store.ManagedService(ctx, firstID)
		if err != nil || currentService == nil {
			return nil, errors.New("retained service unavailable")
		}
		merged := map[string]any{}
		if err := json.Unmarshal(defaultReceipt, &merged); err != nil {
			return nil, err
		}
		observed := map[string]any{}
		if err := json.Unmarshal(observedSourceStatusReceipt(*currentSource, *currentService), &observed); err != nil {
			return nil, err
		}
		for key, value := range observed {
			merged[key] = value
		}
		return json.Marshal(merged)
	}
	journey.reconciler.ContinuityControl = &continuity.Coordinator{
		Store: journey.store, Registry: continuity.StateRegistry{Store: journey.store, Now: journey.reconciler.Now},
		Now: journey.reconciler.Now,
	}
	journey.manifest.ManagedServices = append(journey.manifest.ManagedServices, second.ServiceManifest)
	journey.manifest.SetupOperations = append(journey.manifest.SetupOperations, second.SetupManifest)
	journey.manifest.Sandboxes = append(journey.manifest.Sandboxes, model.Sandbox{
		ID: second.ServiceManifest.Identity.SandboxID, Name: "independent-active-service",
		DesiredState: "running", Generation: 2, Lifetime: "persistent",
		Resources: model.Resources{CPUMillicores: 1000, MemoryMiB: 1024, WorkspaceDiskGiB: 2, PIDs: 64},
	})

	// Persisted signed-44 failure shape: failed service row (native registration
	// already overwritten), retained source stopped with availability available
	// and Reason nil after a genuine probe, exact tuple and session, plus a fresh
	// verified continuity registration.
	processInstance := model.ManagedServiceProcessInstance(first.Identity.Instance, first.Identity.ExpectedServiceGeneration)
	if err := journey.store.PutManagedServiceIntent(ctx, state.LocalManagedService{
		Manifest: first, Phase: "pending", ProcessInstance: processInstance,
		Port: managedServicePort, ServiceGeneration: first.Identity.ExpectedServiceGeneration,
	}); err != nil {
		t.Fatal(err)
	}
	if err := journey.store.MarkManagedServiceCreationDispatched(ctx, firstID, first.ConfigDigest); err != nil {
		t.Fatal(err)
	}
	failedReport := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: first.OperationID, ActionRevision: first.ActionRevision,
		ObservedDesiredRevision: first.DesiredRevision, ConfigDigest: first.ConfigDigest, ObservedState: "failed",
		Identity: first.Identity, ServiceGeneration: first.Identity.ExpectedServiceGeneration,
		ProfileStatus: "ready", WorkspaceStatus: "ready", EnrollmentStatus: "failed", WorkerStatus: "failed",
		InstructionRevision: first.Instructions.InstructionRevision, InstructionDigest: first.Instructions.InstructionDigest,
		LastError: &model.ManagedServiceErrorV1{Code: "enrollment_unavailable"},
	}
	if err := journey.store.UpdateManagedService(ctx, firstID, "failed", &failedReport, "enrollment_unavailable"); err != nil {
		t.Fatal(err)
	}
	project, err := journey.store.ManagedProject(ctx, first.Workspace.SelectionID)
	if err != nil || project == nil {
		t.Fatalf("managed project = %#v, %v", project, err)
	}
	// Complete projection input: the coordinator writes
	// continuity-registration.json only when the exact instance directory
	// exists, as the supervisor creates it in production.
	if err := os.MkdirAll(filepath.Join(project.Anchor, ".warpmetal", "opencode", "instances", first.Identity.Instance), 0700); err != nil {
		t.Fatal(err)
	}
	sourceID := managedSourceID(firstID)
	nativeSession := "ses_managedservice0001"
	nativeProjectID := "0123456789abcdef0123456789abcdef01234567"
	nativeLocationDigest := "sha256:d9cf96858af585c5acc19643dfba975c35894edd0b85f88e96e82f88988beab6"
	observedAt := journey.reconciler.Now()
	sourceReport := model.ContinuitySourceReportV1{
		FormatVersion: 1, RegisteredSourceID: sourceID, ServiceRegistrationID: firstID,
		ServiceGeneration: first.Identity.ExpectedServiceGeneration, ProjectID: first.Workspace.ProjectID,
		SandboxID: first.Identity.SandboxID, SandboxGeneration: first.Identity.SandboxGeneration,
		WorkspaceEpoch: first.Workspace.WorkspaceEpoch, NativeSessionID: nativeSession,
		NativeProjectID: nativeProjectID, NativeLocationDigest: nativeLocationDigest,
		ScopeRevision: first.Workspace.ScopeRevision, Role: first.Identity.Role,
		ProfileRevision: first.Profile.ProfileRevision, InstructionRevision: first.Instructions.InstructionRevision,
		Availability: "available", LastObservedAt: observedAt,
	}
	if err := journey.store.PutContinuitySource(ctx, state.LocalContinuitySource{
		Report: sourceReport, Root: project.HostRoot, Instance: first.Identity.Instance,
		Lifecycle: "stopped", LifecycleRevision: 2, NoAdmittedExecution: true,
	}); err != nil {
		t.Fatal(err)
	}
	registration := model.ContinuityRegistrationV1{
		FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: first.Workspace.ScopeRevision,
		Identity: model.ContinuityIdentityV1{
			WorkID: "work_retained_recovery_first", ProjectID: first.Workspace.ProjectID,
			SandboxID: first.Identity.SandboxID, WorkspaceEpoch: first.Workspace.WorkspaceEpoch,
			SandboxGeneration: first.Identity.SandboxGeneration, ExpectedRevision: 1,
		},
		Binding: model.ContinuityBindingV1{
			BindingID: "binding_retained_recovery_first", BindingRevision: 1,
			RegisteredSourceID: sourceID, ServiceRegistrationID: firstID,
			NativeSessionID: nativeSession, NativeProjectID: nativeProjectID, NativeLocationDigest: nativeLocationDigest,
		},
	}
	if err := journey.store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
		Manifest: registration, ObservedStatus: "verified",
		ServiceGeneration: sourceReport.ServiceGeneration,
		ReceiptDigest:     acknowledgementRegistrationReceiptDigest(registration, sourceReport),
	}); err != nil {
		t.Fatal(err)
	}
	journey.manifest.ContinuityRegistrations = append(journey.manifest.ContinuityRegistrations, registration)

	policy := model.InsightPolicyV1{
		SandboxID: first.Identity.SandboxID, Revision: 4, Enabled: true, ExpiresAt: observedAt.Add(90 * time.Second),
		Sources: []model.InsightPolicySourceV1{{
			RegisteredSourceID: sourceID, ServiceRegistrationID: firstID,
			SandboxGeneration: first.Identity.SandboxGeneration, ServiceGeneration: first.Identity.ExpectedServiceGeneration,
			WorkspaceEpoch: first.Workspace.WorkspaceEpoch, NativeSessionID: nativeSession,
		}},
	}
	journey.reconciler.ManagedControl.(*isolatedServiceControl).policies = model.InsightPolicyEnvelopeV1{
		Policies: []model.InsightPolicyV1{policy},
	}
	firstControl.enrollErr = nil

	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
		t.Fatalf("retained stopped-by-failure service did not recover under fresh desired-active intent: %v", err)
	}
	recovered, err := journey.store.ManagedService(ctx, firstID)
	if err != nil || recovered == nil || recovered.Phase != "ready" {
		t.Fatalf("first service did not recover to ready: %#v %v", recovered, err)
	}
	recoveredSource, err := journey.store.ContinuitySource(ctx, sourceID)
	if err != nil || recoveredSource == nil || recoveredSource.Lifecycle != "running" ||
		recoveredSource.Report.NativeSessionID != nativeSession {
		t.Fatalf("retained source did not recover with the same session: %#v %v", recoveredSource, err)
	}
	recoveredRegistration, err := journey.store.ContinuityRegistration(ctx, registration.Binding.BindingID)
	if err != nil || recoveredRegistration == nil || recoveredRegistration.ObservedStatus != "verified" {
		t.Fatalf("continuity registration authority changed: %#v %v", recoveredRegistration, err)
	}
	secondStored, err := journey.store.ManagedService(ctx, secondID)
	if err != nil || secondStored == nil || secondStored.Phase != "ready" {
		t.Fatalf("second healthy service did not progress: %#v %v", secondStored, err)
	}
}

// TestTransientEnrollmentFailureRecoversWithEnabledMonitor reproduces the real
// ready -> transient failure -> recovery transition in the same journey: pass 1
// reaches ready with a genuine retained source; the enabled policy and a fresh
// verified registration are then present; pass 2 injects one real fake-control
// enrollmentErr and tombstones the source; pass 3 clears it and requires
// recovery with the same session. The second healthy service must show actual
// enrollment progress in the failure pass.
func TestTransientEnrollmentFailureRecoversWithEnabledMonitor(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	ctx := context.Background()
	second := independentActiveServiceFixture(t, journey.store, journey.reconciler.Now)
	first := journey.fixture.ServiceManifest
	firstID := first.Identity.ServiceRegistrationID
	secondID := second.ServiceManifest.Identity.ServiceRegistrationID

	firstControl := journey.reconciler.ManagedControl.(*fakeManagedControl)
	firstRuntime := journey.reconciler.ManagedRuntime.(*fakeManagedRuntime)
	secondControl := &fakeManagedControl{fixture: second}
	secondRuntime := &fakeManagedRuntime{store: journey.store, serviceID: secondID, fixture: second}
	journey.reconciler.ManagedControl = &isolatedServiceControl{byService: map[string]*fakeManagedControl{
		firstID: firstControl, secondID: secondControl,
	}}
	journey.reconciler.ManagedRuntime = &isolatedServiceRuntime{bySandbox: map[string]*fakeManagedRuntime{
		first.Identity.SandboxID:                  firstRuntime,
		second.ServiceManifest.Identity.SandboxID: secondRuntime,
	}}
	// Reuse the complete source-observation adapter so the actual probe sees the
	// exact retained tuple instead of a fixture-shaped mismatch.
	firstRuntime.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
		payload, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		// Delegate the original fake status behavior so managed capability
		// fields stay intact; the adapter only completes observation identity.
		original := firstRuntime.statusProbe
		firstRuntime.statusProbe = nil
		defaultReceipt, _, defaultErr := firstRuntime.ExecManagedSupervisor(
			context.Background(), sandboxID, containers.ManagedSupervisorStatus, payload,
		)
		firstRuntime.statusProbe = original
		if defaultErr != nil {
			return nil, defaultErr
		}
		currentSource, err := journey.store.ContinuitySource(ctx, managedSourceID(firstID))
		if err != nil {
			return nil, err
		}
		if currentSource == nil {
			return defaultReceipt, nil
		}
		currentService, err := journey.store.ManagedService(ctx, firstID)
		if err != nil || currentService == nil {
			return nil, errors.New("retained service unavailable")
		}
		merged := map[string]any{}
		if err := json.Unmarshal(defaultReceipt, &merged); err != nil {
			return nil, err
		}
		observed := map[string]any{}
		if err := json.Unmarshal(observedSourceStatusReceipt(*currentSource, *currentService), &observed); err != nil {
			return nil, err
		}
		for key, value := range observed {
			merged[key] = value
		}
		return json.Marshal(merged)
	}
	journey.reconciler.ContinuityControl = &continuity.Coordinator{
		Store: journey.store, Registry: continuity.StateRegistry{Store: journey.store, Now: journey.reconciler.Now},
		Now: journey.reconciler.Now,
	}
	journey.manifest.ManagedServices = append(journey.manifest.ManagedServices, second.ServiceManifest)
	journey.manifest.SetupOperations = append(journey.manifest.SetupOperations, second.SetupManifest)
	journey.manifest.Sandboxes = append(journey.manifest.Sandboxes, model.Sandbox{
		ID: second.ServiceManifest.Identity.SandboxID, Name: "independent-active-service",
		DesiredState: "running", Generation: 2, Lifetime: "persistent",
		Resources: model.Resources{CPUMillicores: 1000, MemoryMiB: 1024, WorkspaceDiskGiB: 2, PIDs: 64},
	})

	// Pass 1: genuine ready state with the retained source running.
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
		t.Fatalf("healthy baseline pass failed: %v", err)
	}
	firstStored, err := journey.store.ManagedService(ctx, firstID)
	if err != nil || firstStored == nil || firstStored.Phase != "ready" {
		t.Fatalf("baseline first service = %#v %v", firstStored, err)
	}
	sourceID := managedSourceID(firstID)
	source, err := journey.store.ContinuitySource(ctx, sourceID)
	if err != nil || source == nil || source.Lifecycle != "running" || source.Report.NativeSessionID == "" {
		t.Fatalf("baseline retained source = %#v %v", source, err)
	}
	project, err := journey.store.ManagedProject(ctx, first.Workspace.SelectionID)
	if err != nil || project == nil {
		t.Fatalf("managed project = %#v, %v", project, err)
	}
	// Complete projection input: the instance directory the coordinator writes
	// continuity-registration.json into must already exist.
	if err := os.MkdirAll(filepath.Join(project.Anchor, ".warpmetal", "opencode", "instances", first.Identity.Instance), 0700); err != nil {
		t.Fatal(err)
	}

	// Fresh verified registration and enabled policy using the actual source tuple.
	registration := model.ContinuityRegistrationV1{
		FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: source.Report.ScopeRevision,
		Identity: model.ContinuityIdentityV1{
			WorkID: "work_transient_recovery_first", ProjectID: first.Workspace.ProjectID,
			SandboxID: first.Identity.SandboxID, WorkspaceEpoch: first.Workspace.WorkspaceEpoch,
			SandboxGeneration: first.Identity.SandboxGeneration, ExpectedRevision: 1,
		},
		Binding: model.ContinuityBindingV1{
			BindingID: "binding_transient_recovery_first", BindingRevision: 1,
			RegisteredSourceID: sourceID, ServiceRegistrationID: firstID,
			NativeSessionID: source.Report.NativeSessionID, NativeProjectID: source.Report.NativeProjectID,
			NativeLocationDigest: source.Report.NativeLocationDigest,
		},
	}
	if err := journey.store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
		Manifest: registration, ObservedStatus: "verified",
		ServiceGeneration: source.Report.ServiceGeneration,
		ReceiptDigest:     acknowledgementRegistrationReceiptDigest(registration, source.Report),
	}); err != nil {
		t.Fatal(err)
	}
	journey.manifest.ContinuityRegistrations = append(journey.manifest.ContinuityRegistrations, registration)
	policy := model.InsightPolicyV1{
		SandboxID: first.Identity.SandboxID, Revision: 4, Enabled: true,
		ExpiresAt: journey.reconciler.Now().Add(90 * time.Second),
		Sources: []model.InsightPolicySourceV1{{
			RegisteredSourceID: sourceID, ServiceRegistrationID: firstID,
			SandboxGeneration: first.Identity.SandboxGeneration, ServiceGeneration: first.Identity.ExpectedServiceGeneration,
			WorkspaceEpoch: first.Workspace.WorkspaceEpoch, NativeSessionID: source.Report.NativeSessionID,
		}},
	}
	journey.reconciler.ManagedControl.(*isolatedServiceControl).policies = model.InsightPolicyEnvelopeV1{
		Policies: []model.InsightPolicyV1{policy},
	}

	// Pass 2: one real transient enrollment failure; the source is closed or
	// marked unavailable with its identity/session unchanged, and the second
	// healthy service still reaches enrollment.
	secondEnrollmentsBefore := len(secondControl.enrollments)
	firstControl.enrollErr = errors.New("control-plane response 504 (unexpected_status)")
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err == nil ||
		!strings.Contains(err.Error(), "apply managed services: managed service "+firstID) {
		t.Fatalf("transient enrollment failure was not surfaced as the fatal cause: %v", err)
	}
	failedStored, err := journey.store.ManagedService(ctx, firstID)
	if err != nil || failedStored == nil || failedStored.Phase != "failed" ||
		failedStored.Report.LastError == nil || failedStored.Report.LastError.Code != "enrollment_unavailable" {
		t.Fatalf("first service did not fail closed with the exact code: %#v %v", failedStored, err)
	}
	failedSource, err := journey.store.ContinuitySource(ctx, sourceID)
	if err != nil || failedSource == nil ||
		failedSource.Report.NativeSessionID != source.Report.NativeSessionID ||
		(failedSource.Lifecycle != "stopped" && failedSource.Report.Availability != "unavailable") {
		t.Fatalf("failure did not close the retained source while preserving identity/session: %#v %v", failedSource, err)
	}
	if len(secondControl.enrollments) <= secondEnrollmentsBefore {
		t.Fatalf("second healthy service did not progress in the failure pass")
	}

	// Pass 3: clear the transient error and require recovery on the same
	// authenticated desired-active manifest with the same session.
	firstControl.enrollErr = nil
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
		t.Fatalf("retained source did not recover after one transient enrollment failure: %v", err)
	}
	recovered, err := journey.store.ManagedService(ctx, firstID)
	if err != nil || recovered == nil || recovered.Phase != "ready" {
		t.Fatalf("first service did not recover to ready: %#v %v", recovered, err)
	}
	recoveredSource, err := journey.store.ContinuitySource(ctx, sourceID)
	if err != nil || recoveredSource == nil || recoveredSource.Lifecycle != "running" ||
		recoveredSource.Report.NativeSessionID != source.Report.NativeSessionID {
		t.Fatalf("retained source did not recover with the same session: %#v %v", recoveredSource, err)
	}
	recoveredRegistration, err := journey.store.ContinuityRegistration(ctx, registration.Binding.BindingID)
	if err != nil || recoveredRegistration == nil || recoveredRegistration.ObservedStatus != "verified" {
		t.Fatalf("continuity registration authority changed: %#v %v", recoveredRegistration, err)
	}
	secondStored, err := journey.store.ManagedService(ctx, secondID)
	if err != nil || secondStored == nil || secondStored.Phase != "ready" {
		t.Fatalf("second healthy service did not stay ready: %#v %v", secondStored, err)
	}
}
