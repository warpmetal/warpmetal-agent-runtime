package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

const (
	successionHandoffOperationID   = "op_finish_handoff0001"
	successionHandoffTargetService = "service_finish_target0001"
	successionHandoffTargetSelect  = "selection_finish_target0001"
	successionHandoffMappedSource  = "source_finish_handoff0001"
	// A49: the target managed service primary (the generic status surface) and
	// the distinct mapped target session (the reconcile_handoff surface) are
	// separate native sessions owned by separate source rows.
	successionHandoffTargetInstance = "handoff-target"
	successionHandoffPrimarySource  = "source_finish_targetprimary0001"
	successionHandoffPrimarySession = "ses_finish_targetprimary0001"
	successionHandoffPrimarySelect  = "selection_finish_targetprimary0001"
	successionHandoffPrimaryProject = "project_finish_targetprimary0001"
	successionHandoffPrimaryEpoch   = "epoch_finish_targetprimary0001"
	successionHandoffMappedSession  = "ses_finish_handoff0001"
	successionHandoffMappedProject  = "project_finish_handoff0001"
	successionHandoffMappedEpoch    = "epoch_finish_handoff0001"
	successionHandoffMappedBinding  = "binding_finish_handoff0001"
)

// successionHandoffNativeProject derives one 40-hex native project identifier
// for the distinct primary and mapped target sessions.
func successionHandoffNativeProject(label string) string {
	sum := sha256.Sum256([]byte("handoff-native-project|" + label))
	return hex.EncodeToString(sum[:20])
}

// successionHandoffSupervisor answers the ready handoff target side's ordinary
// supervisor status surface (the target managed service primary session) and
// records every call, so the A49 journey can prove the target primary is
// observed exactly once through its correct boundary.
type successionHandoffSupervisor struct {
	calls    int
	receipts map[string][]byte
	failures map[string]error
}

func (supervisor *successionHandoffSupervisor) ExecManagedSupervisor(_ context.Context, _ string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	supervisor.calls++
	if action != containers.ManagedSupervisorStatus {
		return nil, nil, fmt.Errorf("ready handoff target must not dispatch %s", action)
	}
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	instance, _ := request["instance"].(string)
	if err := supervisor.failures[instance]; err != nil {
		return nil, nil, err
	}
	if receipt, ok := supervisor.receipts[instance]; ok {
		return receipt, nil, nil
	}
	return nil, nil, fmt.Errorf("ready handoff target supervisor has no receipt for instance %q", instance)
}

func (supervisor *successionHandoffSupervisor) assertIdle(t *testing.T) {
	t.Helper()
	if supervisor.calls != 0 {
		t.Fatalf("ready handoff target supervisor was probed %d times", supervisor.calls)
	}
}

func (supervisor *successionHandoffSupervisor) assertTargetObservedOnce(t *testing.T) {
	t.Helper()
	if supervisor.calls != 1 {
		t.Fatalf("target primary status probes = %d, want exactly 1", supervisor.calls)
	}
}

// successionHandoffObjects, successionHandoffCatalog and
// successionHandoffAdmission are tripwires for every allocation,
// materialization, admission and registration boundary: the A49 target-side
// observation must never prepare, create, publish, admit or register.
type successionHandoffObjects struct {
	calls int
}

func (objects *successionHandoffObjects) Verify(context.Context, string) (storage.DurableCapture, error) {
	objects.calls++
	return storage.DurableCapture{}, errors.New("ready handoff succession deferral must not verify a capture")
}

func (objects *successionHandoffObjects) VerifyWorkspace(context.Context, string, string) error {
	objects.calls++
	return errors.New("ready handoff succession deferral must not verify a workspace")
}

func (objects *successionHandoffObjects) MaterializeNew(context.Context, storage.MaterializeNewRequest) (storage.MaterializeReceipt, error) {
	objects.calls++
	return storage.MaterializeReceipt{}, errors.New("ready handoff succession deferral must not materialize a workspace")
}

type successionHandoffCatalog struct {
	calls int
}

func (catalog *successionHandoffCatalog) Resolve(context.Context, workspacecatalog.ResolveProjectRequest) (workspacecatalog.RegisteredProject, error) {
	catalog.calls++
	return workspacecatalog.RegisteredProject{}, errors.New("ready handoff succession deferral must not resolve a project")
}

func (catalog *successionHandoffCatalog) AllocateRestore(context.Context, workspacecatalog.RestoreProjectRequest) (workspacecatalog.RegisteredProject, error) {
	catalog.calls++
	return workspacecatalog.RegisteredProject{}, errors.New("ready handoff succession deferral must not allocate a restore")
}

func (catalog *successionHandoffCatalog) CompleteRestore(context.Context, string) (workspacecatalog.RegisteredProject, error) {
	catalog.calls++
	return workspacecatalog.RegisteredProject{}, errors.New("ready handoff succession deferral must not complete a restore")
}

func (catalog *successionHandoffCatalog) AllocateHandoff(context.Context, workspacecatalog.HandoffProjectRequest) (workspacecatalog.RegisteredProject, error) {
	catalog.calls++
	return workspacecatalog.RegisteredProject{}, errors.New("ready handoff succession deferral must not allocate a handoff workspace")
}

func (catalog *successionHandoffCatalog) CompleteHandoff(context.Context, string) (workspacecatalog.RegisteredProject, error) {
	catalog.calls++
	return workspacecatalog.RegisteredProject{}, errors.New("ready handoff succession deferral must not complete a handoff workspace")
}

// successionHandoffHelper answers the existing idempotent reconcile_handoff
// request with the exact immutable stored ready report envelope and records
// every call, so the A49 journey can prove the mapped target session is
// observed exactly once through its correct boundary and that no
// prepare/create/publish/admit/register/release action is ever dispatched.
type successionHandoffHelper struct {
	calls               int
	reconciles          int
	registrations       int
	envelope            []byte
	registrationReceipt []byte
	refusal             []byte
	failure             error
}

func (helper *successionHandoffHelper) ExecContinuity(_ context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	helper.calls++
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	switch request["action"] {
	case "reconcile_handoff":
		helper.reconciles++
		if helper.refusal != nil {
			return helper.refusal, nil, errors.New("continuity helper refused")
		}
		if helper.failure != nil {
			return nil, nil, helper.failure
		}
		return helper.envelope, nil, nil
	case "register_continuation_target":
		// The ordinary pre-existing target-registration re-dispatch (never part
		// of the A49 target-side observation boundary) answers its exact
		// idempotent receipt.
		helper.registrations++
		return helper.registrationReceipt, nil, nil
	default:
		return nil, nil, fmt.Errorf("ready handoff target must not dispatch continuity action %v", request["action"])
	}
}

func (helper *successionHandoffHelper) assertIdle(t *testing.T) {
	t.Helper()
	if helper.calls != 0 {
		t.Fatalf("ready handoff target helper was executed %d times", helper.calls)
	}
}

func (helper *successionHandoffHelper) assertMappedObservedOnce(t *testing.T) {
	t.Helper()
	if helper.calls != 1 || helper.reconciles != 1 {
		t.Fatalf("mapped session reconcile_handoff calls = %d/%d, want exactly 1/1", helper.calls, helper.reconciles)
	}
}

type successionHandoffAdmission struct {
	calls int
}

func (admission *successionHandoffAdmission) ScheduleContinuationHandoff(context.Context, string, model.ContinuationHandoffManifestV1, model.ContinuityRegistrationV1) error {
	admission.calls++
	// The ordinary pre-existing handoff admission boundary is idempotent for an
	// already registered mapped target; it is never part of the A49
	// target-side observation.
	return nil
}

// successionHandoffFixture carries the durable ready handoff and the tripwire
// bound to the current reopened store.
type successionHandoffFixture struct {
	controller  *continuity.S2Controller
	manifest    model.ContinuationHandoffManifestV1
	report      model.ContinuationHandoffReportV1
	readyReport model.ContinuationHandoffReportV1
	supervisor  *successionHandoffSupervisor
	objects     *successionHandoffObjects
	catalog     *successionHandoffCatalog
	helper      *successionHandoffHelper
	admission   *successionHandoffAdmission
	serverID    string
	selectionID string
}

// setHelperReport replaces the helper's reconcile_handoff envelope report, so a
// negative can prove the exact immutable prepared report requirement.
func (fixture *successionHandoffFixture) setHelperReport(t *testing.T, report model.ContinuationHandoffReportV1) {
	t.Helper()
	envelope, err := json.Marshal(map[string]any{
		"formatVersion": 1, "action": "reconcile_handoff", "status": "ready", "state": "prepared",
		"report": report, "consumption": nil, "release": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.helper.envelope = envelope
}

// setHelperRefusal makes the helper answer reconcile_handoff with a bounded
// refusal receipt and a nonzero exit.
func (fixture *successionHandoffFixture) setHelperRefusal(t *testing.T, code string) {
	t.Helper()
	refusal, err := json.Marshal(map[string]any{
		"formatVersion": 1, "action": "reconcile_handoff", "status": "refused", "error": code,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.helper.refusal = refusal
}

func (fixture *successionHandoffFixture) rebind(journey *acknowledgementJourney) {
	fixture.controller = &continuity.S2Controller{
		Store: journey.store, ServerID: fixture.serverID,
		Objects: fixture.objects, Catalog: fixture.catalog, Helper: fixture.helper,
		HandoffSupervisor: fixture.supervisor, HandoffAdmission: fixture.admission, Now: journey.now,
	}
}

// assertUntouched proves the ready handoff never verified, materialized,
// allocated, admitted or registered anything, in every succession shape.
func (fixture *successionHandoffFixture) assertUntouched(t *testing.T) {
	t.Helper()
	if fixture.objects.calls != 0 || fixture.catalog.calls != 0 || fixture.admission.calls != 0 {
		t.Fatalf("ready handoff touched allocation/materialization/admission boundaries: objects %d catalog %d admission %d",
			fixture.objects.calls, fixture.catalog.calls, fixture.admission.calls)
	}
}

// assertTargetObservedOnce proves the exact succession deferral still observed
// the target side of the same ready preparation through its own boundaries: the
// target service primary status receipt exactly once and the distinct mapped
// session's idempotent reconcile_handoff exactly once, with no allocation,
// materialization, admission or registration.
func (fixture *successionHandoffFixture) assertTargetObservedOnce(t *testing.T) {
	t.Helper()
	fixture.supervisor.assertTargetObservedOnce(t)
	fixture.helper.assertMappedObservedOnce(t)
	fixture.assertUntouched(t)
}

// assertIdle is the strict zero-touch shape for every non-succession
// classification failure.
func (fixture *successionHandoffFixture) assertIdle(t *testing.T) {
	t.Helper()
	fixture.supervisor.assertIdle(t)
	fixture.helper.assertIdle(t)
	fixture.assertUntouched(t)
}

// reset zeroes the per-pass boundary counters so a repeated pass can be
// asserted independently.
func (fixture *successionHandoffFixture) reset() {
	fixture.supervisor.calls = 0
	fixture.helper.calls = 0
	fixture.helper.reconciles = 0
	fixture.objects.calls = 0
	fixture.catalog.calls = 0
	fixture.admission.calls = 0
}

// successionHandoffSeed is one ready preparation under construction, so a
// negative can move the stored handoff binding/identity while the report stays
// byte-consistent with it.
type successionHandoffSeed struct {
	manifest         model.ContinuationHandoffManifestV1
	report           model.ContinuationHandoffReportV1
	selectionID      string
	skipTarget       bool
	withMappedTarget bool
}

// withMappedTargetRegistration carries the exact active mapped handoff-target
// registration the ready preparation owns (the live reviewer target
// registration) in the fresh manifest and the durable store.
func withMappedTargetRegistration() successionJourneyOption {
	return func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
		seed.withMappedTarget = true
	}
}

func (seed *successionHandoffSeed) setBinding(mutate func(*model.ContinuationBindingRefV1)) {
	mutate(&seed.manifest.Binding)
	seed.report.Binding = seed.manifest.Binding
}

func (seed *successionHandoffSeed) setIdentity(mutate func(*model.ContinuationIdentityV1)) {
	mutate(&seed.manifest.Identity)
	seed.report.Identity = seed.manifest.Identity
}

type successionJourneyOption func(t *testing.T, journey *acknowledgementJourney, seed *successionHandoffSeed)

// successionHandoffSeedDefaults is the exact post-.54 ready handoff: the stored
// source binding is the historical finish predecessor (same binding ID,
// revision 1, scope 2, service generation 1) while the local durable
// registration and the same fresh manifest's effective finish registration are
// the active, continuity-enabled successor (revision 2, scope 3, every
// immutable field otherwise equal). The target side carries the live reviewer
// shape: a ready target managed service whose primary native session is
// distinct from the create_separate mapped target session stored in the ready
// report.
func successionHandoffSeedDefaults(journey *acknowledgementJourney) successionHandoffSeed {
	predecessor := journey.finish.registration
	registrationIdentity := journey.replacement.registration.Identity
	identity := model.ContinuationIdentityV1{
		WorkID: registrationIdentity.WorkID, ProjectID: registrationIdentity.ProjectID,
		SandboxID: registrationIdentity.SandboxID, WorkspaceEpoch: registrationIdentity.WorkspaceEpoch,
		SandboxGeneration: registrationIdentity.SandboxGeneration, ExpectedRevision: registrationIdentity.ExpectedRevision,
	}
	checkpoint := model.ContinuationCheckpointRefV1{
		OperationID: "op_finish_checkpoint0001", CheckpointID: "checkpoint_finish000001",
		ManifestDigest: acknowledgementDigest([]byte("handoff-checkpoint-manifest")), Bytes: 4096, ObjectCount: 2,
	}
	targetPolicy := model.ContinuationHandoffTargetPolicyV1{
		TeamID: journey.fixture.ServiceManifest.Identity.TeamID, TeamRevision: 1, PolicyRevision: 1,
		MemberID: journey.fixture.ServiceManifest.Identity.MemberID, Role: "reviewer",
		SandboxID: identity.SandboxID, SandboxGeneration: identity.SandboxGeneration,
		ServiceRegistrationID: successionHandoffTargetService, ServiceGeneration: 1,
		ServiceDesiredRevision: 1, ServiceActionRevision: 1,
		ProfileID: "opencode", ProfileRevision: 1, ProfileDigest: journey.fixture.SetupManifest.ProfileDigest,
		InstructionRevision: 1, InstructionDigest: acknowledgementDigest([]byte("handoff-target-instruction")),
	}
	scopeRevision := int64(1)
	workspace := model.ContinuationHandoffWorkspaceRequestV1{
		Mode: "allocate_and_materialize",
	}
	contextValue := model.ContinuationContextV1{
		Digest: acknowledgementDigest([]byte("handoff-context")), Bytes: 128, TokenUpperBound: 64,
	}
	manifest := model.ContinuationHandoffManifestV1{
		FormatVersion: 1, OperationID: successionHandoffOperationID, Action: "prepare_handoff",
		DesiredRevision: journey.manifest.DesiredRevision, HandoffKind: "reviewer", SessionMode: "create_separate",
		TargetWorkID: "work_finish_target0001", MappingID: "mapping_finish_handoff0001",
		Identity: identity,
		Binding: model.ContinuationBindingRefV1{
			BindingID: predecessor.Binding.BindingID, BindingRevision: predecessor.Binding.BindingRevision,
			ScopeRevision: predecessor.ScopeRevision, ServiceGeneration: journey.finish.source.ServiceGeneration,
			RegisteredSourceID: predecessor.Binding.RegisteredSourceID, ServiceRegistrationID: predecessor.Binding.ServiceRegistrationID,
			NativeSessionID: predecessor.Binding.NativeSessionID, NativeProjectID: predecessor.Binding.NativeProjectID,
			NativeLocationDigest: predecessor.Binding.NativeLocationDigest,
		},
		Checkpoint: checkpoint,
		Lineage: model.ContinuationHandoffLineageV1{
			SourceWorkID: identity.WorkID, SourceRevision: identity.ExpectedRevision,
			CheckpointOperationID: checkpoint.OperationID,
		},
		TargetPolicy: targetPolicy, Workspace: workspace, Context: contextValue,
	}
	report := model.ContinuationHandoffReportV1{
		FormatVersion: manifest.FormatVersion, OperationID: manifest.OperationID, Action: manifest.Action,
		DesiredRevision: manifest.DesiredRevision, HandoffKind: manifest.HandoffKind, SessionMode: manifest.SessionMode,
		TargetWorkID: manifest.TargetWorkID, MappingID: manifest.MappingID,
		Identity: manifest.Identity, Binding: manifest.Binding, Checkpoint: manifest.Checkpoint, Lineage: manifest.Lineage,
		TargetPolicy: manifest.TargetPolicy, WorkspaceRequest: manifest.Workspace, ContextDigest: manifest.Context.Digest,
		Status: "ready",
		TargetWorkspace: &model.ContinuationHandoffTargetWorkspaceV1{
			SelectionID: successionHandoffTargetSelect, ProjectID: successionHandoffMappedProject,
			WorkspaceEpoch: successionHandoffMappedEpoch, ScopeRevision: scopeRevision,
			RootAttestation: acknowledgementDigest([]byte("handoff-target-root")),
		},
		Session: &model.ContinuationHandoffSessionV1{
			MappingID: manifest.MappingID, RegisteredSourceID: successionHandoffMappedSource,
			NativeSessionID: successionHandoffMappedSession, NativeProjectID: successionHandoffNativeProject("mapped"),
			NativeLocationDigest: acknowledgementDigest([]byte("handoff-mapped-location")),
			InstructionRevision:  targetPolicy.InstructionRevision, InstructionDigest: targetPolicy.InstructionDigest,
			InstructionApplied: true,
		},
		Baseline: &model.ContinuationBaselineV1{
			BaselineID: "baseline_finish_handoff0001", BaselineDigest: acknowledgementDigest([]byte("handoff-baseline")),
			NativeSessionID:   successionHandoffMappedSession,
			ServiceGeneration: targetPolicy.ServiceGeneration, ReadyAt: journey.now(),
		},
		ReceiptDigest: acknowledgementDigest([]byte("handoff-receipt")),
	}
	return successionHandoffSeed{manifest: manifest, report: report, selectionID: successionHandoffTargetSelect}
}

// completeSuccessionHandoff stores one byte-consistent ready preparation, using
// the ordinary store admission path (structure check included) so the record is
// the same shape the real controller publishes.
func completeSuccessionHandoff(
	t *testing.T,
	journey *acknowledgementJourney,
	seed successionHandoffSeed,
	operationID, targetWorkID, mappedSource string,
) {
	t.Helper()
	ctx := context.Background()
	manifest := seed.manifest
	manifest.OperationID = operationID
	manifest.TargetWorkID = targetWorkID
	report := seed.report
	report.OperationID = operationID
	report.TargetWorkID = targetWorkID
	targetWorkspace := *report.TargetWorkspace
	targetWorkspace.SelectionID = seed.selectionID
	report.TargetWorkspace = &targetWorkspace
	session := *report.Session
	session.RegisteredSourceID = mappedSource
	report.Session = &session
	if err := journey.store.PutContinuationHandoffPreparation(ctx, state.LocalContinuationHandoffPreparation{
		Manifest: manifest, Phase: "allocating",
	}); err != nil {
		t.Fatalf("ready handoff preparation %s was rejected: %v", operationID, err)
	}
	if err := journey.store.CompleteContinuationHandoffPreparation(ctx, operationID, seed.selectionID, report); err != nil {
		t.Fatalf("ready handoff report %s was rejected: %v", operationID, err)
	}
}

// seedSuccessionSourceServiceReport stores the ready report of the finish
// successor's managed service so the handoff classification can prove the
// service-generation and instruction fences from the durable row, exactly like
// the live ready service.
func seedSuccessionSourceServiceReport(t *testing.T, journey *acknowledgementJourney) {
	t.Helper()
	serviceID := journey.replacement.registration.Binding.ServiceRegistrationID
	service := journey.storedService(t, serviceID)
	if service == nil {
		t.Fatalf("finish successor service %s is missing", serviceID)
	}
	report := model.ManagedServiceReportV1{
		FormatVersion: 1, ObservedState: "ready", Identity: service.Manifest.Identity,
		ServiceGeneration:   service.ServiceGeneration,
		InstructionApplied:  true,
		InstructionRevision: service.Manifest.Instructions.InstructionRevision,
		InstructionDigest:   service.Manifest.Instructions.InstructionDigest,
	}
	if err := journey.store.UpdateManagedService(context.Background(), serviceID, "ready", &report, ""); err != nil {
		t.Fatal(err)
	}
}

// seedSuccessionHandoffTarget seeds the complete live reviewer target side: a
// ready target managed service with its distinct primary native registration
// and primary source row, the mapped handoff target project, and the distinct
// stale mapped session source row. It returns the primary source row and the
// target service so the journey's supervisor surface can answer with the
// primary receipt.
func seedSuccessionHandoffTarget(
	t *testing.T, journey *acknowledgementJourney, selectionID string, withProject bool,
) (state.LocalContinuitySource, state.LocalManagedService) {
	t.Helper()
	ctx := context.Background()
	identity := journey.replacement.registration.Identity
	serverID := journey.fixture.ServiceManifest.Identity.ServerID
	teamID := journey.fixture.ServiceManifest.Identity.TeamID
	memberID := journey.fixture.ServiceManifest.Identity.MemberID
	primaryRoot := "/host/workspaces/handoff-primary"
	mappedRoot := "/host/workspaces/handoff-mapped"
	primaryWorkspace := model.ManagedServiceWorkspaceV1{
		SelectionID: successionHandoffPrimarySelect, ProjectID: successionHandoffPrimaryProject,
		WorkspaceEpoch: successionHandoffPrimaryEpoch, ScopeRevision: 1, Designation: "team_project",
		RootAttestation: acknowledgementDigest([]byte("handoff-primary-root")),
	}
	service := state.LocalManagedService{
		Manifest: model.ManagedServiceV1{
			FormatVersion: 1, ActionRevision: 1, DesiredRevision: 1, DesiredState: "active", SessionMode: "lookup_only",
			Identity: model.ManagedServiceIdentityV1{
				ServerID: serverID, TeamID: teamID, MemberID: memberID,
				SandboxID: identity.SandboxID, SandboxGeneration: identity.SandboxGeneration,
				ServiceRegistrationID: successionHandoffTargetService, ExpectedServiceGeneration: 1,
				Instance: successionHandoffTargetInstance, Role: "reviewer",
			},
			Profile: model.ManagedServiceProfileV1{
				SetupOperationID: journey.fixture.SetupManifest.ID, ProfileID: "opencode",
				ProfileRevision: 1, ProfileDigest: journey.fixture.SetupManifest.ProfileDigest,
			},
			Instructions: model.ManagedServiceInstructionsV1{
				InstructionRevision: 1,
				InstructionDigest:   acknowledgementDigest([]byte("handoff-target-instruction")),
			},
			Workspace: primaryWorkspace,
		},
		Phase: "ready", ServiceGeneration: 1,
		ProcessInstance: "wmsup-handoff-target-0001", Port: 18444,
	}
	if err := journey.store.PutManagedServiceIntent(ctx, service); err != nil {
		t.Fatal(err)
	}
	serviceID := successionHandoffTargetService
	report := model.ManagedServiceReportV1{
		FormatVersion: 1, ObservedState: "ready", Identity: service.Manifest.Identity,
		ServiceGeneration: 1, InstructionApplied: true,
		InstructionRevision: service.Manifest.Instructions.InstructionRevision,
		InstructionDigest:   service.Manifest.Instructions.InstructionDigest,
		NativeRegistration: &model.ManagedNativeRegistrationV1{
			RegisteredSourceID: successionHandoffPrimarySource, WorkspaceEpoch: successionHandoffPrimaryEpoch,
			NativeSessionID: successionHandoffPrimarySession, NativeProjectID: successionHandoffNativeProject("primary"),
			NativeLocationDigest: acknowledgementDigest([]byte("handoff-primary-location")),
		},
		ReceiptDigest: acknowledgementDigest([]byte("handoff-target-service-receipt")),
	}
	if err := journey.store.UpdateManagedService(ctx, serviceID, "ready", &report, ""); err != nil {
		t.Fatal(err)
	}
	if err := journey.store.PutManagedProject(ctx, state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: successionHandoffPrimarySelect,
			ProjectID: successionHandoffPrimaryProject, WorkspaceEpoch: successionHandoffPrimaryEpoch,
			SandboxID: identity.SandboxID, SandboxGeneration: identity.SandboxGeneration,
			ServiceRegistrationID: &serviceID,
			Designation:           "team_project", Label: "handoff-target-primary",
			Availability:    "available",
			RootAttestation: primaryWorkspace.RootAttestation,
			LastObservedAt:  journey.now(),
		},
		ServerID: serverID, TeamID: teamID, MemberID: memberID,
		Anchor: t.TempDir(), HostRoot: primaryRoot, ContainerRoot: "/home/agent/projects/handoff-primary",
		Phase: "ready", ScopeRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if withProject {
		if err := journey.store.PutManagedProject(ctx, state.LocalManagedProject{
			Report: model.ProjectCatalogReportV1{
				FormatVersion: 1, SelectionID: selectionID,
				ProjectID: successionHandoffMappedProject, WorkspaceEpoch: successionHandoffMappedEpoch,
				SandboxID: identity.SandboxID, SandboxGeneration: identity.SandboxGeneration,
				ServiceRegistrationID: &serviceID,
				Designation:           "continuity-handoff", Label: "handoff-target",
				Availability:    "available",
				RootAttestation: acknowledgementDigest([]byte("handoff-target-root")),
				LastObservedAt:  journey.now(),
			},
			ServerID: serverID, TeamID: teamID, MemberID: memberID,
			Anchor: t.TempDir(), HostRoot: mappedRoot, ContainerRoot: "/home/agent/projects/handoff-target",
			Phase: "ready", ScopeRevision: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	reason := "probe_stale"
	stale := journey.now().Add(-10 * time.Minute)
	primary := state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: successionHandoffPrimarySource,
			ServiceRegistrationID: successionHandoffTargetService, ServiceGeneration: 1,
			ProjectID: successionHandoffPrimaryProject, SandboxID: identity.SandboxID,
			SandboxGeneration: identity.SandboxGeneration, WorkspaceEpoch: successionHandoffPrimaryEpoch,
			NativeSessionID: successionHandoffPrimarySession, NativeProjectID: successionHandoffNativeProject("primary"),
			NativeLocationDigest: acknowledgementDigest([]byte("handoff-primary-location")),
			ScopeRevision:        1, Role: "reviewer", ProfileRevision: 1, InstructionRevision: 1,
			Availability: "unavailable", Reason: &reason, LastObservedAt: stale,
		},
		Root: primaryRoot, Instance: successionHandoffTargetInstance, Lifecycle: "running", LifecycleRevision: 1,
	}
	if err := journey.store.PutContinuitySource(ctx, primary); err != nil {
		t.Fatal(err)
	}
	mapped := state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: successionHandoffMappedSource,
			ServiceRegistrationID: successionHandoffTargetService, ServiceGeneration: 1,
			ProjectID: successionHandoffMappedProject, SandboxID: identity.SandboxID,
			SandboxGeneration: identity.SandboxGeneration, WorkspaceEpoch: successionHandoffMappedEpoch,
			NativeSessionID: successionHandoffMappedSession, NativeProjectID: successionHandoffNativeProject("mapped"),
			NativeLocationDigest: acknowledgementDigest([]byte("handoff-mapped-location")),
			ScopeRevision:        1, Role: "reviewer", ProfileRevision: 1, InstructionRevision: 1,
			Availability: "unavailable", Reason: &reason, LastObservedAt: stale,
		},
		Root: mappedRoot, Instance: successionHandoffTargetInstance, Lifecycle: "running", LifecycleRevision: 1,
	}
	if err := journey.store.PutContinuitySource(ctx, mapped); err != nil {
		t.Fatal(err)
	}
	return primary, service
}

// seedSuccessionMappedRegistration stores the exact active mapped handoff
// target registration the ready preparation owns and carries it in the fresh
// manifest, exactly like the live reviewer target registration.
func seedSuccessionMappedRegistration(t *testing.T, journey *acknowledgementJourney, seed successionHandoffSeed) {
	t.Helper()
	mapped := model.ContinuityRegistrationV1{
		FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true,
		ScopeRevision: seed.report.TargetWorkspace.ScopeRevision,
		Identity: model.ContinuityIdentityV1{
			WorkID: seed.manifest.TargetWorkID, ProjectID: seed.report.TargetWorkspace.ProjectID,
			SandboxID: seed.manifest.TargetPolicy.SandboxID, WorkspaceEpoch: seed.report.TargetWorkspace.WorkspaceEpoch,
			SandboxGeneration: seed.manifest.TargetPolicy.SandboxGeneration, ExpectedRevision: 1,
		},
		Binding: model.ContinuityBindingV1{
			BindingID: successionHandoffMappedBinding, BindingRevision: 1,
			RegisteredSourceID:    seed.report.Session.RegisteredSourceID,
			ServiceRegistrationID: seed.manifest.TargetPolicy.ServiceRegistrationID,
			NativeSessionID:       seed.report.Session.NativeSessionID, NativeProjectID: seed.report.Session.NativeProjectID,
			NativeLocationDigest: seed.report.Session.NativeLocationDigest,
		},
	}
	if err := journey.store.PutContinuityRegistration(context.Background(), state.LocalContinuityRegistration{
		Manifest: mapped, ObservedStatus: "verified", ServiceGeneration: seed.manifest.TargetPolicy.ServiceGeneration,
		ReceiptDigest: acknowledgementDigest(append([]byte("mapped-registration|"), seed.report.Session.NativeSessionID...)),
	}); err != nil {
		t.Fatal(err)
	}
	journey.manifest.ContinuityRegistrations = append(journey.manifest.ContinuityRegistrations, mapped)
}

// newHandoffSuccessionJourney is the exact post-.54 Reconciler-to-serialized-
// report journey: the accepted/ready handoff whose stored source registration
// is the authentic historical finish predecessor (binding revision 1, scope 2)
// while the local durable registration and the same fresh manifest's effective
// finish registration are the active continuity-enabled successor (revision 2,
// scope 3), the manager revoked/failed with enrollment_unavailable, the six
// echoes retired and applied/desired 64/67.
func newHandoffSuccessionJourney(t *testing.T, options ...successionJourneyOption) (*acknowledgementJourney, *successionHandoffFixture) {
	t.Helper()
	journey := newObservedSourceJourney(t, 3)
	seedSuccessionSourceServiceReport(t, journey)
	seed := successionHandoffSeedDefaults(journey)
	for _, option := range options {
		option(t, journey, &seed)
	}
	primary, targetService := seedSuccessionHandoffTarget(t, journey, seed.selectionID, !seed.skipTarget)
	baseProbe := journey.statusProbe
	journey.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
		// The live generic managed-supervisor status surface for the target
		// service proves the PRIMARY session, while the mapped handoff-target
		// source row stores the distinct create_separate session: a generic
		// probe of the mapped source therefore fails session_mismatch until the
		// A49 boundaries separate the two observation owners.
		if request["instance"] == successionHandoffTargetInstance {
			return observedSourceStatusReceipt(primary, targetService), nil
		}
		return baseProbe(sandboxID, request)
	}
	completeSuccessionHandoff(t, journey, seed, seed.manifest.OperationID, seed.manifest.TargetWorkID, successionHandoffMappedSource)
	// The fresh manifest carries the handoff as typed current intent: the
	// authority-bound recovery owns exactly what the validated intent names,
	// and a valid manifest also carries the handoff's target sandbox.
	journey.manifest.ContinuityHandoffs = []model.ContinuationHandoffManifestV1{seed.manifest}
	targetSandbox := model.Sandbox{
		ID: seed.manifest.TargetPolicy.SandboxID, Name: "handoff-target", DesiredState: "running",
		Generation: seed.manifest.TargetPolicy.SandboxGeneration, Lifetime: "persistent",
		Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 64},
	}
	targetPresent := false
	for index, sandbox := range journey.manifest.Sandboxes {
		if sandbox.ID == targetSandbox.ID {
			journey.manifest.Sandboxes[index].Generation = targetSandbox.Generation
			targetPresent = true
		}
	}
	if !targetPresent {
		journey.manifest.Sandboxes = append(journey.manifest.Sandboxes, targetSandbox)
	}
	if seed.withMappedTarget {
		seedSuccessionMappedRegistration(t, journey, seed)
	}
	record, err := journey.store.ContinuationHandoffPreparation(context.Background(), seed.manifest.OperationID)
	if err != nil || record == nil || record.Report == nil {
		t.Fatalf("stored ready handoff %s = %#v, %v", seed.manifest.OperationID, record, err)
	}
	envelope, err := json.Marshal(map[string]any{
		"formatVersion": 1, "action": "reconcile_handoff", "status": "ready", "state": "prepared",
		"report": record.Report, "consumption": nil, "release": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	helper := &successionHandoffHelper{envelope: envelope}
	if seed.withMappedTarget {
		var mapped model.ContinuityRegistrationV1
		for _, registration := range journey.manifest.ContinuityRegistrations {
			if registration.Binding.BindingID == successionHandoffMappedBinding {
				mapped = registration
			}
		}
		if mapped.Binding.BindingID == "" {
			t.Fatal("mapped target registration was not carried into the manifest")
		}
		receipt, err := json.Marshal(map[string]any{
			"formatVersion": 1, "action": "register_continuation_target", "status": "registered",
			"operationId": seed.manifest.OperationID, "workId": mapped.Identity.WorkID,
			"expectedRevision": mapped.Identity.ExpectedRevision, "binding": mapped.Binding,
			"receiptDigest": acknowledgementDigest([]byte("mapped-target-registration")),
		})
		if err != nil {
			t.Fatal(err)
		}
		helper.registrationReceipt = receipt
	}
	fixture := &successionHandoffFixture{
		manifest: seed.manifest, report: seed.report, readyReport: *record.Report,
		supervisor: &successionHandoffSupervisor{
			receipts: map[string][]byte{successionHandoffTargetInstance: observedSourceStatusReceipt(primary, targetService)},
			failures: map[string]error{},
		},
		objects: &successionHandoffObjects{}, catalog: &successionHandoffCatalog{},
		helper:    helper,
		admission: &successionHandoffAdmission{},
		serverID:  journey.fixture.ServiceManifest.Identity.ServerID, selectionID: seed.selectionID,
	}
	fixture.rebind(journey)
	journey.handoff = fixture.controller
	journey.reconciler = journey.newReconciler()
	return journey, fixture
}

func (journey *acknowledgementJourney) storedHandoff(t *testing.T, operationID string) state.LocalContinuationHandoffPreparation {
	t.Helper()
	record, err := journey.store.ContinuationHandoffPreparation(context.Background(), operationID)
	if err != nil || record == nil {
		t.Fatalf("stored handoff %s = %#v, %v", operationID, record, err)
	}
	return *record
}

func (journey *acknowledgementJourney) storedSources(t *testing.T) map[string]state.LocalContinuitySource {
	t.Helper()
	sources, err := journey.store.ContinuitySources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rows := make(map[string]state.LocalContinuitySource, len(sources))
	for _, source := range sources {
		rows[source.Report.RegisteredSourceID] = source
	}
	return rows
}

func (journey *acknowledgementJourney) handoffPreparations(t *testing.T) []state.LocalContinuationHandoffPreparation {
	t.Helper()
	values, err := journey.store.ContinuationHandoffPreparations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func (journey *acknowledgementJourney) putRegistration(
	t *testing.T,
	mutate func(*state.LocalContinuityRegistration),
) {
	t.Helper()
	bindingID := journey.finish.registration.Binding.BindingID
	value, ok := journey.storedRegistrations(t)[bindingID]
	if !ok {
		t.Fatalf("local finish successor %s is missing", bindingID)
	}
	mutate(&value)
	if err := journey.store.PutContinuityRegistration(context.Background(), value); err != nil {
		t.Fatal(err)
	}
}

func (journey *acknowledgementJourney) putSource(
	t *testing.T,
	mutate func(*state.LocalContinuitySource),
) {
	t.Helper()
	sourceID := journey.finish.registration.Binding.RegisteredSourceID
	source := journey.storedSource(t, sourceID)
	mutate(&source)
	if err := journey.store.PutContinuitySource(context.Background(), source); err != nil {
		t.Fatal(err)
	}
}

// successionManifestRegistration returns the fresh manifest's effective finish
// registration.
func successionManifestRegistration(journey *acknowledgementJourney, manifest *model.Manifest) *model.ContinuityRegistrationV1 {
	for index := range manifest.ContinuityRegistrations {
		registration := &manifest.ContinuityRegistrations[index]
		if registration.Binding.BindingID == journey.finish.registration.Binding.BindingID &&
			registration.DesiredState == "active" {
			return registration
		}
	}
	return nil
}

// successionManifestPredecessor returns the fresh manifest's re-listed revoked
// finish predecessor.
func successionManifestPredecessor(journey *acknowledgementJourney, manifest *model.Manifest) *model.ContinuityRegistrationV1 {
	for index := range manifest.ContinuityRegistrations {
		registration := &manifest.ContinuityRegistrations[index]
		if registration.Binding.BindingID == journey.finish.registration.Binding.BindingID &&
			registration.DesiredState == "revoked" {
			return registration
		}
	}
	return nil
}

func (journey *acknowledgementJourney) appliedRevision(t *testing.T) int64 {
	t.Helper()
	revision, err := journey.store.Revision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

// TestReconcilerDefersReadyHandoffSuccessionAndKeepsTheReportCurrent is the A45
// RED/GREEN journey. RED: the ready handoff's stored source registration is the
// historical finish predecessor (binding revision 1, scope 2) while the local
// durable registration and the same fresh manifest's effective registration are
// the active successor (revision 2, scope 3), so handoff recovery fails the
// exactness conjunction first on the binding revision and then on the scope,
// aborts the pass before A41 acknowledgement, A43 source observation, managed
// services and SetRevision, and the rebuilt report stays stale: the frozen
// backend v21 returns the exact live HTTP 409 runtime_report_conflict
// "Registration is no longer current and admissible.". GREEN: the pair is
// classified as the already-authorized monotonic succession, deferred with zero
// handoff mutation and zero handoff probes, and the ordinary pass proceeds
// through A41/A43/managed services with the truthful failed manager,
// enrollment_unavailable, the ready handoff and applied 64 all visible; the
// rebuilt report carries only the active successor and the genuine fresh source
// observation and is accepted at the serialized boundary. A later ordinary
// lifecycle with a fresh selection recovers enrollment and reaches
// applied==desired 67 while the historical handoff and every backend terminal
// row stay byte-identical.
func TestReconcilerDefersReadyHandoffSuccessionAndKeepsTheReportCurrent(t *testing.T) {
	ctx := context.Background()
	backend := loadFrozenBackendV21(t)
	journey, handoff := newHandoffSuccessionJourney(t)
	operationID := handoff.manifest.OperationID
	finishSourceID := journey.finish.registration.Binding.RegisteredSourceID
	ba1bSourceID := journey.ba1b.registration.Binding.RegisteredSourceID
	beforePassFinish := journey.storedSource(t, finishSourceID)
	beforePassBa1b := journey.storedSource(t, ba1bSourceID)
	beforeHandoff := journey.storedHandoff(t, operationID)
	beforePreparations := journey.handoffPreparations(t)
	predecessor := journey.finish.registration
	successor := journey.replacement.registration
	if predecessor.Binding.BindingRevision != 1 || predecessor.ScopeRevision != 2 ||
		successor.Binding.BindingRevision != 2 || successor.ScopeRevision != 3 {
		t.Fatalf("journey is not the proven predecessor/successor pair: %#v -> %#v", predecessor, successor)
	}

	beforePass := journey.sourceObservationDurableState(t)
	beforeFinishRegistration := journey.storedRegistrations(t)[journey.finish.registration.Binding.BindingID]
	passErr := journey.reconciler.Reconcile(ctx, journey.manifest)
	afterPass := journey.sourceObservationDurableState(t)
	afterHandoff := journey.storedHandoff(t, operationID)
	finishAfterPass := journey.storedRegistrations(t)[journey.finish.registration.Binding.BindingID]
	t.Logf("ordinary pass error: %v", passErr)
	t.Logf("source probe instances this pass: %v", journey.probeInstances)
	t.Logf("finish registration after the pass: status=%s serviceGeneration=%d receiptDigest=%q error=%q",
		finishAfterPass.ObservedStatus, finishAfterPass.ServiceGeneration, finishAfterPass.ReceiptDigest, finishAfterPass.ErrorCode)
	t.Logf("handoff supervisor calls: %d helper calls: %d object calls: %d catalog calls: %d",
		handoff.supervisor.calls, handoff.helper.calls, handoff.objects.calls, handoff.catalog.calls)
	t.Logf("ready handoff byte-identical over the pass: %v", reflect.DeepEqual(beforeHandoff, afterHandoff))
	t.Logf("durable rows byte-identical over the pass: %v", reflect.DeepEqual(beforePass, afterPass))
	t.Logf("handoff preparations byte-identical over the pass: %v", reflect.DeepEqual(beforePreparations, journey.handoffPreparations(t)))
	t.Logf("applied revision after the pass: %d", journey.appliedRevision(t))
	if _, payload := journey.daemonReport(t, passErr); payload != nil {
		verdict, _ := backend.applyReport(
			t, payload, journey.backendV21Rows(t), journey.backendV21Sources(t),
			journey.now(), frozenBackendV21CurrentTokenHash,
		)
		if verdict.Accepted {
			t.Logf("frozen backend verdict on this pass: accepted=true")
		} else {
			t.Logf("frozen backend verdict on this pass: accepted=false HTTP=%d code=%s message=%s",
				verdict.Error.Status, verdict.Error.Code, verdict.Error.Message)
		}
	}

	// GREEN: the dedicated deferral is exactly like the handoff-probe deferral:
	// it stays visible in the pass error but the ordinary pass still reaches
	// the failure-prone managed-service enrollment and reports it. Everything
	// before A41 wrote nothing.
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") {
		t.Fatalf("ready-handoff succession was not deferred into the ordinary pass: %v", passErr)
	}
	if !strings.Contains(passErr.Error(), "recover continuation handoffs:") ||
		!strings.Contains(passErr.Error(), "continuation baseline recovery is unknown") ||
		!strings.Contains(passErr.Error(), "handoff source registration no longer matches the stored manifest") {
		t.Fatalf("deferred succession classification is not visible in the pass error: %v", passErr)
	}
	if !errors.Is(passErr, continuity.ErrS2RecoveryUnknown) {
		t.Fatalf("deferred succession lost the retained fatal classification: %v", passErr)
	}
	handoff.assertTargetObservedOnce(t)
	if !reflect.DeepEqual(beforeHandoff, afterHandoff) {
		t.Fatalf("ready handoff record changed across the deferral:\nbefore %#v\nafter  %#v", beforeHandoff, afterHandoff)
	}
	if !reflect.DeepEqual(beforePreparations, journey.handoffPreparations(t)) {
		t.Fatal("deferral changed the handoff preparation history")
	}
	// The acknowledgement resolved only the effective successor: the equal
	// verified durable row is preserved byte-for-field against the stale source
	// instead of being re-evaluated and downgraded.
	if !reflect.DeepEqual(beforeFinishRegistration, finishAfterPass) ||
		finishAfterPass.ObservedStatus != "verified" || finishAfterPass.ServiceGeneration != 1 ||
		finishAfterPass.ReceiptDigest == "" || finishAfterPass.ErrorCode != "" {
		t.Fatalf("acknowledgement re-evaluated the equal durable successor:\nbefore %#v\nafter  %#v",
			beforeFinishRegistration, finishAfterPass)
	}

	// A43 ran as the sole source-observation writer: exactly the two unique
	// active sources are probed once each, in deterministic source order.
	if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b", "finish"}) {
		t.Fatalf("source probes = %v, want exactly the active ba1b and finish sources", journey.probeInstances)
	}
	finishObserved := journey.storedSource(t, finishSourceID)
	ba1bObserved := journey.storedSource(t, ba1bSourceID)
	for _, observed := range []state.LocalContinuitySource{finishObserved, ba1bObserved} {
		if observed.Report.Availability != "available" || observed.Report.Reason != nil ||
			!observed.Report.LastObservedAt.Equal(journey.now()) {
			t.Fatalf("source %s was not re-observed completely: %#v", observed.Report.RegisteredSourceID, observed)
		}
	}
	if !reflect.DeepEqual(observedSourceIdentityOf(finishObserved), observedSourceIdentityOf(beforePassFinish)) ||
		!reflect.DeepEqual(observedSourceIdentityOf(ba1bObserved), observedSourceIdentityOf(beforePassBa1b)) {
		t.Fatalf("observation content drifted:\nfinish got %#v want %#v\nba1b got %#v want %#v",
			observedSourceIdentityOf(finishObserved), observedSourceIdentityOf(beforePassFinish),
			observedSourceIdentityOf(ba1bObserved), observedSourceIdentityOf(beforePassBa1b))
	}

	// The truthful failed manager service, enrollment_unavailable, the ready
	// handoff and applied 64 remain visible.
	service := journey.storedService(t, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if service == nil || service.Phase != "failed" || service.ErrorCode != "enrollment_unavailable" {
		t.Fatalf("manager failure was not preserved: %#v", service)
	}
	if applied := journey.appliedRevision(t); applied != 64 {
		t.Fatalf("applied revision = %d, want the unchanged 64", applied)
	}
	report, payload := journey.daemonReport(t, passErr)
	if _, repeated := journey.daemonReport(t, passErr); !bytes.Equal(payload, repeated) {
		t.Fatal("report is not rebuilt deterministically from the durable rows")
	}
	if report.LastError == nil || report.LastError.Code != "reconcile_failed" ||
		!strings.Contains(report.LastError.Message, "stale") ||
		!strings.Contains(report.LastError.Message, "handoff source registration") {
		t.Fatalf("deferred succession and stale-selection failure are not both visible: %#v", report.LastError)
	}
	if len(report.ContinuityRegistrations) != 2 ||
		report.ContinuityRegistrations[0].Binding.BindingID != journey.ba1b.registration.Binding.BindingID ||
		report.ContinuityRegistrations[1].Binding.BindingID != journey.finish.registration.Binding.BindingID ||
		report.ContinuityRegistrations[1].Binding.BindingRevision != 2 ||
		report.ContinuityRegistrations[1].ScopeRevision != 3 {
		t.Fatalf("report registration shape drifted: %#v", report.ContinuityRegistrations)
	}
	for _, observation := range report.ContinuityRegistrations {
		if observation.Binding.BindingID == journey.manager.registration.Binding.BindingID {
			t.Fatalf("revoked manager tuple was serialized: %#v", observation)
		}
	}
	if len(report.ContinuityOperations) != 0 {
		t.Fatalf("retired operation echoes were serialized: %#v", report.ContinuityOperations)
	}
	verdict, sourcesAfter := backend.applyReport(
		t, payload, journey.backendV21Rows(t), journey.backendV21Sources(t),
		journey.now(), frozenBackendV21CurrentTokenHash,
	)
	if !verdict.Accepted {
		t.Fatalf("deferred-succession report was rejected by frozen backend v21: HTTP %d %s: %s\n%s",
			verdict.Error.Status, verdict.Error.Code, verdict.Error.Message, payload)
	}
	t.Logf("frozen backend v21 verdict: accepted the deferred-succession report")
	if row := sourcesAfter[frozenSourceKey(finishObserved.Report.SandboxID, finishObserved.Report.RegisteredSourceID)]; row.NodeTokenHash != frozenBackendV21CurrentTokenHash ||
		!row.LastObservedAt.Equal(journey.now()) {
		t.Fatalf("accepted report did not refresh the backend token/freshness: %#v", row)
	}

	// A repeated ordinary pass repeats the exact deferral idempotently: only
	// the genuine observations are re-written (identically under the fixed
	// clock); the handoff, every registration, tombstone, service row and
	// revision stay byte-identical.
	settled := journey.sourceObservationDurableState(t)
	settledHandoff := journey.storedHandoff(t, operationID)
	settledHandoffPreparations := journey.handoffPreparations(t)
	settledFinish := journey.storedSource(t, finishSourceID)
	settledBa1b := journey.storedSource(t, ba1bSourceID)
	handoff.reset()
	probesBefore := len(journey.probeInstances)
	passErr = journey.reconciler.Reconcile(ctx, journey.manifest)
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") ||
		!strings.Contains(passErr.Error(), "recover continuation handoffs:") {
		t.Fatalf("second deferred-succession pass did not preserve both conditions: %v", passErr)
	}
	if !reflect.DeepEqual(journey.probeInstances[probesBefore:], []string{"ba1b", "finish"}) {
		t.Fatalf("second pass probes = %v", journey.probeInstances[probesBefore:])
	}
	settledAgain := journey.sourceObservationDurableState(t)
	if !reflect.DeepEqual(settled.withoutSources(), settledAgain.withoutSources()) {
		t.Fatalf("second deferral touched unrelated durable state:\nbefore %#v\nafter  %#v",
			settled.withoutSources(), settledAgain.withoutSources())
	}
	if !reflect.DeepEqual(settledHandoff, journey.storedHandoff(t, operationID)) ||
		!reflect.DeepEqual(settledHandoffPreparations, journey.handoffPreparations(t)) {
		t.Fatal("second deferral changed the ready handoff record")
	}
	handoff.assertTargetObservedOnce(t)

	// Reopen/restart: the same deterministic deferral, the same genuine
	// observations and an accepted report.
	journey.restart(t)
	handoff.rebind(journey)
	journey.handoff = handoff.controller
	journey.reconciler = journey.newReconciler()
	handoff.reset()
	probesBefore = len(journey.probeInstances)
	passErr = journey.reconciler.Reconcile(ctx, journey.manifest)
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") ||
		!strings.Contains(passErr.Error(), "recover continuation handoffs:") {
		t.Fatalf("restarted deferred-succession pass did not preserve both conditions: %v", passErr)
	}
	if !reflect.DeepEqual(journey.probeInstances[probesBefore:], []string{"ba1b", "finish"}) {
		t.Fatalf("restarted pass probes = %v", journey.probeInstances[probesBefore:])
	}
	if !reflect.DeepEqual(settledHandoff, journey.storedHandoff(t, operationID)) ||
		!reflect.DeepEqual(settledHandoffPreparations, journey.handoffPreparations(t)) {
		t.Fatal("restart changed the ready handoff record")
	}
	if !reflect.DeepEqual(journey.storedSource(t, finishSourceID), settledFinish) ||
		!reflect.DeepEqual(journey.storedSource(t, ba1bSourceID), settledBa1b) {
		t.Fatal("restart changed the genuine observations")
	}
	_, restartedPayload := journey.daemonReport(t, passErr)
	restartedVerdict, restartedSources := backend.applyReport(
		t, restartedPayload, journey.backendV21Rows(t), journey.backendV21Sources(t),
		journey.now(), frozenBackendV21CurrentTokenHash,
	)
	if !restartedVerdict.Accepted {
		t.Fatalf("restarted report was rejected: HTTP %d %s: %s",
			restartedVerdict.Error.Status, restartedVerdict.Error.Code, restartedVerdict.Error.Message)
	}
	if row := restartedSources[frozenSourceKey(settledFinish.Report.SandboxID, finishSourceID)]; row.NodeTokenHash != frozenBackendV21CurrentTokenHash {
		t.Fatalf("restarted report did not carry the current token hash: %#v", row)
	}

	// The next ordinary lifecycle with a fresh selection - no forced retry, no
	// bypass, no manual enrollment, no handoff rewrite, no special success path
	// - recovers enrollment, clears enrollment_unavailable, reports the manager
	// ready and reaches applied==desired 67, while the historical handoff and
	// all six backend terminal rows/checkpoint stay byte-identical.
	journey.control.enrollErr = nil
	handoff.reset()
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
		t.Fatalf("ordinary convergence did not complete: %v", err)
	}
	if applied := journey.appliedRevision(t); applied != journey.manifest.DesiredRevision {
		t.Fatalf("converged applied revision = %d, want %d", applied, journey.manifest.DesiredRevision)
	}
	service = journey.storedService(t, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" ||
		service.ErrorCode != "" || service.Manifest.Identity.Role != "manager" {
		t.Fatalf("manager enrollment did not recover through the ordinary lifecycle: %#v", service)
	}
	if !reflect.DeepEqual(settledHandoff, journey.storedHandoff(t, operationID)) ||
		!reflect.DeepEqual(settledHandoffPreparations, journey.handoffPreparations(t)) {
		t.Fatal("ordinary convergence rewrote the historical ready handoff")
	}
	handoff.assertTargetObservedOnce(t)
	if !reflect.DeepEqual(journey.storedSource(t, finishSourceID), settledFinish) ||
		!reflect.DeepEqual(journey.storedSource(t, ba1bSourceID), settledBa1b) {
		t.Fatal("ordinary convergence changed the genuine observations")
	}
	converged := journey.sourceObservationDurableState(t)
	if len(converged.retirements) != len(journey.echoes) || len(converged.operations) != 0 {
		t.Fatalf("terminal echo history drifted: retirements %d operations %d",
			len(converged.retirements), len(converged.operations))
	}
}

// TestReconcilerKeepsEveryNonSuccessionHandoffMismatchFatal is the A45
// mutation-blind negative matrix: only the exact historical predecessor /
// current successor pair may be deferred. Every equal, reversed or skipped
// binding revision, scope equality/regression/jump, changed binding ID or
// identity/work/service-generation/workspace/sandbox/native-location/role/
// profile/instruction/project/epoch fence, stale or regressed manifest,
// local-vs-manifest mismatch, foreign or missing source, ambiguous duplicate
// and changed handoff target keeps the existing fatal ErrS2RecoveryUnknown
// recovery path with zero handoff, source, registration, service, operation,
// tombstone, revision or backend writes.
func TestReconcilerKeepsEveryNonSuccessionHandoffMismatchFatal(t *testing.T) {
	ctx := context.Background()
	failingFatal := func(t *testing.T, passErr error) {
		t.Helper()
		if passErr == nil || !strings.Contains(passErr.Error(), "recover continuation handoffs:") {
			t.Fatalf("non-succession mismatch did not keep the fatal recovery path: %v", passErr)
		}
		if strings.Contains(passErr.Error(), "apply managed services:") {
			t.Fatalf("non-succession mismatch was deferred into the ordinary pass: %v", passErr)
		}
		if !errors.Is(passErr, continuity.ErrS2RecoveryUnknown) {
			t.Fatalf("non-succession mismatch lost the fatal recovery classification: %v", passErr)
		}
	}

	cases := []struct {
		name                 string
		expectTargetObserved bool
		// validationFirst marks mutations whose manifest no longer forms a
		// valid effective registration set: with the authorized validation-first
		// boundary the pass fails closed at the manifest gate before recovery.
		validationFirst bool
		options         []successionJourneyOption
		mutate          func(t *testing.T, journey *acknowledgementJourney, fixture *successionHandoffFixture) model.Manifest
		check           func(t *testing.T, passErr error)
	}{
		{
			name: "equal_binding_revision_is_not_succession", validationFirst: true,
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				journey.putRegistration(t, func(value *state.LocalContinuityRegistration) {
					value.Manifest.Binding.BindingRevision = 1
				})
				successionManifestRegistration(journey, &manifest).Binding.BindingRevision = 1
				return manifest
			},
		},
		{
			name: "skipped_binding_revision_is_not_succession", validationFirst: true,
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				journey.putRegistration(t, func(value *state.LocalContinuityRegistration) {
					value.Manifest.Binding.BindingRevision = 3
				})
				successionManifestRegistration(journey, &manifest).Binding.BindingRevision = 3
				return manifest
			},
		},
		{
			name: "reversed_binding_revision_is_not_succession",
			options: []successionJourneyOption{func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
				seed.setBinding(func(binding *model.ContinuationBindingRefV1) {
					binding.BindingRevision = 3
					binding.ScopeRevision = 4
				})
			}},
		},
		{
			name: "equal_scope_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				journey.putRegistration(t, func(value *state.LocalContinuityRegistration) {
					value.Manifest.ScopeRevision = 2
				})
				successionManifestRegistration(journey, &manifest).ScopeRevision = 2
				return manifest
			},
		},
		{
			name: "regressed_scope_is_not_succession", validationFirst: true,
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				journey.putRegistration(t, func(value *state.LocalContinuityRegistration) {
					value.Manifest.ScopeRevision = 1
				})
				successionManifestRegistration(journey, &manifest).ScopeRevision = 1
				return manifest
			},
		},
		{
			name: "jumped_scope_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				journey.putRegistration(t, func(value *state.LocalContinuityRegistration) {
					value.Manifest.ScopeRevision = 4
				})
				successionManifestRegistration(journey, &manifest).ScopeRevision = 4
				return manifest
			},
		},
		{
			name: "foreign_binding_id_is_not_succession",
			options: []successionJourneyOption{func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
				seed.setBinding(func(binding *model.ContinuationBindingRefV1) {
					binding.BindingID = "binding_finish_foreign0001"
				})
			}},
		},
		{
			name: "missing_local_registration_is_not_succession",
			options: []successionJourneyOption{func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
				seed.setBinding(func(binding *model.ContinuationBindingRefV1) {
					binding.BindingID = "binding_finish_missing0001"
				})
			}},
		},
		{
			name: "changed_work_identity_is_not_succession", validationFirst: true,
			options: []successionJourneyOption{func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
				seed.setIdentity(func(identity *model.ContinuationIdentityV1) {
					identity.WorkID = "work_finish_foreign0001"
				})
			}},
		},
		{
			name: "changed_project_identity_is_not_succession",
			options: []successionJourneyOption{func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
				seed.setIdentity(func(identity *model.ContinuationIdentityV1) {
					identity.ProjectID = "project_finish_foreign0001"
				})
			}},
		},
		{
			name: "changed_workspace_epoch_is_not_succession",
			options: []successionJourneyOption{func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
				seed.setIdentity(func(identity *model.ContinuationIdentityV1) {
					identity.WorkspaceEpoch = "epoch_finish_foreign0001"
				})
			}},
		},
		{
			name: "changed_sandbox_generation_is_not_succession", validationFirst: true,
			options: []successionJourneyOption{func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
				seed.setIdentity(func(identity *model.ContinuationIdentityV1) {
					identity.SandboxGeneration = 3
				})
			}},
		},
		{
			name: "changed_native_location_is_not_succession",
			options: []successionJourneyOption{func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
				seed.setBinding(func(binding *model.ContinuationBindingRefV1) {
					binding.NativeLocationDigest = "sha256:" + strings.Repeat("b", 64)
				})
			}},
		},
		{
			name: "changed_sandbox_row_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				sandboxID := journey.replacement.registration.Identity.SandboxID
				sandbox, err := journey.store.Sandbox(context.Background(), sandboxID)
				if err != nil || sandbox == nil {
					t.Fatalf("stored sandbox %s = %#v, %v", sandboxID, sandbox, err)
				}
				sandbox.ObservedGeneration = journey.replacement.registration.Identity.SandboxGeneration + 1
				if err := journey.store.PutSandbox(context.Background(), *sandbox); err != nil {
					t.Fatal(err)
				}
				return journey.manifest
			},
		},
		{
			name: "changed_service_generation_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				journey.putRegistration(t, func(value *state.LocalContinuityRegistration) {
					value.ServiceGeneration = 2
				})
				return journey.manifest
			},
		},
		{
			name: "failed_successor_status_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				journey.putRegistration(t, func(value *state.LocalContinuityRegistration) {
					value.ObservedStatus = "failed"
				})
				return journey.manifest
			},
		},
		{
			name: "disabled_successor_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				journey.putRegistration(t, func(value *state.LocalContinuityRegistration) {
					value.Manifest.ContinuityEnabled = false
				})
				return journey.manifest
			},
		},
		{
			name: "revoked_successor_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				journey.putRegistration(t, func(value *state.LocalContinuityRegistration) {
					value.Manifest.DesiredState = "revoked"
				})
				return journey.manifest
			},
		},
		{
			name: "changed_source_role_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				journey.putSource(t, func(source *state.LocalContinuitySource) {
					source.Report.Role = "manager"
				})
				return journey.manifest
			},
		},
		{
			name: "changed_source_profile_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				journey.putSource(t, func(source *state.LocalContinuitySource) {
					source.Report.ProfileRevision = 2
				})
				return journey.manifest
			},
		},
		{
			name: "changed_source_instruction_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				journey.putSource(t, func(source *state.LocalContinuitySource) {
					source.Report.InstructionRevision = 2
				})
				return journey.manifest
			},
		},
		{
			name: "foreign_source_service_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				journey.putSource(t, func(source *state.LocalContinuitySource) {
					source.Report.ServiceRegistrationID = "service_finish_foreign0001"
				})
				return journey.manifest
			},
		},
		{
			name: "local_vs_manifest_mismatch_is_not_succession", expectTargetObserved: true,
			mutate: func(_ *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				successionManifestRegistration(journey, &manifest).ScopeRevision = 4
				return manifest
			},
		},
		{
			name: "manifest_without_the_active_successor_is_not_succession", expectTargetObserved: true,
			mutate: func(_ *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				filtered := make([]model.ContinuityRegistrationV1, 0, len(manifest.ContinuityRegistrations))
				for _, registration := range manifest.ContinuityRegistrations {
					if registration.Binding.BindingID == journey.finish.registration.Binding.BindingID &&
						registration.DesiredState == "active" {
						continue
					}
					filtered = append(filtered, registration)
				}
				manifest.ContinuityRegistrations = filtered
				return manifest
			},
		},
		{
			name: "manifest_predecessor_revision_not_exact_is_not_succession", validationFirst: true, expectTargetObserved: true,
			mutate: func(_ *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				predecessor := successionManifestPredecessor(journey, &manifest)
				predecessor.Binding.BindingRevision = 3
				predecessor.ScopeRevision = 4
				return manifest
			},
		},
		{
			name: "manifest_extra_registration_is_not_succession", validationFirst: true, expectTargetObserved: true,
			mutate: func(_ *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				extra := *successionManifestPredecessor(journey, &manifest)
				extra.Binding.BindingRevision = 2
				extra.ScopeRevision = 3
				registrations := append([]model.ContinuityRegistrationV1(nil), manifest.ContinuityRegistrations...)
				manifest.ContinuityRegistrations = append(registrations, extra)
				return manifest
			},
		},
		{
			name: "manifest_scope_step_not_exact_is_not_succession", expectTargetObserved: true,
			mutate: func(_ *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				successionManifestPredecessor(journey, &manifest).ScopeRevision = 1
				return manifest
			},
		},
		{
			name: "manifest_predecessor_enabled_is_not_succession", expectTargetObserved: true,
			mutate: func(_ *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				successionManifestPredecessor(journey, &manifest).ContinuityEnabled = true
				return manifest
			},
		},
		{
			name: "handoff_revision_jump_is_not_succession",
			mutate: func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				journey.putRegistration(t, func(value *state.LocalContinuityRegistration) {
					value.Manifest.Binding.BindingRevision = 3
					value.Manifest.ScopeRevision = 3
				})
				predecessor := successionManifestPredecessor(journey, &manifest)
				predecessor.Binding.BindingRevision = 2
				predecessor.ScopeRevision = 2
				active := successionManifestRegistration(journey, &manifest)
				active.Binding.BindingRevision = 3
				active.ScopeRevision = 3
				return manifest
			},
		},
		{
			name: "handoff_scope_equality_is_not_succession",
			options: []successionJourneyOption{func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
				seed.setBinding(func(binding *model.ContinuationBindingRefV1) {
					binding.ScopeRevision = 3
				})
			}},
		},
		{
			name: "manifest_pair_foreign_predecessor_is_not_succession", expectTargetObserved: true,
			mutate: func(_ *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				foreign := "sha256:" + strings.Repeat("c", 64)
				successionManifestPredecessor(journey, &manifest).Binding.NativeLocationDigest = foreign
				successionManifestRegistration(journey, &manifest).Binding.NativeLocationDigest = foreign
				return manifest
			},
		},
		{
			name: "stale_or_regressed_manifest_is_not_succession", expectTargetObserved: true, validationFirst: true,
			mutate: func(_ *testing.T, journey *acknowledgementJourney, _ *successionHandoffFixture) model.Manifest {
				manifest := journey.manifest
				manifest.DesiredRevision = 63
				return manifest
			},
			// The confirmation itself must reject the stale manifest, so the
			// pass can never fall through to the normal manifest validation
			// with the deferral already applied.
			check: func(t *testing.T, passErr error) {
				if passErr != nil && strings.Contains(passErr.Error(), "manifest revision moved backwards") {
					t.Fatalf("regressed manifest was deferred into the ordinary validation instead of failing handoff recovery: %v", passErr)
				}
			},
		},
		{
			name: "ambiguous_duplicate_ready_handoff_is_not_succession", expectTargetObserved: true,
			options: []successionJourneyOption{func(t *testing.T, journey *acknowledgementJourney, _ *successionHandoffSeed) {
				duplicate := successionHandoffSeedDefaults(journey)
				completeSuccessionHandoff(t, journey, duplicate, "op_finish_handoff0002", "work_finish_target0002", "source_finish_handoff0002")
			}},
		},
		{
			name: "missing_handoff_target_project_is_not_succession",
			options: []successionJourneyOption{func(_ *testing.T, _ *acknowledgementJourney, seed *successionHandoffSeed) {
				seed.skipTarget = true
			}},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			journey, handoff := newHandoffSuccessionJourney(t, test.options...)
			manifest := journey.manifest
			if test.mutate != nil {
				manifest = test.mutate(t, journey, handoff)
			}
			before := journey.sourceObservationDurableState(t)
			beforeSources := journey.storedSources(t)
			beforeHandoff := journey.storedHandoff(t, handoff.manifest.OperationID)
			beforePreparations := journey.handoffPreparations(t)
			passErr := journey.reconciler.Reconcile(ctx, manifest)
			after := journey.sourceObservationDurableState(t)
			afterSources := journey.storedSources(t)
			afterHandoff := journey.storedHandoff(t, handoff.manifest.OperationID)
			t.Logf("pass error: %v", passErr)
			if test.validationFirst {
				// The authorized validation-first boundary fails closed at the
				// manifest gate before any recovery for an invalid or stale
				// manifest; the handoff history stays untouched.
				if passErr == nil {
					t.Fatal("invalid or stale manifest was accepted by the validation-first gate")
				}
				if strings.Contains(passErr.Error(), "recover continuation handoffs:") {
					t.Fatalf("validation-first gate did not precede handoff recovery: %v", passErr)
				}
				if !reflect.DeepEqual(beforeHandoff, afterHandoff) ||
					!reflect.DeepEqual(beforePreparations, journey.handoffPreparations(t)) {
					t.Fatal("validation-first failure changed the ready handoff history")
				}
				return
			}
			failingFatal(t, passErr)
			if test.check != nil {
				test.check(t, passErr)
			}
			if test.expectTargetObserved {
				handoff.assertTargetObservedOnce(t)
			} else {
				handoff.assertIdle(t)
			}
			if len(journey.probeInstances) != 0 {
				t.Fatalf("fatal mismatch ran the A43 observation phase: %v", journey.probeInstances)
			}
			if !reflect.DeepEqual(before.withoutSources(), after.withoutSources()) {
				t.Fatalf("fatal mismatch wrote durable state:\nbefore %#v\nafter  %#v",
					before.withoutSources(), after.withoutSources())
			}
			for id, beforeSource := range beforeSources {
				if test.expectTargetObserved && (id == successionHandoffPrimarySource || id == successionHandoffMappedSource) {
					continue
				}
				afterSource, ok := afterSources[id]
				if !ok || !reflect.DeepEqual(beforeSource, afterSource) {
					t.Fatalf("fatal mismatch changed source %s:\nbefore %#v\nafter  %#v", id, beforeSource, afterSource)
				}
			}
			if !reflect.DeepEqual(beforeHandoff, afterHandoff) || !reflect.DeepEqual(beforePreparations, journey.handoffPreparations(t)) {
				t.Fatal("fatal mismatch changed the ready handoff history")
			}
			if applied := journey.appliedRevision(t); applied != 64 {
				t.Fatalf("fatal mismatch advanced the applied revision to %d", applied)
			}
		})
	}
}
