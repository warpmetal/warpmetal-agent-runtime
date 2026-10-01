package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type fakeManagerCoordinator struct {
	recoverCalls  int
	renewals      []model.Manifest
	manifests     []model.Manifest
	policyApplies []model.Manifest
	policies      []model.InsightsManagerPolicyReportV1
	runs          []model.InsightsManagerRunReportV1
	takeovers     []model.InsightsTakeoverReportV1
}

func (manager *fakeManagerCoordinator) RenewPendingTakeovers(_ context.Context, manifest model.Manifest) error {
	manager.renewals = append(manager.renewals, manifest)
	return nil
}

func (manager *fakeManagerCoordinator) Recover(context.Context) error {
	manager.recoverCalls++
	return nil
}

func (manager *fakeManagerCoordinator) ApplyPolicies(_ context.Context, manifest model.Manifest) error {
	manager.policyApplies = append(manager.policyApplies, manifest)
	return nil
}

func (manager *fakeManagerCoordinator) Apply(_ context.Context, manifest model.Manifest) error {
	manager.manifests = append(manager.manifests, manifest)
	return nil
}

func (manager *fakeManagerCoordinator) Reports(context.Context, continuity.StaleSourceSet) ([]model.InsightsManagerPolicyReportV1, []model.InsightsManagerRunReportV1, []model.InsightsTakeoverReportV1, error) {
	return manager.policies, manager.runs, manager.takeovers, nil
}

func TestReconcilerWiresManagerManifestRecoveryAndSanitizedReports(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := &fakeManagerCoordinator{
		policies:  []model.InsightsManagerPolicyReportV1{{FormatVersion: 1}},
		runs:      []model.InsightsManagerRunReportV1{{FormatVersion: 1}},
		takeovers: []model.InsightsTakeoverReportV1{{FormatVersion: 1}},
	}
	reconciler := &Reconciler{Store: store, ServerID: "srv_managerwire0001", Manager: manager,
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		HostCapacity: model.Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20}}
	manifest := model.Manifest{ServerID: reconciler.ServerID, DesiredRevision: 1,
		ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
		Capacity:    reconciler.HostCapacity,
	}
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if manager.recoverCalls != 1 || len(manager.manifests) != 1 || manager.manifests[0].DesiredRevision != manifest.DesiredRevision {
		t.Fatalf("manager reconcile wiring = recover %d manifests %#v", manager.recoverCalls, manager.manifests)
	}
	if len(manager.renewals) != 1 || manager.renewals[0].DesiredRevision != manifest.DesiredRevision {
		t.Fatalf("pending manager recovery preparation wiring = %#v", manager.renewals)
	}
	if len(manager.policyApplies) != 1 || manager.policyApplies[0].DesiredRevision != manifest.DesiredRevision {
		t.Fatalf("early manager policy apply wiring = %#v", manager.policyApplies)
	}
	report, err := reconciler.Report(context.Background(), reconciler.ServerID, "test")
	if err != nil || len(report.InsightsManagerPolicies) != 1 || len(report.InsightsManagerReviews) != 1 || len(report.InsightsTakeovers) != 1 {
		t.Fatalf("manager report wiring = %#v, %v", report, err)
	}
}

var _ ManagerControl = (*fakeManagerCoordinator)(nil)

// pendingPauseHelper models the actual helper boundary: an expired operation
// cannot be reconciled, and successful reconciliation echoes the exact fresh lease.
// Only the initial acquire is dispatched; recovery must never repeat it.
type pendingPauseHelper struct {
	now          func() time.Time
	loseAcquire  bool
	reconcileErr error
	actions      []string
	manifests    []model.InsightsTakeoverManifestV1
}

func (helper *pendingPauseHelper) ExecManager(_ context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	var request struct {
		FormatVersion int                              `json:"formatVersion"`
		Action        string                           `json:"action"`
		Instance      string                           `json:"instance"`
		Manifest      model.InsightsTakeoverManifestV1 `json:"manifest"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	helper.actions = append(helper.actions, request.Action)
	helper.manifests = append(helper.manifests, request.Manifest)
	if request.Action == "acquire_intervention_hold" && helper.loseAcquire {
		helper.loseAcquire = false
		return nil, nil, errors.New("initial protective acquire response lost")
	}
	if request.Action != "reconcile_intervention_hold" {
		return nil, nil, errors.New("recovery repeated a hold mutation")
	}
	if !helper.now().Before(request.Manifest.ValidUntil) {
		return nil, nil, errors.New("helper refused expired persisted takeover lease")
	}
	if helper.reconcileErr != nil {
		return nil, nil, helper.reconcileErr
	}
	// Reuse the actual outgoing manifest's closed authority representation; the
	// native helper receipt changes the action and adds only receipt fields.
	encoded, _ := json.Marshal(request.Manifest)
	var receipt map[string]any
	if err := json.Unmarshal(encoded, &receipt); err != nil {
		return nil, nil, err
	}
	receipt["action"], receipt["status"] = request.Action, "active"
	receipt["pendingInput"] = model.InsightsTakeoverPendingInputV1{State: "none_pending"}
	receipt["receiptDigest"], receipt["errorCode"] = "sha256:"+strings.Repeat("a", 64), nil
	output, err := json.Marshal(receipt)
	return output, nil, err
}

type pendingPauseJourney struct {
	*managerPolicyJourney
	helper  *pendingPauseHelper
	pending state.LocalManagerTakeover
	prior   state.LocalManagerTakeover
}

func newPendingPauseJourney(t *testing.T) *pendingPauseJourney {
	t.Helper()
	journey := newManagerPolicyJourney(t)
	ctx := context.Background()
	clock := journey.reconciler.Now()
	now := func() time.Time { return clock }
	journey.coordinator.Now, journey.reconciler.Now = now, now
	journey.fresh.Mode, journey.fresh.AllowedRules = "off", []string{}
	journey.fresh.PolicyRevision, journey.fresh.RunGeneration = 5, 5
	journey.fresh.ValidUntil = clock.Add(30 * time.Second)
	if err := journey.store.PutSandbox(ctx, state.LocalSandbox{ID: journey.fresh.SandboxID,
		DesiredState: "running", ObservedState: "running", Generation: 2, ObservedGeneration: 2, Lifetime: "persistent"}); err != nil {
		t.Fatal(err)
	}
	service := journey.fixture.ServiceManifest
	serviceReport := journey.fixture.ServiceReport
	serviceReport.Identity = service.Identity
	if err := journey.store.PutManagedServiceIntent(ctx, state.LocalManagedService{Manifest: service, Phase: "ready",
		ServiceGeneration: serviceReport.ServiceGeneration, ProcessInstance: "default", Port: 18443, CreationDispatched: true}); err != nil {
		t.Fatal(err)
	}
	if err := journey.store.UpdateManagedService(ctx, service.Identity.ServiceRegistrationID, "ready", &serviceReport, ""); err != nil {
		t.Fatal(err)
	}
	source, err := journey.store.ContinuitySource(ctx, "source_managerpolicy0001")
	if err != nil || source == nil {
		t.Fatalf("seeded source = %#v, %v", source, err)
	}
	source.Report.ServiceRegistrationID = service.Identity.ServiceRegistrationID
	source.Report.ServiceGeneration = serviceReport.ServiceGeneration
	source.Report.Availability, source.Report.Reason, source.Lifecycle = "available", nil, "running"
	source.Report.LastObservedAt = clock
	if err := journey.store.PutContinuitySource(ctx, *source); err != nil {
		t.Fatal(err)
	}
	exactSource := model.InsightsManagerSourceV1{RegisteredSourceID: source.Report.RegisteredSourceID,
		WorkspaceEpoch: source.Report.WorkspaceEpoch, NativeSessionID: source.Report.NativeSessionID,
		ServiceRegistrationID: source.Report.ServiceRegistrationID, ServiceGeneration: source.Report.ServiceGeneration,
		SandboxGeneration: source.Report.SandboxGeneration, ProfileRevision: source.Report.ProfileRevision,
		InstructionRevision: source.Report.InstructionRevision}
	taskID, attempt := "task_pendingpause0001", int64(1)
	workID, workRevision := "work_pendingpause0001", int64(1)
	bindingID, bindingRevision := "binding_pendingpause0001", int64(1)
	target := model.InsightsManagerTargetV1{TeamID: service.Identity.TeamID, MemberID: service.Identity.MemberID,
		TaskID: &taskID, TaskAttempt: &attempt, WorkID: &workID, WorkRevision: &workRevision,
		BindingID: &bindingID, BindingRevision: &bindingRevision}
	if err := journey.store.PutManagedTaskAuthority(ctx, state.LocalManagedTaskAuthority{
		ServiceRegistrationID: exactSource.ServiceRegistrationID, ServiceGeneration: exactSource.ServiceGeneration,
		SandboxGeneration: exactSource.SandboxGeneration, TaskID: &taskID, TaskAttempt: &attempt, Busy: true, ObservedAt: clock}); err != nil {
		t.Fatal(err)
	}
	registration := model.ContinuityRegistrationV1{FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true}
	registration.Identity.WorkID, registration.Identity.ExpectedRevision = workID, workRevision
	registration.Identity.WorkspaceEpoch, registration.Identity.SandboxGeneration = exactSource.WorkspaceEpoch, exactSource.SandboxGeneration
	registration.Identity.TaskID, registration.Identity.TaskAttempt = &taskID, &attempt
	registration.Binding.BindingID, registration.Binding.BindingRevision = bindingID, bindingRevision
	registration.Binding.RegisteredSourceID, registration.Binding.ServiceRegistrationID = exactSource.RegisteredSourceID, exactSource.ServiceRegistrationID
	registration.Binding.NativeSessionID = exactSource.NativeSessionID
	if err := journey.store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{Manifest: registration,
		ObservedStatus: "verified", ServiceGeneration: exactSource.ServiceGeneration}); err != nil {
		t.Fatal(err)
	}
	pause := model.InsightsTakeoverManifestV1{FormatVersion: 1, OperationID: "takeover_pendingpause0001",
		Action: "pause_manager_and_hold_member", FindingID: "finding_pendingpause0001", FindingRevision: 1,
		PolicyRevision: 5, RunGeneration: 5, HoldID: "hold_pendingpause0001", HoldRevision: 1, HoldState: "active",
		Source: exactSource, Target: target, ValidUntil: journey.fresh.ValidUntil}
	helper := &pendingPauseHelper{now: now, loseAcquire: true}
	journey.coordinator.Helper = helper
	if err := journey.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{journey.fresh},
		InsightsTakeovers: []model.InsightsTakeoverManifestV1{pause}}); err == nil || !strings.Contains(err.Error(), "initial protective acquire response lost") {
		t.Fatalf("initial acquire did not persist the actual unknown boundary: %v", err)
	}
	pending, err := journey.store.ManagerTakeover(ctx, pause.OperationID)
	if err != nil || pending == nil || pending.Phase != "acquire_unknown" || !pending.DispatchStarted || pending.Report != nil {
		t.Fatalf("pending protective pause = %#v, %v", pending, err)
	}
	priorManifest := pause
	predecessor := "takeover_previouspause0001"
	priorManifest.OperationID, priorManifest.PredecessorOperationID = "takeover_releasedresume0001", &predecessor
	priorManifest.Action, priorManifest.HoldState = "resume_manager_and_release_member", "released"
	priorManifest.HoldID, priorManifest.HoldRevision = "hold_releasedresume0001", 2
	priorManifest.PolicyRevision, priorManifest.RunGeneration = 4, 4
	encodedPrior, _ := json.Marshal(priorManifest)
	var priorReport model.InsightsTakeoverReportV1
	if err := json.Unmarshal(encodedPrior, &priorReport); err != nil {
		t.Fatal(err)
	}
	priorReport.Status = "ready"
	priorReport.PendingInput = model.InsightsTakeoverPendingInputV1{State: "none_pending"}
	priorReport.ReceiptDigest = "sha256:" + strings.Repeat("b", 64)
	prior := state.LocalManagerTakeover{Manifest: priorManifest, Phase: "released", DispatchStarted: true, Report: &priorReport}
	if err := journey.store.PutManagerTakeover(ctx, prior); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Minute)
	journey.fresh.ValidUntil = clock.Add(time.Minute)
	journey.manifest.InsightsManagerPolicies = []model.InsightsManagerPolicyManifestV1{journey.fresh}
	pause.ValidUntil = journey.fresh.ValidUntil
	journey.manifest.InsightsTakeovers = []model.InsightsTakeoverManifestV1{pause}
	// Keep the existing Reconciler/Coordinator journey and real persisted local
	// authority. Managed service enrollment is outside this recovery regression.
	journey.manifest.SetupOperations, journey.manifest.ManagedServices = nil, nil
	journey.reconciler.ManagedControl, journey.reconciler.ManagedRuntime, journey.reconciler.ManagedCatalog = nil, nil, nil
	journey.reconciler.ContinuityControl = nil
	helper.actions, helper.manifests = nil, nil
	return &pendingPauseJourney{managerPolicyJourney: journey, helper: helper, pending: *pending, prior: prior}
}

func (journey *pendingPauseJourney) assertRetained(t *testing.T, expected state.LocalManagerTakeover) {
	t.Helper()
	stored, err := journey.store.ManagerTakeover(context.Background(), expected.Manifest.OperationID)
	if err != nil || stored == nil || !reflect.DeepEqual(*stored, expected) {
		t.Fatalf("retained operation changed: got %#v, want %#v, error %v", stored, expected, err)
	}
}

func TestReconcileRenewsPendingPauseBeforeRecovery(t *testing.T) {
	t.Run("same pending Pause renews before exact reconciliation without acquire replay", func(t *testing.T) {
		journey := newPendingPauseJourney(t)
		ctx := context.Background()
		if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
			t.Fatalf("fresh same-operation manifest could not recover the expired pending protective Pause: %v", err)
		}
		if !reflect.DeepEqual(journey.helper.actions, []string{"reconcile_intervention_hold"}) ||
			len(journey.helper.manifests) != 1 || !reflect.DeepEqual(journey.helper.manifests[0], journey.manifest.InsightsTakeovers[0]) {
			t.Fatalf("recovery changed authority or replayed acquire: actions %#v manifests %#v", journey.helper.actions, journey.helper.manifests)
		}
		stored, err := journey.store.ManagerTakeover(ctx, journey.pending.Manifest.OperationID)
		if err != nil || stored == nil || stored.Phase != "ready" || stored.Report == nil || stored.Report.Status != "ready" ||
			!reflect.DeepEqual(stored.Manifest, journey.manifest.InsightsTakeovers[0]) {
			t.Fatalf("renewed protective Pause = %#v, %v", stored, err)
		}
		journey.assertRetained(t, journey.prior)
		if retained, err := journey.store.ManagerTakeovers(ctx); err != nil || len(retained) != 2 {
			t.Fatalf("reconciliation changed operation history: %#v, %v", retained, err)
		}
		if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil || len(journey.helper.actions) != 1 {
			t.Fatalf("same completed manifest repeated helper work: %v %#v", err, journey.helper.actions)
		}
		if revision, err := journey.store.Revision(ctx); err != nil || revision != journey.manifest.DesiredRevision {
			t.Fatalf("completed recovery revision = %d, %v", revision, err)
		}
	})
	for _, test := range []struct {
		name   string
		change func(*pendingPauseJourney)
	}{
		{"changed source", func(j *pendingPauseJourney) {
			j.manifest.InsightsTakeovers[0].Source.NativeSessionID = "ses_foreignpending0001"
		}},
		{"changed member", func(j *pendingPauseJourney) {
			j.manifest.InsightsTakeovers[0].Target.MemberID = "tmem_foreignpending0001"
		}},
		{"changed policy revision", func(j *pendingPauseJourney) { j.manifest.InsightsTakeovers[0].PolicyRevision++ }},
		{"different operation", func(j *pendingPauseJourney) {
			j.manifest.InsightsTakeovers[0].OperationID = "takeover_foreignpending0001"
		}},
		{"expired renewal", func(j *pendingPauseJourney) {
			j.manifest.InsightsTakeovers[0].ValidUntil = j.coordinator.Now().Add(-time.Second)
		}},
		{"unbounded renewal", func(j *pendingPauseJourney) {
			j.manifest.InsightsTakeovers[0].ValidUntil = j.coordinator.Now().Add(121 * time.Second)
		}},
		{"changed fresh Off policy", func(j *pendingPauseJourney) { j.manifest.InsightsManagerPolicies[0].RunGeneration++ }},
		{"wrong server manifest", func(j *pendingPauseJourney) { j.manifest.ServerID = "srv_foreignpending0001" }},
		{"invalid full manifest", func(j *pendingPauseJourney) { j.manifest.ImageDigest = "mutable:latest" }},
		{"local service no longer ready", func(j *pendingPauseJourney) {
			if err := j.store.UpdateManagedService(context.Background(), j.pending.Manifest.Source.ServiceRegistrationID, "failed", nil, "failed"); err != nil {
				t.Fatal(err)
			}
		}},
		{"local Work binding changed", func(j *pendingPauseJourney) {
			row, err := j.store.ContinuityRegistration(context.Background(), *j.pending.Manifest.Target.BindingID)
			if err != nil || row == nil {
				t.Fatalf("registration = %#v, %v", row, err)
			}
			row.Manifest.Binding.BindingRevision++
			if err := j.store.PutContinuityRegistration(context.Background(), *row); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			journey := newPendingPauseJourney(t)
			test.change(journey)
			if err := journey.reconciler.Reconcile(context.Background(), journey.manifest); err == nil {
				t.Fatal("mismatched or stale authority renewed the pending operation")
			}
			journey.assertRetained(t, journey.pending)
			journey.assertRetained(t, journey.prior)
			if _, after := journey.revisions(t); after != journey.priorRevision {
				t.Fatalf("rejected renewal advanced applied revision: %d", after)
			}
			for _, seen := range journey.helper.manifests {
				if !reflect.DeepEqual(seen, journey.pending.Manifest) {
					t.Fatalf("rejected renewal crossed helper boundary: %#v", seen)
				}
			}
		})
	}
	t.Run("fresh renewal preserves a later recovery failure and pending identity", func(t *testing.T) {
		journey := newPendingPauseJourney(t)
		journey.helper.reconcileErr = errors.New("independent native hold lookup remains unknown")
		err := journey.reconciler.Reconcile(context.Background(), journey.manifest)
		if err == nil || !strings.Contains(err.Error(), "independent native hold lookup remains unknown") {
			t.Fatalf("genuine recovery failure was ignored: %v", err)
		}
		expected := journey.pending
		expected.Manifest.ValidUntil = journey.manifest.InsightsTakeovers[0].ValidUntil
		journey.assertRetained(t, expected)
		journey.assertRetained(t, journey.prior)
		if _, after := journey.revisions(t); after != journey.priorRevision {
			t.Fatalf("failed recovery advanced revision: %d", after)
		}
	})
	t.Run("pending Resume lease is never renewed", func(t *testing.T) {
		journey := newPendingPauseJourney(t)
		ctx := context.Background()
		settled := journey.pending
		settled.Phase = "ready"
		if err := journey.store.PutManagerTakeover(ctx, settled); err != nil {
			t.Fatal(err)
		}
		resume := journey.pending.Manifest
		predecessor := resume.OperationID
		resume.OperationID, resume.PredecessorOperationID = "takeover_pendingresume0001", &predecessor
		resume.Action, resume.HoldState, resume.HoldRevision = "resume_manager_and_release_member", "released", 2
		pending := state.LocalManagerTakeover{Manifest: resume, Phase: "release_unknown", DispatchStarted: true}
		if err := journey.store.PutManagerTakeover(ctx, pending); err != nil {
			t.Fatal(err)
		}
		resume.ValidUntil = journey.fresh.ValidUntil
		journey.manifest.InsightsTakeovers = []model.InsightsTakeoverManifestV1{resume}
		err := journey.reconciler.Reconcile(ctx, journey.manifest)
		if err == nil || !strings.Contains(err.Error(), "helper refused expired persisted takeover lease") {
			t.Fatalf("expired pending Resume was renewed or its failure ignored: %v", err)
		}
		// Preserve the existing error-phase classification in dispatchTakeover;
		// this change must not renew or otherwise rewrite Resume authority.
		expected := pending
		expected.Phase = "acquire_unknown"
		journey.assertRetained(t, expected)
		journey.assertRetained(t, settled)
		journey.assertRetained(t, journey.prior)
		if !reflect.DeepEqual(journey.helper.actions, []string{"reconcile_intervention_hold"}) ||
			len(journey.helper.manifests) != 1 || !reflect.DeepEqual(journey.helper.manifests[0], pending.Manifest) {
			t.Fatalf("pending Resume crossed recovery with a changed lease: %#v %#v", journey.helper.actions, journey.helper.manifests)
		}
	})
	t.Run("unrelated unknown review stays fatal and untouched", func(t *testing.T) {
		journey := newPendingPauseJourney(t)
		ctx := context.Background()
		run := state.LocalManagerRun{Manifest: managerReviewManifest(journey.fresh.ValidUntil),
			Phase: "execution_unknown", DispatchStarted: true}
		if err := journey.store.PutManagerRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		err := journey.reconciler.Reconcile(ctx, journey.manifest)
		if err == nil || !strings.Contains(err.Error(), "recover manager operations: manager recovery finding missing") {
			t.Fatalf("unrelated unknown review recovery error changed: %v", err)
		}
		stored, err := journey.store.ManagerRun(ctx, run.Manifest.RunID)
		if err != nil || stored == nil || !reflect.DeepEqual(*stored, run) {
			t.Fatalf("unrelated unknown review changed: %#v %v", stored, err)
		}
		expected := journey.pending
		expected.Manifest.ValidUntil = journey.fresh.ValidUntil
		journey.assertRetained(t, expected)
		journey.assertRetained(t, journey.prior)
		if len(journey.helper.actions) != 0 {
			t.Fatalf("lookup/actions bypassed unrelated recovery failure: %#v", journey.helper.actions)
		}
		if _, after := journey.revisions(t); after != journey.priorRevision {
			t.Fatalf("unrelated failed recovery advanced revision: %d", after)
		}
	})
}
