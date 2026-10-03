package reconcile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/manager"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// policyStubControl and policyStubHelper satisfy the manager coordinator's
// action-bearing dependencies without granting any authority: the early policy
// apply must never need them.
type policyStubControl struct {
	canonical *model.InsightsManagerTargetEnvelopeV1
}

func (policyStubControl) ReserveInsightsManagerReview(context.Context, model.InsightsManagerReservationRequestV1) (model.InsightsManagerReservationV1, error) {
	return model.InsightsManagerReservationV1{}, errors.New("stub control has no review authority")
}

func (policyStubControl) SubmitInsightsManagerRunReport(context.Context, model.InsightsManagerRunReportV1) (model.InsightsManagerActivityV1, error) {
	return model.InsightsManagerActivityV1{}, errors.New("stub control has no run authority")
}

func (control policyStubControl) GetInsightsManagerTarget(_ context.Context, findingID string, registeredSourceID string) (model.InsightsManagerTargetEnvelopeV1, error) {
	if control.canonical != nil && control.canonical.FindingID == findingID && control.canonical.Source.RegisteredSourceID == registeredSourceID {
		return *control.canonical, nil
	}
	return model.InsightsManagerTargetEnvelopeV1{}, errors.New("stub control has no canonical target read")
}

type policyStubHelper struct{}

func (policyStubHelper) ExecManager(context.Context, string, []byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("stub helper has no execution authority")
}

// failingRestoreControl aborts the pass at the continuation/restore step, after
// the early policy apply and before the end-of-pass Manager.Apply.
type failingRestoreControl struct{ applyErr error }

func (control *failingRestoreControl) Recover(context.Context) error { return nil }

func (control *failingRestoreControl) RecoverCurrent(ctx context.Context, _ model.Manifest) error {
	return control.Recover(ctx)
}

func (control *failingRestoreControl) Apply(context.Context, []model.ContinuationManifestV1, []model.RestoreManifestV1) error {
	return control.applyErr
}

func (control *failingRestoreControl) ApplyReleases(context.Context, []model.ContinuationReleaseManifestV1) error {
	return nil
}

func (control *failingRestoreControl) Reports(context.Context) ([]model.ContinuationReportV1, []model.RestoreReportV1, error) {
	return nil, nil, nil
}

func (control *failingRestoreControl) ReportsCurrent(ctx context.Context, _ model.Manifest) ([]model.ContinuationReportV1, []model.RestoreReportV1, error) {
	return control.Reports(ctx)
}

func (control *failingRestoreControl) ReleaseReports(context.Context) ([]model.ContinuationReleaseReportV1, error) {
	return nil, nil
}

func (control *failingRestoreControl) ReleaseReportsCurrent(ctx context.Context, _ model.Manifest) ([]model.ContinuationReleaseReportV1, error) {
	return control.ReleaseReports(ctx)
}

func managerPolicyManifest(sandboxID string, generation, revision, runGeneration int64, validUntil time.Time) model.InsightsManagerPolicyManifestV1 {
	return model.InsightsManagerPolicyManifestV1{
		FormatVersion: 1, SandboxID: sandboxID, SandboxGeneration: generation, PolicyRevision: revision, Mode: "recommend",
		AllowedRules: []string{"repeated_identical_failure@1"}, DailyRunLimit: 30, DailyInputTokenLimit: 480000, DailyOutputTokenLimit: 60000,
		EffectiveLimits: model.InsightsManagerEffectiveLimitsV1{
			SandboxDailyRuns: 30, SandboxHourlyRuns: 10, SessionRuns24h: 3, SessionCooldownSeconds: 300,
			ServerConcurrentRuns: 2, ServerHourlyStarts: 20, PerRunModelRequests: 2, PerRunInputTokens: 16000, PerRunOutputTokens: 2000,
		},
		ManagerProfile: model.InsightsManagerProfileV1{
			ProfileID: "warpmetal-insights-manager", ProfileRevision: 1,
			ProfileDigest: "sha256:4ea596774c5b66bfc395bda3f6c00765d4e89e22f270235a327872b3760e5e17",
		},
		ValidUntil: validUntil, RunGeneration: runGeneration,
	}
}

func managerReviewManifest(validUntil time.Time) model.InsightsManagerReviewManifestV1 {
	return model.InsightsManagerReviewManifestV1{
		FormatVersion: 1, ReservationID: "reservation_managerpolicy0001", RunID: "run_managerpolicy0001", Manual: true,
		FindingID: "finding_managerpolicy0001", FindingRevision: 1, PolicyRevision: 3,
		RuleID: "repeated_identical_failure@1", RecipeID: "inspect_first_failure@1",
		ProviderRouteDigest: "sha256:" + strings.Repeat("c", 64),
		ManagerProfile: model.InsightsManagerProfileV1{
			ProfileID: "warpmetal-insights-manager", ProfileRevision: 1, ProfileDigest: "sha256:" + strings.Repeat("d", 64),
		},
		Source: model.InsightsManagerSourceV1{
			RegisteredSourceID: "source_managerpolicy0001", WorkspaceEpoch: "epoch_managerpolicy0001",
			NativeSessionID: "ses_managerpolicy0001", ServiceRegistrationID: "service_managerpolicy0001",
			ServiceGeneration: 3, SandboxGeneration: 2, ProfileRevision: 1, InstructionRevision: 1,
		},
		Target:     model.InsightsManagerTargetV1{TeamID: "team_managedservice0001", MemberID: "tmem_managedservice0001"},
		Budget:     model.InsightsManagerBudgetV1{ModelRequests: 1, InputTokens: 1, OutputTokens: 1},
		ValidUntil: validUntil,
	}
}

// seedManagerPolicyAuthority writes the exact manager authority a policy apply
// re-derives from: one capability whose source is currently unavailable, plus
// the previously applied (expired) policy lease.
func seedManagerPolicyAuthority(t *testing.T, store *state.Store, sandboxID string, generation int64, now func() time.Time) (model.InsightsManagerPolicyManifestV1, model.InsightsManagerPolicyManifestV1) {
	t.Helper()
	ctx := context.Background()
	reason := "service_failed"
	if err := store.PutContinuitySource(ctx, state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: "source_managerpolicy0001", ServiceRegistrationID: "service_managerpolicy0001",
			ServiceGeneration: 3, ProjectID: "project_managerpolicy0001", SandboxID: sandboxID, SandboxGeneration: generation,
			WorkspaceEpoch: "epoch_managerpolicy0001", NativeSessionID: "ses_managerpolicy0001",
			NativeProjectID: strings.Repeat("a", 40), NativeLocationDigest: "sha256:" + strings.Repeat("b", 64),
			ScopeRevision: 1, Role: "worker", ProfileRevision: 1, InstructionRevision: 1,
			Availability: "unavailable", Reason: &reason, LastObservedAt: now().Add(-time.Minute),
		},
		Root: t.TempDir(), Instance: "default", Lifecycle: "stopped", LifecycleRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutManagerCapability(ctx, state.LocalManagerCapability{
		RegisteredSourceID: "source_managerpolicy0001", ServiceRegistrationID: "service_managerpolicy0001",
		ServiceGeneration: 3, WorkspaceEpoch: "epoch_managerpolicy0001", NativeSessionID: "ses_managerpolicy0001",
		SandboxID: sandboxID, SandboxGeneration: generation, ProfileRevision: 1, InstructionRevision: 1,
		ProviderID: "openai", ModelID: "gpt-6-astra", NativeProtocol: "openai_chat", Protocol: "opencode-supervisor/1",
		ProviderRouteDigest: "sha256:" + strings.Repeat("c", 64),
		ManagerProfile: model.InsightsManagerProfileV1{
			ProfileID: "warpmetal-insights-manager", ProfileRevision: 1, ProfileDigest: "sha256:" + strings.Repeat("d", 64),
		},
		RecipeIDs: []string{"inspect_first_failure@1"}, Available: true,
	}); err != nil {
		t.Fatal(err)
	}
	fresh := managerPolicyManifest(sandboxID, generation, 3, 3, now().Add(time.Minute))
	expired := managerPolicyManifest(sandboxID, generation, 3, 3, now().Add(-10*time.Minute))
	if err := store.PutManagerPolicy(ctx, state.LocalManagerPolicy{
		Manifest: expired,
		Report: model.InsightsManagerPolicyReportV1{
			FormatVersion: 1, SandboxID: sandboxID, SandboxGeneration: generation, PolicyRevision: 3, RunGeneration: 3,
			Status: "applied", Recommend: model.InsightsManagerCapabilityV1{Available: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return fresh, expired
}

type managerPolicyJourney struct {
	fixture       producerFixture
	fresh         model.InsightsManagerPolicyManifestV1
	expired       model.InsightsManagerPolicyManifestV1
	store         *state.Store
	databasePath  string
	imagePath     string
	control       *fakeManagedControl
	coordinator   *manager.Coordinator
	reconciler    *Reconciler
	manifest      model.Manifest
	priorRevision int64
}

func newManagerPolicyJourney(t *testing.T) *managerPolicyJourney {
	t.Helper()
	fixture := loadProducerFixture(t)
	fixture.ServiceManifest.Identity.SandboxGeneration = 2
	fixture.SetupManifest.SandboxGeneration = 2
	fixture.InstructionRequest.SandboxGeneration = 2
	fixture.EnrollmentRequest.SandboxGeneration = 2
	sandboxID := fixture.SetupManifest.SandboxID
	// The fixture's enrollment/instruction windows are anchored to its own date.
	now := func() time.Time { return time.Date(2026, 9, 27, 17, 0, 30, 0, time.UTC) }
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	seedReadyProfile(t, store, fixture.SetupManifest)
	// The documented Workspaces.Ensure layout: the per-sandbox workspace image
	// file next to the mountpoint anchor the catalog attests. The catalog binds
	// the image's durable identity when the project record is created, so every
	// remount journey below runs against a genuinely recorded backing image.
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
		Anchor: anchor, ServerID: fixture.ServiceManifest.Identity.ServerID, TeamID: fixture.ServiceManifest.Identity.TeamID,
		MemberID: fixture.ServiceManifest.Identity.MemberID, SandboxID: sandboxID, SandboxGeneration: 2,
		ServiceRegistrationID: fixture.ServiceManifest.Identity.ServiceRegistrationID,
		AllocationDigest:      fixture.WorkspaceRequestManifest.AllocationDigest, ConfigDigest: fixture.ServiceManifest.ConfigDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.ServiceManifest.Workspace.SelectionID = workspace.Report.SelectionID
	fixture.ServiceManifest.Workspace.ProjectID = workspace.Report.ProjectID
	fixture.ServiceManifest.Workspace.WorkspaceEpoch = workspace.Report.WorkspaceEpoch
	fixture.ServiceManifest.Workspace.RootAttestation = workspace.Report.RootAttestation
	fresh, expired := seedManagerPolicyAuthority(t, store, sandboxID, 2, now)
	control := &fakeManagedControl{fixture: fixture}
	runtime := &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture}
	coordinator := &manager.Coordinator{Store: store, Control: policyStubControl{}, Helper: policyStubHelper{}, Now: now}
	reconciler := &Reconciler{
		Store: store, Engine: &contractEngine{}, Workspaces: &contractWorkspaces{},
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		HostCapacity: model.Resources{CPUMillicores: 2000, MemoryMiB: 4096, WorkspaceDiskGiB: 20, PIDs: 128},
		ServerID:     fixture.ServiceManifest.Identity.ServerID, Now: now,
		ContinuityControl: &continuity.Coordinator{Store: store, Now: now},
		ManagedCatalog:    catalog, ManagedControl: control, ManagedRuntime: runtime, Manager: coordinator,
	}
	manifest := model.Manifest{
		ServerID: reconciler.ServerID, DesiredRevision: 57, Capacity: reconciler.HostCapacity,
		ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
		Sandboxes: []model.Sandbox{{
			ID: sandboxID, Name: "manager-service", DesiredState: "running", Generation: 2, Lifetime: "persistent",
			Resources: model.Resources{CPUMillicores: 1000, MemoryMiB: 1024, WorkspaceDiskGiB: 2, PIDs: 64},
		}},
		SetupOperations:         []model.SetupOperation{fixture.SetupManifest},
		ManagedServices:         []model.ManagedServiceV1{fixture.ServiceManifest},
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fresh},
	}
	prior, err := store.Revision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &managerPolicyJourney{fixture: fixture, fresh: fresh, expired: expired, store: store, databasePath: databasePath,
		imagePath: imagePath, control: control, coordinator: coordinator, reconciler: reconciler, manifest: manifest, priorRevision: prior}
}

func (journey *managerPolicyJourney) storedPolicy(t *testing.T) state.LocalManagerPolicy {
	t.Helper()
	stored, err := journey.store.ManagerPolicy(context.Background(), journey.fresh.SandboxID)
	if err != nil || stored == nil {
		t.Fatalf("stored manager policy = %#v, %v", stored, err)
	}
	return *stored
}

func (journey *managerPolicyJourney) revisions(t *testing.T) (int64, int64) {
	t.Helper()
	revision, err := journey.store.Revision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return journey.priorRevision, revision
}

// TestReconcileAppliesFreshManagerPolicyBeforeServiceEnrollmentFailure is the
// paired .40 -> .41 journey: a freshly fetched recommend policy is followed by
// an authority-exact managed-service enrollment failure. On .40 the stored
// policy lease stayed expired and the report derived policy_expired; on .41 the
// lease refreshes while Reconcile still returns the same service error,
// SetRevision does not advance, and reviews/takeovers/actions stay untouched.
// Clearing the failure then proves the existing end-of-pass apply and
// SetRevision complete once.
func TestReconcileAppliesFreshManagerPolicyBeforeServiceEnrollmentFailure(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	ctx := context.Background()
	journey.control.enrollErr = errors.New("managed workspace is unavailable")

	err := journey.reconciler.Reconcile(ctx, journey.manifest)
	if err == nil || !strings.Contains(err.Error(), "apply managed services: managed service "+journey.fixture.ServiceManifest.Identity.ServiceRegistrationID) {
		t.Fatalf("managed-service enrollment failure was not preserved: %v", err)
	}
	if !strings.Contains(err.Error(), "managed workspace is unavailable") {
		t.Fatalf("service failure cause was not preserved: %v", err)
	}
	stored := journey.storedPolicy(t)
	if !stored.Manifest.ValidUntil.Equal(journey.fresh.ValidUntil) {
		t.Fatalf("fresh policy lease was not applied early: stored %s, fetched %s", stored.Manifest.ValidUntil, journey.fresh.ValidUntil)
	}
	if stored.Manifest.PolicyRevision != journey.fresh.PolicyRevision || stored.Manifest.RunGeneration != journey.fresh.RunGeneration ||
		stored.Manifest.SandboxGeneration != journey.fresh.SandboxGeneration || stored.Manifest.Mode != "recommend" {
		t.Fatalf("policy fences drifted: %#v", stored.Manifest)
	}
	if prior, after := journey.revisions(t); after != prior {
		t.Fatalf("failed pass advanced the applied revision %d -> %d", prior, after)
	}
	if runs, err := journey.store.ManagerRuns(ctx); err != nil || len(runs) != 0 {
		t.Fatalf("action-bearing manager work applied during a failed pass: %#v %v", runs, err)
	}
	if takeovers, err := journey.store.ManagerTakeovers(ctx); err != nil || len(takeovers) != 0 {
		t.Fatalf("takeover work applied during a failed pass: %#v %v", takeovers, err)
	}
	policies, runs, takeovers, err := journey.coordinator.Reports(ctx, nil)
	if err != nil || len(policies) != 1 || len(runs) != 0 || len(takeovers) != 0 {
		t.Fatalf("report derivation = %#v %#v %#v %v", policies, runs, takeovers, err)
	}
	if policies[0].Recommend.Available || policies[0].Recommend.Reason == nil || *policies[0].Recommend.Reason != "source_unavailable" {
		t.Fatalf("fresh policy lease did not yield the fail-closed source reason: %#v", policies[0].Recommend)
	}
	if len(policies[0].RecommendCapabilities) != 1 || policies[0].RecommendCapabilities[0].Available ||
		policies[0].RecommendCapabilities[0].Reason == nil || *policies[0].RecommendCapabilities[0].Reason != "source_unavailable" {
		t.Fatalf("capability derivation drifted: %#v", policies[0].RecommendCapabilities)
	}
	// Idempotent duplicate policy apply: a second failed pass restores the same
	// stored manifest and re-derives the same report.
	firstDigest := stored.Report.ReceiptDigest
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err == nil {
		t.Fatal("second failed pass unexpectedly succeeded")
	}
	replayed := journey.storedPolicy(t)
	if !replayed.Manifest.ValidUntil.Equal(stored.Manifest.ValidUntil) || replayed.Report.ReceiptDigest != firstDigest {
		t.Fatalf("duplicate policy apply was not idempotent: %#v vs %#v", replayed, stored)
	}
	// Clearing the service failure lets the end-of-pass apply and SetRevision
	// complete exactly once.
	journey.control.enrollErr = nil
	if err := journey.reconciler.Reconcile(ctx, journey.manifest); err != nil {
		t.Fatalf("cleared-failure pass did not complete: %v", err)
	}
	if _, completed := journey.revisions(t); completed != journey.manifest.DesiredRevision {
		t.Fatalf("completed pass did not advance the applied revision to %d: %d", journey.manifest.DesiredRevision, completed)
	}
	if settled := journey.storedPolicy(t); !settled.Manifest.ValidUntil.Equal(journey.fresh.ValidUntil) {
		t.Fatalf("completed pass lost the fresh policy lease: %s", settled.Manifest.ValidUntil)
	}
	service, err := journey.store.ManagedService(ctx, journey.fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if err != nil || service == nil || service.Phase == "failed" {
		t.Fatalf("service did not recover on the completed pass: %#v %v", service, err)
	}
}

// TestReconcilePreservesPolicyAuthorityAndLaterStepAborts covers the required
// negatives: an invalid/stale policy authority fails the pass before any
// service work; a valid-but-expired review stays unapplied even when the pass
// completes its later steps; a non-service later-step abort keeps its own error
// while the fresh policy lease is already stored.
func TestReconcilePreservesPolicyAuthorityAndLaterStepAborts(t *testing.T) {
	t.Run("invalid policy authority fails before service work", func(t *testing.T) {
		journey := newManagerPolicyJourney(t)
		ctx := context.Background()
		journey.manifest.InsightsManagerPolicies = []model.InsightsManagerPolicyManifestV1{
			managerPolicyManifest(journey.fresh.SandboxID, 3, 3, 3, journey.fresh.ValidUntil),
		}
		err := journey.reconciler.Reconcile(ctx, journey.manifest)
		if err == nil || !strings.Contains(err.Error(), "invalid insights manager policy") {
			t.Fatalf("stale policy authority was not refused: %v", err)
		}
		if len(journey.control.enrollments) != 0 {
			t.Fatalf("service work ran after the policy authority failure: %#v", journey.control.enrollments)
		}
		if stored := journey.storedPolicy(t); !stored.Manifest.ValidUntil.Equal(journey.expired.ValidUntil) {
			t.Fatalf("refused policy authority changed the stored lease: %s", stored.Manifest.ValidUntil)
		}
		if prior, after := journey.revisions(t); after != prior {
			t.Fatalf("refused pass advanced the applied revision: %d -> %d", prior, after)
		}
	})

	t.Run("regressed policy revision fails at the early apply before service work", func(t *testing.T) {
		journey := newManagerPolicyJourney(t)
		ctx := context.Background()
		journey.manifest.InsightsManagerPolicies = []model.InsightsManagerPolicyManifestV1{
			managerPolicyManifest(journey.fresh.SandboxID, 2, 2, 2, journey.fresh.ValidUntil),
		}
		err := journey.reconciler.Reconcile(ctx, journey.manifest)
		if err == nil || !strings.Contains(err.Error(), "apply manager policies:") ||
			!strings.Contains(err.Error(), "manager immutable identity conflict") {
			t.Fatalf("regressed policy authority was not refused at the early apply: %v", err)
		}
		if len(journey.control.enrollments) != 0 {
			t.Fatalf("service work ran after the early policy refusal: %#v", journey.control.enrollments)
		}
		if stored := journey.storedPolicy(t); !stored.Manifest.ValidUntil.Equal(journey.expired.ValidUntil) || stored.Manifest.PolicyRevision != 3 {
			t.Fatalf("refused policy regression changed the stored lease: %#v", stored.Manifest)
		}
		if prior, after := journey.revisions(t); after != prior {
			t.Fatalf("refused pass advanced the applied revision: %d -> %d", prior, after)
		}
	})

	t.Run("expired review stays unapplied while the fresh lease is stored", func(t *testing.T) {
		journey := newManagerPolicyJourney(t)
		ctx := context.Background()
		journey.manifest.InsightsManagerReviews = []model.InsightsManagerReviewManifestV1{
			managerReviewManifest(journey.reconciler.Now().Add(-time.Minute)),
		}
		journey.control.enrollErr = errors.New("managed workspace is unavailable")
		err := journey.reconciler.Reconcile(ctx, journey.manifest)
		if err == nil || !strings.Contains(err.Error(), "apply managed services:") {
			t.Fatalf("service failure was not preserved with a review present: %v", err)
		}
		if runs, err := journey.store.ManagerRuns(ctx); err != nil || len(runs) != 0 {
			t.Fatalf("early apply touched an action-bearing review: %#v %v", runs, err)
		}
		if stored := journey.storedPolicy(t); !stored.Manifest.ValidUntil.Equal(journey.fresh.ValidUntil) {
			t.Fatalf("fresh lease was not stored before the service failure: %s", stored.Manifest.ValidUntil)
		}
		// With the service healthy the pass reaches the end-of-pass apply: the
		// expired review is refused there and everything else stays intact.
		journey.control.enrollErr = nil
		err = journey.reconciler.Reconcile(ctx, journey.manifest)
		if err == nil || !strings.Contains(err.Error(), "apply manager manifest:") ||
			!strings.Contains(err.Error(), "manager review authority expired") {
			t.Fatalf("expired review was not refused at the end-of-pass apply: %v", err)
		}
		if runs, err := journey.store.ManagerRuns(ctx); err != nil || len(runs) != 0 {
			t.Fatalf("expired review was applied: %#v %v", runs, err)
		}
		if stored := journey.storedPolicy(t); !stored.Manifest.ValidUntil.Equal(journey.fresh.ValidUntil) {
			t.Fatalf("fresh lease was lost behind the end-of-pass review refusal: %s", stored.Manifest.ValidUntil)
		}
		if prior, after := journey.revisions(t); after != prior {
			t.Fatalf("review-refused pass advanced the applied revision: %d -> %d", prior, after)
		}
	})

	t.Run("non-service later step abort keeps its error and the fresh lease", func(t *testing.T) {
		journey := newManagerPolicyJourney(t)
		ctx := context.Background()
		restoreErr := errors.New("restore transport unavailable")
		journey.reconciler.ContinuationRestore = &failingRestoreControl{applyErr: restoreErr}
		err := journey.reconciler.Reconcile(ctx, journey.manifest)
		if err == nil || !strings.Contains(err.Error(), "apply continuation/restore manifest: restore transport unavailable") {
			t.Fatalf("later-step abort error was not preserved: %v", err)
		}
		if stored := journey.storedPolicy(t); !stored.Manifest.ValidUntil.Equal(journey.fresh.ValidUntil) {
			t.Fatalf("fresh lease was not stored before the later-step abort: %s", stored.Manifest.ValidUntil)
		}
		if runs, err := journey.store.ManagerRuns(ctx); err != nil || len(runs) != 0 {
			t.Fatalf("later-step abort executed action-bearing work: %#v %v", runs, err)
		}
		if prior, after := journey.revisions(t); after != prior {
			t.Fatalf("later-step abort advanced the applied revision: %d -> %d", prior, after)
		}
	})
}
