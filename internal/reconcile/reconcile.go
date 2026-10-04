package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type Workspaces interface {
	Ensure(context.Context, string, int) (string, error)
	Destroy(context.Context, string) error
}

type Sessions interface {
	TerminateGrant(context.Context, string) error
	TerminateSandbox(context.Context, string) error
}

type ContinuityRecovery interface {
	Recover(context.Context) error
	RecoverLocalSafety(context.Context) error
	RecoverCurrent(context.Context, model.Manifest) error
}

type ContinuityControl interface {
	Apply(context.Context, model.Manifest) error
	// Acknowledge is the pre-failure acknowledgement phase: it applies only
	// the continuity registration state the same fresh manifest carries and
	// retires only the terminal operation echoes that manifest no longer
	// carries, before any failure-prone managed-service enrollment can abort
	// the pass.
	Acknowledge(context.Context, model.Manifest) error
	Reports(context.Context) ([]model.ContinuitySourceReportV1, []model.ContinuityRegistrationReportV1, []model.ContinuityOperationReportV1, error)
	ReportsCurrent(context.Context, model.Manifest) ([]model.ContinuitySourceReportV1, []model.ContinuityRegistrationReportV1, []model.ContinuityOperationReportV1, error)
}

type ContinuationRestoreControl interface {
	Recover(context.Context) error
	RecoverCurrent(context.Context, model.Manifest) error
	Apply(context.Context, []model.ContinuationManifestV1, []model.RestoreManifestV1) error
	ApplyReleases(context.Context, []model.ContinuationReleaseManifestV1) error
	Reports(context.Context) ([]model.ContinuationReportV1, []model.RestoreReportV1, error)
	ReportsCurrent(context.Context, model.Manifest) ([]model.ContinuationReportV1, []model.RestoreReportV1, error)
	ReleaseReports(context.Context) ([]model.ContinuationReleaseReportV1, error)
	ReleaseReportsCurrent(context.Context, model.Manifest) ([]model.ContinuationReleaseReportV1, error)
}

type ContinuationHandoffControl interface {
	// RecoverHandoffsCurrent is the authority-bound recovery the production
	// reconciler always uses: only the operations the fully validated current
	// authority carries as typed intent are recovered. RecoverHandoffs remains
	// the standalone controller surface for direct tests.
	RecoverHandoffsCurrent(context.Context, model.Manifest) error
	RecoverHandoffs(context.Context) error
	ApplyHandoffs(context.Context, []model.ContinuationHandoffManifestV1) error
	ApplyHandoffTargetRegistrations(context.Context, []model.ContinuityRegistrationV1) error
	ApplyHandoffReleases(context.Context, []model.ContinuationHandoffReleaseManifestV1) error
	HandoffReports(context.Context) ([]model.ContinuationHandoffReportV1, []model.ContinuationHandoffReleaseReportV1, error)
	HandoffReportsCurrent(context.Context, model.Manifest) ([]model.ContinuationHandoffReportV1, []model.ContinuationHandoffReleaseReportV1, error)
}

type ManagedWorkspaceCatalog interface {
	EnsureDefault(context.Context, workspacecatalog.DefaultProjectRequest) (workspacecatalog.RegisteredProject, error)
	Resolve(context.Context, workspacecatalog.ResolveProjectRequest) (workspacecatalog.RegisteredProject, error)
	Reports(context.Context) ([]model.ProjectCatalogReportV1, error)
	// ReobserveRemountedRoots re-attests host-private records whose live root
	// identity differs solely by the loop device of the documented workspace
	// remount, before any managed service resolves its project.
	ReobserveRemountedRoots(context.Context) error
}

type ManagedServiceControl interface {
	ManagedServiceEnrollment(context.Context, string, model.ManagedServiceFetchRequestV1) (model.ManagedServiceEnrollmentV1, error)
	ManagedServiceInstructions(context.Context, string, model.ManagedServiceFetchRequestV1) (model.ManagedServiceInstructionV1, error)
	ManagedServiceEndpoint() string
}

type ManagedSandboxRuntime interface {
	ExecManagedSupervisor(context.Context, string, containers.ManagedSupervisorAction, []byte) ([]byte, []byte, error)
	ExecManagedWorker(context.Context, string, containers.ManagedWorkerAction, []byte) ([]byte, []byte, error)
}

type InsightCollector interface {
	RunOnce(context.Context) error
}

type CheckpointLifecycle interface {
	Run(context.Context) error
}

type ManagerControl interface {
	RenewPendingTakeovers(context.Context, model.Manifest) error
	Recover(context.Context) error
	ApplyPolicies(context.Context, model.Manifest) error
	ApplyLifecycle(context.Context, model.Manifest) error
	Apply(context.Context, model.Manifest) error
	Reports(context.Context, continuity.StaleSourceSet) ([]model.InsightsManagerPolicyReportV1, []model.InsightsManagerRunReportV1, []model.InsightsTakeoverReportV1, error)
	ReportsCurrent(context.Context, model.Manifest, []model.ContinuitySourceReportV1, continuity.StaleSourceSet) ([]model.InsightsManagerPolicyReportV1, []model.InsightsManagerRunReportV1, []model.InsightsTakeoverReportV1, error)
	GuidanceReports(context.Context) ([]model.InsightsManagerGuidanceV1, error)
}

type managedWorkerExecution struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	idle   bool
}

type Reconciler struct {
	Store               *state.Store
	Engine              containers.Engine
	Workspaces          Workspaces
	Access              access.Renderer
	Sessions            Sessions
	HostCapacity        model.Resources
	ServerID            string
	Now                 func() time.Time
	Continuity          ContinuityRecovery
	ContinuityControl   ContinuityControl
	ContinuationRestore ContinuationRestoreControl
	ContinuationHandoff ContinuationHandoffControl
	ManagedCatalog      ManagedWorkspaceCatalog
	ManagedControl      ManagedServiceControl
	ManagedRuntime      ManagedSandboxRuntime
	Insights            InsightCollector
	ContinuityLifecycle CheckpointLifecycle
	Manager             ManagerControl
	// ManagedExecutionContext is the daemon lifecycle, not a poll/reconcile
	// context. Worker one-shots may outlive one control-plane poll but are
	// cancelled by daemon shutdown and explicit pause/stop policy.
	ManagedExecutionContext context.Context

	mu                sync.Mutex
	authorityMu       sync.Mutex
	currentAuthority  *model.Manifest
	managedWorkerMu   sync.Mutex
	managedExecutions map[string]*managedWorkerExecution
}

// FeedbackManager is the narrow post-Report-ACK automatic manager boundary.
// Manual review, takeover and unrelated recovery remain owned by the ordinary
// heavy Recover/Apply lifecycle path.
type FeedbackManager interface {
	ReconsiderAdmissions(context.Context) error
	DispatchReadyGuidance(context.Context) error
	AdvanceAutomaticRuns(context.Context) error
	AutomaticWorkPending(context.Context) (bool, error)
}

// AutomaticFeedback exposes the narrow automatic boundary of the configured
// manager, when it supports it.
func (r *Reconciler) AutomaticFeedback() (FeedbackManager, bool) {
	value, ok := r.Manager.(FeedbackManager)
	return value, ok
}

// ApplyFeedbackManifest validates a fresh post-ACK manifest under the existing
// reconcile mutex with the full manifest validation and requires its desired
// revision to equal the fully applied store revision. Only current manager
// policies are applied; no lifecycle effects are executed here, so a changed
// or unprocessed lifecycle authority defers to the next ordinary heavy pass.
func (r *Reconciler) ApplyFeedbackManifest(ctx context.Context, manifest model.Manifest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	lastRevision, err := r.Store.Revision(ctx)
	if err != nil {
		return err
	}
	if err := model.ValidateManifest(manifest, r.ServerID, lastRevision); err != nil {
		return err
	}
	if manifest.DesiredRevision != lastRevision {
		return errors.New("feedback manifest revision is not the fully applied authority")
	}
	if r.Manager != nil {
		return r.Manager.ApplyPolicies(ctx, manifest)
	}
	return nil
}

func (r *Reconciler) setCurrentAuthority(manifest model.Manifest) {
	// Proportionate deep snapshot: the authority must never alias the caller's
	// slices, maps or pointers for the lifetime of the process.
	payload, err := json.Marshal(manifest)
	if err != nil {
		return
	}
	var snapshot model.Manifest
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return
	}
	r.authorityMu.Lock()
	defer r.authorityMu.Unlock()
	r.currentAuthority = &snapshot
}

// currentAuthorityManifest returns the last fully validated immutable current
// authority, or an empty authority (empty current arrays) before the first
// valid manifest. Historical stored state is never an authority default.
func (r *Reconciler) currentAuthorityManifest() model.Manifest {
	r.authorityMu.Lock()
	defer r.authorityMu.Unlock()
	if r.currentAuthority == nil {
		return model.Manifest{}
	}
	return *r.currentAuthority
}

// currentManagedServiceTuple is the reviewed strict outgoing service tuple:
// only a stored service whose typed identity, config digest, operation id,
// action revision and observed desired revision match a current authority
// service is emitted. Superseded tuples are omitted; nothing is synthesized.
func currentManagedServiceTuple(authority model.Manifest, stored state.LocalManagedService) bool {
	for _, desired := range authority.ManagedServices {
		if stored.Manifest.OperationID == desired.OperationID &&
			stored.Manifest.ActionRevision == desired.ActionRevision &&
			stored.Manifest.DesiredRevision == desired.DesiredRevision &&
			stored.Manifest.ConfigDigest == desired.ConfigDigest &&
			reflect.DeepEqual(stored.Manifest.Identity, desired.Identity) {
			return true
		}
	}
	return false
}

func (r *Reconciler) Reconcile(ctx context.Context, manifest model.Manifest) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lastRevision, err := r.Store.Revision(ctx)
	if err != nil {
		return err
	}
	if err := model.ValidateManifest(manifest, r.ServerID, lastRevision); err != nil {
		return err
	}
	if !requested(manifest.Sandboxes).Fits(r.HostCapacity) {
		return errors.New("desired sandboxes exceed detected host capacity")
	}
	// One narrow immutable current authority: the fully validated fresh
	// manifest owns every action-recovery and reporting decision of this pass.
	// The last validated process manifest is the fallback owner; before the
	// first valid manifest the authority carries empty current arrays.
	r.setCurrentAuthority(manifest)
	authority := r.currentAuthorityManifest()
	if r.Continuity != nil {
		if err := r.Continuity.RecoverLocalSafety(ctx); err != nil {
			return fmt.Errorf("recover local continuity safety: %w", err)
		}
		if err := r.Continuity.RecoverCurrent(ctx, authority); err != nil {
			return fmt.Errorf("recover continuity operations: %w", err)
		}
	}
	if r.ContinuationRestore != nil {
		if err := r.ContinuationRestore.RecoverCurrent(ctx, authority); err != nil {
			return fmt.Errorf("recover continuation/restore operations: %w", err)
		}
	}
	// A ready continuation handoff whose source or target supervisor probe did
	// not complete is a bounded, retryable condition: its record stays
	// fail-closed and unadvanced, but the probe failure must not abort the
	// manifest, sandbox, managed-service, workspace and report work of this pass
	// (that work is what restores the probe precondition, and the pass still
	// advances the applied revision when everything else succeeds). The
	// dedicated wrapped probe error is returned only when nothing else in the
	// pass could proceed, so it stays visible alongside any unrelated abort.
	var deferredHandoffProbe error
	if r.ContinuationHandoff != nil {
		if err := r.ContinuationHandoff.RecoverHandoffsCurrent(ctx, authority); err != nil {
			var succession *continuity.HandoffSourceSuccessionDeferral
			switch {
			case errors.As(err, &succession):
				// The one owner-authorized monotonic succession is deferred
				// exactly like the handoff-probe condition, but only when the
				// same fresh authenticated, schema-valid manifest carries the
				// byte-for-field effective successor registration for that
				// binding. Every other shape keeps the existing fatal recovery
				// error.
				if !r.handoffSourceSuccessionConfirmed(ctx, manifest, succession.BindingID) {
					return fmt.Errorf("recover continuation handoffs: %w", err)
				}
				deferredHandoffProbe = fmt.Errorf("recover continuation handoffs: %w", err)
			case errors.Is(err, continuity.ErrHandoffProbeUnknown):
				deferredHandoffProbe = fmt.Errorf("recover continuation handoffs: %w", err)
			default:
				return fmt.Errorf("recover continuation handoffs: %w", err)
			}
		}
	}
	// A managed service whose project root was re-mounted onto a new loop device
	// is a bounded, retryable condition too: the service stays fail-closed and
	// unadvanced, but the pass still re-observes the root, publishes the
	// re-attested root through the ordinary workspace report for backend
	// ratification, and finishes its sandbox, managed-service and workspace work
	// so a later manifest carrying that ratified authority can let the service
	// proceed. The dedicated remount reason is returned only when nothing else in
	// the pass could proceed, so it stays visible alongside any unrelated abort.
	var deferredManagedProjectRemount error
	defer func() {
		if err == nil {
			return
		}
		if deferredHandoffProbe != nil {
			err = errors.Join(deferredHandoffProbe, err)
		}
		if deferredManagedProjectRemount != nil {
			err = errors.Join(deferredManagedProjectRemount, err)
		}
	}()
	// The authenticated manifest has passed the existing complete identity,
	// schema, revision and capacity gates before its fresh lease may prepare an
	// exact pending protective Pause. This phase stores only that operation's
	// deadline. Bounded exact-operation reconciliation follows immediately, and
	// reservation, review, release and unrelated recovery errors remain fatal.
	if r.Manager != nil {
		if err := r.Manager.RenewPendingTakeovers(ctx, manifest); err != nil {
			return fmt.Errorf("renew pending manager takeovers: %w", err)
		}
		if err := r.Manager.Recover(ctx); err != nil {
			return fmt.Errorf("recover manager operations: %w", err)
		}
	}
	setupSandboxes := make(map[string]bool, len(manifest.SetupOperations))
	for _, operation := range manifest.SetupOperations {
		setupSandboxes[operation.SandboxID] = true
	}
	for _, desired := range manifest.Sandboxes {
		if err := r.reconcileSandbox(ctx, desired, manifest.ImageDigest, setupSandboxes[desired.ID]); err != nil {
			return fmt.Errorf("reconcile sandbox %s: %w", desired.ID, err)
		}
	}
	if err := r.reconcileMissingSandboxes(ctx, manifest.Sandboxes); err != nil {
		return err
	}
	if err := r.reconcileGrants(ctx, manifest.AccessGrants); err != nil {
		return err
	}
	setupReady, err := r.reconcileSetupOperations(ctx, manifest)
	if err != nil {
		return err
	}
	if !setupReady {
		return nil
	}
	// Apply only the freshly fetched manager policy manifests here, after the
	// sandbox/grant/setup prerequisites and before the failure-prone managed
	// service, handoff and continuity steps: a renewed policy lease must be
	// stored even when a later step aborts. Reviews, takeovers, run execution
	// and every other action-bearing manager apply remain at the existing
	// end-of-pass position, and a failed pass never advances the applied
	// revision.
	if r.Manager != nil {
		if err := r.Manager.ApplyPolicies(ctx, manifest); err != nil {
			return fmt.Errorf("apply manager policies: %w", err)
		}
	}
	if r.ManagedCatalog != nil {
		// Re-observe the host-private roots before any project is resolved: a
		// workspace image that an authorized re-mount moved onto a new loop
		// device is re-attested here, and the ordinary report publishes that
		// observation for backend ratification. Only the documented remount
		// qualifies; every other difference stays as it was and keeps failing
		// closed on the ordinary paths.
		if err := r.ManagedCatalog.ReobserveRemountedRoots(ctx); err != nil {
			return fmt.Errorf("reobserve managed workspace roots: %w", err)
		}
		if err := r.reconcileManagedWorkspaceRequests(ctx, manifest); err != nil {
			return fmt.Errorf("apply managed workspace requests: %w", err)
		}
	}
	// The pre-failure acknowledgement phase runs after every manifest,
	// revision, capacity, sandbox, setup, policy and workspace authority
	// validation but before the failure-prone managed-service enrollment. A
	// managed-service failure still leaves the applied revision unchanged,
	// while the current registration observations are adopted/revoked exactly
	// once and the terminal operation echoes the fresh manifest no longer
	// carries are retired locally, so the next report is conflict-free instead
	// of re-emitting revoked tuples and acknowledged echoes.
	if r.ContinuityControl != nil {
		if err := r.ContinuityControl.Acknowledge(ctx, manifest); err != nil {
			return fmt.Errorf("acknowledge continuity manifest: %w", err)
		}
	}
	// The pre-failure source observation phase runs after every manifest,
	// revision, capacity, sandbox, setup, workspace and continuity-registration
	// authority check and after the acknowledgement phase, but before the
	// failure-prone managed-service enrollment. A managed-service failure (or a
	// deferred handoff) can no longer skip the genuine re-observation of every
	// source that currently backs an active registration, so the next report
	// carries current source availability instead of a stale one.
	if err := r.observeContinuitySources(ctx, manifest); err != nil {
		return fmt.Errorf("observe continuity sources: %w", err)
	}
	if r.ManagedControl != nil || r.ManagedRuntime != nil {
		if r.ManagedControl == nil || r.ManagedRuntime == nil || r.ManagedCatalog == nil {
			return errors.New("managed service producer is incompletely configured")
		}
		deferred, fatal := r.reconcileManagedServices(ctx, manifest)
		if deferred != nil {
			deferredManagedProjectRemount = fmt.Errorf("apply managed services: %w", deferred)
		}
		if fatal != nil {
			return fmt.Errorf("apply managed services: %w", fatal)
		}
	}
	if r.ContinuationHandoff != nil {
		if err := r.ContinuationHandoff.ApplyHandoffs(ctx, manifest.ContinuityHandoffs); err != nil {
			return fmt.Errorf("apply continuation handoffs: %w", err)
		}
		if err := r.ContinuationHandoff.ApplyHandoffTargetRegistrations(ctx, manifest.ContinuityRegistrations); err != nil {
			return fmt.Errorf("apply continuation handoff registrations: %w", err)
		}
		if err := r.ContinuationHandoff.ApplyHandoffReleases(ctx, manifest.ContinuityHandoffReleases); err != nil {
			return fmt.Errorf("apply continuation handoff releases: %w", err)
		}
	}
	if r.ContinuityControl != nil {
		if err := r.ContinuityControl.Apply(ctx, manifest); err != nil {
			return fmt.Errorf("apply continuity manifest: %w", err)
		}
	}
	if r.ContinuationRestore != nil {
		if err := r.ContinuationRestore.Apply(ctx, manifest.ContinuityContinuations, manifest.ContinuityRestores); err != nil {
			return fmt.Errorf("apply continuation/restore manifest: %w", err)
		}
		if err := r.ContinuationRestore.ApplyReleases(ctx, manifest.ContinuityContinuationReleases); err != nil {
			return fmt.Errorf("apply continuation release manifest: %w", err)
		}
	}
	if r.Manager != nil {
		if err := r.Manager.ApplyLifecycle(ctx, manifest); err != nil {
			return fmt.Errorf("apply manager manifest: %w", err)
		}
	}
	return r.Store.SetRevision(ctx, manifest.DesiredRevision)
}

// handoffSourceSuccessionConfirmed confirms the manifest-dependent half of the
// one owner-authorized monotonic handoff succession deferral. The same fresh
// authenticated manifest must still be schema-valid for the current applied
// revision and must resolve exactly one effective registration for the binding
// the way ValidateManifest resolves a valid succession: the single active
// entry, or the active successor of the one exact revoked-predecessor /
// active-successor pair the backend re-lists when it reactivates a binding
// (same binding ID, successor binding revision exactly predecessor + 1,
// successor scope exactly the journey-proven predecessor + 1, identical
// identity and binding fences). That effective successor must be
// byte-for-field equal to the durable local successor, and exactly one ready
// handoff preparation must own the binding, so an ambiguous duplicate stays
// fatal. Anything else leaves the existing fatal recovery error untouched, and
// nothing is written here.
func (r *Reconciler) handoffSourceSuccessionConfirmed(ctx context.Context, manifest model.Manifest, bindingID string) bool {
	applied, err := r.Store.Revision(ctx)
	if err != nil {
		return false
	}
	if err := model.ValidateManifest(manifest, r.ServerID, applied); err != nil {
		return false
	}
	preparations, err := r.Store.ContinuationHandoffPreparations(ctx)
	if err != nil {
		return false
	}
	ready := 0
	for _, preparation := range preparations {
		if preparation.Report != nil && preparation.Report.Status == "ready" &&
			preparation.Manifest.Binding.BindingID == bindingID {
			ready++
		}
	}
	if ready != 1 {
		return false
	}
	local, err := r.Store.ContinuityRegistration(ctx, bindingID)
	if err != nil || local == nil {
		return false
	}
	effective, ok := effectiveHandoffSuccessionRegistration(manifest, bindingID)
	if !ok {
		return false
	}
	return reflect.DeepEqual(effective, local.Manifest)
}

// effectiveHandoffSuccessionRegistration resolves the manifest's effective
// registration for one binding exactly the way ValidateManifest resolves a
// valid succession: a single structurally valid entry, or the active successor
// of the one revoked-predecessor / active-successor pair the backend emits when
// it reactivates a durable binding. The pair must advance the binding revision
// by exactly one, advance the workspace scope by exactly the journey-proven one
// step, keep the predecessor revoked and continuity-disabled with the successor
// active and continuity-enabled, and keep every other identity and binding
// field identical. Every other shape - no successor, an extra or ambiguous
// entry, a non-succession duplicate, a reversed or skipped relation, an inexact
// scope step or any inconsistent fence - returns false so the caller keeps the
// fatal recovery path.
func effectiveHandoffSuccessionRegistration(manifest model.Manifest, bindingID string) (model.ContinuityRegistrationV1, bool) {
	var group []model.ContinuityRegistrationV1
	for _, registration := range manifest.ContinuityRegistrations {
		if registration.Binding.BindingID == bindingID {
			group = append(group, registration)
		}
	}
	switch len(group) {
	case 1:
		registration := group[0]
		if registration.DesiredState != "active" || !registration.ContinuityEnabled {
			return model.ContinuityRegistrationV1{}, false
		}
		return registration, true
	case 2:
		var revoked, active *model.ContinuityRegistrationV1
		for index := range group {
			switch group[index].DesiredState {
			case "revoked":
				if revoked != nil {
					return model.ContinuityRegistrationV1{}, false
				}
				revoked = &group[index]
			case "active":
				if active != nil {
					return model.ContinuityRegistrationV1{}, false
				}
				active = &group[index]
			default:
				return model.ContinuityRegistrationV1{}, false
			}
		}
		if revoked == nil || active == nil || revoked.ContinuityEnabled || !active.ContinuityEnabled {
			return model.ContinuityRegistrationV1{}, false
		}
		if active.Binding.BindingRevision != revoked.Binding.BindingRevision+1 ||
			active.ScopeRevision != revoked.ScopeRevision+1 {
			return model.ContinuityRegistrationV1{}, false
		}
		if !model.SameContinuityWorkFence(revoked.Identity, active.Identity) {
			return model.ContinuityRegistrationV1{}, false
		}
		revokedBinding, activeBinding := revoked.Binding, active.Binding
		revokedBinding.BindingRevision, activeBinding.BindingRevision = 0, 0
		if revokedBinding != activeBinding {
			return model.ContinuityRegistrationV1{}, false
		}
		return *active, true
	default:
		return model.ContinuityRegistrationV1{}, false
	}
}

func (r *Reconciler) reconcileContinuationRestore(ctx context.Context, manifest model.Manifest) error {
	if r.ContinuationRestore == nil {
		return nil
	}
	if err := r.ContinuationRestore.RecoverCurrent(ctx, r.currentAuthorityManifest()); err != nil {
		return err
	}
	if err := r.ContinuationRestore.Apply(ctx, manifest.ContinuityContinuations, manifest.ContinuityRestores); err != nil {
		return err
	}
	return r.ContinuationRestore.ApplyReleases(ctx, manifest.ContinuityContinuationReleases)
}

func (r *Reconciler) reconcileMissingSandboxes(
	ctx context.Context,
	desired []model.Sandbox,
) error {
	desiredIDs := make(map[string]bool, len(desired))
	for _, sandbox := range desired {
		desiredIDs[sandbox.ID] = true
	}
	current, err := r.Store.Sandboxes(ctx)
	if err != nil {
		return err
	}
	for index := range current {
		local := &current[index]
		if desiredIDs[local.ID] {
			continue
		}
		if local.ObservedState != "deleted" {
			local.DesiredState = "deleted"
			if err := r.removeSandbox(ctx, local); err != nil {
				return fmt.Errorf("remove omitted sandbox %s: %w", local.ID, err)
			}
		}
		if err := r.Store.DeleteSandbox(ctx, local.ID); err != nil {
			return fmt.Errorf("prune sandbox tombstone %s: %w", local.ID, err)
		}
	}
	return nil
}

func (r *Reconciler) Expire(ctx context.Context) error {
	if r.ContinuityLifecycle != nil {
		if err := r.ContinuityLifecycle.Run(ctx); err != nil {
			return fmt.Errorf("collect continuity checkpoints: %w", err)
		}
	}
	values, err := r.Store.Sandboxes(ctx)
	if err != nil {
		return err
	}
	current := r.now()
	for index := range values {
		value := &values[index]
		if value.Lifetime == "temporary" && value.ExpiresAt != nil &&
			!current.Before(*value.ExpiresAt) && value.ObservedState != "deleted" {
			value.DesiredState = "deleted"
			if err := r.removeSandbox(ctx, value); err != nil {
				return fmt.Errorf("expire sandbox %s: %w", value.ID, err)
			}
		}
	}
	return nil
}

func (r *Reconciler) Report(ctx context.Context, serverID, version string) (model.Report, error) {
	authority := r.currentAuthorityManifest()
	revision, err := r.Store.Revision(ctx)
	if err != nil {
		return model.Report{}, err
	}
	sandboxes, err := r.Store.Sandboxes(ctx)
	if err != nil {
		return model.Report{}, err
	}
	grants, err := r.Store.Grants(ctx)
	if err != nil {
		return model.Report{}, err
	}
	report := model.Report{
		ServerID:                       serverID,
		AppliedRevision:                revision,
		SupervisorVersion:              version,
		Sandboxes:                      make([]model.SandboxReport, 0),
		AccessGrants:                   make([]model.GrantReport, 0),
		SetupOperations:                make([]model.SetupOperationReport, 0),
		ContinuitySources:              make([]model.ContinuitySourceReportV1, 0),
		ContinuityRegistrations:        make([]model.ContinuityRegistrationReportV1, 0),
		ContinuityOperations:           make([]model.ContinuityOperationReportV1, 0),
		ManagedWorkspaceSelections:     make([]model.ProjectCatalogReportV1, 0),
		ManagedServices:                make([]model.ManagedServiceReportV1, 0),
		ContinuityContinuations:        make([]model.ContinuationReportV1, 0),
		ContinuityContinuationReleases: make([]model.ContinuationReleaseReportV1, 0),
		ContinuityRestores:             make([]model.RestoreReportV1, 0),
		ContinuityHandoffs:             make([]model.ContinuationHandoffReportV1, 0),
		ContinuityHandoffReleases:      make([]model.ContinuationHandoffReleaseReportV1, 0),
		InsightsManagerPolicies:        make([]model.InsightsManagerPolicyReportV1, 0),
		InsightsManagerReviews:         make([]model.InsightsManagerRunReportV1, 0),
		InsightsTakeovers:              make([]model.InsightsTakeoverReportV1, 0),
		InsightsManagerGuidance:        make([]model.InsightsManagerGuidanceV1, 0),
	}
	for _, value := range sandboxes {
		item := model.SandboxReport{
			ID:                 value.ID,
			ObservedState:      value.ObservedState,
			ObservedGeneration: value.ObservedGeneration,
			ImageDigest:        value.ImageDigest,
			StartedAt:          value.StartedAt,
			ExpiresAt:          value.ExpiresAt,
		}
		if value.ErrorCode != "" {
			item.LastError = &model.ItemError{Code: value.ErrorCode, Message: value.ErrorMessage}
		}
		report.Sandboxes = append(report.Sandboxes, item)
	}
	for _, value := range grants {
		item := model.GrantReport{ID: value.ID, ObservedState: value.ObservedState}
		if value.ErrorCode != "" {
			item.LastError = &model.ItemError{Code: value.ErrorCode, Message: value.ErrorMessage}
		}
		report.AccessGrants = append(report.AccessGrants, item)
	}
	setupOperations, err := r.Store.SetupOperations(ctx)
	if err != nil {
		return model.Report{}, err
	}
	for _, value := range setupOperations {
		item := model.SetupOperationReport{
			ID:                value.ID,
			SandboxID:         value.SandboxID,
			SandboxGeneration: value.SandboxGeneration,
			ProfileID:         value.ProfileID,
			ProfileRevision:   value.ProfileRevision,
			ProfileDigest:     value.ProfileDigest,
			Status:            value.State,
			ReceiptDigest:     value.ReceiptDigest,
		}
		if value.ErrorCode != "" {
			item.LastError = &model.ItemError{Code: value.ErrorCode, Message: value.ErrorMessage}
		}
		report.SetupOperations = append(report.SetupOperations, item)
	}
	if r.ContinuityControl != nil {
		sources, registrations, operations, err := r.ContinuityControl.ReportsCurrent(ctx, authority)
		if err != nil {
			return model.Report{}, err
		}
		report.ContinuitySources, report.ContinuityRegistrations, report.ContinuityOperations = sources, registrations, operations
	}
	// ONE freshness decision for this report. A continuity source whose
	// authentic stored observation is older than the shared freshness contract
	// is serialized as unavailable while its real observation timestamp and
	// identity are preserved, and every manager capability item that references
	// the same source derives the fail-closed unavailable pair from the same
	// decision below. A genuinely fresh re-observation is inside the contract
	// and keeps ordinary available reporting.
	staleSources := continuity.DecideStaleSourceSet(report.ContinuitySources, r.now())
	for index := range report.ContinuitySources {
		report.ContinuitySources[index] = staleSources.DeriveSourceReport(report.ContinuitySources[index])
	}
	if r.ContinuationRestore != nil {
		continuations, restores, err := r.ContinuationRestore.ReportsCurrent(ctx, authority)
		if err != nil {
			return model.Report{}, err
		}
		report.ContinuityContinuations, report.ContinuityRestores = continuations, restores
		releases, err := r.ContinuationRestore.ReleaseReportsCurrent(ctx, authority)
		if err != nil {
			return model.Report{}, err
		}
		report.ContinuityContinuationReleases = releases
	}
	if r.ContinuationHandoff != nil {
		handoffs, releases, err := r.ContinuationHandoff.HandoffReportsCurrent(ctx, authority)
		if err != nil {
			return model.Report{}, err
		}
		report.ContinuityHandoffs, report.ContinuityHandoffReleases = handoffs, releases
	}
	if r.ManagedCatalog != nil {
		selections, err := r.ManagedCatalog.Reports(ctx)
		if err != nil {
			return model.Report{}, err
		}
		// Catalog rows are durable provenance. Only the current, observed
		// sandbox generation is an admissible live selection for the node API.
		for _, selection := range selections {
			for _, sandbox := range sandboxes {
				if sandbox.ID == selection.SandboxID && sandbox.Generation == selection.SandboxGeneration &&
					sandbox.ObservedGeneration == selection.SandboxGeneration && sandbox.ObservedState != "deleted" {
					report.ManagedWorkspaceSelections = append(report.ManagedWorkspaceSelections, selection)
					break
				}
			}
		}
	}
	services, err := r.Store.ManagedServices(ctx)
	if err != nil {
		return model.Report{}, err
	}
	for _, service := range services {
		if service.Report.FormatVersion != 1 {
			continue
		}
		if !currentManagedServiceTuple(authority, service) {
			// Superseded or foreign stored tuples are omitted from the outgoing
			// report without any local mutation or synthesis.
			continue
		}
		report.ManagedServices = append(report.ManagedServices, service.Report)
	}
	if r.Manager != nil {
		policies, reviews, takeovers, err := r.Manager.ReportsCurrent(ctx, authority, report.ContinuitySources, staleSources)
		if err != nil {
			return model.Report{}, err
		}
		guidance, guidanceErr := r.Manager.GuidanceReports(ctx)
		if guidanceErr != nil {
			return model.Report{}, guidanceErr
		}
		report.InsightsManagerPolicies = policies
		report.InsightsManagerReviews = reviews
		report.InsightsTakeovers = takeovers
		report.InsightsManagerGuidance = guidance
	}
	return report, nil
}

var setupReceiptDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type runnerSetupReceipt struct {
	ID                string                  `json:"id"`
	SandboxID         string                  `json:"sandboxId"`
	SandboxGeneration int64                   `json:"sandboxGeneration"`
	ProfileID         string                  `json:"profileId"`
	ProfileRevision   int64                   `json:"profileRevision"`
	ProfileDigest     string                  `json:"profileDigest"`
	ReceiptDigest     string                  `json:"receiptDigest"`
	Status            string                  `json:"status"`
	Provenance        *setupReceiptProvenance `json:"provenance,omitempty"`
	Error             *setupReceiptError      `json:"error,omitempty"`
}

type setupReceiptProvenance struct {
	Source         string `json:"source"`
	ArtifactSHA256 string `json:"artifactSha256"`
}

type setupReceiptError struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

func (r *Reconciler) reconcileSetupOperations(
	ctx context.Context,
	manifest model.Manifest,
) (bool, error) {
	desiredIDs := make(map[string]bool, len(manifest.SetupOperations))
	for _, desired := range manifest.SetupOperations {
		desiredIDs[desired.ID] = true
		request, err := json.Marshal(desired)
		if err != nil {
			return false, fmt.Errorf("encode setup operation %s: %w", desired.ID, err)
		}
		bodyDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(request))
		if err := r.Store.PutSetupOperation(ctx, state.LocalSetupOperation{
			ID:                desired.ID,
			SandboxID:         desired.SandboxID,
			SandboxGeneration: desired.SandboxGeneration,
			ProfileID:         desired.ProfileID,
			ProfileRevision:   desired.ProfileRevision,
			ProfileDigest:     desired.ProfileDigest,
			DesiredRevision:   manifest.DesiredRevision,
			BodyDigest:        bodyDigest,
			RequestJSON:       request,
			State:             "pending",
		}); err != nil {
			return false, fmt.Errorf("persist setup operation %s: %w", desired.ID, err)
		}
	}

	current, err := r.Store.SetupOperations(ctx)
	if err != nil {
		return false, err
	}
	for index := range current {
		operation := &current[index]
		if desiredIDs[operation.ID] || operation.State == "ready" ||
			operation.State == "failed" || operation.State == "cancelled" {
			continue
		}
		if err := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "cancelled", nil, "", "",
		); err != nil {
			return false, fmt.Errorf("cancel omitted setup operation %s: %w", operation.ID, err)
		}
	}

	runnable := make([]state.LocalSetupOperation, 0, len(manifest.SetupOperations))
	newlyApplying := false
	for _, desired := range manifest.SetupOperations {
		operation, err := r.Store.SetupOperation(ctx, desired.ID)
		if err != nil {
			return false, err
		}
		if operation == nil {
			return false, fmt.Errorf("setup operation %s disappeared", desired.ID)
		}
		switch operation.State {
		case "ready":
			continue
		case "failed", "cancelled":
			return false, fmt.Errorf(
				"setup operation %s is terminal in state %s",
				operation.ID,
				operation.State,
			)
		}
		sandbox, err := r.Store.Sandbox(ctx, operation.SandboxID)
		if err != nil {
			return false, err
		}
		if sandbox == nil || sandbox.ObservedState != "running" ||
			sandbox.ObservedGeneration != operation.SandboxGeneration {
			return false, fmt.Errorf(
				"setup operation %s is waiting for its running sandbox generation",
				operation.ID,
			)
		}
		if operation.State == "pending" {
			if err := r.Store.TransitionSetupOperation(
				ctx, operation.ID, "applying", nil, "", "",
			); err != nil {
				return false, fmt.Errorf("start setup operation %s: %w", operation.ID, err)
			}
			newlyApplying = true
			continue
		}
		runnable = append(runnable, *operation)
	}
	if newlyApplying {
		return false, nil
	}
	if len(runnable) == 0 {
		return true, nil
	}
	if err := r.executeSetupOperation(ctx, runnable[0]); err != nil {
		return false, err
	}
	return len(runnable) == 1, nil
}

func (r *Reconciler) executeSetupOperation(
	ctx context.Context,
	operation state.LocalSetupOperation,
) error {
	executionContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	// Setup may arrive after creation, or resume after a daemon restart. Never
	// treat prior lifecycle readiness as proof of the current nested boundary.
	if err := r.Engine.Preflight(executionContext, operation.SandboxID); err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		transitionErr := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "failed", nil, "nested_sandbox_preflight_failed", "nested sandbox preflight failed",
		)
		return errors.Join(fmt.Errorf("preflight setup operation %s: %w", operation.ID, err), transitionErr)
	}
	receiptJSON, _, err := r.Engine.ExecSetup(
		executionContext,
		operation.SandboxID,
		operation.RequestJSON,
	)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		transitionErr := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "failed", nil, "setup_execution_failed", "setup runner failed",
		)
		return errors.Join(fmt.Errorf("execute setup operation %s: %w", operation.ID, err), transitionErr)
	}
	receipt, err := validateSetupReceipt(receiptJSON, operation)
	if err != nil {
		transitionErr := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "failed", nil, "invalid_setup_receipt", "setup receipt was invalid",
		)
		return errors.Join(fmt.Errorf("validate setup operation %s receipt: %w", operation.ID, err), transitionErr)
	}
	if receipt.Status == "cancelled" {
		transitionErr := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "cancelled", nil, "", "",
		)
		return errors.Join(
			fmt.Errorf("setup operation %s was cancelled by the runner", operation.ID),
			transitionErr,
		)
	}
	if receipt.Status == "failed" {
		code := "setup_failed"
		if receipt.Error != nil && receipt.Error.Code != "" {
			code = bounded(receipt.Error.Code, 80)
		}
		transitionErr := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "failed", nil, code, "setup runner reported failure",
		)
		return errors.Join(
			fmt.Errorf("setup operation %s failed", operation.ID),
			transitionErr,
		)
	}
	if err := r.Store.TransitionSetupOperation(
		ctx, operation.ID, "ready", receiptJSON, "", "",
	); err != nil {
		return err
	}
	return nil
}

func validateSetupReceipt(payload []byte, operation state.LocalSetupOperation) (*runnerSetupReceipt, error) {
	if len(payload) == 0 || len(payload) > 64*1024 {
		return nil, errors.New("setup receipt size is invalid")
	}
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var receipt runnerSetupReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("setup receipt contains trailing data")
	}
	if receipt.ID != operation.ID || receipt.SandboxID != operation.SandboxID ||
		receipt.SandboxGeneration != operation.SandboxGeneration ||
		receipt.ProfileID != operation.ProfileID ||
		receipt.ProfileRevision != operation.ProfileRevision ||
		receipt.ProfileDigest != operation.ProfileDigest {
		return nil, errors.New("setup receipt immutable tuple does not match")
	}
	if !setupReceiptDigestPattern.MatchString(receipt.ReceiptDigest) {
		return nil, errors.New("setup receipt digest is invalid")
	}
	canonical, err := canonicalUnsignedSetupReceipt(payload)
	if err != nil {
		return nil, err
	}
	expectedDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(canonical))
	if subtle.ConstantTimeCompare(
		[]byte(receipt.ReceiptDigest),
		[]byte(expectedDigest),
	) != 1 {
		return nil, errors.New("setup receipt digest does not authenticate its content")
	}
	if receipt.Status != "ready" && receipt.Status != "failed" && receipt.Status != "cancelled" {
		return nil, errors.New("setup receipt status is invalid")
	}
	if receipt.Provenance != nil &&
		(utf8.RuneCountInString(receipt.Provenance.Source) == 0 ||
			utf8.RuneCountInString(receipt.Provenance.Source) > 512 ||
			!setupReceiptDigestPattern.MatchString(receipt.Provenance.ArtifactSHA256)) {
		return nil, errors.New("setup receipt provenance is invalid")
	}
	if receipt.Error != nil &&
		(utf8.RuneCountInString(receipt.Error.Code) == 0 ||
			utf8.RuneCountInString(receipt.Error.Code) > 80 ||
			utf8.RuneCountInString(receipt.Error.Detail) > 500) {
		return nil, errors.New("setup receipt error is invalid")
	}
	if receipt.Status == "ready" && receipt.Error != nil {
		return nil, errors.New("ready setup receipt cannot contain an error")
	}
	if receipt.Status == "failed" && receipt.Error == nil {
		return nil, errors.New("failed setup receipt requires an error")
	}
	var objects map[string]json.RawMessage
	if err := json.Unmarshal(payload, &objects); err != nil {
		return nil, err
	}
	for _, field := range []string{"error", "provenance"} {
		if value, exists := objects[field]; exists && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("setup receipt %s must be an object", field)
		}
	}
	return &receipt, nil
}

func canonicalUnsignedSetupReceipt(payload []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode setup receipt for digest: %w", err)
	}
	delete(document, "receiptDigest")
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("encode canonical setup receipt: %w", err)
	}
	return bytes.TrimSuffix(canonical.Bytes(), []byte("\n")), nil
}

func rejectDuplicateJSONFields(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := validateUniqueJSONValue(decoder); err != nil {
		return fmt.Errorf("setup receipt is not canonical JSON: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("setup receipt has trailing JSON token %v", token)
	}
	return nil
}

func validateUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = true
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func (r *Reconciler) reconcileSandbox(
	ctx context.Context,
	desired model.Sandbox,
	imageDigest string,
	requiresSetup bool,
) error {
	local, err := r.Store.Sandbox(ctx, desired.ID)
	if err != nil {
		return err
	}
	isNew := local == nil
	if isNew {
		local = &state.LocalSandbox{
			ID:                 desired.ID,
			Name:               desired.Name,
			ObservedState:      "pending",
			ObservedGeneration: 0,
		}
	}
	local.Name = desired.Name
	local.DesiredState = desired.DesiredState
	local.Generation = desired.Generation
	local.Lifetime = desired.Lifetime
	local.ExpiresInSeconds = desired.ExpiresInSeconds
	local.Resources = desired.Resources
	targetImageDigest := desired.ImageDigest
	if targetImageDigest == "" {
		if local.ImageDigest != "" {
			targetImageDigest = local.ImageDigest
		} else {
			targetImageDigest = imageDigest
		}
	}
	// Pin a sandbox to the image used when it was first created. A new default
	// applies only to new sandboxes: when the control plane omits the explicit
	// per-sandbox digest the pinned local digest wins, so the default never
	// moves an existing sandbox. An explicit per-sandbox digest patches the
	// image in place at the current generation; a higher generation advances
	// the incarnation as before. A backwards generation is refused.
	if local.ImageDigest == "" {
		local.ImageDigest = targetImageDigest
	}
	refreshImage := local.ImageDigest != targetImageDigest
	if refreshImage && desired.Generation < local.ObservedGeneration {
		return errors.New("sandbox generation moved backwards")
	}
	if local.StartedAt == nil && desired.StartedAt != nil {
		local.StartedAt = desired.StartedAt
	}
	if local.ExpiresAt == nil && desired.ExpiresAt != nil {
		local.ExpiresAt = desired.ExpiresAt
	}
	if local.Lifetime == "persistent" {
		local.ExpiresInSeconds = nil
		local.ExpiresAt = nil
	}
	if local.Lifetime == "temporary" && local.ExpiresAt != nil &&
		!r.now().Before(*local.ExpiresAt) {
		local.DesiredState = "deleted"
	}
	if err := r.Store.PutSandbox(ctx, *local); err != nil {
		return err
	}
	switch local.DesiredState {
	case "deleted":
		return r.removeSandbox(ctx, local)
	case "stopped":
		if refreshImage {
			workspace, err := r.Workspaces.Ensure(
				ctx,
				local.ID,
				local.Resources.WorkspaceDiskGiB,
			)
			if err != nil {
				return r.failSandbox(ctx, local, "workspace_create_failed", err)
			}
			local.ObservedState = "restarting"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
			if r.Sessions != nil {
				_ = r.Sessions.TerminateSandbox(ctx, local.ID)
			}
			if err := r.Engine.Replace(
				ctx,
				desired,
				workspace,
				targetImageDigest,
				false,
			); err != nil {
				return r.failSandbox(ctx, local, imageReplaceErrorCode(err), err)
			}
			local.ImageDigest = targetImageDigest
		}
		if local.ObservedState != "stopped" {
			local.ObservedState = "stopping"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
		}
		if r.Sessions != nil {
			_ = r.Sessions.TerminateSandbox(ctx, local.ID)
		}
		if err := r.Engine.Stop(ctx, local.ID); err != nil {
			return r.failSandbox(ctx, local, "container_stop_failed", err)
		}
		local.ObservedState = "stopped"
		local.ObservedGeneration = local.Generation
		return r.Store.PutSandbox(ctx, *local)
	case "running":
		if local.ObservedState == "deleted" && local.Lifetime == "temporary" {
			return nil
		}
		requiresNestedPreflight := requiresSetup && (refreshImage || local.ObservedState != "running" ||
			local.ObservedGeneration < local.Generation)
		workspace, err := r.Workspaces.Ensure(ctx, local.ID, local.Resources.WorkspaceDiskGiB)
		if err != nil {
			return r.failSandbox(ctx, local, "workspace_create_failed", err)
		}
		if refreshImage {
			local.ObservedState = "restarting"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
			if r.Sessions != nil {
				_ = r.Sessions.TerminateSandbox(ctx, local.ID)
			}
			if err := r.Engine.Replace(
				ctx,
				desired,
				workspace,
				targetImageDigest,
				true,
			); err != nil {
				return r.failSandbox(ctx, local, imageReplaceErrorCode(err), err)
			}
			local.ImageDigest = targetImageDigest
		} else if local.ObservedState == "running" && local.ObservedGeneration < local.Generation {
			local.ObservedState = "restarting"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
			if r.Sessions != nil {
				_ = r.Sessions.TerminateSandbox(ctx, local.ID)
			}
			if err := r.Engine.Restart(ctx, local.ID); err != nil {
				return r.failSandbox(ctx, local, "container_restart_failed", err)
			}
		} else if local.ObservedState == "stopped" {
			if err := r.Engine.Start(ctx, local.ID); err != nil {
				return r.failSandbox(ctx, local, "container_start_failed", err)
			}
		} else if local.ObservedState == "running" {
			if err := r.Engine.Ensure(ctx, desired, workspace, local.ImageDigest); err != nil {
				return r.failSandbox(ctx, local, "container_reconcile_failed", err)
			}
		} else if local.ObservedState != "running" {
			local.ObservedState = "creating"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
			desired.ExpiresAt = local.ExpiresAt
			if err := r.Engine.Ensure(ctx, desired, workspace, local.ImageDigest); err != nil {
				return r.failSandbox(ctx, local, "container_create_failed", err)
			}
		}
		if requiresNestedPreflight {
			if err := r.Engine.Preflight(ctx, local.ID); err != nil {
				stopErr := r.Engine.Stop(ctx, local.ID)
				return r.failSandbox(
					ctx,
					local,
					"nested_sandbox_preflight_failed",
					errors.Join(err, stopErr),
				)
			}
		}
		started := r.now()
		if local.StartedAt == nil {
			local.StartedAt = &started
			if local.Lifetime == "temporary" && local.ExpiresInSeconds != nil {
				expires := started.Add(time.Duration(*local.ExpiresInSeconds) * time.Second)
				local.ExpiresAt = &expires
			}
		}
		local.ObservedState = "running"
		local.ObservedGeneration = local.Generation
		local.ErrorCode = ""
		local.ErrorMessage = ""
		if err := r.Store.PutSandbox(ctx, *local); err != nil {
			return err
		}
		return nil
	default:
		return errors.New("unsupported desired state")
	}
}

func imageReplaceErrorCode(err error) string {
	if errors.Is(err, containers.ErrImagePullFailed) {
		return "sandbox_image_pull_failed"
	}
	if errors.Is(err, containers.ErrImageRollbackFailed) {
		return "container_image_rollback_failed"
	}
	return "container_image_replace_failed"
}

func (r *Reconciler) removeSandbox(ctx context.Context, local *state.LocalSandbox) error {
	if local.ObservedState == "deleted" {
		return nil
	}
	local.ObservedState = "deleting"
	if err := r.Store.PutSandbox(ctx, *local); err != nil {
		return err
	}
	if r.Sessions != nil {
		_ = r.Sessions.TerminateSandbox(ctx, local.ID)
	}
	if err := r.Engine.Remove(ctx, local.ID); err != nil {
		return r.failSandbox(ctx, local, "container_delete_failed", err)
	}
	if err := r.Workspaces.Destroy(ctx, local.ID); err != nil {
		return r.failSandbox(ctx, local, "workspace_delete_failed", err)
	}
	local.ObservedState = "deleted"
	local.ObservedGeneration = local.Generation
	local.ErrorCode = ""
	local.ErrorMessage = ""
	return r.Store.PutSandbox(ctx, *local)
}

func (r *Reconciler) failSandbox(
	ctx context.Context,
	local *state.LocalSandbox,
	code string,
	err error,
) error {
	local.ObservedState = "failed"
	local.ErrorCode = code
	local.ErrorMessage = bounded(err.Error(), 300)
	if saveErr := r.Store.PutSandbox(ctx, *local); saveErr != nil {
		return errors.Join(err, saveErr)
	}
	return err
}

func (r *Reconciler) reconcileGrants(ctx context.Context, desired []model.AccessGrant) error {
	existing, err := r.Store.Grants(ctx)
	if err != nil {
		return err
	}
	desiredIDs := map[string]bool{}
	for _, grant := range desired {
		desiredIDs[grant.ID] = true
		value := state.LocalGrant{
			ID:            grant.ID,
			SandboxID:     grant.SandboxID,
			SSHPublicKey:  grant.SSHPublicKey,
			DesiredState:  grant.DesiredState,
			ObservedState: "pending",
		}
		for _, current := range existing {
			if current.ID == grant.ID {
				value.ObservedState = current.ObservedState
			}
		}
		if grant.DesiredState == "revoked" {
			value.ObservedState = "revoking"
			if r.Sessions != nil {
				if err := r.Sessions.TerminateGrant(ctx, grant.ID); err != nil {
					return err
				}
			}
		}
		if err := r.Store.PutGrant(ctx, value); err != nil {
			return err
		}
	}
	for _, current := range existing {
		if !desiredIDs[current.ID] && current.DesiredState == "active" {
			current.DesiredState = "revoked"
			current.ObservedState = "revoking"
			if r.Sessions != nil {
				if err := r.Sessions.TerminateGrant(ctx, current.ID); err != nil {
					return err
				}
			}
			if err := r.Store.PutGrant(ctx, current); err != nil {
				return err
			}
		}
	}
	all, err := r.Store.Grants(ctx)
	if err != nil {
		return err
	}
	if err := r.Access.Write(all); err != nil {
		for index := range all {
			if all[index].DesiredState == "active" {
				all[index].ObservedState = "failed"
				all[index].ErrorCode = "access_mapping_failed"
				all[index].ErrorMessage = bounded(err.Error(), 300)
				_ = r.Store.PutGrant(ctx, all[index])
			}
		}
		return err
	}
	for index := range all {
		if all[index].DesiredState == "active" {
			all[index].ObservedState = "applied"
		} else {
			all[index].ObservedState = "revoked"
		}
		all[index].ErrorCode = ""
		all[index].ErrorMessage = ""
		if err := r.Store.PutGrant(ctx, all[index]); err != nil {
			return err
		}
		if !desiredIDs[all[index].ID] && all[index].DesiredState == "revoked" {
			if err := r.Store.DeleteGrant(ctx, all[index].ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func requested(sandboxes []model.Sandbox) model.Resources {
	value := model.Resources{}
	for _, sandbox := range sandboxes {
		if sandbox.DesiredState == "deleted" {
			continue
		}
		value.WorkspaceDiskGiB += sandbox.Resources.WorkspaceDiskGiB
		if sandbox.DesiredState == "running" {
			value.CPUMillicores += sandbox.Resources.CPUMillicores
			value.MemoryMiB += sandbox.Resources.MemoryMiB
		}
	}
	return value
}

func bounded(value string, maximum int) string {
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}
