package continuity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// ErrSourceServiceNotReady marks a handoff source service whose stored tuple is
// structurally exact but whose local row is not ready. Ready-preparation
// recovery skips exactly this bounded reason so a failed local service cannot
// wedge unrelated recovery work, without weakening any authority fence.
var ErrSourceServiceNotReady = errors.New("source_service_not_ready")

// ErrTargetServiceNotReady marks a ready handoff preparation whose exact target
// tuple points at a managed service that is transiently starting or whose
// supported enrollment retry failed with enrollment_unavailable. The reconcile
// pass defers only these bounded cases so it can continue into the ordinary
// service apply that advances the phase; every other target failure stays
// fail-closed.
var ErrTargetServiceNotReady = errors.New("target_service_not_ready")

// ErrHandoffProbeUnknown marks a ready handoff preparation whose source or
// target supervisor probe could not be dispatched or answered: the supervisor
// status dispatch (source native session or target-service registered primary)
// or the target session reconcile dispatch failed with a transport or process
// error, for example error=stale_process or a stopped sandbox that can no
// longer create exec sessions. The handoff row stays byte-unchanged and
// fail-closed, and the reconcile pass defers exactly this bounded reason so
// unrelated manifest validation, sandbox, managed-service, workspace and report
// work still executes and can repair the probe precondition. A receipt that
// answers but does not prove the stored tuple, authority drift, and every other
// recovery failure remain fatal.
var ErrHandoffProbeUnknown = errors.New("handoff supervisor probe is unknown")

// ErrHandoffSourceSuccessionPending marks a ready handoff whose stored source
// binding is the historical predecessor of the current local registration and
// whose successor is an exact, monotonic, continuity-enabled succession. The
// reconciler confirms the manifest-dependent half of the classification (the
// successor is byte-for-field equal to the effective registration of the same
// fresh authenticated, schema-valid manifest) before the record is deferred;
// every other source-registration mismatch stays ErrS2RecoveryUnknown.
var ErrHandoffSourceSuccessionPending = errors.New("handoff source succession awaits the fresh manifest")

// HandoffSourceSuccessionDeferral is the dedicated retryable outcome for the
// exact monotonic handoff succession. Its message is the retained fatal
// classification, so a manifest that does not confirm the succession leaves
// the pre-existing ErrS2RecoveryUnknown failure byte-visible; the reconciler
// defers it exactly like the handoff-probe deferral instead of failing the
// pass.
type HandoffSourceSuccessionDeferral struct {
	BindingID string
	fatal     error
}

func (value *HandoffSourceSuccessionDeferral) Error() string { return value.fatal.Error() }

func (value *HandoffSourceSuccessionDeferral) Unwrap() []error {
	return []error{ErrHandoffSourceSuccessionPending, value.fatal}
}

type handoffWorkspaceRegistration struct {
	FormatVersion   int                                        `json:"formatVersion"`
	OperationID     string                                     `json:"operationId"`
	DesiredRevision int64                                      `json:"desiredRevision"`
	MappingID       string                                     `json:"mappingId"`
	TargetWorkID    string                                     `json:"targetWorkId"`
	TargetWorkspace model.ContinuationHandoffTargetWorkspaceV1 `json:"targetWorkspace"`
	ProjectRoot     string                                     `json:"projectRoot"`
}

type handoffWorkspaceRequest struct {
	SchemaVersion int                          `json:"schemaVersion"`
	SandboxID     string                       `json:"sandboxId"`
	Instance      string                       `json:"instance"`
	ProfileID     string                       `json:"profileId"`
	Registration  handoffWorkspaceRegistration `json:"registration"`
}

type handoffWorkspaceReceipt struct {
	SchemaVersion   int                                        `json:"schemaVersion"`
	Command         string                                     `json:"command"`
	Status          string                                     `json:"status"`
	SandboxID       string                                     `json:"sandboxId"`
	Instance        string                                     `json:"instance"`
	ProfileID       string                                     `json:"profileId"`
	OperationID     string                                     `json:"operationId"`
	MappingID       string                                     `json:"mappingId"`
	TargetWorkID    string                                     `json:"targetWorkId"`
	TargetWorkspace model.ContinuationHandoffTargetWorkspaceV1 `json:"targetWorkspace"`
	Ready           bool                                       `json:"ready"`
}

type handoffHelperRequest struct {
	model.ContinuationHandoffManifestV1
	Instance        string                                     `json:"instance"`
	TargetWorkspace model.ContinuationHandoffTargetWorkspaceV1 `json:"targetWorkspace"`
}

type handoffReleaseRequest struct {
	model.ContinuationHandoffReleaseManifestV1
	Instance string `json:"instance"`
}

type handoffRecoveryEnvelope struct {
	FormatVersion int                                       `json:"formatVersion"`
	Action        string                                    `json:"action"`
	Status        string                                    `json:"status"`
	State         string                                    `json:"state"`
	Report        *model.ContinuationHandoffReportV1        `json:"report"`
	Consumption   *continuationConsumption                  `json:"consumption"`
	Release       *model.ContinuationHandoffReleaseReportV1 `json:"release"`
}

// handoffHelperRefusal is the bounded stdout receipt a nonzero helper exit
// prints. Facts are parsed as opaque bytes and never interpreted.
type handoffHelperRefusal struct {
	FormatVersion int             `json:"formatVersion"`
	Action        string          `json:"action"`
	Status        string          `json:"status"`
	Error         string          `json:"error"`
	Facts         json.RawMessage `json:"facts"`
}

// handoffStatusReceipt models only the supervisor status fields a handoff
// source probe must prove. The live receipt carries many more supervisor
// fields, so unknown fields are deliberately ignored; the probe tuple itself
// is verified exactly.
type handoffStatusReceipt struct {
	SchemaVersion        int    `json:"schemaVersion"`
	Command              string `json:"command"`
	Status               string `json:"status"`
	Ready                bool   `json:"ready"`
	SessionID            string `json:"sessionId"`
	NativeProjectID      string `json:"nativeProjectId"`
	NativeLocationDigest string `json:"nativeLocationDigest"`
	InstructionRevision  int64  `json:"instructionRevision"`
	InstructionDigest    string `json:"instructionDigest"`
	InstructionApplied   bool   `json:"instructionApplied"`
}

type currentHandoffTarget struct {
	service state.LocalManagedService
	primary state.LocalManagedProject
}

func (c *S2Controller) ApplyHandoffs(ctx context.Context, manifests []model.ContinuationHandoffManifestV1) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.handoffConfigured(); err != nil {
		if len(manifests) == 0 {
			return nil
		}
		return err
	}
	for _, manifest := range manifests {
		if err := c.applyHandoff(ctx, manifest); err != nil {
			return err
		}
	}
	return nil
}

func (c *S2Controller) RecoverHandoffs(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.handoffConfigured(); err != nil {
		return err
	}
	records, err := c.Store.ContinuationHandoffPreparations(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Report == nil {
			if err := c.recoverHandoff(ctx, record); err != nil {
				return err
			}
			continue
		}
		if record.Report.Status == "ready" {
			projectRecord, lookupErr := c.Store.ManagedProject(ctx, record.TargetSelectionID)
			if lookupErr != nil || projectRecord == nil {
				return errors.Join(ErrS2RecoveryUnknown, lookupErr)
			}
			instance, lookupErr := c.handoffInstance(ctx, &record)
			if lookupErr != nil {
				return lookupErr
			}
			project := workspacecatalog.RegisteredProject{
				Report: projectRecord.Report, HostRoot: projectRecord.HostRoot,
				ContainerRoot: projectRecord.ContainerRoot, ScopeRevision: projectRecord.ScopeRevision,
			}
			if err := c.reobserveHandoffSources(ctx, record, instance); err != nil {
				if errors.Is(err, ErrSourceServiceNotReady) || errors.Is(err, ErrTargetServiceNotReady) {
					// The preparation, report, and observation timestamps stay
					// byte-unchanged; the local source service or the transiently
					// starting target service must advance before this record can
					// resume. The pass continues into the ordinary apply so the
					// service can reach ready.
					continue
				}
				return err
			}
			if err := c.publishHandoffReady(ctx, record.Manifest, project, *record.Report, instance); err != nil {
				return err
			}
		}
	}
	releases, err := c.Store.ContinuationHandoffReleases(ctx)
	if err != nil {
		return err
	}
	for _, release := range releases {
		if release.Report == nil {
			if err := c.recoverHandoffRelease(ctx, release.Manifest); err != nil {
				return err
			}
		}
	}
	return nil
}

// reobserveHandoffSources truthfully re-probes both sources required by a ready
// handoff before the pass assembles its outbound report. A cached ready report
// is never a heartbeat: probe failure or tuple drift leaves the stored rows
// stale and unavailable, and the pass reports the bounded probe error.
//
// The source side may carry the already-reviewed exact same-binding succession:
// the ready handoff's stored binding is the historical predecessor while the
// acknowledgement phase has durably adopted the active successor (A45/A46).
// That bounded condition keeps the original deferral, but the target side of
// the SAME preparation is still observed through its own boundaries - the
// target service primary source through the ordinary status receipt, then the
// distinct mapped target session through the idempotent reconcile_handoff
// request. Every other source-side failure stays fatal before any target
// probing.
func (c *S2Controller) reobserveHandoffSources(ctx context.Context, record state.LocalContinuationHandoffPreparation, instance string) error {
	var succession *HandoffSourceSuccessionDeferral
	if err := c.reobserveHandoffSource(ctx, record.Manifest); err != nil {
		if !errors.As(err, &succession) {
			return err
		}
	}
	target, err := c.validateHandoffTargetForRecovery(ctx, record.Manifest.TargetPolicy)
	if err != nil {
		return err
	}
	if err := c.reobserveHandoffServiceSource(ctx, target); err != nil {
		return err
	}
	if err := c.reobserveHandoffTarget(ctx, record, instance); err != nil {
		return err
	}
	if succession != nil {
		return succession
	}
	return nil
}

// reobserveHandoffSource probes the primary managed native session through the
// supervisor status boundary without any freshness precondition. Only a status
// receipt that proves the exact stored session, service generation, sandbox
// generation, profile, and instruction tuple advances LastObservedAt.
//
// The stored source row may carry exactly one guarded workspace-scope advance
// beyond the handoff binding: the backend-ratified A5 workspace remount moves
// the source service's workspace scope one step while the handoff keeps the
// binding it was prepared with (owner decision A27). That one step is never
// taken from the observation. It is proven from durable current records - the
// same service generation carrying the advanced workspace scope, and its exact
// workspace tuple matching one ready, available team project that carries the
// current service root, the A5 superseded-root provenance, a fully nonzero
// durable image identity and the anchor/root-device fence - and the complete
// source authority is re-read and re-proven after the supervisor receipt,
// immediately before the observation write. Every other scope relation stays
// fail-closed, and the exact stored-scope path is unchanged.
func (c *S2Controller) reobserveHandoffSource(ctx context.Context, manifest model.ContinuationHandoffManifestV1) error {
	binding := manifest.Binding
	registration, err := c.Store.ContinuityRegistration(ctx, binding.BindingID)
	if err != nil || !handoffSourceRegistrationExact(registration, binding, manifest) {
		if deferral := c.handoffSourceSuccessionDeferral(ctx, registration, binding, manifest); deferral != nil {
			return deferral
		}
		return errors.Join(ErrS2RecoveryUnknown, errors.New("handoff source registration no longer matches the stored manifest"), err)
	}
	source, err := c.Store.ContinuitySource(ctx, binding.RegisteredSourceID)
	if err != nil || source == nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	service, err := c.Store.ManagedService(ctx, binding.ServiceRegistrationID)
	if err != nil || service == nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	if !handoffSourceServiceAuthorityExact(service, binding, manifest) {
		return errors.Join(ErrS2RecoveryUnknown, errors.New("handoff source service generation or identity no longer matches the stored manifest"), err)
	}
	if !handoffSourceServiceInstructionExact(service) {
		return errors.Join(ErrS2RecoveryUnknown, errors.New("handoff source instruction tuple no longer matches the stored manifest"), err)
	}
	if service.Phase != "ready" || service.Report.ObservedState != "ready" {
		return ErrSourceServiceNotReady
	}
	if !service.Report.InstructionApplied {
		return errors.Join(ErrS2RecoveryUnknown, errors.New("handoff source instruction proof is invalid"), err)
	}
	sandbox, err := c.Store.Sandbox(ctx, manifest.Identity.SandboxID)
	if err != nil || !handoffSourceSandboxRunning(sandbox, manifest) {
		return errors.Join(ErrS2RecoveryUnknown, errors.New("handoff source sandbox is not running"), err)
	}
	if !handoffSourceRowExact(source, service, manifest) {
		return errors.Join(ErrS2RecoveryUnknown, ErrS2AuthorityChanged, errors.New("handoff source row no longer matches the stored manifest"))
	}
	// The one-step workspace-scope advance the backend-ratified A5 remount
	// produces is admitted only when the durable current records prove it,
	// before the probe and again immediately before the observation write.
	scopeAdvanced := source.Report.ScopeRevision != binding.ScopeRevision
	if scopeAdvanced {
		proven, err := c.handoffSourceScopeAdvanceProven(ctx, binding, manifest.Identity, *source, *service)
		if err != nil || !proven {
			return errors.Join(ErrS2RecoveryUnknown, ErrS2AuthorityChanged, errors.New("handoff source scope advance is not proven by durable current records"), err)
		}
	}
	statusPayload, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "sandboxId": service.Manifest.Identity.SandboxID, "instance": service.Manifest.Identity.Instance,
		"profileId": service.Manifest.Profile.ProfileID, "profileDigest": service.Manifest.Profile.ProfileDigest,
		"probe": true, "requestTimeoutSeconds": 30,
	})
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	stdout, stderr, err := c.HandoffSupervisor.ExecManagedSupervisor(ctx, service.Manifest.Identity.SandboxID, containers.ManagedSupervisorStatus, statusPayload)
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, ErrHandoffProbeUnknown, fmt.Errorf("handoff source status probe: %s: %w", boundedHelperOutput(stderr), err))
	}
	receipt, err := decodeHandoffStatusReceipt(stdout)
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	if receipt.SchemaVersion != 1 || receipt.Command != "status" || receipt.Status != "running" || !receipt.Ready ||
		receipt.SessionID != source.Report.NativeSessionID || receipt.NativeProjectID != source.Report.NativeProjectID ||
		receipt.NativeLocationDigest != source.Report.NativeLocationDigest ||
		receipt.InstructionRevision != service.Manifest.Instructions.InstructionRevision ||
		receipt.InstructionDigest != service.Manifest.Instructions.InstructionDigest || !receipt.InstructionApplied {
		return errors.Join(ErrS2RecoveryUnknown, errors.New("handoff source status probe did not prove the stored native session"))
	}
	if scopeAdvanced {
		observed, proven, err := c.recheckHandoffSourceScopeAdvance(ctx, manifest, *source)
		if err != nil || !proven {
			return errors.Join(ErrS2RecoveryUnknown, ErrS2AuthorityChanged, errors.New("handoff source scope advance no longer holds before the observation write"), err)
		}
		source = &observed
	}
	source.Report.Availability = "available"
	source.Report.Reason = nil
	source.Report.LastObservedAt = c.now()
	return c.Store.PutContinuitySource(ctx, *source)
}

// handoffSourceRegistrationExact is every registration clause the handoff
// source re-observation requires. The registration tuple never advances with
// the source row: it must stay exactly the binding the handoff was prepared
// with.
func handoffSourceRegistrationExact(registration *state.LocalContinuityRegistration, binding model.ContinuationBindingRefV1, manifest model.ContinuationHandoffManifestV1) bool {
	return registration != nil && registration.ObservedStatus == "verified" && registration.Manifest.ContinuityEnabled &&
		registration.Manifest.DesiredState == "active" && registration.Manifest.Binding.BindingRevision == binding.BindingRevision &&
		registration.Manifest.ScopeRevision == binding.ScopeRevision && registration.ServiceGeneration == binding.ServiceGeneration &&
		sameS2Identity(registration.Manifest.Identity, manifest.Identity) && sameS2Binding(registration.Manifest.Binding, binding)
}

// handoffSourceSuccessionDeferral classifies the one monotonic succession the
// owner-authorized acknowledgement phase may have durably applied to a ready
// handoff's stored source binding. The stored handoff binding is the historical
// predecessor and the current local registration must be its exact successor:
// same binding ID, binding revision exactly predecessor + 1, scope exactly
// predecessor + 1, desired state active and continuity enabled, with every
// immutable identity, binding, service-generation, workspace, sandbox,
// native-location, role, profile, instruction, project and epoch fence still
// matching the handoff's source service and source row. The manifest-dependent
// half of the classification is confirmed by the reconciler; every other
// mismatch returns nil so the caller keeps the existing fatal
// ErrS2RecoveryUnknown path. This predicate never replaces or weakens
// handoffSourceRegistrationExact and never writes anything.
func (c *S2Controller) handoffSourceSuccessionDeferral(
	ctx context.Context,
	registration *state.LocalContinuityRegistration,
	binding model.ContinuationBindingRefV1,
	manifest model.ContinuationHandoffManifestV1,
) error {
	if registration == nil || binding.BindingRevision < 1 || binding.ScopeRevision < 1 {
		return nil
	}
	successor := registration.Manifest
	if successor.Binding.BindingID != binding.BindingID ||
		successor.Binding.BindingRevision != binding.BindingRevision+1 ||
		successor.ScopeRevision != binding.ScopeRevision+1 ||
		successor.Identity.TaskID != nil || successor.Identity.TaskAttempt != nil {
		return nil
	}
	successorBinding := binding
	successorBinding.BindingRevision = binding.BindingRevision + 1
	successorBinding.ScopeRevision = binding.ScopeRevision + 1
	successorManifest := manifest
	successorManifest.Binding = successorBinding
	if !handoffSourceRegistrationExact(registration, successorBinding, successorManifest) {
		return nil
	}
	source, err := c.Store.ContinuitySource(ctx, binding.RegisteredSourceID)
	if err != nil || source == nil {
		return nil
	}
	service, err := c.Store.ManagedService(ctx, binding.ServiceRegistrationID)
	if err != nil || service == nil {
		return nil
	}
	if !handoffSourceServiceAuthorityExact(service, successorBinding, successorManifest) ||
		!handoffSourceServiceInstructionExact(service) ||
		!handoffSourceRowExact(source, service, successorManifest) {
		return nil
	}
	sandbox, err := c.Store.Sandbox(ctx, manifest.Identity.SandboxID)
	if err != nil || !handoffSourceSandboxRunning(sandbox, successorManifest) {
		return nil
	}
	return &HandoffSourceSuccessionDeferral{
		BindingID: binding.BindingID,
		fatal: errors.Join(ErrS2RecoveryUnknown,
			errors.New("handoff source registration no longer matches the stored manifest")),
	}
}

// handoffSourceServiceAuthorityExact is every source-service generation and
// identity clause the handoff source re-observation requires.
func handoffSourceServiceAuthorityExact(service *state.LocalManagedService, binding model.ContinuationBindingRefV1, manifest model.ContinuationHandoffManifestV1) bool {
	return service != nil && service.ServiceGeneration == binding.ServiceGeneration &&
		service.Report.ServiceGeneration == binding.ServiceGeneration &&
		service.Manifest.Identity.ServiceRegistrationID == binding.ServiceRegistrationID &&
		service.Manifest.Identity.SandboxID == manifest.Identity.SandboxID &&
		service.Manifest.Identity.SandboxGeneration == manifest.Identity.SandboxGeneration
}

// handoffSourceServiceInstructionExact is the instruction tuple the stored
// source service report must still prove.
func handoffSourceServiceInstructionExact(service *state.LocalManagedService) bool {
	return service != nil && service.Report.InstructionRevision == service.Manifest.Instructions.InstructionRevision &&
		service.Report.InstructionDigest == service.Manifest.Instructions.InstructionDigest
}

// handoffSourceSandboxRunning is the sandbox lifecycle clause the handoff
// source re-observation requires.
func handoffSourceSandboxRunning(sandbox *state.LocalSandbox, manifest model.ContinuationHandoffManifestV1) bool {
	return sandbox != nil && sandbox.ObservedState == "running" &&
		sandbox.ObservedGeneration == manifest.Identity.SandboxGeneration
}

// handoffSourceRowExact is every source-row clause except the separately proven
// scope relation: the stored scope itself, or the single guarded one-step
// advance owner decision A27 admits only when the durable records prove it.
func handoffSourceRowExact(source *state.LocalContinuitySource, service *state.LocalManagedService, manifest model.ContinuationHandoffManifestV1) bool {
	if source == nil || service == nil {
		return false
	}
	binding := manifest.Binding
	return source.Report.RegisteredSourceID == binding.RegisteredSourceID &&
		source.Report.ServiceRegistrationID == binding.ServiceRegistrationID &&
		source.Report.ServiceGeneration == binding.ServiceGeneration &&
		source.Report.ProjectID == manifest.Identity.ProjectID &&
		source.Report.SandboxID == manifest.Identity.SandboxID &&
		source.Report.SandboxGeneration == manifest.Identity.SandboxGeneration &&
		source.Report.WorkspaceEpoch == manifest.Identity.WorkspaceEpoch &&
		(source.Report.ScopeRevision == binding.ScopeRevision ||
			handoffSourceScopeAdvanceWithinOne(binding.ScopeRevision, source.Report.ScopeRevision)) &&
		source.Report.NativeSessionID == binding.NativeSessionID && source.Report.NativeProjectID == binding.NativeProjectID &&
		source.Report.NativeLocationDigest == binding.NativeLocationDigest &&
		source.Report.Role == service.Manifest.Identity.Role &&
		source.Report.ProfileRevision == service.Manifest.Profile.ProfileRevision &&
		source.Report.InstructionRevision == service.Manifest.Instructions.InstructionRevision
}

// handoffSourceScopeAdvanceWithinOne reports whether an observed scope is
// exactly the one step beyond the stored handoff binding. A zero, negative or
// maximal binding has no representable one-step successor, so it never
// qualifies.
func handoffSourceScopeAdvanceWithinOne(binding, observed int64) bool {
	return binding >= 1 && binding < math.MaxInt64 && observed == binding+1
}

// handoffSourceScopeAdvanceProven proves the guarded one-step source scope
// advance owner decision A27 authorizes from durable current records alone. The
// caller's observed rows never decide anything: the matching managed project is
// read here.
func (c *S2Controller) handoffSourceScopeAdvanceProven(ctx context.Context, binding model.ContinuationBindingRefV1, identity model.ContinuationIdentityV1, source state.LocalContinuitySource, service state.LocalManagedService) (bool, error) {
	project, err := c.Store.ManagedProject(ctx, service.Manifest.Workspace.SelectionID)
	if err != nil {
		return false, err
	}
	return handoffSourceScopeAdvanceRecords(binding, identity, source, service, project), nil
}

// handoffSourceScopeAdvanceRecords is the complete durable-records predicate
// for the one-step advance: the same service generation carries the advanced
// workspace scope, its exact selection/project/workspace-epoch, sandbox
// generation, service registration, designation and root match one ready,
// available team project, and that project still carries the exact current
// service root, the nonempty A5 superseded-root provenance, a fully nonzero
// durable image identity and the A5 anchor/root-device fence. The service scope
// and the source scope must both equal exactly the stored binding plus one, and
// the project the service carries must be the stored handoff identity's
// project and workspace epoch.
func handoffSourceScopeAdvanceRecords(binding model.ContinuationBindingRefV1, identity model.ContinuationIdentityV1, source state.LocalContinuitySource, service state.LocalManagedService, project *state.LocalManagedProject) bool {
	if !handoffSourceScopeAdvanceWithinOne(binding.ScopeRevision, source.Report.ScopeRevision) {
		return false
	}
	if service.Manifest.Workspace.ScopeRevision != binding.ScopeRevision+1 {
		return false
	}
	workspace := service.Manifest.Workspace
	if workspace.ProjectID != identity.ProjectID || workspace.WorkspaceEpoch != identity.WorkspaceEpoch {
		return false
	}
	if project == nil || project.Phase != "ready" || project.Report.Availability != "available" ||
		project.Report.SelectionID != workspace.SelectionID || project.Report.ProjectID != workspace.ProjectID ||
		project.Report.WorkspaceEpoch != workspace.WorkspaceEpoch ||
		project.Report.SandboxID != service.Manifest.Identity.SandboxID ||
		project.Report.SandboxGeneration != service.Manifest.Identity.SandboxGeneration ||
		project.Report.ServiceRegistrationID == nil ||
		*project.Report.ServiceRegistrationID != service.Manifest.Identity.ServiceRegistrationID ||
		project.Report.Designation != "team_project" || workspace.Designation != "team_project" ||
		project.Report.RootAttestation == "" || project.Report.RootAttestation != workspace.RootAttestation {
		return false
	}
	// The exact current service root the ordinary observation recorded: the
	// record must still carry the root the source row was observed at.
	if project.HostRoot == "" || source.Root == "" || project.HostRoot != source.Root {
		return false
	}
	// The A5 remount provenance and the A25 durable image identity: only a
	// record the documented remount re-attested carries the superseded root,
	// and only a record with a fully nonzero durable object identity proves the
	// backing image.
	if project.SupersededRootAttestation == "" {
		return false
	}
	if project.ImageIdentity.Device == 0 || project.ImageIdentity.Inode == 0 || project.ImageIdentity.Size == 0 {
		return false
	}
	// The A5 anchor/root-device fence.
	if project.AnchorDevice == 0 || project.AnchorDevice != project.RootDevice {
		return false
	}
	return true
}

// recheckHandoffSourceScopeAdvance re-reads the source, registration, service,
// sandbox and managed-project records after the external supervisor status
// receipt and re-proves the complete source authority and the one-step scope
// advance immediately before the observation write. Any read error, any moved
// authority clause or any change to the source row beyond the observation
// fields returns not-proven and the caller writes nothing. The freshly read
// source row is returned so the successful write is based on current durable
// state.
func (c *S2Controller) recheckHandoffSourceScopeAdvance(ctx context.Context, manifest model.ContinuationHandoffManifestV1, initial state.LocalContinuitySource) (state.LocalContinuitySource, bool, error) {
	binding := manifest.Binding
	registration, err := c.Store.ContinuityRegistration(ctx, binding.BindingID)
	if err != nil {
		return initial, false, err
	}
	if !handoffSourceRegistrationExact(registration, binding, manifest) {
		return initial, false, nil
	}
	source, err := c.Store.ContinuitySource(ctx, binding.RegisteredSourceID)
	if err != nil {
		return initial, false, err
	}
	service, err := c.Store.ManagedService(ctx, binding.ServiceRegistrationID)
	if err != nil {
		return initial, false, err
	}
	if !handoffSourceServiceAuthorityExact(service, binding, manifest) ||
		!handoffSourceServiceInstructionExact(service) ||
		service.Phase != "ready" || service.Report.ObservedState != "ready" || !service.Report.InstructionApplied {
		return initial, false, nil
	}
	sandbox, err := c.Store.Sandbox(ctx, manifest.Identity.SandboxID)
	if err != nil {
		return initial, false, err
	}
	if !handoffSourceSandboxRunning(sandbox, manifest) {
		return initial, false, nil
	}
	if source == nil || !handoffSourceRowExact(source, service, manifest) {
		return initial, false, nil
	}
	if !handoffSourceObservationStable(initial, *source) {
		return initial, false, nil
	}
	project, err := c.Store.ManagedProject(ctx, service.Manifest.Workspace.SelectionID)
	if err != nil {
		return initial, false, err
	}
	if !handoffSourceScopeAdvanceRecords(binding, manifest.Identity, *source, *service, project) {
		return initial, false, nil
	}
	return *source, true, nil
}

// handoffSourceObservationStable reports whether the freshly read source row is
// still exactly the row the probe proved, ignoring only the observation fields
// this path is about to move.
func handoffSourceObservationStable(initial, observed state.LocalContinuitySource) bool {
	expected, current := initial, observed
	expected.Report.Availability, current.Report.Availability = "", ""
	expected.Report.Reason, current.Report.Reason = nil, nil
	expected.Report.LastObservedAt, current.Report.LastObservedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(expected, current)
}

// reobserveHandoffServiceSource probes the target managed service's registered
// primary source through the supervisor status boundary, using the exact
// target-service authority already validated by validateHandoffTarget. The row
// is advanced only by a current running+ready receipt that proves the exact
// service generation, sandbox, workspace, native session, role, profile, and
// instruction tuple.
func (c *S2Controller) reobserveHandoffServiceSource(ctx context.Context, target currentHandoffTarget) error {
	service := target.service
	native := service.Report.NativeRegistration
	if native == nil {
		return errors.Join(ErrS2RecoveryUnknown, errors.New("handoff target service has no native registration"))
	}
	source, err := c.Store.ContinuitySource(ctx, native.RegisteredSourceID)
	if err != nil || source == nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	if source.Report.RegisteredSourceID != native.RegisteredSourceID ||
		source.Report.ServiceRegistrationID != service.Manifest.Identity.ServiceRegistrationID ||
		source.Report.ServiceGeneration != service.ServiceGeneration || source.Report.ServiceGeneration != service.Report.ServiceGeneration ||
		source.Report.ProjectID != service.Manifest.Workspace.ProjectID ||
		source.Report.SandboxID != service.Manifest.Identity.SandboxID ||
		source.Report.SandboxGeneration != service.Manifest.Identity.SandboxGeneration ||
		source.Report.WorkspaceEpoch != service.Manifest.Workspace.WorkspaceEpoch || source.Report.WorkspaceEpoch != native.WorkspaceEpoch ||
		source.Report.ScopeRevision != service.Manifest.Workspace.ScopeRevision ||
		source.Report.NativeSessionID != native.NativeSessionID || source.Report.NativeProjectID != native.NativeProjectID ||
		source.Report.NativeLocationDigest != native.NativeLocationDigest ||
		source.Report.Role != service.Manifest.Identity.Role ||
		source.Report.ProfileRevision != service.Manifest.Profile.ProfileRevision ||
		source.Report.InstructionRevision != service.Manifest.Instructions.InstructionRevision ||
		source.Root != target.primary.HostRoot || source.Instance != service.Manifest.Identity.Instance ||
		source.Lifecycle != "running" {
		return errors.Join(ErrS2RecoveryUnknown, ErrS2AuthorityChanged, errors.New("handoff target service source no longer matches the stored service"))
	}
	statusPayload, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "sandboxId": service.Manifest.Identity.SandboxID, "instance": service.Manifest.Identity.Instance,
		"profileId": service.Manifest.Profile.ProfileID, "profileDigest": service.Manifest.Profile.ProfileDigest,
		"probe": true, "requestTimeoutSeconds": 30,
	})
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	stdout, stderr, err := c.HandoffSupervisor.ExecManagedSupervisor(ctx, service.Manifest.Identity.SandboxID, containers.ManagedSupervisorStatus, statusPayload)
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, ErrHandoffProbeUnknown, fmt.Errorf("handoff target service status probe: %s: %w", boundedHelperOutput(stderr), err))
	}
	receipt, err := decodeHandoffStatusReceipt(stdout)
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	if receipt.SchemaVersion != 1 || receipt.Command != "status" || receipt.Status != "running" || !receipt.Ready ||
		receipt.SessionID != native.NativeSessionID || receipt.NativeProjectID != native.NativeProjectID ||
		receipt.NativeLocationDigest != native.NativeLocationDigest ||
		receipt.InstructionRevision != service.Manifest.Instructions.InstructionRevision ||
		receipt.InstructionDigest != service.Manifest.Instructions.InstructionDigest || !receipt.InstructionApplied {
		return errors.Join(ErrS2RecoveryUnknown, errors.New("handoff target service status probe did not prove the registered primary session"))
	}
	source.Report.Availability = "available"
	source.Report.Reason = nil
	source.Report.LastObservedAt = c.now()
	return c.Store.PutContinuitySource(ctx, *source)
}

// reobserveHandoffTarget probes the separate target session through the
// idempotent reconcile_handoff request. Only a ready/prepared envelope whose
// session tuple equals the stored ready report advances the target
// LastObservedAt; any refusal or transport error leaves the row untouched.
func (c *S2Controller) reobserveHandoffTarget(ctx context.Context, record state.LocalContinuationHandoffPreparation, instance string) error {
	report := record.Report
	if report == nil || report.Session == nil || report.TargetWorkspace == nil {
		return errors.Join(ErrS2RecoveryUnknown, errors.New("ready handoff report lacks the prepared target tuple"))
	}
	request := handoffHelperRequest{
		ContinuationHandoffManifestV1: record.Manifest, Instance: instance,
		TargetWorkspace: *report.TargetWorkspace,
	}
	request.Action = "reconcile_handoff"
	response, refusal, err := c.execHandoffReconcile(ctx, record.Manifest.TargetPolicy.SandboxID, request)
	if refusal != "" {
		return errors.Join(ErrS2RecoveryUnknown, fmt.Errorf("handoff target reconcile refused: %s", refusal))
	}
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, ErrHandoffProbeUnknown, err)
	}
	probed, err := handoffPreparedReport(record.Manifest, *report.TargetWorkspace, response)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(probed.Session, report.Session) {
		return errors.Join(ErrS2RecoveryUnknown, errors.New("handoff target session changed since the ready report"))
	}
	source, err := c.Store.ContinuitySource(ctx, report.Session.RegisteredSourceID)
	if err != nil || source == nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	source.Report.Availability = "available"
	source.Report.Reason = nil
	source.Report.LastObservedAt = c.now()
	return c.Store.PutContinuitySource(ctx, *source)
}

// decodeHandoffStatusReceipt parses the bounded supervisor status receipt. The
// live receipt carries supervisor fields beyond the probe tuple, so only the
// modeled fields are verified and everything else is ignored.
func decodeHandoffStatusReceipt(payload []byte) (handoffStatusReceipt, error) {
	if len(payload) == 0 || len(payload) > 64*1024 {
		return handoffStatusReceipt{}, errors.New("handoff status receipt size is invalid")
	}
	var receipt handoffStatusReceipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		return handoffStatusReceipt{}, err
	}
	return receipt, nil
}

func (c *S2Controller) ApplyHandoffReleases(ctx context.Context, releases []model.ContinuationHandoffReleaseManifestV1) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.handoffConfigured(); err != nil {
		if len(releases) == 0 {
			return nil
		}
		return err
	}
	for _, release := range releases {
		if err := c.applyHandoffRelease(ctx, release); err != nil {
			return err
		}
	}
	return nil
}

func (c *S2Controller) HandoffReports(ctx context.Context) ([]model.ContinuationHandoffReportV1, []model.ContinuationHandoffReleaseReportV1, error) {
	preparations, err := c.Store.ContinuationHandoffPreparations(ctx)
	if err != nil {
		return nil, nil, err
	}
	releases, err := c.Store.ContinuationHandoffReleases(ctx)
	if err != nil {
		return nil, nil, err
	}
	preparedReports := make([]model.ContinuationHandoffReportV1, 0, len(preparations))
	for _, record := range preparations {
		if record.Report != nil {
			preparedReports = append(preparedReports, *record.Report)
		}
	}
	releaseReports := make([]model.ContinuationHandoffReleaseReportV1, 0, len(releases))
	for _, record := range releases {
		if record.Report != nil {
			releaseReports = append(releaseReports, *record.Report)
		}
	}
	return preparedReports, releaseReports, nil
}

func (c *S2Controller) applyHandoff(ctx context.Context, manifest model.ContinuationHandoffManifestV1) error {
	existing, err := c.Store.ContinuationHandoffPreparation(ctx, manifest.OperationID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Manifest, manifest) {
			return state.ErrContinuationHandoffConflict
		}
		if existing.Report != nil {
			return nil
		}
		return c.recoverHandoff(ctx, *existing)
	}
	source, checkpoint, target, err := c.validateHandoffAuthority(ctx, manifest)
	if err != nil {
		return err
	}
	if err := c.Store.PutContinuationHandoffPreparation(ctx, state.LocalContinuationHandoffPreparation{
		Manifest: manifest, Phase: "allocating",
	}); err != nil {
		return err
	}
	project, err := c.realizeHandoffWorkspace(ctx, manifest, source, checkpoint, target)
	if err != nil {
		return err
	}
	return c.completeHandoffWorkspace(ctx, manifest, target.service, project)
}

// completeHandoffWorkspace registers the realized target and dispatches the
// single native preparation before publishing the ready report.
func (c *S2Controller) completeHandoffWorkspace(
	ctx context.Context,
	manifest model.ContinuationHandoffManifestV1,
	service state.LocalManagedService,
	project workspacecatalog.RegisteredProject,
) error {
	if err := c.Store.SetContinuationHandoffPhase(ctx, manifest.OperationID, "workspace_registered", project.Report.SelectionID); err != nil {
		return err
	}
	if err := c.registerHandoffWorkspace(ctx, manifest, service, project); err != nil {
		return err
	}
	response, err := c.execHandoffHelper(ctx, manifest.TargetPolicy.SandboxID, handoffHelperRequest{
		ContinuationHandoffManifestV1: manifest, Instance: service.Manifest.Identity.Instance,
		TargetWorkspace: handoffWorkspace(project),
	})
	if err != nil {
		_ = c.Store.SetContinuationHandoffPhase(ctx, manifest.OperationID, "recovery_required", project.Report.SelectionID)
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	var report model.ContinuationHandoffReportV1
	if err := decodeClosed(response, &report); err != nil || !validHandoffReadyReport(manifest, handoffWorkspace(project), report) {
		_ = c.Store.SetContinuationHandoffPhase(ctx, manifest.OperationID, "recovery_required", project.Report.SelectionID)
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	return c.publishHandoffReady(ctx, manifest, project, report, service.Manifest.Identity.Instance)
}

// recoverMaterializedHandoff resumes a preparation that was persisted after the
// target workspace was materialized but before workspace registration and the
// native prepare_handoff dispatch. Those steps are ordered behind the
// workspace_registered phase write, so a durable materializing record proves
// the native preparation never ran. Only the retained target and checkpoint are
// re-validated: the source authority may have advanced since the handoff was
// accepted, while the materialized target remains authoritative.
func (c *S2Controller) recoverMaterializedHandoff(ctx context.Context, record state.LocalContinuationHandoffPreparation) error {
	manifest := record.Manifest
	target, err := c.validateHandoffTarget(ctx, manifest.TargetPolicy)
	if err != nil {
		return err
	}
	project, err := c.Store.ManagedProject(ctx, record.TargetSelectionID)
	if err != nil || project == nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	if project.Report.SelectionID != record.TargetSelectionID || project.Report.Designation != "continuity-handoff" ||
		project.Report.ProjectID == "" || project.Report.WorkspaceEpoch == "" || project.Report.RootAttestation == "" ||
		project.RootInode == 0 || (project.Phase != "handoff_allocated" && project.Phase != "ready") ||
		project.ServerID != c.ServerID || project.TeamID != manifest.TargetPolicy.TeamID || project.MemberID != manifest.TargetPolicy.MemberID ||
		project.Report.SandboxID != manifest.TargetPolicy.SandboxID ||
		project.Report.SandboxGeneration != manifest.TargetPolicy.SandboxGeneration ||
		project.Report.ServiceRegistrationID == nil || *project.Report.ServiceRegistrationID != manifest.TargetPolicy.ServiceRegistrationID {
		return ErrS2AuthorityChanged
	}
	checkpoint, err := c.validateRetainedCheckpoint(ctx, manifest.Identity, manifest.Checkpoint)
	if err != nil {
		return err
	}
	source, err := c.Store.ContinuitySource(ctx, manifest.Binding.RegisteredSourceID)
	if err != nil || source == nil || source.Root == "" {
		return errors.Join(ErrS2AuthorityChanged, err)
	}
	registered, err := c.realizeHandoffWorkspace(ctx, manifest, currentS2Authority{source: *source}, checkpoint, target)
	if err != nil {
		return err
	}
	return c.completeHandoffWorkspace(ctx, manifest, target.service, registered)
}

// recoverRegisteredHandoff resumes a preparation whose single prepare_handoff
// dispatch failed after the workspace was registered. The helper's reconcile
// refusal for a missing session record positively proves no native session was
// created, so the ready target is re-driven through the idempotent register and
// prepare path; a prepared envelope publishes directly. Only the retained
// target is re-validated because the source authority may have advanced.
func (c *S2Controller) recoverRegisteredHandoff(ctx context.Context, record state.LocalContinuationHandoffPreparation) error {
	manifest := record.Manifest
	target, err := c.validateHandoffTarget(ctx, manifest.TargetPolicy)
	if err != nil {
		return err
	}
	projectRecord, err := c.Store.ManagedProject(ctx, record.TargetSelectionID)
	if err != nil || projectRecord == nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	if projectRecord.Report.SelectionID != record.TargetSelectionID || projectRecord.Report.Designation != "continuity-handoff" ||
		projectRecord.Report.ProjectID == "" || projectRecord.Report.WorkspaceEpoch == "" || projectRecord.Report.RootAttestation == "" ||
		projectRecord.RootInode == 0 || projectRecord.Phase != "ready" ||
		projectRecord.ServerID != c.ServerID || projectRecord.TeamID != manifest.TargetPolicy.TeamID ||
		projectRecord.MemberID != manifest.TargetPolicy.MemberID ||
		projectRecord.Report.SandboxID != manifest.TargetPolicy.SandboxID ||
		projectRecord.Report.SandboxGeneration != manifest.TargetPolicy.SandboxGeneration ||
		projectRecord.Report.ServiceRegistrationID == nil || *projectRecord.Report.ServiceRegistrationID != manifest.TargetPolicy.ServiceRegistrationID {
		return ErrS2AuthorityChanged
	}
	project := workspacecatalog.RegisteredProject{
		Report: projectRecord.Report, HostRoot: projectRecord.HostRoot, ContainerRoot: projectRecord.ContainerRoot,
		ScopeRevision: projectRecord.ScopeRevision, RootDevice: projectRecord.RootDevice, RootInode: projectRecord.RootInode,
	}
	request := handoffHelperRequest{
		ContinuationHandoffManifestV1: manifest, Instance: target.service.Manifest.Identity.Instance,
		TargetWorkspace: handoffWorkspace(project),
	}
	request.Action = "reconcile_handoff"
	response, refusal, err := c.execHandoffReconcile(ctx, manifest.TargetPolicy.SandboxID, request)
	if refusal != "" {
		if refusal == "handoff_session_missing" {
			return c.completeHandoffWorkspace(ctx, manifest, target.service, project)
		}
		return errors.Join(ErrS2RecoveryUnknown, fmt.Errorf("continuation handoff reconcile refused: %s", refusal))
	}
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	report, err := handoffPreparedReport(manifest, handoffWorkspace(project), response)
	if err != nil {
		return err
	}
	return c.publishHandoffReady(ctx, manifest, project, *report, target.service.Manifest.Identity.Instance)
}

func (c *S2Controller) recoverHandoff(ctx context.Context, record state.LocalContinuationHandoffPreparation) error {
	if record.Phase == "materializing" && record.TargetSelectionID != "" &&
		record.Manifest.Workspace.Mode == "allocate_and_materialize" {
		return c.recoverMaterializedHandoff(ctx, record)
	}
	if record.Phase == "recovery_required" && record.TargetSelectionID != "" &&
		record.Manifest.Workspace.Mode == "allocate_and_materialize" {
		return c.recoverRegisteredHandoff(ctx, record)
	}
	_, _, target, err := c.validateHandoffAuthority(ctx, record.Manifest)
	if err != nil {
		return err
	}
	if record.TargetSelectionID == "" {
		return ErrS2RecoveryUnknown
	}
	projectRecord, err := c.Store.ManagedProject(ctx, record.TargetSelectionID)
	if err != nil || projectRecord == nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	project := workspacecatalog.RegisteredProject{
		Report: projectRecord.Report, HostRoot: projectRecord.HostRoot,
		ContainerRoot: projectRecord.ContainerRoot, ScopeRevision: projectRecord.ScopeRevision,
	}
	request := handoffHelperRequest{
		ContinuationHandoffManifestV1: record.Manifest, Instance: target.service.Manifest.Identity.Instance,
		TargetWorkspace: handoffWorkspace(project),
	}
	request.Action = "reconcile_handoff"
	response, err := c.execHandoffHelper(ctx, record.Manifest.TargetPolicy.SandboxID, request)
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	report, err := handoffPreparedReport(record.Manifest, handoffWorkspace(project), response)
	if err != nil {
		return err
	}
	return c.publishHandoffReady(ctx, record.Manifest, project, *report, target.service.Manifest.Identity.Instance)
}

// handoffPreparedReport accepts only a ready/prepared reconcile envelope whose
// report matches the stored manifest and the registered target workspace.
func handoffPreparedReport(manifest model.ContinuationHandoffManifestV1, workspace model.ContinuationHandoffTargetWorkspaceV1, response []byte) (*model.ContinuationHandoffReportV1, error) {
	var envelope handoffRecoveryEnvelope
	if err := decodeClosed(response, &envelope); err != nil || envelope.FormatVersion != 1 ||
		envelope.Action != "reconcile_handoff" || envelope.Report == nil ||
		!validHandoffReadyReport(manifest, workspace, *envelope.Report) {
		return nil, errors.Join(ErrS2RecoveryUnknown, err)
	}
	if envelope.Status != "ready" || envelope.State != "prepared" || envelope.Consumption != nil || envelope.Release != nil {
		return nil, ErrS2RecoveryUnknown
	}
	return envelope.Report, nil
}

func (c *S2Controller) realizeHandoffWorkspace(
	ctx context.Context,
	manifest model.ContinuationHandoffManifestV1,
	source currentS2Authority,
	checkpoint *state.LocalCheckpoint,
	target currentHandoffTarget,
) (workspacecatalog.RegisteredProject, error) {
	if manifest.Workspace.Mode == "accepted_restore" {
		restore, err := c.Store.RestoreOperation(ctx, *manifest.Workspace.RestoreOperationID)
		if err != nil || restore == nil || restore.Report == nil || restore.Report.Status != "accepted" || restore.Report.Target == nil {
			return workspacecatalog.RegisteredProject{}, errors.Join(ErrS2AuthorityChanged, err)
		}
		result := restore.Report.Target
		if result.SelectionID != *manifest.Workspace.SelectionID || result.ProjectID != *manifest.Workspace.ProjectID ||
			result.WorkspaceEpoch != *manifest.Workspace.WorkspaceEpoch || result.ScopeRevision != *manifest.Workspace.ScopeRevision ||
			result.RootAttestation != *manifest.Workspace.RootAttestation {
			return workspacecatalog.RegisteredProject{}, ErrS2AuthorityChanged
		}
		record, err := c.Store.ManagedProject(ctx, result.SelectionID)
		if err != nil || record == nil || record.Phase != "ready" || record.Report.Availability != "available" ||
			record.Report.SandboxID != manifest.TargetPolicy.SandboxID || record.Report.SandboxGeneration != manifest.TargetPolicy.SandboxGeneration ||
			record.Report.ProjectID != result.ProjectID || record.Report.WorkspaceEpoch != result.WorkspaceEpoch ||
			record.Report.RootAttestation != result.RootAttestation {
			return workspacecatalog.RegisteredProject{}, errors.Join(ErrS2AuthorityChanged, err)
		}
		if err := c.Objects.VerifyWorkspace(ctx, checkpoint.CaptureID, record.HostRoot); err != nil {
			return workspacecatalog.RegisteredProject{}, err
		}
		if err := c.Store.SetContinuationHandoffPhase(ctx, manifest.OperationID, "materializing", record.Report.SelectionID); err != nil {
			return workspacecatalog.RegisteredProject{}, err
		}
		return workspacecatalog.RegisteredProject{Report: record.Report, HostRoot: record.HostRoot, ContainerRoot: record.ContainerRoot, ScopeRevision: record.ScopeRevision, RootDevice: record.RootDevice, RootInode: record.RootInode}, nil
	}
	project, err := c.Catalog.AllocateHandoff(ctx, workspacecatalog.HandoffProjectRequest{
		OperationID: manifest.OperationID, Anchor: target.primary.Anchor, ServerID: c.ServerID,
		TeamID: manifest.TargetPolicy.TeamID, MemberID: manifest.TargetPolicy.MemberID,
		SandboxID: manifest.TargetPolicy.SandboxID, SandboxGeneration: manifest.TargetPolicy.SandboxGeneration,
		ServiceRegistrationID: manifest.TargetPolicy.ServiceRegistrationID,
	})
	if err != nil {
		return workspacecatalog.RegisteredProject{}, err
	}
	if err := c.Store.SetContinuationHandoffPhase(ctx, manifest.OperationID, "materializing", project.Report.SelectionID); err != nil {
		return workspacecatalog.RegisteredProject{}, err
	}
	destination := checkpoint.Identity
	destination.ProjectID, destination.WorkspaceEpoch = project.Report.ProjectID, project.Report.WorkspaceEpoch
	destination.SandboxID, destination.SandboxGeneration = manifest.TargetPolicy.SandboxID, manifest.TargetPolicy.SandboxGeneration
	destination.TaskID, destination.TaskAttempt = nil, nil
	receipt, err := c.Objects.MaterializeNew(ctx, storage.MaterializeNewRequest{
		CheckpointID: checkpoint.CaptureID, SourceIdentity: checkpoint.Identity, DestinationIdentity: destination,
		SourceRoot: source.source.Root, DestinationRoot: project.HostRoot,
		Ownership: &storage.MaterializationOwnership{Anchor: target.primary.Anchor, RootDevice: project.RootDevice, RootInode: project.RootInode},
	})
	if err != nil {
		return workspacecatalog.RegisteredProject{}, err
	}
	if receipt.ManifestDigest != manifest.Checkpoint.ManifestDigest || receipt.Bytes != manifest.Checkpoint.Bytes ||
		receipt.ObjectCount != manifest.Checkpoint.ObjectCount || !receipt.DestinationIdentity.Equal(destination) {
		return workspacecatalog.RegisteredProject{}, storage.ErrCheckpointCorrupt
	}
	project, err = c.Catalog.CompleteHandoff(ctx, manifest.OperationID)
	if err != nil {
		return workspacecatalog.RegisteredProject{}, err
	}
	if err := c.Objects.VerifyWorkspace(ctx, checkpoint.CaptureID, project.HostRoot); err != nil {
		return workspacecatalog.RegisteredProject{}, err
	}
	return project, nil
}

func (c *S2Controller) validateHandoffAuthority(ctx context.Context, manifest model.ContinuationHandoffManifestV1) (currentS2Authority, *state.LocalCheckpoint, currentHandoffTarget, error) {
	source, checkpoint, err := c.validateCommonAuthority(ctx, manifest.Identity, manifest.Binding, manifest.Checkpoint)
	if err != nil {
		return currentS2Authority{}, nil, currentHandoffTarget{}, err
	}
	target, err := c.validateHandoffTarget(ctx, manifest.TargetPolicy)
	if err != nil {
		return currentS2Authority{}, nil, currentHandoffTarget{}, err
	}
	return source, checkpoint, target, nil
}

// validateHandoffTarget checks only the durable target tuple shared by the
// stored manifest policy and the local target records.
func (c *S2Controller) validateHandoffTarget(ctx context.Context, target model.ContinuationHandoffTargetPolicyV1) (currentHandoffTarget, error) {
	return c.validateHandoffTargetMode(ctx, target, false)
}

// validateHandoffTargetForRecovery is the ready-preparation recovery variant.
// A target service that is transiently starting, or whose supported enrollment
// retry failed with enrollment_unavailable or enrollment_failed, and whose
// immutable authority clauses are otherwise exact returns ErrTargetServiceNotReady
// so the reconcile pass can continue into the ordinary service apply that
// advances the phase. Every other failure stays fail-closed exactly like
// validateHandoffTarget.
func (c *S2Controller) validateHandoffTargetForRecovery(ctx context.Context, target model.ContinuationHandoffTargetPolicyV1) (currentHandoffTarget, error) {
	return c.validateHandoffTargetMode(ctx, target, true)
}

func (c *S2Controller) validateHandoffTargetMode(ctx context.Context, target model.ContinuationHandoffTargetPolicyV1, deferTransient bool) (currentHandoffTarget, error) {
	sandbox, err := c.Store.Sandbox(ctx, target.SandboxID)
	if err != nil || sandbox == nil || sandbox.ObservedState != "running" || sandbox.ObservedGeneration != target.SandboxGeneration {
		return currentHandoffTarget{}, errors.Join(ErrS2AuthorityChanged, err)
	}
	service, err := c.Store.ManagedService(ctx, target.ServiceRegistrationID)
	if err != nil || service == nil {
		return currentHandoffTarget{}, errors.Join(ErrS2AuthorityChanged, err)
	}
	if deferTransient && service.Phase == "starting" && handoffTargetServiceExact(service, target) {
		return currentHandoffTarget{}, ErrTargetServiceNotReady
	}
	if deferTransient && enrollmentRetryableTargetService(service, target) {
		return currentHandoffTarget{}, ErrTargetServiceNotReady
	}
	if service.Phase != "ready" || !handoffTargetServiceExact(service, target) {
		return currentHandoffTarget{}, errors.Join(ErrS2AuthorityChanged, err)
	}
	primary, err := c.Store.ManagedProject(ctx, service.Manifest.Workspace.SelectionID)
	if err != nil || primary == nil || primary.Phase != "ready" || primary.Report.Availability != "available" ||
		primary.Report.ProjectID != service.Manifest.Workspace.ProjectID || primary.Report.WorkspaceEpoch != service.Manifest.Workspace.WorkspaceEpoch ||
		primary.Report.RootAttestation != service.Manifest.Workspace.RootAttestation || primary.Anchor == "" {
		return currentHandoffTarget{}, errors.Join(ErrS2AuthorityChanged, err)
	}
	return currentHandoffTarget{service: *service, primary: *primary}, nil
}

// handoffTargetServiceExact is every stored target-service clause except the
// transient phase itself.
func handoffTargetServiceExact(service *state.LocalManagedService, target model.ContinuationHandoffTargetPolicyV1) bool {
	return service.Report.ObservedState == "ready" && service.Report.InstructionApplied &&
		handoffTargetServiceAuthorityExact(service, target)
}

// handoffTargetServiceAuthorityExact is every immutable target-service
// authority clause shared by the ready and transiently failed recovery cases.
func handoffTargetServiceAuthorityExact(service *state.LocalManagedService, target model.ContinuationHandoffTargetPolicyV1) bool {
	return service.ServiceGeneration == target.ServiceGeneration && service.Report.ServiceGeneration == target.ServiceGeneration &&
		service.Manifest.ActionRevision == target.ServiceActionRevision && service.Manifest.DesiredRevision == target.ServiceDesiredRevision &&
		service.Manifest.Identity.TeamID == target.TeamID && service.Manifest.Identity.MemberID == target.MemberID &&
		service.Manifest.Identity.SandboxID == target.SandboxID && service.Manifest.Identity.SandboxGeneration == target.SandboxGeneration &&
		service.Manifest.Identity.ServiceRegistrationID == target.ServiceRegistrationID && service.Manifest.Identity.Role == target.Role &&
		service.Manifest.Profile.ProfileID == target.ProfileID && service.Manifest.Profile.ProfileRevision == target.ProfileRevision &&
		service.Manifest.Profile.ProfileDigest == target.ProfileDigest &&
		service.Manifest.Instructions.InstructionRevision == target.InstructionRevision &&
		service.Manifest.Instructions.InstructionDigest == target.InstructionDigest &&
		service.Report.InstructionRevision == target.InstructionRevision && service.Report.InstructionDigest == target.InstructionDigest
}

// enrollmentRetryableTargetService reports the supported transient enrollment
// failures: the exact immutable target authority with a durable and report
// enrollment proof (enrollment_unavailable or enrollment_failed) that the
// ordinary service apply retries.
func enrollmentRetryableTargetService(service *state.LocalManagedService, target model.ContinuationHandoffTargetPolicyV1) bool {
	if service.Phase != "failed" || service.Report.ObservedState != "failed" || service.Report.LastError == nil {
		return false
	}
	switch service.ErrorCode {
	case "enrollment_unavailable", "enrollment_failed":
	default:
		return false
	}
	return service.Report.LastError.Code == service.ErrorCode &&
		handoffTargetServiceAuthorityExact(service, target)
}

func (c *S2Controller) registerHandoffWorkspace(ctx context.Context, manifest model.ContinuationHandoffManifestV1, service state.LocalManagedService, project workspacecatalog.RegisteredProject) error {
	request := handoffWorkspaceRequest{
		SchemaVersion: 1, SandboxID: manifest.TargetPolicy.SandboxID,
		Instance: service.Manifest.Identity.Instance, ProfileID: service.Manifest.Profile.ProfileID,
		Registration: handoffWorkspaceRegistration{
			FormatVersion: 1, OperationID: manifest.OperationID, DesiredRevision: manifest.DesiredRevision,
			MappingID: manifest.MappingID, TargetWorkID: manifest.TargetWorkID,
			TargetWorkspace: handoffWorkspace(project), ProjectRoot: project.ContainerRoot,
		},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	stdout, stderr, err := c.HandoffSupervisor.ExecManagedSupervisor(ctx, manifest.TargetPolicy.SandboxID, containers.ManagedSupervisorRegisterHandoffWorkspace, payload)
	if err != nil {
		return fmt.Errorf("handoff workspace registration: %s: %w", boundedHelperOutput(stderr), err)
	}
	var receipt handoffWorkspaceReceipt
	if err := decodeClosed(stdout, &receipt); err != nil || receipt.SchemaVersion != 1 || receipt.Command != "register-handoff-workspace" ||
		(receipt.Status != "registered" && receipt.Status != "unchanged") || receipt.SandboxID != request.SandboxID ||
		receipt.Instance != request.Instance || receipt.ProfileID != request.ProfileID || receipt.OperationID != manifest.OperationID ||
		receipt.MappingID != manifest.MappingID || receipt.TargetWorkID != manifest.TargetWorkID ||
		receipt.TargetWorkspace != request.Registration.TargetWorkspace || receipt.Ready {
		return ErrS2RecoveryUnknown
	}
	return nil
}

func (c *S2Controller) publishHandoffReady(ctx context.Context, manifest model.ContinuationHandoffManifestV1, project workspacecatalog.RegisteredProject, report model.ContinuationHandoffReportV1, instance string) error {
	if err := c.Store.CompleteContinuationHandoffPreparation(ctx, manifest.OperationID, project.Report.SelectionID, report); err != nil {
		return err
	}
	session := report.Session
	if session == nil {
		return ErrS2RecoveryUnknown
	}
	existing, err := c.Store.ContinuitySource(ctx, session.RegisteredSourceID)
	if err != nil {
		return err
	}
	source := state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: session.RegisteredSourceID,
			ServiceRegistrationID: manifest.TargetPolicy.ServiceRegistrationID,
			ServiceGeneration:     manifest.TargetPolicy.ServiceGeneration, ProjectID: project.Report.ProjectID,
			SandboxID: manifest.TargetPolicy.SandboxID, SandboxGeneration: manifest.TargetPolicy.SandboxGeneration,
			WorkspaceEpoch: project.Report.WorkspaceEpoch, NativeSessionID: session.NativeSessionID,
			NativeProjectID: session.NativeProjectID, NativeLocationDigest: session.NativeLocationDigest,
			ScopeRevision: project.ScopeRevision, Role: manifest.TargetPolicy.Role,
			ProfileRevision:     manifest.TargetPolicy.ProfileRevision,
			InstructionRevision: manifest.TargetPolicy.InstructionRevision,
			Availability:        "available", LastObservedAt: c.now(),
		},
		Root: project.HostRoot, Instance: instance, Lifecycle: "running",
		LifecycleRevision: manifest.DesiredRevision, NoAdmittedExecution: true,
	}
	if existing != nil {
		source.Report.LastObservedAt = existing.Report.LastObservedAt
		if !reflect.DeepEqual(*existing, source) {
			return state.ErrContinuationHandoffConflict
		}
		return nil
	}
	return c.Store.PutContinuitySource(ctx, source)
}

func handoffWorkspace(project workspacecatalog.RegisteredProject) model.ContinuationHandoffTargetWorkspaceV1 {
	return model.ContinuationHandoffTargetWorkspaceV1{
		SelectionID: project.Report.SelectionID, ProjectID: project.Report.ProjectID,
		WorkspaceEpoch: project.Report.WorkspaceEpoch, ScopeRevision: project.ScopeRevision,
		RootAttestation: project.Report.RootAttestation,
	}
}

func validHandoffReadyReport(manifest model.ContinuationHandoffManifestV1, workspace model.ContinuationHandoffTargetWorkspaceV1, report model.ContinuationHandoffReportV1) bool {
	return report.Status == "ready" && report.ErrorCode == nil && report.TargetWorkspace != nil &&
		*report.TargetWorkspace == workspace && report.Session != nil && report.Baseline != nil &&
		report.Session.MappingID == manifest.MappingID && report.Session.InstructionApplied &&
		report.Session.InstructionRevision == manifest.TargetPolicy.InstructionRevision &&
		report.Session.InstructionDigest == manifest.TargetPolicy.InstructionDigest &&
		report.Baseline.NativeSessionID == report.Session.NativeSessionID &&
		report.Baseline.ServiceGeneration == manifest.TargetPolicy.ServiceGeneration &&
		continuationHandoffReportMatches(manifest, report) && digestPattern.MatchString(report.ReceiptDigest) &&
		digestPattern.MatchString(report.Session.NativeLocationDigest) && digestPattern.MatchString(report.Baseline.BaselineDigest) &&
		safeIdentifier.MatchString(report.Session.RegisteredSourceID) && safeIdentifier.MatchString(report.Session.NativeSessionID) &&
		safeIdentifier.MatchString(report.Baseline.BaselineID) && !report.Baseline.ReadyAt.IsZero()
}

func continuationHandoffReportMatches(manifest model.ContinuationHandoffManifestV1, report model.ContinuationHandoffReportV1) bool {
	return report.FormatVersion == manifest.FormatVersion && report.OperationID == manifest.OperationID && report.Action == manifest.Action &&
		report.DesiredRevision == manifest.DesiredRevision && report.HandoffKind == manifest.HandoffKind &&
		report.SessionMode == manifest.SessionMode && report.TargetWorkID == manifest.TargetWorkID && report.MappingID == manifest.MappingID &&
		reflect.DeepEqual(report.Identity, manifest.Identity) && reflect.DeepEqual(report.Binding, manifest.Binding) &&
		reflect.DeepEqual(report.Checkpoint, manifest.Checkpoint) && reflect.DeepEqual(report.Lineage, manifest.Lineage) &&
		reflect.DeepEqual(report.TargetPolicy, manifest.TargetPolicy) && reflect.DeepEqual(report.WorkspaceRequest, manifest.Workspace) &&
		report.ContextDigest == manifest.Context.Digest
}

// handoffTargetOwnership is the exact preparation and mapped source that own a
// continuation-handoff target registration.
type handoffTargetOwnership struct {
	preparation *state.LocalContinuationHandoffPreparation
	source      state.LocalContinuitySource
}

// handoffTargetRegistrationOwnedByPreparation reports whether one continuity
// registration exactly matches a completed ready continuation-handoff
// preparation whose mapped source is still current. A missing preparation
// returns (nil, false, nil); a lookup failure returns its error; an existing
// preparation the registration does not match returns ErrS2AuthorityChanged.
// Both the handoff target registration apply and the coordinator's
// registration-projection repair share this exact qualification.
func handoffTargetRegistrationOwnedByPreparation(ctx context.Context, store *state.Store, registration model.ContinuityRegistrationV1) (*handoffTargetOwnership, bool, error) {
	preparation, err := store.ContinuationHandoffBySource(ctx, registration.Binding.RegisteredSourceID)
	if err != nil {
		return nil, false, err
	}
	if preparation == nil {
		return nil, false, nil
	}
	if preparation.Report == nil || preparation.Report.Status != "ready" || preparation.Report.Session == nil ||
		preparation.Report.TargetWorkspace == nil || registration.DesiredState != "active" || !registration.ContinuityEnabled ||
		registration.Identity.WorkID != preparation.Manifest.TargetWorkID ||
		registration.Identity.ProjectID != preparation.Report.TargetWorkspace.ProjectID ||
		registration.Identity.SandboxID != preparation.Manifest.TargetPolicy.SandboxID ||
		registration.Identity.WorkspaceEpoch != preparation.Report.TargetWorkspace.WorkspaceEpoch ||
		registration.Identity.SandboxGeneration != preparation.Manifest.TargetPolicy.SandboxGeneration ||
		registration.Identity.TaskID != nil || registration.Identity.TaskAttempt != nil || registration.ScopeRevision != preparation.Report.TargetWorkspace.ScopeRevision ||
		registration.Binding.RegisteredSourceID != preparation.Report.Session.RegisteredSourceID ||
		registration.Binding.ServiceRegistrationID != preparation.Manifest.TargetPolicy.ServiceRegistrationID ||
		registration.Binding.NativeSessionID != preparation.Report.Session.NativeSessionID ||
		registration.Binding.NativeProjectID != preparation.Report.Session.NativeProjectID ||
		registration.Binding.NativeLocationDigest != preparation.Report.Session.NativeLocationDigest {
		return nil, false, fmt.Errorf("%w: target registration does not match prepared handoff", ErrS2AuthorityChanged)
	}
	source, err := store.ContinuitySource(ctx, registration.Binding.RegisteredSourceID)
	if err != nil || source == nil || source.Report.ServiceGeneration != preparation.Manifest.TargetPolicy.ServiceGeneration ||
		source.Report.ProjectID != registration.Identity.ProjectID || source.Report.WorkspaceEpoch != registration.Identity.WorkspaceEpoch {
		return nil, false, errors.Join(fmt.Errorf("%w: mapped source is no longer current", ErrS2AuthorityChanged), err)
	}
	return &handoffTargetOwnership{preparation: preparation, source: *source}, true, nil
}

// HandoffTargetRegistrationOwnedByPreparation reports whether one completed
// ready handoff preparation exactly owns the active registration as its mapped
// target source, using the complete existing target-registration fence. A
// missing preparation is not owned; a structural lookup failure or an existing
// preparation the registration does not match returns an error.
func HandoffTargetRegistrationOwnedByPreparation(ctx context.Context, store *state.Store, registration model.ContinuityRegistrationV1) (bool, error) {
	_, owned, err := handoffTargetRegistrationOwnedByPreparation(ctx, store, registration)
	return owned, err
}

func (c *S2Controller) ApplyHandoffTargetRegistrations(ctx context.Context, registrations []model.ContinuityRegistrationV1) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(registrations) == 0 {
		return nil
	}
	if err := c.handoffConfigured(); err != nil || c.HandoffAdmission == nil {
		return errors.Join(ErrS2ControllerUnavailable, err)
	}
	for _, registration := range registrations {
		ownership, owned, err := handoffTargetRegistrationOwnedByPreparation(ctx, c.Store, registration)
		if err != nil {
			return err
		}
		if !owned {
			continue
		}
		preparation, source := ownership.preparation, ownership.source
		request := model.ContinuationTargetRegistrationRequestV1{
			FormatVersion: 1, Action: "register_continuation_target", Instance: source.Instance,
			OperationID: preparation.Manifest.OperationID, PrepareDesiredRevision: preparation.Manifest.DesiredRevision,
			Registration: model.ContinuationTargetRegistrationV1{
				FormatVersion: 1, WorkID: registration.Identity.WorkID, ProjectID: registration.Identity.ProjectID,
				SandboxID: registration.Identity.SandboxID, WorkspaceEpoch: registration.Identity.WorkspaceEpoch,
				SandboxGeneration: registration.Identity.SandboxGeneration, TaskID: nil, TaskAttempt: nil,
				ExpectedRevision: registration.Identity.ExpectedRevision, BackgroundWriterState: "idle",
				LastAcceptedExecutionID: nil, Binding: registration.Binding,
			},
		}
		response, err := c.execHandoffHelper(ctx, registration.Identity.SandboxID, request)
		if err != nil {
			return err
		}
		var receipt model.ContinuationTargetRegistrationReceiptV1
		if err := decodeClosed(response, &receipt); err != nil || receipt.FormatVersion != 1 || receipt.Action != request.Action ||
			(receipt.Status != "registered" && receipt.Status != "unchanged") || receipt.OperationID != request.OperationID ||
			receipt.WorkID != registration.Identity.WorkID || receipt.ExpectedRevision != registration.Identity.ExpectedRevision ||
			receipt.Binding != registration.Binding || !digestPattern.MatchString(receipt.ReceiptDigest) {
			return ErrS2RecoveryUnknown
		}
		if err := c.Store.PutContinuityRegistration(ctx, state.LocalContinuityRegistration{
			Manifest: registration, ObservedStatus: "verified", ServiceGeneration: preparation.Manifest.TargetPolicy.ServiceGeneration,
			ReceiptDigest: receipt.ReceiptDigest,
		}); err != nil {
			return err
		}
		if err := c.HandoffAdmission.ScheduleContinuationHandoff(ctx, preparation.Manifest.OperationID, preparation.Manifest, registration); err != nil {
			return err
		}
	}
	return nil
}

func (c *S2Controller) applyHandoffRelease(ctx context.Context, release model.ContinuationHandoffReleaseManifestV1) error {
	existing, err := c.Store.ContinuationHandoffRelease(ctx, release.OperationID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Manifest, release) {
			return state.ErrContinuationHandoffConflict
		}
		if existing.Report != nil {
			return nil
		}
		return c.recoverHandoffRelease(ctx, release)
	}
	preparation, err := c.handoffReleasePreparation(ctx, release)
	if err != nil {
		return err
	}
	if err := c.Store.PutContinuationHandoffRelease(ctx, state.LocalContinuationHandoffRelease{Manifest: release, Phase: "releasing"}); err != nil {
		return err
	}
	instance, err := c.handoffInstance(ctx, preparation)
	if err != nil {
		return err
	}
	response, err := c.execHandoffHelper(ctx, release.TargetPolicy.SandboxID, handoffReleaseRequest{
		ContinuationHandoffReleaseManifestV1: release, Instance: instance,
	})
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	return c.acceptHandoffReleaseEnvelope(ctx, release, response, "release_handoff")
}

func (c *S2Controller) recoverHandoffRelease(ctx context.Context, release model.ContinuationHandoffReleaseManifestV1) error {
	preparation, err := c.handoffReleasePreparation(ctx, release)
	if err != nil {
		return err
	}
	instance, err := c.handoffInstance(ctx, preparation)
	if err != nil {
		return err
	}
	project, err := c.Store.ManagedProject(ctx, preparation.TargetSelectionID)
	if err != nil || project == nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	request := handoffHelperRequest{
		ContinuationHandoffManifestV1: preparation.Manifest, Instance: instance,
		TargetWorkspace: model.ContinuationHandoffTargetWorkspaceV1{
			SelectionID: project.Report.SelectionID, ProjectID: project.Report.ProjectID,
			WorkspaceEpoch: project.Report.WorkspaceEpoch, ScopeRevision: project.ScopeRevision,
			RootAttestation: project.Report.RootAttestation,
		},
	}
	request.Action = "reconcile_handoff"
	response, err := c.execHandoffHelper(ctx, release.TargetPolicy.SandboxID, request)
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	return c.acceptHandoffReleaseEnvelope(ctx, release, response, "reconcile_handoff")
}

func (c *S2Controller) acceptHandoffReleaseEnvelope(ctx context.Context, release model.ContinuationHandoffReleaseManifestV1, response []byte, action string) error {
	var envelope handoffRecoveryEnvelope
	if err := decodeClosed(response, &envelope); err != nil || envelope.FormatVersion != 1 || envelope.Action != action ||
		envelope.Status != "released" || envelope.State != "released" || envelope.Report == nil || envelope.Release == nil ||
		envelope.Consumption != nil || !validHandoffReleaseReport(release, *envelope.Release) {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	return c.Store.CompleteContinuationHandoffRelease(ctx, release.OperationID, *envelope.Release)
}

func (c *S2Controller) handoffReleasePreparation(ctx context.Context, release model.ContinuationHandoffReleaseManifestV1) (*state.LocalContinuationHandoffPreparation, error) {
	records, err := c.Store.ContinuationHandoffPreparations(ctx)
	if err != nil {
		return nil, err
	}
	for i := range records {
		record := &records[i]
		manifest := record.Manifest
		if manifest.DesiredRevision == release.PrepareDesiredRevision && manifest.MappingID == release.MappingID &&
			manifest.TargetWorkID == release.TargetWorkID && record.Report != nil &&
			releaseHandoffMatchesPreparation(release, manifest) {
			return record, nil
		}
	}
	return nil, ErrS2AuthorityChanged
}

func releaseHandoffMatchesPreparation(release model.ContinuationHandoffReleaseManifestV1, prepare model.ContinuationHandoffManifestV1) bool {
	return release.PrepareDesiredRevision == prepare.DesiredRevision && release.HandoffKind == prepare.HandoffKind &&
		release.SessionMode == prepare.SessionMode && release.TargetWorkID == prepare.TargetWorkID && release.MappingID == prepare.MappingID &&
		reflect.DeepEqual(release.Identity, prepare.Identity) && reflect.DeepEqual(release.Binding, prepare.Binding) &&
		reflect.DeepEqual(release.Checkpoint, prepare.Checkpoint) && reflect.DeepEqual(release.Lineage, prepare.Lineage) &&
		reflect.DeepEqual(release.TargetPolicy, prepare.TargetPolicy) && reflect.DeepEqual(release.Workspace, prepare.Workspace) &&
		reflect.DeepEqual(release.Context, prepare.Context)
}

func validHandoffReleaseReport(manifest model.ContinuationHandoffReleaseManifestV1, report model.ContinuationHandoffReleaseReportV1) bool {
	return reflect.DeepEqual(report.ContinuationHandoffReleaseManifestV1, manifest) && report.Status == "released" &&
		report.ErrorCode == nil && digestPattern.MatchString(report.ReceiptDigest)
}

func (c *S2Controller) handoffInstance(ctx context.Context, preparation *state.LocalContinuationHandoffPreparation) (string, error) {
	service, err := c.Store.ManagedService(ctx, preparation.Manifest.TargetPolicy.ServiceRegistrationID)
	if err != nil || service == nil || service.Manifest.Identity.Instance == "" {
		return "", errors.Join(ErrS2AuthorityChanged, err)
	}
	return service.Manifest.Identity.Instance, nil
}

func (c *S2Controller) execHandoffHelper(ctx context.Context, sandboxID string, request any) ([]byte, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	stdout, stderr, err := c.Helper.ExecContinuity(ctx, sandboxID, payload)
	if err != nil {
		return nil, fmt.Errorf("continuation handoff helper: %s: %w", boundedHelperOutput(stderr), err)
	}
	return stdout, nil
}

// execHandoffReconcile dispatches a reconcile_handoff request. A nonzero helper
// exit with a valid bounded refusal receipt on stdout returns the refusal code;
// every other execution failure keeps the execHandoffHelper error shape.
func (c *S2Controller) execHandoffReconcile(ctx context.Context, sandboxID string, request handoffHelperRequest) ([]byte, string, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, "", err
	}
	stdout, stderr, err := c.Helper.ExecContinuity(ctx, sandboxID, payload)
	if err == nil {
		return stdout, "", nil
	}
	var refusal handoffHelperRefusal
	if decodeClosed(stdout, &refusal) == nil && refusal.FormatVersion == 1 && refusal.Action == "reconcile_handoff" &&
		refusal.Status == "refused" && safeIdentifier.MatchString(refusal.Error) {
		return nil, refusal.Error, nil
	}
	return nil, "", fmt.Errorf("continuation handoff helper: %s: %w", boundedHelperOutput(stderr), err)
}

func (c *S2Controller) handoffConfigured() error {
	if err := c.configured(); err != nil {
		return err
	}
	if c.HandoffSupervisor == nil {
		return ErrS2ControllerUnavailable
	}
	return nil
}
