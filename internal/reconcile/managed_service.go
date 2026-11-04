package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

const managedServicePort = 18443

var managedNativeProjectPattern = regexp.MustCompile(`^(global|[a-f0-9]{40})$`)
var managedSafeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`)
var managedWorkerTaskPattern = regexp.MustCompile(`^task_[A-Za-z0-9_-]{4,72}$`)

var managedWorkerActivePhases = map[string]bool{
	"claimed": true, "payload": true, "prompt_pending": true, "running": true,
}

var managedWorkerSettledPhases = map[string]bool{
	"reported": true, "requeued": true, "reconciling": true,
}

type managedSupervisorReceipt struct {
	NativeRoleReadback         *model.ControllerRoleReadback   `json:"nativeRoleReadback,omitempty"`
	AppliedProfile             *model.AppliedExpertiseProfile  `json:"appliedProfile,omitempty"`
	MaterializerDigest         string                          `json:"materializerDigest,omitempty"`
	SchemaVersion              int                             `json:"schemaVersion"`
	Command                    string                          `json:"command"`
	Status                     string                          `json:"status"`
	Phase                      string                          `json:"phase"`
	Reason                     string                          `json:"reason"`
	Error                      string                          `json:"error"`
	Instance                   string                          `json:"instance"`
	SandboxID                  string                          `json:"sandboxId"`
	ProfileID                  string                          `json:"profileId"`
	ProfileDigest              string                          `json:"profileDigest"`
	ProfileRevision            int64                           `json:"profileRevision"`
	Version                    string                          `json:"version"`
	Hostname                   string                          `json:"hostname"`
	Port                       int                             `json:"port"`
	PID                        int                             `json:"pid"`
	Ready                      bool                            `json:"ready"`
	StartCount                 int                             `json:"startCount"`
	SessionID                  string                          `json:"sessionId"`
	SessionCreated             bool                            `json:"sessionCreated"`
	SessionReused              bool                            `json:"sessionReused"`
	SessionCreatedCount        int                             `json:"sessionCreatedCount"`
	ConversationCount          int                             `json:"conversationCount"`
	SessionMode                string                          `json:"sessionMode"`
	NativeProjectID            string                          `json:"nativeProjectId"`
	NativeLocationDigest       string                          `json:"nativeLocationDigest"`
	InstructionRevision        int64                           `json:"instructionRevision"`
	InstructionDigest          string                          `json:"instructionDigest"`
	InstructionApplied         bool                            `json:"instructionApplied"`
	ManagerPluginDigest        string                          `json:"managerPluginDigest"`
	ManagerPluginLoaded        bool                            `json:"managerPluginLoaded"`
	ManagerProfile             model.InsightsManagerProfileV1  `json:"managerProfile"`
	ManagerProviderID          string                          `json:"managerProviderId"`
	ManagerModelID             string                          `json:"managerModelId"`
	ManagerNativeProtocol      string                          `json:"managerNativeProtocol"`
	ManagerProviderRouteDigest string                          `json:"managerProviderRouteDigest"`
	ManagerRecommendAvailable  bool                            `json:"managerRecommendAvailable"`
	ManagerCapabilityReason    *string                         `json:"managerCapabilityReason"`
	ManagerRecipeIDs           []string                        `json:"managerRecipeIds"`
	NativeGuard                *model.NativeGuardObservationV1 `json:"nativeGuard,omitempty"`
	MonitorReadinessVersion    int                             `json:"monitorReadinessVersion"`
	MonitorEnabled             bool                            `json:"monitorEnabled"`
	MonitorSourceInstanceID    string                          `json:"monitorSourceInstanceId"`
	MonitorWorkspaceEpoch      string                          `json:"monitorWorkspaceEpoch"`
	MonitorWriterReady         bool                            `json:"monitorWriterReady"`
	MonitorJournalGeneration   string                          `json:"monitorJournalGeneration"`
	Applied                    bool                            `json:"applied"`
	Restarted                  bool                            `json:"restarted"`
	BindingRevision            int64                           `json:"bindingRevision"`
	Binding                    json.RawMessage                 `json:"binding"`
	Stored                     bool                            `json:"stored"`
	EnrollmentID               string                          `json:"enrollmentId"`
	Drained                    bool                            `json:"drained"`
	ReceiptDigest              string                          `json:"receiptDigest"`
	LeaseTokenPresent          bool                            `json:"leaseTokenPresent"`
	LeaseRole                  string                          `json:"leaseRole"`
	LeaseExpired               bool                            `json:"leaseExpired"`
	Generation                 int64                           `json:"generation"`
}

type managedWorkerReceipt struct {
	SchemaVersion int             `json:"schemaVersion"`
	Command       string          `json:"command"`
	Status        string          `json:"status"`
	Instance      string          `json:"instance"`
	Busy          bool            `json:"busy"`
	ActiveTask    json.RawMessage `json:"activeTask"`
	TaskID        *string         `json:"taskId"`
	MessageID     *string         `json:"messageId"`
	Attempt       *int64          `json:"attempt"`
	Outcome       *string         `json:"outcome"`
	Deduped       bool            `json:"deduped"`
}

type managedWorkerActiveTask struct {
	TaskID    string  `json:"taskId"`
	Phase     string  `json:"phase"`
	Attempt   *int64  `json:"attempt"`
	MessageID *string `json:"messageId"`
	SessionID *string `json:"sessionId"`
	Outcome   *string `json:"outcome"`
	UpdatedAt *string `json:"updatedAt"`
}

type managedSourceRegistrationReceipt struct {
	SchemaVersion         int    `json:"schemaVersion"`
	Command               string `json:"command"`
	Status                string `json:"status"`
	Instance              string `json:"instance"`
	SandboxID             string `json:"sandboxId"`
	ProfileID             string `json:"profileId"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	RegisteredSourceID    string `json:"registeredSourceId"`
	WorkspaceEpoch        string `json:"workspaceEpoch"`
	NativeSessionID       string `json:"nativeSessionId"`
	NativeProjectID       string `json:"nativeProjectId"`
	NativeLocationDigest  string `json:"nativeLocationDigest"`
	ProfileRevision       int64  `json:"profileRevision"`
	ProfileDigest         string `json:"profileDigest"`
	InstructionRevision   int64  `json:"instructionRevision"`
	InstructionDigest     string `json:"instructionDigest"`
	Ready                 bool   `json:"ready"`
}

func (r *Reconciler) reconcileManagedWorkspaceRequests(ctx context.Context, manifest model.Manifest) error {
	for _, request := range manifest.ManagedWorkspaceRequests {
		if request.Request != "create_default" {
			return errors.New("unsupported managed workspace request")
		}
		if r.Workspaces == nil {
			return errors.New("managed workspace request has no trusted workspace provider")
		}
		diskGiB := 0
		for _, sandbox := range manifest.Sandboxes {
			if sandbox.ID == request.SandboxID && sandbox.Generation == request.SandboxGeneration {
				diskGiB = sandbox.Resources.WorkspaceDiskGiB
				break
			}
		}
		if diskGiB < 1 {
			return errors.New("managed workspace request has no current sandbox disk authority")
		}
		anchor, err := r.Workspaces.Ensure(ctx, request.SandboxID, diskGiB)
		if err != nil {
			return fmt.Errorf("resolve trusted workspace anchor: %w", err)
		}
		if request.TargetKind == "cell_session" {
			_, err = r.ManagedCatalog.EnsureCellDefault(ctx, workspacecatalog.CellDefaultProjectRequest{
				Anchor: anchor, ServerID: request.ServerID,
				SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration,
				ServiceRegistrationID: request.ServiceRegistrationID, AllocationDigest: request.AllocationDigest,
				OwnerCellID: request.OwnerCellID, OwnerRole: request.OwnerRole, OwnerGeneration: request.OwnerGeneration,
				SelectionID: request.SelectionID, ProjectID: request.ProjectID,
				WorkspaceEpoch: request.WorkspaceEpoch, ScopeRevision: request.ScopeRevision,
			})
			if err != nil {
				return fmt.Errorf("create cell workspace %s: %w", request.OperationID, err)
			}
			continue
		}
		_, err = r.ManagedCatalog.EnsureDefault(ctx, workspacecatalog.DefaultProjectRequest{
			Anchor: anchor, ServerID: request.ServerID, TeamID: request.TeamID, MemberID: request.MemberID,
			SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration,
			ServiceRegistrationID: request.ServiceRegistrationID, AllocationDigest: request.AllocationDigest,
		})
		if err != nil {
			return fmt.Errorf("create managed project %s: %w", request.OperationID, err)
		}
	}
	return nil
}

// controllerParentFailure marks a fail-closed controller-parent failure that is
// ISOLATED from the rest of the pass (R-WP125-2). The parent itself has already
// been persisted as failed and is never advanced; the remaining independent
// stages of the pass (notably the V3 execute stage and its grant window) still
// run, and Reconcile returns this failure AFTER them so the pass still fails
// closed and the applied revision does not advance.
type controllerParentFailure struct{ err error }

func (failure *controllerParentFailure) Error() string { return failure.err.Error() }
func (failure *controllerParentFailure) Unwrap() error { return failure.err }

// controllerParentFailureOf extracts the isolated parent failure, if any.
func controllerParentFailureOf(err error) error {
	var failure *controllerParentFailure
	if errors.As(err, &failure) {
		return failure.err
	}
	return nil
}

// reconcileManagedServices reconciles every managed service of the manifest. It
// returns the bounded, retryable reasons it deferred and, in a separate error,
// the first fatal failure: a deferred service never hides the failure of another
// service, and a fatal failure never turns a deferred reason into a silent skip
// of the whole pass. A fatal failure is retained while the remaining
// independently owned services still reconcile (isolation, not suppression), and
// it is returned after the pass so Reconcile cannot advance the global applied
// revision.
//
// A controller parent whose approved-application control-plane read was bounded
// out (R-WP122-2) is such a retryable deferral: the parent stays fail-closed,
// unadvanced and durably named, but it no longer starves the independent V3
// execute stage of the same pass while the execution grant TTL drains.
func (r *Reconciler) reconcileManagedServices(ctx context.Context, manifest model.Manifest) (deferred, fatal error) {
	// Separate durable parent metadata, never Team enrollment or a child execution.
	for _, parent := range manifest.ParentServices {
		if err := r.reconcileControllerParent(ctx, manifest, parent); err != nil {
			// A bounded read block is named and retryable; every other parent
			// failure has already persisted the parent as FAILED (fail-closed,
			// never ready, never advanced). Neither may abort the pass: a parent
			// flap used to return a fatal error here, which skipped the
			// independent V3 execute stage in the same pass and, after a restart,
			// did so on every pass - permanently removing the grant gate while
			// the execution stayed pending and its grant drained (R-WP125-2).
			// Isolation, not suppression: the failure is retained as a deferral,
			// the other parent and every independent service still reconcile, and
			// the node report still describes the failed parent honestly.
			if code, blocked := controllerApplicationReadBlockedCode(err); blocked {
				deferred = errors.Join(deferred, fmt.Errorf("controller parent %s: %s", parent.ServiceRegistrationID, code))
				continue
			}
			deferred = errors.Join(deferred, &controllerParentFailure{fmt.Errorf("controller parent %s: %w", parent.ServiceRegistrationID, err)})
		}
	}
	// Authenticated inactive intents (stopped/retired/paused) are processed
	// before active services so an earlier fallible active service cannot
	// starve an independent Stop/retire/pause intent. Order is preserved
	// within each group and the existing first-fatal and remount-deferral
	// behavior is unchanged.
	for _, active := range []bool{false, true} {
		for _, desired := range manifest.ManagedServices {
			if (desired.DesiredState == "active") != active {
				continue
			}
			if err := r.reconcileManagedService(ctx, desired); err != nil {
				wrapped := fmt.Errorf("managed service %s: %w", desired.Identity.ServiceRegistrationID, err)
				if errors.Is(err, workspacecatalog.ErrManagedProjectRemountAttestation) {
					// Fail-closed: this service was not admitted, executed or
					// advanced. Its bounded, retryable remount reason is deferred so
					// every other service in the same manifest still reconciles.
					deferred = errors.Join(deferred, wrapped)
					continue
				}
				// Isolation, not suppression: retain the first fatal cause and keep
				// reconciling the other independently owned services in this pass,
				// so an earlier active enrollment failure cannot starve a later
				// independent valid start. The failed service itself stays closed;
				// the fatal is returned after the pass so Reconcile cannot
				// SetRevision.
				if fatal == nil {
					fatal = wrapped
				}
				continue
			}
		}
	}
	return deferred, fatal
}

const (
	// managedMonitorPolicyReadTimeout bounds the fresh startup policy read. It
	// is a child of the reconcile context so a slow control plane cannot hold
	// the pass beyond the ordinary reconcile timeout.
	managedMonitorPolicyReadTimeout = 5 * time.Second
)

// managedMonitorIntent is the explicit monitor decision for one actual spawn.
type managedMonitorIntent struct {
	Enabled          bool
	SourceInstanceID string
	WorkspaceEpoch   string
}

// managedLaunchComposition is the single typed launch tuple shared by the
// ordinary managed start and the monitor restart paths. Every actual spawn
// carries explicit monitor intent.
type managedLaunchComposition struct {
	SandboxID              string
	Instance               string
	ProfileID              string
	ProfileDigest          string
	Version                string
	Port                   int
	ProjectRoot            string
	SessionMode            string
	InstructionText        string
	InstructionDigest      string
	InstructionRevision    int64
	RuntimeContractVersion string
	Monitor                managedMonitorIntent
}

func (composition managedLaunchComposition) request() map[string]any {
	request := map[string]any{
		"schemaVersion":       1,
		"sandboxId":           composition.SandboxID,
		"instance":            composition.Instance,
		"profileId":           composition.ProfileID,
		"profileDigest":       composition.ProfileDigest,
		"version":             composition.Version,
		"port":                composition.Port,
		"projectRoot":         composition.ProjectRoot,
		"sessionMode":         composition.SessionMode,
		"instructionText":     composition.InstructionText,
		"instructionDigest":   composition.InstructionDigest,
		"instructionRevision": composition.InstructionRevision,
		"monitorEnabled":      composition.Monitor.Enabled,
	}
	if composition.RuntimeContractVersion != "" {
		request["runtimeContractVersion"] = composition.RuntimeContractVersion
	}
	if composition.Monitor.Enabled {
		request["monitorSourceInstanceId"] = composition.Monitor.SourceInstanceID
		request["monitorWorkspaceEpoch"] = composition.Monitor.WorkspaceEpoch
	}
	return request
}

// managedStartupMonitorIntent resolves the explicit monitor intent for one
// actual spawn from the current authenticated policy read. Startup permission
// is the fresh per-sandbox entry plus the pinned retained source/session.
// Source collection eligibility (for example the backend's 120s observation
// window) remains the collector's concern and never blocks retained bootstrap.
func (r *Reconciler) managedStartupMonitorIntent(ctx context.Context, desired model.ManagedServiceV1) (managedMonitorIntent, error) {
	sourceID := managedSourceID(desired.Identity.ServiceRegistrationID)
	previous, err := r.Store.InsightPolicyState(ctx, sourceID)
	if err != nil {
		return managedMonitorIntent{}, err
	}
	source, err := r.Store.ContinuitySource(ctx, sourceID)
	if err != nil {
		return managedMonitorIntent{}, err
	}
	readContext, cancelRead := context.WithTimeout(ctx, managedMonitorPolicyReadTimeout)
	envelope, readErr := r.ManagedControl.InsightPolicies(readContext)
	cancelRead()
	if readErr != nil {
		// Any read failure holds. An old applied row cannot prove the current
		// intent: a previously disabled service may have just been enabled.
		return managedMonitorIntent{}, fmt.Errorf("current insight policy read failed: %w", readErr)
	}
	var policy *model.InsightPolicyV1
	for index := range envelope.Policies {
		if envelope.Policies[index].SandboxID == desired.Identity.SandboxID {
			policy = &envelope.Policies[index]
			break
		}
	}
	if policy == nil {
		if previous != nil {
			// A known service with a successful empty response is not proof of
			// never-configured; hold rather than silently composing disabled.
			return managedMonitorIntent{}, errors.New("current insight policy is missing for a known service")
		}
		// Only a successful empty response for a never-configured service
		// proves default-disabled startup.
		return managedMonitorIntent{}, nil
	}
	if !policy.ExpiresAt.After(r.now()) {
		return managedMonitorIntent{}, errors.New("current insight policy lease is expired")
	}
	if !policy.Enabled {
		// Explicit current disabled authority composes false without identity.
		return managedMonitorIntent{}, nil
	}
	var sourceInstanceID string
	var workspaceEpoch string
	if source == nil {
		// Monitoring is per sandbox: an enabled sandbox may start a new managed
		// service before that service has a ContinuitySource row. Derive the
		// monitor identity from the existing managed authority instead of
		// permanently blocking create_initial. A policy ref for this derived
		// source would imply a retained session we do not have; never invent or
		// replace it.
		for _, ref := range policy.Sources {
			if ref.RegisteredSourceID == sourceID {
				return managedMonitorIntent{}, errors.New("current insight policy source ref exists without a retained local source")
			}
		}
		sourceInstanceID = sourceID
		workspaceEpoch = desired.Workspace.WorkspaceEpoch
	} else {
		// A retained source row exists: strictly validate its tuple/session and
		// reuse it. Current desired-active authority plus the exact pinned tuple
		// is the recovery authority; a lifecycle stopped by a transient control
		// failure is derived failure state, not an intent. Explicit Stop/retire
		// never reaches this active path.
		if source.Report.SandboxID != desired.Identity.SandboxID ||
			source.Report.SandboxGeneration != desired.Identity.SandboxGeneration ||
			source.Report.ServiceRegistrationID != desired.Identity.ServiceRegistrationID ||
			source.Report.ServiceGeneration != desired.Identity.ExpectedServiceGeneration ||
			source.Report.WorkspaceEpoch != desired.Workspace.WorkspaceEpoch ||
			source.Report.NativeSessionID == "" {
			return managedMonitorIntent{}, errors.New("retained source does not match the authenticated managed authority")
		}
		for _, ref := range policy.Sources {
			if ref.RegisteredSourceID != source.Report.RegisteredSourceID {
				continue
			}
			if ref.ServiceRegistrationID != source.Report.ServiceRegistrationID ||
				ref.SandboxGeneration != source.Report.SandboxGeneration ||
				ref.ServiceGeneration != source.Report.ServiceGeneration ||
				ref.WorkspaceEpoch != source.Report.WorkspaceEpoch ||
				ref.NativeSessionID != source.Report.NativeSessionID {
				return managedMonitorIntent{}, errors.New("current insight policy source ref does not match the pinned retained source")
			}
		}
		sourceInstanceID = source.Report.RegisteredSourceID
		workspaceEpoch = source.Report.WorkspaceEpoch
	}
	return managedMonitorIntent{
		Enabled:          true,
		SourceInstanceID: sourceInstanceID,
		WorkspaceEpoch:   workspaceEpoch,
	}, nil
}

// validateManagedMonitorReceipt enforces the explicit monitor intent on the
// current process receipt. Legacy receipts keep legacy behavior but are never
// claimed as qualified for the current writer-proof guarantee.
func validateManagedMonitorReceipt(intent managedMonitorIntent, receipt *managedSupervisorReceipt) error {
	if receipt.MonitorReadinessVersion == 0 && !receipt.MonitorEnabled &&
		receipt.MonitorSourceInstanceID == "" && receipt.MonitorWorkspaceEpoch == "" &&
		!receipt.MonitorWriterReady && receipt.MonitorJournalGeneration == "" {
		// Legacy supervisor receipt: compatibility is preserved, qualification
		// for the current writer-proof guarantee is explicitly not claimed.
		return nil
	}
	if !intent.Enabled {
		if receipt.MonitorEnabled {
			return errors.New("managed receipt reported monitoring without current intent")
		}
		return nil
	}
	if !receipt.MonitorEnabled || receipt.MonitorSourceInstanceID != intent.SourceInstanceID ||
		receipt.MonitorWorkspaceEpoch != intent.WorkspaceEpoch {
		return errors.New("managed receipt lost the explicit monitor configuration")
	}
	switch receipt.MonitorReadinessVersion {
	case 1:
		if !receipt.MonitorWriterReady {
			return errors.New("managed receipt did not prove current writer readiness")
		}
		return nil
	default:
		return fmt.Errorf("managed receipt reported unknown monitor readiness version %d", receipt.MonitorReadinessVersion)
	}
}

// reestablishManagedMonitorIntent performs the single bounded recovery for a
// live process whose current monitor configuration does not match the fresh
// startup intent. It reuses the existing safe-idle authority check and the
// shared launch composition; it never restarts an active task and never loops
// beyond the current pass.
func (r *Reconciler) reestablishManagedMonitorIntent(
	ctx context.Context, desired model.ManagedServiceV1, project workspacecatalog.RegisteredProject,
	version string, instruction model.ManagedServiceInstructionV1, intent managedMonitorIntent,
) ([]byte, error) {
	sourceID := managedSourceID(desired.Identity.ServiceRegistrationID)
	source, err := r.Store.ContinuitySource(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	if source == nil || !source.NoAdmittedExecution ||
		source.Report.SandboxID != desired.Identity.SandboxID ||
		source.Report.SandboxGeneration != desired.Identity.SandboxGeneration ||
		source.Report.ServiceRegistrationID != desired.Identity.ServiceRegistrationID ||
		source.Report.ServiceGeneration != desired.Identity.ExpectedServiceGeneration ||
		source.Report.WorkspaceEpoch != desired.Workspace.WorkspaceEpoch ||
		source.Report.NativeSessionID == "" {
		return nil, errors.New("managed monitor re-establishment requires the pinned retained source at a safe idle boundary")
	}
	restartRequest := managedLaunchComposition{
		SandboxID:              desired.Identity.SandboxID,
		Instance:               desired.Identity.Instance,
		ProfileID:              desired.Profile.ProfileID,
		ProfileDigest:          desired.Profile.ProfileDigest,
		Version:                version,
		Port:                   managedServicePort,
		ProjectRoot:            project.ContainerRoot,
		SessionMode:            "lookup_only",
		InstructionText:        instruction.Content,
		InstructionDigest:      instruction.InstructionDigest,
		InstructionRevision:    instruction.InstructionRevision,
		RuntimeContractVersion: desired.RuntimeContractVersion,
		Monitor:                intent,
	}.request()
	payload, _ := json.Marshal(restartRequest)
	receiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorRestart, payload)
	if err != nil {
		return nil, err
	}
	restarted, err := validateManagedSupervisorReceipt(receiptJSON, "restart", "ready")
	if err != nil || !restarted.Ready || restarted.SessionID != source.Report.NativeSessionID ||
		restarted.NativeProjectID != source.Report.NativeProjectID ||
		restarted.NativeLocationDigest != source.Report.NativeLocationDigest ||
		restarted.InstructionRevision != instruction.InstructionRevision ||
		restarted.InstructionDigest != instruction.InstructionDigest || !restarted.InstructionApplied {
		return nil, errors.Join(err, errors.New("managed monitor re-establishment did not preserve current native authority"))
	}
	if err := validateManagedMonitorReceipt(intent, restarted); err != nil {
		return nil, err
	}
	return receiptJSON, nil
}

func (r *Reconciler) reconcileManagedService(ctx context.Context, desired model.ManagedServiceV1) error {
	// A durably completed stop/retirement is an acknowledgement of that exact
	// intent, not authority to stop a later sandbox generation or registration.
	// Replay it before resolving the now potentially replaced live resources.
	if desired.DesiredState == "stopped" || desired.DesiredState == "retired" {
		completed, err := r.Store.ManagedService(ctx, desired.Identity.ServiceRegistrationID)
		if err != nil {
			return err
		}
		if completed != nil && completed.Phase == desired.DesiredState && completed.ErrorCode == "" &&
			reflect.DeepEqual(completed.Manifest, desired) &&
			completed.Report.FormatVersion == 1 && completed.Report.LastError == nil &&
			completed.Report.Identity == desired.Identity && completed.Report.ConfigDigest == desired.ConfigDigest &&
			completed.Report.OperationID == desired.OperationID && completed.Report.ActionRevision == desired.ActionRevision &&
			completed.Report.ObservedDesiredRevision == desired.DesiredRevision &&
			completed.Report.ObservedState == desired.DesiredState && completed.Report.WorkerStatus == "stopped" &&
			setupReceiptDigestPattern.MatchString(completed.Report.ReceiptDigest) &&
			!r.managedWorkerExecutionActive(desired.Identity.ServiceRegistrationID) {
			return nil
		}
	}
	sandbox, err := r.Store.Sandbox(ctx, desired.Identity.SandboxID)
	if err != nil {
		return err
	}
	if sandbox == nil || sandbox.ObservedState != "running" ||
		sandbox.ObservedGeneration != desired.Identity.SandboxGeneration {
		return errors.New("managed service sandbox generation is not running")
	}
	setup, err := r.Store.SetupOperation(ctx, desired.Profile.SetupOperationID)
	if err != nil {
		return err
	}
	if setup == nil || setup.State != "ready" || setup.SandboxID != desired.Identity.SandboxID ||
		setup.SandboxGeneration != desired.Identity.SandboxGeneration || setup.ProfileID != desired.Profile.ProfileID ||
		setup.ProfileRevision != desired.Profile.ProfileRevision || setup.ProfileDigest != desired.Profile.ProfileDigest {
		return errors.New("managed service profile is not exactly ready")
	}
	project, err := r.resolveManagedProject(ctx, desired)
	if err != nil {
		return err
	}
	processInstance := model.ManagedServiceProcessInstance(desired.Identity.Instance, desired.Identity.ExpectedServiceGeneration)
	if err := r.Store.PutManagedServiceIntent(ctx, state.LocalManagedService{
		Manifest: desired, Phase: "pending", ProcessInstance: processInstance, Port: managedServicePort,
		ServiceGeneration: desired.Identity.ExpectedServiceGeneration,
	}); err != nil {
		return err
	}
	local, err := r.Store.ManagedService(ctx, desired.Identity.ServiceRegistrationID)
	if err != nil || local == nil {
		return errors.Join(err, errors.New("managed service intent disappeared"))
	}
	if desired.DesiredState != "active" {
		return r.reconcileManagedServiceInactive(ctx, desired, project, local)
	}
	fetch := model.ManagedServiceFetchRequestV1{
		FormatVersion: 1, OperationID: desired.OperationID, ActionRevision: desired.ActionRevision,
		DesiredRevision: desired.DesiredRevision, ConfigDigest: desired.ConfigDigest,
		ServiceRegistrationID: desired.Identity.ServiceRegistrationID,
		ServiceGeneration:     desired.Identity.ExpectedServiceGeneration,
		SandboxID:             desired.Identity.SandboxID, SandboxGeneration: desired.Identity.SandboxGeneration,
		ProcessInstance: processInstance,
	}
	enrollment, err := r.ManagedControl.ManagedServiceEnrollment(ctx, desired.Identity.ServiceRegistrationID, fetch)
	if err != nil {
		return r.failManagedService(ctx, desired, "enrollment_unavailable", err)
	}
	instruction, err := r.ManagedControl.ManagedServiceInstructions(ctx, desired.Identity.ServiceRegistrationID, fetch)
	if err != nil {
		return r.failManagedService(ctx, desired, "instruction_unavailable", err)
	}
	if enrollment.EnrollmentToken == "" || enrollment.ExchangePath == "" || !enrollment.EnrollmentExpiresAt.After(r.now()) {
		return r.failManagedService(ctx, desired, "invalid_enrollment", errors.New("node enrollment is absent or expired"))
	}
	if instruction.InstructionRevision != desired.Instructions.InstructionRevision ||
		instruction.InstructionDigest != desired.Instructions.InstructionDigest || !instruction.ExpiresAt.After(r.now()) ||
		!validateManagedInstruction(instruction.Content, instruction.InstructionDigest) {
		return r.failManagedService(ctx, desired, "invalid_instruction", errors.New("node instruction tuple is invalid"))
	}
	enrollRequest := map[string]any{
		"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance,
		"profileId": desired.Profile.ProfileID, "endpoint": r.ManagedControl.ManagedServiceEndpoint(),
		"enrollmentToken": enrollment.EnrollmentToken, "serverId": desired.Identity.ServerID,
		"teamId": desired.Identity.TeamID, "memberId": desired.Identity.MemberID,
		"generation": desired.Identity.SandboxGeneration, "processInstance": processInstance,
		"allowInsecureLoopback": false, "requestTimeoutSeconds": 30,
	}
	enrollPayload, _ := json.Marshal(enrollRequest)
	enrollReceipt, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorEnroll, enrollPayload)
	if err != nil {
		return r.failManagedService(ctx, desired, "enrollment_failed", err)
	}
	var enrolled managedSupervisorReceipt
	err = decodeManagedSupervisorReceipt(enrollReceipt, &enrolled)
	validEnrollmentStatus := enrolled.Status == "enrolled" || enrolled.Status == "refreshed"
	if enrolled.SchemaVersion != 1 || enrolled.Command != "enroll" {
		validEnrollmentStatus = false
	}
	if err != nil || !validEnrollmentStatus || !enrolled.Stored || !enrolled.LeaseTokenPresent || enrolled.LeaseExpired ||
		enrolled.LeaseRole != desired.Identity.Role || enrolled.Generation != desired.Identity.SandboxGeneration {
		if err == nil {
			err = errors.New("managed enrollment receipt did not prove current role and lease")
		}
		return r.failManagedService(ctx, desired, "invalid_enrollment_receipt", err)
	}
	rebindReceipt, err := r.rebindManagedServiceAuthority(ctx, desired)
	if err != nil {
		return r.failManagedService(ctx, desired, "authority_rebind_failed", err)
	}
	// Fresh authenticated policy read before the creation-dispatched marker:
	// failing here must not consume create_initial and force later lookup_only
	// session_missing loops.
	monitorIntent, err := r.managedStartupMonitorIntent(ctx, desired)
	if err != nil {
		return err
	}
	pinnedSource, err := r.Store.ContinuitySource(ctx, managedSourceID(desired.Identity.ServiceRegistrationID))
	if err != nil {
		return err
	}
	sessionMode := local.RecoverySessionMode()
	if err := r.Store.MarkManagedServiceCreationDispatched(ctx, desired.Identity.ServiceRegistrationID, desired.ConfigDigest); err != nil {
		return err
	}
	var setupManifest model.SetupOperation
	if err := json.Unmarshal(setup.RequestJSON, &setupManifest); err != nil {
		return r.failManagedService(ctx, desired, "invalid_profile_state", err)
	}
	version := ""
	if desired.Profile.ProfileID == "opencode" && setupManifest.Materializer.Bin != nil {
		version = setupManifest.Materializer.Bin.Version
	}
	// Fresh policy read already resolved before the creation-dispatched marker.
	startRequest := managedLaunchComposition{
		SandboxID:              desired.Identity.SandboxID,
		Instance:               desired.Identity.Instance,
		ProfileID:              desired.Profile.ProfileID,
		ProfileDigest:          desired.Profile.ProfileDigest,
		Version:                version,
		Port:                   managedServicePort,
		ProjectRoot:            project.ContainerRoot,
		SessionMode:            sessionMode,
		InstructionText:        instruction.Content,
		InstructionDigest:      instruction.InstructionDigest,
		InstructionRevision:    instruction.InstructionRevision,
		RuntimeContractVersion: desired.RuntimeContractVersion,
		Monitor:                monitorIntent,
	}.request()
	startPayload, _ := json.Marshal(startRequest)
	startReceiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorStart, startPayload)
	if err != nil {
		return r.progressManagedService(ctx, desired, "start_outcome_unknown", fmt.Errorf("managed start outcome is unknown: %w", err))
	}
	var startReceipt managedSupervisorReceipt
	err = decodeManagedSupervisorReceipt(startReceiptJSON, &startReceipt)
	reestablished := false
	if startReceipt.Status == "failed" &&
		(startReceipt.Error == "monitor_configuration_mismatch" || startReceipt.Reason == "monitor_configuration_mismatch") {
		// A live native process is running without the requested monitor
		// configuration. Re-establish the fresh intent once through the
		// existing safe-idle authority: only when the pinned retained source
		// proves no admitted execution, and never by restarting an active task.
		// This applies to explicit disabled intent as well, so a running
		// enabled configuration can be turned off without starving the
		// collector.
		restarted, restartErr := r.reestablishManagedMonitorIntent(ctx, desired, project, version, instruction, monitorIntent)
		if restartErr != nil {
			return restartErr
		}
		startReceiptJSON = restarted
		err = decodeManagedSupervisorReceipt(startReceiptJSON, &startReceipt)
		reestablished = true
	}
	validStartStatus := startReceipt.Status == "ready" || startReceipt.Status == "already_running"
	if startReceipt.SchemaVersion != 1 || (startReceipt.Command != "start" && !(reestablished && startReceipt.Command == "restart")) {
		validStartStatus = false
	}
	if err != nil || !validStartStatus || !startReceipt.Ready || startReceipt.Phase != "running" || startReceipt.SessionID == "" ||
		startReceipt.Instance != desired.Identity.Instance || startReceipt.SandboxID != desired.Identity.SandboxID ||
		startReceipt.ProfileID != desired.Profile.ProfileID || startReceipt.ProfileDigest != desired.Profile.ProfileDigest ||
		startReceipt.ProfileRevision != desired.Profile.ProfileRevision || startReceipt.Version != version ||
		startReceipt.Port != managedServicePort ||
		!managedNativeProjectPattern.MatchString(startReceipt.NativeProjectID) || !setupReceiptDigestPattern.MatchString(startReceipt.NativeLocationDigest) ||
		startReceipt.InstructionRevision != instruction.InstructionRevision ||
		startReceipt.InstructionDigest != instruction.InstructionDigest || !startReceipt.InstructionApplied {
		if err == nil {
			err = errors.New("managed start receipt did not prove native and instruction readiness")
		}
		return r.failManagedService(ctx, desired, "invalid_start_receipt", err)
	}
	if err := validateManagedMonitorReceipt(monitorIntent, &startReceipt); err != nil {
		return r.failManagedService(ctx, desired, "invalid_monitor_receipt", err)
	}
	if pinnedSource != nil && pinnedSource.Report.NativeSessionID != "" && startReceipt.SessionID != pinnedSource.Report.NativeSessionID {
		return r.failManagedService(ctx, desired, "native_session_changed", errors.New("managed start did not preserve the retained native session"))
	}
	statusRequest := map[string]any{
		"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance,
		"profileId": desired.Profile.ProfileID, "profileDigest": desired.Profile.ProfileDigest,
		"probe": true, "requestTimeoutSeconds": 30,
	}
	// The capability consumer compares the start and status receipts, so the
	// status probe negotiates exactly when the start request did.
	if version := desired.RuntimeContractVersion; version != "" {
		statusRequest["runtimeContractVersion"] = version
	}
	statusPayload, _ := json.Marshal(statusRequest)
	statusReceiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorStatus, statusPayload)
	if err != nil {
		return r.failManagedService(ctx, desired, "native_status_failed", err)
	}
	statusReceipt, err := validateManagedSupervisorReceipt(statusReceiptJSON, "status", "running")
	if err != nil || !statusReceipt.Ready || statusReceipt.SessionID != startReceipt.SessionID ||
		statusReceipt.NativeProjectID != startReceipt.NativeProjectID || statusReceipt.NativeLocationDigest != startReceipt.NativeLocationDigest ||
		statusReceipt.InstructionRevision != instruction.InstructionRevision || statusReceipt.InstructionDigest != instruction.InstructionDigest ||
		!statusReceipt.InstructionApplied {
		if err == nil {
			err = errors.New("managed status did not preserve exact native readiness")
		}
		return r.failManagedService(ctx, desired, "invalid_native_status", err)
	}
	if err := validateManagedMonitorReceipt(monitorIntent, statusReceipt); err != nil {
		return r.failManagedService(ctx, desired, "invalid_monitor_receipt", err)
	}
	workerReceipts, err := r.runManagedWorkerBoundary(ctx, desired)
	if err != nil {
		return r.failManagedService(ctx, desired, "worker_not_ready", err)
	}
	if err := r.recheckManagedAuthority(ctx, desired, project); err != nil {
		return r.failManagedService(ctx, desired, "authority_changed", err)
	}
	registeredSourceID := managedSourceID(desired.Identity.ServiceRegistrationID)
	registrationReceipt, err := r.registerManagedSource(ctx, desired, registeredSourceID, startReceipt, instruction)
	if err != nil {
		return r.failManagedService(ctx, desired, "source_registration_failed", err)
	}
	var execution *managedWorkerExecution
	if desired.Identity.Role != "manager" {
		execution = r.ensureManagedWorkerExecution(desired, project)
	}
	native := &model.ManagedNativeRegistrationV1{
		RegisteredSourceID: registeredSourceID, WorkspaceEpoch: desired.Workspace.WorkspaceEpoch,
		NativeSessionID: startReceipt.SessionID, NativeProjectID: startReceipt.NativeProjectID,
		NativeLocationDigest: startReceipt.NativeLocationDigest,
	}
	receiptDigest := digestManagedReceipts(enrollReceipt, append(append(append(rebindReceipt, startReceiptJSON...), statusReceiptJSON...), registrationReceipt...), workerReceipts)
	report := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: desired.OperationID, ActionRevision: desired.ActionRevision,
		ObservedDesiredRevision: desired.DesiredRevision, ConfigDigest: desired.ConfigDigest, ObservedState: "ready",
		Identity: desired.Identity, ServiceGeneration: desired.Identity.ExpectedServiceGeneration,
		ProfileStatus: "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "ready",
		InstructionApplied: true, InstructionRevision: instruction.InstructionRevision,
		InstructionDigest: instruction.InstructionDigest, NativeRegistration: native, ReceiptDigest: receiptDigest,
	}
	// A lease renewal proves current health but does not replace the durable
	// completion receipt for this action. Preserve it only after all fresh
	// boundary checks above and only if every reported semantic field matches.
	if local.Phase == "ready" && local.ErrorCode == "" && setupReceiptDigestPattern.MatchString(local.Report.ReceiptDigest) {
		renewed := report
		renewed.ReceiptDigest = local.Report.ReceiptDigest
		if reflect.DeepEqual(renewed, local.Report) {
			report = local.Report
		}
	}
	previousSource, err := r.Store.ContinuitySource(ctx, registeredSourceID)
	if err != nil {
		return r.failManagedService(ctx, desired, "source_registration_failed", err)
	}
	source := state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: registeredSourceID,
			ServiceRegistrationID: desired.Identity.ServiceRegistrationID,
			ServiceGeneration:     desired.Identity.ExpectedServiceGeneration, ProjectID: desired.Workspace.ProjectID,
			SandboxID: desired.Identity.SandboxID, SandboxGeneration: desired.Identity.SandboxGeneration,
			WorkspaceEpoch: desired.Workspace.WorkspaceEpoch, NativeSessionID: startReceipt.SessionID,
			NativeProjectID: startReceipt.NativeProjectID, NativeLocationDigest: startReceipt.NativeLocationDigest,
			ScopeRevision: desired.Workspace.ScopeRevision, Role: desired.Identity.Role,
			ProfileRevision: desired.Profile.ProfileRevision, InstructionRevision: instruction.InstructionRevision,
			Availability: "available", LastObservedAt: r.now(),
		},
		Root: project.HostRoot, Instance: desired.Identity.Instance, Lifecycle: "running",
		LifecycleRevision:   desired.ActionRevision,
		NoAdmittedExecution: preservedIdleBoundary(desired, previousSource, startReceipt.SessionID),
	}
	capability, err := managedManagerCapability(desired, registeredSourceID, startReceipt, *statusReceipt)
	if err != nil {
		return r.failManagedService(ctx, desired, "manager_capability_invalid", err)
	}
	if err := r.Store.PutManagerCapability(ctx, capability); err != nil {
		return err
	}
	if err := r.Store.PutContinuitySource(ctx, source); err != nil {
		return err
	}
	if execution != nil {
		r.promoteIdleManagedExecution(ctx, desired, execution)
	}
	return r.Store.UpdateManagedService(ctx, desired.Identity.ServiceRegistrationID, "ready", &report, "")
}

func (r *Reconciler) rebindManagedServiceAuthority(ctx context.Context, desired model.ManagedServiceV1) ([]byte, error) {
	authority, modelID, authMode, ok := completeManagedServiceAuthority(desired)
	if !ok {
		return nil, nil
	}
	request := map[string]any{
		"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance,
		"profileId": desired.Profile.ProfileID, "profileDigest": desired.Profile.ProfileDigest,
		"provider": authority.ProviderID, "model": modelID, "authMode": authMode,
		"bindingRevision": authority.TeamRevision, "restart": false,
	}
	if version := desired.RuntimeContractVersion; version != "" {
		request["runtimeContractVersion"] = version
	}
	payload, _ := json.Marshal(request)
	receiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorRebind, payload)
	if err != nil {
		// The explicit Team revision makes this exact replay idempotent. If the
		// first call durably wrote the tuple but lost its response, the supervisor
		// accepts the same revision and tuple without another drain or restart.
		receiptJSON, _, err = r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorRebind, payload)
	}
	if err != nil {
		return nil, fmt.Errorf("rebind managed provider authority: %w", err)
	}
	var receipt managedSupervisorReceipt
	err = decodeManagedSupervisorReceipt(receiptJSON, &receipt)
	if err != nil || receipt.SchemaVersion != 1 || receipt.Command != "rebind" || receipt.Status != "applied" ||
		!receipt.Applied || receipt.Restarted || receipt.BindingRevision != authority.TeamRevision ||
		receipt.SandboxID != desired.Identity.SandboxID || receipt.Instance != desired.Identity.Instance ||
		receipt.ProfileID != desired.Profile.ProfileID || receipt.ProfileDigest != desired.Profile.ProfileDigest {
		if err == nil {
			err = errors.New("managed rebind receipt did not prove the exact service authority")
		}
		return nil, err
	}
	var binding struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
		AuthMode string `json:"authMode"`
	}
	decoder := json.NewDecoder(bytes.NewReader(receipt.Binding))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		binding.Provider != authority.ProviderID || binding.Model != normalizedManagedModelID(authority.ProviderID, modelID) ||
		binding.AuthMode != authMode {
		if err == nil {
			err = errors.New("managed rebind receipt changed the authority tuple")
		}
		return nil, err
	}
	return receiptJSON, nil
}

func completeManagedServiceAuthority(desired model.ManagedServiceV1) (*model.ManagedServiceAuthorityV1, string, string, bool) {
	authority := desired.Authority
	if authority == nil || authority.ModelID == nil || authority.AuthMode == nil {
		return authority, "", "", false
	}
	return authority, *authority.ModelID, *authority.AuthMode, true
}

func normalizedManagedModelID(providerID, modelID string) string {
	return strings.TrimPrefix(modelID, providerID+"/")
}

// managedManagerBinding is the exact non-secret authority tuple a cell's
// manager session is bound to before it starts. It is never credential
// material and never persisted by the Runtime.
type managedManagerBinding struct {
	ProviderID string
	ModelID    string
	AuthMode   string
}

// bindCellManagerAuthority records the cell manifest's exact
// provider/model/auth-mode authority in the supervisor's binding store BEFORE
// any native start. The retained 0.1.52 supervisor has no binding field on
// start/restart (unknown request fields are rejected), so the Runtime carries
// the binding in the launch sequence as a product-issued rebind; the following
// start builds OPENCODE_CONFIG_CONTENT and the manager route from that exact
// tuple. This is the product path: no venue/harness rebind is needed. Absence
// or an invalid/incomplete tuple fails closed before any native effect, because
// an unbound manager silently falls back to the default provider route and
// cannot read or accept a product wake.
// managedSupervisorActionFailure is the bounded, non-secret description of a
// managed supervisor command that exited non-zero. The in-cell supervisor
// writes a safe receipt even when it refuses a command, but the process
// transport reports a non-zero exit as a bare "exit status N", so the receipt's
// own closed status/error fields are the only place that names WHICH
// precondition rejected the command. This value carries those closed fields plus
// a bounded single-line diagnostic; it never carries a prompt, credential or
// free-text payload.
type managedSupervisorActionFailure struct {
	Action     string
	Status     string
	Reason     string
	Diagnostic string
	Err        error
}

// supervisorActionFailure classifies a failed managed supervisor call. The
// receipt and diagnostic bytes are only ever reduced to closed, bounded tokens,
// so the resulting error can safely reach the Runtime report and the durable
// preparation row.
func supervisorActionFailure(action containers.ManagedSupervisorAction, receipt, diagnostic []byte, cause error) error {
	if cause == nil {
		return nil
	}
	failure := &managedSupervisorActionFailure{Action: string(action), Err: cause}
	var decoded struct {
		Status    string `json:"status"`
		Error     string `json:"error"`
		ErrorCode string `json:"errorCode"`
	}
	if len(receipt) != 0 && json.Unmarshal(receipt, &decoded) == nil {
		failure.Status = managedSupervisorToken(decoded.Status)
		failure.Reason = managedSupervisorToken(decoded.Error)
		if failure.Reason == "" {
			failure.Reason = managedSupervisorToken(decoded.ErrorCode)
		}
	}
	if failure.Reason == "" && len(diagnostic) != 0 {
		failure.Diagnostic = managedSupervisorDiagnostic(diagnostic)
	}
	return failure
}

// managedSupervisorToken keeps only the bounded closed-vocabulary shape of a
// supervisor receipt field; anything else is dropped rather than reported.
func managedSupervisorToken(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if len(value) > 48 {
		value = value[:48]
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '_' && character != '.' && character != '-' {
			return ""
		}
	}
	return value
}

// managedSupervisorDiagnostic reduces arbitrary supervisor stderr to one bounded
// printable line. It is only used when no receipt explains the failure (a crash
// or a launcher refusal), and it never carries a request payload.
func managedSupervisorDiagnostic(diagnostic []byte) string {
	const maximum = 160
	text := strings.TrimSpace(string(diagnostic))
	if index := strings.IndexAny(text, "\r\n"); index >= 0 {
		text = text[:index]
	}
	printable := strings.Map(func(character rune) rune {
		if character == '\t' {
			return ' '
		}
		if character < 0x20 || character > 0x7e {
			return -1
		}
		return character
	}, text)
	printable = strings.Join(strings.Fields(printable), " ")
	if len(printable) > maximum {
		printable = printable[:maximum]
	}
	return printable
}

func (f *managedSupervisorActionFailure) reasonToken() string {
	if f == nil {
		return ""
	}
	return f.Reason
}

func (f *managedSupervisorActionFailure) Error() string {
	message := fmt.Sprintf("managed supervisor %s failed: %v", f.Action, f.Err)
	if f.Status != "" || f.Reason != "" {
		message += fmt.Sprintf(" (receipt status=%s", f.Status)
		if f.Reason != "" {
			message += " error=" + f.Reason
		}
		message += ")"
	}
	if f.Diagnostic != "" {
		message += " (diagnostic: " + f.Diagnostic + ")"
	}
	return message
}

func (f *managedSupervisorActionFailure) Unwrap() error { return f.Err }

func (r *Reconciler) bindCellManagerAuthority(ctx context.Context, entry model.ManagedServiceV2) (managedManagerBinding, error) {
	providerID, modelID, authMode, err := entry.Authority.ManagerLaunchBinding()
	if err != nil {
		return managedManagerBinding{}, err
	}
	binding := managedManagerBinding{ProviderID: providerID, ModelID: modelID, AuthMode: authMode}
	request := map[string]any{
		"schemaVersion": 1, "sandboxId": entry.SandboxID, "instance": entry.Instance,
		"profileId": entry.Profile.ProfileID, "profileDigest": entry.Profile.ProfileDigest,
		"provider": providerID, "model": modelID, "authMode": authMode,
		"restart": false,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return managedManagerBinding{}, err
	}
	receiptJSON, diagnosticJSON, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorRebind, payload)
	if err != nil {
		// A lost response may still have durably written the tuple. The replay is
		// safe: the supervisor only drains when the tuple changes, and an
		// identical tuple is rewritten without restarting or admitting work.
		receiptJSON, diagnosticJSON, err = r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorRebind, payload)
	}
	if err != nil {
		return managedManagerBinding{}, fmt.Errorf("bind cell manager authority: %w", supervisorActionFailure(containers.ManagedSupervisorRebind, receiptJSON, diagnosticJSON, err))
	}
	var receipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(receiptJSON, &receipt); err != nil {
		return managedManagerBinding{}, fmt.Errorf("invalid cell manager binding receipt: %w", err)
	}
	if receipt.SchemaVersion != 1 || receipt.Command != "rebind" || receipt.Status != "applied" ||
		!receipt.Applied || receipt.Restarted || receipt.BindingRevision < 1 ||
		receipt.SandboxID != entry.SandboxID || receipt.Instance != entry.Instance ||
		receipt.ProfileID != entry.Profile.ProfileID || receipt.ProfileDigest != entry.Profile.ProfileDigest {
		return managedManagerBinding{}, errors.New("cell manager binding receipt did not prove the applied binding")
	}
	var stored struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
		AuthMode string `json:"authMode"`
	}
	decoder := json.NewDecoder(bytes.NewReader(receipt.Binding))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		stored.Provider != providerID || stored.Model != modelID || stored.AuthMode != authMode {
		return managedManagerBinding{}, errors.New("cell manager binding receipt changed the authority tuple")
	}
	return binding, nil
}

// verifyCellManagerRoute proves the start/status receipt was produced with the
// exact bound tuple. The supervisor derives these fields from the binding store
// while building the managed configuration, so a manager that started unbound
// (or with a substituted model) cannot masquerade as bound.
func verifyCellManagerRoute(observed managedSupervisorReceipt, binding managedManagerBinding) error {
	if observed.ManagerProviderID != binding.ProviderID || observed.ManagerModelID != binding.ModelID {
		return errors.New("cell native server manager route did not bind the manifest authority")
	}
	return nil
}

func (r *Reconciler) registerManagedSource(ctx context.Context, desired model.ManagedServiceV1, registeredSourceID string, native managedSupervisorReceipt, instruction model.ManagedServiceInstructionV1) ([]byte, error) {
	request := map[string]any{
		"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance,
		"profileId": desired.Profile.ProfileID,
		"registration": map[string]any{
			"formatVersion": 1,
			"identity": map[string]any{
				"serverId": desired.Identity.ServerID, "teamId": desired.Identity.TeamID, "memberId": desired.Identity.MemberID,
				"sandboxId": desired.Identity.SandboxID, "sandboxGeneration": desired.Identity.SandboxGeneration,
				"serviceRegistrationId": desired.Identity.ServiceRegistrationID, "serviceGeneration": desired.Identity.ExpectedServiceGeneration,
				"instance": desired.Identity.Instance, "role": desired.Identity.Role, "projectId": desired.Workspace.ProjectID,
				"workspaceEpoch": desired.Workspace.WorkspaceEpoch, "profileId": desired.Profile.ProfileID,
				"profileRevision": desired.Profile.ProfileRevision, "profileDigest": desired.Profile.ProfileDigest,
				"instructionRevision": instruction.InstructionRevision, "instructionDigest": instruction.InstructionDigest,
			},
			"source": map[string]any{
				"registeredSourceId": registeredSourceID, "nativeSessionId": native.SessionID,
				"nativeProjectId": native.NativeProjectID, "nativeLocationDigest": native.NativeLocationDigest,
			},
		},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	receiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorRegisterSource, payload)
	if err != nil {
		return nil, err
	}
	var receipt managedSourceRegistrationReceipt
	if err := decodeManagedReceipt(receiptJSON, &receipt, true); err != nil {
		return nil, err
	}
	validStatus := receipt.Status == "registered" || receipt.Status == "unchanged"
	if receipt.SchemaVersion != 1 || receipt.Command != "register-source" || !validStatus || receipt.Ready ||
		receipt.Instance != desired.Identity.Instance || receipt.SandboxID != desired.Identity.SandboxID ||
		receipt.ProfileID != desired.Profile.ProfileID || receipt.ServiceRegistrationID != desired.Identity.ServiceRegistrationID ||
		receipt.ServiceGeneration != desired.Identity.ExpectedServiceGeneration || receipt.RegisteredSourceID != registeredSourceID ||
		receipt.WorkspaceEpoch != desired.Workspace.WorkspaceEpoch || receipt.NativeSessionID != native.SessionID ||
		receipt.NativeProjectID != native.NativeProjectID || receipt.NativeLocationDigest != native.NativeLocationDigest ||
		receipt.ProfileRevision != desired.Profile.ProfileRevision || receipt.ProfileDigest != desired.Profile.ProfileDigest ||
		receipt.InstructionRevision != instruction.InstructionRevision || receipt.InstructionDigest != instruction.InstructionDigest {
		return nil, errors.New("managed source registration receipt did not preserve exact host authority")
	}
	return receiptJSON, nil
}

func (r *Reconciler) resolveManagedProject(ctx context.Context, desired model.ManagedServiceV1) (workspacecatalog.RegisteredProject, error) {
	project, err := r.ManagedCatalog.Resolve(ctx, workspacecatalog.ResolveProjectRequest{
		SelectionID: desired.Workspace.SelectionID, ProjectID: desired.Workspace.ProjectID,
		WorkspaceEpoch: desired.Workspace.WorkspaceEpoch, SandboxID: desired.Identity.SandboxID,
		SandboxGeneration:     desired.Identity.SandboxGeneration,
		ServiceRegistrationID: desired.Identity.ServiceRegistrationID, ConfigDigest: desired.ConfigDigest,
	})
	if err == nil {
		if project.Report.RootAttestation != desired.Workspace.RootAttestation {
			// The local record is fully verified and holds a newer root
			// attestation than the manifest. When its superseded attestation is
			// exactly the manifest's, the manifest still carries the
			// pre-remount authority of the documented workspace remount: the
			// service stays untouched and the bounded reason is deferred until a
			// manifest carrying the ratified re-attestation arrives. Any other
			// attestation mismatch stays a project change.
			if project.SupersededRootAttestation != "" && project.SupersededRootAttestation == desired.Workspace.RootAttestation {
				return workspacecatalog.RegisteredProject{}, workspacecatalog.ErrManagedProjectRemountAttestation
			}
			return workspacecatalog.RegisteredProject{}, workspacecatalog.ErrProjectChanged
		}
		return project, nil
	}
	record, stateErr := r.Store.ManagedProject(ctx, desired.Workspace.SelectionID)
	if stateErr != nil || record == nil {
		return workspacecatalog.RegisteredProject{}, errors.Join(err, stateErr)
	}
	project, err = r.ManagedCatalog.EnsureDefault(ctx, workspacecatalog.DefaultProjectRequest{
		Anchor: record.Anchor, ServerID: record.ServerID, TeamID: record.TeamID, MemberID: record.MemberID,
		SandboxID: record.Report.SandboxID, SandboxGeneration: record.Report.SandboxGeneration,
		ServiceRegistrationID: desired.Identity.ServiceRegistrationID, AllocationDigest: record.AllocationDigest,
		ConfigDigest: desired.ConfigDigest, RebindSelectionID: desired.Workspace.SelectionID,
	})
	if err != nil || project.Report.ProjectID != desired.Workspace.ProjectID ||
		project.Report.WorkspaceEpoch != desired.Workspace.WorkspaceEpoch {
		return workspacecatalog.RegisteredProject{}, errors.Join(err, workspacecatalog.ErrProjectChanged)
	}
	if project.Report.RootAttestation != desired.Workspace.RootAttestation {
		return workspacecatalog.RegisteredProject{}, errors.New("managed project was rebound; wait for the current catalog attestation")
	}
	return project, nil
}

func (r *Reconciler) reconcileManagedServiceInactive(ctx context.Context, desired model.ManagedServiceV1, project workspacecatalog.RegisteredProject, local *state.LocalManagedService) error {
	if err := r.cancelManagedWorkerExecution(ctx, desired.Identity.ServiceRegistrationID); err != nil {
		return r.failManagedService(ctx, desired, "worker_cancel_failed", err)
	}
	action := containers.ManagedSupervisorDrain
	expectedStatus := "drained"
	phase := desired.DesiredState
	if desired.DesiredState == "stopped" || desired.DesiredState == "retired" {
		action = containers.ManagedSupervisorStop
		expectedStatus = "stopped"
	}
	payload, _ := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance, "profileId": desired.Profile.ProfileID, "graceSeconds": 15})
	receipt, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, action, payload)
	if err != nil {
		return r.failManagedService(ctx, desired, "lifecycle_action_failed", err)
	}
	var lifecycleReceipt managedSupervisorReceipt
	err = decodeManagedSupervisorReceipt(receipt, &lifecycleReceipt)
	validStatus := lifecycleReceipt.SchemaVersion == 1 && lifecycleReceipt.Command == string(action) && lifecycleReceipt.Status == expectedStatus
	if action == containers.ManagedSupervisorStop && lifecycleReceipt.Status == "not_running" {
		validStatus = lifecycleReceipt.SchemaVersion == 1 && lifecycleReceipt.Command == string(action)
	}
	if err != nil || !validStatus {
		if err == nil {
			err = errors.New("managed lifecycle receipt did not acknowledge the requested state")
		}
		return r.failManagedService(ctx, desired, "invalid_lifecycle_receipt", err)
	}
	report := local.Report
	if report.FormatVersion != 1 {
		report = model.ManagedServiceReportV1{
			FormatVersion: 1, ConfigDigest: desired.ConfigDigest, Identity: desired.Identity,
			ServiceGeneration: desired.Identity.ExpectedServiceGeneration,
			ProfileStatus:     "ready", WorkspaceStatus: "ready", EnrollmentStatus: "failed",
			InstructionRevision: desired.Instructions.InstructionRevision,
			InstructionDigest:   desired.Instructions.InstructionDigest,
		}
	}
	report.OperationID, report.ActionRevision, report.ObservedDesiredRevision = desired.OperationID, desired.ActionRevision, desired.DesiredRevision
	report.ObservedState = phase
	report.Identity = desired.Identity
	report.LastError = nil
	if phase == "paused" {
		report.WorkerStatus = "paused"
	} else {
		report.WorkerStatus = "stopped"
	}
	report.ReceiptDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(receipt))
	if report.NativeRegistration != nil {
		source, err := r.Store.ContinuitySource(ctx, report.NativeRegistration.RegisteredSourceID)
		if err != nil {
			return err
		}
		if source != nil {
			reason := "service_" + phase
			source.Report.Availability = "unavailable"
			source.Report.Reason = &reason
			source.Report.LastObservedAt = r.now()
			source.Lifecycle = "stopped"
			source.LifecycleRevision = desired.ActionRevision
			if err := r.Store.PutContinuitySource(ctx, *source); err != nil {
				return err
			}
		}
	}
	_ = project
	return r.Store.UpdateManagedService(ctx, desired.Identity.ServiceRegistrationID, phase, &report, "")
}

func (r *Reconciler) runManagedWorkerBoundary(ctx context.Context, desired model.ManagedServiceV1) ([][]byte, error) {
	var receipts [][]byte
	actions := []containers.ManagedWorkerAction{containers.ManagedWorkerReconcile, containers.ManagedWorkerStatus}
	// Managers delegate broker work; only workers/reviewers may claim it.
	// Read-only status still proves that no task is active before publication.
	if desired.Identity.Role == "manager" || r.managedWorkerExecutionActive(desired.Identity.ServiceRegistrationID) {
		actions = []containers.ManagedWorkerAction{containers.ManagedWorkerStatus}
	}
	for _, action := range actions {
		request := map[string]any{
			"schemaVersion": 1, "command": string(action), "instance": desired.Identity.Instance,
			"root": "/home/agent", "allowInsecureLoopback": false, "requestTimeoutSeconds": 30,
		}
		payload, _ := json.Marshal(request)
		receiptJSON, _, err := r.ManagedRuntime.ExecManagedWorker(ctx, desired.Identity.SandboxID, action, payload)
		if err != nil {
			return receipts, err
		}
		receipt, err := validateManagedWorkerReceipt(receiptJSON, string(action))
		if err != nil {
			return receipts, err
		}
		if action == containers.ManagedWorkerStatus && receipt.Status != "ok" {
			return receipts, errors.New("managed worker status is unavailable")
		}
		if action == containers.ManagedWorkerStatus {
			if desired.Identity.Role == "manager" && receipt.Busy {
				return receipts, errors.New("manager has unexpected active broker work")
			}
			taskID, attempt, err := managedWorkerStatusAuthority(receipt)
			if err != nil {
				return receipts, errors.New("managed worker task authority is invalid")
			}
			if err := r.Store.PutManagedTaskAuthority(ctx, state.LocalManagedTaskAuthority{
				ServiceRegistrationID: desired.Identity.ServiceRegistrationID,
				ServiceGeneration:     desired.Identity.ExpectedServiceGeneration,
				SandboxGeneration:     desired.Identity.SandboxGeneration,
				TaskID:                taskID,
				TaskAttempt:           attempt,
				Busy:                  receipt.Busy,
				ObservedAt:            r.now(),
			}); err != nil {
				return receipts, err
			}
		}
		receipts = append(receipts, receiptJSON)
	}
	return receipts, nil
}

func managedWorkerStatusAuthority(receipt *managedWorkerReceipt) (*string, *int64, error) {
	// The packaged status producer carries current and latest task facts only in
	// activeTask. Top-level task fields belong to reconcile/execute receipts and
	// must never substitute authority on a status response.
	if receipt.TaskID != nil || receipt.Attempt != nil {
		return nil, nil, errors.New("status carried top-level task authority")
	}
	raw := bytes.TrimSpace(receipt.ActiveTask)
	if len(raw) == 0 {
		return nil, nil, errors.New("status omitted activeTask")
	}
	if bytes.Equal(raw, []byte("null")) {
		if receipt.Busy {
			return nil, nil, errors.New("busy status omitted active task")
		}
		return nil, nil, nil
	}
	var active managedWorkerActiveTask
	if err := decodeManagedReceipt(raw, &active, true); err != nil {
		return nil, nil, err
	}
	if !managedWorkerTaskPattern.MatchString(active.TaskID) ||
		active.Attempt != nil && *active.Attempt < 1 {
		return nil, nil, errors.New("status active task identity is invalid")
	}
	if receipt.Busy {
		if !managedWorkerActivePhases[active.Phase] || active.Attempt == nil {
			return nil, nil, errors.New("busy status active task is invalid")
		}
		taskID := active.TaskID
		attempt := *active.Attempt
		return &taskID, &attempt, nil
	}
	if !managedWorkerSettledPhases[active.Phase] {
		return nil, nil, errors.New("idle status carried active task")
	}
	// A latest settled marker is useful status metadata but grants no current
	// task authority. Persist the explicit idle observation with nil task refs.
	return nil, nil, nil
}

// preservedIdleBoundary keeps the last verified idle observation for the same
// live source. A managed-service lease renewal or an idle worker-loop restart is
// not an admitted execution, and clearing the flag there races the monitor
// policy apply out of its required safe boundary.
func preservedIdleBoundary(desired model.ManagedServiceV1, previous *state.LocalContinuitySource, nativeSessionID string) bool {
	if desired.Identity.Role == "manager" {
		return true
	}
	if previous == nil || !previous.NoAdmittedExecution {
		return false
	}
	return previous.Report.ServiceRegistrationID == desired.Identity.ServiceRegistrationID &&
		previous.Report.ServiceGeneration == desired.Identity.ExpectedServiceGeneration &&
		previous.Report.NativeSessionID == nativeSessionID
}

func (r *Reconciler) managedWorkerExecutionActive(serviceID string) bool {
	r.managedWorkerMu.Lock()
	defer r.managedWorkerMu.Unlock()
	return r.managedExecutions[serviceID] != nil
}

func (r *Reconciler) ensureManagedWorkerExecution(desired model.ManagedServiceV1, project workspacecatalog.RegisteredProject) *managedWorkerExecution {
	serviceID := desired.Identity.ServiceRegistrationID
	r.managedWorkerMu.Lock()
	if execution := r.managedExecutions[serviceID]; execution != nil {
		r.managedWorkerMu.Unlock()
		return execution
	}
	if r.managedExecutions == nil {
		r.managedExecutions = make(map[string]*managedWorkerExecution)
	}
	lifecycle := r.ManagedExecutionContext
	if lifecycle == nil {
		lifecycle = context.Background()
	}
	executionContext, cancel := context.WithTimeout(lifecycle, 35*time.Minute)
	execution := &managedWorkerExecution{cancel: cancel, done: make(chan struct{})}
	r.managedExecutions[serviceID] = execution
	r.managedWorkerMu.Unlock()

	request, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "command": string(containers.ManagedWorkerExecute), "instance": desired.Identity.Instance,
		"root": "/home/agent", "projectPath": project.ContainerRoot,
		"allowInsecureLoopback": false, "requestTimeoutSeconds": 30,
	})
	go func() {
		defer cancel()
		receiptJSON, _, err := r.ManagedRuntime.ExecManagedWorker(executionContext, desired.Identity.SandboxID, containers.ManagedWorkerExecute, request)
		idle := false
		if err == nil {
			if receipt, validateErr := validateManagedWorkerReceipt(receiptJSON, string(containers.ManagedWorkerExecute)); validateErr == nil {
				idle = receipt.Status == "idle"
			}
		}
		execution.mu.Lock()
		execution.idle = idle
		execution.mu.Unlock()
		close(execution.done)
		r.promoteIdleManagedExecution(context.Background(), desired, execution)
		r.managedWorkerMu.Lock()
		if r.managedExecutions[serviceID] == execution {
			delete(r.managedExecutions, serviceID)
		}
		r.managedWorkerMu.Unlock()
	}()
	return execution
}

// ScheduleContinuationHandoff starts the one targeted broker worker for an
// already projected separate-session baseline. The packaged worker reopens
// the private registration and performs the final consume-before-prompt fence.
func (r *Reconciler) ScheduleContinuationHandoff(
	ctx context.Context,
	operationID string,
	manifest model.ContinuationHandoffManifestV1,
	registration model.ContinuityRegistrationV1,
) error {
	if r.Store == nil || r.ManagedRuntime == nil || !managedSafeIDPattern.MatchString(operationID) || operationID != manifest.OperationID ||
		registration.Binding.RegisteredSourceID == "" || registration.Binding.ServiceRegistrationID != manifest.TargetPolicy.ServiceRegistrationID {
		return errors.New("invalid targeted continuation worker request")
	}
	service, err := r.Store.ManagedService(ctx, manifest.TargetPolicy.ServiceRegistrationID)
	if err != nil || service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" ||
		service.ServiceGeneration != manifest.TargetPolicy.ServiceGeneration ||
		service.Manifest.Identity.SandboxID != manifest.TargetPolicy.SandboxID ||
		service.Manifest.Identity.SandboxGeneration != manifest.TargetPolicy.SandboxGeneration ||
		service.Manifest.Identity.TeamID != manifest.TargetPolicy.TeamID ||
		service.Manifest.Identity.MemberID != manifest.TargetPolicy.MemberID ||
		service.Manifest.Identity.Role != manifest.TargetPolicy.Role ||
		service.Manifest.Profile.ProfileRevision != manifest.TargetPolicy.ProfileRevision ||
		service.Manifest.Profile.ProfileDigest != manifest.TargetPolicy.ProfileDigest ||
		service.Manifest.Instructions.InstructionRevision != manifest.TargetPolicy.InstructionRevision ||
		service.Manifest.Instructions.InstructionDigest != manifest.TargetPolicy.InstructionDigest {
		return errors.Join(err, errors.New("targeted worker service authority changed"))
	}
	stored, err := r.Store.ContinuityRegistration(ctx, registration.Binding.BindingID)
	if err != nil || stored == nil || stored.ObservedStatus != "verified" ||
		stored.ServiceGeneration != manifest.TargetPolicy.ServiceGeneration || !reflect.DeepEqual(stored.Manifest, registration) {
		return errors.Join(err, errors.New("targeted worker registration is not verified"))
	}
	projects, err := r.Store.ManagedProjects(ctx)
	if err != nil {
		return err
	}
	var project *state.LocalManagedProject
	for index := range projects {
		candidate := &projects[index]
		if candidate.Report.ProjectID == registration.Identity.ProjectID && candidate.Report.WorkspaceEpoch == registration.Identity.WorkspaceEpoch {
			if project != nil {
				return errors.New("targeted worker project authority is ambiguous")
			}
			project = candidate
		}
	}
	if project == nil || project.Phase != "ready" || project.Report.Availability != "available" ||
		project.Report.SandboxID != registration.Identity.SandboxID ||
		project.Report.SandboxGeneration != registration.Identity.SandboxGeneration {
		return errors.New("targeted worker project authority changed")
	}
	switch manifest.HandoffKind {
	case "reviewer":
		if project.Report.Designation != "continuity-handoff" || project.Report.ServiceRegistrationID == nil ||
			*project.Report.ServiceRegistrationID != manifest.TargetPolicy.ServiceRegistrationID {
			return errors.New("targeted worker project authority changed")
		}
	case "restored_target":
		if project.Report.Designation != "continuity-materialization" || project.Report.ServiceRegistrationID != nil {
			return errors.New("targeted worker project authority changed")
		}
	default:
		return errors.New("targeted worker handoff kind is invalid")
	}
	serviceID := manifest.TargetPolicy.ServiceRegistrationID
	r.managedWorkerMu.Lock()
	if r.managedExecutions != nil && r.managedExecutions[serviceID] != nil {
		r.managedWorkerMu.Unlock()
		return nil
	}
	if r.managedExecutions == nil {
		r.managedExecutions = make(map[string]*managedWorkerExecution)
	}
	lifecycle := r.ManagedExecutionContext
	if lifecycle == nil {
		lifecycle = context.Background()
	}
	executionContext, cancel := context.WithTimeout(lifecycle, 35*time.Minute)
	execution := &managedWorkerExecution{cancel: cancel, done: make(chan struct{})}
	r.managedExecutions[serviceID] = execution
	r.managedWorkerMu.Unlock()

	request, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "command": string(containers.ManagedWorkerExecute),
		"instance": service.Manifest.Identity.Instance, "root": "/home/agent",
		"projectPath": project.ContainerRoot, "continuationOperationId": operationID,
		"allowInsecureLoopback": false, "requestTimeoutSeconds": 30,
	})
	go func() {
		defer cancel()
		_, _, _ = r.ManagedRuntime.ExecManagedWorker(executionContext, manifest.TargetPolicy.SandboxID, containers.ManagedWorkerExecute, request)
		close(execution.done)
		r.managedWorkerMu.Lock()
		if r.managedExecutions[serviceID] == execution {
			delete(r.managedExecutions, serviceID)
		}
		r.managedWorkerMu.Unlock()
	}()
	return nil
}

func (r *Reconciler) cancelManagedWorkerExecution(ctx context.Context, serviceID string) error {
	r.managedWorkerMu.Lock()
	execution := r.managedExecutions[serviceID]
	r.managedWorkerMu.Unlock()
	if execution == nil {
		return nil
	}
	execution.cancel()
	select {
	case <-execution.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
		return errors.New("managed worker did not stop after cancellation")
	}
}

func (r *Reconciler) promoteIdleManagedExecution(ctx context.Context, desired model.ManagedServiceV1, execution *managedWorkerExecution) {
	select {
	case <-execution.done:
	default:
		return
	}
	execution.mu.Lock()
	idle := execution.idle
	execution.mu.Unlock()
	if !idle {
		return
	}
	sourceID := managedSourceID(desired.Identity.ServiceRegistrationID)
	source, err := r.Store.ContinuitySource(ctx, sourceID)
	if err != nil || source == nil || source.Report.ServiceGeneration != desired.Identity.ExpectedServiceGeneration ||
		source.Lifecycle != "running" || source.LifecycleRevision != desired.ActionRevision {
		return
	}
	_ = r.Store.MarkContinuitySourceIdle(ctx, *source)
}

func (r *Reconciler) recheckManagedAuthority(ctx context.Context, desired model.ManagedServiceV1, project workspacecatalog.RegisteredProject) error {
	sandbox, err := r.Store.Sandbox(ctx, desired.Identity.SandboxID)
	if err != nil || sandbox == nil || sandbox.ObservedState != "running" ||
		sandbox.ObservedGeneration != desired.Identity.SandboxGeneration {
		return errors.Join(err, errors.New("managed sandbox lifecycle changed"))
	}
	local, err := r.Store.ManagedService(ctx, desired.Identity.ServiceRegistrationID)
	if err != nil || local == nil || local.Manifest.ConfigDigest != desired.ConfigDigest ||
		local.Manifest.Identity != desired.Identity || local.Manifest.ActionRevision != desired.ActionRevision {
		return errors.Join(err, errors.New("managed service authority changed"))
	}
	resolved, err := r.ManagedCatalog.Resolve(ctx, workspacecatalog.ResolveProjectRequest{
		SelectionID: desired.Workspace.SelectionID, ProjectID: desired.Workspace.ProjectID,
		WorkspaceEpoch: desired.Workspace.WorkspaceEpoch, SandboxID: desired.Identity.SandboxID,
		SandboxGeneration:     desired.Identity.SandboxGeneration,
		ServiceRegistrationID: desired.Identity.ServiceRegistrationID, ConfigDigest: desired.ConfigDigest,
	})
	if err != nil || resolved.HostRoot != project.HostRoot || resolved.Report.RootAttestation != project.Report.RootAttestation {
		return errors.Join(err, errors.New("managed project authority changed"))
	}
	return nil
}

func (r *Reconciler) failManagedService(ctx context.Context, desired model.ManagedServiceV1, code string, cause error) error {
	digestPayload, _ := json.Marshal(struct {
		OperationID  string `json:"operationId"`
		Action       int64  `json:"actionRevision"`
		ConfigDigest string `json:"configDigest"`
		Code         string `json:"code"`
	}{desired.OperationID, desired.ActionRevision, desired.ConfigDigest, code})
	report := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: desired.OperationID, ActionRevision: desired.ActionRevision,
		ObservedDesiredRevision: desired.DesiredRevision, ConfigDigest: desired.ConfigDigest,
		ObservedState: "failed", Identity: desired.Identity,
		ServiceGeneration: desired.Identity.ExpectedServiceGeneration,
		ProfileStatus:     "ready", WorkspaceStatus: "ready", EnrollmentStatus: "failed", WorkerStatus: "failed",
		InstructionRevision: desired.Instructions.InstructionRevision,
		InstructionDigest:   desired.Instructions.InstructionDigest,
		ReceiptDigest:       fmt.Sprintf("sha256:%x", sha256.Sum256(digestPayload)),
		LastError:           &model.ManagedServiceErrorV1{Code: code},
	}
	var tombstoneErr error
	if previous, err := r.Store.ManagedService(ctx, desired.Identity.ServiceRegistrationID); err != nil {
		tombstoneErr = err
	} else if previous != nil && previous.Report.NativeRegistration != nil {
		if source, err := r.Store.ContinuitySource(ctx, previous.Report.NativeRegistration.RegisteredSourceID); err != nil {
			tombstoneErr = err
		} else if source != nil {
			reason := "service_failed"
			source.Report.Availability = "unavailable"
			source.Report.Reason = &reason
			source.Report.LastObservedAt = r.now()
			if !transientManagedControlFailure(code) {
				source.Lifecycle = "stopped"
				source.LifecycleRevision = desired.ActionRevision
			}
			tombstoneErr = r.Store.PutContinuitySource(ctx, *source)
		}
	}
	updateErr := r.Store.UpdateManagedService(ctx, desired.Identity.ServiceRegistrationID, "failed", &report, code)
	return errors.Join(cause, tombstoneErr, updateErr)
}

// transientManagedControlFailure reports control-plane fetch failures that do
// not by themselves prove the actual process lifecycle changed. Such failures
// mark the source unavailable while keeping it recoverable under fresh
// desired-active authority; only explicit outcomes rewrite the lifecycle.
func transientManagedControlFailure(code string) bool {
	return code == "enrollment_unavailable" || code == "instruction_unavailable"
}

func (r *Reconciler) progressManagedService(ctx context.Context, desired model.ManagedServiceV1, privateCode string, cause error) error {
	digestPayload, _ := json.Marshal(struct {
		OperationID  string `json:"operationId"`
		Action       int64  `json:"actionRevision"`
		ConfigDigest string `json:"configDigest"`
		Progress     string `json:"progress"`
	}{desired.OperationID, desired.ActionRevision, desired.ConfigDigest, "start_dispatched"})
	report := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: desired.OperationID, ActionRevision: desired.ActionRevision,
		ObservedDesiredRevision: desired.DesiredRevision, ConfigDigest: desired.ConfigDigest,
		ObservedState: "registering", Identity: desired.Identity,
		ServiceGeneration: desired.Identity.ExpectedServiceGeneration,
		ProfileStatus:     "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "failed",
		InstructionRevision: desired.Instructions.InstructionRevision,
		InstructionDigest:   desired.Instructions.InstructionDigest,
		ReceiptDigest:       fmt.Sprintf("sha256:%x", sha256.Sum256(digestPayload)),
	}
	updateErr := r.Store.UpdateManagedService(ctx, desired.Identity.ServiceRegistrationID, "recovery_required", &report, privateCode)
	return errors.Join(cause, updateErr)
}

func validateManagedInstruction(content, digest string) bool {
	if content == "" || len([]byte(content)) > 32768 || !utf8.ValidString(content) || strings.ContainsRune(content, 0) {
		return false
	}
	return digest == fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content)))
}

func validateManagedSupervisorReceipt(payload []byte, command, status string) (*managedSupervisorReceipt, error) {
	var receipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(payload, &receipt); err != nil {
		return nil, err
	}
	if receipt.SchemaVersion != 1 || receipt.Command != command || receipt.Status != status {
		return nil, errors.New("managed supervisor receipt envelope is invalid")
	}
	return &receipt, nil
}

func validateManagedWorkerReceipt(payload []byte, command string) (*managedWorkerReceipt, error) {
	var receipt managedWorkerReceipt
	if err := decodeManagedReceipt(payload, &receipt, false); err != nil {
		return nil, err
	}
	validStatus := false
	switch command {
	case "status":
		validStatus = receipt.Status == "ok"
	case "reconcile", "execute":
		validStatus = receipt.Status == "idle" || receipt.Status == "deduped" ||
			receipt.Status == "reconciled" || receipt.Status == "message"
	}
	if receipt.SchemaVersion != 1 || receipt.Command != command || !validStatus {
		return nil, errors.New("managed worker receipt envelope is invalid")
	}
	return &receipt, nil
}

func decodeManagedReceipt(payload []byte, target any, strict bool) error {
	if len(payload) == 0 || len(payload) > 64*1024 {
		return errors.New("managed helper receipt size is invalid")
	}
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("managed helper receipt has trailing data")
	}
	return nil
}

func decodeManagedSupervisorReceipt(payload []byte, target any) error {
	if len(payload) == 0 || len(payload) > 64*1024 {
		return errors.New("managed helper receipt size is invalid")
	}
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return err
	}
	for field := range fields {
		if !managedSupervisorReceiptFields[field] {
			return fmt.Errorf("managed supervisor receipt has unknown field %q", field)
		}
	}
	return json.Unmarshal(payload, target)
}

var managedSupervisorReceiptFields = func() map[string]bool {
	fields := []string{
		"nativeRoleReadback", "appliedProfile", "materializerDigest", "nativeSessionId",
		"schemaVersion", "command", "status", "phase", "instance", "sandboxId", "profileId", "profileDigest",
		"profileRevision", "version", "hostname", "port", "pid", "ready", "error", "upgradeError", "restored",
		"snapshotId", "writerVersion", "sweptProcesses", "activeSessions", "startCount", "state", "reason",
		"serverRunning", "binding", "observed", "install", "admission", "bindingRevision", "generation",
		"settingRevision", "sharingEnabled", "cleared", "checkedAt", "freshUntil", "ttlSeconds", "observation",
		"projection", "action", "applied", "drained", "restarted", "previousBindingRevision", "leaseId",
		"leaseTokenPresent", "leaseRole", "leaseOperations", "leaseExpiresAt", "leaseExpired", "secondsRemaining",
		"clockSkewSeconds", "endpointHost", "stored", "enrolledAt", "sessionId", "sessionCreated", "sessionReused",
		"sessionCreatedCount", "conversationCount", "sessionMode", "nativeProjectId", "nativeLocationDigest",
		"instructionRevision", "instructionDigest", "instructionApplied", "receiptDigest",
		"managerPluginDigest", "managerPluginLoaded", "managerProfile", "managerProviderId", "managerModelId",
		"managerNativeProtocol", "managerProviderRouteDigest", "managerRecommendAvailable", "managerCapabilityReason", "managerRecipeIds",
		"nativeGuard",
		"monitorReadinessVersion", "monitorEnabled", "monitorSourceInstanceId", "monitorWorkspaceEpoch", "monitorWriterReady", "monitorJournalGeneration",
		"mappingId", "operationId", "registeredSourceId", "serviceGeneration", "serviceRegistrationId",
		"targetWorkId", "targetWorkspace", "workspaceEpoch",
	}
	allowed := make(map[string]bool, len(fields))
	for _, field := range fields {
		allowed[field] = true
	}
	return allowed
}()

func managedManagerCapability(desired model.ManagedServiceV1, sourceID string, start, status managedSupervisorReceipt) (state.LocalManagerCapability, error) {
	if start.ManagerPluginDigest == "" || !setupReceiptDigestPattern.MatchString(start.ManagerPluginDigest) || !start.ManagerPluginLoaded ||
		start.ManagerProfile.ProfileID != "warpmetal-insights-manager" || start.ManagerProfile.ProfileRevision < 1 ||
		!setupReceiptDigestPattern.MatchString(start.ManagerProfile.ProfileDigest) ||
		!setupReceiptDigestPattern.MatchString(start.ManagerProviderRouteDigest) ||
		len(start.ManagerRecipeIDs) == 0 || len(start.ManagerRecipeIDs) > 4 {
		return state.LocalManagerCapability{}, errors.New("managed supervisor omitted closed manager capability proof")
	}
	allowedProtocol := start.ManagerNativeProtocol == "" || start.ManagerNativeProtocol == "open_responses" ||
		start.ManagerNativeProtocol == "openai_chat" || start.ManagerNativeProtocol == "anthropic_messages" ||
		start.ManagerNativeProtocol == "google_generative_ai" || start.ManagerNativeProtocol == "bedrock_converse" ||
		start.ManagerNativeProtocol == "mistral_chat"
	if !allowedProtocol || start.ManagerRecommendAvailable &&
		(start.ManagerProviderID == "" || start.ManagerModelID == "" || start.ManagerNativeProtocol == "") {
		return state.LocalManagerCapability{}, errors.New("managed supervisor reported invalid manager route capability")
	}
	if start.NativeGuard != nil {
		guard := start.NativeGuard
		if guard.GuardVersion != "warpmetal.atomic-input.v1" || guard.CustomVersion == "" || guard.SourceRevision == "" ||
			guard.PatchDigest == "" || guard.ArtifactSHA256 == "" || guard.BinarySHA256 == "" {
			return state.LocalManagerCapability{}, errors.New("managed supervisor reported invalid native guard")
		}
	}
	if authority, modelID, _, ok := completeManagedServiceAuthority(desired); ok &&
		(start.ManagerProviderID != authority.ProviderID || start.ManagerModelID != normalizedManagedModelID(authority.ProviderID, modelID)) {
		return state.LocalManagerCapability{}, errors.New("managed supervisor manager route changed the requested authority")
	}
	startCapability := struct {
		PluginDigest                                     string
		PluginLoaded                                     bool
		Profile                                          model.InsightsManagerProfileV1
		ProviderID, ModelID, NativeProtocol, RouteDigest string
		Available                                        bool
		Reason                                           *string
		Recipes                                          string
		Guard                                            *model.NativeGuardObservationV1
	}{start.ManagerPluginDigest, start.ManagerPluginLoaded, start.ManagerProfile, start.ManagerProviderID, start.ManagerModelID,
		start.ManagerNativeProtocol, start.ManagerProviderRouteDigest, start.ManagerRecommendAvailable, start.ManagerCapabilityReason,
		strings.Join(start.ManagerRecipeIDs, "\x00"), start.NativeGuard}
	statusCapability := struct {
		PluginDigest                                     string
		PluginLoaded                                     bool
		Profile                                          model.InsightsManagerProfileV1
		ProviderID, ModelID, NativeProtocol, RouteDigest string
		Available                                        bool
		Reason                                           *string
		Recipes                                          string
		Guard                                            *model.NativeGuardObservationV1
	}{status.ManagerPluginDigest, status.ManagerPluginLoaded, status.ManagerProfile, status.ManagerProviderID, status.ManagerModelID,
		status.ManagerNativeProtocol, status.ManagerProviderRouteDigest, status.ManagerRecommendAvailable, status.ManagerCapabilityReason,
		strings.Join(status.ManagerRecipeIDs, "\x00"), status.NativeGuard}
	if !reflect.DeepEqual(startCapability, statusCapability) {
		return state.LocalManagerCapability{}, errors.New("managed supervisor manager capability changed between ready probes")
	}
	allowedRecipes := map[string]bool{"inspect_first_failure@1": true, "check_repeated_operation@1": true, "refine_query@1": true, "inspect_active_phase@1": true}
	seen := map[string]bool{}
	for _, recipe := range start.ManagerRecipeIDs {
		if !allowedRecipes[recipe] || seen[recipe] {
			return state.LocalManagerCapability{}, errors.New("managed supervisor reported unsupported manager recipe")
		}
		seen[recipe] = true
	}
	reason := ""
	if start.ManagerCapabilityReason != nil {
		reason = *start.ManagerCapabilityReason
	}
	if start.ManagerRecommendAvailable && reason != "" || !start.ManagerRecommendAvailable && reason == "" {
		return state.LocalManagerCapability{}, errors.New("managed supervisor manager availability proof is inconsistent")
	}
	return state.LocalManagerCapability{
		RegisteredSourceID: sourceID, ServiceRegistrationID: desired.Identity.ServiceRegistrationID,
		ServiceGeneration: desired.Identity.ExpectedServiceGeneration, WorkspaceEpoch: desired.Workspace.WorkspaceEpoch,
		NativeSessionID: start.SessionID, SandboxID: desired.Identity.SandboxID, SandboxGeneration: desired.Identity.SandboxGeneration,
		ProfileRevision: desired.Profile.ProfileRevision, InstructionRevision: desired.Instructions.InstructionRevision,
		NativeVersion: start.Version, NativeSourceRevision: "08462140ec0de1e4b17d4a353d8d5827f53cf7b0", Protocol: "opencode-supervisor/1",
		NativeProtocol: start.ManagerNativeProtocol, ProviderID: start.ManagerProviderID, ModelID: start.ManagerModelID,
		ProviderRouteDigest: start.ManagerProviderRouteDigest, RecipeIDs: append([]string(nil), start.ManagerRecipeIDs...),
		ManagerPluginDigest: start.ManagerPluginDigest, ManagerProfile: start.ManagerProfile, NativeGuard: start.NativeGuard,
		MaxInputTokens: 8000, MaxOutputTokens: 1000, FinalRequestMaxBytes: 7000,
		ToolsAllowed: false, MediaAllowed: false, HardOutputTokenLimit: true,
		Available: start.ManagerRecommendAvailable, Reason: reason,
	}, nil
}

func digestManagedReceipts(enroll, start []byte, worker [][]byte) string {
	hash := sha256.New()
	for _, payload := range append([][]byte{enroll, start}, worker...) {
		var length [8]byte
		for index := range length {
			length[7-index] = byte(uint64(len(payload)) >> (index * 8))
		}
		hash.Write(length[:])
		hash.Write(payload)
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}

func managedSourceID(serviceID string) string {
	if strings.HasPrefix(serviceID, "service_") {
		return "source_" + strings.TrimPrefix(serviceID, "service_")
	}
	digest := sha256.Sum256([]byte(serviceID))
	return fmt.Sprintf("source_%x", digest[:12])
}

// CellExecutionEnabled reports whether a supervisor runtime contract version
// advertises cell execution. 0.1.46 and every other contract are refused; only
// the explicit 0.1.47 capability constant enables the cell path.
func CellExecutionEnabled(contractVersion string) bool {
	return model.SupportsCellExecution(contractVersion)
}

// cellAdapterPath is the trusted SA4 cell adapter installed in the sandbox. It
// runs OUTSIDE the bwrap jail with credentials and network; it is never the
// jailed, credential-less tool entrypoint.
const cellAdapterPath = "/usr/local/libexec/warpmetal-agent-cells/warpmetal_cell_adapter.py"

// managedCellCallV1 is the JSON call document handed to the trusted cell
// adapter. Only identity, workspace, model and the first step text cross this
// boundary; the adapter owns create_child -> bind_workspace -> admit_first_step.
type managedCellCallV1 struct {
	SchemaVersion          int    `json:"schemaVersion"`
	Action                 string `json:"action"`
	RuntimeContractVersion string `json:"runtimeContractVersion"`
	OperationID            string `json:"operationId"`
	ServiceRegistrationID  string `json:"serviceRegistrationId"`
	OwnerCellID            string `json:"ownerCellId"`
	OwnerRole              string `json:"ownerRole"`
	OwnerGeneration        int64  `json:"ownerGeneration"`
	SandboxID              string `json:"sandboxId"`
	SandboxGeneration      int64  `json:"sandboxGeneration"`
	Instance               string `json:"instance"`
	Role                   string `json:"role"`
	NativeSessionID        string `json:"nativeSessionId"`
	NativeProjectID        string `json:"nativeProjectId"`
	WorkspaceEpoch         string `json:"workspaceEpoch"`
	ProfileID              string `json:"profileId"`
	ProfileRevision        int64  `json:"profileRevision"`
	ProfileDigest          string `json:"profileDigest"`
	ParentSessionID        string `json:"parentSessionId"`
	Agent                  string `json:"agent"`
	Model                  struct {
		ProviderID string `json:"providerID"`
		ID         string `json:"id"`
	} `json:"model"`
	WorktreeDir string `json:"worktreeDir"`
	FirstText   string `json:"firstText"`
	Attempt     int64  `json:"attempt"`
}

// managedCellResultV1 is the adapter result. It is decoded strictly so a
// malformed or drifted result can never be mistaken for a completion.
type managedCellResultV1 struct {
	SchemaVersion          int     `json:"schemaVersion"`
	Status                 string  `json:"status"`
	RuntimeContractVersion string  `json:"runtimeContractVersion"`
	OperationID            string  `json:"operationId"`
	SessionID              string  `json:"sessionId"`
	MessageID              string  `json:"messageId"`
	State                  string  `json:"state"`
	Attempt                int64   `json:"attempt"`
	Outcome                *string `json:"outcome"`
	Exhausted              bool    `json:"exhausted"`
	Interrupted            bool    `json:"interrupted"`
	ReceiptDigest          string  `json:"receiptDigest"`
	Error                  string  `json:"error"`
}

// reconcileCellServices reconciles every formatVersion 2 cell-owned service of
// the manifest. It is separate from the member path: a cell entry has no
// member/team identity and never runs through the member enrollment/source
// registration machinery. A deferred remount reason is isolated from a fatal
// failure of another cell service exactly like the member path.
func (r *Reconciler) reconcileCellServices(ctx context.Context, manifest model.Manifest) (deferred, fatal error) {
	for _, entry := range manifest.CellEntries {
		if err := r.reconcileCellService(ctx, entry); err != nil {
			wrapped := fmt.Errorf("cell service %s: %w", entry.ServiceRegistrationID, err)
			if errors.Is(err, workspacecatalog.ErrManagedProjectRemountAttestation) {
				deferred = errors.Join(deferred, wrapped)
				continue
			}
			if fatal == nil {
				fatal = wrapped
			}
			continue
		}
	}
	return deferred, fatal
}

// reconcileCellService persists the durable cell operation BEFORE any effect,
// invokes the trusted cell adapter (create -> bind -> admit) with the scoped
// identity/workspace/profile/fence, and reports the exact child/attempt receipt
// with completion, exhaustion or unknown. Exhausted and unknown effects are
// never reported as ordinary terminal completion, and the durable exhaustion
// marker survives restart.
func (r *Reconciler) reconcileCellService(ctx context.Context, entry model.ManagedServiceV2) error {
	// Version gate: cell handling is enabled only by the explicit 0.1.47
	// capability. The adapter call advertises it and the result must echo it.
	if !CellExecutionEnabled(model.CellExecutionContractVersion) {
		return errors.New("cell execution is not enabled by the current supervisor contract")
	}
	if entry.DesiredState == "stopped" {
		// An already-stopped intent needs no cancel (the child never ran).
		return nil
	}
	if entry.DesiredState == "paused" {
		// A held (paused) service must NOT admit a new launch, and it was never
		// revoked, so there is no cancellation obligation either. No effect.
		return nil
	}
	if entry.DesiredState == "retired" {
		// A retired (revoked) service still carries the cancellation obligation:
		// send the cancel action and observe quiescence, reporting cancelled only
		// on the exact correlated ack. Exhausted/unknown effects stay non-terminal.
		return r.reconcileCellCancel(ctx, entry)
	}
	sandbox, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return err
	}
	if sandbox == nil || sandbox.ObservedState != "running" || sandbox.ObservedGeneration != entry.SandboxGeneration {
		return errors.New("cell service sandbox generation is not running")
	}
	worktreeDir, err := r.resolveCellWorktree(ctx, entry)
	if err != nil {
		return err
	}
	instruction, err := r.fetchCellFirstText(ctx, entry)
	if err != nil {
		return err
	}
	// Durable intent BEFORE any adapter effect. The operation id is the durable
	// identity, so a lost response is recovered by re-reading the same row.
	if err := r.Store.PutCellOperation(ctx, state.LocalCellOperation{Entry: entry, Phase: "pending"}); err != nil {
		return err
	}
	local, err := r.Store.CellOperation(ctx, entry.OperationID)
	if err != nil || local == nil {
		return errors.Join(err, errors.New("cell operation intent disappeared"))
	}
	// The authoritative execution attempt is immutable per launch and comes
	// from the manifest; it is echoed verbatim in the report and in the adapter
	// call. The local retry counter is separate: it tracks transport
	// reconciliation only and must never advance or replace the authoritative
	// attempt.
	retry := local.Attempt + 1
	previous := local
	// Provision the protected native opencode server instance BEFORE the trusted
	// cell adapter runs, so the adapter's instance control-metadata read succeeds.
	// A missing/failed server is a bounded pending hold (cell_native_server_not_ready),
	// never an unbounded adapter retry against absent metadata.
	// The manager/controller session (the supervisor's own session) is the child's
	// parent; entry.NativeSessionID is the DETERMINISTIC CHILD session. Never pass
	// the child as its own parent.
	parentSessionID, err := r.ensureCellNativeServer(ctx, entry, worktreeDir, instruction)
	if err != nil {
		return errors.Join(err, r.storeCellUnknown(ctx, entry, previous, retry, "cell_native_server_not_ready"))
	}
	modelID := ""
	if entry.Authority != nil && entry.Authority.ModelID != nil {
		modelID = *entry.Authority.ModelID
	}
	call := managedCellCallV1{
		SchemaVersion: 1, Action: "launch", RuntimeContractVersion: model.CellExecutionContractVersion,
		OperationID: entry.LaunchOperationID, ServiceRegistrationID: entry.ServiceRegistrationID,
		OwnerCellID: entry.OwnerCellID, OwnerRole: entry.OwnerRole, OwnerGeneration: entry.OwnerGeneration,
		SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration,
		Instance: entry.Instance, Role: entry.Role,
		NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID,
		WorkspaceEpoch: entry.WorkspaceEpoch, ProfileID: entry.Profile.ProfileID,
		ProfileRevision: entry.Profile.ProfileRevision, ProfileDigest: entry.Profile.ProfileDigest,
		ParentSessionID: parentSessionID, Agent: "warpmetal-managed", WorktreeDir: worktreeDir,
		FirstText: instruction, Attempt: entry.Attempt,
	}
	if entry.Authority != nil {
		call.Model.ProviderID = entry.Authority.ProviderID
		call.Model.ID = modelID
	}
	payload, err := json.Marshal(call)
	if err != nil {
		return err
	}
	receiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorCell, payload)
	if err != nil {
		// A lost/unknown adapter effect must never be an ordinary completion and
		// must survive restart as unknown rather than terminal.
		return errors.Join(err, r.storeCellUnknown(ctx, entry, previous, retry, "cell_outcome_unknown"))
	}
	var receipt managedCellResultV1
	if err := decodeManagedReceipt(receiptJSON, &receipt, true); err != nil {
		return errors.Join(err, r.storeCellUnknown(ctx, entry, previous, retry, "invalid_cell_receipt"))
	}
	if receipt.SchemaVersion != 1 || receipt.OperationID != entry.LaunchOperationID ||
		!CellExecutionEnabled(receipt.RuntimeContractVersion) {
		// A contract that does not advertise cell execution (for example
		// 0.1.46) must never be reported as a cell result.
		return r.storeCellUnknown(ctx, entry, previous, retry, "cell_contract_unsupported")
	}
	if !model.ValidCellAdapterState(receipt.State) {
		return r.storeCellUnknown(ctx, entry, previous, retry, "invalid_cell_state")
	}
	child := &model.ManagedCellChildV1{
		OperationID: receipt.OperationID, SessionID: receipt.SessionID, MessageID: receipt.MessageID,
		State: receipt.State, Attempt: receipt.Attempt, Outcome: receipt.Outcome, Exhausted: receipt.Exhausted,
	}
	exhausted := previous.Exhausted || receipt.Exhausted || receipt.State == "exhausted"
	phase := "unknown"
	observed := "unknown"
	switch {
	case exhausted:
		phase, observed = "exhausted", "exhausted"
	case receipt.State == "terminal" && receipt.Outcome != nil && model.ValidCellTerminalOutcome(*receipt.Outcome):
		// Only an ordinary terminal idle is a completion.
		phase, observed = "terminal", "ready"
	case receipt.Status == "failed":
		phase, observed = "failed", "failed"
	default:
		phase, observed = "unknown", "unknown"
	}
	report := model.CellServiceReportV1{
		FormatVersion: 2, OperationID: entry.OperationID, ActionRevision: entry.ActionRevision,
		ObservedDesiredRevision: entry.DesiredRevision, ServiceRegistrationID: entry.ServiceRegistrationID,
		ObservedState: observed, DesiredState: entry.DesiredState,
		OwnerCellID: entry.OwnerCellID, OwnerRole: entry.OwnerRole, OwnerGeneration: entry.OwnerGeneration,
		SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration,
		ServiceGeneration: entry.ServiceGeneration, Fence: entry.Fence,
		Instance: entry.Instance, Role: entry.Role,
		NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID,
		WorkspaceEpoch: entry.WorkspaceEpoch, Attempt: entry.Attempt, Child: child, Exhausted: exhausted,
		ReceiptDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(receiptJSON)),
	}
	if observed == "failed" {
		code := "cell_failed"
		if receipt.Error != "" {
			code = bounded(receipt.Error, 80)
		}
		report.LastError = &model.ManagedServiceErrorV1{Code: code}
	}
	errorCode := ""
	if report.LastError != nil {
		errorCode = report.LastError.Code
	}
	stored := state.LocalCellOperation{
		Entry: entry, Phase: phase, Attempt: retry, Child: child, Exhausted: exhausted,
		Report: report, ErrorCode: errorCode,
	}
	return r.Store.UpdateCellOperation(ctx, stored)
}

// cancelledReport builds the current-authority cell report for a retired
// (revoked) service. observed is "cancelled" (exact quiescence ack), "exhausted"
// (unknown effects remain), "failed" or "unknown".
func (r *Reconciler) cancelledReport(entry model.ManagedServiceV2, attempt int64, observed, receiptDigest string) model.CellServiceReportV1 {
	return model.CellServiceReportV1{
		FormatVersion: 2, OperationID: entry.OperationID, ActionRevision: entry.ActionRevision,
		ObservedDesiredRevision: entry.DesiredRevision, ServiceRegistrationID: entry.ServiceRegistrationID,
		ObservedState: observed, DesiredState: entry.DesiredState,
		OwnerCellID: entry.OwnerCellID, OwnerRole: entry.OwnerRole, OwnerGeneration: entry.OwnerGeneration,
		SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration,
		ServiceGeneration: entry.ServiceGeneration, Fence: entry.Fence,
		Instance: entry.Instance, Role: entry.Role,
		NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID,
		WorkspaceEpoch: entry.WorkspaceEpoch, Attempt: attempt, Exhausted: observed == "exhausted",
		ReceiptDigest: receiptDigest,
	}
}

// reconcileCellCancel sends the cancel action for a retired (revoked) cell
// service and reports the observed quiescence. "cancelled" is reported only when
// the receipt is a terminal/interrupted outcome and NOT exhausted/unknown; an
// exhausted or uncertain effect remains non-terminal (backend apply_cancellation
// enforces the same fence).
func (r *Reconciler) reconcileCellCancel(ctx context.Context, entry model.ManagedServiceV2) error {
	if !CellExecutionEnabled(model.CellExecutionContractVersion) {
		return errors.New("cell execution is not enabled by the current supervisor contract")
	}
	local, err := r.Store.CellOperation(ctx, entry.OperationID)
	if err != nil {
		return err
	}
	missingLocal := local == nil
	if missingLocal {
		// No durable local launch record. Reconcile against the persisted
		// backend/native binding (operation + native session) WITHOUT
		// relaunching: persist an explicit non-terminal hold first, then send
		// the adapter cancel/observe for the manifest's authoritative identity.
		// If the adapter cannot prove identity or absence the hold stays
		// explicitly unknown; this is never an invisible deferral and never a
		// fabricated "cancelled".
		if err := r.Store.PutCellOperation(ctx, state.LocalCellOperation{Entry: entry, Phase: "pending"}); err != nil {
			return err
		}
		local, err = r.Store.CellOperation(ctx, entry.OperationID)
		if err != nil || local == nil {
			return errors.Join(err, errors.New("cell hold intent disappeared"))
		}
	}
	// The authoritative execution attempt is immutable and comes from the
	// manifest; the local retry counter (local.Attempt) is never sent.
	attempt := entry.Attempt
	retry := local.Attempt
	// Resolve the manager/supervisor session BEFORE any adapter effect. The
	// trusted adapter verifies the deterministic child's native parentID
	// against this exact identity, while the manifest carries only the child
	// session. The manager session is the one recorded by the launch/bind
	// sequence in the supervisor's durable state. If it cannot be resolved,
	// fail closed with a precise reason instead of sending the child as its own
	// parent (the 0.1.52 defect that made every cancel exit 1 and left the
	// execution revoked without a quiescence ack).
	managerSessionID, err := r.resolveCellManagerSession(ctx, entry)
	if err != nil {
		code := "cell_manager_identity_unavailable"
		var identityErr *cellManagerIdentityError
		if errors.As(err, &identityErr) {
			code = identityErr.code
		}
		return errors.Join(err, r.storeCellUnknown(ctx, entry, local, retry, code))
	}
	// Resolve the exact persisted launch identity (worktree + model) so the
	// adapter's classify_child can verify it: an empty model or worktree makes
	// every real cancellation fail classification after the interrupt is sent.
	worktreeDir, err := r.resolveCellWorktree(ctx, entry)
	if err != nil {
		if missingLocal {
			// The binding cannot even be resolved locally, so identity/absence
			// is unprovable: record the explicit non-terminal hold instead of
			// deferring invisibly.
			return errors.Join(err, r.storeCellUnknown(ctx, entry, local, retry, "cell_local_state_missing"))
		}
		return err
	}
	modelID := ""
	if entry.Authority != nil && entry.Authority.ModelID != nil {
		modelID = *entry.Authority.ModelID
	}
	call := managedCellCallV1{
		SchemaVersion: 1, Action: "cancel", RuntimeContractVersion: model.CellExecutionContractVersion,
		OperationID: entry.LaunchOperationID, ServiceRegistrationID: entry.ServiceRegistrationID,
		OwnerCellID: entry.OwnerCellID, OwnerRole: entry.OwnerRole, OwnerGeneration: entry.OwnerGeneration,
		SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration,
		Instance: entry.Instance, Role: entry.Role,
		NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID,
		WorkspaceEpoch: entry.WorkspaceEpoch, ProfileID: entry.Profile.ProfileID,
		ProfileRevision: entry.Profile.ProfileRevision, ProfileDigest: entry.Profile.ProfileDigest,
		ParentSessionID: managerSessionID, Agent: "warpmetal-managed", Attempt: attempt,
		WorktreeDir: worktreeDir,
	}
	if entry.Authority != nil {
		call.Model.ProviderID = entry.Authority.ProviderID
		call.Model.ID = modelID
	}
	payload, err := json.Marshal(call)
	if err != nil {
		return err
	}
	receiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorCell, payload)
	if err != nil {
		// A lost cancel effect must never be reported as cancelled.
		return errors.Join(err, r.storeCellUnknown(ctx, entry, local, retry, "cell_cancel_unknown"))
	}
	var receipt managedCellResultV1
	if err := decodeManagedReceipt(receiptJSON, &receipt, true); err != nil {
		return errors.Join(err, r.storeCellUnknown(ctx, entry, local, retry, "invalid_cell_cancel_receipt"))
	}
	// Validate the receipt identity before it can terminalize anything: schema,
	// contract, operation, session and attempt must all match. A receipt that
	// does not advertise cell execution, names a different operation/session, or
	// echoes a different attempt must remain unknown.
	if receipt.SchemaVersion != 1 || receipt.OperationID != entry.LaunchOperationID ||
		!CellExecutionEnabled(receipt.RuntimeContractVersion) ||
		receipt.SessionID != entry.NativeSessionID ||
		receipt.Attempt != entry.Attempt {
		return r.storeCellUnknown(ctx, entry, local, retry, "cell_cancel_contract_unsupported")
	}
	observed := "unknown"
	switch {
	case receipt.Exhausted || receipt.State == "exhausted":
		observed = "exhausted"
	case receipt.Status == "failed":
		// A failed cancellation attempt is NOT terminal: the child may still be
		// running or its effects unresolved. Report unknown until a stopped
		// observation is independently established.
		observed = "unknown"
	case receipt.State == "terminal" && receipt.Outcome != nil && model.ValidCellTerminalOutcome(*receipt.Outcome):
		observed = "cancelled"
	}
	report := r.cancelledReport(entry, attempt, observed, fmt.Sprintf("sha256:%x", sha256.Sum256(receiptJSON)))
	// Phase is the durable operation phase (pending/admitted/terminal/exhausted/
	// unknown/failed); "cancelled" is an observed state, not a phase. A resolved
	// stop is terminal; exhausted/unknown effects stay non-terminal.
	phase := "terminal"
	if observed == "exhausted" {
		phase = "exhausted"
	} else if observed == "unknown" {
		phase = "unknown"
	} else if observed == "failed" {
		phase = "failed"
	}
	errorCode := ""
	if missingLocal && observed != "cancelled" {
		// The execution has no durable local launch record, so identity/absence
		// could not be locally proven: stamp the non-terminal hold explicitly.
		errorCode = "cell_local_state_missing"
		report.LastError = &model.ManagedServiceErrorV1{Code: errorCode}
	}
	stored := state.LocalCellOperation{
		Entry: entry, Phase: phase, Attempt: retry, ErrorCode: errorCode,
		Exhausted: observed == "exhausted", Report: report,
	}
	return r.Store.UpdateCellOperation(ctx, stored)
}

// cellManagerIdentityError carries the stable non-terminal hold reason for a
// manager/supervisor session that cannot be proven. The message is diagnostic;
// the code is what the durable cell report and the operator surface.
type cellManagerIdentityError struct {
	code string
	err  error
}

func (e *cellManagerIdentityError) Error() string { return e.err.Error() }
func (e *cellManagerIdentityError) Unwrap() error { return e.err }

func errCellManagerIdentity(code, message string) error {
	return &cellManagerIdentityError{code: code, err: errors.New(message)}
}

// resolveCellManagerSession resolves the manager/supervisor session recorded
// for this cell instance by the launch/bind sequence, using the supervisor's
// lookup-only status receipt. The trusted cell adapter requires the
// deterministic child's native parentID to be exactly this identity; the
// formatVersion 2 manifest carries only the child NativeSessionID, so the
// Runtime must read the recorded manager identity instead of guessing.
//
// The probe is read-only: probe=false makes the supervisor return its durable
// saved conversation without a native readiness request, a credential write, a
// start, or any other effect. A missing, malformed, child-equal or foreign
// identity fails closed before any adapter call, so a wrong id is never sent.
func (r *Reconciler) resolveCellManagerSession(ctx context.Context, entry model.ManagedServiceV2) (string, error) {
	request := map[string]any{
		"schemaVersion": 1, "sandboxId": entry.SandboxID, "instance": entry.Instance,
		"profileId": entry.Profile.ProfileID, "profileDigest": entry.Profile.ProfileDigest,
		"probe": false,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	receiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorStatus, payload)
	if err != nil {
		return "", &cellManagerIdentityError{
			code: "cell_manager_status_unavailable",
			err:  fmt.Errorf("resolve cell manager session: %w", err),
		}
	}
	var receipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(receiptJSON, &receipt); err != nil {
		return "", &cellManagerIdentityError{
			code: "cell_manager_status_unavailable",
			err:  fmt.Errorf("invalid cell manager status receipt: %w", err),
		}
	}
	if receipt.SchemaVersion != 1 || receipt.Command != "status" {
		return "", errCellManagerIdentity("cell_manager_identity_mismatch",
			"cell manager status receipt is not a status response")
	}
	if receipt.SessionID == "" {
		return "", errCellManagerIdentity("cell_manager_identity_missing",
			"cell manager session identity is missing")
	}
	if !model.ValidCellNativeSessionID(receipt.SessionID) {
		return "", errCellManagerIdentity("cell_manager_identity_invalid",
			"cell manager session identity is malformed")
	}
	if receipt.SessionID == entry.NativeSessionID {
		return "", errCellManagerIdentity("cell_manager_identity_invalid",
			"cell manager session identity equals the deterministic child session")
	}
	// The recorded session must belong to this exact sandbox and instance. The
	// supervisor's instance root is scoped by those two values, so anything else
	// is a foreign registration and must never become the child's parent. The
	// profile digest is deliberately NOT compared: the manager state carries the
	// profile the child was actually launched under, and a later manifest profile
	// revision must not block cancellation of that older child.
	if receipt.SandboxID != entry.SandboxID || receipt.Instance != entry.Instance ||
		receipt.ProfileID != entry.Profile.ProfileID {
		return "", errCellManagerIdentity("cell_manager_identity_mismatch",
			"cell manager session identity does not describe this service instance")
	}
	return receipt.SessionID, nil
}

// storeCellUnknown records the durable non-terminal hold for a lost or
// unprovable adapter outcome. The report echoes the manifest's authoritative
// execution attempt; retry is the separate local transport counter persisted on
// the row. The two must never be conflated.
func (r *Reconciler) storeCellUnknown(ctx context.Context, entry model.ManagedServiceV2, previous *state.LocalCellOperation, retry int64, code string) error {
	exhausted := previous.Exhausted
	phase := "unknown"
	if exhausted {
		phase = "exhausted"
	}
	observed := "unknown"
	if exhausted {
		observed = "exhausted"
	}
	// Preserve the prior receipt digest when the operation is exhausted: the
	// backend's apply_completion(exhausted=True) requires a valid sha256: digest,
	// and an empty one would replace a valid exhausted report with one that can
	// never be ingested.
	receiptDigest := ""
	if exhausted && previous.Report.ReceiptDigest != "" {
		receiptDigest = previous.Report.ReceiptDigest
	}
	report := model.CellServiceReportV1{
		FormatVersion: 2, OperationID: entry.OperationID, ActionRevision: entry.ActionRevision,
		ObservedDesiredRevision: entry.DesiredRevision, ServiceRegistrationID: entry.ServiceRegistrationID,
		ObservedState: observed, DesiredState: entry.DesiredState,
		OwnerCellID: entry.OwnerCellID, OwnerRole: entry.OwnerRole, OwnerGeneration: entry.OwnerGeneration,
		SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration,
		ServiceGeneration: entry.ServiceGeneration, Fence: entry.Fence,
		Instance: entry.Instance, Role: entry.Role,
		NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID,
		WorkspaceEpoch: entry.WorkspaceEpoch, Attempt: entry.Attempt, Exhausted: exhausted,
		ReceiptDigest: receiptDigest,
		LastError:     &model.ManagedServiceErrorV1{Code: code},
	}
	return r.Store.UpdateCellOperation(ctx, state.LocalCellOperation{
		Entry: entry, Phase: phase, Attempt: retry, Exhausted: exhausted, Report: report, ErrorCode: code,
	})
}

// ensureCellNativeServer provisions (or reuses) the protected native opencode
// server instance for a cell-owned service and confirms readiness BEFORE the
// trusted cell adapter runs, as an explicit state machine:
//
//	profile attested -> status/lookup -> authorized single create/start if absent -> ready verification.
//
// A live server + bound session is proven by the supervisor's own lookup-only
// status probe (running + ready + sessionId), never by coercing a failed receipt;
// only a stopped or session-less server is created with create_initial. A stale
// or mismatched status/start fails closed to a bounded pending hold, never an
// unbounded adapter retry.
// ensureCellNativeServer ensures the protected native opencode server instance
// is running and delivers the cell-owner credential via the supervisor. It
// returns the manager/controller (parent) session. The formatVersion 3 prepare
// path calls ensureCellNativeServerRunning directly and NEVER the V2 credential
// provisioning: the trusted adapter adopts the credential itself.
func (r *Reconciler) ensureCellNativeServer(ctx context.Context, entry model.ManagedServiceV2, projectRoot, instruction string) (string, error) {
	sessionID, err := r.ensureCellNativeServerRunning(ctx, entry, projectRoot, instruction)
	if err != nil {
		return "", err
	}
	return r.provisionCellCredential(ctx, entry, sessionID)
}

func (r *Reconciler) ensureCellNativeServerRunning(ctx context.Context, entry model.ManagedServiceV2, projectRoot, instruction string) (string, error) {
	setup, err := r.Store.SetupOperation(ctx, entry.Profile.SetupOperationID)
	if err != nil {
		return "", fmt.Errorf("cell setup operation unavailable: %w", err)
	}
	if setup == nil {
		return "", errors.New("cell setup operation missing")
	}
	var setupManifest model.SetupOperation
	if err := json.Unmarshal(setup.RequestJSON, &setupManifest); err != nil {
		return "", fmt.Errorf("cell setup manifest invalid: %w", err)
	}
	version := ""
	if entry.Profile.ProfileID == "opencode" && setupManifest.Materializer.Bin != nil {
		version = setupManifest.Materializer.Bin.Version
	}

	// 0. Bind the manager BEFORE the probe/start. The retained 0.1.52 launch
	// request has no binding field, so the product launch sequence carries the
	// manifest's exact authority tuple as an explicit rebind. Doing it first also
	// recovers a running-but-unbound manager (the venue-rebind case): a changed
	// tuple drains the server, the probe then sees a stopped/drained instance,
	// and the start below reuses the saved session with the requested model.
	// Absent/invalid authority fails closed here, before any native start or
	// adapter effect.
	binding, err := r.bindCellManagerAuthority(ctx, entry)
	if err != nil {
		return "", fmt.Errorf("cell manager authority binding: %w", err)
	}

	// 1. Status/lookup: the supervisor's lookup-only readiness probe. It never
	// creates a session, so a live server + bound session is proven by a real
	// status receipt, and a stale/foreign instance fails closed.
	statusRequest := map[string]any{
		"schemaVersion": 1, "sandboxId": entry.SandboxID, "instance": entry.Instance,
		"profileId": entry.Profile.ProfileID, "profileDigest": entry.Profile.ProfileDigest,
		"probe": true, "requestTimeoutSeconds": 30,
	}
	statusPayload, err := json.Marshal(statusRequest)
	if err != nil {
		return "", err
	}
	statusReceiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorStatus, statusPayload)
	if err != nil {
		return "", err
	}
	var statusReceipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(statusReceiptJSON, &statusReceipt); err != nil {
		return "", err
	}
	switch statusReceipt.Status {
	case "running":
		if statusReceipt.Ready && statusReceipt.SessionID != "" {
			if statusReceipt.Instance != entry.Instance || statusReceipt.SandboxID != entry.SandboxID ||
				statusReceipt.ProfileID != entry.Profile.ProfileID || statusReceipt.ProfileDigest != entry.Profile.ProfileDigest {
				return "", errors.New("cell native server identity mismatch")
			}
			if err := verifyCellManagerRoute(statusReceipt, binding); err != nil {
				return "", err
			}
			return statusReceipt.SessionID, nil
		}
		// A running server without a bound session needs the single create below.
	case "stopped", "drained":
		// No live server. "drained" is a stopped instance whose binding the
		// rebind above just changed; the saved session below decides whether the
		// follow-up start may reuse it (lookup_only) or must create the first one.
	default:
		return "", errors.New("cell native server status did not prove readiness")
	}

	// A manager that already owns a native session must never be re-created: a
	// changed authority drains the running server and the follow-up start looks
	// up the same session with the new binding. Only a genuinely session-less
	// instance creates its first session.
	sessionMode := "create_initial"
	if statusReceipt.SessionID != "" {
		sessionMode = "lookup_only"
	}

	// 2. Authorized single create/start for the absent server/session. The
	// credential is provisioned afterward by provisionCellCredential (protected
	// native HTTP store), never in the start environment.
	startRequest := managedLaunchComposition{
		SandboxID:              entry.SandboxID,
		Instance:               entry.Instance,
		ProfileID:              entry.Profile.ProfileID,
		ProfileDigest:          entry.Profile.ProfileDigest,
		Version:                version,
		Port:                   managedServicePort,
		ProjectRoot:            projectRoot,
		SessionMode:            sessionMode,
		InstructionText:        instruction,
		InstructionDigest:      entry.Instructions.InstructionDigest,
		InstructionRevision:    entry.Instructions.InstructionRevision,
		RuntimeContractVersion: "",
		Monitor:                managedMonitorIntent{},
	}.request()
	startPayload, err := json.Marshal(startRequest)
	if err != nil {
		return "", err
	}
	startReceiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorStart, startPayload)
	if err != nil {
		return "", err
	}
	var startReceipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(startReceiptJSON, &startReceipt); err != nil {
		return "", err
	}
	// Only a genuine ready/already_running start is accepted; a failed receipt is
	// never coerced into success.
	if (startReceipt.Status != "ready" && startReceipt.Status != "already_running") || !startReceipt.Ready ||
		startReceipt.SessionID == "" || startReceipt.Instance != entry.Instance || startReceipt.SandboxID != entry.SandboxID {
		return "", errors.New("cell native server start did not prove readiness")
	}
	if err := verifyCellManagerRoute(startReceipt, binding); err != nil {
		return "", err
	}
	return startReceipt.SessionID, nil
}

// provisionCellCredential delivers the cell-owner provider key into the managed
// server's protected credential store over the authenticated native HTTP route
// (POST /api/integration/:id/connect/key), so the key is in the store — never
// the server/tool environment. It works on an already-running server (no
// restart) and returns the parent session only once the credential is applied.
func (r *Reconciler) provisionCellCredential(ctx context.Context, entry model.ManagedServiceV2, sessionID string) (string, error) {
	if entry.Authority == nil || entry.Authority.AuthMode == nil || *entry.Authority.AuthMode != "api_key" {
		return sessionID, nil
	}
	// API Client exposes the retained V2 envelope separately. Test/custom control
	// implementations that already implement the original seam remain compatible.
	fetch := r.ManagedControl.CellCredential
	if legacy, ok := r.ManagedControl.(legacyCellCredentialControl); ok {
		fetch = legacy.LegacyCellCredential
	}
	cred, err := fetch(ctx, entry.ServiceRegistrationID)
	if err != nil {
		return "", fmt.Errorf("cell credential fetch failed: %w", err)
	}
	// The connection label is the IMMUTABLE lease identity (credentialId), not
	// the serviceRegistrationId: a rotated/expired lease is a distinct
	// credential and must replace only its own connection, never reuse the old
	// one under the same service label.
	credentialRequest := map[string]any{
		"schemaVersion": 1, "sandboxId": entry.SandboxID, "instance": entry.Instance,
		"profileId": entry.Profile.ProfileID, "profileDigest": entry.Profile.ProfileDigest,
		"provider": entry.Authority.ProviderID, "providerApiKey": cred.APIKey,
		"credentialId": cred.CredentialID,
	}
	payload, err := json.Marshal(credentialRequest)
	if err != nil {
		return "", err
	}
	receiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorCredential, payload)
	if err != nil {
		return "", err
	}
	var receipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(receiptJSON, &receipt); err != nil {
		return "", err
	}
	if !receipt.Ready || receipt.Status != "applied" {
		return "", errors.New("cell credential provisioning did not prove readiness")
	}
	return sessionID, nil
}

// resolveCellWorktree resolves (and, when the exact binding is not yet
// registered, materializes) the cell service's ordinary-directory project
// binding from the manifest's exact workspace contract, with the exact sandbox
// generation. A project already registered for this exact
// (selection, project, epoch, generation, service) tuple is reused. An
// unregistered tuple is created under the trusted workspace anchor as an
// ordinary directory and recorded from the manifest's contract: the Runtime
// never invents repo/Git metadata and never falls back to the legacy Team
// workspace path. The binding is established BEFORE any prompt is fetched or
// admitted.
func (r *Reconciler) resolveCellWorktree(ctx context.Context, entry model.ManagedServiceV2) (string, error) {
	match, err := r.lookupCellProject(ctx, entry)
	if err != nil {
		return "", err
	}
	if match != nil {
		return match.ContainerRoot, nil
	}
	return r.materializeCellProject(ctx, entry)
}

// lookupCellProject resolves existing authority without materialization. V3
// execution/cancellation cannot recreate a workspace accepted during prepare.
func (r *Reconciler) lookupCellProject(ctx context.Context, entry model.ManagedServiceV2) (*state.LocalManagedProject, error) {
	projects, err := r.Store.ManagedProjects(ctx)
	if err != nil {
		return nil, err
	}
	var match *state.LocalManagedProject
	for index := range projects {
		project := &projects[index]
		if project.Report.SelectionID != entry.Workspace.SelectionID ||
			project.Report.ProjectID != entry.Workspace.ProjectID ||
			project.Report.WorkspaceEpoch != entry.Workspace.WorkspaceEpoch ||
			project.Report.SandboxID != entry.SandboxID ||
			project.Report.SandboxGeneration != entry.SandboxGeneration ||
			!cellProjectServiceMatch(project, entry) {
			continue
		}
		if match != nil {
			return nil, errors.New("cell service project authority is ambiguous")
		}
		match = project
	}
	if match != nil {
		if match.Report.RootAttestation != entry.Workspace.RootAttestation {
			return nil, workspacecatalog.ErrProjectChanged
		}
		if match.Phase != "ready" || match.ContainerRoot == "" {
			return nil, errors.New("cell service project authority is not ready")
		}
	}
	return match, nil
}

// cellProjectServiceMatch binds a registered cell project to the cell service
// entry. A project registered by a cell service itself carries that exact
// service registration id. A project registered by the manifest's cell
// workspace intent (managedWorkspaceRequests, targetKind=cell_session) is
// created BEFORE any service exists and is bound to the CELL OWNER, not to a
// service instance: its report carries serviceRegistrationId=null and its
// label is the owner cell id. Requiring a service id on that record made the
// admitted launch re-materialize an already-attested ordinary directory and
// fail closed with `managed project changed` (WP-20, fixed in WP-23).
func cellProjectServiceMatch(project *state.LocalManagedProject, entry model.ManagedServiceV2) bool {
	if project.Report.ServiceRegistrationID != nil {
		return *project.Report.ServiceRegistrationID == entry.ServiceRegistrationID
	}
	return entry.OwnerCellID != "" && project.Report.Label == entry.OwnerCellID
}

// materializeCellProject registers the exact cell workspace binding as an
// ordinary directory under the trusted workspace anchor, derived from the
// manifest's native project id. It creates no repository, no commit and no
// legacy Team path: the backend-attested selection/project/epoch/scope/root are
// copied verbatim into the local binding.
func (r *Reconciler) materializeCellProject(ctx context.Context, entry model.ManagedServiceV2) (string, error) {
	if r.Workspaces == nil {
		return "", errors.New("cell service has no trusted workspace provider")
	}
	if r.ManagedCatalog == nil {
		return "", errors.New("cell service has no trusted workspace catalog")
	}
	sandbox, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return "", err
	}
	diskGiB := 0
	if sandbox != nil {
		diskGiB = sandbox.Resources.WorkspaceDiskGiB
	}
	if diskGiB < 1 {
		return "", errors.New("cell service workspace has no current sandbox disk authority")
	}
	anchor, err := r.Workspaces.Ensure(ctx, entry.SandboxID, diskGiB)
	if err != nil {
		return "", fmt.Errorf("resolve trusted cell workspace anchor: %w", err)
	}
	// Delegate to the catalog's cell materializer so the ACTUAL root is attested
	// (attest() hashes filesystem device/inode/mount) — never the manifest's
	// caller-supplied RootAttestation, which the Runtime cannot pre-know.
	project, err := r.ManagedCatalog.EnsureCellDefault(ctx, workspacecatalog.CellDefaultProjectRequest{
		Anchor: anchor, ServerID: r.ServerID,
		SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration,
		ServiceRegistrationID: entry.ServiceRegistrationID,
		AllocationDigest:      entry.ConfigDigest,
		ConfigDigest:          entry.ConfigDigest,
		OwnerCellID:           entry.OwnerCellID,
		OwnerRole:             entry.OwnerRole,
		OwnerGeneration:       entry.OwnerGeneration,
		SelectionID:           entry.Workspace.SelectionID,
		ProjectID:             entry.Workspace.ProjectID,
		WorkspaceEpoch:        entry.Workspace.WorkspaceEpoch,
		ScopeRevision:         entry.Workspace.ScopeRevision,
	})
	if err != nil {
		return "", err
	}
	return project.ContainerRoot, nil
}

// fetchCellFirstText resolves the first admitted step text from the same
// authenticated instruction authority the member path uses; it never invents a
// prompt locally. The fetch carries the ACTUAL cell service tuple: the canonical
// service registration, the cell entry's pinned instruction/config digest, the
// service generation and the derived nonempty process instance. It must never
// substitute the profile digest, the owner generation or an empty process
// instance.
func (r *Reconciler) fetchCellFirstText(ctx context.Context, entry model.ManagedServiceV2) (string, error) {
	if r.ManagedControl == nil {
		return "", errors.New("cell service has no trusted instruction authority")
	}
	processInstance := model.ManagedServiceProcessInstance(entry.Instance, entry.ServiceGeneration)
	fetch := model.ManagedServiceFetchRequestV1{
		FormatVersion: 1, OperationID: entry.OperationID, ActionRevision: entry.ActionRevision,
		DesiredRevision: entry.DesiredRevision, ConfigDigest: entry.ConfigDigest,
		ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration,
		SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration,
		ProcessInstance: processInstance,
	}
	instruction, err := r.ManagedControl.ManagedServiceInstructions(ctx, entry.ServiceRegistrationID, fetch)
	if err != nil {
		return "", err
	}
	if instruction.InstructionRevision != entry.Instructions.InstructionRevision ||
		instruction.InstructionDigest != entry.Instructions.InstructionDigest ||
		!instruction.ExpiresAt.After(r.now()) ||
		!validateManagedInstruction(instruction.Content, instruction.InstructionDigest) {
		return "", errors.New("cell service instruction tuple is invalid")
	}
	return instruction.Content, nil
}
