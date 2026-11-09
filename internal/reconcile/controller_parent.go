package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// A controller parent is an ordinary opencode process with a genuinely cold
// native start. The installed supervisor already waits for native readiness,
// but the whole cold start (native boot, controller agent visibility, manager
// plugin activation) is not a fixed latency: the installed venue observed
// 29-44s. The Runtime therefore grants the supervisor a longer bounded window
// and, when a start RPC itself is lost or reports "not ready yet", re-reads the
// supervisor's durable state with backoff before recording a terminal failure.
// Only an exact running/instructionApplied native identity may be upgraded.
var (
	controllerParentReadinessWindow = 90 * time.Second
	controllerParentReadinessPoll   = 2 * time.Second
)

const controllerParentStatusProbeTimeoutSeconds = 30

var (
	// Closed internal classifications; the wire code remains the backend's
	// existing enum (native_role_mismatch / native_identity_mismatch).
	errControllerParentRoleMismatch     = errors.New("controller parent native role mismatch")
	errControllerParentIdentityMismatch = errors.New("controller parent native identity mismatch")
)

func parentRequest(parent model.ControllerParentIntent) map[string]any {
	return map[string]any{"schemaVersion": 1, "sandboxId": parent.Owner.SandboxID, "instance": parent.Instance, "profileId": parent.Profile.ProfileID}
}

// controllerHelper decodes the supervisor receipt even when the exec exits
// nonzero. The supervisor emits one typed receipt on failure as well; dropping
// it hides the difference between "still starting" (resumable) and a terminal
// identity refusal.
func (r *Reconciler) controllerHelper(ctx context.Context, parent model.ControllerParentIntent, action containers.ManagedSupervisorAction, request map[string]any) (*managedSupervisorReceipt, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	raw, _, execErr := r.ManagedRuntime.ExecManagedSupervisor(ctx, parent.Owner.SandboxID, action, payload)
	if len(raw) == 0 {
		return nil, execErr
	}
	var receipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(raw, &receipt); err != nil {
		return nil, errors.Join(execErr, err)
	}
	if receipt.SchemaVersion != 1 || receipt.Command != string(action) || receipt.Instance != parent.Instance || receipt.SandboxID != parent.Owner.SandboxID || receipt.ProfileID != parent.Profile.ProfileID {
		return nil, errors.Join(execErr, errors.New("parent helper outer identity conflict"))
	}
	if execErr != nil {
		return &receipt, execErr
	}
	return &receipt, nil
}

func validateParentNativeReceipt(parent model.ControllerParentIntent, receipt *managedSupervisorReceipt, materializer string) error {
	port := 18444
	if parent.Role == "orchestrator" {
		port = 18445
	}
	if receipt == nil || (receipt.Status != "ready" && receipt.Status != "running" && receipt.Status != "already_running") || !receipt.Ready || receipt.Phase != "running" || receipt.PID < 1 || receipt.Port != port || receipt.ProfileDigest != parent.Profile.ProfileDigest || receipt.ProfileRevision != parent.Profile.ProfileRevision || !receipt.InstructionApplied || receipt.InstructionRevision != parent.Instructions.InstructionRevision || receipt.InstructionDigest != parent.Instructions.InstructionDigest || receipt.MaterializerDigest != materializer || receipt.NativeRoleReadback == nil {
		return errors.New("parent dedicated current readback conflict")
	}
	return nil
}

// controllerParentNativeDiag renders the exact supervisor-visible native
// identity against the issued intent in one bounded line. It carries no
// credential and no instruction text, only the values the Runtime compares:
// expected project root and canonical location digest, observed supervisor
// session/project/location, receipt state and the role readback. WP-196 adds it
// because the WP-195 parent failed closed with `native_identity_mismatch` while
// no receipt field was retained to say which comparison refused.
func controllerParentNativeDiag(project workspacecatalog.RegisteredProject, parent model.ControllerParentIntent, receipt *managedSupervisorReceipt, materializer string) string {
	if receipt == nil {
		return `{"receipt":null}`
	}
	role := map[string]any{}
	if receipt.NativeRoleReadback != nil {
		role = map[string]any{
			"role": receipt.NativeRoleReadback.Role, "nativeAgentId": receipt.NativeRoleReadback.NativeAgentID,
			"sessionAgentId": receipt.NativeRoleReadback.SessionAgentID, "parentSessionId": receipt.NativeRoleReadback.ParentSessionID,
			"roleAgentDigest": receipt.NativeRoleReadback.RoleAgentDigest,
		}
	}
	diag := map[string]any{
		"expectedProjectRoot":                project.ContainerRoot,
		"expectedWorkspaceProjectId":         parent.Workspace.ProjectID,
		"expectedLocationDigestNilWorkspace": model.WorkspaceDigest(map[string]any{"directory": project.ContainerRoot, "projectId": receipt.NativeProjectID, "workspaceId": nil}),
		"observedSessionId":                  receipt.SessionID,
		"observedNativeProjectId":            receipt.NativeProjectID,
		"observedNativeLocationDigest":       receipt.NativeLocationDigest,
		"observedStatus":                     receipt.Status,
		"observedPhase":                      receipt.Phase,
		"observedError":                      receipt.Error,
		"observedReady":                      receipt.Ready,
		"observedPort":                       receipt.Port,
		"observedPID":                        receipt.PID,
		"observedInstructionApplied":         receipt.InstructionApplied,
		"observedInstructionRevision":        receipt.InstructionRevision,
		"expectedInstructionRevision":        parent.Instructions.InstructionRevision,
		"observedInstructionDigest":          receipt.InstructionDigest,
		"expectedInstructionDigest":          parent.Instructions.InstructionDigest,
		"observedMaterializerDigest":         receipt.MaterializerDigest,
		"expectedMaterializerDigest":         materializer,
		"observedProfileDigest":              receipt.ProfileDigest,
		"expectedProfileDigest":              parent.Profile.ProfileDigest,
		"observedProfileRevision":            receipt.ProfileRevision,
		"expectedProfileRevision":            parent.Profile.ProfileRevision,
		"observedRoleReadback":               role,
		"expectedRoleAgentDigest":            parent.RoleAgentDigest,
		"expectedNativeAgentId":              "warpmetal-controller-" + parent.Role,
	}
	raw, err := json.Marshal(diag)
	if err != nil {
		return `{"diag":"marshal_failed"}`
	}
	return string(raw)
}

func controllerParentReadyReport(parent model.ControllerParentIntent, receipt *managedSupervisorReceipt) (model.ControllerParentReport, error) {
	report, _ := parent.PendingReport()
	report.ObservedState = "ready"
	report.ProfileStatus = "ready"
	report.WorkspaceStatus = "ready"
	report.InstructionApplied = true
	report.LastError = nil
	report.NativeRegistration = &model.ManagedNativeRegistrationV1{RegisteredSourceID: managedSourceID(parent.ServiceRegistrationID), WorkspaceEpoch: parent.Workspace.WorkspaceEpoch, NativeSessionID: receipt.SessionID, NativeProjectID: receipt.NativeProjectID, NativeLocationDigest: receipt.NativeLocationDigest}
	report.NativeRoleReadback = receipt.NativeRoleReadback
	if err := report.Seal(); err != nil {
		return model.ControllerParentReport{}, err
	}
	if err := report.ValidateReady(parent); err != nil {
		native := map[string]any{}
		if report.NativeRegistration != nil {
			native = map[string]any{"registeredSourceId": report.NativeRegistration.RegisteredSourceID, "workspaceEpoch": report.NativeRegistration.WorkspaceEpoch, "nativeSessionId": report.NativeRegistration.NativeSessionID, "nativeProjectId": report.NativeRegistration.NativeProjectID, "nativeLocationDigest": report.NativeRegistration.NativeLocationDigest}
		}
		readback := map[string]any{}
		if report.NativeRoleReadback != nil {
			readback = map[string]any{"role": report.NativeRoleReadback.Role, "nativeAgentId": report.NativeRoleReadback.NativeAgentID, "sessionAgentId": report.NativeRoleReadback.SessionAgentID, "parentSessionId": report.NativeRoleReadback.ParentSessionID, "roleAgentDigest": report.NativeRoleReadback.RoleAgentDigest}
		}
		log.Printf("controller parent %s ready report refused: %v native=%v roleReadback=%v expectedNativeAgentId=%q expectedRoleAgentDigest=%q", parent.ServiceRegistrationID, err, native, readback, "warpmetal-controller-"+parent.Role, parent.RoleAgentDigest)
		return model.ControllerParentReport{}, fmt.Errorf("%w: %v", errControllerParentIdentityMismatch, err)
	}
	return report, nil
}

// finalizeControllerParent verifies one current native receipt, registers the
// exact source (idempotently), re-reads the current status and only then emits
// the ready report. The same path serves a first start and a later upgrade, so
// the authority semantics are identical and no row is fabricated.
func (r *Reconciler) finalizeControllerParent(ctx context.Context, parent model.ControllerParentIntent, projection model.ControllerRoleProjection, previous *model.ManagedNativeRegistrationV1, receipt *managedSupervisorReceipt, materializer string, project workspacecatalog.RegisteredProject) error {
	log.Printf("controller parent %s finalize: %s", parent.ServiceRegistrationID, controllerParentNativeDiag(project, parent, receipt, materializer))
	if err := validateParentNativeReceipt(parent, receipt, materializer); err != nil {
		log.Printf("controller parent %s receipt refused: %v", parent.ServiceRegistrationID, err)
		return fmt.Errorf("%w: %v", errControllerParentRoleMismatch, err)
	}
	expectedLocation := model.WorkspaceDigest(map[string]any{"directory": project.ContainerRoot, "projectId": receipt.NativeProjectID, "workspaceId": nil})
	if receipt.NativeLocationDigest != expectedLocation {
		log.Printf("controller parent %s native location conflict: expected=%s observed=%s directory=%q nativeProjectId=%q", parent.ServiceRegistrationID, expectedLocation, receipt.NativeLocationDigest, project.ContainerRoot, receipt.NativeProjectID)
		return fmt.Errorf("%w: parent canonical native location conflict", errControllerParentIdentityMismatch)
	}
	if previous != nil && (previous.NativeSessionID != receipt.SessionID || previous.NativeProjectID != receipt.NativeProjectID || previous.NativeLocationDigest != receipt.NativeLocationDigest) {
		return fmt.Errorf("%w: parent native identity changed", errControllerParentIdentityMismatch)
	}
	native := model.ManagedNativeRegistrationV1{RegisteredSourceID: managedSourceID(parent.ServiceRegistrationID), WorkspaceEpoch: parent.Workspace.WorkspaceEpoch, NativeSessionID: receipt.SessionID, NativeProjectID: receipt.NativeProjectID, NativeLocationDigest: receipt.NativeLocationDigest}
	register, registerErr := controllerSourceRegistrationRequest(parent, projection, native)
	if registerErr != nil {
		return fmt.Errorf("%w: %v", errControllerParentIdentityMismatch, registerErr)
	}
	payload, _ := json.Marshal(register)
	raw, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, parent.Owner.SandboxID, containers.ManagedSupervisorRegisterSource, payload)
	if err != nil {
		log.Printf("controller parent %s register-source exec failed: %v", parent.ServiceRegistrationID, err)
		return fmt.Errorf("%w: %v", errControllerParentIdentityMismatch, err)
	}
	var source managedSourceRegistrationReceipt
	if err := decodeManagedSupervisorReceipt(raw, &source); err != nil {
		log.Printf("controller parent %s register-source decode failed: %v", parent.ServiceRegistrationID, err)
		return fmt.Errorf("%w: %v", errControllerParentIdentityMismatch, err)
	}
	if source.SchemaVersion != 1 || source.Command != "register-source" || (source.Status != "registered" && source.Status != "unchanged") || source.Instance != parent.Instance || source.SandboxID != parent.Owner.SandboxID || source.ServiceRegistrationID != parent.ServiceRegistrationID || source.ServiceGeneration != parent.ServiceGeneration || source.RegisteredSourceID != native.RegisteredSourceID || source.WorkspaceEpoch != native.WorkspaceEpoch || source.NativeSessionID != native.NativeSessionID || source.NativeProjectID != native.NativeProjectID || source.NativeLocationDigest != native.NativeLocationDigest || source.ProfileID != parent.Profile.ProfileID || source.ProfileRevision != parent.Profile.ProfileRevision || source.ProfileDigest != parent.Profile.ProfileDigest || source.InstructionRevision != parent.Instructions.InstructionRevision || source.InstructionDigest != parent.Instructions.InstructionDigest {
		log.Printf("controller parent %s register-source readback conflict: status=%q registeredSourceId=%q nativeSessionId=%q nativeProjectId=%q nativeLocationDigest=%q profileDigest=%q profileRevision=%d instructionDigest=%q instructionRevision=%d", parent.ServiceRegistrationID, source.Status, source.RegisteredSourceID, source.NativeSessionID, source.NativeProjectID, source.NativeLocationDigest, source.ProfileDigest, source.ProfileRevision, source.InstructionDigest, source.InstructionRevision)
		return fmt.Errorf("%w: parent protected source readback conflict", errControllerParentIdentityMismatch)
	}
	current, err := r.controllerParentStatus(ctx, parent, projection, &native)
	if err != nil {
		return fmt.Errorf("%w: %v", errControllerParentIdentityMismatch, err)
	}
	if err = validateParentNativeReceipt(parent, current, materializer); err != nil {
		return fmt.Errorf("%w: %v", errControllerParentRoleMismatch, err)
	}
	if current.SessionID != native.NativeSessionID || current.NativeProjectID != native.NativeProjectID || current.NativeLocationDigest != native.NativeLocationDigest || !reflect.DeepEqual(current.NativeRoleReadback, receipt.NativeRoleReadback) {
		return fmt.Errorf("%w: parent native changed during source registration", errControllerParentIdentityMismatch)
	}
	report, err := controllerParentReadyReport(parent, current)
	if err != nil {
		return err
	}
	return r.Store.PutControllerParentReport(ctx, parent, report)
}

func (r *Reconciler) controllerParentStatus(ctx context.Context, parent model.ControllerParentIntent, projection model.ControllerRoleProjection, native *model.ManagedNativeRegistrationV1) (*managedSupervisorReceipt, error) {
	statusRequest := parentRequest(parent)
	statusRequest["probe"] = true
	statusRequest["requestTimeoutSeconds"] = controllerParentStatusProbeTimeoutSeconds
	if native != nil {
		if err := addDeepSeekControllerIdentity(statusRequest, parent, projection, *native); err != nil {
			return nil, err
		}
	}
	return r.controllerHelper(ctx, parent, containers.ManagedSupervisorStatus, statusRequest)
}

// awaitControllerParentReady re-reads the supervisor's durable state for at
// most the readiness window. It returns nil only after finalizeControllerParent
// has re-proved the exact running/instructionApplied native identity.
func (r *Reconciler) awaitControllerParentReady(ctx context.Context, parent model.ControllerParentIntent, projection model.ControllerRoleProjection, previous *model.ManagedNativeRegistrationV1, materializer string, project workspacecatalog.RegisteredProject, deadline time.Time) error {
	var lastErr error
	for {
		current, err := r.controllerParentStatus(ctx, parent, projection, previous)
		if err == nil && current != nil {
			if verifyErr := validateParentNativeReceipt(parent, current, materializer); verifyErr == nil {
				if finalizeErr := r.finalizeControllerParent(ctx, parent, projection, previous, current, materializer, project); finalizeErr == nil {
					return nil
				} else {
					if errors.Is(finalizeErr, errControllerParentIdentityMismatch) || errors.Is(finalizeErr, errControllerParentRoleMismatch) {
						// Exact native identity is visible but conflicts with the
						// issued intent. Waiting cannot make that current.
						return finalizeErr
					}
					lastErr = finalizeErr
				}
			} else if current.Status == "failed" || current.Phase == "failed" || current.PID == 0 {
				// The supervisor explicitly stopped/killed the process. No later
				// state can become ready without a new start.
				return fmt.Errorf("%w: parent not running after start", errControllerParentIdentityMismatch)
			} else {
				lastErr = fmt.Errorf("%w: %v", errControllerParentRoleMismatch, verifyErr)
			}
		} else if err != nil {
			lastErr = err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr == nil {
				lastErr = errors.New("parent readiness window expired")
			}
			return fmt.Errorf("%w: %v", errControllerParentIdentityMismatch, lastErr)
		}
		wait := controllerParentReadinessPoll
		if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// startControllerParent sends the launch and keeps the exact receipt available
// on failure. A start RPC that reports "not ready yet" is not a terminal parent
// state; it is resumed by reading the same supervisor state until the bounded
// readiness window closes.
func (r *Reconciler) startControllerParent(ctx context.Context, parent model.ControllerParentIntent, projection model.ControllerRoleProjection, previous *model.ManagedNativeRegistrationV1, materializer string, project workspacecatalog.RegisteredProject, request map[string]any) error {
	deadline := time.Now().Add(controllerParentReadinessWindow)
	started, startErr := r.controllerHelper(ctx, parent, containers.ManagedSupervisorStart, request)
	if started != nil {
		log.Printf("controller parent %s start receipt: %s", parent.ServiceRegistrationID, controllerParentNativeDiag(project, parent, started, materializer))
	} else if startErr != nil {
		log.Printf("controller parent %s start failed without receipt: %v", parent.ServiceRegistrationID, startErr)
	}
	if startErr == nil && started != nil && (started.Status == "ready" || started.Status == "already_running") {
		return r.finalizeControllerParent(ctx, parent, projection, previous, started, materializer, project)
	}
	if started == nil {
		// The launch response was lost before any typed receipt existed. The
		// current pass must remain failed/unknown (no fabricated ready); the
		// later-reconcile resume path upgrades it only from the supervisor's
		// current durable identity.
		if startErr != nil {
			return fmt.Errorf("%w: %v", errControllerParentIdentityMismatch, startErr)
		}
		return fmt.Errorf("%w: parent start returned no receipt", errControllerParentIdentityMismatch)
	}
	log.Printf("controller parent %s start not ready: status=%q phase=%q error=%q receiptDigest=%q", parent.ServiceRegistrationID, started.Status, started.Phase, started.Error, started.ReceiptDigest)
	if started.Status == "failed" && (started.Phase == "failed" || started.PID == 0) {
		return fmt.Errorf("%w: parent start refused: %s", errControllerParentIdentityMismatch, started.Error)
	}
	return r.awaitControllerParentReady(ctx, parent, projection, previous, materializer, project, deadline)
}

// upgradeControllerParentFromCurrent is the later-reconcile resume path. It
// only probes before a new start when a prior launch was already dispatched,
// and only writes ready when the current supervisor state proves the exact
// issued native identity. Any mismatch falls through to the ordinary start
// path, where existing authority checks still apply.
func (r *Reconciler) upgradeControllerParentFromCurrent(ctx context.Context, parent model.ControllerParentIntent, projection model.ControllerRoleProjection, previous *model.ManagedNativeRegistrationV1, materializer string, project workspacecatalog.RegisteredProject) (bool, error) {
	current, err := r.controllerParentStatus(ctx, parent, projection, previous)
	if err != nil || current == nil {
		return false, nil
	}
	if validateParentNativeReceipt(parent, current, materializer) != nil {
		log.Printf("controller parent %s upgrade probe not current: %s", parent.ServiceRegistrationID, controllerParentNativeDiag(project, parent, current, materializer))
		return false, nil
	}
	if err := r.finalizeControllerParent(ctx, parent, projection, previous, current, materializer, project); err != nil {
		if errors.Is(err, errControllerParentIdentityMismatch) || errors.Is(err, errControllerParentRoleMismatch) {
			log.Printf("controller parent %s upgrade refused: %v", parent.ServiceRegistrationID, err)
			return false, err
		}
		return false, nil
	}
	return true, nil
}

func (r *Reconciler) failControllerParent(ctx context.Context, parent model.ControllerParentIntent, code string, cause error) error {
	report, _ := parent.PendingReport()
	report.ObservedState = "failed"
	report.LastError = &model.ManagedServiceErrorV1{Code: code}
	old, err := r.Store.ControllerParent(ctx, parent.ServiceRegistrationID)
	if err != nil {
		return errors.Join(cause, err)
	}
	if old != nil {
		report.NativeRegistration = old.Report.NativeRegistration
		report.NativeRoleReadback = old.Report.NativeRoleReadback
	}
	_ = report.Seal()
	return errors.Join(cause, r.Store.PutControllerParentReport(ctx, parent, report))
}

func controllerParentFailureCode(err error) string {
	if errors.Is(err, errControllerParentRoleMismatch) {
		return "native_role_mismatch"
	}
	return "native_identity_mismatch"
}

func (r *Reconciler) reconcileControllerParent(ctx context.Context, manifest model.Manifest, parent model.ControllerParentIntent) error {
	if err := r.Store.PutControllerParentIntent(ctx, parent); err != nil {
		return err
	}
	local, err := r.Store.ControllerParent(ctx, parent.ServiceRegistrationID)
	if err != nil {
		return err
	}
	if parent.DesiredState != "active" {
		request := parentRequest(parent)
		if local.CreationDispatched {
			receipt, err := r.controllerHelper(ctx, parent, containers.ManagedSupervisorStop, request)
			if err != nil {
				return r.failControllerParent(ctx, parent, "authority_changed", err)
			}
			if receipt.Status != "stopped" && receipt.Status != "not_running" {
				return r.failControllerParent(ctx, parent, "native_identity_mismatch", errors.New("parent stop not observed"))
			}
		}
		report, _ := parent.PendingReport()
		report.ObservedState = parent.DesiredState
		report.LastError = nil
		report.NativeRegistration = local.Report.NativeRegistration
		report.NativeRoleReadback = local.Report.NativeRoleReadback
		_ = report.Seal()
		return r.Store.PutControllerParentReport(ctx, parent, report)
	}
	op, dependency, err := r.readControllerApplication(ctx, manifest, parent)
	if err != nil {
		// R-WP122-2: a bounded read block is NOT a parent state transition. The
		// native parent did not change; only this pass's read of its approved
		// application was cut at the bound. Retaining the last durable
		// observation keeps the parent's ready/failed gate honest instead of
		// flapping it (R-WP123-1) and lets the independent V3 execute stage of
		// this same pass proceed while the read is retried next pass.
		if _, blocked := controllerApplicationReadBlockedCode(err); blocked {
			r.recordControllerApplicationBlocked(ctx, parent, err)
			return err
		}
		return r.failControllerParent(ctx, parent, "dependency_pending", err)
	}
	if err = r.Store.PutWorkspaceApplication(ctx, op); err != nil {
		return err
	}
	if err = r.stageControllerApplicationProfiles(ctx, op, parent); err != nil {
		if _, blocked := controllerApplicationReadBlockedCode(err); blocked {
			r.recordControllerApplicationBlocked(ctx, parent, err)
			return err
		}
		return r.failControllerParent(ctx, parent, "profile_incomplete", err)
	}
	// Staging already resolved and enforced this identity; the parent start and
	// status readbacks must be compared against the same Supervisor-visible
	// closure, never against the producer-declared source pin.
	materializer, err := controllerMaterializer(op.MaterializerDigest)
	if err != nil {
		return r.failControllerParent(ctx, parent, "profile_incomplete", err)
	}
	project, err := r.resolveControllerProject(ctx, op, parent)
	if err != nil {
		return r.failControllerParent(ctx, parent, "authority_changed", err)
	}
	control, ok := r.ManagedControl.(controllerApplicationReader)
	if !ok {
		return r.failControllerParent(ctx, parent, "dependency_pending", errors.New("application transport dependency pending"))
	}
	instruction, instructionErr := r.readApplicationInstructions(ctx, control, op.OperationID, parent.ServiceRegistrationID)
	if instructionErr != nil {
		// R-WP122-2: a bounded read block is a retryable transport condition.
		// Record its closed local code and keep the wire code inside the
		// backend's enum instead of reporting an authority change it cannot see.
		if _, blocked := controllerApplicationReadBlockedCode(instructionErr); blocked {
			r.recordControllerApplicationBlocked(ctx, parent, instructionErr)
			return instructionErr
		}
		return r.failControllerParent(ctx, parent, "authority_changed", errors.Join(instructionErr, errors.New("current parent instruction conflict")))
	}
	if instruction.InstructionDigest != parent.Instructions.InstructionDigest || instruction.InstructionRevision != parent.Instructions.InstructionRevision {
		return r.failControllerParent(ctx, parent, "authority_changed", errors.New("current parent instruction conflict"))
	}
	setup, err := r.Store.SetupOperation(ctx, parent.Profile.SetupOperationID)
	if err != nil {
		return err
	}
	var installed model.SetupOperation
	if setup == nil || json.Unmarshal(setup.RequestJSON, &installed) != nil || installed.Materializer.Bin == nil || installed.Materializer.Bin.Version == "" {
		return r.failControllerParent(ctx, parent, "dependency_pending", errors.New("parent verified native engine version missing"))
	}
	// Later reconcile: a prior launch was already dispatched. When the
	// supervisor now reports the exact running/instructionApplied identity the
	// failed/pending row is upgraded idempotently, without a second creation and
	// without re-running the cold-start start gate.
	if local.CreationDispatched && local.Report.ObservedState != "ready" {
		upgraded, upgradeErr := r.upgradeControllerParentFromCurrent(ctx, parent, dependency.Projection, local.Report.NativeRegistration, materializer, project)
		if upgradeErr != nil {
			return r.failControllerParent(ctx, parent, controllerParentFailureCode(upgradeErr), upgradeErr)
		}
		if upgraded {
			return nil
		}
	}
	mode := parent.SessionMode
	if local.CreationDispatched {
		mode = "lookup_only"
	}
	if err = r.Store.MarkControllerParentCreationDispatched(ctx, parent); err != nil {
		return err
	}
	port := 18444
	if parent.Role == "orchestrator" {
		port = 18445
	}
	request := managedLaunchComposition{SandboxID: parent.Owner.SandboxID, Instance: parent.Instance, ProfileID: parent.Profile.ProfileID, ProfileDigest: parent.Profile.ProfileDigest, Version: installed.Materializer.Bin.Version, Port: port, ProjectRoot: project.ContainerRoot, SessionMode: mode, InstructionText: instruction.Content, InstructionDigest: instruction.InstructionDigest, InstructionRevision: instruction.InstructionRevision, RuntimeContractVersion: parent.RuntimeContractVersion}.request()
	request["controllerParent"] = parent
	request["roleProjection"] = dependency.Projection
	request["materializerDigest"] = materializer
	request["readinessSeconds"] = int(controllerParentReadinessWindow / time.Second)
	if local.Report.NativeRegistration != nil {
		// A resumed launch binds the retained native source identity; a first
		// launch learns it from the start receipt instead.
		if err := addDeepSeekControllerIdentity(request, parent, dependency.Projection, *local.Report.NativeRegistration); err != nil {
			return r.failControllerParent(ctx, parent, "authority_changed", err)
		}
	}
	if err := r.startControllerParent(ctx, parent, dependency.Projection, local.Report.NativeRegistration, materializer, project, request); err != nil {
		log.Printf("controller parent %s failed: %v", parent.ServiceRegistrationID, err)
		return r.failControllerParent(ctx, parent, controllerParentFailureCode(err), err)
	}
	return nil
}
