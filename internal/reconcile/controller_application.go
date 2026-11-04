package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// Additive application transport stays separate from the retained Team/V3
// control interface. The production existing api.Client implements it; older
// control adapters fail closed, rather than supplying a fake Team enrollment.
type controllerApplicationReader interface {
	WorkspaceApplicationOperation(context.Context, string) (model.WorkspaceApplicationOperation, error)
	WorkspaceApplicationInstructions(context.Context, string, string) (api.WorkspaceApplicationInstructions, error)
	WorkspaceApplicationBundle(context.Context, string, model.ApprovedExpertiseProfile) (json.RawMessage, error)
}

// R-WP122-2: one controller-application control-plane read must never consume
// the reconcile pass or the execution-grant window. The api.Client transport
// aborts at 45s and the pass context at 10m5s, so before this bound a single
// WorkspaceApplicationBundle GET waiting on the venue TLS proxy could hold the
// whole serial pass (SIGQUIT goroutine dump: controller_application.go:114), and
// the V3 execute stage later in the same pass never ran while the 5-minute grant
// TTL drained. Every application read attempt now carries its own context
// deadline, is retried a fixed number of times with a fixed backoff, and is
// abandoned as a CLOSED, durable block code the parent loop can defer on
// instead of failing the whole pass.
//
// These are variables only so bounded tests can scale the fixed budget; the
// production values are the constants below and nothing at runtime writes them.
const (
	controllerApplicationReadAttemptTimeoutDefault = 12 * time.Second
	controllerApplicationReadAttemptsDefault       = 2
	controllerApplicationReadBackoffDefault        = 250 * time.Millisecond
)

var (
	controllerApplicationReadAttemptTimeout = controllerApplicationReadAttemptTimeoutDefault
	controllerApplicationReadAttempts       = controllerApplicationReadAttemptsDefault
	controllerApplicationReadBackoff        = controllerApplicationReadBackoffDefault
)

// Closed block codes. They are persisted on the controller-parent row (never on
// the wire report, whose lastError.code is a closed backend enum) so a pass that
// was abandoned on a slow read is nameable after the fact.
const (
	controllerApplicationBlockedOperation    = "application_read_blocked:application_operation"
	controllerApplicationBlockedBundle       = "application_read_blocked:application_bundle"
	controllerApplicationBlockedInstructions = "application_read_blocked:application_instructions"
)

// controllerApplicationReadBlocked is a bounded, retryable transport condition,
// not an authority or product conflict: the same read is retried on the next
// pass and the parent stays fail-closed and unadvanced.
type controllerApplicationReadBlocked struct {
	Code     string
	Attempts int
	Err      error
}

func (e *controllerApplicationReadBlocked) Error() string {
	return fmt.Sprintf("controller application read blocked (%s) after %d attempt(s): %v", e.Code, e.Attempts, e.Err)
}

func (e *controllerApplicationReadBlocked) Unwrap() error { return e.Err }

// controllerApplicationReadBlockedCode reports the closed block code carried by
// err, including through the errors.Join that failControllerParent returns.
func controllerApplicationReadBlockedCode(err error) (string, bool) {
	var blocked *controllerApplicationReadBlocked
	if errors.As(err, &blocked) && blocked.Code != "" {
		return blocked.Code, true
	}
	return "", false
}

// controllerApplicationReadRetryable keeps a 4xx authority conflict fatal and
// immediate while a transport deadline, a transport error or a 5xx/429 is
// retried. A cancelled/expired parent context is never retried.
func controllerApplicationReadRetryable(err error, parent context.Context) bool {
	if err == nil || parent.Err() != nil {
		return false
	}
	var response *api.ResponseError
	if errors.As(err, &response) {
		return response.Status == http.StatusTooManyRequests || response.Status >= 500
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var transport net.Error
	if errors.As(err, &transport) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// applicationRead runs one bounded, retried control-plane read and converts
// every abandoned attempt into the closed block code for that read.
func (r *Reconciler) applicationRead(ctx context.Context, code string, read func(context.Context) error) error {
	attempts := controllerApplicationReadAttempts
	if attempts < 1 {
		attempts = 1
	}
	var last error
	for attempt := 1; attempt <= attempts; attempt++ {
		attemptContext, cancel := context.WithTimeout(ctx, controllerApplicationReadAttemptTimeout)
		err := read(attemptContext)
		// The attempt consumed its own deadline (rather than the far end
		// answering): this is the bound, not an authority/product answer.
		timedOut := attemptContext.Err() == context.DeadlineExceeded
		cancel()
		if err == nil {
			return nil
		}
		last = err
		retryable := controllerApplicationReadRetryable(err, ctx)
		if attempt == attempts || !retryable {
			// Fail-closed: a named 4xx answer (an authority/product conflict)
			// is returned exactly as before and stays fatal. Only the bound's
			// own timeout or a retryable transport/5xx outcome is a deferrable
			// read block.
			if !timedOut && !retryable {
				return err
			}
			return &controllerApplicationReadBlocked{Code: code, Attempts: attempt, Err: last}
		}
		timer := time.NewTimer(controllerApplicationReadBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return &controllerApplicationReadBlocked{Code: code, Attempts: attempt, Err: errors.Join(last, ctx.Err())}
		case <-timer.C:
		}
	}
	return &controllerApplicationReadBlocked{Code: code, Attempts: attempts, Err: last}
}

func (r *Reconciler) readApplicationOperation(ctx context.Context, control controllerApplicationReader, operationID string) (model.WorkspaceApplicationOperation, error) {
	var operation model.WorkspaceApplicationOperation
	err := r.applicationRead(ctx, controllerApplicationBlockedOperation, func(readContext context.Context) error {
		value, err := control.WorkspaceApplicationOperation(readContext, operationID)
		operation = value
		return err
	})
	return operation, err
}

func (r *Reconciler) readApplicationInstructions(ctx context.Context, control controllerApplicationReader, operationID, serviceID string) (api.WorkspaceApplicationInstructions, error) {
	var instructions api.WorkspaceApplicationInstructions
	err := r.applicationRead(ctx, controllerApplicationBlockedInstructions, func(readContext context.Context) error {
		value, err := control.WorkspaceApplicationInstructions(readContext, operationID, serviceID)
		instructions = value
		return err
	})
	return instructions, err
}

func (r *Reconciler) readApplicationBundle(ctx context.Context, control controllerApplicationReader, operation model.WorkspaceApplicationOperation, profile model.ApprovedExpertiseProfile) (json.RawMessage, error) {
	var bundle json.RawMessage
	err := r.applicationRead(ctx, controllerApplicationBlockedBundle, func(readContext context.Context) error {
		value, err := control.WorkspaceApplicationBundle(readContext, operation.OperationID, profile)
		bundle = value
		return err
	})
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

// recordControllerApplicationBlocked persists the closed block code on the
// controller-parent row and logs one line per transition. It never advances the
// parent and never rewrites the wire report code, whose enum is closed.
func (r *Reconciler) recordControllerApplicationBlocked(ctx context.Context, parent model.ControllerParentIntent, err error) {
	code, blocked := controllerApplicationReadBlockedCode(err)
	if !blocked || r.Store == nil {
		return
	}
	changed, setErr := r.Store.SetControllerParentBlocked(ctx, parent.ServiceRegistrationID, code)
	if setErr != nil || !changed {
		return
	}
	log.Printf("controller parent %s application read blocked: %s", parent.ServiceRegistrationID, code)
}

// This is the SAME atomic role/running source candidate closure, NOT approval or
// a ready/installed flag. The predecessor remains immutable evidence. The
// operation must carry an approved exact pin; Supervisor then computes the same
// closure from actual installed files before publication.
//
// R-WP92-2 is resolved by the explicit approval/adoption record in
// controller_materializer_adoption.go: production accepts only F1's candidate,
// while one exact test-scoped adoption may name the installed closure the
// packaged Supervisor actually measures. The producer-declared digest is never
// rewritten in the operation or in the backend readback.

// applicationRevisionCurrent keeps an applied operation authority-valid after
// the single node-wide desired revision advances for another workspace. A
// retained (locally applied + exact-retained envelope) operation accepted at an
// earlier target remains immutable evidence; a not-yet-retained operation still
// requires exact equality and a target ahead of the node is refused.
func applicationRevisionCurrent(op model.WorkspaceApplicationOperation, desiredRevision int64, retained bool) bool {
	if op.TargetRuntimeRevision == desiredRevision {
		return true
	}
	return retained && desiredRevision > op.TargetRuntimeRevision
}

func (r *Reconciler) readControllerApplication(ctx context.Context, manifest model.Manifest, parent model.ControllerParentIntent) (model.WorkspaceApplicationOperation, model.ApplicationRoleDependency, error) {
	control, ok := r.ManagedControl.(controllerApplicationReader)
	if !ok {
		return model.WorkspaceApplicationOperation{}, model.ApplicationRoleDependency{}, errors.New("application transport dependency pending")
	}
	op, err := r.readApplicationOperation(ctx, control, parent.ApplicationOperationID)
	if err != nil {
		return op, model.ApplicationRoleDependency{}, err
	}
	dependency, err := op.ParentDependency(parent)
	if err != nil {
		return op, dependency, err
	}
	expiry, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	accepted, readErr := r.Store.WorkspaceApplication(ctx, op.OperationID)
	if readErr != nil {
		return op, dependency, readErr
	}
	retained := accepted != nil && accepted.Applied && reflect.DeepEqual(accepted.Operation, op) && len(accepted.EnvelopeJSON) > 0
	revisionCurrent := applicationRevisionCurrent(op, manifest.DesiredRevision, retained)
	if op.TargetRuntimeRevision != manifest.DesiredRevision {
		// P7g bounded trace: identify the exact multi-workspace authority frame
		// without secrets. One line per read transition, never rewritten as a
		// success; retained operations accepted at an earlier node revision are
		// allowed to remain current while the node advances for another workspace.
		log.Printf("controller application authority trace: operation=%s targetRuntimeRevision=%d manifestDesiredRevision=%d retained=%t accepted=%t revisionCurrent=%t",
			op.OperationID, op.TargetRuntimeRevision, manifest.DesiredRevision, retained, accepted != nil, revisionCurrent)
	}
	if err != nil || !retained && !expiry.After(r.now()) || !revisionCurrent || op.ServerID != r.ServerID {
		return op, dependency, errors.New("application current Runtime authority changed")
	}
	// Current engine receipts are local observations from the ordinary setup
	// path, not an inverse digest lookup or owner-supplied installation claim.
	for _, receipt := range op.Dependencies.SetupReceipts {
		setup, err := r.Store.SetupOperation(ctx, receipt.SetupOperationID)
		if err != nil {
			return op, dependency, err
		}
		if setup == nil || setup.State != "ready" || setup.SandboxID != op.SandboxID || setup.SandboxGeneration != op.SandboxGeneration || setup.ReceiptDigest != receipt.ReceiptDigest {
			return op, dependency, errors.New("application setup receipt dependency pending")
		}
	}
	instruction, err := r.readApplicationInstructions(ctx, control, op.OperationID, parent.ServiceRegistrationID)
	if err != nil {
		return op, dependency, err
	}
	if instruction.InstructionRevision != dependency.Instructions.InstructionRevision || instruction.InstructionDigest != dependency.Instructions.InstructionDigest {
		return op, dependency, fmt.Errorf("application role instruction authority changed")
	}
	return op, dependency, nil
}

func (r *Reconciler) stageControllerApplicationProfiles(ctx context.Context, op model.WorkspaceApplicationOperation, parent model.ControllerParentIntent) error {
	// A controller parent is prompt-free: the closure may be absent (retained
	// six-field wire) but a present closure must be the exact empty disabled
	// deployment. A non-empty tool/MCP surface belongs to a future specialist
	// consumer and is not staged through a controller-parent application.
	materializer, err := controllerMaterializer(op.MaterializerDigest)
	if err != nil || len(op.Dependencies.Tools) != 0 || !op.Dependencies.ControllerParentToolSurfaceEmpty() {
		return errors.New("exact approved materializer/tool closure dependency pending")
	}
	box, err := r.Store.Sandbox(ctx, op.SandboxID)
	if err != nil {
		return err
	}
	if box == nil || box.ObservedState != "running" || box.ObservedGeneration != op.SandboxGeneration {
		return errors.New("application sandbox generation not running")
	}
	// Reopen the same registered root using its existing HOST-private authority.
	// This does not relabel that root's owning service as a parent or change its
	// allocation. The independently authenticated application authorizes the exact
	// parent to select this root; the catalog still verifies live device/inode/owner.
	project, err := r.resolveControllerProject(ctx, op, parent)
	if err != nil {
		return err
	}
	control, ok := r.ManagedControl.(controllerApplicationReader)
	if !ok || r.ManagedRuntime == nil {
		return errors.New("application producer dependency pending")
	}
	requests := make([][]byte, 0, len(op.Dependencies.Profiles))
	// Data-only profile staging has its own deterministic operation identity.
	// Never route it through a running parent's default-denied activity branch.
	stageInstance := "profile-" + model.WorkspaceDigest(op.OperationID)[7:19]
	for _, profile := range op.Dependencies.Profiles {
		bundle, err := r.readApplicationBundle(ctx, control, op, profile.ApprovedProfile)
		if err != nil {
			return err
		}
		if err := rejectDuplicateJSONFields(bundle); err != nil {
			return err
		}
		request, err := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": op.SandboxID,
			"instance": stageInstance, "profileId": "opencode", "expected": profile, "bundle": bundle,
			"materializerDigest": materializer})
		if err != nil || len(request) > 2*1024*1024 {
			return errors.Join(err, errors.New("application profile input exceeds bound"))
		}
		requests = append(requests, request)
	}
	for index, request := range requests {
		raw, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, op.SandboxID, containers.ManagedSupervisorMaterializeProfile, request)
		if err != nil {
			return err
		}
		var receipt managedSupervisorReceipt
		if err := decodeManagedSupervisorReceipt(raw, &receipt); err != nil {
			return err
		}
		if receipt.SchemaVersion != 1 || receipt.Command != "materialize-profile" || receipt.Status != "ready" || !receipt.Ready || receipt.SandboxID != op.SandboxID || receipt.Instance != stageInstance || receipt.MaterializerDigest != materializer || receipt.AppliedProfile == nil || !reflect.DeepEqual(*receipt.AppliedProfile, op.Dependencies.Profiles[index]) {
			return fmt.Errorf("application complete profile readback conflict: status=%s error=%s", receipt.Status, receipt.Error)
		}
	}
	// WP-211B prepare-stage agent-kit materialization: an applied v2
	// configuration's agentSetup becomes in-cell content through the packaged
	// supervisor action, verified before persistence. Unset/unknown TEST venue
	// selects nothing, so the production default remains exactly the profile
	// staging above (declared-only kit).
	return r.stageControllerAgentKit(ctx, op, parent, project)
}

// controllerParentWorkspaceLayout is the durable project layout a controller
// parent application may name. Controller parents run on the cell's own
// ordinary-directory workspace (EnsureCellDefault): a team_project with no
// service registration, no Team/Member identity, the owner cell as label and
// no Git repository. Member projects keep the strict Team/Git lineage. Any
// other shape is unknown and is refused before a catalog resolve, so a
// malformed or relabelled row can never borrow either lineage's semantics.
type controllerParentWorkspaceLayout int

const (
	controllerParentWorkspaceUnknown controllerParentWorkspaceLayout = iota
	controllerParentWorkspaceMember
	controllerParentWorkspaceCell
)

func controllerParentWorkspaceLayoutOf(record *state.LocalManagedProject, ownerCellID string) controllerParentWorkspaceLayout {
	if record == nil || record.Report.Designation != "team_project" {
		return controllerParentWorkspaceUnknown
	}
	serviceID := ""
	if record.Report.ServiceRegistrationID != nil {
		serviceID = *record.Report.ServiceRegistrationID
	}
	switch {
	case serviceID == "" && record.TeamID == "" && record.MemberID == "":
		if ownerCellID == "" {
			return controllerParentWorkspaceUnknown
		}
		return controllerParentWorkspaceCell
	case serviceID != "" && record.TeamID != "" && record.MemberID != "":
		return controllerParentWorkspaceMember
	default:
		return controllerParentWorkspaceUnknown
	}
}

func (r *Reconciler) resolveControllerProject(ctx context.Context, op model.WorkspaceApplicationOperation, parent model.ControllerParentIntent) (workspacecatalog.RegisteredProject, error) {
	record, err := r.Store.ManagedProject(ctx, parent.Workspace.SelectionID)
	if err != nil {
		return workspacecatalog.RegisteredProject{}, err
	}
	if record == nil || record.ServerID != op.ServerID || record.Report.RootAttestation != parent.Workspace.RootAttestation || record.ScopeRevision != parent.Workspace.ScopeRevision {
		return workspacecatalog.RegisteredProject{}, errors.New("application registered root dependency pending")
	}
	serviceID := ""
	if record.Report.ServiceRegistrationID != nil {
		serviceID = *record.Report.ServiceRegistrationID
	}
	request := workspacecatalog.ResolveProjectRequest{
		SelectionID: parent.Workspace.SelectionID, ProjectID: parent.Workspace.ProjectID, WorkspaceEpoch: parent.Workspace.WorkspaceEpoch,
		SandboxID: op.SandboxID, SandboxGeneration: op.SandboxGeneration, ServiceRegistrationID: serviceID, ConfigDigest: record.ConfigDigest}
	var project workspacecatalog.RegisteredProject
	switch controllerParentWorkspaceLayoutOf(record, parent.Owner.CellID) {
	case controllerParentWorkspaceCell:
		project, err = r.ManagedCatalog.ResolveCell(ctx, request, parent.Owner.CellID)
	case controllerParentWorkspaceMember:
		project, err = r.ManagedCatalog.Resolve(ctx, request)
	default:
		return workspacecatalog.RegisteredProject{}, workspacecatalog.ErrProjectChanged
	}
	if err != nil {
		return workspacecatalog.RegisteredProject{}, err
	}
	if project.Report.RootAttestation != parent.Workspace.RootAttestation || project.ScopeRevision != parent.Workspace.ScopeRevision {
		return workspacecatalog.RegisteredProject{}, errors.New("application current root changed")
	}
	return project, nil
}
