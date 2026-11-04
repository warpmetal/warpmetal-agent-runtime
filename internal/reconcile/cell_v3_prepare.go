package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// Bounded formatVersion 3 preparation stages. Each value names the exact
// predicate that admitted, rejected or skipped the managed child for one
// preparation. They are persisted (with an optional closed reason) in
// cell_v3_operations.error_code while the row is still pending, so a blocked
// preparation is diagnosable without a live pass, sqlite spelunking or a
// reproduction. Values are closed vocabulary: no free text, no prompt, no
// secret material.
const (
	cellV3StageContract             = "contract"
	cellV3StagePreparedTuple        = "prepared_tuple"
	cellV3StageJournalIntent        = "journal_intent"
	cellV3StageQuiescence           = "quiescence"
	cellV3StageProductQualification = "product_qualification"
	cellV3StageReplayReport         = "replay_report"
	cellV3StageSandboxGeneration    = "sandbox_generation"
	cellV3StageWorktree             = "worktree"
	cellV3StageInstructionFetch     = "instruction_fetch"
	cellV3StageNativeServer         = "native_server"
	cellV3StageNativeContext        = "native_context"
	cellV3StageCredentialLease      = "credential_lease"
	cellV3StageCredentialBinding    = "credential_binding"
	cellV3StageCredentialMaterial   = "credential_material"
	cellV3StagePrepareCall          = "prepare_call"
	cellV3StagePrepareReceipt       = "prepare_receipt"
	cellV3StageReceiptPersist       = "receipt_persist"
	cellV3StageReport               = "report"
	// Deferral stages are recorded by the caller when an admitted entry is
	// removed from the pass BEFORE its own branch runs (a silent skip).
	cellV3StageDeferredFirstTaskDelivery = "deferred:first_task_delivery"
	cellV3StageDeferredManagedProject    = "deferred:managed_project_remount"
)

// managedCellPrepareCallV1 is the frozen R -> trusted-adapter formatVersion 3
// prepare call. It carries the EXACT preparedTuple object plus the identity the
// adapter needs to create a prompt-free native child; credential material travels
// only in the protected stdin request, never argv/env/workspace. Provider,
// authMode and connection identity are crosschecked equal to the tuple before
// the call.
type managedCellPrepareCallV1 struct {
	SchemaVersion   int                             `json:"schemaVersion"`
	Action          string                          `json:"action"`
	Instance        string                          `json:"instance"`
	SandboxID       string                          `json:"sandboxId"`
	OperationID     string                          `json:"operationId"`
	PreparationID   string                          `json:"preparationId"`
	NativeProjectID string                          `json:"nativeProjectId"`
	Workspace       model.ManagedServiceV2Workspace `json:"workspace"`
	ProfileID       string                          `json:"profileId"`
	ProfileDigest   string                          `json:"profileDigest"`
	ParentSessionID string                          `json:"parentSessionId"`
	Agent           string                          `json:"agent"`
	WorktreeDir     string                          `json:"worktreeDir"`
	Model           struct {
		ProviderID string `json:"providerID"`
		ID         string `json:"id"`
	} `json:"model"`
	Provider              string              `json:"provider"`
	AuthMode              string              `json:"authMode"`
	Material              json.RawMessage     `json:"material"`
	CredentialID          string              `json:"credentialId"`
	ConnectionID          string              `json:"connectionId"`
	ConnectionRevision    int64               `json:"connectionRevision"`
	PreparedTuple         model.PreparedTuple `json:"preparedTuple"`
	RequestTimeoutSeconds int                 `json:"requestTimeoutSeconds"`
}

// managedCellPrepareResultV1 is the safe prepare receipt returned by the trusted
// adapter after the native durable bind. It never carries secret material.
type managedCellPrepareResultV1 struct {
	SchemaVersion   int                    `json:"schemaVersion"`
	Command         string                 `json:"command"`
	Status          string                 `json:"status"`
	Ready           bool                   `json:"ready"`
	SandboxID       string                 `json:"sandboxId"`
	Instance        string                 `json:"instance"`
	ProfileDigest   string                 `json:"profileDigest"`
	PreparedReceipt *model.PreparedReceipt `json:"preparedReceipt"`
}

// cellV2View projects a formatVersion 3 entry onto the retained formatVersion 2
// shape for the shared Runtime helpers that only read the common
// identity/workspace/profile fields. It never feeds the V2 launch path.
func cellV2View(entry model.CellServiceV3) model.ManagedServiceV2 {
	return model.ManagedServiceV2{
		FormatVersion: 2, TargetKind: "cell_session",
		OperationID: entry.OperationID, LaunchOperationID: entry.LaunchOperationID,
		ActionRevision: entry.ActionRevision, DesiredRevision: entry.DesiredRevision,
		DesiredState: entry.DesiredState, SessionMode: entry.SessionMode,
		ServiceRegistrationID: entry.ServiceRegistrationID, OwnerCellID: entry.OwnerCellID,
		OwnerRole: entry.OwnerRole, OwnerGeneration: entry.OwnerGeneration,
		SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration,
		ServiceGeneration: entry.ServiceGeneration, ConfigDigest: entry.ConfigDigest,
		Fence: entry.Fence, Attempt: entry.Attempt, Instance: entry.Instance, Role: entry.Role,
		NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID,
		WorkspaceEpoch: entry.WorkspaceEpoch, Workspace: entry.Workspace,
		Instructions: entry.Instructions, Profile: entry.Profile, Authority: entry.Authority,
	}
}

// reconcileCellServicesV3 routes preparation and separately authorized execution
// without falling back to the retained V2 same-pass launch.
func (r *Reconciler) reconcileCellServicesV3(ctx context.Context, manifest model.Manifest) (deferred, fatal error) {
	// One bounded line per pass names the V3 entries the manifest carried, so a
	// manifest whose execute entry never reaches its own branch (because an
	// upstream step returned, or the entry was filtered) is still observable in
	// the Runtime log (R-WP121-1). It never carries prompt/credential material.
	for index, entry := range manifest.CellEntriesV3 {
		if index >= 4 {
			break
		}
		log.Printf("cell v3 manifest %s phase=%s desired=%s desiredRevision=%d actionRevision=%d attempt=%d grant=%t",
			entry.PreparationID, cellV3TraceToken(entry.LifecyclePhase, 16),
			cellV3TraceToken(entry.DesiredState, 16), entry.DesiredRevision, entry.ActionRevision,
			entry.Attempt, entry.ExecutionGrant != nil)
	}
	for _, entry := range manifest.CellEntriesV3 {
		var err error
		if entry.LifecyclePhase == "prepare" {
			err = r.reconcileCellServiceV3PrepareCurrent(ctx, entry, &manifest)
		} else {
			err = r.reconcileCellServiceV3ExecuteCurrent(ctx, entry, &manifest)
		}
		if err != nil {
			wrapped := fmt.Errorf("cell v3 preparation %s: %w", entry.PreparationID, err)
			if errors.Is(err, errCellV3ExecuteDeferred) {
				// Named bounded wait: the branch already persisted the closed
				// code, so the pass stays a healthy deferral instead of failing
				// the reconcile (which would suppress the report entirely).
				deferred = errors.Join(deferred, wrapped)
				continue
			}
			if errors.Is(err, workspacecatalog.ErrManagedProjectRemountAttestation) {
				r.recordCellV3PrepareBlockCode(ctx, entry, cellV3StageDeferredManagedProject)
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

// recordCellV3PrepareBlock persists the bounded diagnostic for a rejected or
// skipped preparation. It is best effort: the prepare error stays the returned
// error (fail closed), and a store refusal never masks it. It logs once per
// transition, not once per pass.
func (r *Reconciler) recordCellV3PrepareBlock(ctx context.Context, entry model.CellServiceV3, stage string, cause error, trace *cellV3PrepareTrace) {
	code := cellV3PrepareBlockCode(stage, cause)
	if r.Store == nil || entry.PreparationID == "" || code == "" {
		return
	}
	changed, err := r.Store.SetCellV3PrepareBlocked(ctx, entry.PreparationID, code)
	if err != nil {
		return
	}
	if changed {
		// One bounded line names the persisted code, the exact step, the closed
		// cause class and the steps reached in this pass, so a blocked child
		// creation is diagnosable from the Runtime log alone (R-WP120-1).
		log.Printf("cell v3 preparation %s child not created: %s step=%s cause=%s elapsed=%s steps=%s",
			entry.PreparationID, code, cellV3TraceToken(stage, cellV3TraceMaxToken),
			cellV3CauseToken(cause), trace.total().Round(time.Millisecond), trace.trail())
	}
}

// recordCellV3PrepareBlockCode persists one already-classified closed code.
func (r *Reconciler) recordCellV3PrepareBlockCode(ctx context.Context, entry model.CellServiceV3, code string) {
	if r.Store == nil || entry.PreparationID == "" || code == "" {
		return
	}
	changed, err := r.Store.SetCellV3PrepareBlocked(ctx, entry.PreparationID, code)
	if err != nil {
		return
	}
	if changed {
		log.Printf("cell v3 preparation %s child not created: %s", entry.PreparationID, code)
	}
}

// cellV3PrepareBlockCode reduces a stage and its cause to the bounded closed
// code persisted on the preparation row. A managed supervisor failure keeps its
// own closed reason, so the row names the exact in-cell predicate (for example
// native_server:install_not_ready); anything else keeps the stage alone.
func cellV3PrepareBlockCode(stage string, cause error) string {
	code := stage
	var failure *managedSupervisorActionFailure
	if errors.As(cause, &failure) && failure.reasonToken() != "" {
		code = stage + ":" + failure.reasonToken()
	}
	if len(code) > 96 {
		code = code[:96]
	}
	return code
}

// reconcileCellServiceV3Prepare performs the durable prepare-only branch:
// journal the authoritative intent, ensure the native server, fetch the
// protected account lease and verify it against the manifest binding, run the
// trusted adapter prepare command (which adopts the credential, binds the exact
// native credential id and returns a safe receipt WITHOUT a prompt), persist the
// receipt BEFORE the backend report, then report. Replays reuse the persisted
// bytes; a paused/stopped/retired preparation admits no effect.
//
// The named return plus the per-step stage label is the bounded diagnostic: a
// rejected or skipped preparation persists the exact predicate that stopped the
// managed child from being created, so the row is never left as an unexplained
// phase=pending/attempt=0 with an empty error code.
func (r *Reconciler) reconcileCellServiceV3Prepare(ctx context.Context, entry model.CellServiceV3) error {
	return r.reconcileCellServiceV3PrepareCurrent(ctx, entry, nil)
}
func (r *Reconciler) reconcileCellServiceV3PrepareCurrent(ctx context.Context, entry model.CellServiceV3, current *model.Manifest) (err error) {
	stage := cellV3StageContract
	trace := newCellV3PrepareTrace(entry.PreparationID)
	defer func() {
		if err != nil {
			r.recordCellV3PrepareBlock(ctx, entry, stage, err, trace)
		}
	}()
	if !CellExecutionEnabled(model.CellExecutionContractVersion) {
		return errors.New("cell execution is not enabled by the current supervisor contract")
	}
	stage = cellV3StagePreparedTuple
	tuple, err := entry.PreparedTuple()
	if err != nil {
		return err
	}
	// Always compare current authority with the journal BEFORE a replay, report,
	// workspace/server effect, or credential fetch; existing rows are not exempt.
	stage = cellV3StageJournalIntent
	if err := r.Store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: entry, Phase: "pending"}); err != nil {
		return err
	}
	local, err := r.Store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if local == nil {
		return errors.New("cell v3 preparation intent disappeared")
	}
	if entry.DesiredState != "active" {
		stage = cellV3StageQuiescence
		return r.reconcileCellV3Quiescence(ctx, entry, local)
	}
	stage = cellV3StageProductQualification
	if err := r.verifyCellProductOrQualification(ctx, entry, current); err != nil {
		return err
	}
	if local.Phase == "prepared" || local.Phase == "reported" {
		stage = cellV3StageReplayReport
		return r.reportCellV3PreparationCurrent(ctx, *local, current)
	}
	stage = cellV3StageSandboxGeneration
	sandbox, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return err
	}
	if sandbox == nil || sandbox.ObservedState != "running" || sandbox.ObservedGeneration != entry.SandboxGeneration {
		return errors.New("cell v3 preparation sandbox generation is not running")
	}
	view := cellV2View(entry)
	stage = cellV3StageWorktree
	worktreeDir, err := r.resolveCellWorktree(ctx, view)
	if err != nil {
		return err
	}
	stage = cellV3StageInstructionFetch
	instruction, err := r.fetchCellFirstText(ctx, view)
	if err != nil {
		return err
	}
	stage = cellV3StageNativeServer
	trace.step("native_server_start")
	var parentSessionID string
	if entry.SessionMode == "lookup_only" {
		// A V3 child preparation with sessionMode=lookup_only attaches to an
		// ALREADY-RUNNING manager parent. Rebinding or starting that parent is
		// refused by the retained supervisor (`controller_activity_dependency_pending`),
		// so this branch only PROBES the signed live session and fails closed if
		// it is not a ready manager (see resolveCellV3ControllerParentManager).
		parentSessionID, err = r.resolveCellV3ControllerParentManager(ctx, entry)
		if err != nil {
			return err
		}
	} else {
		parentSessionID, err = r.ensureCellNativeServerRunning(ctx, view, worktreeDir, instruction)
		if err != nil {
			return err
		}
	}
	trace.step("native_server_ok")
	stage = cellV3StageNativeContext
	if err := r.Store.PutCellV3NativeContext(ctx, entry, parentSessionID, worktreeDir); err != nil {
		return err
	}
	stage = cellV3StageCredentialLease
	trace.step("credential_fetch_start")
	lease, err := r.fetchCellCredentialLease(ctx, entry.ServiceRegistrationID, trace)
	if err != nil {
		return fmt.Errorf("cell v3 credential fetch failed: %w", err)
	}
	trace.step("credential_fetch_ok")
	stage = cellV3StageCredentialBinding
	if !entry.CredentialBinding.MatchesLease(lease.ConnectionID, lease.ConnectionRevision) {
		return errors.New("cell v3 credential lease does not match the manifest binding")
	}
	trace.step("credential_binding_ok")
	stage = cellV3StageCredentialMaterial
	if err := model.ValidateCellCredentialMaterial(lease.Material, tuple.CredentialBinding.ProviderID, tuple.CredentialBinding.AuthMode); err != nil {
		return err
	}
	trace.step("credential_material_ok")
	stage = cellV3StagePrepareCall
	call := managedCellPrepareCallV1{
		SchemaVersion: 1, Action: "prepare",
		Instance: entry.Instance, SandboxID: entry.SandboxID, OperationID: entry.LaunchOperationID,
		PreparationID: entry.PreparationID, NativeProjectID: entry.NativeProjectID,
		Workspace: entry.Workspace, ProfileID: entry.Profile.ProfileID, ProfileDigest: entry.Profile.ProfileDigest,
		ParentSessionID: parentSessionID, Agent: "warpmetal-managed", WorktreeDir: worktreeDir,
		Provider: tuple.Authority.ProviderID, AuthMode: tuple.Authority.AuthMode,
		Material: lease.Material, CredentialID: lease.CredentialID,
		ConnectionID: lease.ConnectionID, ConnectionRevision: lease.ConnectionRevision,
		PreparedTuple: tuple, RequestTimeoutSeconds: 30,
	}
	call.Model.ProviderID, call.Model.ID = tuple.Authority.ProviderID, tuple.Authority.ModelID
	payload, err := json.Marshal(call)
	if err != nil {
		return err
	}
	trace.step("prepare_call_start")
	receiptJSON, diagnosticJSON, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorPrepare, payload)
	if err != nil {
		return fmt.Errorf("cell v3 prepare effect did not return a receipt: %w", supervisorActionFailure(containers.ManagedSupervisorPrepare, receiptJSON, diagnosticJSON, err))
	}
	trace.step("prepare_call_ok")
	stage = cellV3StagePrepareReceipt
	var receipt managedCellPrepareResultV1
	if err := decodeManagedReceipt(receiptJSON, &receipt, true); err != nil {
		return fmt.Errorf("invalid cell v3 prepare receipt: %w", err)
	}
	if receipt.SchemaVersion != 1 || receipt.Command != "prepare" || receipt.Status != "prepared" || !receipt.Ready ||
		receipt.SandboxID != entry.SandboxID || receipt.Instance != entry.Instance ||
		receipt.ProfileDigest != entry.Profile.ProfileDigest || receipt.PreparedReceipt == nil {
		return errors.New("cell v3 prepare receipt is not a ready prepared receipt")
	}
	if err := receipt.PreparedReceipt.ValidateFor(entry); err != nil {
		return fmt.Errorf("cell v3 prepare receipt is inconsistent: %w", err)
	}
	trace.step("prepare_receipt_ok")
	exact, err := json.Marshal(receipt.PreparedReceipt)
	if err != nil {
		return err
	}
	stage = cellV3StageReceiptPersist
	if err := r.Store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{
		Entry: entry, Phase: "prepared", Attempt: entry.Attempt,
		PreparedReceiptDigest: receipt.PreparedReceipt.PreparedReceiptDigest,
		Receipt:               *receipt.PreparedReceipt, ReceiptJSON: exact,
	}); err != nil {
		return err
	}
	persisted, err := r.Store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || persisted == nil {
		return errors.Join(err, errors.New("cell v3 prepared receipt disappeared"))
	}
	trace.step("receipt_persisted")
	stage = cellV3StageReport
	return r.reportCellV3PreparationCurrent(ctx, *persisted, current)
}

// resolveCellV3ControllerParentManager proves the manager that will host the V3
// child is the exact signed controller parent and is live, WITHOUT mutating its
// supervisor binding.
//
// The backend issues a V3 child preparation with sessionMode=lookup_only: the
// child attaches to an ALREADY-RUNNING manager parent, so the preparation must
// never bind, drain or start that parent. The retained supervisor allows only
// the controller transport commands on a controller-parent instance and refuses
// `rebind`/`start` with `controller_activity_dependency_pending`; that refusal
// is what left the fixture V3 preparation at phase=pending with no managed child
// (R-WP108-1). A controller-parent instance is the only instance whose status
// receipt carries a signed native role readback, so this branch requires that
// readback (and the signed owner role) before the trusted adapter creates the
// child under the live session; it never rewrites the parent's authority.
func (r *Reconciler) resolveCellV3ControllerParentManager(ctx context.Context, entry model.CellServiceV3) (string, error) {
	if entry.OwnerRole != "manager" || (entry.Role != "worker" && entry.Role != "reviewer") {
		return "", errors.New("cell v3 lookup preparation requires a manager-owned worker or reviewer")
	}
	statusRequest := map[string]any{
		"schemaVersion": 1, "sandboxId": entry.SandboxID, "instance": entry.Instance,
		"profileId": entry.Profile.ProfileID, "profileDigest": entry.Profile.ProfileDigest,
		"probe": true, "requestTimeoutSeconds": 30,
	}
	statusPayload, err := json.Marshal(statusRequest)
	if err != nil {
		return "", err
	}
	statusReceiptJSON, diagnostic, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorStatus, statusPayload)
	if err != nil {
		return "", fmt.Errorf("cell v3 manager session probe failed: %w", supervisorActionFailure(containers.ManagedSupervisorStatus, statusReceiptJSON, diagnostic, err))
	}
	var statusReceipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(statusReceiptJSON, &statusReceipt); err != nil {
		return "", err
	}
	if statusReceipt.SchemaVersion != 1 || statusReceipt.Command != "status" || statusReceipt.Status != "running" || !statusReceipt.Ready ||
		statusReceipt.SessionID == "" || statusReceipt.Instance != entry.Instance || statusReceipt.SandboxID != entry.SandboxID ||
		statusReceipt.ProfileID != entry.Profile.ProfileID || statusReceipt.ProfileDigest != entry.Profile.ProfileDigest {
		return "", errors.New("cell v3 lookup manager session is not live and ready")
	}
	// Only a controller-parent instance reports the signed native role readback;
	// a standalone manager can never satisfy this branch.
	if statusReceipt.NativeRoleReadback == nil || statusReceipt.NativeRoleReadback.Role != entry.OwnerRole ||
		statusReceipt.NativeRoleReadback.NativeAgentID == "" {
		return "", errors.New("cell v3 lookup manager role readback is missing")
	}
	return statusReceipt.SessionID, nil
}

// The idempotent credential-lease fetch is bounded by a TOTAL WALL-CLOCK
// BUDGET, not by a fixed attempt count (R-WP120-1). A fixed count of three was
// indistinguishable from "the venue is slow for one pass": each attempt burned
// the control-plane client's per-request timeout and the preparation failed
// closed with credential_lease while the backend kept answering 200.
//
// The budget is clamped to the pass deadline, every retry keeps a capped
// exponential backoff so a fast refusal loop stays bounded, and the per-attempt
// transport deadline is raised to the control-plane budget for THIS idempotent
// read only. Fail-closed semantics are unchanged: a definitive 4xx is never
// retried, cancellation stops immediately, and an exhausted budget returns a
// bounded error naming the attempt count, elapsed time and the closed cause.
const (
	cellCredentialMaxAttempts = 24
)

var (
	// cellCredentialLeaseBudget is the total wall clock one preparation pass may
	// spend fetching the lease.
	cellCredentialLeaseBudget = 150 * time.Second
	// cellCredentialAttemptTimeout is the per-attempt transport deadline.
	cellCredentialAttemptTimeout = 60 * time.Second
	// cellCredentialRetryDelay is the first backoff step (a variable so a
	// bounded test does not sleep for the production interval).
	cellCredentialRetryDelay = 500 * time.Millisecond
	// cellCredentialRetryMaxDelay caps the exponential backoff.
	cellCredentialRetryMaxDelay = 8 * time.Second
)

// cellCredentialDeadlineControl is the optional control-plane capability that
// lets the idempotent lease fetch use an explicit per-request transport
// deadline. Implementations that do not provide it (the retained test doubles
// and any non-HTTP transport) keep the ordinary CellCredential call.
type cellCredentialDeadlineControl interface {
	CellCredentialWithTimeout(context.Context, string, time.Duration) (api.CellCredentialResult, error)
}

// cellCredentialBackoff is the capped exponential backoff between attempts.
func cellCredentialBackoff(attempt int) time.Duration {
	delay := cellCredentialRetryDelay
	for step := 1; step < attempt; step++ {
		if delay >= cellCredentialRetryMaxDelay/2 {
			break
		}
		delay *= 2
	}
	if delay > cellCredentialRetryMaxDelay {
		delay = cellCredentialRetryMaxDelay
	}
	if delay <= 0 {
		delay = time.Millisecond
	}
	return delay
}

// cellCredentialLeaseDeadline is the total budget clamped to the pass deadline.
func cellCredentialLeaseDeadline(ctx context.Context) time.Duration {
	budget := cellCredentialLeaseBudget
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < budget {
			budget = remaining
		}
	}
	return budget
}

// fetchCellCredentialLease consumes its own success: a timeout/transport error
// on an earlier attempt does not discard a later 200 for the same immutable
// lease. Definitive authority responses (4xx) are never retried.
//
// Every failed attempt is logged with its own elapsed time and a closed cause
// token (R-WP120-1): a lease that never arrives because the control-plane
// request timed out is indistinguishable, from the durable row, from one the
// backend refused.
func (r *Reconciler) fetchCellCredentialLease(ctx context.Context, serviceRegistrationID string, trace *cellV3PrepareTrace) (api.CellCredentialResult, error) {
	leaseContext, cancel := context.WithTimeout(ctx, cellCredentialLeaseDeadline(ctx))
	defer cancel()
	var last error
	attempts := 0
	started := time.Now()
	for attempts < cellCredentialMaxAttempts {
		attempts++
		attemptStarted := time.Now()
		attemptContext, cancelAttempt := context.WithTimeout(leaseContext, cellCredentialAttemptTimeout)
		lease, err := r.cellCredential(attemptContext, serviceRegistrationID)
		cancelAttempt()
		if err == nil {
			trace.note("credential_lease ready attempt=%d attempt_elapsed=%s",
				attempts, time.Since(attemptStarted).Round(time.Millisecond))
			if attempts > 1 {
				log.Printf("cell v3 credential lease recovered on attempt %d", attempts)
			}
			return lease, nil
		}
		last = err
		trace.note("credential_lease attempt=%d failed attempt_elapsed=%s cause=%s ctx=%s",
			attempts, time.Since(attemptStarted).Round(time.Millisecond),
			cellV3CauseToken(err), cellV3CauseToken(leaseContext.Err()))
		if leaseContext.Err() != nil || !cellCredentialRetryable(err) {
			break
		}
		delay := cellCredentialBackoff(attempts)
		if deadline, ok := leaseContext.Deadline(); ok && time.Until(deadline) <= delay {
			break
		}
		timer := time.NewTimer(delay)
		select {
		case <-leaseContext.Done():
			timer.Stop()
			return api.CellCredentialResult{}, fmt.Errorf(
				"credential lease unavailable after %d attempt(s) in %s (cause=%s)",
				attempts, time.Since(started).Round(time.Millisecond), cellV3CauseToken(last))
		case <-timer.C:
		}
	}
	return api.CellCredentialResult{}, fmt.Errorf(
		"credential lease unavailable after %d attempt(s) in %s (cause=%s): %w",
		attempts, time.Since(started).Round(time.Millisecond), cellV3CauseToken(last), last)
}

// cellCredential performs one lease fetch, using the optional explicit
// transport deadline when the control client supports it.
func (r *Reconciler) cellCredential(ctx context.Context, serviceRegistrationID string) (api.CellCredentialResult, error) {
	if extended, ok := r.ManagedControl.(cellCredentialDeadlineControl); ok {
		return extended.CellCredentialWithTimeout(ctx, serviceRegistrationID, cellCredentialAttemptTimeout)
	}
	return r.ManagedControl.CellCredential(ctx, serviceRegistrationID)
}

// Only a definite 4xx authority refusal is final. Transport failures and
// transient 5xx/429 are retried against the same immutable lease identity.
func cellCredentialRetryable(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var response *api.ResponseError
	if errors.As(err, &response) {
		return response.Status == 429 || response.Status >= 500
	}
	return true
}

// reportCellV3Preparation reports the prepared receipt to the backend over the// node-authenticated transport. The exact persisted bytes are reused so a lost
// acknowledgement replays the same receipt identity; the journal only advances
// to reported after the backend accepts.
func (r *Reconciler) reportCellV3Preparation(ctx context.Context, local state.LocalCellV3Operation) error {
	return r.reportCellV3PreparationCurrent(ctx, local, nil)
}
func (r *Reconciler) reportCellV3PreparationCurrent(ctx context.Context, local state.LocalCellV3Operation, authority *model.Manifest) error {
	if err := r.verifyCellProductOrQualification(ctx, local.Entry, authority); err != nil {
		return err
	}
	current, err := r.Store.CellV3Operation(ctx, local.Entry.PreparationID)
	if err != nil {
		return err
	}
	if current == nil || !reflect.DeepEqual(current.Entry, local.Entry) || !bytes.Equal(current.ReceiptJSON, local.ReceiptJSON) {
		return state.ErrCellV3OperationConflict
	}
	receipt := local.Receipt
	if len(local.ReceiptJSON) != 0 {
		if err := json.Unmarshal(local.ReceiptJSON, &receipt); err != nil {
			return err
		}
	}
	if err := receipt.ValidateFor(local.Entry); err != nil {
		return fmt.Errorf("persisted cell v3 receipt is no longer valid: %w", err)
	}
	report := model.CellPreparationReport{PreparationID: local.Entry.PreparationID, PreparedReceipt: receipt}
	view, err := r.ManagedControl.ReportCellPreparation(ctx, report)
	if err != nil {
		return fmt.Errorf("cell v3 preparation report failed: %w", err)
	}
	if err := view.ValidateFor(local.Entry, receipt); err != nil {
		return err
	}
	if local.Phase != "reported" {
		local.Phase = "reported"
		if err := r.Store.UpdateCellV3Operation(ctx, local); err != nil {
			return err
		}
	}
	// The native header must be observed after the backend's prepared_at cut.
	// A missing observer/unknown handoff never causes credential re-adoption.
	if err := r.captureCellQualificationAuthorization(ctx, local.Entry, receipt); err != nil {
		return err
	}
	if authority != nil {
		target, err := childSourceTransportTarget(local.Entry, *authority)
		if err != nil {
			return err
		}
		if err = r.publishSourcePreparedProcess(ctx, *authority, target); err != nil {
			return err
		}
	}
	return nil
}
