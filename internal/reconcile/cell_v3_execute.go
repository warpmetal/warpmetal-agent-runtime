package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// V3 never uses the retained unguarded launch. Common identity plumbing is
// reused, but the accepted receipt and separately issued grant are mandatory.
type managedCellExecuteCallV3 struct {
	managedCellCallV1
	FormatVersion   int                         `json:"formatVersion"`
	PreparedReceipt *model.PreparedReceipt      `json:"preparedReceipt"`
	PreparedTuple   *model.PreparedTuple        `json:"preparedTuple,omitempty"`
	ExecutionGrant  *model.CellExecutionGrantV3 `json:"executionGrant"`
	DesiredState    string                      `json:"desiredState"`
}

type cellGuardReceipt struct {
	FormatVersion int     `json:"formatVersion"`
	SessionID     string  `json:"sessionID"`
	InboxID       string  `json:"inboxID"`
	GuardID       string  `json:"guardID"`
	BindingDigest string  `json:"bindingDigest"`
	State         string  `json:"state"`
	AdmittedAt    *int64  `json:"admittedAt"`
	AvailableAt   *int64  `json:"availableAt"`
	SettledAt     *int64  `json:"settledAt"`
	RefusalCode   *string `json:"refusalCode"`
	LogCursor     *int64  `json:"logCursor"`
}

type managedCellExecuteResultV3 struct {
	managedCellResultV1
	GuardReceipt    *cellGuardReceipt      `json:"guardReceipt"`
	PreparedReceipt *model.PreparedReceipt `json:"preparedReceipt,omitempty"`
	PreparedTuple   *model.PreparedTuple   `json:"preparedTuple,omitempty"`
}

// journalCellV3Execute performs the bounded local journal write of one execute
// pass (R-WP125-2). The store write is already bounded (state.ErrCellV3JournalBusy);
// this adds ONE bounded retry, which is the retry path for a transient local
// lock. A second bound expiry is returned unchanged so the branch can defer the
// pass instead of hanging the reconcile loop or failing it fatally.
func (r *Reconciler) journalCellV3Execute(ctx context.Context, entry model.CellServiceV3, trace *cellV3ExecuteTrace) error {
	value := state.LocalCellV3Operation{Entry: entry, Phase: "pending"}
	err := cellV3JournalPut(r.Store, ctx, value)
	if err == nil || !errors.Is(err, state.ErrCellV3JournalBusy) || ctx.Err() != nil {
		return err
	}
	trace.note("journal busy; bounded retry")
	select {
	case <-ctx.Done():
		return errors.Join(err, ctx.Err())
	case <-time.After(cellV3JournalRetryDelay):
	}
	return cellV3JournalPut(r.Store, ctx, value)
}

// cellV3JournalPut is the single local journal-write boundary of the execute
// branch. It is a variable so the bounded-deferral mapping can be tested without
// a wedged database (the bound itself is tested against real contention in
// internal/state).
var cellV3JournalPut = (*state.Store).PutCellV3Operation

// cellV3JournalRetryDelay is the single bounded pause before the journal retry.
const cellV3JournalRetryDelay = 250 * time.Millisecond

func (r *Reconciler) reconcileCellServiceV3Execute(ctx context.Context, entry model.CellServiceV3) error {
	return r.reconcileCellServiceV3ExecuteCurrent(ctx, entry, nil)
}
func (r *Reconciler) reconcileCellServiceV3ExecuteCurrent(ctx context.Context, entry model.CellServiceV3, current *model.Manifest) (err error) {
	// The named return plus a closed stage label is the bounded diagnostic for
	// the execute branch: a manifest that carries lifecyclePhase=execute plus an
	// issued grant must never be a nameless no-op. Every deliberate deferral
	// records its own closed code instead of leaving the row `phase=reported`
	// with an empty error code (R-WP121-1).
	stage := cellV3StageExecuteContract
	trace := newCellV3ExecuteTrace(entry.PreparationID)
	trace.step("execute_entry")
	defer func() {
		r.recordCellV3ExecuteBlock(ctx, entry, stage, err, trace)
	}()
	if !CellExecutionEnabled(model.CellExecutionContractVersion) {
		return errors.New("cell execution contract unavailable")
	}
	// Put is an explicit transition check, not an unchecked upsert. It also
	// requires a backend-accepted receipt before persisting execute authority.
	stage = cellV3StageExecuteJournal
	if err := r.journalCellV3Execute(ctx, entry, trace); err != nil {
		if errors.Is(err, state.ErrCellV3JournalBusy) {
			// R-WP125-2: the backend COMMITTED this execute intent, but the local
			// journal write was cut at its bound. The durable intent is unchanged
			// and no effect is attempted; defer the pass (the V3 loop keeps it
			// healthy and the report is still sent) and re-drive the exact same
			// entry on the next pass. Fail-closed: nothing advances.
			stage = cellV3StageExecuteJournal
			return fmt.Errorf("%w: %v", errCellV3ExecuteDeferred, err)
		}
		return err
	}
	trace.step("journal_ok")
	preparation, err := r.Store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if preparation == nil {
		return errors.New("cell v3 preparation missing")
	}
	if entry.DesiredState != "active" {
		stage = cellV3StageExecuteQuiescence
		trace.step("quiescence")
		stage = cellV3ExecuteDeferredQuiescence
		return r.reconcileCellV3Quiescence(ctx, entry, preparation)
	}
	stage = cellV3StageExecuteProductGate
	if err := r.verifyCellProductOrQualification(ctx, entry, current); err != nil {
		return err
	}
	trace.step("product_qualification_ok")
	stage = cellV3StageExecuteAuthority
	if err := entry.ValidateExecutionAuthority(preparation.Receipt); err != nil {
		return err
	}
	trace.step("execution_authority_ok")
	stage = cellV3StageExecuteSandbox
	sandbox, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return err
	}
	if sandbox == nil || sandbox.ObservedState != "running" || sandbox.ObservedGeneration != entry.SandboxGeneration {
		return errors.New("cell v3 execution sandbox generation is not running")
	}
	trace.step("sandbox_ok")
	stage = cellV3StageExecuteExecutionState
	execution, err := r.Store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if execution != nil && (execution.Phase == "terminal" || execution.Phase == "exhausted") {
		stage = cellV3StageExecuteTerminalExecution
		trace.step("execution_terminal")
		stage = cellV3ExecuteDeferredTerminal
		return r.cellQualificationEvidence(ctx, entry, execution)
	}
	if execution == nil {
		trace.step("execution_absent")
	} else {
		trace.step("execution_present:" + cellV3TraceToken(execution.Phase, 16))
	}
	view := cellV2View(entry)
	stage = cellV3StageExecuteWorkspace
	project, err := r.lookupCellProject(ctx, view)
	if err != nil {
		return err
	}
	if project == nil || project.ScopeRevision != entry.Workspace.ScopeRevision || project.ContainerRoot != preparation.WorktreeDir {
		return errors.New("cell v3 prepared workspace authority is missing or changed")
	}
	worktree := project.ContainerRoot
	trace.step("workspace_ok")
	stage = cellV3StageExecuteInstruction
	instruction, err := r.fetchCellFirstText(ctx, view)
	if err != nil {
		return err
	}
	trace.step("instruction_ok")
	if execution == nil {
		stage = cellV3StageExecuteQualification
		if err := r.cellQualificationEvidence(ctx, entry, nil); err != nil {
			return err
		}
		trace.step("qualification_begin_ok")
		stage = cellV3StageExecuteGrantExpiry
		trace.step("grant_expiry_check")
		expires, parseErr := time.Parse(time.RFC3339, entry.ExecutionGrant.ExpiresAt)
		if parseErr != nil {
			return errors.New("cell v3 execution grant expiry is invalid")
		}
		if !r.now().Before(expires) {
			// An expired, never-consumed grant is a BOUNDED WAIT, not a pass
			// failure: the backend's renewal path (R-WP119-1) publishes a fresh
			// grant for the same attempt/fence in a later manifest, and failing
			// the whole reconcile here also suppresses the report, turning one
			// expired grant into an unrecoverable conflict. The wait is named
			// durably (deferred:grant_expired) and re-evaluated next pass.
			stage = cellV3ExecuteDeferredGrantExpiry
			trace.step("grant_expired")
			return errCellV3ExecuteDeferred
		}
		stage = cellV3StageExecuteNativeContext
		if preparation.ParentSessionID == "" || preparation.WorktreeDir != worktree {
			return errors.New("cell v3 prepared native context is missing or changed")
		}
		trace.step("native_context_ok")
		stage = cellV3StageExecuteExecutionPersist
		execution = &state.LocalCellV3Execution{PreparationID: entry.PreparationID, Grant: *entry.ExecutionGrant, Phase: "pending", ParentSessionID: preparation.ParentSessionID, WorktreeDir: worktree}
		if err := r.Store.PutCellV3Execution(ctx, entry, *execution); err != nil {
			return err
		}
		trace.step("execution_persisted")
	}
	stage = cellV3StageExecuteEffect
	trace.step("effect_start")
	if effectErr := r.applyCellV3EffectCurrent(ctx, entry, *preparation, *execution, "execute", instruction, current); effectErr != nil {
		stage = cellV3StageExecuteEffectReceipt
		// A closed in-cell refusal left the local row `pending` (definite
		// non-admission). Name it and defer to the next pass/grant instead of
		// failing the whole reconcile; every other failure keeps failing closed.
		if stored, readErr := r.Store.CellV3Execution(ctx, entry.PreparationID); readErr == nil && stored != nil && stored.Phase == "pending" {
			var failure *managedSupervisorActionFailure
			if errors.As(effectErr, &failure) && failure.Diagnostic != "" {
				trace.note("effect refused reason=%s", cellV3TraceToken(failure.Diagnostic, cellV3TraceMaxToken))
			}
			trace.step("effect_refused")
			stage = cellV3ExecuteDeferredRefused
			return errCellV3ExecuteDeferred
		}
		return effectErr
	}
	trace.step("effect_ok")
	// The effect was applied and reported: no block remains, so the durable
	// diagnostic code is cleared instead of keeping a stale refusal.
	stage = ""
	if r.Store != nil {
		// R-WP126-1: effect_ok only proves the in-cell adapter answered. A child
		// that is admitted and never settles must be visible in the pass trail,
		// instead of leaving the operator with "effect_ok" repeated forever. The
		// naming must be evaluated BEFORE the stale-block clear: clearing first
		// would erase the durable code in the same pass that recorded it, and
		// clear+re-record on every later pass would log a false transition.
		named := false
		if stored, readErr := r.Store.CellV3Execution(ctx, entry.PreparationID); readErr == nil && stored != nil {
			trace.step("effect_state:" + cellV3TraceToken(stored.Phase, 16) + ":" + cellV3ChildState(*stored))
			named = r.nameCellV3Unsettled(ctx, entry, *stored, trace)
		}
		if !named {
			_, _ = r.Store.ClearCellV3Blocked(ctx, entry.PreparationID)
		}
	}
	return nil
}

func (r *Reconciler) reconcileCellV3Quiescence(ctx context.Context, entry model.CellServiceV3, preparation *state.LocalCellV3Operation) error {
	execution, err := r.Store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if execution == nil {
		if preparation.ParentSessionID == "" {
			// No proven native preparation: never invent an absent/settled receipt.
			return errors.New("cell v3 cancellation cannot prove the missing native preparation context")
		}
		if entry.LifecyclePhase == "prepare" {
			return r.cancelCellV3Preparation(ctx, entry, *preparation)
		}
		// Missing local execution state is not permission to fall back to legacy
		// launch or a grant-free stop. Retain the supplied authority and reconcile
		// only native cancel/observation, even after the admission TTL expired.
		execution = &state.LocalCellV3Execution{PreparationID: entry.PreparationID, Grant: *entry.ExecutionGrant, Phase: "unknown", ParentSessionID: preparation.ParentSessionID, WorktreeDir: preparation.WorktreeDir}
		if err := r.Store.PutCellV3Execution(ctx, entry, *execution); err != nil {
			return err
		}
	}
	if execution.Phase == "terminal" && execution.Report.ObservedState == "ready" {
		return nil
	}
	if execution.Report.ObservedState == "cancelled" && execution.Report.ObservedDesiredRevision == entry.DesiredRevision {
		return nil
	}
	return r.applyCellV3Effect(ctx, entry, *preparation, *execution, "cancel", "")
}

func cellV3Call(entry model.CellServiceV3, receipt model.PreparedReceipt, parent, worktree, action, firstText string) (managedCellExecuteCallV3, error) {
	call := managedCellExecuteCallV3{FormatVersion: 3, PreparedReceipt: &receipt, ExecutionGrant: entry.ExecutionGrant, DesiredState: entry.DesiredState}
	call.managedCellCallV1 = managedCellCallV1{
		SchemaVersion: 1, Action: action, RuntimeContractVersion: model.CellExecutionContractVersion,
		OperationID: entry.LaunchOperationID, ServiceRegistrationID: entry.ServiceRegistrationID,
		OwnerCellID: entry.OwnerCellID, OwnerRole: entry.OwnerRole, OwnerGeneration: entry.OwnerGeneration,
		SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration,
		Instance: entry.Instance, Role: entry.Role, NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID,
		WorkspaceEpoch: entry.WorkspaceEpoch, ProfileID: entry.Profile.ProfileID, ProfileRevision: entry.Profile.ProfileRevision, ProfileDigest: entry.Profile.ProfileDigest,
		ParentSessionID: parent, Agent: "warpmetal-managed", WorktreeDir: worktree, FirstText: firstText, Attempt: entry.Attempt,
	}
	tuple, err := entry.PreparedTuple()
	if err != nil {
		return call, err
	}
	call.Model.ProviderID, call.Model.ID = tuple.Authority.ProviderID, tuple.Authority.ModelID
	return call, nil
}

func (r *Reconciler) cancelCellV3Preparation(ctx context.Context, entry model.CellServiceV3, local state.LocalCellV3Operation) error {
	if local.ControlReport.ObservedState == "cancelled" && local.ControlReport.ObservedDesiredRevision == entry.DesiredRevision {
		return nil
	}
	current, err := r.Store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if current == nil || !reflect.DeepEqual(current.Entry, entry) {
		return state.ErrCellV3OperationConflict
	}
	hasReceipt := local.Receipt.PreparedReceiptDigest != ""
	if hasReceipt {
		if err := local.Receipt.ValidateFor(entry); err != nil {
			return err
		}
	} else if local.Phase != "pending" && local.Phase != "unknown" {
		return state.ErrCellV3OperationConflict
	}
	call, err := cellV3Call(entry, local.Receipt, local.ParentSessionID, local.WorktreeDir, "cancel", "")
	if err != nil {
		return err
	}
	if !hasReceipt {
		tuple, err := entry.PreparedTuple()
		if err != nil {
			return err
		}
		call.PreparedReceipt, call.PreparedTuple = nil, &tuple
	}
	payload, err := json.Marshal(call)
	if err != nil {
		return err
	}
	// Capture refusal MUST NOT prevent the actual native interruption.
	sourceErr := r.sourceTerminalBeforeCancel(ctx, entry.PreparationID)
	effect, _, effectErr := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorCell, payload)
	var result managedCellExecuteResultV3
	if effectErr == nil {
		effectErr = decodeManagedReceipt(effect, &result, true)
	}
	if effectErr == nil && (result.SchemaVersion != 1 || !CellExecutionEnabled(result.RuntimeContractVersion) || result.OperationID != entry.LaunchOperationID || result.SessionID != entry.NativeSessionID || result.MessageID != "msg_"+strings.TrimPrefix(entry.NativeSessionID, "ses_") || result.Attempt != entry.Attempt || !model.ValidCellAdapterState(result.State) || (hasReceipt && (result.PreparedReceipt == nil || !reflect.DeepEqual(*result.PreparedReceipt, local.Receipt))) || (!hasReceipt && (result.PreparedTuple == nil || !reflect.DeepEqual(result.PreparedTuple, call.PreparedTuple)))) {
		effectErr = errors.New("prepared cancellation identity mismatch")
	}
	observed := "unknown"
	var child *model.ManagedCellChildV1
	if effectErr == nil {
		child = &model.ManagedCellChildV1{OperationID: result.OperationID, SessionID: result.SessionID, MessageID: result.MessageID, State: result.State, Attempt: entry.Attempt, Outcome: result.Outcome, Exhausted: result.Exhausted}
		if entry.DesiredState == "retired" && result.State == "terminal" && result.Interrupted && result.Outcome != nil && *result.Outcome == "interrupted" && !result.Exhausted {
			observed = "cancelled"
		}
	}
	report := r.cancelledReport(cellV2View(entry), entry.Attempt, observed, fmt.Sprintf("sha256:%x", sha256.Sum256(effect)))
	report.FormatVersion, report.Child = 3, child
	if effectErr != nil {
		report.LastError = &model.ManagedServiceErrorV1{Code: "cell_v3_cancel_unknown"}
	}
	persistErr := r.Store.PutCellV3ControlReport(ctx, entry, report, effect)
	if persistErr == nil {
		sourceErr = errors.Join(sourceErr, r.sourceTerminalComplete(ctx, entry.PreparationID))
	}
	return errors.Join(sourceErr, effectErr, persistErr)
}

func (r *Reconciler) applyCellV3Effect(ctx context.Context, entry model.CellServiceV3, preparation state.LocalCellV3Operation, execution state.LocalCellV3Execution, action, firstText string) error {
	return r.applyCellV3EffectCurrent(ctx, entry, preparation, execution, action, firstText, nil)
}
func (r *Reconciler) applyCellV3EffectCurrent(ctx context.Context, entry model.CellServiceV3, preparation state.LocalCellV3Operation, execution state.LocalCellV3Execution, action, firstText string, authority *model.Manifest) error {
	if action != "cancel" {
		if err := r.verifyCellProductOrQualification(ctx, entry, authority); err != nil {
			return err
		}
	}
	// Recheck the entire current journal identity before *every* native effect.
	current, err := r.Store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if current == nil || !reflect.DeepEqual(current.Entry, entry) || entry.ValidateExecutionAuthority(current.Receipt) != nil {
		return state.ErrCellV3OperationConflict
	}
	call, err := cellV3Call(entry, preparation.Receipt, execution.ParentSessionID, execution.WorktreeDir, action, firstText)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(call)
	if err != nil {
		return err
	}
	var sourceErr error
	if action == "cancel" {
		sourceErr = r.sourceTerminalBeforeCancel(ctx, entry.PreparationID)
	}
	effect, diagnostic, effectErr := r.ManagedRuntime.ExecManagedSupervisor(ctx, entry.SandboxID, containers.ManagedSupervisorCell, payload)
	var result managedCellExecuteResultV3
	if effectErr != nil {
		// The in-cell adapter reports its own closed reason on stderr and exits
		// non-zero. Without this classification the whole execute branch surfaced
		// only "exit status 1" (R-WP121-1), so the refusing in-cell predicate was
		// invisible and the durable code could not name it.
		effectErr = fmt.Errorf("cell v3 execute effect failed: %w",
			supervisorActionFailure(containers.ManagedSupervisorCell, effect, diagnostic, effectErr))
	} else if err := decodeManagedReceipt(effect, &result, true); err != nil {
		effectErr = err
	}
	if effectErr == nil {
		guard := result.GuardReceipt
		if result.SchemaVersion != 1 || !CellExecutionEnabled(result.RuntimeContractVersion) || result.OperationID != entry.LaunchOperationID || result.SessionID != entry.NativeSessionID || result.MessageID != execution.Grant.InputID || result.Attempt != entry.Attempt || !model.ValidCellAdapterState(result.State) || guard == nil || guard.FormatVersion != 1 || guard.SessionID != entry.NativeSessionID || guard.InboxID != execution.Grant.InputID || guard.GuardID != execution.Grant.GrantID || guard.BindingDigest != preparation.Receipt.BindingDigest {
			effectErr = errors.New("cell v3 native admission receipt identity mismatch")
		}
	}
	observed, phase := "unknown", "unknown"
	exhausted := execution.Phase == "exhausted" || result.Exhausted || result.State == "exhausted"
	var child *model.ManagedCellChildV1
	if effectErr == nil {
		guard := result.GuardReceipt
		child = &model.ManagedCellChildV1{OperationID: result.OperationID, SessionID: result.SessionID, MessageID: result.MessageID, State: result.State, Attempt: entry.Attempt, Outcome: result.Outcome, Exhausted: exhausted}
		if guard.State != "admitted" && guard.State != "delivered" && guard.State != "cancelled" && guard.State != "refused" {
			effectErr = errors.New("cell v3 native guard receipt state invalid")
		}
		if action == "execute" && guard.State == "delivered" && result.State == "terminal" && result.Outcome != nil && (*result.Outcome == "succeeded" || *result.Outcome == "failed") {
			observed, phase = "ready", "terminal"
		}
		if action == "cancel" && entry.DesiredState == "retired" && result.State == "terminal" && result.Interrupted && result.Outcome != nil && *result.Outcome == "interrupted" && (guard.State == "cancelled" || guard.State == "delivered") {
			observed, phase = "cancelled", "terminal"
		}
		// V3 STATE distinguishes admission from terminality using the child
		// vocabulary. A proved pending/running admission must consume the backend
		// grant now, rather than first reporting it after its admission TTL.
		if observed == "unknown" && action == "execute" && (guard.State == "admitted" || guard.State == "delivered") && (result.State == "pending" || result.State == "running") {
			observed, phase = "ready", "admitted"
		}
	}
	if effectErr != nil {
		observed, phase, child = "unknown", "unknown", nil
		// A CLOSED in-cell refusal (the adapter's own bounded reason line, with no
		// receipt) is proof the child was never admitted: the adapter validates the
		// whole call and its durable guard before any native effect. Keeping the
		// local row `unknown` instead would make the preparation permanently
		// un-renewable (R-WP119-1), so the definite non-admission stays `pending`
		// and is re-evaluated under the next grant. Any other failure (transport,
		// unclassified exit, partial receipt) keeps the unknown/ownership semantics.
		if action == "execute" && cellV3RefusedBeforeAdmission(effect, effectErr) {
			phase = "pending"
		}
	}
	if exhausted {
		observed, phase = "exhausted", "exhausted"
	}
	report := r.cancelledReport(cellV2View(entry), entry.Attempt, observed, fmt.Sprintf("sha256:%x", sha256.Sum256(effect)))
	report.FormatVersion = 3
	report.Child = child
	if effectErr != nil {
		report.LastError = &model.ManagedServiceErrorV1{Code: "cell_v3_outcome_unknown"}
	}
	execution.Phase, execution.Report, execution.EffectJSON = phase, report, effect
	// Persist native evidence + report before the existing STATE report transport.
	persistErr := r.Store.PutCellV3Execution(ctx, entry, execution)
	if persistErr == nil && action == "cancel" {
		sourceErr = errors.Join(sourceErr, r.sourceTerminalComplete(ctx, entry.PreparationID))
	}
	if persistErr == nil && effectErr == nil && action == "execute" {
		return r.cellQualificationEvidence(ctx, entry, &execution)
	}
	return errors.Join(sourceErr, effectErr, persistErr)
}
