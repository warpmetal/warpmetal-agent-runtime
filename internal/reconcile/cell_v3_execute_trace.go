package reconcile

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Bounded formatVersion 3 EXECUTE diagnostics (R-WP121-1).
//
// The execute branch had no stage diagnostics and no durable block code, so a
// manifest that carried `lifecyclePhase=execute` plus an issued grant could stay
// a no-op: the backend execution remained `pending` with `admitted_at NULL`, the
// grant was never consumed, the local preparation row stayed `phase=reported`
// and the node report carried `lastError=null` (the pass returned nil). A
// nil-returning deferral is indistinguishable from a completed pass from the
// durable rows alone, so this file adds the same bounded instrumentation the
// prepare branch got in WP-121:
//
//   - one closed stage per decision point of ONE execute pass,
//   - the closed cause class only (never an error string, prompt or receipt),
//   - a durable `<stage>` / `deferred:<why>` code on the preparation row so a
//     skip (not just a rejection) is nameable after the fact.
//
// The step vocabulary is fixed and the volume is bounded: at most
// cellV3TraceMaxSteps trace lines per pass, one deferred/rejected line per
// durable transition.
const (
	cellV3StageExecuteContract          = "execute:contract"
	cellV3StageExecuteJournal           = "execute:journal"
	cellV3StageExecuteQuiescence        = "execute:quiescence"
	cellV3StageExecuteProductGate       = "execute:product_qualification"
	cellV3StageExecuteAuthority         = "execute:execution_authority"
	cellV3StageExecuteSandbox           = "execute:sandbox_generation"
	cellV3StageExecuteExecutionState    = "execute:execution_state"
	cellV3StageExecuteWorkspace         = "execute:workspace_authority"
	cellV3StageExecuteInstruction       = "execute:instruction_fetch"
	cellV3StageExecuteGrantExpiry       = "execute:grant_expiry"
	cellV3StageExecuteNativeContext     = "execute:native_context"
	cellV3StageExecuteExecutionPersist  = "execute:execution_persist"
	cellV3StageExecuteEffect            = "execute:effect"
	cellV3StageExecuteEffectReceipt     = "execute:effect_receipt"
	cellV3StageExecuteQualification     = "execute:qualification_evidence"
	cellV3StageExecuteTerminalExecution = "execute:terminal_execution"
)

// Closed deferred codes. They are persisted only when the execute branch
// deliberately does NOT make an effect this pass, so a silent deferral is never
// left nameless.
const (
	cellV3ExecuteDeferredQuiescence  = "deferred:quiescence"
	cellV3ExecuteDeferredTerminal    = "deferred:terminal_execution"
	cellV3ExecuteDeferredEvidence    = "deferred:qualification_evidence"
	cellV3ExecuteDeferredGrantExpiry = "deferred:grant_expired"
	cellV3ExecuteDeferredRefused     = "deferred:effect_refused"
	// R-WP125-2: the backend committed the execute intent but the LOCAL journal
	// write could not complete inside its bound. Nothing advanced; the next pass
	// (or the bounded retry of this one) re-drives the exact same entry.
	cellV3ExecuteDeferredJournal = "deferred:journal_busy"
	// R-WP126-1: the native guard admitted the child and the effect succeeded,
	// but the child produced no terminal state before the settlement bound. This
	// is a DIAGNOSTIC code only: the pass still completes, the report is still
	// sent, nothing is fabricated or released.
	cellV3ExecuteDeferredUnsettled = "deferred:child_not_settled"
)

// cellV3SettleGrace is the bound after the admission grant's expiry. The grant
// was consumed at admission, so its expiry is the one durable timestamp that
// proves how long the child has been admitted; a healthy synthetic turn closes
// in seconds, so one grace window is generous.
const cellV3SettleGrace = 90 * time.Second

// cellV3CellAdapterRefusalPrefix is the cell adapter's own bounded refusal line.
// Its presence (with no receipt) is the closed proof that the adapter rejected the
// call BEFORE any native effect, so the child was never admitted.
const cellV3CellAdapterRefusalPrefix = "warpmetal_cell_adapter: "

// cellV3RefusedBeforeAdmission reports whether a failed execute effect is a
// CLOSED in-cell refusal that PROVABLY happened before the durable guard journal
// and the native prompt, so the child was never admitted.
//
// Only the adapter's own bounded reason line counts (a traceback or a transport
// failure is unclassified and keeps the unknown semantics), and the two reasons
// the adapter raises AT or AFTER the guard write are excluded by name: the grant
// expiry check runs inside the "no guard receipt yet" branch, and "guarded
// admission outcome is unknown" is raised after the prompt was posted. Everything
// else in that vocabulary is raised by _validate_execution_call /
// _verify_qualification_selection / identity / credential-binding checks, all of
// which run before any native effect.
func cellV3RefusedBeforeAdmission(effect []byte, err error) bool {
	if len(effect) != 0 || err == nil {
		return false
	}
	var failure *managedSupervisorActionFailure
	if !errors.As(err, &failure) {
		return false
	}
	if !strings.HasPrefix(failure.Diagnostic, cellV3CellAdapterRefusalPrefix) {
		return false
	}
	reason := strings.ToLower(strings.TrimPrefix(failure.Diagnostic, cellV3CellAdapterRefusalPrefix))
	for _, unprovable := range cellV3UnprovableRefusalReasons {
		if strings.Contains(reason, unprovable) {
			return false
		}
	}
	return true
}

// cellV3UnprovableRefusalReasons are the adapter refusals whose native effect may
// already have been attempted; they must retain the unknown/ownership semantics.
var cellV3UnprovableRefusalReasons = []string{
	"grant expired before admission",
	"guarded admission outcome is unknown",
}

// errCellV3ExecuteDeferred marks an execute pass that deliberately made no
// effect and must be re-evaluated on the next pass. The branch has already
// recorded the durable closed code; the V3 loop treats it as a deferred wait
// (like a managed-project remount) instead of failing the whole reconcile.
var errCellV3ExecuteDeferred = errors.New("cell v3 execution deferred to the next pass")

// cellV3ExecuteTrace records the bounded stage trail of one execute pass. It
// reuses the prepare trace tokens/cause vocabulary so both branches of the V3
// path log in the same shape.
type cellV3ExecuteTrace struct {
	preparationID string
	started       time.Time
	last          time.Time
	steps         []string
}

func newCellV3ExecuteTrace(preparationID string) *cellV3ExecuteTrace {
	now := time.Now()
	return &cellV3ExecuteTrace{preparationID: preparationID, started: now, last: now}
}

// step records and logs one completed stage of the current pass.
func (t *cellV3ExecuteTrace) step(name string) {
	if t == nil {
		return
	}
	now := time.Now()
	delta, total := now.Sub(t.last), now.Sub(t.started)
	t.last = now
	if len(t.steps) < cellV3TraceMaxSteps {
		t.steps = append(t.steps, name)
	}
	log.Printf("cell v3 execute %s step=%s delta=%s total=%s",
		t.preparationID, cellV3TraceToken(name, cellV3TraceMaxToken),
		delta.Round(time.Millisecond), total.Round(time.Millisecond))
}

// note logs one bounded diagnostic line built from closed tokens only.
func (t *cellV3ExecuteTrace) note(format string, arguments ...any) {
	if t == nil {
		return
	}
	log.Printf("cell v3 execute %s "+format+" total=%s",
		append([]any{t.preparationID}, append(arguments, t.total().Round(time.Millisecond))...)...)
}

func (t *cellV3ExecuteTrace) total() time.Duration {
	if t == nil {
		return 0
	}
	return time.Since(t.started)
}

func (t *cellV3ExecuteTrace) trail() string {
	if t == nil || len(t.steps) == 0 {
		return "none"
	}
	return strings.Join(t.steps, ",")
}

// recordCellV3ExecuteBlock persists the bounded diagnostic for an execute pass
// whose native effect was rejected or deliberately deferred. It is best effort:
// the returned error (or nil) is unchanged, and a store refusal never masks it.
func (r *Reconciler) recordCellV3ExecuteBlock(ctx context.Context, entry model.CellServiceV3, stage string, cause error, trace *cellV3ExecuteTrace) {
	code := stage
	if errors.Is(cause, state.ErrCellV3JournalBusy) {
		// A bounded local journal write is a named, retryable deferral, not an
		// unclassified store error (R-WP125-2).
		code = cellV3ExecuteDeferredJournal
	} else if cause != nil {
		code = cellV3PrepareBlockCode(stage, cause)
	}
	if r.Store == nil || entry.PreparationID == "" || code == "" {
		return
	}
	changed, err := r.Store.SetCellV3ExecuteBlocked(ctx, entry.PreparationID, code)
	if err != nil {
		return
	}
	if changed {
		log.Printf("cell v3 execution %s not admitted: %s step=%s cause=%s elapsed=%s steps=%s",
			entry.PreparationID, code, cellV3TraceToken(stage, cellV3TraceMaxToken),
			cellV3CauseToken(cause), trace.total().Round(time.Millisecond), trace.trail())
	}
}

// nameCellV3Unsettled records the closed "admitted but not settling" code ONCE
// the admission grant's expiry plus one grace window has passed. The grant was
// consumed at admission, so its expiry is the durable clock for how long the
// child has been admitted. Nothing about settlement, ownership, the report or
// the applied revision changes here: only the existing diagnostic column is
// named, and the trace note is emitted once per durable transition.
// It reports whether this pass is a named unsettled wait whose durable code
// must be retained, so the caller does not clear it in the same pass. The log
// line is emitted only on the transition (SetCellV3ExecuteBlocked reports
// changed), never on every repeat pass.
func (r *Reconciler) nameCellV3Unsettled(ctx context.Context, entry model.CellServiceV3, execution state.LocalCellV3Execution, trace *cellV3ExecuteTrace) bool {
	if r.Store == nil || entry.ExecutionGrant == nil || execution.Phase == "terminal" || execution.Phase == "exhausted" {
		return false
	}
	expires, err := time.Parse(time.RFC3339, entry.ExecutionGrant.ExpiresAt)
	if err != nil || r.now().Before(expires.Add(cellV3SettleGrace)) {
		return false
	}
	changed, err := r.Store.SetCellV3ExecuteBlocked(ctx, entry.PreparationID, cellV3ExecuteDeferredUnsettled)
	if err != nil {
		return false
	}
	if changed {
		trace.note("admitted but not settled: %s phase=%s child=%s bound=%s",
			cellV3ExecuteDeferredUnsettled, cellV3TraceToken(execution.Phase, 16), cellV3ChildState(execution), cellV3SettleGrace)
	}
	return true
}

// cellV3ChildState is the bounded child-state token for the diagnostic line.
func cellV3ChildState(execution state.LocalCellV3Execution) string {
	if execution.Report.Child == nil || execution.Report.Child.State == "" {
		return "unknown"
	}
	return cellV3TraceToken(execution.Report.Child.State, 16)
}
