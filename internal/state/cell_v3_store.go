package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// ErrCellV3OperationConflict reports a formatVersion 3 cell preparation whose
// immutable identity or revision fence changed under the same preparation id.
// A revision/fence change fails closed; it is never a silent upsert.
var ErrCellV3OperationConflict = errors.New("cell v3 preparation immutable identity conflict")

// ErrCellV3JournalBusy reports that the LOCAL journal write for a formatVersion 3
// cell operation could not be completed inside its bound (R-WP125-2).
//
// The store shares ONE SQLite connection (SetMaxOpenConns(1)); a single wedged
// reader/writer therefore used to block every later call forever. The journal
// write is on the critical path of the execute pass, so an unbounded wait there
// stopped the reconcile loop (no further pass, no report, grant TTL drained) even
// though the backend had already committed the execute intent.
//
// The error is RETRYABLE and CLOSED: nothing was written, nothing advanced, and
// the caller must defer the pass (and re-drive the same committed entry on the
// next pass). It is never a permission to skip or synthesize the journal.
var ErrCellV3JournalBusy = errors.New("cell v3 local journal write is busy")

// cellV3JournalWriteBound bounds ONE local journal write. It is a variable so a
// test can shorten it; production keeps a small fixed bound (observed healthy
// writes take single-digit milliseconds).
var cellV3JournalWriteBound = 5 * time.Second

// cellV3JournalBusy reports whether err is a local store contention/deadline
// condition that must be retried rather than treated as a durable decision.
func cellV3JournalBusy(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrCellV3JournalBusy) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database table is locked") ||
		strings.Contains(message, "sqlite_busy") ||
		strings.Contains(message, "database is busy")
}

func (s *Store) HasCellQualificationPin(ctx context.Context, preparationID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cell_qualification_pins WHERE preparation_id=?`, preparationID).Scan(&count)
	return count != 0, err
}

// PinCellQualification atomically establishes or compares the immutable LOCAL
// association. No credentials or backend/grant authority are added to this table.
func (s *Store) PinCellQualification(ctx context.Context, preparationID, tupleDigest, policyDigest string) error {
	if len(tupleDigest) != 71 || len(policyDigest) != 71 {
		return ErrCellV3OperationConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var entryJSON []byte
	if err = tx.QueryRowContext(ctx, `SELECT entry_json FROM cell_v3_operations WHERE preparation_id=?`, preparationID).Scan(&entryJSON); err != nil {
		return errors.Join(ErrCellV3OperationConflict, err)
	}
	var entry model.CellServiceV3
	if json.Unmarshal(entryJSON, &entry) != nil {
		return ErrCellV3OperationConflict
	}
	tuple, err := entry.PreparedTuple()
	if err != nil {
		return err
	}
	actual, err := tuple.Digest()
	if err != nil || actual != tupleDigest {
		return ErrCellV3OperationConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO cell_qualification_pins(preparation_id,prepared_tuple_digest,policy_digest) VALUES(?,?,?) ON CONFLICT(preparation_id) DO NOTHING`, preparationID, tupleDigest, policyDigest); err != nil {
		return err
	}
	var previousTuple, previousPolicy string
	if err = tx.QueryRowContext(ctx, `SELECT prepared_tuple_digest,policy_digest FROM cell_qualification_pins WHERE preparation_id=?`, preparationID).Scan(&previousTuple, &previousPolicy); err != nil {
		return err
	}
	if previousTuple != tupleDigest || previousPolicy != policyDigest {
		return ErrCellV3OperationConflict
	}
	return tx.Commit()
}

// LocalCellV3Operation is the durable record of one formatVersion 3 cell
// preparation. The authoritative intent is persisted before any effect; the
// safe prepared receipt and its exact bytes are persisted BEFORE the backend
// report so a lost acknowledgement replays the same bytes. It never stores the
// plaintext provider key.
type LocalCellV3Operation struct {
	Entry                 model.CellServiceV3
	Phase                 string
	Attempt               int64
	PreparedReceiptDigest string
	Receipt               model.PreparedReceipt
	ReceiptJSON           []byte
	ErrorCode             string
	ParentSessionID       string
	WorktreeDir           string
	ControlReport         model.CellServiceReportV1
}

// PutCellV3Operation journals the authoritative prepare/execute intent for one
// preparation id. Identity is immutable; prepare -> execute and monotonic
// desired-state control revisions are explicit transitions. A changed native
// session, workspace/profile/connection tuple or grant fails closed.
//
// R-WP125-2: the local write is BOUNDED. The store has a single pooled SQLite
// connection, so a wedged statement would otherwise hold the reconcile pass
// forever (the execute branch is serial). A bound expiry returns the closed,
// retryable ErrCellV3JournalBusy; the durable intent is unchanged, nothing is
// advanced and the caller may retry exactly the same write.
func (s *Store) PutCellV3Operation(ctx context.Context, value LocalCellV3Operation) error {
	if ctx == nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, cellV3JournalWriteBound)
	defer cancel()
	// At most one bounded journal write may be outstanding. A wedged driver call
	// cannot be cancelled, so a second caller must not queue behind it; it fails
	// closed as retryable and the next pass tries again.
	if !s.journalInFlight.CompareAndSwap(false, true) {
		return fmt.Errorf("%w: a previous journal write is still outstanding", ErrCellV3JournalBusy)
	}
	// Run the write on its own goroutine and bound the WAIT: the database/sql
	// pool acquisition and the driver call can both outlive a context, so a
	// select is the only way the PASS itself cannot hang.
	done := make(chan error, 1)
	go func() {
		defer s.journalInFlight.Store(false)
		done <- s.putCellV3Operation(bounded, value)
	}()
	select {
	case err := <-done:
		if cellV3JournalBusy(err) {
			return fmt.Errorf("%w: %v", ErrCellV3JournalBusy, err)
		}
		return err
	case <-bounded.Done():
		return fmt.Errorf("%w: %v", ErrCellV3JournalBusy, bounded.Err())
	}
}

func (s *Store) putCellV3Operation(ctx context.Context, value LocalCellV3Operation) error {
	if value.Entry.PreparationID == "" || value.Entry.OperationID == "" ||
		value.Entry.NativeSessionID == "" || value.Phase != "pending" {
		return ErrCellV3OperationConflict
	}
	existing, err := s.CellV3Operation(ctx, value.Entry.PreparationID)
	if err != nil {
		return err
	}
	entry, err := json.Marshal(value.Entry)
	if err != nil {
		return err
	}
	if existing != nil {
		// R-WP119-1: the backend may re-issue a bounded renewal for an expired,
		// never-consumed grant. That is NOT an immutable identity change, but it
		// is adoptable only while no native effect was ever attempted.
		allowRenewal := false
		if existing.Entry.ExecutionGrant != nil && !reflect.DeepEqual(existing.Entry.ExecutionGrant, value.Entry.ExecutionGrant) {
			execution, executionErr := s.CellV3Execution(ctx, value.Entry.PreparationID)
			if executionErr != nil {
				return executionErr
			}
			allowRenewal = execution == nil || execution.Phase == "pending"
		}
		// R-WP150-2: a still-pending preparation with NO native effect may have
		// its Runtime session mode repaired by the backend (the WP-150 reviewer
		// first preparation was journaled lookup_only, then the product selected
		// create_initial). That is the ONE mutable identity field admitted here,
		// and only through a bounded durable refresh budget (the pending row's
		// attempt column). Every other identity change still fails closed.
		modeRefresh := existing.Entry.SessionMode != value.Entry.SessionMode &&
			existing.Entry.SamePreparationIdentityExceptSessionMode(value.Entry)
		if modeRefresh && !cellV3SessionModeRefreshAllowed(*existing, value.Entry) {
			return ErrCellV3OperationConflict
		}
		if err := validateCellV3Transition(*existing, value.Entry, allowRenewal, modeRefresh); err != nil {
			return err
		}
		if modeRefresh {
			// The refresh consumes one durable slot, clears the previous block
			// code (the journal write now succeeded) and leaves the phase
			// pending, so the SAME pass continues into the native-server branch.
			result, err := s.db.ExecContext(ctx,
				`UPDATE cell_v3_operations
				 SET entry_json=?, attempt=attempt+1, error_code='', updated_at=?
				 WHERE preparation_id=? AND phase='pending' AND attempt < ?
				   AND prepared_receipt_digest=''`,
				entry, time.Now().UTC().Format(time.RFC3339Nano), value.Entry.PreparationID,
				cellV3SessionModeRefreshMax)
			if err != nil {
				return err
			}
			changed, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if changed != 1 {
				return ErrCellV3OperationConflict
			}
			return nil
		}
		_, err := s.db.ExecContext(ctx, `UPDATE cell_v3_operations SET entry_json=?, updated_at=? WHERE preparation_id=?`, entry, time.Now().UTC().Format(time.RFC3339Nano), value.Entry.PreparationID)
		return err
	}
	if value.Entry.LifecyclePhase == "execute" {
		return ErrCellV3OperationConflict
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO cell_v3_operations(preparation_id, operation_id, native_session_id, connection_id,
			connection_revision, credential_id, native_credential_id, entry_json, phase, attempt,
			prepared_receipt_digest, receipt_json, error_code, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		value.Entry.PreparationID, value.Entry.OperationID, value.Entry.NativeSessionID,
		value.Entry.CredentialBinding.ConnectionID, value.Entry.CredentialBinding.ConnectionRevision,
		"", "", entry, value.Phase, value.Attempt, "", nil, value.ErrorCode,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		// A UNIQUE(native_session_id) or binding-identity collision is an
		// immutable conflict, never a silent replacement.
		return errors.Join(ErrCellV3OperationConflict, err)
	}
	return nil
}

// cellV3SessionModeRefreshMax bounds the durable session-mode repair budget for
// one still-pending preparation. Three mode-only refreshes are enough to repair
// a first-preparation policy change (lookup_only -> create_initial) and its
// rollback, while a backend that flip-flops the mode forever is refused.
const cellV3SessionModeRefreshMax = 3

// cellV3SessionModeRefreshAllowed admits a session-mode-only identity refresh
// ONLY while the preparation is still pending, no native effect was ever
// pinned, no prepared receipt exists, the mode moves inside the closed Runtime
// vocabulary, and the durable refresh budget is not exhausted. Anything else
// keeps the original fail-closed journal conflict.
func cellV3SessionModeRefreshAllowed(existing LocalCellV3Operation, entry model.CellServiceV3) bool {
	if existing.Phase != "pending" || existing.Attempt >= cellV3SessionModeRefreshMax {
		return false
	}
	if existing.ParentSessionID != "" || existing.PreparedReceiptDigest != "" || len(existing.ReceiptJSON) != 0 {
		return false
	}
	if existing.Entry.LifecyclePhase != "prepare" || entry.LifecyclePhase != "prepare" {
		return false
	}
	if existing.Entry.SessionMode == entry.SessionMode {
		return false
	}
	if !model.ValidCellV3SessionMode(existing.Entry.SessionMode) || !model.ValidCellV3SessionMode(entry.SessionMode) {
		return false
	}
	return true
}

func validateCellV3Transition(existing LocalCellV3Operation, entry model.CellServiceV3, allowGrantRenewal, allowSessionModeRefresh bool) error {
	identityExact := existing.Entry.SamePreparationIdentity(entry)
	if !identityExact && !(allowSessionModeRefresh && existing.Entry.SamePreparationIdentityExceptSessionMode(entry)) {
		return ErrCellV3OperationConflict
	}
	if entry.DesiredRevision < existing.Entry.DesiredRevision {
		return ErrCellV3OperationConflict
	}
	if entry.ActionRevision != existing.Entry.ActionRevision &&
		(entry.ActionRevision <= existing.Entry.ActionRevision || entry.DesiredRevision <= existing.Entry.DesiredRevision || entry.DesiredState == existing.Entry.DesiredState) {
		return ErrCellV3OperationConflict
	}
	if existing.Entry.LifecyclePhase == "execute" && entry.LifecyclePhase != "execute" {
		return ErrCellV3OperationConflict
	}
	if existing.Entry.ExecutionGrant != nil && !reflect.DeepEqual(existing.Entry.ExecutionGrant, entry.ExecutionGrant) {
		// Only a bounded backend renewal of a never-consumed grant may replace
		// the journaled authority; every other grant change fails closed.
		if !allowGrantRenewal || entry.ExecutionGrant == nil || !entry.ExecutionGrant.Renews(*existing.Entry.ExecutionGrant) {
			return ErrCellV3OperationConflict
		}
	}
	if entry.LifecyclePhase == "execute" {
		if existing.Phase != "reported" || entry.ValidateExecutionAuthority(existing.Receipt) != nil {
			return ErrCellV3OperationConflict
		}
	} else if entry.ExecutionGrant != nil || entry.PreparedReceiptDigest != nil {
		return ErrCellV3OperationConflict
	}
	return nil
}

// cellV3BlockCodePattern bounds the diagnostic code persisted for a preparation
// whose managed child was NOT created. The code names the exact rejecting or
// skipping predicate as <stage>[:<closed-reason>]; it is never free text, never
// a prompt and never secret material, so it can be reported safely.
var cellV3BlockCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}(:[a-z0-9_.-]{1,31})?$`)

// SetCellV3PrepareBlocked records the bounded reason the managed child was not
// created for a still-pending preparation. It never moves the phase, never
// touches a prepared receipt and refuses any code outside the closed shape, so
// a blocked preparation keeps its exact fail-closed identity. It reports
// whether the durable value changed, so the caller logs once per transition
// instead of once per pass.
func (s *Store) SetCellV3PrepareBlocked(ctx context.Context, preparationID, code string) (bool, error) {
	if preparationID == "" || !cellV3BlockCodePattern.MatchString(code) {
		return false, ErrCellV3OperationConflict
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE cell_v3_operations SET error_code=?, updated_at=?
		 WHERE preparation_id=? AND phase='pending' AND error_code<>?`,
		code, time.Now().UTC().Format(time.RFC3339Nano), preparationID, code)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

// SetCellV3ExecuteBlocked records the bounded reason a V3 preparation that
// already reported its prepared receipt did NOT reach an admitted native
// execution this pass. The execute branch is the only branch that can defer with
// a nil error (a desired-state/quiescence decision, an already terminal local
// execution, or qualification evidence), so without this code such a pass is
// invisible in the durable rows: the preparation stays `phase=reported` and the
// node report carries no error.
//
// It never moves the phase, never touches the prepared receipt and refuses any
// code outside the closed shape. It reports whether the durable value changed so
// the caller logs once per transition instead of once per pass.
func (s *Store) SetCellV3ExecuteBlocked(ctx context.Context, preparationID, code string) (bool, error) {
	if preparationID == "" || !cellV3BlockCodePattern.MatchString(code) {
		return false, ErrCellV3OperationConflict
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE cell_v3_operations SET error_code=?, updated_at=?
		 WHERE preparation_id=? AND phase IN ('prepared','reported') AND error_code<>?`,
		code, time.Now().UTC().Format(time.RFC3339Nano), preparationID, code)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

// ClearCellV3Blocked removes a stale bounded block code after the branch that
// recorded it reached its effect. It touches only the diagnostic column.
func (s *Store) ClearCellV3Blocked(ctx context.Context, preparationID string) (bool, error) {
	if preparationID == "" {
		return false, ErrCellV3OperationConflict
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE cell_v3_operations SET error_code='', updated_at=?
		 WHERE preparation_id=? AND error_code<>''`,
		time.Now().UTC().Format(time.RFC3339Nano), preparationID)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

// CellV3Operation returns the durable preparation row, or nil when absent.
func (s *Store) CellV3Operation(ctx context.Context, preparationID string) (*LocalCellV3Operation, error) {
	var entryJSON, receiptJSON, controlReportJSON []byte
	var credentialID, nativeCredentialID, digest, errorCode, phase string
	var connectionID string
	var valueParent, valueWorktree string
	var connectionRevision, attempt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT o.entry_json, o.phase, o.attempt, o.connection_id, o.connection_revision, o.credential_id,
			o.native_credential_id, o.prepared_receipt_digest, o.receipt_json, o.error_code,
			COALESCE(c.parent_session_id,''), COALESCE(c.worktree_dir,''), c.report_json
		 FROM cell_v3_operations o LEFT JOIN cell_v3_native_context c ON c.preparation_id=o.preparation_id WHERE o.preparation_id=?`,
		preparationID).Scan(&entryJSON, &phase, &attempt, &connectionID, &connectionRevision,
		&credentialID, &nativeCredentialID, &digest, &receiptJSON, &errorCode, &valueParent, &valueWorktree, &controlReportJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	value := LocalCellV3Operation{Phase: phase, Attempt: attempt, PreparedReceiptDigest: digest, ErrorCode: errorCode, ParentSessionID: valueParent, WorktreeDir: valueWorktree}
	if len(controlReportJSON) != 0 {
		if err := json.Unmarshal(controlReportJSON, &value.ControlReport); err != nil {
			return nil, err
		}
	}
	if err := json.Unmarshal(entryJSON, &value.Entry); err != nil {
		return nil, err
	}
	if len(receiptJSON) != 0 {
		if err := json.Unmarshal(receiptJSON, &value.Receipt); err != nil {
			return nil, err
		}
		value.ReceiptJSON = receiptJSON
	}
	return &value, nil
}

// PutCellV3NativeContext pins the actual native parent/location before the
// prepare effect. Cancellation never recreates a missing parent or workspace.
func (s *Store) PutCellV3NativeContext(ctx context.Context, entry model.CellServiceV3, parent, worktree string) error {
	current, err := s.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if current == nil || !reflect.DeepEqual(current.Entry, entry) || parent == "" || worktree == "" {
		return ErrCellV3OperationConflict
	}
	if current.ParentSessionID != "" && (current.ParentSessionID != parent || current.WorktreeDir != worktree) {
		return ErrCellV3OperationConflict
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO cell_v3_native_context(preparation_id,parent_session_id,worktree_dir) VALUES(?,?,?) ON CONFLICT(preparation_id) DO NOTHING`, entry.PreparationID, parent, worktree)
	return err
}

func (s *Store) PutCellV3ControlReport(ctx context.Context, entry model.CellServiceV3, report model.CellServiceReportV1, effect []byte) error {
	current, err := s.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if current == nil || !reflect.DeepEqual(current.Entry, entry) || current.ParentSessionID == "" || report.FormatVersion != 3 || report.DesiredState != entry.DesiredState || report.ObservedDesiredRevision != entry.DesiredRevision {
		return ErrCellV3OperationConflict
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE cell_v3_native_context SET report_json=?,effect_json=? WHERE preparation_id=?`, encoded, effect, entry.PreparationID)
	return err
}

// CellV3Operations returns every durable preparation ordered by preparation id.
func (s *Store) CellV3Operations(ctx context.Context) ([]LocalCellV3Operation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT preparation_id FROM cell_v3_operations ORDER BY preparation_id`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	values := make([]LocalCellV3Operation, 0, len(ids))
	for _, id := range ids {
		value, err := s.CellV3Operation(ctx, id)
		if err != nil {
			return nil, err
		}
		values = append(values, *value)
	}
	return values, nil
}

// UpdateCellV3Operation persists the outcome of one prepare attempt. The
// immutable entry identity (operation, attempt, fence, desired revision and
// binding) must be unchanged; a drift fails closed rather than silently
// replacing the persisted intent. The exact receipt bytes are retained for a
// lost-ack replay.
func (s *Store) UpdateCellV3Operation(ctx context.Context, value LocalCellV3Operation) error {
	existing, err := s.CellV3Operation(ctx, value.Entry.PreparationID)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrCellV3OperationConflict
	}
	if !reflect.DeepEqual(existing.Entry, value.Entry) {
		return ErrCellV3OperationConflict
	}
	if existing.PreparedReceiptDigest != "" && (!reflect.DeepEqual(existing.Receipt, value.Receipt) || (value.PreparedReceiptDigest != "" && value.PreparedReceiptDigest != existing.PreparedReceiptDigest)) {
		return ErrCellV3OperationConflict
	}
	var receiptJSON []byte
	switch {
	case len(value.ReceiptJSON) != 0:
		var receipt model.PreparedReceipt
		if json.Unmarshal(value.ReceiptJSON, &receipt) != nil || !reflect.DeepEqual(receipt, value.Receipt) {
			return ErrCellV3OperationConflict
		}
		receiptJSON = value.ReceiptJSON
	case value.Receipt.PreparedReceiptDigest != "":
		receiptJSON, err = json.Marshal(value.Receipt)
		if err != nil {
			return err
		}
	}
	digest := value.PreparedReceiptDigest
	if digest == "" {
		digest = value.Receipt.PreparedReceiptDigest
	}
	if digest != value.Receipt.PreparedReceiptDigest {
		return ErrCellV3OperationConflict
	}
	if existing.PreparedReceiptDigest != "" {
		receiptJSON = existing.ReceiptJSON
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE cell_v3_operations SET phase=?, attempt=?, credential_id=?, native_credential_id=?,
			prepared_receipt_digest=?, receipt_json=?, error_code=?, updated_at=?
		 WHERE preparation_id=?`,
		value.Phase, value.Attempt, value.Receipt.CredentialID, value.Receipt.NativeCredentialID,
		digest, nullableBytes(receiptJSON), value.ErrorCode,
		time.Now().UTC().Format(time.RFC3339Nano), value.Entry.PreparationID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrCellV3OperationConflict
	}
	return nil
}
