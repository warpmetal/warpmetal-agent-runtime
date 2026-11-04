package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// ErrCellOperationConflict reports a cell operation whose immutable identity or
// revision fence changed under the same operation id.
var ErrCellOperationConflict = errors.New("cell operation immutable identity conflict")

// LocalCellOperation is the durable record of one cell-owned operation. It is
// persisted before any adapter effect and preserves the exact entry, the last
// local transport retry, the exact child receipt and the durable exhaustion
// marker across restart. The marker is monotonic: once set it is never
// cleared, so an exhausted or unknown effect can never later be reported as an
// ordinary terminal completion.
type LocalCellOperation struct {
	Entry model.ManagedServiceV2
	Phase string
	// Attempt is the LOCAL transport/retry counter. It is never the
	// authoritative execution attempt: that immutable value lives on
	// Entry.Attempt and is echoed verbatim in every report.
	Attempt     int64
	Child       *model.ManagedCellChildV1
	Exhausted   bool
	ReceiptJSON []byte
	Report      model.CellServiceReportV1
	ErrorCode   string
}

func (s *Store) PutCellOperation(ctx context.Context, value LocalCellOperation) error {
	if value.Entry.OperationID == "" || value.Phase != "pending" {
		return ErrCellOperationConflict
	}
	existing, err := s.CellOperation(ctx, value.Entry.OperationID)
	if err != nil {
		return err
	}
	entry, err := json.Marshal(value.Entry)
	if err != nil {
		return err
	}
	if existing != nil {
		// The operation id is the durable identity. A replay of the same
		// authority keeps every execution fact already recorded (attempt, child,
		// exhausted marker, report). Only a strictly newer desired revision may
		// replace the entry, and even then the exhaustion marker survives.
		if reflect.DeepEqual(existing.Entry, value.Entry) {
			return nil
		}
		if existing.Entry.ServiceRegistrationID != value.Entry.ServiceRegistrationID ||
			existing.Entry.OperationID != value.Entry.OperationID {
			return ErrCellOperationConflict
		}
		if value.Entry.DesiredRevision <= existing.Entry.DesiredRevision {
			return ErrCellOperationConflict
		}
		_, err = s.db.ExecContext(ctx, `UPDATE cell_operations SET entry_json=?, updated_at=? WHERE operation_id=?`,
			entry, time.Now().UTC().Format(time.RFC3339Nano), value.Entry.OperationID)
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO cell_operations(operation_id, entry_json, phase, attempt, child_json, exhausted, report_json, error_code, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		value.Entry.OperationID, entry, value.Phase, value.Attempt, nil, boolInt(value.Exhausted), nil, value.ErrorCode,
		time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) CellOperation(ctx context.Context, operationID string) (*LocalCellOperation, error) {
	var entryJSON, childJSON, reportJSON []byte
	var value LocalCellOperation
	var exhausted int
	err := s.db.QueryRowContext(ctx,
		`SELECT entry_json, phase, attempt, child_json, exhausted, report_json, error_code FROM cell_operations WHERE operation_id=?`,
		operationID).Scan(&entryJSON, &value.Phase, &value.Attempt, &childJSON, &exhausted, &reportJSON, &value.ErrorCode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(entryJSON, &value.Entry); err != nil {
		return nil, err
	}
	if len(childJSON) != 0 {
		value.Child = &model.ManagedCellChildV1{}
		if err := json.Unmarshal(childJSON, value.Child); err != nil {
			return nil, err
		}
	}
	if len(reportJSON) != 0 {
		if err := json.Unmarshal(reportJSON, &value.Report); err != nil {
			return nil, err
		}
	}
	value.Exhausted = exhausted == 1
	return &value, nil
}

func (s *Store) CellOperations(ctx context.Context) ([]LocalCellOperation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT operation_id FROM cell_operations ORDER BY operation_id`)
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
	values := make([]LocalCellOperation, 0, len(ids))
	for _, id := range ids {
		value, err := s.CellOperation(ctx, id)
		if err != nil {
			return nil, err
		}
		values = append(values, *value)
	}
	return values, nil
}

// UpdateCellOperation persists the exact outcome of one adapter attempt. The
// durable exhaustion marker is monotonic: a caller can set it but never clear
// it, and an already-exhausted row keeps its report regardless of a later,
// weaker observation.
//
// The accepted entry advances with the durable outcome. A control action
// (hold/release/revoke) delivers a new desired/action revision and the cancel
// path updates the operation after the adapter effect; if that entry were not
// persisted, the stored entry would stay at the launch revision and the strict
// current-authority report filter (currentCellServiceTuple) would omit the
// accepted report forever. Only a strictly forward tuple replaces entry_json;
// a backward tuple fails closed so a stale authority can never regress the
// durable entry or overwrite a newer accepted report.
func (s *Store) UpdateCellOperation(ctx context.Context, value LocalCellOperation) error {
	existing, err := s.CellOperation(ctx, value.Entry.OperationID)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrCellOperationConflict
	}
	// The durable exhaustion marker is monotonic: a caller can set it but never
	// clear it. Apply the guard BEFORE serializing so an exhausted row keeps its
	// prior report/child/phase/attempt rather than persisting and emitting a
	// newer (e.g. cancelled) report while exhausted=true. The entry is preserved
	// with the report so a durable observation always describes one exact tuple.
	if existing.Exhausted && !value.Exhausted {
		value.Exhausted = true
		value.Report = existing.Report
		value.Phase = existing.Phase
		value.Child = existing.Child
		value.Attempt = existing.Attempt
		value.Entry = existing.Entry
	}
	advance, err := advanceCellOperationEntry(existing.Entry, value.Entry)
	if err != nil {
		return err
	}
	var entryJSON []byte
	if advance {
		entryJSON, err = json.Marshal(value.Entry)
		if err != nil {
			return err
		}
	}
	var childJSON []byte
	if value.Child != nil {
		childJSON, err = json.Marshal(value.Child)
		if err != nil {
			return err
		}
	}
	reportJSON, err := json.Marshal(value.Report)
	if err != nil {
		return err
	}
	query := `UPDATE cell_operations SET phase=?, attempt=?, child_json=?, exhausted=?, report_json=?, error_code=?, updated_at=? WHERE operation_id=?`
	args := []any{value.Phase, value.Attempt, nullableBytes(childJSON), boolInt(value.Exhausted), reportJSON, value.ErrorCode,
		time.Now().UTC().Format(time.RFC3339Nano), value.Entry.OperationID}
	if advance {
		query = `UPDATE cell_operations SET entry_json=?, phase=?, attempt=?, child_json=?, exhausted=?, report_json=?, error_code=?, updated_at=? WHERE operation_id=?`
		args = append([]any{entryJSON}, args...)
	}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrCellOperationConflict
	}
	return nil
}

// advanceCellOperationEntry decides how one accepted authority entry relates to
// the durable entry. The desired revision is the primary fence and the action
// revision is the secondary fence: only a strictly forward tuple replaces the
// stored entry; an exact replay persists the outcome only; a backward tuple (or
// a changed operation lineage) fails closed instead of silently regressing.
func advanceCellOperationEntry(existing, next model.ManagedServiceV2) (bool, error) {
	if next.ServiceRegistrationID != existing.ServiceRegistrationID {
		return false, ErrCellOperationConflict
	}
	switch {
	case next.DesiredRevision > existing.DesiredRevision:
		return true, nil
	case next.DesiredRevision < existing.DesiredRevision:
		return false, ErrCellOperationConflict
	case next.ActionRevision > existing.ActionRevision:
		return true, nil
	case next.ActionRevision < existing.ActionRevision:
		return false, ErrCellOperationConflict
	default:
		return false, nil
	}
}
