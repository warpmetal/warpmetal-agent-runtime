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

// LocalCellV3Execution is separate from prompt-free preparation. Only the
// backend's accepted grant can create this row. Unknown effects retain ownership.
type LocalCellV3Execution struct {
	PreparationID   string
	Grant           model.CellExecutionGrantV3
	Phase           string
	ParentSessionID string
	WorktreeDir     string
	EffectJSON      []byte
	Report          model.CellServiceReportV1
}

func (s *Store) CellV3Execution(ctx context.Context, id string) (*LocalCellV3Execution, error) {
	value := LocalCellV3Execution{PreparationID: id}
	var grantJSON, reportJSON []byte
	err := s.db.QueryRowContext(ctx, `SELECT grant_json,phase,parent_session_id,worktree_dir,effect_json,report_json FROM cell_v3_executions WHERE preparation_id=?`, id).Scan(&grantJSON, &value.Phase, &value.ParentSessionID, &value.WorktreeDir, &value.EffectJSON, &reportJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(grantJSON, &value.Grant); err != nil {
		return nil, err
	}
	if len(reportJSON) != 0 {
		if err := json.Unmarshal(reportJSON, &value.Report); err != nil {
			return nil, err
		}
	}
	return &value, nil
}

func (s *Store) PutCellV3Execution(ctx context.Context, entry model.CellServiceV3, value LocalCellV3Execution) error {
	preparation, err := s.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if preparation == nil || !reflect.DeepEqual(preparation.Entry, entry) || preparation.Phase != "reported" || entry.ValidateExecutionAuthority(preparation.Receipt) != nil || !reflect.DeepEqual(entry.ExecutionGrant, &value.Grant) || value.PreparationID != entry.PreparationID {
		return ErrCellV3OperationConflict
	}
	previous, err := s.CellV3Execution(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if previous != nil {
		if !reflect.DeepEqual(previous.Grant, value.Grant) || previous.ParentSessionID != value.ParentSessionID || previous.WorktreeDir != value.WorktreeDir {
			return ErrCellV3OperationConflict
		}
		if previous.Phase == "exhausted" && value.Phase != "exhausted" {
			return ErrCellV3OperationConflict
		}
	}
	grantJSON, err := json.Marshal(value.Grant)
	if err != nil {
		return err
	}
	var reportJSON []byte
	if value.Report.FormatVersion != 0 {
		reportJSON, err = json.Marshal(value.Report)
		if err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO cell_v3_executions(preparation_id,grant_json,phase,parent_session_id,worktree_dir,effect_json,report_json,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(preparation_id) DO UPDATE SET phase=excluded.phase,effect_json=excluded.effect_json,report_json=excluded.report_json,updated_at=excluded.updated_at`, entry.PreparationID, grantJSON, value.Phase, value.ParentSessionID, value.WorktreeDir, nullableBytes(value.EffectJSON), nullableBytes(reportJSON), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
