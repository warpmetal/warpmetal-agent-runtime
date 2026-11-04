package state

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

type ControllerActivityStage string

const (
	ControllerApprovedContext        ControllerActivityStage = "approved-context"
	ControllerInstalledApplicability ControllerActivityStage = "installed-applicability"
	ControllerPolicyVerified         ControllerActivityStage = "verified-policy"
	ControllerNativePrepared         ControllerActivityStage = "native-prepared"
	ControllerHeaderObserved         ControllerActivityStage = "header-observed"
	ControllerGrantOriginal          ControllerActivityStage = "grant-original"
	ControllerActivated              ControllerActivityStage = "activated"
	ControllerOutputOperation        ControllerActivityStage = "output-operation"
	ControllerOutputEnvelope         ControllerActivityStage = "output-envelope"
	ControllerActionReceipt          ControllerActivityStage = "action-receipt"
)

var ErrControllerActivityConflict = errors.New("controller activity immutable correlation conflict")
var controllerJournalID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

const controllerActivitySchema = `CREATE TABLE IF NOT EXISTS controller_activity_journal (
 preparation_id TEXT NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('approved-context','installed-applicability','verified-policy','native-prepared','header-observed','grant-original','activated','prompt-dispatch','output-operation','output-envelope','action-receipt')),
 data_json BLOB NOT NULL,
 PRIMARY KEY(preparation_id,stage)
);`

// SQLite CHECK constraints cannot be ALTERed. Copy exact BLOB originals and every
// prompt-dispatch fence in one transaction on the SAME WAL/FULL store. No new
// authority/ledger/table survives this scoped upgrade; failures roll it back.
func (s *Store) ensureControllerActivitySchema(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var ddl string
	if err = tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name='controller_activity_journal'`).Scan(&ddl); err != nil {
		return err
	}
	if strings.Contains(ddl, "'installed-applicability'") && strings.Contains(ddl, "'header-observed'") && strings.Contains(ddl, "'grant-original'") && strings.Contains(ddl, "'verified-policy'") {
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `ALTER TABLE controller_activity_journal RENAME TO controller_activity_journal_stage_upgrade`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, controllerActivitySchema); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO controller_activity_journal(preparation_id,stage,data_json) SELECT preparation_id,stage,data_json FROM controller_activity_journal_stage_upgrade`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DROP TABLE controller_activity_journal_stage_upgrade`); err != nil {
		return err
	}
	return tx.Commit()
}

// Correlation is not authority. Callers validate current signed/native/context
// facts independently before each effect; this journal never refunds or allocates.
func (s *Store) PinControllerActivityStage(ctx context.Context, id string, stage ControllerActivityStage, raw []byte) error {
	if !controllerJournalID.MatchString(id) || len(raw) == 0 || len(raw) > 2*1024*1024 || !json.Valid(raw) {
		return ErrControllerActivityConflict
	}
	switch stage {
	case ControllerInstalledApplicability, ControllerPolicyVerified, ControllerApprovedContext, ControllerNativePrepared, ControllerHeaderObserved, ControllerGrantOriginal, ControllerActivated, ControllerOutputOperation, ControllerOutputEnvelope, ControllerActionReceipt:
	default:
		return ErrControllerActivityConflict
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(ctx, `INSERT INTO controller_activity_journal(preparation_id,stage,data_json) VALUES(?,?,?) ON CONFLICT(preparation_id,stage) DO NOTHING`, id, string(stage), raw)
	if e != nil {
		return e
	}
	var old []byte
	e = tx.QueryRowContext(ctx, `SELECT data_json FROM controller_activity_journal WHERE preparation_id=? AND stage=?`, id, string(stage)).Scan(&old)
	if e != nil {
		return e
	}
	if !bytes.Equal(raw, old) {
		return ErrControllerActivityConflict
	}
	return tx.Commit()
}
func (s *Store) ControllerActivityStage(ctx context.Context, id string, stage ControllerActivityStage) ([]byte, error) {
	var raw []byte
	e := s.db.QueryRowContext(ctx, `SELECT data_json FROM controller_activity_journal WHERE preparation_id=? AND stage=?`, id, string(stage)).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return raw, e
}
func (s *Store) FenceControllerActivityPrompt(ctx context.Context, id string) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var count int
	e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM controller_activity_journal WHERE preparation_id=? AND stage IN ('approved-context','native-prepared','activated')`, id).Scan(&count)
	if e != nil {
		return e
	}
	if count != 3 {
		return ErrControllerActivityConflict
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO controller_activity_journal(preparation_id,stage,data_json) VALUES(?,'prompt-dispatch','{"dispatched":true}')`, id)
	if e != nil {
		return ErrControllerActivityConflict
	}
	return tx.Commit()
}
