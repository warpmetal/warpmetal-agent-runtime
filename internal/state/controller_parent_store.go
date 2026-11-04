package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

var ErrControllerParentConflict = errors.New("controller parent immutable state conflict")

type LocalControllerParent struct {
	Intent                model.ControllerParentIntent
	CreationDispatched    bool
	Report                model.ControllerParentReport
	AcceptedReceiptDigest string
	// BlockCode is the closed diagnostic reason this pass could not read the
	// parent's approved application (R-WP122-2). It is local-only: the wire
	// report's lastError.code stays inside the backend's closed enum.
	BlockCode string
}

// Separate durable parent records; no delegated cell/Team/Work row or ledger.
func (s *Store) PutControllerParentIntent(ctx context.Context, intent model.ControllerParentIntent) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT intent_json FROM controller_parent_services WHERE service_id=?`, intent.ServiceRegistrationID).Scan(&raw)
	if err == nil {
		var old model.ControllerParentIntent
		if json.Unmarshal(raw, &old) != nil {
			return ErrControllerParentConflict
		}
		if old == intent {
			return tx.Commit()
		}
		identity := old
		identity.OperationID = intent.OperationID
		identity.ActionRevision = intent.ActionRevision
		identity.DesiredRevision = intent.DesiredRevision
		identity.ConfigDigest = intent.ConfigDigest
		identity.DesiredState = intent.DesiredState
		identity.SessionMode = intent.SessionMode
		if identity != intent || intent.ActionRevision <= old.ActionRevision || intent.DesiredRevision <= old.DesiredRevision {
			return ErrControllerParentConflict
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	data, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO controller_parent_services(service_id,intent_json) VALUES(?,?) ON CONFLICT(service_id) DO UPDATE SET intent_json=excluded.intent_json, accepted_receipt_digest=''`, intent.ServiceRegistrationID, data)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ControllerParent(ctx context.Context, id string) (*LocalControllerParent, error) {
	var intent, report []byte
	var creation bool
	var accepted, blockCode string
	err := s.db.QueryRowContext(ctx, `SELECT intent_json,creation_dispatched,report_json,accepted_receipt_digest,block_code FROM controller_parent_services WHERE service_id=?`, id).Scan(&intent, &creation, &report, &accepted, &blockCode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	value := &LocalControllerParent{CreationDispatched: creation, AcceptedReceiptDigest: accepted, BlockCode: blockCode}
	if err = json.Unmarshal(intent, &value.Intent); err != nil {
		return nil, err
	}
	if len(report) > 0 {
		if err = json.Unmarshal(report, &value.Report); err != nil {
			return nil, err
		}
	}
	return value, nil
}
func (s *Store) MarkControllerParentCreationDispatched(ctx context.Context, intent model.ControllerParentIntent) error {
	raw, _ := json.Marshal(intent)
	result, err := s.db.ExecContext(ctx, `UPDATE controller_parent_services SET creation_dispatched=1 WHERE service_id=? AND intent_json=?`, intent.ServiceRegistrationID, raw)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrControllerParentConflict
	}
	return nil
}
func (s *Store) PutControllerParentReport(ctx context.Context, intent model.ControllerParentIntent, report model.ControllerParentReport) error {
	local, err := s.ControllerParent(ctx, intent.ServiceRegistrationID)
	if err != nil {
		return err
	}
	if local == nil || local.Intent != intent {
		return ErrControllerParentConflict
	}
	if report.ObservedState == "ready" {
		if err := report.ValidateReady(intent); err != nil {
			return err
		}
	}
	if local.Report.NativeRegistration != nil && report.NativeRegistration != nil && !reflect.DeepEqual(local.Report.NativeRegistration, report.NativeRegistration) {
		return ErrControllerParentConflict
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var session any
	if report.NativeRegistration != nil {
		session = report.NativeRegistration.NativeSessionID
	}
	// A parent that is no longer failed clears the bounded read block: a stale
	// diagnostic must never outlive the condition it named.
	_, err = s.db.ExecContext(ctx, `UPDATE controller_parent_services SET report_json=?,native_session_id=COALESCE(native_session_id,?),accepted_receipt_digest=CASE WHEN report_json=? THEN accepted_receipt_digest ELSE '' END,block_code=CASE WHEN ?='failed' THEN block_code ELSE '' END WHERE service_id=?`, raw, session, raw, report.ObservedState, intent.ServiceRegistrationID)
	return err
}

// SetControllerParentBlocked records the closed reason this pass could not read
// the parent's approved application (R-WP122-2). It touches only the local
// diagnostic column: the phase, dispatch flag, report and accepted receipt are
// unchanged, so the parent keeps its exact fail-closed identity. It reports
// whether the durable value changed so the caller logs once per transition.
func (s *Store) SetControllerParentBlocked(ctx context.Context, serviceID, code string) (bool, error) {
	if serviceID == "" || !cellV3BlockCodePattern.MatchString(code) {
		return false, ErrControllerParentConflict
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE controller_parent_services SET block_code=? WHERE service_id=? AND block_code<>?`,
		code, serviceID, code)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

type LocalWorkspaceApplication struct {
	Operation     model.WorkspaceApplicationOperation
	EnvelopeJSON  []byte
	Applied       bool
	ApplicationID string
}

func (s *Store) WorkspaceApplication(ctx context.Context, id string) (*LocalWorkspaceApplication, error) {
	var op, envelope []byte
	var applied bool
	var applicationID string
	err := s.db.QueryRowContext(ctx, `SELECT operation_json,envelope_json,applied,application_id FROM workspace_applications WHERE operation_id=?`, id).Scan(&op, &envelope, &applied, &applicationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	local := &LocalWorkspaceApplication{EnvelopeJSON: envelope, Applied: applied, ApplicationID: applicationID}
	if err = json.Unmarshal(op, &local.Operation); err != nil {
		return nil, err
	}
	return local, nil
}
func (s *Store) PutWorkspaceApplication(ctx context.Context, op model.WorkspaceApplicationOperation) error {
	if err := op.Validate(); err != nil {
		return err
	}
	raw, _ := json.Marshal(op)
	_, err := s.db.ExecContext(ctx, `INSERT INTO workspace_applications(operation_id,operation_json) VALUES(?,?) ON CONFLICT(operation_id) DO NOTHING`, op.OperationID, raw)
	if err != nil {
		return err
	}
	old, err := s.WorkspaceApplication(ctx, op.OperationID)
	if err != nil {
		return err
	}
	if old == nil || !reflect.DeepEqual(old.Operation, op) {
		return ErrControllerParentConflict
	}
	return nil
}
func (s *Store) PinWorkspaceApplicationEnvelope(ctx context.Context, id string, raw []byte) error {
	result, err := s.db.ExecContext(ctx, `UPDATE workspace_applications SET envelope_json=? WHERE operation_id=? AND (envelope_json IS NULL OR envelope_json=?)`, raw, id, raw)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrControllerParentConflict
	}
	return nil
}
func (s *Store) AcceptWorkspaceApplication(ctx context.Context, id, applicationID string, raw []byte) error {
	result, err := s.db.ExecContext(ctx, `UPDATE workspace_applications SET applied=1,application_id=? WHERE operation_id=? AND envelope_json=? AND (application_id='' OR application_id=?)`, applicationID, id, raw, applicationID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrControllerParentConflict
	}
	return nil
}

// Called with the EXACT report whose protected Backend ACK succeeded, never a
// speculative latest-report lookup. Changed local evidence cannot borrow the ACK.
func (s *Store) AcknowledgeControllerParents(ctx context.Context, reports []model.ControllerParentReport) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, report := range reports {
		if report.ObservedState != "ready" {
			continue
		}
		raw, _ := json.Marshal(report)
		result, err := tx.ExecContext(ctx, `UPDATE controller_parent_services SET accepted_receipt_digest=? WHERE service_id=? AND report_json=?`, report.ReceiptDigest, report.ServiceRegistrationID, raw)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return ErrControllerParentConflict
		}
	}
	return tx.Commit()
}
