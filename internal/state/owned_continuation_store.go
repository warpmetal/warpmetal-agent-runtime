package state

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

var ErrOwnedContinuationUnknown = errors.New("owned continuation original completion unknown or changed")

// A new snapshot cannot bypass an older dispatched step with no known result.
// This is a read-only prefix query over the existing journal, not a reset/retry.
func (s *Store) HasPendingOwnedContinuation(ctx context.Context, id, prefix string) (bool, error) {
	if !controllerJournalID.MatchString(id) || !controllerJournalID.MatchString(prefix) {
		return false, ErrOwnedContinuationUnknown
	}
	var pending int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM owned_continuation_journal WHERE caller_id=? AND substr(step,1,length(?))=? AND result_json IS NULL)`, id, prefix, prefix).Scan(&pending)
	return pending != 0, err
}

// Read-only discovery of the already retained owning claim. This is not replay
// permission; callers still use OwnedContinuationResult and validate current scope.
func (s *Store) OwnedContinuationClaim(ctx context.Context, id, step string) ([]byte, error) {
	if !controllerJournalID.MatchString(id) || !controllerJournalID.MatchString(step) {
		return nil, ErrOwnedContinuationUnknown
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT claim_json FROM owned_continuation_journal WHERE caller_id=? AND step=?`, id, step).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

func continuationKey(id, step string, claim []byte) bool {
	return controllerJournalID.MatchString(id) && controllerJournalID.MatchString(step) && len(claim) > 0 && len(claim) <= 65536 && json.Valid(claim)
}

// Exclusive pre-effect claim; a repeated claim is never redispatch permission.
func (s *Store) ClaimOwnedContinuation(ctx context.Context, id, step string, claim []byte) error {
	if !continuationKey(id, step, claim) {
		return ErrOwnedContinuationUnknown
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO owned_continuation_journal(caller_id,step,claim_json) VALUES(?,?,?)`, id, step, claim)
	if err != nil {
		return errors.Join(ErrOwnedContinuationUnknown, err)
	}
	return nil
}

// Absent => nil,nil. Claimed but no original completion => explicit UNKNOWN.
func (s *Store) OwnedContinuationResult(ctx context.Context, id, step string, claim []byte) ([]byte, error) {
	if !continuationKey(id, step, claim) {
		return nil, ErrOwnedContinuationUnknown
	}
	var old, result []byte
	err := s.db.QueryRowContext(ctx, `SELECT claim_json,result_json FROM owned_continuation_journal WHERE caller_id=? AND step=?`, id, step).Scan(&old, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(old, claim) || len(result) == 0 {
		return nil, ErrOwnedContinuationUnknown
	}
	return result, nil
}

func (s *Store) CompleteOwnedContinuation(ctx context.Context, id, step string, claim, result []byte) error {
	if !continuationKey(id, step, claim) || len(result) == 0 || len(result) > 65536 || !json.Valid(result) {
		return ErrOwnedContinuationUnknown
	}
	_, err := s.db.ExecContext(ctx, `UPDATE owned_continuation_journal SET result_json=? WHERE caller_id=? AND step=? AND claim_json=? AND result_json IS NULL`, result, id, step, claim)
	if err != nil {
		return err
	}
	old, err := s.OwnedContinuationResult(ctx, id, step, claim)
	if err != nil || !bytes.Equal(old, result) {
		return ErrOwnedContinuationUnknown
	}
	return nil
}
