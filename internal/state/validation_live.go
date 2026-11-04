package state

import (
	"context"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Verified original consumer associations in SAME SQLite/WAL/FULL, not manager
// allowance state. Strict inserts fence replay/ordinal reuse across restarts and
// concurrent delivery; failure rolls back all three associations.
func (s *Store) RetainValidationLiveFacts(ctx context.Context, attemptKey, inputKey, ordinalKey string, first, receipt []byte) error {
	if !model.PhysicalIDValid(attemptKey) || !model.PhysicalIDValid(inputKey) || !model.PhysicalIDValid(ordinalKey) || attemptKey == inputKey || attemptKey == ordinalKey || inputKey == ordinalKey || len(first) == 0 || len(first) > 65536 || len(receipt) == 0 || len(receipt) > 65536 {
		return ErrPhysicalConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, fact := range []struct {
		key string
		raw []byte
	}{{inputKey, first}, {ordinalKey, receipt}, {attemptKey, receipt}} {
		if _, err = tx.ExecContext(ctx, `INSERT INTO physical_gate_facts VALUES(?,?)`, fact.key, fact.raw); err != nil {
			return err
		}
	}
	return tx.Commit()
}
