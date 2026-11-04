package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// FIRST independently observed process identity; retained across daemon restart.
func (s *Store) RetainPhysicalProcess(ctx context.Context, digest string, raw []byte) error {
	if !model.PhysicalDigestValid(digest) || len(raw) == 0 || len(raw) > 65536 {
		return ErrPhysicalConflict
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO physical_gate_processes(identity_digest,registration_json) VALUES(?,?) ON CONFLICT(identity_digest) DO NOTHING`, digest, raw)
	if err != nil {
		return err
	}
	var original []byte
	if s.db.QueryRowContext(ctx, `SELECT registration_json FROM physical_gate_processes WHERE identity_digest=?`, digest).Scan(&original) != nil || !bytes.Equal(original, raw) {
		return ErrPhysicalConflict
	}
	return nil
}
func (s *Store) PhysicalProcesses(ctx context.Context) ([][]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT registration_json FROM physical_gate_processes ORDER BY identity_digest`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

// Individual private facts are immutable. Missing facts do not create authority.
func (s *Store) PhysicalFact(ctx context.Context, key string) ([]byte, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}
func (s *Store) RetainPhysicalFact(ctx context.Context, key string, raw []byte) error {
	if !model.PhysicalIDValid(key) || len(raw) == 0 || len(raw) > 65536 {
		return ErrPhysicalConflict
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO physical_gate_facts VALUES(?,?) ON CONFLICT(fact_id) DO NOTHING`, key, raw)
	if err != nil {
		return err
	}
	old, err := s.PhysicalFact(ctx, key)
	if err != nil || !bytes.Equal(old, raw) {
		return ErrPhysicalConflict
	}
	return nil
}
