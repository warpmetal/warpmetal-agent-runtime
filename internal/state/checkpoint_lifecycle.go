package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type CheckpointGCIntent struct {
	SandboxID      string
	CheckpointID   string
	CaptureID      string
	ObjectID       string
	ManifestDigest string
	Bytes          int64
	Phase          string
	PlannedAt      time.Time
	NotBefore      time.Time
}

const checkpointGCSelect = `SELECT sandbox_id, checkpoint_id, capture_id, object_id,
manifest_digest, bytes, phase, planned_at, not_before FROM checkpoint_gc_intents`

func (s *Store) ensureCheckpointLifecycleSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(checkpoint_policies)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == "max_per_box" {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !found {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE checkpoint_policies
ADD COLUMN max_per_box INTEGER NOT NULL DEFAULT 20 CHECK(max_per_box > 0)`); err != nil {
			return err
		}
	}
	const fences = `
CREATE TRIGGER IF NOT EXISTS checkpoint_gc_block_pointer_insert
BEFORE INSERT ON work_checkpoint_pointers
WHEN EXISTS(SELECT 1 FROM checkpoint_gc_intents WHERE phase='deleting' AND checkpoint_id=NEW.checkpoint_id)
  OR EXISTS(SELECT 1 FROM checkpoint_gc_tombstones WHERE checkpoint_id=NEW.checkpoint_id)
BEGIN SELECT RAISE(ABORT, 'checkpoint unavailable'); END;
CREATE TRIGGER IF NOT EXISTS checkpoint_gc_block_pointer_update
BEFORE UPDATE OF checkpoint_id ON work_checkpoint_pointers
WHEN EXISTS(SELECT 1 FROM checkpoint_gc_intents WHERE phase='deleting' AND checkpoint_id=NEW.checkpoint_id)
  OR EXISTS(SELECT 1 FROM checkpoint_gc_tombstones WHERE checkpoint_id=NEW.checkpoint_id)
BEGIN SELECT RAISE(ABORT, 'checkpoint unavailable'); END;
CREATE TRIGGER IF NOT EXISTS checkpoint_gc_block_operation_insert
BEFORE INSERT ON continuity_operations
WHEN NEW.checkpoint_id <> '' AND EXISTS(
  SELECT 1 FROM checkpoint_gc_intents WHERE phase='deleting' AND checkpoint_id=NEW.checkpoint_id)
BEGIN SELECT RAISE(ABORT, 'checkpoint unavailable'); END;
CREATE TRIGGER IF NOT EXISTS checkpoint_gc_block_operation_update
BEFORE UPDATE OF checkpoint_id ON continuity_operations
WHEN NEW.checkpoint_id <> '' AND EXISTS(
  SELECT 1 FROM checkpoint_gc_intents WHERE phase='deleting' AND checkpoint_id=NEW.checkpoint_id)
BEGIN SELECT RAISE(ABORT, 'checkpoint unavailable'); END;
`
	if _, err := s.db.ExecContext(ctx, fences); err != nil {
		return err
	}
	for _, table := range []string{
		"continuation_preparations",
		"continuation_releases",
		"continuation_handoff_preparations",
		"continuation_handoff_releases",
		"restore_operations",
	} {
		for _, action := range []string{"INSERT", "UPDATE OF manifest_json"} {
			name := fmt.Sprintf("checkpoint_gc_block_%s_%s", table, action[:6])
			statement := fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS %s
BEFORE %s ON %s
WHEN EXISTS(SELECT 1 FROM checkpoint_gc_intents WHERE phase='deleting'
  AND checkpoint_id=json_extract(NEW.manifest_json, '$.checkpoint.checkpointId'))
BEGIN SELECT RAISE(ABORT, 'checkpoint unavailable'); END;`, name, action, table)
			if _, err := s.db.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
	}
	return nil
}

func scanCheckpointGCIntent(row scanner) (CheckpointGCIntent, error) {
	var value CheckpointGCIntent
	var checkpoint sql.NullString
	var plannedAt, notBefore string
	err := row.Scan(
		&value.SandboxID, &checkpoint, &value.CaptureID, &value.ObjectID,
		&value.ManifestDigest, &value.Bytes, &value.Phase, &plannedAt, &notBefore,
	)
	if err != nil {
		return CheckpointGCIntent{}, err
	}
	value.CheckpointID = checkpoint.String
	value.PlannedAt, err = time.Parse(time.RFC3339Nano, plannedAt)
	if err != nil {
		return CheckpointGCIntent{}, err
	}
	value.NotBefore, err = time.Parse(time.RFC3339Nano, notBefore)
	return value, err
}

func (s *Store) CheckpointGCIntents(ctx context.Context) ([]CheckpointGCIntent, error) {
	rows, err := s.db.QueryContext(ctx, checkpointGCSelect+` ORDER BY planned_at, capture_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []CheckpointGCIntent
	for rows.Next() {
		value, err := scanCheckpointGCIntent(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) PlanCheckpointCollection(ctx context.Context, now time.Time, grace time.Duration, limit int) ([]CheckpointGCIntent, error) {
	if limit <= 0 || grace < 0 {
		return nil, errors.New("invalid checkpoint collection bounds")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	sandboxRows, err := tx.QueryContext(ctx, `SELECT DISTINCT sandbox_id FROM continuity_captures ORDER BY sandbox_id`)
	if err != nil {
		return nil, err
	}
	var sandboxIDs []string
	for sandboxRows.Next() {
		var sandboxID string
		if err := sandboxRows.Scan(&sandboxID); err != nil {
			sandboxRows.Close()
			return nil, err
		}
		sandboxIDs = append(sandboxIDs, sandboxID)
	}
	if err := sandboxRows.Close(); err != nil {
		return nil, err
	}

	planned := 0
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM checkpoint_gc_intents`).Scan(&planned); err != nil {
		return nil, err
	}
	for _, sandboxID := range sandboxIDs {
		if planned >= limit {
			break
		}
		policy, err := checkpointPolicy(ctx, tx, sandboxID)
		if err != nil {
			return nil, err
		}
		checkpoints, err := checkpointsForSandbox(ctx, tx, sandboxID)
		if err != nil {
			return nil, err
		}
		protected := make(map[string]bool, len(checkpoints))
		protectedCount := 0
		var protectedBytes int64
		for _, checkpoint := range checkpoints {
			rooted, err := checkpointIsRooted(ctx, tx, checkpoint)
			if err != nil {
				return nil, err
			}
			if rooted {
				protected[checkpoint.ID] = true
				protectedCount++
				protectedBytes += checkpoint.Bytes
			}
		}
		remainingCount := policy.MaxPerBox - protectedCount
		remainingBytes := policy.MaxBytes - protectedBytes
		cutoff := now.Add(-policy.MaxAge)
		for _, checkpoint := range checkpoints {
			if protected[checkpoint.ID] {
				continue
			}
			keep := remainingCount > 0 && remainingBytes >= checkpoint.Bytes && !checkpoint.CreatedAt.Before(cutoff)
			if keep {
				remainingCount--
				remainingBytes -= checkpoint.Bytes
				continue
			}
			inserted, err := insertCheckpointGCIntent(ctx, tx, checkpoint.Identity.SandboxID,
				checkpoint.ID, checkpoint.CaptureID, checkpoint.CaptureID,
				checkpoint.ManifestDigest, checkpoint.Bytes, now, now.Add(grace))
			if err != nil {
				return nil, err
			}
			if inserted {
				planned++
				if planned >= limit {
					break
				}
			}
		}
		if planned >= limit {
			break
		}
		orphanRows, err := tx.QueryContext(ctx, `SELECT c.id, c.object_id, c.manifest_digest, c.bytes, c.created_at
FROM continuity_captures c
LEFT JOIN checkpoints p ON p.capture_id=c.id
LEFT JOIN checkpoint_gc_intents g ON g.capture_id=c.id
WHERE c.sandbox_id=? AND p.id IS NULL AND g.capture_id IS NULL
ORDER BY c.created_at, c.id`, sandboxID)
		if err != nil {
			return nil, err
		}
		for orphanRows.Next() && planned < limit {
			var captureID, objectID, digest, created string
			var bytes int64
			if err := orphanRows.Scan(&captureID, &objectID, &digest, &bytes, &created); err != nil {
				orphanRows.Close()
				return nil, err
			}
			createdAt, err := time.Parse(time.RFC3339Nano, created)
			if err != nil {
				orphanRows.Close()
				return nil, err
			}
			rooted, err := captureIsRooted(ctx, tx, captureID)
			if err != nil {
				orphanRows.Close()
				return nil, err
			}
			if rooted || createdAt.After(now.Add(-grace)) {
				continue
			}
			inserted, err := insertCheckpointGCIntent(ctx, tx, sandboxID, "", captureID,
				objectID, digest, bytes, now, now.Add(grace))
			if err != nil {
				orphanRows.Close()
				return nil, err
			}
			if inserted {
				planned++
			}
		}
		if err := orphanRows.Close(); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	intents, err := s.CheckpointGCIntents(ctx)
	if err != nil {
		return nil, err
	}
	if len(intents) > limit {
		intents = intents[:limit]
	}
	return intents, nil
}

func checkpointsForSandbox(ctx context.Context, tx *sql.Tx, sandboxID string) ([]LocalCheckpoint, error) {
	rows, err := tx.QueryContext(ctx, checkpointSelect+` WHERE sandbox_id=? ORDER BY created_at DESC, id DESC`, sandboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalCheckpoint
	for rows.Next() {
		value, err := scanCheckpoint(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, *value)
	}
	return values, rows.Err()
}

func insertCheckpointGCIntent(ctx context.Context, tx *sql.Tx, sandboxID, checkpointID,
	captureID, objectID, manifestDigest string, bytes int64, plannedAt, notBefore time.Time,
) (bool, error) {
	result, err := tx.ExecContext(ctx, `INSERT INTO checkpoint_gc_intents(
sandbox_id, checkpoint_id, capture_id, object_id, manifest_digest, bytes, phase, planned_at, not_before)
VALUES(?, NULLIF(?, ''), ?, ?, ?, ?, 'planned', ?, ?) ON CONFLICT(capture_id) DO NOTHING`,
		sandboxID, checkpointID, captureID, objectID, manifestDigest, bytes,
		plannedAt.UTC().Format(time.RFC3339Nano), notBefore.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed == 1, err
}

func checkpointIsRooted(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, checkpoint LocalCheckpoint) (bool, error) {
	if checkpoint.Pinned {
		return true, nil
	}
	var rooted int
	err := query.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM work_checkpoint_pointers WHERE checkpoint_id=?
UNION ALL SELECT 1 FROM continuity_operations
  WHERE checkpoint_id=? AND state NOT IN ('succeeded','failed')
UNION ALL SELECT 1 FROM continuation_preparations p
  WHERE json_extract(p.manifest_json,'$.checkpoint.checkpointId')=? AND p.phase<>'failed'
    AND NOT EXISTS(SELECT 1 FROM continuation_releases r
      WHERE r.operation_id=p.operation_id AND r.phase='released'
        AND json_extract(r.manifest_json,'$.formatVersion')=json_extract(p.manifest_json,'$.formatVersion')
        AND json_extract(r.manifest_json,'$.desiredRevision')>json_extract(p.manifest_json,'$.desiredRevision')
        AND json_extract(r.manifest_json,'$.identity')=json_extract(p.manifest_json,'$.identity')
        AND json_extract(r.manifest_json,'$.binding')=json_extract(p.manifest_json,'$.binding')
        AND json_extract(r.manifest_json,'$.checkpoint')=json_extract(p.manifest_json,'$.checkpoint')
        AND json_extract(r.manifest_json,'$.target')=json_extract(p.manifest_json,'$.target')
        AND json_extract(r.manifest_json,'$.context')=json_extract(p.manifest_json,'$.context'))
UNION ALL SELECT 1 FROM continuation_releases
  WHERE json_extract(manifest_json,'$.checkpoint.checkpointId')=? AND phase='releasing'
UNION ALL SELECT 1 FROM continuation_handoff_preparations p
  WHERE json_extract(p.manifest_json,'$.checkpoint.checkpointId')=? AND p.phase<>'failed'
    AND NOT EXISTS(SELECT 1 FROM continuation_handoff_releases r
      WHERE r.phase='released'
        AND json_extract(r.manifest_json,'$.formatVersion')=json_extract(p.manifest_json,'$.formatVersion')
        AND json_extract(r.manifest_json,'$.prepareDesiredRevision')=json_extract(p.manifest_json,'$.desiredRevision')
        AND json_extract(r.manifest_json,'$.handoffKind')=json_extract(p.manifest_json,'$.handoffKind')
        AND json_extract(r.manifest_json,'$.sessionMode')=json_extract(p.manifest_json,'$.sessionMode')
        AND json_extract(r.manifest_json,'$.targetWorkId')=json_extract(p.manifest_json,'$.targetWorkId')
        AND json_extract(r.manifest_json,'$.mappingId')=json_extract(p.manifest_json,'$.mappingId')
        AND json_extract(r.manifest_json,'$.identity')=json_extract(p.manifest_json,'$.identity')
        AND json_extract(r.manifest_json,'$.binding')=json_extract(p.manifest_json,'$.binding')
        AND json_extract(r.manifest_json,'$.checkpoint')=json_extract(p.manifest_json,'$.checkpoint')
        AND json_extract(r.manifest_json,'$.lineage')=json_extract(p.manifest_json,'$.lineage')
        AND json_extract(r.manifest_json,'$.targetPolicy')=json_extract(p.manifest_json,'$.targetPolicy')
        AND json_extract(r.manifest_json,'$.workspace')=json_extract(p.manifest_json,'$.workspace')
        AND json_extract(r.manifest_json,'$.context')=json_extract(p.manifest_json,'$.context'))
UNION ALL SELECT 1 FROM continuation_handoff_releases
  WHERE json_extract(manifest_json,'$.checkpoint.checkpointId')=? AND phase='releasing'
UNION ALL SELECT 1 FROM restore_operations
  WHERE json_extract(manifest_json,'$.checkpoint.checkpointId')=?
    AND phase IN ('allocating','materializing'))`, checkpoint.ID, checkpoint.ID,
		checkpoint.ID, checkpoint.ID, checkpoint.ID, checkpoint.ID, checkpoint.ID).Scan(&rooted)
	return rooted != 0, err
}

func captureIsRooted(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, captureID string) (bool, error) {
	var rooted int
	err := query.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM continuity_operations
WHERE capture_id=? AND state NOT IN ('succeeded','failed'))`, captureID).Scan(&rooted)
	return rooted != 0, err
}

func (s *Store) ConfirmCheckpointCollection(ctx context.Context, expected CheckpointGCIntent) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	current, err := scanCheckpointGCIntent(tx.QueryRowContext(ctx, checkpointGCSelect+` WHERE capture_id=?`, expected.CaptureID))
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !sameCheckpointGCIntent(current, expected) {
		return false, errors.New("checkpoint collection intent changed")
	}
	if current.Phase == "deleting" {
		return true, tx.Commit()
	}
	rooted := false
	if current.CheckpointID != "" {
		checkpoint, err := scanCheckpoint(tx.QueryRowContext(ctx, checkpointSelect+` WHERE id=?`, current.CheckpointID))
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrCheckpointUnavailable
		}
		if err != nil {
			return false, err
		}
		if checkpoint.CaptureID != current.CaptureID || checkpoint.ManifestDigest != current.ManifestDigest {
			return false, errors.New("checkpoint collection identity changed")
		}
		rooted, err = checkpointIsRooted(ctx, tx, *checkpoint)
		if err != nil {
			return false, err
		}
	} else {
		rooted, err = captureIsRooted(ctx, tx, current.CaptureID)
		if err != nil {
			return false, err
		}
	}
	if rooted {
		if _, err := tx.ExecContext(ctx, `DELETE FROM checkpoint_gc_intents WHERE capture_id=?`, current.CaptureID); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	result, err := tx.ExecContext(ctx, `UPDATE checkpoint_gc_intents SET phase='deleting'
WHERE capture_id=? AND phase='planned'`, current.CaptureID)
	if err != nil {
		return false, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return false, errors.New("checkpoint collection fence changed")
	}
	return true, tx.Commit()
}

func sameCheckpointGCIntent(left, right CheckpointGCIntent) bool {
	return left.SandboxID == right.SandboxID && left.CheckpointID == right.CheckpointID &&
		left.CaptureID == right.CaptureID && left.ObjectID == right.ObjectID &&
		left.ManifestDigest == right.ManifestDigest && left.Bytes == right.Bytes &&
		left.Phase == right.Phase && left.PlannedAt.Equal(right.PlannedAt) &&
		left.NotBefore.Equal(right.NotBefore)
}

func (s *Store) CompleteCheckpointCollection(ctx context.Context, expected CheckpointGCIntent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := scanCheckpointGCIntent(tx.QueryRowContext(ctx, checkpointGCSelect+` WHERE capture_id=?`, expected.CaptureID))
	if errors.Is(err, sql.ErrNoRows) {
		var tombstone int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM checkpoint_gc_tombstones
WHERE capture_id=? AND object_id=? AND manifest_digest=?)`, expected.CaptureID,
			expected.ObjectID, expected.ManifestDigest).Scan(&tombstone); err != nil {
			return err
		}
		if tombstone != 0 {
			return tx.Commit()
		}
		return ErrCheckpointUnavailable
	}
	if err != nil {
		return err
	}
	if !sameCheckpointGCIntent(current, expected) || current.Phase != "deleting" {
		return errors.New("checkpoint collection is not durably deleting")
	}
	if current.CheckpointID != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM checkpoints WHERE id=? AND capture_id=?`,
			current.CheckpointID, current.CaptureID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM continuity_captures
WHERE id=? AND object_id=? AND manifest_digest=?`, current.CaptureID,
		current.ObjectID, current.ManifestDigest); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO checkpoint_gc_tombstones(
capture_id, checkpoint_id, object_id, manifest_digest, collected_at)
VALUES(?, NULLIF(?, ''), ?, ?, ?) ON CONFLICT(capture_id) DO NOTHING`,
		current.CaptureID, current.CheckpointID, current.ObjectID, current.ManifestDigest,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM checkpoint_gc_intents WHERE capture_id=?`,
		current.CaptureID); err != nil {
		return err
	}
	return tx.Commit()
}
