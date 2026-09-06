package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type Store struct {
	db *sql.DB
}

type LocalSandbox struct {
	ID                 string
	Name               string
	DesiredState       string
	ObservedState      string
	Generation         int64
	ObservedGeneration int64
	Lifetime           string
	ExpiresInSeconds   *int
	StartedAt          *time.Time
	ExpiresAt          *time.Time
	Resources          model.Resources
	ImageDigest        string
	CLITools           []string
	ObservedCLITools   []model.CLIToolReport
	CLIToolsGeneration int64
	ErrorCode          string
	ErrorMessage       string
}

type LocalGrant struct {
	ID            string
	SandboxID     string
	SSHPublicKey  string
	DesiredState  string
	ObservedState string
	ErrorCode     string
	ErrorMessage  string
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open local database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.initialize(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("protect local database: %w", err)
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) initialize(ctx context.Context) error {
	const schema = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sandboxes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  desired_state TEXT NOT NULL,
  observed_state TEXT NOT NULL,
  generation INTEGER NOT NULL,
  observed_generation INTEGER NOT NULL,
  lifetime TEXT NOT NULL,
  expires_in_seconds INTEGER,
  started_at TEXT,
  expires_at TEXT,
  cpu_millicores INTEGER NOT NULL,
  memory_mib INTEGER NOT NULL,
  workspace_disk_gib INTEGER NOT NULL,
  pids_limit INTEGER NOT NULL,
  image_digest TEXT NOT NULL,
  cli_tools TEXT NOT NULL DEFAULT '[]',
  observed_cli_tools TEXT NOT NULL DEFAULT '[]',
  cli_tools_generation INTEGER NOT NULL DEFAULT 0,
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sandboxes_expiry_idx ON sandboxes(expires_at);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  sandbox_id TEXT NOT NULL REFERENCES sandboxes(id) ON DELETE CASCADE,
  ssh_public_key TEXT NOT NULL,
  desired_state TEXT NOT NULL,
  observed_state TEXT NOT NULL,
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS grants_sandbox_idx ON grants(sandbox_id);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initialize local database: %w", err)
	}
	if err := s.migrateSandboxToolColumns(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Store) migrateSandboxToolColumns(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(sandboxes)`)
	if err != nil {
		return fmt.Errorf("inspect local sandbox schema: %w", err)
	}
	columns := map[string]bool{}
	for rows.Next() {
		var sequence int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue sql.NullString
		if err := rows.Scan(
			&sequence,
			&name,
			&columnType,
			&notNull,
			&defaultValue,
			&primaryKey,
		); err != nil {
			rows.Close()
			return fmt.Errorf("inspect local sandbox schema: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("inspect local sandbox schema: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect local sandbox schema: %w", err)
	}
	statements := []struct {
		column string
		sql    string
	}{
		{"cli_tools", `ALTER TABLE sandboxes ADD COLUMN cli_tools TEXT NOT NULL DEFAULT '[]'`},
		{"observed_cli_tools", `ALTER TABLE sandboxes ADD COLUMN observed_cli_tools TEXT NOT NULL DEFAULT '[]'`},
		{"cli_tools_generation", `ALTER TABLE sandboxes ADD COLUMN cli_tools_generation INTEGER NOT NULL DEFAULT 0`},
	}
	for _, statement := range statements {
		if columns[statement.column] {
			continue
		}
		if _, err := s.db.ExecContext(ctx, statement.sql); err != nil {
			return fmt.Errorf("upgrade local sandbox schema: %w", err)
		}
	}
	return nil
}

func (s *Store) Revision(ctx context.Context) (int64, error) {
	var revision int64
	err := s.db.QueryRowContext(
		ctx,
		`SELECT CAST(value AS INTEGER) FROM metadata WHERE key = 'desired_revision'`,
	).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return revision, err
}

func (s *Store) SetRevision(ctx context.Context, revision int64) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO metadata(key, value) VALUES('desired_revision', ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		revision,
	)
	return err
}

func (s *Store) DeleteSandbox(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sandboxes WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteGrant(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE id = ?`, id)
	return err
}

func (s *Store) Sandbox(ctx context.Context, id string) (*LocalSandbox, error) {
	row := s.db.QueryRowContext(ctx, sandboxSelect+` WHERE id = ?`, id)
	value, err := scanSandbox(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return value, err
}

const sandboxSelect = `SELECT id, name, desired_state, observed_state, generation,
observed_generation, lifetime, expires_in_seconds, started_at, expires_at,
cpu_millicores, memory_mib, workspace_disk_gib, pids_limit, image_digest,
cli_tools, observed_cli_tools, cli_tools_generation, error_code, error_message FROM sandboxes`

type scanner interface {
	Scan(dest ...any) error
}

func scanSandbox(row scanner) (*LocalSandbox, error) {
	var value LocalSandbox
	var expiresSeconds sql.NullInt64
	var started, expires sql.NullString
	var cliTools, observedCLITools string
	err := row.Scan(
		&value.ID,
		&value.Name,
		&value.DesiredState,
		&value.ObservedState,
		&value.Generation,
		&value.ObservedGeneration,
		&value.Lifetime,
		&expiresSeconds,
		&started,
		&expires,
		&value.Resources.CPUMillicores,
		&value.Resources.MemoryMiB,
		&value.Resources.WorkspaceDiskGiB,
		&value.Resources.PIDs,
		&value.ImageDigest,
		&cliTools,
		&observedCLITools,
		&value.CLIToolsGeneration,
		&value.ErrorCode,
		&value.ErrorMessage,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(cliTools), &value.CLITools); err != nil {
		return nil, fmt.Errorf("decode desired CLI tools: %w", err)
	}
	if err := json.Unmarshal([]byte(observedCLITools), &value.ObservedCLITools); err != nil {
		return nil, fmt.Errorf("decode observed CLI tools: %w", err)
	}
	if expiresSeconds.Valid {
		seconds := int(expiresSeconds.Int64)
		value.ExpiresInSeconds = &seconds
	}
	value.StartedAt, err = parseNullableTime(started)
	if err != nil {
		return nil, err
	}
	value.ExpiresAt, err = parseNullableTime(expires)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) Sandboxes(ctx context.Context) ([]LocalSandbox, error) {
	rows, err := s.db.QueryContext(ctx, sandboxSelect+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalSandbox
	for rows.Next() {
		value, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, *value)
	}
	return values, rows.Err()
}

func (s *Store) PutSandbox(ctx context.Context, value LocalSandbox) error {
	cliTools, err := marshalArray(value.CLITools)
	if err != nil {
		return fmt.Errorf("encode desired CLI tools: %w", err)
	}
	observedCLITools, err := marshalArray(value.ObservedCLITools)
	if err != nil {
		return fmt.Errorf("encode observed CLI tools: %w", err)
	}
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO sandboxes(
id, name, desired_state, observed_state, generation, observed_generation,
lifetime, expires_in_seconds, started_at, expires_at, cpu_millicores,
memory_mib, workspace_disk_gib, pids_limit, image_digest, error_code,
error_message, cli_tools, observed_cli_tools, cli_tools_generation, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
name=excluded.name, desired_state=excluded.desired_state,
observed_state=excluded.observed_state, generation=excluded.generation,
observed_generation=excluded.observed_generation, lifetime=excluded.lifetime,
expires_in_seconds=excluded.expires_in_seconds, started_at=excluded.started_at,
expires_at=excluded.expires_at, cpu_millicores=excluded.cpu_millicores,
memory_mib=excluded.memory_mib, workspace_disk_gib=excluded.workspace_disk_gib,
pids_limit=excluded.pids_limit, image_digest=excluded.image_digest,
error_code=excluded.error_code, error_message=excluded.error_message,
cli_tools=excluded.cli_tools, observed_cli_tools=excluded.observed_cli_tools,
cli_tools_generation=excluded.cli_tools_generation,
updated_at=excluded.updated_at`,
		value.ID,
		value.Name,
		value.DesiredState,
		value.ObservedState,
		value.Generation,
		value.ObservedGeneration,
		value.Lifetime,
		nullableInt(value.ExpiresInSeconds),
		formatTime(value.StartedAt),
		formatTime(value.ExpiresAt),
		value.Resources.CPUMillicores,
		value.Resources.MemoryMiB,
		value.Resources.WorkspaceDiskGiB,
		value.Resources.PIDs,
		value.ImageDigest,
		value.ErrorCode,
		value.ErrorMessage,
		cliTools,
		observedCLITools,
		value.CLIToolsGeneration,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

func marshalArray[T any](values []T) (string, error) {
	if values == nil {
		values = []T{}
	}
	payload, err := json.Marshal(values)
	return string(payload), err
}

func (s *Store) PutGrant(ctx context.Context, value LocalGrant) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO grants(id, sandbox_id, ssh_public_key, desired_state,
observed_state, error_code, error_message, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET sandbox_id=excluded.sandbox_id,
ssh_public_key=excluded.ssh_public_key, desired_state=excluded.desired_state,
observed_state=excluded.observed_state, error_code=excluded.error_code,
error_message=excluded.error_message, updated_at=excluded.updated_at`,
		value.ID,
		value.SandboxID,
		value.SSHPublicKey,
		value.DesiredState,
		value.ObservedState,
		value.ErrorCode,
		value.ErrorMessage,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *Store) Grants(ctx context.Context) ([]LocalGrant, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, sandbox_id, ssh_public_key, desired_state, observed_state,
error_code, error_message FROM grants ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalGrant
	for rows.Next() {
		var value LocalGrant
		if err := rows.Scan(
			&value.ID,
			&value.SandboxID,
			&value.SSHPublicKey,
			&value.DesiredState,
			&value.ObservedState,
			&value.ErrorCode,
			&value.ErrorMessage,
		); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) Grant(ctx context.Context, id string) (*LocalGrant, error) {
	var value LocalGrant
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, sandbox_id, ssh_public_key, desired_state, observed_state,
error_code, error_message FROM grants WHERE id = ?`,
		id,
	).Scan(
		&value.ID,
		&value.SandboxID,
		&value.SSHPublicKey,
		&value.DesiredState,
		&value.ObservedState,
		&value.ErrorCode,
		&value.ErrorMessage,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &value, err
}

func nullableInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func formatTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func parseNullableTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}
