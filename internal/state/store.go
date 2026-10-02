package state

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

type LocalSetupOperation struct {
	ID                string
	SandboxID         string
	SandboxGeneration int64
	ProfileID         string
	ProfileRevision   int64
	ProfileDigest     string
	DesiredRevision   int64
	BodyDigest        string
	RequestJSON       []byte
	State             string
	ReceiptJSON       []byte
	ReceiptDigest     string
	ErrorCode         string
	ErrorMessage      string
}

type LocalContinuityOperation struct {
	ID                     string
	Kind                   string
	Identity               model.ContinuityIdentityV1
	RequestDigest          string
	State                  string
	Deadline               time.Time
	PauseOwned             bool
	PauseGeneration        int64
	PauseLifecycleRevision int64
	CaptureID              string
	CheckpointID           string
	ErrorCode              string
	ErrorMessage           string
}

type ContinuityTransition struct {
	From                   string
	To                     string
	PauseOwned             bool
	PauseGeneration        int64
	PauseLifecycleRevision int64
	CaptureID              string
	CheckpointID           string
	ErrorCode              string
	ErrorMessage           string
}

type LocalContinuityCapture struct {
	ID             string
	Identity       model.ContinuityIdentityV1
	ObjectID       string
	ManifestDigest string
	Bytes          int64
	ObjectCount    int
	Verified       bool
	CreatedAt      time.Time
}

type LocalCheckpoint struct {
	ID             string
	CaptureID      string
	Identity       model.ContinuityIdentityV1
	ManifestDigest string
	Bytes          int64
	ObjectCount    int
	Pinned         bool
	CreatedAt      time.Time
}

type CheckpointPolicy struct {
	MaxBytes  int64
	MaxPerBox int
	MaxAge    time.Duration
}

type LocalContinuitySource struct {
	Report              model.ContinuitySourceReportV1
	Root                string
	Instance            string
	Lifecycle           string
	LifecycleRevision   int64
	NoAdmittedExecution bool
}

type LocalContinuityRegistration struct {
	Manifest          model.ContinuityRegistrationV1
	ObservedStatus    string
	ServiceGeneration int64
	ReceiptDigest     string
	ErrorCode         string
}

// ContinuityOperationCandidate is one local terminal continuity-operation
// outbox row offered to the acknowledgement retirement predicate with the two
// live-state fences the store reads inside the same retirement transaction.
type ContinuityOperationCandidate struct {
	Report             model.ContinuityOperationReportV1
	BarrierPresent     bool
	LocalOperationLive bool
}

// ContinuityOperationRetirement is the immutable local tombstone of one
// acknowledged terminal continuity-operation outbox row. It retains the exact
// request digest and report payload the outbox held, so the acknowledgement is
// auditable byte-for-byte after the row leaves the reported outbox.
type ContinuityOperationRetirement struct {
	Report    model.ContinuityOperationReportV1
	Reason    string
	RetiredAt time.Time
}

// LocalManagedProject retains the authority that must never cross the host
// boundary: the source root and filesystem identities behind a safe catalog
// report.
type LocalManagedProject struct {
	Report           model.ProjectCatalogReportV1
	ServerID         string
	TeamID           string
	MemberID         string
	AllocationDigest string
	ConfigDigest     string
	Anchor           string
	HostRoot         string
	ContainerRoot    string
	Phase            string
	AnchorDevice     uint64
	AnchorInode      uint64
	AnchorMount      string
	RootDevice       uint64
	RootInode        uint64
	RootMount        string
	ScopeRevision    int64
	// SupersededRootAttestation is the root attestation this record carried
	// before the documented workspace remount moved the unchanged workspace
	// image onto a new loop device and the re-observation re-attested the record
	// to the live device. It is host-private provenance: it lets a later pass
	// recognize a manifest that still carries the pre-remount authority as the
	// same bounded, retryable remount rather than a project change. Any other
	// re-attestation of the record clears it. It is never published: only the
	// ordinary root attestation admits a managed service.
	SupersededRootAttestation string
	// ImageIdentity is the durable object identity (device, inode, size) of the
	// workspace image file that carried this project's root when the record was
	// attested. It is host-private, never published, and once recorded the same
	// object must still be observed before the documented workspace remount may
	// re-attest the record, so a different image object that happens to
	// reproduce the same ext4 inode numbers can never be adopted. The image's
	// modification time is deliberately not compared: mounted filesystem writes
	// legitimately move it while the object stays unchanged. The zero value
	// means the record predates the field and no durable image identity is
	// available.
	ImageIdentity ManagedProjectImageIdentity
}

// ManagedProjectImageIdentity is the durable object identity of a workspace
// image file: the file's device, inode and size. The modification time is
// deliberately not part of the identity and not compared, because mounted
// filesystem writes legitimately move it. It is persisted inside the
// managed-project record's private JSON, so records written before the field
// existed simply load with the zero value.
type ManagedProjectImageIdentity struct {
	Device uint64
	Inode  uint64
	Size   int64
	// ModifiedUnixNano is the observed modification time, kept as host-private
	// observation provenance only: mounted filesystem writes move it while the
	// durable object stays unchanged, so it is never compared.
	ModifiedUnixNano int64
}

// SameDurableObject reports whether both observations name the same durable
// workspace image object: the same device, inode and size. The modification
// time is deliberately not compared because mounted filesystem writes
// legitimately move it.
func (value ManagedProjectImageIdentity) SameDurableObject(other ManagedProjectImageIdentity) bool {
	return value.Device == other.Device && value.Inode == other.Inode && value.Size == other.Size
}

type LocalManagedService struct {
	Manifest           model.ManagedServiceV1
	Phase              string
	ProcessInstance    string
	Port               int
	CreationDispatched bool
	ServiceGeneration  int64
	Report             model.ManagedServiceReportV1
	ErrorCode          string
}

type LocalContinuationPreparation struct {
	Manifest model.ContinuationManifestV1
	Phase    string
	Report   *model.ContinuationReportV1
}

type LocalContinuationRelease struct {
	Manifest model.ContinuationReleaseManifestV1
	Phase    string
	Report   *model.ContinuationReleaseReportV1
}

type LocalContinuationHandoffPreparation struct {
	Manifest          model.ContinuationHandoffManifestV1
	Phase             string
	TargetSelectionID string
	Report            *model.ContinuationHandoffReportV1
}

type LocalContinuationHandoffRelease struct {
	Manifest model.ContinuationHandoffReleaseManifestV1
	Phase    string
	Report   *model.ContinuationHandoffReleaseReportV1
}

type LocalRestoreOperation struct {
	Manifest model.RestoreManifestV1
	Phase    string
	Report   *model.RestoreReportV1
}

type InsightCursor struct {
	RegisteredSourceID string
	PolicyRevision     int64
	WorkspaceEpoch     string
	JournalGeneration  string
	ChangeSequence     int64
	ThroughSequence    int64
	Status             string
	GapReason          string
	ProjectionDigest   string
}

type InsightOutboxItem struct {
	Batch      model.InsightBatchV1
	BodyDigest string
	NextCursor InsightCursor
}

type InsightPolicyState struct {
	RegisteredSourceID string
	Revision           int64
	Enabled            bool
}

type InsightPolicyLease struct {
	Policy model.InsightPolicyV1
}

type InsightOutboxRetirement struct {
	InsightOutboxItem
	Reason    string
	RetiredAt time.Time
}

func (value LocalManagedService) RecoverySessionMode() string {
	if value.CreationDispatched {
		return "lookup_only"
	}
	return value.Manifest.SessionMode
}

var ErrCheckpointQuota = errors.New("checkpoint quota exceeded")
var ErrCheckpointUnavailable = errors.New("checkpoint object is no longer retained")
var ErrManagedProjectConflict = errors.New("managed project immutable identity conflict")
var ErrManagedServiceConflict = errors.New("managed service immutable identity conflict")
var ErrContinuationConflict = errors.New("continuation preparation immutable identity conflict")
var ErrContinuationHandoffConflict = errors.New("continuation handoff immutable identity conflict")
var ErrRestoreConflict = errors.New("restore operation immutable identity conflict")
var ErrInsightOutboxConflict = errors.New("insight outbox immutable identity conflict")
var ErrInsightOutboxCapacity = errors.New("insight outbox capacity exceeded")

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
CREATE TABLE IF NOT EXISTS setup_operations (
  id TEXT PRIMARY KEY,
  sandbox_id TEXT NOT NULL REFERENCES sandboxes(id) ON DELETE CASCADE,
  sandbox_generation INTEGER NOT NULL CHECK(sandbox_generation > 0),
  profile_id TEXT NOT NULL,
  profile_revision INTEGER NOT NULL CHECK(profile_revision > 0),
  profile_digest TEXT NOT NULL,
  desired_revision INTEGER NOT NULL CHECK(desired_revision > 0),
  body_digest TEXT NOT NULL,
  request_json BLOB NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending', 'applying', 'ready', 'failed', 'cancelled')),
  receipt_json BLOB,
  receipt_digest TEXT NOT NULL DEFAULT '',
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS setup_operations_sandbox_idx
ON setup_operations(sandbox_id, sandbox_generation);
CREATE INDEX IF NOT EXISTS setup_operations_revision_idx
ON setup_operations(desired_revision, state);
CREATE TABLE IF NOT EXISTS continuity_operations (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('capture', 'checkpoint', 'materialize')),
  work_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  sandbox_id TEXT NOT NULL,
  workspace_epoch TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK(sandbox_generation > 0),
  task_id TEXT,
  task_attempt INTEGER,
  expected_revision INTEGER NOT NULL CHECK(expected_revision > 0),
  request_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN (
    'pending', 'pausing', 'paused', 'capturing', 'captured', 'verifying',
    'materializing', 'succeeded', 'failed', 'recovery_required'
  )),
  deadline TEXT NOT NULL,
  pause_owned INTEGER NOT NULL DEFAULT 0 CHECK(pause_owned IN (0, 1)),
  pause_generation INTEGER NOT NULL DEFAULT 0,
  pause_lifecycle_revision INTEGER NOT NULL DEFAULT 0,
  capture_id TEXT NOT NULL DEFAULT '',
  checkpoint_id TEXT NOT NULL DEFAULT '',
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
  ,CHECK((task_id IS NULL AND task_attempt IS NULL) OR
         (task_id IS NOT NULL AND task_id <> '' AND task_attempt > 0))
);
CREATE INDEX IF NOT EXISTS continuity_operations_state_idx
ON continuity_operations(state, deadline);
CREATE TABLE IF NOT EXISTS continuity_captures (
  id TEXT PRIMARY KEY,
  work_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  sandbox_id TEXT NOT NULL,
  workspace_epoch TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL,
  task_id TEXT,
  task_attempt INTEGER,
  expected_revision INTEGER NOT NULL,
  object_id TEXT NOT NULL UNIQUE,
  manifest_digest TEXT NOT NULL,
  bytes INTEGER NOT NULL CHECK(bytes >= 0),
  object_count INTEGER NOT NULL CHECK(object_count >= 0),
  verified INTEGER NOT NULL CHECK(verified IN (0, 1)),
  created_at TEXT NOT NULL,
  CHECK((task_id IS NULL AND task_attempt IS NULL) OR
        (task_id IS NOT NULL AND task_id <> '' AND task_attempt > 0))
);
CREATE TABLE IF NOT EXISTS checkpoint_policies (
  sandbox_id TEXT PRIMARY KEY,
  max_bytes INTEGER NOT NULL CHECK(max_bytes > 0),
  max_per_work INTEGER NOT NULL CHECK(max_per_work > 0),
  max_per_box INTEGER NOT NULL DEFAULT 20 CHECK(max_per_box > 0),
  max_age_seconds INTEGER NOT NULL CHECK(max_age_seconds > 0),
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
  id TEXT PRIMARY KEY,
  capture_id TEXT NOT NULL UNIQUE REFERENCES continuity_captures(id),
  work_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  sandbox_id TEXT NOT NULL,
  workspace_epoch TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL,
  task_id TEXT,
  task_attempt INTEGER,
  expected_revision INTEGER NOT NULL,
  manifest_digest TEXT NOT NULL,
  bytes INTEGER NOT NULL CHECK(bytes >= 0),
  object_count INTEGER NOT NULL CHECK(object_count >= 0),
  pinned INTEGER NOT NULL DEFAULT 0 CHECK(pinned IN (0, 1)),
  created_at TEXT NOT NULL,
  CHECK((task_id IS NULL AND task_attempt IS NULL) OR
        (task_id IS NOT NULL AND task_id <> '' AND task_attempt > 0))
);
CREATE INDEX IF NOT EXISTS checkpoints_sandbox_idx ON checkpoints(sandbox_id, created_at);
CREATE INDEX IF NOT EXISTS checkpoints_work_idx ON checkpoints(work_id, created_at DESC);
CREATE TABLE IF NOT EXISTS work_checkpoint_pointers (
  work_id TEXT PRIMARY KEY,
  checkpoint_id TEXT NOT NULL REFERENCES checkpoints(id),
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoint_gc_intents (
  capture_id TEXT PRIMARY KEY,
  sandbox_id TEXT NOT NULL,
  checkpoint_id TEXT,
  object_id TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  bytes INTEGER NOT NULL CHECK(bytes >= 0),
  phase TEXT NOT NULL CHECK(phase IN ('planned','deleting')),
  planned_at TEXT NOT NULL,
  not_before TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS checkpoint_gc_intents_phase_idx
ON checkpoint_gc_intents(phase, not_before, capture_id);
CREATE TABLE IF NOT EXISTS checkpoint_gc_tombstones (
  capture_id TEXT PRIMARY KEY,
  checkpoint_id TEXT,
  object_id TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS continuity_sources (
  registered_source_id TEXT PRIMARY KEY,
  report_json BLOB NOT NULL,
  workspace_root TEXT NOT NULL,
  instance TEXT NOT NULL,
  lifecycle TEXT NOT NULL CHECK(lifecycle IN ('running','stopped')),
  lifecycle_revision INTEGER NOT NULL CHECK(lifecycle_revision > 0),
  no_admitted_execution INTEGER NOT NULL CHECK(no_admitted_execution IN (0,1)),
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS continuity_registrations (
  binding_id TEXT PRIMARY KEY,
  manifest_json BLOB NOT NULL,
  observed_status TEXT NOT NULL CHECK(observed_status IN ('verified','revoked','failed')),
  service_generation INTEGER NOT NULL DEFAULT 0,
  receipt_digest TEXT NOT NULL DEFAULT '',
  error_code TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS continuity_barriers (
  operation_id TEXT PRIMARY KEY,
  request_json BLOB NOT NULL,
  receipt_json BLOB NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS continuity_remote_operations (
  operation_id TEXT PRIMARY KEY,
  request_digest TEXT NOT NULL,
  report_json BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS continuity_remote_operation_retirements (
  operation_id TEXT PRIMARY KEY,
  request_digest TEXT NOT NULL,
  report_json BLOB NOT NULL,
  reason TEXT NOT NULL,
  retired_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS managed_workspace_projects (
  selection_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL UNIQUE,
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK(sandbox_generation > 0),
  team_id TEXT NOT NULL DEFAULT '',
  report_json BLOB NOT NULL,
  private_json BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS managed_workspace_projects_team_idx
ON managed_workspace_projects(sandbox_id, sandbox_generation, team_id);
CREATE TABLE IF NOT EXISTS managed_services (
  service_registration_id TEXT PRIMARY KEY,
  manifest_json BLOB NOT NULL,
  phase TEXT NOT NULL,
  process_instance TEXT NOT NULL,
  port INTEGER NOT NULL CHECK(port >= 1024 AND port <= 65535),
  creation_dispatched INTEGER NOT NULL CHECK(creation_dispatched IN (0,1)),
  service_generation INTEGER NOT NULL CHECK(service_generation > 0),
  report_json BLOB,
  error_code TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS continuation_preparations (
  operation_id TEXT PRIMARY KEY,
  manifest_json BLOB NOT NULL,
  phase TEXT NOT NULL CHECK(phase IN ('preparing','recovery_required','ready','failed')),
  report_json BLOB,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS continuation_releases (
  operation_id TEXT PRIMARY KEY,
  manifest_json BLOB NOT NULL,
  phase TEXT NOT NULL CHECK(phase IN ('releasing','released','failed')),
  report_json BLOB,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS continuation_handoff_preparations (
  operation_id TEXT PRIMARY KEY,
  manifest_json BLOB NOT NULL,
  phase TEXT NOT NULL CHECK(phase IN ('allocating','materializing','workspace_registered','recovery_required','ready','registration_pending','admission_pending','failed')),
  target_selection_id TEXT NOT NULL DEFAULT '',
  mapped_source_id TEXT NOT NULL DEFAULT '',
  report_json BLOB,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS continuation_handoff_source_idx
ON continuation_handoff_preparations(mapped_source_id) WHERE mapped_source_id <> '';
CREATE TABLE IF NOT EXISTS continuation_handoff_releases (
  operation_id TEXT PRIMARY KEY,
  manifest_json BLOB NOT NULL,
  phase TEXT NOT NULL CHECK(phase IN ('releasing','released','failed')),
  report_json BLOB,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS restore_operations (
  operation_id TEXT PRIMARY KEY,
  manifest_json BLOB NOT NULL,
  phase TEXT NOT NULL CHECK(phase IN ('allocating','materializing','accepted','failed')),
  report_json BLOB,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS insight_cursors (
  registered_source_id TEXT PRIMARY KEY,
  cursor_json BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS insight_outbox (
  batch_id TEXT PRIMARY KEY,
  registered_source_id TEXT NOT NULL,
  body_digest TEXT NOT NULL,
  batch_json BLOB NOT NULL,
  next_cursor_json BLOB NOT NULL,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS insight_outbox_source_idx
ON insight_outbox(registered_source_id) WHERE registered_source_id <> '';
CREATE TABLE IF NOT EXISTS insight_policy_state (
  registered_source_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK(revision > 0),
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS insight_policy_leases (
  sandbox_id TEXT PRIMARY KEY,
  policy_json BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS insight_outbox_retirements (
  batch_id TEXT PRIMARY KEY,
  body_digest TEXT NOT NULL,
  batch_json BLOB NOT NULL,
  next_cursor_json BLOB NOT NULL,
  reason TEXT NOT NULL CHECK(reason IN ('policy_superseded','source_rotated')),
  retired_at TEXT NOT NULL
);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initialize local database: %w", err)
	}
	if err := s.ensureCheckpointLifecycleSchema(ctx); err != nil {
		return fmt.Errorf("upgrade checkpoint lifecycle schema: %w", err)
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
error_code, error_message FROM sandboxes`

type scanner interface {
	Scan(dest ...any) error
}

func scanSandbox(row scanner) (*LocalSandbox, error) {
	var value LocalSandbox
	var expiresSeconds sql.NullInt64
	var started, expires sql.NullString
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
		&value.ErrorCode,
		&value.ErrorMessage,
	)
	if err != nil {
		return nil, err
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
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO sandboxes(
id, name, desired_state, observed_state, generation, observed_generation,
lifetime, expires_in_seconds, started_at, expires_at, cpu_millicores,
memory_mib, workspace_disk_gib, pids_limit, image_digest, error_code,
error_message, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
name=excluded.name, desired_state=excluded.desired_state,
observed_state=excluded.observed_state, generation=excluded.generation,
observed_generation=excluded.observed_generation, lifetime=excluded.lifetime,
expires_in_seconds=excluded.expires_in_seconds, started_at=excluded.started_at,
expires_at=excluded.expires_at, cpu_millicores=excluded.cpu_millicores,
memory_mib=excluded.memory_mib, workspace_disk_gib=excluded.workspace_disk_gib,
pids_limit=excluded.pids_limit, image_digest=excluded.image_digest,
error_code=excluded.error_code, error_message=excluded.error_message,
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
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
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

const setupOperationSelect = `SELECT id, sandbox_id, sandbox_generation,
profile_id, profile_revision, profile_digest, desired_revision, body_digest,
request_json, state, receipt_json, receipt_digest, error_code, error_message
FROM setup_operations`

func scanSetupOperation(row scanner) (*LocalSetupOperation, error) {
	var value LocalSetupOperation
	var receipt []byte
	if err := row.Scan(
		&value.ID,
		&value.SandboxID,
		&value.SandboxGeneration,
		&value.ProfileID,
		&value.ProfileRevision,
		&value.ProfileDigest,
		&value.DesiredRevision,
		&value.BodyDigest,
		&value.RequestJSON,
		&value.State,
		&receipt,
		&value.ReceiptDigest,
		&value.ErrorCode,
		&value.ErrorMessage,
	); err != nil {
		return nil, err
	}
	value.RequestJSON = append([]byte(nil), value.RequestJSON...)
	value.ReceiptJSON = append([]byte(nil), receipt...)
	return &value, nil
}

func (s *Store) SetupOperation(ctx context.Context, id string) (*LocalSetupOperation, error) {
	value, err := scanSetupOperation(s.db.QueryRowContext(ctx, setupOperationSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return value, err
}

func (s *Store) SetupOperations(ctx context.Context) ([]LocalSetupOperation, error) {
	rows, err := s.db.QueryContext(ctx, setupOperationSelect+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalSetupOperation
	for rows.Next() {
		value, err := scanSetupOperation(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, *value)
	}
	return values, rows.Err()
}

// PutSetupOperation creates an immutable desired-operation fence. Reusing an
// ID for a different operation is rejected rather than silently replacing a
// terminal receipt or changing the work represented by an in-flight row.
func (s *Store) PutSetupOperation(ctx context.Context, value LocalSetupOperation) error {
	if value.State != "pending" {
		return errors.New("new setup operation must be pending")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO setup_operations(
id, sandbox_id, sandbox_generation, profile_id, profile_revision, profile_digest,
desired_revision, body_digest, request_json, state, receipt_json, receipt_digest,
error_code, error_message, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, '', '', '', ?)
ON CONFLICT(id) DO NOTHING`,
		value.ID,
		value.SandboxID,
		value.SandboxGeneration,
		value.ProfileID,
		value.ProfileRevision,
		value.ProfileDigest,
		value.DesiredRevision,
		value.BodyDigest,
		value.RequestJSON,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted == 1 {
		return err
	}
	existing, err := s.SetupOperation(ctx, value.ID)
	if err != nil {
		return err
	}
	if existing == nil || existing.SandboxID != value.SandboxID ||
		existing.SandboxGeneration != value.SandboxGeneration ||
		existing.ProfileID != value.ProfileID ||
		existing.ProfileRevision != value.ProfileRevision ||
		existing.ProfileDigest != value.ProfileDigest ||
		existing.BodyDigest != value.BodyDigest ||
		string(existing.RequestJSON) != string(value.RequestJSON) {
		return errors.New("setup operation ID conflicts with a different immutable fence")
	}
	return nil
}

// TransitionSetupOperation enforces the only allowed state edges:
// pending -> applying, pending/applying -> cancelled, and applying -> ready/failed.
func (s *Store) TransitionSetupOperation(
	ctx context.Context,
	id string,
	status string,
	receipt []byte,
	errorCode string,
	errorMessage string,
) error {
	current, err := s.SetupOperation(ctx, id)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.New("setup operation does not exist")
	}
	allowed := current.State == "pending" && (status == "applying" || status == "cancelled") ||
		current.State == "applying" && (status == "ready" || status == "failed" || status == "cancelled")
	if !allowed {
		return fmt.Errorf("invalid setup operation transition %s -> %s", current.State, status)
	}
	if status == "ready" && len(receipt) == 0 {
		return errors.New("ready setup operation requires a receipt")
	}
	if status != "ready" {
		receipt = nil
	}
	receiptDigest := ""
	if status == "ready" {
		var envelope struct {
			ReceiptDigest string `json:"receiptDigest"`
		}
		if err := json.Unmarshal(receipt, &envelope); err == nil {
			receiptDigest = envelope.ReceiptDigest
		}
	}
	if len(errorMessage) > 300 {
		errorMessage = errorMessage[:300]
	}
	result, err := s.db.ExecContext(ctx, `UPDATE setup_operations
SET state = ?, receipt_json = ?, receipt_digest = ?, error_code = ?, error_message = ?, updated_at = ?
WHERE id = ? AND state = ?`, status, nullableBytes(receipt), receiptDigest, errorCode, errorMessage,
		time.Now().UTC().Format(time.RFC3339Nano), id, current.State)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("setup operation transition lost its state fence")
	}
	return nil
}

const continuityOperationSelect = `SELECT id, kind, work_id, project_id, sandbox_id,
workspace_epoch, sandbox_generation, task_id, task_attempt, expected_revision,
request_digest, state, deadline, pause_owned, pause_generation, pause_lifecycle_revision, capture_id,
checkpoint_id, error_code, error_message FROM continuity_operations`

func scanContinuityOperation(row scanner) (*LocalContinuityOperation, error) {
	var value LocalContinuityOperation
	var deadline string
	var pauseOwned int
	err := row.Scan(
		&value.ID, &value.Kind, &value.Identity.WorkID, &value.Identity.ProjectID,
		&value.Identity.SandboxID, &value.Identity.WorkspaceEpoch,
		&value.Identity.SandboxGeneration, &value.Identity.TaskID,
		&value.Identity.TaskAttempt, &value.Identity.ExpectedRevision,
		&value.RequestDigest, &value.State, &deadline, &pauseOwned,
		&value.PauseGeneration, &value.PauseLifecycleRevision, &value.CaptureID, &value.CheckpointID,
		&value.ErrorCode, &value.ErrorMessage,
	)
	if err != nil {
		return nil, err
	}
	value.Deadline, err = time.Parse(time.RFC3339Nano, deadline)
	if err != nil {
		return nil, err
	}
	value.PauseOwned = pauseOwned != 0
	return &value, nil
}

func (s *Store) ContinuityOperation(ctx context.Context, id string) (*LocalContinuityOperation, error) {
	value, err := scanContinuityOperation(s.db.QueryRowContext(ctx, continuityOperationSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return value, err
}

func (s *Store) ContinuityOperationsByState(ctx context.Context, states ...string) ([]LocalContinuityOperation, error) {
	if len(states) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(states))
	arguments := make([]any, len(states))
	for index, state := range states {
		placeholders[index] = "?"
		arguments[index] = state
	}
	rows, err := s.db.QueryContext(ctx, continuityOperationSelect+` WHERE state IN (`+
		strings.Join(placeholders, ",")+`) ORDER BY id`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalContinuityOperation
	for rows.Next() {
		value, err := scanContinuityOperation(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, *value)
	}
	return values, rows.Err()
}

func (s *Store) PutContinuityOperation(ctx context.Context, value LocalContinuityOperation) error {
	if value.State != "pending" {
		return errors.New("new continuity operation must be pending")
	}
	if value.Deadline.IsZero() {
		return errors.New("continuity operation requires a deadline")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	identity := value.Identity
	result, err := s.db.ExecContext(ctx, `INSERT INTO continuity_operations(
id, kind, work_id, project_id, sandbox_id, workspace_epoch,
sandbox_generation, task_id, task_attempt, expected_revision, request_digest,
state, deadline, created_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
ON CONFLICT(id) DO NOTHING`,
		value.ID, value.Kind, identity.WorkID, identity.ProjectID, identity.SandboxID,
		identity.WorkspaceEpoch, identity.SandboxGeneration, identity.TaskID,
		identity.TaskAttempt, identity.ExpectedRevision, value.RequestDigest,
		value.Deadline.UTC().Format(time.RFC3339Nano), now, now,
	)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted == 1 {
		return err
	}
	existing, err := s.ContinuityOperation(ctx, value.ID)
	if err != nil {
		return err
	}
	if existing == nil || existing.Kind != value.Kind || !existing.Identity.Equal(value.Identity) ||
		existing.RequestDigest != value.RequestDigest {
		return errors.New("continuity operation ID conflicts with a different immutable fence")
	}
	return nil
}

func validContinuityTransition(from, to string) bool {
	switch from {
	case "pending":
		return to == "pausing" || to == "capturing" || to == "verifying" ||
			to == "materializing" || to == "failed"
	case "pausing":
		return to == "paused" || to == "recovery_required" || to == "failed"
	case "paused":
		return to == "capturing" || to == "recovery_required" || to == "failed"
	case "capturing":
		return to == "captured" || to == "recovery_required" || to == "failed"
	case "verifying", "materializing":
		return to == "succeeded" || to == "failed" || to == "recovery_required"
	case "recovery_required":
		return to == "failed"
	default:
		return false
	}
}

func (s *Store) TransitionContinuityOperation(ctx context.Context, id string, transition ContinuityTransition) error {
	if !validContinuityTransition(transition.From, transition.To) {
		return fmt.Errorf("invalid continuity operation transition %s -> %s", transition.From, transition.To)
	}
	if len(transition.ErrorMessage) > 300 {
		transition.ErrorMessage = transition.ErrorMessage[:300]
	}
	result, err := s.db.ExecContext(ctx, `UPDATE continuity_operations SET
state = ?, pause_owned = ?, pause_generation = ?, pause_lifecycle_revision = ?, capture_id = ?, checkpoint_id = ?,
error_code = ?, error_message = ?, updated_at = ?
WHERE id = ? AND state = ?`,
		transition.To, boolInt(transition.PauseOwned), transition.PauseGeneration,
		transition.PauseLifecycleRevision,
		transition.CaptureID, transition.CheckpointID, transition.ErrorCode,
		transition.ErrorMessage, time.Now().UTC().Format(time.RFC3339Nano), id, transition.From,
	)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("continuity operation transition lost its state fence")
	}
	return nil
}

const continuityCaptureSelect = `SELECT id, work_id, project_id, sandbox_id,
workspace_epoch, sandbox_generation, task_id, task_attempt, expected_revision,
object_id, manifest_digest, bytes, object_count, verified, created_at FROM continuity_captures`

func scanContinuityCapture(row scanner) (*LocalContinuityCapture, error) {
	var value LocalContinuityCapture
	var verified int
	var created string
	err := row.Scan(
		&value.ID, &value.Identity.WorkID, &value.Identity.ProjectID,
		&value.Identity.SandboxID, &value.Identity.WorkspaceEpoch,
		&value.Identity.SandboxGeneration, &value.Identity.TaskID,
		&value.Identity.TaskAttempt, &value.Identity.ExpectedRevision,
		&value.ObjectID, &value.ManifestDigest, &value.Bytes, &value.ObjectCount,
		&verified, &created,
	)
	if err != nil {
		return nil, err
	}
	value.Verified = verified != 0
	value.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	return &value, err
}

func (s *Store) PutContinuityCapture(ctx context.Context, value LocalContinuityCapture) error {
	if value.CreatedAt.IsZero() {
		value.CreatedAt = time.Now().UTC()
	}
	existing, err := s.ContinuityCapture(ctx, value.ID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !existing.Identity.Equal(value.Identity) || existing.ObjectID != value.ObjectID ||
			existing.ManifestDigest != value.ManifestDigest || existing.Bytes != value.Bytes ||
			existing.ObjectCount != value.ObjectCount || existing.Verified != value.Verified {
			return errors.New("continuity capture ID conflicts with different immutable content")
		}
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var unavailable int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM checkpoint_gc_tombstones
WHERE capture_id = ? OR object_id = ? OR manifest_digest = ?)`,
		value.ID, value.ObjectID, value.ManifestDigest).Scan(&unavailable); err != nil {
		return err
	}
	if unavailable != 0 {
		return ErrCheckpointUnavailable
	}
	policy, err := checkpointPolicy(ctx, tx, value.Identity.SandboxID)
	if err != nil {
		return err
	}
	var used int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes), 0)
FROM continuity_captures WHERE sandbox_id = ?`, value.Identity.SandboxID).Scan(&used); err != nil {
		return err
	}
	if used+value.Bytes > policy.MaxBytes {
		return ErrCheckpointQuota
	}
	identity := value.Identity
	_, err = tx.ExecContext(ctx, `INSERT INTO continuity_captures(
id, work_id, project_id, sandbox_id, workspace_epoch, sandbox_generation,
task_id, task_attempt, expected_revision, object_id, manifest_digest, bytes,
object_count, verified, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		value.ID, identity.WorkID, identity.ProjectID, identity.SandboxID,
		identity.WorkspaceEpoch, identity.SandboxGeneration, identity.TaskID,
		identity.TaskAttempt, identity.ExpectedRevision, value.ObjectID,
		value.ManifestDigest, value.Bytes, value.ObjectCount, boolInt(value.Verified),
		value.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ContinuityCapture(ctx context.Context, id string) (*LocalContinuityCapture, error) {
	value, err := scanContinuityCapture(s.db.QueryRowContext(ctx, continuityCaptureSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return value, err
}

func (s *Store) SetCheckpointPolicy(ctx context.Context, sandboxID string, policy CheckpointPolicy) error {
	if policy.MaxBytes <= 0 || policy.MaxPerBox <= 0 || policy.MaxAge <= 0 {
		return errors.New("checkpoint policy limits must be positive")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO checkpoint_policies(
sandbox_id, max_bytes, max_per_work, max_per_box, max_age_seconds, updated_at)
VALUES(?, ?, ?, ?, ?, ?)
ON CONFLICT(sandbox_id) DO UPDATE SET max_bytes=excluded.max_bytes,
max_per_work=excluded.max_per_work, max_per_box=excluded.max_per_box,
max_age_seconds=excluded.max_age_seconds, updated_at=excluded.updated_at`,
		sandboxID, policy.MaxBytes, policy.MaxPerBox, policy.MaxPerBox,
		int64(policy.MaxAge/time.Second), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) CheckpointBudget(ctx context.Context, sandboxID string) (int64, error) {
	policy, err := checkpointPolicy(ctx, s.db, sandboxID)
	if err != nil {
		return 0, err
	}
	var used int64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes), 0)
FROM continuity_captures WHERE sandbox_id = ?`, sandboxID).Scan(&used); err != nil {
		return 0, err
	}
	remaining := policy.MaxBytes - used
	if remaining < 0 {
		remaining = 0
	}
	return remaining, nil
}

func checkpointPolicy(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, sandboxID string) (CheckpointPolicy, error) {
	policy := CheckpointPolicy{MaxBytes: 1 << 30, MaxPerBox: 20, MaxAge: 30 * 24 * time.Hour}
	var ageSeconds int64
	err := query.QueryRowContext(ctx, `SELECT max_bytes, max_per_box, max_age_seconds
FROM checkpoint_policies WHERE sandbox_id = ?`, sandboxID).Scan(
		&policy.MaxBytes, &policy.MaxPerBox, &ageSeconds,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return policy, nil
	}
	if err != nil {
		return CheckpointPolicy{}, err
	}
	policy.MaxAge = time.Duration(ageSeconds) * time.Second
	return policy, nil
}

const checkpointSelect = `SELECT id, capture_id, work_id, project_id, sandbox_id,
workspace_epoch, sandbox_generation, task_id, task_attempt, expected_revision,
manifest_digest, bytes, object_count, pinned, created_at FROM checkpoints`

func scanCheckpoint(row scanner) (*LocalCheckpoint, error) {
	var value LocalCheckpoint
	var pinned int
	var created string
	err := row.Scan(
		&value.ID, &value.CaptureID, &value.Identity.WorkID,
		&value.Identity.ProjectID, &value.Identity.SandboxID,
		&value.Identity.WorkspaceEpoch, &value.Identity.SandboxGeneration,
		&value.Identity.TaskID, &value.Identity.TaskAttempt,
		&value.Identity.ExpectedRevision, &value.ManifestDigest, &value.Bytes,
		&value.ObjectCount, &pinned, &created,
	)
	if err != nil {
		return nil, err
	}
	value.Pinned = pinned != 0
	value.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	return &value, err
}

func (s *Store) Checkpoint(ctx context.Context, id string) (*LocalCheckpoint, error) {
	value, err := scanCheckpoint(s.db.QueryRowContext(ctx, checkpointSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return value, err
}

func (s *Store) AcceptedCheckpoint(ctx context.Context, workID string) (*LocalCheckpoint, error) {
	value, err := scanCheckpoint(s.db.QueryRowContext(ctx, checkpointSelect+`
WHERE id = (SELECT checkpoint_id FROM work_checkpoint_pointers WHERE work_id = ?)`, workID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return value, err
}

func (s *Store) AcceptCheckpoint(ctx context.Context, value LocalCheckpoint) error {
	if value.CreatedAt.IsZero() {
		value.CreatedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var unavailable int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM checkpoint_gc_tombstones
WHERE checkpoint_id = ? OR capture_id = ? OR manifest_digest = ?
UNION ALL
SELECT 1 FROM checkpoint_gc_intents
WHERE phase = 'deleting' AND (checkpoint_id = ? OR capture_id = ? OR manifest_digest = ?))`,
		value.ID, value.CaptureID, value.ManifestDigest,
		value.ID, value.CaptureID, value.ManifestDigest).Scan(&unavailable); err != nil {
		return err
	}
	if unavailable != 0 {
		return ErrCheckpointUnavailable
	}
	var capture LocalContinuityCapture
	var verified int
	err = tx.QueryRowContext(ctx, continuityCaptureSelect+` WHERE id = ?`, value.CaptureID).Scan(
		&capture.ID, &capture.Identity.WorkID, &capture.Identity.ProjectID,
		&capture.Identity.SandboxID, &capture.Identity.WorkspaceEpoch,
		&capture.Identity.SandboxGeneration, &capture.Identity.TaskID,
		&capture.Identity.TaskAttempt, &capture.Identity.ExpectedRevision,
		&capture.ObjectID, &capture.ManifestDigest, &capture.Bytes, &capture.ObjectCount,
		&verified, new(string),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("continuity capture does not exist")
		}
		return err
	}
	if verified == 0 || !capture.Identity.Equal(value.Identity) || capture.ManifestDigest != value.ManifestDigest ||
		capture.Bytes != value.Bytes || capture.ObjectCount != value.ObjectCount {
		return errors.New("checkpoint does not match a verified durable capture")
	}
	existing, err := scanCheckpoint(tx.QueryRowContext(ctx, checkpointSelect+` WHERE id = ?`, value.ID))
	if err == nil {
		if existing.CaptureID != value.CaptureID || !existing.Identity.Equal(value.Identity) ||
			existing.ManifestDigest != value.ManifestDigest || existing.Bytes != value.Bytes ||
			existing.ObjectCount != value.ObjectCount {
			return errors.New("checkpoint ID conflicts with different immutable content")
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO work_checkpoint_pointers(work_id, checkpoint_id, updated_at)
VALUES(?, ?, ?) ON CONFLICT(work_id) DO UPDATE SET checkpoint_id=excluded.checkpoint_id,
updated_at=excluded.updated_at`, value.Identity.WorkID, value.ID,
			time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	policy, err := checkpointPolicy(ctx, tx, value.Identity.SandboxID)
	if err != nil {
		return err
	}
	var used int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes), 0) FROM checkpoints
WHERE sandbox_id = ?`, value.Identity.SandboxID).Scan(&used); err != nil {
		return err
	}
	if used+value.Bytes > policy.MaxBytes {
		return ErrCheckpointQuota
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM checkpoints
WHERE sandbox_id = ?`, value.Identity.SandboxID).Scan(&count); err != nil {
		return err
	}
	if count >= policy.MaxPerBox {
		return ErrCheckpointQuota
	}
	identity := value.Identity
	_, err = tx.ExecContext(ctx, `INSERT INTO checkpoints(
id, capture_id, work_id, project_id, sandbox_id, workspace_epoch,
sandbox_generation, task_id, task_attempt, expected_revision, manifest_digest,
bytes, object_count, pinned, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		value.ID, value.CaptureID, identity.WorkID, identity.ProjectID,
		identity.SandboxID, identity.WorkspaceEpoch, identity.SandboxGeneration,
		identity.TaskID, identity.TaskAttempt, identity.ExpectedRevision,
		value.ManifestDigest, value.Bytes, value.ObjectCount, boolInt(value.Pinned),
		value.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO work_checkpoint_pointers(work_id, checkpoint_id, updated_at)
VALUES(?, ?, ?) ON CONFLICT(work_id) DO UPDATE SET checkpoint_id=excluded.checkpoint_id,
updated_at=excluded.updated_at`, identity.WorkID, value.ID,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CheckpointsForWork(ctx context.Context, workID string) ([]LocalCheckpoint, error) {
	rows, err := s.db.QueryContext(ctx, checkpointSelect+` WHERE work_id = ? ORDER BY created_at, id`, workID)
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

func (s *Store) ApplyCheckpointRetention(ctx context.Context, sandboxID string, now time.Time) ([]LocalCheckpoint, error) {
	policy, err := checkpointPolicy(ctx, s.db, sandboxID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, checkpointSelect+` WHERE sandbox_id = ? ORDER BY work_id, created_at DESC, id DESC`, sandboxID)
	if err != nil {
		return nil, err
	}
	var all []LocalCheckpoint
	for rows.Next() {
		value, scanErr := scanCheckpoint(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		all = append(all, *value)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	pointers := map[string]string{}
	pointerRows, err := s.db.QueryContext(ctx, `SELECT work_id, checkpoint_id FROM work_checkpoint_pointers`)
	if err != nil {
		return nil, err
	}
	for pointerRows.Next() {
		var workID, checkpointID string
		if err := pointerRows.Scan(&workID, &checkpointID); err != nil {
			pointerRows.Close()
			return nil, err
		}
		pointers[workID] = checkpointID
	}
	if err := pointerRows.Close(); err != nil {
		return nil, err
	}
	var removed []LocalCheckpoint
	cutoff := now.Add(-policy.MaxAge)
	protectedCount := 0
	for _, checkpoint := range all {
		if checkpoint.Pinned || pointers[checkpoint.Identity.WorkID] == checkpoint.ID {
			protectedCount++
		}
	}
	remaining := policy.MaxPerBox - protectedCount
	for _, checkpoint := range all {
		protected := checkpoint.Pinned || pointers[checkpoint.Identity.WorkID] == checkpoint.ID
		if protected {
			continue
		}
		if remaining > 0 && !checkpoint.CreatedAt.Before(cutoff) {
			remaining--
			continue
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM checkpoints WHERE id = ?`, checkpoint.ID); err != nil {
			return nil, err
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM continuity_captures WHERE id = ?`, checkpoint.CaptureID); err != nil {
			return nil, err
		}
		removed = append(removed, checkpoint)
	}
	return removed, nil
}

func (s *Store) PutContinuitySource(ctx context.Context, value LocalContinuitySource) error {
	if value.Root == "" || value.Instance == "" || value.LifecycleRevision < 1 ||
		(value.Lifecycle != "running" && value.Lifecycle != "stopped") || value.Report.FormatVersion != 1 {
		return errors.New("invalid host continuity source")
	}
	payload, err := json.Marshal(value.Report)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO continuity_sources(
registered_source_id, report_json, workspace_root, instance, lifecycle,
lifecycle_revision, no_admitted_execution, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(registered_source_id) DO UPDATE SET report_json=excluded.report_json,
workspace_root=excluded.workspace_root, instance=excluded.instance, lifecycle=excluded.lifecycle,
lifecycle_revision=excluded.lifecycle_revision, no_admitted_execution=excluded.no_admitted_execution,
updated_at=excluded.updated_at`, value.Report.RegisteredSourceID, payload, value.Root, value.Instance,
		value.Lifecycle, value.LifecycleRevision, boolInt(value.NoAdmittedExecution),
		time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// MarkContinuitySourceIdle changes only the execution flag for the exact
// observation read by a completed worker. A newer report or lifecycle wins.
func (s *Store) MarkContinuitySourceIdle(ctx context.Context, observed LocalContinuitySource) error {
	if observed.Lifecycle != "running" || observed.LifecycleRevision < 1 || observed.Report.FormatVersion != 1 {
		return errors.New("invalid idle continuity observation")
	}
	payload, err := json.Marshal(observed.Report)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE continuity_sources SET no_admitted_execution=1, updated_at=?
WHERE registered_source_id=? AND report_json=? AND workspace_root=? AND instance=?
AND lifecycle='running' AND lifecycle_revision=?`, time.Now().UTC().Format(time.RFC3339Nano),
		observed.Report.RegisteredSourceID, payload, observed.Root, observed.Instance, observed.LifecycleRevision)
	return err
}

func (s *Store) ContinuitySource(ctx context.Context, id string) (*LocalContinuitySource, error) {
	var value LocalContinuitySource
	var payload []byte
	var noExecution int
	err := s.db.QueryRowContext(ctx, `SELECT report_json, workspace_root, instance, lifecycle,
lifecycle_revision, no_admitted_execution FROM continuity_sources WHERE registered_source_id=?`, id).Scan(
		&payload, &value.Root, &value.Instance, &value.Lifecycle, &value.LifecycleRevision, &noExecution)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &value.Report); err != nil {
		return nil, err
	}
	value.NoAdmittedExecution = noExecution != 0
	return &value, nil
}

func (s *Store) ContinuitySources(ctx context.Context) ([]LocalContinuitySource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT report_json, workspace_root, instance, lifecycle,
lifecycle_revision, no_admitted_execution FROM continuity_sources ORDER BY registered_source_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalContinuitySource
	for rows.Next() {
		var value LocalContinuitySource
		var payload []byte
		var noExecution int
		if err := rows.Scan(&payload, &value.Root, &value.Instance, &value.Lifecycle,
			&value.LifecycleRevision, &noExecution); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &value.Report); err != nil {
			return nil, err
		}
		value.NoAdmittedExecution = noExecution != 0
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) PutContinuityRegistration(ctx context.Context, value LocalContinuityRegistration) error {
	if value.Manifest.FormatVersion != 1 || value.Manifest.Binding.BindingID == "" ||
		(value.ObservedStatus != "verified" && value.ObservedStatus != "revoked" && value.ObservedStatus != "failed") {
		return errors.New("invalid continuity registration")
	}
	payload, err := json.Marshal(value.Manifest)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO continuity_registrations(
binding_id, manifest_json, observed_status, service_generation, receipt_digest, error_code, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?) ON CONFLICT(binding_id) DO UPDATE SET
manifest_json=excluded.manifest_json, observed_status=excluded.observed_status,
service_generation=excluded.service_generation, receipt_digest=excluded.receipt_digest,
error_code=excluded.error_code, updated_at=excluded.updated_at`, value.Manifest.Binding.BindingID,
		payload, value.ObservedStatus, value.ServiceGeneration, value.ReceiptDigest, value.ErrorCode,
		time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ContinuityRegistration(ctx context.Context, bindingID string) (*LocalContinuityRegistration, error) {
	var value LocalContinuityRegistration
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT manifest_json, observed_status, service_generation,
receipt_digest, error_code FROM continuity_registrations WHERE binding_id=?`, bindingID).Scan(
		&payload, &value.ObservedStatus, &value.ServiceGeneration, &value.ReceiptDigest, &value.ErrorCode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &value.Manifest); err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) ContinuityRegistrations(ctx context.Context) ([]LocalContinuityRegistration, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT manifest_json, observed_status, service_generation,
receipt_digest, error_code FROM continuity_registrations ORDER BY binding_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalContinuityRegistration
	for rows.Next() {
		var value LocalContinuityRegistration
		var payload []byte
		if err := rows.Scan(&payload, &value.ObservedStatus, &value.ServiceGeneration,
			&value.ReceiptDigest, &value.ErrorCode); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &value.Manifest); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) AdvanceContinuityLifecycle(ctx context.Context, sourceID string, expected int64, lifecycle string) error {
	if lifecycle != "running" && lifecycle != "stopped" {
		return errors.New("invalid continuity lifecycle")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE continuity_sources SET lifecycle=?, lifecycle_revision=lifecycle_revision+1,
updated_at=? WHERE registered_source_id=? AND lifecycle_revision=?`, lifecycle,
		time.Now().UTC().Format(time.RFC3339Nano), sourceID, expected)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("continuity lifecycle fence changed")
	}
	return nil
}

func (s *Store) PutContinuityBarrier(ctx context.Context, operationID string, request, receipt []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO continuity_barriers(operation_id, request_json, receipt_json, created_at)
VALUES(?, ?, ?, ?) ON CONFLICT(operation_id) DO UPDATE SET request_json=excluded.request_json,
receipt_json=excluded.receipt_json`, operationID, request, receipt, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) DeleteContinuityBarrier(ctx context.Context, operationID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM continuity_barriers WHERE operation_id=?`, operationID)
	return err
}

type ContinuityBarrier struct {
	OperationID      string
	Request, Receipt []byte
}

func (s *Store) ContinuityBarriers(ctx context.Context) ([]ContinuityBarrier, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT operation_id, request_json, receipt_json FROM continuity_barriers ORDER BY operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []ContinuityBarrier
	for rows.Next() {
		var v ContinuityBarrier
		if err := rows.Scan(&v.OperationID, &v.Request, &v.Receipt); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func (s *Store) PutContinuityOperationReport(ctx context.Context, report model.ContinuityOperationReportV1) error {
	if report.RequestDigest == "" {
		return errors.New("continuity operation report is missing its host replay digest")
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO continuity_remote_operations(operation_id, request_digest, report_json, updated_at)
VALUES(?, ?, ?, ?) ON CONFLICT(operation_id) DO UPDATE SET request_digest=excluded.request_digest,
report_json=excluded.report_json, updated_at=excluded.updated_at`,
		report.OperationID, report.RequestDigest, payload, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ContinuityOperationReports(ctx context.Context) ([]model.ContinuityOperationReportV1, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT request_digest, report_json FROM continuity_remote_operations ORDER BY operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.ContinuityOperationReportV1
	for rows.Next() {
		var payload []byte
		var v model.ContinuityOperationReportV1
		if err := rows.Scan(&v.RequestDigest, &payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// RetireContinuityOperationReports atomically retires the local terminal
// continuity-operation outbox rows the caller's eligible predicate accepts.
// One transaction reads the barrier rows and the nonterminal local continuity
// operations, offers every structurally addressable outbox row to the
// predicate with those live-state fences, writes an immutable retirement
// tombstone and removes the outbox row. A callback error, a write error or a
// conflicting existing tombstone leaves every outbox row and every retained
// receipt exactly as it was: a partial acknowledgement can neither lose a
// receipt nor advance any revision. A row whose stored JSON is unparseable or
// whose embedded operation ID does not match its primary key is never offered
// to the predicate and never retired.
func (s *Store) RetireContinuityOperationReports(
	ctx context.Context,
	eligible func(ContinuityOperationCandidate) (bool, error),
	reason string,
) ([]model.ContinuityOperationReportV1, error) {
	if eligible == nil || strings.TrimSpace(reason) == "" || len(reason) > 160 {
		return nil, errors.New("invalid continuity operation retirement request")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	barriers := map[string]bool{}
	barrierRows, err := tx.QueryContext(ctx, `SELECT operation_id FROM continuity_barriers`)
	if err != nil {
		return nil, err
	}
	for barrierRows.Next() {
		var operationID string
		if err := barrierRows.Scan(&operationID); err != nil {
			barrierRows.Close()
			return nil, err
		}
		barriers[operationID] = true
	}
	if err := barrierRows.Err(); err != nil {
		barrierRows.Close()
		return nil, err
	}
	if err := barrierRows.Close(); err != nil {
		return nil, err
	}

	live := map[string]bool{}
	liveRows, err := tx.QueryContext(ctx,
		`SELECT id FROM continuity_operations WHERE state NOT IN ('captured','succeeded','failed')`)
	if err != nil {
		return nil, err
	}
	for liveRows.Next() {
		var operationID string
		if err := liveRows.Scan(&operationID); err != nil {
			liveRows.Close()
			return nil, err
		}
		live[operationID] = true
	}
	if err := liveRows.Err(); err != nil {
		liveRows.Close()
		return nil, err
	}
	if err := liveRows.Close(); err != nil {
		return nil, err
	}

	type storedRow struct {
		operationID string
		digest      string
		payload     []byte
	}
	var stored []storedRow
	rows, err := tx.QueryContext(ctx,
		`SELECT operation_id, request_digest, report_json FROM continuity_remote_operations ORDER BY operation_id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var row storedRow
		if err := rows.Scan(&row.operationID, &row.digest, &row.payload); err != nil {
			rows.Close()
			return nil, err
		}
		stored = append(stored, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	retired := make([]model.ContinuityOperationReportV1, 0)
	for _, row := range stored {
		var report model.ContinuityOperationReportV1
		if err := json.Unmarshal(row.payload, &report); err != nil {
			continue
		}
		if report.OperationID != row.operationID {
			continue
		}
		report.RequestDigest = row.digest
		decision, err := eligible(ContinuityOperationCandidate{
			Report: report, BarrierPresent: barriers[row.operationID],
			LocalOperationLive: live[row.operationID+"_capture"] || live[row.operationID+"_checkpoint"],
		})
		if err != nil {
			return nil, err
		}
		if !decision {
			continue
		}
		var existingDigest string
		var existingPayload []byte
		err = tx.QueryRowContext(ctx,
			`SELECT request_digest, report_json FROM continuity_remote_operation_retirements WHERE operation_id=?`,
			row.operationID).Scan(&existingDigest, &existingPayload)
		switch {
		case err == nil:
			if existingDigest != row.digest || !bytes.Equal(existingPayload, row.payload) {
				// Conflicting duplicate: the retained acknowledgement tombstone
				// is immutable, and the conflicting outbox row stays untouched.
				continue
			}
		case errors.Is(err, sql.ErrNoRows):
		default:
			return nil, err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO continuity_remote_operation_retirements(
operation_id, request_digest, report_json, reason, retired_at) VALUES(?,?,?,?,?)`,
			row.operationID, row.digest, row.payload, reason,
			time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM continuity_remote_operations WHERE operation_id=?`, row.operationID); err != nil {
			return nil, err
		}
		retired = append(retired, report)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return retired, nil
}

func (s *Store) ContinuityOperationRetirements(ctx context.Context) ([]ContinuityOperationRetirement, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT request_digest, report_json, reason, retired_at FROM continuity_remote_operation_retirements ORDER BY retired_at, operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []ContinuityOperationRetirement
	for rows.Next() {
		var value ContinuityOperationRetirement
		var payload []byte
		var retiredAt string
		if err := rows.Scan(&value.Report.RequestDigest, &payload, &value.Reason, &retiredAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &value.Report); err != nil {
			return nil, err
		}
		value.RetiredAt, err = time.Parse(time.RFC3339Nano, retiredAt)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

// ContinuityOperationRetirement reads one acknowledged-operation tombstone by
// operation ID. A missing tombstone returns (nil, nil); the exact retained
// request digest and report payload are returned for terminal replay fences.
func (s *Store) ContinuityOperationRetirement(ctx context.Context, operationID string) (*ContinuityOperationRetirement, error) {
	var value ContinuityOperationRetirement
	var payload []byte
	var retiredAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT request_digest, report_json, reason, retired_at FROM continuity_remote_operation_retirements WHERE operation_id=?`,
		operationID).Scan(&value.Report.RequestDigest, &payload, &value.Reason, &retiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &value.Report); err != nil {
		return nil, err
	}
	value.RetiredAt, err = time.Parse(time.RFC3339Nano, retiredAt)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) PutManagedProject(ctx context.Context, value LocalManagedProject) error {
	existing, err := s.ManagedProject(ctx, value.Report.SelectionID)
	if err != nil {
		return err
	}
	if existing != nil && !managedProjectWriteAllowed(*existing, value) {
		return ErrManagedProjectConflict
	}
	report, err := json.Marshal(value.Report)
	if err != nil {
		return err
	}
	private, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO managed_workspace_projects(
selection_id, project_id, sandbox_id, sandbox_generation, team_id, report_json, private_json, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(selection_id) DO UPDATE SET project_id=excluded.project_id,
sandbox_id=excluded.sandbox_id, sandbox_generation=excluded.sandbox_generation,
team_id=excluded.team_id, report_json=excluded.report_json,
private_json=excluded.private_json, updated_at=excluded.updated_at`,
		value.Report.SelectionID, value.Report.ProjectID, value.Report.SandboxID,
		value.Report.SandboxGeneration, value.TeamID, report, private,
		time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// BindManagedProjectImageIdentity is the narrow store admission and write path
// for the single durable transition A25 authorizes: one existing managed
// project record whose durable image identity is still exactly zero may bind
// the fully nonzero durable object identity of the workspace image its
// unchanged recorded device is loop-backed by. It is deliberately not a
// generic managed-project write: the caller must pass the record with that
// identity set, the stored row must be exactly that record with the identity
// zeroed, and the stored record must be the ready, available, self-attesting
// team project on one nonzero recorded device carrying the exact anchor and
// project-root inodes. Every other durable field, the published report and the
// row's other columns are never written, and a record that already carries an
// identity is immutable: it is never refreshed or replaced. The stored row is
// read, compared and written inside one transaction whose update is
// conditional on the exact private bytes it read, so a record that moved under
// the caller stays untouched and the bind is refused. Read and write errors -
// including a compare that no longer matches - are returned, never turned into
// a permissive result.
func (s *Store) BindManagedProjectImageIdentity(ctx context.Context, expected LocalManagedProject) error {
	identity := expected.ImageIdentity
	if identity.Device == 0 || identity.Inode == 0 || identity.Size == 0 {
		return ErrManagedProjectConflict
	}
	preBind := expected
	preBind.ImageIdentity = ManagedProjectImageIdentity{}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var payload []byte
	err = tx.QueryRowContext(ctx,
		`SELECT private_json FROM managed_workspace_projects WHERE selection_id=?`,
		preBind.Report.SelectionID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrManagedProjectConflict
	}
	if err != nil {
		return err
	}
	var stored LocalManagedProject
	if err := json.Unmarshal(payload, &stored); err != nil {
		return err
	}
	if !bindableManagedProjectImage(preBind, stored) {
		return ErrManagedProjectConflict
	}
	stored.ImageIdentity = identity
	private, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE managed_workspace_projects SET private_json=?, updated_at=?
WHERE selection_id=? AND private_json=?`,
		private, time.Now().UTC().Format(time.RFC3339Nano), stored.Report.SelectionID, payload)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrManagedProjectConflict
	}
	return tx.Commit()
}

// bindableManagedProjectImage reports whether the durable row is exactly the
// re-proven pre-bind record of the one authorized transition. The store cannot
// observe the filesystem, so it holds the caller to the record it read before
// its observation and refuses every shape outside the ready, available,
// self-attesting team project with one nonzero recorded device, exact recorded
// anchor and project-root inodes, nonempty recorded mount provenance, a
// nonempty root attestation and an exactly zero durable image identity.
func bindableManagedProjectImage(preBind, stored LocalManagedProject) bool {
	if stored.ImageIdentity != (ManagedProjectImageIdentity{}) {
		return false
	}
	if stored.Phase != "ready" || stored.Report.Designation != "team_project" ||
		stored.Report.Availability != "available" || stored.Report.RootAttestation == "" {
		return false
	}
	if stored.AnchorDevice == 0 || stored.AnchorDevice != stored.RootDevice ||
		stored.AnchorInode == 0 || stored.RootInode == 0 ||
		stored.AnchorMount == "" || stored.RootMount == "" {
		return false
	}
	return reflect.DeepEqual(preBind, stored)
}

// managedProjectWriteAllowed reports whether a candidate may replace a stored
// managed-project record. Every durable identity, allocation, config, path and
// anchoring field stays pinned: only the documented workspace remount may move
// the loop device of the unchanged image. A moved root attestation must be
// justified by that same remount, or by a change of at least one attested input
// field with any remount provenance cleared; the superseded remount provenance
// only ever moves together with a re-attestation.
func managedProjectWriteAllowed(existing, value LocalManagedProject) bool {
	if pinnedManagedProjectIdentityDiffers(existing, value) {
		return remountAttestationAdoption(existing, value)
	}
	if existing.Report.RootAttestation == value.Report.RootAttestation {
		return value.SupersededRootAttestation == existing.SupersededRootAttestation
	}
	if remountAttestationAdoption(existing, value) {
		return true
	}
	if value.SupersededRootAttestation != "" {
		return false
	}
	return existing.ConfigDigest != value.ConfigDigest ||
		managedServiceReference(existing.Report.ServiceRegistrationID) != managedServiceReference(value.Report.ServiceRegistrationID) ||
		existing.ScopeRevision != value.ScopeRevision ||
		existing.AnchorDevice != value.AnchorDevice || existing.AnchorInode != value.AnchorInode || existing.AnchorMount != value.AnchorMount ||
		existing.RootDevice != value.RootDevice || existing.RootInode != value.RootInode || existing.RootMount != value.RootMount
}

func managedServiceReference(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// pinnedManagedProjectIdentityDiffers reports whether a candidate record moves
// any durable field of the stored managed-project record: identity, allocation
// and config digests, paths, container root, phase-independent anchoring, the
// device/inode objects that carry the workspace image, and the durable backing
// image object itself.
func pinnedManagedProjectIdentityDiffers(existing, value LocalManagedProject) bool {
	return existing.Report.ProjectID != value.Report.ProjectID ||
		existing.Report.WorkspaceEpoch != value.Report.WorkspaceEpoch ||
		existing.Report.SandboxID != value.Report.SandboxID ||
		existing.Report.SandboxGeneration != value.Report.SandboxGeneration ||
		existing.ServerID != value.ServerID || existing.TeamID != value.TeamID || existing.MemberID != value.MemberID ||
		existing.AllocationDigest != value.AllocationDigest || existing.Anchor != value.Anchor ||
		existing.AnchorDevice != value.AnchorDevice || existing.AnchorInode != value.AnchorInode || existing.AnchorMount != value.AnchorMount ||
		existing.HostRoot != value.HostRoot || existing.ContainerRoot != value.ContainerRoot ||
		!existing.ImageIdentity.SameDurableObject(value.ImageIdentity) ||
		existing.RootInode != 0 && (existing.RootDevice != value.RootDevice || existing.RootInode != value.RootInode || existing.RootMount != value.RootMount)
}

// remountAttestationAdoption reports whether a managed-project record may adopt
// the loop device of the documented workspace remount, the operation Runtime
// itself performs when it re-mounts a workspace image that a host restart lost.
// The workspace image and every durable object in the record stay exactly as
// they are: only the single loop device that currently carries the same anchor
// and project root may change, the root attestation derived from it may be
// recomputed, the persisted backing image identity never moves, and the
// superseded attestation is retained so a manifest that still carries the
// pre-remount authority stays classifiable. Anything else remains an immutable
// identity conflict. The candidate must be derived from the stored record.
func remountAttestationAdoption(existing, value LocalManagedProject) bool {
	if existing.AnchorDevice == 0 || existing.AnchorDevice != existing.RootDevice ||
		value.AnchorDevice == 0 || value.AnchorDevice != value.RootDevice ||
		value.AnchorDevice == existing.AnchorDevice {
		return false
	}
	if value.Report.RootAttestation == "" || value.Report.RootAttestation == existing.Report.RootAttestation ||
		value.SupersededRootAttestation != existing.Report.RootAttestation {
		return false
	}
	before, candidate := existing, value
	before.SupersededRootAttestation, candidate.SupersededRootAttestation = "", ""
	before.AnchorDevice, candidate.AnchorDevice = 0, 0
	before.RootDevice, candidate.RootDevice = 0, 0
	before.Report.RootAttestation, candidate.Report.RootAttestation = "", ""
	return reflect.DeepEqual(before, candidate)
}

func (s *Store) ManagedProject(ctx context.Context, selectionID string) (*LocalManagedProject, error) {
	return managedProjectRow(ctx, s.db, selectionID)
}

func managedProjectRow(ctx context.Context, q rowQuerier, selectionID string) (*LocalManagedProject, error) {
	var payload []byte
	err := q.QueryRowContext(ctx, `SELECT private_json FROM managed_workspace_projects WHERE selection_id=?`, selectionID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value LocalManagedProject
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) ManagedProjects(ctx context.Context) ([]LocalManagedProject, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT private_json FROM managed_workspace_projects ORDER BY selection_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalManagedProject
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var value LocalManagedProject
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) ManagedProjectForTeam(ctx context.Context, sandboxID string, generation int64, teamID string) (*LocalManagedProject, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT private_json FROM managed_workspace_projects
WHERE sandbox_id=? AND sandbox_generation=? AND team_id=? ORDER BY selection_id LIMIT 1`,
		sandboxID, generation, teamID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value LocalManagedProject
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) ManagedProjectForRoot(ctx context.Context, sandboxID string, generation int64, hostRoot string) (*LocalManagedProject, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT private_json FROM managed_workspace_projects
WHERE sandbox_id=? AND sandbox_generation=?`, sandboxID, generation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var value LocalManagedProject
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, err
		}
		if value.HostRoot == hostRoot {
			return &value, nil
		}
	}
	return nil, rows.Err()
}

func (s *Store) PutManagedServiceIntent(ctx context.Context, value LocalManagedService) error {
	id := value.Manifest.Identity.ServiceRegistrationID
	existing, err := s.ManagedService(ctx, id)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.Phase == "retired" && sameManagedServicePrincipal(existing.Manifest.Identity, value.Manifest.Identity) &&
			value.Manifest.Identity.ExpectedServiceGeneration > existing.Manifest.Identity.ExpectedServiceGeneration {
			manifest, err := json.Marshal(value.Manifest)
			if err != nil {
				return err
			}
			_, err = s.db.ExecContext(ctx, `UPDATE managed_services SET manifest_json=?, phase=?, process_instance=?, port=?, creation_dispatched=0, service_generation=?, report_json=NULL, error_code='', updated_at=? WHERE service_registration_id=?`,
				manifest, value.Phase, value.ProcessInstance, value.Port,
				value.Manifest.Identity.ExpectedServiceGeneration, time.Now().UTC().Format(time.RFC3339Nano), id)
			return err
		}
		if existing.Manifest.Identity != value.Manifest.Identity || existing.Manifest.ConfigDigest != value.Manifest.ConfigDigest || existing.ProcessInstance != value.ProcessInstance || existing.Port != value.Port {
			return ErrManagedServiceConflict
		}
		if value.Manifest.DesiredRevision < existing.Manifest.DesiredRevision {
			return ErrManagedServiceConflict
		}
		if value.Manifest.ActionRevision == existing.Manifest.ActionRevision && !reflect.DeepEqual(value.Manifest, existing.Manifest) {
			// The one same-action-revision change the backend-ratified A5
			// workspace remount may produce is decided and written against the
			// durable managed-project record on a single store transaction, so
			// the adoption can never rest on the caller's manifest or on a
			// project authority that moved between the check and the write.
			adopted, err := s.adoptRegisteredManagedServiceManifest(ctx, id, value)
			if err != nil {
				return err
			}
			if !adopted {
				return ErrManagedServiceConflict
			}
			return nil
		}
		if value.Manifest.ActionRevision < existing.Manifest.ActionRevision &&
			!terminalManagedServiceReissue(existing, value) {
			return ErrManagedServiceConflict
		}
		payload, err := json.Marshal(value.Manifest)
		if err != nil {
			return err
		}
		_, err = s.db.ExecContext(ctx, `UPDATE managed_services SET manifest_json=?, updated_at=? WHERE service_registration_id=?`, payload, time.Now().UTC().Format(time.RFC3339Nano), id)
		return err
	}
	manifest, err := json.Marshal(value.Manifest)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO managed_services(service_registration_id, manifest_json, phase, process_instance, port, creation_dispatched, service_generation, report_json, error_code, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, id, manifest, value.Phase, value.ProcessInstance, value.Port, boolInt(value.CreationDispatched), value.Manifest.Identity.ExpectedServiceGeneration, nil, value.ErrorCode, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func sameManagedServicePrincipal(left, right model.ManagedServiceIdentityV1) bool {
	left.ExpectedServiceGeneration = 0
	right.ExpectedServiceGeneration = 0
	return left == right
}

// terminalManagedServiceReissue reports whether a retained terminal record may
// adopt a re-issued terminal operation whose team-level action revision is
// lower than the record's. Both manifests must target the same terminal
// desired state and the local execution must already be terminal; the caller
// has already proven the immutable identity, config digest, process instance
// and port all match. Any other revision regression stays immutable.
func terminalManagedServiceReissue(existing *LocalManagedService, value LocalManagedService) bool {
	if existing == nil || existing.Manifest.DesiredState != value.Manifest.DesiredState {
		return false
	}
	terminal := func(state string) bool { return state == "stopped" || state == "retired" }
	return terminal(value.Manifest.DesiredState) && terminal(existing.Phase)
}

// rowQuerier is the narrow read shape shared by the store's database handle and
// a decision transaction, so a read-decide-write guard can run on the same
// connection that performs its write.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// adoptRegisteredManagedServiceManifest decides and performs the one
// same-action-revision adoption the backend-ratified A5 workspace remount
// authorizes. The service row and the selected managed-project record are both
// read inside the single transaction that writes the manifest, so the decision
// is made against durable state, never the caller's manifest alone, and no
// concurrent store writer can move the project authority between the check and
// the write. Only manifest_json and the ordinary write timestamp move: the
// phase, report, error, creation-dispatched flag, service generation, process
// instance and port are never written, so adoption cannot duplicate creation or
// replace the retained native session/process facts.
func (s *Store) adoptRegisteredManagedServiceManifest(ctx context.Context, id string, value LocalManagedService) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	existing, err := managedServiceRow(ctx, tx, id)
	if err != nil {
		return false, err
	}
	if existing == nil {
		return false, nil
	}
	adopted, err := managedServiceRemountAdoption(ctx, tx, existing, value)
	if err != nil {
		return false, err
	}
	if !adopted {
		return false, nil
	}
	payload, err := json.Marshal(value.Manifest)
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE managed_services SET manifest_json=?, updated_at=? WHERE service_registration_id=?`,
		payload, time.Now().UTC().Format(time.RFC3339Nano), id); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// managedServiceRemountAdoption reports whether the retained record of a ready,
// active managed service may adopt the backend-ratified manifest of the
// documented workspace remount at an unchanged action revision. The manifest
// must differ from the stored manifest in exactly two workspace fields: the
// scope revision advancing exactly one, and the root attestation changing to
// the local managed-project record's current attestation, whose retained
// superseded provenance still names the stored root. Every other manifest
// field, revision, identity, digest and the exact selected project tuple stays
// untouched, and the record must be the ready, available team project of that
// tuple carrying the documented remount's durable backing-image provenance.
// The caller's manifest alone never admits anything: the authority to adopt is
// read from the stored record, which only the ordinary catalog paths write.
//
// The record's own ScopeRevision is deliberately not compared with the incoming
// workspace scope: a runtime-written team-project record retains the creation
// scope (1, or 0 for a refresh-created record) while the trusted backend
// manifest advances the service workspace scope independently. The incoming
// scope is bound by the exact stored+1 advance and by the record's
// current/superseded root authority instead.
func managedServiceRemountAdoption(ctx context.Context, q rowQuerier, existing *LocalManagedService, value LocalManagedService) (bool, error) {
	if existing == nil || existing.Phase != "ready" {
		return false, nil
	}
	stored, incoming := existing.Manifest, value.Manifest
	if stored.DesiredState != "active" || incoming.DesiredState != "active" || stored.Workspace.Designation != "team_project" {
		return false, nil
	}
	if existing.Manifest.Identity != incoming.Identity || existing.Manifest.ConfigDigest != incoming.ConfigDigest ||
		existing.ProcessInstance != value.ProcessInstance || existing.Port != value.Port {
		return false, nil
	}
	if incoming.FormatVersion != stored.FormatVersion || incoming.OperationID != stored.OperationID ||
		incoming.ActionRevision != stored.ActionRevision || incoming.DesiredRevision != stored.DesiredRevision ||
		incoming.SessionMode != stored.SessionMode || !reflect.DeepEqual(incoming.Authority, stored.Authority) ||
		incoming.Profile != stored.Profile || incoming.Instructions != stored.Instructions {
		return false, nil
	}
	if incoming.Workspace.SelectionID != stored.Workspace.SelectionID ||
		incoming.Workspace.ProjectID != stored.Workspace.ProjectID ||
		incoming.Workspace.WorkspaceEpoch != stored.Workspace.WorkspaceEpoch ||
		incoming.Workspace.Designation != stored.Workspace.Designation {
		return false, nil
	}
	if stored.Workspace.RootAttestation == "" || incoming.Workspace.RootAttestation == "" ||
		incoming.Workspace.RootAttestation == stored.Workspace.RootAttestation ||
		stored.Workspace.ScopeRevision < 1 || incoming.Workspace.ScopeRevision != stored.Workspace.ScopeRevision+1 {
		return false, nil
	}
	// Prove the only differences are those two ratified workspace fields: the
	// stored manifest with exactly them applied must reproduce the incoming
	// manifest.
	ratified := stored
	ratified.Workspace.ScopeRevision = incoming.Workspace.ScopeRevision
	ratified.Workspace.RootAttestation = incoming.Workspace.RootAttestation
	if !reflect.DeepEqual(ratified, incoming) {
		return false, nil
	}
	record, err := managedProjectRow(ctx, q, incoming.Workspace.SelectionID)
	if err != nil {
		return false, err
	}
	if record == nil {
		return false, nil
	}
	if record.Phase != "ready" || record.Report.Availability != "available" ||
		record.Report.SelectionID != incoming.Workspace.SelectionID ||
		record.Report.ProjectID != incoming.Workspace.ProjectID ||
		record.Report.WorkspaceEpoch != incoming.Workspace.WorkspaceEpoch ||
		record.Report.SandboxID != incoming.Identity.SandboxID ||
		record.Report.SandboxGeneration != incoming.Identity.SandboxGeneration ||
		managedServiceReference(record.Report.ServiceRegistrationID) != incoming.Identity.ServiceRegistrationID ||
		record.Report.Designation != stored.Workspace.Designation || record.ConfigDigest != incoming.ConfigDigest {
		return false, nil
	}
	// The A5 remount provenance: the record's current attestation is exactly the
	// incoming ratified root and its retained superseded attestation is exactly
	// the stored root, so only the A5 re-observation and the backend ratification
	// of that observation admit the change.
	if record.Report.RootAttestation != incoming.Workspace.RootAttestation ||
		record.SupersededRootAttestation == "" || record.SupersededRootAttestation != stored.Workspace.RootAttestation {
		return false, nil
	}
	// The A5 durable backing-image fence: the record must be the single-image
	// root object the documented remount re-attests and must carry the durable
	// image identity the A5 re-observation proved.
	if record.ImageIdentity == (ManagedProjectImageIdentity{}) || record.AnchorDevice == 0 || record.AnchorDevice != record.RootDevice {
		return false, nil
	}
	return true, nil
}

func (s *Store) ManagedService(ctx context.Context, id string) (*LocalManagedService, error) {
	return managedServiceRow(ctx, s.db, id)
}

func managedServiceRow(ctx context.Context, q rowQuerier, id string) (*LocalManagedService, error) {
	var manifestJSON, reportJSON []byte
	var value LocalManagedService
	var dispatched int
	err := q.QueryRowContext(ctx, `SELECT manifest_json,phase,process_instance,port,creation_dispatched,service_generation,report_json,error_code FROM managed_services WHERE service_registration_id=?`, id).Scan(&manifestJSON, &value.Phase, &value.ProcessInstance, &value.Port, &dispatched, &value.ServiceGeneration, &reportJSON, &value.ErrorCode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(manifestJSON, &value.Manifest); err != nil {
		return nil, err
	}
	if len(reportJSON) != 0 {
		if err := json.Unmarshal(reportJSON, &value.Report); err != nil {
			return nil, err
		}
	}
	value.CreationDispatched = dispatched == 1
	return &value, nil
}

func (s *Store) ManagedServices(ctx context.Context) ([]LocalManagedService, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT service_registration_id FROM managed_services ORDER BY service_registration_id`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	var values []LocalManagedService
	for _, id := range ids {
		value, err := s.ManagedService(ctx, id)
		if err != nil {
			return nil, err
		}
		values = append(values, *value)
	}
	return values, nil
}

func (s *Store) PutContinuationPreparation(ctx context.Context, value LocalContinuationPreparation) error {
	if value.Manifest.OperationID == "" || value.Phase != "preparing" || value.Report != nil {
		return ErrContinuationConflict
	}
	existing, err := s.ContinuationPreparation(ctx, value.Manifest.OperationID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Manifest, value.Manifest) {
			return ErrContinuationConflict
		}
		return nil
	}
	manifest, err := json.Marshal(value.Manifest)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO continuation_preparations(operation_id, manifest_json, phase, report_json, updated_at)
VALUES(?, ?, 'preparing', NULL, ?)`, value.Manifest.OperationID, manifest, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ContinuationPreparation(ctx context.Context, operationID string) (*LocalContinuationPreparation, error) {
	var manifest, report []byte
	var phase string
	err := s.db.QueryRowContext(ctx, `SELECT manifest_json, phase, report_json FROM continuation_preparations WHERE operation_id=?`, operationID).Scan(&manifest, &phase, &report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	value := &LocalContinuationPreparation{Phase: phase}
	if err := json.Unmarshal(manifest, &value.Manifest); err != nil {
		return nil, err
	}
	if len(report) != 0 {
		value.Report = &model.ContinuationReportV1{}
		if err := json.Unmarshal(report, value.Report); err != nil {
			return nil, err
		}
	}
	return value, nil
}

func (s *Store) ContinuationPreparations(ctx context.Context) ([]LocalContinuationPreparation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT manifest_json, phase, report_json FROM continuation_preparations ORDER BY operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalContinuationPreparation
	for rows.Next() {
		var manifest, report []byte
		var value LocalContinuationPreparation
		if err := rows.Scan(&manifest, &value.Phase, &report); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(manifest, &value.Manifest); err != nil {
			return nil, err
		}
		if len(report) != 0 {
			value.Report = &model.ContinuationReportV1{}
			if err := json.Unmarshal(report, value.Report); err != nil {
				return nil, err
			}
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) CompleteContinuationPreparation(ctx context.Context, operationID string, report model.ContinuationReportV1) error {
	existing, err := s.ContinuationPreparation(ctx, operationID)
	if err != nil {
		return err
	}
	if existing == nil || !continuationReportMatches(existing.Manifest, report) {
		return ErrContinuationConflict
	}
	if existing.Report != nil {
		if !reflect.DeepEqual(*existing.Report, report) {
			return ErrContinuationConflict
		}
		return nil
	}
	validReady := report.Status == "ready" && report.Baseline != nil && report.ErrorCode == nil
	validFailed := report.Status == "failed" && report.Baseline == nil && report.ErrorCode != nil &&
		*report.ErrorCode != "" && len(*report.ErrorCode) <= 80
	if !validReady && !validFailed {
		return ErrContinuationConflict
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE continuation_preparations SET phase=?, report_json=?, updated_at=? WHERE operation_id=? AND report_json IS NULL`, report.Status, payload, time.Now().UTC().Format(time.RFC3339Nano), operationID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrContinuationConflict
	}
	return nil
}

func continuationReportMatches(manifest model.ContinuationManifestV1, report model.ContinuationReportV1) bool {
	return report.FormatVersion == manifest.FormatVersion && report.OperationID == manifest.OperationID && report.Action == manifest.Action &&
		report.DesiredRevision == manifest.DesiredRevision && reflect.DeepEqual(report.Identity, manifest.Identity) &&
		reflect.DeepEqual(report.Binding, manifest.Binding) && reflect.DeepEqual(report.Checkpoint, manifest.Checkpoint) &&
		reflect.DeepEqual(report.Target, manifest.Target) && report.ContextDigest == manifest.Context.Digest
}

func (s *Store) PutContinuationRelease(ctx context.Context, value LocalContinuationRelease) error {
	if value.Manifest.OperationID == "" || value.Phase != "releasing" || value.Report != nil {
		return ErrContinuationConflict
	}
	existing, err := s.ContinuationRelease(ctx, value.Manifest.OperationID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Manifest, value.Manifest) {
			return ErrContinuationConflict
		}
		return nil
	}
	payload, err := json.Marshal(value.Manifest)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO continuation_releases(operation_id, manifest_json, phase, report_json, updated_at)
VALUES(?, ?, 'releasing', NULL, ?)`, value.Manifest.OperationID, payload, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ContinuationRelease(ctx context.Context, operationID string) (*LocalContinuationRelease, error) {
	var manifest, report []byte
	var phase string
	err := s.db.QueryRowContext(ctx, `SELECT manifest_json, phase, report_json FROM continuation_releases WHERE operation_id=?`, operationID).Scan(&manifest, &phase, &report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	value := &LocalContinuationRelease{Phase: phase}
	if err := json.Unmarshal(manifest, &value.Manifest); err != nil {
		return nil, err
	}
	if len(report) != 0 {
		value.Report = &model.ContinuationReleaseReportV1{}
		if err := json.Unmarshal(report, value.Report); err != nil {
			return nil, err
		}
	}
	return value, nil
}

func (s *Store) ContinuationReleases(ctx context.Context) ([]LocalContinuationRelease, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT manifest_json, phase, report_json FROM continuation_releases ORDER BY operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalContinuationRelease
	for rows.Next() {
		var manifest, report []byte
		var value LocalContinuationRelease
		if err := rows.Scan(&manifest, &value.Phase, &report); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(manifest, &value.Manifest); err != nil {
			return nil, err
		}
		if len(report) != 0 {
			value.Report = &model.ContinuationReleaseReportV1{}
			if err := json.Unmarshal(report, value.Report); err != nil {
				return nil, err
			}
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) CompleteContinuationRelease(ctx context.Context, operationID string, report model.ContinuationReleaseReportV1) error {
	existing, err := s.ContinuationRelease(ctx, operationID)
	if err != nil {
		return err
	}
	if existing == nil || !continuationReleaseReportMatches(existing.Manifest, report) {
		return ErrContinuationConflict
	}
	if existing.Report != nil {
		if !reflect.DeepEqual(*existing.Report, report) {
			return ErrContinuationConflict
		}
		return nil
	}
	validReleased := report.Status == "released" && report.ErrorCode == nil
	validFailed := report.Status == "failed" && report.ErrorCode != nil && *report.ErrorCode != "" && len(*report.ErrorCode) <= 80
	if (!validReleased && !validFailed) || report.ReceiptDigest == "" {
		return ErrContinuationConflict
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE continuation_releases SET phase=?, report_json=?, updated_at=? WHERE operation_id=? AND report_json IS NULL`, report.Status, payload, time.Now().UTC().Format(time.RFC3339Nano), operationID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrContinuationConflict
	}
	return nil
}

func continuationReleaseReportMatches(manifest model.ContinuationReleaseManifestV1, report model.ContinuationReleaseReportV1) bool {
	return report.FormatVersion == manifest.FormatVersion && report.OperationID == manifest.OperationID && report.Action == manifest.Action &&
		report.DesiredRevision == manifest.DesiredRevision && reflect.DeepEqual(report.Identity, manifest.Identity) &&
		reflect.DeepEqual(report.Binding, manifest.Binding) && reflect.DeepEqual(report.Checkpoint, manifest.Checkpoint) &&
		reflect.DeepEqual(report.Target, manifest.Target) && reflect.DeepEqual(report.Context, manifest.Context) && report.Reason == manifest.Reason
}

func (s *Store) PutContinuationHandoffPreparation(ctx context.Context, value LocalContinuationHandoffPreparation) error {
	if value.Manifest.OperationID == "" || value.Phase != "allocating" || value.Report != nil {
		return ErrContinuationHandoffConflict
	}
	existing, err := s.ContinuationHandoffPreparation(ctx, value.Manifest.OperationID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Manifest, value.Manifest) {
			return ErrContinuationHandoffConflict
		}
		return nil
	}
	payload, err := json.Marshal(value.Manifest)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO continuation_handoff_preparations(operation_id,manifest_json,phase,target_selection_id,mapped_source_id,report_json,updated_at) VALUES(?,?,'allocating','', '',NULL,?)`,
		value.Manifest.OperationID, payload, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrContinuationHandoffConflict
	}
	return err
}

func (s *Store) ContinuationHandoffPreparation(ctx context.Context, operationID string) (*LocalContinuationHandoffPreparation, error) {
	var manifest, report []byte
	var value LocalContinuationHandoffPreparation
	err := s.db.QueryRowContext(ctx, `SELECT manifest_json,phase,target_selection_id,report_json FROM continuation_handoff_preparations WHERE operation_id=?`, operationID).
		Scan(&manifest, &value.Phase, &value.TargetSelectionID, &report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(manifest, &value.Manifest); err != nil {
		return nil, err
	}
	if len(report) != 0 {
		value.Report = &model.ContinuationHandoffReportV1{}
		if err := json.Unmarshal(report, value.Report); err != nil {
			return nil, err
		}
	}
	return &value, nil
}

func (s *Store) ContinuationHandoffPreparations(ctx context.Context) ([]LocalContinuationHandoffPreparation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT manifest_json,phase,target_selection_id,report_json FROM continuation_handoff_preparations ORDER BY operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalContinuationHandoffPreparation
	for rows.Next() {
		var value LocalContinuationHandoffPreparation
		var manifest, report []byte
		if err := rows.Scan(&manifest, &value.Phase, &value.TargetSelectionID, &report); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(manifest, &value.Manifest); err != nil {
			return nil, err
		}
		if len(report) != 0 {
			value.Report = &model.ContinuationHandoffReportV1{}
			if err := json.Unmarshal(report, value.Report); err != nil {
				return nil, err
			}
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) ContinuationHandoffBySource(ctx context.Context, sourceID string) (*LocalContinuationHandoffPreparation, error) {
	var operationID string
	err := s.db.QueryRowContext(ctx, `SELECT operation_id FROM continuation_handoff_preparations WHERE mapped_source_id=?`, sourceID).Scan(&operationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.ContinuationHandoffPreparation(ctx, operationID)
}

func (s *Store) SetContinuationHandoffPhase(ctx context.Context, operationID, phase, selectionID string) error {
	switch phase {
	case "allocating", "materializing", "workspace_registered", "recovery_required", "registration_pending", "admission_pending":
	default:
		return ErrContinuationHandoffConflict
	}
	existing, err := s.ContinuationHandoffPreparation(ctx, operationID)
	if err != nil || existing == nil || existing.Report != nil {
		return errors.Join(err, ErrContinuationHandoffConflict)
	}
	if existing.TargetSelectionID != "" && selectionID != existing.TargetSelectionID {
		return ErrContinuationHandoffConflict
	}
	if selectionID == "" {
		selectionID = existing.TargetSelectionID
	}
	_, err = s.db.ExecContext(ctx, `UPDATE continuation_handoff_preparations SET phase=?,target_selection_id=?,updated_at=? WHERE operation_id=? AND report_json IS NULL`,
		phase, selectionID, time.Now().UTC().Format(time.RFC3339Nano), operationID)
	return err
}

func (s *Store) CompleteContinuationHandoffPreparation(ctx context.Context, operationID, selectionID string, report model.ContinuationHandoffReportV1) error {
	existing, err := s.ContinuationHandoffPreparation(ctx, operationID)
	if err != nil {
		return err
	}
	if existing == nil || existing.TargetSelectionID != "" && existing.TargetSelectionID != selectionID ||
		!continuationHandoffReportMatches(existing.Manifest, report) {
		return ErrContinuationHandoffConflict
	}
	if existing.Report != nil {
		if !reflect.DeepEqual(*existing.Report, report) || existing.TargetSelectionID != selectionID {
			return ErrContinuationHandoffConflict
		}
		return nil
	}
	validReady := report.Status == "ready" && report.TargetWorkspace != nil && report.Session != nil && report.Baseline != nil && report.ErrorCode == nil &&
		report.TargetWorkspace.SelectionID == selectionID
	validFailed := report.Status == "failed" && report.TargetWorkspace == nil && report.Session == nil && report.Baseline == nil &&
		report.ErrorCode != nil && *report.ErrorCode != "" && len(*report.ErrorCode) <= 80
	if !validReady && !validFailed {
		return ErrContinuationHandoffConflict
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	mappedSource := ""
	if report.Session != nil {
		mappedSource = report.Session.RegisteredSourceID
	}
	if mappedSource != "" {
		preparations, listErr := s.ContinuationHandoffPreparations(ctx)
		if listErr != nil {
			return listErr
		}
		for _, preparation := range preparations {
			if preparation.Manifest.OperationID != operationID &&
				preparation.Manifest.TargetWorkID == existing.Manifest.TargetWorkID {
				return ErrContinuationHandoffConflict
			}
		}
		owner, lookupErr := s.ContinuationHandoffBySource(ctx, mappedSource)
		if lookupErr != nil {
			return lookupErr
		}
		if owner != nil && owner.Manifest.OperationID != operationID {
			return ErrContinuationHandoffConflict
		}
	}
	result, err := s.db.ExecContext(ctx, `UPDATE continuation_handoff_preparations SET phase=?,target_selection_id=?,mapped_source_id=?,report_json=?,updated_at=? WHERE operation_id=? AND report_json IS NULL`,
		report.Status, selectionID, mappedSource, payload, time.Now().UTC().Format(time.RFC3339Nano), operationID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrContinuationHandoffConflict
	}
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrContinuationHandoffConflict
	}
	return nil
}

func continuationHandoffReportMatches(manifest model.ContinuationHandoffManifestV1, report model.ContinuationHandoffReportV1) bool {
	return report.FormatVersion == manifest.FormatVersion && report.OperationID == manifest.OperationID &&
		report.Action == manifest.Action && report.DesiredRevision == manifest.DesiredRevision &&
		report.HandoffKind == manifest.HandoffKind && report.SessionMode == manifest.SessionMode &&
		report.TargetWorkID == manifest.TargetWorkID && report.MappingID == manifest.MappingID &&
		reflect.DeepEqual(report.Identity, manifest.Identity) && reflect.DeepEqual(report.Binding, manifest.Binding) &&
		reflect.DeepEqual(report.Checkpoint, manifest.Checkpoint) && reflect.DeepEqual(report.Lineage, manifest.Lineage) &&
		reflect.DeepEqual(report.TargetPolicy, manifest.TargetPolicy) && reflect.DeepEqual(report.WorkspaceRequest, manifest.Workspace) &&
		report.ContextDigest == manifest.Context.Digest
}

func (s *Store) PutContinuationHandoffRelease(ctx context.Context, value LocalContinuationHandoffRelease) error {
	if value.Manifest.OperationID == "" || value.Phase != "releasing" || value.Report != nil {
		return ErrContinuationHandoffConflict
	}
	existing, err := s.ContinuationHandoffRelease(ctx, value.Manifest.OperationID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Manifest, value.Manifest) {
			return ErrContinuationHandoffConflict
		}
		return nil
	}
	payload, err := json.Marshal(value.Manifest)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO continuation_handoff_releases(operation_id,manifest_json,phase,report_json,updated_at) VALUES(?,?,'releasing',NULL,?)`,
		value.Manifest.OperationID, payload, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ContinuationHandoffRelease(ctx context.Context, operationID string) (*LocalContinuationHandoffRelease, error) {
	var manifest, report []byte
	var value LocalContinuationHandoffRelease
	err := s.db.QueryRowContext(ctx, `SELECT manifest_json,phase,report_json FROM continuation_handoff_releases WHERE operation_id=?`, operationID).
		Scan(&manifest, &value.Phase, &report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(manifest, &value.Manifest); err != nil {
		return nil, err
	}
	if len(report) != 0 {
		value.Report = &model.ContinuationHandoffReleaseReportV1{}
		if err := json.Unmarshal(report, value.Report); err != nil {
			return nil, err
		}
	}
	return &value, nil
}

func (s *Store) ContinuationHandoffReleases(ctx context.Context) ([]LocalContinuationHandoffRelease, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT manifest_json,phase,report_json FROM continuation_handoff_releases ORDER BY operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalContinuationHandoffRelease
	for rows.Next() {
		var value LocalContinuationHandoffRelease
		var manifest, report []byte
		if err := rows.Scan(&manifest, &value.Phase, &report); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(manifest, &value.Manifest); err != nil {
			return nil, err
		}
		if len(report) != 0 {
			value.Report = &model.ContinuationHandoffReleaseReportV1{}
			if err := json.Unmarshal(report, value.Report); err != nil {
				return nil, err
			}
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) CompleteContinuationHandoffRelease(ctx context.Context, operationID string, report model.ContinuationHandoffReleaseReportV1) error {
	existing, err := s.ContinuationHandoffRelease(ctx, operationID)
	if err != nil {
		return err
	}
	if existing == nil || !reflect.DeepEqual(existing.Manifest, report.ContinuationHandoffReleaseManifestV1) {
		return ErrContinuationHandoffConflict
	}
	if existing.Report != nil {
		if !reflect.DeepEqual(*existing.Report, report) {
			return ErrContinuationHandoffConflict
		}
		return nil
	}
	validReleased := report.Status == "released" && report.ErrorCode == nil
	validFailed := report.Status == "failed" && report.ErrorCode != nil && *report.ErrorCode != "" && len(*report.ErrorCode) <= 80
	if (!validReleased && !validFailed) || report.ReceiptDigest == "" {
		return ErrContinuationHandoffConflict
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE continuation_handoff_releases SET phase=?,report_json=?,updated_at=? WHERE operation_id=? AND report_json IS NULL`,
		report.Status, payload, time.Now().UTC().Format(time.RFC3339Nano), operationID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrContinuationHandoffConflict
	}
	return nil
}

func (s *Store) PutRestoreOperation(ctx context.Context, value LocalRestoreOperation) error {
	if value.Manifest.OperationID == "" || value.Phase != "allocating" || value.Report != nil {
		return ErrRestoreConflict
	}
	existing, err := s.RestoreOperation(ctx, value.Manifest.OperationID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Manifest, value.Manifest) {
			return ErrRestoreConflict
		}
		return nil
	}
	manifest, err := json.Marshal(value.Manifest)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO restore_operations(operation_id, manifest_json, phase, report_json, updated_at)
VALUES(?, ?, 'allocating', NULL, ?)`, value.Manifest.OperationID, manifest, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) RestoreOperation(ctx context.Context, operationID string) (*LocalRestoreOperation, error) {
	var manifest, report []byte
	var phase string
	err := s.db.QueryRowContext(ctx, `SELECT manifest_json, phase, report_json FROM restore_operations WHERE operation_id=?`, operationID).Scan(&manifest, &phase, &report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	value := &LocalRestoreOperation{Phase: phase}
	if err := json.Unmarshal(manifest, &value.Manifest); err != nil {
		return nil, err
	}
	if len(report) != 0 {
		value.Report = &model.RestoreReportV1{}
		if err := json.Unmarshal(report, value.Report); err != nil {
			return nil, err
		}
	}
	return value, nil
}

func (s *Store) RestoreOperations(ctx context.Context) ([]LocalRestoreOperation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT manifest_json, phase, report_json FROM restore_operations ORDER BY operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalRestoreOperation
	for rows.Next() {
		var manifest, report []byte
		var value LocalRestoreOperation
		if err := rows.Scan(&manifest, &value.Phase, &report); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(manifest, &value.Manifest); err != nil {
			return nil, err
		}
		if len(report) != 0 {
			value.Report = &model.RestoreReportV1{}
			if err := json.Unmarshal(report, value.Report); err != nil {
				return nil, err
			}
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) CompleteRestoreOperation(ctx context.Context, operationID string, report model.RestoreReportV1) error {
	existing, err := s.RestoreOperation(ctx, operationID)
	if err != nil {
		return err
	}
	if existing == nil || !restoreReportMatches(existing.Manifest, report) {
		return ErrRestoreConflict
	}
	if existing.Report != nil {
		if !reflect.DeepEqual(*existing.Report, report) {
			return ErrRestoreConflict
		}
		return nil
	}
	phase := report.Status
	if phase != "accepted" && phase != "failed" {
		return ErrRestoreConflict
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE restore_operations SET phase=?, report_json=?, updated_at=? WHERE operation_id=? AND report_json IS NULL`, phase, payload, time.Now().UTC().Format(time.RFC3339Nano), operationID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrRestoreConflict
	}
	return nil
}

func restoreReportMatches(manifest model.RestoreManifestV1, report model.RestoreReportV1) bool {
	return report.FormatVersion == manifest.FormatVersion && report.OperationID == manifest.OperationID && report.Action == manifest.Action &&
		report.DesiredRevision == manifest.DesiredRevision && reflect.DeepEqual(report.Identity, manifest.Identity) &&
		reflect.DeepEqual(report.Binding, manifest.Binding) && reflect.DeepEqual(report.Checkpoint, manifest.Checkpoint)
}

func (s *Store) MarkManagedServiceCreationDispatched(ctx context.Context, id, configDigest string) error {
	value, err := s.ManagedService(ctx, id)
	if err != nil {
		return err
	}
	if value == nil || value.Manifest.ConfigDigest != configDigest {
		return ErrManagedServiceConflict
	}
	// Dispatch is durable once recorded. Health renewals and lookup-only
	// recovery must preserve the established phase until they observe a result.
	if value.CreationDispatched {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `UPDATE managed_services SET creation_dispatched=1, phase='starting', updated_at=? WHERE service_registration_id=?`, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) UpdateManagedService(ctx context.Context, id, phase string, report *model.ManagedServiceReportV1, errorCode string) error {
	var payload []byte
	var err error
	if report != nil {
		payload, err = json.Marshal(report)
		if err != nil {
			return err
		}
	}
	result, err := s.db.ExecContext(ctx, `UPDATE managed_services SET phase=?, report_json=?, error_code=?, updated_at=? WHERE service_registration_id=?`, phase, nullableBytes(payload), errorCode, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("managed service is missing")
	}
	return nil
}

func (s *Store) PutInsightOutbox(ctx context.Context, value InsightOutboxItem) error {
	if value.Batch.BatchID == "" || value.Batch.FormatVersion != 1 || value.BodyDigest == "" {
		return ErrInsightOutboxConflict
	}
	batchJSON, err := json.Marshal(value.Batch)
	if err != nil {
		return err
	}
	cursorJSON, err := json.Marshal(value.NextCursor)
	if err != nil {
		return err
	}
	var existingDigest string
	var existingBatch, existingCursor []byte
	err = s.db.QueryRowContext(ctx, `SELECT body_digest,batch_json,next_cursor_json FROM insight_outbox WHERE batch_id=?`, value.Batch.BatchID).Scan(&existingDigest, &existingBatch, &existingCursor)
	if err == nil {
		if existingDigest != value.BodyDigest || !bytesEqual(existingBatch, batchJSON) || !bytesEqual(existingCursor, cursorJSON) {
			return ErrInsightOutboxConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var count int
	var bytes int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(batch_json)),0) FROM insight_outbox`).Scan(&count, &bytes); err != nil {
		return err
	}
	if count >= 256 || bytes+int64(len(batchJSON)) > 16*1024*1024 {
		return ErrInsightOutboxCapacity
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO insight_outbox(batch_id,registered_source_id,body_digest,batch_json,next_cursor_json,created_at) VALUES(?,?,?,?,?,?)`,
		value.Batch.BatchID, value.Batch.RegisteredSourceID, value.BodyDigest, batchJSON, cursorJSON, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrInsightOutboxConflict
	}
	return err
}

func (s *Store) InsightOutbox(ctx context.Context) ([]InsightOutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT body_digest,batch_json,next_cursor_json FROM insight_outbox ORDER BY created_at,batch_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []InsightOutboxItem
	for rows.Next() {
		var value InsightOutboxItem
		var batchJSON, cursorJSON []byte
		if err := rows.Scan(&value.BodyDigest, &batchJSON, &cursorJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(batchJSON, &value.Batch); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(cursorJSON, &value.NextCursor); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) RetireInsightOutbox(ctx context.Context, batchID, reason string) error {
	if reason != "policy_superseded" && reason != "source_rotated" {
		return ErrInsightOutboxConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existingReason string
	err = tx.QueryRowContext(ctx, `SELECT reason FROM insight_outbox_retirements WHERE batch_id=?`, batchID).Scan(&existingReason)
	if err == nil {
		if existingReason != reason {
			return ErrInsightOutboxConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var digest string
	var batchJSON, cursorJSON []byte
	if err := tx.QueryRowContext(ctx, `SELECT body_digest,batch_json,next_cursor_json FROM insight_outbox WHERE batch_id=?`, batchID).Scan(&digest, &batchJSON, &cursorJSON); err != nil {
		return err
	}
	var count int
	var bytes int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(batch_json)),0) FROM insight_outbox_retirements`).Scan(&count, &bytes); err != nil {
		return err
	}
	if count >= 256 || bytes+int64(len(batchJSON)) > 16*1024*1024 {
		return ErrInsightOutboxCapacity
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO insight_outbox_retirements(batch_id,body_digest,batch_json,next_cursor_json,reason,retired_at) VALUES(?,?,?,?,?,?)`,
		batchID, digest, batchJSON, cursorJSON, reason, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM insight_outbox WHERE batch_id=?`, batchID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) InsightOutboxRetirements(ctx context.Context) ([]InsightOutboxRetirement, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT body_digest,batch_json,next_cursor_json,reason,retired_at FROM insight_outbox_retirements ORDER BY retired_at,batch_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []InsightOutboxRetirement
	for rows.Next() {
		var value InsightOutboxRetirement
		var batchJSON, cursorJSON []byte
		var retiredAt string
		if err := rows.Scan(&value.BodyDigest, &batchJSON, &cursorJSON, &value.Reason, &retiredAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(batchJSON, &value.Batch); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(cursorJSON, &value.NextCursor); err != nil {
			return nil, err
		}
		value.RetiredAt, err = time.Parse(time.RFC3339Nano, retiredAt)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) AcknowledgeInsightBatch(ctx context.Context, batchID string, receipt model.InsightBatchReceiptV1) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var batchJSON, cursorJSON []byte
	if err := tx.QueryRowContext(ctx, `SELECT batch_json,next_cursor_json FROM insight_outbox WHERE batch_id=?`, batchID).Scan(&batchJSON, &cursorJSON); err != nil {
		return err
	}
	var batch model.InsightBatchV1
	var cursor InsightCursor
	if json.Unmarshal(batchJSON, &batch) != nil || json.Unmarshal(cursorJSON, &cursor) != nil ||
		receipt.BatchID != batchID || receipt.Accepted != len(batch.Findings) || receipt.ThroughSequence != batch.ThroughSequence {
		return ErrInsightOutboxConflict
	}
	if cursor.RegisteredSourceID != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO insight_cursors(registered_source_id,cursor_json,updated_at) VALUES(?,?,?) ON CONFLICT(registered_source_id) DO UPDATE SET cursor_json=excluded.cursor_json,updated_at=excluded.updated_at`,
			cursor.RegisteredSourceID, cursorJSON, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM insight_outbox WHERE batch_id=?`, batchID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) InsightCursor(ctx context.Context, sourceID string) (*InsightCursor, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT cursor_json FROM insight_cursors WHERE registered_source_id=?`, sourceID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value InsightCursor
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) InsightPolicyState(ctx context.Context, sourceID string) (*InsightPolicyState, error) {
	var value InsightPolicyState
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT registered_source_id,revision,enabled FROM insight_policy_state WHERE registered_source_id=?`, sourceID).Scan(&value.RegisteredSourceID, &value.Revision, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	value.Enabled = enabled == 1
	return &value, err
}

func (s *Store) PutInsightPolicyState(ctx context.Context, value InsightPolicyState) error {
	if value.RegisteredSourceID == "" || value.Revision < 1 {
		return errors.New("invalid insight policy state")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO insight_policy_state(registered_source_id,revision,enabled,updated_at) VALUES(?,?,?,?) ON CONFLICT(registered_source_id) DO UPDATE SET revision=excluded.revision,enabled=excluded.enabled,updated_at=excluded.updated_at`,
		value.RegisteredSourceID, value.Revision, boolInt(value.Enabled), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) PutInsightPolicyLease(ctx context.Context, value InsightPolicyLease) error {
	if value.Policy.SandboxID == "" || value.Policy.Revision < 1 || value.Policy.ExpiresAt.IsZero() {
		return errors.New("invalid insight policy lease")
	}
	payload, err := json.Marshal(value.Policy)
	if err != nil {
		return err
	}
	var current []byte
	err = s.db.QueryRowContext(ctx, `SELECT policy_json FROM insight_policy_leases WHERE sandbox_id=?`, value.Policy.SandboxID).Scan(&current)
	if err == nil {
		var prior model.InsightPolicyV1
		if json.Unmarshal(current, &prior) != nil || value.Policy.Revision < prior.Revision {
			return errors.New("insight policy lease regressed")
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO insight_policy_leases(sandbox_id,policy_json,updated_at) VALUES(?,?,?) ON CONFLICT(sandbox_id) DO UPDATE SET policy_json=excluded.policy_json,updated_at=excluded.updated_at`,
		value.Policy.SandboxID, payload, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) InsightPolicyLeases(ctx context.Context) ([]InsightPolicyLease, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT policy_json FROM insight_policy_leases ORDER BY sandbox_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []InsightPolicyLease
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var value InsightPolicyLease
		if err := json.Unmarshal(payload, &value.Policy); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func bytesEqual(left, right []byte) bool {
	return string(left) == string(right)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
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
