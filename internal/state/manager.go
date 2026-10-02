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

var ErrManagerConflict = errors.New("manager immutable identity conflict")

type LocalManagerCapability struct {
	RegisteredSourceID    string                          `json:"registeredSourceId"`
	ServiceRegistrationID string                          `json:"serviceRegistrationId"`
	ServiceGeneration     int64                           `json:"serviceGeneration"`
	WorkspaceEpoch        string                          `json:"workspaceEpoch"`
	NativeSessionID       string                          `json:"nativeSessionId"`
	SandboxID             string                          `json:"sandboxId"`
	SandboxGeneration     int64                           `json:"sandboxGeneration"`
	ProfileRevision       int64                           `json:"profileRevision"`
	InstructionRevision   int64                           `json:"instructionRevision"`
	NativeVersion         string                          `json:"nativeVersion"`
	NativeSourceRevision  string                          `json:"nativeSourceRevision"`
	Protocol              string                          `json:"protocol"`
	NativeProtocol        string                          `json:"nativeProtocol"`
	ProviderID            string                          `json:"providerId"`
	ModelID               string                          `json:"modelId"`
	ProviderRouteDigest   string                          `json:"providerRouteDigest"`
	RecipeIDs             []string                        `json:"recipeIds"`
	ManagerPluginDigest   string                          `json:"managerPluginDigest"`
	ManagerProfile        model.InsightsManagerProfileV1  `json:"managerProfile"`
	NativeGuard           *model.NativeGuardObservationV1 `json:"nativeGuard,omitempty"`
	MaxInputTokens        int64                           `json:"maxInputTokens"`
	MaxOutputTokens       int64                           `json:"maxOutputTokens"`
	FinalRequestMaxBytes  int64                           `json:"finalRequestMaxBytes"`
	ToolsAllowed          bool                            `json:"toolsAllowed"`
	MediaAllowed          bool                            `json:"mediaAllowed"`
	HardOutputTokenLimit  bool                            `json:"hardOutputTokenLimit"`
	Available             bool                            `json:"available"`
	Reason                string                          `json:"reason"`
}

type LocalManagerFinding struct {
	Finding           model.InsightFindingV1        `json:"finding"`
	Source            model.InsightsManagerSourceV1 `json:"source"`
	PolicyRevision    int64                         `json:"policyRevision"`
	JournalGeneration string                        `json:"journalGeneration"`
	Acknowledged      bool                          `json:"acknowledged"`
}

type LocalManagerPolicy struct {
	Manifest model.InsightsManagerPolicyManifestV1 `json:"manifest"`
	Report   model.InsightsManagerPolicyReportV1   `json:"report"`
}

type LocalManagerRun struct {
	Manifest                  model.InsightsManagerReviewManifestV1      `json:"manifest"`
	ReservationRequest        *model.InsightsManagerReservationRequestV1 `json:"reservationRequest"`
	Reservation               *model.InsightsManagerReservationV1        `json:"reservation"`
	Phase                     string                                     `json:"phase"`
	Capability                LocalManagerCapability                     `json:"capability"`
	DispatchStarted           bool                                       `json:"dispatchStarted"`
	Report                    *model.InsightsManagerRunReportV1          `json:"report"`
	ManagerRegisteredSourceID string                                     `json:"managerRegisteredSourceId"`
	ManagerSession            *model.InsightsManagerSessionV1            `json:"managerSession"`
	StartedAt                 time.Time                                  `json:"startedAt"`
	AutomaticOrigin           bool                                       `json:"automaticOrigin"`
	GuidanceAttempted         bool                                       `json:"guidanceAttempted"`
	OriginRunGeneration       int64                                      `json:"originRunGeneration"`
	OriginValidUntil          time.Time                                  `json:"originValidUntil"`
	Guidance                  *model.InsightsManagerGuidanceV1           `json:"guidance,omitempty"`
}

type LocalManagerReservation struct {
	Request     model.InsightsManagerReservationRequestV1 `json:"request"`
	Reservation *model.InsightsManagerReservationV1       `json:"reservation"`
	Phase       string                                    `json:"phase"`
}

type LocalManagerTakeover struct {
	Manifest        model.InsightsTakeoverManifestV1 `json:"manifest"`
	Phase           string                           `json:"phase"`
	DispatchStarted bool                             `json:"dispatchStarted"`
	Report          *model.InsightsTakeoverReportV1  `json:"report"`
}

type LocalManagedTaskAuthority struct {
	ServiceRegistrationID string    `json:"serviceRegistrationId"`
	ServiceGeneration     int64     `json:"serviceGeneration"`
	SandboxGeneration     int64     `json:"sandboxGeneration"`
	TaskID                *string   `json:"taskId"`
	TaskAttempt           *int64    `json:"taskAttempt"`
	Busy                  bool      `json:"busy"`
	ObservedAt            time.Time `json:"observedAt"`
}

func (s *Store) ensureManagerSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS manager_capabilities (registered_source_id TEXT PRIMARY KEY, value_json BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS manager_policies (sandbox_id TEXT PRIMARY KEY, value_json BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS manager_findings (finding_id TEXT PRIMARY KEY, value_json BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS manager_runs (run_id TEXT PRIMARY KEY, manager_source_id TEXT NOT NULL DEFAULT '', value_json BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS manager_runs_source_unique ON manager_runs(manager_source_id) WHERE manager_source_id <> '';
CREATE TABLE IF NOT EXISTS manager_reservations (reservation_id TEXT PRIMARY KEY, value_json BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS manager_takeovers (operation_id TEXT PRIMARY KEY, value_json BLOB NOT NULL, updated_at TEXT NOT NULL);`)
	if err == nil {
		_, err = s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS manager_task_authorities (service_registration_id TEXT PRIMARY KEY, value_json BLOB NOT NULL, updated_at TEXT NOT NULL);`)
	}
	return err
}

func (s *Store) PutManagerReservation(ctx context.Context, value LocalManagerReservation) error {
	if value.Request.ReservationID == "" || value.Phase == "" {
		return ErrManagerConflict
	}
	if err := s.ensureManagerSchema(ctx); err != nil {
		return err
	}
	prior, err := s.ManagerReservation(ctx, value.Request.ReservationID)
	if err != nil {
		return err
	}
	if prior != nil {
		// The automatic descriptor target may be re-derived from the current
		// continuity registration for a reservation created before the
		// descriptor-shape correction; every other request field and the
		// reservation itself stay immutable (fail closed).
		priorRequest, nextRequest := prior.Request, value.Request
		priorRequest.Target, nextRequest.Target = model.InsightsManagerTargetV1{}, model.InsightsManagerTargetV1{}
		if !reflect.DeepEqual(priorRequest, nextRequest) ||
			prior.Reservation != nil && value.Reservation != nil && !reflect.DeepEqual(prior.Reservation, value.Reservation) {
			return ErrManagerConflict
		}
	}
	return putManagerJSON(ctx, s.db, "manager_reservations", "reservation_id", value.Request.ReservationID, value)
}

func (s *Store) ManagerReservation(ctx context.Context, id string) (*LocalManagerReservation, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	var value LocalManagerReservation
	found, err := getManagerJSON(ctx, s.db, `SELECT value_json FROM manager_reservations WHERE reservation_id=?`, id, &value)
	if !found || err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) ManagerReservations(ctx context.Context) ([]LocalManagerReservation, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT value_json FROM manager_reservations ORDER BY reservation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalManagerReservation
	for rows.Next() {
		var payload []byte
		var value LocalManagerReservation
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) PutManagedTaskAuthority(ctx context.Context, value LocalManagedTaskAuthority) error {
	if value.ServiceRegistrationID == "" || value.ServiceGeneration < 1 || value.SandboxGeneration < 1 || value.ObservedAt.IsZero() ||
		(value.TaskID == nil) != (value.TaskAttempt == nil) || value.Busy != (value.TaskID != nil) {
		return ErrManagerConflict
	}
	if value.TaskAttempt != nil && *value.TaskAttempt < 1 {
		return ErrManagerConflict
	}
	if err := s.ensureManagerSchema(ctx); err != nil {
		return err
	}
	return putManagerJSON(ctx, s.db, "manager_task_authorities", "service_registration_id", value.ServiceRegistrationID, value)
}

func (s *Store) ManagedTaskAuthority(ctx context.Context, serviceID string) (*LocalManagedTaskAuthority, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	var value LocalManagedTaskAuthority
	found, err := getManagerJSON(ctx, s.db, `SELECT value_json FROM manager_task_authorities WHERE service_registration_id=?`, serviceID, &value)
	if !found || err != nil {
		return nil, err
	}
	return &value, nil
}

func putManagerJSON(ctx context.Context, db *sql.DB, table, keyColumn, key string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	query := "INSERT INTO " + table + "(" + keyColumn + ",value_json,updated_at) VALUES(?,?,?) ON CONFLICT(" + keyColumn + ") DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at"
	_, err = db.ExecContext(ctx, query, key, payload, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func getManagerJSON(ctx context.Context, db *sql.DB, query string, key string, target any) (bool, error) {
	var payload []byte
	err := db.QueryRowContext(ctx, query, key).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(payload, target)
}

func (s *Store) PutManagerCapability(ctx context.Context, value LocalManagerCapability) error {
	if value.RegisteredSourceID == "" || value.ServiceGeneration < 1 || value.ProviderRouteDigest == "" {
		return ErrManagerConflict
	}
	if err := s.ensureManagerSchema(ctx); err != nil {
		return err
	}
	prior, err := s.ManagerCapability(ctx, value.RegisteredSourceID)
	if err != nil {
		return err
	}
	if prior != nil && prior.ServiceGeneration > value.ServiceGeneration {
		return ErrManagerConflict
	}
	if prior != nil && prior.ServiceGeneration == value.ServiceGeneration && !reflect.DeepEqual(*prior, value) {
		return ErrManagerConflict
	}
	return putManagerJSON(ctx, s.db, "manager_capabilities", "registered_source_id", value.RegisteredSourceID, value)
}

func (s *Store) ManagerCapability(ctx context.Context, sourceID string) (*LocalManagerCapability, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	var value LocalManagerCapability
	found, err := getManagerJSON(ctx, s.db, `SELECT value_json FROM manager_capabilities WHERE registered_source_id=?`, sourceID, &value)
	if !found || err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) ManagerCapabilities(ctx context.Context) ([]LocalManagerCapability, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT value_json FROM manager_capabilities ORDER BY registered_source_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalManagerCapability
	for rows.Next() {
		var payload []byte
		var value LocalManagerCapability
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) PutManagerPolicy(ctx context.Context, value LocalManagerPolicy) error {
	if value.Manifest.SandboxID == "" {
		return ErrManagerConflict
	}
	if err := s.ensureManagerSchema(ctx); err != nil {
		return err
	}
	prior, err := s.ManagerPolicy(ctx, value.Manifest.SandboxID)
	if err != nil {
		return err
	}
	if prior != nil && (value.Manifest.PolicyRevision < prior.Manifest.PolicyRevision || value.Manifest.RunGeneration < prior.Manifest.RunGeneration) {
		return ErrManagerConflict
	}
	return putManagerJSON(ctx, s.db, "manager_policies", "sandbox_id", value.Manifest.SandboxID, value)
}

func (s *Store) ManagerPolicy(ctx context.Context, sandboxID string) (*LocalManagerPolicy, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	var value LocalManagerPolicy
	found, err := getManagerJSON(ctx, s.db, `SELECT value_json FROM manager_policies WHERE sandbox_id=?`, sandboxID, &value)
	if !found || err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) ManagerPolicies(ctx context.Context) ([]LocalManagerPolicy, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT value_json FROM manager_policies ORDER BY sandbox_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalManagerPolicy
	for rows.Next() {
		var payload []byte
		var value LocalManagerPolicy
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) PutManagerFinding(ctx context.Context, value LocalManagerFinding) error {
	if value.Finding.FindingID == "" || value.Finding.Revision < 1 || value.JournalGeneration == "" || !value.Acknowledged {
		return ErrManagerConflict
	}
	if err := s.ensureManagerSchema(ctx); err != nil {
		return err
	}
	prior, err := s.ManagerFinding(ctx, value.Finding.FindingID)
	if err != nil {
		return err
	}
	if prior != nil && value.Finding.Revision < prior.Finding.Revision {
		return ErrManagerConflict
	}
	return putManagerJSON(ctx, s.db, "manager_findings", "finding_id", value.Finding.FindingID, value)
}
func (s *Store) ManagerFinding(ctx context.Context, id string) (*LocalManagerFinding, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	var value LocalManagerFinding
	found, err := getManagerJSON(ctx, s.db, `SELECT value_json FROM manager_findings WHERE finding_id=?`, id, &value)
	if !found || err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) PutManagerRun(ctx context.Context, value LocalManagerRun) error {
	if value.Manifest.RunID == "" || value.Phase == "" {
		return ErrManagerConflict
	}
	if err := s.ensureManagerSchema(ctx); err != nil {
		return err
	}
	prior, err := s.ManagerRun(ctx, value.Manifest.RunID)
	if err != nil {
		return err
	}
	if prior != nil && !reflect.DeepEqual(prior.Manifest, value.Manifest) {
		return ErrManagerConflict
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO manager_runs(run_id,manager_source_id,value_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET manager_source_id=excluded.manager_source_id,value_json=excluded.value_json,updated_at=excluded.updated_at`, value.Manifest.RunID, value.ManagerRegisteredSourceID, payload, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) RenewManagerRunLease(ctx context.Context, runID string, priorValidUntil, validUntil time.Time) error {
	if runID == "" || !validUntil.After(priorValidUntil) {
		return ErrManagerConflict
	}
	if err := s.ensureManagerSchema(ctx); err != nil {
		return err
	}
	prior, err := s.ManagerRun(ctx, runID)
	if err != nil {
		return err
	}
	if prior == nil || !prior.Manifest.ValidUntil.Equal(priorValidUntil) {
		return ErrManagerConflict
	}
	priorPayload, err := json.Marshal(prior)
	if err != nil {
		return err
	}
	prior.Manifest.ValidUntil = validUntil
	renewedPayload, err := json.Marshal(prior)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE manager_runs SET value_json=?,updated_at=? WHERE run_id=? AND value_json=?`, renewedPayload, time.Now().UTC().Format(time.RFC3339Nano), runID, priorPayload)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrManagerConflict
	}
	return nil
}
func (s *Store) ManagerRun(ctx context.Context, id string) (*LocalManagerRun, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	var value LocalManagerRun
	found, err := getManagerJSON(ctx, s.db, `SELECT value_json FROM manager_runs WHERE run_id=?`, id, &value)
	if !found || err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) ManagerRunBySource(ctx context.Context, id string) (*LocalManagerRun, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	var value LocalManagerRun
	found, err := getManagerJSON(ctx, s.db, `SELECT value_json FROM manager_runs WHERE manager_source_id=?`, id, &value)
	if !found || err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) ManagerRuns(ctx context.Context) ([]LocalManagerRun, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT value_json FROM manager_runs ORDER BY run_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalManagerRun
	for rows.Next() {
		var payload []byte
		var value LocalManagerRun
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) PutManagerTakeover(ctx context.Context, value LocalManagerTakeover) error {
	if value.Manifest.OperationID == "" || value.Phase == "" {
		return ErrManagerConflict
	}
	if err := s.ensureManagerSchema(ctx); err != nil {
		return err
	}
	prior, err := s.ManagerTakeover(ctx, value.Manifest.OperationID)
	if err != nil {
		return err
	}
	if prior != nil && !reflect.DeepEqual(prior.Manifest, value.Manifest) {
		left, right := prior.Manifest, value.Manifest
		left.ValidUntil, right.ValidUntil = time.Time{}, time.Time{}
		if !reflect.DeepEqual(left, right) || !value.Manifest.ValidUntil.After(prior.Manifest.ValidUntil) {
			return ErrManagerConflict
		}
	}
	return putManagerJSON(ctx, s.db, "manager_takeovers", "operation_id", value.Manifest.OperationID, value)
}
func (s *Store) ManagerTakeover(ctx context.Context, id string) (*LocalManagerTakeover, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	var value LocalManagerTakeover
	found, err := getManagerJSON(ctx, s.db, `SELECT value_json FROM manager_takeovers WHERE operation_id=?`, id, &value)
	if !found || err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) ManagerTakeovers(ctx context.Context) ([]LocalManagerTakeover, error) {
	if err := s.ensureManagerSchema(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT value_json FROM manager_takeovers ORDER BY operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []LocalManagerTakeover
	for rows.Next() {
		var payload []byte
		var value LocalManagerTakeover
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

// PutManagerGuidance applies the Runtime-owned guidance revision with CAS and
// final-disposition immutability through the existing manager run row.
func (s *Store) PutManagerGuidance(ctx context.Context, runID string, value model.InsightsManagerGuidanceV1, expectedRevision int64) error {
	prior, err := s.ManagerRun(ctx, runID)
	if err != nil {
		return err
	}
	if prior == nil {
		return ErrManagerConflict
	}
	current := int64(0)
	if prior.Guidance != nil {
		current = prior.Guidance.Revision
	}
	if expectedRevision != current {
		return ErrManagerConflict
	}
	if value.Revision != current+1 {
		return ErrManagerConflict
	}
	prior.Guidance = &value
	return s.PutManagerRun(ctx, *prior)
}
