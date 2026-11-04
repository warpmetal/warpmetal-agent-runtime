package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
)

var ErrPhysicalConflict = errors.New("physical gate authority/history conflict")

const PhysicalReservationUsdMicros int64 = 421000

// Private verified facts, never a producer/RPC wire. Absent baseline stays unknown.
type PhysicalCase struct {
	AccountingVersion                                     int    `json:",omitempty"`
	ProviderPolicyDigest                                  string `json:",omitempty"`
	TaskID, ServerID, CaseDigest, BaselineDigest          string
	Requests, Preparations, ModelRequests, AccessRequests int
	UsdMicros                                             int64
}
type PhysicalSubject struct {
	SandboxID                            string
	SandboxGeneration                    int64
	NativeInstance, NativeIdentityDigest string
}
type PhysicalPermit struct {
	Case               PhysicalCase
	Caller             PhysicalSubject
	Request            model.PhysicalAdmitRequest
	PreparationOrdinal int
	AllocationID       string
	// Private owner-derived authority, never a field in the seven-field RPC.
	Offline    *OfflineAdmission  `json:",omitempty"`
	PaidDomain string             `json:",omitempty"`
	Provider   *ProviderAdmission `json:",omitempty"`
}
type PhysicalOperation struct {
	OperationID            string
	ImportedOriginalDigest string `json:",omitempty"`
	Permit                 PhysicalPermit
	Phase                  string
	ReservedUsdMicros      int64
	Settlement             *model.PhysicalSettlement
	LocalTerminal          *OfflineTerminal `json:",omitempty"`
	StartedAt              string           `json:",omitempty"`
}

const physicalSchema = `
CREATE TABLE IF NOT EXISTS physical_gate_processes (identity_digest TEXT PRIMARY KEY,registration_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS physical_gate_facts (fact_id TEXT PRIMARY KEY,fact_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS physical_gate_case (singleton INTEGER PRIMARY KEY CHECK(singleton=1),case_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS physical_gate_operations (operation_id TEXT PRIMARY KEY,outer_index INTEGER UNIQUE NOT NULL,request_lane TEXT NOT NULL CHECK(request_lane IN ('access','model')),preparation_id TEXT NOT NULL,request_index INTEGER NOT NULL,operation_json BLOB NOT NULL,evidence_class TEXT NOT NULL DEFAULT 'PAID' CHECK(evidence_class IN ('PAID','OFFLINE')),UNIQUE(request_lane,preparation_id,request_index));
CREATE TABLE IF NOT EXISTS physical_gate_owner (singleton INTEGER PRIMARY KEY CHECK(singleton=1),operation_id TEXT NOT NULL REFERENCES physical_gate_operations(operation_id));`

func (c PhysicalCase) validate() bool {
	if c.AccountingVersion != 0 || c.ProviderPolicyDigest != "" {
		policy, selected := providerpolicy.Select(c.ProviderPolicyDigest)
		if !selected || c.AccountingVersion != policy.Accounting.Version || c.Requests > policy.Accounting.PhysicalRequestLimit || c.UsdMicros != policy.Accounting.MaximumExposureMicros {
			return false
		}
	}
	return model.PhysicalIDValid(c.TaskID) && model.PhysicalIDValid(c.ServerID) && model.PhysicalDigestValid(c.CaseDigest) && model.PhysicalDigestValid(c.BaselineDigest) && c.Requests > 0 && c.Preparations > 0 && c.ModelRequests >= 0 && c.AccessRequests >= 0 && c.Requests == c.ModelRequests+c.AccessRequests && c.UsdMicros > 0
}
func (p PhysicalPermit) validate() bool {
	if p.Offline != nil {
		return p.PaidDomain == "" && p.validateOffline()
	}
	if p.PaidDomain != "" && !model.PhysicalDigestValid(p.PaidDomain) {
		return false
	}
	ordinal := p.PreparationOrdinal > 0 && p.PreparationOrdinal <= p.Case.Preparations
	if p.Request.Consumer == "access" {
		ordinal = p.PreparationOrdinal == 0
	}
	return p.Case.validate() && p.Request.Validate() == nil && model.PhysicalIDValid(p.Caller.SandboxID) && p.Caller.SandboxGeneration > 0 && model.PhysicalIDValid(p.Caller.NativeInstance) && model.PhysicalDigestValid(p.Caller.NativeIdentityDigest) && model.PhysicalIDValid(p.AllocationID) && ordinal
}
func (s *Store) AdoptPhysicalLedger(ctx context.Context, c PhysicalCase, baseline []PhysicalOperation) error {
	if !c.validate() || c.ProviderPolicyDigest == providerpolicy.ParticipantDigest {
		return ErrPhysicalConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT case_json FROM physical_gate_case WHERE singleton=1`).Scan(&raw)
	if err == nil {
		var old PhysicalCase
		if json.Unmarshal(raw, &old) != nil || old != c {
			return ErrPhysicalConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	encoded, _ := json.Marshal(c)
	if _, err = tx.ExecContext(ctx, `INSERT INTO physical_gate_case VALUES(1,?)`, encoded); err != nil {
		return err
	}
	for i, o := range baseline {
		if o.Permit.Offline != nil || o.Permit.Case != c || o.Permit.Request.OuterPhysicalIndex != i+1 || o.ReservedUsdMicros != PhysicalReservationUsdMicros || !model.PhysicalIDValid(o.OperationID) || !o.Permit.validate() || (o.Phase != "settled" && o.Phase != "unknown") || (o.Phase == "unknown" && o.Settlement != nil) || (o.Phase == "settled" && (o.Settlement == nil || o.Settlement.Validate() != nil || o.Settlement.RequestDigest != o.Permit.Request.RequestDigest || o.Settlement.UsageUsdMicros > o.ReservedUsdMicros)) {
			return ErrPhysicalConflict
		}
		if err = validatePhysicalAppend(c, baseline[:i], o.OperationID, o.Permit); err != nil {
			return err
		}
		if err = insertPhysical(ctx, tx, o); err != nil {
			return err
		}
		if o.Phase == "unknown" {
			if _, err = tx.ExecContext(ctx, `INSERT INTO physical_gate_owner VALUES(1,?)`, o.OperationID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
func insertPhysical(ctx context.Context, tx *sql.Tx, o PhysicalOperation) error {
	raw, _ := json.Marshal(o)
	lane := "model"
	if o.Permit.Request.Consumer == "access" {
		lane = "access"
	}
	class, index := "PAID", o.Permit.Request.OuterPhysicalIndex
	if o.Permit.Offline != nil {
		class = "OFFLINE"
		// Existing positive paid indices and their unique constraint remain exact.
		// Negative STORAGE indices are only the disjoint cumulative local domain;
		// original RPC/operation JSON keep the positive owner-declared ordinal.
		w, err := readOfflineWindow(ctx, tx, o.Permit.Offline.WindowID)
		if err != nil {
			return err
		}
		cumulative, err := offlineStoragePosition(ctx, tx, w, o.Permit.Offline.Slot)
		if err != nil {
			return err
		}
		index = -cumulative
	} else if o.Permit.PaidDomain != "" {
		d, err := readPaidDomain(ctx, tx, o.Permit.PaidDomain)
		if err != nil {
			return err
		}
		index = d.Bases.PhysicalRequests + index
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO physical_gate_operations(operation_id,outer_index,request_lane,preparation_id,request_index,operation_json,evidence_class) VALUES(?,?,?,?,?,?,?)`, o.OperationID, index, lane, o.Permit.Request.PreparationID, o.Permit.Request.RequestIndex, raw, class)
	return err
}
func physicalHistory(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]PhysicalOperation, error) {
	rows, err := q.QueryContext(ctx, `SELECT operation_json FROM physical_gate_operations WHERE evidence_class='PAID' ORDER BY outer_index`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PhysicalOperation{}
	for rows.Next() {
		var raw []byte
		var o PhysicalOperation
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &o) != nil {
			return nil, ErrPhysicalConflict
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
func (s *Store) PhysicalHistory(ctx context.Context, c PhysicalCase) ([]PhysicalOperation, error) {
	var raw []byte
	var current PhysicalCase
	if s.db.QueryRowContext(ctx, `SELECT case_json FROM physical_gate_case WHERE singleton=1`).Scan(&raw) != nil || json.Unmarshal(raw, &current) != nil {
		return nil, ErrPhysicalConflict
	}
	{
		rows, err := s.db.QueryContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id LIKE 'paid_domain_basis_%'`)
		if err != nil {
			return nil, err
		}
		var selected *PaidDomain
		for rows.Next() {
			var b []byte
			var d PaidDomain
			if rows.Scan(&b) != nil || json.Unmarshal(b, &d) != nil {
				rows.Close()
				return nil, ErrPhysicalConflict
			}
			if d.Case == c {
				if selected != nil {
					rows.Close()
					return nil, ErrPhysicalConflict
				}
				selected = &d
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if selected != nil {
			d, err := readPaidDomain(ctx, s.db, selected.DemandManifestDigest)
			if err != nil {
				return nil, err
			}
			return paidDomainHistory(ctx, s.db, d)
		}
	}
	if current != c {
		return nil, ErrPhysicalConflict
	}
	history, err := physicalHistory(ctx, s.db)
	if err != nil {
		return nil, err
	}
	own := []PhysicalOperation{}
	for _, o := range history {
		if o.Permit.PaidDomain == "" {
			if o.Permit.Case != c {
				return nil, ErrPhysicalConflict
			}
			own = append(own, o)
		}
	}
	return own, nil
}
func (s *Store) PhysicalOperation(ctx context.Context, id string) (*PhysicalOperation, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT operation_json FROM physical_gate_operations WHERE operation_id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var o PhysicalOperation
	if json.Unmarshal(raw, &o) != nil {
		return nil, ErrPhysicalConflict
	}
	return &o, nil
}

// Read the existing singleton owner without requiring a financial-domain cut.
// Missing ledger on unrelated native cancellation is not SOURCE enrollment.
// A dangling owner is a conflict, not falsely observed quiescence/no-owner.
func (s *Store) PhysicalOwner(ctx context.Context) (*PhysicalOperation, error) {
	var raw []byte
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT o.operation_json, own.operation_id FROM physical_gate_owner own LEFT JOIN physical_gate_operations o ON o.operation_id=own.operation_id WHERE own.singleton=1`).Scan(&raw, &id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var o PhysicalOperation
	if model.DecodePhysicalClosed(raw, &o) != nil || o.OperationID != id {
		return nil, ErrPhysicalConflict
	}
	return &o, nil
}
func (s *Store) AdmitPhysical(ctx context.Context, id string, p PhysicalPermit) error {
	if !model.PhysicalIDValid(id) || !p.validate() {
		return ErrPhysicalConflict
	}
	if p.Offline != nil {
		return s.admitOffline(ctx, id, p)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Obtain SQLite's cross-connection write lock before measuring the prefix.
	result, err := tx.ExecContext(ctx, `UPDATE physical_gate_case SET singleton=singleton WHERE singleton=1`)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrPhysicalConflict
	}
	var raw []byte
	var c PhysicalCase
	if tx.QueryRowContext(ctx, `SELECT case_json FROM physical_gate_case WHERE singleton=1`).Scan(&raw) != nil || json.Unmarshal(raw, &c) != nil || (p.PaidDomain == "" && c != p.Case) {
		return ErrPhysicalConflict
	}
	var active string
	if err = tx.QueryRowContext(ctx, `SELECT operation_id FROM physical_gate_owner WHERE singleton=1`).Scan(&active); !errors.Is(err, sql.ErrNoRows) {
		return ErrPhysicalConflict
	}
	if p.PaidDomain != "" {
		if err = s.admitPaidDomain(ctx, tx, id, p); err != nil {
			return err
		}
	} else {
		var mapped int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM physical_gate_facts WHERE fact_id LIKE 'paid_domain_basis_%'`).Scan(&mapped) != nil || mapped != 0 {
			return ErrPhysicalConflict
		}
		history, e := physicalHistory(ctx, tx)
		if e != nil {
			return e
		}
		if c.ProviderPolicyDigest == providerpolicy.ParticipantDigest {
			err = validateParticipantAppend(ctx, tx, c, history, id, p)
		} else {
			err = validatePhysicalAppend(c, history, id, p)
		}
		if err != nil {
			return err
		}
	}
	o := PhysicalOperation{OperationID: id, Permit: p, Phase: "unknown", ReservedUsdMicros: PhysicalReservationUsdMicros}
	if p.Provider != nil && p.Case.AccountingVersion == 2 {
		o.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err = insertPhysical(ctx, tx, o); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO physical_gate_owner VALUES(1,?)`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// One prefix/preparation/reservation rule for both imported original history and
// new transactions. Importing provenance cannot create otherwise denied headroom.
func validatePhysicalAppend(c PhysicalCase, history []PhysicalOperation, id string, p PhysicalPermit) error {
	preps := map[string]int{}
	ordinals := map[int]string{}
	modelCount, accessCount, last := 0, 0, 0
	var reserved int64
	for _, o := range history {
		if o.OperationID == id || o.Phase != "settled" {
			return ErrPhysicalConflict
		}
		r := o.Permit.Request
		if r.Consumer != "access" {
			preps[r.PreparationID] = o.Permit.PreparationOrdinal
			ordinals[o.Permit.PreparationOrdinal] = r.PreparationID
		}
		if r.PreparationID == p.Request.PreparationID && (r.Consumer == "access") == (p.Request.Consumer == "access") {
			if o.Permit.Caller != p.Caller || o.Permit.AllocationID != p.AllocationID || o.Permit.PreparationOrdinal != p.PreparationOrdinal {
				return ErrPhysicalConflict
			}
			last = r.RequestIndex
		}
		if r.Consumer == "access" {
			accessCount++
		} else {
			modelCount++
		}
		if c.AccountingVersion == 2 {
			// Only verified settled cost releases cash exposure. The immutable
			// physical prefix and singleton UNKNOWN exclusion above stay intact.
			if o.Settlement == nil || o.Settlement.Validate() != nil || o.Settlement.UsageUsdMicros > o.ReservedUsdMicros {
				return ErrPhysicalConflict
			}
			reserved += o.Settlement.UsageUsdMicros
		} else {
			reserved += o.ReservedUsdMicros
		}
	}
	expectedRequest := last + 1
	if p.Request.Consumer == "parent" {
		// The frozen parent grant numbers its CASE model-request stream (access
		// excluded), unlike PRODUCT/shell2's local turn. Never renumber that grant.
		if last != 0 {
			return ErrPhysicalConflict
		}
		expectedRequest = modelCount + 1
	}
	if p.Request.OuterPhysicalIndex != len(history)+1 || p.Request.RequestIndex != expectedRequest || len(history) >= c.Requests || reserved > c.UsdMicros-PhysicalReservationUsdMicros {
		return ErrPhysicalConflict
	}
	if p.Request.Consumer != "access" {
		if ordinal, ok := preps[p.Request.PreparationID]; ok {
			if ordinal != p.PreparationOrdinal {
				return ErrPhysicalConflict
			}
		} else if len(preps) >= c.Preparations || p.PreparationOrdinal != len(preps)+1 || ordinals[p.PreparationOrdinal] != "" {
			return ErrPhysicalConflict
		}
	}
	if (p.Request.Consumer == "access" && accessCount >= c.AccessRequests) || (p.Request.Consumer != "access" && modelCount >= c.ModelRequests) {
		return ErrPhysicalConflict
	}
	return nil
}
func (s *Store) SettlePhysical(ctx context.Context, id string, subject PhysicalSubject, e model.PhysicalSettlement) error {
	if e.Validate() != nil {
		return ErrPhysicalConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	var o PhysicalOperation
	if tx.QueryRowContext(ctx, `SELECT operation_json FROM physical_gate_operations WHERE operation_id=?`, id).Scan(&raw) != nil || json.Unmarshal(raw, &o) != nil || o.Permit.Offline != nil || o.Permit.Caller != subject || o.Permit.Request.RequestDigest != e.RequestDigest {
		return ErrPhysicalConflict
	}
	if e.UsageUsdMicros > o.ReservedUsdMicros {
		return ErrPhysicalConflict
	}
	if o.Permit.Case.AccountingVersion == 2 && o.Permit.Provider != nil {
		var ack []byte
		if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "provider_settlement_ack_"+model.RawPhysicalDigest([]byte(id))[7:]).Scan(&ack) != nil || len(ack) == 0 {
			return ErrPhysicalConflict
		}
	}
	var originalIndex []byte
	archiveErr := tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, nativeSettlementFactID(id)).Scan(&originalIndex)
	if archiveErr == nil {
		var index struct {
			Settlement model.PhysicalSettlement `json:"settlement"`
		}
		if json.Unmarshal(originalIndex, &index) != nil || index.Settlement != e {
			return ErrPhysicalConflict
		}
	} else if !errors.Is(archiveErr, sql.ErrNoRows) {
		return archiveErr
	}
	if o.Phase == "settled" {
		if !reflect.DeepEqual(o.Settlement, &e) {
			return ErrPhysicalConflict
		}
		return tx.Commit()
	}
	var owner string
	if tx.QueryRowContext(ctx, `SELECT operation_id FROM physical_gate_owner WHERE singleton=1`).Scan(&owner) != nil || owner != id {
		return ErrPhysicalConflict
	}
	o.Phase = "settled"
	o.Settlement = &e
	raw, _ = json.Marshal(o)
	if _, err = tx.ExecContext(ctx, `UPDATE physical_gate_operations SET operation_json=? WHERE operation_id=?`, raw, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM physical_gate_owner WHERE singleton=1 AND operation_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}
