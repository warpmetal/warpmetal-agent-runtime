package state

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Private association derived from the current protected role/preparation.
// The backend reservation is joined afterward; native cannot choose these IDs.
type ProviderAdmission struct {
	NativeSessionID *string         `json:"nativeSessionId"`
	NativeInputID   *string         `json:"nativeInputId"`
	Reservation     json.RawMessage `json:"reservation"`
}

func (s *Store) AcceptProviderOpening(ctx context.Context, pair json.RawMessage) error {
	if workflowcontract.Validate(workflowcontract.ProviderAccounting, "openingHandshake", pair) != nil {
		return ErrPhysicalConflict
	}
	var originals struct{ Backend, Runtime json.RawMessage }
	if json.Unmarshal(pair, &originals) != nil {
		return ErrPhysicalConflict
	}
	for name, raw := range map[string]json.RawMessage{"provider_opening_backend": originals.Backend, "provider_opening_runtime": originals.Runtime} {
		first, err := s.PhysicalFact(ctx, name)
		if err != nil || model.WorkspaceDigest(json.RawMessage(first)) != model.WorkspaceDigest(raw) {
			return ErrPhysicalConflict
		}
	}
	canonical, err := model.WorkspaceCanonicalJSON(pair)
	if err != nil {
		return err
	}
	return s.RetainPhysicalFact(ctx, "provider_opening_pair", canonical)
}

func (s *Store) ProviderOpening(ctx context.Context) (json.RawMessage, error) {
	raw, err := s.PhysicalFact(ctx, "provider_opening_pair")
	if err != nil || workflowcontract.ValidateProviderAccounting("openingHandshake", raw) != nil {
		return nil, ErrPhysicalConflict
	}
	return raw, nil
}

func providerReservationFact(id string) string {
	return "provider_reservation_" + model.RawPhysicalDigest([]byte(id))[7:]
}

// Join an authenticated backend reservation to independently derived current
// native IDs and this Runtime's retained prefix. A backend summary can never
// fill missing local history or release an UNKNOWN owner.
func (s *Store) BindProviderReservation(ctx context.Context, p PhysicalPermit, current json.RawMessage) (PhysicalPermit, error) {
	if p.Case.AccountingVersion != 2 || p.Provider == nil || workflowcontract.ValidateProviderReadback(current) != nil {
		return p, ErrPhysicalConflict
	}
	var prefix model.ProviderAccountingPrefix
	if json.Unmarshal(current, &prefix) != nil {
		return p, ErrPhysicalConflict
	}
	opening, err := s.ProviderOpening(ctx)
	if err != nil || model.WorkspaceDigest(opening) != model.WorkspaceDigest(prefix.Opening) {
		return p, ErrPhysicalConflict
	}
	var pair struct {
		Backend struct {
			Payload struct{ AuthorityDigest, DemandManifestDigest string } `json:"payload"`
		} `json:"backend"`
	}
	if json.Unmarshal(opening, &pair) != nil || prefix.AuthorityDigest != pair.Backend.Payload.AuthorityDigest {
		return p, ErrPhysicalConflict
	}
	history, err := s.PhysicalHistory(ctx, p.Case)
	if err != nil || p.Request.OuterPhysicalIndex != len(history)+1 || len(prefix.Reservations) < p.Request.OuterPhysicalIndex {
		return p, ErrPhysicalConflict
	}
	for i, raw := range prefix.Reservations {
		var reservation model.ProviderReservation
		if json.Unmarshal(raw, &reservation) != nil || reservation.PhysicalIndex != i+1 || reservation.AuthorityDigest != prefix.AuthorityDigest || reservation.DemandManifestDigest != pair.Backend.Payload.DemandManifestDigest || reservation.OpeningDigest != model.WorkspaceDigest(opening) || reservation.PhysicalID != model.WorkspaceDigest(map[string]any{"ledgerId": reservation.LedgerID, "physicalIndex": i + 1}) {
			return p, ErrPhysicalConflict
		}
		if i < len(history) && (history[i].Permit.Provider == nil || model.WorkspaceDigest(history[i].Permit.Provider.Reservation) != model.WorkspaceDigest(raw)) {
			return p, ErrPhysicalConflict
		}
	}
	raw := prefix.Reservations[p.Request.OuterPhysicalIndex-1]
	var reservation model.ProviderReservation
	_ = json.Unmarshal(raw, &reservation)
	if reservation.AllocationID != p.AllocationID || reservation.PreparationOrdinal != p.PreparationOrdinal || reservation.ProviderPolicyDigest != p.Case.ProviderPolicyDigest || !reflect.DeepEqual(reservation.NativeSessionID, p.Provider.NativeSessionID) || !reflect.DeepEqual(reservation.NativeInputID, p.Provider.NativeInputID) || (p.Request.Consumer == "access") != (reservation.Kind == "access") {
		return p, ErrPhysicalConflict
	}
	if p.Request.Consumer == "parent" && (reservation.ModelRequestIndex == nil || *reservation.ModelRequestIndex != p.Request.RequestIndex) {
		return p, ErrPhysicalConflict
	}
	for _, settlement := range prefix.Settlements {
		var value struct {
			Payload struct {
				PhysicalID string `json:"physicalId"`
			} `json:"payload"`
		}
		if json.Unmarshal(settlement, &value) != nil {
			return p, ErrPhysicalConflict
		}
		matched := false
		for i, o := range history {
			var old model.ProviderReservation
			_ = json.Unmarshal(prefix.Reservations[i], &old)
			if old.PhysicalID == value.Payload.PhysicalID {
				first, err := s.PhysicalFact(ctx, "provider_settlement_"+model.RawPhysicalDigest([]byte(o.OperationID))[7:])
				if err != nil || model.WorkspaceDigest(json.RawMessage(first)) != model.WorkspaceDigest(settlement) {
					return p, ErrPhysicalConflict
				}
				matched = true
			}
		}
		if !matched {
			return p, ErrPhysicalConflict
		}
	}
	copy := *p.Provider
	copy.Reservation = append(json.RawMessage(nil), raw...)
	p.Provider = &copy
	id := "pg_" + model.WorkspaceDigest(p.Request)[7:]
	canonical, err := model.WorkspaceCanonicalJSON(raw)
	if err != nil {
		return p, err
	}
	if err = s.RetainPhysicalFact(ctx, providerReservationFact(id), canonical); err != nil {
		return p, err
	}
	return p, nil
}

// ObserveEmptyProviderOpening holds the existing SQLite writer while measuring
// all local physical history and retaining the FIRST signed observation. The
// callback signs only this measured empty cut; it must not call the Store.
// Existing history or a different opening cannot be replaced by a new case.
func (s *Store) ObserveEmptyProviderOpening(ctx context.Context, c PhysicalCase, backend []byte, observe func() ([]byte, error)) ([]byte, error) {
	if !c.validate() || c.AccountingVersion != 2 || c.BaselineDigest != model.WorkspaceDigest(json.RawMessage(backend)) || workflowcontract.ValidateProviderAccounting("openingEnvelope", backend) != nil || observe == nil {
		return nil, ErrPhysicalConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	caseBytes, _ := json.Marshal(c)
	if _, err = tx.ExecContext(ctx, `INSERT INTO physical_gate_case VALUES(1,?) ON CONFLICT(singleton) DO NOTHING`, caseBytes); err != nil {
		return nil, err
	}
	var actual []byte
	if tx.QueryRowContext(ctx, `SELECT case_json FROM physical_gate_case WHERE singleton=1`).Scan(&actual) != nil || !bytes.Equal(actual, caseBytes) {
		return nil, ErrPhysicalConflict
	}
	var first, original []byte
	err = tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id='provider_opening_runtime'`).Scan(&first)
	if err == nil {
		if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id='provider_opening_backend'`).Scan(&original) != nil || !bytes.Equal(original, backend) {
			return nil, ErrPhysicalConflict
		}
		return first, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	for _, table := range []string{"physical_gate_operations", "physical_gate_owner", "physical_gate_facts"} {
		var count int
		// Table names are closed owner constants, never request-selected.
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count) != nil || count != 0 {
			return nil, ErrPhysicalConflict
		}
	}
	first, err = observe()
	if err != nil {
		return nil, err
	}
	valid := workflowcontract.Validate(workflowcontract.ProviderAccounting, "openingEnvelope", first)
	if c.ProviderPolicyDigest == providerpolicy.ParticipantDigest {
		valid = workflowcontract.Validate(workflowcontract.ProviderParticipantAccounting, "runtimeOpeningEnvelope3", first)
	}
	if valid != nil {
		return nil, ErrPhysicalConflict
	}
	if err = retainPaidFact(ctx, tx, "provider_opening_backend", backend); err != nil {
		return nil, err
	}
	if err = retainPaidFact(ctx, tx, "provider_opening_runtime", first); err != nil {
		return nil, err
	}
	return first, tx.Commit()
}
