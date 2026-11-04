package state

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type ProviderSnapshot struct {
	PhysicalRequests  int   `json:"physicalRequests"`
	ModelRequests     int   `json:"modelRequests"`
	Turns             int   `json:"turns"`
	Preparations      int   `json:"preparations"`
	ReservedUsdMicros int64 `json:"reservedUsdMicros"`
	ActualUsdMicros   int64 `json:"actualUsdMicros"`
}
type ProviderLocalCut struct {
	PhysicalIDs []string         `json:"physicalIds"`
	Snapshot    ProviderSnapshot `json:"snapshot"`
}

// VerifiedProviderPrefix is an internal owner result, never an RPC body. The
// enrolled Producer verifies participant signatures and the full tariff/case.
type VerifiedProviderPrefix struct {
	ParticipantID string
	Prefix        model.ProviderAccountingPrefix
}

func (s *Store) AcceptVerifiedProviderOpening(ctx context.Context, participantID string, opening json.RawMessage) error {
	if !model.PhysicalDigestValid(participantID) || workflowcontract.Validate(workflowcontract.ProviderParticipantAccounting, "openingHandshake3", opening) != nil {
		return ErrPhysicalConflict
	}
	var in struct {
		Backend  json.RawMessage
		Runtimes []json.RawMessage
	}
	_ = json.Unmarshal(opening, &in)
	first, err := s.PhysicalFact(ctx, "provider_opening_runtime")
	if err != nil {
		return err
	}
	backend, err := s.PhysicalFact(ctx, "provider_opening_backend")
	if err != nil || !bytes.Equal(paidCanonical(backend), paidCanonical(in.Backend)) {
		return ErrPhysicalConflict
	}
	matches := 0
	for _, raw := range in.Runtimes {
		var v struct {
			Payload struct{ ParticipantID string }
		}
		_ = json.Unmarshal(raw, &v)
		if v.Payload.ParticipantID == participantID {
			if !bytes.Equal(paidCanonical(raw), paidCanonical(first)) {
				return ErrPhysicalConflict
			}
			matches++
		}
	}
	if matches != 1 {
		return ErrPhysicalConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = retainPaidFact(ctx, tx, "provider_participant_identity", []byte(participantID)); err != nil {
		return err
	}
	if err = retainPaidFact(ctx, tx, "provider_opening_pair", paidCanonical(opening)); err != nil {
		return err
	}
	return tx.Commit()
}

func providerGlobalFact(kind string, index int) string {
	return fmt.Sprintf("provider_global_%s_%02d", kind, index)
}

func retainProviderPrefix(ctx context.Context, tx *sql.Tx, v VerifiedProviderPrefix) (ProviderLocalCut, error) {
	empty := ProviderLocalCut{}
	var own, opening []byte
	if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id='provider_participant_identity'`).Scan(&own) != nil || string(own) != v.ParticipantID || tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id='provider_opening_pair'`).Scan(&opening) != nil || paidDigest(opening) != model.WorkspaceDigest(v.Prefix.Opening) {
		return empty, ErrPhysicalConflict
	}
	raw, _ := json.Marshal(v.Prefix)
	if v.Prefix.FormatVersion != 3 || workflowcontract.ValidateProviderReadback(raw) != nil {
		return empty, ErrPhysicalConflict
	}
	// Acquiring the writer precedes measuring either side of the composite cut.
	if _, err := tx.ExecContext(ctx, `UPDATE physical_gate_case SET singleton=singleton WHERE singleton=1`); err != nil {
		return empty, err
	}
	for _, list := range []struct {
		kind   string
		values []json.RawMessage
	}{{"reservation", v.Prefix.Reservations}, {"settlement", v.Prefix.Settlements}} {
		var count int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM physical_gate_facts WHERE fact_id LIKE ?`, "provider_global_"+list.kind+"_%").Scan(&count) != nil || count > len(list.values) {
			return empty, ErrPhysicalConflict
		}
		for i, value := range list.values {
			if err := retainPaidFact(ctx, tx, providerGlobalFact(list.kind, i+1), paidCanonical(value)); err != nil {
				return empty, err
			}
		}
	}
	return providerLocalCut(ctx, tx, v)
}

func providerLocalCut(ctx context.Context, q paidQuery, v VerifiedProviderPrefix) (ProviderLocalCut, error) {
	cut := ProviderLocalCut{PhysicalIDs: []string{}}
	history, err := physicalHistory(ctx, q)
	if err != nil {
		return cut, err
	}
	settlements := map[string]json.RawMessage{}
	for _, raw := range v.Prefix.Settlements {
		var x struct{ Payload struct{ PhysicalID string } }
		_ = json.Unmarshal(raw, &x)
		settlements[x.Payload.PhysicalID] = raw
	}
	preps := map[string]bool{}
	localIDs := map[string]bool{}
	previous := 0
	for _, o := range history {
		p := o.Permit
		index := p.Request.OuterPhysicalIndex
		if p.Case.ProviderPolicyDigest != providerpolicy.ParticipantDigest || p.Provider == nil || index <= previous || index > len(v.Prefix.Reservations) {
			return cut, ErrPhysicalConflict
		}
		previous = index
		var reservation model.ProviderReservation
		raw := v.Prefix.Reservations[index-1]
		_ = json.Unmarshal(raw, &reservation)
		if reservation.ParticipantID != v.ParticipantID || !bytes.Equal(paidCanonical(p.Provider.Reservation), paidCanonical(raw)) {
			return cut, ErrPhysicalConflict
		}
		cut.PhysicalIDs = append(cut.PhysicalIDs, reservation.PhysicalID)
		localIDs[reservation.PhysicalID] = true
		cut.Snapshot.PhysicalRequests++
		if reservation.Kind != "access" {
			cut.Snapshot.ModelRequests++
			cut.Snapshot.Turns++
			preps[p.Request.PreparationID] = true
		}
		if o.Phase == "unknown" {
			if o.Settlement != nil {
				return cut, ErrPhysicalConflict
			}
			cut.Snapshot.ReservedUsdMicros += o.ReservedUsdMicros
			if settled := settlements[reservation.PhysicalID]; len(settled) > 0 {
				var first []byte
				if q.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "provider_settlement_"+model.RawPhysicalDigest([]byte(o.OperationID))[7:]).Scan(&first) != nil || !bytes.Equal(paidCanonical(first), paidCanonical(settled)) {
					return cut, ErrPhysicalConflict
				}
			}
			continue
		}
		if o.Phase != "settled" || o.Settlement == nil || o.Settlement.Validate() != nil {
			return cut, ErrPhysicalConflict
		}
		var first, ack []byte
		key := model.RawPhysicalDigest([]byte(o.OperationID))[7:]
		if q.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "provider_settlement_"+key).Scan(&first) != nil || q.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "provider_settlement_ack_"+key).Scan(&ack) != nil || len(ack) == 0 || !bytes.Equal(paidCanonical(first), paidCanonical(settlements[reservation.PhysicalID])) {
			return cut, ErrPhysicalConflict
		}
		var e struct {
			Payload struct {
				ActualUsdMicros                   int64
				RequestDigest, WireResponseDigest string
			}
		}
		_ = json.Unmarshal(first, &e)
		if e.Payload.ActualUsdMicros != o.Settlement.UsageUsdMicros || e.Payload.RequestDigest != o.Settlement.RequestDigest || e.Payload.WireResponseDigest != o.Settlement.ResponseDigest {
			return cut, ErrPhysicalConflict
		}
		cut.Snapshot.ActualUsdMicros += o.Settlement.UsageUsdMicros
	}
	for _, raw := range v.Prefix.Reservations {
		var reservation model.ProviderReservation
		_ = json.Unmarshal(raw, &reservation)
		if reservation.ParticipantID == v.ParticipantID && len(settlements[reservation.PhysicalID]) > 0 && !localIDs[reservation.PhysicalID] {
			return cut, ErrPhysicalConflict
		}
	}
	cut.Snapshot.Preparations = len(preps)
	return cut, nil
}

// ObserveProviderComposite neither admits nor settles. Only the global metadata
// mirror and first signed observation can be appended by this transaction.
func (s *Store) ObserveProviderComposite(ctx context.Context, v VerifiedProviderPrefix, observe func(ProviderLocalCut) ([]byte, error)) ([]byte, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	cut, err := retainProviderPrefix(ctx, tx, v)
	if err != nil {
		return nil, err
	}
	identity := model.WorkspaceDigest(map[string]any{"participantId": v.ParticipantID, "prefix": v.Prefix, "local": cut})
	key := "provider_readback_" + identity[7:]
	var first []byte
	err = tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, key).Scan(&first)
	if err == nil {
		var prior struct {
			Payload struct {
				Local  ProviderLocalCut
				Global struct {
					Reservations, Settlements []json.RawMessage
					Snapshot                  json.RawMessage
				}
			}
		}
		if workflowcontract.ValidateProviderRuntimeReadback(first) != nil || json.Unmarshal(first, &prior) != nil || !reflect.DeepEqual(prior.Payload.Local, cut) || model.WorkspaceDigest(prior.Payload.Global.Reservations) != model.WorkspaceDigest(v.Prefix.Reservations) || model.WorkspaceDigest(prior.Payload.Global.Settlements) != model.WorkspaceDigest(v.Prefix.Settlements) || model.WorkspaceDigest(prior.Payload.Global.Snapshot) != model.WorkspaceDigest(v.Prefix.Snapshot) {
			return nil, ErrPhysicalConflict
		}
		return first, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	if observe == nil {
		return nil, ErrPhysicalConflict
	}
	first, err = observe(cut)
	if err != nil {
		return nil, err
	}
	if workflowcontract.ValidateProviderRuntimeReadback(first) != nil {
		return nil, ErrPhysicalConflict
	}
	// Specific signed readback bound; ordinary original facts remain <=64KiB.
	if len(first) > workflowcontract.ProviderReadbackMaximum {
		return nil, ErrPhysicalConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO physical_gate_facts VALUES(?,?)`, key, first); err != nil {
		return nil, err
	}
	return first, tx.Commit()
}

func (s *Store) BindVerifiedProviderReservation(ctx context.Context, p PhysicalPermit, v VerifiedProviderPrefix) (PhysicalPermit, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	if _, err = retainProviderPrefix(ctx, tx, v); err != nil {
		return p, err
	}
	i := p.Request.OuterPhysicalIndex
	if p.Provider == nil || p.Case.ProviderPolicyDigest != providerpolicy.ParticipantDigest || i < 1 || i > len(v.Prefix.Reservations) {
		return p, ErrPhysicalConflict
	}
	var r model.ProviderReservation
	raw := v.Prefix.Reservations[i-1]
	_ = json.Unmarshal(raw, &r)
	if r.ParticipantID != v.ParticipantID || r.AllocationID != p.AllocationID || r.PreparationOrdinal != p.PreparationOrdinal || !reflect.DeepEqual(r.NativeSessionID, p.Provider.NativeSessionID) || !reflect.DeepEqual(r.NativeInputID, p.Provider.NativeInputID) || (r.Kind == "access") != (p.Request.Consumer == "access") {
		return p, ErrPhysicalConflict
	}
	copy := *p.Provider
	copy.Reservation = append(json.RawMessage(nil), raw...)
	p.Provider = &copy
	if err = retainPaidFact(ctx, tx, providerReservationFact("pg_"+model.WorkspaceDigest(p.Request)[7:]), paidCanonical(raw)); err != nil {
		return p, err
	}
	return p, tx.Commit()
}

func validateParticipantAppend(ctx context.Context, tx *sql.Tx, c PhysicalCase, history []PhysicalOperation, id string, p PhysicalPermit) error {
	if p.Provider == nil || p.PaidDomain != "" || p.Offline != nil {
		return ErrPhysicalConflict
	}
	var own, bound, global []byte
	index := p.Request.OuterPhysicalIndex
	if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id='provider_participant_identity'`).Scan(&own) != nil || tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, providerReservationFact(id)).Scan(&bound) != nil || tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, providerGlobalFact("reservation", index)).Scan(&global) != nil || !bytes.Equal(paidCanonical(bound), paidCanonical(global)) || !bytes.Equal(paidCanonical(bound), paidCanonical(p.Provider.Reservation)) {
		return ErrPhysicalConflict
	}
	var r model.ProviderReservation
	_ = json.Unmarshal(bound, &r)
	if r.ParticipantID != string(own) || r.PhysicalIndex != index || r.PhysicalIndex > c.Requests {
		return ErrPhysicalConflict
	}
	var already []byte
	if err := tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, providerGlobalFact("settlement", index)).Scan(&already); err != sql.ErrNoRows {
		return ErrPhysicalConflict
	}
	// Every earlier global index must have an immutable signed settlement. Own
	// earlier operations additionally require their actual local ACK/settled row.
	for i := 1; i < index; i++ {
		var raw []byte
		if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, providerGlobalFact("settlement", i)).Scan(&raw) != nil {
			return ErrPhysicalConflict
		}
	}
	last := 0
	preps := map[int]string{}
	for _, o := range history {
		if o.OperationID == id || o.Phase != "settled" || o.Permit.Request.OuterPhysicalIndex >= index || o.Settlement == nil {
			return ErrPhysicalConflict
		}
		old := o.Permit
		preps[old.PreparationOrdinal] = old.Request.PreparationID
		if old.Request.PreparationID == p.Request.PreparationID {
			if old.AllocationID != p.AllocationID || old.Caller != p.Caller || old.PreparationOrdinal != p.PreparationOrdinal {
				return ErrPhysicalConflict
			}
			last = old.Request.RequestIndex
		}
	}
	if p.Request.Consumer != "access" && preps[p.PreparationOrdinal] != "" && preps[p.PreparationOrdinal] != p.Request.PreparationID {
		return ErrPhysicalConflict
	}
	// Parent's declared model index is global; native input fetches stay local.
	expected := last + 1
	if p.Request.Consumer == "parent" {
		if last != 0 || r.ModelRequestIndex == nil {
			return ErrPhysicalConflict
		}
		expected = *r.ModelRequestIndex
	}
	if p.Request.RequestIndex != expected {
		return ErrPhysicalConflict
	}
	return nil
}
