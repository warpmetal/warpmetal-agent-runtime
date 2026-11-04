package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Private verified projections. Never supplied by native RPC or a public lane.
type PaidCounters struct {
	PhysicalRequests int `json:"physicalRequests"`
	ModelRequests    int `json:"modelRequests"`
	Preparations     int `json:"preparations"`
}
type PaidOperationRef struct {
	OperationID            string  `json:"operationId"`
	OperationDigest        string  `json:"operationDigest"`
	StoragePhysicalIndex   int     `json:"storagePhysicalIndex"`
	ImportedOriginalDigest *string `json:"importedOriginalDigest"`
}
type PhysicalOwnerRef struct {
	OperationID     string `json:"operationId"`
	OperationDigest string `json:"operationDigest"`
}
type PaidLedgerCut struct {
	Anchor               PhysicalCase
	Cumulative           PaidCounters
	PaidHistory          []PaidOperationRef
	OfflineHistoryDigest string
	OfflineHistory       []json.RawMessage
	Owner                *PhysicalOwnerRef
	Originals            map[string]json.RawMessage
}
type PaidAllocation struct {
	AllocationID                                                             string
	FirstPhysicalIndex, LastPhysicalIndex, PreparationOrdinal, ModelRequests int
}
type PaidDomain struct {
	DemandManifestDigest, AdoptionEnvelopeDigest, RuntimeReadbackEnvelopeDigest string
	AdoptionEnvelope                                                            json.RawMessage
	Case                                                                        PhysicalCase
	Bases                                                                       PaidCounters
	Opening                                                                     PaidLedgerCut
	Allocations                                                                 []PaidAllocation
}
type paidOperationDomain struct {
	AdoptionEnvelopeDigest       string `json:"adoptionEnvelopeDigest"`
	StoragePhysicalIndex         int    `json:"storagePhysicalIndex"`
	CumulativeModelIndex         *int   `json:"cumulativeModelIndex"`
	CumulativePreparationOrdinal *int   `json:"cumulativePreparationOrdinal"`
}
type paidQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func paidOperationFactID(id string) string {
	h := sha256.Sum256([]byte(id))
	return "paid_op_domain_" + hex.EncodeToString(h[:])
}
func paidDomainFactID(d string) string  { return "paid_domain_" + d[7:] }
func paidDomainBasisID(d string) string { return "paid_domain_basis_" + d[7:] }
func paidCanonical(raw []byte) []byte {
	canonical, err := model.WorkspaceCanonicalJSON(json.RawMessage(raw))
	if err != nil {
		return nil
	}
	return canonical
}
func paidDigest(raw []byte) string { return model.RawPhysicalDigest(paidCanonical(raw)) }
func retainPaidFact(ctx context.Context, tx *sql.Tx, id string, raw []byte) error {
	if len(raw) == 0 || len(raw) > 65536 {
		return ErrPhysicalConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO physical_gate_facts VALUES(?,?) ON CONFLICT(fact_id) DO NOTHING`, id, raw); err != nil {
		return err
	}
	var old []byte
	if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, id).Scan(&old) != nil || !bytes.Equal(raw, old) {
		return ErrPhysicalConflict
	}
	return nil
}
func readPaidDomain(ctx context.Context, q paidQuery, digest string) (PaidDomain, error) {
	var d PaidDomain
	var raw, original []byte
	if !model.PhysicalDigestValid(digest) || q.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, paidDomainBasisID(digest)).Scan(&raw) != nil || json.Unmarshal(raw, &d) != nil || d.DemandManifestDigest != digest || !d.valid() {
		return d, ErrPhysicalConflict
	}
	if q.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, paidDomainFactID(digest)).Scan(&original) != nil || !bytes.Equal(original, d.AdoptionEnvelope) {
		return d, ErrPhysicalConflict
	}
	return d, nil
}
func (d PaidDomain) valid() bool {
	if !d.Case.validate() || !model.PhysicalDigestValid(d.DemandManifestDigest) || !model.PhysicalDigestValid(d.RuntimeReadbackEnvelopeDigest) || !model.PhysicalDigestValid(d.AdoptionEnvelopeDigest) || model.RawPhysicalDigest(d.AdoptionEnvelope) != d.AdoptionEnvelopeDigest || len(d.AdoptionEnvelope) > 65536 || d.Bases != d.Opening.Cumulative || d.Opening.Owner != nil || d.Bases.PhysicalRequests < 0 || d.Bases.ModelRequests < 0 || d.Bases.Preparations < 0 || d.Bases.PhysicalRequests > 128 || len(d.Allocations) == 0 || len(d.Allocations) > 19 {
		return false
	}
	next, models, preps, access := 1, 0, 0, 0
	ids := map[string]bool{}
	for _, a := range d.Allocations {
		count := a.LastPhysicalIndex - a.FirstPhysicalIndex + 1
		if !model.PhysicalIDValid(a.AllocationID) || ids[a.AllocationID] || a.FirstPhysicalIndex != next || count < 1 || a.LastPhysicalIndex > d.Case.Requests {
			return false
		}
		ids[a.AllocationID] = true
		if a.ModelRequests == 0 {
			if count != 1 || a.PreparationOrdinal != 0 {
				return false
			}
			access++
		} else {
			if a.ModelRequests != count || a.PreparationOrdinal != preps+1 {
				return false
			}
			preps++
			models += count
		}
		next = a.LastPhysicalIndex + 1
	}
	return next == d.Case.Requests+1 && models == d.Case.ModelRequests && preps == d.Case.Preparations && access == d.Case.AccessRequests
}
func paidAssociation(d PaidDomain, p PhysicalPermit, index int) (paidOperationDomain, error) {
	out := paidOperationDomain{AdoptionEnvelopeDigest: d.AdoptionEnvelopeDigest, StoragePhysicalIndex: d.Bases.PhysicalRequests + p.Request.OuterPhysicalIndex}
	modelStart := 1
	for _, a := range d.Allocations {
		if a.AllocationID == p.AllocationID {
			if p.Case != d.Case || p.PreparationOrdinal != a.PreparationOrdinal || p.Request.OuterPhysicalIndex < a.FirstPhysicalIndex || p.Request.OuterPhysicalIndex > a.LastPhysicalIndex || out.StoragePhysicalIndex != index || (p.Request.Consumer == "access") != (a.ModelRequests == 0) {
				return out, ErrPhysicalConflict
			}
			if a.ModelRequests > 0 {
				m := d.Bases.ModelRequests + modelStart + p.Request.OuterPhysicalIndex - a.FirstPhysicalIndex
				prep := d.Bases.Preparations + a.PreparationOrdinal
				out.CumulativeModelIndex = &m
				out.CumulativePreparationOrdinal = &prep
			}
			return out, nil
		}
		modelStart += a.ModelRequests
	}
	return out, ErrPhysicalConflict
}
func physicalLedgerCut(ctx context.Context, q paidQuery) (PaidLedgerCut, error) {
	cut := PaidLedgerCut{PaidHistory: []PaidOperationRef{}, Originals: map[string]json.RawMessage{}}
	var anchor PhysicalCase
	var anchorBytes []byte
	if q.QueryRowContext(ctx, `SELECT case_json FROM physical_gate_case WHERE singleton=1`).Scan(&anchorBytes) != nil || json.Unmarshal(anchorBytes, &anchor) != nil || !anchor.validate() {
		return cut, ErrPhysicalConflict
	}
	cut.Anchor = anchor
	rows, err := q.QueryContext(ctx, `SELECT outer_index,operation_json,evidence_class FROM physical_gate_operations ORDER BY rowid`)
	if err != nil {
		return cut, err
	}
	type row struct {
		index int
		raw   []byte
		class string
	}
	all := []row{}
	for rows.Next() {
		var r row
		if rows.Scan(&r.index, &r.raw, &r.class) != nil {
			rows.Close()
			return cut, ErrPhysicalConflict
		}
		all = append(all, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return cut, err
	}
	preps := map[string]bool{}
	offline := []json.RawMessage{}
	unknown := ""
	for _, r := range all {
		var o PhysicalOperation
		if json.Unmarshal(r.raw, &o) != nil || !o.Permit.validate() || o.ReservedUsdMicros != 421000 {
			return cut, ErrPhysicalConflict
		}
		if !model.PhysicalIDValid(o.OperationID) || (o.ImportedOriginalDigest != "" && !model.PhysicalDigestValid(o.ImportedOriginalDigest)) {
			return cut, ErrPhysicalConflict
		}
		canonical := paidCanonical(r.raw)
		digest := paidDigest(r.raw)
		cut.Originals[digest] = canonical
		closed := o.Phase == "settled" && o.Settlement != nil && o.Settlement.Validate() == nil && o.Settlement.RequestDigest == o.Permit.Request.RequestDigest && o.Settlement.UsageUsdMicros <= o.ReservedUsdMicros
		if r.class == "OFFLINE" {
			closed = o.Phase == "local-terminal" && o.LocalTerminal != nil && o.Settlement == nil
		}
		if !closed {
			if o.Phase != "unknown" || o.Settlement != nil || unknown != "" {
				return cut, ErrPhysicalConflict
			}
			unknown = o.OperationID
		}
		if r.class == "OFFLINE" {
			if r.index >= 0 || o.Permit.Offline == nil {
				return cut, ErrPhysicalConflict
			}
			offline = append(offline, canonical)
			continue
		}
		if r.index != cut.Cumulative.PhysicalRequests+1 || o.Permit.Offline != nil {
			return cut, ErrPhysicalConflict
		}
		if o.Permit.PaidDomain != "" {
			d, e := readPaidDomain(ctx, q, o.Permit.PaidDomain)
			if e != nil {
				return cut, e
			}
			expected, e := paidAssociation(d, o.Permit, r.index)
			var association paidOperationDomain
			var raw []byte
			if e != nil || q.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, paidOperationFactID(o.OperationID)).Scan(&raw) != nil || json.Unmarshal(raw, &association) != nil || !reflect.DeepEqual(expected, association) {
				return cut, ErrPhysicalConflict
			}
		} else if r.index != o.Permit.Request.OuterPhysicalIndex || o.Permit.Case != anchor {
			return cut, ErrPhysicalConflict
		}
		cut.Cumulative.PhysicalRequests++
		if o.Permit.Request.Consumer != "access" {
			cut.Cumulative.ModelRequests++
			preps[o.Permit.Request.PreparationID] = true
		}
		ref := PaidOperationRef{OperationID: o.OperationID, OperationDigest: digest, StoragePhysicalIndex: r.index}
		if o.ImportedOriginalDigest != "" {
			s := o.ImportedOriginalDigest
			ref.ImportedOriginalDigest = &s
		}
		cut.PaidHistory = append(cut.PaidHistory, ref)
	}
	cut.Cumulative.Preparations = len(preps)
	b, _ := json.Marshal(offline)
	cut.OfflineHistory = offline
	cut.OfflineHistoryDigest = paidDigest(b)
	var owner string
	err = q.QueryRowContext(ctx, `SELECT operation_id FROM physical_gate_owner WHERE singleton=1`).Scan(&owner)
	if err == nil {
		var raw []byte
		if q.QueryRowContext(ctx, `SELECT operation_json FROM physical_gate_operations WHERE operation_id=?`, owner).Scan(&raw) != nil {
			return cut, ErrPhysicalConflict
		}
		cut.Owner = &PhysicalOwnerRef{owner, paidDigest(raw)}
		if owner != unknown {
			return cut, ErrPhysicalConflict
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return cut, err
	} else if unknown != "" {
		return cut, ErrPhysicalConflict
	}
	return cut, nil
}
func (s *Store) PhysicalAnchor(ctx context.Context) (*PhysicalCase, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT case_json FROM physical_gate_case WHERE singleton=1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c PhysicalCase
	if json.Unmarshal(raw, &c) != nil || !c.validate() {
		return nil, ErrPhysicalConflict
	}
	return &c, nil
}
func (s *Store) PhysicalLedgerCut(ctx context.Context) (PaidLedgerCut, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PaidLedgerCut{}, err
	}
	defer tx.Rollback()
	cut, err := physicalLedgerCut(ctx, tx)
	if err != nil {
		return cut, err
	}
	return cut, tx.Commit()
}
func (s *Store) AdoptPaidDomain(ctx context.Context, d PaidDomain) error {
	if !d.valid() {
		return ErrPhysicalConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE physical_gate_case SET singleton=singleton WHERE singleton=1`)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrPhysicalConflict
	}
	var anchorBytes []byte
	var anchor PhysicalCase
	if tx.QueryRowContext(ctx, `SELECT case_json FROM physical_gate_case WHERE singleton=1`).Scan(&anchorBytes) != nil || json.Unmarshal(anchorBytes, &anchor) != nil || anchor.TaskID != d.Case.TaskID || anchor.ServerID != d.Case.ServerID || anchor.BaselineDigest != d.Case.BaselineDigest {
		return ErrPhysicalConflict
	}
	var prior []byte
	err = tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, paidDomainFactID(d.DemandManifestDigest)).Scan(&prior)
	if err == nil {
		old, e := readPaidDomain(ctx, tx, d.DemandManifestDigest)
		if e != nil || !bytes.Equal(prior, d.AdoptionEnvelope) || !reflect.DeepEqual(old, d) {
			return ErrPhysicalConflict
		}
		if _, e = physicalLedgerCut(ctx, tx); e != nil {
			return e
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	cut, err := physicalLedgerCut(ctx, tx)
	if err != nil || cut.Owner != nil || !reflect.DeepEqual(cut, d.Opening) {
		return ErrPhysicalConflict
	}
	priorRows, err := tx.QueryContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id LIKE 'paid_domain_basis_%'`)
	if err != nil {
		return err
	}
	priorDomains := []PaidDomain{}
	for priorRows.Next() {
		var raw []byte
		var priorDomain PaidDomain
		if priorRows.Scan(&raw) != nil || json.Unmarshal(raw, &priorDomain) != nil {
			priorRows.Close()
			return ErrPhysicalConflict
		}
		priorDomains = append(priorDomains, priorDomain)
	}
	err = priorRows.Err()
	priorRows.Close()
	if err != nil {
		return err
	}
	for _, priorDomain := range priorDomains {
		verified, e := readPaidDomain(ctx, tx, priorDomain.DemandManifestDigest)
		if e != nil || verified.Case.CaseDigest == d.Case.CaseDigest {
			return ErrPhysicalConflict
		}
		own, e := paidDomainHistory(ctx, tx, verified)
		if e != nil || len(own) != verified.Case.Requests {
			return ErrPhysicalConflict
		}
	}
	// No lost singleton can hide an unclosed paid/offline predecessor.
	rows, err := tx.QueryContext(ctx, `SELECT operation_json,evidence_class FROM physical_gate_operations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var raw []byte
		var class string
		var o PhysicalOperation
		if rows.Scan(&raw, &class) != nil || json.Unmarshal(raw, &o) != nil || (class == "PAID" && o.Phase != "settled") || (class == "OFFLINE" && o.Phase != "local-terminal") {
			rows.Close()
			return ErrPhysicalConflict
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	encoded, _ := json.Marshal(d)
	if err = retainPaidFact(ctx, tx, paidDomainFactID(d.DemandManifestDigest), d.AdoptionEnvelope); err != nil {
		return err
	}
	if err = retainPaidFact(ctx, tx, paidDomainBasisID(d.DemandManifestDigest), encoded); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) AcceptPaidDomain(ctx context.Context, demand, adoption string, original []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	d, err := readPaidDomain(ctx, tx, demand)
	if err != nil || d.AdoptionEnvelopeDigest != adoption {
		return ErrPhysicalConflict
	}
	if err = retainPaidFact(ctx, tx, "paid_domain_acceptance_"+demand[7:], original); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PaidDomain(ctx context.Context, demand string) (PaidDomain, error) {
	return readPaidDomain(ctx, s.db, demand)
}

// Only the owning independently verifying HTTP consumer calls this after the
// backend returns its FIRST exact signed acceptance. A POST ACK is insufficient.
func (s *Store) ConfirmPaidDomainAcceptance(ctx context.Context, demand string, original []byte) error {
	if !model.PhysicalDigestValid(demand) {
		return ErrPhysicalConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var local []byte
	if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "paid_domain_acceptance_"+demand[7:]).Scan(&local) != nil || !bytes.Equal(local, original) {
		return ErrPhysicalConflict
	}
	if err = retainPaidFact(ctx, tx, "paid_backend_acceptance_"+demand[7:], original); err != nil {
		return err
	}
	return tx.Commit()
}
func paidDomainHistory(ctx context.Context, q paidQuery, d PaidDomain) ([]PhysicalOperation, error) {
	global, err := physicalHistory(ctx, q)
	if err != nil {
		return nil, err
	}
	own := []PhysicalOperation{}
	for _, o := range global {
		if o.Permit.PaidDomain == d.DemandManifestDigest {
			if o.Permit.Case != d.Case {
				return nil, ErrPhysicalConflict
			}
			own = append(own, o)
		}
	}
	return own, nil
}
func (s *Store) admitPaidDomain(ctx context.Context, tx *sql.Tx, id string, p PhysicalPermit) error {
	d, err := readPaidDomain(ctx, tx, p.PaidDomain)
	if err != nil || d.Case != p.Case {
		return ErrPhysicalConflict
	}
	var acceptance []byte
	if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "paid_domain_acceptance_"+p.PaidDomain[7:]).Scan(&acceptance) != nil || len(acceptance) == 0 {
		return ErrPhysicalConflict
	}
	var backendAcceptance []byte
	if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "paid_backend_acceptance_"+p.PaidDomain[7:]).Scan(&backendAcceptance) != nil || !bytes.Equal(backendAcceptance, acceptance) {
		return ErrPhysicalConflict
	}
	cut, err := physicalLedgerCut(ctx, tx)
	if err != nil || cut.Owner != nil {
		return ErrPhysicalConflict
	}
	own, err := paidDomainHistory(ctx, tx, d)
	if err != nil {
		return err
	}
	if cut.Cumulative.PhysicalRequests != d.Bases.PhysicalRequests+len(own) {
		return ErrPhysicalConflict
	}
	if err = validatePhysicalAppend(d.Case, own, id, p); err != nil {
		return err
	}
	association, err := paidAssociation(d, p, cut.Cumulative.PhysicalRequests+1)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(association)
	if err = retainPaidFact(ctx, tx, paidOperationFactID(id), raw); err != nil {
		return err
	}
	return nil
}
