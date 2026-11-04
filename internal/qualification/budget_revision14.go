package qualification

import (
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func (c RealCase) MarshalJSON() ([]byte, error) {
	type legacy RealCase
	raw, err := json.Marshal(legacy(c))
	if err != nil || c.FormatVersion == 0 {
		return raw, err
	}
	// Mandatory zero model/access counts remain part of the signed typed wire;
	// legacy omission remains byte-identical. Do not change a payload to sign it.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	fields["modelRequests"], _ = json.Marshal(c.ModelRequests)
	fields["accessRequests"], _ = json.Marshal(c.AccessRequests)
	return json.Marshal(fields)
}

// Array order is signed knowledge. Keep revision14's original list, not a map
// reconstructed/sorted from model-selected names. Legacy map bytes stay unchanged.
func (d DemandManifest) all() []DemandAllocation {
	if d.FormatVersion == 2 || d.FormatVersion == 3 || d.FormatVersion == 5 {
		return d.AllocationList
	}
	var out []DemandAllocation
	for _, a := range d.Allocations {
		out = append(out, a)
	}
	return out
}

type demand2Wire struct {
	ParticipantInventoryDigest string            `json:"participantInventoryDigest,omitempty"`
	AccountingVersion          int               `json:"accountingVersion,omitempty"`
	ProviderPolicyDigest       string            `json:"providerPolicyDigest,omitempty"`
	MaximumExposureMicros      int64             `json:"maximumExposureMicros,omitempty"`
	PhysicalRequestLimit       int               `json:"physicalRequestLimit,omitempty"`
	FormatVersion              int               `json:"formatVersion"`
	CaseID                     string            `json:"caseId"`
	CaseManifestDigest         string            `json:"caseManifestDigest"`
	LedgerID                   string            `json:"ledgerId"`
	CandidateInventoryDigest   string            `json:"candidateInventoryDigest"`
	AccountScopeDigest         string            `json:"accountScopeDigest"`
	PricingDigest              string            `json:"pricingDigest"`
	TupleInventoryDigest       string            `json:"tupleInventoryDigest"`
	RequestReserveMicros       int64             `json:"requestReserveMicros"`
	Allocations                []json.RawMessage `json:"allocations"`
	Controls                   json.RawMessage   `json:"controls"`
	Tariff                     json.RawMessage   `json:"tariff"`
	DeclaredAt                 string            `json:"declaredAt"`
	NotAfter                   string            `json:"notAfter"`
	SourceContinuation         json.RawMessage   `json:"sourceContinuation,omitempty"`
}

func (d DemandManifest) MarshalJSON() ([]byte, error) {
	type legacy DemandManifest
	if d.FormatVersion != 2 && d.FormatVersion != 3 && d.FormatVersion != 5 {
		return json.Marshal(legacy(d))
	}
	w := demand2Wire{ParticipantInventoryDigest: d.ParticipantInventoryDigest, AccountingVersion: d.AccountingVersion, ProviderPolicyDigest: d.ProviderPolicyDigest, MaximumExposureMicros: d.MaximumExposureMicros, PhysicalRequestLimit: d.PhysicalRequestLimit, FormatVersion: d.FormatVersion, CaseID: d.CaseID, CaseManifestDigest: d.CaseManifestDigest, LedgerID: d.LedgerID,
		CandidateInventoryDigest: d.CandidateInventoryDigest, AccountScopeDigest: d.AccountScopeDigest, PricingDigest: d.PricingDigest,
		TupleInventoryDigest: d.TupleInventoryDigest, RequestReserveMicros: d.RequestReserveMicros, Controls: d.Controls, Tariff: d.Tariff,
		DeclaredAt: d.DeclaredAt, NotAfter: d.NotAfter, Allocations: []json.RawMessage{}, SourceContinuation: d.SourceContinuation}
	for _, a := range d.AllocationList {
		raw, err := typedAllocationJSON(a)
		if err != nil {
			return nil, err
		}
		w.Allocations = append(w.Allocations, raw)
	}
	return json.Marshal(w)
}

// Typed signed demand requires dependsOn even for the first empty dependency
// list. Use its same representation for individual allocation comparisons.
func typedAllocationJSON(a DemandAllocation) (json.RawMessage, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	fields := childFields(raw)
	deps := a.DependsOn
	if deps == nil {
		deps = []string{}
	}
	fields["dependsOn"], _ = json.Marshal(deps)
	return json.Marshal(fields)
}
func (d *DemandManifest) UnmarshalJSON(raw []byte) error {
	var header struct {
		FormatVersion int `json:"formatVersion"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return ErrUntrusted
	}
	type legacy DemandManifest
	if header.FormatVersion != 2 && header.FormatVersion != 3 && header.FormatVersion != 5 {
		var v legacy
		if decode(raw, &v) != nil {
			return ErrUntrusted
		}
		*d = DemandManifest(v)
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ErrUntrusted
	}
	document := workflowcontract.Budget
	if header.FormatVersion == 5 {
		document = workflowcontract.BudgetParticipants
	}
	if header.FormatVersion == 3 {
		document = workflowcontract.BudgetProvider
	}
	if _, present := fields["sourceContinuation"]; present && header.FormatVersion == 2 {
		document = workflowcontract.BudgetSourceContinuation
	}
	if workflowcontract.Validate(document, "demandManifest", raw) != nil {
		return ErrUntrusted
	}
	var w demand2Wire
	if decode(raw, &w) != nil {
		return ErrUntrusted
	}
	v := DemandManifest{ParticipantInventoryDigest: w.ParticipantInventoryDigest, AccountingVersion: w.AccountingVersion, ProviderPolicyDigest: w.ProviderPolicyDigest, MaximumExposureMicros: w.MaximumExposureMicros, PhysicalRequestLimit: w.PhysicalRequestLimit, FormatVersion: w.FormatVersion, CaseID: w.CaseID, CaseManifestDigest: w.CaseManifestDigest, LedgerID: w.LedgerID,
		CandidateInventoryDigest: w.CandidateInventoryDigest, AccountScopeDigest: w.AccountScopeDigest, PricingDigest: w.PricingDigest,
		TupleInventoryDigest: w.TupleInventoryDigest, RequestReserveMicros: w.RequestReserveMicros, Controls: w.Controls, Tariff: w.Tariff,
		DeclaredAt: w.DeclaredAt, NotAfter: w.NotAfter, AllocationList: []DemandAllocation{}, SourceContinuation: w.SourceContinuation}
	for _, raw := range w.Allocations {
		var a DemandAllocation
		if decode(raw, &a) != nil {
			return ErrUntrusted
		}
		v.AllocationList = append(v.AllocationList, a)
	}
	*d = v
	return nil
}

func (d DemandManifest) validateRevision14(c RealCase, now time.Time) error {
	if d.FormatVersion != 2 || c.FormatVersion != 2 || d.TupleInventoryDigest != c.TupleInventoryDigest || CanonicalDigest(d.Controls) != c.ControlsDigest ||
		c.Requests != c.ModelRequests+c.AccessRequests || c.Requests > c.PhysicalCeiling || c.USDMicros > c.USDCeilingMicros {
		return ErrUntrusted
	}
	names, ids := map[string]bool{}, map[string]DemandAllocation{}
	for _, a := range d.AllocationList {
		if names[a.Name] || ids[a.AllocationID].AllocationID != "" || a.LastPhysicalIndex < a.FirstPhysicalIndex || a.FirstPhysicalIndex < 1 || a.LastPhysicalIndex > c.Requests {
			return ErrUntrusted
		}
		names[a.Name] = true
		ids[a.AllocationID] = a
		if (a.Kind == "access") != (a.PreparationOrdinal == 0) || (a.Kind == "access" && (a.AccessRequests != 1 || a.ModelRequests != 0)) || (a.Kind != "access" && a.AccessRequests != 0) {
			return ErrUntrusted
		}
	}
	// Dependency cycles and missing allocation IDs are refused here. Exact current
	// consumer inventory/own-tuple qualification-prefix adoption remains a separate
	// prerequisite; this graph traversal cannot certify the selected full26 case.
	visiting, done := map[string]bool{}, map[string]bool{}
	var visit func(string) bool
	visit = func(id string) bool {
		if visiting[id] {
			return false
		}
		if done[id] {
			return true
		}
		a, ok := ids[id]
		if !ok {
			return false
		}
		visiting[id] = true
		for _, dep := range a.DependsOn {
			if !visit(dep) {
				return false
			}
		}
		visiting[id] = false
		done[id] = true
		return true
	}
	for id := range ids {
		if !visit(id) {
			return ErrUntrusted
		}
	}
	_ = now
	return nil
}
