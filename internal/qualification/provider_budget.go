package qualification

import (
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// This validates the immutable finite plan, not current financial exposure.
// Durable admission must still add settled usage, holds and the next reserve.
func (d DemandManifest) validateProvider(c RealCase, now time.Time) error {
	p, selected := providerpolicy.Select(c.ProviderPolicyDigest)
	family := (c.FormatVersion == 3 && d.FormatVersion == 3 && c.ProviderPolicyDigest == providerpolicy.FlashDigest && c.ParticipantInventoryDigest == "" && d.ParticipantInventoryDigest == "") || (c.FormatVersion == 5 && d.FormatVersion == 5 && c.ProviderPolicyDigest == providerpolicy.ParticipantDigest && c.ParticipantInventoryDigest == d.ParticipantInventoryDigest && hash.MatchString(c.ParticipantInventoryDigest))
	raw, err := json.Marshal(d)
	if err != nil || !selected || !family || !c.typed() ||
		workflowcontract.Validate(c.contract(), "demandManifest", raw) != nil ||
		CanonicalDigest(d) != c.DemandManifestDigest || d.ProviderPolicyDigest != c.ProviderPolicyDigest ||
		d.AccountingVersion != p.Accounting.Version || d.CaseID != c.CaseID || d.CaseManifestDigest != c.CaseManifestDigest ||
		d.LedgerID != c.LedgerID || d.PricingDigest != c.PricingDigest || d.TupleInventoryDigest != c.TupleInventoryDigest ||
		CanonicalDigest(d.Controls) != c.ControlsDigest || !live(d.NotAfter, now) {
		return ErrUntrusted
	}
	issued, ie := time.Parse(time.RFC3339Nano, d.DeclaredAt)
	expiry, ee := time.Parse(time.RFC3339Nano, d.NotAfter)
	if ie != nil || ee != nil || issued.After(now) || !issued.Before(expiry) {
		return ErrUntrusted
	}
	ids, names, slots, preps := map[string]DemandAllocation{}, map[string]bool{}, map[int]bool{}, map[int]bool{}
	models, access, quals := 0, 0, 0
	weights := map[string]int{"access": 0, "qualification": 2, "parent": 1, "coding_worker": 2, "integrator": 2, "reviewer": 1}
	for _, a := range d.AllocationList {
		weight, known := weights[a.Kind]
		accessCount := 0
		if a.Kind == "access" {
			accessCount = 1
		}
		if !known || ids[a.AllocationID].AllocationID != "" || names[a.Name] || a.ModelRequests != weight || a.AccessRequests != accessCount ||
			a.FirstPhysicalIndex < 1 || a.LastPhysicalIndex > c.Requests ||
			a.LastPhysicalIndex-a.FirstPhysicalIndex+1 != weight+accessCount || a.USDMicros != int64(weight+accessCount)*p.Accounting.RequestReserveMicros ||
			(a.Kind == "access") != (a.PreparationOrdinal == 0) || a.PreparationOrdinal > c.Preparations {
			return ErrUntrusted
		}
		ids[a.AllocationID], names[a.Name] = a, true
		for n := a.FirstPhysicalIndex; n <= a.LastPhysicalIndex; n++ {
			if slots[n] {
				return ErrUntrusted
			}
			slots[n] = true
		}
		if a.PreparationOrdinal > 0 {
			if preps[a.PreparationOrdinal] {
				return ErrUntrusted
			}
			preps[a.PreparationOrdinal] = true
		}
		models += weight
		access += accessCount
		if a.Kind == "qualification" {
			quals++
		}
	}
	if len(slots) != c.Requests || len(preps) != c.Preparations || models != c.ModelRequests || access != c.AccessRequests || quals != c.QualificationTuples || c.Requests != models+access {
		return ErrUntrusted
	}
	for n := 1; n <= c.Preparations; n++ {
		if !preps[n] {
			return ErrUntrusted
		}
	}
	active, done := map[string]bool{}, map[string]bool{}
	var visit func(string) bool
	visit = func(id string) bool {
		a, ok := ids[id]
		if !ok || active[id] {
			return false
		}
		if done[id] {
			return true
		}
		active[id] = true
		seen := map[string]bool{}
		for _, dep := range a.DependsOn {
			if seen[dep] || !visit(dep) {
				return false
			}
			seen[dep] = true
		}
		active[id], done[id] = false, true
		return true
	}
	for id := range ids {
		if !visit(id) {
			return ErrUntrusted
		}
	}
	return nil
}
