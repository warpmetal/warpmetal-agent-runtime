package qualification

import (
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func (c RealCase) legacy() bool {
	return c.ParticipantInventoryDigest == "" && c.AccountingVersion == 0 && c.ProviderPolicyDigest == "" && c.FormatVersion == 0 && c.ModelRequests == 0 && c.AccessRequests == 0 && c.PhysicalCeiling == 0 && c.USDCeilingMicros == 0 && c.DemandManifestDigest == "" && c.QualificationTuples == 0 && c.TupleInventoryDigest == "" && c.ControlsDigest == ""
}
func (c RealCase) typed() bool {
	raw, err := json.Marshal(c)
	pricing := PricingDigest()
	if c.FormatVersion == 3 || c.FormatVersion == 5 {
		pricing = providerpolicy.FlashPricingDigest()
	}
	return err == nil && workflowcontract.Validate(c.contract(), "typedCase", raw) == nil && c.PricingDigest == pricing
}

func (c RealCase) contract() string {
	if c.FormatVersion == 5 {
		return workflowcontract.BudgetParticipants
	}
	if c.FormatVersion == 3 {
		return workflowcontract.BudgetProvider
	}
	if c.FormatVersion == 2 {
		return workflowcontract.Budget
	}
	return workflowcontract.Manager
}

type DemandAllocation struct {
	Name               string                `json:"name,omitempty"`
	TupleDigest        string                `json:"tupleDigest,omitempty"`
	DependsOn          []string              `json:"dependsOn,omitempty"`
	AllocationID       string                `json:"allocationId"`
	Kind               string                `json:"kind"`
	Scope              model.ControllerOwner `json:"scope"`
	SourceID           string                `json:"sourceId"`
	ScopeDigest        string                `json:"scopeDigest"`
	PreparationOrdinal int                   `json:"preparationOrdinal"`
	FirstPhysicalIndex int                   `json:"firstPhysicalIndex"`
	LastPhysicalIndex  int                   `json:"lastPhysicalIndex"`
	ModelRequests      int                   `json:"modelRequests"`
	AccessRequests     int                   `json:"accessRequests"`
	USDMicros          int64                 `json:"usdMicros"`
}
type DemandManifest struct {
	ParticipantInventoryDigest string                      `json:"-"`
	AccountingVersion          int                         `json:"-"`
	ProviderPolicyDigest       string                      `json:"-"`
	MaximumExposureMicros      int64                       `json:"-"`
	PhysicalRequestLimit       int                         `json:"-"`
	FormatVersion              int                         `json:"formatVersion"`
	CaseID                     string                      `json:"caseId"`
	CaseManifestDigest         string                      `json:"caseManifestDigest"`
	LedgerID                   string                      `json:"ledgerId"`
	CandidateInventoryDigest   string                      `json:"candidateInventoryDigest"`
	AccountScopeDigest         string                      `json:"accountScopeDigest"`
	PricingDigest              string                      `json:"pricingDigest"`
	RequestReserveMicros       int64                       `json:"requestReserveMicros"`
	Allocations                map[string]DemandAllocation `json:"allocations"`
	SDKRetries                 int                         `json:"sdkRetries"`
	ApplicationRetries         int                         `json:"applicationRetries"`
	AuxiliaryRequests          int                         `json:"auxiliaryRequests"`
	DeclaredAt                 string                      `json:"declaredAt"`
	NotAfter                   string                      `json:"notAfter"`
	AllocationList             []DemandAllocation          `json:"-"`
	TupleInventoryDigest       string                      `json:"-"`
	Controls                   json.RawMessage             `json:"-"`
	Tariff                     json.RawMessage             `json:"-"`
	SourceContinuation         json.RawMessage             `json:"-"`
}

func (d DemandManifest) validate(c RealCase, now time.Time) error {
	if d.FormatVersion == 3 || c.FormatVersion == 3 || d.FormatVersion == 5 || c.FormatVersion == 5 {
		return d.validateProvider(c, now)
	}
	raw, err := json.Marshal(d)
	if err != nil || !c.typed() || workflowcontract.Validate(d.contract(c), "demandManifest", raw) != nil || CanonicalDigest(d) != c.DemandManifestDigest ||
		d.CaseID != c.CaseID || d.CaseManifestDigest != c.CaseManifestDigest || d.PricingDigest != c.PricingDigest || d.LedgerID != c.LedgerID || !live(d.NotAfter, now) {
		return ErrUntrusted
	}
	issued, err := time.Parse(time.RFC3339Nano, d.DeclaredAt)
	expiry, xe := time.Parse(time.RFC3339Nano, d.NotAfter)
	if err != nil || xe != nil || issued.After(now) || !issued.Before(expiry) {
		return ErrUntrusted
	}
	ids, slots, ordinals := map[string]bool{}, map[int]bool{}, map[int]bool{}
	var requests, preparations, models, access int
	var usd int64
	if len(d.SourceContinuation) != 0 {
		opening, err := sourceContinuationOpening(d.SourceContinuation, c)
		if err != nil {
			return err
		}
		requests, models, access, preparations, usd = opening.PhysicalRequests, opening.ModelRequests, opening.PhysicalRequests-opening.ModelRequests, opening.Preparations, int64(opening.PhysicalRequests)*RequestMicros
		for n := 1; n <= opening.PhysicalRequests; n++ {
			slots[n] = true
		}
		for n := 1; n <= opening.Preparations; n++ {
			ordinals[n] = true
		}
	}
	for _, a := range d.all() {
		if ids[a.AllocationID] || a.LastPhysicalIndex-a.FirstPhysicalIndex+1 != a.ModelRequests+a.AccessRequests || a.USDMicros != int64(a.ModelRequests+a.AccessRequests)*RequestMicros {
			return ErrUntrusted
		}
		ids[a.AllocationID] = true
		if a.PreparationOrdinal != 0 {
			if ordinals[a.PreparationOrdinal] {
				return ErrUntrusted
			}
			ordinals[a.PreparationOrdinal] = true
			preparations++
		}
		for slot := a.FirstPhysicalIndex; slot <= a.LastPhysicalIndex; slot++ {
			if slots[slot] {
				return ErrUntrusted
			}
			slots[slot] = true
			requests++
		}
		models += a.ModelRequests
		access += a.AccessRequests
		usd += a.USDMicros
	}
	if requests != c.Requests || preparations != c.Preparations || models != c.ModelRequests || access != c.AccessRequests || usd != c.USDMicros {
		return ErrUntrusted
	}
	if c.FormatVersion == 2 {
		return d.validateRevision14(c, now)
	}
	return nil
}

func (d DemandManifest) contract(c RealCase) string {
	if c.FormatVersion == 2 && len(d.SourceContinuation) != 0 {
		return workflowcontract.BudgetSourceContinuation
	}
	return c.contract()
}
func (d DemandManifest) allocation(id string) (DemandAllocation, error) {
	for _, a := range d.all() {
		if a.AllocationID == id {
			return a, nil
		}
	}
	return DemandAllocation{}, ErrUntrusted
}

// Existing signed snapshot store and public operator verifier. This reads only;
// it does not stage, publish, reserve, reallocate or replace any live case.
func (s Store) ReadTypedDemand(box model.Sandbox, c RealCase, now time.Time) (DemandManifest, error) {
	var d DemandManifest
	tree, key, err := s.Paths(box.ID)
	if err != nil || !c.typed() {
		return d, ErrUntrusted
	}
	raw, err := s.signed(tree, key, "snapshots/"+c.DemandManifestDigest[7:]+"/demand", 65536)
	if err != nil || decodeClosed(raw, &d) != nil || !bytesCanonical(raw, d) || d.validate(c, now) != nil {
		return DemandManifest{}, ErrUntrusted
	}
	if len(d.SourceContinuation) != 0 {
		authority, err := s.read(filepath.Join(tree, "snapshots", c.DemandManifestDigest[7:], "source-authority.json"), tree, key, 65536)
		if err != nil || workflowcontract.Validate(workflowcontract.BudgetSourceContinuation, "authority2", authority) != nil || childString(childFields(authority), "evidenceClass") != "source" || !sameProduct(childFields(authority)["sourceContinuation"], d.SourceContinuation) || !sameProduct(childFields(authority)["case"], c) {
			return DemandManifest{}, ErrUntrusted
		}
	}
	keyBytes, err := s.read(key, tree, key, 4096)
	if err != nil || Digest(keyBytes) != c.OperatorKeySHA256 {
		return DemandManifest{}, ErrUntrusted
	}
	return d, nil
}
func bytesCanonical(raw []byte, v any) bool { return string(raw) == string(canonicalBytes(v)) }
