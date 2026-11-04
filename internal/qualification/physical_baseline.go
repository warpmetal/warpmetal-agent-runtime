package qualification

import (
	"context"
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"time"
)

type PhysicalBaseline struct {
	TaskID             string              `json:"taskId"`
	Case               RealCase            `json:"case"`
	HistoryDigests     []string            `json:"historyDigests"`
	Digest             string              `json:"digest"`
	SourceContinuation json.RawMessage     `json:"sourceContinuation,omitempty"`
	PaidDomain         *state.PaidDomain   `json:"-"`
	ProviderCase       *state.PhysicalCase `json:"-"`
}

// Fixed root-private measured SAME history references, never empty-by-default.
// Import requires the complete installed reader/archive/build/self adoption and
// original immutable records. The normal owning baseline producer must supply
// actual legacy/access history; no signed-policy reflection is a history producer.
func (p *Producer) CurrentPhysicalBaseline(ctx context.Context, current model.Manifest) (PhysicalBaseline, []state.PhysicalOperation, error) {
	var b PhysicalBaseline
	if p == nil {
		return b, nil, ErrUntrusted
	}
	raw, err := p.read("physical-gate-baseline.json", 65536)
	if err != nil || decodeClosed(raw, &b) != nil || !bytesCanonical(raw, b) || !safeID.MatchString(b.TaskID) || !hash.MatchString(b.Digest) {
		return b, nil, ErrUntrusted
	}
	preimage := map[string]any{"taskId": b.TaskID, "case": b.Case, "historyDigests": b.HistoryDigests}
	if len(b.SourceContinuation) != 0 {
		preimage["sourceContinuation"] = b.SourceContinuation
	}
	if CanonicalDigest(preimage) != b.Digest {
		return b, nil, ErrUntrusted
	}
	reader, err := verifyCurrentPlanReaderAdoption(ctx, b.TaskID, nil, current, p.config, p.read, SelfBinaryDigest, p.verifyPlanReaderArchive)
	if err != nil || reader.CaseManifestDigest != b.Case.CaseManifestDigest {
		return b, nil, ErrUntrusted
	}
	if !b.Case.typed() && !b.Case.legacy() {
		return b, nil, ErrUntrusted
	}
	if len(b.SourceContinuation) != 0 {
		if _, err := sourceContinuationOpening(b.SourceContinuation, b.Case); err != nil || len(b.HistoryDigests) != 3 {
			return b, nil, ErrUntrusted
		}
		var continuation SourceContinuation
		if decode(b.SourceContinuation, &continuation) != nil || verifyMeasuredSourceOpening(ctx, continuation, p.read) != nil {
			return b, nil, ErrUntrusted
		}
		authority, err := p.read("physical-gate-authority.json", 65536)
		if err != nil {
			return b, nil, ErrUntrusted
		}
		demand, err := p.read("physical-gate-demand-envelope.json", 65536)
		if err != nil {
			return b, nil, ErrUntrusted
		}
		public, err := p.read("physical-gate-operator.pem", 4096)
		if err != nil {
			return b, nil, ErrUntrusted
		}
		_, actual, err := VerifySourceContinuationAuthorityDemand(authority, demand, public, time.Now())
		if err != nil || !sameProduct(actual, continuation) || !sameProduct(childFields(authority)["case"], b.Case) {
			return b, nil, ErrUntrusted
		}
	}
	if b.Case.FormatVersion == 2 && len(b.SourceContinuation) == 0 {
		authority, err := p.read("physical-gate-authority.json", 65536)
		if err != nil || !sameProduct(childFields(authority)["case"], b.Case) {
			return b, nil, ErrUntrusted
		}
		if childString(childFields(authority), "evidenceClass") == "live" {
			if _, _, err := p.CurrentLiveWindowAuthority(ctx, b.Case); err != nil {
				return b, nil, ErrUntrusted
			}
		} else if workflowcontract.Validate(workflowcontract.Budget, "authority2", authority) != nil || childString(childFields(authority), "evidenceClass") != "source" {
			return b, nil, ErrUntrusted
		}
	}
	var history []state.PhysicalOperation
	for _, d := range b.HistoryDigests {
		if !hash.MatchString(d) {
			return b, nil, ErrUntrusted
		}
		raw, err := p.read("physical-baseline-history-"+d[7:]+".json", 65536)
		var o state.PhysicalOperation
		if err != nil || decodeClosed(raw, &o) != nil || !bytesCanonical(raw, o) || Digest(raw) != d || o.Permit.Case.TaskID != b.TaskID || o.Permit.Case.ServerID != current.ServerID {
			return b, nil, ErrUntrusted
		}
		// Preserve the original immutable import digest. Normalized current gate
		// authority is outside its original bytes, avoiding a cyclic baseline hash.
		o.ImportedOriginalDigest = d
		o.Permit.Case = b.StoreCase(current.ServerID)
		history = append(history, o)
	}
	if len(b.SourceContinuation) != 0 {
		var declaration SourceContinuation
		_ = decode(b.SourceContinuation, &declaration)
		var actual int64
		for i, o := range history {
			consumer := o.Permit.Request.Consumer
			if o.Phase != "settled" || o.Settlement == nil || o.Permit.Request.OuterPhysicalIndex != i+1 || o.Permit.Request.PreparationID != declaration.Predecessor.PreparationID {
				return b, nil, ErrUntrusted
			}
			if i == 0 {
				if consumer != "access" || o.Permit.PreparationOrdinal != 0 || o.Permit.AllocationID != declaration.AllocationJoins[0].AllocationID {
					return b, nil, ErrUntrusted
				}
			} else if consumer != "qualification" || o.Permit.PreparationOrdinal != 1 || o.Permit.AllocationID != declaration.AllocationJoins[1].AllocationID {
				return b, nil, ErrUntrusted
			}
			actual += o.Settlement.UsageUsdMicros
		}
		if actual != declaration.Opening.ActualUSDMicros {
			return b, nil, ErrUntrusted
		}
	}
	return b, history, nil
}
func (b PhysicalBaseline) StoreCase(serverID string) state.PhysicalCase {
	if b.ProviderCase != nil && b.ProviderCase.ServerID == serverID {
		return *b.ProviderCase
	}
	if b.PaidDomain != nil && b.PaidDomain.Case.ServerID == serverID {
		return b.PaidDomain.Case
	}
	models, access := b.Case.ModelRequests, b.Case.AccessRequests
	if b.Case.legacy() {
		models = b.Case.Requests
		access = 0
	}
	return state.PhysicalCase{TaskID: b.TaskID, ServerID: serverID, CaseDigest: b.Case.CaseManifestDigest, BaselineDigest: b.Digest, Requests: b.Case.Requests, Preparations: b.Case.Preparations, ModelRequests: models, AccessRequests: access, UsdMicros: b.Case.USDMicros}
}
func (b PhysicalBaseline) PaidDomainDigest() string {
	if b.PaidDomain == nil {
		return ""
	}
	return b.PaidDomain.DemandManifestDigest
}
