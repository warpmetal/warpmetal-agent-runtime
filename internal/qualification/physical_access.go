package qualification

import (
	"context"
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"time"
)

// Approves only the current own access allocation plus original operator-signed
// capability. Node context cannot enroll itself or create financial authority.
func (s Store) ApprovedPhysicalAccess(box model.Sandbox, c RealCase, context model.QualificationAccessContext, app Applicability, capability []byte, now time.Time) (DemandAllocation, error) {
	var empty DemandAllocation
	if context.Validate(context.QualificationID, now) != nil || context.TupleDigest != CanonicalDigest(app) || context.DemandManifestDigest != c.DemandManifestDigest || app.SandboxID != box.ID || app.SandboxGeneration != box.Generation {
		return empty, ErrUntrusted
	}
	d, err := s.ReadTypedDemand(box, c, now)
	if err != nil {
		return empty, err
	}
	for _, a := range d.all() {
		allocation, _ := json.Marshal(a)
		if d.FormatVersion == 2 || d.FormatVersion == 3 {
			allocation, err = typedAllocationJSON(a)
			if err != nil {
				return DemandAllocation{}, err
			}
		}
		if CanonicalDigest(json.RawMessage(allocation)) == CanonicalDigest(context.Allocation) {
			if empty.AllocationID != "" {
				return DemandAllocation{}, ErrUntrusted
			}
			empty = a
		}
	}
	if empty.AllocationID == "" || empty.Kind != "access" || empty.TupleDigest != context.TupleDigest || empty.Scope.AccountID != app.AccountID || empty.Scope.TaskID != app.TaskID || empty.Scope.ServerID != app.ServerID || empty.Scope.SandboxID != box.ID || empty.Scope.SandboxGeneration != box.Generation || empty.AccessRequests != 1 || empty.ModelRequests != 0 || empty.PreparationOrdinal != 0 || empty.FirstPhysicalIndex != empty.LastPhysicalIndex {
		return DemandAllocation{}, ErrUntrusted
	}
	var accounting struct {
		SubjectID, ReservationID, ConfigDigest, DemandManifestDigest, LedgerID string
		Allocation                                                             json.RawMessage
	}
	if json.Unmarshal(context.Accounting, &accounting) != nil || accounting.SubjectID != context.QualificationID || accounting.ReservationID != context.ReservationID || accounting.ConfigDigest != context.AuthorityDigest || accounting.DemandManifestDigest != context.DemandManifestDigest || accounting.LedgerID != c.LedgerID || CanonicalDigest(accounting.Allocation) != CanonicalDigest(context.Allocation) {
		return DemandAllocation{}, ErrUntrusted
	}
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return DemandAllocation{}, err
	}
	pem, err := s.read(key, tree, key, 4096)
	if err != nil || Digest(pem) != c.OperatorKeySHA256 {
		return DemandAllocation{}, ErrUntrusted
	}
	var envelope struct {
		Payload json.RawMessage `json:"payload"`
		KeyID   string          `json:"keyId"`
	}
	if json.Unmarshal(capability, &envelope) != nil || verifyChildEnvelope(capability, envelope.KeyID, pem) != nil {
		return DemandAllocation{}, ErrUntrusted
	}
	var cap struct {
		FormatVersion        int    `json:"formatVersion,omitempty"`
		ProviderPolicyDigest string `json:"providerPolicyDigest,omitempty"`
		Kind                 string `json:"kind"`
		AccountID            string `json:"accountId"`
		TaskID               string `json:"taskId"`
		ConnectionID         string `json:"connectionId"`
		ConnectionRevision   int64  `json:"connectionRevision"`
		ProviderID           string `json:"providerId"`
		ModelID              string `json:"modelId"`
		AuthMode             string `json:"authMode"`
		Scope                string `json:"scope"`
		SourceDigest         string `json:"sourceDigest"`
		NotAfter             string `json:"notAfter"`
	}
	var fields map[string]json.RawMessage
	if decodeClosed(envelope.Payload, &cap) != nil || json.Unmarshal(envelope.Payload, &fields) != nil || cap.AccountID != app.AccountID || cap.TaskID != app.TaskID || cap.ConnectionID != app.Connection.ConnectionID || cap.ConnectionRevision != app.Connection.ConnectionRevision || cap.AuthMode != "api_key" || !hash.MatchString(cap.SourceDigest) || !live(cap.NotAfter, now) {
		return DemandAllocation{}, ErrUntrusted
	}
	if context.FormatVersion == 2 {
		if c.FormatVersion != 3 || app.ProviderPolicyDigest != c.ProviderPolicyDigest || workflowcontract.Validate(workflowcontract.QualificationProvider, "qualificationAccessCapability", envelope.Payload) != nil || cap.ProviderPolicyDigest != c.ProviderPolicyDigest || cap.ProviderID != providerpolicy.Flash().ProviderID || cap.ModelID != providerpolicy.Flash().ModelID {
			return DemandAllocation{}, ErrUntrusted
		}
	} else if len(fields) != 11 || cap.FormatVersion != 0 || cap.ProviderPolicyDigest != "" || cap.ProviderID != "openai" || cap.ModelID != RealModel {
		return DemandAllocation{}, ErrUntrusted
	}
	if !(cap.Kind == "reviewed_owner_project_capability" && cap.Scope == "responses:write") && !(cap.Kind == "owner_authorized_qualification_probe" && cap.Scope == "qualification:responses_probe") {
		return DemandAllocation{}, ErrUntrusted
	}
	return empty, nil
}
func (p *Producer) VerifyPhysicalAccessAuthority(ctx context.Context, context model.QualificationAccessContext, b PhysicalBaseline) error {
	if p == nil || ctx.Err() != nil {
		return ErrUntrusted
	}
	// Original whole root-private authority config, not fields reflected from a
	// GET or from the RPC. Its contextual owner independently provisioned it.
	raw, err := p.read("physical-gate-authority.json", 65536)
	if err != nil || Digest(raw) != context.AuthorityDigest {
		return ErrUntrusted
	}
	var authority struct {
		Case               RealCase `json:"case"`
		CaseManifestDigest string   `json:"caseManifestDigest"`
	}
	if json.Unmarshal(raw, &authority) != nil || authority.Case != b.Case || authority.CaseManifestDigest != b.Case.CaseManifestDigest {
		return ErrUntrusted
	}
	fields := childFields(raw)
	if fields["sourceContinuation"] != nil || len(b.SourceContinuation) != 0 {
		if !sameProduct(fields["sourceContinuation"], b.SourceContinuation) {
			return ErrUntrusted
		}
		public, err := p.read("physical-gate-operator.pem", 4096)
		if err != nil {
			return ErrUntrusted
		}
		demand, err := p.read("physical-gate-demand-envelope.json", 65536)
		if err != nil {
			return ErrUntrusted
		}
		_, continuation, err := VerifySourceContinuationAuthorityDemand(raw, demand, public, time.Now())
		if err != nil || context.QualificationID == continuation.Predecessor.QualificationID || context.PreparationID == continuation.Predecessor.PreparationID || verifyMeasuredSourceOpening(ctx, continuation, p.read) != nil {
			return ErrUntrusted
		}
	} else if b.Case.FormatVersion == 2 {
		if childString(fields, "evidenceClass") == "live" {
			original, _, err := p.CurrentLiveWindowAuthority(ctx, b.Case)
			if err != nil || Digest(original) != context.AuthorityDigest {
				return ErrUntrusted
			}
		} else if workflowcontract.Validate(workflowcontract.Budget, "authority2", raw) != nil || childString(fields, "evidenceClass") != "source" {
			return ErrUntrusted
		}
	} else if b.Case.FormatVersion == 3 {
		if context.FormatVersion != 2 || context.ProviderPolicyDigest != b.Case.ProviderPolicyDigest || context.AccountingVersion != 2 || workflowcontract.Validate(workflowcontract.BudgetProvider, "authority3", raw) != nil {
			return ErrUntrusted
		}
	}
	return nil
}
