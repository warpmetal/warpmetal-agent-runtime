package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Same protected operator leaves as initial-decision selection. The node reply
// supplies no signature, case authority or permission to create an allocation.
func (p *Producer) ReadControllerDeclaredStage(ctx context.Context, current model.Manifest, parent model.ControllerParentIntent, readout model.ControllerStageReadout) (ControllerDeclaredInput, error) {
	var empty ControllerDeclaredInput
	b, _, err := p.CurrentPhysicalBaseline(ctx, current)
	if err != nil {
		return empty, err
	}
	if b.Case.FormatVersion != 3 || len(b.SourceContinuation) != 0 || b.TaskID != parent.Owner.TaskID {
		return empty, ErrUntrusted
	}
	public, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil || Digest(public) != b.Case.OperatorKeySHA256 {
		return empty, ErrUntrusted
	}
	rawDemand, err := p.read("physical-gate-demand-envelope.json", 65536)
	var envelope ChildEnvelope[DemandManifest]
	now := time.Now()
	if err != nil || decode(rawDemand, &envelope) != nil || verifyChildEnvelope(rawDemand, envelope.KeyID, public) != nil || envelope.Payload.validate(b.Case, now) != nil {
		return empty, ErrUntrusted
	}
	if rootPrivate(p.config.EvidenceRoot, true) != nil {
		return empty, ErrUntrusted
	}
	if _, err = os.Lstat(filepath.Join(p.config.EvidenceRoot, "controller-input-contexts.json")); errors.Is(err, os.ErrNotExist) {
		return empty, ErrControllerDeclarationPending
	} else if err != nil {
		return empty, err
	}
	raw, err := p.read("controller-input-contexts.json", 65536)
	if err != nil {
		return empty, err
	}
	item, err := verifyControllerStageDeclaration(raw, public, b.Case, envelope.Payload, parent, readout, now)
	if err != nil {
		return empty, err
	}
	again, err := p.read("controller-input-contexts.json", 65536)
	if err != nil || !bytes.Equal(raw, again) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	return item, nil
}

func verifyControllerStageDeclaration(raw, public []byte, c RealCase, d DemandManifest, parent model.ControllerParentIntent, r model.ControllerStageReadout, now time.Time) (ControllerDeclaredInput, error) {
	var empty ControllerDeclaredInput
	var envelope ChildEnvelope[json.RawMessage]
	if c.FormatVersion != 3 || !c.typed() || d.validate(c, now) != nil || decode(raw, &envelope) != nil || verifyChildEnvelope(raw, envelope.KeyID, public) != nil || Digest(public) != c.OperatorKeySHA256 || workflowcontract.Validate(workflowcontract.ManagerSingle, "inputDeclarationPayload4", envelope.Payload) != nil || workflowcontract.Validate(workflowcontract.ControllerStage, "controllerStageReadout1", canonicalBytes(r)) != nil {
		return empty, ErrUntrusted
	}
	if parent.DesiredState != "active" || r.ApplicationOperationID != parent.ApplicationOperationID || r.ServiceRegistrationID != parent.ServiceRegistrationID || r.ServiceGeneration != parent.ServiceGeneration || r.CaseID != c.CaseID || r.CaseManifestDigest != c.CaseManifestDigest || r.DemandManifestDigest != c.DemandManifestDigest || r.DeclarationItemDigest != CanonicalDigest(r.Item) {
		return empty, ErrUntrusted
	}
	var decl struct {
		CaseID, CaseManifestDigest, DemandManifestDigest, DeclaredAt, NotAfter string
		Inputs                                                                 []ControllerDeclaredInput
	}
	if json.Unmarshal(envelope.Payload, &decl) != nil || decl.CaseID != c.CaseID || decl.CaseManifestDigest != c.CaseManifestDigest || decl.DemandManifestDigest != c.DemandManifestDigest || decl.DemandManifestDigest != CanonicalDigest(d) {
		return empty, ErrUntrusted
	}
	at, ae := time.Parse(time.RFC3339Nano, decl.DeclaredAt)
	end, ee := time.Parse(time.RFC3339Nano, decl.NotAfter)
	start, se := time.Parse(time.RFC3339Nano, d.DeclaredAt)
	until, ue := time.Parse(time.RFC3339Nano, d.NotAfter)
	if ae != nil || ee != nil || se != nil || ue != nil || at.Before(start) || at.After(now) || !now.Before(end) || end.After(until) {
		return empty, ErrUntrusted
	}
	seenInputs, seenAllocations := map[string]bool{}, map[string]bool{}
	var selected *ControllerDeclaredInput
	for _, item := range decl.Inputs {
		a, err := d.allocation(item.AllocationID)
		id := item.ServiceRegistrationID + "\x00" + item.InputID
		if err != nil || seenInputs[id] || seenAllocations[item.AllocationID] || a.Kind != "parent" || a.SourceID != item.ServiceRegistrationID || a.ScopeDigest != CanonicalDigest(a.Scope) || a.PreparationOrdinal != item.PreparationOrdinal || a.FirstPhysicalIndex != item.PhysicalIndex {
			return empty, ErrUntrusted
		}
		seenInputs[id], seenAllocations[item.AllocationID] = true, true
		if a.Name != r.AllocationName {
			continue
		}
		if selected != nil || a.Scope != parent.Owner || a.SourceID != parent.ServiceRegistrationID || a.ModelRequests != 1 || a.AccessRequests != 0 || a.FirstPhysicalIndex != a.LastPhysicalIndex || !sameProduct(item, r.Item) || item.Target.Role != parent.Role {
			return empty, ErrUntrusted
		}
		switch r.AllocationName {
		case "manager_integrate", "manager_review":
			purpose := "integrate"
			if r.AllocationName == "manager_review" {
				purpose = "review"
			}
			var target struct{ Purpose string }
			if json.Unmarshal(canonicalBytes(item.Target), &target) != nil || parent.Role != "manager" || item.Target.Kind != "manager_intent" || target.Purpose != purpose {
				return empty, ErrUntrusted
			}
		case "manager_accept":
			if parent.Role != "manager" || item.Target.Kind != "result_decision" {
				return empty, ErrUntrusted
			}
		case "followup", "peer_advice":
			if parent.Role != "orchestrator" || item.Target.Kind != "advice" {
				return empty, ErrUntrusted
			}
		case "continuation":
			if parent.Role != "manager" || item.Target.Kind != "advice_decision" {
				return empty, ErrUntrusted
			}
		default:
			return empty, ErrUntrusted // Initial stages retain their existing owner path.
		}
		copy := item
		selected = &copy
	}
	if selected == nil {
		return empty, ErrControllerDeclarationPending
	}
	return *selected, nil
}
