package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Existing approvedInputItem2, not a new HTTP/task/relay contract.
type ControllerDeclaredInput struct {
	ServiceRegistrationID string                         `json:"serviceRegistrationId"`
	InputID               string                         `json:"inputId"`
	InputText             string                         `json:"inputText"`
	PolicyDigest          string                         `json:"policyDigest"`
	WorkflowRequestID     string                         `json:"workflowRequestId"`
	Plan                  model.ControllerPlan           `json:"plan"`
	Target                model.ControllerWorkflowTarget `json:"target"`
	AllocationID          string                         `json:"allocationId"`
	PreparationOrdinal    int                            `json:"preparationOrdinal"`
	PhysicalIndex         int                            `json:"physicalIndex"`
}

var ErrControllerDeclarationPending = errors.New("existing signed initialDecision declaration original pending")

// Read the operator's existing declaration and demand through the SAME protected
// producer store. No model output/template, policy reflection, signer or allocation.
func (p *Producer) ReadControllerInitialDecision(ctx context.Context, current model.Manifest, parent model.ControllerParentIntent, adviceContext model.ControllerApprovedInputContext, advice json.RawMessage) (ControllerDeclaredInput, error) {
	var empty ControllerDeclaredInput
	b, _, err := p.CurrentPhysicalBaseline(ctx, current)
	if err != nil {
		return empty, err
	}
	if b.TaskID != parent.Owner.TaskID || parent.Role != "manager" || parent.DesiredState != "active" || b.Case.CaseID != adviceContext.CaseID || b.Case.CaseManifestDigest != adviceContext.CaseManifestDigest || b.Case.DemandManifestDigest != adviceContext.DemandManifestDigest {
		return empty, ErrUntrusted
	}
	public, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil || Digest(public) != b.Case.OperatorKeySHA256 {
		return empty, ErrUntrusted
	}
	demandRaw, err := p.read("physical-gate-demand-envelope.json", 65536)
	var demand ChildEnvelope[DemandManifest]
	if err != nil || decode(demandRaw, &demand) != nil || verifyChildEnvelope(demandRaw, demand.KeyID, public) != nil || demand.Payload.validate(b.Case, time.Now()) != nil {
		return empty, ErrUntrusted
	}
	// p.read deliberately collapses unsafe paths to ErrUntrusted. Distinguish
	// ONLY a missing fixed leaf under the already verified protected root.
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
	return verifyControllerInitialDecision(raw, public, b.Case, demand.Payload, parent, adviceContext, advice, time.Now())
}

// Exact signed declaration -> independently returned backend context, checked
// BEFORE credential/native preparation. A same-text target/policy rebind is denial.
func (d ControllerDeclaredInput) MatchesContext(c model.ControllerApprovedInputContext) bool {
	document, definition := workflowcontract.Budget, "approvedInputItem2"
	if c.FormatVersion == 4 {
		document, definition = workflowcontract.ManagerSingle, "approvedInputItem3"
	}
	return (c.FormatVersion == 2 || c.FormatVersion == 3 || c.FormatVersion == 4) && workflowcontract.Validate(document, definition, canonicalBytes(d)) == nil && c.InputID == d.InputID && c.InputDigest == model.ControllerTextDigest(d.InputText) && c.PolicyDigest == d.PolicyDigest && c.WorkflowRequestID == d.WorkflowRequestID && c.AllocationID == d.AllocationID && c.PreparationOrdinal == d.PreparationOrdinal && c.PhysicalIndex == d.PhysicalIndex && c.DeclarationItemDigest == CanonicalDigest(d) && sameProduct(c.Plan, d.Plan) && sameProduct(c.Target, d.Target)
}

func verifyControllerInitialDecision(raw, public []byte, c RealCase, d DemandManifest, parent model.ControllerParentIntent, adviceContext model.ControllerApprovedInputContext, advice json.RawMessage, now time.Time) (ControllerDeclaredInput, error) {
	var empty ControllerDeclaredInput
	var envelope ChildEnvelope[json.RawMessage]
	// Raw declaration payload contains mandatory schema-authorized nulls inside
	// intents. decodeClosed's legacy non-null shape rule is not this selected wire.
	// Strict envelope/duplicate rejection plus the authoritative schema is closed.
	if decode(raw, &envelope) != nil || verifyChildEnvelope(raw, envelope.KeyID, public) != nil || Digest(public) != c.OperatorKeySHA256 || workflowcontract.Validate(workflowcontract.Domain, "adviceReceipt", advice) != nil {
		return empty, errors.Join(ErrUntrusted, errors.New("controller declaration original integrity refused"))
	}
	var version struct {
		FormatVersion int `json:"formatVersion"`
	}
	if json.Unmarshal(envelope.Payload, &version) != nil {
		return empty, ErrUntrusted
	}
	document, definition := workflowcontract.Budget, "inputDeclarationPayload3"
	allocationName, targetKind := "initialDecision", "manager_work_intents"
	if version.FormatVersion == 4 && c.FormatVersion == 3 {
		document, definition = workflowcontract.ManagerSingle, "inputDeclarationPayload4"
		allocationName, targetKind = "manager_initial", "manager_work_intent"
	} else if version.FormatVersion != 3 {
		return empty, ErrUntrusted
	}
	if workflowcontract.Validate(document, definition, envelope.Payload) != nil {
		return empty, ErrUntrusted
	}
	var declaration struct {
		FormatVersion                                                          int `json:"formatVersion"`
		CaseID, CaseManifestDigest, DemandManifestDigest, DeclaredAt, NotAfter string
		Inputs                                                                 []ControllerDeclaredInput
	}
	if json.Unmarshal(envelope.Payload, &declaration) != nil || declaration.CaseID != c.CaseID || declaration.CaseManifestDigest != c.CaseManifestDigest || declaration.DemandManifestDigest != c.DemandManifestDigest || declaration.DemandManifestDigest != CanonicalDigest(d) {
		return empty, errors.Join(ErrUntrusted, errors.New("controller declaration case/demand join refused"))
	}
	at, ae := time.Parse(time.RFC3339Nano, declaration.DeclaredAt)
	end, ee := time.Parse(time.RFC3339Nano, declaration.NotAfter)
	demandAt, de := time.Parse(time.RFC3339Nano, d.DeclaredAt)
	demandEnd, xe := time.Parse(time.RFC3339Nano, d.NotAfter)
	if ae != nil || ee != nil || de != nil || xe != nil || at.Before(demandAt) || at.After(now) || !now.Before(end) || end.After(demandEnd) {
		return empty, errors.Join(ErrUntrusted, errors.New("controller declaration validity refused"))
	}
	var accepted struct {
		AdviceID string
		Plan     model.ControllerPlan
	}
	if json.Unmarshal(advice, &accepted) != nil || !sameProduct(accepted.Plan, adviceContext.Plan) || adviceContext.Target.Kind != "advice" || adviceContext.Target.Role != "orchestrator" {
		return empty, errors.Join(ErrUntrusted, errors.New("controller declaration accepted advice join refused"))
	}
	seenInputs, seenSlots := map[string]bool{}, map[string]bool{}
	var selected *ControllerDeclaredInput
	for _, item := range declaration.Inputs {
		allocation, err := d.allocation(item.AllocationID)
		identity := item.ServiceRegistrationID + "\x00" + item.InputID
		if err != nil || seenInputs[identity] || seenSlots[item.AllocationID] || allocation.Kind != "parent" || allocation.SourceID != item.ServiceRegistrationID || allocation.PreparationOrdinal != item.PreparationOrdinal || allocation.FirstPhysicalIndex != item.PhysicalIndex || allocation.ScopeDigest != CanonicalDigest(allocation.Scope) {
			return empty, errors.Join(ErrUntrusted, errors.New("controller declaration allocation join refused"))
		}
		seenInputs[identity], seenSlots[item.AllocationID] = true, true
		if allocation.Name != allocationName {
			continue
		}
		if selected != nil || allocation.Scope != parent.Owner || allocation.SourceID != parent.ServiceRegistrationID || allocation.ModelRequests != 1 || allocation.AccessRequests != 0 || allocation.FirstPhysicalIndex != allocation.LastPhysicalIndex || item.Target.Kind != targetKind || item.Target.Role != "manager" || item.Target.ResourceID == nil || *item.Target.ResourceID != accepted.AdviceID || item.Target.Advice == nil || !sameProduct(*item.Target.Advice, advice) || !sameProduct(item.Plan, accepted.Plan) {
			return empty, errors.Join(ErrUntrusted, errors.New("controller declaration actual manager/advice selection refused"))
		}
		copy := item
		selected = &copy
	}
	if selected == nil {
		return empty, ErrControllerDeclarationPending
	}
	return *selected, nil
}
