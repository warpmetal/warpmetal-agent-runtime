package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Identity constraint only. Runtime NEVER opens/claims/signs the manager store.
const validationAttemptStore = "/private/var/folders/ln/3pk8bkxd7f72yhhjwpwpb56m0000gn/T/opencode/workspace-current-window-attempt-owner-20261010"

func verifyValidationBaseline(raw, dispatch, authority, operator []byte) error {
	op := childFields(childFields(authority)["operator"])
	if workflowcontract.Validate(workflowcontract.ValidationBaselineLive, "baselineEnvelope", raw) != nil ||
		workflowcontract.Validate(workflowcontract.ValidationDispatch, "dispatchReceiptEnvelope", dispatch) != nil ||
		!bytes.Equal(raw, canonicalBytes(json.RawMessage(raw))) || !bytes.Equal(dispatch, canonicalBytes(json.RawMessage(dispatch))) ||
		childString(op, "keySHA256") != Digest(operator)[7:] || verifyChildEnvelope(raw, childString(op, "keyId"), operator) != nil || verifyChildEnvelope(dispatch, childString(op, "keyId"), operator) != nil {
		return ErrUntrusted
	}
	b, d := childFields(childFields(raw)["payload"]), childFields(childFields(dispatch)["payload"])
	if childString(d, "baselineEnvelopeDigest") != Digest(raw) || childString(b, "authoritativeStore") != validationAttemptStore || !sameProduct(b["validationWindow"], d["validationWindow"]) {
		return ErrUntrusted
	}
	for left, right := range map[string]string{"integratedConsumed": "integratedBaselineConsumed", "integratedLimit": "integratedLimit", "liveConsumed": "liveBaselineConsumed", "liveLimit": "liveLimit", "correctionAllocated": "correctionAllocated", "correctionLimit": "correctionLimit"} {
		if !sameProduct(b[left], d[right]) {
			return ErrUntrusted
		}
	}
	return nil
}

func verifyValidationLiveReceipt(raw, dispatch, baseline, authority, operator []byte, input string, now time.Time) error {
	if !hash.MatchString(input) || verifyValidationBaseline(baseline, dispatch, authority, operator) != nil ||
		workflowcontract.Validate(workflowcontract.ValidationBaselineLive, "liveReceiptEnvelope", raw) != nil || !bytes.Equal(raw, canonicalBytes(json.RawMessage(raw))) ||
		verifyChildEnvelope(raw, childString(childFields(childFields(authority)["operator"]), "keyId"), operator) != nil {
		return ErrUntrusted
	}
	l, d := childFields(childFields(raw)["payload"]), childFields(childFields(dispatch)["payload"])
	if childString(l, "dispatchReceiptDigest") != Digest(dispatch) || childString(l, "physicalAttemptDigest") != input {
		return ErrUntrusted
	}
	for _, field := range []string{"attemptId", "validationWindow", "baselineEnvelopeDigest"} {
		if !sameProduct(l[field], d[field]) {
			return ErrUntrusted
		}
	}
	claimed, ce := time.Parse(time.RFC3339Nano, childString(l, "claimedAt"))
	parent, pe := time.Parse(time.RFC3339Nano, childString(d, "claimedAt"))
	if ce != nil || pe != nil || claimed.Before(parent) || claimed.After(now) {
		return ErrUntrusted
	}
	return nil
}

type validationLiveInput struct {
	Context    model.QualificationAccessContext `json:"context"`
	Capability json.RawMessage                  `json:"capability"`
}

func liveAttemptKey(attempt string) string {
	return "validation_live_attempt_" + Digest([]byte(attempt))[7:]
}
func liveInputKey(attempt string) string {
	return "validation_live_input_" + Digest([]byte(attempt))[7:]
}
func liveOrdinalKey(receipt []byte) string {
	payload := childFields(childFields(receipt)["payload"])
	return "validation_live_ordinal_" + CanonicalDigest(payload["validationWindow"])[7:] + "_" + string(payload["liveOrdinal"])
}

// Only the manager's private bridge supplies the FIRST signed allowance. All
// business/installed/capability/receipt checks of normal enrollment precede this.
// No helper invocation, signing, HTTP request, credentials or manager root access.
func (p *Producer) AcceptValidationLiveReceipt(ctx context.Context, current model.Manifest, store *state.Store, access *physicalgate.AccessRegistry, input model.QualificationAccessContext, capability, receipt []byte) error {
	if store == nil || access == nil || access.Store != store || input.Validate(input.QualificationID, time.Now()) != nil {
		return ErrUntrusted
	}
	b, _, err := p.CurrentPhysicalBaseline(ctx, current)
	if err != nil || p.VerifyPhysicalAccessAuthority(ctx, input, b) != nil {
		return ErrUntrusted
	}
	domain, err := p.CurrentPaidCaseDomain(ctx, current, store, b)
	if err != nil || domain.DemandManifestDigest != input.DemandManifestDigest {
		return ErrUntrusted
	}
	enrolled, err := access.Enrollment(ctx, input.PreparationID)
	if err != nil || !sameProduct(enrolled.Context, input) || enrolled.CapabilityDigest != Digest(capability) {
		return ErrUntrusted
	}
	inventory, err := p.read("complete-execution-inventory.json", 65536)
	if err != nil || p.verifyCurrentValidationDispatch(ctx, store, inventory, b.Case.OperatorKeySHA256) != nil {
		return ErrUntrusted
	}
	i := childFields(childFields(inventory)["payload"])
	attempt := childString(i, "attemptId")
	prior, err := store.PhysicalFact(ctx, liveAttemptKey(attempt))
	if err != nil {
		return err
	}
	if len(receipt) == 0 {
		if prior == nil {
			return ErrUntrusted
		}
		// A retained allowance alone must never reopen FIRST delivery after a
		// lost callback/send. Receipt-less access is only a later settled-first
		// consumer, not a retry of the first request on a restarted adapter.
		first, fe := store.PhysicalFact(ctx, liveInputKey(attempt))
		var saved validationLiveInput
		if fe != nil || decodeClosed(first, &saved) != nil {
			return ErrUntrusted
		}
		firstDomain, fe := store.PaidDomain(ctx, saved.Context.DemandManifestDigest)
		cut, ce := store.PhysicalLedgerCut(ctx)
		if fe != nil || ce != nil || cut.Cumulative.PhysicalRequests <= firstDomain.Bases.PhysicalRequests {
			return ErrUntrusted
		}
		return p.VerifyValidationLivePhysicalRequest(ctx, current, store, enrolled.Caller, model.PhysicalAdmitRequest{Consumer: "access", PreparationID: input.PreparationID}, nil)
	}
	if prior != nil {
		return ErrUntrusted
	} // Never accept/replace/replay a second claim.
	if err = p.verifyFirstSelectedAccess(i, input, capability); err != nil {
		return err
	}
	cut, err := store.PhysicalLedgerCut(ctx)
	if err != nil || cut.Owner != nil || cut.Cumulative != domain.Bases {
		return ErrUntrusted
	}
	dispatch, err := p.readValidationDispatch(attempt)
	if err != nil {
		return err
	}
	baseline, err := p.paidOriginal(childString(childFields(childFields(dispatch)["payload"]), "baselineEnvelopeDigest"))
	operator, oe := p.read("physical-gate-operator.pem", 4096)
	first := canonicalBytes(validationLiveInput{Context: input, Capability: capability})
	if err != nil || oe != nil || verifyValidationLiveReceipt(receipt, dispatch, baseline, mustReadAuthority(p), operator, Digest(first), time.Now()) != nil {
		return ErrUntrusted
	}
	// Immutable independent consumer associations, NOT allowance counters. Partial
	// retention refuses; it cannot refund/retry the manager's already consumed claim.
	return store.RetainValidationLiveFacts(ctx, liveAttemptKey(attempt), liveInputKey(attempt), liveOrdinalKey(receipt), first, receipt)
}

func mustReadAuthority(p *Producer) []byte {
	raw, err := p.read("physical-gate-authority.json", 65536)
	if err != nil {
		return nil
	}
	return raw
}

func (p *Producer) verifyFirstSelectedAccess(inventory map[string]json.RawMessage, input model.QualificationAccessContext, capability []byte) error {
	operator, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil {
		return err
	}
	authority := childFields(mustReadAuthority(p))
	key := childString(childFields(authority["operator"]), "keyId")
	if verifyChildEnvelope(capability, key, operator) != nil {
		return ErrUntrusted
	}
	selectedDemand := childString(inventory, "paidSelectionEnvelopeDigest")
	if string(inventory["sourceQualification"]) != "null" {
		selection, err := p.paidOriginal(childString(childFields(inventory["sourceQualification"]), "selectionEnvelopeDigest"))
		if err != nil || workflowcontract.Validate(workflowcontract.CompleteExecutionInventory, "freshSourceQualificationSelectionEnvelope", selection) != nil || verifyChildEnvelope(selection, key, operator) != nil {
			return ErrUntrusted
		}
		selectedDemand = childString(childFields(childFields(selection)["payload"]), "originalDemandEnvelopeDigest")
	} else {
		selection, err := p.paidOriginal(selectedDemand)
		if err != nil || workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "selectedManifest26Envelope", selection) != nil || verifyChildEnvelope(selection, key, operator) != nil {
			return ErrUntrusted
		}
		selectedDemand = CanonicalDigest(childFields(childFields(selection)["payload"])["demand"])
	}
	demand, err := p.paidOriginal(selectedDemand)
	if err != nil || workflowcontract.Validate(workflowcontract.Budget, "demandManifestEnvelope", demand) != nil || verifyChildEnvelope(demand, key, operator) != nil {
		return ErrUntrusted
	}
	var manifest ChildEnvelope[DemandManifest]
	if decodeClosed(demand, &manifest) != nil || CanonicalDigest(manifest.Payload) != input.DemandManifestDigest {
		return ErrUntrusted
	}
	count := 0
	for _, a := range manifest.Payload.all() {
		if a.FirstPhysicalIndex != 1 {
			continue
		}
		if a.Kind != "access" || a.LastPhysicalIndex != 1 || a.AccessRequests != 1 || a.ModelRequests != 0 || a.PreparationOrdinal != 0 || a.TupleDigest != input.TupleDigest || !sameProduct(a, input.Allocation) {
			return ErrUntrusted
		}
		count++
	}
	if count != 1 {
		return ErrUntrusted
	}
	return nil
}

// Every actual PAID admission calls this; OFFLINE is excluded by the owning
// caller, never reclassified here. Read-only: no claim/accept/credential/HTTP.
func (p *Producer) VerifyValidationLivePhysicalRequest(ctx context.Context, current model.Manifest, store *state.Store, caller physicalgate.Caller, request model.PhysicalAdmitRequest, permit *state.PhysicalPermit) error {
	b, _, err := p.CurrentPhysicalBaseline(ctx, current)
	if err != nil {
		return err
	}
	domain, err := p.CurrentPaidCaseDomain(ctx, current, store, b)
	if err != nil || (permit != nil && (permit.PaidDomain != domain.DemandManifestDigest || permit.Caller != caller.Subject())) {
		return ErrUntrusted
	}
	inventory, err := p.read("complete-execution-inventory.json", 65536)
	if err != nil || p.verifyCurrentValidationDispatch(ctx, store, inventory, b.Case.OperatorKeySHA256) != nil {
		return ErrUntrusted
	}
	i := childFields(childFields(inventory)["payload"])
	attempt := childString(i, "attemptId")
	raw, err := store.PhysicalFact(ctx, liveAttemptKey(attempt))
	first, ie := store.PhysicalFact(ctx, liveInputKey(attempt))
	var input validationLiveInput
	if err != nil || ie != nil || raw == nil || first == nil || decodeClosed(first, &input) != nil || !bytes.Equal(first, canonicalBytes(input)) {
		return ErrUntrusted
	}
	ordinal, err := store.PhysicalFact(ctx, liveOrdinalKey(raw))
	dispatch, de := p.readValidationDispatch(attempt)
	baseline, be := p.paidOriginal(childString(childFields(childFields(dispatch)["payload"]), "baselineEnvelopeDigest"))
	operator, oe := p.read("physical-gate-operator.pem", 4096)
	if err != nil || de != nil || be != nil || oe != nil || !bytes.Equal(raw, ordinal) || verifyValidationLiveReceipt(raw, dispatch, baseline, mustReadAuthority(p), operator, Digest(first), time.Now()) != nil {
		return ErrUntrusted
	}
	// Admission may precede the first successful provider response. Native cannot
	// slip in before access: owning history must contain the SAME settled first GET.
	cut, err := store.PhysicalLedgerCut(ctx)
	if err != nil {
		return err
	}
	firstDomain, err := store.PaidDomain(ctx, input.Context.DemandManifestDigest)
	if err != nil || !sameProduct(childFields(childFields(firstDomain.AdoptionEnvelope)["payload"])["completeInventoryEnvelopeDigest"], childFields(childFields(domain.AdoptionEnvelope)["payload"])["completeInventoryEnvelopeDigest"]) {
		return ErrUntrusted
	}
	operation, err := verifyValidationLiveOrder(cut, firstDomain, input, domain.DemandManifestDigest, caller, request, permit)
	if err != nil {
		return err
	}
	if operation == nil {
		return ctx.Err()
	}
	original, err := store.PhysicalFact(ctx, "probe_request_"+operation.OperationID)
	if err != nil || len(original) == 0 || Digest(original) != operation.Permit.Request.RequestDigest {
		return ErrUntrusted
	}
	return ctx.Err()
}

// Ordering policy over independently verified immutable originals/cut. Kept
// separate from receipt crypto and acquisition; never substitutes for either.
func verifyValidationLiveOrder(cut state.PaidLedgerCut, firstDomain state.PaidDomain, input validationLiveInput, currentDomain string, caller physicalgate.Caller, request model.PhysicalAdmitRequest, permit *state.PhysicalPermit) (*state.PhysicalOperation, error) {
	if cut.Owner != nil || firstDomain.Bases.PhysicalRequests < 0 || firstDomain.DemandManifestDigest != input.Context.DemandManifestDigest {
		return nil, ErrUntrusted
	}
	if cut.Cumulative.PhysicalRequests == firstDomain.Bases.PhysicalRequests {
		if request.Consumer != "access" || request.PreparationID != input.Context.PreparationID || input.Context.DemandManifestDigest != currentDomain || (permit != nil && (request.RequestIndex != 1 || request.OuterPhysicalIndex != 1 || request.AuthorityDigest != input.Context.AuthorityDigest || caller.NativeInstance != "runtime-access" || permit.AllocationID != childString(childFields(input.Context.Allocation), "allocationId"))) {
			return nil, ErrUntrusted
		}
		return nil, nil
	}
	if len(cut.PaidHistory) <= firstDomain.Bases.PhysicalRequests {
		return nil, ErrUntrusted
	}
	var operation state.PhysicalOperation
	if decodeClosed(cut.Originals[cut.PaidHistory[firstDomain.Bases.PhysicalRequests].OperationDigest], &operation) != nil || operation.Phase != "settled" || operation.Settlement == nil || operation.Permit.Request.Consumer != "access" || operation.Permit.Request.RequestIndex != 1 || operation.Permit.Request.OuterPhysicalIndex != 1 || operation.Permit.Request.AuthorityDigest != input.Context.AuthorityDigest || operation.Permit.AllocationID != childString(childFields(input.Context.Allocation), "allocationId") || operation.Permit.Caller.NativeInstance != "runtime-access" || operation.Permit.Request.PreparationID != input.Context.PreparationID || operation.Permit.PaidDomain != input.Context.DemandManifestDigest {
		return nil, ErrUntrusted
	}
	return &operation, nil
}
