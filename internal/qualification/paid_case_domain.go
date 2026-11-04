package qualification

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sort"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func paidBootstrapFact(d string) string { return "paid_bootstrap_" + d[7:] }
func (p *Producer) paidPublic() ([]byte, error) {
	if p == nil || p.key == nil {
		return nil, ErrUntrusted
	}
	der, e := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	if e != nil {
		return nil, e
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if Digest(public) != p.config.KeySHA256 {
		return nil, ErrUntrusted
	}
	return public, nil
}
func (p *Producer) paidOriginal(d string) ([]byte, error) {
	if !hash.MatchString(d) {
		return nil, ErrUntrusted
	}
	raw, e := p.read(d[7:], 65536)
	if e != nil || Digest(raw) != d || !bytes.Equal(raw, canonicalBytes(json.RawMessage(raw))) {
		return nil, ErrUntrusted
	}
	return raw, nil
}

// FIRST bootstrap metadata is retained before POST, so an interrupted transport
// resumes the identical original explicitly; there is no automatic retry or new
// readback/signature substituting for a possibly committed backend transaction.
func (p *Producer) PreparePaidCaseDomainAdoption(ctx context.Context, current model.Manifest, store *state.Store) (model.PaidCaseDomainAdoptionRequest, error) {
	var empty model.PaidCaseDomainAdoptionRequest
	if p == nil || store == nil {
		return empty, ErrUntrusted
	}
	b, history, err := p.CurrentPhysicalBaseline(ctx, current)
	if err != nil {
		return empty, err
	}
	// Manager receipt must precede even the local bootstrap/mapping, not merely
	// backend acceptance. Construction/readback never claims an attempt.
	inventory, err := p.read("complete-execution-inventory.json", 65536)
	if err != nil || p.verifyCurrentValidationDispatch(ctx, store, inventory, b.Case.OperatorKeySHA256) != nil {
		return empty, ErrUntrusted
	}
	anchor, err := store.PhysicalAnchor(ctx)
	if err != nil {
		return empty, err
	}
	if anchor == nil {
		if err = store.AdoptPhysicalLedger(ctx, b.StoreCase(current.ServerID), history); err != nil {
			return empty, err
		}
	}
	if !hash.MatchString(b.Case.DemandManifestDigest) || len(b.SourceContinuation) != 0 {
		return empty, ErrUntrusted
	}
	inventoryDigest := Digest(inventory)
	prior, err := store.PhysicalFact(ctx, paidBootstrapFact(b.Case.DemandManifestDigest))
	if err != nil {
		return empty, err
	}
	if len(prior) != 0 {
		var request model.PaidCaseDomainAdoptionRequest
		if decodeClosed(prior, &request) != nil || request.Validate() != nil || request.CompleteInventoryEnvelopeDigest != inventoryDigest || request.DemandManifestDigest != b.Case.DemandManifestDigest {
			return empty, ErrUntrusted
		}
		if _, _, _, err = p.paidBootstrapOriginals(ctx, current, store, request); err != nil {
			return empty, err
		}
		return request, nil
	}
	readback, err := p.ObservePaidLedgerReadback(ctx, current, store)
	if err != nil {
		return empty, err
	}
	request := model.PaidCaseDomainAdoptionRequest{FormatVersion: 1, CompleteInventoryEnvelopeDigest: inventoryDigest, DemandManifestDigest: b.Case.DemandManifestDigest, RuntimeReadback: readback}
	// Archive original aliases BEFORE a current case/control selector can advance.
	for _, name := range []string{"complete-execution-inventory.json", "physical-gate-authority.json", "physical-gate-demand-envelope.json", "selected-manifest26.json"} {
		raw, e := p.read(name, 65536)
		if e != nil || !bytes.Equal(raw, canonicalBytes(json.RawMessage(raw))) {
			return empty, ErrUntrusted
		}
		if e = p.append(Digest(raw)[7:], raw); e != nil {
			return empty, e
		}
	}
	if _, _, _, err = p.paidBootstrapOriginals(ctx, current, store, request); err != nil {
		return empty, err
	}
	if err = store.RetainPhysicalFact(ctx, paidBootstrapFact(request.DemandManifestDigest), canonicalBytes(request)); err != nil {
		return empty, err
	}
	return request, nil
}

// Independently configured operator/Runtime trust and current installed baseline;
// no trust/scope/path/counter value is taken from a node request or HTTP ACK.
func (p *Producer) paidBootstrapOriginals(ctx context.Context, current model.Manifest, store *state.Store, request model.PaidCaseDomainAdoptionRequest) (PhysicalBaseline, map[string]json.RawMessage, state.PaidLedgerCut, error) {
	var b PhysicalBaseline
	var cut state.PaidLedgerCut
	if request.Validate() != nil {
		return b, nil, cut, ErrUntrusted
	}
	b, _, err := p.CurrentPhysicalBaseline(ctx, current)
	if err != nil || b.Case.DemandManifestDigest != request.DemandManifestDigest || len(b.SourceContinuation) != 0 {
		return b, nil, cut, ErrUntrusted
	}
	inventoryRaw, err := p.read("complete-execution-inventory.json", 65536)
	if err != nil || Digest(inventoryRaw) != request.CompleteInventoryEnvelopeDigest || workflowcontract.Validate(workflowcontract.CompleteExecutionInventory, "completeExecutionInventoryEnvelope", inventoryRaw) != nil {
		return b, nil, cut, ErrUntrusted
	}
	operator, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil || Digest(operator) != b.Case.OperatorKeySHA256 || verifyChildEnvelope(inventoryRaw, childString(childFields(inventoryRaw), "keyId"), operator) != nil {
		return b, nil, cut, ErrUntrusted
	}
	inventory := childFields(childFields(inventoryRaw)["payload"])
	if err = p.verifyCurrentValidationDispatch(ctx, store, inventoryRaw, b.Case.OperatorKeySHA256); err != nil {
		return b, nil, cut, err
	}
	scope := childFields(inventory["scope"])
	now := time.Now()
	if childString(scope, "taskId") != b.TaskID || childString(scope, "serverId") != current.ServerID || !live(childString(inventory, "expiresAt"), now) || mustChildTime(childString(inventory, "issuedAt")).After(now) {
		return b, nil, cut, ErrUntrusted
	}
	public, err := p.paidPublic()
	if err != nil || bytes.Equal(public, operator) || verifyChildEnvelope(request.RuntimeReadback, p.config.KeyID, public) != nil {
		return b, nil, cut, ErrUntrusted
	}
	r := childFields(childFields(request.RuntimeReadback)["payload"])
	actual, err := store.PhysicalLedgerCut(ctx)
	if err != nil || actual.Anchor.TaskID != b.TaskID || actual.Anchor.ServerID != current.ServerID || childString(r, "taskId") != b.TaskID || childString(r, "serverId") != current.ServerID || childString(r, "baselineDigest") != actual.Anchor.BaselineDigest || !sameProduct(r["validationWindow"], inventory["validationWindow"]) || childString(r, "candidateInventoryDigest") != childString(inventory, "candidateInventoryDigest") || string(r["owner"]) != "null" {
		return b, nil, cut, ErrUntrusted
	}
	cut = state.PaidLedgerCut{Anchor: actual.Anchor, Originals: map[string]json.RawMessage{}}
	if decode(r["paidHistory"], &cut.PaidHistory) != nil || decode(r["cumulative"], &cut.Cumulative) != nil || CanonicalDigest(cut.PaidHistory) != childString(r, "paidHistoryDigest") {
		return b, nil, cut, ErrUntrusted
	}
	for i, ref := range cut.PaidHistory {
		original, e := p.paidOriginal(ref.OperationDigest)
		var operation state.PhysicalOperation
		if e != nil || decodeClosed(original, &operation) != nil || operation.OperationID != ref.OperationID || ref.StoragePhysicalIndex != i+1 || operation.Phase != "settled" || operation.Settlement == nil {
			return b, nil, cut, ErrUntrusted
		}
		cut.Originals[ref.OperationDigest] = original
		if ref.ImportedOriginalDigest != nil {
			if _, e = p.paidOriginal(*ref.ImportedOriginalDigest); e != nil {
				return b, nil, cut, e
			}
		}
	}
	cut.OfflineHistoryDigest = childString(r, "offlineHistoryDigest")
	offline, e := p.paidOriginal(cut.OfflineHistoryDigest)
	if e != nil || decode(offline, &cut.OfflineHistory) != nil {
		return b, nil, cut, ErrUntrusted
	}
	for _, original := range cut.OfflineHistory {
		var operation state.PhysicalOperation
		if decodeClosed(original, &operation) != nil || operation.Phase != "local-terminal" || operation.LocalTerminal == nil {
			return b, nil, cut, ErrUntrusted
		}
		cut.Originals[Digest(original)] = original
	}
	return b, inventory, cut, nil
}

type paidAdoptionBasis struct {
	baseline           PhysicalBaseline
	inventory, payload map[string]json.RawMessage
	opening            state.PaidLedgerCut
	public             []byte
}

// One verification boundary, shared by archive acquisition and acceptance.
// Verifying a locator here does not verify the referenced financial evidence.
func (p *Producer) verifiedPaidAdoptionBasis(ctx context.Context, current model.Manifest, store *state.Store, request model.PaidCaseDomainAdoptionRequest, adoption json.RawMessage) (paidAdoptionBasis, error) {
	var empty paidAdoptionBasis
	b, inventory, opening, err := p.paidBootstrapOriginals(ctx, current, store, request)
	if err != nil {
		return empty, err
	}
	retained, err := store.PhysicalFact(ctx, paidBootstrapFact(request.DemandManifestDigest))
	if err != nil || !bytes.Equal(retained, canonicalBytes(request)) {
		return empty, ErrUntrusted
	}
	public, err := p.paidPublic()
	if err != nil || workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAdoptionEnvelope", adoption) != nil || verifyChildEnvelope(adoption, p.config.KeyID, public) != nil || !bytes.Equal(adoption, canonicalBytes(adoption)) {
		return empty, ErrUntrusted
	}
	a := childFields(childFields(adoption)["payload"])
	r := childFields(childFields(request.RuntimeReadback)["payload"])
	for _, name := range []string{"attemptId", "validationWindow", "candidateInventoryDigest", "scope", "openingReceiptDigest", "producerReconciliationEnvelopeDigest"} {
		if !sameProduct(a[name], inventory[name]) {
			return empty, ErrUntrusted
		}
	}
	if childString(a, "completeInventoryEnvelopeDigest") != request.CompleteInventoryEnvelopeDigest || childString(a, "demandManifestDigest") != request.DemandManifestDigest || childString(a, "runtimeReadbackEnvelopeDigest") != CanonicalDigest(request.RuntimeReadback) || childString(a, "caseId") != b.Case.CaseID || childString(a, "caseManifestDigest") != b.Case.CaseManifestDigest || !sameProduct(a["bases"], opening.Cumulative) {
		return empty, ErrUntrusted
	}
	backend := childFields(a["backendOpening"])
	if !sameProduct(backend["turns"], backend["modelRequests"]) {
		return empty, ErrUntrusted
	}
	for _, name := range []string{"physicalRequests", "modelRequests", "preparations"} {
		if !sameProduct(backend[name], childFields(r["cumulative"])[name]) {
			return empty, ErrUntrusted
		}
	}
	observed, oe := time.Parse(time.RFC3339Nano, childString(r, "observedAt"))
	expiry, ee := time.Parse(time.RFC3339Nano, childString(r, "expiresAt"))
	retainedAt, re := time.Parse(time.RFC3339Nano, childString(a, "retainedAt"))
	if oe != nil || ee != nil || re != nil || expiry.Sub(observed) > 120*time.Second || !observed.Before(expiry) || retainedAt.Before(observed) || !retainedAt.Before(expiry) || retainedAt.After(time.Now()) {
		return empty, ErrUntrusted
	}
	return paidAdoptionBasis{b, inventory, a, opening, public}, nil
}

func (p *Producer) AcceptPaidCaseDomainAdoption(ctx context.Context, current model.Manifest, store *state.Store, request model.PaidCaseDomainAdoptionRequest, adoption json.RawMessage) (json.RawMessage, error) {
	basis, err := p.verifiedPaidAdoptionBasis(ctx, current, store, request, adoption)
	if err != nil {
		return nil, err
	}
	b, inventory, a, opening, public := basis.baseline, basis.inventory, basis.payload, basis.opening, basis.public
	expiry, _ := time.Parse(time.RFC3339Nano, childString(childFields(childFields(request.RuntimeReadback)["payload"]), "expiresAt"))
	retainedAt, _ := time.Parse(time.RFC3339Nano, childString(a, "retainedAt"))
	operator, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil {
		return nil, err
	}
	authority, err := p.read("physical-gate-authority.json", 65536)
	if err != nil || Digest(authority) != childString(a, "authorityDigest") {
		return nil, ErrUntrusted
	}
	demandRaw, err := p.read("physical-gate-demand-envelope.json", 65536)
	var demand ChildEnvelope[DemandManifest]
	if err != nil || Digest(demandRaw) != childString(a, "demandEnvelopeDigest") || decode(demandRaw, &demand) != nil || demand.Payload.validate(b.Case, time.Now()) != nil || demand.Payload.CandidateInventoryDigest != childString(inventory, "candidateInventoryDigest") {
		return nil, ErrUntrusted
	}
	selection, err := p.paidOriginal(childString(a, "selectionEnvelopeDigest"))
	if err != nil || verifyChildEnvelope(selection, childString(childFields(selection), "keyId"), operator) != nil {
		return nil, ErrUntrusted
	}
	selected := childFields(childFields(selection)["payload"])
	var allocationIDs []string
	if decode(a["selectedAllocationIds"], &allocationIDs) != nil {
		return nil, ErrUntrusted
	}
	switch childString(a, "domainKind") {
	case "paid_full26":
		if childString(inventory, "paidSelectionEnvelopeDigest") != Digest(selection) || workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "selectedManifest26Envelope", selection) != nil || !sameProduct(selected["case"], b.Case) || !sameProduct(selected["demand"], json.RawMessage(demandRaw)) {
			return nil, ErrUntrusted
		}
		all := demand.Payload.all()
		sort.Slice(all, func(i, j int) bool { return all[i].FirstPhysicalIndex < all[j].FirstPhysicalIndex })
		expected := []string{}
		for _, allocation := range all {
			expected = append(expected, allocation.AllocationID)
		}
		if !sameProduct(expected, allocationIDs) {
			return nil, ErrUntrusted
		}
		if string(inventory["sourceQualification"]) != "null" {
			ref := childFields(inventory["sourceQualification"])
			freshRaw, e := p.paidOriginal(childString(ref, "selectionEnvelopeDigest"))
			if e != nil || workflowcontract.Validate(workflowcontract.CompleteExecutionInventory, "freshSourceQualificationSelectionEnvelope", freshRaw) != nil || verifyChildEnvelope(freshRaw, childString(childFields(freshRaw), "keyId"), operator) != nil {
				return nil, ErrUntrusted
			}
			fresh := childFields(childFields(freshRaw)["payload"])
			freshDemandRaw, e := p.paidOriginal(childString(fresh, "originalDemandEnvelopeDigest"))
			var freshDemand ChildEnvelope[DemandManifest]
			if e != nil || decode(freshDemandRaw, &freshDemand) != nil || verifyChildEnvelope(freshDemandRaw, childString(childFields(freshDemandRaw), "keyId"), operator) != nil {
				return nil, ErrUntrusted
			}
			previous, e := store.PaidDomain(ctx, CanonicalDigest(freshDemand.Payload))
			if e != nil || verifyChildEnvelope(previous.AdoptionEnvelope, p.config.KeyID, public) != nil {
				return nil, ErrUntrusted
			}
			previousPayload := childFields(childFields(previous.AdoptionEnvelope)["payload"])
			if childString(previousPayload, "completeInventoryEnvelopeDigest") != request.CompleteInventoryEnvelopeDigest || childString(previousPayload, "selectionEnvelopeDigest") != Digest(freshRaw) || childString(previousPayload, "domainKind") != "fresh_source_qualification_pair" {
				return nil, ErrUntrusted
			}
			previousAccepted, e := store.PhysicalFact(ctx, "paid_backend_acceptance_"+previous.DemandManifestDigest[7:])
			if e != nil || workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAcceptanceEnvelope", previousAccepted) != nil || verifyChildEnvelope(previousAccepted, p.config.KeyID, public) != nil || childString(childFields(childFields(previousAccepted)["payload"]), "adoptionEnvelopeDigest") != previous.AdoptionEnvelopeDigest {
				return nil, ErrUntrusted
			}
			previousHistory, e := store.PhysicalHistory(ctx, previous.Case)
			if e != nil || len(previousHistory) != 3 {
				return nil, ErrUntrusted
			}
			for _, operation := range previousHistory {
				if operation.Phase != "settled" || operation.Settlement == nil {
					return nil, ErrUntrusted
				}
			}
		}
	case "fresh_source_qualification_pair":
		ref := childFields(inventory["sourceQualification"])
		if childString(ref, "selectionEnvelopeDigest") != Digest(selection) || workflowcontract.Validate(workflowcontract.CompleteExecutionInventory, "freshSourceQualificationSelectionEnvelope", selection) != nil || childString(selected, "originalDemandEnvelopeDigest") != Digest(demandRaw) || childString(selected, "authorityDigest") != Digest(authority) || childString(selected, "caseId") != b.Case.CaseID || childString(selected, "tupleDigest") != childString(ref, "tupleDigest") {
			return nil, ErrUntrusted
		}
		for _, name := range []string{"attemptId", "validationWindow", "candidateInventoryDigest", "scope"} {
			if !sameProduct(selected[name], inventory[name]) {
				return nil, ErrUntrusted
			}
		}
		if !sameProduct(allocationIDs, []string{childString(selected, "accessAllocationId"), childString(selected, "modelAllocationId")}) || !live(childString(selected, "expiresAt"), time.Now()) {
			return nil, ErrUntrusted
		}
		access, e := demand.Payload.allocation(allocationIDs[0])
		models, me := demand.Payload.allocation(allocationIDs[1])
		if e != nil || me != nil || access.Kind != "access" || models.Kind != "qualification" || access.TupleDigest != childString(selected, "tupleDigest") || models.TupleDigest != access.TupleDigest || !sameProduct(access.Scope, models.Scope) || CanonicalDigest(selected["applicability"]) != access.TupleDigest || access.FirstPhysicalIndex != 1 || access.LastPhysicalIndex != 1 || models.FirstPhysicalIndex != 2 || models.LastPhysicalIndex != 3 {
			return nil, ErrUntrusted
		}
	default:
		return nil, ErrUntrusted
	}
	// The signed adoption is backend commit metadata, not a financial-original or
	// reserve release. Require original locators; do not turn settled usage into cash.
	var joins []map[string]json.RawMessage
	if decode(a["accountingJoins"], &joins) != nil {
		return nil, ErrUntrusted
	}
	covered := map[string]bool{}
	for _, join := range joins {
		if _, err = p.paidOriginal(childString(join, "recordDigest")); err != nil {
			return nil, err
		}
		var refs []state.PhysicalOwnerRef
		if decode(join["physicalOperations"], &refs) != nil {
			return nil, ErrUntrusted
		}
		for _, ref := range refs {
			raw, ok := opening.Originals[ref.OperationDigest]
			var operation state.PhysicalOperation
			if !ok || decodeClosed(raw, &operation) != nil || operation.OperationID != ref.OperationID || operation.Permit.AllocationID != childString(join, "allocationId") || covered[ref.OperationID] {
				return nil, ErrUntrusted
			}
			covered[ref.OperationID] = true
			if operation.Permit.PaidDomain != "" && operation.Permit.PaidDomain != childString(join, "demandManifestDigest") {
				return nil, ErrUntrusted
			}
		}
	}
	for _, ref := range opening.PaidHistory {
		if !covered[ref.OperationID] {
			return nil, ErrUntrusted
		}
	}
	limits := childFields(a["limits"])
	c := b.StoreCase(current.ServerID)
	c.BaselineDigest = opening.Anchor.BaselineDigest
	if decode(limits["physicalRequests"], &c.Requests) != nil || decode(limits["modelRequests"], &c.ModelRequests) != nil || decode(limits["accessRequests"], &c.AccessRequests) != nil || decode(limits["preparations"], &c.Preparations) != nil || decode(limits["usdMicros"], &c.UsdMicros) != nil {
		return nil, ErrUntrusted
	}
	d := state.PaidDomain{DemandManifestDigest: request.DemandManifestDigest, AdoptionEnvelopeDigest: Digest(adoption), RuntimeReadbackEnvelopeDigest: CanonicalDigest(request.RuntimeReadback), AdoptionEnvelope: adoption, Case: c, Bases: opening.Cumulative, Opening: opening}
	for _, id := range allocationIDs {
		allocation, e := demand.Payload.allocation(id)
		if e != nil {
			return nil, e
		}
		d.Allocations = append(d.Allocations, state.PaidAllocation{AllocationID: id, FirstPhysicalIndex: allocation.FirstPhysicalIndex, LastPhysicalIndex: allocation.LastPhysicalIndex, PreparationOrdinal: allocation.PreparationOrdinal, ModelRequests: allocation.ModelRequests})
	}
	// SAME owner transaction commits before any Runtime acceptance signature.
	if err = p.verifyPaidFinancialBeforeAdoption(ctx, store, basis, adoption); err != nil {
		return nil, err
	}
	prior, err := store.PhysicalFact(ctx, "paid_domain_acceptance_"+request.DemandManifestDigest[7:])
	if err != nil {
		return nil, err
	}
	if len(prior) == 0 && !time.Now().Before(expiry) {
		return nil, ErrUntrusted
	}
	if err = store.AdoptPaidDomain(ctx, d); err != nil {
		return nil, err
	}
	if err = p.retainPaidDomainEnvelope(request.DemandManifestDigest, "adoption-envelope.json", adoption); err != nil {
		return nil, err
	}
	if err = p.append(Digest(adoption)[7:], adoption); err != nil {
		return nil, err
	}
	acceptance := prior
	if len(acceptance) == 0 {
		first, e := p.readPaidDomainEnvelope(request.DemandManifestDigest, "acceptance-envelope.json")
		if e == nil {
			acceptance = first
		} else if !errors.Is(e, syscall.ENOENT) {
			return nil, e
		}
	}
	if len(acceptance) == 0 {
		payload := map[string]any{"formatVersion": 1, "purpose": "paid_case_relative_domain_acceptance", "adoptionEnvelopeDigest": Digest(adoption), "runtimeReadbackEnvelopeDigest": CanonicalDigest(request.RuntimeReadback), "acceptedAt": time.Now().UTC().Format(time.RFC3339Nano)}
		h := sha256.Sum256(canonicalBytes(payload))
		sig, e := ecdsa.SignASN1(rand.Reader, p.key, h[:])
		if e != nil {
			return nil, e
		}
		acceptance = canonicalBytes(map[string]any{"payload": payload, "keyId": p.config.KeyID, "signature": base64.StdEncoding.EncodeToString(sig)})
	}
	if workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAcceptanceEnvelope", acceptance) != nil || verifyChildEnvelope(acceptance, p.config.KeyID, public) != nil {
		return nil, ErrUntrusted
	}
	acceptedPayload := childFields(childFields(acceptance)["payload"])
	acceptedAt, ae := time.Parse(time.RFC3339Nano, childString(acceptedPayload, "acceptedAt"))
	if ae != nil || acceptedAt.Before(retainedAt) || !acceptedAt.Before(expiry) || childString(acceptedPayload, "adoptionEnvelopeDigest") != Digest(adoption) || childString(acceptedPayload, "runtimeReadbackEnvelopeDigest") != CanonicalDigest(request.RuntimeReadback) {
		return nil, ErrUntrusted
	}
	if err = p.retainPaidDomainEnvelope(request.DemandManifestDigest, "acceptance-envelope.json", acceptance); err != nil {
		return nil, err
	}
	if err = store.AcceptPaidDomain(ctx, request.DemandManifestDigest, Digest(adoption), acceptance); err != nil {
		return nil, err
	}
	if err = p.append(Digest(acceptance)[7:], acceptance); err != nil {
		return nil, err
	}
	return acceptance, nil
}

func (p *Producer) ConfirmPaidCaseDomainAcceptance(ctx context.Context, current model.Manifest, store *state.Store, request model.PaidCaseDomainAdoptionRequest, local, backend json.RawMessage) error {
	if _, _, _, err := p.paidBootstrapOriginals(ctx, current, store, request); err != nil {
		return err
	}
	public, err := p.paidPublic()
	if err != nil || !bytes.Equal(local, backend) || workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAcceptanceEnvelope", backend) != nil || verifyChildEnvelope(backend, p.config.KeyID, public) != nil {
		return ErrUntrusted
	}
	d, err := store.PaidDomain(ctx, request.DemandManifestDigest)
	if err != nil {
		return err
	}
	payload := childFields(childFields(backend)["payload"])
	if childString(payload, "adoptionEnvelopeDigest") != d.AdoptionEnvelopeDigest || childString(payload, "runtimeReadbackEnvelopeDigest") != d.RuntimeReadbackEnvelopeDigest {
		return ErrUntrusted
	}
	return store.ConfirmPaidDomainAcceptance(ctx, request.DemandManifestDigest, backend)
}

// Normal admission reads the accepted FIRST metadata without a POST or signing
// side effect. Current original case/install/process/grant gates remain separate.
func (p *Producer) CurrentPaidCaseDomain(ctx context.Context, current model.Manifest, store *state.Store, b PhysicalBaseline) (state.PaidDomain, error) {
	var empty state.PaidDomain
	if !hash.MatchString(b.Case.DemandManifestDigest) || store == nil {
		return empty, ErrUntrusted
	}
	raw, err := store.PhysicalFact(ctx, paidBootstrapFact(b.Case.DemandManifestDigest))
	var request model.PaidCaseDomainAdoptionRequest
	if err != nil || decodeClosed(raw, &request) != nil {
		return empty, ErrUntrusted
	}
	originalBasis, _, opening, err := p.paidBootstrapOriginals(ctx, current, store, request)
	if err != nil || originalBasis.Case != b.Case {
		return empty, ErrUntrusted
	}
	d, err := store.PaidDomain(ctx, request.DemandManifestDigest)
	if err != nil || d.Case.CaseDigest != b.Case.CaseManifestDigest || !sameProduct(d.Opening, opening) {
		return empty, ErrUntrusted
	}
	public, err := p.paidPublic()
	if err != nil || workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAdoptionEnvelope", d.AdoptionEnvelope) != nil || verifyChildEnvelope(d.AdoptionEnvelope, p.config.KeyID, public) != nil {
		return empty, ErrUntrusted
	}
	a := childFields(childFields(d.AdoptionEnvelope)["payload"])
	authority, err := p.read("physical-gate-authority.json", 65536)
	if err != nil || Digest(authority) != childString(a, "authorityDigest") || childString(a, "completeInventoryEnvelopeDigest") != request.CompleteInventoryEnvelopeDigest || childString(a, "demandManifestDigest") != request.DemandManifestDigest || childString(a, "runtimeReadbackEnvelopeDigest") != CanonicalDigest(request.RuntimeReadback) {
		return empty, ErrUntrusted
	}
	acceptance, err := store.PhysicalFact(ctx, "paid_domain_acceptance_"+request.DemandManifestDigest[7:])
	if err != nil {
		return empty, err
	}
	backend, err := store.PhysicalFact(ctx, "paid_backend_acceptance_"+request.DemandManifestDigest[7:])
	if err != nil || !bytes.Equal(acceptance, backend) || workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAcceptanceEnvelope", backend) != nil || verifyChildEnvelope(backend, p.config.KeyID, public) != nil {
		return empty, ErrUntrusted
	}
	f := childFields(childFields(backend)["payload"])
	r := childFields(childFields(request.RuntimeReadback)["payload"])
	accepted, ae := time.Parse(time.RFC3339Nano, childString(f, "acceptedAt"))
	observed, oe := time.Parse(time.RFC3339Nano, childString(r, "observedAt"))
	expiry, ee := time.Parse(time.RFC3339Nano, childString(r, "expiresAt"))
	if ae != nil || oe != nil || ee != nil || accepted.Before(observed) || !accepted.Before(expiry) || childString(f, "adoptionEnvelopeDigest") != d.AdoptionEnvelopeDigest || childString(f, "runtimeReadbackEnvelopeDigest") != d.RuntimeReadbackEnvelopeDigest {
		return empty, ErrUntrusted
	}
	if _, err = store.PhysicalLedgerCut(ctx); err != nil {
		return empty, err
	}
	return d, nil
}
