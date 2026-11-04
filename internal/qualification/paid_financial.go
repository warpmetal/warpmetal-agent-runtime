package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

var ErrPaidFinancialImportPending = errors.New("original committed qualification-import cash verification pending")
var ErrPaidFinancialOpeningPending = errors.New("original343 included cash attribution pending")

type financialVector struct {
	LedgerID          string `json:"ledgerId"`
	PhysicalRequests  int    `json:"physicalRequests"`
	ModelRequests     int    `json:"modelRequests"`
	Turns             int    `json:"turns"`
	Preparations      int    `json:"preparations"`
	ReservedUsdMicros int64  `json:"reservedUsdMicros"`
	ActualUsdMicros   int64  `json:"actualUsdMicros"`
}
type financialAllocation struct {
	First, Last, Models, Preparations int
	Reserved                          int64
	// Set only after the committed import's original graph and SAME settled
	// operations verify. Native settlement alone never supplies this credit.
	ImportActual *int64
}
type financialLocalHold struct {
	IncludedAtOpening bool
	Reserved          int64
}

// Native settled usage is deliberately absent from this cash policy. Until a
// committed import's original credit is independently verified, all holds survive.
func reconstructFinancialCash(opening, current financialVector, paid []financialAllocation, local []financialLocalHold, unknown, limit int64) error {
	if opening.LedgerID != "model-qualification-and-product" || current.LedgerID != opening.LedgerID || opening.ActualUsdMicros != 0 {
		return ErrPaidFinancialOpeningPending
	}
	prefix := financialVector{LedgerID: opening.LedgerID}
	actual := prefix
	next := 1
	for _, a := range paid {
		if a.First != next || a.Last < a.First || a.Reserved != int64(a.Last-a.First+1)*421000 || (a.Models != 0 && a.Models != a.Last-a.First+1) || (a.Models == 0 && (a.Last != a.First || a.Preparations != 0)) || a.Preparations < 0 || a.Preparations > 1 || a.First <= opening.PhysicalRequests && a.Last > opening.PhysicalRequests {
			return ErrUntrusted
		}
		actual.PhysicalRequests += a.Last - a.First + 1
		actual.ModelRequests += a.Models
		actual.Turns += a.Models
		actual.Preparations += a.Preparations
		actual.ReservedUsdMicros += a.Reserved
		if a.Last <= opening.PhysicalRequests {
			prefix = actual
		}
		next = a.Last + 1
	}
	// Zero opening actual is the supported cut. Do not infer an earlier import's
	// inclusion from response/settlement time. Prefix remains the full original
	// allocation; all verified later credits affect current cash only.
	for _, a := range paid {
		if a.ImportActual != nil {
			if a.Models != 2 || *a.ImportActual < 0 || *a.ImportActual > a.Reserved {
				return ErrUntrusted
			}
			actual.ReservedUsdMicros -= a.Reserved
			actual.ActualUsdMicros += *a.ImportActual
		}
	}
	for _, hold := range local {
		if hold.Reserved != 1263000 {
			return ErrUntrusted
		}
		actual.ReservedUsdMicros += hold.Reserved
		if hold.IncludedAtOpening {
			prefix.ReservedUsdMicros += hold.Reserved
		}
	}
	if prefix != opening || actual != current || unknown < 0 || limit != 30000000 || current.ReservedUsdMicros+current.ActualUsdMicros+unknown > limit {
		return ErrUntrusted
	}
	return nil
}

func financialIndexFact(adoption string) string { return "financial_initial_index_" + adoption[7:] }

func (p *Producer) verifiedFinancialIndex(raw []byte, basis paidAdoptionBasis, adoption []byte, now time.Time) (map[string]json.RawMessage, error) {
	if workflowcontract.ValidateFinancialOriginalIndex(raw) != nil || !bytes.Equal(raw, canonicalBytes(json.RawMessage(raw))) || verifyChildEnvelope(raw, p.config.KeyID, basis.public) != nil {
		return nil, ErrUntrusted
	}
	index := childFields(childFields(raw)["payload"])
	if childString(index, "adoptionEnvelopeDigest") != Digest(adoption) {
		return nil, ErrUntrusted
	}
	for _, field := range []string{"validationWindow", "candidateInventoryDigest", "scope", "attemptId"} {
		if !sameProduct(index[field], basis.payload[field]) {
			return nil, ErrUntrusted
		}
	}
	observed, oe := time.Parse(time.RFC3339Nano, childString(index, "observedAt"))
	expires, ee := time.Parse(time.RFC3339Nano, childString(index, "expiresAt"))
	if oe != nil || ee != nil || observed.After(now) || now.Sub(observed) > 120*time.Second || !observed.Before(expires) || expires.Sub(observed) > 120*time.Second || !now.Before(expires) || expires.After(mustChildTime(childString(basis.inventory, "expiresAt"))) {
		return nil, ErrUntrusted
	}
	return index, nil
}

// Normal authenticated caller acquires catalog and declared raw leaves BEFORE
// acceptance. Verification is independent of fetch/file presence and never books
// cash. Historical inventories retain their original candidate identity.
func (p *Producer) AcquirePaidFinancialOriginals(ctx context.Context, current model.Manifest, store *state.Store, request model.PaidCaseDomainAdoptionRequest, adoption, catalog json.RawMessage, read func(context.Context, string) ([]byte, error)) error {
	basis, err := p.verifiedPaidAdoptionBasis(ctx, current, store, request, adoption)
	if err != nil {
		return err
	}
	index, err := p.verifiedFinancialIndex(catalog, basis, adoption, time.Now())
	if err != nil || read == nil {
		return ErrUntrusted
	}
	var refs []map[string]json.RawMessage
	if decode(index["localRetentions"], &refs) != nil {
		return ErrUntrusted
	}
	total := 0
	seen := map[string]bool{}
	for _, ref := range refs {
		for _, field := range []string{"recordDigest", "completeInventoryEnvelopeDigest", "localCaseEnvelopeDigest"} {
			d := childString(ref, field)
			if seen[d] {
				continue
			}
			seen[d] = true
			raw, e := read(ctx, d)
			total += len(raw)
			if e != nil {
				return e
			}
			if total > model.PaidObservationMaximum || len(raw) > 65536 || Digest(raw) != d || !bytes.Equal(raw, canonicalBytes(json.RawMessage(raw))) {
				return ErrUntrusted
			}
			if e = p.append(d[7:], raw); e != nil {
				return e
			}
		}
	}
	if _, err = p.verifyLocalFinancialOriginals(index, basis, time.Now()); err != nil {
		return err
	}
	if err = p.append(Digest(catalog)[7:], catalog); err != nil {
		return err
	}
	// FIRST acceptance cut only; fresh LOCAL readback must be separately acquired
	// at the normal LOCAL caller, never overwritten into this immutable snapshot.
	prior, err := store.PhysicalFact(ctx, financialIndexFact(Digest(adoption)))
	if err != nil {
		return err
	}
	if prior != nil {
		return nil
	}
	return store.RetainPhysicalFact(ctx, financialIndexFact(Digest(adoption)), []byte(Digest(catalog)))
}

func (p *Producer) verifyLocalFinancialOriginals(index map[string]json.RawMessage, basis paidAdoptionBasis, now time.Time) ([]financialLocalHold, error) {
	operator, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil {
		return nil, err
	}
	opID := childString(childFields(childFields(mustReadAuthority(p))["operator"]), "keyId")
	var refs []map[string]json.RawMessage
	if decode(index["localRetentions"], &refs) != nil {
		return nil, ErrUntrusted
	}
	holds := []financialLocalHold{}
	prior := ""
	reconciliation, err := p.paidOriginal(childString(basis.payload, "producerReconciliationEnvelopeDigest"))
	if err != nil {
		return nil, err
	}
	cut := mustChildTime(childString(childFields(childFields(childFields(reconciliation)["payload"])["ledger"]), "observedAt"))
	for _, ref := range refs {
		identity := childString(ref, "identityDigest")
		if identity <= prior {
			return nil, ErrUntrusted
		}
		prior = identity
		record, err := p.paidOriginal(childString(ref, "recordDigest"))
		if err != nil {
			return nil, err
		}
		expected := map[string]json.RawMessage{}
		for field, value := range ref {
			if field != "formatVersion" && field != "purpose" && field != "journalId" && field != "recordDigest" {
				expected[field] = value
			}
		}
		if !bytes.Equal(record, canonicalBytes(expected)) {
			return nil, ErrUntrusted
		}
		inventory, err := p.paidOriginal(childString(ref, "completeInventoryEnvelopeDigest"))
		if err != nil || workflowcontract.Validate(workflowcontract.CompleteExecutionInventory, "completeExecutionInventoryEnvelope", inventory) != nil || verifyChildEnvelope(inventory, opID, operator) != nil {
			return nil, ErrUntrusted
		}
		i := childFields(childFields(inventory)["payload"])
		if !sameProduct(i["validationWindow"], index["validationWindow"]) {
			return nil, ErrUntrusted
		}
		for _, field := range []string{"accountId", "taskId", "serverId"} {
			if !sameProduct(childFields(i["scope"])[field], childFields(index["scope"])[field]) {
				return nil, ErrUntrusted
			}
		}
		projection := map[string]json.RawMessage{}
		for field, value := range i {
			if field != "localAllocations" {
				projection[field] = value
			}
		}
		inventoryIdentity := CanonicalDigest(projection)
		if childString(ref, "inventoryIdentityDigest") != inventoryIdentity || identity != CanonicalDigest(map[string]any{"purpose": "source_local_financial_retention", "localCaseEnvelopeDigest": childString(i, "localCaseEnvelopeDigest"), "inventoryIdentityDigest": inventoryIdentity}) || !sameProduct(ref["localAllocations"], i["localAllocations"]) || !sameProduct(ref["localCaseEnvelopeDigest"], i["localCaseEnvelopeDigest"]) {
			return nil, ErrUntrusted
		}
		if childString(ref, "journalId") != financialJournalID("source-local-financial-retention", identity) {
			return nil, ErrUntrusted
		}
		local, err := p.paidOriginal(childString(ref, "localCaseEnvelopeDigest"))
		if err != nil || workflowcontract.Validate(workflowcontract.SourceLocalTransport, "localCaseEnvelope", local) != nil || verifyChildEnvelope(local, opID, operator) != nil {
			return nil, ErrUntrusted
		}
		l := childFields(childFields(local)["payload"])
		if !sameProduct(l["scope"], i["scope"]) || !sameProduct(l["candidateInventoryDigest"], i["candidateInventoryDigest"]) {
			return nil, ErrUntrusted
		}
		retained, err := time.Parse(time.RFC3339Nano, childString(ref, "retainedAt"))
		if err != nil || retained.After(now) || retained.Before(mustChildTime(childString(i, "issuedAt"))) || !retained.Before(mustChildTime(childString(i, "expiresAt"))) {
			return nil, ErrUntrusted
		}
		var allocations []map[string]json.RawMessage
		if decode(ref["localAllocations"], &allocations) != nil || len(allocations) != 3 {
			return nil, ErrUntrusted
		}
		for n, a := range allocations {
			suffix := Digest([]byte(identity + ":" + string(rune('1'+n))))[7:47]
			if childString(a, "allocationId") != "localalloc_"+suffix || childString(a, "reservationId") != "localres_"+suffix {
				return nil, ErrUntrusted
			}
		}
		holds = append(holds, financialLocalHold{IncludedAtOpening: !retained.After(cut), Reserved: 1263000})
	}
	return holds, nil
}

func financialJournalID(kind, identity string) string {
	return "ctrl_" + Digest([]byte(kind + ":" + identity))[7:55]
}

// Recovery uses only the original signed acceptance's valid FIRST cut, not a
// caller timestamp or a fresh signature. Readback/adoption trust is verified by
// verifiedPaidAdoptionBasis before this narrow timestamp join.
func verifyFinancialAcceptedCut(accepted []byte, basis paidAdoptionBasis, adoption, readback []byte, producer ProducerConfig, now time.Time) (time.Time, error) {
	if workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAcceptanceEnvelope", accepted) != nil || !bytes.Equal(accepted, canonicalBytes(json.RawMessage(accepted))) || Digest(basis.public) != producer.KeySHA256 || verifyChildEnvelope(accepted, producer.KeyID, basis.public) != nil || Digest(readback) != childString(basis.payload, "runtimeReadbackEnvelopeDigest") {
		return time.Time{}, ErrUntrusted
	}
	payload := childFields(childFields(accepted)["payload"])
	readbackPayload := childFields(childFields(readback)["payload"])
	at, ae := time.Parse(time.RFC3339Nano, childString(payload, "acceptedAt"))
	retained, re := time.Parse(time.RFC3339Nano, childString(basis.payload, "retainedAt"))
	observed, oe := time.Parse(time.RFC3339Nano, childString(readbackPayload, "observedAt"))
	expires, ee := time.Parse(time.RFC3339Nano, childString(readbackPayload, "expiresAt"))
	if ae != nil || re != nil || oe != nil || ee != nil || at.After(now) || at.Before(retained) || at.Before(observed) || !at.Before(expires) || !observed.Before(expires) || expires.Sub(observed) > 120*time.Second || childString(payload, "adoptionEnvelopeDigest") != Digest(adoption) || childString(payload, "runtimeReadbackEnvelopeDigest") != Digest(readback) {
		return time.Time{}, ErrUntrusted
	}
	return at, nil
}

func (p *Producer) verifyPaidFinancialBeforeAdoption(ctx context.Context, store *state.Store, basis paidAdoptionBasis, adoption []byte) error {
	verificationTime := time.Now()
	accepted, ae := store.PhysicalFact(ctx, "paid_domain_acceptance_"+childString(basis.payload, "demandManifestDigest")[7:])
	if ae != nil {
		return ae
	}
	// The archive commits before AcceptPaidDomain's SQLite association. A crash
	// in between must consume the SAME original, never re-sign or refresh the cut.
	archived, archiveErr := p.readPaidDomainEnvelope(childString(basis.payload, "demandManifestDigest"), "acceptance-envelope.json")
	if archiveErr != nil && !errors.Is(archiveErr, syscall.ENOENT) {
		return archiveErr
	}
	if archiveErr == nil {
		if accepted != nil && !bytes.Equal(accepted, archived) {
			return ErrUntrusted
		}
		accepted = archived
	}
	if accepted != nil {
		readback, err := p.paidOriginal(childString(basis.payload, "runtimeReadbackEnvelopeDigest"))
		if err != nil {
			return err
		}
		at, err := verifyFinancialAcceptedCut(accepted, basis, adoption, readback, p.config, verificationTime)
		if err != nil {
			return err
		}
		// FIRST accepted bytes recover at their verified original cut. A fresh
		// catalog never rewrites/re-signs an already accepted opening after120s.
		verificationTime = at
	}
	reference, err := store.PhysicalFact(ctx, financialIndexFact(Digest(adoption)))
	if err != nil || !hash.Match(reference) {
		return ErrUntrusted
	}
	catalog, err := p.read(string(reference)[7:], workflowcontract.FinancialOriginalIndexMaximum)
	if err != nil || Digest(catalog) != string(reference) {
		return ErrUntrusted
	}
	index, err := p.verifiedFinancialIndex(catalog, basis, adoption, verificationTime)
	if err != nil {
		return err
	}
	holds, err := p.verifyLocalFinancialOriginals(index, basis, verificationTime)
	if err != nil {
		return err
	}
	reconciliation, err := p.paidOriginal(childString(basis.payload, "producerReconciliationEnvelopeDigest"))
	if err != nil || workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "currentWindowReconciliationEnvelope", reconciliation) != nil || verifyChildEnvelope(reconciliation, p.config.KeyID, basis.public) != nil {
		return ErrUntrusted
	}
	r := childFields(childFields(reconciliation)["payload"])
	for _, field := range []string{"validationWindow", "candidateInventoryDigest", "openingReceiptDigest"} {
		if !sameProduct(r[field], basis.payload[field]) {
			return ErrUntrusted
		}
	}
	var opening, current financialVector
	ledger := childFields(r["ledger"])
	// The original ledger has identity/observed/UNKNOWN fields, not a cash-vector
	// wire. Its complete shape/signature was checked above; select only its
	// existing counter fields rather than trying to decode it as another schema.
	vector := map[string]json.RawMessage{}
	for _, name := range []string{"ledgerId", "physicalRequests", "modelRequests", "preparations", "reservedUsdMicros", "actualUsdMicros"} {
		vector[name] = ledger[name]
	}
	if decode(canonicalBytes(vector), &opening) != nil || decodeClosed(basis.payload["backendOpening"], &current) != nil || !sameProduct(ledger["unknownUsdMicros"], basis.payload["unknownUsdMicros"]) {
		return ErrUntrusted
	}
	opening.Turns = opening.ModelRequests
	var joins []map[string]json.RawMessage
	if decode(basis.payload["accountingJoins"], &joins) != nil {
		return ErrUntrusted
	}
	paid := []financialAllocation{}
	seen := map[string]bool{}
	seenImports := map[string]bool{}
	seenOperations := map[string]bool{}
	var covered int64
	for _, join := range joins {
		id := childString(join, "journalId")
		if seen[id] {
			return ErrUntrusted
		}
		seen[id] = true
		record, err := p.paidOriginal(childString(join, "recordDigest"))
		if err != nil {
			return err
		}
		fields := childFields(record)
		var allocation DemandAllocation
		if decodeClosed(fields["allocation"], &allocation) != nil || workflowcontract.Validate(workflowcontract.Budget, "allocation", fields["allocation"]) != nil || allocation.AllocationID != childString(join, "allocationId") || childString(fields, "demandManifestDigest") != childString(join, "demandManifestDigest") || childString(fields, "ledgerId") != opening.LedgerID || id != financialJournalID("typed-budget-allocation", childString(fields, "demandManifestDigest")+":"+allocation.AllocationID) {
			return ErrUntrusted
		}
		if allocation.ScopeDigest != CanonicalDigest(allocation.Scope) {
			return ErrUntrusted
		}
		for _, field := range []string{"accountId", "taskId", "serverId"} {
			if !sameProduct(childFields(childFields(fields["allocation"])["scope"])[field], childFields(index["scope"])[field]) {
				return ErrUntrusted
			}
		}
		originalAuthority, err := p.paidOriginal(childString(fields, "configDigest"))
		if err != nil || (workflowcontract.Validate(workflowcontract.Budget, "authority2", originalAuthority) != nil && workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "authority2", originalAuthority) != nil) {
			return ErrUntrusted
		}
		authority := childFields(originalAuthority)
		if childString(childFields(authority["case"]), "demandManifestDigest") != childString(join, "demandManifestDigest") {
			return ErrUntrusted
		}
		first, last := allocation.FirstPhysicalIndex, allocation.LastPhysicalIndex
		if string(join["domainAdoptionEnvelopeDigest"]) != "null" {
			domain, err := p.paidOriginal(childString(join, "domainAdoptionEnvelopeDigest"))
			if err != nil || workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAdoptionEnvelope", domain) != nil || verifyChildEnvelope(domain, p.config.KeyID, basis.public) != nil {
				return ErrUntrusted
			}
			d := childFields(childFields(domain)["payload"])
			var base state.PaidCounters
			if decode(d["bases"], &base) != nil || childString(d, "demandManifestDigest") != childString(join, "demandManifestDigest") || childString(d, "authorityDigest") != Digest(originalAuthority) || !sameProduct(d["validationWindow"], index["validationWindow"]) {
				return ErrUntrusted
			}
			if childString(d, "completeInventoryEnvelopeDigest") == childString(basis.payload, "completeInventoryEnvelopeDigest") {
				covered += allocation.USDMicros
			}
			demandRaw, err := p.paidOriginal(childString(d, "demandEnvelopeDigest"))
			operator, oe := p.read("physical-gate-operator.pem", 4096)
			if err != nil || oe != nil || Digest(operator)[7:] != childString(childFields(authority["operator"]), "keySHA256") || workflowcontract.Validate(workflowcontract.Budget, "demandManifestEnvelope", demandRaw) != nil || verifyChildEnvelope(demandRaw, childString(childFields(authority["operator"]), "keyId"), operator) != nil {
				return ErrUntrusted
			}
			var demand ChildEnvelope[DemandManifest]
			if decodeClosed(demandRaw, &demand) != nil || CanonicalDigest(demand.Payload) != childString(join, "demandManifestDigest") {
				return ErrUntrusted
			}
			selected, e := demand.Payload.allocation(allocation.AllocationID)
			if e != nil || !sameProduct(selected, allocation) {
				return ErrUntrusted
			}
			first += base.PhysicalRequests
			last += base.PhysicalRequests
		}
		var operations []state.PhysicalOwnerRef
		if decode(join["physicalOperations"], &operations) != nil || len(operations) != last-first+1 {
			return ErrUntrusted
		}
		actualOperations := []state.PhysicalOperation{}
		for n, ref := range operations {
			raw, ok := basis.opening.Originals[ref.OperationDigest]
			var operation state.PhysicalOperation
			if !ok || seenOperations[ref.OperationID] || Digest(raw) != ref.OperationDigest || decodeClosed(raw, &operation) != nil || operation.OperationID != ref.OperationID || operation.Permit.AllocationID != allocation.AllocationID || operation.Permit.PreparationOrdinal != allocation.PreparationOrdinal || operation.Permit.Request.OuterPhysicalIndex != allocation.FirstPhysicalIndex+n || operation.Permit.Caller.SandboxID != allocation.Scope.SandboxID || operation.Permit.Caller.SandboxGeneration != allocation.Scope.SandboxGeneration {
				return ErrUntrusted
			}
			seenOperations[ref.OperationID] = true
			actualOperations = append(actualOperations, operation)
		}
		cash := financialAllocation{First: first, Last: last, Models: allocation.ModelRequests, Preparations: boolInt(allocation.PreparationOrdinal > 0), Reserved: allocation.USDMicros}
		// Only the signed adoption's exact committed event locator is eligible.
		// The existing raw GET independently requires accepted run+import event;
		// here we reverify original bytes/signature/request/tool/physical joins.
		if string(join["qualificationImport"]) != "null" {
			ref := childFields(join["qualificationImport"])
			event := childString(ref, "eventId")
			if seenImports[event] {
				return ErrUntrusted
			}
			seenImports[event] = true
			evidence, e := p.paidOriginal(childString(ref, "evidenceDigest"))
			producer := childFields(authority["producer"])
			if e != nil || childString(producer, "keyId") != p.config.KeyID || childString(producer, "keySHA256") != Digest(basis.public)[7:] {
				return ErrUntrusted
			}
			actual, e := verifyQualificationImportCash(evidence, childString(ref, "qualificationId"), fields, allocation, actualOperations, p.config.KeyID, basis.public, verificationTime, func(d string, maximum int) ([]byte, error) {
				if !hash.MatchString(d) {
					return nil, ErrUntrusted
				}
				raw, e := p.read(d[7:], maximum)
				if e != nil || Digest(raw) != d {
					return nil, ErrUntrusted
				}
				return raw, nil
			})
			if e != nil {
				return e
			}
			cash.ImportActual = &actual
		}
		paid = append(paid, cash)
	}
	// Joins are ordered by owning physical history; no caller-selected cash order.
	var unknown, limit int64
	if decode(basis.payload["unknownUsdMicros"], &unknown) != nil || decode(childFields(index["validationWindow"])["totalUsdMicros"], &limit) != nil {
		return ErrUntrusted
	}
	var refs []map[string]json.RawMessage
	if decode(index["localRetentions"], &refs) != nil {
		return ErrUntrusted
	}
	for _, ref := range refs {
		if childString(ref, "completeInventoryEnvelopeDigest") == childString(basis.payload, "completeInventoryEnvelopeDigest") {
			covered += 1263000
		}
	}
	var prospective int64
	if decode(childFields(basis.inventory["totals"])["reservedUsdMicros"], &prospective) != nil || covered > prospective || current.ReservedUsdMicros+current.ActualUsdMicros+unknown+prospective-covered > limit {
		return ErrUntrusted
	}
	return reconstructFinancialCash(opening, current, paid, holds, unknown, limit)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
