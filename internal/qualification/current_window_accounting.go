package qualification

// Independent verification of the registered backend snapshot's CURRENT window
// origins. The backend remains owner of row locking, committed event membership
// and namespace coverage. This module neither creates rows nor claims that global
// historical cash is current-window debt. It reuses the existing no-refund policy.
import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func (p *Producer) verifyCurrentWindowSnapshotOrigins(snapshot, request map[string]json.RawMessage, cut state.PaidLedgerCut, public []byte, now time.Time, get func(string, int) ([]byte, error)) (map[string]json.RawMessage, error) {
	ledger, err := currentWindowFields(snapshot["windowLedger"], "ledgerId", "identityDigest", "observedAt", "physicalRequests", "modelRequests", "preparations", "reservedUsdMicros", "actualUsdMicros", "unknownUsdMicros")
	if err != nil || workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "ledgerProjection", snapshot["windowLedger"]) != nil || childString(ledger, "identityDigest") != CanonicalDigest(map[string]any{"ledgerId": "model-qualification-and-product", "validationWindow": request["validationWindow"]}) || !sameProduct(ledger["observedAt"], snapshot["observedAt"]) {
		return nil, ErrUntrusted
	}
	var row financialVector
	if _, err = currentWindowFields(snapshot["backendVector"], "ledgerId", "physicalRequests", "modelRequests", "turns", "preparations", "reservedUsdMicros", "actualUsdMicros"); err != nil || decodeClosed(snapshot["backendVector"], &row) != nil || row.LedgerID != "model-qualification-and-product" || row.PhysicalRequests < 0 || row.ModelRequests < 0 || row.Preparations < 0 || row.Turns != row.ModelRequests || row.ReservedUsdMicros < 0 || row.ActualUsdMicros < 0 {
		return nil, ErrUntrusted
	}
	// Opening authenticity/current namespace coverage is checked by the registered
	// backend observation owner. These are original accepted window bytes, NOT an
	// invented Oct10 database snapshot or executable authority with config zeros.
	openingRaw, err := get(childString(snapshot, "openingReceiptDigest"), 65536)
	if err != nil {
		return nil, err
	}
	// Historical opening bytes may be a manager-retained non-JSON original. The
	// independently registered backend snapshot binds them to this namespace;
	// never invent a structured historical cash receipt as a new prerequisite.
	if len(openingRaw) == 0 {
		return nil, ErrUntrusted
	}
	associationRaw, err := get(childString(snapshot, "openingBackendCutDigest"), 65536)
	if err != nil {
		return nil, err
	}
	if workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "namespaceAssociation", associationRaw) != nil {
		return nil, ErrUntrusted
	}
	association := childFields(associationRaw)
	for _, name := range []string{"validationWindow", "scope", "nodeTokenHash", "candidateInventoryDigest", "openingReceiptDigest", "continuationReceiptDigests"} {
		if !sameProduct(association[name], request[name]) {
			return nil, ErrUntrusted
		}
	}
	if string(association["exclusiveWindowRow"]) != "true" {
		return nil, ErrUntrusted
	}
	at, e := time.Parse(time.RFC3339Nano, childString(association, "observedAt"))
	if e != nil || at.After(now) || now.Sub(at) > 120*time.Second || mustChildTime(childString(association, "expiresAt")).Before(mustChildTime(childString(request, "expiresAt"))) {
		return nil, ErrUntrusted
	}
	origins := func(name string, fields ...string) ([]map[string]json.RawMessage, error) {
		var values []json.RawMessage
		if decode(snapshot[name], &values) != nil || values == nil || len(values) > 128 {
			return nil, ErrUntrusted
		}
		result := []map[string]json.RawMessage{}
		for _, raw := range values {
			f, e := currentWindowFields(raw, fields...)
			if e != nil {
				return nil, e
			}
			result = append(result, f)
		}
		return result, nil
	}
	allocations, err := origins("allocationOrigins", "journalId", "recordDigest", "createdAt")
	if err != nil {
		return nil, err
	}
	localOrigins, err := origins("localHoldOrigins", "journalId", "recordDigest", "createdAt")
	if err != nil {
		return nil, err
	}
	imports, err := origins("importOrigins", "eventId", "qualificationId", "allocationJournalId", "evidenceDigest", "createdAt")
	if err != nil {
		return nil, err
	}
	pending, err := origins("pendingOrigins", "originDigest", "allocationJournalId", "retainedUsdMicros", "classification")
	if err != nil {
		return nil, err
	}
	physicalRaw, err := get(childString(request, "physicalCutDigest"), 65536)
	if err != nil || !sameProduct(childFields(physicalRaw)["pendingOrigins"], snapshot["pendingOrigins"]) {
		return nil, ErrUntrusted
	}
	windowStart := mustChildTime(childString(childFields(request["validationWindow"]), "openedAt"))
	validTime := func(f map[string]json.RawMessage) bool {
		at, e := time.Parse(time.RFC3339Nano, childString(f, "createdAt"))
		return e == nil && !at.Before(windowStart) && !at.After(now)
	}
	type originalAllocation struct {
		record     map[string]json.RawMessage
		allocation DemandAllocation
		operations []state.PhysicalOperation
		cashIndex  int
	}
	booked := map[string]originalAllocation{}
	paid := []financialAllocation{}
	local := []financialLocalHold{}
	seenRecords := map[string]bool{}
	next := 1
	for _, origin := range allocations {
		id, d := childString(origin, "journalId"), childString(origin, "recordDigest")
		if !validTime(origin) || seenRecords[d] {
			return nil, ErrUntrusted
		}
		seenRecords[d] = true
		raw, e := get(d, 65536)
		if e != nil {
			return nil, e
		}
		record, e := currentWindowFields(raw, "ledgerId", "demandManifestDigest", "allocation", "reservationId", "subjectId", "modelDispatchStart", "configDigest")
		if e != nil || childString(record, "ledgerId") != "model-qualification-and-product" {
			return nil, ErrUntrusted
		}
		var a DemandAllocation
		if err := workflowcontract.Validate(workflowcontract.Budget, "allocation", record["allocation"]); err != nil {
			return nil, fmt.Errorf("current-window allocation original %s violates existing allocation wire: %w", id, err)
		}
		// Existing allocation schema above owns the complete required key tree,
		// including dependsOn:[] for the first access. Strict duplicate-free decode
		// preserves it; a Go omitempty re-marshal is not that authoritative wire.
		if decode(record["allocation"], &a) != nil || a.USDMicros != int64(a.ModelRequests+a.AccessRequests)*RequestMicros || a.ScopeDigest != CanonicalDigest(a.Scope) || id != financialJournalID("typed-budget-allocation", childString(record, "demandManifestDigest")+":"+a.AllocationID) {
			return nil, fmt.Errorf("allocation identity/full-weight/scope digest: %w", ErrUntrusted)
		}
		for _, name := range []string{"accountId", "taskId", "serverId"} {
			if !sameProduct(childFields(record["allocation"])["scope"], a.Scope) || !sameProduct(childFields(childFields(record["allocation"])["scope"])[name], childFields(request["scope"])[name]) {
				return nil, fmt.Errorf("allocation owning scope %s: %w", name, ErrUntrusted)
			}
		}
		configRaw, e := get(childString(record, "configDigest"), 65536)
		if e != nil {
			return nil, e
		}
		if workflowcontract.Validate(workflowcontract.Budget, "authority2", configRaw) != nil && workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "authority2", configRaw) != nil {
			return nil, ErrUntrusted
		}
		config := childFields(configRaw)
		var c RealCase
		if decodeClosed(config["case"], &c) != nil || c.DemandManifestDigest != childString(record, "demandManifestDigest") {
			return nil, ErrUntrusted
		}
		// Immutable demand PAYLOAD original at its existing digest. The signed
		// snapshot independently attests authenticated committed journal origin;
		// this lookup does not invent a signature or change a historical alias.
		demandRaw, e := get(c.DemandManifestDigest, 65536)
		var demand DemandManifest
		if e != nil || decode(demandRaw, &demand) != nil {
			return nil, ErrUntrusted
		}
		declared, e := time.Parse(time.RFC3339Nano, demand.DeclaredAt)
		if e != nil || demand.validate(c, declared) != nil {
			return nil, fmt.Errorf("original allocation demand/case owning validation: %w", ErrUntrusted)
		}
		selected, e := demand.allocation(a.AllocationID)
		if e != nil || !sameProduct(selected, a) {
			return nil, ErrUntrusted
		}
		operations := []state.PhysicalOperation{}
		for _, ref := range cut.PaidHistory {
			raw, e := get(ref.OperationDigest, 65536)
			var o state.PhysicalOperation
			if e != nil || model.DecodePhysicalClosed(raw, &o) != nil {
				return nil, ErrUntrusted
			}
			if o.Permit.AllocationID == a.AllocationID && (o.Permit.PaidDomain == c.DemandManifestDigest || o.Permit.PaidDomain == "" && o.Permit.Case.CaseDigest == c.CaseManifestDigest) {
				if o.ReservedUsdMicros != RequestMicros || o.Permit.Caller.SandboxID != a.Scope.SandboxID || o.Permit.Caller.SandboxGeneration != a.Scope.SandboxGeneration || o.Permit.PreparationOrdinal != a.PreparationOrdinal || o.Permit.Request.OuterPhysicalIndex < a.FirstPhysicalIndex || o.Permit.Request.OuterPhysicalIndex > a.LastPhysicalIndex {
					return nil, fmt.Errorf("allocation physical original owner/full hold: %w", ErrUntrusted)
				}
				operations = append(operations, o)
			}
		}
		if _, duplicate := booked[id]; duplicate {
			return nil, ErrUntrusted
		}
		cash := financialAllocation{First: next, Last: next + a.ModelRequests + a.AccessRequests - 1, Models: a.ModelRequests, Preparations: boolInt(a.PreparationOrdinal > 0), Reserved: a.USDMicros}
		booked[id] = originalAllocation{record, a, operations, len(paid)}
		paid = append(paid, cash)
		next = cash.Last + 1
	}
	for _, origin := range localOrigins {
		d := childString(origin, "recordDigest")
		if !validTime(origin) || seenRecords[d] {
			return nil, ErrUntrusted
		}
		seenRecords[d] = true
		raw, e := get(d, 65536)
		if e != nil {
			return nil, e
		}
		record := childFields(raw)
		var retained int64
		if decode(record["reservedUsdMicros"], &retained) != nil || retained != 1263000 || childString(record, "ledgerId") != "model-qualification-and-product" || childString(origin, "journalId") != financialJournalID("source-local-financial-retention", childString(record, "identityDigest")) {
			return nil, ErrUntrusted
		}
		inventoryRaw, e := get(childString(record, "completeInventoryEnvelopeDigest"), 65536)
		if e != nil || workflowcontract.Validate(workflowcontract.CompleteExecutionInventory, "completeExecutionInventoryEnvelope", inventoryRaw) != nil {
			return nil, ErrUntrusted
		}
		inventory := childFields(childFields(inventoryRaw)["payload"])
		operator, e := p.read("physical-gate-operator.pem", 4096)
		if e != nil || verifyChildEnvelope(inventoryRaw, childString(childFields(inventoryRaw), "keyId"), operator) != nil || !sameProduct(inventory["validationWindow"], request["validationWindow"]) || !sameProduct(inventory["scope"], request["scope"]) {
			return nil, ErrUntrusted
		}
		projection := map[string]json.RawMessage{}
		for name, value := range inventory {
			if name != "localAllocations" {
				projection[name] = value
			}
		}
		identity := CanonicalDigest(map[string]any{"purpose": "source_local_financial_retention", "localCaseEnvelopeDigest": childString(inventory, "localCaseEnvelopeDigest"), "inventoryIdentityDigest": CanonicalDigest(projection)})
		if childString(record, "identityDigest") != identity || !sameProduct(record["localAllocations"], inventory["localAllocations"]) {
			return nil, ErrUntrusted
		}
		localRaw, e := get(childString(inventory, "localCaseEnvelopeDigest"), 65536)
		if e != nil || workflowcontract.Validate(workflowcontract.SourceLocalTransport, "localCaseEnvelope", localRaw) != nil || verifyChildEnvelope(localRaw, childString(childFields(localRaw), "keyId"), operator) != nil {
			return nil, ErrUntrusted
		}
		local = append(local, financialLocalHold{Reserved: 1263000})
	}
	seenEvents := map[string]bool{}
	credited := map[string]bool{}
	for _, origin := range imports {
		event, id := childString(origin, "eventId"), childString(origin, "allocationJournalId")
		a, ok := booked[id]
		if !ok || !validTime(origin) || !safeID.MatchString(event) || seenEvents[event] || credited[id] {
			return nil, ErrUntrusted
		}
		seenEvents[event] = true
		credited[id] = true
		raw, e := get(childString(origin, "evidenceDigest"), 65536)
		if e != nil {
			return nil, e
		}
		actual, e := verifyQualificationImportCash(raw, childString(origin, "qualificationId"), a.record, a.allocation, a.operations, p.config.KeyID, public, now, get)
		if e != nil {
			return nil, e
		}
		paid[a.cashIndex].ImportActual = &actual
	}
	var unknown int64
	seenPending := map[string]bool{}
	ownerCovered := cut.Owner == nil
	for _, origin := range pending {
		d := childString(origin, "originDigest")
		if seenPending[d] {
			return nil, ErrUntrusted
		}
		seenPending[d] = true
		raw, e := get(d, 65536)
		if e != nil || len(raw) == 0 {
			return nil, ErrUntrusted
		}
		var retained int64
		if decode(origin["retainedUsdMicros"], &retained) != nil || retained != RequestMicros {
			return nil, ErrUntrusted
		}
		if cut.Owner != nil && cut.Owner.OperationDigest == d {
			ownerCovered = true
		}
		switch childString(origin, "classification") {
		case "retained_full_hold":
			a, ok := booked[childString(origin, "allocationJournalId")]
			if !ok || retained != RequestMicros {
				return nil, ErrUntrusted
			}
			var o state.PhysicalOperation
			// SAME physical owner wire permits Settlement:null for UNKNOWN. Reuse
			// its closed decoder; a mandatory non-null settlement would erase the
			// very unresolved original whose full hold this observation preserves.
			if model.DecodePhysicalClosed(raw, &o) != nil || o.Phase != "unknown" || o.ReservedUsdMicros != retained || o.Permit.AllocationID != a.allocation.AllocationID {
				return nil, ErrUntrusted
			}
			if actual, ok := cut.Originals[d]; !ok || !sameProduct(json.RawMessage(raw), actual) {
				return nil, ErrUntrusted
			}
		case "bounded_unbooked_unknown":
			if string(origin["allocationJournalId"]) != "null" || retained > 30000000-unknown {
				return nil, ErrUntrusted
			}
			var o state.PhysicalOperation
			if cut.Owner == nil || cut.Owner.OperationDigest != d || model.DecodePhysicalClosed(raw, &o) != nil || o.OperationID != cut.Owner.OperationID || o.Phase != "unknown" || o.Settlement != nil || o.Permit.Offline != nil || o.ReservedUsdMicros != retained {
				return nil, ErrUntrusted
			}
			if actual, ok := cut.Originals[d]; !ok || !sameProduct(json.RawMessage(raw), actual) {
				return nil, ErrUntrusted
			}
			for _, a := range booked {
				for _, operation := range a.operations {
					if operation.OperationID == o.OperationID {
						return nil, ErrUntrusted
					}
				}
			}
			unknown += retained
		default:
			return nil, ErrUntrusted
		}
	}
	if !ownerCovered {
		return nil, ErrUntrusted
	}
	vector := map[string]json.RawMessage{}
	for _, name := range []string{"ledgerId", "physicalRequests", "modelRequests", "preparations", "reservedUsdMicros", "actualUsdMicros"} {
		vector[name] = ledger[name]
	}
	var current financialVector
	if decode(canonicalBytes(vector), &current) != nil {
		return nil, ErrUntrusted
	}
	current.Turns = current.ModelRequests
	var projectedUnknown int64
	if decode(ledger["unknownUsdMicros"], &projectedUnknown) != nil || projectedUnknown != unknown {
		return nil, ErrUntrusted
	}
	if err := reconstructFinancialCash(financialVector{LedgerID: "model-qualification-and-product"}, current, paid, local, unknown, 30000000); err != nil {
		return nil, fmt.Errorf("current-window original cash conservation: %w", err)
	}
	// The backend signed CURRENT namespace association owns cumulative prefix
	// verification. Do not demand a historical DB cut or charge excluded old cash.
	// Its actual row cannot be smaller than the authenticated current-window facts.
	if row.PhysicalRequests < current.PhysicalRequests || row.ModelRequests < current.ModelRequests || row.Preparations < current.Preparations || row.ReservedUsdMicros < current.ReservedUsdMicros || row.ActualUsdMicros < current.ActualUsdMicros {
		return nil, ErrUntrusted
	}
	return ledger, nil
}
