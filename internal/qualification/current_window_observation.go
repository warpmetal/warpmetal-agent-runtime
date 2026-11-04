package qualification

// The registered observation owner reads protected PUBLIC originals and SAME
// physical history. No operator signing key, financial mutation or execution RPC.
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
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

var ErrCurrentWindowObservationPending = errors.New("current window public snapshot/CORE observation pending")
var ErrCurrentWindowObservationUnknown = errors.New("current window FIRST observation incomplete; permanent UNKNOWN")

const currentWindowRequest = "current-window-snapshot-request.json"
const currentWindowSnapshot = "current-window-backend-snapshot.json"

// This optional fixed leaf selects ONLY the finite observation. Its absence does
// not make a zero ledger or grant admission; existing paid validators still gate
// every paid path. Unsafe/malformed present leaves are never treated as absent.
func (p *Producer) currentWindowLeaf(name string) ([]byte, error) {
	if p == nil || rootPrivate(p.config.EvidenceRoot, true) != nil || filepath.Base(name) != name {
		return nil, ErrUntrusted
	}
	if _, err := os.Lstat(filepath.Join(p.config.EvidenceRoot, name)); errors.Is(err, syscall.ENOENT) {
		return nil, ErrCurrentWindowObservationPending
	} else if err != nil {
		return nil, err
	}
	return p.read(name, 65536)
}

func currentWindowFields(raw []byte, names ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if decode(raw, &fields) != nil || len(fields) != len(names) || !bytes.Equal(raw, canonicalBytes(json.RawMessage(raw))) {
		return nil, ErrUntrusted
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return nil, ErrUntrusted
		}
	}
	return fields, nil
}

func (p *Producer) currentWindowRequestFields(ctx context.Context, current model.Manifest) (map[string]json.RawMessage, []byte, error) {
	return p.currentWindowRequestFieldsAt(ctx, current, time.Now().UTC())
}

func (p *Producer) currentWindowRequestFieldsAt(ctx context.Context, current model.Manifest, now time.Time) (map[string]json.RawMessage, []byte, error) {
	if ctx.Err() != nil || p == nil || p.key == nil || current.ServerID != p.config.ServerID {
		return nil, nil, ErrUntrusted
	}
	raw, err := p.currentWindowLeaf(currentWindowRequest)
	if err != nil {
		return nil, nil, err
	}
	f, err := currentWindowFields(raw, "formatVersion", "purpose", "requestId", "scope", "nodeTokenHash", "candidateInventoryDigest", "authorityCorePath", "workflowProducerConfigDigest", "validationWindow", "prospectiveProjectionDigest", "openingReceiptDigest", "openingBackendCutDigest", "physicalCutDigest", "continuationReceiptDigests", "approvedAt", "expiresAt")
	if err != nil || workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "snapshotRequest", raw) != nil || childString(f, "nodeTokenHash") != p.config.NodeTokenHash || childString(f, "authorityCorePath") != filepath.Join(p.config.EvidenceRoot, "current-window-authority-core.json") {
		return nil, nil, ErrUntrusted
	}
	if workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "validationWindow", f["validationWindow"]) != nil {
		return nil, nil, ErrUntrusted
	}
	scope := childFields(f["scope"])
	if err != nil || childString(scope, "serverId") != current.ServerID {
		return nil, nil, ErrUntrusted
	}
	for _, name := range []string{"accountId", "taskId", "serverId"} {
		if !safeID.MatchString(childString(scope, name)) {
			return nil, nil, ErrUntrusted
		}
	}
	for _, name := range []string{"candidateInventoryDigest", "workflowProducerConfigDigest", "prospectiveProjectionDigest", "openingReceiptDigest", "openingBackendCutDigest", "physicalCutDigest"} {
		if !hash.MatchString(childString(f, name)) {
			return nil, nil, ErrUntrusted
		}
	}
	var refs []string
	if decode(f["continuationReceiptDigests"], &refs) != nil || len(refs) == 0 || len(refs) > 128 {
		return nil, nil, ErrUntrusted
	}
	seen := map[string]bool{}
	for _, d := range refs {
		if !hash.MatchString(d) || seen[d] {
			return nil, nil, ErrUntrusted
		}
		seen[d] = true
	}
	approved, ae := time.Parse(time.RFC3339Nano, childString(f, "approvedAt"))
	expires, ee := time.Parse(time.RFC3339Nano, childString(f, "expiresAt"))
	if ae != nil || ee != nil || approved.After(now) || !now.Before(expires) || !approved.Before(expires) {
		return nil, nil, ErrUntrusted
	}
	return f, raw, nil
}

// Finite preselection completion, not execution admission. FIRST accepted
// metadata owns the historical cut; ongoing installed/grant/financial/physical
// checks remain with the existing paid owners. A mere adoption (or a different
// case) cannot suppress preselection checks. No files/facts/signatures are changed.
func (p *Producer) CurrentWindowPhaseComplete(ctx context.Context, current model.Manifest, store *state.Store) (bool, error) {
	requestRaw, err := p.currentWindowLeaf(currentWindowRequest)
	if errors.Is(err, ErrCurrentWindowObservationPending) {
		return false, nil
	}
	if err != nil || store == nil || ctx.Err() != nil || workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "snapshotRequest", requestRaw) != nil {
		return false, ErrUntrusted
	}
	coreRaw, err := p.currentWindowLeaf("selected-manifest26-core.json")
	if errors.Is(err, ErrCurrentWindowObservationPending) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	core, err := currentWindowFields(coreRaw, "formatVersion", "selection", "case", "demand", "tupleInventory", "installedReadinessDigest", "responsesPermissionDigest")
	if err != nil || workflowcontract.Validate(workflowcontract.Budget, "selectedCase26", core["case"]) != nil {
		return false, ErrUntrusted
	}
	c := childFields(core["case"])
	digest := childString(c, "demandManifestDigest")
	original, err := store.PhysicalFact(ctx, "paid_domain_"+digest[7:])
	if err != nil {
		return false, err
	}
	if len(original) == 0 {
		return false, nil
	}
	local, err := store.PhysicalFact(ctx, "paid_domain_acceptance_"+digest[7:])
	if err != nil {
		return false, err
	}
	confirmed, err := store.PhysicalFact(ctx, "paid_backend_acceptance_"+digest[7:])
	if err != nil {
		return false, err
	}
	if len(local) == 0 || len(confirmed) == 0 {
		return false, nil
	}
	public, err := p.paidPublic()
	if err != nil || !bytes.Equal(local, confirmed) || workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAcceptanceEnvelope", confirmed) != nil || verifyChildEnvelope(confirmed, p.config.KeyID, public) != nil {
		return false, ErrUntrusted
	}
	acceptance := childFields(childFields(confirmed)["payload"])
	acceptedAt, err := time.Parse(time.RFC3339Nano, childString(acceptance, "acceptedAt"))
	if err != nil || acceptedAt.After(time.Now()) {
		return false, ErrUntrusted
	}
	request, requestAgain, err := p.currentWindowRequestFieldsAt(ctx, current, acceptedAt)
	if err != nil || !bytes.Equal(requestRaw, requestAgain) {
		return false, ErrUntrusted
	}
	d, err := store.PaidDomain(ctx, digest)
	if err != nil || !bytes.Equal(original, d.AdoptionEnvelope) || Digest(original) != d.AdoptionEnvelopeDigest || workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAdoptionEnvelope", original) != nil || verifyChildEnvelope(original, p.config.KeyID, public) != nil {
		return false, ErrUntrusted
	}
	a := childFields(childFields(original)["payload"])
	if childString(a, "domainKind") != "paid_full26" || childString(a, "demandManifestDigest") != digest || childString(a, "caseManifestDigest") != childString(c, "caseManifestDigest") || childString(a, "caseId") != childString(c, "caseId") || childString(acceptance, "adoptionEnvelopeDigest") != d.AdoptionEnvelopeDigest || childString(acceptance, "runtimeReadbackEnvelopeDigest") != d.RuntimeReadbackEnvelopeDigest {
		return false, ErrUntrusted
	}
	operator, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil || bytes.Equal(operator, public) || Digest(operator) != childString(c, "operatorKeySHA256") {
		return false, ErrUntrusted
	}
	authorityCore, err := p.currentWindowLeaf("current-window-authority-core.json")
	if err != nil || workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "authorityCore", authorityCore) != nil {
		return false, ErrUntrusted
	}
	ac := childFields(authorityCore)
	op := childFields(ac["operator"])
	pp := childFields(ac["producer"])
	if childString(op, "keySHA256") != Digest(operator)[7:] || childString(op, "keyId") == p.config.KeyID || childString(pp, "keyId") != p.config.KeyID || childString(pp, "keySHA256") != Digest(public)[7:] || childString(pp, "nodeTokenHash") != p.config.NodeTokenHash || childString(ac, "evidenceRoot") != p.config.EvidenceRoot || !sameProduct(ac["case"], core["case"]) || !sameProduct(ac["tupleInventory"], core["tupleInventory"]) || !sameProduct(ac["validationWindow"], request["validationWindow"]) {
		return false, ErrUntrusted
	}
	selection, err := p.currentWindowLeaf("selected-manifest26.json")
	if err != nil || workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "selectedManifest26Envelope", selection) != nil || verifyChildEnvelope(selection, childString(op, "keyId"), operator) != nil || Digest(selection) != childString(a, "selectionEnvelopeDigest") {
		return false, ErrUntrusted
	}
	selected := childFields(childFields(selection)["payload"])
	for name, value := range core {
		if !sameProduct(value, selected[name]) {
			return false, ErrUntrusted
		}
	}
	inventoryRaw, err := p.currentWindowLeaf("complete-execution-inventory.json")
	if err != nil || workflowcontract.Validate(workflowcontract.CompleteExecutionInventory, "completeExecutionInventoryEnvelope", inventoryRaw) != nil || verifyChildEnvelope(inventoryRaw, childString(op, "keyId"), operator) != nil || Digest(inventoryRaw) != childString(a, "completeInventoryEnvelopeDigest") {
		return false, ErrUntrusted
	}
	inventory := childFields(childFields(inventoryRaw)["payload"])
	for _, name := range []string{"attemptId", "scope", "validationWindow", "candidateInventoryDigest", "openingReceiptDigest", "producerReconciliationEnvelopeDigest"} {
		if !sameProduct(a[name], inventory[name]) {
			return false, ErrUntrusted
		}
	}
	for _, name := range []string{"scope", "validationWindow", "candidateInventoryDigest", "openingReceiptDigest"} {
		if !sameProduct(inventory[name], request[name]) {
			return false, ErrUntrusted
		}
	}
	if childString(inventory, "paidSelectionEnvelopeDigest") != Digest(selection) || mustChildTime(childString(inventory, "issuedAt")).After(acceptedAt) || !acceptedAt.Before(mustChildTime(childString(inventory, "expiresAt"))) {
		return false, ErrUntrusted
	}
	authorityRaw, err := p.currentWindowLeaf("physical-gate-authority.json")
	if err != nil || workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "authority2", authorityRaw) != nil || Digest(authorityRaw) != childString(a, "authorityDigest") {
		return false, ErrUntrusted
	}
	authority := childFields(authorityRaw)
	for name, value := range ac {
		if !sameProduct(value, authority[name]) {
			return false, ErrUntrusted
		}
	}
	if !sameProduct(authority["ledgerReconciliation"], selected["liveLedger"]) {
		return false, ErrUntrusted
	}
	var realCase RealCase
	var demand ChildEnvelope[DemandManifest]
	if decodeClosed(core["case"], &realCase) != nil || decode(core["demand"], &demand) != nil || verifyChildEnvelope(core["demand"], childString(op, "keyId"), operator) != nil || demand.Payload.validate(realCase, acceptedAt) != nil || demand.Payload.CandidateInventoryDigest != childString(request, "candidateInventoryDigest") || Digest(core["demand"]) != childString(a, "demandEnvelopeDigest") {
		return false, ErrUntrusted
	}
	for _, name := range []string{"demand-manifest.json", "physical-gate-demand-envelope.json"} {
		raw, e := p.currentWindowLeaf(name)
		if e != nil || !bytes.Equal(raw, core["demand"]) {
			return false, ErrUntrusted
		}
	}
	ids := []string{}
	allocations := []state.PaidAllocation{}
	for _, allocation := range demand.Payload.all() {
		ids = append(ids, allocation.AllocationID)
		allocations = append(allocations, state.PaidAllocation{AllocationID: allocation.AllocationID, FirstPhysicalIndex: allocation.FirstPhysicalIndex, LastPhysicalIndex: allocation.LastPhysicalIndex, PreparationOrdinal: allocation.PreparationOrdinal, ModelRequests: allocation.ModelRequests})
	}
	if !sameProduct(a["selectedAllocationIds"], ids) || !sameProduct(d.Allocations, allocations) || d.Case.TaskID != childString(childFields(request["scope"]), "taskId") || d.Case.ServerID != current.ServerID || d.Case.CaseDigest != realCase.CaseManifestDigest || d.Case.Requests != realCase.Requests || d.Case.ModelRequests != realCase.ModelRequests || d.Case.AccessRequests != realCase.AccessRequests || d.Case.Preparations != realCase.Preparations || d.Case.UsdMicros != realCase.USDMicros || !sameProduct(a["bases"], d.Bases) || !sameProduct(d.Bases, d.Opening.Cumulative) {
		return false, ErrUntrusted
	}
	readback, err := p.paidOriginal(d.RuntimeReadbackEnvelopeDigest)
	if err != nil || workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidLedgerReadbackEnvelope", readback) != nil || verifyChildEnvelope(readback, p.config.KeyID, public) != nil || childString(a, "runtimeReadbackEnvelopeDigest") != d.RuntimeReadbackEnvelopeDigest {
		return false, ErrUntrusted
	}
	r := childFields(childFields(readback)["payload"])
	if childString(r, "taskId") != d.Case.TaskID || childString(r, "serverId") != current.ServerID || childString(r, "baselineDigest") != d.Case.BaselineDigest || !sameProduct(r["validationWindow"], request["validationWindow"]) || !sameProduct(r["candidateInventoryDigest"], request["candidateInventoryDigest"]) || string(r["owner"]) != "null" || !sameProduct(r["cumulative"], d.Opening.Cumulative) || !sameProduct(r["paidHistory"], d.Opening.PaidHistory) || childString(r, "paidHistoryDigest") != CanonicalDigest(d.Opening.PaidHistory) || childString(r, "offlineHistoryDigest") != d.Opening.OfflineHistoryDigest {
		return false, ErrUntrusted
	}
	retainedAt := mustChildTime(childString(a, "retainedAt"))
	observed := mustChildTime(childString(r, "observedAt"))
	expiry := mustChildTime(childString(r, "expiresAt"))
	if retainedAt.Before(observed) || acceptedAt.Before(retainedAt) || !acceptedAt.Before(expiry) || expiry.Sub(observed) > 120*time.Second {
		return false, ErrUntrusted
	}
	// The registered producer's FIRST D1 signature and claim bind the exact
	// preselection request/snapshot/CORE. Verify at original acceptance time,
	// never reinterpret natural paid drift or elapsed freshness as a new cut.
	firstDigest := childString(inventory, "producerReconciliationEnvelopeDigest")
	first, err := p.paidOriginal(firstDigest)
	if err != nil || workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "currentWindowReconciliationEnvelope", first) != nil || verifyChildEnvelope(first, p.config.KeyID, public) != nil {
		return false, ErrUntrusted
	}
	f := childFields(childFields(first)["payload"])
	if childString(f, "selectionDigest") != Digest(coreRaw) || !sameProduct(f["validationWindow"], request["validationWindow"]) || !sameProduct(f["candidateInventoryDigest"], request["candidateInventoryDigest"]) || !sameProduct(f["openingReceiptDigest"], request["openingReceiptDigest"]) || !acceptedAt.Before(mustChildTime(childString(f, "notAfter"))) {
		return false, ErrUntrusted
	}
	liveLedger := childFields(selected["liveLedger"])
	if childString(liveLedger, "receiptDigest") != firstDigest {
		return false, ErrUntrusted
	}
	delete(liveLedger, "receiptDigest")
	if !sameProduct(liveLedger, f["ledger"]) {
		return false, ErrUntrusted
	}
	firstAlias, err := p.currentWindowLeaf("current-window-core-observation-" + Digest(coreRaw)[7:] + ".json")
	if err != nil || !bytes.Equal(firstAlias, first) {
		return false, ErrUntrusted
	}
	snapshotRaw, err := p.currentWindowLeaf(currentWindowSnapshot)
	if err != nil || workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "backendSnapshotEnvelope", snapshotRaw) != nil || verifyChildEnvelope(snapshotRaw, p.config.KeyID, public) != nil {
		return false, ErrUntrusted
	}
	snapshot := childFields(childFields(snapshotRaw)["payload"])
	for _, name := range []string{"scope", "nodeTokenHash", "candidateInventoryDigest", "validationWindow", "prospectiveProjectionDigest", "openingReceiptDigest", "openingBackendCutDigest", "physicalCutDigest", "continuationReceiptDigests"} {
		if !sameProduct(snapshot[name], request[name]) {
			return false, ErrUntrusted
		}
	}
	if !sameProduct(snapshot["windowLedger"], f["ledger"]) || !acceptedAt.Before(mustChildTime(childString(snapshot, "expiresAt"))) || acceptedAt.Before(mustChildTime(childString(snapshot, "observedAt"))) {
		return false, ErrUntrusted
	}
	claim, err := p.currentWindowLeaf("current-window-core-observation-" + Digest(coreRaw)[7:] + ".claim.json")
	wantClaim := canonicalBytes(map[string]any{"purpose": "current_validation_window_reconciliation", "selectionDigest": Digest(coreRaw), "snapshotEnvelopeDigest": Digest(snapshotRaw), "requestDigest": Digest(requestRaw), "payloadDigest": Digest(childFields(first)["payload"])})
	if err != nil || !bytes.Equal(claim, wantClaim) {
		return false, ErrUntrusted
	}
	// Completion retains all shared original joins, but evaluates their finite
	// validity at FIRST acceptance rather than refreshing their history NOW.
	d0Raw, err := p.paidOriginal(childString(request, "prospectiveProjectionDigest"))
	if err != nil {
		return false, ErrUntrusted
	}
	d0, err := currentWindowFields(d0Raw, "scope", "authorityCore", "ownerRequestDigest", "demand", "selectionPins", "localCase", "completeInventoryPlan", "prospectiveInventory", "validationWindow")
	if err != nil || workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "scope", d0["scope"]) != nil || !sameProduct(childFields(d0["scope"])["owner"], request["scope"]) || !sameProduct(d0["authorityCore"], json.RawMessage(authorityCore)) || !sameProduct(d0["demand"], childFields(core["demand"])["payload"]) || !sameProduct(d0["validationWindow"], request["validationWindow"]) {
		return false, ErrUntrusted
	}
	for _, name := range []string{"installedReadinessDigest", "responsesPermissionDigest"} {
		if !sameProduct(childFields(d0["selectionPins"])[name], core[name]) {
			return false, ErrUntrusted
		}
	}
	physical, err := p.paidOriginal(childString(request, "physicalCutDigest"))
	if err != nil || workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "physicalCut", physical) != nil {
		return false, ErrUntrusted
	}
	namespace, err := p.paidOriginal(childString(request, "openingBackendCutDigest"))
	if err != nil || workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "namespaceAssociation", namespace) != nil {
		return false, ErrUntrusted
	}
	for _, raw := range [][]byte{physical, namespace} {
		fields := childFields(raw)
		for _, name := range []string{"scope", "nodeTokenHash", "candidateInventoryDigest", "validationWindow"} {
			if !sameProduct(fields[name], request[name]) {
				return false, ErrUntrusted
			}
		}
		if mustChildTime(childString(fields, "observedAt")).After(acceptedAt) || !acceptedAt.Before(mustChildTime(childString(fields, "expiresAt"))) {
			return false, ErrUntrusted
		}
	}
	refs := []string{childString(request, "openingReceiptDigest"), Digest(snapshotRaw), childString(request, "physicalCutDigest")}
	var requestRefs, firstRefs []string
	if decode(request["continuationReceiptDigests"], &requestRefs) != nil || decode(f["continuationReceiptDigests"], &firstRefs) != nil {
		return false, ErrUntrusted
	}
	refs = append(refs, requestRefs...)
	for _, ref := range refs {
		raw, e := p.currentWindowLeaf(ref[7:])
		if e != nil || Digest(raw) != ref {
			return false, ErrUntrusted
		}
		if ref != childString(request, "openingReceiptDigest") {
			found := false
			for _, firstRef := range firstRefs {
				found = found || firstRef == ref
			}
			if !found {
				return false, ErrUntrusted
			}
		}
	}
	for _, raw := range [][]byte{selection, inventoryRaw, authorityRaw, snapshotRaw} {
		original, e := p.paidOriginal(Digest(raw))
		if e != nil || !bytes.Equal(original, raw) {
			return false, ErrUntrusted
		}
	}
	return true, nil
}

// The public wire is the frozen F1 projection, not the internal SQLite cut. Its
// time bounds come from the protected request for this finite observation; its
// counters, original references and pending full hold come ONLY from the owner.
func (p *Producer) currentWindowPhysicalProjection(request map[string]json.RawMessage, cut state.PaidLedgerCut) ([]byte, error) {
	pending := []any{}
	var pendingID any
	var journal any
	if cut.Owner != nil {
		raw, ok := cut.Originals[cut.Owner.OperationDigest]
		var o state.PhysicalOperation
		if !ok || model.DecodePhysicalClosed(raw, &o) != nil || o.OperationID != cut.Owner.OperationID || o.Phase != "unknown" || o.Settlement != nil || o.Permit.Offline != nil || o.ReservedUsdMicros != RequestMicros {
			return nil, ErrUntrusted
		}
		// The original authority names the existing owning budget journal. This
		// is a locator, NOT an assertion that a backend row exists: F1 must join
		// the actual committed full-hold original before signing its snapshot.
		authorityRaw, err := p.currentWindowLeaf(o.Permit.Request.AuthorityDigest[7:])
		if err == nil {
			if Digest(authorityRaw) != o.Permit.Request.AuthorityDigest || (workflowcontract.Validate(workflowcontract.Budget, "authority2", authorityRaw) != nil && workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "authority2", authorityRaw) != nil) {
				return nil, ErrUntrusted
			}
			var c RealCase
			if decodeClosed(childFields(authorityRaw)["case"], &c) != nil || c.CaseManifestDigest != o.Permit.Case.CaseDigest || (o.Permit.PaidDomain != "" && o.Permit.PaidDomain != c.DemandManifestDigest) {
				return nil, ErrUntrusted
			}
			journal = financialJournalID("typed-budget-allocation", c.DemandManifestDigest+":"+o.Permit.AllocationID)
		} else if !errors.Is(err, ErrCurrentWindowObservationPending) {
			return nil, err
		}
		pendingID = o.OperationID
		pending = append(pending, map[string]any{"originDigest": cut.Owner.OperationDigest, "allocationJournalId": nil, "retainedUsdMicros": o.ReservedUsdMicros, "classification": "bounded_unbooked_unknown"})
	}
	projection := map[string]any{"formatVersion": 1, "purpose": "current_validation_window_physical_cut", "scope": request["scope"], "nodeTokenHash": request["nodeTokenHash"], "candidateInventoryDigest": request["candidateInventoryDigest"], "validationWindow": request["validationWindow"], "cumulative": cut.Cumulative, "paidHistory": cut.PaidHistory, "offlineHistoryDigest": cut.OfflineHistoryDigest, "pendingOperationId": pendingID, "pendingOrigins": pending, "observedAt": request["approvedAt"], "expiresAt": request["expiresAt"]}
	raw := canonicalBytes(projection)
	// Booking membership is F1-owned. The protected request commits one of the
	// two FIXED classifications of the exact owning UNKNOWN, never arbitrary
	// caller money. Both must still be confirmed by the registered backend and
	// verified against original committed journals before Runtime D1 emission.
	if Digest(raw) != childString(request, "physicalCutDigest") && journal != nil {
		origin := pending[0].(map[string]any)
		origin["allocationJournalId"], origin["classification"] = journal, "retained_full_hold"
		raw = canonicalBytes(projection)
	}
	if workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "physicalCut", raw) != nil {
		return nil, ErrUntrusted
	}
	return raw, nil
}

// BEFORE any CurrentPhysicalBaseline/FINAL/inventory/adoption read. The caller
// supplies no physical projection. Retain exact original bytes at existing digest
// addresses; this publication cannot book/release cash or clear the physical owner.
func (p *Producer) PublishCurrentWindowPhysicalCut(ctx context.Context, current model.Manifest, store *state.Store) error {
	f, request, err := p.currentWindowRequestFields(ctx, current)
	if err != nil {
		return err
	}
	if store == nil {
		return ErrUntrusted
	}
	cut, err := store.PhysicalLedgerCut(ctx)
	if err != nil || cut.Anchor.ServerID != current.ServerID || cut.Anchor.TaskID != childString(childFields(f["scope"]), "taskId") || len(cut.PaidHistory) > 128 || len(cut.Originals) > 128 {
		return ErrUntrusted
	}
	raw, err := p.currentWindowPhysicalProjection(f, cut)
	if err != nil || Digest(raw) != childString(f, "physicalCutDigest") {
		return ErrUntrusted
	}
	if err = p.append(cut.OfflineHistoryDigest[7:], canonicalBytes(cut.OfflineHistory)); err != nil {
		return err
	}
	for d, original := range cut.Originals {
		if !hash.MatchString(d) || Digest(original) != d || len(original) > 65536 {
			return ErrUntrusted
		}
		if err = p.append(d[7:], original); err != nil {
			return err
		}
	}
	if err = p.append(Digest(raw)[7:], raw); err != nil {
		return err
	}
	again, err := store.PhysicalLedgerCut(ctx)
	requestAgain, e := p.currentWindowLeaf(currentWindowRequest)
	if err != nil || e != nil || !bytes.Equal(canonicalBytes(cut), canonicalBytes(again)) || !bytes.Equal(request, requestAgain) || ctx.Err() != nil {
		return ErrUntrusted
	}
	return nil
}

// Normal private caller only. Backend snapshot is independently registered and
// signed; execution-operator/config numbers never enter this operation.
func (p *Producer) ObserveCurrentWindowReconciliation(ctx context.Context, current model.Manifest, store *state.Store) (json.RawMessage, error) {
	request, requestRaw, err := p.currentWindowRequestFields(ctx, current)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, ErrUntrusted
	}
	// The early publication is a required independently owned FIRST operation.
	cut, err := store.PhysicalLedgerCut(ctx)
	if err != nil {
		return nil, ErrUntrusted
	}
	projection, err := p.currentWindowPhysicalProjection(request, cut)
	if err != nil || Digest(projection) != childString(request, "physicalCutDigest") {
		return nil, ErrUntrusted
	}
	tracked := map[string][]byte{currentWindowRequest: requestRaw}
	read := func(name string) ([]byte, error) {
		raw, e := p.currentWindowLeaf(name)
		if e == nil {
			tracked[name] = raw
		}
		return raw, e
	}
	get := func(d string, maximum int) ([]byte, error) {
		if !hash.MatchString(d) || maximum > 65536 {
			return nil, ErrUntrusted
		}
		raw, e := read(d[7:])
		if e != nil || len(raw) > maximum || Digest(raw) != d {
			return nil, ErrUntrusted
		}
		return raw, nil
	}
	physical, err := get(childString(request, "physicalCutDigest"), 65536)
	if err != nil || !bytes.Equal(physical, projection) {
		return nil, ErrUntrusted
	}
	snapshotRaw, err := read(currentWindowSnapshot)
	if err != nil {
		return nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	if err != nil {
		return nil, err
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "backendSnapshotEnvelope", snapshotRaw) != nil || verifyChildEnvelope(snapshotRaw, p.config.KeyID, public) != nil {
		return nil, ErrUntrusted
	}
	envelope, err := currentWindowFields(snapshotRaw, "payload", "keyId", "signature")
	if err != nil {
		return nil, err
	}
	snapshot, err := currentWindowFields(envelope["payload"], "formatVersion", "purpose", "validationWindow", "scope", "nodeTokenHash", "candidateInventoryDigest", "prospectiveProjectionDigest", "backendVector", "windowLedger", "openingReceiptDigest", "openingBackendCutDigest", "physicalCutDigest", "continuationReceiptDigests", "allocationOrigins", "localHoldOrigins", "importOrigins", "pendingOrigins", "observedAt", "expiresAt")
	if err != nil || string(snapshot["formatVersion"]) != "1" || childString(snapshot, "purpose") != "current_validation_window_backend_snapshot" {
		return nil, ErrUntrusted
	}
	for _, name := range []string{"validationWindow", "scope", "nodeTokenHash", "candidateInventoryDigest", "prospectiveProjectionDigest", "openingReceiptDigest", "openingBackendCutDigest", "physicalCutDigest", "continuationReceiptDigests"} {
		if !sameProduct(snapshot[name], request[name]) {
			return nil, ErrUntrusted
		}
	}
	now := time.Now().UTC()
	observed, oe := time.Parse(time.RFC3339Nano, childString(snapshot, "observedAt"))
	expires, ee := time.Parse(time.RFC3339Nano, childString(snapshot, "expiresAt"))
	if oe != nil || ee != nil || observed.After(now) || now.Sub(observed) > 120*time.Second || !now.Before(expires) || !observed.Before(expires) || expires.Sub(observed) > 120*time.Second || observed.Before(mustChildTime(childString(childFields(request["validationWindow"]), "openedAt"))) {
		return nil, ErrUntrusted
	}
	if reqExpiry := mustChildTime(childString(request, "expiresAt")); reqExpiry.Before(expires) {
		expires = reqExpiry
	}
	// Both genuine opening/no-live provenance and the honestly timed NOW
	// namespace association are immutable public originals, not a past DB cut.
	if _, err = get(childString(snapshot, "openingReceiptDigest"), 65536); err != nil {
		return nil, err
	}
	if _, err = get(childString(snapshot, "openingBackendCutDigest"), 65536); err != nil {
		return nil, err
	}
	var continuations []string
	if decode(snapshot["continuationReceiptDigests"], &continuations) != nil {
		return nil, ErrUntrusted
	}
	for _, d := range continuations {
		if _, err = get(d, 65536); err != nil {
			return nil, err
		}
	}
	ledger, err := p.verifyCurrentWindowSnapshotOrigins(snapshot, request, cut, public, now, get)
	if err != nil {
		return nil, fmt.Errorf("verify current-window backend snapshot origins: %w", err)
	}
	coreRaw, err := read("selected-manifest26-core.json")
	if err != nil {
		return nil, err
	}
	core, err := currentWindowFields(coreRaw, "formatVersion", "selection", "case", "demand", "tupleInventory", "installedReadinessDigest", "responsesPermissionDigest")
	if err != nil || string(core["formatVersion"]) != "1" || childString(core, "selection") != "two_sandbox_exact_two_tuple_full26" {
		return nil, ErrUntrusted
	}
	operator, err := read("physical-gate-operator.pem")
	if err != nil || bytes.Equal(operator, public) {
		return nil, ErrUntrusted
	}
	authorityRaw, err := read("current-window-authority-core.json")
	if err != nil {
		return nil, err
	}
	authority, err := currentWindowFields(authorityRaw, "formatVersion", "caseId", "caseManifestDigest", "usdLimitMicros", "requestLimit", "turnLimit", "backend", "native", "runtime", "sandbox", "profileBundleDigest", "pricing", "operator", "producer", "evidenceRoot", "case", "evidenceClass", "tupleInventory", "validationWindow")
	if err != nil || childString(authority, "evidenceClass") != "live" || childString(authority, "evidenceRoot") != p.config.EvidenceRoot || !sameProduct(authority["case"], core["case"]) || !sameProduct(authority["tupleInventory"], core["tupleInventory"]) || !sameProduct(authority["validationWindow"], request["validationWindow"]) {
		return nil, ErrUntrusted
	}
	candidate := map[string]json.RawMessage{}
	for _, name := range []string{"backend", "native", "runtime", "sandbox", "profileBundleDigest"} {
		candidate[name] = authority[name]
	}
	if CanonicalDigest(candidate) != childString(request, "candidateInventoryDigest") {
		return nil, ErrUntrusted
	}
	producerPin := childFields(authority["producer"])
	operatorPin := childFields(authority["operator"])
	if childString(producerPin, "keyId") != p.config.KeyID || childString(producerPin, "keySHA256") != Digest(public)[7:] || childString(producerPin, "nodeTokenHash") != p.config.NodeTokenHash || childString(operatorPin, "keySHA256") != Digest(operator)[7:] || childString(operatorPin, "keyId") == p.config.KeyID {
		return nil, ErrUntrusted
	}
	var c RealCase
	var demand ChildEnvelope[DemandManifest]
	if workflowcontract.Validate(workflowcontract.Budget, "selectedCase26", core["case"]) != nil || workflowcontract.Validate(workflowcontract.Budget, "tupleInventory", core["tupleInventory"]) != nil || decodeClosed(core["case"], &c) != nil || verifyChildEnvelope(core["demand"], childString(operatorPin, "keyId"), operator) != nil || decode(core["demand"], &demand) != nil || demand.Payload.validate(c, now) != nil || demand.Payload.CandidateInventoryDigest != childString(request, "candidateInventoryDigest") || c.OperatorKeySHA256 != Digest(operator) {
		return nil, ErrUntrusted
	}
	for _, name := range []string{"demand-manifest.json", "physical-gate-demand-envelope.json"} {
		original, e := read(name)
		if e != nil || !bytes.Equal(original, core["demand"]) {
			return nil, ErrUntrusted
		}
	}
	d0Raw, err := get(childString(request, "prospectiveProjectionDigest"), 65536)
	if err != nil {
		return nil, err
	}
	d0, err := currentWindowFields(d0Raw, "scope", "authorityCore", "ownerRequestDigest", "demand", "selectionPins", "localCase", "completeInventoryPlan", "prospectiveInventory", "validationWindow")
	if err != nil || workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, "scope", d0["scope"]) != nil || !sameProduct(childFields(d0["scope"])["owner"], request["scope"]) || childString(childFields(d0["scope"]), "nodeTokenHash") != p.config.NodeTokenHash || childString(childFields(d0["scope"]), "candidateInventoryDigest") != childString(request, "candidateInventoryDigest") || childString(childFields(d0["scope"]), "caseId") != c.CaseID || !sameProduct(d0["authorityCore"], json.RawMessage(authorityRaw)) || !sameProduct(d0["demand"], childFields(core["demand"])["payload"]) || !sameProduct(d0["validationWindow"], request["validationWindow"]) {
		return nil, ErrUntrusted
	}
	for _, name := range []string{"authorityCore", "selectionPins", "completeInventoryPlan", "prospectiveInventory"} {
		if workflowcontract.Validate(workflowcontract.ExecutionOperatorFinancial, name, d0[name]) != nil {
			return nil, ErrUntrusted
		}
	}
	if workflowcontract.Validate(workflowcontract.SourceLocalTransport, "localCase3", d0["localCase"]) != nil {
		return nil, ErrUntrusted
	}
	pins, err := currentWindowFields(d0["selectionPins"], "installedReadinessDigest", "responsesPermissionDigest")
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"installedReadinessDigest", "responsesPermissionDigest"} {
		if !sameProduct(pins[name], core[name]) {
			return nil, ErrUntrusted
		}
	}
	if bound := mustChildTime(demand.Payload.NotAfter); bound.Before(expires) {
		expires = bound
	}
	if !now.Before(expires) {
		return nil, ErrUntrusted
	}
	// Every money term is bounded before addition. Observation never reserves it.
	remaining := int64(30000000) - c.USDMicros
	for _, name := range []string{"actualUsdMicros", "reservedUsdMicros", "unknownUsdMicros"} {
		var value int64
		if decode(ledger[name], &value) != nil || value < 0 || value > remaining {
			return nil, ErrUntrusted
		}
		remaining -= value
	}
	if _, err = get(Digest(snapshotRaw), 65536); err != nil {
		return nil, err
	}
	for _, d := range []string{Digest(snapshotRaw), childString(request, "physicalCutDigest")} {
		found := false
		for _, old := range continuations {
			found = found || old == d
		}
		if !found {
			continuations = append(continuations, d)
		}
	}
	payload := canonicalBytes(map[string]any{"formatVersion": 1, "purpose": "current_validation_window_reconciliation", "validationWindow": request["validationWindow"], "candidateInventoryDigest": childString(request, "candidateInventoryDigest"), "selectionDigest": Digest(coreRaw), "ledger": ledger, "openingReceiptDigest": childString(snapshot, "openingReceiptDigest"), "continuationReceiptDigests": continuations, "notAfter": expires.Format(time.RFC3339Nano)})
	if workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "currentWindowReconciliation", payload) != nil {
		return nil, ErrUntrusted
	}
	stable := func() bool {
		again, e := store.PhysicalLedgerCut(ctx)
		if e != nil || !bytes.Equal(canonicalBytes(again), canonicalBytes(cut)) || ctx.Err() != nil {
			return false
		}
		for name, raw := range tracked {
			again, e := p.currentWindowLeaf(name)
			if e != nil || !bytes.Equal(raw, again) {
				return false
			}
		}
		return true
	}
	if !stable() {
		return nil, ErrUntrusted
	}
	name := "current-window-core-observation-" + Digest(coreRaw)[7:]
	claim := canonicalBytes(map[string]any{"purpose": "current_validation_window_reconciliation", "selectionDigest": Digest(coreRaw), "snapshotEnvelopeDigest": Digest(snapshotRaw), "requestDigest": Digest(requestRaw), "payloadDigest": Digest(payload)})
	old, oldErr := p.currentWindowLeaf(name + ".json")
	if oldErr == nil {
		oldClaim, e := p.currentWindowLeaf(name + ".claim.json")
		if e != nil || !bytes.Equal(oldClaim, claim) || verifyChildEnvelope(old, p.config.KeyID, public) != nil || !bytes.Equal(childFields(old)["payload"], payload) || !stable() {
			return nil, ErrUntrusted
		}
		return append(json.RawMessage(nil), old...), nil
	}
	if !errors.Is(oldErr, ErrCurrentWindowObservationPending) {
		return nil, oldErr
	}
	if err = p.create(name+".claim.json", claim); errors.Is(err, syscall.EEXIST) {
		return nil, ErrCurrentWindowObservationUnknown
	} else if err != nil {
		return nil, err
	}
	// Nothing reconstructs an incomplete FIRST signature/append transaction.
	if !stable() {
		return nil, ErrCurrentWindowObservationUnknown
	}
	sum := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if err != nil {
		return nil, err
	}
	result := canonicalBytes(map[string]any{"payload": json.RawMessage(payload), "keyId": p.config.KeyID, "signature": base64.StdEncoding.EncodeToString(sig)})
	if workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "currentWindowReconciliationEnvelope", result) != nil {
		return nil, ErrCurrentWindowObservationUnknown
	}
	if err = p.append(Digest(result)[7:], result); err != nil {
		return nil, err
	}
	if err = p.append(name+".json", result); err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), result...), nil
}
