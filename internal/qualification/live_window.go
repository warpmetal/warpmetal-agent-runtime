package qualification

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// A read-only join of F1's exact additive contract. The protected owning config
// and independent registered producer are inputs; an installed consumer hash is
// NEVER a selector. No reservation/history change, success cache or issuance.
func verifyLiveWindowAuthority(ctx context.Context, c RealCase, trusted ProducerConfig, operatorPEM, producerPEM []byte, load func(string, int) ([]byte, error), now time.Time) ([]byte, []byte, error) {
	if ctx.Err() != nil || load == nil || trusted.KeySHA256 != Digest(producerPEM) || Digest(operatorPEM) != c.OperatorKeySHA256 || bytes.Equal(operatorPEM, producerPEM) {
		return nil, nil, ErrUntrusted
	}
	originals := map[string][]byte{}
	read := func(name string) ([]byte, error) {
		raw, err := load(name, 65536)
		if err != nil || len(raw) == 0 || len(raw) > 65536 {
			return nil, ErrUntrusted
		}
		originals[name] = append([]byte(nil), raw...)
		return raw, nil
	}
	authority, err := read("physical-gate-authority.json")
	if err != nil || workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "authority2", authority) != nil {
		return nil, nil, ErrUntrusted
	}
	f := childFields(authority)
	operator, producer := childFields(f["operator"]), childFields(f["producer"])
	if !sameProduct(f["case"], c) || childString(f, "caseId") != c.CaseID || childString(f, "caseManifestDigest") != c.CaseManifestDigest || CanonicalDigest(f["tupleInventory"]) != c.TupleInventoryDigest || CanonicalDigest(f["pricing"]) != c.PricingDigest ||
		childString(operator, "keySHA256") != strings.TrimPrefix(Digest(operatorPEM), "sha256:") || childString(producer, "keySHA256") != strings.TrimPrefix(trusted.KeySHA256, "sha256:") || childString(producer, "keyId") != trusted.KeyID || childString(producer, "nodeTokenHash") != trusted.NodeTokenHash {
		return nil, nil, ErrUntrusted
	}
	for name, limit := range map[string]any{"requestLimit": c.PhysicalCeiling, "turnLimit": c.ModelRequests, "usdLimitMicros": c.USDCeilingMicros} {
		if !sameProduct(f[name], limit) {
			return nil, nil, ErrUntrusted
		}
	}
	selectedRaw, err := read("selected-manifest26.json")
	if err != nil || workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "selectedManifest26Envelope", selectedRaw) != nil || verifyChildEnvelope(selectedRaw, childString(operator, "keyId"), operatorPEM) != nil {
		return nil, nil, ErrUntrusted
	}
	selected := childFields(childFields(selectedRaw)["payload"])
	if !sameProduct(selected["case"], f["case"]) || !sameProduct(selected["tupleInventory"], f["tupleInventory"]) || !sameProduct(selected["liveLedger"], f["ledgerReconciliation"]) {
		return nil, nil, ErrUntrusted
	}
	demandRaw, err := read("demand-manifest.json")
	var demand ChildEnvelope[DemandManifest]
	if err != nil || workflowcontract.Validate(workflowcontract.Budget, "demandManifestEnvelope", demandRaw) != nil || verifyChildEnvelope(demandRaw, childString(operator, "keyId"), operatorPEM) != nil || decode(demandRaw, &demand) != nil || demand.Payload.validate(c, now) != nil || !sameProduct(json.RawMessage(demandRaw), selected["demand"]) {
		return nil, nil, ErrUntrusted
	}
	// Both existing owning callers consume this original alias. A fresh valid
	// signature over equivalent fields is not the retained FIRST envelope.
	alias, err := read("physical-gate-demand-envelope.json")
	if err != nil || !sameProduct(json.RawMessage(alias), json.RawMessage(demandRaw)) {
		return nil, nil, ErrUntrusted
	}
	candidate := map[string]json.RawMessage{}
	for _, name := range []string{"backend", "native", "runtime", "sandbox", "profileBundleDigest"} {
		candidate[name] = f[name]
	}
	candidateDigest := CanonicalDigest(candidate)
	if demand.Payload.CandidateInventoryDigest != candidateDigest || childString(childFields(f["tupleInventory"]), "candidateInventoryDigest") != candidateDigest {
		return nil, nil, ErrUntrusted
	}
	ledger := childFields(f["ledgerReconciliation"])
	readDigest := func(d string) ([]byte, error) {
		if !hash.MatchString(d) {
			return nil, ErrUntrusted
		}
		raw, err := read(d[7:])
		if err != nil || Digest(raw) != d {
			return nil, ErrUntrusted
		}
		return raw, nil
	}
	receiptRaw, err := readDigest(childString(ledger, "receiptDigest"))
	if err != nil || workflowcontract.Validate(workflowcontract.BudgetLiveWindow, "currentWindowReconciliationEnvelope", receiptRaw) != nil || verifyChildEnvelope(receiptRaw, trusted.KeyID, producerPEM) != nil {
		return nil, nil, ErrUntrusted
	}
	receipt := childFields(childFields(receiptRaw)["payload"])
	delete(selected, "liveLedger")
	delete(ledger, "receiptDigest")
	if !sameProduct(receipt["validationWindow"], f["validationWindow"]) || childString(receipt, "candidateInventoryDigest") != candidateDigest || childString(receipt, "selectionDigest") != CanonicalDigest(selected) || !sameProduct(receipt["ledger"], ledger) || childString(ledger, "identityDigest") != CanonicalDigest(map[string]any{"ledgerId": childString(ledger, "ledgerId"), "validationWindow": f["validationWindow"]}) {
		return nil, nil, ErrUntrusted
	}
	opened, oe := time.Parse(time.RFC3339Nano, childString(childFields(f["validationWindow"]), "openedAt"))
	observed, ve := time.Parse(time.RFC3339Nano, childString(ledger, "observedAt"))
	expiry, ee := time.Parse(time.RFC3339Nano, childString(receipt, "notAfter"))
	demandExpiry, de := time.Parse(time.RFC3339Nano, demand.Payload.NotAfter)
	if oe != nil || ve != nil || ee != nil || de != nil || observed.Before(opened) || observed.After(now) || !now.Before(expiry) || expiry.After(demandExpiry) {
		return nil, nil, ErrUntrusted
	}
	if _, err = readDigest(childString(receipt, "openingReceiptDigest")); err != nil {
		return nil, nil, ErrUntrusted
	}
	var references []string
	if json.Unmarshal(receipt["continuationReceiptDigests"], &references) != nil {
		return nil, nil, ErrUntrusted
	}
	for _, d := range references {
		if _, err = readDigest(d); err != nil {
			return nil, nil, ErrUntrusted
		}
	}
	// Subtraction instead of addition prevents signed oversized counters from
	// overflowing into apparent headroom. Exact window constant comes from schema.
	var remaining int64
	if json.Unmarshal(childFields(f["validationWindow"])["totalUsdMicros"], &remaining) != nil || c.USDMicros > remaining {
		return nil, nil, ErrUntrusted
	}
	remaining -= c.USDMicros
	for _, name := range []string{"actualUsdMicros", "reservedUsdMicros", "unknownUsdMicros"} {
		var n int64
		if json.Unmarshal(ledger[name], &n) != nil || n < 0 || n > remaining {
			return nil, nil, ErrUntrusted
		}
		remaining -= n
	}
	for name, raw := range originals {
		again, err := load(name, 65536)
		if err != nil || !bytes.Equal(raw, again) || ctx.Err() != nil {
			return nil, nil, ErrUntrusted
		}
	}
	return authority, demandRaw, nil
}

// The existing protected operator pin and SAME registered host producer select
// the trust domains. A record/keyPath/consumer claim cannot supply a verifier key.
func (p *Producer) CurrentLiveWindowAuthority(ctx context.Context, c RealCase) ([]byte, []byte, error) {
	if p == nil || p.key == nil {
		return nil, nil, ErrUntrusted
	}
	operator, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil {
		return nil, nil, ErrUntrusted
	}
	der, err := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	if err != nil {
		return nil, nil, ErrUntrusted
	}
	producer := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return verifyLiveWindowAuthority(ctx, c, p.config, operator, producer, p.read, time.Now())
}
