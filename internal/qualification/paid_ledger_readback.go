package qualification

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Called privately by the owning Runtime, never by a native request. All scope
// selectors are read from existing protected originals. This observation cannot
// grant a paid slot, adopt a backend mapping, establish a hold or clear UNKNOWN.
func (p *Producer) ObservePaidLedgerReadback(ctx context.Context, current model.Manifest, store *state.Store) (json.RawMessage, error) {
	if p == nil || p.key == nil || store == nil || ctx.Err() != nil {
		return nil, ErrUntrusted
	}
	b, _, err := p.CurrentPhysicalBaseline(ctx, current)
	if err != nil {
		return nil, err
	}
	inventoryRaw, err := p.read("complete-execution-inventory.json", 65536)
	if err != nil || workflowcontract.Validate(workflowcontract.CompleteExecutionInventory, "completeExecutionInventoryEnvelope", inventoryRaw) != nil || !bytes.Equal(inventoryRaw, canonicalBytes(json.RawMessage(inventoryRaw))) {
		return nil, ErrUntrusted
	}
	operator, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil || Digest(operator) != b.Case.OperatorKeySHA256 {
		return nil, ErrUntrusted
	}
	fields := childFields(inventoryRaw)
	if verifyChildEnvelope(inventoryRaw, childString(fields, "keyId"), operator) != nil {
		return nil, ErrUntrusted
	}
	inventory := childFields(fields["payload"])
	scope := childFields(inventory["scope"])
	if childString(scope, "taskId") != b.TaskID || childString(scope, "serverId") != current.ServerID {
		return nil, ErrUntrusted
	}
	now := time.Now().UTC()
	issued, ie := time.Parse(time.RFC3339Nano, childString(inventory, "issuedAt"))
	expiry, ee := time.Parse(time.RFC3339Nano, childString(inventory, "expiresAt"))
	if ie != nil || ee != nil || issued.After(now) || !now.Before(expiry) {
		return nil, ErrUntrusted
	}
	demandRaw, err := p.read("physical-gate-demand-envelope.json", 65536)
	var demand ChildEnvelope[DemandManifest]
	if err != nil || workflowcontract.Validate(workflowcontract.Budget, "demandManifestEnvelope", demandRaw) != nil || decode(demandRaw, &demand) != nil || verifyChildEnvelope(demandRaw, childString(childFields(demandRaw), "keyId"), operator) != nil || demand.Payload.validate(b.Case, now) != nil || demand.Payload.CandidateInventoryDigest != childString(inventory, "candidateInventoryDigest") {
		return nil, ErrUntrusted
	}
	demandExpiry, e := time.Parse(time.RFC3339Nano, demand.Payload.NotAfter)
	if e != nil {
		return nil, ErrUntrusted
	}
	if demandExpiry.Before(expiry) {
		expiry = demandExpiry
	}
	if bound := now.Add(120 * time.Second); bound.Before(expiry) {
		expiry = bound
	}
	if !now.Before(expiry) {
		return nil, ErrUntrusted
	}
	cut, err := store.PhysicalLedgerCut(ctx)
	if err != nil || len(cut.PaidHistory) > 128 || cut.Anchor.TaskID != b.TaskID || cut.Anchor.ServerID != current.ServerID {
		return nil, ErrUntrusted
	}
	// Read/import archives independently. Preserve the ORIGINAL bytes; observing
	// an import digest in an operation is not proof that its original is present.
	for _, ref := range cut.PaidHistory {
		if ref.ImportedOriginalDigest != nil {
			original, e := p.read("physical-baseline-history-"+(*ref.ImportedOriginalDigest)[7:]+".json", 65536)
			if e != nil || Digest(original) != *ref.ImportedOriginalDigest {
				return nil, ErrUntrusted
			}
			if e = p.append((*ref.ImportedOriginalDigest)[7:], original); e != nil {
				return nil, e
			}
		}
	}
	for digest, original := range cut.Originals {
		if Digest(original) != digest || len(original) > 65536 {
			return nil, ErrUntrusted
		}
		if err = p.append(digest[7:], original); err != nil {
			return nil, err
		}
	}
	offlineBytes := canonicalBytes(cut.OfflineHistory)
	if Digest(offlineBytes) != cut.OfflineHistoryDigest {
		return nil, ErrUntrusted
	}
	if err = p.append(cut.OfflineHistoryDigest[7:], offlineBytes); err != nil {
		return nil, err
	}
	payload := map[string]any{"formatVersion": 1, "purpose": "paid_case_ledger_readback", "taskId": b.TaskID, "serverId": current.ServerID,
		"validationWindow": inventory["validationWindow"], "candidateInventoryDigest": childString(inventory, "candidateInventoryDigest"), "baselineDigest": cut.Anchor.BaselineDigest,
		"paidHistoryDigest": CanonicalDigest(cut.PaidHistory), "paidHistory": cut.PaidHistory, "offlineHistoryDigest": cut.OfflineHistoryDigest, "owner": cut.Owner, "cumulative": cut.Cumulative,
		"observedAt": now.Format(time.RFC3339Nano), "expiresAt": expiry.Format(time.RFC3339Nano)}
	if workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidLedgerReadback", canonicalBytes(payload)) != nil {
		return nil, ErrUntrusted
	}
	// Re-read protected scope aliases and SAME owning cut before observing/signing.
	again, err := store.PhysicalLedgerCut(ctx)
	inventoryAgain, e := p.read("complete-execution-inventory.json", 65536)
	demandAgain, de := p.read("physical-gate-demand-envelope.json", 65536)
	if err != nil || e != nil || de != nil || !sameProduct(cut, again) || !bytes.Equal(inventoryRaw, inventoryAgain) || !bytes.Equal(demandRaw, demandAgain) || ctx.Err() != nil {
		return nil, ErrUntrusted
	}
	h := sha256.Sum256(canonicalBytes(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, h[:])
	if err != nil {
		return nil, err
	}
	envelope := canonicalBytes(map[string]any{"payload": payload, "keyId": p.config.KeyID, "signature": base64.StdEncoding.EncodeToString(sig)})
	if workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidLedgerReadbackEnvelope", envelope) != nil {
		return nil, ErrUntrusted
	}
	if err = p.append(Digest(envelope)[7:], envelope); err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), envelope...), nil
}
