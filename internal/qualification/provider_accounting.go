package qualification

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// ObserveProviderOpening is a private owner entry using the already enrolled
// Producer. Authority/keys come from protected owner configuration, not native
// RPC. It independently measures SQLite; the backend snapshot is never imported.
// This observation alone grants no model, reservation, native or artifact access.
func (p *Producer) ObserveProviderOpening(ctx context.Context, store *state.Store, authority, demandEnvelope, backendOpening json.RawMessage, operator []byte) (json.RawMessage, error) {
	if p != nil && p.key != nil && store != nil && ctx.Err() == nil && sameProduct(childFields(authority)["formatVersion"], 5) {
		return p.observeParticipantOpening(ctx, store, authority, demandEnvelope, backendOpening, operator)
	}
	if p == nil || p.key == nil || store == nil || ctx.Err() != nil || workflowcontract.Validate(workflowcontract.BudgetProvider, "authority3", authority) != nil || workflowcontract.Validate(workflowcontract.BudgetProvider, "demandManifestEnvelope", demandEnvelope) != nil || workflowcontract.Validate(workflowcontract.ProviderAccounting, "openingEnvelope", backendOpening) != nil {
		return nil, ErrUntrusted
	}
	a := childFields(authority)
	producer := childFields(a["producer"])
	op := childFields(a["operator"])
	if childString(producer, "keyId") != p.config.KeyID || "sha256:"+childString(producer, "keySHA256") != p.config.KeySHA256 || childString(producer, "nodeTokenHash") != p.config.NodeTokenHash || "sha256:"+childString(op, "keySHA256") != Digest(operator) || Digest(operator) == p.config.KeySHA256 {
		return nil, ErrUntrusted
	}
	if verifyChildEnvelope(backendOpening, childString(op, "keyId"), operator) != nil || verifyChildEnvelope(demandEnvelope, childString(op, "keyId"), operator) != nil {
		return nil, ErrUntrusted
	}
	var c RealCase
	var demand ChildEnvelope[DemandManifest]
	now := time.Now().UTC()
	if decode(a["case"], &c) != nil || decode(demandEnvelope, &demand) != nil || demand.Payload.validateProvider(c, now) != nil {
		return nil, ErrUntrusted
	}
	if c.OperatorKeySHA256 != Digest(operator) || CanonicalDigest(a["tupleInventory"]) != c.TupleInventoryDigest || childString(a, "caseId") != c.CaseID || childString(a, "caseManifestDigest") != c.CaseManifestDigest {
		return nil, ErrUntrusted
	}
	b := childFields(childFields(backendOpening)["payload"])
	expected := map[string]any{"formatVersion": 2, "accountingVersion": 2, "ledgerId": c.LedgerID, "providerPolicyDigest": providerpolicy.FlashDigest, "authorityDigest": CanonicalDigest(authority), "demandManifestDigest": c.DemandManifestDigest, "caseId": c.CaseID, "candidateInventoryDigest": demand.Payload.CandidateInventoryDigest, "accountScopeDigest": demand.Payload.AccountScopeDigest}
	for key, value := range expected {
		if !sameProduct(b[key], value) {
			return nil, ErrUntrusted
		}
	}
	observed, err := time.Parse(time.RFC3339Nano, childString(b, "observedAt"))
	expiry, ee := time.Parse(time.RFC3339Nano, childString(b, "notAfter"))
	first, readErr := store.PhysicalFact(ctx, "provider_opening_runtime")
	if readErr != nil {
		return nil, readErr
	}
	if err != nil || ee != nil || childString(b, "surface") != "backend" || (!observed.Before(expiry)) || (len(first) == 0 && (observed.After(now) || observed.Before(now.Add(-120*time.Second)) || !now.Before(expiry) || expiry.After(now.Add(5*time.Minute)))) {
		return nil, ErrUntrusted
	}
	var inventory struct {
		Tuples []struct {
			Applicability struct {
				TaskID string `json:"taskId"`
			} `json:"applicability"`
		} `json:"tuples"`
	}
	if json.Unmarshal(a["tupleInventory"], &inventory) != nil || len(inventory.Tuples) == 0 || !safeID.MatchString(p.config.ServerID) {
		return nil, ErrUntrusted
	}
	taskID := inventory.Tuples[0].Applicability.TaskID
	for _, tuple := range inventory.Tuples {
		if tuple.Applicability.TaskID != taskID {
			return nil, ErrUntrusted
		}
	}
	selected := state.PhysicalCase{AccountingVersion: 2, ProviderPolicyDigest: providerpolicy.FlashDigest, TaskID: taskID, ServerID: p.config.ServerID, CaseDigest: c.CaseManifestDigest, BaselineDigest: CanonicalDigest(backendOpening), Requests: c.Requests, Preparations: c.Preparations, ModelRequests: c.ModelRequests, AccessRequests: c.AccessRequests, UsdMicros: c.USDMicros}
	return store.ObserveEmptyProviderOpening(ctx, selected, canonicalBytes(backendOpening), func() ([]byte, error) {
		// The Store has independently measured zero physical records, zero owner,
		// and zero financial facts while holding its existing write transaction.
		payload := map[string]any{}
		for key, value := range b {
			payload[key] = value
		}
		payload["surface"] = "runtime"
		payload["snapshot"] = map[string]any{"physicalRequests": 0, "modelRequests": 0, "turns": 0, "preparations": 0, "reservedUsdMicros": 0, "actualUsdMicros": 0}
		payload["historyDigest"] = CanonicalDigest([]any{})
		payload["observedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
		h := sha256.Sum256(canonicalBytes(payload))
		sig, err := ecdsa.SignASN1(rand.Reader, p.key, h[:])
		if err != nil {
			return nil, err
		}
		return canonicalBytes(map[string]any{"payload": payload, "keyId": p.config.KeyID, "signature": base64.StdEncoding.EncodeToString(sig)}), nil
	})
}
