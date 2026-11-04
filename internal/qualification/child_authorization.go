package qualification

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Private normal supplier packet: originals from the owning authenticated F1
// getter, not a public dispatch/RPC or locally reconstructed accepted association.
type ChildAuthorizationIntent struct {
	PreparationID          string          `json:"preparationId"`
	PreparationAssociation json.RawMessage `json:"preparationAssociation"`
	Policy                 json.RawMessage `json:"policy"`
	PolicyBinding          json.RawMessage `json:"policyBinding"`
	GrantIntent            json.RawMessage `json:"grantIntent"`
}

type childAuthorizationGrantIntent struct {
	FormatVersion                int                        `json:"formatVersion"`
	HandleID                     string                     `json:"handleId"`
	PreparationAssociationDigest string                     `json:"preparationAssociationDigest"`
	PolicyDigest                 string                     `json:"policyDigest"`
	PolicyBindingDigest          string                     `json:"policyBindingDigest"`
	Assignment                   json.RawMessage            `json:"assignment"`
	Reservation                  ChildReservation           `json:"reservation"`
	Grant                        model.CellExecutionGrantV3 `json:"grant"`
	GrantDigest                  string                     `json:"grantDigest"`
	NotBefore                    string                     `json:"notBefore"`
	ExpiresAt                    string                     `json:"expiresAt"`
	State                        string                     `json:"state"`
}

// Opaque SAME-producer, pre-activation context. Neither a caller observation nor
// an activated PRODUCT witness can create it. It never admits/releases a slot.
type ChildAuthorizationContext struct {
	producer                    *Producer
	policy                      ChildProductPolicy
	preparationID               string
	notBefore, until, checkedAt time.Time
	originalsDigest             string
	originals                   json.RawMessage
	producerPEM                 []byte
}

func (p *Producer) PrepareChildAuthorization(ctx context.Context, store Store, box model.Sandbox, w ChildProductWitness, receipt model.PreparedReceipt, original ChildAuthorizationIntent, now time.Time) (*ChildAuthorizationContext, error) {
	if p == nil || p.key == nil || ctx.Err() != nil || w.Entry.LifecyclePhase != "prepare" || original.PreparationID != w.Entry.PreparationID || receipt.ValidateFor(w.Entry) != nil ||
		w.Root.Producer != (model.WorkspaceRegisteredProducer{KeyID: p.config.KeyID, KeySHA256: p.config.KeySHA256, ServerID: p.config.ServerID, NodeTokenHash: p.config.NodeTokenHash}) {
		return nil, ErrUntrusted
	}
	c, err := store.ReadChildProduct(box, original.PreparationID, w, now)
	if err != nil || c.Generation.Phase != "prepare" {
		return nil, ErrUntrusted
	}
	basis := c.Generation.PreparationPolicy.Payload
	var policy ChildEnvelope[ChildProductPolicy]
	var binding ChildEnvelope[ChildPolicyBinding]
	var intent childAuthorizationGrantIntent
	tree, key, err := store.Paths(box.ID)
	if err != nil {
		return nil, ErrUntrusted
	}
	pem, err := store.read(key, tree, key, 4096)
	family := workflowcontract.ChildProduct
	if basis.Case.FormatVersion == 2 {
		family = workflowcontract.Budget
	}
	if len(w.SourceContinuation) != 0 {
		family = workflowcontract.BudgetSourceContinuation
	}
	bindingFamily, bindingDefinition := workflowcontract.Manager, "productPolicyEnvelope"
	if basis.Case.FormatVersion == 2 {
		bindingFamily, bindingDefinition = family, "bindingEnvelope"
	}
	for _, wire := range []struct {
		raw                json.RawMessage
		family, definition string
		target             any
	}{
		{original.Policy, family, "productPolicyEnvelope", &policy}, {original.PolicyBinding, bindingFamily, bindingDefinition, &binding}, {original.GrantIntent, family, "grantIntent", &intent},
	} {
		if workflowcontract.Validate(wire.family, wire.definition, wire.raw) != nil || decode(wire.raw, wire.target) != nil {
			return nil, ErrUntrusted
		}
	}
	if err != nil || verifyChildEnvelope(original.Policy, w.OperatorKeyID, pem) != nil || verifyChildEnvelope(original.PolicyBinding, w.OperatorKeyID, pem) != nil ||
		workflowcontract.Validate(workflowcontract.Manager, "actualPreparationAssociation", original.PreparationAssociation) != nil {
		return nil, ErrUntrusted
	}
	q, b := policy.Payload, binding.Payload
	association := childFields(original.PreparationAssociation)
	associationDigest := childString(association, "associationDigest")
	delete(association, "associationDigest")
	before, err := time.Parse(time.RFC3339Nano, intent.NotBefore)
	until, ue := time.Parse(time.RFC3339Nano, intent.ExpiresAt)
	if err != nil || ue != nil || before.After(now) || !now.Before(until) || until.Sub(before) > 120*time.Second || until.After(w.AuthorizedUntil) ||
		q.PreparationPolicyDigest != CanonicalDigest(basis) ||
		verifyChildProductPolicyBasis(basis, q, b, &receipt, association["binding"], intent.Assignment, w.SigningNotBefore, now) != nil ||
		until.After(mustChildTime(q.ExpiresAt)) || until.After(mustChildTime(b.ExpiresAt)) || until.After(mustChildTime(intent.Grant.ExpiresAt)) ||
		intent.PolicyDigest != CanonicalDigest(q) || intent.PolicyBindingDigest != CanonicalDigest(b) || intent.HandleID != basis.Handle.HandleID ||
		intent.PreparationAssociationDigest != associationDigest || CanonicalDigest(association) != associationDigest ||
		childString(association, "preparationId") != original.PreparationID || childString(association, "handleId") != intent.HandleID ||
		!sameProduct(association["preparedReceipt"], receipt) || !sameProduct(association["binding"], q.Binding) || !sameProduct(association["intent"], q.Intent) ||
		!sameProduct(intent.Assignment, q.Assignment) || !sameProduct(intent.Reservation, basis.Reservation) || intent.GrantDigest != CanonicalDigest(intent.Grant) {
		return nil, ErrUntrusted
	}
	// Validate the original normal V3 grant without exposing an execute manifest or
	// requiring the future activation. The copy is never published/admitted.
	check := w.Entry
	check.LifecyclePhase = "execute"
	check.PreparedReceiptDigest = &receipt.PreparedReceiptDigest
	check.ExecutionGrant = &intent.Grant
	if check.ValidateExecutionAuthority(receipt) != nil {
		return nil, ErrUntrusted
	}
	if Digest(w.ProducerPEM) != p.config.KeySHA256 {
		return nil, ErrUntrusted
	}
	return &ChildAuthorizationContext{producer: p, policy: q, preparationID: original.PreparationID, notBefore: before, until: until, checkedAt: now, originalsDigest: CanonicalDigest(original), originals: canonicalBytes(original), producerPEM: append([]byte(nil), w.ProducerPEM...)}, nil
}

// This signs the FROZEN child observation only after protected native readback and
// independently current originals. SAME producer key; no activation or new issuer.
func (p *Producer) AttestChildAuthorization(observed ChildAuthorizationObservation, current *ChildAuthorizationContext, now time.Time) (ChildEnvelope[ChildAuthorizationObservation], error) {
	var empty ChildEnvelope[ChildAuthorizationObservation]
	if p == nil || p.key == nil || current == nil || current.producer != p || current.checkedAt.After(now) || now.Sub(current.checkedAt) > 120*time.Second || !now.Before(current.until) ||
		!hash.MatchString(current.originalsDigest) || Digest(current.originals) != current.originalsDigest || workflowcontract.Validate(workflowcontract.ChildProduct, "authorizationObservation", canonicalBytes(observed)) != nil ||
		observed.PreparationID != current.preparationID || observed.PreparedReceiptDigest != current.policy.PreparedReceipt.PreparedReceiptDigest ||
		observed.TaskID != current.policy.Applicability.TaskID || observed.NodeTokenHash != p.config.NodeTokenHash || !sameProduct(observed.Root, current.policy.Root) {
		return empty, ErrUntrusted
	}
	when, err := time.Parse(time.RFC3339Nano, observed.ObservedAt)
	if err != nil || when.Before(current.notBefore) || when.Before(current.checkedAt) || when.After(now) || !when.Before(current.until) {
		return empty, ErrUntrusted
	}
	name := "child-authorization-" + observed.PreparationID + ".json"
	// Read FIRST signature unchanged. Changed credentials/root/receipt cannot bind a
	// later native readback to that original; failures have no grant/retry effect.
	if rootPrivate(p.config.EvidenceRoot, true) != nil {
		return empty, ErrUntrusted
	}
	// The observation envelope stays frozen; bind FIRST complete current originals
	// in the existing private producer journal instead of adding policy/grant fields.
	if err = p.append("child-authorization-"+observed.PreparationID+"-intent.json", current.originals); err != nil {
		return empty, err
	}
	if _, e := os.Lstat(filepath.Join(p.config.EvidenceRoot, name)); e == nil {
		raw, e := p.read(name, 65536)
		if e != nil {
			return empty, ErrUntrusted
		}
		var old ChildEnvelope[ChildAuthorizationObservation]
		if decode(raw, &old) != nil || verifyChildEnvelope(raw, p.config.KeyID, current.producerPEM) != nil {
			return empty, ErrUntrusted
		}
		comparison := old.Payload
		comparison.ObservedAt = observed.ObservedAt
		first, fe := time.Parse(time.RFC3339Nano, old.Payload.ObservedAt)
		if !sameProduct(comparison, observed) || fe != nil || first.Before(current.notBefore) || first.After(now) || !first.Before(current.until) {
			return empty, ErrUntrusted
		}
		return old, nil
	} else if !os.IsNotExist(e) {
		return empty, ErrUntrusted
	}
	sum := sha256.Sum256(canonicalBytes(observed))
	signature, err := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if err != nil {
		return empty, err
	}
	envelope := ChildEnvelope[ChildAuthorizationObservation]{Payload: observed, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(signature)}
	if err = p.append(name, canonicalBytes(envelope)); err != nil {
		return empty, err
	}
	return envelope, nil
}
