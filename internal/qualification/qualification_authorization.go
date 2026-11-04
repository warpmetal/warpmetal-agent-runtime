package qualification

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Native-r2 authorization observation. It describes a protected inactive
// binding; it is neither an activation nor permission to issue a request.
type QualificationAuthorizationObservation struct {
	FormatVersion         int    `json:"formatVersion"`
	Purpose               string `json:"purpose"`
	TaskID                string `json:"taskId"`
	NodeTokenHash         string `json:"nodeTokenHash"`
	QualificationID       string `json:"qualificationId"`
	PreparationID         string `json:"preparationId"`
	PreparedTupleDigest   string `json:"preparedTupleDigest"`
	PreparedReceiptDigest string `json:"preparedReceiptDigest"`
	NativeSessionID       string `json:"nativeSessionId"`
	NativeInputID         string `json:"nativeInputId"`
	AuthorizationSHA256   string `json:"authorizationSha256"`
	ObservedAt            string `json:"observedAt"`
}

type QualificationAuthorizationContext struct {
	producer                       *Producer
	expected                       QualificationAuthorizationObservation
	checkedAt, issuedAt, expiresAt time.Time
	originals                      []byte
	producerPEM                    []byte
	nativeContract                 string
}

// Select the current signed pre-prepare authority, without requiring or
// manufacturing the future native activation. The caller supplies the durable
// backend-acknowledged receipt and rechecks it after the protected observation.
func (p *Producer) PrepareQualificationAuthorization(s Store, box model.Sandbox, entry model.CellServiceV3, receipt model.PreparedReceipt, workspace string, now time.Time) (*QualificationAuthorizationContext, error) {
	if p == nil || entry.LifecyclePhase != "prepare" || entry.DesiredState != "active" || receipt.ValidateFor(entry) != nil {
		return nil, ErrUntrusted
	}
	b, policy, d, err := s.SelectedPolicy(box, entry, workspace, now)
	if err != nil || b.FormatVersion != 3 || b.Producer == nil || policy.FormatVersion != 4 || policy.Run == nil || policy.SourcePolicy == nil || len(policy.Preparations) != 1 {
		return nil, ErrUntrusted
	}
	ours := QualificationProducerIdentity{p.config.KeyID, p.config.KeySHA256, p.config.ServerID, p.config.NodeTokenHash}
	if *b.Producer != ours || CanonicalDigest(receipt.PreparedTuple) != d.PreparedTupleDigest || policy.Run.Tuple.ServerID != p.config.ServerID {
		return nil, ErrUntrusted
	}
	public, err := qualificationBase64(b.ProducerPublicKeyBase64, 4096)
	if err != nil || Digest(public) != p.config.KeySHA256 {
		return nil, ErrUntrusted
	}
	// This source policy was already verified by SelectedPolicy. Its original
	// issue time bounds replay; the fresh check bounds the new native observation.
	source, err := qualificationBase64(policy.SourcePolicy.ContentBase64, 32768)
	issued, ie := time.Parse(time.RFC3339Nano, childString(childFields(source), "issuedAt"))
	until, ue := time.Parse(time.RFC3339Nano, policy.ExpiresAt)
	if err != nil || ie != nil || ue != nil || issued.After(now) || !now.Before(until) {
		return nil, ErrUntrusted
	}
	prep := policy.Preparations[0]
	nativeContract, _, familyOK := qualificationFamily(b.Case)
	if !familyOK {
		return nil, ErrUntrusted
	}
	expected := QualificationAuthorizationObservation{FormatVersion: 1, Purpose: "qualification_authorization", TaskID: policy.Run.Tuple.TaskID, NodeTokenHash: p.config.NodeTokenHash, QualificationID: policy.Run.QualificationID, PreparationID: entry.PreparationID, PreparedTupleDigest: d.PreparedTupleDigest, PreparedReceiptDigest: receipt.PreparedReceiptDigest, NativeSessionID: prep.SessionID, NativeInputID: prep.InputID}
	return &QualificationAuthorizationContext{producer: p, expected: expected, checkedAt: now, issuedAt: issued, expiresAt: until, producerPEM: public, nativeContract: nativeContract, originals: canonicalBytes(map[string]any{"bootstrapDigest": policy.SidecarBootstrapDigest, "sidecarPolicyDigest": d.PolicyDigest, "sourcePolicyDigest": policy.SourcePolicy.Digest, "preparedReceipt": receipt, "entry": entry})}, nil
}

func (c *QualificationAuthorizationContext) Matches(other *QualificationAuthorizationContext) bool {
	return c != nil && other != nil && c.producer == other.producer && sameProduct(c.originals, other.originals)
}

func (c *QualificationAuthorizationContext) ValidateObservation(observed QualificationAuthorizationObservation, now time.Time) error {
	if c == nil || c.nativeContract == "" || workflowcontract.Validate(c.nativeContract, "authorizationObservation", canonicalBytes(observed)) != nil || c.checkedAt.After(now) || now.Sub(c.checkedAt) > 120*time.Second || !now.Before(c.expiresAt) {
		return ErrUntrusted
	}
	comparison := observed
	comparison.AuthorizationSHA256, comparison.ObservedAt = "", ""
	when, err := time.Parse(time.RFC3339Nano, observed.ObservedAt)
	if !sameProduct(comparison, c.expected) || err != nil || when.Before(c.checkedAt) || when.After(now) || !when.Before(c.expiresAt) {
		return ErrUntrusted
	}
	return nil
}

// Preserve FIRST original signature in the existing protected producer journal.
// The operator consumes this fixed handoff to request/sign a separate native
// activation. A changed receipt/policy/header never overwrites the original.
func (p *Producer) AttestQualificationAuthorization(observed QualificationAuthorizationObservation, current *QualificationAuthorizationContext, now time.Time) (ChildEnvelope[QualificationAuthorizationObservation], error) {
	var empty ChildEnvelope[QualificationAuthorizationObservation]
	if p == nil || p.key == nil || current == nil || current.producer != p || current.ValidateObservation(observed, now) != nil || rootPrivate(p.config.EvidenceRoot, true) != nil {
		return empty, ErrUntrusted
	}
	stem := "qualification-authorization-" + observed.PreparationID
	if err := p.append(stem+"-context.json", current.originals); err != nil {
		return empty, err
	}
	name := stem + ".json"
	if _, err := os.Lstat(filepath.Join(p.config.EvidenceRoot, name)); err == nil {
		raw, err := p.read(name, 32768)
		var old ChildEnvelope[QualificationAuthorizationObservation]
		if err != nil || current.nativeContract == "" || workflowcontract.Validate(current.nativeContract, "authorizationEnvelope", raw) != nil || decodeClosed(raw, &old) != nil || verifyChildEnvelope(raw, p.config.KeyID, current.producerPEM) != nil {
			return empty, ErrUntrusted
		}
		comparison := old.Payload
		comparison.ObservedAt = observed.ObservedAt
		when, err := time.Parse(time.RFC3339Nano, old.Payload.ObservedAt)
		if err != nil || when.Before(current.issuedAt) || when.After(now) || !when.Before(current.expiresAt) || !sameProduct(comparison, observed) {
			return empty, ErrUntrusted
		}
		return old, nil
	} else if !os.IsNotExist(err) {
		return empty, ErrUntrusted
	}
	sum := sha256.Sum256(canonicalBytes(observed))
	signature, err := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if err != nil {
		return empty, err
	}
	envelope := ChildEnvelope[QualificationAuthorizationObservation]{Payload: observed, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(signature)}
	if err = p.append(name, canonicalBytes(envelope)); err != nil {
		return empty, err
	}
	return envelope, nil
}
