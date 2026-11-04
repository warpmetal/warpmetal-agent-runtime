package qualification

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Called only with the installed protected native credential readback, not a
// caller credential, a manifest digest, a transport flag or a model request.
func (p *Producer) AttestControllerAuthorization(observed model.ControllerAuthorizationObservation, receipt model.ControllerPreparedReceipt, w ControllerOutputWitness, now time.Time) (model.ControllerAuthorizationEnvelope, error) {
	var empty model.ControllerAuthorizationEnvelope
	if p == nil || p.key == nil || observed.FormatVersion != 1 || observed.TargetKind != "controller_authorization" || !hash.MatchString(observed.AuthorizationSHA256) || observed.PreparationID != receipt.PreparationID || observed.PreparedReceiptDigest != receipt.PreparedReceiptDigest {
		return empty, ErrUntrusted
	}
	// Reuse the complete prepared/root/application/policy verification and SAME
	// append-only signed preparation; it cannot create a new preparation/grant.
	if _, err := p.AttestControllerPrepared(receipt, w, now); err != nil {
		return empty, err
	}
	name := receipt.PreparationID + "-controller-authorization.json"
	if raw, err := p.read(name, 16384); err == nil {
		var prior model.ControllerAuthorizationEnvelope
		if decodeClosed(raw, &prior) != nil || !reflect.DeepEqual(prior.Payload, observed) || prior.KeyID != p.config.KeyID {
			return empty, ErrUntrusted
		}
		body, _ := model.WorkspaceCanonicalJSON(prior.Payload)
		sum := sha256.Sum256(body)
		sig, _ := base64.StdEncoding.DecodeString(prior.Signature)
		if !ecdsa.VerifyASN1(&p.key.PublicKey, sum[:], sig) {
			return empty, ErrUntrusted
		}
		return prior, nil
	}
	body, err := model.WorkspaceCanonicalJSON(observed)
	if err != nil {
		return empty, err
	}
	sum := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if err != nil {
		return empty, err
	}
	result := model.ControllerAuthorizationEnvelope{Payload: observed, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}
	raw, err := json.Marshal(result)
	if err == nil {
		err = p.append(name, raw)
	}
	return result, err
}
