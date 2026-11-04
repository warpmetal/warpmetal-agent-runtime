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

func (p *Producer) AttestControllerPrepared(receipt model.ControllerPreparedReceipt, w ControllerOutputWitness, now time.Time) (model.ControllerPreparedEnvelope, error) {
	var empty model.ControllerPreparedEnvelope
	if p == nil || p.key == nil || w.Parent.Report.ValidateReady(w.Parent.Parent) != nil {
		return empty, ErrUntrusted
	}
	if w.Producer.KeyID != p.config.KeyID || w.Producer.KeySHA256 != p.config.KeySHA256 || w.Producer.ServerID != p.config.ServerID || w.Producer.NodeTokenHash != p.config.NodeTokenHash || receipt.PreparedTuple.Owner.ServerID != p.config.ServerID {
		return empty, ErrUntrusted
	}
	policy, e := w.Authority.ReadControllerPolicy(w.Sandbox, CanonicalDigest(w.Policy), w.Installed, now)
	if e != nil || !reflect.DeepEqual(policy, w.Policy) || policy.ValidatePreparedReceipt(receipt) != nil {
		return empty, ErrUntrusted
	}
	t, c := receipt.PreparedTuple, w.ApprovedContext
	native, application := policy.NativeIdentity(), policy.ApplicationReference()
	if t.ConfigurationDigest != w.ApplicationOperation.ConfigurationDigest || w.ApplicationOperation.OperationID != application.OperationID || w.ApplicationOperation.OperationDigest != application.OperationDigest {
		return empty, ErrUntrusted
	}
	if t.Owner != native.Intent.Owner || t.Role != native.Intent.Role || t.ServiceRegistrationID != native.Intent.ServiceRegistrationID || t.ServiceGeneration != native.Intent.ServiceGeneration ||
		t.ConfigDigest != native.Intent.ConfigDigest || t.RoleAgentDigest != native.Intent.RoleAgentDigest || t.CredentialBinding != policy.Applicability.Connection ||
		c.PreparationID != receipt.PreparationID || c.CaseID != policy.Case.CaseID || c.CaseManifestDigest != policy.Case.CaseManifestDigest || c.PolicyDigest != CanonicalDigest(policy) ||
		c.InputID != t.InputID || c.InputDigest != t.InputDigest || w.Parent.Report.NativeRegistration == nil || *w.Parent.Report.NativeRegistration != t.NativeRegistration {
		return empty, ErrUntrusted
	}
	root, e := confinedRoot(w.Parent.Workspace.HostRoot, w.Parent.Workspace.Device, w.Parent.Workspace.Inode)
	if e != nil {
		return empty, e
	}
	root.Close()
	if w.Parent.Workspace.WorkspaceDigest != w.Parent.Parent.Workspace.RootAttestation || t.NativeRegistration.NativeLocationDigest != model.WorkspaceDigest(map[string]any{"directory": w.Parent.Workspace.ContainerRoot, "projectId": t.NativeRegistration.NativeProjectID, "workspaceId": nil}) {
		return empty, ErrUntrusted
	}
	name := receipt.PreparationID + "-controller-prepared.json"
	if raw, e := p.read(name, 131072); e == nil {
		var prior model.ControllerPreparedEnvelope
		if decodeClosed(raw, &prior) != nil || !reflect.DeepEqual(prior.Payload, receipt) || prior.KeyID != p.config.KeyID {
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
	body, e := model.WorkspaceCanonicalJSON(receipt)
	if e != nil {
		return empty, e
	}
	sum := sha256.Sum256(body)
	sig, e := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if e != nil {
		return empty, e
	}
	envelope := model.ControllerPreparedEnvelope{Payload: receipt, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}
	raw, e := json.Marshal(envelope)
	if e != nil {
		return empty, e
	}
	if e = p.append(name, raw); e != nil {
		return empty, e
	}
	return envelope, nil
}
