package qualification

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// One purpose-specific producer using the SAME registered protected key/root.
// The owning caller obtains the operation first, then fresh native/root/role
// witnesses without a workflow lease; enrollment never confers activity grants.
func (p *Producer) workflowRolePayload(op model.WorkflowRoleOperation, w WorkspaceApplicationWitness, registered model.WorkspaceRegisteredProducer, now time.Time) (model.WorkflowRolePayload, error) {
	var empty model.WorkflowRolePayload
	if p == nil || registered.KeyID != p.config.KeyID || registered.KeySHA256 != p.config.KeySHA256 || registered.ServerID != p.config.ServerID || registered.NodeTokenHash != p.config.NodeTokenHash || op.Validate() != nil || op.NodeTokenHash != p.config.NodeTokenHash || w.Report.ValidateReady(w.Parent) != nil || w.Report.NativeRegistration == nil || w.Report.NativeRoleReadback == nil {
		return empty, ErrUntrusted
	}
	n := *w.Report.NativeRegistration
	if op.Subject != model.CurrentWorkflowRoleSubject(w.Parent, n) || op.ManagedServiceReceiptDigest != w.Report.ReceiptDigest || op.NativeContextDigest != model.WorkspaceDigest(n) || w.Parent.Owner.ServerID != p.config.ServerID || w.Workspace.WorkspaceDigest != w.Parent.Workspace.RootAttestation || w.Workspace.ContainerRoot == "" || n.NativeLocationDigest != model.WorkspaceDigest(map[string]any{"directory": w.Workspace.ContainerRoot, "projectId": n.NativeProjectID, "workspaceId": nil}) {
		return empty, ErrUntrusted
	}
	root, err := confinedRoot(w.Workspace.HostRoot, w.Workspace.Device, w.Workspace.Inode)
	if err != nil {
		return empty, err
	}
	root.Close()
	expiry, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if err != nil || !now.Before(expiry) {
		return empty, ErrUntrusted
	}
	if limit := now.Add(300 * time.Second); limit.Before(expiry) {
		expiry = limit
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	native := model.WorkflowRoleNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: w.Parent.ServiceRegistrationID, ServiceGeneration: w.Parent.ServiceGeneration, NativeSessionID: n.NativeSessionID, NativeProjectID: n.NativeProjectID, NativeLocationDigest: n.NativeLocationDigest, Role: w.Parent.Role, RootAttestation: w.Parent.Workspace.RootAttestation, ObservedAt: stamp, Readback: model.WorkflowRoleReadback{Subject: op.Subject, NativeContextDigest: op.NativeContextDigest}}
	payload := model.WorkflowRolePayload{FormatVersion: 1, Purpose: "workspace_workflow_role", RequestID: "wfrole_receipt_" + op.OperationDigest[7:39], TaskID: op.Subject.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: expiry.UTC().Format(time.RFC3339Nano), ManagedServiceReceiptDigest: op.ManagedServiceReceiptDigest, NativeReceipt: native, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Subject: op.Subject, NativeContextDigest: op.NativeContextDigest}
	if workflowcontract.Validate(workflowcontract.Producer, "payload", canonicalBytes(payload)) != nil {
		return empty, ErrUntrusted
	}
	return payload, nil
}

func (p *Producer) AttestWorkflowRole(op model.WorkflowRoleOperation, w WorkspaceApplicationWitness, registered model.WorkspaceRegisteredProducer, now time.Time) (model.WorkflowRoleEnvelope, error) {
	var empty model.WorkflowRoleEnvelope
	payload, err := p.workflowRolePayload(op, w, registered, now)
	if err != nil {
		return empty, err
	}
	return p.sealWorkflowRole(op, payload, registered, now)
}

// Parent and execution-scoped child witnesses stay separate; only immutable
// signing/replay mechanics are shared after their own validation succeeds.
func (p *Producer) sealWorkflowRole(op model.WorkflowRoleOperation, payload model.WorkflowRolePayload, registered model.WorkspaceRegisteredProducer, now time.Time) (model.WorkflowRoleEnvelope, error) {
	var empty model.WorkflowRoleEnvelope
	if p.key == nil {
		return empty, ErrUntrusted
	}
	der, err := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	if err != nil {
		return empty, err
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if Digest(public) != registered.KeySHA256 {
		return empty, ErrUntrusted
	}
	name := op.OperationID + "-workflow-role.json"
	if rootPrivate(p.config.EvidenceRoot, true) != nil {
		return empty, ErrUntrusted
	}
	_, statErr := os.Lstat(filepath.Join(p.config.EvidenceRoot, name))
	if statErr == nil {
		old, err := p.read(name, 65536)
		if err != nil {
			return empty, err
		}
		var envelope model.WorkflowRoleEnvelope
		if decode(old, &envelope) != nil || envelope.Validate() != nil || verifyChildEnvelope(old, p.config.KeyID, public) != nil || !live(envelope.Payload.NotAfter, now) {
			return empty, ErrUntrusted
		}
		i, ie := time.Parse(time.RFC3339Nano, envelope.Payload.IssuedAt)
		o, oe := time.Parse(time.RFC3339Nano, envelope.Payload.NativeReceipt.ObservedAt)
		e, ee := time.Parse(time.RFC3339Nano, envelope.Payload.NotAfter)
		limit, _ := time.Parse(time.RFC3339Nano, op.ExpiresAt)
		if ie != nil || oe != nil || ee != nil || i.After(now) || o.Before(i) || o.After(now) || e.After(limit) || e.After(i.Add(300*time.Second)) {
			return empty, ErrUntrusted
		}
		expected := payload
		expected.IssuedAt, expected.NotAfter, expected.NativeReceipt.ObservedAt = envelope.Payload.IssuedAt, envelope.Payload.NotAfter, envelope.Payload.NativeReceipt.ObservedAt
		if !reflect.DeepEqual(expected, envelope.Payload) {
			return empty, ErrUntrusted
		}
		return envelope, nil
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		return empty, statErr
	}
	if p.key == nil {
		return empty, ErrUntrusted
	}
	h := sha256.Sum256(canonicalBytes(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, h[:])
	if err != nil {
		return empty, err
	}
	envelope := model.WorkflowRoleEnvelope{Payload: payload, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}
	raw, err := json.Marshal(envelope)
	if err != nil || workflowcontract.Validate(workflowcontract.Producer, "envelope", raw) != nil {
		return empty, ErrUntrusted
	}
	if err = p.append(name, canonicalBytes(envelope)); err != nil {
		return empty, err
	}
	return envelope, nil
}
