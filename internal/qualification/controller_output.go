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

// Protected preparation consumers supply these independently retained witnesses.
// Approved context must come from F1 before input; neither output text nor this
// witness selects a workflow target. Executable consumers validate real policy.
type ControllerOutputWitness struct {
	Producer             model.WorkspaceRegisteredProducer
	Authority            Store
	Sandbox              model.Sandbox
	Installed            ControllerPolicyWitness
	Parent               WorkspaceApplicationWitness
	Policy               ControllerPolicy
	Activation           ControllerActivation
	ApprovedContext      model.ControllerApprovedInputContext
	ApprovedInputText    string
	ApplicationOperation model.WorkspaceApplicationOperation
}

func (p *Producer) controllerOutputPayload(op model.ControllerOutputOperation, capture ControllerCapture, w ControllerOutputWitness, now time.Time) (model.ControllerOutputPayload, error) {
	var empty model.ControllerOutputPayload
	if p == nil || p.key == nil || op.Producer != w.Producer || op.Producer.KeyID != p.config.KeyID || op.Producer.KeySHA256 != p.config.KeySHA256 || op.Producer.ServerID != p.config.ServerID || op.Producer.NodeTokenHash != p.config.NodeTokenHash {
		return empty, ErrUntrusted
	}
	policy, err := w.Authority.ReadControllerPolicy(w.Sandbox, w.Activation.PolicyDigest, w.Installed, now)
	if err != nil || !reflect.DeepEqual(policy, w.Policy) {
		return empty, ErrUntrusted
	}
	a, err := w.Authority.ReadControllerRetainedActivation(w.Sandbox, policy, w.Activation.Admission.PreparedReceipt, now)
	if err != nil || !reflect.DeepEqual(a, w.Activation) {
		return empty, ErrUntrusted
	}
	if a.ValidateContext(policy, w.ApprovedContext) != nil {
		return empty, ErrUntrusted
	}
	identity, _ := json.Marshal(policy.NativeIdentity())
	lineage, err := capture.Verify(w.ApprovedInputText, identity, a.Admission)
	if err != nil {
		return empty, err
	}
	raw, err := json.Marshal(op)
	var checked model.ControllerOutputOperation
	if err != nil || json.Unmarshal(raw, &checked) != nil || !reflect.DeepEqual(op.Lineage, lineage) || !reflect.DeepEqual(op.Context, w.ApprovedContext) || w.Parent.Report.ValidateReady(w.Parent.Parent) != nil || !reflect.DeepEqual(w.Installed.Identity.Intent, w.Parent.Parent) {
		return empty, ErrUntrusted
	}
	if !safeID.MatchString(op.RoleBindingID) || op.RoleBindingRevision < 1 || op.RoleBindingRevision > 9007199254740991 {
		return empty, ErrUntrusted
	}
	c, t, g := op.Context, a.Admission.PreparedReceipt.PreparedTuple, a.Admission.Grant
	if policy.ValidatePreparedReceipt(a.Admission.PreparedReceipt) != nil {
		return empty, ErrUntrusted
	}
	if c.PreparationID != a.Admission.PreparedReceipt.PreparationID || c.InputID != t.InputID || c.InputDigest != t.InputDigest || c.PolicyDigest != a.PolicyDigest || c.CaseID != g.CaseID || c.CaseManifestDigest != g.CaseManifestDigest {
		return empty, ErrUntrusted
	}
	proposal, err := model.ControllerProposal(c, lineage.OutputText)
	if err != nil || model.WorkspaceDigest(proposal) != model.WorkspaceDigest(op.Proposal) {
		return empty, ErrUntrusted
	}
	s := op.Subject
	o := t.Owner
	if s.AccountID != o.AccountID || s.TaskID != o.TaskID || s.ServerID != o.ServerID || s.SandboxID != o.SandboxID || s.SandboxGeneration != o.SandboxGeneration || s.CellID != o.CellID || s.ControllerID != o.ControllerID || s.ControllerRevision != o.ControllerRevision || s.AuthorityRevision != o.AuthorityRevision || s.Role != t.Role || s.WorkID != nil || s.ExecutionID != nil || s.ServiceRegistrationID != t.ServiceRegistrationID || s.ServiceGeneration != t.ServiceGeneration || s.NativeSessionID != t.NativeRegistration.NativeSessionID || op.Workspace != w.Parent.Parent.Workspace || op.ConfigurationDigest != t.ConfigurationDigest || op.ConfigurationDigest != w.ApplicationOperation.ConfigurationDigest || op.ManagedServiceReceiptDigest != w.Parent.Report.ReceiptDigest {
		return empty, ErrUntrusted
	}
	application := policy.ApplicationReference()
	if policy.FormatVersion == 6 {
		app := policy.ApplicationIdentity().Intent
		if (op.FormatVersion != 3 && op.FormatVersion != 4) || op.ApplicationRoleAgentDigest != app.RoleAgentDigest || op.ApplicationConfigDigest != app.ConfigDigest || op.NativeRoleAgentDigest != t.RoleAgentDigest || op.NativeConfigDigest != t.ConfigDigest || op.IdentityAssociationDigest != policy.IdentityAssociation.AssociationDigest || op.ProviderPolicyDigest != policy.ProviderPolicyDigest {
			return empty, ErrUntrusted
		}
	} else if op.FormatVersion > 2 || op.ConfigDigest != t.ConfigDigest || op.RoleAgentDigest != t.RoleAgentDigest {
		return empty, ErrUntrusted
	}
	if w.ApplicationOperation.OperationID != application.OperationID || w.ApplicationOperation.OperationDigest != application.OperationDigest {
		return empty, ErrUntrusted
	}
	if _, err := w.ApplicationOperation.ParentDependency(w.Parent.Parent); err != nil {
		return empty, ErrUntrusted
	}
	root, err := confinedRoot(w.Parent.Workspace.HostRoot, w.Parent.Workspace.Device, w.Parent.Workspace.Inode)
	if err != nil {
		return empty, err
	}
	root.Close()
	n := t.NativeRegistration
	workspace := w.Parent.Workspace
	if workspace.WorkspaceDigest != op.Workspace.RootAttestation || w.Parent.Report.NativeRegistration == nil || *w.Parent.Report.NativeRegistration != n || model.WorkspaceDigest(map[string]any{"directory": workspace.ContainerRoot, "projectId": n.NativeProjectID, "workspaceId": nil}) != n.NativeLocationDigest {
		return empty, ErrUntrusted
	}
	observed := time.UnixMilli(capture.NativeOutput.Data.ControllerOutput.Current.ObservedAt).UTC()
	expiry, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	pe, _ := time.Parse(time.RFC3339Nano, policy.ExpiresAt)
	if err != nil || !now.Before(expiry) || observed.After(now) || observed.Before(now.Add(-300*time.Second)) {
		return empty, ErrUntrusted
	}
	// F1 compares expiry with the transmitted (UTC second-precision) issuedAt,
	// not the later root wall clock or raw millisecond observation.
	horizon := observed.Truncate(time.Second).Add(300 * time.Second)
	if expiry.After(horizon) {
		expiry = horizon
	}
	if expiry.After(pe) {
		expiry = pe
	}
	if !observed.Before(expiry) {
		return empty, ErrUntrusted
	}
	stamp := model.ControllerOutputTimestamp(observed.UnixMilli())
	readback := model.ControllerOutputReadback{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: t.ServiceRegistrationID, ServiceGeneration: t.ServiceGeneration, NativeSessionID: n.NativeSessionID, NativeProjectID: n.NativeProjectID, NativeLocationDigest: n.NativeLocationDigest, Role: t.Role, RootAttestation: workspace.WorkspaceDigest, ObservedAt: stamp, Lineage: lineage, NativeReadback: capture.NativeOutput}
	return model.ControllerOutputPayload{FormatVersion: 1, Purpose: "workspace_workflow_controller_output", RequestID: op.RequestID, TaskID: s.TaskID, NodeTokenHash: op.Producer.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: expiry.UTC().Format(time.RFC3339Nano), ManagedServiceReceiptDigest: op.ManagedServiceReceiptDigest, NativeReceipt: readback, OperationID: op.OperationID, OperationDigest: op.OperationDigest}, nil
}

// Narrow same-root signing only after verifying native/log/operator/application
// witnesses. No backend-supplied lineage alone reaches the existing private key.
func (p *Producer) AttestControllerOutput(op model.ControllerOutputOperation, capture ControllerCapture, w ControllerOutputWitness, now time.Time) (model.ControllerOutputEnvelope, error) {
	payload, err := p.controllerOutputPayload(op, capture, w, now)
	if err != nil {
		return model.ControllerOutputEnvelope{}, err
	}
	if !safeID.MatchString(op.OperationID) {
		return model.ControllerOutputEnvelope{}, ErrUntrusted
	}
	name := op.OperationID + "-controller-output.json"
	if raw, err := p.read(name, 2*1024*1024); err == nil {
		var prior model.ControllerOutputEnvelope
		if decode(raw, &prior) != nil || prior.KeyID != p.config.KeyID || prior.Payload.OperationDigest != op.OperationDigest || !reflect.DeepEqual(prior.Payload.NativeReceipt.Lineage, payload.NativeReceipt.Lineage) {
			return prior, ErrUntrusted
		}
		old := prior.Payload.NativeReceipt.NativeReadback
		old.Data.ControllerOutput.Current.ObservedAt = capture.NativeOutput.Data.ControllerOutput.Current.ObservedAt
		if !reflect.DeepEqual(old, capture.NativeOutput) {
			return prior, ErrUntrusted
		}
		exp, err := time.Parse(time.RFC3339Nano, prior.Payload.NotAfter)
		if err != nil || !now.Before(exp) {
			return prior, ErrUntrusted
		}
		body, _ := model.WorkspaceCanonicalJSON(prior.Payload)
		sum := sha256.Sum256(body)
		sig, _ := base64.StdEncoding.DecodeString(prior.Signature)
		if !ecdsa.VerifyASN1(&p.key.PublicKey, sum[:], sig) {
			return prior, ErrUntrusted
		}
		return prior, nil
	}
	body, err := model.WorkspaceCanonicalJSON(payload)
	if err != nil {
		return model.ControllerOutputEnvelope{}, err
	}
	sum := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if err != nil {
		return model.ControllerOutputEnvelope{}, err
	}
	envelope := model.ControllerOutputEnvelope{Payload: payload, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}
	raw, err := json.Marshal(envelope)
	if err == nil {
		err = p.append(name, raw)
	}
	return envelope, err
}
