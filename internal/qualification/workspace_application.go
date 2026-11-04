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

// Typed current root/native witness only; no caller-supplied payload or generic
// Sign(any) capability. Protected Runtime constructs this from verified catalog
// records and EXACT separately acknowledged current parent reports.
type WorkspaceApplicationWitness struct {
	Parent    model.ControllerParentIntent
	Report    model.ControllerParentReport
	Workspace TrustedWorkspace
}

func (p *Producer) workspaceApplicationPayload(readback model.WorkspaceApplicationReadback, witnesses []WorkspaceApplicationWitness, now time.Time) (model.WorkspaceApplicationPayload, error) {
	op := readback.Operation
	if p == nil || op.Producer.KeyID != p.config.KeyID || op.Producer.KeySHA256 != p.config.KeySHA256 || op.Producer.ServerID != p.config.ServerID || op.Producer.NodeTokenHash != p.config.NodeTokenHash || len(witnesses) != 2 {
		return model.WorkspaceApplicationPayload{}, ErrUntrusted
	}
	parents := []model.ControllerParentIntent{}
	reports := []model.ControllerParentReport{}
	for _, w := range witnesses {
		root, err := confinedRoot(w.Workspace.HostRoot, w.Workspace.Device, w.Workspace.Inode)
		if err != nil {
			return model.WorkspaceApplicationPayload{}, err
		}
		root.Close()
		if w.Report.NativeRegistration == nil || w.Workspace.WorkspaceDigest != w.Parent.Workspace.RootAttestation || w.Workspace.ContainerRoot == "" || w.Report.NativeRegistration.NativeLocationDigest != model.WorkspaceDigest(map[string]any{"directory": w.Workspace.ContainerRoot, "projectId": w.Report.NativeRegistration.NativeProjectID, "workspaceId": nil}) {
			return model.WorkspaceApplicationPayload{}, ErrUntrusted
		}
		parents = append(parents, w.Parent)
		reports = append(reports, w.Report)
	}
	if err := readback.Validate(parents, reports); err != nil {
		return model.WorkspaceApplicationPayload{}, err
	}
	expiry, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if err != nil || !expiry.After(now) {
		return model.WorkspaceApplicationPayload{}, ErrUntrusted
	}
	if expiry.After(now.Add(300 * time.Second)) {
		expiry = now.Add(300 * time.Second)
	}
	manager := readback.RoleBindings[0]
	var report model.ControllerParentReport
	for _, w := range witnesses {
		if w.Parent.ServiceRegistrationID == manager.Binding.ServiceRegistrationID {
			report = w.Report
		}
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	payload := model.WorkspaceApplicationPayload{FormatVersion: 1, Purpose: "workspace_workflow_application", RequestID: "wfapp_receipt_" + model.WorkspaceDigest(op.OperationID)[7:39], TaskID: op.TaskID, NodeTokenHash: op.Producer.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: expiry.UTC().Format(time.RFC3339Nano), ManagedServiceReceiptDigest: report.ReceiptDigest, OperationID: op.OperationID, OperationDigest: op.OperationDigest,
		NativeReceipt: model.WorkspaceApplicationNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: manager.Binding.ServiceRegistrationID, ServiceGeneration: manager.Binding.ServiceGeneration, NativeSessionID: manager.NativeRegistration.NativeSessionID, NativeProjectID: manager.NativeRegistration.NativeProjectID, NativeLocationDigest: manager.NativeRegistration.NativeLocationDigest, Role: "manager", RootAttestation: op.Dependencies.Roles[0].Workspace.RootAttestation, ObservedAt: stamp, Readback: readback}}
	return payload, payload.Validate()
}

func (p *Producer) AttestWorkspaceApplication(readback model.WorkspaceApplicationReadback, witnesses []WorkspaceApplicationWitness, now time.Time) (model.WorkspaceApplicationEnvelope, error) {
	payload, err := p.workspaceApplicationPayload(readback, witnesses, now)
	if err != nil {
		return model.WorkspaceApplicationEnvelope{}, err
	}
	// Same host-private append-only evidence and registered P-256 key as Q33.
	name := readback.Operation.OperationID + "-workspace-application.json"
	if old, err := p.read(name, 2*1024*1024); err == nil {
		var envelope model.WorkspaceApplicationEnvelope
		if decodeClosed(old, &envelope) != nil || envelope.Validate() != nil || !reflect.DeepEqual(envelope.Payload.NativeReceipt.Readback, readback) || envelope.Payload.ManagedServiceReceiptDigest != payload.ManagedServiceReceiptDigest {
			return model.WorkspaceApplicationEnvelope{}, ErrUntrusted
		}
		body, _ := model.WorkspaceCanonicalJSON(envelope.Payload)
		sum := sha256.Sum256(body)
		sig, _ := base64.StdEncoding.DecodeString(envelope.Signature)
		if !ecdsa.VerifyASN1(&p.key.PublicKey, sum[:], sig) {
			return model.WorkspaceApplicationEnvelope{}, ErrUntrusted
		}
		return envelope, nil
	}
	body, err := model.WorkspaceCanonicalJSON(payload)
	if err != nil {
		return model.WorkspaceApplicationEnvelope{}, err
	}
	sum := sha256.Sum256(body)
	signature, err := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if err != nil {
		return model.WorkspaceApplicationEnvelope{}, err
	}
	envelope := model.WorkspaceApplicationEnvelope{Payload: payload, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(signature)}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return model.WorkspaceApplicationEnvelope{}, err
	}
	if err := p.append(name, raw); err != nil {
		return model.WorkspaceApplicationEnvelope{}, err
	}
	return envelope, nil
}
