package qualification

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Current local consumed execution, current registered root and independently
// fetched backend snapshot are separate from the operation and signed policy.
// The fixed native capture proves the completed child; it is not a role label.
type ChildWorkflowRoleWitness struct {
	Authority       Store
	Sandbox         model.Sandbox
	Product         ChildProductWitness
	ExecutionReport model.CellServiceReportV1
	ConsumedGrant   model.CellExecutionGrantV3
	CurrentSnapshot json.RawMessage
	Workspace       TrustedWorkspace
	Result          model.ChildNativeResultCapture
	Integration     *model.ChildNativeIntegrationCapture
	Reviewer        *model.ChildNativeReviewerCapture
}

func (p *Producer) childWorkflowRolePayload(op model.WorkflowRoleOperation, w ChildWorkflowRoleWitness, now time.Time) (model.WorkflowRolePayload, error) {
	var empty model.WorkflowRolePayload
	registered := w.Product.Root.Producer
	if p == nil || p.key == nil || registered != (model.WorkspaceRegisteredProducer{KeyID: p.config.KeyID, KeySHA256: p.config.KeySHA256, ServerID: p.config.ServerID, NodeTokenHash: p.config.NodeTokenHash}) || op.Validate() != nil || op.NodeTokenHash != p.config.NodeTokenHash {
		return empty, ErrUntrusted
	}
	current, err := w.Authority.ReadChildProduct(w.Sandbox, w.Product.Preparation.PreparationID, w.Product, now)
	if err != nil || current.Generation.Policy == nil || current.Generation.Activation == nil {
		return empty, ErrUntrusted
	}
	q := current.Generation.Policy.Payload
	e, report := w.Product.Entry, w.ExecutionReport
	proof := ChildWorkflowNativeCapture{Integration: w.Integration, Reviewer: w.Reviewer}
	if w.Result.Purpose != "" {
		proof.Result = &w.Result
	}
	nativeCapture, role, _, nativeError := proof.completion(e, current)
	if nativeError != nil || e.Role != role || !childCompletionReport(e, report, w.ConsumedGrant, nativeCapture) || !sameProduct(w.ConsumedGrant, current.Generation.Activation.Payload.Grant) {
		return empty, ErrUntrusted
	}

	// Canonical child service_source.native is exactly these FOUR fields. Parent
	// registeredSourceId is deliberately absent from the child receipt contract.
	native := map[string]any{"nativeSessionId": nativeCapture.SessionID, "nativeProjectId": nativeCapture.NativeProjectID, "nativeLocationDigest": nativeCapture.NativeLocationDigest, "workspaceEpoch": report.WorkspaceEpoch}
	nativeDigest := CanonicalDigest(native)
	snapshot := childFields(w.CurrentSnapshot)
	if len(snapshot) != 10 || childString(snapshot, "executionState") != "completed" || childString(snapshot, "executionReceiptDigest") != report.ReceiptDigest ||
		childString(snapshot, "desiredState") != "active" || childInteger(snapshot, "desiredRevision") != e.DesiredRevision || childString(snapshot, "role") != role ||
		childString(snapshot, "nativeContextDigest") != nativeDigest || childString(snapshot, "managedServiceReceiptDigest") != nativeDigest ||
		op.NativeContextDigest != nativeDigest || op.ManagedServiceReceiptDigest != nativeDigest {
		return empty, ErrUntrusted
	}
	var grants []struct {
		GrantID string `json:"grantId"`
		State   string `json:"state"`
		Fence   string `json:"fence"`
		Attempt int64  `json:"attempt"`
	}
	if decode(snapshot["grants"], &grants) != nil {
		return empty, ErrUntrusted
	}
	consumed := 0
	for _, grant := range grants {
		if grant.GrantID == w.ConsumedGrant.GrantID && grant.State == "consumed" && grant.Fence == e.Fence && grant.Attempt == e.Attempt {
			consumed++
		}
	}
	if consumed != 1 {
		return empty, ErrUntrusted
	}
	var scope struct {
		Owner model.ControllerOwner `json:"owner"`
	}
	var binding struct {
		WorkID         string `json:"workId"`
		ExecutionID    string `json:"executionId"`
		WorkspaceEpoch string `json:"workspaceEpoch"`
	}
	if json.Unmarshal(q.Scope, &scope) != nil || json.Unmarshal(q.Binding, &binding) != nil || binding.WorkID == "" || binding.ExecutionID == "" || binding.WorkspaceEpoch != report.WorkspaceEpoch {
		return empty, ErrUntrusted
	}
	o := scope.Owner
	subject := model.WorkflowRoleSubject{AccountID: o.AccountID, TaskID: o.TaskID, ServerID: o.ServerID, SandboxID: o.SandboxID, SandboxGeneration: o.SandboxGeneration, CellID: o.CellID, Role: role, ControllerID: o.ControllerID, ControllerRevision: o.ControllerRevision, AuthorityRevision: o.AuthorityRevision, ServiceRegistrationID: e.ServiceRegistrationID, ServiceGeneration: e.ServiceGeneration, NativeSessionID: nativeCapture.SessionID, WorkID: &binding.WorkID, ExecutionID: &binding.ExecutionID}
	if !reflect.DeepEqual(op.Subject, subject) || w.Workspace.WorkspaceDigest != w.Product.Root.Workspace.RootAttestation || w.Workspace.ContainerRoot == "" || nativeCapture.NativeLocationDigest != CanonicalDigest(map[string]any{"directory": w.Workspace.ContainerRoot, "projectId": nativeCapture.NativeProjectID, "workspaceId": nil}) {
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
	receipt := model.WorkflowRoleNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: e.ServiceRegistrationID, ServiceGeneration: e.ServiceGeneration, NativeSessionID: nativeCapture.SessionID, NativeProjectID: nativeCapture.NativeProjectID, NativeLocationDigest: nativeCapture.NativeLocationDigest, Role: role, RootAttestation: w.Product.Root.Workspace.RootAttestation, ObservedAt: stamp, Readback: model.WorkflowRoleReadback{Subject: subject, NativeContextDigest: nativeDigest}}
	payload := model.WorkflowRolePayload{FormatVersion: 1, Purpose: "workspace_workflow_role", RequestID: "wfrole_receipt_" + op.OperationDigest[7:39], TaskID: subject.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: expiry.UTC().Format(time.RFC3339Nano), ManagedServiceReceiptDigest: nativeDigest, NativeReceipt: receipt, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Subject: subject, NativeContextDigest: nativeDigest}
	if workflowcontract.Validate(workflowcontract.Producer, "payload", canonicalBytes(payload)) != nil {
		return empty, ErrUntrusted
	}
	return payload, nil
}

func (p *Producer) AttestChildWorkflowRole(op model.WorkflowRoleOperation, w ChildWorkflowRoleWitness, now time.Time) (model.WorkflowRoleEnvelope, error) {
	payload, err := p.childWorkflowRolePayload(op, w, now)
	if err != nil {
		return model.WorkflowRoleEnvelope{}, err
	}
	return p.sealWorkflowRole(op, payload, w.Product.Root.Producer, now)
}
