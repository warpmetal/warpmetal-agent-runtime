package qualification

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// A different witness from completed-child enrollment. The only eligible
// current backend phase is pending/bound with this still-issued grant. Its role lease
// is dynamically limited by the backend to its own exact reviewer target GETs.
type PreparedChildWorkflowRoleWitness struct {
	Authority       Store
	Sandbox         model.Sandbox
	Product         ChildProductWitness
	Delivery        model.ChildProductDelivery
	Receipt         model.PreparedReceipt
	ParentSessionID string
	CurrentSnapshot json.RawMessage
	Workspace       TrustedWorkspace
	Native          model.ChildPreparedCapture
}

func preparedReviewerRolePayload(op model.WorkflowRoleOperation, w PreparedChildWorkflowRoleWitness, now time.Time) (model.WorkflowRolePayload, error) {
	var empty model.WorkflowRolePayload
	e := w.Product.Entry
	if op.Validate() != nil || op.NodeTokenHash != w.Product.Root.Producer.NodeTokenHash || w.Native.ValidateFor(e, w.Receipt, w.ParentSessionID, w.Workspace.ContainerRoot, now) != nil ||
		w.Workspace.WorkspaceDigest != w.Product.Root.Workspace.RootAttestation || w.Delivery.GenerationDigest() == "" {
		return empty, ErrUntrusted
	}
	q, err := w.Authority.ChildProductSourceReadPolicy(w.Sandbox, w.Delivery, w.Product, now)
	if err != nil || q.FormatVersion != 4 || q.Purpose != "reviewer" || q.ReviewDelivery == nil || q.ReviewDelivery.FormatVersion != 2 || !sameProduct(q.PreparedReceipt, w.Receipt) || !sameProduct(q.Binding, w.Product.Binding) ||
		w.Product.Grant == nil || !sameProduct(e.ExecutionGrant, w.Product.Grant) {
		return empty, ErrUntrusted
	}
	location := CanonicalDigest(map[string]any{"directory": w.Native.Session.Directory, "projectId": w.Native.Session.ProjectID, "workspaceId": nil})
	nativeDigest := CanonicalDigest(map[string]any{"nativeSessionId": w.Native.Session.ID, "nativeProjectId": w.Native.Session.ProjectID, "nativeLocationDigest": location, "workspaceEpoch": e.Workspace.WorkspaceEpoch})
	snapshot := childFields(w.CurrentSnapshot)
	phase := childString(snapshot, "executionState")
	if len(snapshot) != 10 || (phase != "pending" && phase != "bound") || childString(snapshot, "desiredState") != "active" || childInteger(snapshot, "desiredRevision") != e.DesiredRevision || childString(snapshot, "role") != "reviewer" ||
		childString(snapshot, "nativeContextDigest") != nativeDigest || childString(snapshot, "managedServiceReceiptDigest") != nativeDigest || op.NativeContextDigest != nativeDigest || op.ManagedServiceReceiptDigest != nativeDigest {
		return empty, ErrUntrusted
	}
	var grants []struct {
		GrantID string `json:"grantId"`
		State   string `json:"state"`
		Fence   string `json:"fence"`
		Attempt int64  `json:"attempt"`
	}
	if decode(snapshot["grants"], &grants) != nil || len(grants) != 1 || grants[0].GrantID != e.ExecutionGrant.GrantID || grants[0].State != "issued" || grants[0].Fence != e.Fence || grants[0].Attempt != e.Attempt ||
		string(snapshot["executionReceiptDigest"]) != "null" || string(snapshot["children"]) != "[]" || string(snapshot["effects"]) != "[]" {
		return empty, ErrUntrusted
	}
	var scope struct {
		Owner model.ControllerOwner `json:"owner"`
	}
	var binding struct {
		WorkID               string `json:"workId"`
		ExecutionID          string `json:"executionId"`
		WorkspaceEpoch       string `json:"workspaceEpoch"`
		NativeLocationDigest string `json:"nativeLocationDigest"`
	}
	if json.Unmarshal(q.Scope, &scope) != nil || json.Unmarshal(q.Binding, &binding) != nil || binding.WorkID == "" || binding.ExecutionID == "" || binding.WorkspaceEpoch != e.Workspace.WorkspaceEpoch || binding.NativeLocationDigest != location {
		return empty, ErrUntrusted
	}
	o := scope.Owner
	subject := model.WorkflowRoleSubject{AccountID: o.AccountID, TaskID: o.TaskID, ServerID: o.ServerID, SandboxID: o.SandboxID, SandboxGeneration: o.SandboxGeneration, CellID: o.CellID, Role: "reviewer", ControllerID: o.ControllerID, ControllerRevision: o.ControllerRevision, AuthorityRevision: o.AuthorityRevision, ServiceRegistrationID: e.ServiceRegistrationID, ServiceGeneration: e.ServiceGeneration, NativeSessionID: w.Native.Session.ID, WorkID: &binding.WorkID, ExecutionID: &binding.ExecutionID}
	if !reflect.DeepEqual(subject, op.Subject) {
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
	for _, raw := range []string{q.ExpiresAt, e.ExecutionGrant.ExpiresAt} {
		limit, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || !now.Before(limit) {
			return empty, ErrUntrusted
		}
		if limit.Before(expiry) {
			expiry = limit
		}
	}
	if limit := now.Add(300 * time.Second); limit.Before(expiry) {
		expiry = limit
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	native := model.WorkflowRoleNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: e.ServiceRegistrationID, ServiceGeneration: e.ServiceGeneration, NativeSessionID: w.Native.Session.ID, NativeProjectID: w.Native.Session.ProjectID, NativeLocationDigest: location, Role: "reviewer", RootAttestation: w.Workspace.WorkspaceDigest, ObservedAt: stamp, Readback: model.WorkflowRoleReadback{Subject: subject, NativeContextDigest: nativeDigest}}
	payload := model.WorkflowRolePayload{FormatVersion: 1, Purpose: "workspace_workflow_role", RequestID: "wfrole_receipt_" + op.OperationDigest[7:39], TaskID: subject.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: expiry.UTC().Format(time.RFC3339Nano), ManagedServiceReceiptDigest: nativeDigest, NativeReceipt: native, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Subject: subject, NativeContextDigest: nativeDigest}
	if workflowcontract.Validate(workflowcontract.Producer, "payload", canonicalBytes(payload)) != nil {
		return empty, ErrUntrusted
	}
	return payload, nil
}

func (p *Producer) AttestPreparedChildWorkflowRole(op model.WorkflowRoleOperation, w PreparedChildWorkflowRoleWitness, now time.Time) (model.WorkflowRoleEnvelope, error) {
	if p == nil || p.key == nil || w.Product.Root.Producer != (model.WorkspaceRegisteredProducer{KeyID: p.config.KeyID, KeySHA256: p.config.KeySHA256, ServerID: p.config.ServerID, NodeTokenHash: p.config.NodeTokenHash}) {
		return model.WorkflowRoleEnvelope{}, ErrUntrusted
	}
	payload, err := preparedReviewerRolePayload(op, w, now)
	if err != nil {
		return model.WorkflowRoleEnvelope{}, err
	}
	return p.sealWorkflowRole(op, payload, w.Product.Root.Producer, now)
}
