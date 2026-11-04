package model

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Existing producer subject/role envelope. Parent roles have no work/execution;
// child roles name both exact owning IDs. The protected producer independently
// verifies the current native binding before an operation can become a proof.
type WorkflowRoleSubject struct {
	AccountID             string  `json:"account_id"`
	TaskID                string  `json:"task_id"`
	ServerID              string  `json:"server_id"`
	SandboxID             string  `json:"sandbox_id"`
	SandboxGeneration     int64   `json:"sandbox_generation"`
	CellID                string  `json:"cell_id"`
	Role                  string  `json:"role"`
	ControllerID          string  `json:"controller_id"`
	ControllerRevision    int64   `json:"controller_revision"`
	AuthorityRevision     int64   `json:"authority_revision"`
	ServiceRegistrationID string  `json:"service_registration_id"`
	ServiceGeneration     int64   `json:"service_generation"`
	NativeSessionID       string  `json:"native_session_id"`
	WorkID                *string `json:"work_id"`
	ExecutionID           *string `json:"execution_id"`
}

func CurrentWorkflowRoleSubject(parent ControllerParentIntent, native ManagedNativeRegistrationV1) WorkflowRoleSubject {
	o := parent.Owner
	return WorkflowRoleSubject{o.AccountID, o.TaskID, o.ServerID, o.SandboxID, o.SandboxGeneration, o.CellID, parent.Role, o.ControllerID, o.ControllerRevision, o.AuthorityRevision, parent.ServiceRegistrationID, parent.ServiceGeneration, native.NativeSessionID, nil, nil}
}

type WorkflowRoleOperationRequest struct {
	FormatVersion int                 `json:"formatVersion"`
	RequestID     string              `json:"requestId"`
	Subject       WorkflowRoleSubject `json:"subject"`
}
type WorkflowRoleOperation struct {
	FormatVersion               int                 `json:"formatVersion"`
	OperationID                 string              `json:"operationId"`
	OperationDigest             string              `json:"operationDigest"`
	Subject                     WorkflowRoleSubject `json:"subject"`
	NativeContextDigest         string              `json:"nativeContextDigest"`
	ManagedServiceReceiptDigest string              `json:"managedServiceReceiptDigest"`
	NodeTokenHash               string              `json:"nodeTokenHash"`
	ExpiresAt                   string              `json:"expiresAt"`
}

func (o WorkflowRoleOperation) Validate() error {
	raw, _ := json.Marshal(o.Subject)
	expiry, err := time.Parse(time.RFC3339Nano, o.ExpiresAt)
	fields := map[string]any{"formatVersion": o.FormatVersion, "operationId": o.OperationID, "subject": o.Subject, "nativeContextDigest": o.NativeContextDigest, "managedServiceReceiptDigest": o.ManagedServiceReceiptDigest, "nodeTokenHash": o.NodeTokenHash, "expiresAt": o.ExpiresAt}
	roleScope := false
	switch o.Subject.Role {
	case "manager", "orchestrator":
		roleScope = o.Subject.WorkID == nil && o.Subject.ExecutionID == nil
	case "worker", "reviewer":
		roleScope = o.Subject.WorkID != nil && o.Subject.ExecutionID != nil
	}
	if err != nil || expiry.IsZero() || o.FormatVersion != 1 || !strings.HasPrefix(o.OperationID, "wfroleop_") || workflowcontract.Validate(workflowcontract.Producer, "subject", raw) != nil || !roleScope || o.OperationDigest != WorkspaceDigest(fields) || len(o.NodeTokenHash) != 64 {
		return errors.New("workflow role operation conflict")
	}
	for _, value := range []struct{ definition, value string }{{"id", o.OperationID}, {"digest", o.NativeContextDigest}, {"digest", o.ManagedServiceReceiptDigest}} {
		raw, _ := json.Marshal(value.value)
		if workflowcontract.Validate(workflowcontract.Producer, value.definition, raw) != nil {
			return errors.New("workflow role operation identity conflict")
		}
	}
	for _, r := range o.NodeTokenHash {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return errors.New("workflow role node conflict")
		}
	}
	return nil
}

type WorkflowRoleReadback struct {
	Subject             WorkflowRoleSubject `json:"subject"`
	NativeContextDigest string              `json:"nativeContextDigest"`
}
type WorkflowRoleNativeReceipt struct {
	FormatVersion         int                  `json:"formatVersion"`
	OperationID           string               `json:"operationId"`
	OperationDigest       string               `json:"operationDigest"`
	ServiceRegistrationID string               `json:"serviceRegistrationId"`
	ServiceGeneration     int64                `json:"serviceGeneration"`
	NativeSessionID       string               `json:"nativeSessionId"`
	NativeProjectID       string               `json:"nativeProjectId"`
	NativeLocationDigest  string               `json:"nativeLocationDigest"`
	Role                  string               `json:"role"`
	RootAttestation       string               `json:"rootAttestation"`
	ObservedAt            string               `json:"observedAt"`
	Readback              WorkflowRoleReadback `json:"readback"`
}
type WorkflowRolePayload struct {
	FormatVersion               int                       `json:"formatVersion"`
	Purpose                     string                    `json:"purpose"`
	RequestID                   string                    `json:"requestId"`
	TaskID                      string                    `json:"taskId"`
	NodeTokenHash               string                    `json:"nodeTokenHash"`
	BridgeVersion               string                    `json:"bridgeVersion"`
	IssuedAt                    string                    `json:"issuedAt"`
	NotAfter                    string                    `json:"notAfter"`
	ManagedServiceReceiptDigest string                    `json:"managedServiceReceiptDigest"`
	NativeReceipt               WorkflowRoleNativeReceipt `json:"nativeReceipt"`
	OperationID                 string                    `json:"operationId"`
	OperationDigest             string                    `json:"operationDigest"`
	Subject                     WorkflowRoleSubject       `json:"subject"`
	NativeContextDigest         string                    `json:"nativeContextDigest"`
}
type WorkflowRoleEnvelope struct {
	Payload   WorkflowRolePayload `json:"payload"`
	KeyID     string              `json:"keyId"`
	Signature string              `json:"signature"`
}

func (e WorkflowRoleEnvelope) Validate() error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if e.Payload.Purpose != "workspace_workflow_role" {
		return errors.New("workflow role proof conflict")
	}
	return workflowcontract.Validate(workflowcontract.Producer, "envelope", raw)
}

type WorkflowRoleEnrollment struct {
	FormatVersion       int    `json:"formatVersion"`
	RoleBindingID       string `json:"roleBindingId"`
	RoleBindingRevision int64  `json:"roleBindingRevision"`
	ExpiresAt           string `json:"expiresAt"`
	Lease               string `json:"lease"`
}

func (e WorkflowRoleEnrollment) Validate() error {
	_, err := time.Parse(time.RFC3339Nano, e.ExpiresAt)
	if err != nil || e.FormatVersion != 1 || !strings.HasPrefix(e.RoleBindingID, "wrole_") || e.RoleBindingRevision < 1 || !strings.HasPrefix(e.Lease, "wfl_") || len(e.Lease) > 256 || strings.ContainsAny(e.Lease, "\r\n\x00") {
		return errors.New("workflow role enrollment conflict")
	}
	return nil
}
