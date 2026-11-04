package model

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Additive consumers of the existing canonical facts variants. Observation
// operations keep their own closed DTO and cannot be relabeled as facts.
type WorkflowReceiptRef struct {
	ReceiptID     string `json:"receiptId"`
	ReceiptDigest string `json:"receiptDigest"`
}
type WorkflowFactsSelector struct {
	Kind    string              `json:"kind"`
	Receipt *WorkflowReceiptRef `json:"receipt,omitempty"`
}
type WorkflowFactsRequest struct {
	FormatVersion int                   `json:"formatVersion"`
	RequestID     string                `json:"requestId"`
	Binding       json.RawMessage       `json:"binding"`
	Operation     WorkflowFactsSelector `json:"operation"`
}
type WorkflowFactsOperation struct {
	FormatVersion   int                   `json:"formatVersion"`
	OperationID     string                `json:"operationId"`
	Binding         json.RawMessage       `json:"binding"`
	Operation       WorkflowFactsSelector `json:"operation"`
	Snapshot        json.RawMessage       `json:"snapshot"`
	NodeTokenHash   string                `json:"nodeTokenHash"`
	RuntimeRevision int64                 `json:"runtimeRevision"`
	ExpiresAt       string                `json:"expiresAt"`
	OperationDigest string                `json:"operationDigest"`
}
type WorkflowFactsPayload struct {
	FormatVersion               int                   `json:"formatVersion"`
	Purpose                     string                `json:"purpose"`
	RequestID                   string                `json:"requestId"`
	TaskID                      string                `json:"taskId"`
	NodeTokenHash               string                `json:"nodeTokenHash"`
	BridgeVersion               string                `json:"bridgeVersion"`
	IssuedAt                    string                `json:"issuedAt"`
	NotAfter                    string                `json:"notAfter"`
	ManagedServiceReceiptDigest string                `json:"managedServiceReceiptDigest"`
	NativeReceipt               WorkflowNativeReceipt `json:"nativeReceipt"`
	OperationID                 string                `json:"operationId"`
	OperationDigest             string                `json:"operationDigest"`
	Binding                     json.RawMessage       `json:"binding"`
	Readback                    json.RawMessage       `json:"readback"`
}
type WorkflowFactsEnvelope struct {
	Payload   WorkflowFactsPayload `json:"payload"`
	KeyID     string               `json:"keyId"`
	Signature string               `json:"signature"`
}
type WorkflowFactsReceipt struct {
	FormatVersion int    `json:"formatVersion"`
	ProofID       string `json:"proofId"`
	ProofDigest   string `json:"proofDigest"`
	ExpiresAt     string `json:"expiresAt"`
}

func (r WorkflowFactsRequest) Validate() error {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 65536 || workflowcontract.Validate(workflowcontract.Producer, "operationRequest", raw) != nil || (r.Operation.Kind != "execution_settlement" && r.Operation.Kind != "integration_candidate") {
		return errors.New("workflow facts request refused")
	}
	return nil
}
func DecodeWorkflowFactsOperation(raw []byte, dst *WorkflowFactsOperation) error {
	if len(raw) > 65536 || rejectDuplicateJSONFields(raw) != nil {
		return errors.New("workflow facts operation framing refused")
	}
	return decodeStrictCellJSON(raw, dst)
}
func (o WorkflowFactsOperation) ValidateFor(r WorkflowFactsRequest, nodeHash string, revision int64, now time.Time) error {
	bad := errors.New("workflow facts operation conflict")
	if r.Validate() != nil || o.FormatVersion != 1 || !cellV3SafeIDPattern.MatchString(o.OperationID) || o.NodeTokenHash != nodeHash || o.RuntimeRevision != revision || WorkspaceDigest(o.Binding) != WorkspaceDigest(r.Binding) || WorkspaceDigest(o.Operation) != WorkspaceDigest(r.Operation) {
		return bad
	}
	var snapshot map[string]json.RawMessage
	if len(o.Snapshot) > 65536 || rejectDuplicateJSONFields(o.Snapshot) != nil || json.Unmarshal(o.Snapshot, &snapshot) != nil || len(snapshot) == 0 {
		return bad
	}
	candidate, present := snapshot["candidate"]
	if (o.Operation.Kind == "integration_candidate" && (!present || len(candidate) == 0 || string(candidate) == "null")) || (o.Operation.Kind == "execution_settlement" && present) {
		return bad
	}
	expiry, err := time.Parse(time.RFC3339Nano, o.ExpiresAt)
	if err != nil || !now.Before(expiry) || expiry.After(now.Add(300*time.Second)) {
		return bad
	}
	raw, _ := json.Marshal(o)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "operationDigest")
	if WorkspaceDigest(fields) != o.OperationDigest {
		return bad
	}
	return nil
}

// The caller must supply the independently reconstructed complete snapshot. For
// candidate facts that includes the retained acknowledged integration candidate;
// this comparison deliberately does not strip a granted candidate field.
func (o WorkflowFactsOperation) MatchesCurrentSnapshot(current json.RawMessage) bool {
	return len(current) > 0 && len(current) <= 65536 && rejectDuplicateJSONFields(current) == nil && WorkspaceDigest(current) == WorkspaceDigest(o.Snapshot)
}
func (e WorkflowFactsEnvelope) Validate() error {
	bad := errors.New("workflow facts envelope refused")
	raw, err := json.Marshal(e)
	p := e.Payload
	n := p.NativeReceipt
	if err != nil || len(raw) > 65536 || workflowcontract.Validate(workflowcontract.Producer, "envelope", raw) != nil || p.Purpose != "workspace_workflow_facts" || n.OperationID != p.OperationID || n.OperationDigest != p.OperationDigest {
		return bad
	}
	var binding struct {
		ServiceRegistrationID string `json:"serviceRegistrationId"`
		ServiceGeneration     int64  `json:"serviceGeneration"`
		NativeSessionID       string `json:"nativeSessionId"`
		NativeProjectID       string `json:"nativeProjectId"`
		NativeLocationDigest  string `json:"nativeLocationDigest"`
		RootAttestation       string `json:"rootAttestation"`
	}
	if json.Unmarshal(p.Binding, &binding) != nil || n.ServiceRegistrationID != binding.ServiceRegistrationID || n.ServiceGeneration != binding.ServiceGeneration || n.NativeSessionID != binding.NativeSessionID || n.NativeProjectID != binding.NativeProjectID || n.NativeLocationDigest != binding.NativeLocationDigest || n.RootAttestation != binding.RootAttestation {
		return bad
	}
	var readback map[string]json.RawMessage
	if rejectDuplicateJSONFields(p.Readback) != nil || json.Unmarshal(p.Readback, &readback) != nil {
		return bad
	}
	var nativeDigest, sid, role string
	if json.Unmarshal(readback["nativeReceiptDigest"], &nativeDigest) != nil || nativeDigest != WorkspaceDigest(n) || json.Unmarshal(readback["nativeSessionId"], &sid) != nil || json.Unmarshal(readback["nativeRole"], &role) != nil || sid != n.NativeSessionID || role != n.Role {
		return bad
	}
	delete(readback, "nativeReceiptDigest")
	if WorkspaceDigest(readback) != WorkspaceDigest(n.Readback) {
		return bad
	}
	issued, e1 := time.Parse(time.RFC3339Nano, p.IssuedAt)
	observed, e2 := time.Parse(time.RFC3339Nano, n.ObservedAt)
	expiry, e3 := time.Parse(time.RFC3339Nano, p.NotAfter)
	if e1 != nil || e2 != nil || e3 != nil || observed.Before(issued) || !observed.Before(expiry) || !issued.Before(expiry) || expiry.Sub(issued) > 300*time.Second {
		return bad
	}
	return nil
}
func (r WorkflowFactsReceipt) ValidateFor(e WorkflowFactsEnvelope, now time.Time) error {
	expiry, e1 := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	expected, e2 := time.Parse(time.RFC3339Nano, e.Payload.NotAfter)
	if e.Validate() != nil || r.FormatVersion != 1 || !cellV3SafeIDPattern.MatchString(r.ProofID) || r.ProofDigest != WorkspaceDigest(e) || e1 != nil || e2 != nil || !expiry.Equal(expected) || !now.Before(expiry) {
		return errors.New("workflow facts retention conflict")
	}
	return nil
}
