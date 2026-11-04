package model

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Existing producer/domain wire, restricted here to observation captures. The
// opaque nested bytes remain complete; no tool/context or source path is authority.
type WorkflowCaptureRequest struct {
	FormatVersion int             `json:"formatVersion"`
	RequestID     string          `json:"requestId"`
	Binding       json.RawMessage `json:"binding"`
	Operation     WorkflowCapture `json:"operation"`
}
type WorkflowCapture struct {
	Kind        string          `json:"kind"`
	Reconciles  json.RawMessage `json:"reconciles"`
	Observation json.RawMessage `json:"observation"`
}
type WorkflowCaptureOperation struct {
	FormatVersion   int             `json:"formatVersion"`
	OperationID     string          `json:"operationId"`
	Binding         json.RawMessage `json:"binding"`
	Operation       WorkflowCapture `json:"operation"`
	Snapshot        json.RawMessage `json:"snapshot"`
	NodeTokenHash   string          `json:"nodeTokenHash"`
	RuntimeRevision int64           `json:"runtimeRevision"`
	ExpiresAt       string          `json:"expiresAt"`
	OperationDigest string          `json:"operationDigest"`
}
type WorkflowObservationRequest struct {
	FormatVersion int             `json:"formatVersion"`
	RequestID     string          `json:"requestId"`
	Binding       json.RawMessage `json:"binding"`
	Reconciles    json.RawMessage `json:"reconciles"`
	Observation   json.RawMessage `json:"observation"`
}
type WorkflowNativeReceipt struct {
	FormatVersion         int             `json:"formatVersion"`
	OperationID           string          `json:"operationId"`
	OperationDigest       string          `json:"operationDigest"`
	ServiceRegistrationID string          `json:"serviceRegistrationId"`
	ServiceGeneration     int64           `json:"serviceGeneration"`
	NativeSessionID       string          `json:"nativeSessionId"`
	NativeProjectID       string          `json:"nativeProjectId"`
	NativeLocationDigest  string          `json:"nativeLocationDigest"`
	Role                  string          `json:"role"`
	RootAttestation       string          `json:"rootAttestation"`
	ObservedAt            string          `json:"observedAt"`
	Readback              json.RawMessage `json:"readback"`
}
type WorkflowObservationPayload struct {
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
	Request                     json.RawMessage       `json:"request"`
}
type WorkflowObservationEnvelope struct {
	Payload   WorkflowObservationPayload `json:"payload"`
	KeyID     string                     `json:"keyId"`
	Signature string                     `json:"signature"`
}
type WorkflowObservationReceipt struct {
	FormatVersion int    `json:"formatVersion"`
	ReceiptID     string `json:"receiptId"`
	ReceiptDigest string `json:"receiptDigest"`
	ExecutionID   string `json:"executionId"`
	Type          string `json:"type"`
	Status        string `json:"status"`
	CreatedAt     string `json:"createdAt"`
}

type WorkflowArtifactReceipt struct {
	FormatVersion         int             `json:"formatVersion"`
	ArtifactID            string          `json:"artifactId"`
	ExecutionID           string          `json:"executionId"`
	SourcePath            string          `json:"sourcePath"`
	Purpose               string          `json:"purpose"`
	Digest                string          `json:"digest"`
	ByteCount             int             `json:"byteCount"`
	ContentType           string          `json:"contentType"`
	NativeReadReceipt     json.RawMessage `json:"nativeReadReceipt"`
	ArtifactReceiptDigest string          `json:"artifactReceiptDigest"`
	CreatedAt             string          `json:"createdAt"`
}

func (o WorkflowCaptureOperation) ValidateFor(r WorkflowCaptureRequest, nodeHash string, revision int64, now time.Time) error {
	bad := errors.New("workflow capture operation conflict")
	raw, err := json.Marshal(r)
	if err != nil || workflowcontract.Validate(workflowcontract.Producer, "operationRequest", raw) != nil || r.Operation.Kind != "observation" {
		return bad
	}
	if o.FormatVersion != 1 || !cellV3SafeIDPattern.MatchString(o.OperationID) || o.NodeTokenHash != nodeHash || o.RuntimeRevision != revision ||
		WorkspaceDigest(o.Binding) != WorkspaceDigest(r.Binding) || WorkspaceDigest(o.Operation) != WorkspaceDigest(r.Operation) {
		return bad
	}
	if len(o.Snapshot) == 0 || string(o.Snapshot) == "null" {
		return bad
	}
	if expiry, err := time.Parse(time.RFC3339Nano, o.ExpiresAt); err != nil || !now.Before(expiry) || expiry.After(now.Add(300*time.Second)) {
		return bad
	}
	raw, _ = json.Marshal(o)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "operationDigest")
	if WorkspaceDigest(fields) != o.OperationDigest {
		return bad
	}
	return nil
}

// There is no separate schema for the backend operation response. Preserve its
// closed outer fields and opaque CURRENT snapshot; ValidateFor joins the exact
// owner request and digest before it can reach an operation-specific producer.
func DecodeWorkflowCaptureOperation(raw []byte, dst *WorkflowCaptureOperation) error {
	if len(raw) > 65536 {
		return errors.New("workflow capture operation oversized")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	return decodeStrictCellJSON(raw, dst)
}

// The owning current snapshot predates operation creation. F1 appends only the
// operation-specific childToolCaptureJoin; that join is independently checked
// against current effect authority/native capture, not borrowed as installed
// truth. All original lifecycle/workflow snapshot fields must still match.
func (o WorkflowCaptureOperation) MatchesCurrentSnapshot(current json.RawMessage) bool {
	var granted, actual map[string]json.RawMessage
	if len(o.Snapshot) > 65536 || len(current) > 65536 || rejectDuplicateJSONFields(o.Snapshot) != nil || rejectDuplicateJSONFields(current) != nil || decodeStrictCellJSON(o.Snapshot, &granted) != nil || decodeStrictCellJSON(current, &actual) != nil || granted == nil || actual == nil {
		return false
	}
	delete(granted, "childToolCaptureJoin")
	if _, ok := actual["childToolCaptureJoin"]; ok {
		return false
	}
	return WorkspaceDigest(granted) == WorkspaceDigest(actual)
}
func (e WorkflowObservationEnvelope) Validate() error {
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > 65536 || workflowcontract.Validate(workflowcontract.Producer, "envelope", raw) != nil ||
		e.Payload.Purpose != "workspace_workflow_observation" || e.Payload.NativeReceipt.OperationID != e.Payload.OperationID ||
		e.Payload.NativeReceipt.OperationDigest != e.Payload.OperationDigest || WorkspaceDigest(e.Payload.NativeReceipt.Readback) != WorkspaceDigest(e.Payload.Request) {
		return errors.New("workflow observation envelope refused")
	}
	n := e.Payload.NativeReceipt
	var request struct {
		Binding     json.RawMessage `json:"binding"`
		Reconciles  json.RawMessage `json:"reconciles"`
		Observation json.RawMessage `json:"observation"`
	}
	if decodeStrictCellJSON(e.Payload.Request, &request) != nil {
		return errors.New("workflow observation request refused")
	}
	var b struct {
		ServiceRegistrationID string `json:"serviceRegistrationId"`
		ServiceGeneration     int64  `json:"serviceGeneration"`
		NativeSessionID       string `json:"nativeSessionId"`
		NativeProjectID       string `json:"nativeProjectId"`
		NativeLocationDigest  string `json:"nativeLocationDigest"`
		RootAttestation       string `json:"rootAttestation"`
	}
	if json.Unmarshal(request.Binding, &b) != nil || n.ServiceRegistrationID != b.ServiceRegistrationID || n.ServiceGeneration != b.ServiceGeneration || n.NativeSessionID != b.NativeSessionID || n.NativeProjectID != b.NativeProjectID || n.NativeLocationDigest != b.NativeLocationDigest || n.RootAttestation != b.RootAttestation {
		return errors.New("workflow observation native binding conflict")
	}
	issued, e1 := time.Parse(time.RFC3339Nano, e.Payload.IssuedAt)
	observed, e2 := time.Parse(time.RFC3339Nano, n.ObservedAt)
	expiry, e3 := time.Parse(time.RFC3339Nano, e.Payload.NotAfter)
	if e1 != nil || e2 != nil || e3 != nil || observed.Before(issued) || !observed.Before(expiry) || !issued.Before(expiry) || expiry.Sub(issued) > 300*time.Second {
		return errors.New("workflow observation expiry conflict")
	}
	return nil
}
