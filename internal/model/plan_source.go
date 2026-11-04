package model

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type PlanSourceApproval struct {
	Reference ControllerPlanReference `json:"reference"`
	ByteCount int                     `json:"byteCount"`
}
type PlanSourceDocument struct {
	FormatVersion   int                       `json:"formatVersion"`
	Kind            string                    `json:"kind"`
	Plan            ControllerPlan            `json:"plan"`
	Owner           ControllerOwner           `json:"owner"`
	Workspace       ManagedServiceWorkspaceV1 `json:"workspace"`
	Source          PlanSourceApproval        `json:"source"`
	TargetAuthority json.RawMessage           `json:"targetAuthority"`
	DocumentDigest  string                    `json:"documentDigest"`
}
type PlanSourceReader struct {
	CaseID                    string                      `json:"caseId"`
	CaseManifestDigest        string                      `json:"caseManifestDigest"`
	CandidateDescriptorDigest string                      `json:"candidateDescriptorDigest"`
	ImplementationDigest      string                      `json:"implementationDigest"`
	Producer                  WorkspaceRegisteredProducer `json:"producer"`
}
type PlanSourceReaderConfig struct {
	FormatVersion int              `json:"formatVersion"`
	TaskID        string           `json:"taskId"`
	NodeTokenHash string           `json:"nodeTokenHash"`
	Reader        PlanSourceReader `json:"reader"`
}
type PlanSourceReadOperation struct {
	FormatVersion   int                `json:"formatVersion"`
	Kind            string             `json:"kind"`
	OperationID     string             `json:"operationId"`
	OperationDigest string             `json:"operationDigest"`
	Document        PlanSourceDocument `json:"document"`
	Reader          PlanSourceReader   `json:"reader"`
	RuntimeRevision int64              `json:"runtimeRevision"`
	ExpiresAt       string             `json:"expiresAt"`
}
type PlanSourceReadback struct {
	Operation         PlanSourceReadOperation `json:"operation"`
	ObservedAt        string                  `json:"observedAt"`
	RootDevice        uint64                  `json:"rootDevice"`
	RootInode         uint64                  `json:"rootInode"`
	SourceDevice      uint64                  `json:"sourceDevice"`
	SourceInode       uint64                  `json:"sourceInode"`
	SourceBytesBase64 string                  `json:"sourceBytesBase64"`
}
type PlanSourceReadPayload struct {
	FormatVersion   int                `json:"formatVersion"`
	Purpose         string             `json:"purpose"`
	RequestID       string             `json:"requestId"`
	OperationID     string             `json:"operationId"`
	OperationDigest string             `json:"operationDigest"`
	TaskID          string             `json:"taskId"`
	NodeTokenHash   string             `json:"nodeTokenHash"`
	BridgeVersion   string             `json:"bridgeVersion"`
	IssuedAt        string             `json:"issuedAt"`
	NotAfter        string             `json:"notAfter"`
	Readback        PlanSourceReadback `json:"readback"`
}
type PlanSourceReadEnvelope struct {
	Payload   PlanSourceReadPayload `json:"payload"`
	KeyID     string                `json:"keyId"`
	Signature string                `json:"signature"`
}
type PlanSourceReadReceipt struct {
	FormatVersion   int            `json:"formatVersion"`
	Kind            string         `json:"kind"`
	ReadID          string         `json:"readId"`
	OperationID     string         `json:"operationId"`
	OperationDigest string         `json:"operationDigest"`
	DocumentDigest  string         `json:"documentDigest"`
	Plan            ControllerPlan `json:"plan"`
	ObservedAt      string         `json:"observedAt"`
	SourceByteCount int            `json:"sourceByteCount"`
	EvidenceDigest  string         `json:"evidenceDigest"`
	ReadDigest      string         `json:"readDigest"`
}

func planObjectDigest(value any, field string) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ""
	}
	delete(fields, field)
	return WorkspaceDigest(fields)
}
func (op PlanSourceReadOperation) Validate() error {
	raw, err := json.Marshal(op)
	if err != nil || workflowcontract.Validate(workflowcontract.PlanGenesis, "readOperation", raw) != nil || op.OperationDigest != planObjectDigest(op, "operationDigest") ||
		op.Document.DocumentDigest != planObjectDigest(op.Document, "documentDigest") || op.Document.Plan.PlanRef != op.Document.Source.Reference ||
		op.Reader.Producer.ServerID != op.Document.Owner.ServerID {
		return errors.New("plan source operation refused")
	}
	return nil
}

// Byte integrity is deliberately separate from signatures and installed read
// authority. It cannot convert a genesis proof into child consumedRefs.
func (b PlanSourceReadback) ValidateBytes() error {
	raw, err := base64.StdEncoding.Strict().DecodeString(b.SourceBytesBase64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != b.SourceBytesBase64 || len(raw) < 1 || len(raw) > 262144 || !utf8.Valid(raw) ||
		len(raw) != b.Operation.Document.Source.ByteCount || fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != b.Operation.Document.Source.Reference.SourceDigest {
		return errors.New("plan source byte integrity refused")
	}
	return nil
}
func (e PlanSourceReadEnvelope) Validate() error {
	raw, err := json.Marshal(e)
	p, op := e.Payload, e.Payload.Readback.Operation
	issued, ie := time.Parse(time.RFC3339Nano, p.IssuedAt)
	observed, oe := time.Parse(time.RFC3339Nano, p.Readback.ObservedAt)
	expiry, xe := time.Parse(time.RFC3339Nano, p.NotAfter)
	operationExpiry, pe := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if err != nil || workflowcontract.ValidatePlanRead("readEnvelope", raw) != nil || op.Validate() != nil || p.Readback.ValidateBytes() != nil ||
		p.OperationID != op.OperationID || p.OperationDigest != op.OperationDigest || p.RequestID != op.OperationID || p.TaskID != op.Document.Owner.TaskID ||
		p.NodeTokenHash != op.Reader.Producer.NodeTokenHash || e.KeyID != op.Reader.Producer.KeyID || ie != nil || oe != nil || xe != nil || pe != nil ||
		observed.After(issued) || !issued.Before(expiry) || expiry.After(operationExpiry) || observed.Before(operationExpiry.Add(-60*time.Second)) {
		return errors.New("plan source envelope refused")
	}
	return nil
}
func (r PlanSourceReadReceipt) ValidateFor(e PlanSourceReadEnvelope) error {
	raw, err := json.Marshal(r)
	op := e.Payload.Readback.Operation
	if err != nil || workflowcontract.Validate(workflowcontract.PlanGenesis, "readReceipt", raw) != nil || e.Validate() != nil || r.ReadDigest != planObjectDigest(r, "readDigest") ||
		r.OperationID != op.OperationID || r.OperationDigest != op.OperationDigest || r.DocumentDigest != op.Document.DocumentDigest || !reflect.DeepEqual(r.Plan, op.Document.Plan) ||
		r.ObservedAt != e.Payload.Readback.ObservedAt || r.SourceByteCount != op.Document.Source.ByteCount || r.EvidenceDigest != WorkspaceDigest(e) {
		return errors.New("plan source receipt conflict")
	}
	return nil
}
