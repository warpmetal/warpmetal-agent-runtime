package model

import (
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type IntentRef struct {
	IntentID       string `json:"intentId"`
	IntentRevision int64  `json:"intentRevision"`
	IntentDigest   string `json:"intentDigest"`
}
type IntentAcceptance struct {
	Intent                    IntentRef `json:"intent"`
	ExpectedAdmissionRevision int64     `json:"expectedAdmissionRevision"`
	Choice                    string    `json:"choice"`
	DecisionDigest            string    `json:"decisionDigest"`
	Handle                    *string   `json:"handle"`
	ReceiptDigest             string    `json:"receiptDigest"`
}
type IntentPairReceipt struct {
	FormatVersion     int              `json:"formatVersion"`
	ContextID         string           `json:"contextId"`
	OperationID       string           `json:"operationId"`
	AssociationDigest string           `json:"associationDigest"`
	First             IntentAcceptance `json:"first"`
	Second            IntentAcceptance `json:"second"`
}
type IntentHandle struct {
	FormatVersion       int             `json:"formatVersion"`
	HandleID            string          `json:"handleId"`
	HandleDigest        string          `json:"handleDigest"`
	ContextID           string          `json:"contextId"`
	OperationID         string          `json:"operationId"`
	AssociationDigest   string          `json:"associationDigest"`
	Intent              IntentRef       `json:"intent"`
	Owner               ControllerOwner `json:"owner"`
	RoleBindingID       string          `json:"roleBindingId"`
	RoleBindingRevision int64           `json:"roleBindingRevision"`
	AllocationID        string          `json:"allocationId"`
	NotAfter            string          `json:"notAfter"`
}
type IntentPrepareRequest struct {
	FormatVersion             int    `json:"formatVersion"`
	RequestID                 string `json:"requestId"`
	HandleID                  string `json:"handleId"`
	ExpectedAdmissionRevision int64  `json:"expectedAdmissionRevision"`
}
type IntentPreparationReference struct {
	FormatVersion          int       `json:"formatVersion"`
	HandleID               string    `json:"handleId"`
	Intent                 IntentRef `json:"intent"`
	PreparationID          string    `json:"preparationId"`
	LifecycleRequestDigest string    `json:"lifecycleRequestDigest"`
}
type ActualPreparationAssociation struct {
	FormatVersion     int             `json:"formatVersion"`
	HandleID          string          `json:"handleId"`
	Intent            IntentRef       `json:"intent"`
	PreparationID     string          `json:"preparationId"`
	PreparedReceipt   PreparedReceipt `json:"preparedReceipt"`
	Binding           json.RawMessage `json:"binding"`
	AssignmentBody    json.RawMessage `json:"assignmentBody"`
	AssociationDigest string          `json:"associationDigest"`
}
type IntentGrantRequest struct {
	FormatVersion         int    `json:"formatVersion"`
	RequestID             string `json:"requestId"`
	HandleID              string `json:"handleId"`
	PreparedReceiptDigest string `json:"preparedReceiptDigest"`
	AssignmentDigest      string `json:"assignmentDigest"`
	ProductPolicyDigest   string `json:"productPolicyDigest"`
}
type ChildAdmissionAssociation struct {
	FormatVersion                int                  `json:"formatVersion"`
	HandleID                     string               `json:"handleId"`
	PreparationAssociationDigest string               `json:"preparationAssociationDigest"`
	Assignment                   json.RawMessage      `json:"assignment"`
	AllocationID                 string               `json:"allocationId"`
	ReservationID                string               `json:"reservationId"`
	PolicyDigest                 string               `json:"policyDigest"`
	ActivationDigest             string               `json:"activationDigest"`
	Grant                        CellExecutionGrantV3 `json:"grant"`
	AssociationDigest            string               `json:"associationDigest"`
}

// These are closed owner definitions, not generic response envelopes. Nested
// raw binding/assignment values are preserved and checked by the owner schema.
func DecodeManagerContract(definition string, raw []byte, dst any) error {
	if err := workflowcontract.Validate(workflowcontract.Manager, definition, raw); err != nil {
		return err
	}
	return decodeStrictCellJSON(raw, dst)
}

// ManagerIntentSelection is a read-only selection from accepted context+receipt;
// it is NOT a handle, credential, preparation or V3 execution grant.
type ManagerIntentSelection struct {
	Ref                       IntentRef
	Owner                     ControllerOwner
	AllocationID              string
	PrepareRequestID          string
	AssignmentRequestID       string
	GrantRequestID            string
	LifecycleRequestDigest    string
	ExpectedAdmissionRevision int64
	NotAfter                  string
}

func (op ControllerOutputOperation) ManagerIntentSelection(receipt IntentPairReceipt, member string) (ManagerIntentSelection, error) {
	var result ManagerIntentSelection
	bad := errors.New("manager intent association refused")
	operationRaw, err := json.Marshal(op)
	var verified ControllerOutputOperation
	if err != nil || json.Unmarshal(operationRaw, &verified) != nil {
		return result, bad
	}
	raw, err := json.Marshal(receipt)
	if err != nil || workflowcontract.Validate(workflowcontract.Manager, "intentPairReceipt", raw) != nil || op.FormatVersion != 2 ||
		receipt.ContextID != op.Context.ContextID || receipt.OperationID != op.OperationID ||
		(op.Context.Target.Kind != "manager_work_intents" && op.Context.Target.Kind != "manager_intent_pair") || op.Subject.Role != "manager" {
		return result, bad
	}
	if !managerAssociationDigest(receipt, receipt.AssociationDigest) {
		return result, bad
	}
	facts, err := op.Context.Target.retainedFacts()
	if err != nil {
		return result, bad
	}
	members := workflowObject(facts["members"])
	body := workflowObject(op.Proposal.Body)
	for _, name := range []string{"first", "second"} {
		decision := receipt.First
		if name == "second" {
			decision = receipt.Second
		}
		intent := workflowObject(members[name])
		ref, _ := json.Marshal(decision.Intent)
		selected, _ := json.Marshal(map[string]json.RawMessage{"intentId": intent["intentId"], "intentRevision": intent["intentRevision"], "intentDigest": intent["intentDigest"]})
		if !sameWorkflowFact(ref, selected) || decision.ExpectedAdmissionRevision != workflowInteger(intent["expectedAdmissionRevision"]) {
			return result, bad
		}
		if op.Context.Target.Kind == "manager_intent_pair" {
			proposed := workflowObject(workflowObject(body["members"])[name])
			if decision.Choice != workflowString(proposed["choice"]) {
				return result, bad
			}
		} else if decision.Choice == "admit" && workflowString(body["choice"]) != "adopt" {
			return result, bad
		}
	}
	decision := receipt.First
	if member == "second" {
		decision = receipt.Second
	} else if member != "first" {
		return result, bad
	}
	if decision.Choice != "admit" || decision.Handle == nil {
		return result, bad
	}
	intent := workflowObject(members[member])
	scope := workflowObject(intent["scope"])
	if json.Unmarshal(scope["owner"], &result.Owner) != nil {
		return result, bad
	}
	prepare := workflowObject(intent["prepareBody"])
	result.Ref = decision.Intent
	result.AllocationID = workflowString(intent["allocationId"])
	result.PrepareRequestID = workflowString(prepare["requestId"])
	result.AssignmentRequestID = workflowString(intent["assignmentRequestId"])
	result.GrantRequestID = workflowString(intent["grantRequestId"])
	result.LifecycleRequestDigest = workflowString(intent["lifecycleRequestDigest"])
	result.ExpectedAdmissionRevision = decision.ExpectedAdmissionRevision
	result.NotAfter = workflowString(intent["notAfter"])
	return result, nil
}

func managerAssociationDigest(value any, digest string) bool {
	raw, err := json.Marshal(value)
	if err != nil {
		return false
	}
	fields := workflowObject(raw)
	delete(fields, "associationDigest")
	return WorkspaceDigest(fields) == digest
}
func (a ActualPreparationAssociation) ValidateIntegrity() error {
	raw, err := json.Marshal(a)
	if err != nil || workflowcontract.Validate(workflowcontract.Manager, "actualPreparationAssociation", raw) != nil || !managerAssociationDigest(a, a.AssociationDigest) || a.PreparedReceipt.ValidateIntegrity() != nil {
		return errors.New("actual preparation association refused")
	}
	binding, assignment := workflowObject(a.Binding), workflowObject(a.AssignmentBody)
	if workflowString(binding["preparationId"]) != a.PreparationID || !sameWorkflowFact(assignment["binding"], a.Binding) {
		return errors.New("actual preparation binding conflict")
	}
	tupleRaw, _ := json.Marshal(a.PreparedReceipt.PreparedTuple)
	tuple := workflowObject(tupleRaw)
	// The existing domain binding deliberately has no controllerId/revision or
	// sandboxId fields. Those remain in the V3 tuple and are joined to the current
	// owner/entry by its caller; comparing nonexistent binding fields rejects every
	// actual backend association. Compare ALL authoritative fields shared here.
	for _, field := range []string{"serviceRegistrationId", "serviceGeneration", "sandboxGeneration", "parentExecutionId", "parentPacketId", "packetId", "packetRevision", "configDigest", "profileDigest", "attempt", "fence"} {
		if !sameWorkflowFact(binding[field], tuple[field]) {
			return errors.New("actual prepared tuple binding conflict")
		}
	}
	workspace := map[string]json.RawMessage{}
	for _, field := range []string{"selectionId", "projectId", "workspaceEpoch", "scopeRevision", "rootAttestation"} {
		workspace[field] = binding[field]
	}
	if WorkspaceDigest(workspace) != a.PreparedReceipt.PreparedTuple.WorkspaceDigest {
		return errors.New("actual prepared workspace binding conflict")
	}
	return nil
}
func (a ChildAdmissionAssociation) ValidateIntegrity() error {
	raw, err := json.Marshal(a)
	if err != nil || workflowcontract.Validate(workflowcontract.Manager, "childAdmissionAssociation", raw) != nil || !managerAssociationDigest(a, a.AssociationDigest) {
		return errors.New("child admission association refused")
	}
	return nil
}
