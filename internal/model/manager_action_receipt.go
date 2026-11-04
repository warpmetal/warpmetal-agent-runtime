package model

import (
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type IntentReceipt struct {
	FormatVersion     int              `json:"formatVersion"`
	ContextID         string           `json:"contextId"`
	OperationID       string           `json:"operationId"`
	AssociationDigest string           `json:"associationDigest"`
	Member            IntentAcceptance `json:"member"`
}

// Closed acceptance union. A single member is never represented as half of a
// pair, and retained legacy receipts serialize to their original wire shape.
type ManagerActionReceipt struct {
	pair   *IntentPairReceipt
	single *IntentReceipt
}

func (r *ManagerActionReceipt) UnmarshalJSON(raw []byte) error {
	var version struct {
		FormatVersion int `json:"formatVersion"`
	}
	if err := json.Unmarshal(raw, &version); err != nil {
		return err
	}
	*r = ManagerActionReceipt{}
	if version.FormatVersion == 1 {
		var pair IntentPairReceipt
		if err := DecodeManagerContract("intentPairReceipt", raw, &pair); err != nil {
			return err
		}
		r.pair = &pair
	} else if version.FormatVersion == 2 {
		var single IntentReceipt
		if err := workflowcontract.Validate(workflowcontract.ManagerSingle, "intentReceipt2", raw); err != nil {
			return err
		}
		if err := decodeStrictCellJSON(raw, &single); err != nil {
			return err
		}
		r.single = &single
	} else {
		return errors.New("manager acceptance version refused")
	}
	return nil
}

// Backend controller_output owns this association recipe. It binds the actual
// signed output payload, not a hash of the receipt that merely references it.
func (r ManagerActionReceipt) ValidateOutput(op ControllerOutputOperation, proof ControllerOutputEnvelope) error {
	if r.pair != nil {
		return nil // The unchanged legacy selection owns its historical validation.
	}
	if r.single == nil || op.FormatVersion != 4 || proof.Payload.OperationID != op.OperationID || proof.Payload.OperationDigest != op.OperationDigest || WorkspaceDigest(proof.Payload.NativeReceipt.Lineage) != WorkspaceDigest(op.Lineage) {
		return errors.New("single manager output association refused")
	}
	resource := op.Context.ContextID
	if op.Context.Target.ResourceID != nil {
		resource = *op.Context.Target.ResourceID
	}
	association := map[string]any{"operationDigest": op.OperationDigest, "proofDigest": WorkspaceDigest(proof.Payload), "lineageDigest": WorkspaceDigest(op.Lineage), "body": op.Proposal.Body, "action": op.Context.Target.Kind, "resource": resource}
	if WorkspaceDigest(association) != r.single.AssociationDigest {
		return errors.New("single manager output proof association mismatch")
	}
	return nil
}

func (r ManagerActionReceipt) MarshalJSON() ([]byte, error) {
	if r.pair != nil && r.single == nil {
		return json.Marshal(r.pair)
	}
	if r.single != nil && r.pair == nil {
		return json.Marshal(r.single)
	}
	return nil, errors.New("manager acceptance missing")
}

func (r ManagerActionReceipt) AssociationDigest() string {
	if r.pair != nil {
		return r.pair.AssociationDigest
	}
	if r.single != nil {
		return r.single.AssociationDigest
	}
	return ""
}

func (r ManagerActionReceipt) Members() []string {
	if r.pair != nil {
		return []string{"first", "second"}
	}
	if r.single != nil {
		return []string{"member"}
	}
	return nil
}

func (r ManagerActionReceipt) Decision(member string) (IntentAcceptance, error) {
	if r.pair != nil && member == "first" {
		return r.pair.First, nil
	}
	if r.pair != nil && member == "second" {
		return r.pair.Second, nil
	}
	if r.single != nil && member == "member" {
		return r.single.Member, nil
	}
	return IntentAcceptance{}, errors.New("manager acceptance member refused")
}

func (r ManagerActionReceipt) Select(op ControllerOutputOperation, member string) (ManagerIntentSelection, error) {
	if r.pair != nil {
		return op.ManagerIntentSelection(*r.pair, member)
	}
	var result ManagerIntentSelection
	bad := errors.New("single manager intent association refused")
	if r.single == nil || member != "member" {
		return result, bad
	}
	receipt := *r.single
	raw, err := json.Marshal(op)
	var verified ControllerOutputOperation
	if err != nil || json.Unmarshal(raw, &verified) != nil || op.FormatVersion != 4 || op.Subject.Role != "manager" || receipt.ContextID != op.Context.ContextID || receipt.OperationID != op.OperationID || (op.Context.Target.Kind != "manager_work_intent" && op.Context.Target.Kind != "manager_intent") {
		return result, bad
	}
	facts, err := op.Context.Target.retainedFacts()
	if err != nil {
		return result, bad
	}
	intent, decision := workflowObject(facts["intent"]), receipt.Member
	ref, _ := json.Marshal(decision.Intent)
	expected, _ := json.Marshal(map[string]json.RawMessage{"intentId": intent["intentId"], "intentRevision": intent["intentRevision"], "intentDigest": intent["intentDigest"]})
	body := workflowObject(op.Proposal.Body)
	if !sameWorkflowFact(ref, expected) || decision.ExpectedAdmissionRevision != workflowInteger(intent["expectedAdmissionRevision"]) || decision.Choice != "admit" || decision.Handle == nil {
		return result, bad
	}
	if op.Context.Target.Kind == "manager_work_intent" {
		if workflowString(body["choice"]) != "adopt" {
			return result, bad
		}
	} else if workflowString(workflowObject(body["member"])["choice"]) != decision.Choice {
		return result, bad
	}
	scope, prepare := workflowObject(intent["scope"]), workflowObject(intent["prepareBody"])
	if json.Unmarshal(scope["owner"], &result.Owner) != nil {
		return result, bad
	}
	result.Ref, result.ExpectedAdmissionRevision = decision.Intent, decision.ExpectedAdmissionRevision
	result.AllocationID, result.PrepareRequestID = workflowString(intent["allocationId"]), workflowString(prepare["requestId"])
	result.AssignmentRequestID, result.GrantRequestID = workflowString(intent["assignmentRequestId"]), workflowString(intent["grantRequestId"])
	result.LifecycleRequestDigest, result.NotAfter = workflowString(intent["lifecycleRequestDigest"]), workflowString(intent["notAfter"])
	return result, nil
}
