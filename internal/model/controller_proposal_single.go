package model

import (
	"encoding/json"
	"errors"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// The closed context4 target supplies one intent. Model text may choose its
// allowed disposition, never add a second allocation or rewrite selected scope.
func controllerProposalSingle(c ControllerApprovedInputContext, text string) (ControllerWorkflowProposal, error) {
	bad := errors.New("single controller proposal mismatch")
	out := ControllerWorkflowProposal{Target: c.Target, Body: json.RawMessage(text)}
	raw, err := json.Marshal(out)
	if err != nil || workflowcontract.Validate(workflowcontract.ManagerSingle, "controllerProposal3", raw) != nil {
		return ControllerWorkflowProposal{}, bad
	}
	target, err := c.Target.retainedFacts()
	if err != nil {
		return ControllerWorkflowProposal{}, bad
	}
	body := workflowObject([]byte(text))
	plan, _ := json.Marshal(c.Plan)
	if workflowString(body["requestId"]) != c.WorkflowRequestID {
		return ControllerWorkflowProposal{}, bad
	}
	if selectedPlan, present := body["plan"]; present && !sameWorkflowFact(selectedPlan, plan) {
		return ControllerWorkflowProposal{}, bad
	}
	switch c.Target.Kind {
	case "manager_work_intent":
		advice, intent := workflowObject(target["advice"]), workflowObject(target["intent"])
		if c.Target.ResourceID == nil || workflowString(advice["adviceId"]) != *c.Target.ResourceID || !sameWorkflowFact(advice["plan"], plan) || !sameWorkflowFact(body["expectedAdviceRevision"], advice["adviceRevision"]) || !sameWorkflowFact(intent["plan"], plan) || workflowString(intent["purpose"]) != "implement" {
			return ControllerWorkflowProposal{}, bad
		}
		var lanes []json.RawMessage
		if json.Unmarshal(body["lanes"], &lanes) != nil {
			return ControllerWorkflowProposal{}, bad
		}
		if workflowString(body["choice"]) == "decline" {
			if len(lanes) != 0 {
				return ControllerWorkflowProposal{}, bad
			}
			return out, nil
		}
		if len(lanes) != 1 {
			return ControllerWorkflowProposal{}, bad
		}
		lane := workflowObject(lanes[0])
		packet := workflowObject(workflowObject(workflowObject(intent["prepareBody"])["content"])["workflowPacket"])
		ref, _ := json.Marshal([]map[string]json.RawMessage{{"packetId": packet["packetId"], "packetRevision": packet["packetRevision"]}})
		if !sameWorkflowFact(lane["laneId"], intent["laneId"]) || !sameWorkflowFact(lane["packetRefs"], ref) || !sameWorkflowFact(lane["writeScope"], packet["writeScope"]) || workflowInteger(lane["requestedParallelism"]) != 1 {
			return ControllerWorkflowProposal{}, bad
		}
		var dependencies []string
		var proposed []controllerPacketRef
		if json.Unmarshal(packet["dependencies"], &dependencies) != nil || json.Unmarshal(lane["dependencies"], &proposed) != nil || len(proposed) != len(dependencies) {
			return ControllerWorkflowProposal{}, bad
		}
		for i, dependency := range dependencies {
			if proposed[i].PacketID != dependency {
				return ControllerWorkflowProposal{}, bad
			}
		}
	case "manager_intent":
		intent, decision := workflowObject(target["intent"]), workflowObject(body["member"])
		ref, _ := json.Marshal(map[string]json.RawMessage{"intentId": intent["intentId"], "intentRevision": intent["intentRevision"], "intentDigest": intent["intentDigest"]})
		if !sameWorkflowFact(body["purpose"], target["purpose"]) || !sameWorkflowFact(intent["purpose"], target["purpose"]) || !sameWorkflowFact(intent["plan"], plan) || !sameWorkflowFact(decision["intent"], ref) || !sameWorkflowFact(decision["expectedAdmissionRevision"], intent["expectedAdmissionRevision"]) {
			return ControllerWorkflowProposal{}, bad
		}
	case "advice_decision":
		legacy := c
		legacy.FormatVersion = 1
		return ControllerProposal(legacy, text)
	default:
		return controllerProposal2(c, text)
	}
	return out, nil
}
