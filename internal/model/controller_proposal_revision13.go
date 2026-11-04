package model

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func sameWorkflowFact(a, b json.RawMessage) bool {
	x, err := WorkspaceCanonicalJSON(a)
	if err != nil {
		return false
	}
	y, err := WorkspaceCanonicalJSON(b)
	return err == nil && bytes.Equal(x, y)
}
func workflowObject(raw json.RawMessage) map[string]json.RawMessage {
	var result map[string]json.RawMessage
	_ = json.Unmarshal(raw, &result)
	return result
}
func workflowString(raw json.RawMessage) string { var s string; _ = json.Unmarshal(raw, &s); return s }
func workflowInteger(raw json.RawMessage) int64 { var n int64; _ = json.Unmarshal(raw, &n); return n }

// Target2 is independently supplied BEFORE prompt admission. This parses only
// the ONE original BODY and compares all authority selectors with that target.
// Current node/lease/root/holds/receipt checks remain at the existing API/root
// seams; neither this parser nor a schema can grant or dispatch a child.
func controllerProposal2(c ControllerApprovedInputContext, text string) (ControllerWorkflowProposal, error) {
	bad := errors.New("revision13 controller proposal mismatch")
	out := ControllerWorkflowProposal{Target: c.Target, Body: json.RawMessage(text)}
	raw, err := json.Marshal(out)
	if err != nil || workflowcontract.Validate(workflowcontract.Manager, "controllerProposal2", raw) != nil {
		return ControllerWorkflowProposal{}, bad
	}
	target, err := c.Target.retainedFacts()
	if err != nil {
		return ControllerWorkflowProposal{}, bad
	}
	body := workflowObject([]byte(text))
	if workflowString(body["requestId"]) != c.WorkflowRequestID {
		return ControllerWorkflowProposal{}, bad
	}
	if plan, present := body["plan"]; present {
		selected, _ := json.Marshal(c.Plan)
		if !sameWorkflowFact(plan, selected) {
			return ControllerWorkflowProposal{}, bad
		}
	}
	valid := false
	switch c.Target.Kind {
	case "advice":
		// Preserve the established lane/path/material rules, in addition to the
		// exact domain schema. Legacy parser cannot widen this advice target.
		legacy := c
		legacy.FormatVersion = 1
		_, err := ControllerProposal(legacy, text)
		valid = err == nil
	case "manager_work_intents":
		advice := workflowObject(target["advice"])
		selectedPlan, _ := json.Marshal(c.Plan)
		valid = c.Target.ResourceID != nil && workflowString(advice["adviceId"]) == *c.Target.ResourceID &&
			sameWorkflowFact(advice["plan"], selectedPlan) && sameWorkflowFact(body["expectedAdviceRevision"], advice["adviceRevision"]) &&
			managerSelectedLanes(target["members"], body["lanes"], workflowString(body["choice"]), selectedPlan)
	case "manager_intent_pair":
		valid = sameWorkflowFact(body["purpose"], target["purpose"])
		intents, decisions := workflowObject(target["members"]), workflowObject(body["members"])
		for _, member := range []string{"first", "second"} {
			intent, decision := workflowObject(intents[member]), workflowObject(decisions[member])
			ref, _ := json.Marshal(map[string]json.RawMessage{"intentId": intent["intentId"], "intentRevision": intent["intentRevision"], "intentDigest": intent["intentDigest"]})
			selectedPlan, _ := json.Marshal(c.Plan)
			valid = valid && sameWorkflowFact(decision["intent"], ref) && sameWorkflowFact(decision["expectedAdmissionRevision"], intent["expectedAdmissionRevision"]) &&
				sameWorkflowFact(intent["purpose"], target["purpose"]) && sameWorkflowFact(intent["plan"], selectedPlan)
		}
		valid = valid && distinctIntentPair(target["members"])
	case "result_decision":
		result, receipt := workflowObject(target["result"]), workflowObject(target["resultReceipt"])
		valid = c.Target.ResourceID != nil && workflowString(result["resultId"]) == *c.Target.ResourceID &&
			sameWorkflowFact(body["target"], target["result"]) && sameWorkflowFact(body["expectedDecisionRevision"], target["expectedDecisionRevision"])
		for _, key := range []string{"resultId", "resultRevision", "resultDigest"} {
			valid = valid && sameWorkflowFact(result[key], receipt[key])
		}
		if workflowString(body["decision"]) == "accept" {
			review, candidate := workflowObject(target["review"]), workflowObject(target["candidate"])
			reviewRef, _ := json.Marshal(map[string]json.RawMessage{"reviewId": review["reviewId"], "reviewDigest": review["reviewDigest"]})
			valid = valid && workflowString(review["disposition"]) == "approve" && sameWorkflowFact(review["target"], target["result"]) &&
				sameWorkflowFact(body["review"], reviewRef) && sameWorkflowFact(body["integration"], candidate["integration"]) && sameWorkflowFact(review["integration"], candidate["integration"]) &&
				workflowString(review["reviewerExecutionId"]) != workflowString(receipt["executionId"])
		} else if string(body["review"]) != "null" {
			review := workflowObject(target["review"])
			ref, _ := json.Marshal(map[string]json.RawMessage{"reviewId": review["reviewId"], "reviewDigest": review["reviewDigest"]})
			valid = valid && sameWorkflowFact(body["review"], ref) && sameWorkflowFact(review["target"], target["result"])
		}
	case "peer_request", "peer_reply", "peer_disposition":
		valid = peerSelectedFacts(c.Target.Kind, target, body)
	}
	if !valid {
		return ControllerWorkflowProposal{}, bad
	}
	return out, nil
}

func distinctIntentPair(raw json.RawMessage) bool {
	members := workflowObject(raw)
	first, second := workflowObject(members["first"]), workflowObject(members["second"])
	return workflowString(first["intentId"]) != workflowString(second["intentId"]) &&
		workflowString(first["allocationId"]) != workflowString(second["allocationId"])
}

func managerSelectedLanes(rawMembers, rawLanes json.RawMessage, choice string, plan json.RawMessage) bool {
	if !distinctIntentPair(rawMembers) {
		return false
	}
	members := workflowObject(rawMembers)
	first, second := workflowObject(members["first"]), workflowObject(members["second"])
	if workflowString(first["laneId"]) == workflowString(second["laneId"]) {
		return false
	}
	for _, intent := range []map[string]json.RawMessage{first, second} {
		if !sameWorkflowFact(intent["plan"], plan) || workflowString(intent["purpose"]) != "implement" {
			return false
		}
	}
	var lanes []json.RawMessage
	if json.Unmarshal(rawLanes, &lanes) != nil {
		return false
	}
	if choice == "decline" {
		return len(lanes) == 0
	}
	seen := map[string]bool{}
	for _, rawLane := range lanes {
		lane := workflowObject(rawLane)
		laneID := workflowString(lane["laneId"])
		if seen[laneID] {
			return false
		}
		seen[laneID] = true
		matched := false
		for _, name := range []string{"first", "second"} {
			intent := workflowObject(members[name])
			if workflowString(intent["laneId"]) != laneID {
				continue
			}
			packet := workflowObject(workflowObject(workflowObject(intent["prepareBody"])["content"])["workflowPacket"])
			ref, _ := json.Marshal([]map[string]json.RawMessage{{"packetId": packet["packetId"], "packetRevision": packet["packetRevision"]}})
			if !sameWorkflowFact(lane["packetRefs"], ref) || !sameWorkflowFact(lane["writeScope"], packet["writeScope"]) || workflowInteger(lane["requestedParallelism"]) != 1 {
				return false
			}
			var dependencies []string
			if json.Unmarshal(packet["dependencies"], &dependencies) != nil {
				return false
			}
			var proposed []controllerPacketRef
			if json.Unmarshal(lane["dependencies"], &proposed) != nil || len(proposed) != len(dependencies) {
				return false
			}
			for i, ref := range proposed {
				if ref.PacketID != dependencies[i] {
					return false
				}
			}
			matched = true
		}
		if !matched {
			return false
		}
	}
	return len(lanes) > 0 && len(lanes) <= 2
}

func peerSelectedFacts(kind string, target, body map[string]json.RawMessage) bool {
	authority := workflowObject(target["authority"])
	source, destination := workflowObject(authority["sourceGrant"]), workflowObject(authority["destinationGrant"])
	sourceEndpoint, destinationEndpoint := workflowObject(source["source"]), workflowObject(source["destination"])
	if !sameWorkflowFact(sourceEndpoint["serverId"], destinationEndpoint["serverId"]) || sameWorkflowFact(sourceEndpoint["cellId"], destinationEndpoint["cellId"]) {
		return false
	}
	if string(source["enabled"]) != "true" || string(destination["enabled"]) != "true" ||
		!sameWorkflowFact(source["source"], destination["destination"]) || !sameWorkflowFact(source["destination"], destination["source"]) ||
		!sameWorkflowFact(source["peerCellId"], workflowObject(source["destination"])["cellId"]) ||
		!sameWorkflowFact(destination["peerCellId"], workflowObject(source["source"])["cellId"]) {
		return false
	}
	exchange := workflowObject(target["exchange"])
	scope := target["scope"]
	if kind != "peer_request" {
		scope = exchange["scope"]
		if !sameWorkflowFact(target["resourceId"], exchange["exchangeId"]) || !sameWorkflowFact(exchange["source"], source["source"]) ||
			!sameWorkflowFact(exchange["destination"], source["destination"]) || !sameWorkflowFact(exchange["sourceGrantRevision"], source["revision"]) ||
			!sameWorkflowFact(exchange["destinationGrantRevision"], destination["revision"]) {
			return false
		}
	}
	for _, grant := range []map[string]json.RawMessage{source, destination} {
		var scopes []json.RawMessage
		if json.Unmarshal(grant["scopes"], &scopes) != nil {
			return false
		}
		found := false
		for _, allowed := range scopes {
			found = found || sameWorkflowFact(scope, allowed)
		}
		if !found {
			return false
		}
	}
	switch kind {
	case "peer_request":
		return sameWorkflowFact(body["destinationCellId"], source["peerCellId"]) && sameWorkflowFact(body["scope"], scope) &&
			sameWorkflowFact(body["expiresAt"], target["expiresAt"]) && sameWorkflowFact(body["artifactRefs"], target["artifactRefs"])
	case "peer_reply":
		return sameWorkflowFact(body["correlationId"], exchange["correlationId"]) && sameWorkflowFact(body["artifactRefs"], target["artifactRefs"])
	case "peer_disposition":
		reply := workflowObject(target["reply"])
		return sameWorkflowFact(reply["exchangeId"], exchange["exchangeId"]) && sameWorkflowFact(reply["correlationId"], exchange["correlationId"]) &&
			sameWorkflowFact(body["exchange"], target["exchange"]) && sameWorkflowFact(body["reply"], target["reply"]) &&
			sameWorkflowFact(body["expectedDispositionRevision"], target["expectedDispositionRevision"])
	}
	return false
}
