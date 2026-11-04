package model

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

type controllerPacketRef struct {
	PacketID       string `json:"packetId"`
	PacketRevision int64  `json:"packetRevision"`
}
type controllerLane struct {
	LaneID       string                `json:"laneId"`
	PacketRefs   []controllerPacketRef `json:"packetRefs"`
	Dependencies []controllerPacketRef `json:"dependencies"`
	WriteScope   struct {
		Mode  string   `json:"mode"`
		Paths []string `json:"paths"`
	} `json:"writeScope"`
	RequestedParallelism int64  `json:"requestedParallelism"`
	Reason               string `json:"reason"`
}
type controllerAdviceBody struct {
	FormatVersion int              `json:"formatVersion"`
	RequestID     string           `json:"requestId"`
	Plan          ControllerPlan   `json:"plan"`
	Lanes         []controllerLane `json:"lanes"`
	Reason        string           `json:"reason"`
}
type controllerDecisionBody struct {
	FormatVersion          int              `json:"formatVersion"`
	RequestID              string           `json:"requestId"`
	ExpectedAdviceRevision int64            `json:"expectedAdviceRevision"`
	Plan                   ControllerPlan   `json:"plan"`
	Choice                 string           `json:"choice"`
	Lanes                  []controllerLane `json:"lanes"`
	Reason                 string           `json:"reason"`
}

func controllerDomainText(s string) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= 2048 && !strings.ContainsRune(s, 0)
}
func controllerWorkflowPath(s string) bool {
	if !utf8.ValidString(s) || len(s) == 0 || utf8.RuneCountInString(s) > 1024 || strings.ContainsAny(s, "\\:#?\x00") || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	first, _ := utf8.DecodeRuneInString(s)
	return !unicode.IsSpace(first)
}

// One closed existing domain body, never prose extraction or model-selected
// target/resource. Both authorization and root signing use this SAME parser.
func ControllerProposal(c ControllerApprovedInputContext, text string) (ControllerWorkflowProposal, error) {
	var out ControllerWorkflowProposal
	bad := errors.New("controller workflow proposal mismatch")
	if !ControllerTextValid(text) {
		return out, bad
	}
	if c.FormatVersion == 4 {
		return controllerProposalSingle(c, text)
	}
	if c.FormatVersion == 2 || c.FormatVersion == 3 {
		return controllerProposal2(c, text)
	}
	var lanes []controllerLane
	var reason, request string
	var plan ControllerPlan
	var version int
	if c.Target.Kind == "advice" {
		if c.Target.Role != "orchestrator" || c.Target.ResourceID != nil || c.Target.Advice != nil {
			return out, bad
		}
		var body controllerAdviceBody
		if decodeControllerClosed([]byte(text), &body) != nil || len(body.Lanes) < 1 {
			return out, bad
		}
		lanes, reason, request, plan, version = body.Lanes, body.Reason, body.RequestID, body.Plan, body.FormatVersion
	} else if c.Target.Kind == "advice_decision" {
		if c.Target.Role != "manager" || c.Target.ResourceID == nil || !cellV3SafeIDPattern.MatchString(*c.Target.ResourceID) || c.Target.Advice == nil {
			return out, bad
		}
		var body controllerDecisionBody
		var advice struct {
			AdviceID       string         `json:"adviceId"`
			AdviceRevision int64          `json:"adviceRevision"`
			Plan           ControllerPlan `json:"plan"`
		}
		if decodeControllerClosed([]byte(text), &body) != nil || json.Unmarshal(*c.Target.Advice, &advice) != nil || advice.AdviceID != *c.Target.ResourceID || advice.Plan != c.Plan || body.ExpectedAdviceRevision != advice.AdviceRevision || body.ExpectedAdviceRevision < 1 || (body.Choice != "adopt" && body.Choice != "change" && body.Choice != "decline") || (body.Choice == "decline" && len(body.Lanes) != 0) || (body.Choice != "decline" && len(body.Lanes) < 1) {
			return out, bad
		}
		lanes, reason, request, plan, version = body.Lanes, body.Reason, body.RequestID, body.Plan, body.FormatVersion
	} else {
		return out, bad
	}
	if version != 1 || request != c.WorkflowRequestID || plan != c.Plan || len(lanes) > 64 || !controllerDomainText(reason) {
		return out, bad
	}
	for _, lane := range lanes {
		if !cellV3SafeIDPattern.MatchString(lane.LaneID) || lane.RequestedParallelism < 1 || lane.RequestedParallelism > 9007199254740991 || !controllerDomainText(lane.Reason) || len(lane.PacketRefs) < 1 || len(lane.PacketRefs) > 64 || len(lane.Dependencies) > 64 || (lane.WriteScope.Mode != "exclusive" && lane.WriteScope.Mode != "consultation") || len(lane.WriteScope.Paths) < 1 || len(lane.WriteScope.Paths) > 64 {
			return out, bad
		}
		for _, ref := range append(append([]controllerPacketRef{}, lane.PacketRefs...), lane.Dependencies...) {
			if !cellV3SafeIDPattern.MatchString(ref.PacketID) || ref.PacketRevision < 1 || ref.PacketRevision > 9007199254740991 {
				return out, bad
			}
		}
		seen := map[string]bool{}
		for _, path := range lane.WriteScope.Paths {
			if !controllerWorkflowPath(path) || seen[path] {
				return out, bad
			}
			seen[path] = true
		}
	}
	return ControllerWorkflowProposal{Target: c.Target, Body: json.RawMessage(text)}, nil
}
