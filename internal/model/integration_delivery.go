package model

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// This is the integrator's immutable input contract. It contains no candidate,
// protected source-read receipt, staging receipt, or acceptance authority.
type IntegrationByteSpan struct {
	Kind            string                  `json:"kind"`
	Reference       ControllerPlanReference `json:"reference"`
	Artifact        json.RawMessage         `json:"artifact"`
	RootGrantDigest string                  `json:"rootGrantDigest"`
	Encoding        string                  `json:"encoding"`
	ByteCount       int                     `json:"byteCount"`
	Offset          int                     `json:"offset"`
	Length          int                     `json:"length"`
}
type IntegrationDeliveryPlan struct {
	FormatVersion      int                   `json:"formatVersion"`
	DeliveryPlanID     string                `json:"deliveryPlanId"`
	DeliveryPlanDigest string                `json:"deliveryPlanDigest"`
	Intent             IntentRef             `json:"intent"`
	Binding            json.RawMessage       `json:"binding"`
	Assignment         json.RawMessage       `json:"assignment"`
	Target             json.RawMessage       `json:"target"`
	TargetBinding      json.RawMessage       `json:"targetBinding"`
	InputID            string                `json:"inputId"`
	InputDigest        string                `json:"inputDigest"`
	InputByteCount     int                   `json:"inputByteCount"`
	Spans              []IntegrationByteSpan `json:"spans"`
	NotAfter           string                `json:"notAfter"`
}

// InputBytes returns the complete lossless span; this is input integrity only.
func (s IntegrationByteSpan) InputBytes(input []byte) ([]byte, error) {
	bad := errors.New("integration input span refused")
	if s.Encoding != "json_string_fragment_utf8" || s.Reference.Status != "accepted" || s.Offset < 0 || s.Length < 0 || s.Offset > len(input) || s.Length > len(input)-s.Offset || s.ByteCount < 0 || s.ByteCount > 16384 {
		return nil, bad
	}
	fragment := input[s.Offset : s.Offset+s.Length]
	var decoded string
	if json.Unmarshal(append(append([]byte{'"'}, fragment...), '"'), &decoded) != nil || !utf8.ValidString(decoded) || len(decoded) != s.ByteCount || fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(decoded))) != s.Reference.SourceDigest {
		return nil, bad
	}
	encoded, err := WorkspaceCanonicalJSON(decoded)
	if err != nil || string(encoded[1:len(encoded)-1]) != string(fragment) {
		return nil, bad
	}
	return []byte(decoded), nil
}

func VerifyIntegrationInput(plan IntegrationDeliveryPlan, input []byte, now time.Time) error {
	bad := errors.New("integration input delivery refused")
	raw, err := json.Marshal(plan)
	if err != nil || workflowcontract.ValidateChildIntegrator("integrationDelivery", raw) != nil || !ControllerTextValid(string(input)) || len(input) != plan.InputByteCount || fmt.Sprintf("sha256:%x", sha256.Sum256(input)) != plan.InputDigest {
		return bad
	}
	expires, err := time.Parse(time.RFC3339Nano, plan.NotAfter)
	if err != nil || !now.Before(expires) {
		return bad
	}
	fields := workflowObject(raw)
	delete(fields, "deliveryPlanDigest")
	if WorkspaceDigest(fields) != plan.DeliveryPlanDigest {
		return bad
	}
	b, a, target := workflowObject(plan.Binding), workflowObject(plan.Assignment), workflowObject(plan.TargetBinding)
	if workflowString(a["purpose"]) != "integrate" || !sameWorkflowFact(a["target"], plan.Target) || !sameWorkflowFact(a["executionId"], b["executionId"]) || sameWorkflowFact(b["executionId"], target["executionId"]) {
		return bad
	}
	for _, k := range []string{"projectId", "workspaceEpoch", "selectionId", "scopeRevision", "rootAttestation", "nativeProjectId", "nativeLocationDigest"} {
		if !sameWorkflowFact(b[k], target[k]) {
			return bad
		}
	}
	ordered := append([]IntegrationByteSpan(nil), plan.Spans...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	end, targets := 0, 0
	seen := map[string]bool{}
	for _, span := range ordered {
		if span.Offset < end {
			return bad
		}
		end = span.Offset + span.Length
		if _, err := span.InputBytes(input); err != nil {
			return bad
		}
		key := WorkspaceDigest(span.Reference)
		if seen[key] {
			return bad
		}
		seen[key] = true
		if span.Kind == "target_artifact" {
			targets++
			artifact := workflowObject(span.Artifact)
			if span.ByteCount > 8192 || workflowString(artifact["digest"]) != span.Reference.SourceDigest || workflowInteger(artifact["byteCount"]) != int64(span.ByteCount) {
				return bad
			}
		}
	}
	if targets != 1 {
		return bad
	}
	return nil
}
