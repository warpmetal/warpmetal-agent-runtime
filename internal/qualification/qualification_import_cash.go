package qualification

import (
	"bytes"
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Private cash verification for an import locator from the independently verified
// committed backend adoption. This is not an import API, issuer or qualification
// substitute. Callers still verify the original accounting journal/window first.
type qualificationCashTool struct {
	ToolCallID            string `json:"toolCallId"`
	Tool                  string `json:"tool"`
	ArgumentsDigest       string `json:"argumentsDigest"`
	ExitCode              int    `json:"exitCode"`
	WorkspaceDigest       string `json:"workspaceDigest"`
	ArtifactRelativePath  string `json:"artifactRelativePath"`
	ArtifactDigest        string `json:"artifactDigest"`
	ArtifactSize          int    `json:"artifactSize"`
	TerminalJSONDigest    string `json:"terminalJSONDigest"`
	OutcomeDigest         string `json:"outcomeDigest"`
	ToolObservationDigest string `json:"toolObservationDigest"`
}
type qualificationCashEvidence struct {
	FormatVersion         int           `json:"formatVersion"`
	QualificationID       string        `json:"qualificationId"`
	Tuple                 Applicability `json:"tuple"`
	TupleDigest           string        `json:"tupleDigest"`
	PermitDigest          string        `json:"permitDigest"`
	PreparationID         string        `json:"preparationId"`
	PreparedTupleDigest   string        `json:"preparedTupleDigest"`
	PreparedReceiptDigest string        `json:"preparedReceiptDigest"`
	GrantID               string        `json:"grantId"`
	PolicyDigest          string        `json:"policyDigest"`
	NativeIdentity        struct {
		ExecutionID  string `json:"executionId"`
		OperationID  string `json:"operationId"`
		SessionID    string `json:"sessionId"`
		InputID      string `json:"inputId"`
		Attempt      int    `json:"attempt"`
		Fence        string `json:"fence"`
		BinarySHA256 string `json:"binarySHA256"`
	} `json:"nativeIdentity"`
	Requests             []RequestObservation  `json:"requests"`
	ToolOutcome          qualificationCashTool `json:"toolOutcome"`
	TerminalReportDigest string                `json:"terminalReportDigest"`
	StartedAt            string                `json:"startedAt"`
	CompletedAt          string                `json:"completedAt"`
	ProducerAttestation  json.RawMessage       `json:"producerAttestation"`
}

func verifyQualificationImportCash(raw []byte, qualificationID string, record map[string]json.RawMessage, allocation DemandAllocation, operations []state.PhysicalOperation, keyID string, public []byte, now time.Time, read func(string, int) ([]byte, error)) (int64, error) {
	var e qualificationCashEvidence
	if len(raw) > 65536 || decodeClosed(raw, &e) != nil || read == nil || allocation.Kind != "qualification" || allocation.ModelRequests != 2 || allocation.AccessRequests != 0 || allocation.USDMicros != 2*RequestMicros || len(operations) != 2 || len(e.Requests) != 2 || e.FormatVersion != 1 || e.QualificationID != qualificationID || e.QualificationID != childString(record, "subjectId") || e.TupleDigest != allocation.TupleDigest || CanonicalDigest(e.Tuple) != e.TupleDigest {
		return 0, ErrUntrusted
	}
	payload := childFields(raw)
	delete(payload, "producerAttestation")
	if verifyChildEnvelope(e.ProducerAttestation, keyID, public) != nil || !sameProduct(childFields(e.ProducerAttestation)["payload"], payload) {
		return 0, ErrUntrusted
	}
	if e.Tuple.AccountID != allocation.Scope.AccountID || e.Tuple.TaskID != allocation.Scope.TaskID || e.Tuple.ServerID != allocation.Scope.ServerID || e.Tuple.SandboxID != allocation.Scope.SandboxID || e.Tuple.SandboxGeneration != allocation.Scope.SandboxGeneration || e.NativeIdentity.BinarySHA256 != e.Tuple.Native.BinarySHA256 || e.NativeIdentity.Attempt < 1 {
		return 0, ErrUntrusted
	}
	for _, id := range []string{e.QualificationID, e.PreparationID, e.GrantID, e.NativeIdentity.ExecutionID, e.NativeIdentity.OperationID, e.NativeIdentity.SessionID, e.NativeIdentity.InputID} {
		if !safeID.MatchString(id) {
			return 0, ErrUntrusted
		}
	}
	for _, d := range []string{e.PermitDigest, e.PreparedTupleDigest, e.PreparedReceiptDigest, e.PolicyDigest, e.TerminalReportDigest, e.NativeIdentity.BinarySHA256} {
		if !hash.MatchString(d) {
			return 0, ErrUntrusted
		}
	}
	start, se := time.Parse(time.RFC3339Nano, e.StartedAt)
	end, ee := time.Parse(time.RFC3339Nano, e.CompletedAt)
	if se != nil || ee != nil || end.Before(start) || end.After(now) {
		return 0, ErrUntrusted
	}
	get := func(d string, maximum int) ([]byte, error) {
		if !hash.MatchString(d) {
			return nil, ErrUntrusted
		}
		b, err := read(d, maximum)
		if err != nil || len(b) > maximum || Digest(b) != d {
			return nil, ErrUntrusted
		}
		return b, nil
	}
	jsonGet := func(d string, maximum int) (map[string]json.RawMessage, error) {
		b, err := get(d, maximum)
		var value map[string]json.RawMessage
		if err != nil || decode(b, &value) != nil || value == nil {
			return nil, ErrUntrusted
		}
		return value, nil
	}
	requests := []map[string]json.RawMessage{}
	responses := []map[string]json.RawMessage{}
	previous := start
	providerIDs := map[string]bool{}
	responseIDs := map[string]bool{}
	var actual int64
	for n, r := range e.Requests {
		x, xe := time.Parse(time.RFC3339Nano, r.StartedAt)
		y, ye := time.Parse(time.RFC3339Nano, r.CompletedAt)
		micros, valid := cost(r)
		o := operations[n]
		s := o.Settlement
		if !valid || xe != nil || ye != nil || x.Before(previous) || y.Before(x) || y.After(end) || r.RequestIndex != n+1 || r.PhysicalIndex != allocation.FirstPhysicalIndex+n || r.ReservationID != childString(record, "reservationId") || r.ModelID != RealModel || r.HTTPStatus != 200 || r.ReservedUSDMicros != RequestMicros || r.ActualUSDMicros != micros || micros > RequestMicros || r.ProviderRequestID == "" || providerIDs[r.ProviderRequestID] || r.ResponseID == "" || responseIDs[r.ResponseID] {
			return 0, ErrUntrusted
		}
		providerIDs[r.ProviderRequestID] = true
		responseIDs[r.ResponseID] = true
		previous = y
		if o.Phase != "settled" || s == nil || o.Permit.Offline != nil || o.ReservedUsdMicros != RequestMicros || o.Permit.Request.Consumer != "qualification" || o.Permit.Request.PreparationID != e.PreparationID || o.Permit.Request.RequestIndex != r.RequestIndex || o.Permit.Request.OuterPhysicalIndex != r.PhysicalIndex || o.Permit.Request.RequestDigest != r.RequestDigest || o.Permit.AllocationID != allocation.AllocationID || o.Permit.PreparationOrdinal != allocation.PreparationOrdinal || o.Permit.Caller.SandboxID != allocation.Scope.SandboxID || o.Permit.Caller.SandboxGeneration != allocation.Scope.SandboxGeneration || o.Permit.PaidDomain != "" && o.Permit.PaidDomain != childString(record, "demandManifestDigest") || s.RequestDigest != r.RequestDigest || s.ResponseDigest != r.WireResponseDigest || s.HTTPStatus != 200 || s.UsageUsdMicros != micros {
			return 0, ErrUntrusted
		}
		request, err := jsonGet(r.RequestDigest, 32768)
		if err != nil {
			return 0, err
		}
		original, err := jsonGet(r.OriginalRequestDigest, 32768)
		if err != nil {
			return 0, err
		}
		response, err := jsonGet(r.ResponseDigest, 262144)
		if err != nil {
			return 0, err
		}
		wire, err := get(r.WireResponseDigest, 262144)
		if err != nil || len(wire) != s.ResponseByteCount {
			return 0, ErrUntrusted
		}
		completed, err := completedQualificationResponse(wire)
		if err != nil || !sameProduct(completed, response) {
			return 0, ErrUntrusted
		}
		completion, err := jsonGet(s.EvidenceDigest, 65536)
		if err != nil || !sameProduct(completion, map[string]any{"requestDigest": s.RequestDigest, "responseDigest": s.ResponseDigest, "responseByteCount": s.ResponseByteCount, "httpStatus": s.HTTPStatus, "usageUsdMicros": s.UsageUsdMicros}) {
			return 0, ErrUntrusted
		}
		dispatch, err := jsonGet(r.DispatchDigest, 32768)
		if err != nil || !sameProduct(dispatch, map[string]any{"qualificationId": e.QualificationID, "reservationId": r.ReservationID, "requestIndex": n + 1, "requestDigest": r.RequestDigest, "turn": n + 1, "sdkRetries": 0, "applicationRetries": 0, "inputTokenUpperBound": 1047576, "outputTokenLimit": 1000}) {
			return 0, ErrUntrusted
		}
		if err = verifyQualificationCashRequest(request, original, response, r, n+1, e.ToolOutcome); err != nil {
			return 0, err
		}
		requests = append(requests, request)
		responses = append(responses, response)
		actual += micros
	}
	if actual > allocation.USDMicros || verifyQualificationCashTool(e, requests, responses, get, jsonGet) != nil {
		return 0, ErrUntrusted
	}
	return actual, nil
}

func completedQualificationResponse(wire []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(wire) {
		return nil, ErrUntrusted
	}
	var completed map[string]json.RawMessage
	for _, frame := range bytes.Split(bytes.ReplaceAll(wire, []byte("\r\n"), []byte("\n")), []byte("\n\n")) {
		data := [][]byte{}
		for _, line := range bytes.Split(frame, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("data:")) {
				data = append(data, bytes.TrimSpace(line[5:]))
			}
		}
		raw := bytes.Join(data, []byte("\n"))
		if len(raw) == 0 || bytes.Equal(raw, []byte("[DONE]")) {
			continue
		}
		var event map[string]json.RawMessage
		if decode(raw, &event) != nil {
			return nil, ErrUntrusted
		}
		switch childString(event, "type") {
		case "error", "response.failed", "response.incomplete", "":
			return nil, ErrUntrusted
		case "response.completed":
			if completed != nil || decode(event["response"], &completed) != nil || completed == nil {
				return nil, ErrUntrusted
			}
		}
	}
	if completed == nil {
		return nil, ErrUntrusted
	}
	return completed, nil
}

func verifyQualificationCashRequest(request, original, response map[string]json.RawMessage, r RequestObservation, index int, tool qualificationCashTool) error {
	allowed := map[string]bool{}
	for _, name := range []string{"model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "stream", "store", "max_output_tokens", "temperature", "top_p", "text", "include", "prompt_cache_key", "user", "safety_identifier", "truncation", "service_tier", "metadata"} {
		allowed[name] = true
	}
	for name := range request {
		if !allowed[name] {
			return ErrUntrusted
		}
	}
	left, right := map[string]json.RawMessage{}, map[string]json.RawMessage{}
	for k, v := range request {
		if k != "tool_choice" && k != "parallel_tool_calls" && (index != 2 || k != "text") {
			left[k] = v
		}
	}
	for k, v := range original {
		if k != "tool_choice" && k != "parallel_tool_calls" && (index != 2 || k != "text") {
			right[k] = v
		}
	}
	choice := any(map[string]string{"type": "function", "name": "shell"})
	if index == 2 {
		choice = "none"
	}
	if !sameProduct(left, right) || !sameProduct(request["tool_choice"], choice) || !sameProduct(request["parallel_tool_calls"], false) || !sameProduct(request["store"], false) || !sameProduct(request["stream"], true) || !sameProduct(request["max_output_tokens"], 1000) || childString(request, "model") != RealModel || childString(response, "model") != RealModel || childString(response, "id") != r.ResponseID || childString(response, "status") != "completed" {
		return ErrUntrusted
	}
	if include, ok := request["include"]; ok && !sameProduct(include, []any{}) {
		return ErrUntrusted
	}
	if tier, ok := request["service_tier"]; ok && !sameProduct(tier, "default") {
		return ErrUntrusted
	}
	var tools []map[string]json.RawMessage
	if value, ok := request["tools"]; ok {
		if decode(value, &tools) != nil {
			return ErrUntrusted
		}
		for _, t := range tools {
			if childString(t, "type") != "function" || childString(t, "name") != "shell" {
				return ErrUntrusted
			}
		}
	}
	if index == 2 {
		text := map[string]json.RawMessage{}
		if value, ok := original["text"]; ok {
			if decode(value, &text) != nil || text == nil {
				return ErrUntrusted
			}
		}
		text["format"] = canonicalBytes(map[string]any{"type": "json_schema", "name": "qualification_artifact", "strict": true, "schema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"artifact", "sha256"}, "properties": map[string]any{"artifact": map[string]any{"type": "string", "enum": []string{tool.ArtifactRelativePath}}, "sha256": map[string]any{"type": "string", "enum": []string{tool.ArtifactDigest}}}}})
		if !sameProduct(request["text"], text) {
			return ErrUntrusted
		}
	}
	usage := childFields(response["usage"])
	for name := range usage {
		switch name {
		case "input_tokens", "output_tokens", "total_tokens", "input_tokens_details", "output_tokens_details":
		default:
			return ErrUntrusted
		}
	}
	if !sameProduct(usage["input_tokens"], r.InputTokens) || !sameProduct(usage["output_tokens"], r.OutputTokens) || !sameProduct(usage["input_tokens_details"], map[string]int64{"cached_tokens": r.CachedInputTokens}) {
		return ErrUntrusted
	}
	if total, ok := usage["total_tokens"]; ok && !sameProduct(total, r.InputTokens+r.OutputTokens) {
		return ErrUntrusted
	}
	if details, ok := usage["output_tokens_details"]; ok && !sameProduct(details, map[string]int{"reasoning_tokens": 0}) {
		return ErrUntrusted
	}
	return nil
}

func verifyQualificationCashTool(e qualificationCashEvidence, requests, responses []map[string]json.RawMessage, get func(string, int) ([]byte, error), jsonGet func(string, int) (map[string]json.RawMessage, error)) error {
	t := e.ToolOutcome
	if t.Tool != "shell" || t.ExitCode != 0 || !safeID.MatchString(t.ToolCallID) || !artifactName.MatchString(t.ArtifactRelativePath) || !hash.MatchString(t.WorkspaceDigest) {
		return ErrUntrusted
	}
	artifact, err := get(t.ArtifactDigest, 262144)
	if err != nil || len(artifact) != t.ArtifactSize {
		return ErrUntrusted
	}
	terminal, err := jsonGet(t.TerminalJSONDigest, 262144)
	if err != nil || !sameProduct(terminal, map[string]string{"artifact": t.ArtifactRelativePath, "sha256": t.ArtifactDigest}) {
		return ErrUntrusted
	}
	outcome, err := jsonGet(t.OutcomeDigest, 262144)
	fields := childFields(canonicalBytes(t))
	delete(fields, "outcomeDigest")
	if err != nil || !sameProduct(outcome, fields) {
		return ErrUntrusted
	}
	arguments, err := jsonGet(t.ArgumentsDigest, 32768)
	if err != nil || len(arguments) != 4 || childString(arguments, "command") == "" || childString(arguments, "workdir") == "" || !sameProduct(arguments["timeout"], 120000) || !sameProduct(arguments["background"], false) {
		return ErrUntrusted
	}
	observation, err := jsonGet(t.ToolObservationDigest, 262144)
	if err != nil || len(observation) != 10 {
		return ErrUntrusted
	}
	for name, value := range map[string]any{"preparationId": e.PreparationID, "toolCallId": t.ToolCallID, "tool": "shell", "argumentsDigest": t.ArgumentsDigest, "workspaceDigest": t.WorkspaceDigest, "exitCode": 0, "truncated": false, "timedOut": false} {
		if !sameProduct(observation[name], value) {
			return ErrUntrusted
		}
	}
	at, err := time.Parse(time.RFC3339Nano, childString(observation, "observedAt"))
	if err != nil || at.Before(mustChildTime(e.Requests[0].CompletedAt)) || at.After(mustChildTime(e.Requests[1].StartedAt)) {
		return ErrUntrusted
	}
	var first, second []map[string]json.RawMessage
	if decode(responses[0]["output"], &first) != nil || len(first) != 1 || decode(responses[1]["output"], &second) != nil || len(second) != 1 {
		return ErrUntrusted
	}
	isCall := func(item map[string]json.RawMessage) bool {
		var args map[string]json.RawMessage
		return childString(item, "type") == "function_call" && childString(item, "name") == "shell" && childString(item, "call_id") == t.ToolCallID && decode([]byte(childString(item, "arguments")), &args) == nil && sameProduct(args, arguments)
	}
	if !isCall(first[0]) || childString(second[0], "type") != "message" {
		return ErrUntrusted
	}
	var content []map[string]json.RawMessage
	var actualTerminal map[string]json.RawMessage
	if decode(second[0]["content"], &content) != nil || len(content) != 1 || childString(content[0], "type") != "output_text" || decode([]byte(childString(content[0], "text")), &actualTerminal) != nil || !sameProduct(actualTerminal, terminal) {
		return ErrUntrusted
	}
	var input []map[string]json.RawMessage
	if decode(requests[1]["input"], &input) != nil {
		return ErrUntrusted
	}
	calls, outputs := 0, 0
	for _, item := range input {
		if isCall(item) {
			calls++
		}
		if childString(item, "type") == "function_call_output" && childString(item, "call_id") == t.ToolCallID {
			outputs++
			var output any
			if decode(item["output"], &output) != nil || childString(observation, "outputDigest") != CanonicalDigest(output) {
				return ErrUntrusted
			}
			switch output.(type) {
			case string, []any:
			default:
				return ErrUntrusted
			}
		}
	}
	if calls != 1 || outputs != 1 {
		return ErrUntrusted
	}
	return nil
}
