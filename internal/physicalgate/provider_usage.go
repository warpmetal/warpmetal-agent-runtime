package physicalgate

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
)

// ProviderResponseUsage selects a tariff only from trusted private authority,
// never from the response's model name. Missing/ambiguous originals stay UNKNOWN.
func ProviderResponseUsage(policyDigest string, raw []byte, status int) (string, int64, error) {
	id, cost, _, err := ProviderResponseUsageOriginal(policyDigest, raw, status)
	return id, cost, err
}

// The signed nonsensitive projection is derived from the same validated original.
func ProviderResponseUsageOriginal(policyDigest string, raw []byte, status int) (string, int64, providerpolicy.Usage, error) {
	p, selectedPolicy := providerpolicy.Select(policyDigest)
	if !selectedPolicy || status != 200 || len(raw) == 0 || len(raw) > 262144 || !utf8.Valid(raw) {
		return "", 0, providerpolicy.Usage{}, ErrPrerequisite
	}
	var completed map[string]json.RawMessage
	for _, frame := range bytes.Split(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")), []byte("\n\n")) {
		var data [][]byte
		for _, line := range bytes.Split(frame, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("data:")) {
				data = append(data, bytes.TrimSpace(line[5:]))
			}
		}
		value := bytes.Join(data, []byte("\n"))
		if len(value) == 0 || bytes.Equal(value, []byte("[DONE]")) {
			continue
		}
		var event map[string]json.RawMessage
		var kind string
		if model.DecodePhysicalClosed(value, &event) != nil || json.Unmarshal(event["type"], &kind) != nil || kind == "error" || kind == "response.failed" || kind == "response.incomplete" {
			return "", 0, providerpolicy.Usage{}, ErrPrerequisite
		}
		if completed != nil {
			return "", 0, providerpolicy.Usage{}, ErrPrerequisite
		}
		if kind == "response.completed" {
			if model.DecodePhysicalClosed(event["response"], &completed) != nil || completed == nil {
				return "", 0, providerpolicy.Usage{}, ErrPrerequisite
			}
		}
	}
	var id, phase, selected string
	if completed == nil || json.Unmarshal(completed["id"], &id) != nil || !model.PhysicalIDValid(id) || json.Unmarshal(completed["status"], &phase) != nil || phase != "completed" || json.Unmarshal(completed["model"], &selected) != nil || selected != p.ModelID {
		return "", 0, providerpolicy.Usage{}, ErrPrerequisite
	}
	var usage map[string]json.RawMessage
	var input, output, cached int64
	if model.DecodePhysicalClosed(completed["usage"], &usage) != nil || json.Unmarshal(usage["input_tokens"], &input) != nil || json.Unmarshal(usage["output_tokens"], &output) != nil || input < 0 || output < 0 || output > int64(p.Request.MaxOutputTokens) || input > int64(p.Request.InputTokenUpperBound) {
		return "", 0, providerpolicy.Usage{}, ErrPrerequisite
	}
	if value, ok := usage["input_tokens_details"]; ok {
		var details map[string]json.RawMessage
		if model.DecodePhysicalClosed(value, &details) != nil {
			return "", 0, providerpolicy.Usage{}, ErrPrerequisite
		}
		if value, ok := details["cached_tokens"]; ok && json.Unmarshal(value, &cached) != nil {
			return "", 0, providerpolicy.Usage{}, ErrPrerequisite
		}
	}
	if cached < 0 || cached > input {
		return "", 0, providerpolicy.Usage{}, ErrPrerequisite
	}
	if value, ok := usage["total_tokens"]; ok {
		var total int64
		if json.Unmarshal(value, &total) != nil || total != input+output {
			return "", 0, providerpolicy.Usage{}, ErrPrerequisite
		}
	}
	var items []map[string]json.RawMessage
	if json.Unmarshal(completed["output"], &items) != nil || items == nil {
		return "", 0, providerpolicy.Usage{}, ErrPrerequisite
	}
	tools := 0
	for _, item := range items {
		var kind string
		if json.Unmarshal(item["type"], &kind) != nil {
			return "", 0, providerpolicy.Usage{}, ErrPrerequisite
		}
		switch kind {
		case "message":
		case "function_call":
			tools++
		default:
			return "", 0, providerpolicy.Usage{}, ErrPrerequisite
		}
	}
	if tools > 1 {
		return "", 0, providerpolicy.Usage{}, ErrPrerequisite
	}
	cost := (input*p.Accounting.InputMicrosPerMillion + output*p.Accounting.OutputMicrosPerMillion + 999999) / 1000000
	if cost > p.Accounting.RequestReserveMicros {
		return "", 0, providerpolicy.Usage{}, ErrPrerequisite
	}
	return id, cost, providerpolicy.Usage{InputTokens: input, OutputTokens: output, CachedInputTokens: cached}, nil
}
