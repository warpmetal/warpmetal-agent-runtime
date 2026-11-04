package physicalgate

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Verify complete original SSE usage after the private journal hash/identity join.
// PRODUCT retains its frozen no-discount tariff; shell2/parent keep their existing
// cached-input tariff. A failure with no authenticated usage remains unknown.
func verifyOriginalUsage(consumer string, raw []byte, status int, reported int64) error {
	if status != 200 || len(raw) > 262144 || !utf8.Valid(raw) {
		return ErrPrerequisite
	}
	var completed map[string]json.RawMessage
	normalized := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	for _, frame := range bytes.Split(normalized, []byte("\n\n")) {
		var data [][]byte
		for _, line := range bytes.Split(frame, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("data:")) {
				data = append(data, bytes.TrimSpace(line[5:]))
			}
		}
		payload := bytes.Join(data, []byte("\n"))
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		var event map[string]json.RawMessage
		var kind string
		if model.DecodePhysicalClosed(payload, &event) != nil || json.Unmarshal(event["type"], &kind) != nil {
			return ErrPrerequisite
		}
		if kind == "error" || kind == "response.failed" || kind == "response.incomplete" {
			return ErrPrerequisite
		}
		if kind == "response.completed" {
			if completed != nil || model.DecodePhysicalClosed(event["response"], &completed) != nil || completed == nil {
				return ErrPrerequisite
			}
		}
	}
	var id, phase, selected string
	if completed == nil || json.Unmarshal(completed["id"], &id) != nil || id == "" || json.Unmarshal(completed["status"], &phase) != nil || phase != "completed" || json.Unmarshal(completed["model"], &selected) != nil || selected != "gpt-4.1-mini-2025-04-14" {
		return ErrPrerequisite
	}
	var usage map[string]json.RawMessage
	var input, output, cached int64
	if model.DecodePhysicalClosed(completed["usage"], &usage) != nil || json.Unmarshal(usage["input_tokens"], &input) != nil || json.Unmarshal(usage["output_tokens"], &output) != nil || input < 0 || output < 0 || output > 1000 || input > 1047576-output {
		return ErrPrerequisite
	}
	if details, ok := usage["input_tokens_details"]; ok {
		var fields map[string]json.RawMessage
		if model.DecodePhysicalClosed(details, &fields) != nil || json.Unmarshal(fields["cached_tokens"], &cached) != nil {
			return ErrPrerequisite
		}
	} else if consumer == "product" || consumer == "qualification" {
		return ErrPrerequisite
	}
	if cached < 0 || cached > input {
		return ErrPrerequisite
	}
	var weighted int64
	switch consumer {
	case "product":
		weighted = input*400000 + output*1600000
	case "parent", "qualification":
		weighted = (input-cached)*400000 + cached*100000 + output*1600000
	default:
		return ErrPrerequisite
	}
	if reported != (weighted+999999)/1000000 {
		return ErrPrerequisite
	}
	return nil
}
