package providerexec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/providergateway"
)

// This file defines the exact closed wire contract of the external executor.
// There is exactly one request schema and exactly one response schema; anything
// outside them is rejected, never guessed around.
//
// Request (one JSON object on the executor's stdin, newline optional):
//
//	{
//	  "formatVersion": 1,
//	  "providerId": "github",
//	  "connectionId": "conn_...",
//	  "accountId": "acct_...",            // optional metadata
//	  "tool": {"name": "list_repos", "arguments": {<agent JSON object>}},
//	  "credential": {"kind": "oauth2", "fields": {"token": "<secret>"}}
//	}
//
// Response (one JSON object on the executor's stdout):
//
//	{"formatVersion": 1, "content": [{"type": "text", "text": "..."}], "isError": false}
//
// or the bounded provider-error shape:
//
//	{"formatVersion": 1, "error": {"code": "provider_error", "message": "..."}}
//
// Unknown response fields, trailing data, any formatVersion other than 1 and
// content types other than "text" are rejected.

// requestEnvelope is the single closed request schema.
type requestEnvelope struct {
	FormatVersion int               `json:"formatVersion"`
	ProviderID    string            `json:"providerId"`
	ConnectionID  string            `json:"connectionId"`
	AccountID     string            `json:"accountId,omitempty"`
	Tool          requestTool       `json:"tool"`
	Credential    requestCredential `json:"credential"`
}

// requestTool is the tool invocation part of the request.
type requestTool struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// requestCredential is the credential material the reviewed external command
// needs to perform the provider call. It travels only through stdin.
type requestCredential struct {
	Kind   string            `json:"kind"`
	Fields map[string]string `json:"fields"`
}

// responseEnvelope is the single closed response schema.
type responseEnvelope struct {
	FormatVersion int                    `json:"formatVersion"`
	Content       []responseContent      `json:"content,omitempty"`
	IsError       bool                   `json:"isError,omitempty"`
	Error         *responseEnvelopeError `json:"error,omitempty"`
}

// responseContent is one text content block. Text is the only supported type.
type responseContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// responseEnvelopeError is the bounded provider-error shape. It maps to a
// tool-level failure (isError) rather than a process or protocol failure.
type responseEnvelopeError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// buildRequest encodes the single bounded JSON request for one tool call and
// builds the redactor that covers the credential field values it carries.
// The call's per-call credential snapshot is copied, never mutated or retained.
func buildRequest(call providergateway.ToolCall) ([]byte, *redactor, error) {
	if !validToolName(call.Name) {
		return nil, nil, errors.New("provider executor: tool name is not a valid bounded identifier")
	}
	arguments := call.Arguments
	if len(bytes.TrimSpace(arguments)) == 0 || string(bytes.TrimSpace(arguments)) == "null" {
		arguments = json.RawMessage(`{}`)
	}
	if len(arguments) > maxRequestBytes {
		return nil, nil, fmt.Errorf("provider executor: tool arguments exceed %d bytes", maxRequestBytes)
	}
	if !json.Valid(arguments) {
		return nil, nil, errors.New("provider executor: tool arguments are not valid JSON")
	}
	if first := bytes.TrimSpace(arguments); len(first) == 0 || first[0] != '{' {
		return nil, nil, errors.New("provider executor: tool arguments must be a JSON object")
	}

	kind := ""
	fields := map[string]string{}
	if call.Credential != nil {
		kind = call.Credential.Kind
		fields = make(map[string]string, len(call.Credential.Fields))
		for name, value := range call.Credential.Fields {
			fields[name] = value
		}
	}
	request := requestEnvelope{
		FormatVersion: FormatVersion,
		ProviderID:    call.ProviderID,
		ConnectionID:  call.ConnectionID,
		AccountID:     call.AccountID,
		Tool: requestTool{
			Name:      call.Name,
			Arguments: arguments,
		},
		Credential: requestCredential{
			Kind:   kind,
			Fields: fields,
		},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, nil, errors.New("provider executor: request could not be encoded")
	}
	if len(payload) > maxRequestBytes {
		return nil, nil, fmt.Errorf("provider executor: request exceeds %d bytes", maxRequestBytes)
	}
	return payload, newRedactor(fields), nil
}

// decodeResponse strictly decodes the single bounded response object. Decoder
// error text is deliberately not surfaced: it can quote response-controlled
// field names, which may contain provider or credential data.
func decodeResponse(raw []byte) (*responseEnvelope, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("executor returned no response")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var response responseEnvelope
	if err := decoder.Decode(&response); err != nil {
		return nil, errors.New("executor response does not match the closed response schema")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("executor response has trailing data")
	}
	return &response, nil
}

// validate enforces the closed response contract beyond JSON shape.
func (r *responseEnvelope) validate() error {
	if r.FormatVersion != FormatVersion {
		return fmt.Errorf("response formatVersion must be %d", FormatVersion)
	}
	if r.Error != nil && r.Content != nil {
		return errors.New("response must carry either content or error, not both")
	}
	if r.Error != nil {
		if r.Error.Code != "" && (!validErrorCode(r.Error.Code) || len(r.Error.Code) > maxErrorCodeBytes) {
			return errors.New("response error code is not a bounded identifier")
		}
		if strings.TrimSpace(r.Error.Message) == "" {
			return errors.New("response error message is required")
		}
		return nil
	}
	if len(r.Content) == 0 {
		return errors.New("response content is required")
	}
	if len(r.Content) > maxContentBlocks {
		return fmt.Errorf("response content has more than %d blocks", maxContentBlocks)
	}
	for _, block := range r.Content {
		if block.Type != "text" {
			return errors.New("response content type must be text")
		}
	}
	return nil
}

// result renders a validated response as the gateway's tool-level outcome. A
// structured provider error becomes an isError ToolResult (a tool failure the
// model can react to), never a process-level error. All text is scrubbed of
// known credential values and bounded before it leaves this process.
func result(response *responseEnvelope, scrub *redactor, limit int) providergateway.ToolResult {
	if response.Error != nil {
		text := redactedBoundedText(response.Error.Message, scrub, maxErrorResponseTextBytes)
		return providergateway.ToolResult{Text: text, IsError: true}
	}
	texts := make([]string, len(response.Content))
	for index, block := range response.Content {
		texts[index] = block.Text
	}
	joined := strings.Join(texts, "\n")
	// Bound the joined text before redaction so the result cannot grow without
	// limit, then bound the redacted form as well (the redaction marker may be
	// longer than a very short secret value).
	joined = truncateText(joined, limit)
	return providergateway.ToolResult{
		Text:    redactedBoundedText(joined, scrub, limit),
		IsError: response.IsError,
	}
}

// redactedBoundedText sanitizes, redacts and truncates arbitrary executor text.
func redactedBoundedText(text string, scrub *redactor, limit int) string {
	return truncateText(sanitizeText(scrub.redact(text)), limit)
}

// validToolName enforces the same bounded ASCII identifier shape the provider
// gateway allows for declared tool names.
func validToolName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		isAlphanumeric := character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9'
		if isAlphanumeric {
			continue
		}
		if index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

// validErrorCode enforces a bounded safe identifier shape on the optional
// structured provider-error code.
func validErrorCode(code string) bool {
	for index := 0; index < len(code); index++ {
		character := code[index]
		isAlphanumeric := character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9'
		if isAlphanumeric {
			continue
		}
		if index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return len(code) > 0
}
