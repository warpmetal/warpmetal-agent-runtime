package providergateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
)

// Wire limits and JSON-RPC error codes for the newline-delimited MCP subset.
const (
	// maxRequestBytes bounds one request line. A larger line is drained and
	// rejected rather than buffered without limit.
	maxRequestBytes = 1 << 20
	// maxResponseBytes is the hard ceiling for one response line. Content is
	// truncated well below it, so exceeding it is an internal error.
	maxResponseBytes = 2 << 20
	// maxToolResultBytes bounds one tool result text before JSON encoding.
	maxToolResultBytes = 128 << 10
	// maxErrorMessageBytes bounds executor error text returned to the agent.
	maxErrorMessageBytes = 1024
	// maxLogErrorBytes bounds executor error text written to the log.
	maxLogErrorBytes = 512

	jsonRPCVersion = "2.0"

	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603

	initializeMethod              = "initialize"
	initializedNotificationMethod = "notifications/initialized"
	pingMethod                    = "ping"
	toolsListMethod               = "tools/list"
	toolsCallMethod               = "tools/call"
)

// errExecutorPanic is returned internally when an Executor panics. The panic
// value is never surfaced or logged because it may contain provider data; the
// agent sees a generic tool failure.
var errExecutorPanic = errors.New("provider tool executor panicked")

// rpcRequest is one decoded JSON-RPC request or notification. A missing id
// field (len(ID) == 0) marks a notification, which never receives a response.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// rpcError is the JSON-RPC error object. Messages are gateway-generated and
// never contain tool arguments, results or credential material.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcSuccessResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

type rpcErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   rpcError        `json:"error"`
}

// contentItem is one MCP text content block.
type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolCallResult is the MCP tools/call result shape.
type toolCallResult struct {
	Content []contentItem `json:"content"`
	IsError bool          `json:"isError"`
}

// toolsListResult is the MCP tools/list result shape.
type toolsListResult struct {
	Tools []Tool `json:"tools"`
}

// initializeResult is the MCP initialize result shape. The gateway advertises
// only the tools capability.
type initializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    capabilities `json:"capabilities"`
	ServerInfo      serverInfo   `json:"serverInfo"`
}

type capabilities struct {
	Tools struct{} `json:"tools"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// dispatch handles one wire line and returns the response line to write, or nil
// when the request is a notification and must not be answered.
func (g *Gateway) dispatch(ctx context.Context, line []byte) []byte {
	request, requestErr := decodeRequest(line)
	if requestErr != nil {
		var id json.RawMessage
		if request != nil && validRequestID(request.ID) {
			id = request.ID
		}
		return encodeErrorResponse(id, requestErr)
	}
	if request.Method == initializedNotificationMethod {
		// MCP notifications/initialized is never answered, even if a malformed
		// client attaches an id to it.
		return nil
	}

	var result any
	var callErr *rpcError
	switch request.Method {
	case initializeMethod:
		result, callErr = g.handleInitialize(request.Params)
	case pingMethod:
		result = struct{}{}
	case toolsListMethod:
		result = toolsListResult{Tools: g.tools}
	case toolsCallMethod:
		result, callErr = g.handleToolCall(ctx, request.Params)
	default:
		callErr = newRPCError(codeMethodNotFound, "method not found")
	}

	if len(request.ID) == 0 {
		// JSON-RPC notification: processed but never answered.
		return nil
	}
	if callErr != nil {
		return encodeErrorResponse(request.ID, callErr)
	}
	return encodeResultResponse(request.ID, result)
}

// handleInitialize negotiates the MCP protocol version. A requested version the
// gateway supports is echoed; anything else falls back to
// DefaultProtocolVersion, which is what an older or unknown client should get
// rather than an error.
func (g *Gateway) handleInitialize(params json.RawMessage) (any, *rpcError) {
	var initializeParams struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if paramsErr := decodeParams(params, &initializeParams); paramsErr != nil {
		return nil, paramsErr
	}
	return initializeResult{
		ProtocolVersion: negotiateProtocolVersion(initializeParams.ProtocolVersion),
		Capabilities:    capabilities{},
		ServerInfo:      serverInfo{Name: ServerName, Version: ServerVersion},
	}, nil
}

// handleToolCall enforces the declared-tool allowlist before the Executor is
// reached, then renders the executor outcome as MCP content. Executor errors
// become isError content after sanitizing and redacting their text; they are
// never JSON-RPC errors, so the agent can retry or change strategy.
func (g *Gateway) handleToolCall(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if paramsErr := decodeParams(params, &call); paramsErr != nil {
		return nil, paramsErr
	}
	if call.Name == "" {
		return nil, newRPCError(codeInvalidParams, "invalid tool call")
	}
	if _, declared := g.declared[call.Name]; !declared {
		// The Executor is never consulted for an undeclared tool; this is the
		// scoping boundary the whole package exists for.
		return nil, newRPCError(codeInvalidParams, "unknown tool: "+boundedName(call.Name))
	}
	arguments := call.Arguments
	if len(arguments) == 0 || strings.TrimSpace(string(arguments)) == "null" {
		arguments = json.RawMessage(`{}`)
	}
	if !jsonObject(arguments) {
		return nil, newRPCError(codeInvalidParams, "invalid tool arguments")
	}

	callCtx, cancel := context.WithTimeout(ctx, g.toolTimeout)
	defer cancel()
	toolCall := g.executorToolCall(call.Name, arguments)
	// The per-call credential snapshot exists only for this invocation; scrub
	// it as soon as the Executor returned, on every path.
	defer releaseToolCredential(toolCall.Credential)
	result, err := g.invokeExecutor(callCtx, toolCall)
	if err != nil {
		text := g.describeError(err)
		g.logger.Printf("provider gateway: tool %q failed: %s", call.Name, logSafe(text))
		return toolCallResult{
			Content: []contentItem{{Type: "text", Text: text}},
			IsError: true,
		}, nil
	}
	text := truncateText(g.redact(sanitizeText(result.Text)), maxToolResultBytes)
	return toolCallResult{
		Content: []contentItem{{Type: "text", Text: text}},
		IsError: result.IsError,
	}, nil
}

// invokeExecutor isolates Executor panics. The recovered value is deliberately
// discarded: it can contain provider or credential data that must never reach a
// response or a log line.
func (g *Gateway) invokeExecutor(ctx context.Context, call ToolCall) (result ToolResult, err error) {
	defer func() {
		if recover() != nil {
			result = ToolResult{}
			err = errExecutorPanic
		}
	}()
	return g.executor.CallTool(ctx, call)
}

// describeError converts an executor failure into bounded, sanitized, redacted
// text that is safe to hand to the agent and to log. Timeout and cancellation
// are reported as stable messages rather than raw context errors.
func (g *Gateway) describeError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "tool execution timed out"
	case errors.Is(err, context.Canceled):
		return "tool execution canceled"
	case errors.Is(err, errExecutorPanic):
		return "tool execution failed"
	}
	text := truncateText(g.redact(sanitizeText(err.Error())), maxErrorMessageBytes)
	if strings.TrimSpace(text) == "" {
		return "tool execution failed"
	}
	return text
}

// decodeRequest parses one request line. A nil request with an error means the
// line was not JSON at all or was not a request object; a non-nil request with
// an error lets dispatch preserve a valid JSON-RPC id in the error response.
func decodeRequest(line []byte) (*rpcRequest, *rpcError) {
	if !json.Valid(line) {
		return nil, newRPCError(codeParseError, "parse error")
	}
	var request rpcRequest
	if err := json.Unmarshal(line, &request); err != nil {
		return nil, newRPCError(codeInvalidRequest, "invalid request")
	}
	if request.JSONRPC != jsonRPCVersion || request.Method == "" || !validRequestID(request.ID) {
		return &request, newRPCError(codeInvalidRequest, "invalid request")
	}
	return &request, nil
}

// validRequestID enforces the JSON-RPC id shape: string, number, null or
// absent. Objects and arrays are invalid request ids.
func validRequestID(id json.RawMessage) bool {
	if len(id) == 0 {
		return true
	}
	var value any
	if err := json.Unmarshal(id, &value); err != nil {
		return false
	}
	switch value.(type) {
	case nil, string, float64:
		return true
	default:
		return false
	}
}

// decodeParams decodes method params into target. Absent or null params leave
// target untouched; malformed params are an invalid-params error.
func decodeParams(params json.RawMessage, target any) *rpcError {
	if len(params) == 0 || strings.TrimSpace(string(params)) == "null" {
		return nil
	}
	if err := json.Unmarshal(params, target); err != nil {
		return newRPCError(codeInvalidParams, "invalid params")
	}
	return nil
}

// jsonObject reports whether raw is a JSON object. The line has already been
// validated as JSON, so checking the first non-space byte is sufficient.
func jsonObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func newRPCError(code int, message string) *rpcError {
	return &rpcError{Code: code, Message: message}
}

func negotiateProtocolVersion(requested string) string {
	for _, supported := range supportedProtocolVersions {
		if requested == supported {
			return requested
		}
	}
	return DefaultProtocolVersion
}

// boundedName renders a client-supplied name in an error message. It is
// truncated and stripped of control characters, which keeps JSON-RPC errors
// small and prevents log/terminal injection through tool names.
func boundedName(name string) string {
	name = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, name)
	return truncateText(name, maxToolNameBytes)
}

func encodeResultResponse(id json.RawMessage, result any) []byte {
	return encodeResponse(rpcSuccessResponse{JSONRPC: jsonRPCVersion, ID: id, Result: result})
}

func encodeErrorResponse(id json.RawMessage, rpcErr *rpcError) []byte {
	if rpcErr == nil {
		rpcErr = newRPCError(codeInternalError, "internal error")
	}
	return encodeResponse(rpcErrorResponse{JSONRPC: jsonRPCVersion, ID: id, Error: *rpcErr})
}

// encodeResponse marshals a response and enforces the hard response ceiling.
// Any marshaling or sizing failure produces a minimal internal error line that
// leaks nothing, though the per-content bounds should make that unreachable.
func encodeResponse(payload any) []byte {
	line, err := json.Marshal(payload)
	if err != nil || len(line) > maxResponseBytes {
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}`)
	}
	return line
}
