package providergateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/boxcredentials"
)

const (
	// ServerName is the MCP serverInfo name the gateway reports. Sandbox-side
	// MCP configuration will name the server this way.
	ServerName = "warpmetal-provider-gateway"
	// ServerVersion is the MCP serverInfo version the gateway reports.
	ServerVersion = "0.1.0"
	// DefaultProtocolVersion is the MCP protocol version the gateway prefers: it
	// is used when the client asks for a version the gateway does not support.
	DefaultProtocolVersion = "2025-06-18"

	// defaultToolTimeout bounds one executor call when Config.ToolTimeout is
	// unset.
	defaultToolTimeout = 30 * time.Second
	// maxToolTimeout bounds Config.ToolTimeout so a misconfiguration cannot make
	// a hung provider tool outlive a request indefinitely.
	maxToolTimeout = 10 * time.Minute

	// maxDeclaredTools bounds the declared tool list. Each tool is advertised to
	// the agent; a template can never need a larger set.
	maxDeclaredTools = 256
	// maxToolNameBytes bounds one tool name.
	maxToolNameBytes = 128
	// maxToolDescriptionBytes bounds one tool description.
	maxToolDescriptionBytes = 4 << 10
	// maxToolSchemaBytes bounds one tool input schema.
	maxToolSchemaBytes = 64 << 10
	// maxDeclaredSchemaBytes bounds the total advertised schema size so one
	// tools/list response stays well inside maxResponseBytes.
	maxDeclaredSchemaBytes = 1 << 20
	// maxMetadataBytes bounds the non-secret provider/connection identifiers.
	maxMetadataBytes = 256
)

// supportedProtocolVersions is the closed set of MCP protocol versions the
// gateway speaks. Newer versions are wire-compatible for this subset; a client
// that requests another version is answered with DefaultProtocolVersion.
var supportedProtocolVersions = []string{
	DefaultProtocolVersion,
	"2025-03-26",
	"2024-11-05",
}

// toolNamePattern is the MCP-safe tool name shape: no whitespace, no slashes, no
// JSON-RPC control characters. The gateway refuses to advertise anything else
// because the sandbox agent will use these names in generated MCP config.
var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Tool is one template-declared provider tool the gateway is allowed to expose.
// The JSON tags are the MCP wire shape used by tools/list.
type Tool struct {
	// Name is the MCP tool name the agent calls.
	Name string `json:"name"`
	// Description is the tool description shown to the model. Optional.
	Description string `json:"description,omitempty"`
	// InputSchema is the raw JSON object schema advertised through tools/list.
	// The gateway validates that it is a JSON object but does not execute it:
	// P2 has no JSON-schema validation of tool arguments.
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ToolCall is one tools/call invocation handed to an Executor. It contains no
// credential material: the opened credential stays inside the gateway.
type ToolCall struct {
	// Name is a declared tool name that has already passed the allowlist.
	Name string
	// Arguments is the raw JSON object the agent supplied. It is never logged.
	Arguments json.RawMessage
}

// ToolResult is an Executor's tool-level outcome. The gateway renders Text as a
// single MCP text content block; IsError maps to MCP isError so the model sees a
// tool failure while the JSON-RPC session stays usable.
type ToolResult struct {
	// Text is the tool output. It is returned to the agent and is never logged;
	// known credential secret values are redacted before it leaves the process.
	Text string
	// IsError marks a tool-level failure rather than a protocol failure.
	IsError bool
}

// Executor executes one declared provider tool call. Implementations must be
// safe for concurrent use and must honor ctx cancellation, because connections
// are served concurrently and every call is bounded by Config.ToolTimeout.
//
// The Executor is the only place provider work happens. It deliberately
// receives no credential: a provider client is expected to have been built with
// the opened credential by the caller that also builds the Executor, and the
// gateway only ever holds the credential for redaction and destruction. That
// keeps credential material out of the tool result path by construction.
type Executor interface {
	CallTool(ctx context.Context, call ToolCall) (ToolResult, error)
}

// Credential is the gateway's view of one opened provider credential: P2's
// *boxcredentials.Credential satisfies it, and tests substitute a fake that can
// observe destruction. The gateway calls SecretFields at construction time only
// to snapshot the values it must redact, then calls Destroy exactly once when
// the gateway is closed.
type Credential interface {
	// SecretFields returns a fresh copy of the credential's secret field values.
	// The gateway only uses them for redaction and never logs or returns them.
	SecretFields() map[string]string
	// Destroy zeroizes the credential. The gateway calls it exactly once.
	Destroy()
}

// The production P2 credential type is exactly this interface.
var _ Credential = (*boxcredentials.Credential)(nil)

// Config configures one Provider Gateway.
//
// Config holds the opened credential and is deliberately not a serialization
// DTO: the gateway never logs or marshals it (see String, which renders only
// non-secret metadata).
type Config struct {
	// SocketPath is the absolute Unix domain socket path the gateway creates and
	// the sandbox-side socat dials. Required. The socket is created 0600 and its
	// directory must be owner-only: Serve creates a missing directory 0700 and
	// refuses an existing one that grants group or other access.
	SocketPath string
	// RootDir optionally constrains where the socket may live: when set, the
	// socket's directory must resolve inside this root (after resolving
	// symlinks), and the root must already exist. Empty means "the socket's own
	// directory is the root", which only enforces that the directory itself is
	// owner-only.
	RootDir string
	// ProviderID is the non-secret tool provider identifier (for example
	// "github"). Required; used for logs only.
	ProviderID string
	// ConnectionID is the non-secret platform account connection identifier.
	// Required; used for logs only.
	ConnectionID string
	// Tools is the template-declared tool allowlist. Exactly these tools are
	// advertised and callable. Required, at least one.
	Tools []Tool
	// Executor executes tool calls. Required.
	Executor Executor
	// Credential is the opened provider credential held in memory, or nil when
	// the gateway is run without one (tests, or a provider that needs none).
	// Production passes a *boxcredentials.Credential directly; declared as the
	// narrow Credential interface so tests can inject a destroy-observable fake.
	// The gateway owns it once New succeeds and destroys it on close.
	Credential Credential
	// Logger receives secret-free lifecycle and failure lines. Nil uses
	// log.Default(). The gateway never logs tool arguments or results.
	Logger *log.Logger
	// ToolTimeout bounds one executor call. Zero uses defaultToolTimeout.
	ToolTimeout time.Duration
}

// Validate checks the static configuration. It performs no I/O; Serve performs
// the socket filesystem checks (directory creation, symlink escape, stale
// socket, permissions).
func (c Config) Validate() error {
	if strings.TrimSpace(c.SocketPath) == "" {
		return errors.New("providergateway: socket path is required")
	}
	if strings.ContainsRune(c.SocketPath, 0) {
		return errors.New("providergateway: socket path contains a NUL byte")
	}
	if !filepath.IsAbs(c.SocketPath) {
		return errors.New("providergateway: socket path must be absolute")
	}
	if filepath.Clean(c.SocketPath) != c.SocketPath {
		return errors.New("providergateway: socket path must be a clean path")
	}
	base := filepath.Base(c.SocketPath)
	if base == "." || base == ".." || base == string(filepath.Separator) {
		return errors.New("providergateway: socket path must name a file")
	}
	if c.RootDir != "" {
		if strings.ContainsRune(c.RootDir, 0) {
			return errors.New("providergateway: root directory contains a NUL byte")
		}
		if !filepath.IsAbs(c.RootDir) {
			return errors.New("providergateway: root directory must be absolute")
		}
		if filepath.Clean(c.RootDir) != c.RootDir {
			return errors.New("providergateway: root directory must be a clean path")
		}
	}
	if err := validateMetadata("provider id", c.ProviderID); err != nil {
		return err
	}
	if err := validateMetadata("connection id", c.ConnectionID); err != nil {
		return err
	}
	if c.Executor == nil {
		return errors.New("providergateway: executor is required")
	}
	if len(c.Tools) == 0 {
		return errors.New("providergateway: at least one declared tool is required")
	}
	if len(c.Tools) > maxDeclaredTools {
		return fmt.Errorf("providergateway: at most %d declared tools are supported", maxDeclaredTools)
	}
	seen := make(map[string]struct{}, len(c.Tools))
	totalSchemaBytes := 0
	for index := range c.Tools {
		tool := c.Tools[index]
		if err := validateTool(tool); err != nil {
			return err
		}
		if _, duplicate := seen[tool.Name]; duplicate {
			return fmt.Errorf("providergateway: duplicate declared tool %q", tool.Name)
		}
		seen[tool.Name] = struct{}{}
		totalSchemaBytes += len(tool.InputSchema)
	}
	if totalSchemaBytes > maxDeclaredSchemaBytes {
		return fmt.Errorf("providergateway: declared tool schemas exceed %d bytes in total", maxDeclaredSchemaBytes)
	}
	if c.ToolTimeout < 0 {
		return errors.New("providergateway: tool timeout must not be negative")
	}
	if c.ToolTimeout > maxToolTimeout {
		return fmt.Errorf("providergateway: tool timeout must not exceed %s", maxToolTimeout)
	}
	return nil
}

// String renders non-secret configuration metadata for diagnostics. It is safe
// to log; the credential, its secret values and the executor are never
// rendered. Config is not a serialization DTO.
func (c Config) String() string {
	timeout := c.ToolTimeout
	if timeout <= 0 {
		timeout = defaultToolTimeout
	}
	return fmt.Sprintf(
		"providergateway.Config{socketPath=%q rootDir=%q providerId=%q connectionId=%q tools=%d hasCredential=%t toolTimeout=%s}",
		c.SocketPath, c.RootDir, c.ProviderID, c.ConnectionID, len(c.Tools), c.Credential != nil, timeout,
	)
}

// GoString renders Config the same non-secret way for %#v.
func (c Config) GoString() string {
	return c.String()
}

// Format implements fmt.Formatter so every verb renders the non-secret form.
// Without it, a verb that does not consult fmt.Stringer (for example %d) could
// reflect into the Credential or Executor fields of Config.
func (c Config) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(c.String()))
}

func validateMetadata(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("providergateway: %s is required", field)
	}
	if len(value) > maxMetadataBytes {
		return fmt.Errorf("providergateway: %s is too long", field)
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return fmt.Errorf("providergateway: %s must not contain whitespace or control characters", field)
		}
		if !unicode.IsPrint(character) {
			return fmt.Errorf("providergateway: %s must be printable", field)
		}
	}
	return nil
}

func validateTool(tool Tool) error {
	if !toolNamePattern.MatchString(tool.Name) {
		return fmt.Errorf("providergateway: declared tool %q has an invalid name", tool.Name)
	}
	if len(tool.Name) > maxToolNameBytes {
		return fmt.Errorf("providergateway: declared tool %q has a too-long name", tool.Name)
	}
	if len(tool.Description) > maxToolDescriptionBytes {
		return fmt.Errorf("providergateway: declared tool %q has a too-long description", tool.Name)
	}
	if !utf8.ValidString(tool.Description) {
		return fmt.Errorf("providergateway: declared tool %q description is not valid UTF-8", tool.Name)
	}
	if len(tool.InputSchema) == 0 {
		return fmt.Errorf("providergateway: declared tool %q has no input schema", tool.Name)
	}
	if len(tool.InputSchema) > maxToolSchemaBytes {
		return fmt.Errorf("providergateway: declared tool %q input schema is too large", tool.Name)
	}
	if !json.Valid(tool.InputSchema) {
		return fmt.Errorf("providergateway: declared tool %q input schema is not valid JSON", tool.Name)
	}
	// A JSON object is the only usable MCP input schema shape. Checking the first
	// non-space byte rejects JSON null, which json.Unmarshal would otherwise
	// accept into a nil map.
	if !jsonObject(tool.InputSchema) {
		return fmt.Errorf("providergateway: declared tool %q input schema must be a JSON object", tool.Name)
	}
	return nil
}
