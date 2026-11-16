// Package providerexec implements Phase P4a of the provider gateway: the bounded
// contract between the Runtime's scoped provider gateway and a reviewed
// external provider-executor command.
//
// The gateway never hardcodes provider execution. Instead, the operator may
// configure one external executor command (the later containerized skills/CLI
// gateway). For every declared tools/call the gateway hands this package:
//
//   - the tool name and its raw JSON arguments,
//   - the non-secret provider/connection/account binding metadata,
//   - a per-call credential snapshot (the platform-declared material kind plus
//     the opened secret field values).
//
// Executor.CallTool launches the configured command with no shell
// (os/exec with exec.CommandContext), writes exactly one bounded JSON request to
// its stdin, reads exactly one bounded JSON response from its stdout, and maps
// that response to providergateway.ToolResult. Credential field values are only
// ever carried through the stdin request: they are never placed in argv, the
// environment, a file, a log line or a tool result.
//
// Security properties of one call:
//
//   - no shell interpretation: the command and its bounded arguments are exec'd
//     directly; shell metacharacters have no meaning;
//   - the command must be an absolute, executable, non-symlink regular file that
//     is not group/world-writable and not setuid/setgid, checked at startup; the
//     check cannot eliminate a replacement race, so the reviewed command is
//     expected to live in a root-owned location that ordinary users cannot
//     rewrite;
//   - the child runs in its own process group; cancellation, timeout and
//     response-limit aborts kill the whole group, so no child process survives
//     the call or Runtime shutdown;
//   - the inherited environment is rebuilt from a minimal allowlist
//     (PATH/HOME/LANG), so ambient KEY/PASSWORD/SECRET/TOKEN/DSH_* variables are
//     never visible to the executor;
//   - the request and response are bounded (maxRequestBytes / configured
//     maxResponseBytes), extra response fields are rejected, and the response
//     formatVersion is exact;
//   - every known credential field value is redacted from response text, error
//     text and log lines, and the raw request/response/stderr are never logged.
//
// With no executor configured the provider gateway keeps its P2d fail-closed
// behavior: a manifest that requires provider gateways fails the reconcile pass
// with an explicit "feature not enabled" error and no provider call is made.
package providerexec

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// FormatVersion is the only request and response envelope version this
	// package speaks. Any other value is rejected.
	FormatVersion = 1

	// DefaultTimeout bounds one external executor call when
	// Config.TimeoutSeconds is unset.
	DefaultTimeout = 60 * time.Second
	// MinTimeout is the smallest configured per-call timeout.
	MinTimeout = time.Second
	// MaxTimeout bounds a configured per-call timeout so a hung provider tool
	// cannot outlive a request for an unbounded time.
	MaxTimeout = 5 * time.Minute

	// DefaultMaxResponseBytes bounds the executor's stdout response when
	// Config.MaxResponseBytes is unset.
	DefaultMaxResponseBytes = 1 << 20
	// MinMaxResponseBytes is the smallest accepted response bound.
	MinMaxResponseBytes = 1 << 10
	// MaxMaxResponseBytes is the largest accepted response bound.
	MaxMaxResponseBytes = 8 << 20

	// MaxCommandPathBytes bounds the configured command path.
	MaxCommandPathBytes = 4096
	// MaxArgs bounds the number of configured executor arguments.
	MaxArgs = 64
	// MaxArgBytes bounds one configured executor argument.
	MaxArgBytes = 4096
	// MaxArgsBytes bounds all configured executor arguments together.
	MaxArgsBytes = 16 << 10

	// maxRequestBytes bounds the single JSON request written to the executor's
	// stdin. Tool arguments are already bounded by the provider gateway and
	// credential material by the Box credential payload ceiling, so this is a
	// defence-in-depth ceiling rather than the primary limit.
	maxRequestBytes = 2 << 20
	// maxStderrBytes bounds the stderr diagnostic tail kept for error text.
	maxStderrBytes = 4 << 10
	// maxErrorTextBytes bounds error text derived from executor output.
	maxErrorTextBytes = 512
	// maxErrorResponseTextBytes bounds the text of a structured provider-error
	// response handed back to the agent as a tool failure.
	maxErrorResponseTextBytes = 4 << 10
	// maxContentBlocks bounds one response content array.
	maxContentBlocks = 64
	// maxErrorCodeBytes bounds a structured provider-error code.
	maxErrorCodeBytes = 64
	// processWaitDelay bounds how long Wait may keep waiting for inherited I/O
	// pipes after the command's main process exited or was cancelled.
	processWaitDelay = 2 * time.Second
)

// Config is the operator-facing JSON configuration of the optional external
// provider executor, embedded in the runtime config's toolCredentialBridge
// section as "providerExecutor".
//
// Validate performs static checks only (no filesystem I/O); the executable-file
// checks happen when the executor is constructed at Runtime startup.
type Config struct {
	// Command is the absolute path of the reviewed external executor command.
	// Required whenever the providerExecutor object is present. It is exec'd
	// directly, never through a shell.
	Command string `json:"command"`
	// Args is the optional bounded argument vector passed to the command. The
	// Runtime never adds credential material or tool data to argv.
	Args []string `json:"args,omitempty"`
	// TimeoutSeconds bounds one external executor call. Zero selects
	// DefaultTimeout; explicit values must be between MinTimeout and MaxTimeout.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
	// MaxResponseBytes bounds the executor's stdout response. Zero selects
	// DefaultMaxResponseBytes; explicit values must be between
	// MinMaxResponseBytes and MaxMaxResponseBytes.
	MaxResponseBytes int `json:"maxResponseBytes,omitempty"`
}

// Validate checks the static configuration. A nil Config validates as "not
// configured", which keeps an absent providerExecutor inert.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	if strings.TrimSpace(c.Command) == "" {
		return errors.New("provider executor command is required")
	}
	if len(c.Command) > MaxCommandPathBytes {
		return fmt.Errorf("provider executor command path exceeds %d bytes", MaxCommandPathBytes)
	}
	if err := validatePlainString("provider executor command", c.Command); err != nil {
		return err
	}
	if !filepath.IsAbs(c.Command) {
		return errors.New("provider executor command must be an absolute path")
	}
	if filepath.Clean(c.Command) != c.Command {
		return errors.New("provider executor command must be a clean path")
	}
	switch filepath.Base(c.Command) {
	case ".", "..", string(filepath.Separator):
		return errors.New("provider executor command must name a file")
	}
	if len(c.Args) > MaxArgs {
		return fmt.Errorf("provider executor accepts at most %d arguments", MaxArgs)
	}
	totalArgBytes := 0
	for _, argument := range c.Args {
		if len(argument) > MaxArgBytes {
			return fmt.Errorf("provider executor argument exceeds %d bytes", MaxArgBytes)
		}
		if err := validatePlainString("provider executor argument", argument); err != nil {
			return err
		}
		totalArgBytes += len(argument)
	}
	if totalArgBytes > MaxArgsBytes {
		return fmt.Errorf("provider executor arguments exceed %d bytes in total", MaxArgsBytes)
	}
	if c.TimeoutSeconds < 0 {
		return errors.New("provider executor timeoutSeconds must not be negative")
	}
	if c.TimeoutSeconds != 0 {
		timeout := time.Duration(c.TimeoutSeconds) * time.Second
		if timeout < MinTimeout || timeout > MaxTimeout {
			return fmt.Errorf(
				"provider executor timeoutSeconds must be between %d and %d",
				int(MinTimeout/time.Second), int(MaxTimeout/time.Second),
			)
		}
	}
	if c.MaxResponseBytes < 0 {
		return errors.New("provider executor maxResponseBytes must not be negative")
	}
	if c.MaxResponseBytes != 0 &&
		(c.MaxResponseBytes < MinMaxResponseBytes || c.MaxResponseBytes > MaxMaxResponseBytes) {
		return fmt.Errorf(
			"provider executor maxResponseBytes must be between %d and %d",
			MinMaxResponseBytes, MaxMaxResponseBytes,
		)
	}
	return nil
}

// Timeout is the effective per-call timeout, applying DefaultTimeout for an
// unset value. The caller must have validated c (or be prepared for a negative
// value to be treated as the default).
func (c Config) Timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return DefaultTimeout
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// ResponseLimit is the effective stdout response bound, applying
// DefaultMaxResponseBytes for an unset value.
func (c Config) ResponseLimit() int {
	if c.MaxResponseBytes <= 0 {
		return DefaultMaxResponseBytes
	}
	return c.MaxResponseBytes
}

// validatePlainString rejects NUL bytes, invalid UTF-8 and control characters in
// operator-provided path/argument strings. Shell metacharacters are deliberately
// allowed: there is no shell, so they are literal data. Whitespace is allowed
// because absolute paths and arguments may legitimately contain spaces.
func validatePlainString(field, value string) error {
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("%s contains a NUL byte", field)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}
