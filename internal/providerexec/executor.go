package providerexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/providergateway"
)

var (
	// errCallTimeout is the internal cancellation cause used when the configured
	// per-call timeout expires. It is mapped to context.DeadlineExceeded so the
	// gateway reports a stable "timed out" tool failure.
	errCallTimeout = errors.New("provider executor call timed out")
	// errResponseTooLarge is the internal cancellation cause used when the
	// executor's stdout exceeds the configured response bound.
	errResponseTooLarge = errors.New("provider executor response exceeded the configured limit")
)

// Executor runs one configured, reviewed external provider-executor command.
// It implements the providergateway.Executor contract and is safe for
// concurrent use: every CallTool launches an independent child process in its
// own process group.
//
// The Executor holds no credential: credential field values exist only in the
// per-call request payload and the transient redaction copies, both of which are
// released before CallTool returns.
type Executor struct {
	command          string
	args             []string
	timeout          time.Duration
	maxResponseBytes int
	logger           *log.Logger
}

var (
	_ providergateway.Executor            = (*Executor)(nil)
	_ providergateway.ToolTimeoutProvider = (*Executor)(nil)
)

// New validates the configuration, verifies the configured command is a
// reviewed executable regular file, and constructs the executor. It performs
// the executable-file checks that Config.Validate deliberately leaves to
// startup, and it never executes the command.
//
// A nil logger uses log.Default(). The executor never logs the request, the
// tool arguments, raw stdout or raw stderr.
func New(config Config, logger *log.Logger) (*Executor, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("provider executor: %w", err)
	}
	if err := validateCommandFile(config.Command); err != nil {
		return nil, fmt.Errorf("provider executor: %w", err)
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Executor{
		command:          config.Command,
		args:             append([]string(nil), config.Args...),
		timeout:          config.Timeout(),
		maxResponseBytes: config.ResponseLimit(),
		logger:           logger,
	}, nil
}

// ToolTimeout implements providergateway.ToolTimeoutProvider so the gateway can
// apply the same per-call bound as its own call deadline.
func (e *Executor) ToolTimeout() time.Duration {
	return e.timeout
}

// CallTool launches the configured command with no shell, writes one bounded
// JSON request to its stdin and maps one bounded JSON response from its stdout.
//
// A structured provider error reported by the executor becomes a ToolResult with
// IsError set (a tool failure the model can react to). A timeout, cancellation,
// process failure without a valid response, malformed/oversized response or
// contract violation returns an error, which the gateway turns into a bounded
// tool failure. Either way the child's process group is gone when CallTool
// returns.
func (e *Executor) CallTool(
	ctx context.Context,
	call providergateway.ToolCall,
) (providergateway.ToolResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return providergateway.ToolResult{}, fmt.Errorf("provider executor: %w", err)
	}

	payload, scrub, err := buildRequest(call)
	if err != nil {
		return providergateway.ToolResult{}, err
	}
	// The exact request bytes and the transient redaction copies exist for the
	// duration of this call only.
	defer zeroBytes(payload)
	defer scrub.release()

	timeoutCtx, cancelTimeout := context.WithTimeoutCause(ctx, e.timeout, errCallTimeout)
	defer cancelTimeout()
	callCtx, cancelCall := context.WithCancelCause(timeoutCtx)
	defer cancelCall(nil)

	stdout := newBoundedCapture(e.maxResponseBytes, func() { cancelCall(errResponseTooLarge) })
	stderr := newBoundedCapture(maxStderrBytes, nil)
	defer stdout.destroy()
	defer stderr.destroy()

	command := exec.CommandContext(callCtx, e.command, e.args...)
	command.Env = minimalEnv()
	command.Stdin = bytes.NewReader(payload)
	command.Stdout = stdout
	command.Stderr = stderr
	// A child that exits while a descendant keeps the inherited stdio pipes open
	// must not pin Wait forever.
	command.WaitDelay = processWaitDelay
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		// Cancellation, the per-call timeout and the response-limit abort all
		// kill the whole process group, so no descendant survives the call.
		return killProcessGroup(command)
	}

	if startErr := command.Start(); startErr != nil {
		if cause := context.Cause(callCtx); cause != nil {
			return providergateway.ToolResult{}, e.abortError(cause)
		}
		e.logger.Printf("provider executor: tool call failed: could not start the configured command")
		return providergateway.ToolResult{}, errors.New("provider executor: could not start the configured command")
	}
	waitErr := command.Wait()

	if cause := context.Cause(callCtx); cause != nil {
		// The process group was signalled through Cancel; sweep once more so a
		// descendant that outlived the group leader cannot leak.
		_ = killProcessGroup(command)
		return providergateway.ToolResult{}, e.abortError(cause)
	}
	if waitErr != nil {
		// A failed command must not leave background descendants behind.
		_ = killProcessGroup(command)
	}

	// A truncated stderr could have split a credential value across the capture
	// boundary, so a truncated stderr is never surfaced or logged at all.
	var stderrExcerpt []byte
	if !stderr.truncated() {
		stderrExcerpt = stderr.bytes()
	}
	response, decodeErr := decodeResponse(stdout.bytes())
	if decodeErr != nil {
		return providergateway.ToolResult{}, e.outputFailure(waitErr, stderrExcerpt, decodeErr, scrub)
	}
	if validateErr := response.validate(); validateErr != nil {
		return providergateway.ToolResult{}, e.outputFailure(waitErr, stderrExcerpt, validateErr, scrub)
	}
	if waitErr != nil && response.Error == nil && !response.IsError {
		return providergateway.ToolResult{}, e.outputFailure(
			waitErr, stderrExcerpt,
			errors.New("executor exited unsuccessfully without reporting a provider error"), scrub,
		)
	}
	return result(response, scrub, e.maxResponseBytes), nil
}

// abortError maps a per-call cancellation cause to a bounded, secret-free error.
// Timeout and cancellation wrap their context sentinels so the gateway can
// report a stable tool-level outcome.
func (e *Executor) abortError(cause error) error {
	switch {
	case errors.Is(cause, errCallTimeout):
		return fmt.Errorf(
			"provider executor: call exceeded the %s timeout: %w", e.timeout, context.DeadlineExceeded,
		)
	case errors.Is(cause, errResponseTooLarge):
		return fmt.Errorf(
			"provider executor: response exceeded the configured %d-byte limit", e.maxResponseBytes,
		)
	default:
		return fmt.Errorf("provider executor: call canceled: %w", cause)
	}
}

// outputFailure builds a bounded, redacted, logged error for a call whose child
// did not produce a valid response. The raw stdout is never included; stderr is
// reduced to a redacted, sanitized, bounded diagnostic excerpt.
func (e *Executor) outputFailure(
	waitErr error,
	rawStderr []byte,
	reason error,
	scrub *redactor,
) error {
	message := "provider executor: " + reason.Error()
	if waitErr != nil {
		message += " (" + exitStatus(waitErr) + ")"
	}
	if len(rawStderr) > 0 {
		excerpt := redactedBoundedText(string(rawStderr), scrub, maxErrorTextBytes)
		if excerpt != "" {
			message += ": " + excerpt
		}
	}
	e.logger.Printf("provider executor: tool call failed: %s", logSafe(message))
	return errors.New(message)
}

// exitStatus renders the child's bounded exit outcome without any provider data.
func exitStatus(waitErr error) string {
	var exitError *exec.ExitError
	if !errors.As(waitErr, &exitError) {
		return "unknown exit status"
	}
	if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
		if status.Signaled() {
			return "signal " + status.Signal().String()
		}
		return fmt.Sprintf("exit status %d", status.ExitStatus())
	}
	return fmt.Sprintf("exit status %d", exitError.ExitCode())
}

// validateCommandFile enforces the startup executable-file policy: the reviewed
// command must be an existing, non-symlink, executable regular file that is not
// group/world-writable and not setuid/setgid, in a directory that is not
// group/world-writable. Credential material is never involved.
func validateCommandFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("command %q is not available: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("command %q must not be a symbolic link", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("command %q must be a regular file", path)
	}
	permissions := info.Mode().Perm()
	if permissions&0o111 == 0 {
		return fmt.Errorf("command %q is not executable", path)
	}
	if permissions&0o022 != 0 {
		return fmt.Errorf("command %q must not be group- or world-writable", path)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return fmt.Errorf("command %q must not be setuid or setgid", path)
	}
	directory := filepath.Dir(path)
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("command directory %q is not available: %w", directory, err)
	}
	if !directoryInfo.IsDir() {
		return fmt.Errorf("command directory %q is not a directory", directory)
	}
	if directoryInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("command directory %q must not be group- or world-writable", directory)
	}
	return nil
}

// killProcessGroup SIGKILLs the command's process group. It is a no-op when the
// process never started or the group is already gone.
func killProcessGroup(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return nil
	}
	err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ESRCH):
		return nil
	default:
		return err
	}
}

// boundedCapture is a concurrency-safe io.Writer that keeps at most limit bytes
// and drains everything beyond it. Draining (rather than failing the write)
// keeps the child from blocking on a full pipe while the call aborts; the
// overflow is reported through onOverflow exactly as state, not as data.
type boundedCapture struct {
	mu         sync.Mutex
	buffer     []byte
	limit      int
	overflow   bool
	onOverflow func()
}

// newBoundedCapture creates a capture with the given bound and an optional
// overflow callback (used to abort a call whose stdout exceeded its limit).
func newBoundedCapture(limit int, onOverflow func()) *boundedCapture {
	return &boundedCapture{limit: limit, onOverflow: onOverflow}
}

// Write implements io.Writer. It always reports a full write; excess bytes are
// discarded.
func (c *boundedCapture) Write(payload []byte) (int, error) {
	c.mu.Lock()
	if !c.overflow {
		remaining := c.limit - len(c.buffer)
		if len(payload) <= remaining {
			c.buffer = append(c.buffer, payload...)
		} else {
			if remaining > 0 {
				c.buffer = append(c.buffer, payload[:remaining]...)
			}
			c.overflow = true
		}
	}
	overflow := c.overflow
	c.mu.Unlock()
	if overflow && c.onOverflow != nil {
		c.onOverflow()
	}
	return len(payload), nil
}

// truncated reports whether the capture bound was reached, which means the
// captured prefix is not the whole stream.
func (c *boundedCapture) truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.overflow
}

// bytes returns a copy of the captured prefix.
func (c *boundedCapture) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buffer...)
}

// destroy zeroizes the captured bytes.
func (c *boundedCapture) destroy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	zeroBytes(c.buffer)
	c.buffer = nil
}
