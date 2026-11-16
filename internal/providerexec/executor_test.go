package providerexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/providergateway"
)

const (
	testSecret         = "exec-test-secret-canary-91c7"
	testProviderID     = "github"
	testConnectionID   = "conn_exec0000000000000001"
	testAccountID      = "acct_exec0000000000000001"
	testCredentialKind = "oauth2"
	testToolName       = "list_repositories"
	testArgumentCanary = "argument-canary-77b2"
)

// logBuffer is a concurrency-safe log sink for assertions about log content.
type logBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *logBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

// writeShellCommand writes an owner-only executable fake provider executor and
// returns its absolute path. The file mode matches what New's startup policy
// requires; tests that exercise policy violations chmod explicitly.
func writeShellCommand(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provider-exec")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write fake provider executor: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod fake provider executor: %v", err)
	}
	return path
}

// newTestExecutor writes a fake command and constructs the executor under test.
func newTestExecutor(t *testing.T, body string, mutate func(*Config)) (*Executor, *logBuffer) {
	t.Helper()
	logs := &logBuffer{}
	config := Config{Command: writeShellCommand(t, body)}
	if mutate != nil {
		mutate(&config)
	}
	executor, err := New(config, log.New(logs, "", 0))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return executor, logs
}

// execTestCall is one fully-populated tool call: metadata, arguments and a
// per-call credential snapshot the way the provider gateway builds it.
func execTestCall() providergateway.ToolCall {
	return providergateway.ToolCall{
		Name:         testToolName,
		Arguments:    json.RawMessage(`{"q":"` + testArgumentCanary + `"}`),
		ProviderID:   testProviderID,
		ConnectionID: testConnectionID,
		AccountID:    testAccountID,
		Credential: &providergateway.ToolCredential{
			Kind:   testCredentialKind,
			Fields: map[string]string{"token": testSecret},
		},
	}
}

// successScript emits one valid success response.
const successScript = `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"ok"}],"isError":false}'
`

func requireNoSecret(t *testing.T, label string, payload []byte) {
	t.Helper()
	if bytes.Contains(payload, []byte(testSecret)) {
		t.Fatalf("%s leaked the credential secret", label)
	}
}

func requireNoSecretString(t *testing.T, label, payload string) {
	t.Helper()
	if strings.Contains(payload, testSecret) {
		t.Fatalf("%s leaked the credential secret", label)
	}
}

func TestCallToolSuccessAndRequestSchema(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "request.json")
	executor, logs := newTestExecutor(t, `cat > "$1"
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"ok"}],"isError":false}'
`, func(config *Config) {
		config.Args = []string{capture}
	})
	result, err := executor.CallTool(context.Background(), execTestCall())
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("CallTool() result isError: %+v", result)
	}
	if result.Text != "ok" {
		t.Fatalf("CallTool() text = %q, want %q", result.Text, "ok")
	}
	requireNoSecretString(t, "tool result", result.Text)
	requireNoSecretString(t, "executor logs", logs.String())

	// The request is one closed schema with exactly these fields.
	payload, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("read captured request: %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("captured request is not a JSON object: %v", err)
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	wantKeys := []string{"accountId", "connectionId", "credential", "formatVersion", "providerId", "tool"}
	if strings.Join(keys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("request keys = %v, want %v", keys, wantKeys)
	}
	var formatVersion int
	if err := json.Unmarshal(object["formatVersion"], &formatVersion); err != nil || formatVersion != 1 {
		t.Fatalf("request formatVersion = %s (err %v), want 1", object["formatVersion"], err)
	}
	var metadata struct {
		ProviderID   string `json:"providerId"`
		ConnectionID string `json:"connectionId"`
		AccountID    string `json:"accountId"`
	}
	if err := json.Unmarshal(payload, &metadata); err != nil {
		t.Fatalf("decode request metadata: %v", err)
	}
	if metadata.ProviderID != testProviderID || metadata.ConnectionID != testConnectionID ||
		metadata.AccountID != testAccountID {
		t.Fatalf("request metadata = %+v", metadata)
	}
	var tool struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(object["tool"], &tool); err != nil {
		t.Fatalf("decode request tool: %v", err)
	}
	if tool.Name != testToolName {
		t.Fatalf("request tool name = %q, want %q", tool.Name, testToolName)
	}
	var wantArguments, gotArguments any
	if err := json.Unmarshal(tool.Arguments, &gotArguments); err != nil {
		t.Fatalf("decode request arguments: %v", err)
	}
	if err := json.Unmarshal(execTestCall().Arguments, &wantArguments); err != nil {
		t.Fatalf("decode want arguments: %v", err)
	}
	gotArgumentJSON, _ := json.Marshal(gotArguments)
	wantArgumentJSON, _ := json.Marshal(wantArguments)
	if string(gotArgumentJSON) != string(wantArgumentJSON) {
		t.Fatalf("request arguments = %s, want %s", gotArgumentJSON, wantArgumentJSON)
	}
	var credential struct {
		Kind   string            `json:"kind"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(object["credential"], &credential); err != nil {
		t.Fatalf("decode request credential: %v", err)
	}
	if credential.Kind != testCredentialKind {
		t.Fatalf("request credential kind = %q, want %q", credential.Kind, testCredentialKind)
	}
	if credential.Fields["token"] != testSecret {
		t.Fatal("request credential did not carry the opened secret field")
	}
	// The argument canary is carried on stdin only; nothing in the request is
	// logged by the executor.
	requireNoSecretString(t, "executor logs after success", logs.String())
}

func TestCallToolWithoutCredentialSendsEmptyCredential(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "request.json")
	executor, _ := newTestExecutor(t, `cat > "$1"
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"ok"}]}'
`, func(config *Config) {
		config.Args = []string{capture}
	})
	call := execTestCall()
	call.Credential = nil
	if _, err := executor.CallTool(context.Background(), call); err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	payload, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("read captured request: %v", err)
	}
	var request struct {
		Credential requestCredential `json:"credential"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatalf("decode captured request: %v", err)
	}
	if request.Credential.Kind != "" || len(request.Credential.Fields) != 0 {
		t.Fatalf("credential without an opened credential = %+v", request.Credential)
	}
}

func TestCallToolNeverPassesCredentialInArgvOrEnvironment(t *testing.T) {
	t.Setenv("EXEC_TEST_AMBIENT_TOKEN", "ambient-token-canary-3d8a")
	t.Setenv("DSH_AMBIENT_SECRET", "dsh-ambient-canary-5c1f")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-ambient-canary-7e2b")
	argvCapture := filepath.Join(t.TempDir(), "argv.txt")
	envCapture := filepath.Join(t.TempDir(), "env.txt")
	executor, _ := newTestExecutor(t, `printf '%s\n' "$@" > "$1"
env > "$2"
cat > /dev/null
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"ok"}],"isError":false}'
`, func(config *Config) {
		config.Args = []string{argvCapture, envCapture, "reviewed-mode"}
	})
	if _, err := executor.CallTool(context.Background(), execTestCall()); err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	argv, err := os.ReadFile(argvCapture)
	if err != nil {
		t.Fatalf("read argv capture: %v", err)
	}
	argvLines := strings.Split(strings.TrimSpace(string(argv)), "\n")
	wantArgv := []string{argvCapture, envCapture, "reviewed-mode"}
	if strings.Join(argvLines, "|") != strings.Join(wantArgv, "|") {
		t.Fatalf("argv = %q, want %q", argvLines, wantArgv)
	}
	requireNoSecret(t, "argv", argv)
	if strings.Contains(string(argv), testArgumentCanary) {
		t.Fatal("argv leaked the tool arguments")
	}

	environment, err := os.ReadFile(envCapture)
	if err != nil {
		t.Fatalf("read env capture: %v", err)
	}
	for _, canary := range []string{
		"ambient-token-canary-3d8a", "dsh-ambient-canary-5c1f", "aws-ambient-canary-7e2b",
		"EXEC_TEST_AMBIENT_TOKEN", "DSH_AMBIENT_SECRET", "AWS_SECRET_ACCESS_KEY",
	} {
		if strings.Contains(string(environment), canary) {
			t.Fatalf("child environment leaked %q: %s", canary, environment)
		}
	}
	requireNoSecret(t, "child environment", environment)
	if !strings.Contains(string(environment), "PATH=") {
		t.Fatalf("child environment lost PATH: %s", environment)
	}
}

func TestCallToolRedactsCredentialFromResultText(t *testing.T) {
	executor, _ := newTestExecutor(t, `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"token=`+testSecret+` leaked"}],"isError":false}'
`, nil)
	result, err := executor.CallTool(context.Background(), execTestCall())
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	requireNoSecretString(t, "tool result", result.Text)
	if !strings.Contains(result.Text, "[redacted]") {
		t.Fatalf("tool result did not mark the redaction: %q", result.Text)
	}
}

func TestCallToolProviderErrorResponseIsToolLevelFailure(t *testing.T) {
	executor, logs := newTestExecutor(t, `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"error":{"code":"provider_error","message":"upstream rejected `+testSecret+`"}}'
exit 1
`, nil)
	result, err := executor.CallTool(context.Background(), execTestCall())
	if err != nil {
		t.Fatalf("CallTool() returned a process error for a structured provider error: %v", err)
	}
	if !result.IsError {
		t.Fatal("structured provider error was not mapped to an isError tool result")
	}
	requireNoSecretString(t, "tool error text", result.Text)
	if !strings.Contains(result.Text, "[redacted]") {
		t.Fatalf("tool error text did not mark the redaction: %q", result.Text)
	}
	requireNoSecretString(t, "executor logs", logs.String())
}

func TestCallToolIsErrorContentWithSuccessfulExit(t *testing.T) {
	executor, _ := newTestExecutor(t, `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"provider said no"}],"isError":true}'
`, nil)
	result, err := executor.CallTool(context.Background(), execTestCall())
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if !result.IsError || result.Text != "provider said no" {
		t.Fatalf("CallTool() result = %+v", result)
	}
}

func TestCallToolRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "not json", body: `cat > /dev/null
printf 'not-json'`},
		{name: "trailing data", body: `cat > /dev/null
printf '%s' '{"formatVersion":1,"content":[{"type":"text","text":"x"}]}{"again":true}'`},
		{name: "unknown field", body: `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"x"}],"extra":true}'`},
		{name: "unknown content field", body: `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"x","url":"http://x"}]}'`},
		{name: "wrong format version", body: `cat > /dev/null
printf '%s\n' '{"formatVersion":2,"content":[{"type":"text","text":"x"}]}'`},
		{name: "missing format version", body: `cat > /dev/null
printf '%s\n' '{"content":[{"type":"text","text":"x"}]}'`},
		{name: "non-text content", body: `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"content":[{"type":"image","text":"x"}]}'`},
		{name: "empty content", body: `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"content":[]}'`},
		{name: "content and error", body: `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"x"}],"error":{"message":"y"}}'`},
		{name: "error without message", body: `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"error":{"code":"provider_error"}}'`},
		{name: "unbounded error code", body: `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"error":{"code":"not a code","message":"y"}}'`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor, logs := newTestExecutor(t, test.body, nil)
			result, err := executor.CallTool(context.Background(), execTestCall())
			if err == nil {
				t.Fatalf("CallTool() accepted an invalid response: %+v", result)
			}
			requireNoSecretString(t, "returned error", err.Error())
			requireNoSecretString(t, "executor logs", logs.String())
		})
	}
}

func TestCallToolRejectsOversizedResponse(t *testing.T) {
	executor, logs := newTestExecutor(t, `cat > /dev/null
printf '%s' '{"formatVersion":1,"content":[{"type":"text","text":"'
dd if=/dev/zero bs=1024 count=8 2>/dev/null | tr '\000' 'a'
printf '%s\n' '"}]}'
`, func(config *Config) {
		config.MaxResponseBytes = MinMaxResponseBytes
	})
	result, err := executor.CallTool(context.Background(), execTestCall())
	if err == nil {
		t.Fatalf("CallTool() accepted an oversized response: %+v", result)
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized response error = %v, want a limit error", err)
	}
	requireNoSecretString(t, "returned error", err.Error())
	requireNoSecretString(t, "executor logs", logs.String())
}

func TestCallToolNonZeroExitWithoutResponseFailsClosed(t *testing.T) {
	executor, logs := newTestExecutor(t, `cat > /dev/null
printf 'upstream exploded with %s\n' '`+testSecret+`' >&2
exit 7
`, nil)
	result, err := executor.CallTool(context.Background(), execTestCall())
	if err == nil {
		t.Fatalf("CallTool() succeeded on a failing executor: %+v", result)
	}
	if !strings.Contains(err.Error(), "exit status 7") {
		t.Fatalf("error = %v, want the exit status", err)
	}
	if len(err.Error()) > 2048 {
		t.Fatalf("error text is not bounded: %d bytes", len(err.Error()))
	}
	requireNoSecretString(t, "returned error", err.Error())
	requireNoSecretString(t, "executor logs", logs.String())
}

func TestCallToolNonZeroExitWithSuccessPayloadFailsClosed(t *testing.T) {
	executor, _ := newTestExecutor(t, `cat > /dev/null
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"ok"}]}'
exit 3
`, nil)
	if _, err := executor.CallTool(context.Background(), execTestCall()); err == nil {
		t.Fatal("CallTool() accepted a successful payload from a failed process")
	}
}

func TestCallToolBoundedStderrDoesNotDeadlock(t *testing.T) {
	// The secret is written past the stderr capture bound, so the captured
	// prefix is truncated; a truncated stderr must never be surfaced or logged
	// because it could split a credential value across the boundary.
	executor, logs := newTestExecutor(t, `cat > /dev/null
dd if=/dev/zero bs=1024 count=64 2>/dev/null | tr '\000' 'e' >&2
printf '%s' '`+testSecret+`' >&2
exit 1
`, nil)
	started := time.Now()
	_, err := executor.CallTool(context.Background(), execTestCall())
	if err == nil {
		t.Fatal("CallTool() succeeded on a failing executor")
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("stderr flood took %s", elapsed)
	}
	if len(err.Error()) > 2048 {
		t.Fatalf("error text is not bounded: %d bytes", len(err.Error()))
	}
	requireNoSecretString(t, "returned error", err.Error())
	requireNoSecretString(t, "executor logs", logs.String())
}

func TestCallToolTimeoutKillsTheCall(t *testing.T) {
	executor, _ := newTestExecutor(t, `cat > /dev/null
sleep 30
`, func(config *Config) {
		config.TimeoutSeconds = 1
	})
	started := time.Now()
	_, err := executor.CallTool(context.Background(), execTestCall())
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("CallTool() did not time out")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
}

func TestCallToolContextCancellationKillsTheCall(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	executor, _ := newTestExecutor(t, `: > "$1"
sleep 30
`, func(config *Config) {
		config.Args = []string{marker}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := executor.CallTool(ctx, execTestCall())
		result <- err
	}()
	waitForFile(t, marker)
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("CallTool() returned no error after cancellation")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("CallTool() did not return after cancellation")
	}
}

func TestCallToolCancellationKillsWholeProcessGroup(t *testing.T) {
	base := filepath.Join(t.TempDir(), "pids")
	executor, _ := newTestExecutor(t, `: > "$1"
echo $$ > "$1.leader"
sleep 60 &
echo $! > "$1.child"
wait
`, func(config *Config) {
		config.Args = []string{base}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := executor.CallTool(ctx, execTestCall())
		result <- err
	}()
	leaderPID := waitForPID(t, base+".leader")
	childPID := waitForPID(t, base+".child")
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("CallTool() did not return after cancellation")
	}
	requireProcessGone(t, leaderPID)
	requireProcessGone(t, childPID)
}

func TestCallToolRejectsInvalidArgumentsWithoutLaunching(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "invoked")
	executor, _ := newTestExecutor(t, `: > "$1"
printf '%s\n' '{"formatVersion":1,"content":[{"type":"text","text":"ok"}]}'
`, func(config *Config) {
		config.Args = []string{marker}
	})
	tests := []struct {
		name string
		call providergateway.ToolCall
	}{
		{name: "invalid json", call: func() providergateway.ToolCall {
			call := execTestCall()
			call.Arguments = json.RawMessage(`{"q":`)
			return call
		}()},
		{name: "non-object arguments", call: func() providergateway.ToolCall {
			call := execTestCall()
			call.Arguments = json.RawMessage(`["q"]`)
			return call
		}()},
		{name: "invalid tool name", call: func() providergateway.ToolCall {
			call := execTestCall()
			call.Name = "bad tool name"
			return call
		}()},
		{name: "oversized stdin request", call: func() providergateway.ToolCall {
			call := execTestCall()
			call.Arguments = json.RawMessage(
				`{"q":"` + strings.Repeat("a", maxRequestBytes) + `"}`,
			)
			return call
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := executor.CallTool(context.Background(), test.call); err == nil {
				t.Fatal("CallTool() accepted an invalid tool call")
			}
			if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("executor was launched for an invalid tool call: %v", err)
			}
		})
	}
}

func TestNewValidatesCommandFile(t *testing.T) {
	directory := t.TempDir()
	executable := writeShellCommand(t, "exit 0\n")
	notExecutable := filepath.Join(directory, "not-executable")
	if err := os.WriteFile(notExecutable, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatalf("write non-executable file: %v", err)
	}
	groupWritable := filepath.Join(t.TempDir(), "group-writable")
	if err := os.WriteFile(groupWritable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write group-writable file: %v", err)
	}
	if err := os.Chmod(groupWritable, 0o775); err != nil {
		t.Fatalf("chmod group-writable file: %v", err)
	}
	symlink := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(executable, symlink); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	writableDirectory := filepath.Join(t.TempDir(), "writable-dir")
	if err := os.Mkdir(writableDirectory, 0o755); err != nil {
		t.Fatalf("create writable directory: %v", err)
	}
	if err := os.Chmod(writableDirectory, 0o777); err != nil {
		t.Fatalf("chmod writable directory: %v", err)
	}
	commandInWritableDirectory := filepath.Join(writableDirectory, "provider-exec")
	if err := os.WriteFile(commandInWritableDirectory, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write command in writable directory: %v", err)
	}
	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{name: "executable regular file", command: executable},
		{name: "missing file", command: filepath.Join(directory, "missing"), wantErr: true},
		{name: "directory", command: directory, wantErr: true},
		{name: "non-executable file", command: notExecutable, wantErr: true},
		{name: "group-writable file", command: groupWritable, wantErr: true},
		{name: "symlink", command: symlink, wantErr: true},
		{name: "command in a group/world-writable directory", command: commandInWritableDirectory, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(Config{Command: test.command}, nil)
			if test.wantErr && err == nil {
				t.Fatal("New() accepted an unsafe command")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("New() error = %v", err)
			}
		})
	}
}

func TestNewAppliesDefaultBounds(t *testing.T) {
	executor, err := New(Config{Command: writeShellCommand(t, "exit 0\n")}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := executor.ToolTimeout(); got != DefaultTimeout {
		t.Fatalf("ToolTimeout() = %s, want %s", got, DefaultTimeout)
	}
	if executor.maxResponseBytes != DefaultMaxResponseBytes {
		t.Fatalf("maxResponseBytes = %d, want %d", executor.maxResponseBytes, DefaultMaxResponseBytes)
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("file %q did not appear", path)
}

func waitForPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data))); parseErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pid file %q did not appear", path)
	return 0
}

// requireProcessGone waits until the process no longer exists.
func requireProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d survived process-group cancellation", pid)
}
