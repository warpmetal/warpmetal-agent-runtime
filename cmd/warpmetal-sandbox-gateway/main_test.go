package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type notifyingBuffer struct {
	mu         sync.Mutex
	buffer     bytes.Buffer
	firstWrite chan struct{}
	once       sync.Once
}

func newNotifyingBuffer() *notifyingBuffer {
	return &notifyingBuffer{firstWrite: make(chan struct{})}
}

func (buffer *notifyingBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	written, err := buffer.buffer.Write(value)
	if written > 0 {
		buffer.once.Do(func() { close(buffer.firstWrite) })
	}
	return written, err
}

func (buffer *notifyingBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func TestCopySessionOutputStreamsShortInteractiveOutputBeforeTrailer(t *testing.T) {
	marker := "a73d91c6048f2be5d98067ac3142fe09"
	prompt := "sandbox$ "
	reader, input := io.Pipe()
	output := newNotifyingBuffer()
	type copyResult struct {
		status int
		err    error
	}
	completed := make(chan copyResult, 1)
	go func() {
		status, err := copySessionOutput(reader, output, marker)
		completed <- copyResult{status: status, err: err}
	}()
	resultReceived := false
	defer func() {
		_ = input.Close()
		if !resultReceived {
			<-completed
		}
	}()

	if _, err := input.Write([]byte(prompt)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-output.firstWrite:
	case <-time.After(2 * time.Second):
		t.Fatal("short interactive output remained buffered until the exit trailer or EOF")
	}
	if got := output.String(); got != prompt {
		t.Fatalf("streamed output = %q, want %q", got, prompt)
	}

	trailer := "\x00warpmetal-exit:" + marker + ":73\n"
	if _, err := input.Write([]byte(trailer)); err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	result := <-completed
	resultReceived = true
	if result.err != nil || result.status != 73 {
		t.Fatalf("status/error = %d/%v, want 73/nil", result.status, result.err)
	}
	if got := output.String(); got != prompt {
		t.Fatalf("final output = %q, want %q", got, prompt)
	}
	if strings.Contains(output.String(), marker) || strings.Contains(output.String(), "warpmetal-exit") {
		t.Fatal("private exit trailer reached session output")
	}
}

func TestCopySessionOutputReturnsRemoteStatusAndPreservesOutput(t *testing.T) {
	marker := "c1295e7b43d8a60ff24791ce5ab306d4"
	payload := strings.Repeat("sandbox-output\n", 40)
	stream := payload + "\x00warpmetal-exit:" + marker + ":42\n"
	var output bytes.Buffer
	status, err := copySessionOutput(strings.NewReader(stream), &output, marker)
	if err != nil {
		t.Fatal(err)
	}
	if status != 42 {
		t.Fatalf("status = %d, want 42", status)
	}
	if output.String() != payload {
		t.Fatal("session output changed while removing the exit trailer")
	}
	if strings.Contains(output.String(), marker) || strings.Contains(output.String(), ":42\n") {
		t.Fatal("private exit marker or status reached session output")
	}
}

func TestCopySessionOutputPreservesEmbeddedNULAndMismatchedMarkerBytes(t *testing.T) {
	marker := "0123456789abcdef0123456789abcdef"
	payload := "ordinary\x00bytes\n\x00warpmetal-exit:ffffffffffffffffffffffffffffffff:0\nstill-output\n"
	stream := payload + "\x00warpmetal-exit:" + marker + ":1\n"
	var output bytes.Buffer
	status, err := copySessionOutput(strings.NewReader(stream), &output, marker)
	if err != nil {
		t.Fatal(err)
	}
	if status != 1 || output.String() != payload {
		t.Fatalf("status/output = %d/%q", status, output.String())
	}
}

func TestCopySessionOutputRejectsMissingTrailerWithoutDroppingOutput(t *testing.T) {
	marker := "0123456789abcdef0123456789abcdef"
	var output bytes.Buffer
	status, err := copySessionOutput(strings.NewReader("plain output"), &output, marker)
	if err == nil || status != 1 {
		t.Fatalf("status/error = %d/%v, want 1/error", status, err)
	}
	if output.String() != "plain output" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestEntrypointForwardsOriginalSSHCommandOnlyToPrivateSupervisor(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		`command := os.Getenv("SSH_ORIGINAL_COMMAND")`,
		`net.Dial("unix", "/run/warpmetal/supervisor.sock")`,
		"GrantID: os.Args[1]",
		"Command: command",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("forced gateway path omitted %q", required)
		}
	}
	for _, forbidden := range []string{
		`os/exec`,
		`exec.Command`,
		`/bin/sh`,
		`/bin/bash`,
		`ssh-keyscan`,
		`StrictHostKeyChecking`,
		`UserKnownHostsFile`,
		`KnownHostsCommand`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("gateway entrypoint added host execution or alternate trust path %q", forbidden)
		}
	}
}
