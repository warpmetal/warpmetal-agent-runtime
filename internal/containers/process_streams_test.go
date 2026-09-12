package containers

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const processStreamsChildMode = "WARPMETAL_PROCESS_STREAMS_CHILD_MODE"
const processStreamsTestTimeout = 5 * time.Second

func TestRunProcessStreamsReturnsWhenChildExitsWithInputStillOpen(t *testing.T) {
	stdin := newBlockingSessionInput()

	var stdout strings.Builder
	result := make(chan error, 1)
	go func() {
		result <- runProcessStreams(
			processStreamsCommand(context.Background(), "exit"),
			stdin,
			&stdout,
			io.Discard,
		)
	}()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("completed child returned an error: %v", err)
		}
		if got := stdout.String(); got != "finished\n" {
			t.Fatalf("child output = %q, want %q", got, "finished\\n")
		}
		stdin.requireInterruptedAndJoined(t)
	case <-time.After(processStreamsTestTimeout):
		t.Fatal("process runner waited for SSH input to close after the child exited")
	}
}

func TestRunProcessStreamsCancellationReturnsWithInputStillOpen(t *testing.T) {
	stdin := newBlockingSessionInput()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stdout := newProcessReadyWriter()
	result := make(chan error, 1)
	go func() {
		result <- runProcessStreams(
			processStreamsCommand(ctx, "wait"),
			stdin,
			stdout,
			io.Discard,
		)
	}()

	select {
	case <-stdout.ready:
	case err := <-result:
		t.Fatalf("child exited before cancellation: %v", err)
	case <-time.After(processStreamsTestTimeout):
		t.Fatal("child did not start")
	}
	cancel()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled child returned no error")
		}
		stdin.requireInterruptedAndJoined(t)
	case <-time.After(processStreamsTestTimeout):
		t.Fatal("process runner waited for SSH input to close after cancellation")
	}
}

func TestRunProcessStreamsPreservesExitStatusWhileJoiningInputPump(t *testing.T) {
	stdin := newBlockingSessionInput()
	result := make(chan error, 1)
	go func() {
		result <- runProcessStreams(
			processStreamsCommand(context.Background(), "exit-42"),
			stdin,
			io.Discard,
			io.Discard,
		)
	}()

	select {
	case err := <-result:
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() != 42 {
			t.Fatalf("child exit status = %v, want 42", err)
		}
		stdin.requireInterruptedAndJoined(t)
	case <-time.After(processStreamsTestTimeout):
		t.Fatal("process runner lost the child exit status while waiting on input")
	}
}

func TestRunProcessStreamsCopiesInputThroughEOF(t *testing.T) {
	stdin := &eofSessionInput{Reader: strings.NewReader("ordinary input")}
	var stdout strings.Builder
	if err := runProcessStreams(
		processStreamsCommand(context.Background(), "copy-input"),
		stdin,
		&stdout,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != "ordinary input" {
		t.Fatalf("copied stdin = %q, want %q", got, "ordinary input")
	}
}

func TestRunProcessStreamsReturnsGenuineInputReadErrorAfterSuccessfulChild(t *testing.T) {
	readError := errors.New("input read failed")
	stdin := &readErrorSessionInput{err: readError}
	if err := runProcessStreams(
		processStreamsCommand(context.Background(), "copy-input-delayed"),
		stdin,
		io.Discard,
		io.Discard,
	); !errors.Is(err, readError) {
		t.Fatalf("process error = %v, want input error %v", err, readError)
	}
}

func TestRunProcessStreamsSurfacesInterruptFailureAfterSuccessfulChild(t *testing.T) {
	interruptError := errors.New("interrupt failed")
	stdin := newNoisySessionInput(errors.New("teardown read noise"), interruptError)
	err := runProcessStreams(
		processStreamsCommand(context.Background(), "exit"),
		stdin,
		io.Discard,
		io.Discard,
	)
	if !errors.Is(err, interruptError) {
		t.Fatalf("process error = %v, want interrupt error %v", err, interruptError)
	}
	stdin.requireJoined(t)
}

func TestRunProcessStreamsExitStatusHasPriorityOverTeardownNoise(t *testing.T) {
	stdin := newNoisySessionInput(
		errors.New("teardown read noise"),
		errors.New("interrupt failed"),
	)
	err := runProcessStreams(
		processStreamsCommand(context.Background(), "exit-42"),
		stdin,
		io.Discard,
		io.Discard,
	)
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 42 {
		t.Fatalf("child exit status = %v, want 42", err)
	}
	stdin.requireJoined(t)
}

func TestRunProcessStreamsStartFailureDoesNotStartInputPump(t *testing.T) {
	stdin := newBlockingSessionInput()
	command := exec.Command(filepath.Join(t.TempDir(), "missing-process"))
	result := make(chan error, 1)
	go func() {
		result <- runProcessStreams(command, stdin, io.Discard, io.Discard)
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("missing process returned no start error")
		}
		select {
		case <-stdin.readStarted:
			t.Fatal("input pump started before the child process")
		default:
		}
	case <-time.After(processStreamsTestTimeout):
		t.Fatal("process start failure did not return promptly")
	}
}

func TestProcessStreamsChild(t *testing.T) {
	mode := os.Getenv(processStreamsChildMode)
	if mode == "" {
		return
	}
	switch mode {
	case "exit":
		_, _ = io.WriteString(os.Stdout, "finished\n")
		os.Exit(0)
	case "exit-42":
		os.Exit(42)
	case "copy-input":
		_, _ = io.Copy(os.Stdout, os.Stdin)
		os.Exit(0)
	case "copy-input-delayed":
		_, _ = io.Copy(io.Discard, os.Stdin)
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)
	case "wait":
		_, _ = io.WriteString(os.Stdout, "ready\n")
		for {
			time.Sleep(time.Hour)
		}
	default:
		os.Exit(2)
	}
}

var _ SessionInput = (*blockingSessionInput)(nil)
var _ SessionInput = (*eofSessionInput)(nil)

type blockingSessionInput struct {
	readOnce      sync.Once
	interruptOnce sync.Once
	returnOnce    sync.Once
	readStarted   chan struct{}
	interrupted   chan struct{}
	readReturned  chan struct{}
}

func newBlockingSessionInput() *blockingSessionInput {
	return &blockingSessionInput{
		readStarted:  make(chan struct{}),
		interrupted:  make(chan struct{}),
		readReturned: make(chan struct{}),
	}
}

func (i *blockingSessionInput) Read(_ []byte) (int, error) {
	i.readOnce.Do(func() { close(i.readStarted) })
	<-i.interrupted
	i.returnOnce.Do(func() { close(i.readReturned) })
	return 0, io.EOF
}

func (i *blockingSessionInput) InterruptRead() error {
	i.interruptOnce.Do(func() { close(i.interrupted) })
	return nil
}

func (i *blockingSessionInput) requireInterruptedAndJoined(t *testing.T) {
	t.Helper()
	select {
	case <-i.readStarted:
	default:
		t.Fatal("input pump did not start")
	}
	select {
	case <-i.interrupted:
	default:
		t.Fatal("open input read was not interrupted")
	}
	select {
	case <-i.readReturned:
	default:
		t.Fatal("process runner returned before its input pump exited")
	}
}

type eofSessionInput struct {
	*strings.Reader
}

func (i *eofSessionInput) InterruptRead() error { return nil }

type readErrorSessionInput struct {
	err error
}

func (i *readErrorSessionInput) Read(_ []byte) (int, error) { return 0, i.err }
func (i *readErrorSessionInput) InterruptRead() error       { return nil }

type noisySessionInput struct {
	readError      error
	interruptError error
	interrupted    chan struct{}
	readReturned   chan struct{}
	interruptOnce  sync.Once
	returnOnce     sync.Once
}

func newNoisySessionInput(readError, interruptError error) *noisySessionInput {
	return &noisySessionInput{
		readError:      readError,
		interruptError: interruptError,
		interrupted:    make(chan struct{}),
		readReturned:   make(chan struct{}),
	}
}

func (i *noisySessionInput) Read(_ []byte) (int, error) {
	<-i.interrupted
	i.returnOnce.Do(func() { close(i.readReturned) })
	return 0, i.readError
}

func (i *noisySessionInput) InterruptRead() error {
	i.interruptOnce.Do(func() { close(i.interrupted) })
	return i.interruptError
}

func (i *noisySessionInput) requireJoined(t *testing.T) {
	t.Helper()
	select {
	case <-i.readReturned:
	default:
		t.Fatal("process runner returned before the noisy input pump exited")
	}
}

func processStreamsCommand(ctx context.Context, mode string) *exec.Cmd {
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProcessStreamsChild$")
	command.Env = append(os.Environ(), processStreamsChildMode+"="+mode)
	return command
}

type processReadyWriter struct {
	once  sync.Once
	ready chan struct{}
}

func newProcessReadyWriter() *processReadyWriter {
	return &processReadyWriter{ready: make(chan struct{})}
}

func (w *processReadyWriter) Write(value []byte) (int, error) {
	if strings.Contains(string(value), "ready\n") {
		w.once.Do(func() { close(w.ready) })
	}
	return len(value), nil
}
