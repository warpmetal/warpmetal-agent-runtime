package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

var grantID = regexp.MustCompile(`^grant_[A-Za-z0-9_-]{8,60}$`)
var exitMarker = regexp.MustCompile(`^[a-f0-9]{32}$`)

const sessionHandoffCommand = "warpmetal-team-control"

type request struct {
	GrantID             string                  `json:"grantId"`
	Command             string                  `json:"command"`
	TTY                 bool                    `json:"tty"`
	SessionHandoff      *model.SessionHandoffV1 `json:"sessionHandoff,omitempty"`
	SessionHandoffHello []byte                  `json:"sessionHandoffHello,omitempty"`
}

type response struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error"`
	ExitMarker string `json:"exitMarker"`
}

type remoteExitError struct {
	code int
}

func (e *remoteExitError) Error() string { return "remote command exited unsuccessfully" }

func main() {
	if err := run(); err != nil {
		var remote *remoteExitError
		if errors.As(err, &remote) {
			os.Exit(remote.code)
		}
		fmt.Fprintln(os.Stderr, bounded(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 || !grantID.MatchString(os.Args[1]) {
		return errors.New("access_grant_unavailable")
	}
	command := os.Getenv("SSH_ORIGINAL_COMMAND")
	if len(command) > 8192 {
		return errors.New("remote_command_too_large")
	}
	input := io.Reader(os.Stdin)
	var handoff *model.SessionHandoffV1
	var handoffHello []byte
	var err error
	if command == sessionHandoffCommand {
		buffered := bufio.NewReader(os.Stdin)
		readContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		handoff, handoffHello, err = readSessionHandoffPreface(readContext, buffered)
		cancel()
		if err != nil {
			return errors.New("handoff_invalid")
		}
		input = buffered
	}
	connection, err := net.Dial("unix", "/run/warpmetal/supervisor.sock")
	if err != nil {
		return errors.New("sandbox_gateway_unavailable")
	}
	defer connection.Close()
	terminal := false
	if info, statErr := os.Stdin.Stat(); statErr == nil {
		terminal = info.Mode()&os.ModeCharDevice != 0
	}
	gatewayRequest := request{GrantID: os.Args[1], Command: command}
	gatewayRequest.TTY = terminal
	gatewayRequest.SessionHandoff = handoff
	gatewayRequest.SessionHandoffHello = handoffHello
	if err := json.NewEncoder(connection).Encode(gatewayRequest); err != nil {
		return errors.New("sandbox_gateway_unavailable")
	}
	reader := bufio.NewReader(connection)
	var reply response
	if err := json.NewDecoder(reader).Decode(&reply); err != nil || !reply.OK {
		if reply.Error != "" {
			return errors.New(reply.Error)
		}
		return errors.New("sandbox_gateway_unavailable")
	}
	if !exitMarker.MatchString(reply.ExitMarker) {
		return errors.New("sandbox_gateway_unavailable")
	}
	go func() {
		_, _ = io.Copy(connection, input)
		if unix, ok := connection.(*net.UnixConn); ok {
			_ = unix.CloseWrite()
		}
	}()
	status, err := copySessionOutput(reader, os.Stdout, reply.ExitMarker)
	if err != nil {
		return errors.New("sandbox_session_failed")
	}
	if status != 0 {
		return &remoteExitError{code: status}
	}
	return nil
}

type handoffPrefaceResult struct {
	target *model.SessionHandoffV1
	frame  []byte
	err    error
}

func readSessionHandoffPreface(
	ctx context.Context,
	reader *bufio.Reader,
) (*model.SessionHandoffV1, []byte, error) {
	result := make(chan handoffPrefaceResult, 1)
	go func() {
		var header [4]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			result <- handoffPrefaceResult{err: err}
			return
		}
		total := int(binary.BigEndian.Uint32(header[:]))
		if total < 2 || total+4 > 64*1024 {
			result <- handoffPrefaceResult{err: errors.New("invalid handoff frame length")}
			return
		}
		frame := make([]byte, total+4)
		copy(frame, header[:])
		if _, err := io.ReadFull(reader, frame[4:]); err != nil {
			result <- handoffPrefaceResult{err: err}
			return
		}
		if frame[4] != 0x01 {
			result <- handoffPrefaceResult{err: errors.New("invalid handoff frame type")}
			return
		}
		var envelope struct {
			Protocol string          `json:"protocol"`
			Handoff  json.RawMessage `json:"handoff"`
		}
		if err := json.Unmarshal(frame[5:], &envelope); err != nil || envelope.Protocol != "wm-team-control/1" {
			result <- handoffPrefaceResult{err: errors.New("invalid handoff HELLO")}
			return
		}
		if len(envelope.Handoff) == 0 || bytes.Equal(envelope.Handoff, []byte("null")) {
			result <- handoffPrefaceResult{frame: frame}
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(envelope.Handoff))
		decoder.DisallowUnknownFields()
		var target model.SessionHandoffV1
		if err := decoder.Decode(&target); err != nil {
			result <- handoffPrefaceResult{err: errors.New("invalid handoff target")}
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			result <- handoffPrefaceResult{err: errors.New("invalid handoff target")}
			return
		}
		result <- handoffPrefaceResult{target: &target, frame: frame}
	}()
	select {
	case value := <-result:
		return value.target, value.frame, value.err
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func copySessionOutput(reader io.Reader, writer io.Writer, marker string) (int, error) {
	prefix := []byte("\x00warpmetal-exit:" + marker + ":")
	pending := make([]byte, 0, len(prefix)+4)
	buffer := make([]byte, 32*1024)
	for {
		n, readError := reader.Read(buffer)
		if n > 0 {
			output := make([]byte, 0, n+len(pending))
			for _, value := range buffer[:n] {
				if len(pending) > 0 && sessionTrailerState(pending, prefix) == trailerComplete {
					// A real exit trailer is always the final bytes in the stream. If
					// more data follows, the candidate was ordinary sandbox output.
					output = append(output, pending...)
					pending = pending[:0]
				}
				if len(pending) == 0 && value != 0 {
					output = append(output, value)
					continue
				}
				pending = append(pending, value)
				if sessionTrailerState(pending, prefix) != trailerInvalid {
					continue
				}
				if value == 0 {
					output = append(output, pending[:len(pending)-1]...)
					pending = pending[:1]
					pending[0] = 0
				} else {
					output = append(output, pending...)
					pending = pending[:0]
				}
			}
			if len(output) > 0 {
				if _, err := writer.Write(output); err != nil {
					return 1, err
				}
			}
		}
		if readError != nil {
			if !errors.Is(readError, io.EOF) {
				return 1, readError
			}
			break
		}
	}
	if sessionTrailerState(pending, prefix) != trailerComplete {
		_, _ = writer.Write(pending)
		return 1, errors.New("missing exit status")
	}
	statusValue := pending[len(prefix) : len(pending)-1]
	status, err := strconv.Atoi(string(statusValue))
	if err != nil || status < 0 || status > 255 {
		return 1, errors.New("invalid exit status")
	}
	return status, nil
}

type trailerState uint8

const (
	trailerInvalid trailerState = iota
	trailerIncomplete
	trailerComplete
)

func sessionTrailerState(candidate, prefix []byte) trailerState {
	if len(candidate) <= len(prefix) {
		if bytes.Equal(candidate, prefix[:len(candidate)]) {
			return trailerIncomplete
		}
		return trailerInvalid
	}
	status := candidate[len(prefix):]
	if len(status) > 4 {
		return trailerInvalid
	}
	for index, value := range status {
		if value >= '0' && value <= '9' {
			if index >= 3 {
				return trailerInvalid
			}
			continue
		}
		if value == '\n' && index > 0 && index == len(status)-1 {
			return trailerComplete
		}
		return trailerInvalid
	}
	return trailerIncomplete
}

func bounded(value string) string {
	if len(value) > 160 {
		return value[:160]
	}
	return value
}
