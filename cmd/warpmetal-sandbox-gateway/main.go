package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
)

var grantID = regexp.MustCompile(`^grant_[A-Za-z0-9_-]{8,60}$`)
var exitMarker = regexp.MustCompile(`^[a-f0-9]{32}$`)

type request struct {
	GrantID string `json:"grantId"`
	Command string `json:"command"`
	TTY     bool   `json:"tty"`
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
	connection, err := net.Dial("unix", "/run/warpmetal/supervisor.sock")
	if err != nil {
		return errors.New("sandbox_gateway_unavailable")
	}
	defer connection.Close()
	terminal := false
	if info, statErr := os.Stdin.Stat(); statErr == nil {
		terminal = info.Mode()&os.ModeCharDevice != 0
	}
	if err := json.NewEncoder(connection).Encode(request{
		GrantID: os.Args[1],
		Command: command,
		TTY:     terminal,
	}); err != nil {
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
		_, _ = io.Copy(connection, os.Stdin)
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

func copySessionOutput(reader io.Reader, writer io.Writer, marker string) (int, error) {
	const retainedBytes = 128
	tail := make([]byte, 0, retainedBytes)
	buffer := make([]byte, 32*1024)
	for {
		n, readError := reader.Read(buffer)
		if n > 0 {
			tail = append(tail, buffer[:n]...)
			if len(tail) > retainedBytes {
				flush := len(tail) - retainedBytes
				if _, err := writer.Write(tail[:flush]); err != nil {
					return 1, err
				}
				tail = append(tail[:0], tail[flush:]...)
			}
		}
		if readError != nil {
			if !errors.Is(readError, io.EOF) {
				return 1, readError
			}
			break
		}
	}
	prefix := []byte("\x00warpmetal-exit:" + marker + ":")
	index := bytes.LastIndex(tail, prefix)
	if index < 0 || len(tail) == 0 || tail[len(tail)-1] != '\n' {
		_, _ = writer.Write(tail)
		return 1, errors.New("missing exit status")
	}
	statusValue := tail[index+len(prefix) : len(tail)-1]
	status, err := strconv.Atoi(string(statusValue))
	if err != nil || status < 0 || status > 255 {
		_, _ = writer.Write(tail)
		return 1, errors.New("invalid exit status")
	}
	if _, err := writer.Write(tail[:index]); err != nil {
		return 1, err
	}
	return status, nil
}

func bounded(value string) string {
	if len(value) > 160 {
		return value[:160]
	}
	return value
}
