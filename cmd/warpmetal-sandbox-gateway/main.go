package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
)

var grantID = regexp.MustCompile(`^grant_[A-Za-z0-9_-]{8,60}$`)

type request struct {
	GrantID string `json:"grantId"`
	Command string `json:"command"`
	TTY     bool   `json:"tty"`
}

type response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func main() {
	if err := run(); err != nil {
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
	copyError := make(chan error, 2)
	go func() {
		_, err := io.Copy(connection, os.Stdin)
		if unix, ok := connection.(*net.UnixConn); ok {
			_ = unix.CloseWrite()
		}
		copyError <- err
	}()
	go func() {
		_, err := io.Copy(os.Stdout, reader)
		copyError <- err
	}()
	for range 2 {
		if err := <-copyError; err != nil {
			return errors.New("sandbox_session_failed")
		}
	}
	return nil
}

func bounded(value string) string {
	if len(value) > 160 {
		return value[:160]
	}
	return value
}
