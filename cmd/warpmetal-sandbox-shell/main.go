package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
)

var forcedCommand = regexp.MustCompile(
	`^/usr/libexec/warpmetal-sandbox-gateway (grant_[A-Za-z0-9_-]{8,60})$`,
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "-c" {
		deny()
	}
	match := forcedCommand.FindStringSubmatch(strings.TrimSpace(os.Args[2]))
	if len(match) != 2 {
		deny()
	}
	path := "/usr/libexec/warpmetal-sandbox-gateway"
	if err := syscall.Exec(path, []string{path, match[1]}, os.Environ()); err != nil {
		deny()
	}
}

func deny() {
	fmt.Fprintln(os.Stderr, "sandbox_gateway_unavailable")
	os.Exit(1)
}
