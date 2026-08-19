package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func main() {
	flags := flag.NewFlagSet("warpmetal-agentctl", flag.ExitOnError)
	stateRoot := flags.String("state-dir", "/var/lib/warpmetal", "runtime state directory")
	_ = flags.Parse(os.Args[1:])
	arguments := flags.Args()
	if len(arguments) != 2 || arguments[0] != "inspect" {
		fmt.Fprintln(os.Stderr, "usage: warpmetal-agentctl inspect <sandbox-name-or-id>")
		os.Exit(2)
	}
	store, err := state.Open(filepath.Join(*stateRoot, "runtime.sqlite3"))
	if err != nil {
		fatal(err)
	}
	defer store.Close()
	values, err := store.Sandboxes(context.Background())
	if err != nil {
		fatal(err)
	}
	for _, value := range values {
		if value.ID == arguments[1] || value.Name == arguments[1] {
			output := map[string]any{
				"id":                 value.ID,
				"name":               value.Name,
				"desiredState":       value.DesiredState,
				"observedState":      value.ObservedState,
				"generation":         value.Generation,
				"observedGeneration": value.ObservedGeneration,
				"lifetime":           value.Lifetime,
				"startedAt":          value.StartedAt,
				"expiresAt":          value.ExpiresAt,
				"resources":          value.Resources,
			}
			if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
				fatal(err)
			}
			return
		}
	}
	fatal(errors.New("sandbox_not_found"))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
