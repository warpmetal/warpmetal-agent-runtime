package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/capacity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/config"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/reconcile"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "register" {
		if err := register(os.Args[2:]); err != nil {
			log.Fatal(bounded(err.Error()))
		}
		return
	}
	if err := serve(os.Args[1:]); err != nil {
		log.Fatal(bounded(err.Error()))
	}
}

func register(arguments []string) error {
	flags := flag.NewFlagSet("register", flag.ContinueOnError)
	apiOrigin := flags.String("api", "https://api.warpmetal.com", "WarpMetal API origin")
	serverID := flags.String("server", "", "registered server ID")
	configPath := flags.String("config", "/var/lib/warpmetal/runtime.json", "root-only config path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !strings.HasPrefix(*serverID, "srv_") {
		return errors.New("a valid --server is required")
	}
	reader := bufio.NewReader(io.LimitReader(os.Stdin, 513))
	bootstrap, err := reader.ReadString('\n')
	if err != nil && bootstrap == "" {
		return errors.New("bootstrap token is required on stdin")
	}
	bootstrap = strings.TrimSpace(bootstrap)
	if len(bootstrap) > 512 {
		return errors.New("bootstrap input is too large")
	}
	if !strings.HasPrefix(bootstrap, "rtb_") {
		return errors.New("bootstrap token is invalid")
	}
	hostKeys, err := readHostKeys()
	if err != nil {
		return err
	}
	client := control.Client{Origin: *apiOrigin}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	registered, err := client.Register(ctx, bootstrap, control.Registration{
		ServerID:          *serverID,
		SupervisorVersion: version,
		HostKeys:          hostKeys,
	})
	bootstrap = ""
	if err != nil {
		return err
	}
	return config.Save(*configPath, config.Config{
		APIOrigin:          *apiOrigin,
		ServerID:           registered.ServerID,
		NodeToken:          registered.NodeToken,
		NodeTokenExpiresAt: registered.ExpiresAt,
	})
}

func serve(arguments []string) error {
	flags := flag.NewFlagSet("warpmetald", flag.ContinueOnError)
	stateRoot := flags.String("state-dir", "/var/lib/warpmetal", "runtime state directory")
	workspaceRoot := flags.String(
		"workspace-dir",
		"/var/lib/warpmetal-workspaces",
		"sandbox workspace image directory",
	)
	configPath := flags.String("config", "/var/lib/warpmetal/runtime.json", "root-only config path")
	socketPath := flags.String("socket", "/run/warpmetal/supervisor.sock", "gateway socket")
	accessPath := flags.String(
		"authorized-keys",
		"/etc/ssh/warpmetal_sandbox_authorized_keys",
		"generated gateway key map",
	)
	poll := flags.Duration("poll", 10*time.Second, "control-plane poll interval")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	settings, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load registration: %w", err)
	}
	store, err := state.Open(filepath.Join(*stateRoot, "runtime.sqlite3"))
	if err != nil {
		return err
	}
	defer store.Close()
	hostCapacity, err := capacity.Detect(*workspaceRoot)
	if err != nil {
		return fmt.Errorf("detect host capacity: %w", err)
	}
	engine := containers.Podman{RuntimeUser: "warpmetal-runtime"}
	gateway := &access.Gateway{Store: store, Engine: engine}
	reconciler := &reconcile.Reconciler{
		Store:        store,
		Engine:       engine,
		Workspaces:   storage.Workspace{Root: *workspaceRoot, Owner: "warpmetal-runtime"},
		Access:       access.Renderer{Path: *accessPath},
		Sessions:     gateway,
		HostCapacity: hostCapacity,
		ServerID:     settings.ServerID,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	gatewayErrors := make(chan error, 1)
	go func() { gatewayErrors <- gateway.Serve(ctx, *socketPath) }()
	client := control.Client{Origin: settings.APIOrigin, NodeToken: settings.NodeToken}
	hostKeys, err := readHostKeys()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(maxDuration(*poll, 2*time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-gatewayErrors:
			if err != nil {
				return fmt.Errorf("gateway stopped: %w", err)
			}
		case <-ticker.C:
			iteration, cancel := context.WithTimeout(ctx, 45*time.Second)
			err := reconciler.Expire(iteration)
			var manifest model.Manifest
			if err == nil {
				manifest, err = client.Manifest(iteration)
			}
			if err == nil {
				err = reconciler.Reconcile(iteration, manifest)
			}
			report, reportErr := reconciler.Report(iteration, settings.ServerID, version)
			report.HostKeys = hostKeys
			if manifest.ImageDigest != "" {
				report.ImageDigest = manifest.ImageDigest
			}
			if err != nil {
				report.LastError = &model.ItemError{
					Code:    "reconcile_failed",
					Message: bounded(err.Error()),
				}
			}
			if reportErr == nil {
				reportErr = client.Report(iteration, report)
			}
			cancel()
			if reportErr != nil {
				log.Printf("runtime report failed: %s", bounded(reportErr.Error()))
			}
		}
	}
}

func readHostKeys() ([]model.HostKey, error) {
	paths, err := filepath.Glob("/etc/ssh/ssh_host_*_key.pub")
	if err != nil {
		return nil, err
	}
	var keys []model.HostKey
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(string(content))
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid SSH host key %s", path)
		}
		keys = append(keys, model.HostKey{PublicKey: fields[0] + " " + fields[1]})
	}
	if len(keys) == 0 {
		return nil, errors.New("no SSH host public keys were found")
	}
	return keys, nil
}

func bounded(value string) string {
	if len(value) > 300 {
		return value[:300]
	}
	return value
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}
