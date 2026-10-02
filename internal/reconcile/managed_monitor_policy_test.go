package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type monitorConsumerValidation struct {
	Action     string         `json:"action"`
	Request    map[string]any `json:"request"`
	Normalized map[string]any `json:"normalized"`
	Refusal    string         `json:"refusal"`
}

// monitorConsumerRuntime keeps the existing native receipt fixture while the
// unmodified Python Sandbox consumer validates every monitor status/restart
// request before that fixture can accept it. It performs no native execution.
type monitorConsumerRuntime struct {
	*fakeManagedRuntime
	python      string
	consumer    string
	sandboxRoot string
	validations []monitorConsumerValidation
}

func (runtime *monitorConsumerRuntime) ExecManagedSupervisor(ctx context.Context, sandboxID string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	if runtime.consumer == "" {
		return runtime.fakeManagedRuntime.ExecManagedSupervisor(ctx, sandboxID, action, payload)
	}
	const adapter = `
import importlib.util
import json
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location("monitor_contract_consumer", sys.argv[1])
consumer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = consumer
spec.loader.exec_module(consumer)
try:
    normalized = consumer.validate_request(sys.argv[3], json.load(sys.stdin), root=Path(sys.argv[2]))
except consumer.RequestError as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)
json.dump(normalized, sys.stdout, sort_keys=True)
`
	command := exec.CommandContext(ctx, runtime.python, "-c", adapter, runtime.consumer, runtime.sandboxRoot, string(action))
	command.Stdin = bytes.NewReader(payload)
	output, err := command.CombinedOutput()
	validation := monitorConsumerValidation{Action: string(action)}
	if decodeErr := json.Unmarshal(payload, &validation.Request); decodeErr != nil {
		return nil, nil, decodeErr
	}
	if err != nil {
		validation.Refusal = strings.TrimSpace(string(output))
		runtime.validations = append(runtime.validations, validation)
		return nil, nil, fmt.Errorf("actual Sandbox validate_request refused %s: %s", action, validation.Refusal)
	}
	if err := json.Unmarshal(output, &validation.Normalized); err != nil {
		return nil, nil, fmt.Errorf("actual Sandbox validator output: %w", err)
	}
	runtime.validations = append(runtime.validations, validation)
	return runtime.fakeManagedRuntime.ExecManagedSupervisor(ctx, sandboxID, action, payload)
}

func TestManagedMonitorPolicyRestartsOnlyAtSafeIdleWithPinnedConfiguration(t *testing.T) {
	sandboxSource := os.Getenv("WARP_METAL_SANDBOX_SOURCE")
	mode := "standalone pinned fixture"
	var consumerPath, python string
	var consumerBytes []byte
	if sandboxSource != "" {
		mode = "actual Sandbox validate_request"
		consumerPath = filepath.Join(sandboxSource, "runner", "warpmetal_opencode_supervisor.py")
		var err error
		consumerBytes, err = os.ReadFile(consumerPath)
		if err != nil {
			t.Fatal(err)
		}
		python, err = exec.LookPath("python3")
		if err != nil {
			t.Fatal(err)
		}
	} else if os.Getenv("WARPMETAL_MONITOR_CONTRACT_EVIDENCE") != "" {
		t.Fatal("WARP_METAL_SANDBOX_SOURCE is required when real monitor consumer evidence is requested")
	}
	t.Logf("monitor policy journey mode=%s", mode)
	fixture := loadProducerFixture(t)
	// The older synthetic producer fixture predates the Sandbox's exact
	// sbx_ + 24-character identity. Bind the complete fixture to one admitted
	// sandbox identity before any persistent/native authority is created.
	sandboxID := "sbx_0123456789abcdef01234567"
	fixture.SetupManifest.SandboxID = sandboxID
	fixture.WorkspaceRequestManifest.SandboxID = sandboxID
	fixture.WorkspaceCatalogReport.SandboxID = sandboxID
	fixture.ServiceManifest.Identity.SandboxID = sandboxID
	fixture.ServiceReport.Identity.SandboxID = sandboxID
	fixture.EnrollmentRequest.SandboxID = sandboxID
	fixture.InstructionRequest.SandboxID = sandboxID
	databasePath := t.TempDir() + "/runtime.sqlite3"
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedReadyProfile(t, store, fixture.SetupManifest)
	now := time.Date(2026, 9, 27, 17, 0, 0, 0, time.UTC)
	// The disposable fixture uses a physical container view so the consumer's
	// canonical/no-symlink projectRoot validation runs without path rewriting.
	sandboxRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	catalogFixtureStore, err := state.Open(filepath.Join(t.TempDir(), "catalog-fixture.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer catalogFixtureStore.Close()
	catalog := &workspacecatalog.Catalog{State: catalogFixtureStore, Now: func() time.Time { return now }}
	workspace, err := catalog.EnsureDefault(context.Background(), workspacecatalog.DefaultProjectRequest{
		Anchor: sandboxRoot, ServerID: fixture.ServiceManifest.Identity.ServerID,
		TeamID: fixture.ServiceManifest.Identity.TeamID, MemberID: fixture.ServiceManifest.Identity.MemberID,
		SandboxID: fixture.ServiceManifest.Identity.SandboxID, SandboxGeneration: fixture.ServiceManifest.Identity.SandboxGeneration,
		ServiceRegistrationID: fixture.ServiceManifest.Identity.ServiceRegistrationID,
		AllocationDigest:      fixture.WorkspaceRequestManifest.AllocationDigest, ConfigDigest: fixture.ServiceManifest.ConfigDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	workspace.ContainerRoot = workspace.HostRoot
	localProject, err := catalogFixtureStore.ManagedProject(context.Background(), workspace.Report.SelectionID)
	if err != nil || localProject == nil {
		t.Fatalf("managed project fixture = %#v, %v", localProject, err)
	}
	localProject.ContainerRoot = workspace.ContainerRoot
	if err := store.PutManagedProject(context.Background(), *localProject); err != nil {
		t.Fatal(err)
	}
	catalog.State = store
	fixture.ServiceManifest.Workspace.SelectionID = workspace.Report.SelectionID
	fixture.ServiceManifest.Workspace.ProjectID = workspace.Report.ProjectID
	fixture.ServiceManifest.Workspace.WorkspaceEpoch = workspace.Report.WorkspaceEpoch
	fixture.ServiceManifest.Workspace.RootAttestation = workspace.Report.RootAttestation
	control := &fakeManagedControl{fixture: fixture}
	runtime := &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture}
	reconciler := &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtime, Now: func() time.Time { return now }}
	manifest := model.Manifest{ServerID: fixture.ServiceManifest.Identity.ServerID, DesiredRevision: fixture.ServiceManifest.DesiredRevision, ManagedServices: []model.ManagedServiceV1{fixture.ServiceManifest}}
	if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	sourceID := managedSourceID(fixture.ServiceManifest.Identity.ServiceRegistrationID)
	source, err := store.ContinuitySource(context.Background(), sourceID)
	if err != nil || source == nil {
		t.Fatalf("managed source = %#v, %v", source, err)
	}
	source.NoAdmittedExecution = true
	if err := store.PutContinuitySource(context.Background(), *source); err != nil {
		t.Fatal(err)
	}
	consumerRuntime := &monitorConsumerRuntime{fakeManagedRuntime: runtime, python: python, consumer: consumerPath, sandboxRoot: sandboxRoot}
	reconciler.ManagedRuntime = consumerRuntime
	consumerHash := fmt.Sprintf("%x", sha256.Sum256(consumerBytes))
	if consumerPath != "" {
		t.Logf("actual Sandbox consumer sha256=%s path=%s", consumerHash, consumerPath)
	}
	t.Cleanup(func() {
		if path := os.Getenv("WARPMETAL_MONITOR_CONTRACT_EVIDENCE"); path != "" {
			encoded, err := json.MarshalIndent(map[string]any{
				"mode":         mode,
				"consumerPath": consumerPath, "consumerSha256": consumerHash,
				"validations": consumerRuntime.validations,
			}, "", "  ")
			if err != nil {
				t.Error(err)
				return
			}
			output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Error(err)
				return
			}
			defer output.Close()
			if _, err := output.Write(append(encoded, '\n')); err != nil {
				t.Error(err)
			}
		}
	})
	pinnedService, err := store.ManagedService(context.Background(), source.Report.ServiceRegistrationID)
	if err != nil || pinnedService == nil {
		t.Fatalf("ready managed service = %#v, %v", pinnedService, err)
	}
	assertPolicy := func(revision int64, enabled bool) {
		t.Helper()
		stored, err := store.InsightPolicyState(context.Background(), sourceID)
		if err != nil || stored == nil || stored.Revision != revision || stored.Enabled != enabled {
			t.Fatalf("SQLite monitor policy = %#v, %v; want revision=%d enabled=%t", stored, err, revision, enabled)
		}
	}
	assertPinnedState := func() {
		t.Helper()
		service, err := store.ManagedService(context.Background(), source.Report.ServiceRegistrationID)
		if err != nil || !reflect.DeepEqual(service, pinnedService) {
			t.Fatalf("monitor transition changed pinned service authority: %#v, %v", service, err)
		}
		currentSource, err := store.ContinuitySource(context.Background(), sourceID)
		if err != nil || !reflect.DeepEqual(currentSource, source) {
			t.Fatalf("monitor transition changed pinned source authority: %#v, %v", currentSource, err)
		}
	}
	assertPinnedRestart := func(restart managedInvocation, enabled bool) {
		t.Helper()
		expected := map[string]any{
			"schemaVersion": float64(1), "sandboxId": source.Report.SandboxID,
			"instance":      fixture.ServiceManifest.Identity.Instance,
			"profileId":     fixture.ServiceManifest.Profile.ProfileID,
			"profileDigest": fixture.ServiceManifest.Profile.ProfileDigest,
			"version":       fixture.SetupManifest.Materializer.Bin.Version,
			"port":          float64(managedServicePort), "projectRoot": workspace.ContainerRoot,
			"sessionMode": "lookup_only", "instructionText": fixture.InstructionResponse.Content,
			"instructionDigest":   fixture.InstructionResponse.InstructionDigest,
			"instructionRevision": float64(fixture.InstructionResponse.InstructionRevision),
			"monitorEnabled":      enabled,
		}
		if enabled {
			expected["monitorSourceInstanceId"] = source.Report.RegisteredSourceID
			expected["monitorWorkspaceEpoch"] = source.Report.WorkspaceEpoch
		}
		if restart.action != "restart" || !reflect.DeepEqual(restart.request, expected) {
			t.Fatalf("monitor restart lost pinned managed tuple: got %#v want %#v", restart, expected)
		}
	}
	policy := model.InsightPolicyV1{
		SandboxID: source.Report.SandboxID, Revision: 2, Enabled: true, ExpiresAt: now.Add(90 * time.Second),
		Sources: []model.InsightPolicySourceV1{{
			RegisteredSourceID: source.Report.RegisteredSourceID, ServiceRegistrationID: source.Report.ServiceRegistrationID,
			SandboxGeneration: source.Report.SandboxGeneration, ServiceGeneration: source.Report.ServiceGeneration,
			WorkspaceEpoch: source.Report.WorkspaceEpoch, NativeSessionID: source.Report.NativeSessionID,
		}},
	}
	before := len(runtime.invocations)
	if err := reconciler.ApplyInsightMonitorPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if len(runtime.invocations) != before+2 {
		t.Fatalf("monitor enable did not status-check then restart exactly once: %#v", runtime.invocations[before:])
	}
	restart := runtime.invocations[len(runtime.invocations)-1]
	assertPinnedRestart(restart, true)
	assertPolicy(policy.Revision, true)
	assertPinnedState()
	if err := reconciler.ApplyInsightMonitorPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if len(runtime.invocations) != before+2 {
		t.Fatalf("unchanged policy restarted service again: %#v", runtime.invocations[before:])
	}
	source.NoAdmittedExecution = false
	if err := store.PutContinuitySource(context.Background(), *source); err != nil {
		t.Fatal(err)
	}
	disabled := policy
	disabled.Revision++
	disabled.Enabled = false
	validatedBeforeBusy := len(consumerRuntime.validations)
	if err := reconciler.ApplyInsightMonitorPolicy(context.Background(), disabled); err == nil || !strings.Contains(err.Error(), "safe idle monitor boundary") {
		t.Fatalf("monitor disable restarted an active managed execution: %v", err)
	}
	if len(runtime.invocations) != before+2 || len(consumerRuntime.validations) != validatedBeforeBusy {
		t.Fatalf("busy policy transition reached consumer/restart: %#v", runtime.invocations[before:])
	}
	assertPolicy(policy.Revision, true)
	assertPinnedState()
	source.NoAdmittedExecution = true
	if err := store.PutContinuitySource(context.Background(), *source); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.ApplyInsightMonitorPolicy(context.Background(), disabled); err != nil {
		// A refused consumer request must not advance the durable local policy.
		assertPolicy(policy.Revision, true)
		assertPinnedState()
		t.Fatalf("idle disable rejected by real Sandbox consumer; SQLite policy remains revision=%d enabled=true: %v", policy.Revision, err)
	}
	if len(runtime.invocations) != before+4 {
		t.Fatalf("idle disable did not status-check then restart exactly once: %#v", runtime.invocations[before:])
	}
	assertPinnedRestart(runtime.invocations[len(runtime.invocations)-1], false)
	assertPolicy(disabled.Revision, false)
	assertPinnedState()
	if consumerPath != "" {
		lastValidated := consumerRuntime.validations[len(consumerRuntime.validations)-1]
		if lastValidated.Normalized["monitorEnabled"] != false || lastValidated.Normalized["monitorSourceInstanceId"] != nil || lastValidated.Normalized["monitorWorkspaceEpoch"] != nil {
			t.Fatalf("actual consumer did not normalize disabled monitor without identity: %#v", lastValidated)
		}
	}
	reenabled := policy
	reenabled.Revision = disabled.Revision + 1
	if err := reconciler.ApplyInsightMonitorPolicy(context.Background(), reenabled); err != nil {
		t.Fatal(err)
	}
	if len(runtime.invocations) != before+6 {
		t.Fatalf("reenable did not status-check then restart exactly once: %#v", runtime.invocations[before:])
	}
	assertPinnedRestart(runtime.invocations[len(runtime.invocations)-1], true)
	assertPolicy(reenabled.Revision, true)
	assertPinnedState()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	catalog = &workspacecatalog.Catalog{State: store, Now: func() time.Time { return now }}
	reopenedRuntime := &fakeManagedRuntime{store: store, serviceID: fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture: fixture}
	consumerRuntime.fakeManagedRuntime = reopenedRuntime
	reconciler = &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: consumerRuntime, Now: func() time.Time { return now }}
	validatedBeforeReplay := len(consumerRuntime.validations)
	if err := reconciler.ApplyInsightMonitorPolicy(context.Background(), reenabled); err != nil {
		t.Fatal(err)
	}
	if len(reopenedRuntime.invocations) != 0 || len(consumerRuntime.validations) != validatedBeforeReplay {
		t.Fatalf("reopened SQLite forgot the applied monitor policy: %#v", reopenedRuntime.invocations)
	}
	assertPolicy(reenabled.Revision, true)
	assertPinnedState()
}
