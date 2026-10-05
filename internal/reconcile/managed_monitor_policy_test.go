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
	// Keep the control-plane receipts valid for the whole journey; the monitor
	// lease owns the expiry boundary under test.
	fixture.EnrollmentResponse.EnrollmentExpiresAt = now.Add(2 * time.Hour)
	fixture.InstructionResponse.ExpiresAt = now.Add(2 * time.Hour)
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
	if len(runtime.invocations) != before+3 {
		t.Fatalf("unchanged policy did not perform exactly one current-process status check: %#v", runtime.invocations[before:])
	}
	if runtime.invocations[len(runtime.invocations)-1].action != string(containers.ManagedSupervisorStatus) {
		t.Fatalf("unchanged policy did not end at a current-process status check: %#v", runtime.invocations[before:])
	}
	source.NoAdmittedExecution = false
	if err := store.PutContinuitySource(context.Background(), *source); err != nil {
		t.Fatal(err)
	}
	// Same policy while a worker task is active: a matching current-process
	// version1 writer-ready process must validate and no-op without idle.
	runtime.statusMonitorVersion = 1
	runtime.statusMonitorEnabled = true
	runtime.statusMonitorSourceID = source.Report.RegisteredSourceID
	runtime.statusMonitorEpoch = source.Report.WorkspaceEpoch
	runtime.statusMonitorWriterReady = true
	runtime.statusMonitorGeneration = "journal_0123456789abcdef0123456789abcdef"
	activeBefore := len(runtime.invocations)
	if err := reconciler.ApplyInsightMonitorPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if len(runtime.invocations) != activeBefore+1 ||
		runtime.invocations[len(runtime.invocations)-1].action != string(containers.ManagedSupervisorStatus) {
		t.Fatalf("active same-policy did not validate current process without restart: %#v", runtime.invocations[activeBefore:])
	}
	assertPolicy(policy.Revision, true)
	assertPinnedState()
	disabled := policy
	disabled.Revision++
	disabled.Enabled = false
	validatedBeforeBusy := len(consumerRuntime.validations)
	if err := reconciler.ApplyInsightMonitorPolicy(context.Background(), disabled); err == nil || !strings.Contains(err.Error(), "safe idle monitor boundary") {
		t.Fatalf("monitor disable restarted an active managed execution: %v", err)
	}
	if len(runtime.invocations) != before+4 || len(consumerRuntime.validations) != validatedBeforeBusy {
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
	if len(runtime.invocations) != before+6 {
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
	if len(runtime.invocations) != before+8 {
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
	if len(reopenedRuntime.invocations) != 1 || reopenedRuntime.invocations[0].action != string(containers.ManagedSupervisorStatus) {
		t.Fatalf("reopened SQLite did not perform exactly one current-process status check: %#v", reopenedRuntime.invocations)
	}
	if len(consumerRuntime.validations) > validatedBeforeReplay+1 {
		t.Fatalf("reopened SQLite performed more than one current-process validation: %#v", consumerRuntime.validations[validatedBeforeReplay:])
	}
	assertPolicy(reenabled.Revision, true)
	assertPinnedState()
}

// TestManagedServiceOrdinaryStartCarriesCurrentValidatedMonitorPolicy is the
// producer regression for the retained-process task. A currently validated,
// unexpired monitor lease has already been applied, and its revision matches
// the durable applied row. A later ordinary managed-service reconcile models
// the same-generation image replacement: the native process is gone and the
// start path spawns it again. That start must compose the leased policy
// directly, because the unchanged applied revision suppresses monitor
// re-application. Today the start request omits monitor enablement, so the
// replacement runs monitor-less while the applied row suppresses repair.
func TestManagedServiceOrdinaryStartCarriesCurrentValidatedMonitorPolicy(t *testing.T) {
	fixture := loadProducerFixture(t)
	// Test-only compatibility: the default fixture materializer declares
	// 2.0.14, but the signed archive under the installed gate is 2.0.14-wm.2.
	// Override before seedReadyProfile so the actual start request carries the
	// signed version instead of patching emitted output.
	if materializerVersion := os.Getenv("WARPMETAL_TASK12_MATERIALIZER_VERSION"); materializerVersion != "" {
		if fixture.SetupManifest.Materializer.Bin == nil {
			t.Fatal("fixture setup materializer bin is absent")
		}
		fixture.SetupManifest.Materializer.Bin.Version = materializerVersion
	}
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
	// Keep the control-plane receipts valid for the whole journey; the monitor
	// lease owns the expiry boundary under test.
	fixture.EnrollmentResponse.EnrollmentExpiresAt = now.Add(2 * time.Hour)
	fixture.InstructionResponse.ExpiresAt = now.Add(2 * time.Hour)
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
	// The initial spawn has no monitor authority yet.
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
	policy := model.InsightPolicyV1{
		SandboxID: source.Report.SandboxID, Revision: 2, Enabled: true, ExpiresAt: now.Add(90 * time.Second),
		Sources: []model.InsightPolicySourceV1{{
			RegisteredSourceID: source.Report.RegisteredSourceID, ServiceRegistrationID: source.Report.ServiceRegistrationID,
			SandboxGeneration: source.Report.SandboxGeneration, ServiceGeneration: source.Report.ServiceGeneration,
			WorkspaceEpoch: source.Report.WorkspaceEpoch, NativeSessionID: source.Report.NativeSessionID,
		}},
	}
	// This is the collector-validated cached lease the start path must consult.
	if err := store.PutInsightPolicyLease(context.Background(), state.InsightPolicyLease{Policy: policy}); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.ApplyInsightMonitorPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	applied, err := store.InsightPolicyState(context.Background(), sourceID)
	if err != nil || applied == nil || applied.Revision != policy.Revision || !applied.Enabled {
		t.Fatalf("applied monitor policy = %#v, %v", applied, err)
	}
	// The fresh startup read returns the current enabled per-sandbox policy.
	// This is the actual permission the ordinary spawn must compose from; the
	// applied row alone is not authority.
	control.insightPolicies = model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{policy}}
	// The ordinary reconcile is the replacement spawn: the leased policy is
	// current and the applied revision is unchanged, so only the start request
	// itself can keep monitoring enabled.
	before := len(runtime.invocations)
	if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	var start *managedInvocation
	for index := range runtime.invocations[before:] {
		invocation := &runtime.invocations[before+index]
		if invocation.action == string(containers.ManagedSupervisorStart) {
			start = invocation
		}
	}
	if start == nil {
		t.Fatalf("ordinary reconcile did not spawn the managed server: %#v", runtime.invocations[before:])
	}
	// Test-only producer -> installed-consumer export. Emitted before the
	// monitorEnabled assertion so the current RED payload is captured too.
	// Format (JSON):
	//   {"formatVersion":1,
	//    "startRequest":{...actual ManagedSupervisorStart request...},
	//    "fixture":{"sandboxId":...,"instance":...,"profileId":...,
	//               "profileDigest":...,"port":...,"projectRoot":...,
	//               "monitorSourceInstanceId":...,"monitorWorkspaceEpoch":...}}
	// The fixture block is identity-only; it never carries monitorEnabled.
	if emitPath := os.Getenv("WARPMETAL_TASK12_EMIT_START_REQUEST"); emitPath != "" {
		emission := map[string]any{
			"formatVersion": 1,
			"startRequest":  start.request,
			"fixture": map[string]any{
				"sandboxId":               fixture.ServiceManifest.Identity.SandboxID,
				"instance":                fixture.ServiceManifest.Identity.Instance,
				"profileId":               fixture.ServiceManifest.Profile.ProfileID,
				"profileDigest":           fixture.ServiceManifest.Profile.ProfileDigest,
				"port":                    managedServicePort,
				"projectRoot":             workspace.ContainerRoot,
				"monitorSourceInstanceId": source.Report.RegisteredSourceID,
				"monitorWorkspaceEpoch":   source.Report.WorkspaceEpoch,
			},
		}
		encoded, err := json.MarshalIndent(emission, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(emitPath, append(encoded, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if enabled, _ := start.request["monitorEnabled"].(bool); !enabled {
		t.Fatalf("ordinary managed start omitted the current validated monitor lease; replacement spawns monitor-less: %#v", start.request)
	}
	if start.request["monitorSourceInstanceId"] != source.Report.RegisteredSourceID ||
		start.request["monitorWorkspaceEpoch"] != source.Report.WorkspaceEpoch {
		t.Fatalf("ordinary managed start lost leased monitor identity: %#v", start.request)
	}
	// Stale/omitted source observation: the backend's 120s filter may return
	// the enabled per-sandbox policy with no source refs. Retained startup must
	// still compose from the pinned source/session; absence of the ref is not
	// missing authority.
	stalePolicy := policy
	stalePolicy.Sources = nil
	control.insightPolicies = model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{stalePolicy}}
	staleBefore := len(runtime.invocations)
	if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	var staleStart *managedInvocation
	for index := range runtime.invocations[staleBefore:] {
		invocation := &runtime.invocations[staleBefore+index]
		if invocation.action == string(containers.ManagedSupervisorStart) {
			staleStart = invocation
		}
	}
	if staleStart == nil || staleStart.request["monitorEnabled"] != true ||
		staleStart.request["monitorSourceInstanceId"] != source.Report.RegisteredSourceID ||
		staleStart.request["monitorWorkspaceEpoch"] != source.Report.WorkspaceEpoch {
		t.Fatalf("retained startup with omitted stale source refs lost monitor composition: %#v", staleStart)
	}
	// Explicit current disabled authority composes explicit false intent
	// without identity; the collector's disabled authority is preserved.
	disabledPolicy := policy
	disabledPolicy.Enabled = false
	disabledPolicy.Revision++
	control.insightPolicies = model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{disabledPolicy}}
	disabledBefore := len(runtime.invocations)
	if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	var disabledStart *managedInvocation
	for index := range runtime.invocations[disabledBefore:] {
		invocation := &runtime.invocations[disabledBefore+index]
		if invocation.action == string(containers.ManagedSupervisorStart) {
			disabledStart = invocation
		}
	}
	if disabledStart == nil || disabledStart.request["monitorEnabled"] != false {
		t.Fatalf("explicit disabled policy did not compose disabled intent: %#v", disabledStart)
	}
	if _, present := disabledStart.request["monitorSourceInstanceId"]; present {
		t.Fatalf("disabled intent must not carry monitor identity: %#v", disabledStart.request)
	}
	// New managed service on an already monitored sandbox: no ContinuitySource
	// row exists yet, so the enabled sandbox policy must compose the derived
	// managed source identity from the authenticated manifest/project while
	// preserving create_initial authority exactly.
	control.insightPolicies = model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{policy}}
	newService := fixture.ServiceManifest
	newService.Identity.ServiceRegistrationID = "service_managedservice0002"
	newIntent, err := reconciler.managedStartupMonitorIntent(context.Background(), newService)
	if err != nil {
		t.Fatalf("new service on enabled sandbox was blocked: %v", err)
	}
	derivedSourceID := managedSourceID(newService.Identity.ServiceRegistrationID)
	if !newIntent.Enabled || newIntent.SourceInstanceID != derivedSourceID ||
		newIntent.WorkspaceEpoch != newService.Workspace.WorkspaceEpoch {
		t.Fatalf("new-service monitor identity was not derived from managed authority: %#v", newIntent)
	}
	binVersion := ""
	if fixture.SetupManifest.Materializer.Bin != nil {
		binVersion = fixture.SetupManifest.Materializer.Bin.Version
	}
	derivedRequest := managedLaunchComposition{
		SandboxID:           newService.Identity.SandboxID,
		Instance:            newService.Identity.Instance,
		ProfileID:           newService.Profile.ProfileID,
		ProfileDigest:       newService.Profile.ProfileDigest,
		Version:             binVersion,
		Port:                managedServicePort,
		ProjectRoot:         "/managed/project",
		SessionMode:         "create_initial",
		InstructionText:     "instruction",
		InstructionDigest:   "sha256:" + strings.Repeat("a", 64),
		InstructionRevision: 1,
		Monitor:             newIntent,
	}.request()
	if derivedRequest["monitorEnabled"] != true ||
		derivedRequest["monitorSourceInstanceId"] != derivedSourceID ||
		derivedRequest["monitorWorkspaceEpoch"] != newService.Workspace.WorkspaceEpoch ||
		derivedRequest["sessionMode"] != "create_initial" {
		t.Fatalf("new-service create_initial monitor composition changed authority: %#v", derivedRequest)
	}
	// Running mismatched monitor configuration: the current-capable start
	// reports failed/error monitor_configuration_mismatch, and the Runtime
	// performs exactly one safe-idle restart using the fresh enabled intent.
	control.insightPolicies = model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{policy}}
	runtime.startMismatchOnce = true
	mismatchBefore := len(runtime.invocations)
	if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	var mismatchRestart *managedInvocation
	for index := range runtime.invocations[mismatchBefore:] {
		invocation := &runtime.invocations[mismatchBefore+index]
		if invocation.action == string(containers.ManagedSupervisorRestart) {
			mismatchRestart = invocation
		}
	}
	if mismatchRestart == nil || mismatchRestart.request["monitorEnabled"] != true ||
		mismatchRestart.request["monitorSourceInstanceId"] != source.Report.RegisteredSourceID ||
		mismatchRestart.request["monitorWorkspaceEpoch"] != source.Report.WorkspaceEpoch {
		t.Fatalf("enabled mismatch did not restart once with fresh monitor intent: %#v", runtime.invocations[mismatchBefore:])
	}
	// Explicit disabled intent against a running enabled configuration uses the
	// same one safe-idle restart path so the collector can turn monitoring off.
	control.insightPolicies = model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{disabledPolicy}}
	runtime.startMismatchOnce = true
	disabledMismatchBefore := len(runtime.invocations)
	if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	var disabledMismatchRestart *managedInvocation
	for index := range runtime.invocations[disabledMismatchBefore:] {
		invocation := &runtime.invocations[disabledMismatchBefore+index]
		if invocation.action == string(containers.ManagedSupervisorRestart) {
			disabledMismatchRestart = invocation
		}
	}
	if disabledMismatchRestart == nil || disabledMismatchRestart.request["monitorEnabled"] != false {
		t.Fatalf("disabled mismatch did not restart once with disabled intent: %#v", runtime.invocations[disabledMismatchBefore:])
	}
	if _, present := disabledMismatchRestart.request["monitorSourceInstanceId"]; present {
		t.Fatalf("disabled mismatch restart carried monitor identity: %#v", disabledMismatchRestart.request)
	}
	// An active task is never restarted: the mismatch holds at the safe-idle
	// fence instead.
	source.NoAdmittedExecution = false
	if err := store.PutContinuitySource(context.Background(), *source); err != nil {
		t.Fatal(err)
	}
	runtime.startMismatchOnce = true
	activeMismatchBefore := len(runtime.invocations)
	if _, err := reconciler.reconcileManagedServices(context.Background(), manifest); err == nil || !strings.Contains(err.Error(), "safe idle") {
		t.Fatalf("active mismatch did not hold at the safe idle boundary: %v", err)
	}
	for index := range runtime.invocations[activeMismatchBefore:] {
		invocation := &runtime.invocations[activeMismatchBefore+index]
		if invocation.action == string(containers.ManagedSupervisorRestart) {
			t.Fatalf("active mismatch restarted an active task: %#v", invocation)
		}
	}
	source.NoAdmittedExecution = true
	if err := store.PutContinuitySource(context.Background(), *source); err != nil {
		t.Fatal(err)
	}
	// The cached lease expires during a long reconcile while the applied row
	// still says enabled. Dispatching a monitor-less start and completing ready
	// would admit work before any later idle repair; the start path must hold
	// readiness until a fresh validated lease arrives.
	now = policy.ExpiresAt.Add(time.Second)
	expiredBefore := len(runtime.invocations)
	_, expiredErr := reconciler.reconcileManagedServices(context.Background(), manifest)
	service, err := store.ManagedService(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID)
	if err != nil {
		t.Fatal(err)
	}
	var expiredStart *managedInvocation
	for index := range runtime.invocations[expiredBefore:] {
		invocation := &runtime.invocations[expiredBefore+index]
		if invocation.action == string(containers.ManagedSupervisorStart) {
			expiredStart = invocation
		}
	}
	if expiredErr == nil && expiredStart != nil && expiredStart.request["monitorEnabled"] != true &&
		service != nil && service.Phase == "ready" {
		t.Fatalf("expired validated monitor lease completed a monitor-less ready service instead of holding worker readiness: %#v", expiredStart.request)
	}
}
