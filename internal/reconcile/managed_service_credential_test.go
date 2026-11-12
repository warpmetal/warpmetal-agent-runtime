package reconcile

// DeepSeek managed-service account-provider credential and idle worker re-arm.
//
// The DeepSeek supervisor spawns the pinned DSH child at start; the launcher
// reads /home/agent/.deepseek-harness/api-key at that spawn. The Runtime must
// therefore deliver the account-owned provider credential through the
// supervisor's closed one-shot `credential` command BEFORE the enroll/rebind/
// start sequence, validate the ready receipt, and never persist or report the
// plaintext key. Only the DeepSeek worker/reviewer re-arms one execute attempt
// after an idle receipt so a task submitted after Start is claimed; the
// OpenCode worker keeps its established one-shot-per-service-start behavior.

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// The production control-plane client must satisfy the optional DeepSeek
// credential extension; cmd/warpmetald wires exactly this value into
// Reconciler.ManagedControl.
var _ managedServiceCredentialControl = api.Client{}

func managedInvocationIndex(invocations []managedInvocation, action string) int {
	for index, invocation := range invocations {
		if invocation.action == action {
			return index
		}
	}
	return -1
}

func deepSeekCredentialRequest(desired model.ManagedServiceV1) map[string]any {
	return map[string]any{
		"schemaVersion": float64(1), "command": "credential",
		"sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance,
		"profileId": "deepseek", "apiKey": deepSeekCredentialAPIKey,
	}
}

// TestDeepSeekManagedServiceDeliversProviderCredentialBeforeSpawn proves the
// closed credential delivery precedes every action of the existing
// enroll/rebind/start sequence, carries exactly the documented fields, has its
// ready receipt validated, and never writes the plaintext key into durable
// state or a report.
func TestDeepSeekManagedServiceDeliversProviderCredentialBeforeSpawn(t *testing.T) {
	fixture := deepSeekManagerFixture(t)
	runtime := &deepSeekManagedRuntime{}
	control := &deepSeekManagedControl{fakeManagedControl: &fakeManagedControl{fixture: fixture}, endpoint: "https://api.warpmetal.example"}
	journey := newDeepSeekManagedJourneyWithControl(t, fixture, runtime, control)
	local := journey.reconcile(t, "active")
	if local.Phase != "ready" || local.ErrorCode != "" {
		t.Fatalf("DeepSeek managed-service durable report = %#v", local)
	}

	credentialIndex := managedInvocationIndex(runtime.invocations, string(containers.ManagedSupervisorCredential))
	startIndex := managedInvocationIndex(runtime.invocations, string(containers.ManagedSupervisorStart))
	enrollIndex := managedInvocationIndex(runtime.invocations, string(containers.ManagedSupervisorEnroll))
	rebindIndex := managedInvocationIndex(runtime.invocations, string(containers.ManagedSupervisorRebind))
	if credentialIndex < 0 || startIndex < 0 || enrollIndex < 0 || rebindIndex < 0 {
		t.Fatalf("DeepSeek managed-service actions = %#v", runtime.invocations)
	}
	if credentialIndex > enrollIndex || credentialIndex > rebindIndex || credentialIndex > startIndex {
		t.Fatalf("credential action did not precede the spawn sequence: %#v", runtime.invocations)
	}
	credential := runtime.invocations[credentialIndex]
	if !reflect.DeepEqual(credential.request, deepSeekCredentialRequest(journey.desired)) {
		t.Fatalf("closed credential request = %#v", credential.request)
	}
	if len(control.credentialCalls) != 1 || control.credentialCalls[0] != journey.desired.Identity.ServiceRegistrationID {
		t.Fatalf("credential control calls = %#v", control.credentialCalls)
	}

	// The returned ready receipt is the only proof accepted: it names the
	// protected credential file and never contains the key.
	receipt, err := validateManagedSupervisorReceipt(runtime.returned[containers.ManagedSupervisorCredential], "credential", "ready")
	if err != nil || receipt.ProfileID != "deepseek" || receipt.CredentialFile != "/home/agent/.deepseek-harness/api-key" {
		t.Fatalf("validated credential receipt = %#v, %v", receipt, err)
	}
	if bytes.Contains(runtime.returned[containers.ManagedSupervisorCredential], []byte(deepSeekCredentialAPIKey)) {
		t.Fatal("credential receipt carried plaintext key material")
	}

	// No plaintext key material may reach durable state or an outbound report.
	reportJSON, err := json.Marshal(local.Report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(reportJSON, []byte(deepSeekCredentialAPIKey)) || bytes.Contains(reportJSON, []byte("apiKey")) {
		t.Fatalf("managed-service report leaked credential material: %s", reportJSON)
	}
	sources, err := journey.store.ContinuitySources(context.Background())
	if err != nil || len(sources) != 1 {
		t.Fatalf("managed continuity sources = %#v, %v", sources, err)
	}
	sourceJSON, err := json.Marshal(sources[0].Report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sourceJSON, []byte(deepSeekCredentialAPIKey)) {
		t.Fatalf("continuity source report leaked credential material: %s", sourceJSON)
	}
	outbound, err := journey.reconciler.Report(context.Background(), fixture.ServiceManifest.Identity.ServerID, "test")
	if err != nil {
		t.Fatal(err)
	}
	outboundJSON, err := json.Marshal(outbound)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(outboundJSON, []byte(deepSeekCredentialAPIKey)) {
		t.Fatalf("outbound report leaked credential material: %s", outboundJSON)
	}
}

// TestDeepSeekManagedServiceMissingProviderCredentialFailsClosed proves the
// documented 404 provider_credential_missing outcome fails the managed service
// with that exact stable code before any supervisor effect.
func TestDeepSeekManagedServiceMissingProviderCredentialFailsClosed(t *testing.T) {
	fixture := deepSeekManagerFixture(t)
	runtime := &deepSeekManagedRuntime{}
	control := &deepSeekManagedControl{
		fakeManagedControl: &fakeManagedControl{fixture: fixture}, endpoint: "https://api.warpmetal.example",
		credentialErr: &api.ResponseError{Status: 404, Code: "provider_credential_missing"},
	}
	journey := newDeepSeekManagedJourneyWithControl(t, fixture, runtime, control)
	journey.reconciler.setCurrentAuthority(journey.manifest)
	if _, err := journey.reconciler.reconcileManagedServices(context.Background(), journey.manifest); err == nil {
		t.Fatal("managed service without a provider credential was accepted")
	}
	local, err := journey.store.ManagedService(context.Background(), journey.desired.Identity.ServiceRegistrationID)
	if err != nil || local == nil {
		t.Fatalf("failed managed-service row = %#v, %v", local, err)
	}
	if local.Phase != "failed" || local.ErrorCode != "provider_credential_missing" ||
		local.Report.LastError == nil || local.Report.LastError.Code != "provider_credential_missing" ||
		local.Report.ObservedState != "failed" {
		t.Fatalf("missing credential failure row = %#v", local)
	}
	// The credential fetch failed before the supervisor seam: no enroll,
	// rebind or start may have been dispatched.
	if len(runtime.invocations) != 0 {
		t.Fatalf("missing credential dispatched supervisor actions: %#v", runtime.invocations)
	}
	if len(control.credentialCalls) != 1 {
		t.Fatalf("missing credential fetches = %#v", control.credentialCalls)
	}
}

// TestDeepSeekManagedServiceRefusesCredentialReceiptWithoutFile proves a
// receipt that does not name the protected DSH credential file fails closed
// before the spawn sequence.
func TestDeepSeekManagedServiceRefusesCredentialReceiptWithoutFile(t *testing.T) {
	fixture := deepSeekManagerFixture(t)
	runtime := &deepSeekManagedRuntime{credentialReceipt: []byte(`{"schemaVersion":1,"command":"credential","profileId":"deepseek","status":"ready"}`)}
	journey := newDeepSeekManagedJourney(t, fixture, runtime)
	journey.reconciler.setCurrentAuthority(journey.manifest)
	if _, err := journey.reconciler.reconcileManagedServices(context.Background(), journey.manifest); err == nil {
		t.Fatal("credential receipt without a credential file was accepted")
	}
	local, err := journey.store.ManagedService(context.Background(), journey.desired.Identity.ServiceRegistrationID)
	if err != nil || local == nil || local.Phase != "failed" || local.ErrorCode != "invalid_credential_receipt" {
		t.Fatalf("invalid credential receipt row = %#v, %v", local, err)
	}
	if managedInvocationIndex(runtime.invocations, string(containers.ManagedSupervisorCredential)) != 0 ||
		managedInvocationIndex(runtime.invocations, string(containers.ManagedSupervisorEnroll)) >= 0 ||
		managedInvocationIndex(runtime.invocations, string(containers.ManagedSupervisorStart)) >= 0 {
		t.Fatalf("invalid credential receipt actions = %#v", runtime.invocations)
	}
}

// deepSeekRearmRuntime observes the execute one-shots a DeepSeek worker
// reconciles after Start. Every other seam delegates to the closed DeepSeek
// fake so the production managed-service journey stays byte-identical.
type deepSeekRearmRuntime struct {
	base *deepSeekManagedRuntime
	mu   sync.Mutex
	// executeCalls counts actual execute attempts and executeTimes records
	// when each attempt started, proving the injected idle backoff.
	executeCalls int
	executeTimes []time.Time
}

func (runtime *deepSeekRearmRuntime) ExecManagedSupervisor(ctx context.Context, sandboxID string, action containers.ManagedSupervisorAction, payload []byte) ([]byte, []byte, error) {
	return runtime.base.ExecManagedSupervisor(ctx, sandboxID, action, payload)
}

func (runtime *deepSeekRearmRuntime) ExecManagedWorker(ctx context.Context, sandboxID string, action containers.ManagedWorkerAction, profileID string, payload []byte) ([]byte, []byte, error) {
	if action != containers.ManagedWorkerExecute {
		return runtime.base.ExecManagedWorker(ctx, sandboxID, action, profileID, payload)
	}
	runtime.mu.Lock()
	runtime.executeCalls++
	runtime.executeTimes = append(runtime.executeTimes, time.Now())
	runtime.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return []byte(`{"schemaVersion":1,"command":"execute","status":"idle","instance":"default"}`), nil, nil
}

func (runtime *deepSeekRearmRuntime) calls() (int, []time.Time) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.executeCalls, append([]time.Time(nil), runtime.executeTimes...)
}

func waitDeepSeekRearmExecutions(t *testing.T, runtime *deepSeekRearmRuntime, count int) []time.Time {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		calls, times := runtime.calls()
		if calls >= count {
			return times
		}
		time.Sleep(5 * time.Millisecond)
	}
	calls, _ := runtime.calls()
	t.Fatalf("DeepSeek worker execute count = %d, want at least %d", calls, count)
	return nil
}

// TestDeepSeekManagedWorkerExecutionRearmsAfterIdle proves one idle execute is
// followed by another after the injected backoff, and that an explicit pause
// cancels the chain so no further execution is scheduled.
func TestDeepSeekManagedWorkerExecutionRearmsAfterIdle(t *testing.T) {
	fixture := deepSeekManagerFixture(t)
	fixture.ServiceManifest.Identity.Role = "worker"
	base := &deepSeekManagedRuntime{}
	control := &deepSeekManagedControl{fakeManagedControl: &fakeManagedControl{fixture: fixture}, endpoint: "https://api.warpmetal.example"}
	journey := newDeepSeekManagedJourneyWithControl(t, fixture, base, control)
	runtime := &deepSeekRearmRuntime{base: base}
	lifecycle, cancelLifecycle := context.WithCancel(context.Background())
	t.Cleanup(cancelLifecycle)
	const backoff = 20 * time.Millisecond
	journey.reconciler.ManagedRuntime = runtime
	journey.reconciler.ManagedExecutionContext = lifecycle
	journey.reconciler.ManagedWorkerRearmBackoff = backoff

	local := journey.reconcile(t, "active")
	if local.Phase != "ready" || local.ErrorCode != "" {
		t.Fatalf("DeepSeek worker managed-service report = %#v", local)
	}

	times := waitDeepSeekRearmExecutions(t, runtime, 2)
	if gap := times[1].Sub(times[0]); gap < 15*time.Millisecond {
		t.Fatalf("re-armed execute gap = %s, want at least %s", gap, 15*time.Millisecond)
	}

	paused := journey.reconcile(t, "paused")
	if paused.Phase != "paused" || paused.ErrorCode != "" {
		t.Fatalf("DeepSeek worker pause report = %#v", paused)
	}
	afterPause, _ := runtime.calls()
	stopped := journey.reconcile(t, "stopped")
	if stopped.Phase != "stopped" || stopped.ErrorCode != "" {
		t.Fatalf("DeepSeek worker stop report = %#v", stopped)
	}
	// No re-arm survives the explicit pause/stop: the count is stable and the
	// execution registry is empty.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && journey.reconciler.managedWorkerExecutionActive(journey.desired.Identity.ServiceRegistrationID) {
		time.Sleep(5 * time.Millisecond)
	}
	if journey.reconciler.managedWorkerExecutionActive(journey.desired.Identity.ServiceRegistrationID) {
		t.Fatal("worker execution remained registered after pause/stop")
	}
	calls, _ := runtime.calls()
	if calls != afterPause {
		t.Fatalf("worker executes after pause = %d, want stable %d", calls, afterPause)
	}
	time.Sleep(3 * backoff)
	if final, _ := runtime.calls(); final != afterPause {
		t.Fatalf("re-arm loop survived pause/stop: %d executes, want %d", final, afterPause)
	}
}

// TestOpenCodeManagedWorkerExecutionDoesNotRearm proves the DeepSeek-only
// re-arm never changes the OpenCode worker semantics: the OpenCode fixture is
// never eligible, and only a DeepSeek worker/reviewer with an active intent is.
func TestOpenCodeManagedWorkerExecutionDoesNotRearm(t *testing.T) {
	fixture := loadProducerFixture(t)
	if fixture.ServiceManifest.Profile.ProfileID != "opencode" {
		t.Fatalf("producer fixture profile = %q", fixture.ServiceManifest.Profile.ProfileID)
	}
	worker := fixture.ServiceManifest
	worker.Identity.Role = "worker"
	reconciler := &Reconciler{}
	if reconciler.managedWorkerRearmEligible(context.Background(), worker) {
		t.Fatal("OpenCode worker was eligible for the DeepSeek-only idle re-arm")
	}
	deepSeek := worker
	deepSeek.Profile.ProfileID = "deepseek"
	deepSeek.Identity.Role = "manager"
	if reconciler.managedWorkerRearmEligible(context.Background(), deepSeek) {
		t.Fatal("DeepSeek manager was eligible for an idle worker re-arm")
	}
	deepSeek.Identity.Role = "worker"
	deepSeek.DesiredState = "paused"
	if reconciler.managedWorkerRearmEligible(context.Background(), deepSeek) {
		t.Fatal("paused DeepSeek worker was eligible for an idle re-arm")
	}
}
