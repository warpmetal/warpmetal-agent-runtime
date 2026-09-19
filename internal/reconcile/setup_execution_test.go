package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

const (
	setupOperationID = "setup-test12345"
	setupSandboxID   = "sbx_test12345"
	setupProfileID   = "openai-codex"
)

func setupManifest(revision int64) model.Manifest {
	digest := "sha256:" + strings.Repeat("a", 64)
	return model.Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: revision,
		ImageDigest:     "registry.example/sandbox@" + digest,
		Capacity: model.Resources{
			CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30,
		},
		Sandboxes: []model.Sandbox{{
			ID: setupSandboxID, Name: "main", Size: "small",
			Resources: model.Resources{
				CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256,
			},
			Lifetime: "persistent", DesiredState: "running", Generation: 1,
		}},
		SetupOperations: []model.SetupOperation{{
			ID: setupOperationID, SchemaVersion: 1,
			SandboxID: setupSandboxID, SandboxGeneration: 1,
			ProfileID: setupProfileID, ProfileRevision: 1, ProfileDigest: digest,
			Materializer: model.SetupMaterializer{
				Kind: "npm-package-set",
				Artifacts: []model.SetupArtifact{{
					ID: "codex-wrapper", Source: "https://artifacts.example/codex.tgz",
					SHA256: digest, Format: "npm-tgz", SizeBytes: 4096,
					PackageName: "@openai/codex", PackageVersion: "0.156.0-alpha.3",
					InstallAs: "@openai/codex",
				}},
				Bins: []string{"codex"},
			},
		}},
	}
}

func setupReceipt(status string) []byte {
	return setupReceiptFor(setupOperationID, setupSandboxID, setupProfileID, status)
}

func setupReceiptFor(operationID, sandboxID, profileID, status string) []byte {
	receipt := map[string]any{
		"id": operationID, "sandboxId": sandboxID,
		"sandboxGeneration": 1, "profileId": profileID,
		"profileRevision": 1,
		"profileDigest":   "sha256:" + strings.Repeat("a", 64),
		"status":          status,
		"provenance": map[string]any{
			"source":         "https://artifacts.example/codex.tgz?channel=alpha&arch=amd64",
			"artifactSha256": "sha256:" + strings.Repeat("a", 64),
		},
	}
	if status == "failed" || status == "cancelled" {
		receipt["error"] = map[string]any{
			"code": "setup_" + status,
		}
	}
	receipt["receiptDigest"] = canonicalSetupReceiptDigest(receipt)
	payload, err := json.Marshal(receipt)
	if err != nil {
		panic(err)
	}
	return payload
}

func twoSetupManifest(revision int64) model.Manifest {
	manifest := setupManifest(revision)
	secondSandbox := manifest.Sandboxes[0]
	secondSandbox.ID = "sbx_reviewer12345"
	secondSandbox.Name = "reviewer"
	manifest.Sandboxes = append(manifest.Sandboxes, secondSandbox)
	secondOperation := manifest.SetupOperations[0]
	secondOperation.ID = "setup-reviewer12345"
	secondOperation.SandboxID = secondSandbox.ID
	manifest.SetupOperations = append(manifest.SetupOperations, secondOperation)
	return manifest
}

func canonicalSetupReceiptDigest(receipt map[string]any) string {
	unsigned := make(map[string]any, len(receipt))
	for key, value := range receipt {
		if key != "receiptDigest" {
			unsigned[key] = value
		}
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(unsigned); err != nil {
		panic(err)
	}
	payload := bytes.TrimSuffix(canonical.Bytes(), []byte("\n"))
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}

func decodeSetupReceipt(payload []byte) map[string]any {
	var receipt map[string]any
	if err := json.Unmarshal(payload, &receipt); err != nil {
		panic(err)
	}
	return receipt
}

func encodeSetupReceipt(receipt map[string]any) []byte {
	payload, err := json.Marshal(receipt)
	if err != nil {
		panic(err)
	}
	return payload
}

func localSetupReceiptOperation() state.LocalSetupOperation {
	return state.LocalSetupOperation{
		ID: setupOperationID, SandboxID: setupSandboxID, SandboxGeneration: 1,
		ProfileID: setupProfileID, ProfileRevision: 1,
		ProfileDigest:   "sha256:" + strings.Repeat("a", 64),
		DesiredRevision: 1,
	}
}

func setupReconciler(t *testing.T, store *state.Store, engine *fakeEngine) *Reconciler {
	t.Helper()
	return &Reconciler{
		Store: store, Engine: engine, Workspaces: &fakeWorkspaces{}, Sessions: &fakeSessions{},
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		HostCapacity: model.Resources{CPUMillicores: 4000, MemoryMiB: 8192, WorkspaceDiskGiB: 80},
		ServerID:     "srv_test12345",
	}
}

func awaitSetupInvocation(t *testing.T, invoked <-chan setupInvocation) setupInvocation {
	t.Helper()
	select {
	case invocation := <-invoked:
		return invocation
	case <-time.After(time.Second):
		t.Fatal("setup operation was not dispatched to the closed execution seam")
		return setupInvocation{}
	}
}

func awaitReportState(
	t *testing.T,
	reconciler *Reconciler,
	wantState string,
) (model.Report, map[string]any) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		report, err := reconciler.Report(context.Background(), "srv_test12345", "test")
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(payload, &wire); err != nil {
			t.Fatal(err)
		}
		operations, ok := wire["setupOperations"].([]any)
		if ok && len(operations) == 1 {
			operation, ok := operations[0].(map[string]any)
			if ok && operation["status"] == wantState {
				return report, operation
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("setup report never reached %q: %s", wantState, payload)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func beginSetupApplying(t *testing.T, reconciler *Reconciler, engine *fakeEngine) {
	t.Helper()
	if err := reconciler.Reconcile(context.Background(), setupManifest(1)); err != nil {
		t.Fatal(err)
	}
	select {
	case invocation := <-engine.setupInvoked:
		t.Fatalf("new setup executed during its applying-report cycle: %#v", invocation)
	default:
	}
	report, _ := awaitReportState(t, reconciler, "applying")
	if report.AppliedRevision != 0 {
		t.Fatalf("applying setup advanced applied revision: %#v", report)
	}
}

func drainSetupInvocations(invoked <-chan setupInvocation) []setupInvocation {
	var invocations []setupInvocation
	for {
		select {
		case invocation := <-invoked:
			invocations = append(invocations, invocation)
		default:
			return invocations
		}
	}
}

func setupStates(t *testing.T, reconciler *Reconciler) (model.Report, map[string]string) {
	t.Helper()
	report, err := reconciler.Report(context.Background(), "srv_test12345", "test")
	if err != nil {
		t.Fatal(err)
	}
	states := make(map[string]string, len(report.SetupOperations))
	for _, operation := range report.SetupOperations {
		states[operation.ID] = operation.Status
	}
	return report, states
}

func TestSetupRechecksNestedBoundaryBeforeExecutingOnRunningSandbox(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{setupInvoked: make(chan setupInvocation, 1), setupResult: setupReceipt("ready")}
	r := setupReconciler(t, store, engine)
	beginSetupApplying(t, r, engine)
	engine.preflightErr = errors.New("nested boundary unavailable after restart")
	if err := r.Reconcile(context.Background(), setupManifest(1)); err == nil {
		t.Fatal("setup bypassed the nested preflight on an already-running sandbox")
	}
	if invocations := drainSetupInvocations(engine.setupInvoked); len(invocations) != 0 {
		t.Fatalf("setup executed after failed preflight: %#v", invocations)
	}
	report, _ := awaitReportState(t, r, "failed")
	if report.AppliedRevision != 0 || report.SetupOperations[0].LastError == nil ||
		report.SetupOperations[0].LastError.Code != "nested_sandbox_preflight_failed" {
		t.Fatalf("preflight failure did not remain explicit and unapplied: %#v", report)
	}
}

func TestTwoSetupOperationsExecuteOnePerReportCycle(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{
		setupInvoked: make(chan setupInvocation, 4),
		setupResultFor: func(_ string, request []byte) []byte {
			var operation model.SetupOperation
			if err := json.Unmarshal(request, &operation); err != nil {
				panic(err)
			}
			return setupReceiptFor(operation.ID, operation.SandboxID, operation.ProfileID, "ready")
		},
	}
	reconciler := setupReconciler(t, store, engine)
	manifest := twoSetupManifest(1)

	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if invocations := drainSetupInvocations(engine.setupInvoked); len(invocations) != 0 {
		t.Fatalf("initial applying cycle executed %d setup operations, want 0", len(invocations))
	}
	report, states := setupStates(t, reconciler)
	if report.AppliedRevision != 0 || len(states) != 2 ||
		states[setupOperationID] != "applying" || states["setup-reviewer12345"] != "applying" {
		t.Fatalf("initial setup report = revision %d, states %#v; want both applying at revision 0",
			report.AppliedRevision, states)
	}

	started := time.Now()
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	invocations := drainSetupInvocations(engine.setupInvoked)
	if len(invocations) != 1 {
		t.Fatalf("second cycle executed %d setup operations, want exactly 1", len(invocations))
	}
	if budget := invocations[0].deadline.Sub(started); budget < 9*time.Minute+50*time.Second {
		t.Fatalf("first setup execution context budget = %s, want at least 9m50s", budget)
	}
	report, states = setupStates(t, reconciler)
	ready, applying := 0, 0
	for _, status := range states {
		switch status {
		case "ready":
			ready++
		case "applying":
			applying++
		}
	}
	if report.AppliedRevision != 0 || ready != 1 || applying != 1 {
		t.Fatalf("intermediate setup report = revision %d, states %#v; want ready+applying at revision 0",
			report.AppliedRevision, states)
	}

	started = time.Now()
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	invocations = drainSetupInvocations(engine.setupInvoked)
	if len(invocations) != 1 {
		t.Fatalf("final cycle executed %d setup operations, want exactly 1", len(invocations))
	}
	if budget := invocations[0].deadline.Sub(started); budget < 9*time.Minute+50*time.Second {
		t.Fatalf("second setup execution context budget = %s, want at least 9m50s", budget)
	}
	report, states = setupStates(t, reconciler)
	if report.AppliedRevision != 1 || states[setupOperationID] != "ready" ||
		states["setup-reviewer12345"] != "ready" {
		t.Fatalf("final setup report = revision %d, states %#v; want both ready at revision 1",
			report.AppliedRevision, states)
	}
}

func TestSetupOperationUsesClosedBoundedExecutionAndGatesAppliedRevision(t *testing.T) {
	database := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{
		setupResult:  setupReceipt("ready"),
		setupInvoked: make(chan setupInvocation, 2),
	}
	reconciler := setupReconciler(t, store, engine)
	beginSetupApplying(t, reconciler, engine)
	started := time.Now()
	if err := reconciler.Reconcile(context.Background(), setupManifest(1)); err != nil {
		t.Fatal(err)
	}
	invocation := awaitSetupInvocation(t, engine.setupInvoked)
	if invocation.sandboxID != setupSandboxID {
		t.Fatalf("setup was dispatched to %q, want %q", invocation.sandboxID, setupSandboxID)
	}
	if len(invocation.request) == 0 || len(invocation.request) > 64*1024 {
		t.Fatalf("runner request size was %d bytes", len(invocation.request))
	}
	var request map[string]any
	if err := json.Unmarshal(invocation.request, &request); err != nil {
		t.Fatalf("runner request was not JSON: %v", err)
	}
	for _, forbidden := range []string{"argv", "command", "env", "path", "workdir"} {
		if _, exists := request[forbidden]; exists {
			t.Fatalf("runner request exposed forbidden execution control %q", forbidden)
		}
	}
	if invocation.deadline.IsZero() {
		t.Fatal("setup execution had no deadline")
	}
	duration := invocation.deadline.Sub(started)
	if duration < 9*time.Minute+55*time.Second || duration > 10*time.Minute+5*time.Second {
		t.Fatalf("setup deadline was %s, want ten minutes", duration)
	}
	report, operation := awaitReportState(t, reconciler, "ready")
	if report.AppliedRevision != 1 {
		t.Fatalf("ready setup did not advance applied revision: %#v", report)
	}
	for key, want := range map[string]any{
		"id": setupOperationID, "sandboxId": setupSandboxID,
		"sandboxGeneration": float64(1), "profileId": setupProfileID,
		"profileDigest": "sha256:" + strings.Repeat("a", 64),
	} {
		if operation[key] != want {
			t.Fatalf("reported setup tuple %q = %#v, want %#v", key, operation[key], want)
		}
	}
	if err := reconciler.Reconcile(context.Background(), setupManifest(1)); err != nil {
		t.Fatal(err)
	}
	select {
	case replay := <-engine.setupInvoked:
		t.Fatalf("identical ready operation was executed twice: %#v", replay)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestNewSetupOperationReportsApplyingBeforeExecutionOnNextReconcile(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{
		setupResult:  setupReceipt("ready"),
		setupInvoked: make(chan setupInvocation, 1),
	}
	reconciler := setupReconciler(t, store, engine)

	if err := reconciler.Reconcile(context.Background(), setupManifest(1)); err != nil {
		t.Fatal(err)
	}
	select {
	case invocation := <-engine.setupInvoked:
		t.Fatalf("new setup executed before applying could be reported: %#v", invocation)
	default:
	}
	firstReport, _ := awaitReportState(t, reconciler, "applying")
	if firstReport.AppliedRevision != 0 {
		t.Fatalf("applying setup advanced applied revision: %#v", firstReport)
	}
	persisted, err := store.SetupOperation(context.Background(), setupOperationID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted == nil || persisted.State != "applying" {
		t.Fatalf("first reconcile did not persist applying: %#v", persisted)
	}

	if err := reconciler.Reconcile(context.Background(), setupManifest(1)); err != nil {
		t.Fatal(err)
	}
	_ = awaitSetupInvocation(t, engine.setupInvoked)
	readyReport, _ := awaitReportState(t, reconciler, "ready")
	if readyReport.AppliedRevision != 1 {
		t.Fatalf("second reconcile did not advance ready revision: %#v", readyReport)
	}
}

func TestFailedSetupIsDurableAndDoesNotRetryTheSameFence(t *testing.T) {
	database := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	engine := &fakeEngine{
		setupDiagnostic: []byte("candidate self-test failed"),
		setupErr:        errors.New("setup runner failed"),
		setupInvoked:    make(chan setupInvocation, 3),
	}
	reconciler := setupReconciler(t, store, engine)
	beginSetupApplying(t, reconciler, engine)
	_ = reconciler.Reconcile(context.Background(), setupManifest(1))
	_ = awaitSetupInvocation(t, engine.setupInvoked)
	report, operation := awaitReportState(t, reconciler, "failed")
	if report.AppliedRevision != 0 {
		t.Fatalf("failed setup advanced applied revision to %d", report.AppliedRevision)
	}
	encoded, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "candidate self-test failed") {
		t.Fatalf("raw runner stderr escaped into the report: %s", encoded)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restartedEngine := &fakeEngine{setupInvoked: make(chan setupInvocation, 1)}
	restarted := setupReconciler(t, reopened, restartedEngine)
	_ = restarted.Reconcile(context.Background(), setupManifest(1))
	select {
	case retry := <-restartedEngine.setupInvoked:
		t.Fatalf("terminal failed setup was retried without a new fence: %#v", retry)
	case <-time.After(100 * time.Millisecond):
	}
	resumedReport, _ := awaitReportState(t, restarted, "failed")
	if resumedReport.AppliedRevision != 0 {
		t.Fatalf("restart advanced a failed setup revision: %#v", resumedReport)
	}
}

func TestInterruptedSetupResumesAfterRestart(t *testing.T) {
	database := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	interruptedEngine := &fakeEngine{
		setupErr:     context.Canceled,
		setupInvoked: make(chan setupInvocation, 1),
	}
	first := setupReconciler(t, store, interruptedEngine)
	beginSetupApplying(t, first, interruptedEngine)
	_ = first.Reconcile(context.Background(), setupManifest(1))
	_ = awaitSetupInvocation(t, interruptedEngine.setupInvoked)
	_, _ = awaitReportState(t, first, "applying")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	resumedEngine := &fakeEngine{
		setupResult:  setupReceipt("ready"),
		setupInvoked: make(chan setupInvocation, 1),
	}
	resumed := setupReconciler(t, reopened, resumedEngine)
	if err := resumed.Reconcile(context.Background(), setupManifest(1)); err != nil {
		t.Fatal(err)
	}
	_ = awaitSetupInvocation(t, resumedEngine.setupInvoked)
	report, _ := awaitReportState(t, resumed, "ready")
	if report.AppliedRevision != 1 {
		t.Fatalf("resumed setup did not converge revision: %#v", report)
	}
}

func TestRemovedNonterminalSetupIsCancelled(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := &fakeEngine{
		setupErr:     context.Canceled,
		setupInvoked: make(chan setupInvocation, 1),
	}
	reconciler := setupReconciler(t, store, engine)
	beginSetupApplying(t, reconciler, engine)
	_ = reconciler.Reconcile(context.Background(), setupManifest(1))
	_ = awaitSetupInvocation(t, engine.setupInvoked)
	_, _ = awaitReportState(t, reconciler, "applying")

	removed := setupManifest(2)
	removed.SetupOperations = nil
	if err := reconciler.Reconcile(context.Background(), removed); err != nil {
		t.Fatal(err)
	}
	report, _ := awaitReportState(t, reconciler, "cancelled")
	if report.AppliedRevision != 2 {
		t.Fatalf("cancelled removed setup did not allow the new desired revision: %#v", report)
	}
}

func TestSetupReceiptRejectsUnknownOrMismatchedData(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	badReceipt := setupReceipt("ready")
	var decoded map[string]any
	if err := json.Unmarshal(badReceipt, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["sandboxId"] = "sbx_foreign12345"
	decoded["token"] = "must-not-escape"
	badReceipt, err = json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	engine := &fakeEngine{
		setupResult:  badReceipt,
		setupInvoked: make(chan setupInvocation, 1),
	}
	reconciler := setupReconciler(t, store, engine)
	beginSetupApplying(t, reconciler, engine)
	_ = reconciler.Reconcile(context.Background(), setupManifest(1))
	_ = awaitSetupInvocation(t, engine.setupInvoked)
	report, operation := awaitReportState(t, reconciler, "failed")
	if report.AppliedRevision != 0 {
		t.Fatalf("invalid receipt advanced applied revision: %#v", report)
	}
	encoded, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "must-not-escape") ||
		strings.Contains(string(encoded), "sbx_foreign12345") {
		t.Fatalf("invalid receipt content escaped into report: %s", encoded)
	}
}

func TestSetupReceiptDigestAuthenticatesCanonicalContent(t *testing.T) {
	operation := localSetupReceiptOperation()
	valid := decodeSetupReceipt(setupReceipt("ready"))
	const runnerDigest = "sha256:7d7ed0b085bf9c05086cd88f9794811387fd7d5ca3401aae8c5d8c1cd8bbda9e"
	if valid["receiptDigest"] != runnerDigest {
		t.Fatalf("Go fixture canonicalization diverged from the runner: %#v", valid["receiptDigest"])
	}
	if _, err := validateSetupReceipt(encodeSetupReceipt(valid), operation); err != nil {
		t.Fatalf("runner-compatible canonical receipt was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "arbitrary well-formed digest",
			mutate: func(receipt map[string]any) {
				receipt["receiptDigest"] = "sha256:" + strings.Repeat("c", 64)
			},
		},
		{
			name: "content changed after signing",
			mutate: func(receipt map[string]any) {
				provenance := receipt["provenance"].(map[string]any)
				provenance["source"] = "https://artifacts.example/tampered.tgz"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := decodeSetupReceipt(setupReceipt("ready"))
			test.mutate(receipt)
			if _, err := validateSetupReceipt(encodeSetupReceipt(receipt), operation); err == nil {
				t.Fatal("receipt with an unauthenticated body was accepted")
			}
		})
	}
}

func TestSetupReceiptRejectsReadyWithErrorEvenWhenDigestMatches(t *testing.T) {
	receipt := decodeSetupReceipt(setupReceipt("ready"))
	receipt["error"] = map[string]any{
		"code":   "impossible_ready_error",
		"detail": "ready receipts cannot also report failure",
	}
	receipt["receiptDigest"] = canonicalSetupReceiptDigest(receipt)
	if _, err := validateSetupReceipt(
		encodeSetupReceipt(receipt),
		localSetupReceiptOperation(),
	); err == nil {
		t.Fatal("ready receipt with an error object was accepted")
	}
}

func TestVerifiedReceiptDigestIsTheDigestPersistedAndReported(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	receiptJSON := setupReceipt("ready")
	wireReceipt := decodeSetupReceipt(receiptJSON)
	wantDigest := canonicalSetupReceiptDigest(wireReceipt)
	if wireReceipt["receiptDigest"] != wantDigest {
		t.Fatalf("test receipt is not canonically signed: %#v", wireReceipt)
	}
	engine := &fakeEngine{
		setupResult:  receiptJSON,
		setupInvoked: make(chan setupInvocation, 1),
	}
	reconciler := setupReconciler(t, store, engine)
	beginSetupApplying(t, reconciler, engine)
	if err := reconciler.Reconcile(context.Background(), setupManifest(1)); err != nil {
		t.Fatal(err)
	}
	_ = awaitSetupInvocation(t, engine.setupInvoked)
	_, reported := awaitReportState(t, reconciler, "ready")
	operation, err := store.SetupOperation(context.Background(), setupOperationID)
	if err != nil {
		t.Fatal(err)
	}
	if operation == nil {
		t.Fatal("ready setup operation was not persisted")
	}
	storedReceipt := decodeSetupReceipt(operation.ReceiptJSON)
	verifiedStoredDigest := canonicalSetupReceiptDigest(storedReceipt)
	if operation.ReceiptDigest != wantDigest || operation.ReceiptDigest != verifiedStoredDigest {
		t.Fatalf("stored digest is not bound to stored receipt: stored=%q want=%q recomputed=%q",
			operation.ReceiptDigest, wantDigest, verifiedStoredDigest)
	}
	if reported["receiptDigest"] != wantDigest {
		t.Fatalf("reported digest = %#v, want verified digest %q", reported["receiptDigest"], wantDigest)
	}
}

func TestFailedAndCancelledReceiptsNeverPersistAsSuccessfulReceipts(t *testing.T) {
	for _, status := range []string{"failed", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			engine := &fakeEngine{
				setupResult:  setupReceipt(status),
				setupInvoked: make(chan setupInvocation, 1),
			}
			reconciler := setupReconciler(t, store, engine)
			beginSetupApplying(t, reconciler, engine)
			if err := reconciler.Reconcile(context.Background(), setupManifest(1)); err == nil {
				t.Fatalf("runner %s receipt did not stop revision convergence", status)
			}
			_ = awaitSetupInvocation(t, engine.setupInvoked)
			operation, err := store.SetupOperation(context.Background(), setupOperationID)
			if err != nil {
				t.Fatal(err)
			}
			if operation == nil || operation.State != status {
				t.Fatalf("terminal status was not persisted: %#v", operation)
			}
			if len(operation.ReceiptJSON) != 0 || operation.ReceiptDigest != "" {
				t.Fatalf("%s result was persisted as a successful receipt: %#v", status, operation)
			}
			report, _ := awaitReportState(t, reconciler, status)
			if report.AppliedRevision != 0 {
				t.Fatalf("%s receipt advanced applied revision: %#v", status, report)
			}
		})
	}
}
