package insights

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type sandboxInsightFixture struct {
	OpenRequest       map[string]any  `json:"openRequest"`
	OpenResponse      json.RawMessage `json:"openResponse"`
	RecoveredRequest  map[string]any  `json:"recoveredRequest"`
	RecoveredResponse json.RawMessage `json:"recoveredResponse"`
}

type fakeInsightControl struct {
	policy      model.InsightPolicyEnvelopeV1
	policyErr   error
	submissions []model.InsightBatchV1
	loseAck     bool
}

func (f *fakeInsightControl) InsightPolicies(context.Context) (model.InsightPolicyEnvelopeV1, error) {
	return f.policy, f.policyErr
}

func (f *fakeInsightControl) SubmitInsightBatch(_ context.Context, batch model.InsightBatchV1) (model.InsightBatchReceiptV1, error) {
	f.submissions = append(f.submissions, batch)
	receipt := model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: len(batch.Findings), ThroughSequence: batch.ThroughSequence}
	if f.loseAck {
		f.loseAck = false
		return model.InsightBatchReceiptV1{}, errors.New("injected lost batch acknowledgement")
	}
	return receipt, nil
}

type fakeInsightMonitor struct {
	responses []json.RawMessage
	requests  []map[string]any
}

func (f *fakeInsightMonitor) ExecMonitor(_ context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	f.requests = append(f.requests, request)
	if len(f.responses) == 0 {
		return nil, nil, errors.New("unexpected monitor read")
	}
	response := f.responses[0]
	f.responses = f.responses[1:]
	return response, nil, nil
}

type fakeInsightLifecycle struct {
	policies []model.InsightPolicyV1
}

func (f *fakeInsightLifecycle) ApplyInsightMonitorPolicy(_ context.Context, policy model.InsightPolicyV1) error {
	f.policies = append(f.policies, policy)
	return nil
}

func TestCollectorPersistsBeforeSendReplaysLostAckAndCoalescesNoChange(t *testing.T) {
	fixture := readSandboxInsightFixture(t)
	now := time.Date(2026, 9, 27, 18, 0, 30, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	policy := currentInsightPolicy(now)
	seedInsightAuthority(t, store, policy, now)
	control := &fakeInsightControl{policy: model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{policy}}, loseAck: true}
	monitor := &fakeInsightMonitor{responses: []json.RawMessage{fixture.OpenResponse}}
	lifecycle := &fakeInsightLifecycle{}
	collector := &Collector{Store: store, Control: control, Monitor: monitor, Lifecycle: lifecycle, Now: func() time.Time { return now }}
	if err := collector.RunOnce(context.Background()); err == nil {
		t.Fatal("lost backend acknowledgement was treated as committed")
	}
	if len(control.submissions) != 1 || len(monitor.requests) != 1 || !reflect.DeepEqual(monitor.requests[0], fixture.OpenRequest) {
		t.Fatalf("first policy/monitor submission = %#v / %#v", control.submissions, monitor.requests)
	}
	assertSanitizedInsightBatch(t, control.submissions[0])
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered := &Collector{Store: reopened, Control: control, Monitor: monitor, Lifecycle: lifecycle, Now: func() time.Time { return now }}
	if err := recovered.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(control.submissions) != 2 || !reflect.DeepEqual(control.submissions[0], control.submissions[1]) || len(monitor.requests) != 1 {
		t.Fatalf("lost acknowledgement replay/read count = %#v / %#v", control.submissions, monitor.requests)
	}
	cursor, err := reopened.InsightCursor(context.Background(), policy.Sources[0].RegisteredSourceID)
	if err != nil || cursor == nil || cursor.ChangeSequence != 1 || cursor.JournalGeneration == "" {
		t.Fatalf("acknowledged cursor = %#v, %v", cursor, err)
	}

	monitor.responses = append(monitor.responses, fixture.RecoveredResponse, noChangeInsightResponse(t, fixture.RecoveredResponse))
	if err := recovered.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(control.submissions) != 3 || control.submissions[2].Findings[0].State != "resolved" {
		t.Fatalf("recovery submission = %#v", control.submissions)
	}
	if err := recovered.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(control.submissions) != 3 {
		t.Fatalf("unchanged health/status consumed a receipt: %#v", control.submissions)
	}
}

func TestCollectorRejectsStaleAuthorityExpiresPolicyAndPublishesRotationGapFirst(t *testing.T) {
	fixture := readSandboxInsightFixture(t)
	now := time.Date(2026, 9, 27, 18, 0, 30, 0, time.UTC)
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := currentInsightPolicy(now)
	seedInsightAuthority(t, store, policy, now)
	rotation := rotationInsightResponse(t, fixture.OpenResponse)
	control := &fakeInsightControl{policy: model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{policy}}}
	monitor := &fakeInsightMonitor{responses: []json.RawMessage{rotation}}
	lifecycle := &fakeInsightLifecycle{}
	collector := &Collector{Store: store, Control: control, Monitor: monitor, Lifecycle: lifecycle, Now: func() time.Time { return now }}
	if err := collector.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(control.submissions) != 1 || control.submissions[0].GapReason == nil || *control.submissions[0].GapReason != "journal_generation_changed" ||
		len(control.submissions[0].Findings) != 0 {
		t.Fatalf("rotation did not publish one empty gap first: %#v", control.submissions)
	}
	cursor, err := store.InsightCursor(context.Background(), policy.Sources[0].RegisteredSourceID)
	if err != nil || cursor == nil || cursor.JournalGeneration != "journal_rotated0001" || cursor.ChangeSequence != 2 {
		t.Fatalf("rotation floor acknowledgement = %#v, %v", cursor, err)
	}

	stale := policy
	stale.Sources = append([]model.InsightPolicySourceV1(nil), policy.Sources...)
	stale.Sources[0].ServiceGeneration++
	control.policy = model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{stale}}
	if err := collector.RunOnce(context.Background()); err == nil {
		t.Fatal("foreign service generation reached monitor")
	}
	if len(monitor.requests) != 1 {
		t.Fatalf("stale policy reached monitor: %#v", monitor.requests)
	}

	control.policy = model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{policy}}
	collector.Now = func() time.Time { return policy.ExpiresAt.Add(time.Second) }
	if err := collector.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(monitor.requests) != 1 || len(lifecycle.policies) == 0 || lifecycle.policies[len(lifecycle.policies)-1].Enabled ||
		len(control.submissions) != 2 || control.submissions[1].Status != "disabled" || len(control.submissions[1].Findings) != 0 {
		t.Fatalf("expired policy did not acknowledge stopped capture without reading: requests=%#v lifecycle=%#v submissions=%#v", monitor.requests, lifecycle.policies, control.submissions)
	}
}

func readSandboxInsightFixture(t *testing.T) sandboxInsightFixture {
	t.Helper()
	payload, err := os.ReadFile("../api/testdata/agent-insights-v1.sandbox-wire.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture sandboxInsightFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func currentInsightPolicy(now time.Time) model.InsightPolicyV1 {
	return model.InsightPolicyV1{
		SandboxID: "sbx_monitor12345", Revision: 2, Enabled: true, ExpiresAt: now.Add(90 * time.Second),
		Sources: []model.InsightPolicySourceV1{{
			RegisteredSourceID: "source_monitor12345", ServiceRegistrationID: "service_monitor12345",
			SandboxGeneration: 1, ServiceGeneration: 1, WorkspaceEpoch: "epoch_monitor12345", NativeSessionID: "ses_monitor12345",
		}},
	}
}

func seedInsightAuthority(t *testing.T, store *state.Store, policy model.InsightPolicyV1, now time.Time) {
	t.Helper()
	source := policy.Sources[0]
	if err := store.PutSandbox(context.Background(), state.LocalSandbox{
		ID: policy.SandboxID, Name: "monitor", DesiredState: "running", ObservedState: "running",
		Generation: source.SandboxGeneration, ObservedGeneration: source.SandboxGeneration, Lifetime: "persistent",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuitySource(context.Background(), state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: source.RegisteredSourceID, ServiceRegistrationID: source.ServiceRegistrationID,
			ServiceGeneration: source.ServiceGeneration, ProjectID: "project_monitor12345", SandboxID: policy.SandboxID,
			SandboxGeneration: source.SandboxGeneration, WorkspaceEpoch: source.WorkspaceEpoch, NativeSessionID: source.NativeSessionID,
			NativeProjectID:      "0123456789abcdef0123456789abcdef01234567",
			NativeLocationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ScopeRevision:        1, Role: "worker", ProfileRevision: 1, InstructionRevision: 1,
			Availability: "available", LastObservedAt: now,
		},
		Root: t.TempDir(), Instance: "worker-monitor", Lifecycle: "running", LifecycleRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

func assertSanitizedInsightBatch(t *testing.T, batch model.InsightBatchV1) {
	t.Helper()
	payload, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > 64*1024 || bytes.Contains(payload, []byte("serverId")) {
		t.Fatalf("unsafe insight batch: %s", payload)
	}
	for _, forbidden := range []string{"command", "result", "prompt", "arguments", "url", "path", "fingerprint"} {
		if bytes.Contains(payload, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("batch leaked %s: %s", forbidden, payload)
		}
	}
}

func noChangeInsightResponse(t *testing.T, source json.RawMessage) json.RawMessage {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(source, &value); err != nil {
		t.Fatal(err)
	}
	value["fromChangeSequence"] = float64(2)
	value["nextChangeSequence"] = float64(2)
	value["incidentChanges"] = []any{}
	payload, _ := json.Marshal(value)
	return payload
}

func rotationInsightResponse(t *testing.T, source json.RawMessage) json.RawMessage {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(source, &value); err != nil {
		t.Fatal(err)
	}
	value["journalGeneration"] = "journal_rotated0001"
	value["coverage"] = "gap"
	value["gapReason"] = "journal_generation_changed"
	value["fromChangeSequence"] = float64(0)
	value["throughChangeSequence"] = float64(2)
	value["nextChangeSequence"] = float64(2)
	value["incidentChanges"] = []any{}
	health := value["health"].(map[string]any)
	health["journalGeneration"] = "journal_rotated0001"
	payload, _ := json.Marshal(value)
	return payload
}
