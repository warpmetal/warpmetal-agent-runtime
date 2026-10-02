package insights

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func TestCollectorRefetchesAfterTerminal409RetiresOldBatchAndDoesNotStarveOtherSource(t *testing.T) {
	now := time.Date(2026, 9, 27, 19, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old := insightPolicyFor("sbx_superseded0001", 2, true, now.Add(90*time.Second), "source_superseded_old", "service_superseded_old", "epoch_superseded_old", "ses_superseded_old")
	current := insightPolicyFor("sbx_superseded0001", 3, false, now.Add(90*time.Second), "source_superseded_new", "service_superseded_new", "epoch_superseded_new", "ses_superseded_new")
	transient := insightPolicyFor("sbx_transient000001", 5, true, now.Add(90*time.Second), "source_transient000001", "service_transient000001", "epoch_transient000001", "ses_transient000001")
	other := insightPolicyFor("sbx_other00000001", 7, true, now.Add(90*time.Second), "source_other00000001", "service_other00000001", "epoch_other00000001", "ses_other00000001")
	seedInsightAuthority(t, store, old, now)
	seedInsightAuthority(t, store, current, now)
	seedInsightAuthority(t, store, transient, now)
	seedInsightAuthority(t, store, other, now)
	oldBatch := model.InsightBatchV1{
		FormatVersion: 1, BatchID: "batch_superseded_old", SandboxID: old.SandboxID,
		SandboxGeneration: 1, PolicyRevision: old.Revision, RegisteredSourceID: old.Sources[0].RegisteredSourceID,
		ServiceRegistrationID: old.Sources[0].ServiceRegistrationID, ServiceGeneration: 1,
		WorkspaceEpoch: old.Sources[0].WorkspaceEpoch, NativeSessionID: old.Sources[0].NativeSessionID,
		JournalGeneration: "journal_superseded_old", ThroughSequence: 8, ObservedAt: now,
		Status: "ready", GapReason: nil, Findings: []model.InsightFindingV1{},
	}
	oldCursor := state.InsightCursor{RegisteredSourceID: old.Sources[0].RegisteredSourceID, PolicyRevision: 2,
		WorkspaceEpoch: old.Sources[0].WorkspaceEpoch, JournalGeneration: oldBatch.JournalGeneration,
		ChangeSequence: 4, ThroughSequence: 8, Status: "ready"}
	if err := store.PutInsightOutbox(context.Background(), state.InsightOutboxItem{
		Batch: oldBatch, BodyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NextCursor: oldCursor,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var mu sync.Mutex
	policyReads := 0
	oldPosts := 0
	accepted := []model.InsightBatchV1{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/internal/runtime/insights/policies":
			mu.Lock()
			policyReads++
			read := policyReads
			mu.Unlock()
			policies := []model.InsightPolicyV1{old, transient, other}
			if read > 1 {
				policies = []model.InsightPolicyV1{current, transient, other}
			}
			_ = json.NewEncoder(writer).Encode(model.InsightPolicyEnvelopeV1{Policies: policies})
		case "/internal/runtime/insights/batches":
			var batch model.InsightBatchV1
			if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
				t.Error(err)
				return
			}
			if batch.BatchID == oldBatch.BatchID {
				mu.Lock()
				oldPosts++
				mu.Unlock()
				writer.WriteHeader(http.StatusConflict)
				_, _ = writer.Write([]byte(`{"error":{"code":"insights_policy_conflict"}}`))
				return
			}
			mu.Lock()
			accepted = append(accepted, batch)
			mu.Unlock()
			_ = json.NewEncoder(writer).Encode(model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: len(batch.Findings), ThroughSequence: batch.ThroughSequence})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := api.Client{Origin: server.URL, NodeToken: "rtn_supersession", HTTP: server.Client()}
	monitor := &sourceSelectiveMonitor{responses: map[string]json.RawMessage{
		other.Sources[0].RegisteredSourceID: emptyCurrentMonitorResponse(t, other),
	}, failures: map[string]error{transient.Sources[0].RegisteredSourceID: errors.New("temporary exporter failure")}}
	lifecycle := &fakeInsightLifecycle{}
	collector := &Collector{Store: store, Control: client, Monitor: monitor, Lifecycle: lifecycle, Now: func() time.Time { return now }}
	if err := collector.RunOnce(context.Background()); err == nil {
		t.Fatal("transient source failure was hidden")
	}
	if policyReads < 2 || oldPosts != 1 {
		t.Fatalf("terminal conflict recovery reads/posts = %d/%d", policyReads, oldPosts)
	}
	if len(accepted) != 2 || accepted[0].RegisteredSourceID != current.Sources[0].RegisteredSourceID ||
		accepted[0].Status != "disabled" || accepted[1].RegisteredSourceID != other.Sources[0].RegisteredSourceID {
		t.Fatalf("current disabled transition/other source = %#v", accepted)
	}
	if len(monitor.requests) != 2 || monitor.requests[1]["sourceInstanceId"] != other.Sources[0].RegisteredSourceID {
		t.Fatalf("retired source read or other source starved: %#v", monitor.requests)
	}
	pending, err := store.InsightOutbox(context.Background())
	if err != nil || len(pending) != 0 {
		t.Fatalf("terminal old outbox remained blocking: %#v %v", pending, err)
	}
	retired, err := store.InsightOutboxRetirements(context.Background())
	if err != nil || len(retired) != 1 || retired[0].Batch.BatchID != oldBatch.BatchID ||
		retired[0].BodyDigest != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ||
		retired[0].Reason != "policy_superseded" || !reflect.DeepEqual(retired[0].NextCursor, oldCursor) {
		t.Fatalf("immutable retirement tombstone = %#v %v", retired, err)
	}
	if cursor, err := store.InsightCursor(context.Background(), old.Sources[0].RegisteredSourceID); err != nil || cursor != nil {
		t.Fatalf("retired unacknowledged cursor advanced: %#v %v", cursor, err)
	}
}

type sourceSelectiveMonitor struct {
	responses map[string]json.RawMessage
	failures  map[string]error
	requests  []map[string]any
}

func (m *sourceSelectiveMonitor) ExecMonitor(_ context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	m.requests = append(m.requests, request)
	source, _ := request["sourceInstanceId"].(string)
	if err := m.failures[source]; err != nil {
		return nil, nil, err
	}
	response, ok := m.responses[source]
	if !ok {
		return nil, nil, errors.New("unexpected monitor source")
	}
	return response, nil, nil
}

func TestCollectorCachedPolicyDeadlineDisablesAfterFetchFailureOrAbsenceAcrossReopen(t *testing.T) {
	fixture := readSandboxInsightFixture(t)
	now := time.Date(2026, 9, 27, 18, 0, 30, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	policy := currentInsightPolicy(now)
	seedInsightAuthority(t, store, policy, now)
	control := &fakeInsightControl{policy: model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{policy}}}
	monitor := &fakeInsightMonitor{responses: []json.RawMessage{fixture.OpenResponse}}
	lifecycle := &fakeInsightLifecycle{}
	collector := &Collector{Store: store, Control: control, Monitor: monitor, Lifecycle: lifecycle, Now: func() time.Time { return now }}
	if err := collector.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	afterDeadline := policy.ExpiresAt.Add(time.Second)
	control.policyErr = errors.New("temporary policy fetch failure")
	reopened := &Collector{Store: store, Control: control, Monitor: monitor, Lifecycle: lifecycle, Now: func() time.Time { return afterDeadline }}
	if err := reopened.RunOnce(context.Background()); err == nil {
		t.Fatal("policy fetch failure was hidden")
	}
	if len(lifecycle.policies) < 2 || lifecycle.policies[len(lifecycle.policies)-1].Enabled || len(monitor.requests) != 1 {
		t.Fatalf("expired cached authority survived fetch failure: lifecycle=%#v requests=%#v", lifecycle.policies, monitor.requests)
	}

	control.policyErr = nil
	control.policy = model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{}}
	if err := reopened.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lifecycle.policies[len(lifecycle.policies)-1].Enabled || len(monitor.requests) != 1 {
		t.Fatalf("absent policy renewed stale capture authority: lifecycle=%#v requests=%#v", lifecycle.policies, monitor.requests)
	}
}

func insightPolicyFor(sandbox string, revision int64, enabled bool, expires time.Time, source, service, epoch, session string) model.InsightPolicyV1 {
	return model.InsightPolicyV1{SandboxID: sandbox, Revision: revision, Enabled: enabled, ExpiresAt: expires,
		Sources: []model.InsightPolicySourceV1{{RegisteredSourceID: source, ServiceRegistrationID: service,
			SandboxGeneration: 1, ServiceGeneration: 1, WorkspaceEpoch: epoch, NativeSessionID: session}}}
}

func emptyCurrentMonitorResponse(t *testing.T, policy model.InsightPolicyV1) json.RawMessage {
	t.Helper()
	source := policy.Sources[0]
	value := map[string]any{
		"formatVersion": 1, "action": "report_incident_changes", "status": "ok",
		"sourceInstanceId": source.RegisteredSourceID, "workspaceEpoch": source.WorkspaceEpoch,
		"nativeSessionId": source.NativeSessionID, "journalGeneration": "journal_other00000001",
		"throughSequence": 0, "coverage": "complete", "gapReason": nil,
		"fromChangeSequence": 0, "throughChangeSequence": 0, "nextChangeSequence": 0,
		"incidentChanges": []any{}, "health": map[string]any{"enabled": true, "requiresFreshWindow": false,
			"clockId": "host_monotonic_v1", "clockGeneration": "clock_other00000001", "journalGeneration": "journal_other00000001"},
	}
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
