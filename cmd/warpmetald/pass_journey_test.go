package main

// Composed control-loop regression for the extracted runtimeFeedbackLoop.pass
// (the ACTUAL function serve calls). Real store, Reconciler, insights.Collector
// and manager.Coordinator with controlled engine/helper transports and an
// httptest control backend; no production behavior is changed.
//
// R1 (+R3) covers the acknowledged-batch pending-ACK path with a seeded valid
// outbox item; R2 covers the real Monitor report_incident_changes path with the
// Backend 120s source-freshness predicate evaluated against the deterministic
// clock. Both demand same-pass admission and fail the current flow.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/insights"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/manager"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/reconcile"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

const (
	passServerID = "srv_p2c_pass0001"
	passRuleID   = "repeated_identical_failure@1"
	passImageRef = "ghcr.io/warpmetal/warpmetal-agent-sandbox@sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
)

func stringPointer(value string) *string { return &value }
func intPointer(value int64) *int64      { return &value }

type passWireFixture struct {
	Policy model.InsightsManagerPolicyManifestV1 `json:"managerPolicyManifest"`
	Review model.InsightsManagerReviewManifestV1 `json:"manualReviewManifest"`
}

func loadPassFixture(t *testing.T) passWireFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "internal", "manager", "testdata", "backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture passWireFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

type passClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *passClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *passClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// passEngine is the controlled container boundary; it performs no live effect.
type passEngine struct{}

func (passEngine) Ensure(context.Context, model.Sandbox, string, string) error        { return nil }
func (passEngine) Replace(context.Context, model.Sandbox, string, string, bool) error { return nil }
func (passEngine) Start(context.Context, string) error                                { return nil }
func (passEngine) Stop(context.Context, string) error                                 { return nil }
func (passEngine) Restart(context.Context, string) error                              { return nil }
func (passEngine) Remove(context.Context, string) error                               { return nil }
func (passEngine) Preflight(context.Context, string) error                            { return nil }
func (passEngine) ExecSetup(context.Context, string, []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (passEngine) Exec(context.Context, string, string, bool, containers.SessionInput, io.Writer, io.Writer) error {
	return nil
}

// passWorkspaces advances the deterministic clock once at a real reconcile
// boundary to emulate 110s of heavy lifecycle work without sleeping.
type passWorkspaces struct {
	root         string
	clock        *passClock
	mu           sync.Mutex
	did          bool
	count        int
	heavyAt      time.Time
	heavyAdvance time.Duration
}

func (w *passWorkspaces) Ensure(_ context.Context, id string, _ int) (string, error) {
	w.mu.Lock()
	w.count++
	if !w.did {
		w.did = true
		advance := w.heavyAdvance
		if advance <= 0 {
			advance = 110 * time.Second
		}
		w.clock.Advance(advance)
		w.heavyAt = w.clock.Now()
	}
	w.mu.Unlock()
	return filepath.Join(w.root, id), nil
}

func (*passWorkspaces) Destroy(context.Context, string) error { return nil }

// passContinuity is the controlled continuity adapter: it publishes the actual
// seeded SQLite source reports (real LastObservedAt/identity) so the pass Report
// carries a genuinely fresh local observation.
type passContinuity struct{ store *state.Store }

func (passContinuity) Acknowledge(context.Context, model.Manifest) error { return nil }
func (passContinuity) Apply(context.Context, model.Manifest) error       { return nil }
func (passContinuity) Reports(context.Context) ([]model.ContinuitySourceReportV1, []model.ContinuityRegistrationReportV1, []model.ContinuityOperationReportV1, error) {
	return nil, nil, nil, nil
}
func (c passContinuity) ReportsCurrent(ctx context.Context, _ model.Manifest) ([]model.ContinuitySourceReportV1, []model.ContinuityRegistrationReportV1, []model.ContinuityOperationReportV1, error) {
	rows, err := c.store.ContinuitySources(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	reports := make([]model.ContinuitySourceReportV1, 0, len(rows))
	for _, row := range rows {
		reports = append(reports, row.Report)
	}
	return reports, nil, nil, nil
}

type passLifecycle struct{}

func (passLifecycle) ApplyInsightMonitorPolicy(context.Context, model.InsightPolicyV1) error {
	return nil
}

type passHelper struct {
	mu                  sync.Mutex
	source              model.InsightsManagerSourceV1
	sandboxID           string
	calls               []string
	guidanceCalls       int
	runs                map[string]map[string]any
	backend             *passControl
	manifestReadsAtDone int
	originValidUntil    time.Time
	guidanceValidUntil  time.Time
	startDelay          time.Duration
	startCanceled       bool
	phaseManifestReads  int
	startDeadline       time.Time
	continueDeadline    time.Time
	dispatchDeadline    time.Time
	dispatchAt          time.Time
}

func passTime(value any) time.Time {
	text, _ := value.(string)
	moment, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}
	}
	return moment
}

func opaquePassID(prefix, value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%s%x", prefix, sum[:12])
}

func passDigest(value any) string {
	payload, _ := json.Marshal(value)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}

// ExecManager is the controlled native helper transport. It returns reviewing
// on start_review, a valid terminal recommendation with guarded guidance on
// continue_review, and an actual guidance snapshot on dispatch_guidance, so a
// correct production path can reach first delivery.
func (h *passHelper) ExecManager(ctx context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	action, _ := request["action"].(string)
	deadline, _ := ctx.Deadline()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, action)
	if h.runs == nil {
		h.runs = map[string]map[string]any{}
	}
	if action == "start_review" {
		h.startDeadline = deadline
		if h.startDelay > 0 {
			select {
			case <-time.After(h.startDelay):
			case <-ctx.Done():
				h.startCanceled = true
				return nil, nil, ctx.Err()
			}
		}
		authority, _ := request["authority"].(map[string]any)
		runID, _ := authority["runId"].(string)
		reservationID, _ := authority["reservationId"].(string)
		if runID == "" || reservationID == "" {
			return nil, nil, fmt.Errorf("helper start authority missing ids")
		}
		h.runs[runID] = authority
		if h.backend != nil {
			h.phaseManifestReads = h.backend.snapshotManifestReads()
			if h.backend.snapshotFlipOffAtStart() {
				h.backend.setPolicyOff()
			}
			if advance := h.backend.snapshotAdvanceAtStart(); advance > 0 {
				h.backend.clock.Advance(advance)
			}
		}
		receipt := map[string]any{"formatVersion": 1, "action": action, "status": "reviewing",
			"reservationId": reservationID, "runId": runID, "receiptDigest": "sha256:" + strings.Repeat("a", 64)}
		output, err := json.Marshal(receipt)
		if err != nil {
			return nil, nil, err
		}
		return output, nil, nil
	}
	runID, _ := request["runId"].(string)
	reservationID, _ := request["reservationId"].(string)
	if nested, ok := request["authority"].(map[string]any); ok && nested != nil {
		if runID == "" {
			runID, _ = nested["runId"].(string)
		}
		if reservationID == "" {
			reservationID, _ = nested["reservationId"].(string)
		}
	}
	authority := h.runs[runID]
	if runID == "" || reservationID == "" || authority == nil {
		return nil, nil, fmt.Errorf("helper %s missing unknown run data", action)
	}
	source, _ := authority["source"].(map[string]any)
	recipeID, _ := authority["recipeId"].(string)
	providerRouteDigest, _ := authority["providerRouteDigest"].(string)
	managerProfile, _ := authority["managerProfile"].(map[string]any)
	if source == nil || recipeID == "" || providerRouteDigest == "" || managerProfile == nil {
		return nil, nil, fmt.Errorf("helper %s stored authority incomplete", action)
	}
	managerSession := map[string]any{"nativeSessionId": source["nativeSessionId"],
		"nativeProjectId":       strings.Repeat("0", 40),
		"nativeLocationDigest":  "sha256:" + strings.Repeat("e", 64),
		"serviceRegistrationId": source["serviceRegistrationId"],
		"serviceGeneration":     source["serviceGeneration"], "providerRouteDigest": providerRouteDigest, "managerProfile": managerProfile}
	switch action {
	case "continue_review":
		h.continueDeadline = deadline
		if h.backend != nil {
			h.manifestReadsAtDone = h.backend.snapshotManifestReads()
			if h.backend.snapshotFlipOffAtContinue() {
				h.backend.setPolicyOff()
			}
		}
		h.originValidUntil = passTime(authority["validUntil"])
		guidanceDigest := "sha256:" + strings.Repeat("e", 64)
		receipt := map[string]any{"formatVersion": 1, "action": action, "status": "recommended",
			"reservationId": reservationID, "runId": runID, "receiptDigest": "sha256:" + strings.Repeat("b", 64),
			"modelRequests": 2, "reservedInputTokens": 16000, "reservedOutputTokens": 2000,
			"managerRegisteredSourceId": opaquePassID("manager_", runID), "managerSession": managerSession,
			"proposalDigest": "sha256:" + strings.Repeat("c", 64),
			"proposal": map[string]any{"recipeId": recipeID, "outcome": "recommendation",
				"rationaleCode": "unchanged_failure_repeated", "firstSequence": 1, "lastSequence": 4,
				"guidanceDigest": guidanceDigest},
			"guidanceReceipt": map[string]any{"formatVersion": 1, "mode": "recommend_only", "status": "not_delivered",
				"atomicNativeGuard": false, "autoSteer": false, "guidanceDigest": guidanceDigest, "pendingInputId": nil}}
		output, err := json.Marshal(receipt)
		if err != nil {
			return nil, nil, err
		}
		return output, nil, nil
	case "dispatch_guidance":
		h.dispatchDeadline = deadline
		h.dispatchAt = time.Now()
		if nested, ok := request["authority"].(map[string]any); ok && nested != nil {
			h.guidanceValidUntil = passTime(nested["originValidUntil"])
			if h.guidanceValidUntil.IsZero() {
				h.guidanceValidUntil = passTime(nested["validUntil"])
			}
		}
		h.guidanceCalls++
		guardID, pendingInputID := opaquePassID("guard_", runID), opaquePassID("msg_", runID)
		binding := passDigest(map[string]any{"bindingVersion": 1, "guardId": guardID,
			"instructionRevision": source["instructionRevision"], "nativeSessionId": source["nativeSessionId"],
			"pendingInputId": pendingInputID, "profileRevision": source["profileRevision"],
			"registeredSourceId": source["registeredSourceId"], "reservationId": reservationID, "runId": runID,
			"sandboxGeneration": source["sandboxGeneration"], "serviceGeneration": source["serviceGeneration"],
			"serviceRegistrationId": source["serviceRegistrationId"], "workspaceEpoch": source["workspaceEpoch"]})
		snapshot := map[string]any{"formatVersion": 1, "sandboxId": h.sandboxID, "reservationId": reservationID,
			"runId": runID, "revision": 1, "bindingDigest": binding, "guidanceDigest": "sha256:" + strings.Repeat("e", 64),
			"guardId": guardID, "pendingInputId": pendingInputID, "state": "pending", "refusalCode": nil,
			"logCursor": nil, "observedAt": "2026-10-04T12:00:00Z", "admittedAt": nil, "availableAt": nil,
			"settledAt": nil}
		snapshot["receiptDigest"] = passDigest(snapshot)
		receipt := map[string]any{"formatVersion": 1, "action": action, "reservationId": reservationID,
			"runId": runID, "guidance": snapshot}
		output, err := json.Marshal(receipt)
		if err != nil {
			return nil, nil, err
		}
		return output, nil, nil
	default:
		return nil, nil, fmt.Errorf("helper received unexpected action %s", action)
	}
}

// passMonitor is the controlled native helper transport. It returns a valid
// report_incident_changes response: zero changes for the R1 ACK path and one
// genuine new finding for the R2 real monitor path.
type passMonitor struct {
	clock    *passClock
	source   model.InsightsManagerSourceV1
	fresh    bool
	calls    int
	deadline time.Time
}

func (m *passMonitor) ExecMonitor(ctx context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	m.calls++
	m.deadline, _ = ctx.Deadline()
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	if request["formatVersion"] != float64(1) || request["action"] != "report_incident_changes" ||
		request["sourceInstanceId"] != m.source.RegisteredSourceID ||
		request["workspaceEpoch"] != m.source.WorkspaceEpoch || request["nativeSessionId"] != m.source.NativeSessionID {
		return nil, nil, fmt.Errorf("monitor request identity mismatch: %v", request)
	}
	response := map[string]any{
		"formatVersion": 1, "action": "report_incident_changes", "status": "ok",
		"sourceInstanceId": m.source.RegisteredSourceID, "workspaceEpoch": m.source.WorkspaceEpoch,
		"nativeSessionId": m.source.NativeSessionID, "journalGeneration": "journal_p2c_pass0001",
		"throughSequence": 4, "coverage": "complete", "gapReason": nil,
		"fromChangeSequence": 0, "throughChangeSequence": 1, "nextChangeSequence": 1,
		"incidentChanges": []any{}, "health": map[string]any{"journalGeneration": "journal_p2c_pass0001",
			"clockGeneration": "clock_p2c_pass0001", "clockId": "host_monotonic_v1", "enabled": true, "requiresFreshWindow": false},
	}
	if m.fresh {
		finding := model.InsightFindingV1{FindingID: "finding_p2c_pass0001", RuleID: passRuleID, State: "open", Revision: 1,
			FirstSequence: 1, LastSequence: 4, Count: 4, Threshold: 4,
			MatchedCallIDs:  []string{"call_p2c_0001", "call_p2c_0002", "call_p2c_0003", "call_p2c_0004"},
			FirstObservedAt: m.clock.Now().Add(-time.Minute), LastObservedAt: m.clock.Now(), Coverage: "complete",
			ToolCategory: "shell", Phase: "running_tool"}
		response["incidentChanges"] = []any{map[string]any{"changeSequence": 1, "finding": finding}}
	}
	payload, err := json.Marshal(response)
	if err != nil {
		return nil, nil, err
	}
	return payload, nil, nil
}

type passControl struct {
	mu                          sync.Mutex
	policy                      model.InsightsManagerPolicyManifestV1
	source                      model.InsightsManagerSourceV1
	target                      model.InsightsManagerTargetV1
	clock                       *passClock
	requireFreshSourceForPolicy bool
	publishedSourceAt           time.Time
	events                      []string
	lastError                   string
	lastManifestAt              time.Time
	manifestReads               int
	flipOffAtContinue           bool
	flipOffAtStart              bool
	advanceAtStart              time.Duration
	policyWindow                time.Duration
	policiesAt                  time.Time
	collectBoundary             time.Time
	reservationEventIndex       int
	lastBatchID                 string
	lastBatchFindings           int
	reportCount                 int
	lastReportLive              bool
	reservation                 model.InsightsManagerReservationRequestV1
	reservationAt               time.Time
}

func (s *passControl) snapshotManifestReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.manifestReads
}

func (s *passControl) snapshotFlipOffAtStart() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flipOffAtStart
}

func (s *passControl) snapshotAdvanceAtStart() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.advanceAtStart
}

func (s *passControl) snapshotLastReportLive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReportLive
}

// passTransport records the client-side context deadline at each real HTTP
// request boundary. Deadlines are not transmitted on the wire, so this is the
// observation point for the daemon's request contexts.
type passTransport struct {
	mu     sync.Mutex
	base   http.RoundTripper
	paths  []string
	byPath map[string][]time.Time
}

func (t *passTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	deadline, _ := request.Context().Deadline()
	t.mu.Lock()
	if t.byPath == nil {
		t.byPath = map[string][]time.Time{}
	}
	t.paths = append(t.paths, request.URL.Path)
	t.byPath[request.URL.Path] = append(t.byPath[request.URL.Path], deadline)
	t.mu.Unlock()
	return t.base.RoundTrip(request)
}

func (t *passTransport) deadlinesFor(path string) []time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]time.Time(nil), t.byPath[path]...)
}

func minPassDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (s *passControl) snapshotFlipOffAtContinue() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flipOffAtContinue
}

func (s *passControl) setPolicyOff() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy.Mode = "off"
	s.policy.AllowedRules = nil
	s.policy.AutoSteerPolicy = nil
	s.policy.AutoSteerAvailable = false
	s.policy.ValidUntil = s.clock.Now().Add(120 * time.Second)
}

func (s *passControl) eventsUpTo(index int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index > len(s.events) {
		return nil
	}
	return append([]string(nil), s.events[:index]...)
}

func (s *passControl) lastIndex(action string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for i, value := range s.events {
		if value == action {
			index = i
		}
	}
	return index
}

func (s *passControl) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("/internal/runtime/manifest", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.events = append(s.events, "manifest")
		s.manifestReads++
		s.lastManifestAt = s.clock.Now()
		policy := s.policy
		window := s.policyWindow
		if window <= 0 {
			window = 120 * time.Second
		}
		policy.ValidUntil = s.clock.Now().Add(window)
		s.mu.Unlock()
		writeJSON(w, model.Manifest{
			ServerID: passServerID, DesiredRevision: 1, ImageDigest: passImageRef,
			Capacity: model.Resources{CPUMillicores: 8000, MemoryMiB: 16384, WorkspaceDiskGiB: 100, PIDs: 4096},
			Sandboxes: []model.Sandbox{{ID: policy.SandboxID, Name: "q5-pass-worker", DesiredState: "running",
				Generation: 1, ImageDigest: passImageRef, Lifetime: "persistent",
				Resources: model.Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 1024}}},
			InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy},
		})
	})
	mux.HandleFunc("/internal/runtime/report", func(w http.ResponseWriter, r *http.Request) {
		var report model.Report
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			http.Error(w, "bad report", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.events = append(s.events, "report")
		s.reportCount++
		s.lastReportLive = r.Context().Err() == nil
		if report.LastError != nil {
			s.lastError = report.LastError.Code + ": " + report.LastError.Message
		}
		for _, source := range report.ContinuitySources {
			if source.RegisteredSourceID == s.source.RegisteredSourceID && source.ServiceRegistrationID == s.source.ServiceRegistrationID &&
				source.SandboxGeneration == s.source.SandboxGeneration && source.ServiceGeneration == s.source.ServiceGeneration &&
				source.WorkspaceEpoch == s.source.WorkspaceEpoch && source.NativeSessionID == s.source.NativeSessionID &&
				!source.LastObservedAt.IsZero() && s.clock.Now().Sub(source.LastObservedAt) <= 120*time.Second {
				s.publishedSourceAt = source.LastObservedAt
			}
		}
		s.mu.Unlock()
		writeJSON(w, map[string]bool{"accepted": true})
	})
	mux.HandleFunc("/internal/runtime/insights/policies", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.events = append(s.events, "policies")
		fresh := !s.requireFreshSourceForPolicy ||
			(!s.publishedSourceAt.IsZero() && s.clock.Now().Sub(s.publishedSourceAt) <= 120*time.Second)
		s.policiesAt = s.clock.Now()
		if fresh && !s.publishedSourceAt.IsZero() {
			s.collectBoundary = s.clock.Now()
		}
		policy := s.policy
		source := s.source
		s.mu.Unlock()
		entry := model.InsightPolicyV1{SandboxID: policy.SandboxID, Revision: policy.PolicyRevision, Enabled: true,
			ExpiresAt: s.clock.Now().Add(120 * time.Second)}
		if fresh {
			entry.Sources = []model.InsightPolicySourceV1{{RegisteredSourceID: source.RegisteredSourceID,
				ServiceRegistrationID: source.ServiceRegistrationID, SandboxGeneration: source.SandboxGeneration,
				ServiceGeneration: source.ServiceGeneration, WorkspaceEpoch: source.WorkspaceEpoch,
				NativeSessionID: source.NativeSessionID}}
		}
		writeJSON(w, model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{entry}})
	})
	mux.HandleFunc("/internal/runtime/insights/batches", func(w http.ResponseWriter, r *http.Request) {
		var batch model.InsightBatchV1
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			http.Error(w, "bad batch", http.StatusBadRequest)
			return
		}
		if batch.FormatVersion != 1 || batch.BatchID == "" || batch.SandboxID != s.policy.SandboxID ||
			batch.PolicyRevision != s.policy.PolicyRevision ||
			(batch.Status != "ready" && batch.Status != "degraded" && batch.Status != "disabled") ||
			len(batch.Findings) > 64 || batch.ThroughSequence < 0 {
			http.Error(w, "invalid batch contract", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.events = append(s.events, "batch")
		s.lastBatchID = batch.BatchID
		s.lastBatchFindings = len(batch.Findings)
		s.mu.Unlock()
		writeJSON(w, model.InsightBatchReceiptV1{BatchID: batch.BatchID, Accepted: len(batch.Findings), ThroughSequence: batch.ThroughSequence})
	})
	mux.HandleFunc("/internal/runtime/insights/manager/target", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		target := s.target
		source := s.source
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.InsightsManagerTargetEnvelopeV1{FormatVersion: 1,
			FindingID: "finding_p2c_pass0001", FindingRevision: 1, Source: source, Target: target})
	})
	mux.HandleFunc("/internal/runtime/insights/manager/reports", func(w http.ResponseWriter, r *http.Request) {
		var report model.InsightsManagerRunReportV1
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			http.Error(w, "bad run report", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.events = append(s.events, "run_report")
		request := s.reservation
		now := s.clock.Now()
		s.mu.Unlock()
		writeJSON(w, model.InsightsManagerActivityV1{RunID: report.RunID, ReservationID: report.ReservationID,
			Manual: report.Manual, FindingID: request.FindingID, RuleID: request.RuleID, RecipeID: request.RecipeID,
			Source: report.Source, Target: report.Target, State: report.State,
			ModelRequests: report.Usage.ModelRequests, InputTokens: report.Usage.InputTokens, OutputTokens: report.Usage.OutputTokens,
			CreatedAt: now, UpdatedAt: now})
	})
	mux.HandleFunc("/internal/runtime/insights/manager/reservations", func(w http.ResponseWriter, r *http.Request) {
		var request model.InsightsManagerReservationRequestV1
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad reservation", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.reservation = request
		s.reservationAt = s.clock.Now()
		s.events = append(s.events, "reservation")
		s.reservationEventIndex = len(s.events) - 1
		s.mu.Unlock()
		writeJSON(w, model.InsightsManagerReservationV1{FormatVersion: 1, ReservationID: request.ReservationID,
			RequestID: request.RequestID, RunID: "run_p2c_pass0001", State: "reserved", FindingID: request.FindingID,
			FindingRevision: request.FindingRevision, PolicyRevision: request.PolicyRevision, Source: request.Source,
			Target: request.Target, ReservedBudget: request.Budget,
			ExpiresAt: s.clock.Now().Add(time.Duration(request.ExpiresInSeconds) * time.Second),
			Execution: model.InsightsManagerReservationExecutionV1{
				ManagerProfile: model.InsightsManagerProfileV1{ProfileID: "warpmetal-insights-manager",
					ProfileRevision: 1, ProfileDigest: "sha256:" + strings.Repeat("b", 64)},
				ProviderRouteDigest: request.ProviderRouteDigest},
			Remaining: model.InsightsManagerRemainingV1{SandboxDailyRuns: 10, SandboxHourlyRuns: 5,
				SandboxDailyInputTokens: 100000, SandboxDailyOutputTokens: 10000, SessionRuns24h: 1,
				ServerConcurrentRuns: 1, ServerHourlyStarts: 5}})
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return server
}

func passAutoSteerPolicy(t *testing.T, fixture passWireFixture, clock *passClock) model.InsightsManagerPolicyManifestV1 {
	t.Helper()
	policy := fixture.Policy
	policy.FormatVersion = 1
	policy.Mode = "auto_steer"
	policy.AllowedRules = []string{passRuleID}
	policy.ValidUntil = clock.Now().Add(120 * time.Second)
	policy.PolicyRevision = 1
	policy.RunGeneration = 1
	policy.DailyRunLimit = 30
	policy.DailyInputTokenLimit = 480000
	policy.DailyOutputTokenLimit = 60000
	policy.EffectiveLimits = model.InsightsManagerEffectiveLimitsV1{PerRunModelRequests: 2, PerRunInputTokens: 16000,
		PerRunOutputTokens: 2000, SandboxDailyRuns: 30, SandboxHourlyRuns: 10, ServerConcurrentRuns: 2,
		ServerHourlyStarts: 20, SessionCooldownSeconds: 300, SessionRuns24h: 3}
	policy.ManagerProfile = model.InsightsManagerProfileV1{ProfileID: "warpmetal-insights-manager",
		ProfileRevision: 1, ProfileDigest: "sha256:" + strings.Repeat("b", 64)}
	policy.AutoSteerAvailable = false
	policy.AutoSteerPolicy = &model.InsightsManagerAutoSteerPolicyV1{FormatVersion: 1, Available: true,
		QualifiedTuple: &model.InsightsManagerAutoSteerTupleV1{
			NativeGuardVersion: "warpmetal.atomic-input.v1", CustomNativeVersion: "2.0.14-wm.1",
			NativeSourceRevision: "rev-084",
			PatchDigest:          "sha256:" + strings.Repeat("1", 64),
			ArtifactSHA256:       "sha256:" + strings.Repeat("d", 64),
			BinarySHA256:         "sha256:" + strings.Repeat("c", 64),
			ImageDigest:          "sha256:" + strings.Repeat("1", 64),
			ManagerProfileDigest: "sha256:" + strings.Repeat("b", 64),
			ManagerPluginDigest:  "sha256:" + strings.Repeat("9", 64)}}
	policy.SandboxGeneration = 1
	if policy.SandboxID == "" {
		policy.SandboxID = "sbx_p2c_pass0001"
	}
	if err := model.ValidateInsightsManagerPolicyManifest(policy); err != nil {
		t.Fatalf("fixture policy invalid: %v", err)
	}
	return policy
}

func passSource() model.InsightsManagerSourceV1 {
	return model.InsightsManagerSourceV1{RegisteredSourceID: "source_p2c_pass0001", WorkspaceEpoch: "epoch_p2c_pass0001",
		NativeSessionID: "ses_p2c_pass0001", ServiceRegistrationID: "service_p2c_pass0001", ServiceGeneration: 1,
		SandboxGeneration: 1, ProfileRevision: 2, InstructionRevision: 1}
}

func seedPassStore(t *testing.T, store *state.Store, policy model.InsightsManagerPolicyManifestV1, source model.InsightsManagerSourceV1, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := store.PutSandbox(ctx, state.LocalSandbox{ID: policy.SandboxID, Name: "q5-pass-worker", DesiredState: "running",
		ObservedState: "running", Generation: 1, ObservedGeneration: 1, Lifetime: "persistent", ImageDigest: passImageRef}); err != nil {
		t.Fatal(err)
	}
	serviceManifest := model.ManagedServiceV1{FormatVersion: 1, OperationID: "op_p2c_pass0001", ActionRevision: 1, DesiredRevision: 1,
		ConfigDigest: "sha256:" + strings.Repeat("a", 64), DesiredState: "active", SessionMode: "lookup_only",
		Identity: model.ManagedServiceIdentityV1{ServerID: passServerID, TeamID: "team_p2c_pass0001", MemberID: "tmem_p2c_pass0001",
			SandboxID: policy.SandboxID, SandboxGeneration: 1, ServiceRegistrationID: source.ServiceRegistrationID,
			ExpectedServiceGeneration: 1, Instance: "default", Role: "worker"}}
	if err := store.PutManagedServiceIntent(ctx, state.LocalManagedService{Manifest: serviceManifest, Phase: "ready",
		ProcessInstance: "default", Port: 18443, CreationDispatched: true, ServiceGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	report := model.ManagedServiceReportV1{FormatVersion: 1, OperationID: serviceManifest.OperationID, ActionRevision: 1,
		ObservedDesiredRevision: 1, ConfigDigest: serviceManifest.ConfigDigest, ObservedState: "ready", Identity: serviceManifest.Identity,
		ServiceGeneration: 1, ProfileStatus: "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "ready",
		InstructionApplied: true, InstructionRevision: 1, InstructionDigest: "sha256:" + strings.Repeat("c", 64),
		NativeRegistration: &model.ManagedNativeRegistrationV1{RegisteredSourceID: source.RegisteredSourceID,
			WorkspaceEpoch: source.WorkspaceEpoch, NativeSessionID: source.NativeSessionID,
			NativeProjectID: strings.Repeat("0", 40), NativeLocationDigest: "sha256:" + strings.Repeat("e", 64)},
		ReceiptDigest: "sha256:" + strings.Repeat("f", 64)}
	if err := store.UpdateManagedService(ctx, source.ServiceRegistrationID, "ready", &report, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.PutContinuitySource(ctx, state.LocalContinuitySource{Report: model.ContinuitySourceReportV1{FormatVersion: 1,
		RegisteredSourceID: source.RegisteredSourceID, ServiceRegistrationID: source.ServiceRegistrationID, ServiceGeneration: 1,
		ProjectID: "project_p2c_pass0001", SandboxID: policy.SandboxID, SandboxGeneration: 1,
		WorkspaceEpoch: source.WorkspaceEpoch, NativeSessionID: source.NativeSessionID, NativeProjectID: strings.Repeat("0", 40),
		NativeLocationDigest: "sha256:" + strings.Repeat("e", 64), ScopeRevision: 1, Role: "worker", ProfileRevision: 2,
		InstructionRevision: 1, Availability: "available", LastObservedAt: now},
		Root: t.TempDir(), Instance: "default", Lifecycle: "running", LifecycleRevision: 1}); err != nil {
		t.Fatal(err)
	}
	registration := state.LocalContinuityRegistration{Manifest: model.ContinuityRegistrationV1{FormatVersion: 1,
		DesiredState: "active", ContinuityEnabled: true, ScopeRevision: 1,
		Identity: model.ContinuityIdentityV1{WorkID: "work_p2c_pass0001", ProjectID: "project_p2c_pass0001",
			SandboxID: policy.SandboxID, WorkspaceEpoch: source.WorkspaceEpoch, SandboxGeneration: 1, ExpectedRevision: 1},
		Binding: model.ContinuityBindingV1{BindingID: "binding_p2c_pass0001", BindingRevision: 1,
			RegisteredSourceID: source.RegisteredSourceID, ServiceRegistrationID: source.ServiceRegistrationID,
			NativeSessionID: source.NativeSessionID, NativeProjectID: strings.Repeat("0", 40),
			NativeLocationDigest: "sha256:" + strings.Repeat("e", 64)}},
		ObservedStatus: "verified", ServiceGeneration: 1}
	if err := store.PutContinuityRegistration(ctx, registration); err != nil {
		t.Fatal(err)
	}
	taskID := "task_p2c_pass0001"
	attempt := int64(1)
	if err := store.PutManagedTaskAuthority(ctx, state.LocalManagedTaskAuthority{ServiceRegistrationID: source.ServiceRegistrationID,
		ServiceGeneration: 1, SandboxGeneration: 1, TaskID: &taskID, TaskAttempt: &attempt, Busy: true, ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	guard := model.NativeGuardObservationV1{GuardVersion: "warpmetal.atomic-input.v1", CustomVersion: "2.0.14-wm.1", SourceRevision: "rev-084",
		PatchDigest: "sha256:" + strings.Repeat("1", 64), ArtifactSHA256: "sha256:" + strings.Repeat("d", 64),
		BinarySHA256: "sha256:" + strings.Repeat("c", 64)}
	capability := state.LocalManagerCapability{RegisteredSourceID: source.RegisteredSourceID,
		ServiceRegistrationID: source.ServiceRegistrationID, ServiceGeneration: 1, WorkspaceEpoch: source.WorkspaceEpoch,
		NativeSessionID: source.NativeSessionID, SandboxID: policy.SandboxID, SandboxGeneration: 1, ProfileRevision: 2,
		InstructionRevision: 1, NativeVersion: "2.0.14-wm.1", NativeSourceRevision: "rev-084", Protocol: "opencode-supervisor/1",
		NativeProtocol: "opencode-supervisor/1", ProviderID: "deepseek", ModelID: "deepseek-flash",
		ProviderRouteDigest: "sha256:" + strings.Repeat("7", 64), RecipeIDs: []string{"inspect_first_failure@1"},
		ManagerPluginDigest: "sha256:" + strings.Repeat("9", 64),
		ManagerProfile: model.InsightsManagerProfileV1{ProfileID: "warpmetal-insights-manager", ProfileRevision: 1,
			ProfileDigest: "sha256:" + strings.Repeat("b", 64)},
		NativeGuard: &guard, MaxInputTokens: 16000, MaxOutputTokens: 2000, FinalRequestMaxBytes: 65536,
		ToolsAllowed: true, Available: true}
	if err := store.PutManagerCapability(ctx, capability); err != nil {
		t.Fatal(err)
	}
}

// seedPassOutbox writes one canonical valid ready batch/cursor/body digest for
// the acknowledged-batch pending-ACK path (R1 only).
func seedPassOutbox(t *testing.T, store *state.Store, policy model.InsightsManagerPolicyManifestV1, source model.InsightsManagerSourceV1, now time.Time) model.InsightFindingV1 {
	t.Helper()
	finding := model.InsightFindingV1{FindingID: "finding_p2c_pass0001", RuleID: passRuleID, State: "open", Revision: 1,
		FirstSequence: 1, LastSequence: 4, Count: 4, Threshold: 4,
		MatchedCallIDs:  []string{"call_p2c_0001", "call_p2c_0002", "call_p2c_0003", "call_p2c_0004"},
		FirstObservedAt: now.Add(-time.Minute), LastObservedAt: now, Coverage: "complete", ToolCategory: "shell", Phase: "tool"}
	batch := model.InsightBatchV1{FormatVersion: 1, BatchID: "batch_p2c_pass0001", SandboxID: policy.SandboxID,
		SandboxGeneration: 1, PolicyRevision: policy.PolicyRevision, RegisteredSourceID: source.RegisteredSourceID,
		ServiceRegistrationID: source.ServiceRegistrationID, ServiceGeneration: 1, WorkspaceEpoch: source.WorkspaceEpoch,
		NativeSessionID: source.NativeSessionID, JournalGeneration: "journal_p2c_pass0001", ThroughSequence: 4,
		ObservedAt: now, Status: "ready", Findings: []model.InsightFindingV1{finding}}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	projection := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("ready\x00")))
	cursor := state.InsightCursor{RegisteredSourceID: source.RegisteredSourceID, PolicyRevision: policy.PolicyRevision,
		WorkspaceEpoch: source.WorkspaceEpoch, JournalGeneration: "journal_p2c_pass0001", ChangeSequence: 1,
		ThroughSequence: 4, Status: "ready", ProjectionDigest: projection}
	if err := store.PutInsightOutbox(context.Background(), state.InsightOutboxItem{Batch: batch, BodyDigest: digest, NextCursor: cursor}); err != nil {
		t.Fatal(err)
	}
	return finding
}

func (h *passHelper) actionCount(action string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	count := 0
	for _, value := range h.calls {
		if value == action {
			count++
		}
	}
	return count
}

func (h *passHelper) actionOrder() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

// seedPendingAdmission writes a valid acknowledged anchor that a previous pass
// deferred, so the next actual daemon pass must own its admission.
func seedPendingAdmission(t *testing.T, h *passHarness, target model.InsightsManagerTargetV1) {
	t.Helper()
	finding := model.InsightFindingV1{FindingID: "finding_p2c_pass0001", RuleID: passRuleID, State: "open", Revision: 1,
		FirstSequence: 1, LastSequence: 4, Count: 4, Threshold: 4,
		MatchedCallIDs:  []string{"call_p2c_0001", "call_p2c_0002", "call_p2c_0003", "call_p2c_0004"},
		FirstObservedAt: h.clock.Now().Add(-time.Minute), LastObservedAt: h.clock.Now(), Coverage: "complete",
		ToolCategory: "shell", Phase: "tool"}
	anchor := &state.LocalManagerAdmission{State: "pending", ObservedAt: h.clock.Now().Add(-time.Minute),
		EvaluatedAt: h.clock.Now().Add(-time.Minute), BatchID: "batch_prior0001",
		SandboxID: h.control.policy.SandboxID, Mode: "auto_steer", PolicyRevision: 1, RunGeneration: 1,
		RuleID: passRuleID, Target: &target}
	if err := h.store.PutManagerFinding(context.Background(), state.LocalManagerFinding{Finding: finding,
		Source: passSource(), PolicyRevision: 1, JournalGeneration: "journal_p2c_pass0001",
		Acknowledged: true, Admission: anchor}); err != nil {
		t.Fatal(err)
	}
}

type passHarness struct {
	store       *state.Store
	clock       *passClock
	control     *passControl
	monitor     *passMonitor
	works       *passWorkspaces
	helper      *passHelper
	loop        runtimeFeedbackLoop
	finding     model.InsightFindingV1
	target      model.InsightsManagerTargetV1
	coordinator *manager.Coordinator
	transport   *passTransport
}

func newPassHarness(t *testing.T, seededOutbox bool, requireFreshSource bool) *passHarness {
	t.Helper()
	fixture := loadPassFixture(t)
	clock := &passClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	policy := passAutoSteerPolicy(t, fixture, clock)
	source := passSource()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	seedPassStore(t, store, policy, source, clock.Now())
	finding := model.InsightFindingV1{}
	if seededOutbox {
		finding = seedPassOutbox(t, store, policy, source, clock.Now())
	}
	target := model.InsightsManagerTargetV1{TeamID: "team_p2c_pass0001", MemberID: "tmem_p2c_pass0001",
		WorkID: stringPointer("work_p2c_pass0001"), WorkRevision: intPointer(1),
		BindingID: stringPointer("binding_p2c_pass0001"), BindingRevision: intPointer(1),
		TaskID: stringPointer("task_p2c_pass0001"), TaskAttempt: intPointer(1)}
	pc := &passControl{policy: policy, source: source, target: target, clock: clock,
		requireFreshSourceForPolicy: requireFreshSource}
	server := pc.server(t)
	transport := &passTransport{base: server.Client().Transport}
	client := control.Client{Origin: server.URL, NodeToken: "rtn_p2c_pass0001", HTTP: &http.Client{Transport: transport}}
	monitor := &passMonitor{clock: clock, source: source, fresh: !seededOutbox}
	works := &passWorkspaces{root: t.TempDir(), clock: clock}
	helper := &passHelper{source: source, sandboxID: policy.SandboxID, backend: pc}
	coordinator := &manager.Coordinator{Store: store, Control: client, Helper: helper, Now: clock.Now}
	collector := &insights.Collector{Store: store, Control: client, Monitor: monitor, Lifecycle: passLifecycle{},
		Manager: coordinator, Now: clock.Now}
	reconciler := &reconcile.Reconciler{Store: store, Engine: passEngine{}, Workspaces: works,
		Access: access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")}, ServerID: passServerID,
		HostCapacity: model.Resources{CPUMillicores: 8000, MemoryMiB: 16384, WorkspaceDiskGiB: 100, PIDs: 4096},
		Manager:      coordinator, Insights: collector, ContinuityControl: passContinuity{store: store}, Now: clock.Now}
	return &passHarness{store: store, clock: clock, control: pc, monitor: monitor, works: works, helper: helper, coordinator: coordinator,
		loop: runtimeFeedbackLoop{reconciler: reconciler, client: client, serverID: passServerID, version: "test",
			controlPlaneTimeout: 5 * time.Second, reconcileTimeout: 5 * time.Second,
			feedbackWait: func(context.Context, time.Duration) bool { return true }}, finding: finding, target: target, transport: transport}
}

// TestRuntimePassSameCycleAdmission is the composed control-loop regression.
func TestRuntimePassSameCycleAdmission(t *testing.T) {
	t.Run("R1 R3 same-cycle reservation after ACKed pending batch with exact task identity and fresh lease", func(t *testing.T) {
		h := newPassHarness(t, true, false)
		h.loop.pass(context.Background())
		findings, err := h.store.ManagerFindings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if h.control.lastError != "" {
			t.Fatalf("pass reported a setup/validation error: %s", h.control.lastError)
		}
		if len(findings) != 1 || !findings[0].Acknowledged || findings[0].Finding.State != "open" || findings[0].Admission == nil {
			t.Fatalf("anchor missing/malformed after ACKed batch: %+v events=%v", findings, h.control.events)
		}
		admission := findings[0].Admission
		if admission.State != "pending" && admission.State != "deferred" && admission.State != "admitted" {
			t.Fatalf("anchor state = %s/%s, want pending/deferred/admitted (declined/missing identity is a fixture failure)", admission.State, admission.Reason)
		}
		if admission.Target == nil || !reflect.DeepEqual(*admission.Target, h.target) {
			t.Fatalf("anchor target = %+v, want exact active task %+v", admission.Target, h.target)
		}
		reservations, err := h.store.ManagerReservations(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(reservations) != 1 || findings[0].Admission.State != "admitted" {
			t.Fatalf("same-cycle durable reservation count = %d admission=%s/%s, want 1 admitted; ACKed exact-target anchor target=%+v waits a full next pass (events=%v)",
				len(reservations), findings[0].Admission.State, findings[0].Admission.Reason, *admission.Target, h.control.events)
		}
		request := reservations[0].Request
		if !reflect.DeepEqual(request.Target, h.target) {
			t.Fatalf("reservation target = %+v, want exact %+v", request.Target, h.target)
		}
		if request.ExpiresInSeconds < 100 || request.ExpiresInSeconds > 120 {
			t.Fatalf("reservation lease seconds = %d, want a fresh 100..120 after heavy work", request.ExpiresInSeconds)
		}
		if h.control.lastManifestAt.Before(h.works.heavyAt) {
			t.Fatalf("manifest lease issued at %s before heavy work at %s; lease must be fresh after the heavy lifecycle",
				h.control.lastManifestAt, h.works.heavyAt)
		}
		if h.control.reservationAt.Sub(h.control.lastManifestAt) > 20*time.Second {
			t.Fatalf("reservation at %s is %s after lease issuance %s; lease was already stale",
				h.control.reservationAt, h.control.reservationAt.Sub(h.control.lastManifestAt), h.control.lastManifestAt)
		}
	})

	t.Run("R2 stale prior backend source collects and admits in the same pass after the Report ACK", func(t *testing.T) {
		h := newPassHarness(t, false, true)
		if !h.control.publishedSourceAt.IsZero() {
			t.Fatal("fixture precondition: backend must start with no fresh published source")
		}
		h.loop.pass(context.Background())
		if h.control.lastError != "" {
			t.Fatalf("pass reported a setup/validation error: %s", h.control.lastError)
		}
		if h.control.publishedSourceAt.IsZero() {
			t.Fatalf("fixture positive control: the actual pass Report did not publish the seeded source")
		}
		if !h.control.collectBoundary.IsZero() && h.control.collectBoundary.Sub(h.control.publishedSourceAt) > 120*time.Second {
			t.Fatalf("collection boundary %s is not fresh against the actual published observation %s", h.control.collectBoundary, h.control.publishedSourceAt)
		}
		findings, err := h.store.ManagerFindings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 1 || !findings[0].Acknowledged || findings[0].Admission == nil {
			t.Fatalf("finding = %+v, want the real monitor path collected, ACKed and anchored in the same pass (events=%v monitorCalls=%d)",
				findings, h.control.events, h.monitor.calls)
		}
		reservations, err := h.store.ManagerReservations(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(reservations) != 1 {
			t.Fatalf("stale-source reservation count = %d, want 1 same pass (events=%v)", len(reservations), h.control.events)
		}
		if !reflect.DeepEqual(reservations[0].Request.Target, h.target) {
			t.Fatalf("reservation target = %+v, want exact %+v", reservations[0].Request.Target, h.target)
		}
		if reservations[0].Request.ExpiresInSeconds < 100 || reservations[0].Request.ExpiresInSeconds > 120 {
			t.Fatalf("reservation lease seconds = %d, want a fresh 100..120 after heavy work", reservations[0].Request.ExpiresInSeconds)
		}
	})

	t.Run("fixture positive control direct coordinator (NOT the daemon regression)", func(t *testing.T) {
		h := newPassHarness(t, true, false)
		ctx := context.Background()
		if err := h.coordinator.ApplyPolicies(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{h.control.policy}}); err != nil {
			t.Fatalf("fixture cannot apply the auto_steer policy: %v", err)
		}
		pending, err := h.store.InsightOutbox(ctx)
		if err != nil || len(pending) != 1 {
			t.Fatalf("fixture outbox missing: %v", err)
		}
		item := pending[0]
		receipt := model.InsightBatchReceiptV1{BatchID: item.Batch.BatchID, Accepted: len(item.Batch.Findings), ThroughSequence: item.Batch.ThroughSequence}
		if err := h.coordinator.ObserveAcknowledgedInsightBatch(ctx, item.Batch, receipt); err != nil {
			t.Fatalf("fixture observe failed: %v", err)
		}
		if err := h.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{h.control.policy}}); err != nil {
			t.Fatalf("fixture direct admitted path failed: %v", err)
		}
		reservations, err := h.store.ManagerReservations(ctx)
		if err != nil || len(reservations) != 1 {
			t.Fatalf("fixture cannot produce a durable reservation through the direct coordinator path: %v", err)
		}
		findings, err := h.store.ManagerFindings(ctx)
		if err != nil || len(findings) != 1 || findings[0].Admission == nil || findings[0].Admission.State != "admitted" {
			t.Fatalf("fixture direct admitted path did not admit: %+v", findings)
		}
	})

	t.Run("D1 same-pass reviewing to terminal recommendation to first actual guidance", func(t *testing.T) {
		h := newPassHarness(t, true, false)
		h.loop.pass(context.Background())
		order := h.helper.actionOrder()
		has := func(action string) bool { return h.helper.actionCount(action) == 1 }
		if !has("start_review") || !has("continue_review") || !has("dispatch_guidance") {
			t.Fatalf("helper actions = %v, want one start_review, one continue_review and one dispatch_guidance in the same pass (current admission gap prevents the run from starting)", order)
		}
		reservations, err := h.store.ManagerReservations(context.Background())
		if err != nil || len(reservations) != 1 {
			t.Fatalf("reservations = %v, want exactly one", err)
		}
		runs, err := h.store.ManagerRuns(context.Background())
		if err != nil || len(runs) != 1 {
			t.Fatalf("runs = %v, want exactly one", err)
		}
		run := runs[0]
		if reservations[0].Reservation == nil || run.Manifest.RunID != reservations[0].Reservation.RunID || run.Manifest.ReservationID != reservations[0].Request.ReservationID {
			t.Fatalf("run identity changed: run.RunID=%s reservation.RunID=%v request.ReservationID=%s", run.Manifest.RunID, reservations[0].Reservation, reservations[0].Request.ReservationID)
		}
		if !run.GuidanceAttempted || run.Guidance == nil {
			t.Fatalf("guidance attempted=%v guidance=%v, want the first actual guidance attempt durably recorded", run.GuidanceAttempted, run.Guidance)
		}
		if !run.OriginValidUntil.Equal(reservations[0].Reservation.ExpiresAt) || !h.helper.originValidUntil.Equal(run.OriginValidUntil) {
			t.Fatalf("origin expiry changed: run.OriginValidUntil=%s reservation=%s dispatch authority=%s", run.OriginValidUntil, reservations[0].Reservation.ExpiresAt, h.helper.originValidUntil)
		}
		if h.helper.guidanceValidUntil.IsZero() || !h.helper.guidanceValidUntil.Equal(run.OriginValidUntil) {
			t.Fatalf("guidance dispatch request validUntil=%s, want the original %s", h.helper.guidanceValidUntil, run.OriginValidUntil)
		}
		if h.control.manifestReads < 2 {
			t.Fatalf("manifest reads = %d, want more than one fresh read in the bounded feedback window", h.control.manifestReads)
		}
		if h.works.count != 1 {
			t.Fatalf("heavy boundary count = %d, want exactly one heavy pass", h.works.count)
		}
	})

	t.Run("D2 owner Off at review completion refuses first guidance after a fresh Manifest", func(t *testing.T) {
		h := newPassHarness(t, true, false)
		h.control.flipOffAtContinue = true
		h.loop.pass(context.Background())
		if h.helper.actionCount("continue_review") != 1 {
			t.Fatalf("continue_review did not occur (actions=%v); the fresh-manifest refusal cannot be proven without the actual scheduling path", h.helper.actionOrder())
		}
		if h.control.snapshotManifestReads() <= h.helper.manifestReadsAtDone {
			t.Fatalf("no Manifest was fetched after review completion (reads=%d atCompletion=%d); Off must be observed before first dispatch",
				h.control.snapshotManifestReads(), h.helper.manifestReadsAtDone)
		}
		if h.helper.actionCount("dispatch_guidance") != 0 {
			t.Fatalf("guidance POST occurred under an Off policy: actions=%v", h.helper.actionOrder())
		}
		runs, err := h.store.ManagerRuns(context.Background())
		if err != nil || len(runs) != 1 || runs[0].GuidanceAttempted || runs[0].Guidance != nil {
			t.Fatalf("Off during review did not refuse first guidance: %v %+v", err, runs)
		}
	})

	t.Run("fixture positive control downstream direct coordinator (NOT the daemon regression)", func(t *testing.T) {
		h := newPassHarness(t, true, false)
		ctx := context.Background()
		policy := h.control.policy
		manifest := model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}
		if err := h.coordinator.ApplyPolicies(ctx, manifest); err != nil {
			t.Fatalf("fixture apply policy: %v", err)
		}
		pending, err := h.store.InsightOutbox(ctx)
		if err != nil || len(pending) != 1 {
			t.Fatalf("fixture outbox: %v", err)
		}
		item := pending[0]
		receipt := model.InsightBatchReceiptV1{BatchID: item.Batch.BatchID, Accepted: len(item.Batch.Findings), ThroughSequence: item.Batch.ThroughSequence}
		if err := h.coordinator.ObserveAcknowledgedInsightBatch(ctx, item.Batch, receipt); err != nil {
			t.Fatalf("fixture observe: %v", err)
		}
		if err := h.coordinator.Apply(ctx, manifest); err != nil {
			t.Fatalf("fixture admit/start: %v", err)
		}
		if err := h.coordinator.AdvanceAutomaticRuns(ctx); err != nil {
			t.Fatalf("fixture continue/terminalize: %v", err)
		}
		if h.helper.actionCount("continue_review") != 1 {
			t.Fatalf("fixture did not terminalize the reviewing run: actions=%v", h.helper.actionOrder())
		}
		fresh := policy
		fresh.ValidUntil = h.clock.Now().Add(120 * time.Second)
		if err := h.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{fresh}}); err != nil {
			t.Fatalf("fixture guidance apply: %v", err)
		}
		runs, err := h.store.ManagerRuns(ctx)
		if err != nil || len(runs) != 1 || !runs[0].GuidanceAttempted || runs[0].Guidance == nil {
			t.Fatalf("fixture positive control did not dispatch guidance: %v %+v", err, runs)
		}
		if h.helper.actionCount("dispatch_guidance") != 1 {
			t.Fatalf("fixture guidance transport calls = %d, want 1", h.helper.actionCount("dispatch_guidance"))
		}
	})

	t.Run("owner Off during review refuses first guidance dispatch", func(t *testing.T) {
		h := newPassHarness(t, true, false)
		ctx := context.Background()
		policy := h.control.policy
		manifest := model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{policy}}
		if err := h.coordinator.ApplyPolicies(ctx, manifest); err != nil {
			t.Fatalf("fixture apply policy: %v", err)
		}
		pending, err := h.store.InsightOutbox(ctx)
		if err != nil || len(pending) != 1 {
			t.Fatalf("fixture outbox: %v", err)
		}
		item := pending[0]
		receipt := model.InsightBatchReceiptV1{BatchID: item.Batch.BatchID, Accepted: len(item.Batch.Findings), ThroughSequence: item.Batch.ThroughSequence}
		if err := h.coordinator.ObserveAcknowledgedInsightBatch(ctx, item.Batch, receipt); err != nil {
			t.Fatalf("fixture observe: %v", err)
		}
		if err := h.coordinator.Apply(ctx, manifest); err != nil {
			t.Fatalf("fixture admit/start: %v", err)
		}
		if err := h.coordinator.AdvanceAutomaticRuns(ctx); err != nil {
			t.Fatalf("fixture continue/terminalize: %v", err)
		}
		if h.helper.actionCount("continue_review") != 1 {
			t.Fatalf("fixture did not terminalize before the refusal control: actions=%v", h.helper.actionOrder())
		}
		off := policy
		off.Mode = "off"
		off.AllowedRules = nil
		off.AutoSteerPolicy = nil
		off.AutoSteerAvailable = false
		off.ValidUntil = h.clock.Now().Add(120 * time.Second)
		if err := h.coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{off}}); err != nil {
			t.Fatalf("fixture off apply: %v", err)
		}
		runs, err := h.store.ManagerRuns(ctx)
		if err != nil || len(runs) != 1 {
			t.Fatalf("fixture run missing: %v", err)
		}
		if h.helper.actionCount("dispatch_guidance") != 0 || runs[0].GuidanceAttempted || runs[0].Guidance != nil {
			t.Fatalf("Off during review dispatched guidance: calls=%d attempted=%v guidance=%v", h.helper.actionCount("dispatch_guidance"), runs[0].GuidanceAttempted, runs[0].Guidance)
		}
	})

	t.Run("R3 deferred acknowledged anchor reserves only on a fresh post-heavy lease", func(t *testing.T) {
		h := newPassHarness(t, true, false)
		seedPendingAdmission(t, h, h.target)
		h.loop.pass(context.Background())
		if h.control.lastError != "" {
			t.Fatalf("pass reported a setup/validation error: %s", h.control.lastError)
		}
		reservations, err := h.store.ManagerReservations(context.Background())
		if err != nil || len(reservations) != 1 || reservations[0].Reservation == nil {
			t.Fatalf("deferred acknowledged anchor reservation = %v (err=%v), want exactly one admitted automatic reservation", reservations, err)
		}
		request := reservations[0].Request
		if request.ExpiresInSeconds < 100 || request.ExpiresInSeconds > 120 {
			t.Fatalf("reservation lease = %ds from the pre-heavy manifest (manifest read %s, heavy work %s); automatic admission must be owned by the post-Report-ACK fresh phase",
				request.ExpiresInSeconds, h.control.lastManifestAt, h.works.heavyAt)
		}
		if h.control.lastManifestAt.Before(h.works.heavyAt) {
			t.Fatalf("manifest lease fetched at %s before heavy work %s; the reservation used a stale pre-heavy lease",
				h.control.lastManifestAt, h.works.heavyAt)
		}
		seenReport, manifestAfterReport := false, false
		for _, event := range h.control.eventsUpTo(h.control.reservationEventIndex) {
			if event == "report" {
				seenReport = true
			}
			if event == "manifest" && seenReport {
				manifestAfterReport = true
			}
		}
		if !manifestAfterReport {
			t.Fatalf("causal order violated before the reservation: events=%v, want a successful report followed by a fresh manifest",
				h.control.eventsUpTo(h.control.reservationEventIndex))
		}
		if reservations[0].Reservation.ExpiresAt.Sub(h.works.heavyAt) < 100*time.Second {
			t.Fatalf("reservation expires at %s, only %s after heavy work; want a fresh post-heavy lease",
				reservations[0].Reservation.ExpiresAt, reservations[0].Reservation.ExpiresAt.Sub(h.works.heavyAt))
		}
	})

	t.Run("F1 review start outlives the control-plane timeout inside the run, action and tail bounds", func(t *testing.T) {
		h := newPassHarness(t, true, false)
		h.loop.controlPlaneTimeout = 50 * time.Millisecond
		h.loop.reconcileTimeout = 5 * time.Second
		h.helper.startDelay = 200 * time.Millisecond
		h.loop.pass(context.Background())
		if h.helper.startCanceled {
			t.Fatalf("start_review was clipped by the control-plane timeout; the review start must use a distinct action context bounded by the original run, the action ceiling and the feedback window (actions=%v events=%v)",
				h.helper.actionOrder(), h.control.events)
		}
		reservations, err := h.store.ManagerReservations(context.Background())
		if err != nil || len(reservations) != 1 || reservations[0].Reservation == nil {
			t.Fatalf("admitted run missing: reservations=%v err=%v actions=%v", reservations, err, h.helper.actionOrder())
		}
		runs, err := h.store.ManagerRuns(context.Background())
		if err != nil || len(runs) != 1 {
			t.Fatalf("runs=%v err=%v actions=%v", runs, err, h.helper.actionOrder())
		}
		run := runs[0]
		if !run.OriginValidUntil.Equal(reservations[0].Reservation.ExpiresAt) {
			t.Fatalf("origin bound changed: run=%s reservation=%s", run.OriginValidUntil, reservations[0].Reservation.ExpiresAt)
		}
		if h.helper.actionCount("continue_review") != 1 || h.helper.actionCount("dispatch_guidance") != 1 || !run.GuidanceAttempted || run.Guidance == nil {
			t.Fatalf("one pass did not continue and first-dispatch the original run: actions=%v attempted=%v guidance=%v",
				h.helper.actionOrder(), run.GuidanceAttempted, run.Guidance)
		}
	})

	t.Run("F2 post-ACK action contexts are capped by the original run expiry, not only the tail deadline", func(t *testing.T) {
		h := newPassHarness(t, true, false)
		h.loop.reconcileTimeout = 10 * time.Minute
		h.works.heavyAdvance = 5 * time.Second
		h.control.policyWindow = 30 * time.Second
		h.loop.pass(context.Background())
		reservations, err := h.store.ManagerReservations(context.Background())
		if err != nil || len(reservations) != 1 || reservations[0].Reservation == nil {
			t.Fatalf("admitted run missing: reservations=%v err=%v actions=%v", reservations, err, h.helper.actionOrder())
		}
		runs, err := h.store.ManagerRuns(context.Background())
		if err != nil || len(runs) != 1 {
			t.Fatalf("runs=%v err=%v actions=%v", runs, err, h.helper.actionOrder())
		}
		run := runs[0]
		if h.helper.dispatchAt.IsZero() || h.helper.dispatchDeadline.IsZero() {
			t.Fatalf("fixture: no first-guidance dispatch observed under a valid run origin: actions=%v", h.helper.actionOrder())
		}
		budget := h.helper.dispatchDeadline.Sub(h.helper.dispatchAt)
		originRemaining := run.OriginValidUntil.Sub(h.clock.Now())
		if budget > originRemaining+time.Second {
			t.Fatalf("guidance dispatch context budget %s exceeds the original run expiry remaining %s (context deadline %s, run origin %s, clock %s); every post-ACK action context must be capped by min(feedback deadline, run.OriginValidUntil, action ceiling)",
				budget, originRemaining, h.helper.dispatchDeadline, run.OriginValidUntil, h.clock.Now())
		}
	})

	t.Run("F2 whole post-ACK phase shares one parent deadline and cancellation stops the wait while the final Report stays outside", func(t *testing.T) {
		h := newPassHarness(t, false, true)
		h.loop.controlPlaneTimeout = 2 * time.Second
		h.loop.reconcileTimeout = 2 * time.Second
		h.loop.feedbackWindowOverride = 500 * time.Millisecond
		h.loop.feedbackCadenceOverride = 5 * time.Second
		var waitBudget time.Duration
		var waitReturned bool
		waits := 0
		h.loop.feedbackWait = func(ctx context.Context, d time.Duration) bool {
			waits++
			waitBudget = d
			deadline, ok := ctx.Deadline()
			if !ok {
				// An unbounded wait would be the defect; let the caller proceed
				// so the deadline/cancellation assertions below can fail.
				time.Sleep(minPassDuration(d, 800*time.Millisecond))
				waitReturned = true
				return true
			}
			<-time.After(time.Until(deadline) + 50*time.Millisecond)
			waitReturned = ctx.Err() == nil
			return waitReturned
		}
		h.loop.pass(context.Background())
		if h.helper.actionCount("start_review") != 1 || h.helper.actionCount("continue_review") != 1 {
			t.Fatalf("fixture: the run did not start and continue through the actual daemon: actions=%v", h.helper.actionOrder())
		}
		if h.monitor.deadline.IsZero() || h.helper.startDeadline.IsZero() || h.helper.continueDeadline.IsZero() {
			t.Fatalf("fixture: missing controlled context deadlines monitor=%s start=%s continue=%s",
				h.monitor.deadline, h.helper.startDeadline, h.helper.continueDeadline)
		}
		manifests := h.transport.deadlinesFor("/internal/runtime/manifest")
		if len(manifests) < 3 {
			t.Fatalf("fixture: need the heavy plus several post-ACK fresh Manifest requests, got %d (events=%v)", len(manifests), h.control.eventsUpTo(len(h.control.events)))
		}
		shared := manifests[1]
		if shared.IsZero() {
			t.Fatal("fixture: the first post-ACK fresh fetch carried no context deadline")
		}
		for index, deadline := range manifests[1:] {
			if !deadline.Equal(shared) {
				t.Fatalf("post-ACK Manifest fetch %d context deadline %s != shared parent deadline %s; the parent created before the first fresh fetch must cover every fetch, collector, admission and round",
					index+1, deadline, shared)
			}
		}
		for _, observed := range []struct {
			name     string
			deadline time.Time
		}{
			{"first post-ACK fetch", shared},
			{"collector", h.monitor.deadline},
			{"admission start", h.helper.startDeadline},
			{"round continuation", h.helper.continueDeadline},
		} {
			if !observed.deadline.Equal(shared) {
				t.Fatalf("%s context deadline %s != shared post-ACK parent deadline %s; one parent created before the first fresh fetch must cover the fetch, collector, admission and rounds (actions=%v waits=%d)",
					observed.name, observed.deadline, shared, h.helper.actionOrder(), waits)
			}
		}
		if waits == 0 {
			t.Fatal("fixture: the bounded tail never waited; the cancellation assertion cannot be proven")
		}
		if waitReturned || waitBudget > 800*time.Millisecond {
			t.Fatalf("wait returned=%v after budget %s; cancellation must stop the wait and the wait must be clamped to the remaining parent deadline (window=%s)",
				waitReturned, waitBudget, h.loop.window())
		}
		if !h.control.snapshotLastReportLive() {
			t.Fatal("final Report used a canceled feedback context; it must run outside the feedback parent")
		}
	})

	for _, arm := range []struct {
		name  string
		setup func(h *passHarness)
	}{
		{"F3 owner Off applied after start_review refuses the reserved continuation and first guidance", func(h *passHarness) {
			h.control.flipOffAtStart = true
		}},
		{"F3 original-run expiry after start_review stops continuation even when a fresh Manifest renews the policy", func(h *passHarness) {
			h.loop.reconcileTimeout = 10 * time.Minute
			h.works.heavyAdvance = 5 * time.Second
			h.control.policyWindow = 30 * time.Second
			h.control.advanceAtStart = 40 * time.Second
		}},
	} {
		t.Run(arm.name, func(t *testing.T) {
			h := newPassHarness(t, true, false)
			arm.setup(h)
			runCtx, cancelRun := context.WithCancel(context.Background())
			defer cancelRun()
			waits := 0
			h.loop.feedbackWait = func(context.Context, time.Duration) bool {
				waits++
				if waits == 1 {
					cancelRun()
				}
				return true
			}
			h.loop.pass(runCtx)
			reservations, err := h.store.ManagerReservations(context.Background())
			if err != nil || len(reservations) != 1 || reservations[0].Reservation == nil {
				t.Fatalf("admitted run missing: reservations=%v err=%v actions=%v", reservations, err, h.helper.actionOrder())
			}
			runs, err := h.store.ManagerRuns(context.Background())
			if err != nil || len(runs) != 1 || runs[0].Manifest.RunID != reservations[0].Reservation.RunID {
				t.Fatalf("run identity mismatch: runs=%v err=%v reservation=%v actions=%v", runs, err, reservations[0].Reservation, h.helper.actionOrder())
			}
			run := runs[0]
			if h.helper.actionCount("start_review") != 1 || h.helper.phaseManifestReads == 0 {
				t.Fatalf("fixture: the run did not reach reviewing through the original admission: actions=%v", h.helper.actionOrder())
			}
			if h.control.snapshotManifestReads() <= h.helper.phaseManifestReads {
				t.Fatalf("no fresh Manifest was consumed after start_review (reads=%d atStart=%d); the refusal must observe current authority",
					h.control.snapshotManifestReads(), h.helper.phaseManifestReads)
			}
			if h.helper.actionCount("continue_review") != 0 {
				t.Fatalf("continue_review was issued after the owner revoked the run (%d calls); the reserved second model request must not be spent: actions=%v",
					h.helper.actionCount("continue_review"), h.helper.actionOrder())
			}
			if h.helper.actionCount("dispatch_guidance") != 0 || run.GuidanceAttempted || run.Guidance != nil {
				t.Fatalf("first guidance was dispatched after the owner revoked the run: dispatch=%d attempted=%v guidance=%v actions=%v",
					h.helper.actionCount("dispatch_guidance"), run.GuidanceAttempted, run.Guidance, h.helper.actionOrder())
			}
			if waits != 0 {
				t.Fatalf("the feedback tail did not stop after revocation: wait called %d times; AutomaticWorkPending must be false for Off/expired/unqualified states",
					waits)
			}
		})
	}

	t.Run("F3 terminal recommendation with expired origin adds no feedback wait and no dispatch", func(t *testing.T) {
		h := newPassHarness(t, true, false)
		h.loop.feedbackWindowOverride = 1500 * time.Millisecond
		h.loop.feedbackWait = func(ctx context.Context, _ time.Duration) bool {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(time.Second):
				return false
			}
		}
		h.loop.pass(context.Background())
		runs, err := h.store.ManagerRuns(context.Background())
		if err != nil || len(runs) != 1 || runs[0].Phase != "recommended" || runs[0].GuidanceAttempted || runs[0].Guidance != nil {
			t.Fatalf("fixture: pass one must leave a terminal recommended unattempted run: %v %+v", err, runs)
		}
		if h.helper.actionCount("dispatch_guidance") != 0 {
			t.Fatalf("fixture: pass one already dispatched guidance: %v", h.helper.actionOrder())
		}
		expired := runs[0]
		expired.OriginValidUntil = h.clock.Now().Add(-time.Second)
		if err := h.store.PutManagerRun(context.Background(), expired); err != nil {
			t.Fatal(err)
		}
		h.control.mu.Lock()
		h.control.policy.PolicyRevision++
		h.control.mu.Unlock()
		h.loop.reconciler.Insights = nil
		passTwo, cancelTwo := context.WithCancel(context.Background())
		defer cancelTwo()
		waits := 0
		h.loop.feedbackWait = func(context.Context, time.Duration) bool {
			waits++
			if waits == 1 {
				cancelTwo()
			}
			return true
		}
		h.loop.pass(passTwo)
		if h.helper.actionCount("dispatch_guidance") != 0 {
			t.Fatalf("guidance dispatched for an expired-origin terminal run: %v", h.helper.actionOrder())
		}
		if waits != 0 {
			t.Fatalf("expired-origin terminal run added %d feedback waits; the shared original-expiry eligibility gate must run before the phase branch (DispatchReadyGuidance already skips it)", waits)
		}
	})
}
