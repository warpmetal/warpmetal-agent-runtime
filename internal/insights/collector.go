package insights

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type Control interface {
	InsightPolicies(context.Context) (model.InsightPolicyEnvelopeV1, error)
	SubmitInsightBatch(context.Context, model.InsightBatchV1) (model.InsightBatchReceiptV1, error)
}

type Monitor interface {
	ExecMonitor(context.Context, string, []byte) ([]byte, []byte, error)
}

type Lifecycle interface {
	ApplyInsightMonitorPolicy(context.Context, model.InsightPolicyV1) error
}

type ManagerObserver interface {
	ObserveAcknowledgedInsightBatch(context.Context, model.InsightBatchV1, model.InsightBatchReceiptV1) error
}

type Collector struct {
	Store     *state.Store
	Control   Control
	Monitor   Monitor
	Lifecycle Lifecycle
	Manager   ManagerObserver
	Now       func() time.Time
}

var insightOpaque = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var insightFindingID = regexp.MustCompile(`^finding_[A-Za-z0-9_-]{4,96}$`)

type monitorRequest struct {
	FormatVersion             int            `json:"formatVersion"`
	Action                    string         `json:"action"`
	Instance                  string         `json:"instance"`
	SourceInstanceID          string         `json:"sourceInstanceId"`
	WorkspaceEpoch            string         `json:"workspaceEpoch"`
	NativeSessionID           string         `json:"nativeSessionId"`
	ExpectedJournalGeneration *string        `json:"expectedJournalGeneration"`
	AfterChangeSequence       int64          `json:"afterChangeSequence"`
	Limit                     int            `json:"limit"`
	HealthSample              map[string]any `json:"healthSample"`
}

type monitorHealth struct {
	ClockGeneration     string `json:"clockGeneration"`
	ClockID             string `json:"clockId"`
	Enabled             bool   `json:"enabled"`
	JournalGeneration   string `json:"journalGeneration"`
	RequiresFreshWindow bool   `json:"requiresFreshWindow"`
}

type monitorIncidentChange struct {
	ChangeSequence int64                  `json:"changeSequence"`
	Finding        model.InsightFindingV1 `json:"finding"`
}

type monitorResponse struct {
	FormatVersion         int                     `json:"formatVersion"`
	Action                string                  `json:"action"`
	Status                string                  `json:"status"`
	SourceInstanceID      string                  `json:"sourceInstanceId"`
	WorkspaceEpoch        string                  `json:"workspaceEpoch"`
	NativeSessionID       string                  `json:"nativeSessionId"`
	JournalGeneration     string                  `json:"journalGeneration"`
	ThroughSequence       int64                   `json:"throughSequence"`
	Coverage              string                  `json:"coverage"`
	GapReason             *string                 `json:"gapReason"`
	FromChangeSequence    int64                   `json:"fromChangeSequence"`
	ThroughChangeSequence int64                   `json:"throughChangeSequence"`
	NextChangeSequence    int64                   `json:"nextChangeSequence"`
	IncidentChanges       []monitorIncidentChange `json:"incidentChanges"`
	Health                monitorHealth           `json:"health"`
}

func (c *Collector) RunOnce(ctx context.Context) error {
	if c.Store == nil || c.Control == nil || c.Monitor == nil || c.Lifecycle == nil {
		return errors.New("insights collector is incompletely configured")
	}
	policies, err := c.Control.InsightPolicies(ctx)
	if err != nil {
		return errors.Join(err, c.disableExpiredCachedPolicies(ctx, nil, c.now()))
	}
	now := c.now()
	if err := c.cachePolicies(ctx, policies.Policies); err != nil {
		return err
	}
	var failures []error
	skippedSources := map[string]bool{}
	pending, err := c.Store.InsightOutbox(ctx)
	if err != nil {
		return err
	}
	for _, item := range pending {
		reason, exact := pendingDisposition(item.Batch, policies.Policies, now)
		if reason != "" {
			if err := c.Store.RetireInsightOutbox(ctx, item.Batch.BatchID, reason); err != nil {
				failures = append(failures, err)
			}
			continue
		}
		if !exact {
			continue
		}
		receipt, submitErr := c.Control.SubmitInsightBatch(ctx, item.Batch)
		if submitErr == nil {
			if err := c.acknowledge(ctx, item.Batch, receipt); err != nil {
				failures = append(failures, err)
			} else {
				skippedSources[item.Batch.RegisteredSourceID] = true
			}
			continue
		}
		code := api.ErrorCode(submitErr)
		if code != "insights_policy_conflict" && code != "insights_source_conflict" {
			failures = append(failures, submitErr)
			continue
		}
		refreshed, refreshErr := c.Control.InsightPolicies(ctx)
		if refreshErr != nil {
			failures = append(failures, submitErr, refreshErr)
			continue
		}
		if err := c.cachePolicies(ctx, refreshed.Policies); err != nil {
			failures = append(failures, err)
			continue
		}
		policies = refreshed
		reason, _ = pendingDisposition(item.Batch, policies.Policies, now)
		if reason == "" {
			failures = append(failures, submitErr)
			continue
		}
		if err := c.Store.RetireInsightOutbox(ctx, item.Batch.BatchID, reason); err != nil {
			failures = append(failures, err)
		}
	}
	if err := c.disableExpiredCachedPolicies(ctx, policies.Policies, now); err != nil {
		failures = append(failures, err)
	}
	for _, policy := range policies.Policies {
		if policy.Revision < 1 || policy.SandboxID == "" {
			failures = append(failures, errors.New("insights policy is invalid"))
			continue
		}
		validUntil := policy.ExpiresAt.Sub(now)
		enabled := policy.Enabled && validUntil > 0 && validUntil <= 120*time.Second
		applied := policy
		applied.Enabled = enabled
		if err := c.Lifecycle.ApplyInsightMonitorPolicy(ctx, applied); err != nil {
			failures = append(failures, err)
			continue
		}
		if !enabled {
			for _, source := range policy.Sources {
				if skippedSources[source.RegisteredSourceID] {
					continue
				}
				if err := c.publishDisabled(ctx, policy, source, now); err != nil {
					failures = append(failures, err)
				}
			}
			continue
		}
		for _, source := range policy.Sources {
			if skippedSources[source.RegisteredSourceID] {
				continue
			}
			if err := c.collectSource(ctx, policy, source, now); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func (c *Collector) cachePolicies(ctx context.Context, policies []model.InsightPolicyV1) error {
	for _, policy := range policies {
		if err := c.Store.PutInsightPolicyLease(ctx, state.InsightPolicyLease{Policy: policy}); err != nil {
			return err
		}
	}
	return nil
}

func (c *Collector) disableExpiredCachedPolicies(ctx context.Context, fresh []model.InsightPolicyV1, now time.Time) error {
	current := make(map[string]bool, len(fresh))
	for _, policy := range fresh {
		current[policy.SandboxID] = true
	}
	leases, err := c.Store.InsightPolicyLeases(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, lease := range leases {
		if current[lease.Policy.SandboxID] || !lease.Policy.Enabled || now.Before(lease.Policy.ExpiresAt) {
			continue
		}
		disabled := lease.Policy
		disabled.Enabled = false
		if err := c.Lifecycle.ApplyInsightMonitorPolicy(ctx, disabled); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func pendingDisposition(batch model.InsightBatchV1, policies []model.InsightPolicyV1, now time.Time) (string, bool) {
	for _, policy := range policies {
		if policy.SandboxID != batch.SandboxID {
			continue
		}
		if policy.Revision != batch.PolicyRevision || !policy.ExpiresAt.After(now) || policy.ExpiresAt.Sub(now) > 120*time.Second ||
			!policy.Enabled && batch.Status != "disabled" {
			return "policy_superseded", false
		}
		for _, source := range policy.Sources {
			if source.RegisteredSourceID == batch.RegisteredSourceID && source.ServiceRegistrationID == batch.ServiceRegistrationID &&
				source.SandboxGeneration == batch.SandboxGeneration && source.ServiceGeneration == batch.ServiceGeneration &&
				source.WorkspaceEpoch == batch.WorkspaceEpoch && source.NativeSessionID == batch.NativeSessionID {
				return "", true
			}
		}
		return "source_rotated", false
	}
	return "", false
}

func (c *Collector) publishDisabled(ctx context.Context, policy model.InsightPolicyV1, ref model.InsightPolicySourceV1, now time.Time) error {
	if _, _, err := c.currentAuthority(ctx, policy, ref, now); err != nil {
		return err
	}
	cursor, err := c.Store.InsightCursor(ctx, ref.RegisteredSourceID)
	if err != nil {
		return err
	}
	if cursor != nil && cursor.PolicyRevision == policy.Revision && cursor.Status == "disabled" {
		return nil
	}
	journal := "journal_unobserved"
	var change, through int64
	if cursor != nil {
		journal = cursor.JournalGeneration
		change = cursor.ChangeSequence
		through = cursor.ThroughSequence
	}
	reason := "monitor_disabled"
	batch := model.InsightBatchV1{
		FormatVersion: 1, SandboxID: policy.SandboxID, SandboxGeneration: ref.SandboxGeneration,
		PolicyRevision: policy.Revision, RegisteredSourceID: ref.RegisteredSourceID,
		ServiceRegistrationID: ref.ServiceRegistrationID, ServiceGeneration: ref.ServiceGeneration,
		WorkspaceEpoch: ref.WorkspaceEpoch, NativeSessionID: ref.NativeSessionID,
		JournalGeneration: journal, ThroughSequence: through, ObservedAt: now.UTC(), Status: "disabled",
		GapReason: &reason, Findings: []model.InsightFindingV1{},
	}
	batch.BatchID = insightBatchID(batch, change)
	body, _ := json.Marshal(batch)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	next := state.InsightCursor{RegisteredSourceID: ref.RegisteredSourceID, PolicyRevision: policy.Revision,
		WorkspaceEpoch: ref.WorkspaceEpoch, JournalGeneration: journal, ChangeSequence: change,
		ThroughSequence: through, Status: "disabled", GapReason: reason,
		ProjectionDigest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("disabled\x00"+reason)))}
	if err := c.Store.PutInsightOutbox(ctx, state.InsightOutboxItem{Batch: batch, BodyDigest: digest, NextCursor: next}); err != nil {
		return err
	}
	receipt, err := c.Control.SubmitInsightBatch(ctx, batch)
	if err != nil {
		return err
	}
	return c.acknowledge(ctx, batch, receipt)
}

func (c *Collector) collectSource(ctx context.Context, policy model.InsightPolicyV1, ref model.InsightPolicySourceV1, now time.Time) error {
	source, _, err := c.currentAuthority(ctx, policy, ref, now)
	if err != nil {
		return err
	}
	cursor, err := c.Store.InsightCursor(ctx, ref.RegisteredSourceID)
	if err != nil {
		return err
	}
	request := monitorRequest{FormatVersion: 1, Action: "report_incident_changes", Instance: source.Instance,
		SourceInstanceID: ref.RegisteredSourceID, WorkspaceEpoch: ref.WorkspaceEpoch, NativeSessionID: ref.NativeSessionID,
		Limit: 64}
	if cursor != nil {
		request.AfterChangeSequence = cursor.ChangeSequence
		if cursor.JournalGeneration != "" {
			generation := cursor.JournalGeneration
			request.ExpectedJournalGeneration = &generation
		}
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	stdout, _, err := c.Monitor.ExecMonitor(ctx, policy.SandboxID, payload)
	if err != nil {
		return err
	}
	response, err := decodeMonitorResponse(stdout)
	if err != nil {
		return err
	}
	if response.FormatVersion != 1 || response.Action != "report_incident_changes" || response.Status != "ok" ||
		response.SourceInstanceID != ref.RegisteredSourceID || response.WorkspaceEpoch != ref.WorkspaceEpoch ||
		response.NativeSessionID != ref.NativeSessionID || !insightOpaque.MatchString(response.JournalGeneration) ||
		response.Health.JournalGeneration != response.JournalGeneration || response.FromChangeSequence != request.AfterChangeSequence ||
		response.NextChangeSequence < request.AfterChangeSequence ||
		response.ThroughChangeSequence < response.NextChangeSequence || response.ThroughSequence < 0 {
		return errors.New("monitor exporter response is invalid")
	}
	if (response.Coverage == "complete") != (response.GapReason == nil) {
		return errors.New("monitor exporter coverage is invalid")
	}
	if request.ExpectedJournalGeneration != nil && response.JournalGeneration != *request.ExpectedJournalGeneration &&
		(response.GapReason == nil || *response.GapReason != "journal_generation_changed" || len(response.IncidentChanges) != 0 || response.NextChangeSequence != response.ThroughChangeSequence) {
		return errors.New("monitor exporter changed journal without a durable generation floor")
	}
	status := "ready"
	gapReason := backendGapReason(response.GapReason)
	if gapReason != nil {
		status = "degraded"
	}
	if len(response.IncidentChanges) == 0 && cursor != nil && cursor.PolicyRevision == policy.Revision &&
		cursor.Status == status && cursor.GapReason == stringValue(gapReason) {
		return nil
	}
	findings := make([]model.InsightFindingV1, 0, len(response.IncidentChanges))
	previousChange := request.AfterChangeSequence
	for _, change := range response.IncidentChanges {
		if change.ChangeSequence <= previousChange || change.ChangeSequence > response.NextChangeSequence {
			return errors.New("monitor exporter change sequence is invalid")
		}
		previousChange = change.ChangeSequence
		if err := validateFinding(change.Finding, response.ThroughSequence); err != nil {
			return err
		}
		findings = append(findings, change.Finding)
	}
	if len(response.IncidentChanges) > 64 || len(response.IncidentChanges) != 0 && previousChange != response.NextChangeSequence {
		return errors.New("monitor exporter returned an invalid change page")
	}
	batch := model.InsightBatchV1{
		FormatVersion: 1, SandboxID: policy.SandboxID, SandboxGeneration: ref.SandboxGeneration,
		PolicyRevision: policy.Revision, RegisteredSourceID: ref.RegisteredSourceID,
		ServiceRegistrationID: ref.ServiceRegistrationID, ServiceGeneration: ref.ServiceGeneration,
		WorkspaceEpoch: ref.WorkspaceEpoch, NativeSessionID: ref.NativeSessionID,
		JournalGeneration: response.JournalGeneration, ThroughSequence: response.ThroughSequence,
		ObservedAt: now.UTC(), Status: status, GapReason: gapReason, Findings: findings,
	}
	batch.BatchID = insightBatchID(batch, response.NextChangeSequence)
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	if len(body) > 64*1024 {
		return errors.New("sanitized insight batch exceeds the allowed size")
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	projection := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(status+"\x00"+stringValue(gapReason))))
	next := state.InsightCursor{RegisteredSourceID: ref.RegisteredSourceID, PolicyRevision: policy.Revision,
		WorkspaceEpoch: ref.WorkspaceEpoch, JournalGeneration: response.JournalGeneration,
		ChangeSequence: response.NextChangeSequence, ThroughSequence: response.ThroughSequence,
		Status: status, GapReason: stringValue(gapReason), ProjectionDigest: projection}
	if err := c.Store.PutInsightOutbox(ctx, state.InsightOutboxItem{Batch: batch, BodyDigest: digest, NextCursor: next}); err != nil {
		return err
	}
	receipt, err := c.Control.SubmitInsightBatch(ctx, batch)
	if err != nil {
		return err
	}
	return c.acknowledge(ctx, batch, receipt)
}

func (c *Collector) acknowledge(ctx context.Context, batch model.InsightBatchV1, receipt model.InsightBatchReceiptV1) error {
	// Durable observation before the local ACK: a manager observation failure
	// keeps the batch replayable in the outbox instead of losing the finding.
	if c.Manager != nil {
		if err := c.Manager.ObserveAcknowledgedInsightBatch(ctx, batch, receipt); err != nil {
			return err
		}
	}
	return c.Store.AcknowledgeInsightBatch(ctx, batch.BatchID, receipt)
}

func (c *Collector) currentAuthority(ctx context.Context, policy model.InsightPolicyV1, ref model.InsightPolicySourceV1, now time.Time) (*state.LocalContinuitySource, *state.LocalSandbox, error) {
	source, err := c.Store.ContinuitySource(ctx, ref.RegisteredSourceID)
	if err != nil {
		return nil, nil, err
	}
	sandbox, err := c.Store.Sandbox(ctx, policy.SandboxID)
	if err != nil {
		return nil, nil, err
	}
	if source == nil || sandbox == nil || sandbox.ObservedState != "running" || sandbox.ObservedGeneration != ref.SandboxGeneration ||
		source.Lifecycle != "running" || source.Report.Availability != "available" || source.Report.SandboxID != policy.SandboxID ||
		source.Report.SandboxGeneration != ref.SandboxGeneration || source.Report.ServiceRegistrationID != ref.ServiceRegistrationID ||
		source.Report.ServiceGeneration != ref.ServiceGeneration || source.Report.WorkspaceEpoch != ref.WorkspaceEpoch ||
		source.Report.NativeSessionID != ref.NativeSessionID || source.Report.LastObservedAt.IsZero() ||
		now.Sub(source.Report.LastObservedAt) < -time.Second || now.Sub(source.Report.LastObservedAt) > 120*time.Second {
		return nil, nil, errors.New("insights policy does not match current host source authority")
	}
	return source, sandbox, nil
}

func decodeMonitorResponse(payload []byte) (monitorResponse, error) {
	var response monitorResponse
	if len(payload) == 0 || len(payload) > 256*1024 {
		return response, errors.New("monitor exporter response size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return response, errors.New("monitor exporter response has trailing data")
	}
	return response, nil
}

func insightBatchID(batch model.InsightBatchV1, changeSequence int64) string {
	copy := batch
	copy.BatchID = ""
	payload, _ := json.Marshal(struct {
		Batch          model.InsightBatchV1 `json:"batch"`
		ChangeSequence int64                `json:"changeSequence"`
	}{copy, changeSequence})
	digest := sha256.Sum256(payload)
	return fmt.Sprintf("batch_%x", digest[:12])
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func backendGapReason(value *string) *string {
	if value == nil {
		return nil
	}
	mapped := "monitor_gap"
	switch *value {
	case "journal_generation_changed":
		mapped = "journal_generation_changed"
	case "change_cursor_ahead":
		mapped = "cursor_ahead"
	}
	return &mapped
}

func validateFinding(value model.InsightFindingV1, through int64) error {
	recoveryPredicates := map[string]string{
		"repeated_identical_failure@1": "matching_operation_succeeded",
		"repeated_identical_call@1":    "qualified_progress_resumed",
		"empty_result_loop@1":          "nonempty_refined_query",
		"suspected_stall@1":            "qualified_progress_resumed",
	}
	predicate, ruleOK := recoveryPredicates[value.RuleID]
	states := map[string]bool{"open": true, "resolved": true}
	coverages := map[string]bool{"complete": true, "partial": true}
	tools := map[string]bool{"shell": true, "search": true, "file": true, "network": true, "other": true, "unknown": true}
	phases := map[string]bool{"unknown": true, "idle": true, "running_model": true, "running_tool": true, "running_background": true, "waiting_permission": true, "waiting_input": true, "waiting_retry": true, "compacting": true}
	if !insightFindingID.MatchString(value.FindingID) || !ruleOK || !states[value.State] ||
		value.Revision < 1 || value.FirstSequence < 1 || value.LastSequence < value.FirstSequence || value.LastSequence > through ||
		value.Count < 1 || value.Threshold < 1 || value.Count < value.Threshold || len(value.MatchedCallIDs) > 16 ||
		value.FirstObservedAt.IsZero() || value.LastObservedAt.Before(value.FirstObservedAt) ||
		!coverages[value.Coverage] || !tools[value.ToolCategory] || !phases[value.Phase] {
		return errors.New("monitor exporter finding is invalid")
	}
	seen := map[string]bool{}
	for _, id := range value.MatchedCallIDs {
		if !insightOpaque.MatchString(id) || seen[id] {
			return errors.New("monitor exporter finding references are invalid")
		}
		seen[id] = true
	}
	if value.StallThresholdMS != nil && *value.StallThresholdMS < 1 {
		return errors.New("monitor exporter stall threshold is invalid")
	}
	if value.State == "open" && value.Recovery != nil {
		return errors.New("open monitor finding carries recovery proof")
	}
	if value.State == "resolved" && (value.Recovery == nil || value.Recovery.Predicate != predicate ||
		value.Recovery.Sequence <= value.LastSequence || value.Recovery.Sequence > through || !insightOpaque.MatchString(value.Recovery.ReferenceID)) {
		return errors.New("resolved monitor finding lacks exact recovery proof")
	}
	return nil
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}
