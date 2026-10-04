package manager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type Control interface {
	ReserveInsightsManagerReview(context.Context, model.InsightsManagerReservationRequestV1) (model.InsightsManagerReservationV1, error)
	SubmitInsightsManagerRunReport(context.Context, model.InsightsManagerRunReportV1) (model.InsightsManagerActivityV1, error)
	GetInsightsManagerTarget(context.Context, string, string) (model.InsightsManagerTargetEnvelopeV1, error)
}

type Helper interface {
	ExecManager(context.Context, string, []byte) ([]byte, []byte, error)
}

type Coordinator struct {
	Store   *state.Store
	Control Control
	Helper  Helper
	Now     func() time.Time
}

type reviewHelperReceipt struct {
	FormatVersion             int                              `json:"formatVersion"`
	Action                    string                           `json:"action"`
	Status                    string                           `json:"status"`
	ReservationID             string                           `json:"reservationId"`
	RunID                     string                           `json:"runId"`
	ModelRequests             int                              `json:"modelRequests"`
	ReservedInputTokens       int64                            `json:"reservedInputTokens"`
	ReservedOutputTokens      int64                            `json:"reservedOutputTokens"`
	ManagerRegisteredSourceID string                           `json:"managerRegisteredSourceId"`
	ManagerSession            *model.InsightsManagerSessionV1  `json:"managerSession"`
	Proposal                  *model.InsightsManagerProposalV1 `json:"proposal"`
	ProposalDigest            *string                          `json:"proposalDigest"`
	GuidanceReceipt           *struct {
		FormatVersion     int     `json:"formatVersion"`
		Mode              string  `json:"mode"`
		Status            string  `json:"status"`
		AtomicNativeGuard bool    `json:"atomicNativeGuard"`
		AutoSteer         bool    `json:"autoSteer"`
		GuidanceDigest    *string `json:"guidanceDigest"`
		PendingInputID    *string `json:"pendingInputId"`
	} `json:"guidanceReceipt"`
	ReceiptDigest string  `json:"receiptDigest"`
	Error         *string `json:"error"`
}

type takeoverHelperReceipt struct {
	FormatVersion          int                                  `json:"formatVersion"`
	Action                 string                               `json:"action"`
	Status                 string                               `json:"status"`
	OperationID            string                               `json:"operationId"`
	PredecessorOperationID *string                              `json:"predecessorOperationId"`
	FindingID              string                               `json:"findingId"`
	FindingRevision        int64                                `json:"findingRevision"`
	HoldID                 string                               `json:"holdId"`
	HoldRevision           int64                                `json:"holdRevision"`
	HoldState              string                               `json:"holdState"`
	PolicyRevision         int64                                `json:"policyRevision"`
	RunGeneration          int64                                `json:"runGeneration"`
	Source                 model.InsightsManagerSourceV1        `json:"source"`
	Target                 model.InsightsManagerTargetV1        `json:"target"`
	PendingInput           model.InsightsTakeoverPendingInputV1 `json:"pendingInput"`
	ReceiptDigest          string                               `json:"receiptDigest"`
	ErrorCode              *string                              `json:"errorCode"`
	ValidUntil             time.Time                            `json:"validUntil"`
}

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var managerNativeProjectPattern = regexp.MustCompile(`^(global|[a-f0-9]{40})$`)

// ApplyPolicies validates and idempotently applies only the freshly fetched
// manager policy manifests (with their renewed validity windows and exact
// revision/run-generation/profile/source fences). Reconcile calls it after the
// sandbox/grant/setup prerequisites and before the failure-prone
// managed-service/handoff/continuity steps so a renewed policy lease is stored
// even when a later step aborts; reviews, takeovers and run execution stay
// action-bearing work applied by Apply at the end of the pass. Re-applying the
// same manifest restores the same stored manifest and re-derives the same
// report.
func (c *Coordinator) ApplyPolicies(ctx context.Context, manifest model.Manifest) error {
	if c.Store == nil || c.Control == nil || c.Helper == nil {
		return errors.New("manager coordinator is incompletely configured")
	}
	for _, policy := range manifest.InsightsManagerPolicies {
		if err := c.applyPolicy(ctx, policy); err != nil {
			return err
		}
	}
	return nil
}

func (c *Coordinator) Apply(ctx context.Context, manifest model.Manifest) error {
	if err := c.ApplyPolicies(ctx, manifest); err != nil {
		return err
	}
	for _, review := range manifest.InsightsManagerReviews {
		if err := c.applyReview(ctx, review); err != nil {
			return err
		}
	}
	for _, takeover := range manifest.InsightsTakeovers {
		if err := c.applyTakeover(ctx, takeover); err != nil {
			return err
		}
	}
	if err := c.dispatchPendingGuidance(ctx); err != nil {
		return err
	}
	return c.recoverAdmissions(ctx)
}

// RenewPendingTakeovers prepares bounded exact-operation reconciliation from the freshly fetched,
// schema-valid owner manifest. Only an already dispatched, still unknown
// protective Pause may extend its lease; every authority field and the locally
// applied Off policy stay unchanged. No helper action is dispatched here and
// no phase, receipt, predecessor, release or new operation is advanced.
func (c *Coordinator) RenewPendingTakeovers(ctx context.Context, manifest model.Manifest) error {
	if c.Store == nil || c.Control == nil || c.Helper == nil {
		return errors.New("manager coordinator is incompletely configured")
	}
	var renewals []state.LocalManagerTakeover
	for _, candidate := range manifest.InsightsTakeovers {
		if err := model.ValidateInsightsTakeoverManifest(candidate); err != nil {
			return err
		}
		prior, err := c.Store.ManagerTakeover(ctx, candidate.OperationID)
		if err != nil {
			return err
		}
		if prior == nil || prior.Phase != "acquire_unknown" || prior.Manifest.Action != "pause_manager_and_hold_member" ||
			candidate.Action != "pause_manager_and_hold_member" || reflect.DeepEqual(prior.Manifest, candidate) {
			continue
		}
		if !prior.DispatchStarted || prior.Report != nil || !sameTakeoverAuthority(prior.Manifest, candidate) ||
			!candidate.ValidUntil.After(prior.Manifest.ValidUntil) {
			return state.ErrManagerConflict
		}
		now := c.now()
		if !now.Before(candidate.ValidUntil) || candidate.ValidUntil.Sub(now) > 120*time.Second {
			return errors.New("pending protective Pause renewal requires a fresh bounded lease")
		}
		if err := c.takeoverAuthority(ctx, candidate); err != nil {
			return err
		}
		localPolicy, err := c.Store.ManagerPolicy(ctx, sourceSandbox(ctx, c.Store, candidate.Source))
		if err != nil || localPolicy == nil || localPolicy.Manifest.Mode != "off" || localPolicy.Report.Status != "applied" ||
			localPolicy.Manifest.SandboxGeneration != candidate.Source.SandboxGeneration ||
			localPolicy.Report.PolicyRevision != candidate.PolicyRevision || localPolicy.Report.RunGeneration != candidate.RunGeneration {
			return errors.Join(err, errors.New("pending protective Pause requires the exact applied Off policy"))
		}
		var fetchedPolicy *model.InsightsManagerPolicyManifestV1
		for i := range manifest.InsightsManagerPolicies {
			if manifest.InsightsManagerPolicies[i].SandboxID == localPolicy.Manifest.SandboxID {
				if fetchedPolicy != nil {
					return state.ErrManagerConflict
				}
				fetchedPolicy = &manifest.InsightsManagerPolicies[i]
			}
		}
		if fetchedPolicy == nil {
			return errors.New("pending protective Pause renewal requires the fetched Off policy")
		}
		if err := model.ValidateInsightsManagerPolicyManifest(*fetchedPolicy); err != nil {
			return err
		}
		left, right := localPolicy.Manifest, *fetchedPolicy
		left.ValidUntil, right.ValidUntil = time.Time{}, time.Time{}
		if !reflect.DeepEqual(left, right) || !now.Before(fetchedPolicy.ValidUntil) || fetchedPolicy.ValidUntil.Sub(now) > 120*time.Second {
			return errors.New("pending protective Pause renewal changed current Off policy authority")
		}
		renewed := *prior
		renewed.Manifest.ValidUntil = candidate.ValidUntil
		renewals = append(renewals, renewed)
	}
	// Validate every eligible renewal before changing any retained operation.
	for _, renewed := range renewals {
		if err := c.Store.PutManagerTakeover(ctx, renewed); err != nil {
			return err
		}
	}
	return nil
}

func (c *Coordinator) Recover(ctx context.Context) error {
	if c.Store == nil || c.Control == nil || c.Helper == nil {
		return errors.New("manager coordinator is incompletely configured")
	}
	reservations, err := c.Store.ManagerReservations(ctx)
	if err != nil {
		return err
	}
	for i := range reservations {
		if reservations[i].Phase != "pending" && reservations[i].Phase != "reserved" {
			continue
		}
		if err := c.completeAutomaticReservation(ctx, &reservations[i]); err != nil {
			return err
		}
	}
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return err
	}
	for i := range runs {
		switch runs[i].Phase {
		case "start_ack_pending":
			if err := c.recoverStartAck(ctx, &runs[i]); err != nil {
				return err
			}
		case "dispatching", "execution_unknown":
			if err := c.resumeRun(ctx, &runs[i], "reconcile_review"); err != nil {
				return err
			}
		case "reviewing":
			if err := c.resumeRun(ctx, &runs[i], "continue_review"); err != nil {
				return err
			}
		case "report_pending":
			if err := c.submitRunReport(ctx, &runs[i]); err != nil {
				return err
			}
		}
	}
	takeovers, err := c.Store.ManagerTakeovers(ctx)
	if err != nil {
		return err
	}
	for i := range takeovers {
		switch takeovers[i].Phase {
		case "acquiring", "acquire_unknown", "releasing", "release_unknown":
			if err := c.reconcileTakeover(ctx, &takeovers[i]); err != nil {
				return err
			}
		}
	}
	return c.recoverPendingGuidance(ctx)
}

// Reports derives the manager policy reports for the node report.
// staleSources is the report assembly's single freshness decision: every
// capability item that references a source in that set is derived as the
// fail-closed unavailable pair the node API admits for a stale source
// (available=false, reason=source_unavailable), while a genuinely fresh
// re-observation keeps the ordinary available derivation.
func (c *Coordinator) Reports(ctx context.Context, staleSources continuity.StaleSourceSet) ([]model.InsightsManagerPolicyReportV1, []model.InsightsManagerRunReportV1, []model.InsightsTakeoverReportV1, error) {
	return c.reports(ctx, staleSources, nil, nil)
}

// ReportsCurrent scopes policy reports to the current validated authority
// identity (sandboxId, sandboxGeneration, policyRevision, runGeneration); the
// lease validUntil and capability-driven AutoSteerPolicy drift never grant
// identity. Reviews, takeovers and guidance settlement paths are deliberately
// unfiltered.
func (c *Coordinator) ReportsCurrent(ctx context.Context, authority model.Manifest, reportSources []model.ContinuitySourceReportV1, staleSources continuity.StaleSourceSet) ([]model.InsightsManagerPolicyReportV1, []model.InsightsManagerRunReportV1, []model.InsightsTakeoverReportV1, error) {
	current := make(map[string]bool, len(authority.InsightsManagerPolicies))
	for _, policy := range authority.InsightsManagerPolicies {
		current[managerPolicyIdentity(policy.SandboxID, policy.SandboxGeneration, policy.PolicyRevision, policy.RunGeneration)] = true
	}
	return c.reports(ctx, staleSources, current, reportSources)
}

func managerPolicyIdentity(sandboxID string, sandboxGeneration, policyRevision, runGeneration int64) string {
	return fmt.Sprintf("%s|%d|%d|%d", sandboxID, sandboxGeneration, policyRevision, runGeneration)
}

func (c *Coordinator) reports(ctx context.Context, staleSources continuity.StaleSourceSet, current map[string]bool, reportSources []model.ContinuitySourceReportV1) ([]model.InsightsManagerPolicyReportV1, []model.InsightsManagerRunReportV1, []model.InsightsTakeoverReportV1, error) {
	policies, err := c.Store.ManagerPolicies(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	holds, err := c.Store.ManagerTakeovers(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	policyReports := make([]model.InsightsManagerPolicyReportV1, 0, len(policies))
	for _, value := range policies {
		if current != nil && !current[managerPolicyIdentity(value.Manifest.SandboxID, value.Manifest.SandboxGeneration, value.Manifest.PolicyRevision, value.Manifest.RunGeneration)] {
			continue
		}
		report := value.Report
		if derived, deriveErr := c.policyReport(ctx, value.Manifest); deriveErr == nil {
			report = derived
		}
		// The stale derivation is applied to the exact report being serialized,
		// including the cached fallback, so a derivation outage cannot replay an
		// available capability for a source this report already publishes stale.
		report = c.projectPolicyReportSources(value.Manifest, report, reportSources)
		report = c.deriveStaleSourceCapabilities(value.Manifest, report, staleSources)
		policyReports = append(policyReports, report)
	}
	runReports := make([]model.InsightsManagerRunReportV1, 0, len(runs))
	for _, value := range runs {
		if value.Report != nil {
			runReports = append(runReports, *value.Report)
		}
	}
	holdReports := make([]model.InsightsTakeoverReportV1, 0, len(holds))
	for _, value := range holds {
		if value.Report == nil {
			continue
		}
		// Settled receipts remain durable for predecessor authorization and
		// recovery. Once the same sandbox generation has newer policy AND run
		// authority, the node API can no longer accept those old receipts.
		// Unknown/unsettled lifecycle records must remain visible instead of
		// being treated as completed merely because authority advanced.
		settled := (value.Phase == "ready" || value.Phase == "released" || value.Phase == "failed") &&
			(value.Report.Status == "ready" || value.Report.Status == "failed")
		superseded := false
		if settled {
			sandboxID := sourceSandbox(ctx, c.Store, value.Manifest.Source)
			for _, policy := range policies {
				if policy.Manifest.SandboxID == sandboxID &&
					policy.Manifest.SandboxGeneration == value.Manifest.Source.SandboxGeneration &&
					policy.Manifest.PolicyRevision > value.Manifest.PolicyRevision &&
					policy.Manifest.RunGeneration > value.Manifest.RunGeneration {
					superseded = true
					break
				}
			}
		}
		if settled {
			holdSandbox := sourceSandbox(ctx, c.Store, value.Manifest.Source)
			if ok, settleErr := c.guidanceSettled(ctx, holdSandbox); settleErr == nil && !ok {
				continue
			}
		}
		if !superseded {
			holdReports = append(holdReports, *value.Report)
		}
	}
	return policyReports, runReports, holdReports, nil
}

func (c *Coordinator) applyPolicy(ctx context.Context, policy model.InsightsManagerPolicyManifestV1) error {
	if policy.Mode == "off" {
		if err := c.fenceOffGuidance(ctx, policy.SandboxID); err != nil {
			return err
		}
	}
	report, err := c.policyReport(ctx, policy)
	if err != nil {
		return err
	}
	return c.Store.PutManagerPolicy(ctx, state.LocalManagerPolicy{Manifest: policy, Report: report})
}

// policyReport re-derives the manager policy report from the CURRENT source
// state so an outage between reports is reported truthfully instead of
// replaying the state cached at policy apply. Precedence is preserved:
// policy_off and policy_expired win; a capability's own reason wins next; when
// nothing else explains an unavailable capability and the exact source is
// unavailable or stale, the fail-closed reason is source_unavailable.
func (c *Coordinator) policyReport(ctx context.Context, policy model.InsightsManagerPolicyManifestV1) (model.InsightsManagerPolicyReportV1, error) {
	if err := model.ValidateInsightsManagerPolicyManifest(policy); err != nil {
		return model.InsightsManagerPolicyReportV1{}, err
	}
	sandbox, err := c.Store.Sandbox(ctx, policy.SandboxID)
	if err != nil || sandbox == nil || sandbox.ObservedGeneration != policy.SandboxGeneration {
		return model.InsightsManagerPolicyReportV1{}, errors.Join(err, errors.New("manager policy sandbox authority changed"))
	}
	sandboxRunning := sandbox.ObservedState == "running"
	capabilities, err := c.Store.ManagerCapabilities(ctx)
	if err != nil {
		return model.InsightsManagerPolicyReportV1{}, err
	}
	var reports []model.InsightsManagerRecommendCapabilityV1
	negotiated := false
	for _, capability := range capabilities {
		if capability.SandboxID != policy.SandboxID || capability.SandboxGeneration != policy.SandboxGeneration {
			continue
		}
		source, sourceErr := c.Store.ContinuitySource(ctx, capability.RegisteredSourceID)
		currentSource := sourceErr == nil && source != nil && source.Lifecycle == "running" && source.Report.Availability == "available" &&
			source.Report.SandboxGeneration == policy.SandboxGeneration && source.Report.ServiceGeneration == capability.ServiceGeneration &&
			source.Report.WorkspaceEpoch == capability.WorkspaceEpoch && source.Report.NativeSessionID == capability.NativeSessionID
		available := sandboxRunning && policy.Mode == "recommend" && c.now().Before(policy.ValidUntil) && policy.ValidUntil.Sub(c.now()) <= 120*time.Second && capability.Available && currentSource
		reason := capability.Reason
		if policy.Mode == "off" {
			reason = "policy_off"
		} else if !c.now().Before(policy.ValidUntil) {
			reason = "policy_expired"
		} else if reason == "" && !available {
			if !currentSource {
				reason = "source_unavailable"
			} else {
				reason = "runtime_unavailable"
			}
		}
		var nativeGuard *model.NativeGuardObservationV1
		pluginDigest := ""
		var reasonPointer *string
		if capability.NativeGuard != nil {
			negotiated = true
			nativeGuard = capability.NativeGuard
			pluginDigest = capability.ManagerPluginDigest
			hardwareAvailable := sandboxRunning && capability.Available && currentSource
			available = hardwareAvailable
			reason = ""
			if !hardwareAvailable {
				if !currentSource {
					reason = "source_unavailable"
				} else {
					reason = "runtime_unavailable"
				}
			}
			reasonPointer = nil
		}
		if reason != "" {
			value := reason
			reasonPointer = &value
		}
		reports = append(reports, model.InsightsManagerRecommendCapabilityV1{Source: model.InsightsManagerSourceV1{RegisteredSourceID: capability.RegisteredSourceID, WorkspaceEpoch: capability.WorkspaceEpoch, NativeSessionID: capability.NativeSessionID, ServiceRegistrationID: capability.ServiceRegistrationID, ServiceGeneration: capability.ServiceGeneration, SandboxGeneration: capability.SandboxGeneration, ProfileRevision: capability.ProfileRevision, InstructionRevision: capability.InstructionRevision}, ProviderRouteDigest: capability.ProviderRouteDigest, ProviderID: capability.ProviderID, ModelID: capability.ModelID, Protocol: capability.Protocol, RecipeIDs: append([]string(nil), capability.RecipeIDs...), MaxInputTokens: capability.MaxInputTokens, MaxOutputTokens: capability.MaxOutputTokens, ToolsAllowed: capability.ToolsAllowed, MediaAllowed: capability.MediaAllowed, ManagerProfile: capability.ManagerProfile, Available: available, Reason: reasonPointer, NativeGuard: nativeGuard, ManagerPluginDigest: pluginDigest})
	}
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].Source.RegisteredSourceID < reports[j].Source.RegisteredSourceID
	})
	if len(reports) > 8 {
		reports = reports[:8]
	}
	status := "applied"
	if policy.Mode == "off" && negotiated {
		settled, settleErr := c.guidanceSettled(ctx, policy.SandboxID)
		if settleErr != nil {
			return model.InsightsManagerPolicyReportV1{}, settleErr
		}
		if !settled {
			status = "awaiting_guidance"
		}
	}
	report := model.InsightsManagerPolicyReportV1{FormatVersion: 1, SandboxID: policy.SandboxID, SandboxGeneration: policy.SandboxGeneration, PolicyRevision: policy.PolicyRevision, RunGeneration: policy.RunGeneration, Status: status, Recommend: c.policyRollup(policy, reports), RecommendCapabilities: reports}
	report.ReceiptDigest = digestJSON(report)
	return report, nil
}

// policyRollup derives the policy-level recommend capability from the exact
// capability items the report publishes, preserving the existing precedence:
// policy_off and policy_expired win; otherwise the rollup is available when any
// item is available, and when nothing is available every item must carry the
// fail-closed source_unavailable reason for the rollup to carry it too.
func (c *Coordinator) policyRollup(policy model.InsightsManagerPolicyManifestV1, reports []model.InsightsManagerRecommendCapabilityV1) model.InsightsManagerCapabilityV1 {
	available := false
	for _, value := range reports {
		available = available || value.Available
	}
	if policy.Mode != "recommend" {
		available = false
	}
	reason := "runtime_unavailable"
	if policy.Mode == "off" {
		reason = "policy_off"
	} else if !c.now().Before(policy.ValidUntil) {
		reason = "policy_expired"
	} else if available {
		reason = ""
	} else if len(reports) > 0 {
		reason = "source_unavailable"
		for _, value := range reports {
			if value.Reason == nil || *value.Reason != "source_unavailable" {
				reason = "runtime_unavailable"
				break
			}
		}
	}
	var reasonPointer *string
	if reason != "" {
		value := reason
		reasonPointer = &value
	}
	return model.InsightsManagerCapabilityV1{Available: available, Reason: reasonPointer}
}

// projectPolicyReportSources retains only the capability items whose eight
// InsightsManagerSourceV1 identity fields all match a source serialized in the
// SAME report. Absent or mismatched items are omitted; the current policy
// report itself is retained and the rollup and receipt digest are recomputed
// with the existing helpers before the fresh/stale derivation runs.
func (c *Coordinator) projectPolicyReportSources(policy model.InsightsManagerPolicyManifestV1, report model.InsightsManagerPolicyReportV1, sources []model.ContinuitySourceReportV1) model.InsightsManagerPolicyReportV1 {
	if sources == nil {
		return report
	}
	retained := make([]model.InsightsManagerRecommendCapabilityV1, 0, len(report.RecommendCapabilities))
	changed := false
	for _, capability := range report.RecommendCapabilities {
		matched := false
		for _, source := range sources {
			if capability.Source.RegisteredSourceID == source.RegisteredSourceID &&
				capability.Source.WorkspaceEpoch == source.WorkspaceEpoch &&
				capability.Source.NativeSessionID == source.NativeSessionID &&
				capability.Source.ServiceRegistrationID == source.ServiceRegistrationID &&
				capability.Source.ServiceGeneration == source.ServiceGeneration &&
				capability.Source.SandboxGeneration == source.SandboxGeneration &&
				capability.Source.ProfileRevision == source.ProfileRevision &&
				capability.Source.InstructionRevision == source.InstructionRevision {
				matched = true
				break
			}
		}
		if matched {
			retained = append(retained, capability)
		} else {
			changed = true
		}
	}
	if !changed {
		return report
	}
	report.RecommendCapabilities = retained
	report.Recommend = c.policyRollup(policy, retained)
	report.ReceiptDigest = ""
	report.ReceiptDigest = digestJSON(report)
	return report
}

// deriveStaleSourceCapabilities applies the report assembly's single freshness
// decision to the exact policy report being serialized. Every capability item
// that references a stale source is derived as the fail-closed pair the node
// API documents for a stale source — available=false with reason
// source_unavailable — because the node API admits a stale source only through
// that pair; the capability identity, provider route, profile and recipe fields
// are preserved. The policy rollup and receipt digest are recomputed with the
// ordinary derivation rules, and a report with no stale reference is returned
// untouched so fresh observations keep their exact derived receipt.
func (c *Coordinator) deriveStaleSourceCapabilities(policy model.InsightsManagerPolicyManifestV1, report model.InsightsManagerPolicyReportV1, staleSources continuity.StaleSourceSet) model.InsightsManagerPolicyReportV1 {
	capabilities := append([]model.InsightsManagerRecommendCapabilityV1(nil), report.RecommendCapabilities...)
	changed := false
	for index := range capabilities {
		item := &capabilities[index]
		if !staleSources.Stale(item.Source.RegisteredSourceID) {
			continue
		}
		if !item.Available && item.Reason != nil && *item.Reason == "source_unavailable" {
			continue
		}
		reason := "source_unavailable"
		item.Available = false
		item.Reason = &reason
		changed = true
	}
	if !changed {
		return report
	}
	report.RecommendCapabilities = capabilities
	report.Recommend = c.policyRollup(policy, report.RecommendCapabilities)
	report.ReceiptDigest = ""
	report.ReceiptDigest = digestJSON(report)
	return report
}

func (c *Coordinator) applyReview(ctx context.Context, review model.InsightsManagerReviewManifestV1) error {
	if err := model.ValidateInsightsManagerReviewManifest(review); err != nil {
		return err
	}
	prior, err := c.Store.ManagerRun(ctx, review.RunID)
	if err != nil {
		return err
	}
	if prior != nil {
		return c.acceptExistingRun(ctx, prior, review)
	}
	capability, evidence, err := c.reviewAuthority(ctx, review, true)
	if err != nil {
		return err
	}
	run := state.LocalManagerRun{Manifest: review, Phase: "start_ack_pending", Capability: *capability, DispatchStarted: false, StartedAt: c.now(), AutomaticOrigin: !review.Manual, OriginRunGeneration: managerRunGeneration(ctx, c.Store, review.Source), OriginValidUntil: review.ValidUntil}
	if err := c.Store.PutManagerRun(ctx, run); err != nil {
		return err
	}
	return c.startAcknowledgedReview(ctx, &run, evidence)
}

// recoverStartAck retries the exact idempotent reviewing report while the
// original start authority is still valid. A run that never crossed possible
// dispatch settles truthfully as failed/trusted_zero_start once that authority
// is gone; it never reaches the helper and is never helper execution_unknown.
func (c *Coordinator) recoverStartAck(ctx context.Context, run *state.LocalManagerRun) error {
	_, evidence, err := c.reviewAuthority(ctx, run.Manifest, true)
	if err != nil {
		return c.settleUnstartedRun(ctx, run)
	}
	return c.startAcknowledgedReview(ctx, run, evidence)
}

// startAcknowledgedReview performs the frozen durable start transition: the
// exact canonical reviewing report is submitted and its returned immutable
// activity is validated before any possible-dispatch state exists. Only then is
// the possible helper effect persisted and invoked. A refused or mismatched
// acknowledgement leaves the run as a non-dispatched start_ack_pending intent
// with zero helper calls; a post-acknowledgement authority expiry settles it as
// trusted zero start without helper work.
func (c *Coordinator) startAcknowledgedReview(ctx context.Context, run *state.LocalManagerRun, evidence map[string]any) error {
	if err := c.submitStartReviewingReport(ctx, run); err != nil {
		return err
	}
	if _, _, err := c.reviewAuthority(ctx, run.Manifest, true); err != nil {
		return c.settleUnstartedRun(ctx, run)
	}
	run.Phase = "execution_unknown"
	run.DispatchStarted = true
	if err := c.Store.PutManagerRun(ctx, *run); err != nil {
		return err
	}
	return c.dispatchReview(ctx, run, evidence, "start_review")
}

func (c *Coordinator) submitStartReviewingReport(ctx context.Context, run *state.LocalManagerRun) error {
	report := model.InsightsManagerRunReportV1{FormatVersion: 1, ReservationID: run.Manifest.ReservationID, RunID: run.Manifest.RunID,
		Manual: run.Manifest.Manual, State: "reviewing", PolicyRevision: run.Manifest.PolicyRevision, Source: run.Manifest.Source,
		Target: run.Manifest.Target, Usage: model.InsightsManagerUsageV1{UsageCertain: false, UnusedProof: "none"}}
	report.ReceiptDigest = digestJSON(report)
	activity, err := c.Control.SubmitInsightsManagerRunReport(ctx, report)
	if err != nil {
		return err
	}
	if activity.RunID != run.Manifest.RunID || activity.ReservationID != run.Manifest.ReservationID || activity.Manual != run.Manifest.Manual ||
		activity.FindingID != run.Manifest.FindingID || activity.RuleID != run.Manifest.RuleID || activity.RecipeID != run.Manifest.RecipeID ||
		activity.Source != run.Manifest.Source || !reflectTarget(activity.Target, run.Manifest.Target) || activity.State != "reviewing" {
		return errors.New("manager start acknowledgement changed persisted run authority")
	}
	return nil
}

// settleUnstartedRun truthfully retires a genuinely never-dispatched run with
// zero usage once its start authority is gone. It never authorizes helper work.
func (c *Coordinator) settleUnstartedRun(ctx context.Context, run *state.LocalManagerRun) error {
	code := c.unstartedErrorCode(ctx, run)
	report := model.InsightsManagerRunReportV1{FormatVersion: 1, ReservationID: run.Manifest.ReservationID, RunID: run.Manifest.RunID,
		Manual: run.Manifest.Manual, State: "failed", PolicyRevision: run.Manifest.PolicyRevision, Source: run.Manifest.Source,
		Target: run.Manifest.Target, Usage: model.InsightsManagerUsageV1{UsageCertain: true, UnusedProof: "trusted_zero_start"}, ErrorCode: &code}
	report.ReceiptDigest = digestJSON(report)
	run.Phase = "report_pending"
	run.Report = &report
	if err := c.Store.PutManagerRun(ctx, *run); err != nil {
		return err
	}
	return c.submitRunReport(ctx, run)
}

func (c *Coordinator) unstartedErrorCode(ctx context.Context, run *state.LocalManagerRun) string {
	policy, err := c.Store.ManagerPolicy(ctx, sourceSandbox(ctx, c.Store, run.Manifest.Source))
	if err != nil || policy == nil || policy.Manifest.Mode == "off" {
		return "policy_off"
	}
	if !c.now().Before(policy.Manifest.ValidUntil) || policy.Manifest.ValidUntil.Sub(c.now()) > 120*time.Second {
		return "policy_expired"
	}
	return "source_stale"
}

func (c *Coordinator) acceptExistingRun(ctx context.Context, prior *state.LocalManagerRun, review model.InsightsManagerReviewManifestV1) error {
	left, right := prior.Manifest, review
	left.ValidUntil, right.ValidUntil = time.Time{}, time.Time{}
	if !reflect.DeepEqual(left, right) {
		return state.ErrManagerConflict
	}
	if review.ValidUntil.Equal(prior.Manifest.ValidUntil) {
		return nil
	}
	if !review.ValidUntil.After(prior.Manifest.ValidUntil) {
		return state.ErrManagerConflict
	}
	return c.Store.RenewManagerRunLease(ctx, review.RunID, prior.Manifest.ValidUntil, review.ValidUntil)
}

// reviewAuthority is the local execution-authority boundary for a review. The
// current policy revision, fresh lease, source/service/target/capability and
// recipe fences authorize execution; the acknowledged finding evidence only
// proves which finding is being reviewed. The evidence is the canonical local
// observation for automatic reviews, or the authenticated manifest snapshot
// when a manual reservation carries one; the historical observation policy
// revision is provenance and never has to equal the current execution revision.
func (c *Coordinator) reviewAuthority(ctx context.Context, review model.InsightsManagerReviewManifestV1, requireFresh bool) (*state.LocalManagerCapability, map[string]any, error) {
	if requireFresh && (!c.now().Before(review.ValidUntil) || review.ValidUntil.Sub(c.now()) > 120*time.Second) {
		return nil, nil, errors.New("manager review authority expired")
	}
	source, err := c.localSourceAuthority(ctx, review.Source)
	if err != nil {
		return nil, nil, err
	}
	var freshPolicy *state.LocalManagerPolicy
	if requireFresh {
		policy, err := c.Store.ManagerPolicy(ctx, source.Report.SandboxID)
		if err != nil || policy == nil || !reviewPolicyModeValid(policy.Manifest) || policy.Manifest.PolicyRevision != review.PolicyRevision ||
			!c.now().Before(policy.Manifest.ValidUntil) || policy.Manifest.ManagerProfile != review.ManagerProfile {
			return nil, nil, errors.Join(err, errors.New("manager review policy authority changed"))
		}
		freshPolicy = policy
	}
	if err := c.localServiceAuthority(ctx, review.Source, review.Target); err != nil {
		return nil, nil, err
	}
	capability, err := c.Store.ManagerCapability(ctx, review.Source.RegisteredSourceID)
	if err != nil || capability == nil || !capability.Available || capability.ProviderRouteDigest != review.ProviderRouteDigest || capability.ManagerProfile != review.ManagerProfile || capability.ServiceGeneration != review.Source.ServiceGeneration || capability.WorkspaceEpoch != review.Source.WorkspaceEpoch || capability.NativeSessionID != review.Source.NativeSessionID || capability.ProfileRevision != review.Source.ProfileRevision || capability.InstructionRevision != review.Source.InstructionRevision {
		return nil, nil, errors.Join(err, errors.New("manager capability authority changed"))
	}
	if freshPolicy != nil && freshPolicy.Manifest.Mode == "auto_steer" {
		sandbox, sandboxErr := c.Store.Sandbox(ctx, capability.SandboxID)
		if sandboxErr != nil || !autoSteerQualified(freshPolicy.Manifest, capability, sandbox) {
			return nil, nil, errors.Join(sandboxErr, errors.New("manager auto-steer qualification changed"))
		}
	}
	if !contains(capability.RecipeIDs, review.RecipeID) {
		return nil, nil, errors.New("manager recipe unavailable")
	}
	var evidence map[string]any
	if review.FindingEvidence != nil {
		if err := model.ValidateInsightsManagerFindingEvidence(*review.FindingEvidence, review); err != nil {
			return nil, nil, err
		}
		evidence = managerFindingEvidenceV1(*review.FindingEvidence)
	} else {
		finding, err := c.Store.ManagerFinding(ctx, review.FindingID)
		if err != nil || finding == nil || !finding.Acknowledged || finding.Finding.Revision != review.FindingRevision || finding.Finding.RuleID != review.RuleID || finding.Source != review.Source {
			return nil, nil, errors.Join(err, errors.New("manager finding authority changed"))
		}
		evidence = managerFindingEvidence(*finding)
	}
	if err := c.localTargetAuthority(ctx, review.FindingID, review.FindingRevision, review.Source, review.Target); err != nil {
		return nil, nil, err
	}
	return capability, evidence, nil
}

func (c *Coordinator) localSourceAuthority(ctx context.Context, expected model.InsightsManagerSourceV1) (*state.LocalContinuitySource, error) {
	source, err := c.Store.ContinuitySource(ctx, expected.RegisteredSourceID)
	if err != nil || source == nil || source.Report.Availability != "available" || source.Lifecycle != "running" {
		return nil, errors.Join(err, errors.New("manager source is unavailable"))
	}
	actual := model.InsightsManagerSourceV1{RegisteredSourceID: source.Report.RegisteredSourceID, WorkspaceEpoch: source.Report.WorkspaceEpoch, NativeSessionID: source.Report.NativeSessionID, ServiceRegistrationID: source.Report.ServiceRegistrationID, ServiceGeneration: source.Report.ServiceGeneration, SandboxGeneration: source.Report.SandboxGeneration, ProfileRevision: source.Report.ProfileRevision, InstructionRevision: source.Report.InstructionRevision}
	if actual != expected {
		return nil, errors.New("manager source authority changed")
	}
	return source, nil
}

func (c *Coordinator) localServiceAuthority(ctx context.Context, source model.InsightsManagerSourceV1, target model.InsightsManagerTargetV1) error {
	service, err := c.Store.ManagedService(ctx, source.ServiceRegistrationID)
	if err != nil || service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" || service.Manifest.Identity.TeamID != target.TeamID || service.Manifest.Identity.MemberID != target.MemberID || service.ServiceGeneration != source.ServiceGeneration {
		return errors.Join(err, errors.New("manager service authority changed"))
	}
	return nil
}

func (c *Coordinator) localTargetAuthority(ctx context.Context, findingID string, findingRevision int64, source model.InsightsManagerSourceV1, target model.InsightsManagerTargetV1) error {
	envelope, err := c.Control.GetInsightsManagerTarget(ctx, findingID, source.RegisteredSourceID)
	if err != nil {
		return err
	}
	if envelope.FormatVersion != 1 || envelope.FindingID != findingID || envelope.FindingRevision != findingRevision || envelope.Source != source {
		return errors.New("manager canonical descriptor authority changed")
	}
	if !reflect.DeepEqual(envelope.Target, target) {
		return errors.New("manager canonical target changed")
	}
	if err := c.localWorkAuthority(ctx, source, target); err != nil {
		return err
	}
	return c.localBusyTaskConsistency(ctx, source, target)
}

// localWorkAuthority keeps the genuine Work context binding checks: a
// task-bearing target must match the current verified Work registration for
// this source. Registration task provenance is not part of Work authority.
func (c *Coordinator) localWorkAuthority(ctx context.Context, source model.InsightsManagerSourceV1, target model.InsightsManagerTargetV1) error {
	if target.WorkID == nil {
		return nil
	}
	registration, err := c.Store.ContinuityRegistration(ctx, *target.BindingID)
	if err != nil || registration == nil || registration.ObservedStatus != "verified" || !registration.Manifest.ContinuityEnabled ||
		registration.Manifest.DesiredState != "active" || registration.Manifest.Identity.WorkID != *target.WorkID ||
		registration.Manifest.Identity.WorkspaceEpoch != source.WorkspaceEpoch ||
		registration.Manifest.Identity.SandboxGeneration != source.SandboxGeneration ||
		registration.Manifest.Identity.ExpectedRevision != *target.WorkRevision ||
		registration.Manifest.Binding.BindingID != *target.BindingID ||
		registration.Manifest.Binding.BindingRevision != *target.BindingRevision ||
		registration.Manifest.Binding.RegisteredSourceID != source.RegisteredSourceID ||
		registration.Manifest.Binding.ServiceRegistrationID != source.ServiceRegistrationID ||
		registration.Manifest.Binding.NativeSessionID != source.NativeSessionID ||
		registration.ServiceGeneration != source.ServiceGeneration {
		return errors.Join(err, errors.New("manager Work binding authority changed"))
	}
	return nil
}

// localBusyTaskConsistency treats the live member-task authority as additional
// defense only: when the worker reports Busy it must match the canonical task,
// while an idle or absent observation grants nothing and cannot veto the
// canonical waiting/cancel task.
func (c *Coordinator) localBusyTaskConsistency(ctx context.Context, source model.InsightsManagerSourceV1, target model.InsightsManagerTargetV1) error {
	task, err := c.Store.ManagedTaskAuthority(ctx, source.ServiceRegistrationID)
	if err != nil {
		return err
	}
	if task == nil || !task.Busy || task.TaskID == nil || task.TaskAttempt == nil {
		// Idle or absent authority grants nothing and cannot veto the
		// canonical waiting/cancel task.
		return nil
	}
	if target.TaskID == nil || target.TaskAttempt == nil ||
		*task.TaskID != *target.TaskID || *task.TaskAttempt != *target.TaskAttempt ||
		task.ServiceGeneration != source.ServiceGeneration || task.SandboxGeneration != source.SandboxGeneration ||
		task.ObservedAt.After(c.now().Add(5*time.Second)) || c.now().Sub(task.ObservedAt) > 120*time.Second {
		return errors.New("manager Busy task contradicts canonical target")
	}
	return nil
}

func (c *Coordinator) dispatchReview(ctx context.Context, run *state.LocalManagerRun, evidence map[string]any, action string) error {
	sandboxID, instance, err := c.helperTarget(ctx, run.Manifest.Source)
	if err != nil {
		return err
	}
	authority := any(run.Manifest)
	if run.Capability.NativeGuard != nil {
		descriptorPayload, _ := json.Marshal(run.Manifest)
		var descriptor map[string]any
		_ = json.Unmarshal(descriptorPayload, &descriptor)
		descriptor["runGeneration"] = run.OriginRunGeneration
		authority = descriptor
	}
	request := map[string]any{"formatVersion": 1, "action": action, "instance": instance, "authority": authority, "finding": evidence, "capability": managerCapabilityWire(run.Capability)}
	if action != "start_review" {
		request = map[string]any{"formatVersion": 1, "action": action, "instance": instance, "reservationId": run.Manifest.ReservationID, "runId": run.Manifest.RunID, "policyRevision": run.Manifest.PolicyRevision, "runGeneration": managerRunGeneration(ctx, c.Store, run.Manifest.Source), "source": run.Manifest.Source}
	}
	if run.Capability.NativeGuard != nil {
		request["runtimeContractVersion"] = guidanceContractVersion
	}
	payload, _ := json.Marshal(request)
	output, _, err := c.Helper.ExecManager(ctx, sandboxID, payload)
	if err != nil {
		run.Phase = "execution_unknown"
		_ = c.Store.PutManagerRun(ctx, *run)
		return err
	}
	return c.completeReview(ctx, run, output, action)
}

// resumeRun observes or continues the same admitted operation. Non-start
// observation carries no finding requirement: the start evidence was consumed
// when the run crossed possible dispatch, so recovery must not depend on a
// local finding history row.
func (c *Coordinator) resumeRun(ctx context.Context, run *state.LocalManagerRun, action string) error {
	return c.dispatchReview(ctx, run, nil, action)
}

func (c *Coordinator) completeReview(ctx context.Context, run *state.LocalManagerRun, payload []byte, action string) error {
	var receipt reviewHelperReceipt
	if err := decodeClosed(payload, &receipt); err != nil {
		return err
	}
	if receipt.FormatVersion != 1 || receipt.Action != action || receipt.ReservationID != run.Manifest.ReservationID || receipt.RunID != run.Manifest.RunID || !digestPattern.MatchString(receipt.ReceiptDigest) {
		return fmt.Errorf("manager helper receipt changed immutable identity: got v=%d action=%s reservation=%s run=%s digest=%s want action=%s reservation=%s run=%s", receipt.FormatVersion, receipt.Action, receipt.ReservationID, receipt.RunID, receipt.ReceiptDigest, action, run.Manifest.ReservationID, run.Manifest.RunID)
	}
	if receipt.Status == "reviewing" || receipt.Status == "execution_unknown" {
		run.Phase = receipt.Status
		return c.Store.PutManagerRun(ctx, *run)
	}
	if receipt.Status == "refused" {
		if receipt.Error == nil {
			return errors.New("manager refusal omitted its closed reason")
		}
		receipt.Status = "failed"
	}
	if receipt.Status != "recommended" && receipt.Status != "no_action" && receipt.Status != "needs_owner" && receipt.Status != "failed" {
		return errors.New("manager helper status is invalid")
	}
	if receipt.ModelRequests < 0 || receipt.ModelRequests > run.Manifest.Budget.ModelRequests || receipt.ReservedInputTokens < 0 || receipt.ReservedInputTokens > run.Manifest.Budget.InputTokens || receipt.ReservedOutputTokens < 0 || receipt.ReservedOutputTokens > run.Manifest.Budget.OutputTokens {
		return errors.New("manager helper exceeded reserved budget")
	}
	report := model.InsightsManagerRunReportV1{FormatVersion: 1, ReservationID: run.Manifest.ReservationID, RunID: run.Manifest.RunID, Manual: run.Manifest.Manual, State: receipt.Status, PolicyRevision: run.Manifest.PolicyRevision, Source: run.Manifest.Source, Target: run.Manifest.Target, Usage: model.InsightsManagerUsageV1{ModelRequests: receipt.ModelRequests, InputTokens: receipt.ReservedInputTokens, OutputTokens: receipt.ReservedOutputTokens, UsageCertain: false, UnusedProof: "none"}, ReceiptDigest: receipt.ReceiptDigest}
	if receipt.Status != "failed" {
		proposal, err := c.terminalProposal(ctx, run, receipt)
		if err != nil {
			return err
		}
		report.Proposal = proposal
		if proposal != nil {
			report.ManagerSession = receipt.ManagerSession
		}
	}
	if receipt.Error != nil {
		code := closedRunError(*receipt.Error)
		report.ErrorCode = &code
	}
	run.Phase = "report_pending"
	run.Report = &report
	if err := c.Store.PutManagerRun(ctx, *run); err != nil {
		return err
	}
	return c.submitRunReport(ctx, run)
}

// terminalProposal validates and passes through the actual safe proposal
// summary. recommendation, no_action and needs_owner keep their own outcome; a
// needs_owner result without a proposal is the truthful null disposition of an
// invalid completed output. Runtime never invents an outcome, rationale or
// finding window, and citation bounds stay the actual receipt values within the
// consumed evidence.
func (c *Coordinator) terminalProposal(ctx context.Context, run *state.LocalManagerRun, receipt reviewHelperReceipt) (*model.InsightsManagerProposalV1, error) {
	wantOutcome := map[string]string{"recommended": "recommendation", "no_action": "no_action", "needs_owner": "needs_owner"}[receipt.Status]
	if receipt.Proposal == nil {
		if receipt.Status == "needs_owner" {
			return nil, nil
		}
		return nil, errors.New("manager terminal receipt omitted its proposal")
	}
	proposal := receipt.Proposal
	if proposal.Outcome != wantOutcome || proposal.RecipeID != run.Manifest.RecipeID || !validProposalRationale(proposal.RationaleCode) ||
		proposal.FirstSequence < 1 || proposal.LastSequence < proposal.FirstSequence {
		return nil, errors.New("manager proposal changed closed terminal semantics")
	}
	if bound := managerSequenceBound(ctx, c.Store, run); bound > 0 && proposal.LastSequence > bound {
		return nil, errors.New("manager proposal cited outside its acknowledged evidence")
	}
	if proposal.GuidanceDigest != nil && !digestPattern.MatchString(*proposal.GuidanceDigest) {
		return nil, errors.New("manager proposal guidance digest is invalid")
	}
	if receipt.ManagerSession == nil || receipt.ManagerSession.NativeSessionID == "" ||
		!managerNativeProjectPattern.MatchString(receipt.ManagerSession.NativeProjectID) ||
		!digestPattern.MatchString(receipt.ManagerSession.NativeLocationDigest) {
		return nil, errors.New("manager proposal receipt omitted a valid manager session")
	}
	expectedSource := managerSourceID(run.Manifest.RunID)
	if receipt.ManagerRegisteredSourceID != expectedSource || receipt.ManagerSession.ServiceRegistrationID != run.Manifest.Source.ServiceRegistrationID || receipt.ManagerSession.ServiceGeneration != run.Manifest.Source.ServiceGeneration || receipt.ManagerSession.ProviderRouteDigest != run.Manifest.ProviderRouteDigest || receipt.ManagerSession.ManagerProfile != run.Manifest.ManagerProfile {
		return nil, errors.New("manager session receipt changed authority")
	}
	switch receipt.Status {
	case "recommended":
		if receipt.ProposalDigest == nil || !digestPattern.MatchString(*receipt.ProposalDigest) || proposal.GuidanceDigest == nil || receipt.GuidanceReceipt == nil ||
			receipt.GuidanceReceipt.FormatVersion != 1 || receipt.GuidanceReceipt.Mode != "recommend_only" ||
			receipt.GuidanceReceipt.Status != "not_delivered" || receipt.GuidanceReceipt.PendingInputID != nil ||
			receipt.GuidanceReceipt.AutoSteer || receipt.GuidanceReceipt.AtomicNativeGuard || receipt.GuidanceReceipt.GuidanceDigest == nil ||
			*receipt.GuidanceReceipt.GuidanceDigest != *proposal.GuidanceDigest {
			return nil, errors.New("manager recommendation receipt is invalid")
		}
	case "no_action":
		if proposal.GuidanceDigest != nil || receipt.GuidanceReceipt != nil && receipt.GuidanceReceipt.GuidanceDigest != nil {
			return nil, errors.New("manager no-action receipt carried guidance")
		}
	case "needs_owner":
		if receipt.GuidanceReceipt != nil && receipt.GuidanceReceipt.GuidanceDigest != nil && proposal.GuidanceDigest != nil &&
			*receipt.GuidanceReceipt.GuidanceDigest != *proposal.GuidanceDigest {
			return nil, errors.New("manager owner-needed receipt changed guidance")
		}
	}
	run.ManagerRegisteredSourceID = expectedSource
	run.ManagerSession = receipt.ManagerSession
	return &model.InsightsManagerProposalV1{RecipeID: proposal.RecipeID, Outcome: proposal.Outcome, RationaleCode: proposal.RationaleCode,
		FirstSequence: proposal.FirstSequence, LastSequence: proposal.LastSequence, GuidanceDigest: proposal.GuidanceDigest}, nil
}

func managerSequenceBound(ctx context.Context, store *state.Store, run *state.LocalManagerRun) int64 {
	if run.Manifest.FindingEvidence != nil {
		return run.Manifest.FindingEvidence.LastSequence
	}
	if finding, _ := store.ManagerFinding(ctx, run.Manifest.FindingID); finding != nil {
		return finding.Finding.LastSequence
	}
	return 0
}

func validProposalRationale(value string) bool {
	switch value {
	case "unchanged_failure_repeated", "repeated_call_detected", "query_refinement_available", "active_phase_stalled", "no_safe_action":
		return true
	}
	return false
}

func (c *Coordinator) submitRunReport(ctx context.Context, run *state.LocalManagerRun) error {
	if run.Report == nil {
		return errors.New("manager run report is missing")
	}
	activity, err := c.Control.SubmitInsightsManagerRunReport(ctx, *run.Report)
	if err != nil {
		run.Phase = "report_pending"
		_ = c.Store.PutManagerRun(ctx, *run)
		return err
	}
	if activity.RunID != run.Manifest.RunID || activity.ReservationID != run.Manifest.ReservationID ||
		activity.Manual != run.Manifest.Manual || activity.FindingID != run.Manifest.FindingID ||
		activity.RuleID != run.Manifest.RuleID || activity.RecipeID != run.Manifest.RecipeID ||
		activity.Source != run.Manifest.Source || !reflectTarget(activity.Target, run.Manifest.Target) ||
		activity.State != run.Report.State {
		return errors.New("manager report acknowledgement changed persisted run authority")
	}
	run.Phase = run.Report.State
	return c.Store.PutManagerRun(ctx, *run)
}

func (c *Coordinator) ObserveAcknowledgedInsightBatch(ctx context.Context, batch model.InsightBatchV1, receipt model.InsightBatchReceiptV1) error {
	if receipt.BatchID != batch.BatchID || receipt.Accepted != len(batch.Findings) || receipt.ThroughSequence != batch.ThroughSequence {
		return errors.New("manager observation requires exact acknowledged batch")
	}
	if strings.HasPrefix(batch.RegisteredSourceID, "manager_") {
		return nil
	}
	// Retain every genuine acknowledged open finding observation regardless of
	// the current Off/not-current policy, allowed-rule eligibility or historical
	// policy revision: the observation policy revision is provenance, not
	// execution permission. Source identity stays exact.
	source := model.InsightsManagerSourceV1{RegisteredSourceID: batch.RegisteredSourceID, WorkspaceEpoch: batch.WorkspaceEpoch, NativeSessionID: batch.NativeSessionID, ServiceRegistrationID: batch.ServiceRegistrationID, ServiceGeneration: batch.ServiceGeneration, SandboxGeneration: batch.SandboxGeneration}
	continuitySource, err := c.Store.ContinuitySource(ctx, batch.RegisteredSourceID)
	if err != nil || continuitySource == nil ||
		continuitySource.Report.ServiceRegistrationID != batch.ServiceRegistrationID || continuitySource.Report.ServiceGeneration != batch.ServiceGeneration ||
		continuitySource.Report.SandboxID != batch.SandboxID || continuitySource.Report.SandboxGeneration != batch.SandboxGeneration ||
		continuitySource.Report.WorkspaceEpoch != batch.WorkspaceEpoch || continuitySource.Report.NativeSessionID != batch.NativeSessionID {
		return errors.Join(err, errors.New("manager acknowledged source authority changed"))
	}
	source.ProfileRevision = continuitySource.Report.ProfileRevision
	source.InstructionRevision = continuitySource.Report.InstructionRevision
	policyState, err := c.Store.ManagerPolicy(ctx, batch.SandboxID)
	if err != nil {
		return err
	}
	var provenance int64
	if policyState != nil {
		provenance = policyState.Manifest.PolicyRevision
	}
	// Durable automatic-admission anchors are captured before any temporary
	// policy/capability gate so an accepted finding is never silently lost.
	// Observation only persists anchors and read-only captures; every effect is
	// owned by recoverAdmissions at the end-of-pass Apply boundary.
	for _, finding := range batch.Findings {
		stored, err := c.Store.ManagerFinding(ctx, finding.FindingID)
		if err != nil {
			return err
		}
		if stored == nil {
			if finding.State != "open" {
				continue
			}
			anchor := state.LocalManagerAdmission{State: admissionPending, ObservedAt: c.now(), EvaluatedAt: c.now(), BatchID: batch.BatchID, SandboxID: batch.SandboxID, RuleID: finding.RuleID}
			if policyState != nil {
				anchor.PolicyRevision = policyState.Manifest.PolicyRevision
				anchor.RunGeneration = policyState.Manifest.RunGeneration
				anchor.Mode = policyState.Manifest.Mode
			}
			if err := c.captureAdmissionAnchor(ctx, &anchor, finding, source, policyState); err != nil {
				return err
			}
			local := state.LocalManagerFinding{Finding: finding, Source: source, PolicyRevision: provenance, JournalGeneration: batch.JournalGeneration, Acknowledged: true, Admission: &anchor}
			if err := c.Store.PutManagerFinding(ctx, local); err != nil {
				return err
			}
			continue
		}
		// Every genuine observation refreshes current finding content and
		// provenance while preserving the original admission anchor.
		refreshed := *stored
		refreshed.Finding = finding
		refreshed.Source = source
		refreshed.JournalGeneration = batch.JournalGeneration
		refreshed.PolicyRevision = provenance
		refreshed.Acknowledged = true
		if stored.Admission == nil {
			// Legacy rows stay legacy: no backfill of an admission anchor.
			if err := c.Store.PutManagerFinding(ctx, refreshed); err != nil {
				return err
			}
			continue
		}
		anchor := stored.Admission
		switch {
		case source != stored.Source:
			anchor.State, anchor.Reason, anchor.EvaluatedAt = admissionDeclined, "source_changed", c.now()
		case finding.State != "open":
			if liveAdmission(anchor.State) {
				anchor.State, anchor.Reason, anchor.EvaluatedAt = admissionDeclined, "finding_closed", c.now()
			}
		case anchor.Mode == "recommend" && finding.Revision != stored.Finding.Revision:
			// Recommend keeps its existing per-revision episode identity: a new
			// revision is a fresh admission for the same stable finding row.
			fresh := state.LocalManagerAdmission{State: admissionPending, ObservedAt: c.now(), EvaluatedAt: c.now(), BatchID: batch.BatchID, SandboxID: batch.SandboxID, RuleID: finding.RuleID}
			if policyState != nil {
				fresh.PolicyRevision = policyState.Manifest.PolicyRevision
				fresh.RunGeneration = policyState.Manifest.RunGeneration
				fresh.Mode = policyState.Manifest.Mode
			}
			if err := c.captureAdmissionAnchor(ctx, &fresh, finding, source, policyState); err != nil {
				return err
			}
			anchor = &fresh
		}
		refreshed.Admission = anchor
		if err := c.Store.PutManagerFinding(ctx, refreshed); err != nil {
			return err
		}
	}
	return nil
}

const (
	admissionPending  = "pending"
	admissionDeferred = "deferred"
	admissionAdmitted = "admitted"
	admissionDeclined = "declined"
)

func liveAdmission(value string) bool {
	return value == admissionPending || value == admissionDeferred
}

// validPolicyMode is the stable owner lineage predicate. Transient auto_steer
// qualification lives in AutoSteerPolicy and must not be treated as terminal.
func validPolicyMode(mode string) bool {
	return mode == "recommend" || mode == "auto_steer"
}

func admissionReservationID(batchID string, findingID string) string {
	return opaqueID("reservation_", batchID+"\x00"+findingID)
}

func admissionRequestID(batchID string, findingID string) string {
	return opaqueID("req_manager_", batchID+"\x00"+findingID)
}

// captureAdmissionTarget captures the node-authorized canonical target at the
// first observation, before any temporary policy or capability gate.
func (c *Coordinator) captureAdmissionTarget(ctx context.Context, finding model.InsightFindingV1, source model.InsightsManagerSourceV1) (*model.InsightsManagerTargetV1, string) {
	envelope, err := c.Control.GetInsightsManagerTarget(ctx, finding.FindingID, source.RegisteredSourceID)
	if err != nil || envelope.FormatVersion != 1 || envelope.FindingID != finding.FindingID ||
		envelope.FindingRevision != finding.Revision || envelope.Source != source ||
		envelope.Target.TeamID == "" || envelope.Target.MemberID == "" {
		return nil, "transport"
	}
	target := envelope.Target
	return &target, "captured"
}

// freshTaskWitness reports the current live member task only when the helper
// status is fresh and generation-bound. Missing or stale rows are unknown, not
// evidence of a terminal task.
func (c *Coordinator) freshTaskWitness(ctx context.Context, source model.InsightsManagerSourceV1) (*state.LocalManagedTaskAuthority, bool, error) {
	task, err := c.Store.ManagedTaskAuthority(ctx, source.ServiceRegistrationID)
	if err != nil {
		return nil, false, err
	}
	if task == nil || !task.Busy || task.TaskID == nil || task.TaskAttempt == nil ||
		task.ServiceGeneration != source.ServiceGeneration || task.SandboxGeneration != source.SandboxGeneration ||
		task.ObservedAt.After(c.now().Add(5*time.Second)) || c.now().Sub(task.ObservedAt) > 120*time.Second {
		return task, false, nil
	}
	return task, true, nil
}

// captureAdmissionAnchor persists the observation-time anchor: permanent Off or
// removed-rule conditions decline, an existing episode dedupes, and otherwise
// the canonical target or a fresh live-task witness anchors the episode.
func (c *Coordinator) captureAdmissionAnchor(ctx context.Context, anchor *state.LocalManagerAdmission, finding model.InsightFindingV1, source model.InsightsManagerSourceV1, policyState *state.LocalManagerPolicy) error {
	if policyState == nil {
		// A truly absent initial policy is not a temporary readiness gate: the
		// anchor declines explicitly and a later opt-in never revives it.
		anchor.State, anchor.Reason = admissionDeclined, "policy_absent"
		return nil
	}
	if policyState != nil && !validPolicyMode(policyState.Manifest.Mode) {
		anchor.State, anchor.Reason = admissionDeclined, "policy_off"
		return nil
	}
	if policyState != nil && !contains(policyState.Manifest.AllowedRules, finding.RuleID) {
		anchor.State, anchor.Reason = admissionDeclined, "rule_not_allowed"
		return nil
	}
	reservationID := admissionReservationID(anchor.BatchID, finding.FindingID)
	reservation, err := c.Store.ManagerReservation(ctx, reservationID)
	if err != nil {
		return err
	}
	if reservation != nil {
		anchor.State, anchor.Reason = admissionAdmitted, "existing_reservation"
		return nil
	}
	attempted, err := c.automaticEpisodeAttempt(ctx, source, finding.FindingID, finding.Revision, anchor.Mode)
	if err != nil {
		return err
	}
	if attempted {
		anchor.State, anchor.Reason = admissionAdmitted, "existing_episode"
		return nil
	}
	if captured, reason := c.captureAdmissionTarget(ctx, finding, source); captured != nil {
		anchor.Target, anchor.Reason = captured, reason
		return nil
	}
	task, fresh, err := c.freshTaskWitness(ctx, source)
	if err != nil {
		return err
	}
	if fresh {
		anchor.WitnessTaskID, anchor.WitnessTaskAttempt = task.TaskID, task.TaskAttempt
		anchor.WitnessObservedAt, anchor.Reason = task.ObservedAt, "witness_anchored"
		return nil
	}
	anchor.State, anchor.Reason = admissionDeclined, "unbound"
	return nil
}

// sameAdmissionTask compares only the immutable team/member/task identity of an
// anchor, including an explicit null task. Work/binding revisions are live
// authority and are not frozen by the anchor.
func sameAdmissionTask(anchor model.InsightsManagerTargetV1, target model.InsightsManagerTargetV1) bool {
	equal := func(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	equalInt := func(a, b *int64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	return anchor.TeamID == target.TeamID && anchor.MemberID == target.MemberID &&
		equal(anchor.TaskID, target.TaskID) && equalInt(anchor.TaskAttempt, target.TaskAttempt)
}

// automaticEpisodeAttempt applies each mode's backend rule: automatic
// auto_steer claims one attempt per stable findingId episode (revision- and
// policy-revision-immune, matching the backend episode lookup by
// sandbox+findingId), automatic recommend keeps its per-revision episode, and
// manual reservations are never counted as automatic attempts.
func (c *Coordinator) automaticEpisodeAttempt(ctx context.Context, source model.InsightsManagerSourceV1, findingID string, revision int64, mode string) (bool, error) {
	reservations, err := c.Store.ManagerReservations(ctx)
	if err != nil {
		return false, err
	}
	for i := range reservations {
		request := reservations[i].Request
		if request.Manual || request.FindingID != findingID || request.Source.RegisteredSourceID != source.RegisteredSourceID {
			continue
		}
		if mode == "auto_steer" {
			return true, nil
		}
		if request.FindingRevision == revision {
			return true, nil
		}
	}
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return false, err
	}
	for i := range runs {
		manifest := runs[i].Manifest
		if manifest.Manual || manifest.FindingID != findingID || manifest.Source.RegisteredSourceID != source.RegisteredSourceID {
			continue
		}
		if mode == "auto_steer" {
			return true, nil
		}
		if manifest.FindingRevision == revision {
			return true, nil
		}
	}
	return false, nil
}

// recoverAdmissions reconsiders deferred automatic admissions at the
// end-of-pass manager boundary. Only live (pending/deferred) anchors are
// retried; declined and admitted anchors are terminal for the stable finding
// episode, and legacy findings without an anchor are never backfilled.
func (c *Coordinator) recoverAdmissions(ctx context.Context) error {
	findings, err := c.Store.ManagerFindings(ctx)
	if err != nil {
		return err
	}
	for i := range findings {
		stored := &findings[i]
		if stored.Admission == nil || !liveAdmission(stored.Admission.State) {
			continue
		}
		if err := c.attemptAdmission(ctx, stored); err != nil {
			return err
		}
	}
	return nil
}

// attemptAdmission re-evaluates one durable anchor against the current policy
// lineage, lease, qualification, capability, service and canonical authority.
// Team/member/task/attempt are immutable; Work/binding comes from the current
// canonical target and is revalidated against the verified local registration.
func (c *Coordinator) attemptAdmission(ctx context.Context, stored *state.LocalManagerFinding) error {
	admission := stored.Admission
	if admission == nil || !liveAdmission(admission.State) {
		return nil
	}
	now := c.now()
	decline := func(reason string) error {
		admission.State, admission.Reason, admission.EvaluatedAt = admissionDeclined, reason, now
		return c.Store.PutManagerFinding(ctx, *stored)
	}
	deferAdmission := func(reason string) error {
		admission.State, admission.Reason, admission.EvaluatedAt = admissionDeferred, reason, now
		return c.Store.PutManagerFinding(ctx, *stored)
	}
	if stored.Finding.State != "open" {
		return decline("finding_closed")
	}
	reservationID := admissionReservationID(admission.BatchID, stored.Finding.FindingID)
	existing, err := c.Store.ManagerReservation(ctx, reservationID)
	if err != nil {
		return err
	}
	if existing != nil {
		admission.State, admission.Reason, admission.EvaluatedAt = admissionAdmitted, "existing_reservation", now
		return c.Store.PutManagerFinding(ctx, *stored)
	}
	// Stable observed sandbox resolves the policy authority without depending
	// on transient capability readiness.
	policyState, err := c.Store.ManagerPolicy(ctx, admission.SandboxID)
	if err != nil {
		return err
	}
	if policyState == nil {
		return deferAdmission("policy_pending")
	}
	policy := policyState.Manifest
	if !validPolicyMode(policy.Mode) {
		return decline("policy_off")
	}
	if admission.PolicyRevision == 0 || policy.PolicyRevision != admission.PolicyRevision || policy.RunGeneration != admission.RunGeneration || policy.Mode != admission.Mode {
		return decline("policy_changed")
	}
	if !contains(policy.AllowedRules, admission.RuleID) {
		return decline("rule_removed")
	}
	// Episode dedupe precedes any fresh canonical read or new attempt.
	attempted, err := c.automaticEpisodeAttempt(ctx, stored.Source, stored.Finding.FindingID, stored.Finding.Revision, admission.Mode)
	if err != nil {
		return err
	}
	if attempted {
		admission.State, admission.Reason, admission.EvaluatedAt = admissionAdmitted, "existing_episode", now
		return c.Store.PutManagerFinding(ctx, *stored)
	}
	if !now.Before(policy.ValidUntil) || policy.ValidUntil.Sub(now) > 120*time.Second {
		return deferAdmission("policy_window")
	}
	if !c.eligibleAutomatic(ctx, policy, stored.Source, stored.Finding) {
		return deferAdmission("limits")
	}
	capability, err := c.Store.ManagerCapability(ctx, stored.Source.RegisteredSourceID)
	if err != nil {
		return err
	}
	if capability == nil || !capability.Available {
		return deferAdmission("capability")
	}
	recipe := recipeForRule(stored.Finding.RuleID)
	if !contains(capability.RecipeIDs, recipe) {
		return deferAdmission("capability")
	}
	service, err := c.Store.ManagedService(ctx, stored.Source.ServiceRegistrationID)
	if err != nil {
		return err
	}
	if service == nil {
		return deferAdmission("service")
	}
	if policy.Mode == "auto_steer" {
		sandbox, err := c.Store.Sandbox(ctx, capability.SandboxID)
		if err != nil {
			return err
		}
		if !autoSteerQualified(policy, capability, sandbox) {
			return deferAdmission("qualification")
		}
	}
	envelope, err := c.Control.GetInsightsManagerTarget(ctx, stored.Finding.FindingID, stored.Source.RegisteredSourceID)
	if err != nil || envelope.FormatVersion != 1 || envelope.FindingID != stored.Finding.FindingID ||
		envelope.FindingRevision != stored.Finding.Revision || envelope.Source != stored.Source {
		return deferAdmission("transport")
	}
	target := envelope.Target
	if admission.Target == nil {
		// Witness-anchored capture (canonical was unavailable at observation):
		// only the exact observation-time task can complete the anchor.
		if admission.WitnessTaskID == nil || admission.WitnessTaskAttempt == nil ||
			target.TaskID == nil || target.TaskAttempt == nil ||
			*target.TaskID != *admission.WitnessTaskID || *target.TaskAttempt != *admission.WitnessTaskAttempt {
			return decline("task_changed")
		}
		identity := target
		admission.Target = &identity
	} else if !sameAdmissionTask(*admission.Target, target) {
		return decline("task_changed")
	}
	if err := c.localWorkAuthority(ctx, stored.Source, target); err != nil {
		return deferAdmission("work_pending")
	}
	if err := c.localBusyTaskConsistency(ctx, stored.Source, target); err != nil {
		return deferAdmission("task_unknown")
	}
	expiresIn := int(policy.ValidUntil.Sub(now).Seconds())
	if expiresIn > 120 {
		expiresIn = 120
	}
	if expiresIn < 1 {
		return deferAdmission("policy_window")
	}
	request := model.InsightsManagerReservationRequestV1{FormatVersion: 1, ReservationID: reservationID, RequestID: admissionRequestID(admission.BatchID, stored.Finding.FindingID), Manual: false, FindingID: stored.Finding.FindingID, FindingRevision: stored.Finding.Revision, PolicyRevision: policy.PolicyRevision, RuleID: admission.RuleID, RecipeID: recipe, ProviderRouteDigest: capability.ProviderRouteDigest, Source: stored.Source, Target: target, Budget: model.InsightsManagerBudgetV1{ModelRequests: policy.EffectiveLimits.PerRunModelRequests, InputTokens: policy.EffectiveLimits.PerRunInputTokens, OutputTokens: policy.EffectiveLimits.PerRunOutputTokens}, ExpiresInSeconds: expiresIn}
	intent := state.LocalManagerReservation{Request: request, Phase: "pending"}
	if err := c.Store.PutManagerReservation(ctx, intent); err != nil {
		return err
	}
	admission.State, admission.Reason, admission.EvaluatedAt = admissionAdmitted, "admitted", now
	if err := c.Store.PutManagerFinding(ctx, *stored); err != nil {
		return err
	}
	return c.completeAutomaticReservation(ctx, &intent)
}

func (c *Coordinator) canonicalDescriptorTarget(ctx context.Context, finding model.InsightFindingV1, source model.InsightsManagerSourceV1, service *state.LocalManagedService) (model.InsightsManagerTargetV1, error) {
	envelope, err := c.Control.GetInsightsManagerTarget(ctx, finding.FindingID, source.RegisteredSourceID)
	if err != nil {
		return model.InsightsManagerTargetV1{}, err
	}
	if envelope.FormatVersion != 1 || envelope.FindingID != finding.FindingID || envelope.FindingRevision != finding.Revision || envelope.Source != source {
		return model.InsightsManagerTargetV1{}, errors.New("manager canonical descriptor authority changed")
	}
	target := envelope.Target
	if target.TeamID != service.Manifest.Identity.TeamID || target.MemberID != service.Manifest.Identity.MemberID {
		return model.InsightsManagerTargetV1{}, errors.New("manager canonical target service changed")
	}
	if err := c.localWorkAuthority(ctx, source, target); err != nil {
		return model.InsightsManagerTargetV1{}, err
	}
	if err := c.localBusyTaskConsistency(ctx, source, target); err != nil {
		return model.InsightsManagerTargetV1{}, err
	}
	return target, nil
}

// staleReserveRefusal reports whether the control plane refused an automatic
// reservation with a definitive typed stale condition (stale source or stale
// canonical target). Unrecognized 409s and transport errors are not stale.
func staleReserveRefusal(err error) bool {
	var responseErr *api.ResponseError
	return errors.As(err, &responseErr) && responseErr.Status == 409 &&
		(responseErr.Code == "manager_source_stale" || responseErr.Code == "manager_target_stale")
}

// settleUnreservedSourceStale retires a PENDING AUTOMATIC reservation that the
// control plane refused with a definitive typed stale condition (source or
// canonical target) and that never created a backend reservation, run or
// provider execution: the
// intent keeps its request intact as evidence and only moves to the terminal
// "unused" phase so the pass can complete and the source can refresh. A manual
// intent, a non-pending intent, an existing reservation, an existing local run
// for the same reservation or request, and every other refusal fail closed and
// keep the original error.
func (c *Coordinator) settleUnreservedSourceStale(ctx context.Context, intent *state.LocalManagerReservation, cause error) (bool, error) {
	if !staleReserveRefusal(cause) || intent.Phase != "pending" || intent.Request.Manual || intent.Reservation != nil {
		return false, nil
	}
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return false, err
	}
	for i := range runs {
		if runs[i].Manifest.ReservationID == intent.Request.ReservationID ||
			runs[i].ReservationRequest != nil && runs[i].ReservationRequest.ReservationID == intent.Request.ReservationID {
			return false, nil
		}
	}
	intent.Phase = "unused"
	if err := c.Store.PutManagerReservation(ctx, *intent); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Coordinator) completeAutomaticReservation(ctx context.Context, intent *state.LocalManagerReservation) error {
	request := intent.Request
	// The persisted request is immutable: recovery replays the exact stored
	// body and IDs and never recomputes or retargets it. A fresh canonical
	// comparison is enforced by localTargetAuthority before any paid/native
	// effect.
	storedCapability, err := c.Store.ManagerCapability(ctx, request.Source.RegisteredSourceID)
	if err != nil || storedCapability == nil {
		return errors.Join(err, errors.New("manager reservation source catalog is unavailable"))
	}
	policy, err := c.Store.ManagerPolicy(ctx, storedCapability.SandboxID)
	if err != nil || policy == nil || policy.Manifest.PolicyRevision != request.PolicyRevision {
		return errors.Join(err, errors.New("manager reservation policy authority is unavailable"))
	}
	if intent.Reservation == nil {
		reservation, reserveErr := c.Control.ReserveInsightsManagerReview(ctx, request)
		if reserveErr != nil {
			settled, settleErr := c.settleUnreservedSourceStale(ctx, intent, reserveErr)
			if settleErr != nil {
				return settleErr
			}
			if settled {
				return nil
			}
			return reserveErr
		}
		if !reservationMatches(request, reservation, c.now()) || reservation.Execution.ManagerProfile != policy.Manifest.ManagerProfile ||
			!validReservationRemaining(reservation.Remaining) {
			return errors.New("manager reservation response changed request authority")
		}
		intent.Reservation = &reservation
		intent.Phase = "reserved"
		if err := c.Store.PutManagerReservation(ctx, *intent); err != nil {
			return err
		}
	}
	reservation := *intent.Reservation
	review := model.InsightsManagerReviewManifestV1{FormatVersion: 1, ReservationID: reservation.ReservationID, RunID: reservation.RunID, Manual: false, FindingID: request.FindingID, FindingRevision: request.FindingRevision, PolicyRevision: request.PolicyRevision, RuleID: request.RuleID, RecipeID: request.RecipeID, ProviderRouteDigest: reservation.Execution.ProviderRouteDigest, ManagerProfile: reservation.Execution.ManagerProfile, Source: request.Source, Target: request.Target, Budget: reservation.ReservedBudget, ValidUntil: reservation.ExpiresAt}
	prior, err := c.Store.ManagerRun(ctx, review.RunID)
	if err != nil {
		return err
	}
	if prior != nil {
		if err := c.acceptExistingRun(ctx, prior, review); err != nil {
			return err
		}
		intent.Phase = "applied"
		return c.Store.PutManagerReservation(ctx, *intent)
	}
	if !reviewPolicyModeValid(policy.Manifest) || !c.now().Before(policy.Manifest.ValidUntil) {
		code := "policy_off"
		if policy.Manifest.Mode != "off" && !c.now().Before(policy.Manifest.ValidUntil) {
			code = "policy_expired"
		}
		return c.settleReservedWithoutExecution(ctx, intent, review, code)
	}
	capability, evidence, err := c.reviewAuthority(ctx, review, true)
	if err != nil {
		return c.settleReservedWithoutExecution(ctx, intent, review, "source_stale")
	}
	run := state.LocalManagerRun{Manifest: review, ReservationRequest: &request, Reservation: &reservation, Phase: "start_ack_pending", Capability: *capability, DispatchStarted: false, StartedAt: c.now(), AutomaticOrigin: !review.Manual, OriginRunGeneration: policy.Manifest.RunGeneration, OriginValidUntil: review.ValidUntil}
	if err := c.Store.PutManagerRun(ctx, run); err != nil {
		return err
	}
	intent.Phase = "applied"
	if err := c.Store.PutManagerReservation(ctx, *intent); err != nil {
		return err
	}
	return c.startAcknowledgedReview(ctx, &run, evidence)
}

func (c *Coordinator) settleReservedWithoutExecution(ctx context.Context, intent *state.LocalManagerReservation, review model.InsightsManagerReviewManifestV1, code string) error {
	report := model.InsightsManagerRunReportV1{FormatVersion: 1, ReservationID: review.ReservationID, RunID: review.RunID,
		Manual: false, State: "failed", PolicyRevision: review.PolicyRevision, Source: review.Source, Target: review.Target,
		Usage: model.InsightsManagerUsageV1{UsageCertain: true, UnusedProof: "trusted_zero_start"}, ErrorCode: &code}
	report.ReceiptDigest = digestJSON(report)
	run := state.LocalManagerRun{Manifest: review, ReservationRequest: &intent.Request, Reservation: intent.Reservation,
		Phase: "report_pending", Report: &report, StartedAt: c.now()}
	if err := c.Store.PutManagerRun(ctx, run); err != nil {
		return err
	}
	intent.Phase = "applied"
	if err := c.Store.PutManagerReservation(ctx, *intent); err != nil {
		return err
	}
	return c.submitRunReport(ctx, &run)
}

func (c *Coordinator) eligibleAutomatic(ctx context.Context, policy model.InsightsManagerPolicyManifestV1, source model.InsightsManagerSourceV1, finding model.InsightFindingV1) bool {
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return false
	}
	active, serverHourly, sandboxHourly, sandboxDaily, sessionDaily := 0, 0, 0, 0, 0
	var sandboxInput, sandboxOutput int64
	now := c.now()
	for _, run := range runs {
		if run.Manifest.FindingID == finding.FindingID && run.Manifest.FindingRevision == finding.Revision {
			return false
		}
		age := now.Sub(run.StartedAt)
		if !run.StartedAt.IsZero() && age >= 0 && age <= time.Hour {
			serverHourly++
		}
		if run.Phase == "start_ack_pending" || run.Phase == "dispatching" || run.Phase == "execution_unknown" || run.Phase == "reviewing" {
			active++
		}
		runSandbox := run.Capability.SandboxID
		if runSandbox == policy.SandboxID && !run.StartedAt.IsZero() && age >= 0 && age < 24*time.Hour {
			sandboxDaily++
			if age <= time.Hour {
				sandboxHourly++
			}
			sandboxInput += run.Manifest.Budget.InputTokens
			sandboxOutput += run.Manifest.Budget.OutputTokens
		}
		if run.Manifest.Source.NativeSessionID == source.NativeSessionID && !run.StartedAt.IsZero() && age >= 0 && age < 24*time.Hour {
			sessionDaily++
			if age < time.Duration(policy.EffectiveLimits.SessionCooldownSeconds)*time.Second {
				return false
			}
		}
	}
	limits := policy.EffectiveLimits
	return active < limits.ServerConcurrentRuns && serverHourly < limits.ServerHourlyStarts &&
		sandboxHourly < limits.SandboxHourlyRuns && sandboxDaily < min(policy.DailyRunLimit, limits.SandboxDailyRuns) &&
		sessionDaily < limits.SessionRuns24h && sandboxInput+limits.PerRunInputTokens <= policy.DailyInputTokenLimit &&
		sandboxOutput+limits.PerRunOutputTokens <= policy.DailyOutputTokenLimit
}

func (c *Coordinator) applyTakeover(ctx context.Context, manifest model.InsightsTakeoverManifestV1) error {
	if err := model.ValidateInsightsTakeoverManifest(manifest); err != nil {
		return err
	}
	prior, err := c.Store.ManagerTakeover(ctx, manifest.OperationID)
	if err != nil {
		return err
	}
	var renewal *state.LocalManagerTakeover
	if prior != nil {
		if reflect.DeepEqual(prior.Manifest, manifest) {
			return nil
		}
		if !sameTakeoverAuthority(prior.Manifest, manifest) || !manifest.ValidUntil.After(prior.Manifest.ValidUntil) || manifest.Action != "pause_manager_and_hold_member" {
			return state.ErrManagerConflict
		}
		renewal = prior
	}
	if err := c.takeoverAuthority(ctx, manifest); err != nil {
		return err
	}
	if renewal != nil {
		renewal.Manifest = manifest
		renewal.Phase = "acquiring"
		renewal.Report = nil
		if err := c.Store.PutManagerTakeover(ctx, *renewal); err != nil {
			return err
		}
		return c.dispatchTakeover(ctx, renewal, "acquire_intervention_hold")
	}
	value := state.LocalManagerTakeover{Manifest: manifest, Phase: map[bool]string{true: "releasing", false: "acquiring"}[manifest.Action == "resume_manager_and_release_member"], DispatchStarted: true}
	if err := c.Store.PutManagerTakeover(ctx, value); err != nil {
		return err
	}
	return c.dispatchTakeover(ctx, &value, map[bool]string{true: "release_intervention_hold", false: "acquire_intervention_hold"}[manifest.Action == "resume_manager_and_release_member"])
}

func sameTakeoverAuthority(left, right model.InsightsTakeoverManifestV1) bool {
	left.ValidUntil, right.ValidUntil = time.Time{}, time.Time{}
	return reflect.DeepEqual(left, right)
}

// takeoverAuthority is the shared local authority boundary for applying a
// takeover and renewing an already dispatched protective Pause. It does not
// persist an operation, dispatch a helper action, or change the current policy.
func (c *Coordinator) takeoverAuthority(ctx context.Context, manifest model.InsightsTakeoverManifestV1) error {
	policy, err := c.Store.ManagerPolicy(ctx, sourceSandbox(ctx, c.Store, manifest.Source))
	policyModeAllowed := policy != nil && (policy.Manifest.Mode == "off" ||
		manifest.Action == "resume_manager_and_release_member" && policy.Manifest.Mode == "recommend")
	if err != nil || policy == nil || !policyModeAllowed || policy.Manifest.PolicyRevision != manifest.PolicyRevision ||
		policy.Manifest.RunGeneration != manifest.RunGeneration {
		return errors.Join(err, errors.New("takeover requires exact current policy authority"))
	}
	var predecessor *state.LocalManagerTakeover
	if manifest.Action == "resume_manager_and_release_member" {
		predecessor, err = c.Store.ManagerTakeover(ctx, *manifest.PredecessorOperationID)
		if err != nil || predecessor == nil || predecessor.Report == nil || predecessor.Report.PendingInput.State == "unknown" || predecessor.Report.Status != "ready" {
			return errors.Join(err, errors.New("takeover predecessor is unsettled"))
		}
		if predecessor.Manifest.HoldID != manifest.HoldID || predecessor.Manifest.HoldRevision+1 != manifest.HoldRevision ||
			predecessor.Manifest.PolicyRevision+1 != manifest.PolicyRevision || predecessor.Manifest.RunGeneration+1 != manifest.RunGeneration ||
			predecessor.Manifest.FindingID != manifest.FindingID || predecessor.Manifest.FindingRevision != manifest.FindingRevision ||
			predecessor.Manifest.Source != manifest.Source || predecessor.Manifest.Target.TeamID != manifest.Target.TeamID ||
			predecessor.Manifest.Target.MemberID != manifest.Target.MemberID || !sameOptionalWork(predecessor.Manifest.Target, manifest.Target) {
			return errors.New("takeover Resume changed predecessor authority")
		}
	}
	// The authenticated backend owner manifest supplies exact finding authority.
	// Runtime independently checks its current local source, service and target.
	if _, err := c.localSourceAuthority(ctx, manifest.Source); err != nil {
		return err
	}
	if err := c.localServiceAuthority(ctx, manifest.Source, manifest.Target); err != nil {
		return err
	}
	if err := c.localTargetAuthority(ctx, manifest.FindingID, manifest.FindingRevision, manifest.Source, manifest.Target); err != nil {
		return err
	}
	return nil
}

func (c *Coordinator) dispatchTakeover(ctx context.Context, value *state.LocalManagerTakeover, action string) error {
	sandboxID, instance, err := c.helperTarget(ctx, value.Manifest.Source)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"formatVersion": 1, "action": action, "instance": instance, "manifest": value.Manifest})
	output, _, err := c.Helper.ExecManager(ctx, sandboxID, payload)
	if err != nil {
		// Preserve the effect class across every dispatch and observation
		// failure: a Resume that may have been released stays release_unknown,
		// never acquire_unknown, so recovery cannot relabel a lost release.
		if value.Manifest.Action == "resume_manager_and_release_member" {
			value.Phase = "release_unknown"
		} else {
			value.Phase = "acquire_unknown"
		}
		_ = c.Store.PutManagerTakeover(ctx, *value)
		return err
	}
	return c.completeTakeover(ctx, value, output, action)
}
func (c *Coordinator) reconcileTakeover(ctx context.Context, value *state.LocalManagerTakeover) error {
	return c.dispatchTakeover(ctx, value, "reconcile_intervention_hold")
}
func (c *Coordinator) completeTakeover(ctx context.Context, value *state.LocalManagerTakeover, payload []byte, helperAction string) error {
	var receipt takeoverHelperReceipt
	if err := decodeClosed(payload, &receipt); err != nil {
		return err
	}
	if receipt.FormatVersion != 1 || receipt.Action != helperAction || receipt.OperationID != value.Manifest.OperationID ||
		!reflect.DeepEqual(receipt.PredecessorOperationID, value.Manifest.PredecessorOperationID) ||
		receipt.FindingID != value.Manifest.FindingID || receipt.FindingRevision != value.Manifest.FindingRevision ||
		receipt.HoldID != value.Manifest.HoldID || receipt.HoldRevision != value.Manifest.HoldRevision ||
		receipt.HoldState != value.Manifest.HoldState || receipt.PolicyRevision != value.Manifest.PolicyRevision ||
		receipt.RunGeneration != value.Manifest.RunGeneration || receipt.Source != value.Manifest.Source ||
		!reflectTarget(receipt.Target, value.Manifest.Target) || !receipt.ValidUntil.Equal(value.Manifest.ValidUntil) ||
		receipt.ErrorCode != nil || !digestPattern.MatchString(receipt.ReceiptDigest) {
		return errors.New("intervention hold receipt changed authority")
	}
	if receipt.Status != "active" && receipt.Status != "released" && receipt.Status != "unsettled" ||
		receipt.Status == "unsettled" && receipt.PendingInput.State != "unknown" ||
		receipt.Status != "unsettled" && receipt.PendingInput.State == "unknown" {
		return errors.New("intervention hold receipt pending-input state is invalid")
	}
	status := "ready"
	if receipt.Status != "active" && receipt.Status != "released" {
		status = receipt.Status
	}
	report := model.InsightsTakeoverReportV1{FormatVersion: 1, OperationID: value.Manifest.OperationID, PredecessorOperationID: value.Manifest.PredecessorOperationID, Action: value.Manifest.Action, FindingID: value.Manifest.FindingID, FindingRevision: value.Manifest.FindingRevision, PolicyRevision: value.Manifest.PolicyRevision, RunGeneration: value.Manifest.RunGeneration, HoldID: value.Manifest.HoldID, HoldRevision: value.Manifest.HoldRevision, HoldState: value.Manifest.HoldState, Source: value.Manifest.Source, Target: value.Manifest.Target, Status: status, PendingInput: receipt.PendingInput, ReceiptDigest: receipt.ReceiptDigest}
	value.Phase = status
	if receipt.Status == "released" {
		// Helper/local lifecycle records use released; the canonical node
		// report represents a completed pause or release with status ready.
		value.Phase = "released"
	}
	value.Report = &report
	return c.Store.PutManagerTakeover(ctx, *value)
}

func decodeClosed(payload []byte, target any) error {
	if len(payload) == 0 || len(payload) > 64*1024 {
		return errors.New("manager helper output is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("manager helper output has trailing data")
	}
	return nil
}
func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}
func digestJSON(value any) string {
	payload, _ := json.Marshal(value)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}
func opaqueID(prefix, value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%s%x", prefix, sum[:12])
}
func managerSourceID(runID string) string { return opaqueID("manager_", runID) }
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func recipeForRule(rule string) string {
	switch rule {
	case "repeated_identical_failure@1":
		return "inspect_first_failure@1"
	case "repeated_identical_call@1":
		return "check_repeated_operation@1"
	case "empty_result_loop@1":
		return "refine_query@1"
	default:
		return "inspect_active_phase@1"
	}
}
func managerFindingEvidence(value state.LocalManagerFinding) map[string]any {
	return map[string]any{"findingId": value.Finding.FindingID, "findingRevision": value.Finding.Revision, "journalGeneration": value.JournalGeneration, "ruleId": value.Finding.RuleID, "nativeSessionId": value.Source.NativeSessionID, "firstSequence": value.Finding.FirstSequence, "lastSequence": value.Finding.LastSequence, "count": value.Finding.Count, "matchedCallIds": value.Finding.MatchedCallIDs, "coverage": value.Finding.Coverage, "firstObservedAt": value.Finding.FirstObservedAt, "lastObservedAt": value.Finding.LastObservedAt, "toolCategory": value.Finding.ToolCategory, "phase": value.Finding.Phase}
}

func managerFindingEvidenceV1(value model.InsightsManagerFindingEvidenceV1) map[string]any {
	return map[string]any{"findingId": value.FindingID, "findingRevision": value.FindingRevision, "journalGeneration": value.JournalGeneration,
		"ruleId": value.RuleID, "nativeSessionId": value.NativeSessionID, "firstSequence": value.FirstSequence,
		"lastSequence": value.LastSequence, "count": value.Count, "matchedCallIds": value.MatchedCallIDs,
		"coverage": value.Coverage, "firstObservedAt": value.FirstObservedAt, "lastObservedAt": value.LastObservedAt,
		"toolCategory": value.ToolCategory, "phase": value.Phase}
}
func managerCapabilityWire(value state.LocalManagerCapability) map[string]any {
	return map[string]any{"nativeVersion": value.NativeVersion, "nativeSourceRevision": value.NativeSourceRevision, "protocol": value.Protocol, "nativeProtocol": value.NativeProtocol, "providerId": value.ProviderID, "modelId": value.ModelID, "providerRouteDigest": value.ProviderRouteDigest, "recipeIds": value.RecipeIDs, "managerPluginDigest": value.ManagerPluginDigest, "maxInputTokens": value.MaxInputTokens, "maxOutputTokens": value.MaxOutputTokens, "finalRequestMaxBytes": value.FinalRequestMaxBytes, "toolsAllowed": value.ToolsAllowed, "mediaAllowed": value.MediaAllowed, "hardOutputTokenLimit": value.HardOutputTokenLimit, "available": value.Available, "reason": func() any {
		if value.Reason == "" {
			return nil
		}
		return value.Reason
	}()}
}
func managerRunGeneration(ctx context.Context, store *state.Store, source model.InsightsManagerSourceV1) int64 {
	sandbox := sourceSandbox(ctx, store, source)
	policy, _ := store.ManagerPolicy(ctx, sandbox)
	if policy == nil {
		return 0
	}
	return policy.Manifest.RunGeneration
}
func sourceSandbox(ctx context.Context, store *state.Store, source model.InsightsManagerSourceV1) string {
	local, _ := store.ContinuitySource(ctx, source.RegisteredSourceID)
	if local == nil {
		return ""
	}
	return local.Report.SandboxID
}

func (c *Coordinator) helperTarget(ctx context.Context, source model.InsightsManagerSourceV1) (string, string, error) {
	local, err := c.Store.ContinuitySource(ctx, source.RegisteredSourceID)
	if err != nil || local == nil || local.Report.SandboxID == "" || local.Instance == "" {
		return "", "", errors.Join(err, errors.New("manager helper target is unavailable"))
	}
	return local.Report.SandboxID, local.Instance, nil
}
func reservationMatches(request model.InsightsManagerReservationRequestV1, value model.InsightsManagerReservationV1, now time.Time) bool {
	return value.FormatVersion == 1 && value.ReservationID == request.ReservationID && value.RequestID == request.RequestID && !value.Manual && value.State == "reserved" && value.FindingID == request.FindingID && value.FindingRevision == request.FindingRevision && value.PolicyRevision == request.PolicyRevision && value.Source == request.Source && reflectTarget(value.Target, request.Target) && value.ReservedBudget == request.Budget && value.ExpiresAt.After(now) && value.ExpiresAt.Sub(now) <= 120*time.Second && value.Execution.ProviderRouteDigest == request.ProviderRouteDigest && validProfile(value.Execution.ManagerProfile)
}
func validReservationRemaining(value model.InsightsManagerRemainingV1) bool {
	return value.SandboxDailyRuns >= 0 && value.SandboxHourlyRuns >= 0 && value.SandboxDailyInputTokens >= 0 &&
		value.SandboxDailyOutputTokens >= 0 && value.SessionRuns24h >= 0 && value.SessionCooldownSeconds >= 0 &&
		value.ServerConcurrentRuns >= 0 && value.ServerHourlyStarts >= 0
}
func validProfile(value model.InsightsManagerProfileV1) bool {
	return value.ProfileID == "warpmetal-insights-manager" && value.ProfileRevision > 0 && digestPattern.MatchString(value.ProfileDigest)
}
func reflectTarget(left, right model.InsightsManagerTargetV1) bool {
	payloadLeft, _ := json.Marshal(left)
	payloadRight, _ := json.Marshal(right)
	return bytes.Equal(payloadLeft, payloadRight)
}
func sameOptionalWork(left, right model.InsightsManagerTargetV1) bool {
	return reflect.DeepEqual(left.WorkID, right.WorkID) && reflect.DeepEqual(left.WorkRevision, right.WorkRevision) &&
		reflect.DeepEqual(left.BindingID, right.BindingID) && reflect.DeepEqual(left.BindingRevision, right.BindingRevision)
}
func closedRunError(code string) string {
	switch code {
	case "policy_off", "policy_expired", "source_stale", "target_stale", "budget_exhausted", "capability_unavailable", "provider_failed", "provider_timeout", "usage_uncertain", "report_invalid", "superseded", "pending_input_unknown", "runtime_unavailable":
		return code
	default:
		return "runtime_unavailable"
	}
}
