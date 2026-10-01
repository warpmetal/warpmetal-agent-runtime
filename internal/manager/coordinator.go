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
	FormatVersion             int                             `json:"formatVersion"`
	Action                    string                          `json:"action"`
	Status                    string                          `json:"status"`
	ReservationID             string                          `json:"reservationId"`
	RunID                     string                          `json:"runId"`
	ModelRequests             int                             `json:"modelRequests"`
	ReservedInputTokens       int64                           `json:"reservedInputTokens"`
	ReservedOutputTokens      int64                           `json:"reservedOutputTokens"`
	ManagerRegisteredSourceID string                          `json:"managerRegisteredSourceId"`
	ManagerSession            *model.InsightsManagerSessionV1 `json:"managerSession"`
	ProposalDigest            *string                         `json:"proposalDigest"`
	GuidanceReceipt           *struct {
		FormatVersion     int     `json:"formatVersion"`
		Mode              string  `json:"mode"`
		Status            string  `json:"status"`
		AtomicNativeGuard bool    `json:"atomicNativeGuard"`
		AutoSteer         bool    `json:"autoSteer"`
		GuidanceDigest    string  `json:"guidanceDigest"`
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
		case "execution_unknown":
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
		if takeovers[i].Phase != "acquire_unknown" && takeovers[i].Phase != "release_unknown" {
			continue
		}
		if err := c.reconcileTakeover(ctx, &takeovers[i]); err != nil {
			return err
		}
	}
	return nil
}

// Reports derives the manager policy reports for the node report.
// staleSources is the report assembly's single freshness decision: every
// capability item that references a source in that set is derived as the
// fail-closed unavailable pair the node API admits for a stale source
// (available=false, reason=source_unavailable), while a genuinely fresh
// re-observation keeps the ordinary available derivation.
func (c *Coordinator) Reports(ctx context.Context, staleSources continuity.StaleSourceSet) ([]model.InsightsManagerPolicyReportV1, []model.InsightsManagerRunReportV1, []model.InsightsTakeoverReportV1, error) {
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
		report := value.Report
		if derived, deriveErr := c.policyReport(ctx, value.Manifest); deriveErr == nil {
			report = derived
		}
		// The stale derivation is applied to the exact report being serialized,
		// including the cached fallback, so a derivation outage cannot replay an
		// available capability for a source this report already publishes stale.
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
		if !superseded {
			holdReports = append(holdReports, *value.Report)
		}
	}
	return policyReports, runReports, holdReports, nil
}

func (c *Coordinator) applyPolicy(ctx context.Context, policy model.InsightsManagerPolicyManifestV1) error {
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
		var reasonPointer *string
		if reason != "" {
			value := reason
			reasonPointer = &value
		}
		reports = append(reports, model.InsightsManagerRecommendCapabilityV1{Source: model.InsightsManagerSourceV1{RegisteredSourceID: capability.RegisteredSourceID, WorkspaceEpoch: capability.WorkspaceEpoch, NativeSessionID: capability.NativeSessionID, ServiceRegistrationID: capability.ServiceRegistrationID, ServiceGeneration: capability.ServiceGeneration, SandboxGeneration: capability.SandboxGeneration, ProfileRevision: capability.ProfileRevision, InstructionRevision: capability.InstructionRevision}, ProviderRouteDigest: capability.ProviderRouteDigest, ProviderID: capability.ProviderID, ModelID: capability.ModelID, Protocol: capability.Protocol, RecipeIDs: append([]string(nil), capability.RecipeIDs...), MaxInputTokens: capability.MaxInputTokens, MaxOutputTokens: capability.MaxOutputTokens, ToolsAllowed: capability.ToolsAllowed, MediaAllowed: capability.MediaAllowed, ManagerProfile: capability.ManagerProfile, Available: available, Reason: reasonPointer})
	}
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].Source.RegisteredSourceID < reports[j].Source.RegisteredSourceID
	})
	if len(reports) > 8 {
		reports = reports[:8]
	}
	report := model.InsightsManagerPolicyReportV1{FormatVersion: 1, SandboxID: policy.SandboxID, SandboxGeneration: policy.SandboxGeneration, PolicyRevision: policy.PolicyRevision, RunGeneration: policy.RunGeneration, Status: "applied", Recommend: c.policyRollup(policy, reports), RecommendCapabilities: reports}
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
	capability, finding, err := c.reviewAuthority(ctx, review, true)
	if err != nil {
		return err
	}
	run := state.LocalManagerRun{Manifest: review, Phase: "dispatching", Capability: *capability, DispatchStarted: true, StartedAt: c.now()}
	if err := c.Store.PutManagerRun(ctx, run); err != nil {
		return err
	}
	return c.dispatchReview(ctx, &run, *finding, "start_review")
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

func (c *Coordinator) reviewAuthority(ctx context.Context, review model.InsightsManagerReviewManifestV1, requireFresh bool) (*state.LocalManagerCapability, *state.LocalManagerFinding, error) {
	if requireFresh && (!c.now().Before(review.ValidUntil) || review.ValidUntil.Sub(c.now()) > 120*time.Second) {
		return nil, nil, errors.New("manager review authority expired")
	}
	source, err := c.localSourceAuthority(ctx, review.Source)
	if err != nil {
		return nil, nil, err
	}
	if requireFresh {
		policy, err := c.Store.ManagerPolicy(ctx, source.Report.SandboxID)
		if err != nil || policy == nil || policy.Manifest.Mode != "recommend" || policy.Manifest.PolicyRevision != review.PolicyRevision ||
			!c.now().Before(policy.Manifest.ValidUntil) || policy.Manifest.ManagerProfile != review.ManagerProfile {
			return nil, nil, errors.Join(err, errors.New("manager review policy authority changed"))
		}
	}
	if err := c.localServiceAuthority(ctx, review.Source, review.Target); err != nil {
		return nil, nil, err
	}
	capability, err := c.Store.ManagerCapability(ctx, review.Source.RegisteredSourceID)
	if err != nil || capability == nil || !capability.Available || capability.ProviderRouteDigest != review.ProviderRouteDigest || capability.ManagerProfile != review.ManagerProfile || capability.ServiceGeneration != review.Source.ServiceGeneration || capability.WorkspaceEpoch != review.Source.WorkspaceEpoch || capability.NativeSessionID != review.Source.NativeSessionID || capability.ProfileRevision != review.Source.ProfileRevision || capability.InstructionRevision != review.Source.InstructionRevision {
		return nil, nil, errors.Join(err, errors.New("manager capability authority changed"))
	}
	if !contains(capability.RecipeIDs, review.RecipeID) {
		return nil, nil, errors.New("manager recipe unavailable")
	}
	finding, err := c.Store.ManagerFinding(ctx, review.FindingID)
	if err != nil || finding == nil || !finding.Acknowledged || finding.Finding.Revision != review.FindingRevision || finding.Finding.RuleID != review.RuleID || finding.PolicyRevision != review.PolicyRevision || finding.Source != review.Source {
		return nil, nil, errors.Join(err, errors.New("manager finding authority changed"))
	}
	if err := c.localTargetAuthority(ctx, review.Source, review.Target); err != nil {
		return nil, nil, err
	}
	return capability, finding, nil
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

func (c *Coordinator) localTargetAuthority(ctx context.Context, source model.InsightsManagerSourceV1, target model.InsightsManagerTargetV1) error {
	if target.TaskID != nil {
		task, err := c.Store.ManagedTaskAuthority(ctx, source.ServiceRegistrationID)
		if err != nil || task == nil || !task.Busy || task.TaskID == nil || task.TaskAttempt == nil ||
			task.ServiceGeneration != source.ServiceGeneration || task.SandboxGeneration != source.SandboxGeneration ||
			*task.TaskID != *target.TaskID || *task.TaskAttempt != *target.TaskAttempt ||
			task.ObservedAt.After(c.now().Add(5*time.Second)) || c.now().Sub(task.ObservedAt) > 120*time.Second {
			return errors.Join(err, errors.New("manager task authority changed"))
		}
	}
	if target.WorkID != nil {
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
			registration.ServiceGeneration != source.ServiceGeneration ||
			(target.TaskID != nil && (registration.Manifest.Identity.TaskID == nil || registration.Manifest.Identity.TaskAttempt == nil ||
				*registration.Manifest.Identity.TaskID != *target.TaskID || *registration.Manifest.Identity.TaskAttempt != *target.TaskAttempt)) {
			return errors.Join(err, errors.New("manager Work binding authority changed"))
		}
	}
	return nil
}

func (c *Coordinator) dispatchReview(ctx context.Context, run *state.LocalManagerRun, finding state.LocalManagerFinding, action string) error {
	sandboxID, instance, err := c.helperTarget(ctx, run.Manifest.Source)
	if err != nil {
		return err
	}
	request := map[string]any{"formatVersion": 1, "action": action, "instance": instance, "authority": run.Manifest, "finding": managerFindingEvidence(finding), "capability": managerCapabilityWire(run.Capability)}
	if action != "start_review" {
		request = map[string]any{"formatVersion": 1, "action": action, "instance": instance, "reservationId": run.Manifest.ReservationID, "runId": run.Manifest.RunID, "policyRevision": run.Manifest.PolicyRevision, "runGeneration": managerRunGeneration(ctx, c.Store, run.Manifest.Source), "source": run.Manifest.Source}
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

func (c *Coordinator) resumeRun(ctx context.Context, run *state.LocalManagerRun, action string) error {
	finding, err := c.Store.ManagerFinding(ctx, run.Manifest.FindingID)
	if err != nil || finding == nil {
		return errors.Join(err, errors.New("manager recovery finding missing"))
	}
	return c.dispatchReview(ctx, run, *finding, action)
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
	if receipt.Status != "recommended" && receipt.Status != "needs_owner" && receipt.Status != "failed" {
		return errors.New("manager helper status is invalid")
	}
	if receipt.ModelRequests < 0 || receipt.ModelRequests > run.Manifest.Budget.ModelRequests || receipt.ReservedInputTokens < 0 || receipt.ReservedInputTokens > run.Manifest.Budget.InputTokens || receipt.ReservedOutputTokens < 0 || receipt.ReservedOutputTokens > run.Manifest.Budget.OutputTokens {
		return errors.New("manager helper exceeded reserved budget")
	}
	report := model.InsightsManagerRunReportV1{FormatVersion: 1, ReservationID: run.Manifest.ReservationID, RunID: run.Manifest.RunID, Manual: run.Manifest.Manual, State: receipt.Status, PolicyRevision: run.Manifest.PolicyRevision, Source: run.Manifest.Source, Target: run.Manifest.Target, Usage: model.InsightsManagerUsageV1{ModelRequests: receipt.ModelRequests, InputTokens: receipt.ReservedInputTokens, OutputTokens: receipt.ReservedOutputTokens, UsageCertain: false, UnusedProof: "none"}, ReceiptDigest: receipt.ReceiptDigest}
	if receipt.Status == "recommended" {
		if receipt.ManagerSession == nil || receipt.ProposalDigest == nil || !digestPattern.MatchString(*receipt.ProposalDigest) ||
			receipt.GuidanceReceipt == nil || receipt.GuidanceReceipt.FormatVersion != 1 ||
			receipt.GuidanceReceipt.Mode != "recommend_only" || receipt.GuidanceReceipt.Status != "not_delivered" ||
			receipt.GuidanceReceipt.PendingInputID != nil || receipt.GuidanceReceipt.AutoSteer || receipt.GuidanceReceipt.AtomicNativeGuard ||
			!digestPattern.MatchString(receipt.GuidanceReceipt.GuidanceDigest) || receipt.ManagerSession.NativeSessionID == "" ||
			!managerNativeProjectPattern.MatchString(receipt.ManagerSession.NativeProjectID) ||
			!digestPattern.MatchString(receipt.ManagerSession.NativeLocationDigest) {
			return errors.New("manager recommendation receipt is invalid")
		}
		expectedSource := managerSourceID(run.Manifest.RunID)
		if receipt.ManagerRegisteredSourceID != expectedSource || receipt.ManagerSession.ServiceRegistrationID != run.Manifest.Source.ServiceRegistrationID || receipt.ManagerSession.ServiceGeneration != run.Manifest.Source.ServiceGeneration || receipt.ManagerSession.ProviderRouteDigest != run.Manifest.ProviderRouteDigest || receipt.ManagerSession.ManagerProfile != run.Manifest.ManagerProfile {
			return errors.New("manager session receipt changed authority")
		}
		rationale := rationaleForRule(run.Manifest.RuleID)
		report.Proposal = &model.InsightsManagerProposalV1{RecipeID: run.Manifest.RecipeID, Outcome: "recommendation", RationaleCode: rationale, FirstSequence: 1, LastSequence: 1, GuidanceDigest: receipt.GuidanceReceipt.GuidanceDigest}
		if finding, _ := c.Store.ManagerFinding(ctx, run.Manifest.FindingID); finding != nil {
			report.Proposal.FirstSequence = finding.Finding.FirstSequence
			report.Proposal.LastSequence = finding.Finding.LastSequence
		}
		report.ManagerSession = receipt.ManagerSession
		run.ManagerRegisteredSourceID = expectedSource
		run.ManagerSession = receipt.ManagerSession
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
	policyState, err := c.Store.ManagerPolicy(ctx, batch.SandboxID)
	if err != nil || policyState == nil {
		return err
	}
	policy := policyState.Manifest
	if policy.Mode != "recommend" || !c.now().Before(policy.ValidUntil) || policy.ValidUntil.Sub(c.now()) > 120*time.Second {
		return nil
	}
	source := model.InsightsManagerSourceV1{RegisteredSourceID: batch.RegisteredSourceID, WorkspaceEpoch: batch.WorkspaceEpoch, NativeSessionID: batch.NativeSessionID, ServiceRegistrationID: batch.ServiceRegistrationID, ServiceGeneration: batch.ServiceGeneration, SandboxGeneration: batch.SandboxGeneration}
	continuitySource, err := c.Store.ContinuitySource(ctx, batch.RegisteredSourceID)
	if err != nil || continuitySource == nil || continuitySource.Report.Availability != "available" || continuitySource.Lifecycle != "running" ||
		continuitySource.Report.ServiceRegistrationID != batch.ServiceRegistrationID || continuitySource.Report.ServiceGeneration != batch.ServiceGeneration ||
		continuitySource.Report.SandboxID != batch.SandboxID || continuitySource.Report.SandboxGeneration != batch.SandboxGeneration ||
		continuitySource.Report.WorkspaceEpoch != batch.WorkspaceEpoch || continuitySource.Report.NativeSessionID != batch.NativeSessionID {
		return errors.Join(err, errors.New("manager acknowledged source authority changed"))
	}
	source.ProfileRevision = continuitySource.Report.ProfileRevision
	source.InstructionRevision = continuitySource.Report.InstructionRevision
	for _, finding := range batch.Findings {
		if finding.State != "open" || !contains(policy.AllowedRules, finding.RuleID) {
			continue
		}
		local := state.LocalManagerFinding{Finding: finding, Source: source, PolicyRevision: policy.PolicyRevision, JournalGeneration: batch.JournalGeneration, Acknowledged: true}
		if err := c.Store.PutManagerFinding(ctx, local); err != nil {
			return err
		}
		if !c.eligibleAutomatic(ctx, policy, source, finding) {
			continue
		}
		capability, err := c.Store.ManagerCapability(ctx, source.RegisteredSourceID)
		if err != nil || capability == nil || !capability.Available {
			return err
		}
		recipe := recipeForRule(finding.RuleID)
		if !contains(capability.RecipeIDs, recipe) {
			continue
		}
		service, err := c.Store.ManagedService(ctx, source.ServiceRegistrationID)
		if err != nil || service == nil {
			return err
		}
		target, err := c.automaticDescriptorTarget(ctx, source, service)
		if err != nil {
			return err
		}
		expiresIn := int(policy.ValidUntil.Sub(c.now()).Seconds())
		if expiresIn > 120 {
			expiresIn = 120
		}
		if expiresIn < 1 {
			continue
		}
		request := model.InsightsManagerReservationRequestV1{FormatVersion: 1, ReservationID: opaqueID("reservation_", batch.BatchID+"\x00"+finding.FindingID), RequestID: opaqueID("req_manager_", batch.BatchID+"\x00"+finding.FindingID), Manual: false, FindingID: finding.FindingID, FindingRevision: finding.Revision, PolicyRevision: policy.PolicyRevision, RuleID: finding.RuleID, RecipeID: recipe, ProviderRouteDigest: capability.ProviderRouteDigest, Source: source, Target: target, Budget: model.InsightsManagerBudgetV1{ModelRequests: policy.EffectiveLimits.PerRunModelRequests, InputTokens: policy.EffectiveLimits.PerRunInputTokens, OutputTokens: policy.EffectiveLimits.PerRunOutputTokens}, ExpiresInSeconds: expiresIn}
		intent := state.LocalManagerReservation{Request: request, Phase: "pending"}
		if err := c.Store.PutManagerReservation(ctx, intent); err != nil {
			return err
		}
		if err := c.completeAutomaticReservation(ctx, &intent); err != nil {
			return err
		}
	}
	return nil
}

// automaticDescriptorTarget returns the automatic reservation target in the
// exact shape the backend descriptor derives from the same continuity
// registration: the service team/member, the registration's task fields when
// present, and the verified Work binding fields. With no verified binding for
// this source the minimal team/member target is used, exactly as the backend
// descriptor does. The correction keeps the automatic branch consistent with
// the descriptor so a reservation is never refused for a target mismatch.
func (c *Coordinator) automaticDescriptorTarget(ctx context.Context, source model.InsightsManagerSourceV1, service *state.LocalManagedService) (model.InsightsManagerTargetV1, error) {
	target := model.InsightsManagerTargetV1{TeamID: service.Manifest.Identity.TeamID, MemberID: service.Manifest.Identity.MemberID}
	registrations, err := c.Store.ContinuityRegistrations(ctx)
	if err != nil {
		return model.InsightsManagerTargetV1{}, err
	}
	for i := range registrations {
		registration := &registrations[i]
		if registration.ObservedStatus != "verified" ||
			registration.Manifest.Binding.RegisteredSourceID != source.RegisteredSourceID ||
			registration.Manifest.Identity.SandboxGeneration != source.SandboxGeneration {
			continue
		}
		workID := registration.Manifest.Identity.WorkID
		workRevision := registration.Manifest.Identity.ExpectedRevision
		bindingID := registration.Manifest.Binding.BindingID
		bindingRevision := registration.Manifest.Binding.BindingRevision
		target.WorkID = &workID
		target.WorkRevision = &workRevision
		target.BindingID = &bindingID
		target.BindingRevision = &bindingRevision
		if registration.Manifest.Identity.TaskID != nil && registration.Manifest.Identity.TaskAttempt != nil {
			target.TaskID = registration.Manifest.Identity.TaskID
			target.TaskAttempt = registration.Manifest.Identity.TaskAttempt
		}
		return target, nil
	}
	return target, nil
}

// sourceStaleReserveRefusal reports whether the control plane refused an
// automatic reservation specifically because the continuity source is stale.
func sourceStaleReserveRefusal(err error) bool {
	var responseErr *api.ResponseError
	return errors.As(err, &responseErr) && responseErr.Status == 409 && responseErr.Code == "manager_source_stale"
}

// settleUnreservedSourceStale retires a PENDING AUTOMATIC reservation that the
// control plane refused specifically because the continuity source is stale and
// that never created a backend reservation, run or provider execution: the
// intent keeps its request intact as evidence and only moves to the terminal
// "unused" phase so the pass can complete and the source can refresh. A manual
// intent, a non-pending intent, an existing reservation, an existing local run
// for the same reservation or request, and every other refusal fail closed and
// keep the original error.
func (c *Coordinator) settleUnreservedSourceStale(ctx context.Context, intent *state.LocalManagerReservation, cause error) (bool, error) {
	if !sourceStaleReserveRefusal(cause) || intent.Phase != "pending" || intent.Request.Manual || intent.Reservation != nil {
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
	// Re-derive the descriptor target on every completion attempt so a pending
	// automatic reservation created before the descriptor-shape correction
	// recovers without clearing or migration.
	service, err := c.Store.ManagedService(ctx, request.Source.ServiceRegistrationID)
	if err != nil {
		return err
	}
	if service == nil {
		return errors.New("manager reservation service is unavailable")
	}
	target, err := c.automaticDescriptorTarget(ctx, request.Source, service)
	if err != nil {
		return err
	}
	request.Target = target
	intent.Request = request
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
	if policy.Manifest.Mode != "recommend" || !c.now().Before(policy.Manifest.ValidUntil) {
		code := "policy_off"
		if policy.Manifest.Mode == "recommend" {
			code = "policy_expired"
		}
		return c.settleReservedWithoutExecution(ctx, intent, review, code)
	}
	capability, finding, err := c.reviewAuthority(ctx, review, true)
	if err != nil {
		return c.settleReservedWithoutExecution(ctx, intent, review, "source_stale")
	}
	run := state.LocalManagerRun{Manifest: review, ReservationRequest: &request, Reservation: &reservation, Phase: "dispatching", Capability: *capability, DispatchStarted: true, StartedAt: c.now()}
	if err := c.Store.PutManagerRun(ctx, run); err != nil {
		return err
	}
	intent.Phase = "applied"
	if err := c.Store.PutManagerReservation(ctx, *intent); err != nil {
		return err
	}
	return c.dispatchReview(ctx, &run, *finding, "start_review")
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
		if run.Phase == "dispatching" || run.Phase == "execution_unknown" || run.Phase == "reviewing" {
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
		left, right := prior.Manifest, manifest
		left.ValidUntil, right.ValidUntil = time.Time{}, time.Time{}
		if !reflect.DeepEqual(left, right) || !manifest.ValidUntil.After(prior.Manifest.ValidUntil) || manifest.Action != "pause_manager_and_hold_member" {
			return state.ErrManagerConflict
		}
		renewal = prior
	}
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
	if err := c.localTargetAuthority(ctx, manifest.Source, manifest.Target); err != nil {
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

func (c *Coordinator) dispatchTakeover(ctx context.Context, value *state.LocalManagerTakeover, action string) error {
	sandboxID, instance, err := c.helperTarget(ctx, value.Manifest.Source)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"formatVersion": 1, "action": action, "instance": instance, "manifest": value.Manifest})
	output, _, err := c.Helper.ExecManager(ctx, sandboxID, payload)
	if err != nil {
		if action == "release_intervention_hold" {
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
func rationaleForRule(rule string) string {
	switch rule {
	case "repeated_identical_failure@1":
		return "unchanged_failure_repeated"
	case "repeated_identical_call@1":
		return "repeated_call_detected"
	case "empty_result_loop@1":
		return "query_refinement_available"
	default:
		return "active_phase_stalled"
	}
}
func managerFindingEvidence(value state.LocalManagerFinding) map[string]any {
	return map[string]any{"findingId": value.Finding.FindingID, "findingRevision": value.Finding.Revision, "journalGeneration": value.JournalGeneration, "ruleId": value.Finding.RuleID, "nativeSessionId": value.Source.NativeSessionID, "firstSequence": value.Finding.FirstSequence, "lastSequence": value.Finding.LastSequence, "count": value.Finding.Count, "matchedCallIds": value.Finding.MatchedCallIDs, "coverage": value.Finding.Coverage, "firstObservedAt": value.Finding.FirstObservedAt, "lastObservedAt": value.Finding.LastObservedAt, "toolCategory": value.Finding.ToolCategory, "phase": value.Finding.Phase}
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
