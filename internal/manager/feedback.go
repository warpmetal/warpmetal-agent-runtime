package manager

import (
	"context"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// ApplyLifecycle is the heavy-pass manager portion: current policies, manual
// reviews and takeovers. Automatic admission and first guidance are owned by
// the post-Report-ACK feedback phase and are deliberately absent here.
func (c *Coordinator) ApplyLifecycle(ctx context.Context, manifest model.Manifest) error {
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

// ReconsiderAdmissions runs the existing durable automatic-admission path
// (recommend and qualified auto_steer) against the currently applied policy.
func (c *Coordinator) ReconsiderAdmissions(ctx context.Context) error {
	return c.recoverAdmissions(ctx)
}

// DispatchReadyGuidance dispatches guidance for automatic runs whose verified
// terminal recommendation is already complete under the current fresh policy.
// Off, changed or expired authority simply skips the run.
func (c *Coordinator) DispatchReadyGuidance(ctx context.Context) error {
	return c.dispatchPendingGuidance(ctx)
}

// automaticRunEligible is the shared current/original eligibility gate for a
// known automatic run. The durable original lease must be unexpired, the
// existing reviewAuthority boundary must still hold against the current
// applied policy/source/target/capability, and the current run generation and
// allowed rule must match the admitted run. Off, expired, changed or
// unqualified authority is terminal; the original lease is never widened.
func (c *Coordinator) automaticRunEligible(ctx context.Context, run *state.LocalManagerRun) bool {
	if run.OriginValidUntil.IsZero() || !c.now().Before(run.OriginValidUntil) {
		return false
	}
	if _, _, err := c.reviewAuthority(ctx, run.Manifest, true); err != nil {
		return false
	}
	policy, err := c.Store.ManagerPolicy(ctx, sourceSandbox(ctx, c.Store, run.Manifest.Source))
	if err != nil || policy == nil || policy.Manifest.RunGeneration != run.OriginRunGeneration ||
		!contains(policy.Manifest.AllowedRules, run.Manifest.RuleID) {
		return false
	}
	if managerRunGeneration(ctx, c.Store, run.Manifest.Source) != run.OriginRunGeneration {
		return false
	}
	return true
}

// AdvanceAutomaticRuns progresses automatic-origin runs through the existing
// start-ack/continue/reconcile/report semantics. Manual runs, takeovers and
// unrelated recovery stay with the ordinary heavy Recover path. Known
// continuation requires the current applied policy and the original lease;
// unknown dispatched phases remain observation-only through resumeRun and stop
// once the original lease has expired.
func (c *Coordinator) AdvanceAutomaticRuns(ctx context.Context) error {
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return err
	}
	for i := range runs {
		if !runs[i].AutomaticOrigin {
			continue
		}
		if !c.automaticRunEligible(ctx, &runs[i]) {
			continue
		}
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
	return nil
}

// AutomaticWorkPending reports whether any automatic run still has a possible
// first guidance delivery under the currently applied policy. An Off, expired
// or unqualified policy, or an expired original lease, is terminal for the
// bounded feedback wait even in an unresolved phase.
func (c *Coordinator) AutomaticWorkPending(ctx context.Context) (bool, error) {
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return false, err
	}
	for i := range runs {
		run := &runs[i]
		if !run.AutomaticOrigin || run.GuidanceAttempted || run.Guidance != nil || run.Manifest.Manual {
			continue
		}
		if !c.automaticRunEligible(ctx, run) {
			continue
		}
		switch run.Phase {
		case "start_ack_pending", "dispatching", "execution_unknown", "reviewing", "report_pending":
			return true, nil
		}
		if run.Report == nil || run.Phase != run.Report.State {
			continue
		}
		switch run.Report.State {
		case "recommended", "no_action", "needs_owner":
		default:
			continue
		}
		if run.Report.Proposal == nil || run.Report.Proposal.Outcome != "recommendation" ||
			run.Report.Proposal.GuidanceDigest == nil {
			continue
		}
		policy, err := c.Store.ManagerPolicy(ctx, sourceSandbox(ctx, c.Store, run.Manifest.Source))
		if err != nil || policy == nil || !c.now().Before(policy.Manifest.ValidUntil) ||
			policy.Manifest.ValidUntil.Sub(c.now()) > 120*time.Second {
			continue
		}
		sandbox, err := c.Store.Sandbox(ctx, run.Capability.SandboxID)
		if err != nil {
			return false, err
		}
		if !autoSteerQualified(policy.Manifest, &run.Capability, sandbox) {
			continue
		}
		return true, nil
	}
	return false, nil
}
