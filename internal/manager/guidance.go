package manager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Q2 guidance boundary (root178/180/186/193/194). Guidance is a separate
// dimension on the existing manager run: the immutable terminal model result is
// never rewritten, the attempt intent is durable before any helper POST, and
// Runtime is the sole monotonic publisher of canonical guidance revisions.
const (
	guidanceContractVersion = "0.1.32"
	guidanceGuardVersion    = "warpmetal.atomic-input.v1"
)

var autoSteerDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var ociReferencePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(?::[0-9]+)?@(sha256:[a-f0-9]{64})$`)

func guidanceDigest(value any) string {
	payload, _ := json.Marshal(value)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}

// canonicalGuidanceDigest rehashes a snapshot excluding receiptDigest with
// sorted compact JSON, exactly as the backend expects.
func canonicalGuidanceDigest(snapshot model.InsightsManagerGuidanceV1) string {
	payload, _ := json.Marshal(snapshot)
	var fields map[string]any
	_ = json.Unmarshal(payload, &fields)
	delete(fields, "receiptDigest")
	return guidanceDigest(fields)
}

func guidanceIDs(runID string) (string, string) {
	return opaqueID("guard_", runID), opaqueID("msg_", runID)
}

func guidanceBindingDigest(run *state.LocalManagerRun, guardID, pendingInputID string) string {
	source := run.Manifest.Source
	return guidanceDigest(map[string]any{
		"bindingVersion":        1,
		"guardId":               guardID,
		"instructionRevision":   source.InstructionRevision,
		"nativeSessionId":       source.NativeSessionID,
		"pendingInputId":        pendingInputID,
		"profileRevision":       source.ProfileRevision,
		"registeredSourceId":    source.RegisteredSourceID,
		"reservationId":         run.Manifest.ReservationID,
		"runId":                 run.Manifest.RunID,
		"sandboxGeneration":     source.SandboxGeneration,
		"serviceGeneration":     source.ServiceGeneration,
		"serviceRegistrationId": source.ServiceRegistrationID,
		"workspaceEpoch":        source.WorkspaceEpoch,
	})
}

// reviewPolicyModeValid accepts the legacy Recommend mode and a fully qualified
// auto_steer policy object. Only the new object grants auto steering.
func reviewPolicyModeValid(manifest model.InsightsManagerPolicyManifestV1) bool {
	switch manifest.Mode {
	case "recommend":
		return true
	case "auto_steer":
		return manifest.AutoSteerPolicy != nil && manifest.AutoSteerPolicy.Available &&
			manifest.AutoSteerPolicy.QualifiedTuple != nil && manifest.AutoSteerPolicy.QualifiedTuple.Valid()
	}
	return false
}

// autoSteerQualified compares the observed install/capability proof against the
// backend-authoritative tuple. A missing local sandbox image proof never
// qualifies, and the observed image digest must equal the tuple digest exactly.
func autoSteerQualified(manifest model.InsightsManagerPolicyManifestV1, capability *state.LocalManagerCapability, sandbox *state.LocalSandbox) bool {
	if !reviewPolicyModeValid(manifest) || manifest.Mode != "auto_steer" {
		return false
	}
	object := manifest.AutoSteerPolicy
	if object == nil || !object.Available || object.QualifiedTuple == nil {
		return false
	}
	tuple := object.QualifiedTuple
	if capability == nil || capability.NativeGuard == nil {
		return false
	}
	guard := capability.NativeGuard
	if guard.GuardVersion != tuple.NativeGuardVersion || guard.CustomVersion != tuple.CustomNativeVersion ||
		guard.SourceRevision != tuple.NativeSourceRevision || guard.PatchDigest != tuple.PatchDigest ||
		guard.ArtifactSHA256 != tuple.ArtifactSHA256 || guard.BinarySHA256 != tuple.BinarySHA256 {
		return false
	}
	if capability.NativeVersion != tuple.CustomNativeVersion || capability.NativeSourceRevision != tuple.NativeSourceRevision ||
		capability.ManagerProfile.ProfileDigest != tuple.ManagerProfileDigest || capability.ManagerPluginDigest != tuple.ManagerPluginDigest {
		return false
	}
	if sandbox == nil || sandbox.ImageDigest == "" {
		return false
	}
	observed, ok := canonicalImageDigest(sandbox.ImageDigest)
	if !ok || observed != tuple.ImageDigest {
		return false
	}
	return true
}

// canonicalImageDigest accepts an exact bare sha256 digest or an entire
// validated OCI reference and returns the canonical digest. Substring scans or
// partial references are rejected.
func canonicalImageDigest(reference string) (string, bool) {
	if autoSteerDigestPattern.MatchString(reference) {
		return reference, true
	}
	matched := ociReferencePattern.FindStringSubmatch(reference)
	if matched == nil {
		return "", false
	}
	return matched[1], true
}

type guidanceHelperReceipt struct {
	FormatVersion int             `json:"formatVersion"`
	Action        string          `json:"action"`
	ReservationID string          `json:"reservationId"`
	RunID         string          `json:"runId"`
	Guidance      json.RawMessage `json:"guidance"`
}

var guidanceSnapshotKeys = []string{
	"formatVersion", "sandboxId", "reservationId", "runId", "revision", "bindingDigest", "guidanceDigest",
	"guardId", "pendingInputId", "state", "refusalCode", "logCursor", "observedAt", "admittedAt",
	"availableAt", "settledAt", "receiptDigest",
}

// decodeGuidanceReceipt validates the helper receipt digest against the
// ORIGINAL raw closed JSON map (RFC3339 lexical strings preserved, e.g. .030Z)
// BEFORE any Go time normalization, then decodes the typed snapshot. Runtime
// publication canonicalizes its own output digest later.
func decodeGuidanceReceipt(raw []byte) (model.InsightsManagerGuidanceV1, error) {
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return model.InsightsManagerGuidanceV1{}, err
	}
	if len(fields) != len(guidanceSnapshotKeys) {
		return model.InsightsManagerGuidanceV1{}, errors.New("manager guidance snapshot keys are not closed")
	}
	for _, key := range guidanceSnapshotKeys {
		if _, ok := fields[key]; !ok {
			return model.InsightsManagerGuidanceV1{}, errors.New("manager guidance snapshot key set is incomplete")
		}
	}
	declared, _ := fields["receiptDigest"].(string)
	delete(fields, "receiptDigest")
	if declared == "" || guidanceDigest(fields) != declared {
		return model.InsightsManagerGuidanceV1{}, errors.New("manager guidance receipt digest is not canonical")
	}
	var snapshot model.InsightsManagerGuidanceV1
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return model.InsightsManagerGuidanceV1{}, err
	}
	return snapshot, nil
}

func guidanceAuthority(run *state.LocalManagerRun) map[string]any {
	payload, _ := json.Marshal(run.Manifest)
	var authority map[string]any
	_ = json.Unmarshal(payload, &authority)
	authority["runGeneration"] = run.OriginRunGeneration
	if !run.OriginValidUntil.IsZero() {
		authority["validUntil"] = run.OriginValidUntil.UTC().Format(time.RFC3339)
	}
	return authority
}

func (c *Coordinator) guidanceEnvelope(run *state.LocalManagerRun, action string, withAuthority bool) map[string]any {
	guardID, pendingInputID := guidanceIDs(run.Manifest.RunID)
	request := map[string]any{
		"formatVersion": 1,
		"action":        action,
		"bindingDigest": guidanceBindingDigest(run, guardID, pendingInputID),
	}
	if withAuthority {
		request["authority"] = guidanceAuthority(run)
	} else {
		request["reservationId"] = run.Manifest.ReservationID
		request["runId"] = run.Manifest.RunID
	}
	if run.Capability.NativeGuard != nil {
		request["runtimeContractVersion"] = guidanceContractVersion
	}
	return request
}

func (c *Coordinator) callGuidance(ctx context.Context, run *state.LocalManagerRun, action string, withAuthority bool) (model.InsightsManagerGuidanceV1, error) {
	sandboxID, instance, err := c.helperTarget(ctx, run.Manifest.Source)
	if err != nil {
		return model.InsightsManagerGuidanceV1{}, err
	}
	request := c.guidanceEnvelope(run, action, withAuthority)
	request["instance"] = instance
	payload, _ := json.Marshal(request)
	output, _, err := c.Helper.ExecManager(ctx, sandboxID, payload)
	if err != nil {
		return model.InsightsManagerGuidanceV1{}, err
	}
	var receipt guidanceHelperReceipt
	if err := decodeClosed(output, &receipt); err != nil {
		return model.InsightsManagerGuidanceV1{}, err
	}
	if receipt.FormatVersion != 1 || receipt.Action != action || receipt.ReservationID != run.Manifest.ReservationID || receipt.RunID != run.Manifest.RunID {
		return model.InsightsManagerGuidanceV1{}, errors.New("manager guidance receipt changed immutable identity")
	}
	return decodeGuidanceReceipt(receipt.Guidance)
}

// dispatchGuidance persists the durable attempt intent BEFORE any helper POST,
// then performs the single negotiated steer attempt (no model request). No code
// path ever posts a second attempt for the same run.
func (c *Coordinator) dispatchGuidance(ctx context.Context, run *state.LocalManagerRun) error {
	if !run.GuidanceAttempted {
		run.GuidanceAttempted = true
		if err := c.Store.PutManagerRun(ctx, *run); err != nil {
			return err
		}
	}
	snapshot, err := c.callGuidance(ctx, run, "dispatch_guidance", true)
	if err != nil {
		if writeErr := c.persistGuidance(ctx, run, unknownGuidance(c, run)); writeErr != nil {
			return writeErr
		}
		return err
	}
	return c.persistGuidance(ctx, run, snapshot)
}

func (c *Coordinator) observeGuidance(ctx context.Context, run *state.LocalManagerRun) error {
	snapshot, err := c.callGuidance(ctx, run, "observe_guidance", false)
	if err != nil {
		return err
	}
	return c.persistGuidance(ctx, run, snapshot)
}

func (c *Coordinator) cancelGuidance(ctx context.Context, run *state.LocalManagerRun) error {
	snapshot, err := c.callGuidance(ctx, run, "cancel_guidance", false)
	if err != nil {
		return err
	}
	return c.persistGuidance(ctx, run, snapshot)
}

// unknownGuidance uses the ORIGINAL terminal proposal guidance digest (never a
// route digest) and the deterministic IDs.
func unknownGuidance(c *Coordinator, run *state.LocalManagerRun) model.InsightsManagerGuidanceV1 {
	guardID, pendingInputID := guidanceIDs(run.Manifest.RunID)
	digest := ""
	if run.Report != nil && run.Report.Proposal != nil && run.Report.Proposal.GuidanceDigest != nil {
		digest = *run.Report.Proposal.GuidanceDigest
	}
	snapshot := model.InsightsManagerGuidanceV1{
		FormatVersion: 1, SandboxID: run.Capability.SandboxID, ReservationID: run.Manifest.ReservationID,
		RunID: run.Manifest.RunID, Revision: 1,
		BindingDigest:  guidanceBindingDigest(run, guardID, pendingInputID),
		GuidanceDigest: digest, GuardID: guardID, PendingInputID: pendingInputID,
		State: "unknown", ObservedAt: c.now().UTC(),
	}
	snapshot.ReceiptDigest = canonicalGuidanceDigest(snapshot)
	return snapshot
}

var closedGuidanceRefusals = map[string]bool{
	"guard_stale_input": true, "guard_execution_changed": true, "guard_context_changed": true,
	"guard_expired": true, "guard_session_mismatch": true, "authority_expired": true,
	"source_stale": true, "policy_off": true, "capability_unavailable": true, "worker_inactive": true,
}

// validateGuidanceSnapshot checks the closed helper snapshot before any
// publication: identity, deterministic IDs, canonical binding, digest shape,
// closed state/refusal vocabulary, cursor and finite phase stamps.
func validateGuidanceSnapshot(run *state.LocalManagerRun, snapshot model.InsightsManagerGuidanceV1) error {
	guardID, pendingInputID := guidanceIDs(run.Manifest.RunID)
	if snapshot.FormatVersion != 1 || snapshot.SandboxID != run.Capability.SandboxID ||
		snapshot.ReservationID != run.Manifest.ReservationID || snapshot.RunID != run.Manifest.RunID ||
		snapshot.GuardID != guardID || snapshot.PendingInputID != pendingInputID {
		return errors.New("manager guidance snapshot identity is invalid")
	}
	if snapshot.BindingDigest != guidanceBindingDigest(run, guardID, pendingInputID) {
		return errors.New("manager guidance snapshot binding is invalid")
	}
	if !autoSteerDigestPattern.MatchString(snapshot.GuidanceDigest) {
		return errors.New("manager guidance snapshot digest is invalid")
	}
	switch snapshot.State {
	case "pending", "available_to_worker", "cancelled", "refused", "unknown":
	default:
		return errors.New("manager guidance snapshot state is invalid")
	}
	if snapshot.RefusalCode != nil {
		if snapshot.State != "refused" || !closedGuidanceRefusals[*snapshot.RefusalCode] {
			return errors.New("manager guidance snapshot refusal is invalid")
		}
	} else if snapshot.State == "refused" {
		return errors.New("manager guidance refusal omitted its code")
	}
	if snapshot.LogCursor != nil && *snapshot.LogCursor < 0 {
		return errors.New("manager guidance snapshot cursor is invalid")
	}
	if snapshot.ObservedAt.IsZero() {
		return errors.New("manager guidance snapshot observation time is missing")
	}
	if snapshot.AvailableAt != nil && snapshot.State != "available_to_worker" {
		return errors.New("manager guidance availability time is invalid")
	}
	if snapshot.SettledAt != nil {
		switch snapshot.State {
		case "available_to_worker", "cancelled", "refused":
		default:
			return errors.New("manager guidance settled time is invalid")
		}
	}
	return nil
}

func semanticGuidanceEqual(left, right model.InsightsManagerGuidanceV1) bool {
	equal := func(a, b *string) bool {
		if a == nil || b == nil {
			return a == nil && b == nil
		}
		return *a == *b
	}
	equalTime := func(a, b *time.Time) bool {
		if a == nil || b == nil {
			return a == nil && b == nil
		}
		return a.Equal(*b)
	}
	equalCursor := func(a, b *int64) bool {
		if a == nil || b == nil {
			return a == nil && b == nil
		}
		return *a == *b
	}
	return left.State == right.State && left.GuidanceDigest == right.GuidanceDigest && left.BindingDigest == right.BindingDigest &&
		left.GuardID == right.GuardID && left.PendingInputID == right.PendingInputID && equal(left.RefusalCode, right.RefusalCode) &&
		equalCursor(left.LogCursor, right.LogCursor) && equalTime(left.AdmittedAt, right.AdmittedAt) &&
		equalTime(left.AvailableAt, right.AvailableAt) && equalTime(left.SettledAt, right.SettledAt)
}

func validGuidanceTransition(from, to string) bool {
	switch from {
	case "pending", "unknown":
		switch to {
		case "pending", "unknown", "available_to_worker", "cancelled", "refused":
			return true
		}
	}
	return false
}

// persistGuidance validates, deduplicates semantically unchanged observations,
// assigns the Runtime-owned monotonic revision and canonicalizes the receipt
// digest. Final dispositions never regress or change.
func (c *Coordinator) persistGuidance(ctx context.Context, run *state.LocalManagerRun, snapshot model.InsightsManagerGuidanceV1) error {
	if err := validateGuidanceSnapshot(run, snapshot); err != nil {
		return err
	}
	expected := int64(0)
	if run.Guidance != nil {
		expected = run.Guidance.Revision
		if semanticGuidanceEqual(*run.Guidance, snapshot) {
			return nil
		}
		if isFinalGuidanceState(run.Guidance.State) || !validGuidanceTransition(run.Guidance.State, snapshot.State) {
			return errors.New("manager guidance final disposition is immutable")
		}
	}
	snapshot.Revision = expected + 1
	snapshot.ReceiptDigest = canonicalGuidanceDigest(snapshot)
	if err := c.Store.PutManagerGuidance(ctx, run.Manifest.RunID, snapshot, expected); err != nil {
		return err
	}
	run.Guidance = &snapshot
	return nil
}

func isFinalGuidanceState(value string) bool {
	return value == "available_to_worker" || value == "cancelled" || value == "refused"
}

// dispatchPendingGuidance is the only new-attempt admission point: it runs at
// the end of an Apply pass after the durable verified terminal model ACK and
// admits at most one guidance attempt for a qualified automatic origin.
func (c *Coordinator) dispatchPendingGuidance(ctx context.Context) error {
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return err
	}
	for index := range runs {
		run := &runs[index]
		if !run.AutomaticOrigin || run.Report == nil || run.GuidanceAttempted || run.Guidance != nil {
			continue
		}
		if run.Phase != run.Report.State || run.Report.ReceiptDigest == "" || run.Manifest.Manual {
			continue
		}
		switch run.Report.State {
		case "recommended", "no_action", "needs_owner":
		default:
			continue
		}
		if run.Report.Proposal == nil || run.Report.Proposal.Outcome != "recommendation" ||
			run.Report.Proposal.GuidanceDigest == nil || !autoSteerDigestPattern.MatchString(*run.Report.Proposal.GuidanceDigest) {
			continue
		}
		policy, err := c.Store.ManagerPolicy(ctx, sourceSandbox(ctx, c.Store, run.Manifest.Source))
		if err != nil || policy == nil || !c.now().Before(policy.Manifest.ValidUntil) || policy.Manifest.ValidUntil.Sub(c.now()) > 120*time.Second {
			continue
		}
		sandbox, err := c.Store.Sandbox(ctx, run.Capability.SandboxID)
		if err != nil {
			return err
		}
		if !autoSteerQualified(policy.Manifest, &run.Capability, sandbox) {
			continue
		}
		if _, _, err := c.reviewAuthority(ctx, run.Manifest, true); err != nil {
			continue
		}
		actionContext, cancelAction := c.runActionContext(ctx, run)
		err = c.dispatchGuidance(actionContext, run)
		cancelAction()
		if err != nil {
			return err
		}
	}
	return nil
}

// recoverPendingGuidance observes already attempted guidance GET-only. It never
// starts a model review or a new attempt: an attempted run without a snapshot
// recovers to unknown first, then observation only.
func (c *Coordinator) recoverPendingGuidance(ctx context.Context) error {
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return err
	}
	for index := range runs {
		run := &runs[index]
		if run.Guidance == nil {
			if !run.GuidanceAttempted {
				continue
			}
			if err := c.observeGuidance(ctx, run); err != nil {
				if writeErr := c.persistGuidance(ctx, run, unknownGuidance(c, run)); writeErr != nil {
					return writeErr
				}
			}
			continue
		}
		if isFinalGuidanceState(run.Guidance.State) {
			continue
		}
		if run.Guidance.State != "pending" && run.Guidance.State != "unknown" {
			continue
		}
		if _, err := c.Store.ContinuitySource(ctx, run.Manifest.Source.RegisteredSourceID); err != nil {
			continue
		}
		if err := c.observeGuidance(ctx, run); err != nil {
			return err
		}
	}
	return nil
}

// fenceOffGuidance cancels known pending guidance when Off is applied. Unknown
// guidance stays protective and unsettled.
func (c *Coordinator) fenceOffGuidance(ctx context.Context, sandboxID string) error {
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return err
	}
	for index := range runs {
		run := &runs[index]
		if run.Guidance == nil || run.Guidance.State != "pending" {
			continue
		}
		if run.Capability.SandboxID != sandboxID {
			continue
		}
		if err := c.cancelGuidance(ctx, run); err != nil {
			return err
		}
	}
	return nil
}

// guidanceSettled reports whether every attempt for the sandbox reached a final
// disposition (no timeout-based settlement).
func (c *Coordinator) guidanceSettled(ctx context.Context, sandboxID string) (bool, error) {
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return false, err
	}
	for index := range runs {
		run := &runs[index]
		if run.Capability.SandboxID != sandboxID || !run.AutomaticOrigin {
			continue
		}
		if run.GuidanceAttempted && run.Guidance == nil {
			return false, nil
		}
		if run.Guidance != nil && !isFinalGuidanceState(run.Guidance.State) {
			return false, nil
		}
	}
	return true, nil
}

// GuidanceReports returns the latest guidance snapshot per run for the node
// report; empty when no negotiated guidance exists (preserving legacy field
// omission).
func (c *Coordinator) GuidanceReports(ctx context.Context) ([]model.InsightsManagerGuidanceV1, error) {
	runs, err := c.Store.ManagerRuns(ctx)
	if err != nil {
		return nil, err
	}
	reports := make([]model.InsightsManagerGuidanceV1, 0)
	for index := range runs {
		if runs[index].Guidance != nil {
			reports = append(reports, *runs[index].Guidance)
		}
	}
	return reports, nil
}
