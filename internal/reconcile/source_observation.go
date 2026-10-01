package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// sourceProbeReasonPattern is the bounded reason code an unavailable
// observation may carry: the same shape the control plane accepts for an
// unavailable source report.
var sourceProbeReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)

// continuitySourceProbe is one eligible source observation target: the durable
// source row and the managed service that backs it, both already fenced
// against the active registration they were selected from.
type continuitySourceProbe struct {
	source  state.LocalContinuitySource
	service state.LocalManagedService
}

// observeContinuitySources is the pre-failure source observation phase. It runs
// after the fresh authenticated manifest and every server/revision/capacity/
// sandbox/setup/workspace/continuity-registration authority check and after the
// A41 acknowledgement phase, but before the failure-prone managed-service
// enrollment. For each unique source that currently backs a structurally valid
// desired-active, continuity-enabled registration it invokes the existing real
// local supervisor status probe exactly once and persists only the complete
// authentic probe result through the ordinary continuity-source store.
//
// It never writes a timestamp alone, copies desired availability, manufactures
// "available", suppresses a probe error, synthesizes a node-token hash or infers
// health from registration/service/handoff state. A genuine unavailable answer
// is persisted unavailable and visible; an ambiguous, malformed or foreign
// probe result fails the pass closed. The authenticated node token is carried
// by the report request itself; the store never fabricates one. A successful
// probe never marks a managed service ready, clears enrollment_unavailable,
// cancels a handoff deferral, advances the applied revision, rewrites a
// registration or operation, executes an operation helper or changes backend
// state.
func (r *Reconciler) observeContinuitySources(ctx context.Context, manifest model.Manifest) error {
	if r.ManagedRuntime == nil {
		return nil
	}
	probes, err := r.continuitySourceProbes(ctx, manifest)
	if err != nil {
		return err
	}
	for _, probe := range probes {
		if err := r.observeContinuitySource(ctx, probe); err != nil {
			return err
		}
	}
	return nil
}

// continuitySourceProbes selects the eligible observation targets in
// deterministic order and deduplicates by source identity. Revoked/disabled,
// foreign, unowned, ambiguous and locally unmatched registrations are never
// probed.
func (r *Reconciler) continuitySourceProbes(ctx context.Context, manifest model.Manifest) ([]continuitySourceProbe, error) {
	registrations := append([]model.ContinuityRegistrationV1(nil), manifest.ContinuityRegistrations...)
	sort.SliceStable(registrations, func(left, right int) bool {
		if registrations[left].Binding.RegisteredSourceID != registrations[right].Binding.RegisteredSourceID {
			return registrations[left].Binding.RegisteredSourceID < registrations[right].Binding.RegisteredSourceID
		}
		return registrations[left].Binding.BindingID < registrations[right].Binding.BindingID
	})
	seen := map[string]bool{}
	probes := make([]continuitySourceProbe, 0, len(registrations))
	for _, registration := range registrations {
		if registration.DesiredState != "active" || !registration.ContinuityEnabled ||
			model.ValidateContinuityRegistration(registration) != nil {
			continue
		}
		sourceID := registration.Binding.RegisteredSourceID
		if seen[sourceID] {
			continue
		}
		// A registration that one completed ready handoff preparation exactly
		// owns as its mapped target source is observed exclusively through the
		// handoff-specific target boundaries (the target service primary status
		// receipt and the distinct mapped session's idempotent reconcile_handoff
		// request), never by the generic managed-service status probe. Missing
		// ownership stays eligible, and structural lookup or ownership
		// contradictions remain fatal.
		owned, err := continuity.HandoffTargetRegistrationOwnedByPreparation(ctx, r.Store, registration)
		if err != nil {
			return nil, err
		}
		if owned {
			continue
		}
		local, err := r.Store.ContinuityRegistration(ctx, registration.Binding.BindingID)
		if err != nil {
			return nil, err
		}
		if local == nil || !reflect.DeepEqual(local.Manifest, registration) {
			continue
		}
		source, err := r.Store.ContinuitySource(ctx, sourceID)
		if err != nil {
			return nil, err
		}
		service, err := r.Store.ManagedService(ctx, registration.Binding.ServiceRegistrationID)
		if err != nil {
			return nil, err
		}
		probe, ok := continuitySourceProbeFor(*local, source, service)
		if !ok {
			continue
		}
		seen[sourceID] = true
		probes = append(probes, probe)
	}
	return probes, nil
}

// continuitySourceProbeFor is the complete precondition that a durable source
// row currently backs the active registration through the exact managed
// service: the registration, source and service tuple must all agree on
// identity, binding, scope, service generation, workspace, native location,
// role, profile and instruction fences. Anything else is not probed.
func continuitySourceProbeFor(
	local state.LocalContinuityRegistration,
	source *state.LocalContinuitySource,
	service *state.LocalManagedService,
) (continuitySourceProbe, bool) {
	if source == nil || service == nil || local.ServiceGeneration < 1 {
		return continuitySourceProbe{}, false
	}
	registration := local.Manifest
	binding := registration.Binding
	manifest := service.Manifest
	if manifest.Identity.ServiceRegistrationID != binding.ServiceRegistrationID ||
		manifest.Identity.SandboxID != registration.Identity.SandboxID ||
		manifest.Identity.SandboxGeneration != registration.Identity.SandboxGeneration ||
		manifest.Identity.Instance == "" ||
		manifest.Profile.ProfileID == "" || !setupReceiptDigestPattern.MatchString(manifest.Profile.ProfileDigest) ||
		!setupReceiptDigestPattern.MatchString(manifest.Instructions.InstructionDigest) ||
		source.Report.RegisteredSourceID != binding.RegisteredSourceID ||
		source.Report.ServiceRegistrationID != binding.ServiceRegistrationID ||
		source.Report.ServiceGeneration != local.ServiceGeneration ||
		source.Report.ProjectID != registration.Identity.ProjectID ||
		source.Report.SandboxID != registration.Identity.SandboxID ||
		source.Report.SandboxGeneration != registration.Identity.SandboxGeneration ||
		source.Report.WorkspaceEpoch != registration.Identity.WorkspaceEpoch ||
		source.Report.ScopeRevision != registration.ScopeRevision ||
		source.Report.NativeSessionID != binding.NativeSessionID ||
		source.Report.NativeProjectID != binding.NativeProjectID ||
		source.Report.NativeLocationDigest != binding.NativeLocationDigest ||
		source.Instance != manifest.Identity.Instance ||
		source.Root == "" ||
		source.Report.Role != manifest.Identity.Role ||
		source.Report.ProfileRevision != manifest.Profile.ProfileRevision ||
		source.Report.InstructionRevision != manifest.Instructions.InstructionRevision {
		return continuitySourceProbe{}, false
	}
	return continuitySourceProbe{source: *source, service: *service}, true
}

// observeContinuitySource runs the existing real local supervisor status probe
// once and persists only its complete authentic outcome. A running answer that
// proves the exact stored native identity is stored available with the real
// probe completion time; a closed non-running answer is stored unavailable with
// its bounded reason; every ambiguous, malformed or foreign answer fails the
// pass closed without touching the stored row.
func (r *Reconciler) observeContinuitySource(ctx context.Context, probe continuitySourceProbe) error {
	report := probe.source.Report
	statusPayload, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "sandboxId": report.SandboxID, "instance": probe.source.Instance,
		"profileId": probe.service.Manifest.Profile.ProfileID, "profileDigest": probe.service.Manifest.Profile.ProfileDigest,
		"probe": true, "requestTimeoutSeconds": 30,
	})
	if err != nil {
		return err
	}
	stdout, stderr, execErr := r.ManagedRuntime.ExecManagedSupervisor(
		ctx, report.SandboxID, containers.ManagedSupervisorStatus, statusPayload,
	)
	var receipt managedSupervisorReceipt
	decodeErr := decodeManagedSupervisorReceipt(stdout, &receipt)
	if decodeErr != nil || receipt.SchemaVersion != 1 || receipt.Command != "status" {
		cause := decodeErr
		if cause == nil {
			cause = errors.New("status envelope is invalid")
		}
		if message := bounded(strings.TrimSpace(string(stderr)), 300); message != "" {
			cause = fmt.Errorf("%w: %s", cause, message)
		}
		return errors.Join(
			fmt.Errorf("continuity source %s status probe is invalid", report.RegisteredSourceID),
			cause, execErr,
		)
	}
	if receipt.Status == "running" {
		if code := runningReceiptFailureCode(execErr, receipt, probe); code != "" {
			// One bounded, value-free code identifies the first failed member of
			// the running-receipt conjunction in its exact evaluation order; no
			// receipt value, identity, path, command, stderr, token or payload is
			// ever included beyond the existing bounded message structure.
			return fmt.Errorf("continuity source %s status probe did not prove the exact stored native identity: %s", report.RegisteredSourceID, code)
		}
		observed := probe.source
		observed.Report.Availability = "available"
		observed.Report.Reason = nil
		observed.Report.LastObservedAt = r.now()
		return r.Store.PutContinuitySource(ctx, observed)
	}
	// The supervisor answered; the source is genuinely not running. The
	// authentic answer is persisted unavailable and stays visible.
	observed := probe.source
	observed.Report.Availability = "unavailable"
	reason := "source_unavailable"
	if receipt.Reason != "" && sourceProbeReasonPattern.MatchString(receipt.Reason) {
		reason = receipt.Reason
	}
	observed.Report.Reason = &reason
	observed.Report.LastObservedAt = r.now()
	return r.Store.PutContinuitySource(ctx, observed)
}

// runningReceiptFailureCode returns the bounded, value-free code of the FIRST
// failed member of the running status-receipt conjunction, in the exact
// evaluation order the available write requires. An empty code means every
// member proved the exact stored native identity.
func runningReceiptFailureCode(execErr error, receipt managedSupervisorReceipt, probe continuitySourceProbe) string {
	report := probe.source.Report
	switch {
	case execErr != nil:
		return "exec_error"
	case !receipt.Ready:
		return "not_ready"
	case receipt.Instance != probe.service.Manifest.Identity.Instance:
		return "instance_mismatch"
	case receipt.SandboxID != report.SandboxID:
		return "sandbox_mismatch"
	case receipt.ProfileID != probe.service.Manifest.Profile.ProfileID:
		return "profile_id_mismatch"
	case receipt.ProfileDigest != probe.service.Manifest.Profile.ProfileDigest:
		return "profile_digest_mismatch"
	case receipt.ProfileRevision != probe.service.Manifest.Profile.ProfileRevision:
		return "profile_revision_mismatch"
	case receipt.SessionID != report.NativeSessionID:
		return "session_mismatch"
	case receipt.NativeProjectID != report.NativeProjectID:
		return "native_project_mismatch"
	case receipt.NativeLocationDigest != report.NativeLocationDigest:
		return "native_location_mismatch"
	case receipt.InstructionRevision != probe.service.Manifest.Instructions.InstructionRevision:
		return "instruction_revision_mismatch"
	case receipt.InstructionDigest != probe.service.Manifest.Instructions.InstructionDigest:
		return "instruction_digest_mismatch"
	case !receipt.InstructionApplied:
		return "instruction_not_applied"
	default:
		return ""
	}
}
