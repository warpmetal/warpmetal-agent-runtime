package continuity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type BoundaryEngine interface {
	ExecContinuity(context.Context, string, []byte) ([]byte, []byte, error)
}

type Coordinator struct {
	Store    *state.Store
	Service  *Service
	Helper   BoundaryEngine
	Registry StateRegistry
	Now      func() time.Time
}

type boundaryEnvelope struct {
	FormatVersion int                   `json:"formatVersion"`
	Action        string                `json:"action"`
	Status        string                `json:"status"`
	Error         string                `json:"error,omitempty"`
	Receipt       SafeBoundaryReceiptV1 `json:"receipt"`
}

type boundaryRefusal struct{ code string }

func (e boundaryRefusal) Error() string { return "continuity helper refused: " + e.code }

func (c *Coordinator) Apply(ctx context.Context, manifest model.Manifest) error {
	if err := c.applyRegistrations(ctx, manifest); err != nil {
		return err
	}
	for _, operation := range manifest.ContinuityOperations {
		if err := c.applyOperation(ctx, operation); err != nil {
			return err
		}
	}
	return nil
}

// Acknowledge is the pre-failure acknowledgement phase owner decision A41
// adds. It durably applies only the continuity registration state the same
// fresh manifest explicitly carries, using every existing source, identity,
// binding, scope, service-generation, workspace, sandbox-generation and
// projection fence, and then retires only the local terminal
// continuity-operation outbox rows the control plane already acknowledged by
// dropping them from that same fresh manifest. It never executes or reexecutes
// an operation or helper, never acquires or releases a barrier, never
// synthesizes a receipt, never infers authority from absence for a nonterminal
// row, and never alters backend state. Every ambiguous or ineligible row stays
// byte-unchanged and fail-closed.
func (c *Coordinator) Acknowledge(ctx context.Context, manifest model.Manifest) error {
	if c.Store == nil {
		return errors.New("continuity coordinator store is unavailable")
	}
	// The backend's binding reactivation keeps one durable binding row and
	// advances its revision: the same fresh manifest carries the revoked
	// predecessor and the active successor under one binding ID, and the
	// binding-ID-keyed registration row is replaced by the successor. The
	// superseded owner must stay visible to acknowledgement ownership, so the
	// durable registration rows are snapshotted before the apply and the same
	// fresh manifest's validated tuples are kept as the control-plane authority
	// that explicitly named the superseded binding.
	prior, err := c.Store.ContinuityRegistrations(ctx)
	if err != nil {
		return err
	}
	if err := c.applyRegistrations(ctx, manifest); err != nil {
		return err
	}
	owners := make([]model.ContinuityRegistrationV1, 0, len(prior)+len(manifest.ContinuityRegistrations))
	for _, registration := range prior {
		owners = append(owners, registration.Manifest)
	}
	owners = append(owners, manifest.ContinuityRegistrations...)
	return c.retireAcknowledgedOperations(ctx, manifest, owners)
}

// applyRegistrations applies the manifest's continuity registration state. The
// fresh manifest re-lists the backend's binding-reactivation pair: the revoked
// predecessor beside the active successor under one binding ID. Only the
// effective registration per binding is durable state, resolved exactly as the
// validated manifest semantics require; the re-listed predecessor is historical
// manifest context and must never overwrite or downgrade the newer durable
// successor. Resolution is deterministic and order-independent, and every
// unsupported duplicate shape fails closed before any write.
func (c *Coordinator) applyRegistrations(ctx context.Context, manifest model.Manifest) error {
	effective, err := model.EffectiveContinuityRegistrations(manifest.ContinuityRegistrations)
	if err != nil {
		return err
	}
	ordered := append([]model.ContinuityRegistrationV1(nil), effective...)
	sort.SliceStable(ordered, func(left, right int) bool {
		return ordered[left].Binding.BindingID < ordered[right].Binding.BindingID
	})
	for _, desired := range ordered {
		existing, err := c.Store.ContinuityRegistration(ctx, desired.Binding.BindingID)
		if err != nil {
			return err
		}
		// Terminal registration receipts are immutable for the unchanged
		// registration. Re-applying the manifest after a later source
		// observation must not rewrite the verified/revoked/failed receipt the
		// control plane already accepted; freshness is enforced at capture
		// admission, not by rewriting registration history. The box-side
		// projection is still repaired from the trusted registration identity.
		if existing != nil && existing.ObservedStatus != "pending" &&
			reflect.DeepEqual(existing.Manifest, desired) {
			if err := c.repairRegistrationProjection(ctx, manifest, desired, existing.ObservedStatus); err != nil {
				return err
			}
			continue
		}
		local := state.LocalContinuityRegistration{Manifest: desired, ObservedStatus: "failed", ErrorCode: "source_unavailable"}
		if desired.DesiredState == "revoked" {
			local.ObservedStatus = "revoked"
			local.ErrorCode = ""
		} else if source, err := c.Store.ContinuitySource(ctx, desired.Binding.RegisteredSourceID); err == nil && source != nil &&
			sourceMatchesRegistration(*source, desired, c.now()) {
			local.ObservedStatus = "verified"
			local.ErrorCode = ""
			local.ServiceGeneration = source.Report.ServiceGeneration
			local.ReceiptDigest = digestJSON(struct {
				Registration model.ContinuityRegistrationV1 `json:"registration"`
				Source       model.ContinuitySourceReportV1 `json:"source"`
			}{Registration: desired, Source: source.Report})
		}
		if err := c.Store.PutContinuityRegistration(ctx, local); err != nil {
			return err
		}
		if err := c.repairRegistrationProjection(ctx, manifest, desired, local.ObservedStatus); err != nil {
			return err
		}
	}
	return nil
}

// retireAcknowledgedOperations retires exactly the local terminal outbox rows
// whose operation IDs the fresh manifest no longer carries, that have no live
// barrier, no live local operation and no other in-flight state, and whose
// immutable terminal report is structurally exact and owned by the durable
// registration history or by the same fresh manifest's validated registration
// tuples. The store performs the retirement atomically and preserves the exact
// receipt bytes as an immutable local tombstone.
func (c *Coordinator) retireAcknowledgedOperations(ctx context.Context, manifest model.Manifest, owners []model.ContinuityRegistrationV1) error {
	present := make(map[string]bool, len(manifest.ContinuityOperations))
	for _, operation := range manifest.ContinuityOperations {
		present[operation.OperationID] = true
	}
	_, err := c.Store.RetireContinuityOperationReports(ctx, func(candidate state.ContinuityOperationCandidate) (bool, error) {
		report := candidate.Report
		if candidate.BarrierPresent || candidate.LocalOperationLive || present[report.OperationID] {
			return false, nil
		}
		return acknowledgedTerminalOperation(report, owners), nil
	}, "manifest_absent_terminal_acknowledged")
	return err
}

// terminalContinuityOperationExact is the complete structural predicate a
// terminal continuity-operation outbox row must satisfy before it can be
// treated as an immutable acknowledged report. A nonterminal, malformed,
// incomplete or structurally foreign row never qualifies.
func terminalContinuityOperationExact(report model.ContinuityOperationReportV1) bool {
	if report.FormatVersion != 1 || report.Action != "capture_checkpoint" || report.ScopeRevision < 1 ||
		!safeIdentifier.MatchString(report.OperationID) || !validBoundaryBinding(report.Binding) ||
		!digestPattern.MatchString(report.RequestDigest) ||
		!safeIdentifier.MatchString(report.Identity.WorkID) || !safeIdentifier.MatchString(report.Identity.ProjectID) ||
		!safeIdentifier.MatchString(report.Identity.SandboxID) || !safeIdentifier.MatchString(report.Identity.WorkspaceEpoch) ||
		report.Identity.SandboxGeneration < 1 || report.Identity.ExpectedRevision < 1 ||
		(report.Identity.TaskID == nil) != (report.Identity.TaskAttempt == nil) ||
		report.Identity.TaskAttempt != nil && (*report.Identity.TaskAttempt < 1 || !safeIdentifier.MatchString(*report.Identity.TaskID)) ||
		(report.BoundaryKind != "initial" && report.BoundaryKind != "task" && report.BoundaryKind != "stopped") ||
		(report.BoundaryKind == "initial" && report.Identity.TaskID != nil) ||
		(report.BoundaryKind == "task" && report.Identity.TaskID == nil) {
		return false
	}
	switch report.Status {
	case "accepted":
		return report.LastError == nil && digestPattern.MatchString(report.ReceiptDigest) &&
			digestPattern.MatchString(report.ManifestDigest) && safeIdentifier.MatchString(report.CheckpointID) &&
			safeIdentifier.MatchString(report.CaptureID) && report.Bytes >= 0 && report.ObjectCount >= 0
	case "failed", "outcome_unknown":
		return report.LastError != nil && safeIdentifier.MatchString(report.LastError.Code) &&
			len(report.LastError.Message) <= 500
	default:
		return false
	}
}

// acknowledgedOperationOwnedByRegistration ties one terminal outbox row to a
// durable registration tuple this Runtime could have executed it for: either a
// registration row read before the current manifest applied, or a registration
// tuple the same fresh manifest explicitly carries (including the revoked
// predecessor of an in-place binding revision succession). The binding, the
// scope revision and the Work-level identity fence must all match exactly; a
// foreign or ambiguous identity/binding never qualifies.
func acknowledgedOperationOwnedByRegistration(report model.ContinuityOperationReportV1, owners []model.ContinuityRegistrationV1) bool {
	for _, owner := range owners {
		if owner.Binding == report.Binding && owner.ScopeRevision == report.ScopeRevision &&
			model.SameContinuityWorkFence(owner.Identity, report.Identity) {
			return true
		}
	}
	return false
}

func acknowledgedTerminalOperation(report model.ContinuityOperationReportV1, owners []model.ContinuityRegistrationV1) bool {
	return terminalContinuityOperationExact(report) && acknowledgedOperationOwnedByRegistration(report, owners)
}

// repairRegistrationProjection naturally materializes the box-side projection
// for an exact verified active registration, including unchanged terminal
// registrations whose receipt stays immutable. Stale, unavailable, or
// authority-mismatched source authority skips repair without creating or
// refreshing a projection. A projection failure is fail-closed and visible: it
// aborts the pass before any helper or operation, unless the same manifest
// carries an operation for this registration, in which case the operation path
// owns the visible registration_provision_failed outcome.
func (c *Coordinator) repairRegistrationProjection(
	ctx context.Context,
	manifest model.Manifest,
	registration model.ContinuityRegistrationV1,
	observedStatus string,
) error {
	if registration.DesiredState != "active" || !registration.ContinuityEnabled || observedStatus != "verified" {
		return nil
	}
	if _, owned, err := handoffTargetRegistrationOwnedByPreparation(ctx, c.Store, registration); err == nil && owned {
		// A completed ready continuation-handoff preparation exactly owns this
		// registration: its box-side projection belongs to the handoff mapping,
		// so the ordinary service-project authority does not apply.
		return nil
	}
	workspace, err := c.Registry.Resolve(ctx, registration.Identity)
	if err != nil {
		return nil
	}
	if err := c.provisionRegistrationProjection(ctx, registration, registration.Identity.TaskID, registration.Identity.TaskAttempt, workspace); err != nil {
		if registrationOperationCovers(manifest, registration) {
			return nil
		}
		return err
	}
	return nil
}

func registrationOperationCovers(manifest model.Manifest, registration model.ContinuityRegistrationV1) bool {
	for _, operation := range manifest.ContinuityOperations {
		if operation.Binding == registration.Binding &&
			model.SameContinuityWorkFence(operation.Identity, registration.Identity) {
			return true
		}
	}
	return false
}

func (c *Coordinator) applyOperation(ctx context.Context, operation model.ContinuityOperationV1) error {
	// A retired operation ID is a terminal acknowledgement. A later manifest
	// that re-carries the same ID is an ambiguous replay: fail closed before
	// any authority resolution, barrier, helper or capture work instead of
	// re-executing the acknowledged operation.
	if retired, err := c.Store.ContinuityOperationRetirement(ctx, operation.OperationID); err != nil {
		return err
	} else if retired != nil {
		return errors.New("continuity operation was already acknowledged and retired")
	}
	existing, err := c.Store.ContinuityOperationReports(ctx)
	if err != nil {
		return err
	}
	for _, report := range existing {
		if report.OperationID == operation.OperationID {
			if report.Identity.Equal(operation.Identity) && report.Binding == operation.Binding && report.ScopeRevision == operation.ScopeRevision && report.Action == operation.Action && report.BoundaryKind == operation.BoundaryKind && report.RequestDigest == operation.RequestDigest {
				if report.Status == "applying" {
					return nil
				}
				return nil
			}
			return errors.New("continuity operation replay conflicts")
		}
	}
	workspace, err := c.Registry.Resolve(ctx, operation.Identity)
	if err != nil {
		return c.failOperation(ctx, operation, "source_unavailable")
	}
	// The sandbox continuity helper refuses every boundary action until its
	// instance carries the exact registration projection, including this
	// operation's task/attempt pair.
	if err := c.provisionRegistration(ctx, operation, workspace); err != nil {
		return c.failOperation(ctx, operation, "registration_provision_failed")
	}
	request, err := c.helperRequest("acquire_boundary", operation, workspace)
	if err != nil {
		return c.failOperation(ctx, operation, "invalid_request")
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return c.failOperation(ctx, operation, "invalid_request")
	}
	// The intent is durable before the helper can acquire a barrier. An empty
	// receipt means the acquire response is not yet known and must be reconciled.
	if err := c.Store.PutContinuityBarrier(ctx, operation.OperationID, requestJSON, []byte{}); err != nil {
		return err
	}
	if err := c.Store.PutContinuityOperationReport(ctx, operationReport(operation, "applying")); err != nil {
		return err
	}
	receipt, rawReceipt, err := c.callHelper(ctx, operation.Identity.SandboxID, request, "acknowledged")
	if err != nil {
		var refused boundaryRefusal
		if errors.As(err, &refused) {
			if deleteErr := c.Store.DeleteContinuityBarrier(ctx, operation.OperationID); deleteErr != nil {
				return deleteErr
			}
			return c.failOperation(ctx, operation, refused.code)
		}
		return c.unknownOperation(ctx, operation, "boundary_outcome_unknown")
	}
	if err := c.Store.PutContinuityBarrier(ctx, operation.OperationID, requestJSON, rawReceipt); err != nil {
		return err
	}
	currentWorkspace, err := c.Registry.Resolve(ctx, operation.Identity)
	if err != nil || !sameWorkspaceFence(workspace, currentWorkspace) {
		if releaseErr := c.release(ctx, operation, workspace); releaseErr != nil {
			return c.unknownOperation(ctx, operation, "boundary_release_unknown")
		}
		if deleteErr := c.Store.DeleteContinuityBarrier(ctx, operation.OperationID); deleteErr != nil {
			return deleteErr
		}
		return c.failOperation(ctx, operation, "target_changed")
	}
	capture, captureErr := c.Service.Capture(ctx, CaptureRequestV1{
		OperationID: operation.OperationID + "_capture", RequestDigest: operation.RequestDigest,
		Identity: operation.Identity, SafeBoundary: receipt,
	})
	if captureErr != nil {
		if releaseErr := c.release(ctx, operation, workspace); releaseErr != nil {
			if reportErr := c.unknownOperation(ctx, operation, "boundary_release_unknown"); reportErr != nil {
				return errors.Join(captureErr, releaseErr, reportErr)
			}
			return nil
		}
		_ = c.Store.DeleteContinuityBarrier(ctx, operation.OperationID)
		return c.failOperation(ctx, operation, "capture_failed")
	}
	checkpoint, checkpointErr := c.Service.Checkpoint(ctx, CheckpointRequestV1{
		OperationID: operation.OperationID + "_checkpoint", RequestDigest: operation.RequestDigest,
		Identity: operation.Identity, CaptureID: capture.CaptureID,
	})
	if releaseErr := c.release(ctx, operation, workspace); releaseErr != nil {
		if reportErr := c.unknownOperation(ctx, operation, "boundary_release_unknown"); reportErr != nil {
			return errors.Join(releaseErr, reportErr)
		}
		return nil
	}
	if err := c.Store.DeleteContinuityBarrier(ctx, operation.OperationID); err != nil {
		return err
	}
	if checkpointErr != nil {
		return c.failOperation(ctx, operation, "checkpoint_failed")
	}
	report := operationReport(operation, "accepted")
	report.CheckpointID, report.CaptureID, report.ManifestDigest = checkpoint.CheckpointID, capture.CaptureID, capture.ManifestDigest
	report.Bytes, report.ObjectCount = capture.Bytes, capture.ObjectCount
	report.ReceiptDigest = digestJSON(report)
	return c.Store.PutContinuityOperationReport(ctx, report)
}

// provisionRegistration writes the exact continuity registration projection the
// sandbox helper requires before a boundary action. The projection carries this
// operation's task/attempt pair because the helper compares it exactly.
func (c *Coordinator) provisionRegistration(ctx context.Context, operation model.ContinuityOperationV1, workspace RegisteredWorkspace) error {
	registrations, err := c.Store.ContinuityRegistrations(ctx)
	if err != nil {
		return err
	}
	var manifest *model.ContinuityRegistrationV1
	for index := range registrations {
		candidate := registrations[index]
		if candidate.Manifest.Binding != operation.Binding ||
			!model.SameContinuityWorkFence(candidate.Manifest.Identity, operation.Identity) {
			continue
		}
		registration := candidate.Manifest
		manifest = &registration
		break
	}
	if manifest == nil {
		// No registration is associated with this operation; nothing to write.
		return nil
	}
	return c.provisionRegistrationProjection(ctx, *manifest, operation.Identity.TaskID, operation.Identity.TaskAttempt, workspace)
}

// provisionRegistrationProjection writes one exact continuity registration
// projection. The instance directory is a host-owned workspace path, so Runtime
// can provision it directly without a sandbox image change or generation
// advance. Registration-only repair projects the registration identity's
// task/attempt pair (normally null); the operation flow writes the boundary
// task/attempt pair immediately before the helper call.
func (c *Coordinator) provisionRegistrationProjection(
	ctx context.Context,
	registration model.ContinuityRegistrationV1,
	taskID *string,
	taskAttempt *int64,
	workspace RegisteredWorkspace,
) error {
	service, err := c.Store.ManagedService(ctx, registration.Binding.ServiceRegistrationID)
	if err != nil {
		return err
	}
	if service == nil {
		// Environments without a managed catalog cannot be provisioned here.
		return nil
	}
	if service.Phase != "ready" {
		return errors.New("managed service is not ready for continuity provisioning")
	}
	project, err := c.Store.ManagedProject(ctx, service.Manifest.Workspace.SelectionID)
	if err != nil {
		return err
	}
	if project == nil || project.Phase != "ready" {
		return errors.New("managed project is not ready for continuity provisioning")
	}
	identity := registration.Identity
	project_report := project.Report
	if project_report.ProjectID != identity.ProjectID || project_report.WorkspaceEpoch != identity.WorkspaceEpoch ||
		project_report.SandboxID != identity.SandboxID || project_report.SandboxGeneration != identity.SandboxGeneration ||
		project_report.ServiceRegistrationID == nil ||
		*project_report.ServiceRegistrationID != registration.Binding.ServiceRegistrationID ||
		project.HostRoot != workspace.Root || project.ContainerRoot == "" {
		return errors.New("continuity registration authority changed")
	}
	instance := service.Manifest.Identity.Instance
	instance_root := filepath.Join(project.Anchor, ".warpmetal", "opencode", "instances", instance)
	if !filepath.IsAbs(project.Anchor) ||
		!strings.HasPrefix(filepath.Clean(instance_root)+string(os.PathSeparator),
			filepath.Clean(project.Anchor)+string(os.PathSeparator)) {
		return errors.New("continuity registration path is invalid")
	}
	projection := map[string]any{
		"formatVersion":           1,
		"instance":                instance,
		"workId":                  identity.WorkID,
		"projectId":               identity.ProjectID,
		"sandboxId":               identity.SandboxID,
		"workspaceEpoch":          identity.WorkspaceEpoch,
		"sandboxGeneration":       identity.SandboxGeneration,
		"taskId":                  taskID,
		"taskAttempt":             taskAttempt,
		"expectedRevision":        identity.ExpectedRevision,
		"projectRoot":             project.ContainerRoot,
		"backgroundWriterState":   "idle",
		"lastAcceptedExecutionId": nil,
		"binding":                 registration.Binding,
	}
	payload, err := json.Marshal(projection)
	if err != nil {
		return err
	}
	return writeContinuityRegistration(filepath.Clean(instance_root), payload)
}

func writeContinuityRegistration(instanceRoot string, payload []byte) error {
	info, err := os.Lstat(instanceRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("continuity instance directory is unavailable")
	}
	target := filepath.Join(instanceRoot, "continuity-registration.json")
	contents := append(append([]byte(nil), payload...), '\n')
	if existing, err := os.Lstat(target); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 {
			return errors.New("continuity registration path is unsafe")
		}
		if existing.Mode().IsRegular() {
			if current, readErr := os.ReadFile(target); readErr == nil && bytes.Equal(current, contents) {
				// Byte-identical replay is a true no-op: no rename, no
				// mtime/owner/mode churn, and no staging file.
				return nil
			}
		}
	}
	temporary := target + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	// The Runtime supervisor may run as root while the sandbox container reads
	// this projection as its mapped workspace user, so match the instance
	// directory owner exactly as a container-side writer would.
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := os.Chown(target, int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	if directory, err := os.Open(instanceRoot); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func sameWorkspaceFence(left, right RegisteredWorkspace) bool {
	return left.Identity.Equal(right.Identity) && left.Root == right.Root && left.Instance == right.Instance &&
		left.Lifecycle == right.Lifecycle && left.LifecycleRevision == right.LifecycleRevision &&
		left.NoAdmittedExecution == right.NoAdmittedExecution && left.BoundaryBinding == right.BoundaryBinding
}

func (c *Coordinator) Recover(ctx context.Context) error {
	if err := c.Service.Recover(ctx); err != nil {
		return err
	}
	reports, err := c.Store.ContinuityOperationReports(ctx)
	if err != nil {
		return err
	}
	reportByID := make(map[string]model.ContinuityOperationReportV1, len(reports))
	for _, report := range reports {
		reportByID[report.OperationID] = report
	}
	barriers, err := c.Store.ContinuityBarriers(ctx)
	if err != nil {
		return err
	}
	for _, barrier := range barriers {
		var request map[string]any
		if err := json.Unmarshal(barrier.Request, &request); err != nil {
			return err
		}
		request["action"] = "reconcile_boundary"
		sandboxID := fmt.Sprint(request["sandboxId"])
		if _, _, err := c.callHelper(ctx, sandboxID, request, "acknowledged"); err != nil {
			var refused boundaryRefusal
			if errors.As(err, &refused) && refused.code == "boundary_missing" {
				if err := c.Store.DeleteContinuityBarrier(ctx, barrier.OperationID); err != nil {
					return err
				}
				continue
			}
			return err
		}
		request["action"] = "release_boundary"
		if _, _, err := c.callHelper(ctx, sandboxID, request, "released"); err != nil {
			return err
		}
		if err := c.Store.DeleteContinuityBarrier(ctx, barrier.OperationID); err != nil {
			return err
		}
		if report, ok := reportByID[barrier.OperationID]; ok && report.Status == "applying" {
			report.Status = "outcome_unknown"
			report.LastError = &model.ItemError{Code: "recovered_boundary_without_operation_result"}
			if err := c.Store.PutContinuityOperationReport(ctx, report); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Coordinator) Reports(ctx context.Context) ([]model.ContinuitySourceReportV1, []model.ContinuityRegistrationReportV1, []model.ContinuityOperationReportV1, error) {
	sources, err := c.Store.ContinuitySources(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	registrations, err := c.Store.ContinuityRegistrations(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	operations, err := c.Store.ContinuityOperationReports(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	sourceReports := make([]model.ContinuitySourceReportV1, 0, len(sources))
	for _, source := range sources {
		sourceReports = append(sourceReports, source.Report)
	}
	registrationReports := make([]model.ContinuityRegistrationReportV1, 0, len(registrations))
	for _, registration := range registrations {
		item, emit, err := reportableContinuityRegistration(registration)
		if err != nil {
			return nil, nil, nil, err
		}
		if !emit {
			continue
		}
		registrationReports = append(registrationReports, item)
	}
	if operations == nil {
		operations = make([]model.ContinuityOperationReportV1, 0)
	}
	return sourceReports, registrationReports, operations, nil
}

// reportableContinuityRegistration projects exactly one durable registration
// row onto the Runtime report. Only a structurally valid current
// desired-active registration is emitted, carrying the existing observed
// state, service generation, receipt digest and error fields unchanged. The
// exact manifest-revoked/continuity-disabled tuple the acknowledgement phase
// retained is omitted from the wire report without deleting, rewriting,
// re-verifying, synthesizing a digest, changing a timestamp or any other local
// mutation. A malformed or contradictory local manifest (unknown desired
// state, revoked+enabled, active+disabled, invalid identity/binding/revision,
// or an otherwise ambiguous row) fails report construction closed instead of
// being serialized or silently omitted.
func reportableContinuityRegistration(value state.LocalContinuityRegistration) (model.ContinuityRegistrationReportV1, bool, error) {
	manifest := value.Manifest
	if err := model.ValidateContinuityRegistration(manifest); err != nil {
		return model.ContinuityRegistrationReportV1{}, false,
			fmt.Errorf("continuity registration %s is not reportable: %w", manifest.Binding.BindingID, err)
	}
	switch {
	case manifest.DesiredState == "active" && manifest.ContinuityEnabled:
		item := model.ContinuityRegistrationReportV1{
			ContinuityRegistrationV1: manifest,
			ObservedStatus:           value.ObservedStatus,
			ServiceGeneration:        value.ServiceGeneration,
			ReceiptDigest:            value.ReceiptDigest,
		}
		if value.ErrorCode != "" {
			item.LastError = &model.ItemError{Code: value.ErrorCode}
		}
		return item, true, nil
	case manifest.DesiredState == "revoked" && !manifest.ContinuityEnabled &&
		value.ObservedStatus == "revoked" && value.ErrorCode == "":
		return model.ContinuityRegistrationReportV1{}, false, nil
	default:
		return model.ContinuityRegistrationReportV1{}, false,
			fmt.Errorf("continuity registration %s has a contradictory local manifest", manifest.Binding.BindingID)
	}
}

func (c *Coordinator) helperRequest(action string, operation model.ContinuityOperationV1, workspace RegisteredWorkspace) (map[string]any, error) {
	kind := operation.BoundaryKind
	if kind == "stopped" {
		if operation.Identity.TaskID == nil {
			kind = "initial"
		} else {
			kind = "task"
		}
	}
	if workspace.Instance == "" {
		return nil, errors.New("registered source instance is unavailable")
	}
	return map[string]any{"formatVersion": 1, "action": action, "kind": kind, "operationId": operation.OperationID, "instance": workspace.Instance, "workId": operation.Identity.WorkID, "projectId": operation.Identity.ProjectID, "sandboxId": operation.Identity.SandboxID, "workspaceEpoch": operation.Identity.WorkspaceEpoch, "sandboxGeneration": operation.Identity.SandboxGeneration, "taskId": operation.Identity.TaskID, "taskAttempt": operation.Identity.TaskAttempt, "expectedRevision": operation.Identity.ExpectedRevision, "binding": operation.Binding}, nil
}
func (c *Coordinator) callHelper(ctx context.Context, sandboxID string, request any, status string) (SafeBoundaryReceiptV1, []byte, error) {
	requestMap, ok := request.(map[string]any)
	if !ok {
		return SafeBoundaryReceiptV1{}, nil, errors.New("continuity helper request is not an object")
	}
	expectedAction, ok := requestMap["action"].(string)
	if !ok || expectedAction == "" {
		return SafeBoundaryReceiptV1{}, nil, errors.New("continuity helper request has no action")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return SafeBoundaryReceiptV1{}, nil, err
	}
	output, _, err := c.Helper.ExecContinuity(ctx, sandboxID, payload)
	// The packaged helper exits non-zero for structured refusals, so a closed
	// refusal envelope on stdout is authoritative even when exec reports an
	// error. Discarding it would hide the exact refusal code from recovery.
	var envelope boundaryEnvelope
	decoded := json.Unmarshal(output, &envelope) == nil &&
		envelope.FormatVersion == 1 && envelope.Action == expectedAction
	if err != nil {
		if decoded && envelope.Status == "refused" && envelope.Error != "" {
			return SafeBoundaryReceiptV1{}, output, boundaryRefusal{code: envelope.Error}
		}
		return SafeBoundaryReceiptV1{}, nil, err
	}
	if !decoded {
		return SafeBoundaryReceiptV1{}, nil, errors.New("continuity helper refused")
	}
	if envelope.Status == "refused" && envelope.Error != "" {
		return SafeBoundaryReceiptV1{}, output, boundaryRefusal{code: envelope.Error}
	}
	if envelope.Status != status {
		return SafeBoundaryReceiptV1{}, output, errors.New("continuity helper returned an unexpected status")
	}
	return envelope.Receipt, output, nil
}
func (c *Coordinator) release(ctx context.Context, operation model.ContinuityOperationV1, workspace RegisteredWorkspace) error {
	request, err := c.helperRequest("release_boundary", operation, workspace)
	if err != nil {
		return err
	}
	_, _, err = c.callHelper(ctx, operation.Identity.SandboxID, request, "released")
	return err
}
func (c *Coordinator) failOperation(ctx context.Context, operation model.ContinuityOperationV1, code string) error {
	report := operationReport(operation, "failed")
	report.LastError = &model.ItemError{Code: code}
	return c.Store.PutContinuityOperationReport(ctx, report)
}
func (c *Coordinator) unknownOperation(ctx context.Context, operation model.ContinuityOperationV1, code string) error {
	report := operationReport(operation, "outcome_unknown")
	report.LastError = &model.ItemError{Code: code}
	return c.Store.PutContinuityOperationReport(ctx, report)
}
func operationReport(operation model.ContinuityOperationV1, status string) model.ContinuityOperationReportV1 {
	return model.ContinuityOperationReportV1{FormatVersion: 1, OperationID: operation.OperationID, Action: operation.Action, ScopeRevision: operation.ScopeRevision, BoundaryKind: operation.BoundaryKind, Identity: operation.Identity, Binding: operation.Binding, Status: status, RequestDigest: operation.RequestDigest}
}
func sourceMatchesRegistration(source state.LocalContinuitySource, desired model.ContinuityRegistrationV1, now time.Time) bool {
	r := source.Report
	b := desired.Binding
	age := now.Sub(r.LastObservedAt)
	return age >= 0 && age <= SourceFreshness && r.Availability == "available" && r.RegisteredSourceID == b.RegisteredSourceID && r.ServiceRegistrationID == b.ServiceRegistrationID && r.NativeSessionID == b.NativeSessionID && r.NativeProjectID == b.NativeProjectID && r.NativeLocationDigest == b.NativeLocationDigest && r.ProjectID == desired.Identity.ProjectID && r.SandboxID == desired.Identity.SandboxID && r.SandboxGeneration == desired.Identity.SandboxGeneration && r.WorkspaceEpoch == desired.Identity.WorkspaceEpoch && r.ScopeRevision == desired.ScopeRevision
}
func digestJSON(value any) string {
	payload, _ := json.Marshal(value)
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}
