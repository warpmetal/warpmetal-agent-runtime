package continuity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

var (
	ErrS2AuthorityChanged      = errors.New("continuation or restore authority changed")
	ErrS2RecoveryUnknown       = errors.New("continuation baseline recovery is unknown")
	ErrS2ControllerUnavailable = errors.New("continuation baseline and restore controller are not installed")
)

type S2ObjectStore interface {
	Verify(context.Context, string) (storage.DurableCapture, error)
	VerifyWorkspace(context.Context, string, string) error
	MaterializeNew(context.Context, storage.MaterializeNewRequest) (storage.MaterializeReceipt, error)
}

type S2ProjectCatalog interface {
	Resolve(context.Context, workspacecatalog.ResolveProjectRequest) (workspacecatalog.RegisteredProject, error)
	AllocateRestore(context.Context, workspacecatalog.RestoreProjectRequest) (workspacecatalog.RegisteredProject, error)
	CompleteRestore(context.Context, string) (workspacecatalog.RegisteredProject, error)
	AllocateHandoff(context.Context, workspacecatalog.HandoffProjectRequest) (workspacecatalog.RegisteredProject, error)
	CompleteHandoff(context.Context, string) (workspacecatalog.RegisteredProject, error)
}

type HandoffSupervisorEngine interface {
	ExecManagedSupervisor(context.Context, string, containers.ManagedSupervisorAction, []byte) ([]byte, []byte, error)
}

type HandoffAdmissionEngine interface {
	ScheduleContinuationHandoff(context.Context, string, model.ContinuationHandoffManifestV1, model.ContinuityRegistrationV1) error
}

type S2Controller struct {
	Store             *state.Store
	ServerID          string
	Objects           S2ObjectStore
	Catalog           S2ProjectCatalog
	Helper            BoundaryEngine
	HandoffSupervisor HandoffSupervisorEngine
	HandoffAdmission  HandoffAdmissionEngine
	Now               func() time.Time

	mu sync.Mutex
}

type currentS2Authority struct {
	source  state.LocalContinuitySource
	project workspacecatalog.RegisteredProject
	anchor  string
}

type continuationHelperRequest struct {
	model.ContinuationManifestV1
	Instance string `json:"instance"`
}

type continuationConsumption struct {
	TaskID     string    `json:"taskId"`
	MessageID  string    `json:"messageId"`
	Attempt    int64     `json:"attempt"`
	Fence      string    `json:"fence"`
	ConsumedAt time.Time `json:"consumedAt"`
}

type continuationRelease struct {
	ReleasedAt time.Time `json:"releasedAt"`
}

type continuationRecoveryEnvelope struct {
	FormatVersion int                        `json:"formatVersion"`
	Action        string                     `json:"action"`
	Status        string                     `json:"status"`
	State         string                     `json:"state"`
	Report        model.ContinuationReportV1 `json:"report"`
	Consumption   *continuationConsumption   `json:"consumption"`
	Release       *continuationRelease       `json:"release"`
}

type continuationRefusal struct {
	FormatVersion int            `json:"formatVersion"`
	Action        string         `json:"action"`
	Status        string         `json:"status"`
	Error         string         `json:"error"`
	Facts         map[string]any `json:"facts"`
}

func (c *S2Controller) Apply(ctx context.Context, continuations []model.ContinuationManifestV1, restores []model.RestoreManifestV1) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.configured(); err != nil {
		if len(continuations) == 0 && len(restores) == 0 {
			return nil
		}
		return err
	}
	for _, manifest := range continuations {
		if err := c.applyContinuation(ctx, manifest); err != nil {
			return err
		}
	}
	for _, manifest := range restores {
		if err := c.applyRestore(ctx, manifest); err != nil {
			return err
		}
	}
	// Deliberately do not infer abandonment from omission. A prepared baseline
	// may already be consumed by an accepted backend task awaiting claim.
	return nil
}

func (c *S2Controller) Recover(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.configured(); err != nil {
		return err
	}
	continuations, err := c.Store.ContinuationPreparations(ctx)
	if err != nil {
		return err
	}
	for _, record := range continuations {
		if record.Report != nil {
			continue
		}
		if err := c.recoverContinuation(ctx, record.Manifest); err != nil {
			return err
		}
	}
	releases, err := c.Store.ContinuationReleases(ctx)
	if err != nil {
		return err
	}
	for _, record := range releases {
		if record.Report != nil {
			continue
		}
		if err := c.recoverRelease(ctx, record.Manifest); err != nil {
			return err
		}
	}
	restores, err := c.Store.RestoreOperations(ctx)
	if err != nil {
		return err
	}
	for _, record := range restores {
		if record.Report != nil {
			continue
		}
		if err := c.applyRestore(ctx, record.Manifest); err != nil {
			return err
		}
	}
	return nil
}

func (c *S2Controller) ApplyReleases(ctx context.Context, releases []model.ContinuationReleaseManifestV1) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.configured(); err != nil {
		if len(releases) == 0 {
			return nil
		}
		return err
	}
	for _, release := range releases {
		if err := c.applyRelease(ctx, release); err != nil {
			return err
		}
	}
	return nil
}

func (c *S2Controller) ReleaseReports(ctx context.Context) ([]model.ContinuationReleaseReportV1, error) {
	records, err := c.Store.ContinuationReleases(ctx)
	if err != nil {
		return nil, err
	}
	reports := make([]model.ContinuationReleaseReportV1, 0, len(records))
	for _, record := range records {
		if record.Report != nil {
			reports = append(reports, *record.Report)
		}
	}
	return reports, nil
}

func (c *S2Controller) Reports(ctx context.Context) ([]model.ContinuationReportV1, []model.RestoreReportV1, error) {
	continuationRecords, err := c.Store.ContinuationPreparations(ctx)
	if err != nil {
		return nil, nil, err
	}
	restoreRecords, err := c.Store.RestoreOperations(ctx)
	if err != nil {
		return nil, nil, err
	}
	continuations := make([]model.ContinuationReportV1, 0)
	for _, record := range continuationRecords {
		if record.Report != nil {
			continuations = append(continuations, *record.Report)
		}
	}
	restores := make([]model.RestoreReportV1, 0)
	for _, record := range restoreRecords {
		if record.Report != nil {
			restores = append(restores, *record.Report)
		}
	}
	return continuations, restores, nil
}

func (c *S2Controller) applyContinuation(ctx context.Context, manifest model.ContinuationManifestV1) error {
	existing, err := c.Store.ContinuationPreparation(ctx, manifest.OperationID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Manifest, manifest) {
			return state.ErrContinuationConflict
		}
		if existing.Report != nil {
			return nil
		}
		return c.recoverContinuation(ctx, manifest)
	}
	authority, err := c.validateContinuationAuthority(ctx, manifest)
	if err != nil {
		if errors.Is(err, storage.ErrWorkspaceChanged) {
			if putErr := c.Store.PutContinuationPreparation(ctx, state.LocalContinuationPreparation{Manifest: manifest, Phase: "preparing"}); putErr != nil {
				return putErr
			}
			return c.Store.CompleteContinuationPreparation(ctx, manifest.OperationID, failedContinuationReport(manifest, "workspace_changed"))
		}
		return err
	}
	if err := c.Store.PutContinuationPreparation(ctx, state.LocalContinuationPreparation{Manifest: manifest, Phase: "preparing"}); err != nil {
		return err
	}
	request := continuationHelperRequest{ContinuationManifestV1: manifest, Instance: authority.source.Instance}
	response, err := c.execHelper(ctx, manifest.Identity.SandboxID, request)
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	var report model.ContinuationReportV1
	if err := decodeClosed(response, &report); err != nil || !validReadyReport(manifest, report) {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	return c.Store.CompleteContinuationPreparation(ctx, manifest.OperationID, report)
}

func (c *S2Controller) recoverContinuation(ctx context.Context, manifest model.ContinuationManifestV1) error {
	authority, err := c.validateContinuationAuthority(ctx, manifest)
	if err != nil {
		return err
	}
	request := continuationHelperRequest{ContinuationManifestV1: manifest, Instance: authority.source.Instance}
	request.Action = "reconcile_continuation"
	response, err := c.execHelper(ctx, manifest.Identity.SandboxID, request)
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	var envelope continuationRecoveryEnvelope
	if err := decodeClosed(response, &envelope); err != nil || envelope.FormatVersion != 1 || envelope.Action != "reconcile_continuation" ||
		!validReadyReport(manifest, envelope.Report) {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	switch {
	case envelope.Status == "ready" && envelope.State == "prepared" && envelope.Consumption == nil && envelope.Release == nil:
	case envelope.Status == "consumed" && envelope.State == "consumed" && validConsumption(envelope.Consumption) && envelope.Release == nil:
	default:
		return ErrS2RecoveryUnknown
	}
	return c.Store.CompleteContinuationPreparation(ctx, manifest.OperationID, envelope.Report)
}

func (c *S2Controller) applyRelease(ctx context.Context, release model.ContinuationReleaseManifestV1) error {
	existing, err := c.Store.ContinuationRelease(ctx, release.OperationID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Manifest, release) {
			return state.ErrContinuationConflict
		}
		if existing.Report != nil {
			return nil
		}
		return c.recoverRelease(ctx, release)
	}
	preparation, err := c.releasePreparation(ctx, release)
	if err != nil {
		return err
	}
	if err := c.Store.PutContinuationRelease(ctx, state.LocalContinuationRelease{Manifest: release, Phase: "releasing"}); err != nil {
		return err
	}
	if preparation.Report.Status == "failed" && preparation.Report.Baseline == nil {
		return c.Store.CompleteContinuationRelease(ctx, release.OperationID, releasedContinuationReport(release))
	}
	return c.dispatchRelease(ctx, release, *preparation)
}

func (c *S2Controller) recoverRelease(ctx context.Context, release model.ContinuationReleaseManifestV1) error {
	preparation, err := c.releasePreparation(ctx, release)
	if err != nil {
		return err
	}
	if preparation.Report.Status == "failed" && preparation.Report.Baseline == nil {
		return c.Store.CompleteContinuationRelease(ctx, release.OperationID, releasedContinuationReport(release))
	}
	instance, err := c.releaseInstance(ctx, preparation.Manifest)
	if err != nil {
		return err
	}
	request := continuationHelperRequest{ContinuationManifestV1: preparation.Manifest, Instance: instance}
	request.Action = "reconcile_continuation"
	response, err := c.execHelper(ctx, preparation.Manifest.Identity.SandboxID, request)
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	var envelope continuationRecoveryEnvelope
	if err := decodeClosed(response, &envelope); err != nil || envelope.FormatVersion != 1 || envelope.Action != "reconcile_continuation" ||
		!validReadyReport(preparation.Manifest, envelope.Report) {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	switch {
	case envelope.Status == "released" && envelope.State == "released" && envelope.Consumption == nil && validRelease(envelope.Release):
		return c.Store.CompleteContinuationRelease(ctx, release.OperationID, releasedContinuationReport(release))
	case envelope.Status == "consumed" && envelope.State == "consumed" && validConsumption(envelope.Consumption) && envelope.Release == nil:
		return c.Store.CompleteContinuationRelease(ctx, release.OperationID, failedContinuationReleaseReport(release, "continuation_consumed"))
	case envelope.Status == "ready" && envelope.State == "prepared" && envelope.Consumption == nil && envelope.Release == nil:
		return c.dispatchRelease(ctx, release, *preparation)
	default:
		return ErrS2RecoveryUnknown
	}
}

func (c *S2Controller) dispatchRelease(ctx context.Context, release model.ContinuationReleaseManifestV1, preparation state.LocalContinuationPreparation) error {
	instance, err := c.releaseInstance(ctx, preparation.Manifest)
	if err != nil {
		return err
	}
	request := continuationHelperRequest{ContinuationManifestV1: preparation.Manifest, Instance: instance}
	request.Action = "release_continuation"
	response, err := c.execHelper(ctx, preparation.Manifest.Identity.SandboxID, request)
	if err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	var status struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(response, &status); err != nil {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	if status.Status == "refused" {
		var refusal continuationRefusal
		if err := decodeClosed(response, &refusal); err != nil || refusal.FormatVersion != 1 || refusal.Action != "release_continuation" ||
			!safeIdentifier.MatchString(refusal.Error) {
			return errors.Join(ErrS2RecoveryUnknown, err)
		}
		return c.Store.CompleteContinuationRelease(ctx, release.OperationID, failedContinuationReleaseReport(release, refusal.Error))
	}
	var envelope continuationRecoveryEnvelope
	if err := decodeClosed(response, &envelope); err != nil || envelope.FormatVersion != 1 || envelope.Action != "release_continuation" ||
		envelope.Status != "released" || envelope.State != "released" || envelope.Consumption != nil || !validRelease(envelope.Release) ||
		!reflect.DeepEqual(envelope.Report, *preparation.Report) {
		return errors.Join(ErrS2RecoveryUnknown, err)
	}
	return c.Store.CompleteContinuationRelease(ctx, release.OperationID, releasedContinuationReport(release))
}

func (c *S2Controller) releasePreparation(ctx context.Context, release model.ContinuationReleaseManifestV1) (*state.LocalContinuationPreparation, error) {
	preparation, err := c.Store.ContinuationPreparation(ctx, release.OperationID)
	if err != nil || preparation == nil || preparation.Report == nil || !releaseMatchesPreparation(release, preparation.Manifest) {
		return nil, errors.Join(ErrS2AuthorityChanged, err)
	}
	validReady := preparation.Report.Status == "ready" && validReadyReport(preparation.Manifest, *preparation.Report)
	validFailed := preparation.Report.Status == "failed" && preparation.Report.Baseline == nil && preparation.Report.ErrorCode != nil
	if !validReady && !validFailed {
		return nil, ErrS2AuthorityChanged
	}
	return preparation, nil
}

func (c *S2Controller) releaseInstance(ctx context.Context, preparation model.ContinuationManifestV1) (string, error) {
	source, err := c.Store.ContinuitySource(ctx, preparation.Binding.RegisteredSourceID)
	if err != nil || source == nil || source.Instance == "" {
		return "", errors.Join(ErrS2AuthorityChanged, err)
	}
	return source.Instance, nil
}

func (c *S2Controller) applyRestore(ctx context.Context, manifest model.RestoreManifestV1) error {
	existing, err := c.Store.RestoreOperation(ctx, manifest.OperationID)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Manifest, manifest) {
			return state.ErrRestoreConflict
		}
		if existing.Report != nil {
			return nil
		}
	}
	authority, checkpoint, err := c.validateRestoreAuthority(ctx, manifest)
	if err != nil {
		return err
	}
	if existing == nil {
		if err := c.Store.PutRestoreOperation(ctx, state.LocalRestoreOperation{Manifest: manifest, Phase: "allocating"}); err != nil {
			return err
		}
	}
	project, err := c.Catalog.AllocateRestore(ctx, workspacecatalog.RestoreProjectRequest{
		OperationID: manifest.OperationID, Anchor: authority.anchor, ServerID: c.ServerID,
		SandboxID: manifest.Target.SandboxID, SandboxGeneration: manifest.Target.SandboxGeneration,
	})
	if err != nil {
		return err
	}
	destination := checkpoint.Identity
	destination.ProjectID, destination.WorkspaceEpoch = project.Report.ProjectID, project.Report.WorkspaceEpoch
	destination.TaskID, destination.TaskAttempt = nil, nil
	receipt, err := c.Objects.MaterializeNew(ctx, storage.MaterializeNewRequest{
		CheckpointID: checkpoint.CaptureID, SourceIdentity: checkpoint.Identity, DestinationIdentity: destination,
		SourceRoot: authority.source.Root, DestinationRoot: project.HostRoot,
		Ownership: &storage.MaterializationOwnership{Anchor: authority.anchor, RootDevice: project.RootDevice, RootInode: project.RootInode},
	})
	if err != nil {
		return err
	}
	if receipt.ManifestDigest != manifest.Checkpoint.ManifestDigest || receipt.Bytes != manifest.Checkpoint.Bytes ||
		receipt.ObjectCount != manifest.Checkpoint.ObjectCount || !receipt.DestinationIdentity.Equal(destination) {
		return storage.ErrCheckpointCorrupt
	}
	project, err = c.Catalog.CompleteRestore(ctx, manifest.OperationID)
	if err != nil {
		return err
	}
	report := model.RestoreReportV1{
		FormatVersion: 1, OperationID: manifest.OperationID, Action: manifest.Action, Status: "accepted",
		DesiredRevision: manifest.DesiredRevision, Identity: manifest.Identity, Binding: manifest.Binding,
		Checkpoint: manifest.Checkpoint, Target: &model.RestoreResultTargetV1{
			SelectionID: project.Report.SelectionID, ProjectID: project.Report.ProjectID, WorkspaceEpoch: project.Report.WorkspaceEpoch,
			ScopeRevision: project.ScopeRevision, RootAttestation: project.Report.RootAttestation,
		},
		DependencyStatus: "ready", Exclusions: []string{"native_history", "credentials", "runtime_state", "external_side_effects"},
	}
	report.ReceiptDigest = s2ReceiptDigest(report)
	return c.Store.CompleteRestoreOperation(ctx, manifest.OperationID, report)
}

func (c *S2Controller) validateContinuationAuthority(ctx context.Context, manifest model.ContinuationManifestV1) (currentS2Authority, error) {
	authority, accepted, err := c.validateCommonAuthority(ctx, manifest.Identity, manifest.Binding, manifest.Checkpoint)
	if err != nil {
		return currentS2Authority{}, err
	}
	if manifest.Target.Role != "worker" || manifest.Target.SandboxID != manifest.Identity.SandboxID ||
		manifest.Target.SandboxGeneration != manifest.Identity.SandboxGeneration || manifest.Target.ProjectID != manifest.Identity.ProjectID ||
		manifest.Target.WorkspaceEpoch != manifest.Identity.WorkspaceEpoch || manifest.Target.ServiceRegistrationID != manifest.Binding.ServiceRegistrationID ||
		manifest.Target.ServiceGeneration != manifest.Binding.ServiceGeneration || manifest.Target.ScopeRevision != manifest.Binding.ScopeRevision {
		return currentS2Authority{}, ErrS2AuthorityChanged
	}
	service, err := c.Store.ManagedService(ctx, manifest.Binding.ServiceRegistrationID)
	if err != nil || service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" ||
		service.Manifest.ActionRevision != manifest.Target.ServiceActionRevision || service.Manifest.DesiredRevision != manifest.Target.ServiceDesiredRevision ||
		service.ServiceGeneration != manifest.Target.ServiceGeneration || service.Manifest.Identity.TeamID != manifest.Target.TeamID ||
		service.Manifest.Identity.MemberID != manifest.Target.MemberID || service.Manifest.Identity.Role != manifest.Target.Role ||
		service.Manifest.Profile.ProfileID != manifest.Target.ProfileID || service.Manifest.Profile.ProfileRevision != manifest.Target.ProfileRevision ||
		service.Manifest.Profile.ProfileDigest != manifest.Target.ProfileDigest ||
		service.Manifest.Instructions.InstructionRevision != manifest.Target.InstructionRevision ||
		service.Manifest.Instructions.InstructionDigest != manifest.Target.InstructionDigest ||
		service.Manifest.Workspace.SelectionID != manifest.Target.SelectionID || service.Manifest.Workspace.ProjectID != manifest.Target.ProjectID ||
		service.Manifest.Workspace.WorkspaceEpoch != manifest.Target.WorkspaceEpoch || service.Manifest.Workspace.ScopeRevision != manifest.Target.ScopeRevision ||
		service.Manifest.Workspace.RootAttestation != manifest.Target.RootAttestation || !service.Report.InstructionApplied ||
		service.Report.InstructionRevision != manifest.Target.InstructionRevision || service.Report.InstructionDigest != manifest.Target.InstructionDigest ||
		service.Report.NativeRegistration == nil || service.Report.NativeRegistration.RegisteredSourceID != manifest.Binding.RegisteredSourceID ||
		service.Report.NativeRegistration.NativeSessionID != manifest.Binding.NativeSessionID ||
		service.Report.NativeRegistration.NativeProjectID != manifest.Binding.NativeProjectID ||
		service.Report.NativeRegistration.NativeLocationDigest != manifest.Binding.NativeLocationDigest {
		return currentS2Authority{}, errors.Join(ErrS2AuthorityChanged, err)
	}
	project, err := c.Catalog.Resolve(ctx, workspacecatalog.ResolveProjectRequest{
		SelectionID: manifest.Target.SelectionID, ProjectID: manifest.Target.ProjectID, WorkspaceEpoch: manifest.Target.WorkspaceEpoch,
		SandboxID: manifest.Target.SandboxID, SandboxGeneration: manifest.Target.SandboxGeneration,
		ServiceRegistrationID: manifest.Target.ServiceRegistrationID, ConfigDigest: service.Manifest.ConfigDigest,
	})
	if err != nil || project.Report.RootAttestation != manifest.Target.RootAttestation {
		return currentS2Authority{}, errors.Join(ErrS2AuthorityChanged, err)
	}
	if err := c.Objects.VerifyWorkspace(ctx, accepted.CaptureID, authority.source.Root); err != nil {
		return currentS2Authority{}, err
	}
	authority.project = project
	return authority, nil
}

func (c *S2Controller) validateRestoreAuthority(ctx context.Context, manifest model.RestoreManifestV1) (currentS2Authority, *state.LocalCheckpoint, error) {
	if manifest.Target.Mode != "create_new" || manifest.Target.SandboxID != manifest.Identity.SandboxID ||
		manifest.Target.SandboxGeneration != manifest.Identity.SandboxGeneration {
		return currentS2Authority{}, nil, ErrS2AuthorityChanged
	}
	return c.validateCommonAuthority(ctx, manifest.Identity, manifest.Binding, manifest.Checkpoint)
}

// validateRetainedCheckpoint proves the manifest still points at the exact
// accepted, verified capture. It deliberately excludes the source registration
// and freshness fences so that a materialized handoff target can be resumed
// after its source authority advanced.
func (c *S2Controller) validateRetainedCheckpoint(ctx context.Context, identity model.ContinuationIdentityV1, checkpointRef model.ContinuationCheckpointRefV1) (*state.LocalCheckpoint, error) {
	accepted, err := c.Store.AcceptedCheckpoint(ctx, identity.WorkID)
	if err != nil || accepted == nil || accepted.ID != checkpointRef.CheckpointID || accepted.ManifestDigest != checkpointRef.ManifestDigest ||
		accepted.Bytes != checkpointRef.Bytes || accepted.ObjectCount != checkpointRef.ObjectCount || !sameS2Identity(accepted.Identity, identity) {
		return nil, errors.Join(ErrS2AuthorityChanged, err)
	}
	capture, err := c.Objects.Verify(ctx, accepted.CaptureID)
	if err != nil {
		return nil, err
	}
	if capture.ManifestDigest != checkpointRef.ManifestDigest || capture.Bytes != checkpointRef.Bytes || capture.ObjectCount != checkpointRef.ObjectCount ||
		!capture.Manifest.Identity.Equal(accepted.Identity) {
		return nil, storage.ErrCheckpointCorrupt
	}
	operationReports, err := c.Store.ContinuityOperationReports(ctx)
	if err != nil {
		return nil, err
	}
	foundOperation := false
	for _, report := range operationReports {
		if report.OperationID == checkpointRef.OperationID && report.Status == "accepted" && report.CheckpointID == checkpointRef.CheckpointID &&
			report.ManifestDigest == checkpointRef.ManifestDigest && report.Bytes == checkpointRef.Bytes && report.ObjectCount == checkpointRef.ObjectCount {
			foundOperation = true
			break
		}
	}
	if !foundOperation {
		return nil, ErrS2AuthorityChanged
	}
	return accepted, nil
}

func (c *S2Controller) validateCommonAuthority(ctx context.Context, identity model.ContinuationIdentityV1, binding model.ContinuationBindingRefV1, checkpointRef model.ContinuationCheckpointRefV1) (currentS2Authority, *state.LocalCheckpoint, error) {
	accepted, err := c.validateRetainedCheckpoint(ctx, identity, checkpointRef)
	if err != nil {
		return currentS2Authority{}, nil, err
	}
	registration, err := c.Store.ContinuityRegistration(ctx, binding.BindingID)
	if err != nil || registration == nil || registration.ObservedStatus != "verified" || !registration.Manifest.ContinuityEnabled ||
		registration.Manifest.DesiredState != "active" || registration.Manifest.Binding.BindingRevision != binding.BindingRevision ||
		registration.Manifest.ScopeRevision != binding.ScopeRevision || registration.ServiceGeneration != binding.ServiceGeneration ||
		!sameS2Identity(registration.Manifest.Identity, identity) || !sameS2Binding(registration.Manifest.Binding, binding) {
		return currentS2Authority{}, nil, errors.Join(ErrS2AuthorityChanged, err)
	}
	source, err := c.Store.ContinuitySource(ctx, binding.RegisteredSourceID)
	if err != nil || source == nil || source.Report.Availability != "available" || source.Report.ServiceRegistrationID != binding.ServiceRegistrationID ||
		source.Report.ServiceGeneration != binding.ServiceGeneration || source.Report.ProjectID != identity.ProjectID ||
		source.Report.SandboxID != identity.SandboxID || source.Report.SandboxGeneration != identity.SandboxGeneration ||
		source.Report.WorkspaceEpoch != identity.WorkspaceEpoch || source.Report.ScopeRevision != binding.ScopeRevision ||
		source.Report.NativeSessionID != binding.NativeSessionID || source.Report.NativeProjectID != binding.NativeProjectID ||
		source.Report.NativeLocationDigest != binding.NativeLocationDigest || source.Lifecycle != "running" || source.LifecycleRevision < 1 ||
		c.now().Sub(source.Report.LastObservedAt) > 120*time.Second {
		return currentS2Authority{}, nil, errors.Join(ErrS2AuthorityChanged, err)
	}
	barriers, err := c.Store.ContinuityBarriers(ctx)
	if err != nil || len(barriers) != 0 {
		return currentS2Authority{}, nil, errors.Join(ErrS2AuthorityChanged, err)
	}
	project, err := c.Store.ManagedProjectForRoot(ctx, identity.SandboxID, identity.SandboxGeneration, source.Root)
	if err != nil || project == nil || project.Report.ProjectID != identity.ProjectID || project.Report.WorkspaceEpoch != identity.WorkspaceEpoch ||
		project.Report.Availability != "available" || project.Anchor == "" {
		return currentS2Authority{}, nil, errors.Join(ErrS2AuthorityChanged, err)
	}
	return currentS2Authority{source: *source, anchor: project.Anchor}, accepted, nil
}

func (c *S2Controller) configured() error {
	if c.Store == nil || !safeIdentifier.MatchString(c.ServerID) || c.Objects == nil || c.Catalog == nil || c.Helper == nil {
		return ErrS2ControllerUnavailable
	}
	return nil
}

func (c *S2Controller) execHelper(ctx context.Context, sandboxID string, request continuationHelperRequest) ([]byte, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	stdout, stderr, err := c.Helper.ExecContinuity(ctx, sandboxID, payload)
	if err != nil {
		return nil, fmt.Errorf("continuation helper: %s: %w", boundedHelperOutput(stderr), err)
	}
	return stdout, nil
}

func decodeClosed(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("continuation helper emitted trailing JSON")
	}
	return nil
}

func validReadyReport(manifest model.ContinuationManifestV1, report model.ContinuationReportV1) bool {
	return continuationReportMatchesManifest(manifest, report) && report.Status == "ready" && report.ErrorCode == nil && report.Baseline != nil &&
		digestPattern.MatchString(report.Baseline.BaselineDigest) && safeIdentifier.MatchString(report.Baseline.BaselineID) &&
		report.Baseline.NativeSessionID == manifest.Binding.NativeSessionID &&
		report.Baseline.ServiceGeneration == manifest.Binding.ServiceGeneration && !report.Baseline.ReadyAt.IsZero() &&
		digestPattern.MatchString(report.ReceiptDigest)
}

func failedContinuationReport(manifest model.ContinuationManifestV1, code string) model.ContinuationReportV1 {
	report := model.ContinuationReportV1{
		FormatVersion:   manifest.FormatVersion,
		OperationID:     manifest.OperationID,
		Action:          manifest.Action,
		Status:          "failed",
		DesiredRevision: manifest.DesiredRevision,
		Identity:        manifest.Identity,
		Binding:         manifest.Binding,
		Checkpoint:      manifest.Checkpoint,
		Target:          manifest.Target,
		ContextDigest:   manifest.Context.Digest,
		Baseline:        nil,
		ErrorCode:       &code,
	}
	report.ReceiptDigest = s2ReceiptDigest(report)
	return report
}

func continuationReportMatchesManifest(manifest model.ContinuationManifestV1, report model.ContinuationReportV1) bool {
	return report.FormatVersion == 1 && report.OperationID == manifest.OperationID && report.Action == manifest.Action &&
		report.DesiredRevision == manifest.DesiredRevision && reflect.DeepEqual(report.Identity, manifest.Identity) &&
		reflect.DeepEqual(report.Binding, manifest.Binding) && reflect.DeepEqual(report.Checkpoint, manifest.Checkpoint) &&
		reflect.DeepEqual(report.Target, manifest.Target) && report.ContextDigest == manifest.Context.Digest
}

func validConsumption(value *continuationConsumption) bool {
	return value != nil && safeIdentifier.MatchString(value.TaskID) && safeIdentifier.MatchString(value.MessageID) &&
		value.Attempt > 0 && safeIdentifier.MatchString(value.Fence) && !value.ConsumedAt.IsZero()
}

func validRelease(value *continuationRelease) bool {
	return value != nil && !value.ReleasedAt.IsZero()
}

func releaseMatchesPreparation(release model.ContinuationReleaseManifestV1, preparation model.ContinuationManifestV1) bool {
	return release.FormatVersion == preparation.FormatVersion && release.OperationID == preparation.OperationID &&
		release.Action == "release_continuation" && release.DesiredRevision > preparation.DesiredRevision &&
		(release.Reason == "failed" || release.Reason == "superseded") && reflect.DeepEqual(release.Identity, preparation.Identity) &&
		reflect.DeepEqual(release.Binding, preparation.Binding) && reflect.DeepEqual(release.Checkpoint, preparation.Checkpoint) &&
		reflect.DeepEqual(release.Target, preparation.Target) && reflect.DeepEqual(release.Context, preparation.Context)
}

func releasedContinuationReport(manifest model.ContinuationReleaseManifestV1) model.ContinuationReleaseReportV1 {
	report := continuationReleaseReport(manifest, "released", nil)
	report.ReceiptDigest = s2ReceiptDigest(report)
	return report
}

func failedContinuationReleaseReport(manifest model.ContinuationReleaseManifestV1, code string) model.ContinuationReleaseReportV1 {
	report := continuationReleaseReport(manifest, "failed", &code)
	report.ReceiptDigest = s2ReceiptDigest(report)
	return report
}

func continuationReleaseReport(manifest model.ContinuationReleaseManifestV1, status string, code *string) model.ContinuationReleaseReportV1 {
	return model.ContinuationReleaseReportV1{
		FormatVersion: manifest.FormatVersion, OperationID: manifest.OperationID, Action: manifest.Action,
		DesiredRevision: manifest.DesiredRevision, Identity: manifest.Identity, Binding: manifest.Binding,
		Checkpoint: manifest.Checkpoint, Target: manifest.Target, Context: manifest.Context, Reason: manifest.Reason,
		Status: status, ErrorCode: code,
	}
}

func sameS2Identity(value model.ContinuityIdentityV1, expected model.ContinuationIdentityV1) bool {
	return value.WorkID == expected.WorkID && value.ProjectID == expected.ProjectID && value.SandboxID == expected.SandboxID &&
		value.WorkspaceEpoch == expected.WorkspaceEpoch && value.SandboxGeneration == expected.SandboxGeneration &&
		value.ExpectedRevision == expected.ExpectedRevision
}

func sameS2Binding(value model.ContinuityBindingV1, expected model.ContinuationBindingRefV1) bool {
	return value.BindingID == expected.BindingID && value.BindingRevision == expected.BindingRevision &&
		value.RegisteredSourceID == expected.RegisteredSourceID && value.ServiceRegistrationID == expected.ServiceRegistrationID &&
		value.NativeSessionID == expected.NativeSessionID && value.NativeProjectID == expected.NativeProjectID &&
		value.NativeLocationDigest == expected.NativeLocationDigest
}

func s2ReceiptDigest(value any) string {
	payload, _ := json.Marshal(value)
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (c *S2Controller) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func boundedHelperOutput(value []byte) string {
	message := strings.TrimSpace(string(value))
	if len(message) > 300 {
		message = message[:300]
	}
	return message
}
