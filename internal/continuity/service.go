package continuity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
)

const (
	DefaultFreezeTimeout   = 15 * time.Second
	DefaultWatchdogTimeout = 15 * time.Second
	MaterializeDesignation = "continuity-materialization"
)

var (
	ErrTargetChanged            = errors.New("registered continuity target changed")
	ErrPauseOutcomeUnknown      = errors.New("container pause outcome is unknown")
	ErrPauseNotOwned            = errors.New("container is already paused outside this operation")
	ErrSafeBoundaryRequired     = errors.New("acknowledged safe boundary is required")
	ErrDestinationNotDesignated = errors.New("destination is not registered for continuity materialization")
	ErrRecoveryRequired         = errors.New("continuity operation requires lifecycle recovery")
)

var safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type RegisteredWorkspace struct {
	Identity            model.ContinuityIdentityV1
	Root                string
	Instance            string
	Lifecycle           string
	LifecycleRevision   int64
	Fresh               bool
	Designation         string
	NoAdmittedExecution bool
	BoundaryBinding     BoundaryBindingV1
}

type WorkspaceRegistry interface {
	Resolve(context.Context, model.ContinuityIdentityV1) (RegisteredWorkspace, error)
}

type CaptureEngine interface {
	InspectState(context.Context, string) (containers.ContainerState, error)
	Pause(context.Context, string) error
	Unpause(context.Context, string) error
}

type ObjectStore interface {
	Capture(context.Context, storage.CaptureRequest) (storage.DurableCapture, error)
	Verify(context.Context, string) (storage.DurableCapture, error)
	Materialize(context.Context, storage.MaterializeRequest) (storage.MaterializeReceipt, error)
}

type Service struct {
	State           *state.Store
	Objects         ObjectStore
	Engine          CaptureEngine
	Registry        WorkspaceRegistry
	FreezeTimeout   time.Duration
	WatchdogTimeout time.Duration
	Now             func() time.Time
	OnTransition    func(string)

	mu sync.Mutex
}

type BoundaryBindingV1 = model.ContinuityBindingV1

type SafeBoundaryReceiptV1 struct {
	ID                      string            `json:"id"`
	Kind                    string            `json:"kind"`
	AcknowledgedAt          time.Time         `json:"acknowledgedAt"`
	WorkID                  string            `json:"workId"`
	WorkspaceEpoch          string            `json:"workspaceEpoch"`
	SandboxGeneration       int64             `json:"sandboxGeneration"`
	TaskID                  *string           `json:"taskId"`
	TaskAttempt             *int64            `json:"taskAttempt"`
	LastAcceptedExecutionID *string           `json:"lastAcceptedExecutionId"`
	Binding                 BoundaryBindingV1 `json:"binding"`
}

type CaptureRequestV1 struct {
	OperationID   string
	RequestDigest string
	Identity      model.ContinuityIdentityV1
	SafeBoundary  SafeBoundaryReceiptV1
}

type CaptureReceiptV1 struct {
	FormatVersion  int                        `json:"formatVersion"`
	OperationID    string                     `json:"operationId"`
	CaptureID      string                     `json:"captureId"`
	ObjectID       string                     `json:"objectId"`
	ManifestDigest string                     `json:"manifestDigest"`
	Identity       model.ContinuityIdentityV1 `json:"identity"`
	Bytes          int64                      `json:"bytes"`
	ObjectCount    int                        `json:"objectCount"`
	Outcome        string                     `json:"outcome"`
}

type CheckpointRequestV1 struct {
	OperationID   string
	RequestDigest string
	Identity      model.ContinuityIdentityV1
	CaptureID     string
}

type CheckpointReceiptV1 struct {
	FormatVersion  int                        `json:"formatVersion"`
	OperationID    string                     `json:"operationId"`
	CheckpointID   string                     `json:"checkpointId"`
	CaptureID      string                     `json:"captureId"`
	ManifestDigest string                     `json:"manifestDigest"`
	Identity       model.ContinuityIdentityV1 `json:"identity"`
	Outcome        string                     `json:"outcome"`
}

type MaterializeRequestV1 struct {
	OperationID         string
	RequestDigest       string
	SourceIdentity      model.ContinuityIdentityV1
	DestinationIdentity model.ContinuityIdentityV1
	CheckpointID        string
}

type MaterializeReceiptV1 struct {
	FormatVersion       int                        `json:"formatVersion"`
	OperationID         string                     `json:"operationId"`
	CheckpointID        string                     `json:"checkpointId"`
	ManifestDigest      string                     `json:"manifestDigest"`
	DestinationIdentity model.ContinuityIdentityV1 `json:"destinationIdentity"`
	Bytes               int64                      `json:"bytes"`
	ObjectCount         int                        `json:"objectCount"`
	Outcome             string                     `json:"outcome"`
}

func (s *Service) Capture(ctx context.Context, request CaptureRequestV1) (CaptureReceiptV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateOperation(request.OperationID, request.RequestDigest, request.Identity); err != nil {
		return CaptureReceiptV1{}, err
	}
	if err := validateBoundary(request.Identity, request.SafeBoundary); err != nil {
		return CaptureReceiptV1{}, err
	}
	workspace, err := s.resolve(ctx, request.Identity)
	if err != nil {
		return CaptureReceiptV1{}, err
	}
	if err := validateBoundaryForWorkspace(request.Identity, request.SafeBoundary, workspace); err != nil {
		return CaptureReceiptV1{}, err
	}
	deadline := s.now().Add(s.freezeTimeout())
	operation := state.LocalContinuityOperation{
		ID: request.OperationID, Kind: "capture", Identity: request.Identity,
		RequestDigest: request.RequestDigest, State: "pending", Deadline: deadline,
	}
	if err := s.State.PutContinuityOperation(ctx, operation); err != nil {
		return CaptureReceiptV1{}, err
	}
	existing, err := s.State.ContinuityOperation(ctx, request.OperationID)
	if err != nil {
		return CaptureReceiptV1{}, err
	}
	if existing != nil && existing.State == "captured" {
		capture, err := s.Objects.Verify(ctx, existing.CaptureID)
		if err != nil {
			return CaptureReceiptV1{}, err
		}
		return captureReceipt(request.OperationID, capture), nil
	}
	if existing == nil || existing.State != "pending" {
		return CaptureReceiptV1{}, operationOutcomeError(existing)
	}
	remaining, err := s.State.CheckpointBudget(ctx, request.Identity.SandboxID)
	if err != nil {
		return CaptureReceiptV1{}, err
	}
	if remaining <= 0 {
		_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{
			From: "pending", To: "failed", ErrorCode: "checkpoint_quota",
			ErrorMessage: state.ErrCheckpointQuota.Error(),
		})
		return CaptureReceiptV1{}, state.ErrCheckpointQuota
	}

	freezeContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	paused := false
	if workspace.Lifecycle == "stopped" {
		if err := s.transition(ctx, request.OperationID, state.ContinuityTransition{From: "pending", To: "capturing"}); err != nil {
			return CaptureReceiptV1{}, err
		}
	} else if workspace.Lifecycle == "running" {
		if workspace.LifecycleRevision < 1 {
			_ = s.failPending(request.OperationID, "target_changed", ErrTargetChanged)
			return CaptureReceiptV1{}, ErrTargetChanged
		}
		if s.Engine == nil {
			_ = s.failPending(request.OperationID, "engine_unavailable", ErrTargetChanged)
			return CaptureReceiptV1{}, ErrTargetChanged
		}
		engineState, err := s.Engine.InspectState(freezeContext, workspace.Identity.SandboxID)
		if err != nil {
			_ = s.failPending(request.OperationID, "inspect_failed", err)
			return CaptureReceiptV1{}, err
		}
		if engineState == containers.ContainerPaused {
			_ = s.failPending(request.OperationID, "pause_not_owned", ErrPauseNotOwned)
			return CaptureReceiptV1{}, ErrPauseNotOwned
		}
		if engineState != containers.ContainerRunning {
			_ = s.failPending(request.OperationID, "target_changed", ErrTargetChanged)
			return CaptureReceiptV1{}, ErrTargetChanged
		}
		if err := s.transition(ctx, request.OperationID, state.ContinuityTransition{From: "pending", To: "pausing"}); err != nil {
			return CaptureReceiptV1{}, err
		}
		if err := s.Engine.Pause(freezeContext, workspace.Identity.SandboxID); err != nil {
			_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{
				From: "pausing", To: "recovery_required", ErrorCode: "pause_outcome_unknown",
				ErrorMessage: ErrPauseOutcomeUnknown.Error(),
			})
			return CaptureReceiptV1{}, errors.Join(ErrPauseOutcomeUnknown, err)
		}
		engineState, err = s.Engine.InspectState(freezeContext, workspace.Identity.SandboxID)
		if err != nil || engineState != containers.ContainerPaused {
			_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{
				From: "pausing", To: "recovery_required", ErrorCode: "pause_outcome_unknown",
				ErrorMessage: ErrPauseOutcomeUnknown.Error(),
			})
			return CaptureReceiptV1{}, errors.Join(ErrPauseOutcomeUnknown, err)
		}
		if err := s.transition(ctx, request.OperationID, state.ContinuityTransition{
			From: "pausing", To: "paused", PauseOwned: true,
			PauseGeneration:        request.Identity.SandboxGeneration,
			PauseLifecycleRevision: workspace.LifecycleRevision,
		}); err != nil {
			return CaptureReceiptV1{}, err
		}
		paused = true
		if err := s.transition(ctx, request.OperationID, state.ContinuityTransition{
			From: "paused", To: "capturing", PauseOwned: true,
			PauseGeneration:        request.Identity.SandboxGeneration,
			PauseLifecycleRevision: workspace.LifecycleRevision,
		}); err != nil {
			return CaptureReceiptV1{}, err
		}
	} else {
		_ = s.failPending(request.OperationID, "target_changed", ErrTargetChanged)
		return CaptureReceiptV1{}, ErrTargetChanged
	}

	capture, captureErr := s.Objects.Capture(freezeContext, storage.CaptureRequest{
		OperationID: request.OperationID, Identity: request.Identity, WorkspaceRoot: workspace.Root,
		MaxBytes: remaining,
	})
	if paused {
		if err := s.thawOwned(request.OperationID, request.Identity); err != nil {
			return CaptureReceiptV1{}, err
		}
	}
	if captureErr != nil {
		_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{
			From: "capturing", To: "failed", ErrorCode: captureErrorCode(captureErr),
			ErrorMessage: captureErr.Error(),
		})
		return CaptureReceiptV1{}, captureErr
	}
	if !capture.Manifest.Identity.Equal(request.Identity) {
		_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{
			From: "capturing", To: "failed", ErrorCode: "checkpoint_corrupt",
			ErrorMessage: storage.ErrCheckpointCorrupt.Error(),
		})
		return CaptureReceiptV1{}, storage.ErrCheckpointCorrupt
	}
	if err := s.State.PutContinuityCapture(ctx, state.LocalContinuityCapture{
		ID: capture.ID, Identity: request.Identity, ObjectID: capture.ObjectID,
		ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes,
		ObjectCount: capture.ObjectCount, Verified: true, CreatedAt: s.now(),
	}); err != nil {
		_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{
			From: "capturing", To: "failed", CaptureID: capture.ID,
			ErrorCode: captureErrorCode(err), ErrorMessage: err.Error(),
		})
		return CaptureReceiptV1{}, err
	}
	if err := s.transition(ctx, request.OperationID, state.ContinuityTransition{
		From: "capturing", To: "captured", CaptureID: capture.ID,
	}); err != nil {
		return CaptureReceiptV1{}, err
	}
	return captureReceipt(request.OperationID, capture), nil
}

func (s *Service) Checkpoint(ctx context.Context, request CheckpointRequestV1) (CheckpointReceiptV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateOperation(request.OperationID, request.RequestDigest, request.Identity); err != nil {
		return CheckpointReceiptV1{}, err
	}
	operation := state.LocalContinuityOperation{
		ID: request.OperationID, Kind: "checkpoint", Identity: request.Identity,
		RequestDigest: request.RequestDigest, State: "pending", Deadline: s.now().Add(s.freezeTimeout()),
	}
	if err := s.State.PutContinuityOperation(ctx, operation); err != nil {
		return CheckpointReceiptV1{}, err
	}
	existing, err := s.State.ContinuityOperation(ctx, request.OperationID)
	if err != nil {
		return CheckpointReceiptV1{}, err
	}
	if existing != nil && existing.State == "succeeded" {
		checkpoint, err := s.State.Checkpoint(ctx, existing.CheckpointID)
		if err != nil || checkpoint == nil || checkpoint.CaptureID != request.CaptureID {
			return CheckpointReceiptV1{}, errors.Join(storage.ErrCheckpointCorrupt, err)
		}
		return CheckpointReceiptV1{
			FormatVersion: 1, OperationID: request.OperationID, CheckpointID: checkpoint.ID,
			CaptureID: checkpoint.CaptureID, ManifestDigest: checkpoint.ManifestDigest,
			Identity: checkpoint.Identity, Outcome: "succeeded",
		}, nil
	}
	if existing == nil || existing.State != "pending" {
		return CheckpointReceiptV1{}, operationOutcomeError(existing)
	}
	if err := s.transition(ctx, request.OperationID, state.ContinuityTransition{From: "pending", To: "verifying", CaptureID: request.CaptureID}); err != nil {
		return CheckpointReceiptV1{}, err
	}
	capture, err := s.Objects.Verify(ctx, request.CaptureID)
	if err != nil {
		_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{From: "verifying", To: "failed", ErrorCode: "checkpoint_corrupt", ErrorMessage: err.Error()})
		return CheckpointReceiptV1{}, err
	}
	persisted, err := s.State.ContinuityCapture(ctx, request.CaptureID)
	if err != nil || persisted == nil || !persisted.Verified || !persisted.Identity.Equal(request.Identity) ||
		persisted.ManifestDigest != capture.ManifestDigest {
		failure := errors.Join(storage.ErrCheckpointCorrupt, err)
		_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{
			From: "verifying", To: "failed", CaptureID: request.CaptureID,
			ErrorCode: "checkpoint_corrupt", ErrorMessage: failure.Error(),
		})
		return CheckpointReceiptV1{}, failure
	}
	checkpointID := stableID("checkpoint", request.OperationID, request.CaptureID, capture.ManifestDigest)
	if err := s.State.AcceptCheckpoint(ctx, state.LocalCheckpoint{
		ID: checkpointID, CaptureID: capture.ID, Identity: request.Identity,
		ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes,
		ObjectCount: capture.ObjectCount, CreatedAt: s.now(),
	}); err != nil {
		_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{From: "verifying", To: "failed", ErrorCode: checkpointErrorCode(err), ErrorMessage: err.Error()})
		return CheckpointReceiptV1{}, err
	}
	if err := s.transition(ctx, request.OperationID, state.ContinuityTransition{
		From: "verifying", To: "succeeded", CaptureID: capture.ID, CheckpointID: checkpointID,
	}); err != nil {
		return CheckpointReceiptV1{}, err
	}
	return CheckpointReceiptV1{
		FormatVersion: 1, OperationID: request.OperationID, CheckpointID: checkpointID,
		CaptureID: capture.ID, ManifestDigest: capture.ManifestDigest,
		Identity: request.Identity, Outcome: "succeeded",
	}, nil
}

func (s *Service) Materialize(ctx context.Context, request MaterializeRequestV1) (MaterializeReceiptV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateOperation(request.OperationID, request.RequestDigest, request.DestinationIdentity); err != nil {
		return MaterializeReceiptV1{}, err
	}
	if request.SourceIdentity.WorkID != request.DestinationIdentity.WorkID ||
		request.SourceIdentity.ProjectID != request.DestinationIdentity.ProjectID ||
		request.SourceIdentity.WorkspaceEpoch == request.DestinationIdentity.WorkspaceEpoch {
		return MaterializeReceiptV1{}, ErrTargetChanged
	}
	destination, err := s.resolve(ctx, request.DestinationIdentity)
	if err != nil {
		return MaterializeReceiptV1{}, err
	}
	if !destination.Fresh || destination.Lifecycle != "stopped" || destination.Designation != MaterializeDesignation {
		return MaterializeReceiptV1{}, ErrDestinationNotDesignated
	}
	checkpoint, err := s.State.Checkpoint(ctx, request.CheckpointID)
	if err != nil || checkpoint == nil || !checkpoint.Identity.Equal(request.SourceIdentity) {
		return MaterializeReceiptV1{}, errors.Join(ErrTargetChanged, err)
	}
	operation := state.LocalContinuityOperation{
		ID: request.OperationID, Kind: "materialize", Identity: request.DestinationIdentity,
		RequestDigest: request.RequestDigest, State: "pending", Deadline: s.now().Add(s.freezeTimeout()),
	}
	if err := s.State.PutContinuityOperation(ctx, operation); err != nil {
		return MaterializeReceiptV1{}, err
	}
	existing, err := s.State.ContinuityOperation(ctx, request.OperationID)
	if err != nil {
		return MaterializeReceiptV1{}, err
	}
	if existing != nil && existing.State == "succeeded" {
		if existing.CheckpointID != request.CheckpointID {
			return MaterializeReceiptV1{}, ErrTargetChanged
		}
		return MaterializeReceiptV1{
			FormatVersion: 1, OperationID: request.OperationID, CheckpointID: checkpoint.ID,
			ManifestDigest: checkpoint.ManifestDigest, DestinationIdentity: request.DestinationIdentity,
			Bytes: checkpoint.Bytes, ObjectCount: checkpoint.ObjectCount, Outcome: "succeeded",
		}, nil
	}
	if existing == nil || existing.State != "pending" {
		return MaterializeReceiptV1{}, operationOutcomeError(existing)
	}
	if err := s.transition(ctx, request.OperationID, state.ContinuityTransition{From: "pending", To: "materializing", CheckpointID: checkpoint.ID}); err != nil {
		return MaterializeReceiptV1{}, err
	}
	receipt, err := s.Objects.Materialize(ctx, storage.MaterializeRequest{
		CheckpointID: checkpoint.CaptureID, SourceIdentity: request.SourceIdentity,
		DestinationIdentity: request.DestinationIdentity, DestinationRoot: destination.Root,
	})
	if err != nil {
		_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{
			From: "materializing", To: "recovery_required", CheckpointID: checkpoint.ID,
			ErrorCode: "materialize_outcome_unknown", ErrorMessage: err.Error(),
		})
		return MaterializeReceiptV1{}, err
	}
	if receipt.ManifestDigest != checkpoint.ManifestDigest {
		_ = s.transitionIndependent(request.OperationID, state.ContinuityTransition{
			From: "materializing", To: "recovery_required", CheckpointID: checkpoint.ID,
			ErrorCode: "materialize_outcome_unknown", ErrorMessage: storage.ErrCheckpointCorrupt.Error(),
		})
		return MaterializeReceiptV1{}, storage.ErrCheckpointCorrupt
	}
	if err := s.transition(ctx, request.OperationID, state.ContinuityTransition{From: "materializing", To: "succeeded", CheckpointID: checkpoint.ID}); err != nil {
		return MaterializeReceiptV1{}, err
	}
	return MaterializeReceiptV1{
		FormatVersion: 1, OperationID: request.OperationID, CheckpointID: checkpoint.ID,
		ManifestDigest: receipt.ManifestDigest, DestinationIdentity: request.DestinationIdentity,
		Bytes: receipt.Bytes, ObjectCount: receipt.ObjectCount, Outcome: "succeeded",
	}, nil
}

func (s *Service) Recover(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	operations, err := s.State.ContinuityOperationsByState(ctx,
		"pausing", "paused", "capturing", "verifying", "materializing", "recovery_required")
	if err != nil {
		return err
	}
	var recoveryErrors []error
	for _, operation := range operations {
		switch operation.State {
		case "verifying":
			if err := s.recoverCheckpoint(ctx, operation); err != nil {
				recoveryErrors = append(recoveryErrors, fmt.Errorf("%s: %w", operation.ID, err))
			}
			continue
		case "materializing":
			_ = s.transitionIndependent(operation.ID, state.ContinuityTransition{
				From: "materializing", To: "recovery_required", CheckpointID: operation.CheckpointID,
				ErrorCode: "materialize_outcome_unknown", ErrorMessage: ErrRecoveryRequired.Error(),
			})
			recoveryErrors = append(recoveryErrors, fmt.Errorf("%s: %w", operation.ID, ErrRecoveryRequired))
			continue
		case "capturing":
			if !operation.PauseOwned {
				if err := s.transitionIndependent(operation.ID, state.ContinuityTransition{
					From: "capturing", To: "failed", ErrorCode: "capture_interrupted",
					ErrorMessage: "stopped capture interrupted before durable completion",
				}); err != nil {
					recoveryErrors = append(recoveryErrors, err)
				}
				continue
			}
		}
		if operation.State == "pausing" || operation.State == "recovery_required" || !operation.PauseOwned {
			if operation.State == "pausing" {
				_ = s.transitionIndependent(operation.ID, state.ContinuityTransition{
					From: "pausing", To: "recovery_required", ErrorCode: "pause_outcome_unknown",
					ErrorMessage: ErrPauseOutcomeUnknown.Error(),
				})
			}
			recoveryErrors = append(recoveryErrors, fmt.Errorf("%s: %w", operation.ID, ErrRecoveryRequired))
			continue
		}
		workspace, resolveErr := s.resolve(ctx, operation.Identity)
		if resolveErr != nil || workspace.Identity.SandboxGeneration != operation.PauseGeneration ||
			workspace.LifecycleRevision != operation.PauseLifecycleRevision {
			_ = s.transitionIndependent(operation.ID, state.ContinuityTransition{
				From: operation.State, To: "recovery_required", PauseOwned: true,
				PauseGeneration:        operation.PauseGeneration,
				PauseLifecycleRevision: operation.PauseLifecycleRevision,
				ErrorCode:              "target_changed",
				ErrorMessage:           ErrTargetChanged.Error(),
			})
			recoveryErrors = append(recoveryErrors, fmt.Errorf("%s: %w", operation.ID, ErrTargetChanged))
			continue
		}
		watchdog, cancel := context.WithTimeout(context.Background(), s.watchdogTimeout())
		engineState, inspectErr := s.Engine.InspectState(watchdog, workspace.Identity.SandboxID)
		if inspectErr != nil {
			cancel()
			_ = s.transitionIndependent(operation.ID, state.ContinuityTransition{
				From: operation.State, To: "recovery_required", PauseOwned: true,
				PauseGeneration:        operation.PauseGeneration,
				PauseLifecycleRevision: operation.PauseLifecycleRevision,
				ErrorCode:              "pause_state_unknown",
				ErrorMessage:           ErrRecoveryRequired.Error(),
			})
			recoveryErrors = append(recoveryErrors, fmt.Errorf("%s: %w", operation.ID, ErrRecoveryRequired))
			continue
		}
		if engineState == containers.ContainerPaused {
			if err := s.Engine.Unpause(watchdog, workspace.Identity.SandboxID); err != nil {
				cancel()
				recoveryErrors = append(recoveryErrors, fmt.Errorf("%s: %w", operation.ID, err))
				continue
			}
		} else if engineState != containers.ContainerRunning {
			cancel()
			recoveryErrors = append(recoveryErrors, fmt.Errorf("%s: %w", operation.ID, ErrRecoveryRequired))
			continue
		}
		cancel()
		if err := s.transitionIndependent(operation.ID, state.ContinuityTransition{
			From: operation.State, To: "failed", ErrorCode: "capture_interrupted",
			ErrorMessage: "capture interrupted before durable completion",
		}); err != nil {
			recoveryErrors = append(recoveryErrors, err)
		}
	}
	return errors.Join(recoveryErrors...)
}

func (s *Service) recoverCheckpoint(ctx context.Context, operation state.LocalContinuityOperation) error {
	capture, err := s.Objects.Verify(ctx, operation.CaptureID)
	if err != nil {
		_ = s.transitionIndependent(operation.ID, state.ContinuityTransition{
			From: "verifying", To: "failed", CaptureID: operation.CaptureID,
			ErrorCode: "checkpoint_corrupt", ErrorMessage: err.Error(),
		})
		return err
	}
	persisted, err := s.State.ContinuityCapture(ctx, operation.CaptureID)
	if err != nil || persisted == nil || !persisted.Verified ||
		!persisted.Identity.Equal(operation.Identity) || persisted.ManifestDigest != capture.ManifestDigest {
		failure := errors.Join(storage.ErrCheckpointCorrupt, err)
		_ = s.transitionIndependent(operation.ID, state.ContinuityTransition{
			From: "verifying", To: "failed", CaptureID: operation.CaptureID,
			ErrorCode: "checkpoint_corrupt", ErrorMessage: failure.Error(),
		})
		return failure
	}
	checkpointID := stableID("checkpoint", operation.ID, operation.CaptureID, capture.ManifestDigest)
	if err := s.State.AcceptCheckpoint(ctx, state.LocalCheckpoint{
		ID: checkpointID, CaptureID: capture.ID, Identity: operation.Identity,
		ManifestDigest: capture.ManifestDigest, Bytes: capture.Bytes,
		ObjectCount: capture.ObjectCount, CreatedAt: s.now(),
	}); err != nil {
		_ = s.transitionIndependent(operation.ID, state.ContinuityTransition{
			From: "verifying", To: "failed", CaptureID: operation.CaptureID,
			ErrorCode: checkpointErrorCode(err), ErrorMessage: err.Error(),
		})
		return err
	}
	return s.transition(ctx, operation.ID, state.ContinuityTransition{
		From: "verifying", To: "succeeded", CaptureID: capture.ID, CheckpointID: checkpointID,
	})
}

func (s *Service) thawOwned(operationID string, identity model.ContinuityIdentityV1) error {
	watchdog, cancel := context.WithTimeout(context.Background(), s.watchdogTimeout())
	defer cancel()
	operation, err := s.State.ContinuityOperation(watchdog, operationID)
	if err != nil || operation == nil || !operation.PauseOwned || operation.PauseGeneration != identity.SandboxGeneration {
		return errors.Join(ErrRecoveryRequired, err)
	}
	workspace, err := s.resolve(watchdog, identity)
	if err != nil || workspace.Identity.SandboxGeneration != operation.PauseGeneration ||
		workspace.LifecycleRevision != operation.PauseLifecycleRevision || workspace.Lifecycle != "running" {
		_ = s.transitionIndependent(operationID, state.ContinuityTransition{
			From: operation.State, To: "recovery_required", PauseOwned: true,
			PauseGeneration:        operation.PauseGeneration,
			PauseLifecycleRevision: operation.PauseLifecycleRevision,
			ErrorCode:              "target_changed",
			ErrorMessage:           ErrTargetChanged.Error(),
		})
		return errors.Join(ErrTargetChanged, err)
	}
	engineState, err := s.Engine.InspectState(watchdog, identity.SandboxID)
	if err != nil || engineState != containers.ContainerPaused {
		_ = s.transitionIndependent(operationID, state.ContinuityTransition{
			From: operation.State, To: "recovery_required", PauseOwned: true,
			PauseGeneration:        operation.PauseGeneration,
			PauseLifecycleRevision: operation.PauseLifecycleRevision,
			ErrorCode:              "pause_state_unknown",
			ErrorMessage:           ErrRecoveryRequired.Error(),
		})
		return errors.Join(ErrRecoveryRequired, err)
	}
	if err := s.Engine.Unpause(watchdog, identity.SandboxID); err != nil {
		_ = s.transitionIndependent(operationID, state.ContinuityTransition{
			From: operation.State, To: "recovery_required", PauseOwned: true,
			PauseGeneration:        operation.PauseGeneration,
			PauseLifecycleRevision: operation.PauseLifecycleRevision,
			ErrorCode:              "unpause_failed", ErrorMessage: err.Error(),
		})
		return errors.Join(ErrRecoveryRequired, err)
	}
	return nil
}

func validateBoundary(identity model.ContinuityIdentityV1, boundary SafeBoundaryReceiptV1) error {
	if !safeIdentifier.MatchString(boundary.ID) || boundary.AcknowledgedAt.IsZero() ||
		boundary.WorkID != identity.WorkID || boundary.WorkspaceEpoch != identity.WorkspaceEpoch ||
		boundary.SandboxGeneration != identity.SandboxGeneration ||
		!equalOptionalString(boundary.TaskID, identity.TaskID) ||
		!equalOptionalInt64(boundary.TaskAttempt, identity.TaskAttempt) ||
		(boundary.Kind != "task" && boundary.Kind != "stopped" && boundary.Kind != "initial") ||
		!validBoundaryBinding(boundary.Binding) {
		return ErrSafeBoundaryRequired
	}
	return nil
}

func validateBoundaryForWorkspace(
	identity model.ContinuityIdentityV1,
	boundary SafeBoundaryReceiptV1,
	workspace RegisteredWorkspace,
) error {
	hasTask := identity.TaskID != nil && identity.TaskAttempt != nil
	if boundary.Binding != workspace.BoundaryBinding {
		return ErrSafeBoundaryRequired
	}
	switch boundary.Kind {
	case "initial":
		if hasTask || boundary.LastAcceptedExecutionID != nil || !workspace.NoAdmittedExecution {
			return ErrSafeBoundaryRequired
		}
	case "task":
		if !hasTask || boundary.LastAcceptedExecutionID != nil || workspace.Lifecycle != "running" {
			return ErrSafeBoundaryRequired
		}
	case "stopped":
		if workspace.Lifecycle != "stopped" {
			return ErrSafeBoundaryRequired
		}
		if hasTask && (boundary.LastAcceptedExecutionID == nil || *boundary.LastAcceptedExecutionID == "") {
			return ErrSafeBoundaryRequired
		}
		if !hasTask && (boundary.LastAcceptedExecutionID != nil || !workspace.NoAdmittedExecution) {
			return ErrSafeBoundaryRequired
		}
	default:
		return ErrSafeBoundaryRequired
	}
	return nil
}

func validBoundaryBinding(binding BoundaryBindingV1) bool {
	if binding.BindingRevision < 1 {
		return false
	}
	for _, value := range []string{
		binding.BindingID, binding.RegisteredSourceID, binding.ServiceRegistrationID,
		binding.NativeSessionID, binding.NativeProjectID,
	} {
		if !safeIdentifier.MatchString(value) {
			return false
		}
	}
	return digestPattern.MatchString(binding.NativeLocationDigest)
}

func validateOperation(operationID, requestDigest string, identity model.ContinuityIdentityV1) error {
	for _, value := range []string{
		operationID, identity.WorkID, identity.ProjectID, identity.SandboxID,
		identity.WorkspaceEpoch,
	} {
		if !safeIdentifier.MatchString(value) {
			return errors.New("continuity operation contains an invalid identifier")
		}
	}
	hasTaskID := identity.TaskID != nil
	hasTaskAttempt := identity.TaskAttempt != nil
	if hasTaskID != hasTaskAttempt || hasTaskID &&
		(!safeIdentifier.MatchString(*identity.TaskID) || *identity.TaskAttempt < 1) ||
		!digestPattern.MatchString(requestDigest) || identity.SandboxGeneration < 1 ||
		identity.ExpectedRevision < 1 {
		return errors.New("continuity operation contains an invalid revision fence")
	}
	return nil
}

func (s *Service) resolve(ctx context.Context, identity model.ContinuityIdentityV1) (RegisteredWorkspace, error) {
	if s.Registry == nil {
		return RegisteredWorkspace{}, ErrTargetChanged
	}
	workspace, err := s.Registry.Resolve(ctx, identity)
	if err != nil || !workspace.Identity.Equal(identity) || workspace.Root == "" {
		return RegisteredWorkspace{}, errors.Join(ErrTargetChanged, err)
	}
	return workspace, nil
}

func equalOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalOptionalInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (s *Service) transition(ctx context.Context, operationID string, transition state.ContinuityTransition) error {
	if err := s.State.TransitionContinuityOperation(ctx, operationID, transition); err != nil {
		return err
	}
	if s.OnTransition != nil {
		s.OnTransition(transition.To)
	}
	return nil
}

func (s *Service) transitionIndependent(operationID string, transition state.ContinuityTransition) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.watchdogTimeout())
	defer cancel()
	return s.transition(ctx, operationID, transition)
}

func (s *Service) failPending(operationID, code string, failure error) error {
	return s.transitionIndependent(operationID, state.ContinuityTransition{
		From: "pending", To: "failed", ErrorCode: code, ErrorMessage: failure.Error(),
	})
}

func captureReceipt(operationID string, capture storage.DurableCapture) CaptureReceiptV1 {
	return CaptureReceiptV1{
		FormatVersion: 1, OperationID: operationID, CaptureID: capture.ID,
		ObjectID: capture.ObjectID, ManifestDigest: capture.ManifestDigest,
		Identity: capture.Manifest.Identity, Bytes: capture.Bytes,
		ObjectCount: capture.ObjectCount, Outcome: "captured",
	}
}

func captureErrorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "capture_timeout"
	}
	if errors.Is(err, storage.ErrCheckpointQuota) {
		return "checkpoint_quota"
	}
	return "capture_failed"
}

func checkpointErrorCode(err error) string {
	if errors.Is(err, state.ErrCheckpointQuota) {
		return "checkpoint_quota"
	}
	return "checkpoint_failed"
}

func operationOutcomeError(operation *state.LocalContinuityOperation) error {
	if operation == nil {
		return errors.New("continuity operation disappeared")
	}
	if operation.ErrorCode != "" {
		return fmt.Errorf("continuity operation %s: %s", operation.ErrorCode, operation.ErrorMessage)
	}
	return fmt.Errorf("continuity operation is already %s", operation.State)
}

func stableID(prefix string, values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte{0})
		hash.Write([]byte(value))
	}
	return prefix + "_" + hex.EncodeToString(hash.Sum(nil))[:32]
}

func (s *Service) freezeTimeout() time.Duration {
	if s.FreezeTimeout > 0 {
		return s.FreezeTimeout
	}
	return DefaultFreezeTimeout
}

func (s *Service) watchdogTimeout() time.Duration {
	if s.WatchdogTimeout > 0 {
		return s.WatchdogTimeout
	}
	return DefaultWatchdogTimeout
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
