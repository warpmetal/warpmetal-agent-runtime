package continuity

import (
	"context"
	"errors"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
)

type CheckpointLifecycle struct {
	State         *state.Store
	Objects       storage.CheckpointStore
	Now           func() time.Time
	GracePeriod   time.Duration
	MaxPerPass    int
	BeforeCollect func(state.CheckpointGCIntent) error
}

func (l *CheckpointLifecycle) Run(ctx context.Context) error {
	if l == nil || l.State == nil {
		return errors.New("checkpoint lifecycle is not configured")
	}
	now := time.Now().UTC()
	if l.Now != nil {
		now = l.Now().UTC()
	}
	grace := l.GracePeriod
	if grace <= 0 {
		grace = time.Hour
	}
	limit := l.MaxPerPass
	if limit <= 0 || limit > 32 {
		limit = 32
	}
	intents, err := l.State.PlanCheckpointCollection(ctx, now, grace, limit)
	if err != nil {
		return err
	}
	advanced := 0
	for _, intent := range intents {
		if advanced >= limit || now.Before(intent.NotBefore) {
			continue
		}
		confirmed, err := l.State.ConfirmCheckpointCollection(ctx, intent)
		if err != nil {
			return err
		}
		if !confirmed {
			continue
		}
		intent.Phase = "deleting"
		if l.BeforeCollect != nil {
			if err := l.BeforeCollect(intent); err != nil {
				return err
			}
		}
		err = l.Objects.Collect(ctx, storage.CollectionRequest{
			CaptureID: intent.CaptureID, ObjectID: intent.ObjectID,
			ManifestDigest: intent.ManifestDigest,
		})
		if err != nil && !errors.Is(err, storage.ErrCheckpointUnavailable) {
			return err
		}
		if err := l.State.CompleteCheckpointCollection(ctx, intent); err != nil {
			return err
		}
		advanced++
	}
	if limit-advanced <= 0 {
		return nil
	}
	_, err = l.Objects.CollectStaging(ctx, now.Add(-grace), limit-advanced)
	return err
}
