package reconcile

import (
	"context"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Missing independently delivered snapshot/CORE is asynchronous financial
// readiness, not a grant, zero balance or permission to mature a first task.
// Existing paid admission and counted manager launcher remain their owners.
func (r *Reconciler) observeCurrentWindow(ctx context.Context, current model.Manifest) error {
	observer, ok := r.ManagedRuntime.(interface {
		ObserveCurrentWindowReconciliation(context.Context, model.Manifest) error
	})
	if !ok {
		return nil
	}
	err := observer.ObserveCurrentWindowReconciliation(ctx, current)
	if errors.Is(err, qualification.ErrCurrentWindowObservationPending) {
		return nil
	}
	return err
}
