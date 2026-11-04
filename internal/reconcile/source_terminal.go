package reconcile

import (
	"context"
	"time"
)

// Optional private owning boundary, not an admission/grant/source selector.
// Implemented by the configured Podman with SAME physical Store/ProcessRegistry.
type sourceTerminalRuntime interface {
	SourceTerminalBeforeCancel(context.Context, string) error
	SourceTerminalComplete(context.Context, string) error
}

func (r *Reconciler) sourceTerminalBeforeCancel(ctx context.Context, preparation string) error {
	if owner, ok := r.ManagedRuntime.(sourceTerminalRuntime); ok {
		// Capture is bounded independently and leaves time for the actual stop.
		// No detached execution context or retry is created for native effects.
		budget := 5 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline) / 2; remaining < budget {
				budget = remaining
			}
		}
		capture, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		return owner.SourceTerminalBeforeCancel(capture, preparation)
	}
	return nil
}
func (r *Reconciler) sourceTerminalComplete(ctx context.Context, preparation string) error {
	if owner, ok := r.ManagedRuntime.(sourceTerminalRuntime); ok {
		observation, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		return owner.SourceTerminalComplete(observation, preparation)
	}
	return nil
}
