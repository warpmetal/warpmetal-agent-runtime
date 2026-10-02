package continuity

import (
	"context"
	"errors"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

const SourceFreshness = 120 * time.Second

type StateRegistry struct {
	Store *state.Store
	Now   func() time.Time
}

func (r StateRegistry) Resolve(ctx context.Context, identity model.ContinuityIdentityV1) (RegisteredWorkspace, error) {
	registrations, err := r.Store.ContinuityRegistrations(ctx)
	if err != nil {
		return RegisteredWorkspace{}, err
	}
	for _, registration := range registrations {
		if registration.ObservedStatus != "verified" || registration.Manifest.DesiredState != "active" ||
			!registration.Manifest.ContinuityEnabled ||
			!model.SameContinuityWorkFence(registration.Manifest.Identity, identity) {
			continue
		}
		source, err := r.Store.ContinuitySource(ctx, registration.Manifest.Binding.RegisteredSourceID)
		if err != nil || source == nil {
			return RegisteredWorkspace{}, errors.Join(ErrTargetChanged, err)
		}
		now := time.Now().UTC()
		if r.Now != nil {
			now = r.Now().UTC()
		}
		binding := registration.Manifest.Binding
		report := source.Report
		age := now.Sub(report.LastObservedAt)
		if age < 0 || age > SourceFreshness || report.RegisteredSourceID != binding.RegisteredSourceID ||
			report.ServiceRegistrationID != binding.ServiceRegistrationID ||
			report.NativeSessionID != binding.NativeSessionID || report.NativeProjectID != binding.NativeProjectID ||
			report.NativeLocationDigest != binding.NativeLocationDigest || report.ProjectID != identity.ProjectID ||
			report.SandboxID != identity.SandboxID || report.SandboxGeneration != identity.SandboxGeneration ||
			report.WorkspaceEpoch != identity.WorkspaceEpoch || report.ScopeRevision != registration.Manifest.ScopeRevision ||
			report.ServiceGeneration != registration.ServiceGeneration || report.Availability != "available" {
			return RegisteredWorkspace{}, ErrTargetChanged
		}
		return RegisteredWorkspace{Identity: identity, Root: source.Root, Instance: source.Instance, Lifecycle: source.Lifecycle,
			LifecycleRevision: source.LifecycleRevision, NoAdmittedExecution: source.NoAdmittedExecution,
			BoundaryBinding: binding}, nil
	}
	return RegisteredWorkspace{}, ErrTargetChanged
}
