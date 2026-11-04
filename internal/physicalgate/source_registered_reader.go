package physicalgate

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Installed Supervisor and the independently verifying current-original reader
// are narrow private boundaries. Neither receives a PID, URL, path or dispatcher.
// Independently signed current observations cannot be synthesized from a LOCAL
// grant. The original container and kernel identity are re-read at each boundary.
type SourceNativeReader interface {
	ReadSourceNativeTerminal(context.Context, state.PhysicalOperation) (SourceNativeTerminal, error)
}
type SourceCurrentReader interface {
	ReadSourceCurrentTerminal(context.Context, state.PhysicalOperation, SourceTerminalEvidence) (SourceCurrentTerminal, error)
}
type RegisteredSourceTerminalReader struct {
	Processes     *ProcessRegistry
	NativeReader  SourceNativeReader
	CurrentReader SourceCurrentReader
}

// Returns the SAME immutable registration bytes retained by RegisterNative, not
// a reserialization of the grant's five-field registeredProcess reference.
func (r *ProcessRegistry) RegistrationOriginal(ctx context.Context, subject state.PhysicalSubject) ([]byte, NativeRegistration, error) {
	if r == nil || r.Store == nil || r.ObserveContainer == nil {
		return nil, NativeRegistration{}, ErrPrerequisite
	}
	rows, err := r.Store.PhysicalProcesses(ctx)
	if err != nil {
		return nil, NativeRegistration{}, err
	}
	var original []byte
	var registration NativeRegistration
	for _, raw := range rows {
		var n NativeRegistration
		if model.DecodePhysicalClosed(raw, &n) != nil {
			return nil, registration, ErrPrerequisite
		}
		if n.Caller.Subject() == subject {
			if original != nil {
				return nil, registration, ErrPrerequisite
			}
			original, registration = append([]byte(nil), raw...), n
		}
	}
	if original == nil {
		return nil, registration, ErrPrerequisite
	}
	container, err := r.ObserveContainer(ctx, subject.SandboxID)
	if err != nil || !reflect.DeepEqual(container, registration.Container) {
		return nil, registration, ErrPrerequisite
	}
	return original, registration, nil
}

// Process observations use actual independently current kernel/container facts,
// not only an old registration, a native status PID, or a grant-selected identity.
func (r *ProcessRegistry) CurrentRegistrationOriginal(ctx context.Context, subject state.PhysicalSubject) ([]byte, NativeRegistration, error) {
	raw, n, err := r.RegistrationOriginal(ctx, subject)
	if err != nil {
		return nil, n, err
	}
	if _, err = observeRegisteredSourceKernel(n, nil); err != nil {
		return nil, n, err
	}
	again, current, err := r.RegistrationOriginal(ctx, subject)
	if err != nil || !reflect.DeepEqual(n, current) || !reflect.DeepEqual(raw, again) || ctx.Err() != nil {
		return nil, n, ErrPrerequisite
	}
	return raw, n, nil
}
func (r RegisteredSourceTerminalReader) Kernel(ctx context.Context, o state.PhysicalOperation, tracked []ProcessIdentity) (SourceKernelCut, error) {
	raw, registration, err := r.Processes.RegistrationOriginal(ctx, o.Permit.Caller)
	if err != nil {
		return SourceKernelCut{}, err
	}
	cut, err := observeRegisteredSourceKernel(registration, tracked)
	if err != nil {
		return SourceKernelCut{}, err
	}
	// Store's original registration has no signature claim. F1 must independently
	// consume it through the SAME configured producer once that wire is frozen.
	cut.RegistrationDigest = model.RawPhysicalDigest(raw)
	if err = r.Processes.Store.RetainPhysicalFact(ctx, "source_original_"+cut.RegistrationDigest[7:], raw); err != nil {
		return SourceKernelCut{}, err
	}
	return cut, nil
}
func (r RegisteredSourceTerminalReader) Native(ctx context.Context, o state.PhysicalOperation) (SourceNativeTerminal, error) {
	if r.NativeReader == nil {
		return SourceNativeTerminal{}, ErrPrerequisite
	}
	if _, _, err := r.Processes.RegistrationOriginal(ctx, o.Permit.Caller); err != nil {
		return SourceNativeTerminal{}, err
	}
	return r.NativeReader.ReadSourceNativeTerminal(ctx, o)
}
func (r RegisteredSourceTerminalReader) Current(ctx context.Context, o state.PhysicalOperation, evidence SourceTerminalEvidence) (SourceCurrentTerminal, error) {
	if r.CurrentReader == nil {
		return SourceCurrentTerminal{}, ErrPrerequisite
	}
	if _, _, err := r.Processes.RegistrationOriginal(ctx, o.Permit.Caller); err != nil {
		return SourceCurrentTerminal{}, err
	}
	return r.CurrentReader.ReadSourceCurrentTerminal(ctx, o, evidence)
}

// Keep the private cut inside the existing fact cap rather than widening RPC or
// store schemas for a collector. Oversized/incomplete originals deny release.
func boundedSourceKernel(cut SourceKernelCut) error {
	raw, err := json.Marshal(cut)
	if err != nil || len(raw) > model.PhysicalWireMaximum {
		return ErrPrerequisite
	}
	return nil
}
