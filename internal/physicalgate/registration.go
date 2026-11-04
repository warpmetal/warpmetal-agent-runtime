package physicalgate

import (
	"context"
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"reflect"
)

// Current container identity is independently observed through protected Podman,
// with generation from Runtime Store. Never a registration or RPC body claim.
type ContainerObservation struct {
	SandboxID, ContainerID, ImageDigest string
	Generation                          int64
	InitPID                             int
	EndpointDevice, EndpointInode       uint64
}
type ProcessIdentity struct {
	PID, ParentPID, ContainerPID      int
	StartTime                         uint64
	UID, GID                          uint32
	Namespaces                        map[string]string
	Cgroup                            string
	ExecutableDigest                  string
	ExecutableDevice, ExecutableInode uint64
}
type NativeRegistration struct {
	Caller                          Caller
	Container                       ContainerObservation
	Native                          ProcessIdentity
	InterpreterDigest, BridgeDigest string
}
type ProcessRegistry struct {
	Store            *state.Store
	ObserveContainer func(context.Context, string) (ContainerObservation, error)
}

func (r *ProcessRegistry) Registration(ctx context.Context, c Caller) (NativeRegistration, error) {
	var n NativeRegistration
	if r == nil || r.Store == nil {
		return n, ErrPrerequisite
	}
	rows, err := r.Store.PhysicalProcesses(ctx)
	if err != nil {
		return n, err
	}
	for _, raw := range rows {
		var current NativeRegistration
		if model.DecodePhysicalClosed(raw, &current) != nil {
			return n, ErrPrerequisite
		}
		if current.Caller == c {
			return current, nil
		}
	}
	return n, ErrPrerequisite
}
func (r *ProcessRegistry) VerifyNativeDigest(ctx context.Context, c Caller, expected string) error {
	n, err := r.Registration(ctx, c)
	if err != nil || n.Native.ExecutableDigest != expected {
		return ErrPrerequisite
	}
	return nil
}

// Called ONLY on the Runtime->fixed Supervisor successful start/status readback.
// Measured identity is not installed acceptance: admission separately matches the
// signed applicability and final installed052 reader/native/profile pins.
func (r *ProcessRegistry) RegisterNative(ctx context.Context, box, instance string, containerPID int) error {
	if r == nil || r.Store == nil || r.ObserveContainer == nil || !model.PhysicalIDValid(instance) || containerPID < 1 {
		return ErrPrerequisite
	}
	c, err := r.ObserveContainer(ctx, box)
	if err != nil {
		return err
	}
	native, interpreter, bridge, err := observeNativeProcess(c, containerPID)
	if err != nil {
		return err
	}
	identity := model.WorkspaceDigest(struct {
		Container           ContainerObservation
		Native              ProcessIdentity
		Interpreter, Bridge string
	}{c, native, interpreter, bridge})
	entry := NativeRegistration{Caller: Caller{SandboxID: box, SandboxGeneration: c.Generation, NativeInstance: instance, NativeIdentityDigest: identity}, Container: c, Native: native, InterpreterDigest: interpreter, BridgeDigest: bridge}
	raw, _ := json.Marshal(entry)
	return r.Store.RetainPhysicalProcess(ctx, identity, raw)
}
func (r *ProcessRegistry) Authenticate(ctx context.Context, p Peer) (Caller, error) {
	if r == nil || r.Store == nil || r.ObserveContainer == nil {
		return Caller{}, ErrPrerequisite
	}
	entries, err := r.Store.PhysicalProcesses(ctx)
	if err != nil {
		return Caller{}, err
	}
	for _, raw := range entries {
		var n NativeRegistration
		if model.DecodePhysicalClosed(raw, &n) != nil {
			return Caller{}, ErrPrerequisite
		}
		current, err := r.ObserveContainer(ctx, n.Caller.SandboxID)
		if err != nil || !reflect.DeepEqual(current, n.Container) {
			continue
		}
		if verifyNativePeer(p, n) == nil {
			return n.Caller, nil
		}
	}
	return Caller{}, ErrPrerequisite
}
