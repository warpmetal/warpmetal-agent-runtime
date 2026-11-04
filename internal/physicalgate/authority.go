package physicalgate

import (
	"context"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"reflect"
)

// Runtime owns signed/installed authority; the kernel registry owns identities.
// No protocol/environment supplier substitution exists in normal daemon wiring.
type RuntimeAuthority struct {
	Processes                *ProcessRegistry
	Access                   *AccessRegistry
	Resolve                  func(context.Context, Caller, model.PhysicalAdmitRequest) (state.PhysicalPermit, error)
	CommitProviderSettlement func(context.Context, Caller, state.PhysicalOperation, model.PhysicalSettlement) error
}

func (a RuntimeAuthority) Authenticate(ctx context.Context, p Peer) (Caller, error) {
	if a.Access != nil {
		if c, err := a.Access.Authenticate(ctx, p); err == nil {
			return c, nil
		}
	}
	return a.Processes.Authenticate(ctx, p)
}
func (a RuntimeAuthority) HoldPeer(ctx context.Context, p Peer, c Caller) (func() error, func(), error) {
	if c.NativeInstance == "runtime-access" && a.Access != nil {
		check := func() error {
			current, err := a.Access.Authenticate(ctx, p)
			if err != nil || current != c {
				return ErrPrerequisite
			}
			return nil
		}
		if err := check(); err != nil {
			return nil, nil, err
		}
		return check, func() {}, nil
	}
	n, err := a.Processes.Registration(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	verify, close, err := holdNativePeer(p, n)
	if err != nil {
		return nil, nil, err
	}
	check := func() error {
		if a.Processes.ObserveContainer == nil {
			return ErrPrerequisite
		}
		current, err := a.Processes.ObserveContainer(ctx, c.SandboxID)
		if err != nil || !reflect.DeepEqual(current, n.Container) {
			return ErrPrerequisite
		}
		return verify()
	}
	if err = check(); err != nil {
		close()
		return nil, nil, err
	}
	return check, close, nil
}
func (a RuntimeAuthority) AuthorizeAdmission(ctx context.Context, c Caller, r model.PhysicalAdmitRequest) (state.PhysicalPermit, error) {
	if a.Resolve == nil {
		return state.PhysicalPermit{}, ErrPrerequisite
	}
	if r.Consumer == "access" {
		if a.Access == nil || c.NativeInstance != "runtime-access" {
			return state.PhysicalPermit{}, ErrPrerequisite
		}
		if _, err := a.Access.Permit(ctx, c, r); err != nil {
			return state.PhysicalPermit{}, err
		}
	}
	return a.Resolve(ctx, c, r)
}
func (a RuntimeAuthority) VerifySettlement(ctx context.Context, c Caller, o state.PhysicalOperation, e model.PhysicalSettlement) error {
	var err error
	if c.NativeInstance == "runtime-access" && a.Access != nil {
		err = a.Access.VerifySettlement(ctx, c, o, e)
	} else {
		err = a.Processes.VerifySettlement(ctx, c, o, e)
	}
	if err != nil {
		return err
	}
	if o.Permit.Case.AccountingVersion == 2 {
		if a.CommitProviderSettlement == nil {
			return ErrPrerequisite
		}
		return a.CommitProviderSettlement(ctx, c, o, e)
	}
	return nil
}

// Production verifier reads the actual pre-dispatch request retained by its
// owning producer. No manager round trip or new wire; denial precedes SQLite ACK.
func (a RuntimeAuthority) VerifyAdmissionOriginals(ctx context.Context, c Caller, id string, permit state.PhysicalPermit) error {
	if permit.Caller != c.Subject() || id != "pg_"+model.WorkspaceDigest(permit.Request)[7:] {
		return ErrPrerequisite
	}
	if permit.Request.Consumer == "access" {
		if a.Access == nil {
			return ErrPrerequisite
		}
		return a.Access.VerifyAdmissionOriginal(ctx, c, id, permit.Request)
	}
	if a.Processes == nil || a.Processes.Store == nil {
		return ErrPrerequisite
	}
	n, err := a.Processes.Registration(ctx, c)
	if err != nil {
		return err
	}
	original, err := verifiedNativeAdmissionOriginal(n, id, permit.Request)
	if err != nil {
		return err
	}
	return a.Processes.Store.RetainPhysicalFact(ctx, "native_original_"+model.RawPhysicalDigest(original)[7:], original)
}
func (r *ProcessRegistry) VerifySettlement(ctx context.Context, c Caller, o state.PhysicalOperation, e model.PhysicalSettlement) error {
	n, err := r.Registration(ctx, c)
	if err != nil || o.Permit.Caller != c.Subject() {
		return ErrPrerequisite
	}
	originals, err := verifiedNativeSettlementOriginals(n, o, e)
	if err != nil {
		return err
	}
	// Retain the bytes that were just verified, before ACK/owner release. A failed
	// immutable archival transaction leaves UNKNOWN; this is never cash settlement.
	return r.Store.RetainNativeSettlementOriginals(ctx, o.OperationID, c.Subject(), e, originals)
}
