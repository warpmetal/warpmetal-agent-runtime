package reconcile

import (
	"context"
	"encoding/json"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type providerAccountingControl interface {
	qualification.ProviderSettlementControl
	ProviderAccountingCurrent(context.Context, string) (json.RawMessage, error)
	AcceptProviderAccountingOpening(context.Context, json.RawMessage) (json.RawMessage, error)
}

func (r *Reconciler) initializeProviderAccounting(ctx context.Context) error {
	runtime, ok := r.ManagedRuntime.(interface {
		InitializeProviderAccounting(context.Context, qualification.ProviderOpeningControl) error
	})
	if !ok {
		return nil
	}
	// An unrelated legacy pass need not implement the new opening transport.
	// The selected authority3 owner refuses a nil control before any mutation.
	control, _ := r.ManagedControl.(providerAccountingControl)
	if err := runtime.InitializeProviderAccounting(ctx, control); err != nil {
		return err
	}
	if r.Store != nil {
		anchor, err := r.Store.PhysicalAnchor(ctx)
		if err != nil {
			return err
		}
		if anchor != nil && anchor.ProviderPolicyDigest == providerpolicy.ParticipantDigest {
			_, err = r.CollectProviderAccountingReadback(ctx)
			return err
		}
	}
	return nil
}

func (r *Reconciler) bindProviderPhysicalRequest(ctx context.Context, p state.PhysicalPermit) (state.PhysicalPermit, error) {
	control, ok := r.ManagedControl.(providerAccountingControl)
	if !ok || r.Store == nil || p.Provider == nil {
		return state.PhysicalPermit{}, physicalgate.ErrPrerequisite
	}
	if p.Case.ProviderPolicyDigest == providerpolicy.ParticipantDigest {
		owner, ok := r.ManagedRuntime.(interface {
			BindCurrentProviderReservation(context.Context, qualification.ProviderCurrentControl, state.PhysicalPermit) (state.PhysicalPermit, error)
		})
		if !ok {
			return p, physicalgate.ErrPrerequisite
		}
		return owner.BindCurrentProviderReservation(ctx, control, p)
	}
	opening, err := r.Store.ProviderOpening(ctx)
	if err != nil {
		return state.PhysicalPermit{}, err
	}
	var pair struct {
		Backend struct {
			Payload struct {
				AuthorityDigest string `json:"authorityDigest"`
			} `json:"payload"`
		} `json:"backend"`
	}
	if json.Unmarshal(opening, &pair) != nil {
		return state.PhysicalPermit{}, physicalgate.ErrPrerequisite
	}
	prefix, err := control.ProviderAccountingCurrent(ctx, pair.Backend.Payload.AuthorityDigest)
	if err != nil {
		return state.PhysicalPermit{}, err
	}
	return r.Store.BindProviderReservation(ctx, p, prefix)
}

// Called only after the kernel/native verifier retained the actual originals.
// The normal daemon uses the SAME reconciler/current Runtime, never a second gate.
func (r *Reconciler) CommitProviderPhysicalSettlement(ctx context.Context, c physicalgate.Caller, o state.PhysicalOperation, e model.PhysicalSettlement) error {
	control, ok := r.ManagedControl.(providerAccountingControl)
	runtime, rok := r.ManagedRuntime.(interface {
		CommitProviderPhysicalSettlement(context.Context, qualification.ProviderSettlementControl, state.PhysicalOperation, model.PhysicalSettlement) error
	})
	if !ok || !rok || o.Permit.Caller != c.Subject() {
		return physicalgate.ErrPrerequisite
	}
	return runtime.CommitProviderPhysicalSettlement(ctx, control, o, e)
}

// Normal accounting evidence collection uses the protected owner, not native RPC.
func (r *Reconciler) CollectProviderAccountingReadback(ctx context.Context) (json.RawMessage, error) {
	control, ok := r.ManagedControl.(qualification.ProviderCurrentControl)
	owner, found := r.ManagedRuntime.(interface {
		CollectProviderReadback(context.Context, qualification.ProviderCurrentControl) (json.RawMessage, error)
	})
	if !ok || !found {
		return nil, physicalgate.ErrPrerequisite
	}
	return owner.CollectProviderReadback(ctx, control)
}
