package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

var ErrProviderOpeningPending = errors.New("provider participant opening pending")

type ProviderCurrentControl interface {
	ProviderAccountingCurrent(context.Context, string) (json.RawMessage, error)
}
type providerJointOpeningControl interface {
	ProviderOpeningControl
	ProviderAccountingOpening(context.Context) (json.RawMessage, error)
}

func (p *Producer) initializeParticipantAccounting(ctx context.Context, store *state.Store, control ProviderOpeningControl, in providerOpeningInputs) error {
	joint, ok := control.(providerJointOpeningControl)
	if !ok {
		return ErrUntrusted
	}
	runtime, err := p.ObserveProviderOpening(ctx, store, in.authority, in.demand, in.backend, in.operator)
	if err != nil {
		return err
	}
	if existing, e := store.PhysicalFact(ctx, "provider_opening_pair"); e != nil {
		return e
	} else if len(existing) > 0 {
		return p.AcceptProviderParticipantOpening(ctx, store, in.authority, in.demand, existing, in.operator)
	}
	contribution := canonicalBytes(map[string]any{"formatVersion": 3, "backend": in.backend, "runtime": runtime})
	first, err := store.PhysicalFact(ctx, "provider_opening_contribution")
	if err != nil {
		return err
	}
	var response json.RawMessage
	if len(first) == 0 {
		if err = store.RetainPhysicalFact(ctx, "provider_opening_contribution", contribution); err != nil {
			return err
		}
		response, err = joint.AcceptProviderAccountingOpening(ctx, contribution)
	} else {
		if !sameProduct(json.RawMessage(first), json.RawMessage(contribution)) {
			return ErrUntrusted
		}
		response, err = joint.ProviderAccountingOpening(ctx)
		// A missing contribution after a lost POST may safely replay the SAME first
		// idempotent transport. There is no new observation or alternative opening.
		if errors.Is(err, model.ErrProviderOpeningAbsent) {
			response, err = joint.AcceptProviderAccountingOpening(ctx, contribution)
		}
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	if workflowcontract.Validate(workflowcontract.ProviderParticipantAccounting, "openingResponse3", response) != nil {
		return ErrUntrusted
	}
	var reply struct {
		Status, OpeningDigest string
		Opening, Backend      json.RawMessage
		Runtimes              []json.RawMessage
		MissingParticipantIDs []string
		BlockedReason         *string
	}
	_ = json.Unmarshal(response, &reply)
	if reply.Status == "opened" {
		if reply.OpeningDigest != CanonicalDigest(reply.Opening) {
			return ErrUntrusted
		}
		return p.AcceptProviderParticipantOpening(ctx, store, in.authority, in.demand, reply.Opening, in.operator)
	}
	if !sameProduct(reply.Backend, in.backend) {
		return ErrUntrusted
	}
	a, e := p.participantAuthority(in.authority, in.demand, in.operator, time.Now().UTC(), false)
	if e != nil {
		return e
	}
	seen := map[string]bool{}
	previous := ""
	for _, raw := range reply.Runtimes {
		f := childFields(childFields(raw)["payload"])
		id := childString(f, "participantId")
		found := false
		for _, part := range a.participants {
			if part.ParticipantID == id {
				found = a.verifyRuntimeOpening(raw, part, in.backend) == nil
			}
		}
		if !found || id <= previous || childString(f, "backendOpeningDigest") != CanonicalDigest(in.backend) {
			return ErrUntrusted
		}
		previous = id
		seen[id] = true
		if id == a.own.ParticipantID && !sameProduct(raw, runtime) {
			return ErrUntrusted
		}
	}
	missing := []string{}
	for _, part := range a.participants {
		if !seen[part.ParticipantID] {
			missing = append(missing, part.ParticipantID)
		}
	}
	if !sameProduct(canonicalBytes(missing), reply.MissingParticipantIDs) {
		return ErrUntrusted
	}
	if !seen[a.own.ParticipantID] && reply.BlockedReason == nil {
		// Retry only this exact first contribution; eventual complete result is read
		// on the next normal pass. A changed/expired pending opening remains blocked.
		if _, err = joint.AcceptProviderAccountingOpening(ctx, contribution); err != nil {
			return err
		}
	}
	return ErrProviderOpeningPending
}

func (p *Producer) CollectProviderReadback(ctx context.Context, store *state.Store, control ProviderCurrentControl) (json.RawMessage, error) {
	in, selected, err := p.providerOpeningInputs()
	if err != nil || !selected || control == nil || store == nil {
		return nil, ErrUntrusted
	}
	if !sameProduct(childFields(in.authority)["formatVersion"], 5) {
		return nil, ErrUntrusted
	}
	current, err := control.ProviderAccountingCurrent(ctx, CanonicalDigest(in.authority))
	if err != nil {
		return nil, err
	}
	return p.ObserveProviderReadback(ctx, store, in.authority, in.demand, current, in.operator)
}
func (p *Producer) BindCurrentProviderReservation(ctx context.Context, store *state.Store, control ProviderCurrentControl, permit state.PhysicalPermit) (state.PhysicalPermit, error) {
	in, selected, err := p.providerOpeningInputs()
	if err != nil || !selected || control == nil || store == nil {
		return permit, ErrUntrusted
	}
	current, err := control.ProviderAccountingCurrent(ctx, model.WorkspaceDigest(in.authority))
	if err != nil {
		return permit, err
	}
	return p.BindProviderParticipantReservation(ctx, store, in.authority, in.demand, current, in.operator, permit)
}
