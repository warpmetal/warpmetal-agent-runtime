package qualification

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func (p *Producer) signProviderOriginal(payload any) ([]byte, error) {
	h := sha256.Sum256(canonicalBytes(payload))
	signature, err := ecdsa.SignASN1(rand.Reader, p.key, h[:])
	if err != nil {
		return nil, err
	}
	return canonicalBytes(map[string]any{"payload": payload, "keyId": p.config.KeyID, "signature": base64.StdEncoding.EncodeToString(signature)}), nil
}

func (a providerParticipantAuthority) verifyOpening(opening json.RawMessage, operator []byte) error {
	if workflowcontract.Validate(workflowcontract.ProviderParticipantAccounting, "openingHandshake3", opening) != nil {
		return ErrUntrusted
	}
	var h struct {
		Backend  json.RawMessage
		Runtimes []json.RawMessage
	}
	_ = json.Unmarshal(opening, &h)
	if a.backendOpening(h.Backend, operator, time.Now().UTC(), false) != nil || len(h.Runtimes) != len(a.participants) {
		return ErrUntrusted
	}
	for i, raw := range h.Runtimes {
		if a.verifyRuntimeOpening(raw, a.participants[i], h.Backend) != nil {
			return ErrUntrusted
		}
	}

	return nil
}

func (a providerParticipantAuthority) verifyRuntimeOpening(raw json.RawMessage, part providerParticipant, backend json.RawMessage) error {
	if workflowcontract.Validate(workflowcontract.ProviderParticipantAccounting, "runtimeOpeningEnvelope3", raw) != nil {
		return ErrUntrusted
	}
	b := childFields(childFields(backend)["payload"])
	f := childFields(childFields(raw)["payload"])
	start, e := time.Parse(time.RFC3339Nano, childString(b, "observedAt"))
	end, ee := time.Parse(time.RFC3339Nano, childString(b, "notAfter"))
	at, ae := time.Parse(time.RFC3339Nano, childString(f, "observedAt"))
	expected := a.common()
	expected["caseId"], expected["participantId"], expected["backendOpeningDigest"], expected["notAfter"] = a.c.CaseID, part.ParticipantID, CanonicalDigest(backend), childString(b, "notAfter")
	if e != nil || ee != nil || ae != nil || at.Before(start) || !at.Before(end) || at.After(time.Now().UTC()) || verifyChildEnvelope(raw, part.Producer.KeyID, part.public) != nil || !matchesProviderFields(childFields(raw)["payload"], expected) {
		return ErrUntrusted
	}
	return nil
}

// AcceptProviderParticipantOpening accepts only the single complete handshake;
// Store compares its own independently retained first observation byte-for-byte.
func (p *Producer) AcceptProviderParticipantOpening(ctx context.Context, store *state.Store, authority, demand, opening json.RawMessage, operator []byte) error {
	a, err := p.participantAuthority(authority, demand, operator, time.Now().UTC(), false)
	if err != nil {
		return err
	}
	if a.verifyOpening(opening, operator) != nil {
		return ErrUntrusted
	}
	return store.AcceptVerifiedProviderOpening(ctx, a.own.ParticipantID, opening)
}

func (p *Producer) verifyParticipantPrefix(ctx context.Context, store *state.Store, authority, demand, current json.RawMessage, operator []byte, active bool) (providerParticipantAuthority, state.VerifiedProviderPrefix, error) {
	a, err := p.participantAuthority(authority, demand, operator, time.Now().UTC(), active)
	v := state.VerifiedProviderPrefix{}
	if err != nil || store == nil || workflowcontract.ValidateProviderReadback(current) != nil {
		return a, v, ErrUntrusted
	}
	var prefix model.ProviderAccountingPrefix
	if json.Unmarshal(current, &prefix) != nil || prefix.FormatVersion != 3 || prefix.AuthorityDigest != CanonicalDigest(authority) || prefix.ParticipantInventoryDigest != a.c.ParticipantInventoryDigest || a.verifyOpening(prefix.Opening, operator) != nil {
		return a, v, ErrUntrusted
	}
	retained, err := store.ProviderOpening(ctx)
	if err != nil || !sameProduct(retained, prefix.Opening) {
		return a, v, ErrUntrusted
	}
	v.ParticipantID, v.Prefix = a.own.ParticipantID, prefix
	expected := a.common()
	expected["openingDigest"] = CanonicalDigest(prefix.Opening)
	snapshot := state.ProviderSnapshot{}
	preps := map[int]bool{}
	reservations := map[string]model.ProviderReservation{}
	allocationReservations := map[string]model.ProviderReservation{}
	for i, raw := range prefix.Reservations {
		var r model.ProviderReservation
		_ = json.Unmarshal(raw, &r)
		allocation, e := a.demand.allocation(r.AllocationID)
		if e != nil {
			return a, v, ErrUntrusted
		}
		part := a.allocationOwner[r.AllocationID]
		modelIndex := snapshot.ModelRequests + 1
		if !matchesProviderFields(raw, expected) || r.PhysicalIndex != i+1 || r.PhysicalID != CanonicalDigest(map[string]any{"ledgerId": a.c.LedgerID, "physicalIndex": i + 1}) || r.PhysicalIndex < allocation.FirstPhysicalIndex || r.PhysicalIndex > allocation.LastPhysicalIndex || r.ParticipantID != part.ParticipantID || r.ScopeDigest != allocation.ScopeDigest || r.PreparationOrdinal != allocation.PreparationOrdinal || r.Kind != allocation.Kind || r.ReservedUsdMicros != RequestMicros {
			return a, v, ErrUntrusted
		}
		if r.Kind == "access" {
			if r.ModelRequestIndex != nil || r.NativeInputID != nil || r.NativeSessionID != nil {
				return a, v, ErrUntrusted
			}
		} else {
			if r.ModelRequestIndex == nil || *r.ModelRequestIndex != modelIndex || r.NativeInputID == nil || r.NativeSessionID == nil {
				return a, v, ErrUntrusted
			}
			snapshot.ModelRequests++
			snapshot.Turns++
			preps[r.PreparationOrdinal] = true
		}
		if previous, ok := allocationReservations[r.AllocationID]; ok {
			if previous.ReservationID != r.ReservationID || previous.SubjectID != r.SubjectID || !reflect.DeepEqual(previous.NativeSessionID, r.NativeSessionID) || !reflect.DeepEqual(previous.NativeInputID, r.NativeInputID) {
				return a, v, ErrUntrusted
			}
		} else if r.PhysicalIndex != allocation.FirstPhysicalIndex {
			return a, v, ErrUntrusted
		}
		allocationReservations[r.AllocationID] = r
		reservations[r.PhysicalID] = r
		snapshot.PhysicalRequests++
		snapshot.ReservedUsdMicros += r.ReservedUsdMicros
	}
	snapshot.Preparations = len(preps)
	if snapshot.PhysicalRequests > a.c.Requests || snapshot.ModelRequests > a.c.ModelRequests || snapshot.Preparations > a.c.Preparations {
		return a, v, ErrUntrusted
	}
	for i, raw := range prefix.Settlements {
		var signed struct {
			Payload struct {
				PhysicalID, ParticipantID, ReservationDigest, NativeSessionID, NativeInputID string
				ActualUsdMicros                                                              int64
				Usage                                                                        *providerpolicy.Usage
				StartedAt, CompletedAt                                                       string
			}
		}
		// Native IDs are nullable for access; preserve their raw wire for comparison.
		if json.Unmarshal(raw, &signed) != nil {
			return a, v, ErrUntrusted
		}
		f := childFields(childFields(raw)["payload"])
		r, ok := reservations[signed.Payload.PhysicalID]
		if !ok || r.PhysicalIndex != i+1 {
			return a, v, ErrUntrusted
		}
		part := a.allocationOwner[r.AllocationID]
		if workflowcontract.Validate(workflowcontract.ProviderParticipantAccounting, "settlementEnvelope3", raw) != nil || verifyChildEnvelope(raw, part.Producer.KeyID, part.public) != nil || !matchesProviderFields(childFields(raw)["payload"], expected) || signed.Payload.ParticipantID != part.ParticipantID || signed.Payload.ReservationDigest != CanonicalDigest(prefix.Reservations[r.PhysicalIndex-1]) || !sameProduct(f["nativeSessionId"], r.NativeSessionID) || !sameProduct(f["nativeInputId"], r.NativeInputID) {
			return a, v, ErrUntrusted
		}
		cost := int64(0)
		if r.Kind == "access" {
			if signed.Payload.Usage != nil {
				return a, v, ErrUntrusted
			}
		} else {
			if signed.Payload.Usage == nil {
				return a, v, ErrUntrusted
			}
			cost, err = providerpolicy.UsageCost(providerpolicy.ParticipantDigest, *signed.Payload.Usage)
			if err != nil {
				return a, v, ErrUntrusted
			}
		}
		start, se := time.Parse(time.RFC3339Nano, signed.Payload.StartedAt)
		end, ee := time.Parse(time.RFC3339Nano, signed.Payload.CompletedAt)
		if se != nil || ee != nil || start.After(end) || end.After(time.Now().UTC()) || cost != signed.Payload.ActualUsdMicros {
			return a, v, ErrUntrusted
		}
		snapshot.ReservedUsdMicros -= r.ReservedUsdMicros
		snapshot.ActualUsdMicros += cost
	}
	if snapshot.ReservedUsdMicros+snapshot.ActualUsdMicros > a.c.USDMicros || !sameProduct(prefix.Snapshot, snapshot) {
		return a, v, ErrUntrusted
	}
	return a, v, nil
}

func (p *Producer) BindProviderParticipantReservation(ctx context.Context, store *state.Store, authority, demand, current json.RawMessage, operator []byte, permit state.PhysicalPermit) (state.PhysicalPermit, error) {
	a, v, err := p.verifyParticipantPrefix(ctx, store, authority, demand, current, operator, true)
	if err != nil {
		return permit, err
	}
	allocation, ae := a.demand.allocation(permit.AllocationID)
	if ae != nil || permit.Caller.SandboxID != allocation.Scope.SandboxID || permit.Caller.SandboxGeneration != allocation.Scope.SandboxGeneration || permit.Case.TaskID != a.own.TaskID || permit.Case.ServerID != a.own.ServerID || permit.Case.CaseDigest != a.c.CaseManifestDigest || !live(a.demand.NotAfter, time.Now().UTC()) {
		return permit, ErrUntrusted
	}
	return store.BindVerifiedProviderReservation(ctx, permit, v)
}

func (p *Producer) ObserveProviderReadback(ctx context.Context, store *state.Store, authority, demand, current json.RawMessage, operator []byte) (json.RawMessage, error) {
	a, v, err := p.verifyParticipantPrefix(ctx, store, authority, demand, current, operator, false)
	if err != nil {
		return nil, err
	}
	result, err := store.ObserveProviderComposite(ctx, v, func(local state.ProviderLocalCut) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		payload := a.common()
		payload["openingDigest"], payload["participantId"], payload["observedAt"] = CanonicalDigest(v.Prefix.Opening), a.own.ParticipantID, time.Now().UTC().Format(time.RFC3339Nano)
		payload["global"] = map[string]any{"reservations": v.Prefix.Reservations, "settlements": v.Prefix.Settlements, "snapshot": v.Prefix.Snapshot}
		payload["local"] = local
		return p.signProviderOriginal(payload)
	})
	if err != nil {
		return nil, err
	}
	expected := a.common()
	expected["participantId"], expected["openingDigest"] = a.own.ParticipantID, CanonicalDigest(v.Prefix.Opening)
	if verifyChildEnvelope(result, p.config.KeyID, a.own.public) != nil || !matchesProviderFields(childFields(result)["payload"], expected) {
		return nil, ErrUntrusted
	}
	return result, nil
}
