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
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type ProviderSettlementControl interface {
	SettleProviderAccountingOriginals(context.Context, json.RawMessage) (json.RawMessage, error)
}

// SettleProviderPhysical observes the SAME verifier-retained original response,
// preserves the first producer signature, and requires backend acceptance before
// the local owner can release cash exposure. Failure leaves UNKNOWN unchanged.
func (p *Producer) SettleProviderPhysical(ctx context.Context, store *state.Store, control ProviderSettlementControl, operation state.PhysicalOperation, evidence model.PhysicalSettlement) error {
	if p == nil || p.key == nil || store == nil || control == nil || operation.Permit.Provider == nil || operation.Permit.Case.AccountingVersion != 2 || operation.Permit.Case.ServerID != p.config.ServerID {
		return ErrUntrusted
	}
	retained, err := store.PhysicalOperation(ctx, operation.OperationID)
	if err != nil || retained == nil || !reflect.DeepEqual(*retained, operation) {
		return ErrUntrusted
	}
	opening, err := store.ProviderOpening(ctx)
	if err != nil {
		return err
	}
	pair := childFields(opening)
	public, err := p.paidPublic()
	if err != nil {
		return err
	}
	ownOpening := pair["runtime"]
	participantID := ""
	if operation.Permit.Case.ProviderPolicyDigest == providerpolicy.ParticipantDigest {
		var all []json.RawMessage
		if json.Unmarshal(pair["runtimes"], &all) != nil {
			return ErrUntrusted
		}
		ownID, err := store.PhysicalFact(ctx, "provider_participant_identity")
		if err != nil {
			return err
		}
		ownOpening = nil
		for _, raw := range all {
			if childString(childFields(childFields(raw)["payload"]), "participantId") == string(ownID) {
				if ownOpening != nil {
					return ErrUntrusted
				}
				ownOpening = raw
				participantID = childString(childFields(childFields(raw)["payload"]), "participantId")
			}
		}
		if !hash.MatchString(participantID) {
			return ErrUntrusted
		}
	}
	if verifyChildEnvelope(ownOpening, p.config.KeyID, public) != nil {
		return ErrUntrusted
	}
	var reservation model.ProviderReservation
	rawReservation := operation.Permit.Provider.Reservation
	if workflowcontract.ValidateProviderAccounting("reservation", rawReservation) != nil || json.Unmarshal(rawReservation, &reservation) != nil || reservation.ProviderPolicyDigest != operation.Permit.Case.ProviderPolicyDigest || reservation.ParticipantID != participantID || reservation.OpeningDigest != CanonicalDigest(opening) {
		return ErrUntrusted
	}
	originals, completed, err := store.NativeProviderOriginals(ctx, operation.OperationID, evidence)
	if err != nil {
		return err
	}
	responseID, cost := "", int64(0)
	policy, selected := providerpolicy.Select(reservation.ProviderPolicyDigest)
	if !selected {
		return ErrUntrusted
	}
	var usage *providerpolicy.Usage
	if reservation.Kind == "access" {
		var catalog struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(originals.Response, &catalog) != nil || evidence.HTTPStatus != 200 || len(originals.Request) != 0 || !model.PhysicalIDValid(originals.ProviderRequestID) {
			return ErrUntrusted
		}
		found := false
		for _, entry := range catalog.Data {
			if entry.ID == policy.ModelID {
				found = true
			}
		}
		if !found {
			return ErrUntrusted
		}
		responseID = originals.ProviderRequestID
	} else {
		var projection providerpolicy.Usage
		_, cost, projection, err = physicalgate.ProviderResponseUsageOriginal(reservation.ProviderPolicyDigest, originals.Response, evidence.HTTPStatus)
		usage = &projection
		if err != nil {
			return err
		}
		responseID = originals.ProviderRequestID
	}
	if cost != evidence.UsageUsdMicros || !model.PhysicalIDValid(responseID) || len(responseID) > 128 {
		return ErrUntrusted
	}
	var transport struct{ Method, URL, BodyDigest string }
	method, url := policy.Transport.Method, policy.Transport.URL
	if reservation.Kind == "access" {
		method, url = policy.Access.Method, policy.Access.URL
	}
	if workflowcontract.Validate(workflowcontract.ProviderAccounting, "transportOriginal", originals.Transport) != nil || json.Unmarshal(originals.Transport, &transport) != nil || transport.Method != method || transport.URL != url || transport.BodyDigest != model.RawPhysicalDigest(originals.Request) {
		return ErrUntrusted
	}
	start, se := time.Parse(time.RFC3339Nano, operation.StartedAt)
	end, ee := time.Parse(time.RFC3339Nano, completed)
	if se != nil || ee != nil || start.After(end) || end.After(time.Now()) {
		return ErrUntrusted
	}
	payload := map[string]any{"formatVersion": 2, "accountingVersion": 2, "ledgerId": reservation.LedgerID, "providerPolicyDigest": reservation.ProviderPolicyDigest, "authorityDigest": reservation.AuthorityDigest, "demandManifestDigest": reservation.DemandManifestDigest, "openingDigest": reservation.OpeningDigest, "physicalId": reservation.PhysicalID, "reservationDigest": CanonicalDigest(rawReservation), "transportOriginalDigest": Digest(originals.Transport), "requestDigest": Digest(originals.Request), "wireResponseDigest": Digest(originals.Response), "providerRequestId": responseID, "nativeSessionId": reservation.NativeSessionID, "nativeInputId": reservation.NativeInputID, "httpStatus": evidence.HTTPStatus, "actualUsdMicros": cost, "startedAt": operation.StartedAt, "completedAt": completed}
	if participantID != "" {
		payload["formatVersion"] = 3
		payload["participantId"] = participantID
		payload["participantInventoryDigest"] = reservation.ParticipantInventoryDigest
		payload["usage"] = usage
	}
	if workflowcontract.ValidateProviderAccounting("settlement", canonicalBytes(payload)) != nil {
		return ErrUntrusted
	}
	key := "provider_settlement_" + Digest([]byte(operation.OperationID))[7:]
	envelope, err := store.PhysicalFact(ctx, key)
	if err != nil {
		return err
	}
	if len(envelope) == 0 {
		h := sha256.Sum256(canonicalBytes(payload))
		sig, err := ecdsa.SignASN1(rand.Reader, p.key, h[:])
		if err != nil {
			return err
		}
		envelope = canonicalBytes(map[string]any{"payload": payload, "keyId": p.config.KeyID, "signature": base64.StdEncoding.EncodeToString(sig)})
		if err = store.RetainPhysicalFact(ctx, key, envelope); err != nil {
			return err
		}
	}
	if verifyChildEnvelope(envelope, p.config.KeyID, public) != nil || !sameProduct(childFields(envelope)["payload"], payload) {
		return ErrUntrusted
	}
	ackKey := "provider_settlement_ack_" + Digest([]byte(operation.OperationID))[7:]
	if ack, err := store.PhysicalFact(ctx, ackKey); err != nil {
		return err
	} else if len(ack) > 0 {
		return nil
	}
	originalList := []map[string]any{}
	for _, raw := range [][]byte{originals.Transport, originals.Request, originals.Response} {
		originalList = append(originalList, map[string]any{"digest": Digest(raw), "contentBase64": base64.StdEncoding.EncodeToString(raw)})
	}
	format := 2
	if participantID != "" {
		format = 3
	}
	body := canonicalBytes(map[string]any{"formatVersion": format, "settlement": json.RawMessage(envelope), "originals": originalList})
	if workflowcontract.ValidateProviderOriginals(body) != nil {
		return ErrUntrusted
	}
	ack, err := control.SettleProviderAccountingOriginals(ctx, body)
	if err != nil {
		return err
	}
	return store.RetainPhysicalFact(ctx, ackKey, ack)
}
