package qualification

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"sort"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type providerParticipant struct {
	ParticipantID, AccountID, TaskID, ServerID string
	Producer                                   struct{ KeyID, KeySHA256, NodeTokenHash, PublicKeyBase64 string }
	Scopes                                     []model.ControllerOwner
	public                                     []byte
}
type providerParticipantAuthority struct {
	raw             json.RawMessage
	fields          map[string]json.RawMessage
	c               RealCase
	demand          DemandManifest
	own             providerParticipant
	participants    []providerParticipant
	allocationOwner map[string]providerParticipant
	operatorID      string
}

// Public keys are supplied only by the exact operator-bound inventory. Their
// bytes are never inferred from a settlement or fetched from a caller path.
func participantPublic(encoded, expected string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) > 4096 || Digest(raw) != "sha256:"+expected {
		return nil, ErrUntrusted
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		return nil, ErrUntrusted
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve.Params().Name != "P-256" {
		return nil, ErrUntrusted
	}
	return raw, nil
}

func (p *Producer) participantAuthority(authority, demandEnvelope json.RawMessage, operator []byte, now time.Time, current bool) (providerParticipantAuthority, error) {
	out := providerParticipantAuthority{raw: authority, fields: childFields(authority), allocationOwner: map[string]providerParticipant{}}
	if p == nil || p.key == nil || workflowcontract.Validate(workflowcontract.BudgetParticipants, "authority5", authority) != nil || workflowcontract.Validate(workflowcontract.BudgetParticipants, "demandManifestEnvelope", demandEnvelope) != nil {
		return out, ErrUntrusted
	}
	a := out.fields
	op := childFields(a["operator"])
	out.operatorID = childString(op, "keyId")
	if Digest(operator) != "sha256:"+childString(op, "keySHA256") || Digest(operator) == p.config.KeySHA256 || verifyChildEnvelope(demandEnvelope, out.operatorID, operator) != nil {
		return out, ErrUntrusted
	}
	var signed ChildEnvelope[DemandManifest]
	if json.Unmarshal(a["case"], &out.c) != nil || json.Unmarshal(demandEnvelope, &signed) != nil {
		return out, ErrUntrusted
	}
	out.demand = signed.Payload
	// Historical first records retain their signed chronology. New effects still
	// require current demand; this historical option is only opening/readback.
	validationTime := now
	if !current {
		var err error
		validationTime, err = time.Parse(time.RFC3339Nano, out.demand.DeclaredAt)
		if err != nil {
			return out, ErrUntrusted
		}
	}
	if out.c.FormatVersion != 5 || out.demand.validateProvider(out.c, validationTime) != nil || out.c.OperatorKeySHA256 != Digest(operator) || childString(a, "caseId") != out.c.CaseID || childString(a, "caseManifestDigest") != out.c.CaseManifestDigest || CanonicalDigest(a["tupleInventory"]) != out.c.TupleInventoryDigest || CanonicalDigest(a["participantInventory"]) != out.c.ParticipantInventoryDigest {
		return out, ErrUntrusted
	}
	var inventory struct {
		CaseID       string
		Participants []json.RawMessage
	}
	if json.Unmarshal(a["participantInventory"], &inventory) != nil || inventory.CaseID != out.c.CaseID {
		return out, ErrUntrusted
	}
	public, err := p.paidPublic()
	if err != nil {
		return out, err
	}
	scopes := map[string]bool{}
	keys := map[string]bool{}
	tasks := map[string]bool{}
	servers := map[string]bool{}
	previous, account := "", ""
	for _, raw := range inventory.Participants {
		var part providerParticipant
		if json.Unmarshal(raw, &part) != nil {
			return out, ErrUntrusted
		}
		identity := childFields(raw)
		delete(identity, "participantId")
		if CanonicalDigest(identity) != part.ParticipantID || part.ParticipantID <= previous || keys[part.Producer.KeySHA256] || tasks[part.TaskID] || servers[part.ServerID] || (account != "" && account != part.AccountID) {
			return out, ErrUntrusted
		}
		part.public, err = participantPublic(part.Producer.PublicKeyBase64, part.Producer.KeySHA256)
		if err != nil || Digest(part.public) == Digest(operator) {
			return out, ErrUntrusted
		}
		previous, account = part.ParticipantID, part.AccountID
		keys[part.Producer.KeySHA256], tasks[part.TaskID], servers[part.ServerID] = true, true, true
		lastScope := ""
		for _, scope := range part.Scopes {
			key := string(canonicalBytes(scope))
			if key <= lastScope || scopes[key] || scope.AccountID != part.AccountID || scope.TaskID != part.TaskID || scope.ServerID != part.ServerID {
				return out, ErrUntrusted
			}
			scopes[key] = true
			lastScope = key
		}
		if part.Producer.KeyID == p.config.KeyID && "sha256:"+part.Producer.KeySHA256 == p.config.KeySHA256 && part.Producer.NodeTokenHash == p.config.NodeTokenHash && part.ServerID == p.config.ServerID && reflect.DeepEqual(part.public, public) {
			if out.own.ParticipantID != "" {
				return out, ErrUntrusted
			}
			out.own = part
		}
		out.participants = append(out.participants, part)
	}
	if out.own.ParticipantID == "" {
		return out, ErrUntrusted
	}
	var tuples struct {
		CaseID string
		Tuples []struct {
			TupleDigest   string
			Applicability Applicability
			Consumers     []struct {
				SourceID string
				Scope    model.ControllerOwner
			}
		}
	}
	if json.Unmarshal(a["tupleInventory"], &tuples) != nil || tuples.CaseID != out.c.CaseID {
		return out, ErrUntrusted
	}
	sources := map[string]string{}
	tupleScopes := map[string]map[string]bool{}
	for _, tuple := range tuples.Tuples {
		if CanonicalDigest(tuple.Applicability) != tuple.TupleDigest || tuple.Applicability.CaseManifestDigest != out.c.CaseManifestDigest || tupleScopes[tuple.TupleDigest] != nil {
			return out, ErrUntrusted
		}
		tupleScopes[tuple.TupleDigest] = map[string]bool{}
		for _, consumer := range tuple.Consumers {
			key := string(canonicalBytes(consumer.Scope))
			if sources[consumer.SourceID] != "" || !scopes[key] || consumer.Scope.TaskID != tuple.Applicability.TaskID || consumer.Scope.ServerID != tuple.Applicability.ServerID || consumer.Scope.AccountID != tuple.Applicability.AccountID || consumer.Scope.SandboxID != tuple.Applicability.SandboxID || consumer.Scope.SandboxGeneration != tuple.Applicability.SandboxGeneration {
				return out, ErrUntrusted
			}
			sources[consumer.SourceID] = tuple.TupleDigest + key
			tupleScopes[tuple.TupleDigest][key] = true
		}
	}
	used := map[string]bool{}
	for _, allocation := range out.demand.AllocationList {
		key := string(canonicalBytes(allocation.Scope))
		if CanonicalDigest(allocation.Scope) != allocation.ScopeDigest || sources[allocation.SourceID] != allocation.TupleDigest+key || !tupleScopes[allocation.TupleDigest][key] {
			return out, ErrUntrusted
		}
		for _, part := range out.participants {
			for _, scope := range part.Scopes {
				if reflect.DeepEqual(scope, allocation.Scope) {
					out.allocationOwner[allocation.AllocationID] = part
					used[part.ParticipantID] = true
				}
			}
		}
		if out.allocationOwner[allocation.AllocationID].ParticipantID == "" {
			return out, ErrUntrusted
		}
	}
	if len(used) != len(out.participants) {
		return out, ErrUntrusted
	}
	return out, nil
}

func (a providerParticipantAuthority) common() map[string]any {
	return map[string]any{"formatVersion": 3, "accountingVersion": 2, "ledgerId": a.c.LedgerID, "providerPolicyDigest": providerpolicy.ParticipantDigest, "authorityDigest": CanonicalDigest(a.raw), "demandManifestDigest": a.c.DemandManifestDigest, "participantInventoryDigest": a.c.ParticipantInventoryDigest}
}
func matchesProviderFields(raw json.RawMessage, expected map[string]any) bool {
	f := childFields(raw)
	for key, value := range expected {
		if !sameProduct(f[key], value) {
			return false
		}
	}
	return true
}

func (a providerParticipantAuthority) backendOpening(raw json.RawMessage, operator []byte, now time.Time, fresh bool) error {
	if workflowcontract.Validate(workflowcontract.ProviderParticipantAccounting, "backendOpeningEnvelope3", raw) != nil || verifyChildEnvelope(raw, a.operatorID, operator) != nil {
		return ErrUntrusted
	}
	b := childFields(raw)["payload"]
	f := childFields(b)
	expected := a.common()
	expected["caseId"], expected["candidateInventoryDigest"], expected["accountScopeDigest"] = a.c.CaseID, a.demand.CandidateInventoryDigest, a.demand.AccountScopeDigest
	if !matchesProviderFields(b, expected) {
		return ErrUntrusted
	}
	observed, e := time.Parse(time.RFC3339Nano, childString(f, "observedAt"))
	expiry, ee := time.Parse(time.RFC3339Nano, childString(f, "notAfter"))
	end, de := time.Parse(time.RFC3339Nano, a.demand.NotAfter)
	if e != nil || ee != nil || de != nil || !observed.Before(expiry) || expiry.After(end) || expiry.Sub(observed) > 5*time.Minute || (fresh && (observed.After(now) || observed.Before(now.Add(-120*time.Second)) || !now.Before(expiry))) {
		return ErrUntrusted
	}
	var consents []struct{ ParticipantID, TupleDigest, OwnerConsentDigest string }
	if json.Unmarshal(f["ownerConsents"], &consents) != nil {
		return ErrUntrusted
	}
	var tuples struct {
		Tuples []struct {
			TupleDigest   string
			Applicability struct{ TaskID string }
		}
	}
	_ = json.Unmarshal(a.fields["tupleInventory"], &tuples)
	want := []string{}
	for _, tuple := range tuples.Tuples {
		for _, part := range a.participants {
			if part.TaskID == tuple.Applicability.TaskID {
				want = append(want, part.ParticipantID+tuple.TupleDigest)
			}
		}
	}
	sort.Strings(want)
	if len(consents) != len(want) {
		return ErrUntrusted
	}
	for i, c := range consents {
		if c.ParticipantID+c.TupleDigest != want[i] || !hash.MatchString(c.OwnerConsentDigest) {
			return ErrUntrusted
		}
	}
	return nil
}

func (p *Producer) observeParticipantOpening(ctx context.Context, store *state.Store, authority, demand, backend json.RawMessage, operator []byte) (json.RawMessage, error) {
	first, err := store.PhysicalFact(ctx, "provider_opening_runtime")
	if err != nil {
		return nil, err
	}
	a, err := p.participantAuthority(authority, demand, operator, time.Now().UTC(), len(first) == 0)
	if err != nil {
		return nil, err
	}
	if a.backendOpening(backend, operator, time.Now().UTC(), len(first) == 0) != nil {
		return nil, ErrUntrusted
	}
	if len(first) > 0 {
		if a.verifyRuntimeOpening(first, a.own, backend) != nil {
			return nil, ErrUntrusted
		}
	}
	c := state.PhysicalCase{AccountingVersion: 2, ProviderPolicyDigest: providerpolicy.ParticipantDigest, TaskID: a.own.TaskID, ServerID: a.own.ServerID, CaseDigest: a.c.CaseManifestDigest, BaselineDigest: CanonicalDigest(backend), Requests: a.c.Requests, Preparations: a.c.Preparations, ModelRequests: a.c.ModelRequests, AccessRequests: a.c.AccessRequests, UsdMicros: a.c.USDMicros}
	return store.ObserveEmptyProviderOpening(ctx, c, canonicalBytes(backend), func() ([]byte, error) {
		if a.backendOpening(backend, operator, time.Now().UTC(), true) != nil {
			return nil, ErrUntrusted
		}
		payload := a.common()
		payload["caseId"], payload["surface"], payload["participantId"], payload["backendOpeningDigest"] = a.c.CaseID, "runtime", a.own.ParticipantID, CanonicalDigest(backend)
		payload["snapshot"], payload["historyDigest"], payload["observedAt"], payload["notAfter"] = state.ProviderSnapshot{}, CanonicalDigest([]any{}), time.Now().UTC().Format(time.RFC3339Nano), childString(childFields(childFields(backend)["payload"]), "notAfter")
		return p.signProviderOriginal(payload)
	})
}
