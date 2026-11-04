package qualification_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type accountingFamilySource struct {
	Authority, Demand, BackendOpening json.RawMessage
}

// This is a phase of the existing real SQLite opening/admission journey. Keys,
// authority, resolved permits and settlement amounts are explicitly SOURCE;
// SQLite transactions, first signatures, finite slots and UNKNOWN are real.
func runProviderAccountingFamilySource(t *testing.T, raw []byte) {
	t.Helper()
	var packet struct {
		Root                    string
		Producer                qualification.ProducerConfig
		OperatorPublicKeyBase64 string
		Old, Current            accountingFamilySource
		Participants            []struct {
			ParticipantID string
			Producer      qualification.ProducerConfig
		}
	}
	if json.Unmarshal(raw, &packet) != nil || !filepath.IsAbs(packet.Root) {
		t.Fatal("invalid family SOURCE packet")
	}
	producer, err := qualification.SourceAccountingProducerForTest(packet.Producer)
	if err != nil {
		t.Fatal("SOURCE producer key identity", err)
	}
	operator, err := base64.StdEncoding.DecodeString(packet.OperatorPublicKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	open := func(name string) *state.Store {
		s, err := state.Open(filepath.Join(packet.Root, name+".db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	observe := func(s *state.Store, f accountingFamilySource) (json.RawMessage, error) {
		return producer.ObserveProviderOpening(ctx, s, f.Authority, f.Demand, f.BackendOpening, operator)
	}
	caseFor := func(f accountingFamilySource) state.PhysicalCase {
		var a struct {
			Case           qualification.RealCase
			TupleInventory struct {
				Tuples []struct{ Applicability struct{ TaskID string } }
			}
		}
		if json.Unmarshal(f.Authority, &a) != nil || len(a.TupleInventory.Tuples) == 0 {
			t.Fatal("source case")
		}
		c := a.Case
		return state.PhysicalCase{AccountingVersion: c.AccountingVersion, ProviderPolicyDigest: c.ProviderPolicyDigest,
			TaskID: a.TupleInventory.Tuples[0].Applicability.TaskID, ServerID: packet.Producer.ServerID,
			CaseDigest: c.CaseManifestDigest, BaselineDigest: model.WorkspaceDigest(f.BackendOpening), Requests: c.Requests,
			Preparations: c.Preparations, ModelRequests: c.ModelRequests, AccessRequests: c.AccessRequests, UsdMicros: c.USDMicros}
	}
	permits := func(f accountingFamilySource) []state.PhysicalPermit {
		var envelope struct {
			Payload struct {
				Allocations []qualification.DemandAllocation
			}
		}
		if json.Unmarshal(f.Demand, &envelope) != nil {
			t.Fatal("source allocations")
		}
		c := caseFor(f)
		var out []state.PhysicalPermit
		models := 0
		for _, a := range envelope.Payload.Allocations {
			for index := a.FirstPhysicalIndex; index <= a.LastPhysicalIndex; index++ {
				consumer, requestIndex := "product", index-a.FirstPhysicalIndex+1
				if a.Kind == "access" {
					consumer = "access"
				} else {
					models++
					if a.Kind == "parent" {
						consumer = "parent"
						requestIndex = models
					}
				}
				out = append(out, state.PhysicalPermit{Case: c, AllocationID: a.AllocationID, PreparationOrdinal: a.PreparationOrdinal,
					Caller: state.PhysicalSubject{SandboxID: a.Scope.SandboxID, SandboxGeneration: a.Scope.SandboxGeneration, NativeInstance: "source_family_native", NativeIdentityDigest: model.WorkspaceDigest("source native")},
					Request: model.PhysicalAdmitRequest{Consumer: consumer, PreparationID: "source_" + a.AllocationID, RequestIndex: requestIndex, OuterPhysicalIndex: index,
						AuthorityDigest: model.WorkspaceDigest(f.Authority), RequestDigest: model.WorkspaceDigest(map[string]any{"allocation": a.AllocationID, "index": index})}})
			}
		}
		if len(out) != c.Requests {
			t.Fatal("SOURCE allocation coverage")
		}
		return out
	}
	settle := func(s *state.Store, id string, p state.PhysicalPermit) {
		e := model.PhysicalSettlement{RequestDigest: p.Request.RequestDigest, ResponseDigest: model.WorkspaceDigest("source response"), ResponseByteCount: 1, HTTPStatus: 200, UsageUsdMicros: 7, EvidenceDigest: model.WorkspaceDigest("source settlement")}
		if err := s.SettlePhysical(ctx, id, p.Caller, e); err != nil {
			t.Fatal("SOURCE settle", err)
		}
	}
	oldPermits, newPermits := permits(packet.Old), permits(packet.Current)
	if len(oldPermits) != 19 || len(newPermits) != 21 || caseFor(packet.Current).ModelRequests != 19 || caseFor(packet.Current).Preparations != 15 {
		t.Fatal("wrong declared family")
	}

	t.Run("old19_first_signature_and_slot20_refusal", func(t *testing.T) {
		s := open("old19")
		first, err := observe(s, packet.Old)
		if err != nil {
			t.Fatal("old19 opening", err)
		}
		again, err := observe(s, packet.Old)
		if err != nil || !bytes.Equal(first, again) {
			t.Fatal("old first signature changed", err)
		}
		if err := os.WriteFile(filepath.Join(packet.Root, "old-first-opening.json"), first, 0600); err != nil {
			t.Fatal(err)
		}
		for i, p := range oldPermits {
			id := fmt.Sprintf("old_source_%d", i+1)
			if err := s.AdmitPhysical(ctx, id, p); err != nil {
				t.Fatal("old admission", i+1, err)
			}
			settle(s, id, p)
		}
		before, _ := s.PhysicalLedgerCut(ctx)
		p := newPermits[19]
		p.Case = caseFor(packet.Old)
		if s.AdmitPhysical(ctx, "old_slot20", p) == nil {
			t.Fatal("old19 authorized chat slot20")
		}
		if _, err := observe(s, packet.Current); err == nil {
			t.Fatal("nonempty old ledger rolled into new family")
		}
		after, err := s.PhysicalLedgerCut(ctx)
		if err != nil || model.WorkspaceDigest(before) != model.WorkspaceDigest(after) {
			t.Fatal("old settled history changed", err)
		}
		t.Log("old19 actual SQLite opening/replay, 19 finite settled SOURCE slots, slot20 denied, unchanged cut")
	})
	t.Run("mixed_family_and_unknown_survive_reopen", func(t *testing.T) {
		s := open("unknown")
		first, err := observe(s, packet.Old)
		if err != nil {
			t.Fatal(err)
		}
		p := oldPermits[0]
		if err := s.AdmitPhysical(ctx, "first_unknown", p); err != nil {
			t.Fatal(err)
		}
		before, _ := s.PhysicalLedgerCut(ctx)
		mixed := packet.Current
		mixed.Demand = packet.Old.Demand
		if _, err := observe(s, mixed); err == nil {
			t.Fatal("mixed signed family accepted")
		}
		if _, err := observe(s, packet.Current); err == nil {
			t.Fatal("UNKNOWN ledger replaced")
		}
		if s.AdmitPhysical(ctx, "new_case_on_old", newPermits[0]) == nil {
			t.Fatal("new family admitted over old UNKNOWN")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = open("unknown")
		after, err := s.PhysicalLedgerCut(ctx)
		if err != nil || model.WorkspaceDigest(before) != model.WorkspaceDigest(after) {
			t.Fatal("UNKNOWN lost across reopening", err)
		}
		retained, err := observe(s, packet.Old)
		if err != nil || !bytes.Equal(first, retained) {
			t.Fatal("old opening re-signed on resume", err)
		}
		owner, err := s.PhysicalOwner(ctx)
		if err != nil || owner == nil || owner.OperationID != "first_unknown" || owner.ReservedUsdMicros != 421000 {
			t.Fatal("UNKNOWN hold lost", err)
		}
		t.Log("mixed family denied; exact original opening and UNKNOWN421000 retained through same SQLite reopen")
	})
	if len(packet.Participants) != 0 {
		if len(packet.Participants) != 2 {
			t.Fatal("two independent SOURCE participants required")
		}
		for i, participant := range packet.Participants {
			t.Run(fmt.Sprintf("authority5_participant_%d_fresh_empty_opening", i+1), func(t *testing.T) {
				checkAccountingParticipantSource(t, packet.Current.Authority, participant.Producer, participant.ParticipantID)
				own, err := qualification.SourceAccountingProducerForTest(participant.Producer)
				if err != nil {
					t.Fatal("own SOURCE producer key", err)
				}
				s, err := state.Open(filepath.Join(participant.Producer.EvidenceRoot, "runtime.db"))
				if err != nil {
					t.Fatal("own independent SQLite", err)
				}
				defer s.Close()
				first, err := own.ObserveProviderOpening(ctx, s, packet.Current.Authority, packet.Current.Demand, packet.Current.BackendOpening, operator)
				if err != nil {
					anchor, ae := s.PhysicalAnchor(ctx)
					owner, oe := s.PhysicalOwner(ctx)
					retained, re := s.PhysicalFact(ctx, "provider_opening_runtime")
					if ae != nil || oe != nil || re != nil || anchor != nil || owner != nil || len(retained) != 0 {
						t.Fatal("refused participant mutated fresh local ledger", err)
					}
					t.Fatal("AUTHORITY5_PARTICIPANT_OPENING_UNSUPPORTED: schema/signature-validated detached SOURCE authority5/demand5/backendOpening3 refused by actual fresh own SQLite observer; no local mutation", err)
				}
				again, err := own.ObserveProviderOpening(ctx, s, packet.Current.Authority, packet.Current.Demand, packet.Current.BackendOpening, operator)
				if err != nil || !bytes.Equal(first, again) {
					t.Fatal("own first opening signature replaced", err)
				}
				if err := os.WriteFile(filepath.Join(packet.Root, fmt.Sprintf("participant-%d-opening.json", i+1)), first, 0600); err != nil {
					t.Fatal(err)
				}
			})
		}
		return
	}
	t.Run("authority4_fresh_empty_opening_and_finite21", func(t *testing.T) {
		s := open("current21")
		first, err := observe(s, packet.Current)
		if err != nil {
			anchor, _ := s.PhysicalAnchor(ctx)
			if anchor != nil {
				t.Fatal("failed new-family opening mutated ledger", err)
			}
			t.Fatal("AUTHORITY4_FAMILY_UNSUPPORTED: independently schema-validated current authority4/demand4/operator opening refused at actual fresh SQLite opening boundary", err)
		}
		again, err := observe(s, packet.Current)
		if err != nil || !bytes.Equal(first, again) {
			t.Fatal("new first signature changed", err)
		}
		for i, p := range newPermits {
			id := fmt.Sprintf("current_source_%d", i+1)
			if err := s.AdmitPhysical(ctx, id, p); err != nil {
				t.Fatal("current admission", i+1, err)
			}
			settle(s, id, p)
		}
		p := newPermits[20]
		p.Request.OuterPhysicalIndex = 22
		p.Request.RequestIndex = 20
		if s.AdmitPhysical(ctx, "current_slot22", p) == nil {
			t.Fatal("successor finite budget expanded")
		}
		t.Log("fresh21 actual SQLite admission complete; first19 + declared two advisory slots only; no provider/native")
	})
}
