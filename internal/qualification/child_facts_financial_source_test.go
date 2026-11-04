package qualification

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Same signed Store/HTTP/native DATA journey. Public SQLite APIs retain exact
// local HTTP originals. Earlier allocation history is explicitly SOURCE; this
// does not assert backend paid approval, protected signing, or native execution.
func SourceChildFinancialCompletionForTest(t *testing.T, root string, w ChildProductWitness, control ChildProductControl, capture model.ChildNativeIntegrationCapture) {
	t.Helper()
	ctx := context.Background()
	s, err := state.Open(filepath.Join(root, "facts-financial-source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := control.Generation.Policy.Payload
	c := state.PhysicalCase{AccountingVersion: q.AccountingVersion, ProviderPolicyDigest: q.ProviderPolicyDigest, TaskID: w.Applicability.TaskID, ServerID: w.Applicability.ServerID, CaseDigest: q.Case.CaseManifestDigest, BaselineDigest: Digest([]byte("explicit SOURCE prior prefix")), Requests: q.Case.Requests, Preparations: q.Case.Preparations, ModelRequests: q.Case.ModelRequests, AccessRequests: q.Case.AccessRequests, UsdMicros: q.Case.USDMicros}
	caller := state.PhysicalSubject{SandboxID: w.Entry.SandboxID, SandboxGeneration: w.Entry.SandboxGeneration, NativeInstance: w.Entry.Instance, NativeIdentityDigest: Digest([]byte("explicit SOURCE current process identity"))}
	history := []state.PhysicalOperation{}
	originals := map[string]state.NativeSettlementOriginals{}
	for index := 1; index <= q.Reservation.LastPhysicalIndex; index++ {
		var a DemandAllocation
		for _, candidate := range control.Generation.Demand.Payload.AllocationList {
			if candidate.FirstPhysicalIndex <= index && index <= candidate.LastPhysicalIndex {
				a = candidate
			}
		}
		if a.AllocationID == "" {
			t.Fatal("signed allocation prefix absent", index)
		}
		request := model.PhysicalAdmitRequest{Consumer: "product", PreparationID: fmt.Sprintf("source_prior_preparation_%d", a.PreparationOrdinal), RequestIndex: index - a.FirstPhysicalIndex + 1, OuterPhysicalIndex: index, AuthorityDigest: Digest([]byte("SOURCE prior authority")), RequestDigest: Digest([]byte("SOURCE prior request"))}
		if a.AccessRequests == 1 {
			request.Consumer = "access"
			request.PreparationID = fmt.Sprintf("source_prior_access_%d", index)
		}
		permit := state.PhysicalPermit{Case: c, Caller: caller, Request: request, AllocationID: a.AllocationID, PreparationOrdinal: a.PreparationOrdinal}
		settlement := model.PhysicalSettlement{RequestDigest: request.RequestDigest, ResponseDigest: Digest([]byte("SOURCE prior response")), ResponseByteCount: 1, HTTPStatus: 200, UsageUsdMicros: 1, EvidenceDigest: Digest([]byte("SOURCE prior completion"))}
		id := fmt.Sprintf("source_financial_%d", index)
		if a.AllocationID == q.Reservation.AllocationID {
			var requestOriginal struct {
				Admission model.PhysicalAdmitRequest `json:"admission"`
				Request   []byte                     `json:"request"`
				Transport json.RawMessage            `json:"transport"`
			}
			var responseOriginal struct {
				Response          []byte `json:"response"`
				Status            int    `json:"status"`
				Cost              int64  `json:"cost"`
				ProviderRequestID string `json:"providerRequestId"`
			}
			for name, target := range map[string]any{fmt.Sprintf("source-financial-request-%d.json", request.RequestIndex): &requestOriginal, fmt.Sprintf("source-financial-response-%d.json", request.RequestIndex): &responseOriginal} {
				raw, e := os.ReadFile(filepath.Join(root, name))
				if e != nil || json.Unmarshal(raw, target) != nil {
					t.Fatal("actual local HTTP original missing", name, e)
				}
			}
			permit.Request = requestOriginal.Admission
			permit.Request.RequestDigest = Digest(requestOriginal.Request)
			sid, input := capture.Native.SessionID, capture.Native.InputID
			permit.Provider = &state.ProviderAdmission{NativeSessionID: &sid, NativeInputID: &input, Reservation: json.RawMessage(`{}`)}
			// Completion metadata is explicitly SOURCE; raw request/response are the
			// original real loopback bytes from this SAME selected child execution.
			completion := canonicalBytes(map[string]any{"classification": "SOURCE completion metadata", "requestDigest": Digest(requestOriginal.Request), "responseDigest": Digest(responseOriginal.Response)})
			settlement = model.PhysicalSettlement{RequestDigest: Digest(requestOriginal.Request), ResponseDigest: Digest(responseOriginal.Response), ResponseByteCount: len(responseOriginal.Response), HTTPStatus: responseOriginal.Status, UsageUsdMicros: responseOriginal.Cost, EvidenceDigest: Digest(completion)}
			originals[id] = state.NativeSettlementOriginals{Journal: canonicalBytes(permit.Request), Request: requestOriginal.Request, Response: responseOriginal.Response, Completion: completion, Transport: requestOriginal.Transport, ProviderResponse: canonicalBytes(map[string]any{"formatVersion": 1, "providerRequestId": responseOriginal.ProviderRequestID}), ProviderRequestID: responseOriginal.ProviderRequestID}
		}
		history = append(history, state.PhysicalOperation{OperationID: id, Permit: permit, Phase: "settled", ReservedUsdMicros: 421000, Settlement: &settlement})
	}
	if err = s.AdoptPhysicalLedger(ctx, c, history); err != nil {
		t.Fatal("SOURCE SQLite prefix admission", err)
	}
	_, role, digests, nativeErr := (ChildWorkflowNativeCapture{Integration: &capture}).completion(w.Entry, control)
	if nativeErr != nil || role != "worker" {
		t.Fatal("distinct integrator native completion", nativeErr)
	}
	if _, err = childFinancialCompletion(ctx, s, w, control, caller, digests); err == nil {
		t.Fatal("settlement accepted without retained exact provider originals")
	}
	for _, o := range history {
		if original, ok := originals[o.OperationID]; ok {
			if err = s.RetainNativeSettlementOriginals(ctx, o.OperationID, caller, *o.Settlement, original); err != nil {
				t.Fatal("exact SOURCE originals retention", err)
			}
		}
	}
	if _, err = childFinancialCompletion(ctx, s, w, control, caller, digests); err != nil {
		t.Fatal("exact child paid-original completion refused", err)
	}
	if _, err = childFinancialCompletion(ctx, s, w, control, caller, []string{digests[0], Digest([]byte("different original"))}); err == nil {
		t.Fatal("wrong native original response accepted")
	}
	next := q.Reservation.LastPhysicalIndex + 1
	permit := state.PhysicalPermit{Case: c, Caller: caller, Request: model.PhysicalAdmitRequest{Consumer: "product", PreparationID: "source_following_preparation", RequestIndex: 1, OuterPhysicalIndex: next, AuthorityDigest: Digest([]byte("SOURCE following authority")), RequestDigest: Digest([]byte("SOURCE following request"))}, AllocationID: "source_following_allocation", PreparationOrdinal: q.Reservation.PreparationOrdinal + 1}
	if err = s.AdmitPhysical(ctx, "source_pending_owner", permit); err != nil {
		t.Fatal("SOURCE pending owner", err)
	}
	if _, err = childFinancialCompletion(ctx, s, w, control, caller, digests); err == nil {
		t.Fatal("completion ignored current UNKNOWN physical owner")
	}
	t.Log("SOURCE same child paid SQLite + exact local HTTP originals; absent originals/changed response/UNKNOWN owner denied; no protected signature")
}
