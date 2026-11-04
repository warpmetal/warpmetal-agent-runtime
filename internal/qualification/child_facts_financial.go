package qualification

import (
	"context"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Read the owning coherent paid cut and its retained HTTP originals. A native
// terminal, detached local hook ledger, or backend amount cannot fill this gap.
// Caller identity is independently resolved by the protected container adapter.
func childFinancialCompletion(ctx context.Context, store *state.Store, w ChildProductWitness, control ChildProductControl, caller state.PhysicalSubject, responses []string) (state.PaidLedgerCut, error) {
	var empty state.PaidLedgerCut
	if store == nil || control.Generation.Policy == nil || control.Generation.Activation == nil {
		return empty, ErrUntrusted
	}
	q := control.Generation.Policy.Payload
	if !childCompletionPolicy(q) || q.AccountingVersion != 2 || q.ProviderPolicyDigest != providerpolicy.FlashDigest || len(responses) != len(q.Workload.Requests) || len(responses) < 1 || len(responses) > 2 || len(responses) != q.Reservation.ModelRequests || w.Entry.ExecutionGrant == nil || caller.SandboxID != w.Entry.SandboxID || caller.SandboxGeneration != w.Entry.SandboxGeneration || caller.NativeInstance != w.Entry.Instance || !model.PhysicalDigestValid(caller.NativeIdentityDigest) {
		return empty, ErrUntrusted
	}
	cut, err := store.PhysicalLedgerCut(ctx)
	if err != nil || cut.Owner != nil || cut.Anchor.TaskID != w.Applicability.TaskID || cut.Anchor.ServerID != w.Applicability.ServerID {
		return empty, ErrUntrusted
	}
	found := make([]bool, len(responses))
	for _, ref := range cut.PaidHistory {
		var o state.PhysicalOperation
		raw := cut.Originals[ref.OperationDigest]
		if Digest(raw) != ref.OperationDigest || model.DecodePhysicalClosed(raw, &o) != nil || o.OperationID != ref.OperationID {
			return empty, ErrUntrusted
		}
		p := o.Permit
		if p.Request.PreparationID != w.Entry.PreparationID {
			continue
		}
		index := p.Request.RequestIndex - 1
		if index < 0 || index >= len(found) || found[index] || p.Request.Consumer != "product" || p.Request.InnerPhysicalIndex != nil || p.Caller != caller || p.Offline != nil || p.Request.AuthorityDigest != control.Descriptor.GenerationDigest || p.AllocationID != q.Reservation.AllocationID || p.PreparationOrdinal != q.Reservation.PreparationOrdinal || p.Request.OuterPhysicalIndex != q.Workload.Requests[index].PhysicalIndex || q.Workload.Requests[index].RequestIndex != index+1 || p.Request.OuterPhysicalIndex < q.Reservation.FirstPhysicalIndex || p.Request.OuterPhysicalIndex > q.Reservation.LastPhysicalIndex || p.Case.AccountingVersion != q.AccountingVersion || p.Case.ProviderPolicyDigest != q.ProviderPolicyDigest || p.Case.CaseDigest != q.Case.CaseManifestDigest || p.Case.TaskID != w.Applicability.TaskID || p.Case.ServerID != w.Applicability.ServerID || p.Provider == nil || p.Provider.NativeSessionID == nil || p.Provider.NativeInputID == nil || *p.Provider.NativeSessionID != w.Entry.NativeSessionID || *p.Provider.NativeInputID != q.Instructions.InputID || o.Phase != "settled" || o.Settlement == nil || o.Settlement.Validate() != nil || o.Settlement.RequestDigest != p.Request.RequestDigest || o.Settlement.ResponseDigest != responses[index] || o.Settlement.HTTPStatus != 200 {
			return empty, ErrUntrusted
		}
		original, completed, err := store.NativeProviderOriginals(ctx, o.OperationID, *o.Settlement)
		stamp, e := time.Parse(time.RFC3339Nano, completed)
		var transport struct {
			Method     string `json:"method"`
			URL        string `json:"url"`
			BodyDigest string `json:"bodyDigest"`
		}
		policy := providerpolicy.Flash()
		if err != nil || e != nil || stamp.After(time.Now()) || len(original.Request) == 0 || Digest(original.Request) != p.Request.RequestDigest || Digest(original.Response) != responses[index] || len(original.Response) != o.Settlement.ResponseByteCount || model.DecodePhysicalClosed(original.Transport, &transport) != nil || transport.Method != policy.Transport.Method || transport.URL != policy.Transport.URL || transport.BodyDigest != p.Request.RequestDigest {
			return empty, ErrUntrusted
		}
		found[index] = true
	}
	for _, yes := range found {
		if !yes {
			return empty, ErrUntrusted
		}
	}
	again, err := store.PhysicalLedgerCut(ctx)
	if err != nil || !reflect.DeepEqual(cut, again) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	return cut, nil
}
