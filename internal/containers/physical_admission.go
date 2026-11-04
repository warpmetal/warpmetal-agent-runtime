package containers

import (
	"context"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"time"
)

func (p Podman) VerifyPhysicalNativeDigest(ctx context.Context, c physicalgate.Caller, digest string) error {
	if p.PhysicalProcesses == nil {
		return physicalgate.ErrPrerequisite
	}
	return p.PhysicalProcesses.VerifyNativeDigest(ctx, c, digest)
}

func (p Podman) PublishQualificationPhysicalAllocation(ctx context.Context, entry model.CellServiceV3, current model.Manifest) error {
	if p.PhysicalProcesses == nil || entry.LifecyclePhase != "execute" {
		return nil
	}
	b, err := p.PhysicalBaseline(ctx, current)
	if err != nil {
		return err
	}
	local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local == nil {
		return physicalgate.ErrPrerequisite
	}
	s, err := p.qualificationStore(ctx)
	if err != nil {
		return err
	}
	if len(b.SourceContinuation) != 0 {
		if err = p.enrollSourceContinuation(ctx, s, model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, Cell: true}, b.Case, b.SourceContinuation); err != nil {
			return err
		}
	}
	return s.PublishQualificationPhysicalAllocation(model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, Cell: true}, entry, local.WorktreeDir, b.Case, time.Now())
}

func (p Podman) PhysicalBaseline(ctx context.Context, current model.Manifest) (qualification.PhysicalBaseline, error) {
	var empty qualification.PhysicalBaseline
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return empty, err
	}
	b, history, err := producer.CurrentPhysicalBaseline(ctx, current)
	if err != nil {
		return empty, err
	}
	if p.PhysicalStore == nil {
		return empty, physicalgate.ErrPrerequisite
	}
	if b.Case.FormatVersion == 3 || b.Case.FormatVersion == 5 {
		c, err := producer.ProviderPhysicalCase(ctx, current, p.PhysicalStore, b)
		if err != nil {
			return empty, err
		}
		b.ProviderCase = &c
		return b, nil
	}
	anchor, err := p.PhysicalStore.PhysicalAnchor(ctx)
	if err != nil {
		return empty, err
	}
	if anchor == nil {
		if err = p.PhysicalStore.AdoptPhysicalLedger(ctx, b.StoreCase(current.ServerID), history); err != nil {
			return empty, err
		}
	}
	if b.Case.FormatVersion == 2 && len(b.SourceContinuation) == 0 {
		d, err := producer.CurrentPaidCaseDomain(ctx, current, p.PhysicalStore, b)
		if err != nil {
			return empty, err
		}
		b.PaidDomain = &d
	} else if anchor != nil && *anchor != b.StoreCase(current.ServerID) {
		return empty, physicalgate.ErrPrerequisite
	}
	return b, nil
}
func (p Podman) AuthorizeCellPhysicalRequest(ctx context.Context, c physicalgate.Caller, request model.PhysicalAdmitRequest, current model.Manifest, entry model.CellServiceV3, input []byte) (state.PhysicalPermit, error) {
	var empty state.PhysicalPermit
	if p.PhysicalProcesses == nil || request.PreparationID != entry.PreparationID || entry.Instance != c.NativeInstance || entry.SandboxID != c.SandboxID || entry.SandboxGeneration != c.SandboxGeneration || entry.LifecyclePhase != "execute" || entry.DesiredState != "active" || p.verifyQualificationMounts(ctx, entry.SandboxID) != nil {
		return empty, physicalgate.ErrPrerequisite
	}
	b, err := p.PhysicalBaseline(ctx, current)
	if err != nil {
		return empty, err
	}
	box := model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, Cell: true}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return empty, err
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return empty, err
	}
	if request.Consumer == "product" {
		w, err := producer.CurrentChildProductWitness(ctx, entry, current, input)
		if err != nil {
			return empty, err
		}
		control, err := store.ReadChildProduct(box, entry.PreparationID, w, time.Now())
		if err != nil || control.Generation.Policy == nil || control.Generation.Activation == nil {
			return empty, physicalgate.ErrPrerequisite
		}
		q := control.Generation.Policy.Payload
		if q.Case != b.Case || request.AuthorityDigest != control.Descriptor.GenerationDigest || request.RequestIndex > len(q.Workload.Requests) || request.InnerPhysicalIndex != nil {
			return empty, physicalgate.ErrPrerequisite
		}
		r := q.Workload.Requests[request.RequestIndex-1]
		if r.PhysicalIndex != request.OuterPhysicalIndex || r.RequestIndex != request.RequestIndex || p.PhysicalProcesses.VerifyNativeDigest(ctx, c, q.Applicability.Native.BinarySHA256) != nil {
			return empty, physicalgate.ErrPrerequisite
		}
		return state.PhysicalPermit{Case: b.StoreCase(current.ServerID), PaidDomain: b.PaidDomainDigest(), Caller: c.Subject(), Request: request, PreparationOrdinal: q.Reservation.PreparationOrdinal, AllocationID: q.Reservation.AllocationID}, nil
	}
	if request.Consumer == "qualification" {
		local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
		if err != nil || local == nil {
			return empty, physicalgate.ErrPrerequisite
		}
		boot, policy, d, err := store.SelectedPolicy(box, entry, local.WorktreeDir, time.Now())
		if err != nil || policy.Run == nil || request.AuthorityDigest != d.PolicyDigest || request.InnerPhysicalIndex == nil || request.RequestIndex > policy.Run.Budget.Requests {
			return empty, physicalgate.ErrPrerequisite
		}
		selected, err := store.ReadQualificationActivation(box, boot, policy, d, time.Now())
		if err != nil {
			return empty, err
		}
		if p.PhysicalProcesses.VerifyNativeDigest(ctx, c, policy.Run.Tuple.Native.BinarySHA256) != nil {
			return empty, physicalgate.ErrPrerequisite
		}
		// Owning separately signed typed outer allocation; legacy inner policy and
		// indices remain unchanged. There is no automatic inner-to-global fallback.
		allocation, err := store.QualificationPhysicalAllocation(box, b.Case, policy.Run.TupleDigest, time.Now())
		if err != nil {
			return empty, err
		}
		inner := selected.Execution.DispatchStart + request.RequestIndex - 1
		if *request.InnerPhysicalIndex != inner || request.OuterPhysicalIndex != allocation.FirstPhysicalIndex+request.RequestIndex-1 || request.OuterPhysicalIndex > allocation.LastPhysicalIndex {
			return empty, physicalgate.ErrPrerequisite
		}
		return state.PhysicalPermit{Case: b.StoreCase(current.ServerID), PaidDomain: b.PaidDomainDigest(), Caller: c.Subject(), Request: request, PreparationOrdinal: allocation.PreparationOrdinal, AllocationID: allocation.AllocationID}, nil
	}
	return empty, physicalgate.ErrPrerequisite
}
