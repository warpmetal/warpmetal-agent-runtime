package containers

import (
	"context"
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"time"
)

func (p Podman) EnrollPhysicalAccess(ctx context.Context, current model.Manifest, entry model.CellServiceV3, access model.QualificationAccessContext, capability []byte) error {
	if p.PhysicalAccess == nil || p.PhysicalStore == nil || entry.PreparationID != access.PreparationID || entry.DesiredState != "active" || entry.LifecyclePhase != "prepare" || p.verifyQualificationMounts(ctx, entry.SandboxID) != nil {
		return physicalgate.ErrPrerequisite
	}
	b, err := p.PhysicalBaseline(ctx, current)
	if err != nil {
		return err
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil || producer.VerifyPhysicalAccessAuthority(ctx, access, b) != nil {
		return physicalgate.ErrPrerequisite
	}
	local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Receipt.ValidateFor(entry) != nil {
		return physicalgate.ErrPrerequisite
	}
	tupleDigest, err := local.Receipt.PreparedTuple.Digest()
	if err != nil || tupleDigest != access.PreparedTupleDigest {
		return physicalgate.ErrPrerequisite
	}
	s, err := p.qualificationStore(ctx)
	if err != nil {
		return err
	}
	box := model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, Cell: true}
	if len(b.SourceContinuation) != 0 {
		if err = p.enrollSourceContinuation(ctx, s, box, b.Case, b.SourceContinuation); err != nil {
			return err
		}
	}
	_, policy, _, err := s.SelectedPolicy(box, entry, local.WorktreeDir, time.Now())
	if err != nil || policy.Run == nil || policy.Run.QualificationID != access.QualificationID || policy.Run.ReservationID != access.ReservationID {
		return physicalgate.ErrPrerequisite
	}
	allocation, err := s.ApprovedPhysicalAccess(box, b.Case, access, policy.Run.Tuple, capability, time.Now())
	if err != nil {
		return err
	}
	// Bound by the ORIGINAL already verified capability and selected policy, not
	// merely the independently scoped GET's later qualification expiry.
	var original struct {
		Payload struct {
			NotAfter string `json:"notAfter"`
		} `json:"payload"`
	}
	if json.Unmarshal(capability, &original) != nil {
		return physicalgate.ErrPrerequisite
	}
	until, err := time.Parse(time.RFC3339Nano, original.Payload.NotAfter)
	if err != nil {
		return physicalgate.ErrPrerequisite
	}
	policyExpiry, err := time.Parse(time.RFC3339Nano, policy.ExpiresAt)
	if err != nil {
		return physicalgate.ErrPrerequisite
	}
	if policyExpiry.Before(until) {
		until = policyExpiry
	}
	return p.PhysicalAccess.Enroll(ctx, physicalgate.Caller{SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration}, access, b.StoreCase(current.ServerID), allocation.AllocationID, qualification.Digest(capability), policy.Run.Tuple.Connection, until)
}
func (p Podman) AuthorizeAccessPhysicalRequest(ctx context.Context, c physicalgate.Caller, r model.PhysicalAdmitRequest, current model.Manifest, observed model.QualificationAccessContext) (state.PhysicalPermit, error) {
	var empty state.PhysicalPermit
	if p.PhysicalAccess == nil {
		return empty, physicalgate.ErrPrerequisite
	}
	enrollment, err := p.PhysicalAccess.Enrollment(ctx, r.PreparationID)
	if err != nil || model.WorkspaceDigest(enrollment.Context) != model.WorkspaceDigest(observed) {
		return empty, physicalgate.ErrPrerequisite
	}
	found := false
	for _, entry := range current.CellEntriesV3 {
		if entry.PreparationID == r.PreparationID && entry.SandboxID == c.SandboxID && entry.SandboxGeneration == c.SandboxGeneration && entry.DesiredState == "active" && entry.LifecyclePhase == "prepare" {
			local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
			if err != nil || local == nil || local.Receipt.ValidateFor(entry) != nil || entry.CredentialBinding != enrollment.Connection || p.verifyQualificationMounts(ctx, entry.SandboxID) != nil {
				return empty, physicalgate.ErrPrerequisite
			}
			found = true
		}
	}
	if !found {
		return empty, physicalgate.ErrPrerequisite
	}
	b, err := p.PhysicalBaseline(ctx, current)
	if err != nil || b.StoreCase(current.ServerID) != enrollment.Case {
		return empty, physicalgate.ErrPrerequisite
	}
	permit, err := p.PhysicalAccess.Permit(ctx, c, r)
	if err != nil {
		return empty, err
	}
	permit.PaidDomain = b.PaidDomainDigest()
	return permit, nil
}

func (p Podman) RunQualificationPhysicalAccess(ctx context.Context, preparationID, key string, connection model.CellCredentialBindingV3) (physicalgate.AccessProbeResult, error) {
	if p.PhysicalAccess == nil {
		return physicalgate.AccessProbeResult{}, physicalgate.ErrPrerequisite
	}
	return p.PhysicalAccess.RunProbe(ctx, preparationID, key, connection)
}
func (p Podman) PhysicalAccessQualification(ctx context.Context, preparationID string) (string, error) {
	if p.PhysicalAccess == nil {
		return "", physicalgate.ErrPrerequisite
	}
	e, err := p.PhysicalAccess.Enrollment(ctx, preparationID)
	return e.Context.QualificationID, err
}
