package physicalgate

import (
	"context"
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"os"
	"reflect"
	"sync"
	"time"
)

// Separate Runtime-owned access enrollment, never a native model permission.
// Only a trusted owning callback enrolls; the RPC has NO enroll action/identity.
type AccessEnrollment struct {
	Caller           Caller
	Process          ProcessIdentity
	Context          model.QualificationAccessContext
	Case             state.PhysicalCase
	AllocationID     string
	CapabilityDigest string
	Connection       model.CellCredentialBindingV3
	AuthorizedUntil  time.Time
}
type AccessRegistry struct {
	Store    *state.Store
	mu       sync.Mutex
	active   *Caller
	dispatch sync.Mutex
}

func (a *AccessRegistry) Enroll(ctx context.Context, c Caller, current model.QualificationAccessContext, case_ state.PhysicalCase, allocation, capability string, connection model.CellCredentialBindingV3, authorizedUntil time.Time) error {
	if a == nil || a.Store == nil || current.Validate(current.QualificationID, time.Now()) != nil || !time.Now().Before(authorizedUntil) || !model.PhysicalDigestValid(capability) || !model.PhysicalIDValid(allocation) {
		return ErrPrerequisite
	}
	p, err := observeOwnAccessProcess()
	if err != nil {
		return err
	}
	c.NativeInstance = "runtime-access"
	c.NativeIdentityDigest = model.WorkspaceDigest(p)
	if !model.PhysicalIDValid(connection.ConnectionID) || connection.ConnectionRevision < 1 || connection.ProviderID != accessProvider(current) || connection.AuthMode != "api_key" || (current.FormatVersion == 2) != (case_.AccountingVersion == 2) || (current.FormatVersion == 2 && case_.ProviderPolicyDigest != current.ProviderPolicyDigest) {
		return ErrPrerequisite
	}
	e := AccessEnrollment{Caller: c, Process: p, Context: current, Case: case_, AllocationID: allocation, CapabilityDigest: capability, Connection: connection, AuthorizedUntil: authorizedUntil}
	raw, _ := json.Marshal(e)
	if err = a.Store.RetainPhysicalFact(ctx, "access_"+current.PreparationID, raw); err != nil {
		return err
	}
	a.mu.Lock()
	a.active = &c
	a.mu.Unlock()
	return nil
}
func (a *AccessRegistry) Enrollment(ctx context.Context, preparationID string) (AccessEnrollment, error) {
	var e AccessEnrollment
	if a == nil || a.Store == nil {
		return e, ErrPrerequisite
	}
	raw, err := a.Store.PhysicalFact(ctx, "access_"+preparationID)
	if err != nil || model.DecodePhysicalClosed(raw, &e) != nil {
		return e, ErrPrerequisite
	}
	return e, nil
}
func (a *AccessRegistry) Authenticate(ctx context.Context, p Peer) (Caller, error) {
	actual, err := observeOwnAccessProcess()
	if err != nil || p.PID != os.Getpid() || p.UID != actual.UID || p.GID != actual.GID {
		return Caller{}, ErrPrerequisite
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active == nil {
		return Caller{}, ErrPrerequisite
	}
	entries, err := a.Store.PhysicalAccessEnrollments(ctx)
	if err != nil {
		return Caller{}, err
	}
	for _, raw := range entries {
		var e AccessEnrollment
		if model.DecodePhysicalClosed(raw, &e) != nil {
			return Caller{}, ErrPrerequisite
		}
		if e.Caller == *a.active && reflect.DeepEqual(actual, e.Process) {
			return e.Caller, nil
		}
	}
	return Caller{}, ErrPrerequisite
}
func (a *AccessRegistry) Permit(ctx context.Context, c Caller, r model.PhysicalAdmitRequest) (state.PhysicalPermit, error) {
	e, err := a.Enrollment(ctx, r.PreparationID)
	if err != nil || e.Caller != c || r.Consumer != "access" || r.RequestIndex != 1 || r.InnerPhysicalIndex != nil || r.AuthorityDigest != e.Context.AuthorityDigest || !time.Now().Before(e.AuthorizedUntil) || e.Context.Validate(e.Context.QualificationID, time.Now()) != nil {
		return state.PhysicalPermit{}, ErrPrerequisite
	}
	var allocation struct{ FirstPhysicalIndex, LastPhysicalIndex, PreparationOrdinal, AccessRequests, ModelRequests int }
	if json.Unmarshal(e.Context.Allocation, &allocation) != nil || allocation.FirstPhysicalIndex != r.OuterPhysicalIndex || allocation.LastPhysicalIndex != r.OuterPhysicalIndex || allocation.PreparationOrdinal != 0 || allocation.AccessRequests != 1 || allocation.ModelRequests != 0 {
		return state.PhysicalPermit{}, ErrPrerequisite
	}
	return state.PhysicalPermit{Case: e.Case, Caller: c.Subject(), Request: r, PreparationOrdinal: 0, AllocationID: e.AllocationID}, nil
}
