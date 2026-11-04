package reconcile

import (
	"context"
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type physicalAdmissionRuntime interface {
	PhysicalBaseline(context.Context, model.Manifest) (qualification.PhysicalBaseline, error)
	AuthorizeCellPhysicalRequest(context.Context, physicalgate.Caller, model.PhysicalAdmitRequest, model.Manifest, model.CellServiceV3, []byte) (state.PhysicalPermit, error)
	VerifyPhysicalNativeDigest(context.Context, physicalgate.Caller, string) error
}

type physicalAccessProbeRuntime interface {
	RunQualificationPhysicalAccess(context.Context, string, string, model.CellCredentialBindingV3) (physicalgate.AccessProbeResult, error)
}
type physicalAccessCredentialControl interface {
	CellCredential(context.Context, string) (api.CellCredentialResult, error)
}

// The owning continuation may call this once AFTER its whole supplier preflight.
// This method does not enroll a model peer, issue qualification, sign/refresh an
// envelope or replace F1's original attester. Normal current credentials stay only
// in Runtime's protected process/journal; the returned evidence has no credential.
func (r *Reconciler) RunQualificationPhysicalAccess(ctx context.Context, id string, capability []byte) (physicalgate.AccessProbeResult, error) {
	return r.runQualificationPhysicalAccess(ctx, id, capability, nil)
}

func (r *Reconciler) runQualificationPhysicalAccess(ctx context.Context, id string, capability, liveReceipt []byte) (physicalgate.AccessProbeResult, error) {
	var empty physicalgate.AccessProbeResult
	if err := r.EnrollQualificationPhysicalAccess(ctx, id, capability); err != nil {
		return empty, err
	}
	control, ok := r.ManagedControl.(physicalAccessControl)
	credentials, cok := r.ManagedControl.(physicalAccessCredentialControl)
	runtime, rok := r.ManagedRuntime.(physicalAccessProbeRuntime)
	if !ok || !cok || !rok {
		return empty, physicalgate.ErrPrerequisite
	}
	access, err := control.QualificationAccessContext(ctx, id)
	if err != nil {
		return empty, err
	}
	current := r.currentAuthorityManifest()
	if access.FormatVersion == 2 {
		owner, ok := r.ManagedRuntime.(interface {
			VerifyProviderAccessOpening(context.Context, model.Manifest, model.QualificationAccessContext, []byte) error
		})
		if !ok || len(liveReceipt) != 0 {
			return empty, physicalgate.ErrPrerequisite
		}
		if err = owner.VerifyProviderAccessOpening(ctx, current, access, capability); err != nil {
			return empty, err
		}
	} else {
		owner, ok := r.ManagedRuntime.(interface {
			AcceptValidationLiveReceipt(context.Context, model.Manifest, model.QualificationAccessContext, []byte, []byte) error
		})
		if !ok {
			return empty, physicalgate.ErrPrerequisite
		}
		if err = owner.AcceptValidationLiveReceipt(ctx, current, access, capability, liveReceipt); err != nil {
			return empty, err
		}
	}
	for _, entry := range current.CellEntriesV3 {
		if entry.PreparationID == access.PreparationID && entry.LifecyclePhase == "prepare" && entry.DesiredState == "active" {
			lease, err := credentials.CellCredential(ctx, entry.ServiceRegistrationID)
			if err != nil || lease.APIKey == "" || lease.ConnectionID != entry.CredentialBinding.ConnectionID || lease.ConnectionRevision != entry.CredentialBinding.ConnectionRevision || r.currentAuthorityManifest().DesiredRevision != current.DesiredRevision {
				return empty, physicalgate.ErrPrerequisite
			}
			return runtime.RunQualificationPhysicalAccess(ctx, entry.PreparationID, lease.APIKey, entry.CredentialBinding)
		}
	}
	return empty, physicalgate.ErrPrerequisite
}

type physicalAccessControl interface {
	QualificationAccessContext(context.Context, string) (model.QualificationAccessContext, error)
}
type physicalAccessRuntime interface {
	EnrollPhysicalAccess(context.Context, model.Manifest, model.CellServiceV3, model.QualificationAccessContext, []byte) error
	PhysicalAccessQualification(context.Context, string) (string, error)
	AuthorizeAccessPhysicalRequest(context.Context, physicalgate.Caller, model.PhysicalAdmitRequest, model.Manifest, model.QualificationAccessContext) (state.PhysicalPermit, error)
}

// Direct owning entry, NOT an RPC enroll operation or a node/context readiness
// assertion. Independently current exact allocation and installed/key/capability
// checks precede registration. No request/reservation/signature is created here.
func (r *Reconciler) EnrollQualificationPhysicalAccess(ctx context.Context, id string, capability []byte) error {
	control, ok := r.ManagedControl.(physicalAccessControl)
	runtime, rok := r.ManagedRuntime.(physicalAccessRuntime)
	if !ok || !rok {
		return physicalgate.ErrPrerequisite
	}
	access, err := control.QualificationAccessContext(ctx, id)
	if err != nil {
		return err
	}
	current := r.currentAuthorityManifest()
	for _, entry := range current.CellEntriesV3 {
		if entry.PreparationID == access.PreparationID {
			// Authority3 uses its independently observed same-ledger opening; the
			// historical paid-domain issuer remains mandatory only for older authority.
			if access.FormatVersion != 2 {
				if err := r.ensurePaidCaseDomain(ctx, current); err != nil {
					return err
				}
			}
			return runtime.EnrollPhysicalAccess(ctx, current, entry, access, capability)
		}
	}
	return physicalgate.ErrPrerequisite
}

// This narrow daemon callback reads current authority without the heavy-pass
// mutex: the actual native HTTP hook can run while a synchronous prompt POST is
// awaiting its response. It never re-enters Supervisor's held instance lock.
func (r *Reconciler) AuthorizePhysicalRequest(ctx context.Context, c physicalgate.Caller, call model.PhysicalAdmitRequest) (state.PhysicalPermit, error) {
	permit, err := r.resolvePhysicalRequest(ctx, c, call)
	if err != nil || permit.Offline != nil {
		return permit, err
	}
	if permit.Case.AccountingVersion == 2 {
		return r.bindProviderPhysicalRequest(ctx, permit)
	}
	// Private mandatory PAID boundary shared by access, qualification, parent and
	// product. No claim/helper/transport; missing FIRST receipt denies admission.
	owner, ok := r.ManagedRuntime.(interface {
		VerifyValidationLivePhysicalRequest(context.Context, model.Manifest, physicalgate.Caller, model.PhysicalAdmitRequest, state.PhysicalPermit) error
	})
	if !ok || owner.VerifyValidationLivePhysicalRequest(ctx, r.currentAuthorityManifest(), c, call, permit) != nil {
		return state.PhysicalPermit{}, physicalgate.ErrPrerequisite
	}
	return permit, nil
}

func (r *Reconciler) resolvePhysicalRequest(ctx context.Context, c physicalgate.Caller, call model.PhysicalAdmitRequest) (state.PhysicalPermit, error) {
	var empty state.PhysicalPermit
	runtime, ok := r.ManagedRuntime.(physicalAdmissionRuntime)
	if !ok || r.Store == nil {
		return empty, physicalgate.ErrPrerequisite
	}
	current := r.currentAuthorityManifest()
	if call.Consumer == "access" {
		owner, ok := r.ManagedRuntime.(physicalAccessRuntime)
		control, cok := r.ManagedControl.(physicalAccessControl)
		if !ok || !cok {
			return empty, physicalgate.ErrPrerequisite
		}
		id, err := owner.PhysicalAccessQualification(ctx, call.PreparationID)
		if err != nil {
			return empty, err
		}
		access, err := control.QualificationAccessContext(ctx, id)
		if err != nil {
			return empty, err
		}
		permit, err := owner.AuthorizeAccessPhysicalRequest(ctx, c, call, current, access)
		if err == nil && permit.Case.AccountingVersion == 2 {
			permit.Provider = &state.ProviderAdmission{}
		}
		return permit, err
	}
	if call.Consumer == "product" || call.Consumer == "qualification" {
		for _, entry := range current.CellEntriesV3 {
			if entry.PreparationID == call.PreparationID {
				if owner, ok := r.ManagedRuntime.(sourceTransportRuntime); ok {
					target, err := childSourceTransportTarget(entry, current)
					if err != nil {
						return empty, err
					}
					selected, err := owner.SourceTransportSelected(ctx, target)
					if err != nil {
						return empty, err
					}
					if selected {
						return empty, ErrSourceLocalGrantPending
					}
				}
				local, err := r.Store.CellV3Operation(ctx, entry.PreparationID)
				if err != nil || local == nil || entry.ValidateExecutionAuthority(local.Receipt) != nil {
					return empty, physicalgate.ErrPrerequisite
				}
				text, err := r.fetchCellFirstText(ctx, cellV2View(entry))
				if err != nil {
					return empty, err
				}
				permit, err := runtime.AuthorizeCellPhysicalRequest(ctx, c, call, current, entry, []byte(text))
				if err == nil && permit.Case.AccountingVersion == 2 {
					// Independently validated current entry/grant; never RPC-selected IDs.
					if entry.ExecutionGrant == nil {
						return empty, physicalgate.ErrPrerequisite
					}
					session, input := entry.ExecutionGrant.SessionID, entry.ExecutionGrant.InputID
					permit.Provider = &state.ProviderAdmission{NativeSessionID: &session, NativeInputID: &input}
				}
				return permit, err
			}
		}
	}
	if call.Consumer != "parent" {
		return empty, physicalgate.ErrPrerequisite
	}
	activityRaw, err := r.Store.ControllerActivityStage(ctx, call.PreparationID, state.ControllerApprovedContext)
	if err != nil {
		return empty, err
	}
	var activity controllerApprovedInput
	if json.Unmarshal(activityRaw, &activity) != nil {
		return empty, physicalgate.ErrPrerequisite
	}
	preparedRaw, err := r.Store.ControllerActivityStage(ctx, call.PreparationID, state.ControllerNativePrepared)
	if err != nil {
		return empty, err
	}
	var prepared model.ControllerPreparedEnvelope
	if json.Unmarshal(preparedRaw, &prepared) != nil {
		return empty, physicalgate.ErrPrerequisite
	}
	if owner, ok := r.ManagedRuntime.(sourceTransportRuntime); ok {
		tuple := prepared.Payload.PreparedTuple
		selected, err := owner.SourceTransportSelected(ctx, qualification.SourceTransportTarget{TargetKind: "controller_activity", TargetID: tuple.InputID, SourceID: tuple.ServiceRegistrationID})
		if err != nil {
			return empty, err
		}
		if selected {
			return empty, ErrSourceLocalGrantPending
		}
	}
	installedRaw, err := r.Store.ControllerActivityStage(ctx, call.PreparationID, state.ControllerInstalledApplicability)
	if err != nil {
		return empty, err
	}
	var installed qualification.Applicability
	if json.Unmarshal(installedRaw, &installed) != nil {
		return empty, physicalgate.ErrPrerequisite
	}
	w, err := r.controllerActivityCurrentWitness(ctx, prepared.Payload.PreparedTuple.ServiceRegistrationID, installed, false)
	if err != nil {
		return empty, err
	}
	parentRuntime, ok := r.ManagedRuntime.(controllerActivityRuntime)
	if !ok {
		return empty, physicalgate.ErrPrerequisite
	}
	policy, err := parentRuntime.VerifyControllerPolicy(ctx, w.Sandbox, activity.Context.PolicyDigest, w.Installed)
	if err != nil {
		return empty, err
	}
	a, err := parentRuntime.ReadControllerActivation(ctx, w.Sandbox, policy, prepared.Payload, false)
	if err != nil {
		return empty, err
	}
	if policy.ValidateContext(activity.Context) != nil || a.ValidateContext(policy, activity.Context) != nil || call.RequestIndex != a.Admission.Grant.RequestIndex || call.OuterPhysicalIndex != a.Admission.Grant.PhysicalIndex || call.AuthorityDigest != a.PolicyDigest || c.SandboxID != w.Sandbox.ID || c.SandboxGeneration != w.Sandbox.Generation || c.NativeInstance != w.Installed.Identity.Intent.Instance || runtime.VerifyPhysicalNativeDigest(ctx, c, policy.Applicability.Native.BinarySHA256) != nil {
		return empty, physicalgate.ErrPrerequisite
	}
	b, err := runtime.PhysicalBaseline(ctx, current)
	if err != nil || b.Case != policy.Case {
		return empty, physicalgate.ErrPrerequisite
	}
	allocation := policy.AllocationID
	if allocation == "" {
		allocation = a.Admission.Grant.ReservationID
	}
	permit := state.PhysicalPermit{Case: b.StoreCase(current.ServerID), PaidDomain: b.PaidDomainDigest(), Caller: c.Subject(), Request: call, PreparationOrdinal: a.PreparationIndex, AllocationID: allocation}
	if permit.Case.AccountingVersion == 2 {
		session, input := prepared.Payload.PreparedTuple.NativeRegistration.NativeSessionID, prepared.Payload.PreparedTuple.InputID
		permit.Provider = &state.ProviderAdmission{NativeSessionID: &session, NativeInputID: &input}
	}
	return permit, nil
}
