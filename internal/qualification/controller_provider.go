package qualification

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Version-selected accessors preserve the signed A and N bodies. Legacy policy
// identity remains unchanged; no consumer silently normalizes a signed payload.
func (p ControllerPolicy) ApplicationIdentity() model.ControllerIdentity {
	if p.FormatVersion == 6 && p.IdentityAssociation != nil {
		return p.IdentityAssociation.ApplicationIdentity
	}
	return p.Identity
}
func (p ControllerPolicy) NativeIdentity() model.ControllerIdentity {
	if p.FormatVersion == 6 && p.IdentityAssociation != nil {
		return p.IdentityAssociation.NativeIdentity
	}
	return p.Identity
}

func (p ControllerPolicy) ApplicationReference() ControllerApplication {
	if p.FormatVersion == 6 && p.IdentityAssociation != nil {
		a := p.IdentityAssociation.Application
		return ControllerApplication{OperationID: a.OperationID, OperationDigest: a.OperationDigest, ApplicationID: a.ApplicationID, ReceiptDigest: a.ReceiptDigest}
	}
	return p.Application
}

// Call only after the protected policy/current application selection. Native
// model authority and normalized identity are checked together, never inferred
// from receipt provider fields or a transport response.
func (p ControllerPolicy) ValidatePreparedReceipt(r model.ControllerPreparedReceipt) error {
	if p.validatePrepared(r) != nil || r.PreparedTuple.ValidateControllerPolicyIdentity(p.NativeIdentity()) != nil {
		return ErrUntrusted
	}
	return nil
}

func (p ControllerPolicy) MarshalJSON() ([]byte, error) {
	type wire ControllerPolicy
	raw, err := json.Marshal(wire(p))
	if err != nil || p.FormatVersion != 6 {
		return raw, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	delete(fields, "identity")
	delete(fields, "application")
	return json.Marshal(fields)
}
func (p *ControllerPolicy) UnmarshalJSON(raw []byte) error {
	type wire ControllerPolicy
	var value wire
	if err := decode(raw, &value); err != nil {
		return err
	}
	if value.FormatVersion == 6 && workflowcontract.Validate(workflowcontract.ControllerProvider, "controllerPolicy6", raw) != nil {
		return ErrUntrusted
	}
	*p = ControllerPolicy(value)
	return nil
}

func (p ControllerPolicy) validateProvider(w ControllerPolicyWitness, now time.Time) error {
	raw, err := json.Marshal(p)
	if err != nil || workflowcontract.Validate(workflowcontract.ControllerProvider, "controllerPolicy6", raw) != nil ||
		p.IdentityAssociation == nil || p.IdentityAssociation.ValidateIntegrity() != nil || p.Case.FormatVersion != 3 || !p.Case.typed() ||
		w.demand == nil || w.demand.validate(p.Case, now) != nil || !reflect.DeepEqual(p.Applicability, w.Applicability) {
		return ErrUntrusted
	}
	a, i, t := p.IdentityAssociation, p.ApplicationIdentity(), p.Applicability
	if !reflect.DeepEqual(i, w.Identity) || a.Application != (model.ControllerApplicationReference{OperationID: w.Application.OperationID, OperationDigest: w.Application.OperationDigest, ApplicationID: w.Application.ApplicationID, ReceiptDigest: w.Application.ReceiptDigest}) ||
		!hash.MatchString(w.ApplicationConfigurationDigest) || !hash.MatchString(w.WorkspaceMaterializerDigest) || a.Materializer.DeclaredDigest != a.Materializer.InstalledDigest || a.Materializer.InstalledDigest != w.WorkspaceMaterializerDigest {
		return ErrUntrusted
	}
	descriptor := providerpolicy.Flash()
	if i.Projection.ModelSelection == nil || i.Projection.ModelSelection.CredentialBinding == nil ||
		i.Projection.ModelSelection.Authority != (model.CellPreparedAuthorityV3{ProviderID: descriptor.ProviderID, ModelID: descriptor.ModelID, AuthMode: descriptor.AuthMode}) ||
		t.Connection != *i.Projection.ModelSelection.CredentialBinding || t.Model.ProviderID != descriptor.ProviderID || t.Model.ModelID != descriptor.ModelID || t.Model.AuthMode != descriptor.AuthMode || t.Model.Endpoint != descriptor.Transport.URL ||
		t.AccountID != i.Intent.Owner.AccountID || t.TaskID != i.Intent.Owner.TaskID || t.ServerID != i.Intent.Owner.ServerID || t.SandboxID != i.Intent.Owner.SandboxID || t.SandboxGeneration != i.Intent.Owner.SandboxGeneration ||
		t.CaseManifestDigest != p.Case.CaseManifestDigest || t.Profile.SetupOperationID != i.Intent.Profile.SetupOperationID || t.Profile.ProfileID != i.Intent.Profile.ProfileID || t.Profile.Revision != i.Intent.Profile.ProfileRevision || t.Profile.ProfileDigest != i.Intent.Profile.ProfileDigest || t.Profile.BundleDigest != i.Projection.ApprovedProfile.BundleDigest || t.Model.AdapterVersion == "team-adapter-1" {
		return ErrUntrusted
	}
	allocation, err := w.demand.allocation(p.AllocationID)
	if err != nil || allocation.Kind != "parent" || allocation.SourceID != i.Intent.ServiceRegistrationID || allocation.Scope != i.Intent.Owner || allocation.ScopeDigest != CanonicalDigest(i.Intent.Owner) || allocation.TupleDigest != CanonicalDigest(t) || allocation.FirstPhysicalIndex != allocation.LastPhysicalIndex || allocation.ModelRequests != 1 {
		return ErrUntrusted
	}
	expires, ee := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	until, ue := time.Parse(time.RFC3339Nano, w.demand.NotAfter)
	if ee != nil || ue != nil || !now.Before(expires) || expires.After(until) {
		return ErrUntrusted
	}
	return nil
}

func (p ControllerPolicy) validatePrepared(r model.ControllerPreparedReceipt) error {
	if p.FormatVersion == 6 {
		return r.ValidateProvider(p.ProviderPolicyDigest)
	}
	return r.Validate()
}

func (a ControllerActivation) validateProvider(p ControllerPolicy, now time.Time) error {
	raw, err := json.Marshal(a)
	if err != nil || p.FormatVersion != 6 || p.IdentityAssociation == nil || workflowcontract.Validate(workflowcontract.ControllerProvider, "controllerActivation4", raw) != nil ||
		a.PolicyDigest != CanonicalDigest(p) || a.IdentityAssociationDigest != p.IdentityAssociation.AssociationDigest || a.ProviderPolicyDigest != p.ProviderPolicyDigest || a.AccountingVersion != p.AccountingVersion ||
		a.AllocationID != p.AllocationID || a.DemandManifestDigest != p.Case.DemandManifestDigest || a.PreparationIndex > p.Case.Preparations {
		return ErrUntrusted
	}
	r, g := a.Admission.PreparedReceipt, a.Admission.Grant
	if p.validatePrepared(r) != nil || r.PreparedTuple.ValidateControllerPolicyIdentity(p.NativeIdentity()) != nil ||
		g.PreparationID != r.PreparationID || g.PreparedReceiptDigest != r.PreparedReceiptDigest || g.PolicyDigest != a.PolicyDigest || g.CaseID != p.Case.CaseID || g.CaseManifestDigest != p.Case.CaseManifestDigest ||
		g.RequestIndex < 1 || g.RequestIndex > p.Case.ModelRequests || g.PhysicalIndex < 1 || g.PhysicalIndex > p.Case.Requests {
		return ErrUntrusted
	}
	d := providerpolicy.Flash()
	if g.MaxInputTokens < 1 || g.MaxInputTokens > d.Request.InputTokenUpperBound || g.MaxOutputTokens < 1 || g.MaxOutputTokens > d.Request.MaxOutputTokens ||
		g.MaxInputTokens+g.MaxOutputTokens > d.Request.InputTokenUpperBound+d.Request.MaxOutputTokens || g.MaxUSDMicros < 1 || g.MaxUSDMicros > d.Accounting.RequestReserveMicros {
		return ErrUntrusted
	}
	cost := (int64(g.MaxInputTokens)*d.Accounting.InputMicrosPerMillion + int64(g.MaxOutputTokens)*d.Accounting.OutputMicrosPerMillion + 999999) / 1000000
	issued, ie := time.Parse(time.RFC3339Nano, a.IssuedAt)
	deadline, de := time.Parse(time.RFC3339Nano, g.DeadlineAt)
	expiry, ee := time.Parse(time.RFC3339Nano, g.ExpiresAt)
	until, pe := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if cost > g.MaxUSDMicros || ie != nil || de != nil || ee != nil || pe != nil || issued.After(now) || !now.Before(deadline) || !now.Before(expiry) || !issued.Before(deadline) || deadline.After(expiry) || expiry.After(until) || deadline.Sub(issued) > time.Duration(d.Request.DeadlineSeconds)*time.Second {
		return ErrUntrusted
	}
	return nil
}
