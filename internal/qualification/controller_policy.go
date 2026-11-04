package qualification

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Additive parent sidecars in the EXISTING operator store. No child bootstrap,
// request allocator, signing key or independent ledger is introduced here.
type ControllerApplication struct {
	OperationID     string `json:"operationId"`
	OperationDigest string `json:"operationDigest"`
	ApplicationID   string `json:"applicationId"`
	ReceiptDigest   string `json:"receiptDigest"`
}
type ControllerPolicy struct {
	IdentityAssociation  *model.ControllerIdentityAssociation `json:"identityAssociation,omitempty"`
	ProviderPolicyDigest string                               `json:"providerPolicyDigest,omitempty"`
	AccountingVersion    int                                  `json:"accountingVersion,omitempty"`
	FormatVersion        int                                  `json:"formatVersion"`
	TargetKind           string                               `json:"targetKind"`
	Mode                 string                               `json:"mode"`
	Purpose              string                               `json:"purpose"`
	Case                 RealCase                             `json:"case"`
	Applicability        Applicability                        `json:"applicability"`
	Identity             model.ControllerIdentity             `json:"identity"`
	Application          ControllerApplication                `json:"application"`
	ExpiresAt            string                               `json:"expiresAt"`
	AllocationID         string                               `json:"allocationId,omitempty"`
}
type ControllerActivation struct {
	IdentityAssociationDigest string                    `json:"identityAssociationDigest,omitempty"`
	ProviderPolicyDigest      string                    `json:"providerPolicyDigest,omitempty"`
	AccountingVersion         int                       `json:"accountingVersion,omitempty"`
	FormatVersion             int                       `json:"formatVersion"`
	TargetKind                string                    `json:"targetKind"`
	Mode                      string                    `json:"mode"`
	Purpose                   string                    `json:"purpose"`
	PolicyDigest              string                    `json:"policyDigest"`
	Admission                 model.ControllerAdmission `json:"admission"`
	GrantEnvelopeDigest       string                    `json:"grantEnvelopeDigest"`
	AuthorizationSHA256       string                    `json:"authorizationSha256"`
	PreparationIndex          int                       `json:"preparationIndex"`
	IssuedAt                  string                    `json:"issuedAt"`
	AllocationID              string                    `json:"allocationId,omitempty"`
	DemandManifestDigest      string                    `json:"demandManifestDigest,omitempty"`
	ContextDigest             string                    `json:"contextDigest,omitempty"`
}

// Supplied only by protected installed/catalog + accepted-application consumers,
// never from prompt/model/plugin options or from the policy being verified.
type ControllerPolicyWitness struct {
	Applicability Applicability
	Identity      model.ControllerIdentity
	Application   ControllerApplication
	// Accepted workspace configuration and independently observed content
	// closure. Neither is the composed A/N config or the engine setup recipe.
	ApplicationConfigurationDigest string
	WorkspaceMaterializerDigest    string
	demand                         *DemandManifest
}

func (p ControllerPolicy) validate(w ControllerPolicyWitness, now time.Time) error {
	if p.FormatVersion == 6 {
		return p.validateProvider(w, now)
	}
	if p.IdentityAssociation != nil || p.ProviderPolicyDigest != "" || p.AccountingVersion != 0 {
		return ErrUntrusted
	}
	c, t, i := p.Case, p.Applicability, p.Identity
	validCase := p.FormatVersion == 4 && p.AllocationID == "" && c.legacy() && c.Requests >= 1 && c.Requests <= 23 && c.Preparations >= 1 && c.Preparations <= 11 && c.USDMicros >= 1 && c.USDMicros <= 10000000
	if p.FormatVersion == 5 {
		raw, err := json.Marshal(p)
		if err != nil || workflowcontract.Validate(c.contract(), "controllerPolicy5", raw) != nil || !c.typed() || w.demand == nil || w.demand.validate(c, now) != nil {
			return ErrUntrusted
		}
		allocation, err := w.demand.allocation(p.AllocationID)
		if err != nil || allocation.Kind != "parent" || allocation.Scope != i.Intent.Owner || allocation.ModelRequests != 1 || allocation.FirstPhysicalIndex != allocation.LastPhysicalIndex {
			return ErrUntrusted
		}
		validCase = true
	}
	if !validCase || p.TargetKind != "controller_activity" || p.Mode != "real_provider" || p.Purpose != "controller_activity" ||
		!reflect.DeepEqual(p.Applicability, w.Applicability) || !reflect.DeepEqual(i, w.Identity) || p.Application != w.Application ||
		!realTime.MatchString(p.ExpiresAt) || !live(p.ExpiresAt, now) || i.Intent.Validate() != nil || i.Intent.DesiredState != "active" ||
		!safeID.MatchString(c.CaseID) || !hash.MatchString(c.CaseManifestDigest) || c.LedgerID != SharedLedger ||
		c.PricingDigest != PricingDigest() || !hash.MatchString(c.OperatorKeySHA256) {
		return ErrUntrusted
	}
	if !i.Projection.ToolsDisabled || !i.Projection.MCPDisabled || i.Projection.ModelSelection == nil ||
		i.Projection.ModelSelection.CredentialBinding == nil || model.WorkspaceDigest(i.Projection) != i.Intent.RoleAgentDigest ||
		i.Projection.NativeAgentID != "warpmetal-controller-"+i.Intent.Role || i.Projection.SystemDigest != i.Intent.Instructions.InstructionDigest ||
		t.AccountID != i.Intent.Owner.AccountID || t.TaskID != i.Intent.Owner.TaskID || t.ServerID != i.Intent.Owner.ServerID ||
		t.SandboxID != i.Intent.Owner.SandboxID || t.SandboxGeneration != i.Intent.Owner.SandboxGeneration ||
		t.Connection != *i.Projection.ModelSelection.CredentialBinding || t.Connection.Validate() != nil ||
		t.Connection.ProviderID != "openai" || t.Connection.AuthMode != "api_key" ||
		i.Projection.ModelSelection.Authority != (model.CellPreparedAuthorityV3{ProviderID: "openai", ModelID: RealModel, AuthMode: "api_key"}) ||
		t.Model.ProviderID != "openai" || t.Model.ModelID != RealModel || t.Model.AuthMode != "api_key" || t.Model.Endpoint != RealEndpoint ||
		!safeID.MatchString(t.Model.AdapterVersion) || t.Model.AdapterVersion == "team-adapter-1" || !safeID.MatchString(t.Model.EngineProfileVersion) ||
		t.CaseManifestDigest != c.CaseManifestDigest || t.Profile.SetupOperationID != i.Intent.Profile.SetupOperationID ||
		t.Profile.ProfileID != i.Intent.Profile.ProfileID || t.Profile.Revision != i.Intent.Profile.ProfileRevision || t.Profile.ProfileDigest != i.Intent.Profile.ProfileDigest ||
		t.Profile.BundleDigest != i.Projection.ApprovedProfile.BundleDigest || p.Application.OperationID != i.Intent.ApplicationOperationID {
		return ErrUntrusted
	}
	for _, d := range []string{t.Backend.SourceInventoryDigest, t.Backend.ImageDigest, t.Backend.ContractDigest, t.Native.ArchiveSHA256, t.Native.BinarySHA256, t.Runtime.ArchiveSHA256, t.Runtime.BinarySHA256, t.Sandbox.RegistryManifestDigest, t.Sandbox.ConfigDigest, t.Sandbox.PluginDigest, t.Profile.MaterializerDigest, t.Profile.BundleDigest, p.Application.OperationDigest, p.Application.ReceiptDigest} {
		if !hash.MatchString(d) {
			return ErrUntrusted
		}
	}
	for _, id := range []string{t.Native.Version, t.Runtime.Version, t.Backend.MigrationHead, p.Application.ApplicationID} {
		if !safeID.MatchString(id) {
			return ErrUntrusted
		}
	}
	// Actual source registration is the same parent/project/profile/role tuple.
	raw, _ := json.Marshal(i.Intent.Owner)
	var expected map[string]any
	_ = json.Unmarshal(raw, &expected)
	for k, v := range map[string]any{"serviceRegistrationId": i.Intent.ServiceRegistrationID, "serviceGeneration": i.Intent.ServiceGeneration, "instance": i.Intent.Instance, "role": i.Intent.Role, "projectId": i.Intent.Workspace.ProjectID, "workspaceEpoch": i.Intent.Workspace.WorkspaceEpoch, "profileId": i.Intent.Profile.ProfileID, "profileRevision": i.Intent.Profile.ProfileRevision, "profileDigest": i.Intent.Profile.ProfileDigest, "instructionRevision": i.Intent.Instructions.InstructionRevision, "instructionDigest": i.Intent.Instructions.InstructionDigest} {
		expected[k] = v
	}
	if i.Source.FormatVersion != 2 || CanonicalDigest(i.Source.Identity) != CanonicalDigest(expected) || !safeID.MatchString(i.Source.Source.RegisteredSourceID) {
		return ErrUntrusted
	}
	return nil
}

func (a ControllerActivation) validate(p ControllerPolicy, now time.Time) error {
	if a.FormatVersion == 4 || p.FormatVersion == 6 {
		return a.validateProvider(p, now)
	}
	if a.IdentityAssociationDigest != "" || a.ProviderPolicyDigest != "" || a.AccountingVersion != 0 {
		return ErrUntrusted
	}
	r, g := a.Admission.PreparedReceipt, a.Admission.Grant
	i, ie := time.Parse(time.RFC3339Nano, a.IssuedAt)
	deadline, de := time.Parse(time.RFC3339Nano, g.DeadlineAt)
	expiry, xe := time.Parse(time.RFC3339Nano, g.ExpiresAt)
	pe, _ := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	validVersion := a.FormatVersion == 2 && p.FormatVersion == 4 && p.Case.legacy() && a.AllocationID == "" && a.DemandManifestDigest == "" && a.ContextDigest == ""
	if a.FormatVersion == 3 {
		raw, err := json.Marshal(a)
		validVersion = err == nil && workflowcontract.Validate(p.Case.contract(), "controllerActivation3", raw) == nil && p.FormatVersion == 5 && p.Case.typed() &&
			a.AllocationID == p.AllocationID && a.DemandManifestDigest == p.Case.DemandManifestDigest && hash.MatchString(a.ContextDigest) && g.MaxUSDMicros <= RequestMicros
	}
	if !validVersion || a.TargetKind != "controller_activity" || a.Mode != "real_provider" || a.Purpose != "controller_activity" ||
		a.PolicyDigest != CanonicalDigest(p) || !hash.MatchString(a.GrantEnvelopeDigest) || !hash.MatchString(a.AuthorizationSHA256) ||
		a.PreparationIndex < 1 || a.PreparationIndex > p.Case.Preparations || a.Admission.FormatVersion != 1 || a.Admission.TargetKind != "controller_activity" || r.Validate() != nil ||
		g.FormatVersion != 1 || g.TargetKind != "controller_activity" || g.PreparationID != r.PreparationID || g.PreparedReceiptDigest != r.PreparedReceiptDigest ||
		g.PolicyDigest != a.PolicyDigest || g.CaseID != p.Case.CaseID || g.CaseManifestDigest != p.Case.CaseManifestDigest ||
		!safeID.MatchString(g.GrantID) || !safeID.MatchString(g.ReservationID) || g.RequestIndex < 1 || g.RequestIndex > p.Case.Requests ||
		g.PhysicalIndex < 1 || g.PhysicalIndex > p.Case.Requests || g.MaxInputTokens < 1 || g.MaxInputTokens > 2095152 ||
		g.MaxOutputTokens < 1 || g.MaxOutputTokens > 1000 || g.MaxUSDMicros < 1 || g.MaxUSDMicros > p.Case.USDMicros ||
		!realTime.MatchString(a.IssuedAt) || !realTime.MatchString(g.DeadlineAt) || !realTime.MatchString(g.ExpiresAt) || ie != nil || de != nil || xe != nil ||
		i.After(now) || !now.Before(deadline) || !now.Before(expiry) || !i.Before(deadline) || !i.Before(pe) || deadline.After(expiry) ||
		deadline.Sub(i) > 120*time.Second || expiry.After(pe) {
		return ErrUntrusted
	}
	if p.Case.FormatVersion == 2 && g.MaxInputTokens+g.MaxOutputTokens > 1047576 {
		return ErrUntrusted
	}
	usd := (int64(g.MaxInputTokens)*400000 + int64(g.MaxOutputTokens)*1600000 + 999999) / 1000000
	if g.MaxUSDMicros < usd {
		return ErrUntrusted
	}
	return nil
}

func (s Store) ReadControllerPolicy(box model.Sandbox, digest string, w ControllerPolicyWitness, now time.Time) (ControllerPolicy, error) {
	var p ControllerPolicy
	tree, key, e := s.Paths(box.ID)
	if e != nil || !hash.MatchString(digest) {
		return p, ErrUntrusted
	}
	b, e := s.signed(tree, key, "snapshots/"+digest[7:]+"/policy", 131072)
	// Parent nullable model fields use the model's complete decoder below; child
	// decodeClosed's nonnull rule stays untouched.
	if e != nil || Digest(b) != digest || decode(b, &p) != nil || !bytes.Equal(b, canonicalBytes(p)) {
		return p, ErrUntrusted
	}
	if p.FormatVersion == 5 || p.FormatVersion == 6 {
		demand, err := s.ReadTypedDemand(box, p.Case, now)
		if err != nil {
			return p, err
		}
		w.demand = &demand
	}
	if p.validate(w, now) != nil ||
		p.Applicability.SandboxID != box.ID || p.Applicability.SandboxGeneration != box.Generation {
		return p, ErrUntrusted
	}
	kb, e := s.read(key, tree, key, 4096)
	if e != nil || Digest(kb) != p.Case.OperatorKeySHA256 {
		return p, ErrUntrusted
	}
	entries, e := os.ReadDir(filepath.Join(tree, "revocations"))
	if e != nil {
		return p, ErrUntrusted
	}
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) == ".sig" {
			continue
		}
		if len(name) != 69 || !hash.MatchString("sha256:"+name[:64]) || name[64:] != ".json" {
			return p, ErrUntrusted
		}
		raw, e := s.signed(tree, key, "revocations/"+name[:64], 16384)
		var rev Revocation
		if e != nil || decodeClosed(raw, &rev) != nil || Digest(raw) != "sha256:"+name[:64] || rev.FormatVersion != 1 || rev.CampaignID != p.Case.CaseID || rev.SandboxID != box.ID || !hash.MatchString(rev.PolicyDigest) || rev.PolicyDigest == digest {
			return p, ErrUntrusted
		}
	}
	return p, nil
}

// Version-selected current context join at preparation, BEFORE reserve/prompt,
// and at retained output. Context hashes never replace signed store validation.
func (p ControllerPolicy) ValidateContext(c model.ControllerApprovedInputContext) error {
	if p.FormatVersion == 6 || c.FormatVersion == 3 || c.FormatVersion == 4 {
		raw, err := json.Marshal(c)
		document, definition := workflowcontract.ControllerProvider, "approvedContext3"
		if c.FormatVersion == 4 {
			document, definition = workflowcontract.ManagerSingle, "approvedContext4"
		}
		if err != nil || workflowcontract.Validate(document, definition, raw) != nil || p.FormatVersion != 6 || p.IdentityAssociation == nil || c.ProviderPolicyDigest != p.ProviderPolicyDigest || c.IdentityAssociationDigest != p.IdentityAssociation.AssociationDigest || c.PolicyDigest != CanonicalDigest(p) || c.CaseID != p.Case.CaseID || c.CaseManifestDigest != p.Case.CaseManifestDigest || c.AllocationID != p.AllocationID || c.DemandManifestDigest != p.Case.DemandManifestDigest {
			return ErrUntrusted
		}
		return nil
	}
	if c.FormatVersion == 2 {
		raw, err := json.Marshal(c)
		if err != nil || workflowcontract.Validate(p.Case.contract(), "approvedContext2", raw) != nil {
			return ErrUntrusted
		}
	}
	if c.PolicyDigest != CanonicalDigest(p) || c.CaseID != p.Case.CaseID || c.CaseManifestDigest != p.Case.CaseManifestDigest {
		return ErrUntrusted
	}
	if p.FormatVersion == 4 && c.FormatVersion == 1 && p.Case.legacy() {
		return nil
	}
	if p.FormatVersion != 5 || c.FormatVersion != 2 || !p.Case.typed() || c.AllocationID != p.AllocationID || c.DemandManifestDigest != p.Case.DemandManifestDigest {
		return ErrUntrusted
	}
	return nil
}
func (a ControllerActivation) ValidateContext(p ControllerPolicy, c model.ControllerApprovedInputContext) error {
	if p.ValidateContext(c) != nil {
		return ErrUntrusted
	}
	if a.FormatVersion == 2 && c.FormatVersion == 1 {
		return nil
	}
	if ((a.FormatVersion != 3 || c.FormatVersion != 2) && (a.FormatVersion != 4 || (c.FormatVersion != 3 && c.FormatVersion != 4))) || a.ContextDigest != c.ContextDigest || a.AllocationID != c.AllocationID ||
		a.DemandManifestDigest != c.DemandManifestDigest || a.PreparationIndex != c.PreparationOrdinal || a.Admission.Grant.PhysicalIndex != c.PhysicalIndex {
		return ErrUntrusted
	}
	return nil
}

func (s Store) ReadControllerActivation(box model.Sandbox, p ControllerPolicy, r model.ControllerPreparedReceipt, now time.Time) (ControllerActivation, error) {
	return s.readControllerActivation(box, p, r, now, false)
}

// Retained activation proves already-consumed output only. It cannot authorize
// prompt or HTTP after deadline; initial dispatch MUST use ReadControllerActivation.
func (s Store) ReadControllerRetainedActivation(box model.Sandbox, p ControllerPolicy, r model.ControllerPreparedReceipt, now time.Time) (ControllerActivation, error) {
	return s.readControllerActivation(box, p, r, now, true)
}

func (s Store) readControllerActivation(box model.Sandbox, p ControllerPolicy, r model.ControllerPreparedReceipt, now time.Time, retained bool) (ControllerActivation, error) {
	var a ControllerActivation
	tree, key, e := s.Paths(box.ID)
	if e != nil || p.validatePrepared(r) != nil {
		return a, ErrUntrusted
	}
	b, e := s.signed(tree, key, "activations/controller-"+r.PreparationID+"/activation", 131072)
	if e != nil || decodeClosed(b, &a) != nil || !bytes.Equal(b, canonicalBytes(a)) {
		return a, ErrUntrusted
	}
	at := now
	if retained {
		at, e = time.Parse(time.RFC3339Nano, a.IssuedAt)
		if e != nil || at.After(now) {
			return a, ErrUntrusted
		}
	}
	if a.validate(p, at) != nil || !reflect.DeepEqual(a.Admission.PreparedReceipt, r) {
		return a, ErrUntrusted
	}
	if p.FormatVersion == 5 || p.FormatVersion == 6 {
		demand, err := s.ReadTypedDemand(box, p.Case, now)
		if err != nil {
			return a, err
		}
		allocation, err := demand.allocation(a.AllocationID)
		if err != nil || allocation.Scope != p.ApplicationIdentity().Intent.Owner || allocation.Kind != "parent" || a.PreparationIndex != allocation.PreparationOrdinal ||
			a.Admission.Grant.PhysicalIndex != allocation.FirstPhysicalIndex {
			return a, ErrUntrusted
		}
		if p.FormatVersion == 6 {
			modelIndex := 1
			for _, prior := range demand.AllocationList {
				if prior.LastPhysicalIndex < allocation.FirstPhysicalIndex {
					modelIndex += prior.ModelRequests
				}
			}
			if a.Admission.Grant.RequestIndex != modelIndex {
				return a, ErrUntrusted
			}
		}
	}
	t := r.PreparedTuple
	i := p.NativeIdentity()
	if t.Owner != i.Intent.Owner || t.Role != i.Intent.Role || t.ServiceRegistrationID != i.Intent.ServiceRegistrationID || t.ServiceGeneration != i.Intent.ServiceGeneration ||
		t.RoleAgentDigest != i.Intent.RoleAgentDigest || t.ConfigDigest != i.Intent.ConfigDigest || t.CredentialBinding != p.Applicability.Connection ||
		t.NativeRegistration.RegisteredSourceID != i.Source.Source.RegisteredSourceID || t.NativeRegistration.NativeSessionID != i.Source.Source.NativeSessionID ||
		t.NativeRegistration.NativeProjectID != i.Source.Source.NativeProjectID || t.NativeRegistration.NativeLocationDigest != i.Source.Source.NativeLocationDigest || t.NativeRegistration.WorkspaceEpoch != i.Intent.Workspace.WorkspaceEpoch {
		return a, ErrUntrusted
	}
	return a, nil
}
