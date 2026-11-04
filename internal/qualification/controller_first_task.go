package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Independent EXISTING installed tuple inventory, not policy self-applicability.
// Complete archive/build/self adoption and current manifest joins remain required.
func (p *Producer) ReadControllerFirstTaskApplicability(ctx context.Context, current model.Manifest, w ControllerPolicyWitness) (Applicability, error) {
	var empty Applicability
	b, _, err := p.CurrentPhysicalBaseline(ctx, current)
	if err != nil {
		return empty, err
	}
	parent := w.Identity.Intent
	if b.TaskID != parent.Owner.TaskID || len(b.SourceContinuation) != 0 || !b.Case.typed() {
		return empty, ErrUntrusted
	}
	raw, err := p.read("physical-gate-authority.json", 65536)
	if err != nil {
		return empty, err
	}
	fields := childFields(raw)
	if !sameProduct(fields["case"], b.Case) || CanonicalDigest(fields["tupleInventory"]) != b.Case.TupleInventoryDigest {
		return empty, ErrUntrusted
	}
	app, err := controllerApplicabilityFromInventory(fields["tupleInventory"], b.Case, w)
	if err != nil {
		return empty, err
	}
	if app.CaseManifestDigest != b.Case.CaseManifestDigest || !sameProduct(fields["native"], app.Native) || !sameProduct(fields["runtime"], app.Runtime) || !sameProduct(fields["backend"], app.Backend) || !sameProduct(fields["sandbox"], app.Sandbox) || childString(fields, "profileBundleDigest") != app.Profile.BundleDigest {
		return empty, ErrUntrusted
	}
	if validateControllerFirstTaskApplicability(app, b.Case, w) != nil {
		return empty, ErrUntrusted
	}
	actual, err := SelfBinaryDigest()
	if err != nil || actual != app.Runtime.BinarySHA256 {
		return empty, ErrUntrusted
	}
	setupFound, boxFound := false, false
	for _, setup := range current.SetupOperations {
		if setup.ID == parent.Profile.SetupOperationID {
			if setup.Materializer.Bin == nil || setup.Materializer.Artifact == nil || setup.Materializer.Bin.Version != app.Native.Version || "sha256:"+strings.TrimPrefix(setup.Materializer.Bin.SHA256, "sha256:") != app.Native.BinarySHA256 || "sha256:"+strings.TrimPrefix(setup.Materializer.Artifact.SHA256, "sha256:") != app.Native.ArchiveSHA256 || b.Case.FormatVersion == 3 && CanonicalDigest(setup.Materializer) != app.Profile.MaterializerDigest {
				return empty, ErrUntrusted
			}
			setupFound = true
		}
	}
	for _, box := range current.Sandboxes {
		if box.ID == app.SandboxID && box.Generation == app.SandboxGeneration && box.DesiredState == "running" && strings.HasSuffix(box.ImageDigest, "@"+app.Sandbox.RegistryManifestDigest) {
			boxFound = true
		}
	}
	if !setupFound || !boxFound {
		return empty, ErrUntrusted
	}
	again, err := p.read("physical-gate-authority.json", 65536)
	if err != nil || !bytes.Equal(raw, again) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	return app, nil
}

// The caller verifies the whole independently installed authority/schema first.
func controllerApplicabilityFromInventory(raw []byte, c RealCase, w ControllerPolicyWitness) (Applicability, error) {
	var empty Applicability
	var inventory struct {
		Tuples []struct {
			TupleDigest   string
			Applicability Applicability
			Consumers     []struct {
				Kind, SourceID, ConfigurationDigest string
				Scope                               model.ControllerOwner
				Profile                             model.ManagedServiceProfileV1
				CredentialBinding                   model.CellCredentialBindingV3
				Authority                           model.CellPreparedAuthorityV3
			}
		}
	}
	if !c.typed() || json.Unmarshal(raw, &inventory) != nil || w.Identity.Projection.ModelSelection == nil || w.Identity.Projection.ModelSelection.CredentialBinding == nil {
		return empty, ErrUntrusted
	}
	parent, selected := w.Identity.Intent, w.Identity.Projection.ModelSelection
	configuration := parent.ConfigDigest
	if c.FormatVersion == 3 {
		if !hash.MatchString(w.ApplicationConfigurationDigest) || workflowcontract.Validate(workflowcontract.BudgetProvider, "tupleInventory", raw) != nil || CanonicalDigest(json.RawMessage(raw)) != c.TupleInventoryDigest {
			return empty, ErrUntrusted
		}
		configuration = w.ApplicationConfigurationDigest
	}
	seen := map[string]bool{}
	var found *Applicability
	for _, tuple := range inventory.Tuples {
		if tuple.TupleDigest != CanonicalDigest(tuple.Applicability) {
			return empty, ErrUntrusted
		}
		for _, consumer := range tuple.Consumers {
			if c.FormatVersion == 3 && seen[consumer.SourceID] {
				return empty, ErrUntrusted
			}
			seen[consumer.SourceID] = true
			if consumer.SourceID != parent.ServiceRegistrationID {
				continue
			}
			app := tuple.Applicability
			if found != nil || consumer.Kind != "parent" || consumer.Scope != parent.Owner || consumer.ConfigurationDigest != configuration || consumer.Profile != parent.Profile || consumer.CredentialBinding != *selected.CredentialBinding || consumer.Authority != selected.Authority || app.AccountID != parent.Owner.AccountID || app.TaskID != parent.Owner.TaskID || app.ServerID != parent.Owner.ServerID || app.SandboxID != parent.Owner.SandboxID || app.SandboxGeneration != parent.Owner.SandboxGeneration || app.Connection != *selected.CredentialBinding {
				return empty, ErrUntrusted
			}
			found = &app
		}
	}
	if found == nil {
		return empty, ErrUntrusted
	}
	return *found, nil
}

// Selecting an inventory consumer does not admit its installed tuple. Keep the
// private candidate/model/profile contract separate from that identity join.
func validateControllerFirstTaskApplicability(app Applicability, c RealCase, w ControllerPolicyWitness) error {
	parent := w.Identity.Intent
	if !c.typed() {
		return ErrUntrusted
	}
	family, definition := workflowcontract.Manager, "artifactApplicability"
	provider, modelID, endpoint, runtimeVersion := "openai", RealModel, RealEndpoint, "0.1.52"
	if c.FormatVersion == 3 {
		d := providerpolicy.Flash()
		family, definition = workflowcontract.BudgetProvider, "artifactApplicability2"
		provider, modelID, endpoint, runtimeVersion = d.ProviderID, d.ModelID, d.Transport.URL, "0.1.54-e2.1"
		if c.ProviderPolicyDigest != providerpolicy.FlashDigest || c.AccountingVersion != 2 || app.ProviderPolicyDigest != c.ProviderPolicyDigest || app.FormatVersion != 2 {
			return ErrUntrusted
		}
	}
	if workflowcontract.Validate(family, definition, canonicalBytes(app)) != nil || app.CaseManifestDigest != c.CaseManifestDigest || app.Profile.SetupOperationID != parent.Profile.SetupOperationID || app.Profile.ProfileID != parent.Profile.ProfileID || app.Profile.Revision != parent.Profile.ProfileRevision || app.Profile.ProfileDigest != parent.Profile.ProfileDigest || app.Profile.BundleDigest != w.Identity.Projection.ApprovedProfile.BundleDigest || app.Model.ProviderID != provider || app.Model.ModelID != modelID || app.Model.AuthMode != "api_key" || app.Model.Endpoint != endpoint || app.Runtime.Version != runtimeVersion {
		return ErrUntrusted
	}
	return nil
}
