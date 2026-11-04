package qualification

import (
	"context"
	"encoding/json"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Host installation-owner publication, NOT a backend/model upload. The existing
// installation owner supplies its ORIGINAL manifest and mapped root registration;
// no grant/policy can supply HostRoot/dev/inode or create this registry entry.
// Exact originals are immutable: installation/revision drift needs its own new
// owning registration, never replacement of a previous accepted selector.
func (p *Producer) PublishInstalledScriptRoot(ctx context.Context, current model.Manifest, r InstalledScriptRootRegistration) error {
	if p == nil || ctx.Err() != nil || r.FormatVersion != 1 || !safeID.MatchString(r.RegisteredSourceID) || !safeID.MatchString(r.TaskID) ||
		r.ServerID != p.config.ServerID || r.ServerID != current.ServerID || r.RuntimeRevision != current.DesiredRevision || !hash.MatchString(r.CandidateDescriptorDigest) ||
		len(r.InstalledManifest) == 0 || len(r.InstalledManifest) > 262144 || !hash.MatchString(r.Workspace.WorkspaceDigest) || r.Workspace.ContainerRoot == "" {
		return ErrUntrusted
	}
	reader, err := verifyCurrentPlanReaderAdoption(ctx, r.TaskID, nil, current, p.config, p.read, SelfBinaryDigest, p.verifyPlanReaderArchive)
	if err != nil || reader.CandidateDescriptorDigest != r.CandidateDescriptorDigest {
		return ErrUntrusted
	}
	root, err := confinedRoot(r.Workspace.HostRoot, r.Workspace.Device, r.Workspace.Inode)
	if err != nil {
		return err
	}
	root.Close()
	name := "installed-script-root-" + r.RegisteredSourceID + ".json"
	raw := canonicalBytes(r)
	if len(raw) > 512*1024 {
		return ErrUntrusted
	}
	if err = p.append(name, raw); err != nil {
		return err
	}
	retained, err := p.read(name, 512*1024)
	if err != nil || string(retained) != string(raw) || ctx.Err() != nil {
		return ErrUntrusted
	}
	root, err = confinedRoot(r.Workspace.HostRoot, r.Workspace.Device, r.Workspace.Inode)
	if err != nil {
		return err
	}
	return root.Close()
}

// Host-private installed registry record, not a signed read grant or a policy
// field. HostRoot/dev/inode originate at installation registration. Resolution
// never provisions a record, opens script bytes or relaxes installed adoption.
type InstalledScriptRootRegistration struct {
	FormatVersion             int              `json:"formatVersion"`
	RegisteredSourceID        string           `json:"registeredSourceId"`
	TaskID                    string           `json:"taskId"`
	ServerID                  string           `json:"serverId"`
	RuntimeRevision           int64            `json:"runtimeRevision"`
	CandidateDescriptorDigest string           `json:"candidateDescriptorDigest"`
	InstalledManifest         []byte           `json:"installedManifest"`
	Workspace                 TrustedWorkspace `json:"workspace"`
}

func resolveInstalledScriptRoot(ctx context.Context, selector json.RawMessage, w ChildProductWitness, load func(string, int) ([]byte, error)) (TrustedWorkspace, error) {
	var empty TrustedWorkspace
	var root struct {
		RootKind                  string                            `json:"rootKind"`
		RegisteredSourceID        string                            `json:"registeredSourceId"`
		RootAttestation           string                            `json:"rootAttestation"`
		CandidateDescriptorDigest string                            `json:"candidateDescriptorDigest"`
		InstalledManifestDigest   string                            `json:"installedManifestDigest"`
		Producer                  model.WorkspaceRegisteredProducer `json:"producer"`
	}
	if ctx.Err() != nil || load == nil || json.Unmarshal(selector, &root) != nil || root.RootKind != "installed_script" || !safeID.MatchString(root.RegisteredSourceID) ||
		!hash.MatchString(root.InstalledManifestDigest) || !sameProduct(w.SourceRoots[CanonicalDigest(selector)], selector) ||
		root.Producer != w.Root.Producer || root.CandidateDescriptorDigest != w.Root.CandidateDescriptorDigest {
		return empty, ErrUntrusted
	}
	name := "installed-script-root-" + root.RegisteredSourceID + ".json"
	raw, err := load(name, 512*1024)
	var registration InstalledScriptRootRegistration
	if err != nil || decode(raw, &registration) != nil || !bytesCanonical(raw, registration) || registration.FormatVersion != 1 ||
		registration.RegisteredSourceID != root.RegisteredSourceID || registration.TaskID != w.Applicability.TaskID || registration.ServerID != w.Root.Producer.ServerID ||
		registration.RuntimeRevision != w.Root.RuntimeRevision || registration.CandidateDescriptorDigest != root.CandidateDescriptorDigest ||
		len(registration.InstalledManifest) == 0 || Digest(registration.InstalledManifest) != root.InstalledManifestDigest ||
		registration.Workspace.WorkspaceDigest != root.RootAttestation || registration.Workspace.ContainerRoot == "" {
		return empty, ErrUntrusted
	}
	actual, err := confinedRoot(registration.Workspace.HostRoot, registration.Workspace.Device, registration.Workspace.Inode)
	if err != nil {
		return empty, err
	}
	actual.Close()
	again, err := load(name, 512*1024)
	if err != nil || string(raw) != string(again) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	return registration.Workspace, nil
}

// The normal installed-script adapter uses the SAME complete current installed
// verifier as PRODUCT adoption. Wire selectors supply neither paths nor records.
func (p *Producer) ResolveChildProductInstalledScriptRoot(ctx context.Context, entry model.CellServiceV3, current model.Manifest, delivery model.ChildProductDelivery, call model.WorkflowCaptureRequest) (TrustedWorkspace, error) {
	var empty TrustedWorkspace
	if p == nil || !safeID.MatchString(entry.PreparationID) {
		return empty, ErrUntrusted
	}
	raw, err := p.read("child-product-current-"+entry.PreparationID+".json", 512*1024)
	var retained ChildProductWitness
	if err != nil || decode(raw, &retained) != nil {
		return empty, ErrUntrusted
	}
	w, err := p.CurrentChildProductWitness(ctx, entry, current, retained.Input)
	if err != nil {
		return empty, err
	}
	var control ChildProductControl
	var observed struct {
		Reference json.RawMessage `json:"reference"`
	}
	if decode(delivery.Bytes(), &control) != nil || control.Generation.Policy == nil || json.Unmarshal(call.Operation.Observation, &observed) != nil || len(observed.Reference) == 0 {
		return empty, ErrUntrusted
	}
	var selected json.RawMessage
	for _, scope := range control.Generation.Policy.Payload.SourceReads {
		var grant struct {
			Reference json.RawMessage `json:"reference"`
		}
		if json.Unmarshal(scope.Grant, &grant) != nil {
			return empty, ErrUntrusted
		}
		if sameProduct(grant.Reference, observed.Reference) {
			if selected != nil {
				return empty, ErrUntrusted
			}
			selected = scope.Root
		}
	}
	if selected == nil {
		return empty, ErrUntrusted
	}
	return resolveInstalledScriptRoot(ctx, selected, w, p.read)
}
