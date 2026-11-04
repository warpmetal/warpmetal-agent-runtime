package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Called only by the host installation/registry owner with its original measured
// registration. Not exposed on SOURCE RPC/node API; ROOT grants are read selectors
// and cannot provision mappings. Missing archive/self/registration truth denies.
func (p Podman) PublishInstalledScriptRoot(ctx context.Context, current model.Manifest, r qualification.InstalledScriptRootRegistration) error {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	return producer.PublishInstalledScriptRoot(ctx, current, r)
}

// NORMAL owning installation callsite, invoked from original fact export. Only
// original installed-observer scopes select registrations; the image mapping and
// manifest path come from authenticated container inspection/fixed installation.
func (p Podman) publishMeasuredInstalledScriptRoots(ctx context.Context, entry model.CellServiceV3, current model.Manifest, producer *qualification.Producer, input []byte) error {
	w, err := producer.ChildProductSourceReadWitness(ctx, entry, current, input)
	if err != nil {
		return err
	}
	needed := false
	for _, scope := range w.InstalledInputs.SourceReads {
		var root struct {
			RootKind string `json:"rootKind"`
		}
		if json.Unmarshal(scope.Root, &root) != nil {
			return qualification.ErrUntrusted
		}
		if root.RootKind == "installed_script" {
			needed = true
		}
	}
	if !needed {
		return nil
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return err
	}
	if p.verifyQualificationMounts(ctx, entry.SandboxID) != nil || p.verifyQualificationImage(ctx, entry.SandboxID, w.Applicability.Sandbox.ConfigDigest) != nil {
		return qualification.ErrUntrusted
	}
	text, err := p.runOutput(ctx, true, "inspect", containerName(entry.SandboxID))
	if err != nil {
		return err
	}
	imageRoot, err := installedScriptImageMapping([]byte(text), entry.SandboxID, w.Applicability.Sandbox.ConfigDigest)
	if err != nil {
		return err
	}
	// One kernel-owned root link from the authenticated container PID, not a
	// policy path or filesystem scan. Pin the actual init root to Podman's mapping.
	if runtime.GOOS != "linux" {
		return qualification.ErrUntrusted
	}
	var containers []struct {
		State struct {
			PID int `json:"Pid"`
		}
	}
	if json.Unmarshal([]byte(text), &containers) != nil || len(containers) != 1 {
		return qualification.ErrUntrusted
	}
	actualRoot, err := os.Stat(fmt.Sprintf("/proc/%d/root", containers[0].State.PID))
	if err != nil {
		return qualification.ErrUntrusted
	}
	mappedRoot, err := os.Lstat(imageRoot)
	if err != nil || !mappedRoot.IsDir() || !os.SameFile(actualRoot, mappedRoot) {
		return qualification.ErrUntrusted
	}
	registration, err := qualification.MeasureInstalledScriptImageRoot(ctx, imageRoot, store.MappedUID)
	if err != nil {
		return err
	}
	registration.TaskID = w.Applicability.TaskID
	registration.ServerID = current.ServerID
	registration.RuntimeRevision = current.DesiredRevision
	registration.CandidateDescriptorDigest = w.Root.CandidateDescriptorDigest
	var manifest qualification.InstalledScriptManifest
	if json.Unmarshal(registration.InstalledManifest, &manifest) != nil {
		return qualification.ErrUntrusted
	}
	for _, scope := range w.InstalledInputs.SourceReads {
		var root struct {
			RootKind                string `json:"rootKind"`
			RegisteredSourceID      string `json:"registeredSourceId"`
			InstalledManifestDigest string `json:"installedManifestDigest"`
			RootAttestation         string `json:"rootAttestation"`
		}
		if json.Unmarshal(scope.Root, &root) != nil {
			return qualification.ErrUntrusted
		}
		if root.RootKind == "installed_script" && (root.RegisteredSourceID != w.Root.RegisteredSourceID || root.InstalledManifestDigest != qualification.Digest(registration.InstalledManifest) || root.RootAttestation != w.Root.Workspace.RootAttestation) {
			return qualification.ErrUntrusted
		}
		if root.RootKind == "installed_script" {
			// Logical registration/attestation comes from the ORIGINAL independently
			// signed installed observer (not PRODUCT); physical path/dev/inode and
			// manifest bytes come only from the normal image installation owner.
			registration.RegisteredSourceID = root.RegisteredSourceID
			registration.Workspace.WorkspaceDigest = root.RootAttestation
			var grant struct {
				Reference model.ControllerPlanReference `json:"reference"`
				ByteCount int                           `json:"byteCount"`
			}
			if json.Unmarshal(scope.Grant, &grant) != nil || grant.Reference.Path != manifest.ScriptPath || grant.Reference.SourceDigest != "sha256:"+manifest.ScriptSHA256 || grant.ByteCount != manifest.ScriptByteCount {
				return qualification.ErrUntrusted
			}
		}
	}
	again, err := p.runOutput(ctx, true, "inspect", containerName(entry.SandboxID))
	if err != nil || again != text || ctx.Err() != nil {
		return qualification.ErrUntrusted
	}
	return p.PublishInstalledScriptRoot(ctx, current, registration)
}

func installedScriptImageMapping(raw []byte, id, configDigest string) (string, error) {
	var rows []struct {
		Name  string
		Image string
		State struct {
			Running bool
			PID     int `json:"Pid"`
		}
		HostConfig  struct{ ReadonlyRootfs bool }
		GraphDriver struct{ Data struct{ MergedDir string } }
		Mounts      []struct{ Destination string }
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 || rows[0].Name != containerName(id) || !rows[0].State.Running || rows[0].State.PID < 1 || !rows[0].HostConfig.ReadonlyRootfs {
		return "", qualification.ErrUntrusted
	}
	image := rows[0].Image
	if !strings.HasPrefix(image, "sha256:") {
		image = "sha256:" + image
	}
	if image != configDigest || rows[0].GraphDriver.Data.MergedDir == "" {
		return "", qualification.ErrUntrusted
	}
	for _, mount := range rows[0].Mounts {
		path := strings.TrimSuffix(mount.Destination, "/")
		if path == "" || path == "/" || path == qualification.InstalledScriptContainerRoot || strings.HasPrefix(qualification.InstalledScriptContainerRoot, path+"/") || strings.HasPrefix(path, qualification.InstalledScriptContainerRoot+"/") {
			return "", qualification.ErrUntrusted
		}
	}
	return rows[0].GraphDriver.Data.MergedDir, nil
}

func (p Podman) ResolveCellProductSourceRoot(ctx context.Context, entry model.CellServiceV3, current model.Manifest, delivery model.ChildProductDelivery, call model.WorkflowCaptureRequest) (qualification.TrustedWorkspace, error) {
	if p.verifyQualificationMounts(ctx, entry.SandboxID) != nil {
		return qualification.TrustedWorkspace{}, qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return qualification.TrustedWorkspace{}, err
	}
	return producer.ResolveChildProductInstalledScriptRoot(ctx, entry, current, delivery, call)
}
