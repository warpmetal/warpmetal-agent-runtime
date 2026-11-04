package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type productSourceRootRuntime interface {
	ResolveCellProductSourceRoot(context.Context, model.CellServiceV3, model.Manifest, model.ChildProductDelivery, model.WorkflowCaptureRequest) (qualification.TrustedWorkspace, error)
}

// Workspace roots belong to the registered catalog, not to the container engine.
// A signed root grant selects a source registration; it never supplies host path,
// device/inode or a successful catalog row. The physical reader verifies the full
// signed source grant independently before opening any source bytes.
func (r *Reconciler) resolveApprovedProductSourceRoot(ctx context.Context, entry model.CellServiceV3, delivery model.ChildProductDelivery, call model.WorkflowCaptureRequest) (qualification.TrustedWorkspace, error) {
	var empty qualification.TrustedWorkspace
	if r.ManagedCatalog == nil || r.Store == nil {
		return empty, errors.New("registered source catalog absent")
	}
	var wire struct {
		Generation struct {
			Policy struct {
				Payload struct {
					SourceReads []qualification.ChildSourceReadScope `json:"sourceReads"`
				} `json:"payload"`
			} `json:"policy"`
		} `json:"generation"`
	}
	var observation struct {
		Reference json.RawMessage `json:"reference"`
	}
	if json.Unmarshal(delivery.Bytes(), &wire) != nil || json.Unmarshal(call.Operation.Observation, &observation) != nil {
		return empty, errors.New("source selector refused")
	}
	var selected *qualification.ChildSourceReadScope
	for i := range wire.Generation.Policy.Payload.SourceReads {
		scope := &wire.Generation.Policy.Payload.SourceReads[i]
		var grant struct {
			Reference json.RawMessage `json:"reference"`
		}
		if json.Unmarshal(scope.Grant, &grant) != nil {
			return empty, errors.New("source grant selector refused")
		}
		if model.WorkspaceDigest(grant.Reference) == model.WorkspaceDigest(observation.Reference) {
			if selected != nil {
				return empty, errors.New("ambiguous source root")
			}
			selected = scope
		}
	}
	if selected == nil {
		return empty, errors.New("source root absent")
	}
	var root struct {
		RootKind, RegisteredSourceID, RootAttestation string
		Workspace                                     model.ManagedServiceWorkspaceV1
	}
	if json.Unmarshal(selected.Root, &root) != nil {
		return empty, errors.New("source workspace selector refused")
	}
	if root.RootKind == "installed_script" {
		if owner, ok := r.ManagedRuntime.(productSourceRootRuntime); ok {
			return owner.ResolveCellProductSourceRoot(ctx, entry, r.currentAuthorityManifest(), delivery, call)
		}
		return empty, errors.New("installed-script registered root unavailable")
	}
	if root.RootKind != "workspace" || root.RootAttestation != root.Workspace.RootAttestation {
		return empty, errors.New("source root kind refused")
	}
	source, err := r.Store.ContinuitySource(ctx, root.RegisteredSourceID)
	if err != nil {
		return empty, err
	}
	if source == nil || source.Report.Availability != "available" || source.Report.ProjectID != root.Workspace.ProjectID || source.Report.WorkspaceEpoch != root.Workspace.WorkspaceEpoch || source.Report.ScopeRevision != root.Workspace.ScopeRevision {
		return empty, errors.New("registered source identity changed")
	}
	box, err := r.Store.Sandbox(ctx, source.Report.SandboxID)
	if err != nil || box == nil || box.ObservedState != "running" || box.Generation != source.Report.SandboxGeneration || box.ObservedGeneration != box.Generation {
		return empty, errors.New("registered source generation unavailable")
	}
	project, err := r.ManagedCatalog.Resolve(ctx, workspacecatalog.ResolveProjectRequest{SelectionID: root.Workspace.SelectionID, ProjectID: root.Workspace.ProjectID, WorkspaceEpoch: root.Workspace.WorkspaceEpoch, SandboxID: source.Report.SandboxID, SandboxGeneration: source.Report.SandboxGeneration, ServiceRegistrationID: source.Report.ServiceRegistrationID})
	if err != nil {
		return empty, err
	}
	if project.Report.Availability != "available" || project.Report.RootAttestation != root.RootAttestation || project.ScopeRevision != root.Workspace.ScopeRevision || project.HostRoot != source.Root || project.RootDevice == 0 || project.RootInode == 0 {
		return empty, errors.New("registered source physical root changed")
	}
	return qualification.TrustedWorkspace{HostRoot: project.HostRoot, ContainerRoot: project.ContainerRoot, WorkspaceDigest: project.Report.RootAttestation, Device: project.RootDevice, Inode: project.RootInode}, nil
}
