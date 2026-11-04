package reconcile

import (
	"context"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// Current read-only inputs shared by child-role and result/facts consumers.
// The historical terminal record supplies selectors, never fresh authority.
type completedChildAuthority struct {
	Fresh       ControllerFirstTaskChildResult
	Manifest    model.Manifest
	Application *state.LocalWorkspaceApplication
	Sandbox     model.Sandbox
	Project     *state.LocalManagedProject
	Root        workspacecatalog.RegisteredProject
	Input       []byte
}

func (r *Reconciler) currentCompletedChildAuthority(ctx context.Context, owner controllerChildApplication, child ControllerFirstTaskChildResult, entry model.CellServiceV3) (completedChildAuthority, error) {
	var out completedChildAuthority
	fresh, err := r.readControllerChildTerminalLocked(ctx, owner.Owner, child.Handle, child.PreparationAssociation, entry, child.AdmissionAssociation)
	if err != nil {
		return out, err
	}
	if fresh.ExecutionID != child.ExecutionID || !reflect.DeepEqual(fresh.NativeReport, child.NativeReport) {
		return out, state.ErrControllerActivityConflict
	}
	app, err := r.Store.WorkspaceApplication(ctx, owner.ApplicationOperationID)
	if err != nil || app == nil || !app.Applied || app.ApplicationID != owner.ApplicationID || app.Operation.OperationDigest != owner.ApplicationOperationDigest {
		return out, state.ErrControllerActivityConflict
	}
	box, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil || box == nil || box.ObservedState != "running" || box.ObservedGeneration != entry.SandboxGeneration {
		return out, state.ErrControllerActivityConflict
	}
	project, err := r.lookupCellProject(ctx, cellV2View(entry))
	if err != nil || project == nil || project.Report.Availability != "available" || project.ScopeRevision != entry.Workspace.ScopeRevision {
		return out, state.ErrControllerActivityConflict
	}
	text, err := r.fetchCellFirstText(ctx, cellV2View(entry))
	if err != nil {
		return out, err
	}
	return completedChildAuthority{Fresh: fresh, Manifest: r.currentAuthorityManifest(), Application: app, Sandbox: model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ImageDigest: box.ImageDigest, Cell: true}, Project: project, Root: workspacecatalog.RegisteredProject{Report: project.Report, HostRoot: project.HostRoot, ContainerRoot: project.ContainerRoot, ScopeRevision: project.ScopeRevision, RootDevice: project.RootDevice, RootInode: project.RootInode}, Input: []byte(text)}, nil
}
func sameCompletedChildAuthority(a, b completedChildAuthority) bool {
	return a.Manifest.DesiredRevision == b.Manifest.DesiredRevision && reflect.DeepEqual(a.Application, b.Application) && reflect.DeepEqual(a.Sandbox, b.Sandbox) && reflect.DeepEqual(a.Project, b.Project) && reflect.DeepEqual(a.Input, b.Input) && reflect.DeepEqual(a.Fresh.NativeReport, b.Fresh.NativeReport) && model.WorkspaceDigest(a.Fresh.BackendSnapshot) == model.WorkspaceDigest(b.Fresh.BackendSnapshot)
}
