package containers

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// Child-specific enrollment proof, after current owning execution completion.
// The backend snapshot is fetched independently by the normal workflow owner;
// this adapter separately rereads local STATE, installed control, native DATA and
// the registered root. It never accepts a supplied capture or parent witness.
func (p Podman) AttestCellWorkflowRole(ctx context.Context, op model.WorkflowRoleOperation, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject, snapshot json.RawMessage) (model.WorkflowRoleEnvelope, error) {
	var empty model.WorkflowRoleEnvelope
	if p.PhysicalStore == nil || p.verifyQualificationMounts(ctx, box.ID) != nil || root.HostRoot == "" || root.ContainerRoot == "" || root.RootDevice == 0 || root.RootInode == 0 || root.Report.Availability != "available" || root.Report.SandboxID != box.ID || root.Report.SandboxGeneration != box.Generation || root.Report.ServiceRegistrationID == nil || *root.Report.ServiceRegistrationID != entry.ServiceRegistrationID || root.Report.SelectionID != entry.Workspace.SelectionID || root.Report.ProjectID != entry.Workspace.ProjectID || root.Report.WorkspaceEpoch != entry.Workspace.WorkspaceEpoch || root.Report.RootAttestation != entry.Workspace.RootAttestation || root.ScopeRevision != entry.Workspace.ScopeRevision {
		return empty, qualification.ErrUntrusted
	}
	local, err := p.PhysicalStore.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "terminal" || !reflect.DeepEqual(&local.Grant, entry.ExecutionGrant) {
		return empty, qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return empty, err
	}
	w, err := producer.CurrentChildProductWitness(ctx, entry, current, input)
	if err != nil {
		return empty, err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return empty, err
	}
	control, err := store.ReadChildProduct(box, entry.PreparationID, w, time.Now())
	if err != nil {
		return empty, err
	}
	capture, err := p.captureCellWorkflowNative(ctx, box, entry, control)
	if err != nil {
		return empty, err
	}
	again, err := p.PhysicalStore.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || !reflect.DeepEqual(local, again) || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return empty, qualification.ErrUntrusted
	}
	witness := qualification.ChildWorkflowRoleWitness{Authority: store, Sandbox: box, Product: w, ExecutionReport: local.Report, ConsumedGrant: local.Grant, CurrentSnapshot: snapshot, Integration: capture.Integration, Reviewer: capture.Reviewer,
		Workspace: qualification.TrustedWorkspace{HostRoot: root.HostRoot, ContainerRoot: root.ContainerRoot, WorkspaceDigest: root.Report.RootAttestation, Device: root.RootDevice, Inode: root.RootInode}}
	if capture.Result != nil {
		witness.Result = *capture.Result
	}
	return producer.AttestChildWorkflowRole(op, witness, time.Now().UTC())
}
