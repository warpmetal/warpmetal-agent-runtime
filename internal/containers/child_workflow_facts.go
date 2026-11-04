package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

func childFactsRootMatches(box model.Sandbox, e model.CellServiceV3, r workspacecatalog.RegisteredProject) bool {
	return r.HostRoot != "" && r.ContainerRoot != "" && r.RootDevice != 0 && r.RootInode != 0 && r.Report.Availability == "available" && r.Report.SandboxID == box.ID && r.Report.SandboxGeneration == box.Generation && r.Report.ServiceRegistrationID != nil && *r.Report.ServiceRegistrationID == e.ServiceRegistrationID && r.Report.SelectionID == e.Workspace.SelectionID && r.Report.ProjectID == e.Workspace.ProjectID && r.Report.WorkspaceEpoch == e.Workspace.WorkspaceEpoch && r.Report.RootAttestation == e.Workspace.RootAttestation && r.ScopeRevision == e.Workspace.ScopeRevision
}

// An independently current kernel registration, never the caller identity
// copied from a chosen paid operation. Stale registrations do not qualify.
func (p Podman) childFactsProcess(ctx context.Context, e model.CellServiceV3, binary string) (state.PhysicalSubject, []byte, error) {
	var empty state.PhysicalSubject
	if p.PhysicalStore == nil || p.PhysicalProcesses == nil {
		return empty, nil, qualification.ErrUntrusted
	}
	rows, err := p.PhysicalStore.PhysicalProcesses(ctx)
	if err != nil {
		return empty, nil, err
	}
	var selected state.PhysicalSubject
	var original []byte
	for _, raw := range rows {
		var n physicalgate.NativeRegistration
		if model.DecodePhysicalClosed(raw, &n) != nil {
			return empty, nil, qualification.ErrUntrusted
		}
		c := n.Caller
		if c.SandboxID != e.SandboxID || c.SandboxGeneration != e.SandboxGeneration || c.NativeInstance != e.Instance {
			continue
		}
		actual, current, err := p.PhysicalProcesses.CurrentRegistrationOriginal(ctx, c.Subject())
		if err != nil {
			continue
		}
		if original != nil || current.Native.ExecutableDigest != binary {
			return empty, nil, qualification.ErrUntrusted
		}
		selected, original = c.Subject(), actual
	}
	if original == nil {
		return empty, nil, qualification.ErrUntrusted
	}
	return selected, original, nil
}

// Frozen node coordinator boundary. currentSnapshot is independently fetched
// BASE backend state; candidate extension is reconstructed by the ROOT owner.
func (p Podman) AttestCellWorkflowFacts(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, call model.WorkflowFactsRequest, op model.WorkflowFactsOperation, root workspacecatalog.RegisteredProject, currentSnapshot json.RawMessage) (model.WorkflowFactsEnvelope, error) {
	var empty model.WorkflowFactsEnvelope
	if p.PhysicalStore == nil || !childFactsRootMatches(box, entry, root) || p.verifyQualificationMounts(ctx, box.ID) != nil {
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
	if err != nil || control.Generation.Policy == nil {
		return empty, qualification.ErrUntrusted
	}
	subject, process, err := p.childFactsProcess(ctx, entry, control.Generation.Policy.Payload.Applicability.Native.BinarySHA256)
	if err != nil {
		return empty, err
	}
	native, err := p.captureCellWorkflowNative(ctx, box, entry, control)
	if err != nil {
		return empty, err
	}
	envelope, err := producer.AttestChildWorkflowFacts(ctx, call, op, qualification.ChildWorkflowFactsWitness{Authority: store, Sandbox: box, Product: w, ExecutionReport: local.Report, ConsumedGrant: local.Grant, CurrentSnapshot: currentSnapshot, Workspace: qualification.TrustedWorkspace{HostRoot: root.HostRoot, ContainerRoot: root.ContainerRoot, WorkspaceDigest: root.Report.RootAttestation, Device: root.RootDevice, Inode: root.RootInode}, Native: native}, p.PhysicalStore, subject)
	if err != nil {
		return empty, err
	}
	again, err := p.PhysicalStore.CellV3Execution(ctx, entry.PreparationID)
	capture, e := p.captureCellWorkflowNative(ctx, box, entry, control)
	subjectAgain, processAgain, e2 := p.childFactsProcess(ctx, entry, control.Generation.Policy.Payload.Applicability.Native.BinarySHA256)
	if err != nil || e != nil || e2 != nil || !reflect.DeepEqual(local, again) || !reflect.DeepEqual(native, capture) || subject != subjectAgain || !bytes.Equal(process, processAgain) || p.verifyQualificationMounts(ctx, box.ID) != nil || ctx.Err() != nil {
		return empty, qualification.ErrUntrusted
	}
	return envelope, nil
}

// Read-only outcome for the normal coordinator. It contains original native
// bytes and path/digest facts only, never result/review/acceptance decisions.
func (p Podman) ObserveCellWorkflowOutcome(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject) (qualification.ChildWorkflowNativeCapture, error) {
	var empty qualification.ChildWorkflowNativeCapture
	if p.PhysicalStore == nil || !childFactsRootMatches(box, entry, root) || p.verifyQualificationMounts(ctx, box.ID) != nil {
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
	if err != nil || control.Generation.Policy == nil {
		return empty, qualification.ErrUntrusted
	}
	_, before, err := p.childFactsProcess(ctx, entry, control.Generation.Policy.Payload.Applicability.Native.BinarySHA256)
	if err != nil {
		return empty, err
	}
	capture, err := p.captureCellWorkflowNative(ctx, box, entry, control)
	if err != nil {
		return empty, err
	}
	_, after, e := p.childFactsProcess(ctx, entry, control.Generation.Policy.Payload.Applicability.Native.BinarySHA256)
	again, e2 := p.PhysicalStore.CellV3Execution(ctx, entry.PreparationID)
	latest, e3 := store.ReadChildProduct(box, entry.PreparationID, w, time.Now())
	if e != nil || e2 != nil || e3 != nil || !reflect.DeepEqual(control, latest) || !bytes.Equal(before, after) || !reflect.DeepEqual(local, again) || p.verifyQualificationMounts(ctx, box.ID) != nil || ctx.Err() != nil {
		return empty, qualification.ErrUntrusted
	}
	return capture, nil
}
