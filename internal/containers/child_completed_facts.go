package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

const ManagedSupervisorChildCompletedCapture ManagedSupervisorAction = "child-completed-capture"

func (p Podman) captureCompletedChild(ctx context.Context, box model.Sandbox, entry model.CellServiceV3) (model.ChildCompletedCapture, error) {
	var out struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Command       string                      `json:"command"`
		Status        string                      `json:"status"`
		Capture       model.ChildCompletedCapture `json:"capture"`
	}
	request, _ := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": box.ID, "instance": entry.Instance, "profileId": entry.Profile.ProfileID, "nativeSessionId": entry.NativeSessionID})
	raw, _, err := p.ExecManagedSupervisor(ctx, box.ID, ManagedSupervisorChildCompletedCapture, request)
	if err != nil {
		return out.Capture, err
	}
	if len(raw) > 65536 || model.DecodeControllerTransportReceipt(raw, "child-completed-capture", &out) != nil {
		return model.ChildCompletedCapture{}, qualification.ErrUntrusted
	}
	return out.Capture, nil
}

func (p Podman) AttestCompletedCellWorkflowFacts(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, call model.WorkflowFactsRequest, op model.WorkflowFactsOperation, root workspacecatalog.RegisteredProject, snapshot json.RawMessage, first model.WorkflowFactsEnvelope) (model.WorkflowFactsEnvelope, error) {
	var empty model.WorkflowFactsEnvelope
	if p.PhysicalStore == nil || !childFactsRootMatches(box, entry, root) || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return empty, qualification.ErrUntrusted
	}
	local, err := p.PhysicalStore.CellV3Execution(ctx, entry.PreparationID)
	prepared, e := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || e != nil || local == nil || prepared == nil || local.Phase != "terminal" || prepared.Phase != "reported" || !prepared.Entry.SamePreparationIdentity(entry) || !reflect.DeepEqual(&local.Grant, entry.ExecutionGrant) {
		return empty, qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return empty, err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return empty, err
	}
	h, err := producer.ReadCompletedChildFactsHistory(ctx, store, box, entry, current, input, first)
	if err != nil {
		return empty, err
	}
	subject, process, err := p.childFactsProcess(ctx, entry, h.NativeBinaryDigest())
	if err != nil {
		return empty, err
	}
	native, err := p.captureCompletedChild(ctx, box, entry)
	if err != nil || native.ValidateFor(entry, prepared.Receipt, local.ParentSessionID, root.ContainerRoot, time.Now()) != nil {
		return empty, qualification.ErrUntrusted
	}
	proof, err := producer.AttestCompletedChildWorkflowFacts(ctx, call, op, qualification.CompletedChildWorkflowFactsWitness{Authority: store, Sandbox: box, Entry: entry, Manifest: current, Input: input, CurrentSnapshot: snapshot, Workspace: qualification.TrustedWorkspace{HostRoot: root.HostRoot, ContainerRoot: root.ContainerRoot, WorkspaceDigest: root.Report.RootAttestation, Device: root.RootDevice, Inode: root.RootInode}, Native: native, First: first}, p.PhysicalStore, subject)
	if err != nil {
		return empty, err
	}
	again, e := p.PhysicalStore.CellV3Execution(ctx, entry.PreparationID)
	capture, e2 := p.captureCompletedChild(ctx, box, entry)
	subjectAgain, processAgain, e3 := p.childFactsProcess(ctx, entry, h.NativeBinaryDigest())
	if e != nil || e2 != nil || e3 != nil || capture.ValidateFor(entry, prepared.Receipt, local.ParentSessionID, root.ContainerRoot, time.Now()) != nil {
		return empty, qualification.ErrUntrusted
	}
	capture.ObservedAt = native.ObservedAt
	if !reflect.DeepEqual(local, again) || !reflect.DeepEqual(capture, native) || subject != subjectAgain || !bytes.Equal(process, processAgain) || p.verifyQualificationMounts(ctx, box.ID) != nil || ctx.Err() != nil {
		return empty, qualification.ErrUntrusted
	}
	return proof, nil
}
