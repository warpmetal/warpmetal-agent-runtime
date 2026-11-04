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

const ManagedSupervisorChildPreparedCapture ManagedSupervisorAction = "child-prepared-capture"

func (p Podman) capturePreparedChild(ctx context.Context, box model.Sandbox, entry model.CellServiceV3) (model.ChildPreparedCapture, error) {
	var result struct {
		SchemaVersion int                        `json:"schemaVersion"`
		Command       string                     `json:"command"`
		Status        string                     `json:"status"`
		Capture       model.ChildPreparedCapture `json:"capture"`
	}
	request, _ := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": box.ID, "instance": entry.Instance, "profileId": entry.Profile.ProfileID, "nativeSessionId": entry.NativeSessionID})
	raw, _, err := p.ExecManagedSupervisor(ctx, box.ID, ManagedSupervisorChildPreparedCapture, request)
	if err != nil {
		return result.Capture, err
	}
	if len(raw) > 65536 || model.DecodeControllerTransportReceipt(raw, "child-prepared-capture", &result) != nil {
		return model.ChildPreparedCapture{}, qualification.ErrUntrusted
	}
	return result.Capture, nil
}

// Only the pending reviewer's identity is observed here. No prompt, execution
// record, consumed grant or completed-child witness is created. Backend owns
// the prepared lease's dynamic read-only restriction.
func (p Podman) AttestPreparedCellWorkflowRole(ctx context.Context, op model.WorkflowRoleOperation, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, delivery model.ChildProductDelivery, root workspacecatalog.RegisteredProject, snapshot json.RawMessage) (model.WorkflowRoleEnvelope, error) {
	var empty model.WorkflowRoleEnvelope
	if p.PhysicalStore == nil || entry.Role != "reviewer" || entry.LifecyclePhase != "execute" || !childFactsRootMatches(box, entry, root) || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return empty, qualification.ErrUntrusted
	}
	local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "reported" || !local.Entry.SamePreparationIdentity(entry) || local.Receipt.ValidateFor(entry) != nil || local.ParentSessionID == "" || local.WorktreeDir != root.ContainerRoot {
		return empty, qualification.ErrUntrusted
	}
	execution, err := p.PhysicalStore.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || execution != nil {
		return empty, qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return empty, err
	}
	w, err := producer.ChildProductSourceReadWitness(ctx, entry, current, input)
	if err != nil {
		return empty, err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return empty, err
	}
	q, err := store.ChildProductSourceReadPolicy(box, delivery, w, time.Now())
	if err != nil || q.FormatVersion != 4 {
		return empty, qualification.ErrUntrusted
	}
	subject, process, err := p.childFactsProcess(ctx, entry, q.Applicability.Native.BinarySHA256)
	if err != nil {
		return empty, err
	}
	native, err := p.capturePreparedChild(ctx, box, entry)
	if err != nil || native.ValidateFor(entry, local.Receipt, local.ParentSessionID, root.ContainerRoot, time.Now()) != nil {
		return empty, qualification.ErrUntrusted
	}
	next, err := producer.ChildProductSourceReadWitness(ctx, entry, current, input)
	if err != nil || qualification.CanonicalDigest(next) != qualification.CanonicalDigest(w) {
		return empty, qualification.ErrUntrusted
	}
	againPolicy, err := store.ChildProductSourceReadPolicy(box, delivery, next, time.Now())
	if err != nil || qualification.CanonicalDigest(againPolicy) != qualification.CanonicalDigest(q) {
		return empty, qualification.ErrUntrusted
	}
	again, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || !reflect.DeepEqual(local, again) {
		return empty, qualification.ErrUntrusted
	}
	execution, err = p.PhysicalStore.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || execution != nil {
		return empty, qualification.ErrUntrusted
	}
	latest, err := p.capturePreparedChild(ctx, box, entry)
	if err != nil || latest.ValidateFor(entry, local.Receipt, local.ParentSessionID, root.ContainerRoot, time.Now()) != nil {
		return empty, qualification.ErrUntrusted
	}
	comparison := latest
	comparison.ObservedAt = native.ObservedAt
	if !reflect.DeepEqual(comparison, native) {
		return empty, qualification.ErrUntrusted
	}
	currentProcess, _, err := p.PhysicalProcesses.CurrentRegistrationOriginal(ctx, subject)
	if err != nil || !bytes.Equal(process, currentProcess) || p.verifyQualificationMounts(ctx, box.ID) != nil || ctx.Err() != nil {
		return empty, qualification.ErrUntrusted
	}
	return producer.AttestPreparedChildWorkflowRole(op, qualification.PreparedChildWorkflowRoleWitness{Authority: store, Sandbox: box, Product: next, Delivery: delivery, Receipt: local.Receipt, ParentSessionID: local.ParentSessionID, CurrentSnapshot: snapshot,
		Workspace: qualification.TrustedWorkspace{HostRoot: root.HostRoot, ContainerRoot: root.ContainerRoot, WorkspaceDigest: root.Report.RootAttestation, Device: root.RootDevice, Inode: root.RootInode}, Native: latest}, time.Now().UTC())
}
