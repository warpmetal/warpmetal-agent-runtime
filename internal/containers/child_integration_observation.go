package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
	"reflect"
	"time"
)

// A fixed terminal owner read shared by request observation and attestation.
// Neither caller can replace the current process, local grant or native capture.
type cellIntegrationTerminal struct {
	producer *qualification.Producer
	witness  qualification.ChildWorkflowFactsWitness
	control  qualification.ChildProductControl
	local    *state.LocalCellV3Execution
	native   qualification.ChildWorkflowNativeCapture
	subject  state.PhysicalSubject
	process  []byte
}

func (p Podman) readCellIntegrationTerminal(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject, currentSnapshot json.RawMessage) (cellIntegrationTerminal, error) {
	if p.PhysicalStore == nil || !childFactsRootMatches(box, entry, root) || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return cellIntegrationTerminal{}, qualification.ErrUntrusted
	}
	local, err := p.PhysicalStore.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "terminal" || !reflect.DeepEqual(&local.Grant, entry.ExecutionGrant) {
		return cellIntegrationTerminal{}, qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return cellIntegrationTerminal{}, err
	}
	w, err := producer.CurrentChildProductWitness(ctx, entry, current, input)
	if err != nil {
		return cellIntegrationTerminal{}, err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return cellIntegrationTerminal{}, err
	}
	control, err := store.ReadChildProduct(box, entry.PreparationID, w, time.Now())
	if err != nil || control.Generation.Policy == nil {
		return cellIntegrationTerminal{}, qualification.ErrUntrusted
	}
	subject, process, err := p.childFactsProcess(ctx, entry, control.Generation.Policy.Payload.Applicability.Native.BinarySHA256)
	if err != nil {
		return cellIntegrationTerminal{}, err
	}
	native, err := p.captureCellWorkflowNative(ctx, box, entry, control)
	if err != nil {
		return cellIntegrationTerminal{}, err
	}
	return cellIntegrationTerminal{producer, qualification.ChildWorkflowFactsWitness{Authority: store, Sandbox: box, Product: w, ExecutionReport: local.Report, ConsumedGrant: local.Grant, CurrentSnapshot: currentSnapshot, Workspace: qualification.TrustedWorkspace{HostRoot: root.HostRoot, ContainerRoot: root.ContainerRoot, WorkspaceDigest: root.Report.RootAttestation, Device: root.RootDevice, Inode: root.RootInode}, Native: native}, control, local, native, subject, process}, nil
}

func (p Podman) recheckCellIntegrationTerminal(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, original cellIntegrationTerminal) error {
	again, err := p.PhysicalStore.CellV3Execution(ctx, entry.PreparationID)
	capture, e := p.captureCellWorkflowNative(ctx, box, entry, original.control)
	subjectAgain, processAgain, e2 := p.childFactsProcess(ctx, entry, original.control.Generation.Policy.Payload.Applicability.Native.BinarySHA256)
	if err != nil || e != nil || e2 != nil || !reflect.DeepEqual(original.local, again) || !reflect.DeepEqual(original.native, capture) || original.subject != subjectAgain || !bytes.Equal(original.process, processAgain) || p.verifyQualificationMounts(ctx, box.ID) != nil || ctx.Err() != nil {
		return qualification.ErrUntrusted
	}
	return nil
}

// Observe only the existing canonical integration observation. The normal
// operation request comes next; the later signer reads all owner facts again.
func (p Podman) ObserveCellProductIntegration(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject, currentSnapshot json.RawMessage) (json.RawMessage, error) {
	original, err := p.readCellIntegrationTerminal(ctx, box, entry, current, input, root, currentSnapshot)
	if err != nil {
		return nil, err
	}
	observed, err := original.producer.ObserveChildProductIntegration(ctx, original.witness, p.PhysicalStore, original.subject)
	if err != nil {
		return nil, err
	}
	if err = p.recheckCellIntegrationTerminal(ctx, box, entry, original); err != nil {
		return nil, err
	}
	return observed, nil
}

// Fixed protected terminal capture and independently current process/lifecycle.
func (p Podman) AttestCellProductIntegration(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, root workspacecatalog.RegisteredProject, currentSnapshot json.RawMessage) (model.WorkflowObservationEnvelope, error) {
	var empty model.WorkflowObservationEnvelope
	original, err := p.readCellIntegrationTerminal(ctx, box, entry, current, input, root, currentSnapshot)
	if err != nil {
		return empty, err
	}
	envelope, err := original.producer.AttestChildProductIntegration(ctx, call, op, original.witness, p.PhysicalStore, original.subject)
	if err != nil {
		return empty, err
	}
	if err = p.recheckCellIntegrationTerminal(ctx, box, entry, original); err != nil {
		return empty, err
	}
	return envelope, nil
}
