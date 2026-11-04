package containers

import (
	"context"
	"encoding/json"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

func (p Podman) integrationSourceCurrent(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte) (*qualification.Producer, qualification.Store, qualification.ChildProductWitness, qualification.ChildProductControl, error) {
	producer, store, w, c, err := p.publishedChildSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return nil, store, w, c, err
	}
	if _, err = c.IntegrationTarget(); err != nil {
		if err == qualification.ErrIntegrationSourceNotApplicable && p.workerSourceUnchanged(ctx, box, w, c, store) != nil {
			return nil, store, w, c, qualification.ErrUntrusted
		}
		return nil, store, w, c, err
	}
	return producer, store, w, c, nil
}

func (p Podman) IntegrationCellProductTarget(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte) (qualification.ChildIntegrationTarget, error) {
	_, store, w, c, err := p.integrationSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return qualification.ChildIntegrationTarget{}, err
	}
	target, err := c.IntegrationTarget()
	if err != nil {
		return target, err
	}
	if err = p.workerSourceUnchanged(ctx, box, w, c, store); err != nil {
		return qualification.ChildIntegrationTarget{}, err
	}
	return target, nil
}
func (p Podman) StageCellProductIntegrationTarget(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root qualification.TrustedWorkspace, targetDetail json.RawMessage, artifact []byte) error {
	producer, store, w, c, err := p.integrationSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return err
	}
	if err = producer.StageIntegrationTarget(ctx, store, box, w, root, targetDetail, artifact); err != nil {
		return err
	}
	return p.workerSourceUnchanged(ctx, box, w, c, store)
}
func (p Podman) ReadCellProductIntegrationSource(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root qualification.TrustedWorkspace, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var noRead qualification.WorkflowSourceCapture
	producer, store, w, c, err := p.integrationSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return empty, noRead, err
	}
	envelope, read, err := producer.ReadIntegrationSource(ctx, call, op, qualification.ChildWorkflowObservationWitness{Authority: store, Sandbox: box, Product: w, CurrentSnapshot: snapshot, Workspace: root})
	if err != nil {
		return empty, noRead, err
	}
	if err = p.workerSourceUnchanged(ctx, box, w, c, store); err != nil {
		return empty, noRead, err
	}
	return envelope, read, nil
}
func (p Podman) RetainCellProductIntegrationSourceRead(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, envelope model.WorkflowObservationEnvelope, read qualification.WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
	producer, store, w, c, err := p.integrationSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return err
	}
	if err = producer.RetainIntegrationSourceRead(ctx, w, c, envelope, read, receipt); err != nil {
		return err
	}
	return p.workerSourceUnchanged(ctx, box, w, c, store)
}
func (p Podman) ReadCellProductIntegrationSourceReceipts(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte) ([]qualification.ChildSourceReadOriginal, error) {
	producer, store, w, c, err := p.integrationSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return nil, err
	}
	reads, err := producer.ReadIntegrationSourceReceipts(ctx, w, c)
	if err != nil {
		return nil, err
	}
	if err = p.workerSourceUnchanged(ctx, box, w, c, store); err != nil {
		return nil, err
	}
	return reads, nil
}
func (p Podman) SealCellProductIntegrationDelivery(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root qualification.TrustedWorkspace) error {
	producer, store, w, c, err := p.integrationSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return err
	}
	if err = producer.SealIntegrationDelivery(ctx, store, box, w, root); err != nil {
		return err
	}
	return p.workerSourceUnchanged(ctx, box, w, c, store)
}
