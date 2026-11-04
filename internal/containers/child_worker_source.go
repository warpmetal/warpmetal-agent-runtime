package containers

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Worker reads follow execute-control publication and precede prompt admission.
// This never uses or relaxes the reviewer's provisional delivery path.
func (p Podman) publishedChildSourceCurrent(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte) (*qualification.Producer, qualification.Store, qualification.ChildProductWitness, qualification.ChildProductControl, error) {
	var store qualification.Store
	var w qualification.ChildProductWitness
	var c qualification.ChildProductControl
	if entry.LifecyclePhase != "execute" || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return nil, store, w, c, qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return nil, store, w, c, err
	}
	w, err = producer.CurrentChildProductWitness(ctx, entry, current, input)
	if err != nil {
		return nil, store, w, c, err
	}
	store, err = p.qualificationStore(ctx)
	if err != nil {
		return nil, store, w, c, err
	}
	c, err = store.ReadChildProduct(box, entry.PreparationID, w, time.Now())
	if err != nil {
		return nil, store, w, c, err
	}
	if c.Generation.Policy == nil {
		return nil, store, w, c, qualification.ErrUntrusted
	}
	expectedRole := map[string]string{"coding_worker": "worker", "business_worker": "worker", "integrator": "worker", "reviewer": "reviewer"}[c.Generation.Policy.Payload.Purpose]
	if expectedRole == "" || entry.Role != expectedRole {
		return nil, store, w, c, qualification.ErrUntrusted
	}
	return producer, store, w, c, nil
}

func (p Podman) workerSourceCurrent(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte) (*qualification.Producer, qualification.Store, qualification.ChildProductWitness, qualification.ChildProductControl, error) {
	producer, store, w, c, err := p.publishedChildSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return nil, store, w, c, err
	}
	if _, err = c.ApprovedWorkerSourceReads(); err != nil {
		if err == qualification.ErrWorkerSourceNotApplicable && p.workerSourceUnchanged(ctx, box, w, c, store) != nil {
			return nil, store, w, c, qualification.ErrUntrusted
		}
		return nil, store, w, c, err
	}
	return producer, store, w, c, nil
}

func (p Podman) workerSourceUnchanged(ctx context.Context, box model.Sandbox, w qualification.ChildProductWitness, c qualification.ChildProductControl, store qualification.Store) error {
	again, err := store.ReadChildProduct(box, w.Preparation.PreparationID, w, time.Now())
	if err != nil || !reflect.DeepEqual(c, again) || p.verifyQualificationMounts(ctx, box.ID) != nil || ctx.Err() != nil {
		return qualification.ErrUntrusted
	}
	return nil
}

func (p Podman) ApprovedCellProductSourceReads(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte) ([]qualification.ChildApprovedSourceRead, error) {
	_, store, w, c, err := p.workerSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return nil, err
	}
	reads, err := c.ApprovedWorkerSourceReads()
	if err != nil {
		return nil, err
	}
	if err = p.workerSourceUnchanged(ctx, box, w, c, store); err != nil {
		return nil, err
	}
	return reads, nil
}

func (p Podman) ReadCellProductApprovedSource(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root qualification.TrustedWorkspace, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var noRead qualification.WorkflowSourceCapture
	producer, store, w, c, err := p.workerSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return empty, noRead, err
	}
	if root.HostRoot == "" || root.ContainerRoot == "" || root.Device == 0 || root.Inode == 0 {
		return empty, noRead, qualification.ErrUntrusted
	}
	envelope, read, err := producer.ReadWorkerSource(ctx, call, op, qualification.ChildWorkflowObservationWitness{Authority: store, Sandbox: box, Product: w, CurrentSnapshot: snapshot, Workspace: root})
	if err != nil {
		return empty, noRead, err
	}
	if err = p.workerSourceUnchanged(ctx, box, w, c, store); err != nil {
		return empty, noRead, err
	}
	return envelope, read, nil
}

func (p Podman) RetainCellProductSourceRead(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, envelope model.WorkflowObservationEnvelope, read qualification.WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
	producer, store, w, c, err := p.workerSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return err
	}
	if err = producer.RetainWorkerSourceRead(ctx, w, c, envelope, read, receipt); err != nil {
		return err
	}
	return p.workerSourceUnchanged(ctx, box, w, c, store)
}

// Return the first protected own originals, never caller-supplied receipt IDs.
// No ACK file is created or signature issued by this read-only path.
func (p Podman) ReadCellProductSourceReceipts(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte) ([]qualification.ChildSourceReadOriginal, error) {
	producer, store, w, c, err := p.workerSourceCurrent(ctx, box, entry, current, input)
	if err != nil {
		return nil, err
	}
	originals, err := producer.ReadWorkerSourceReceipts(ctx, w, c)
	if err != nil {
		return nil, err
	}
	if err = p.workerSourceUnchanged(ctx, box, w, c, store); err != nil {
		return nil, err
	}
	return originals, nil
}
