package containers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

func (p Podman) reviewerReadCurrent(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, delivery model.ChildProductDelivery) (*qualification.Producer, qualification.Store, qualification.ChildProductWitness, qualification.ChildProductControl, error) {
	var s qualification.Store
	var w qualification.ChildProductWitness
	var c qualification.ChildProductControl
	if p.PhysicalStore == nil || entry.Role != "reviewer" || entry.LifecyclePhase != "execute" || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return nil, s, w, c, qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return nil, s, w, c, err
	}
	w, err = producer.ChildProductSourceReadWitness(ctx, entry, current, input)
	if err != nil {
		return nil, s, w, c, err
	}
	s, err = p.qualificationStore(ctx)
	if err != nil {
		return nil, s, w, c, err
	}
	q, err := s.ChildProductSourceReadPolicy(box, delivery, w, time.Now())
	if err != nil || q.FormatVersion != 4 || json.Unmarshal(delivery.Bytes(), &c) != nil {
		return nil, s, w, c, qualification.ErrUntrusted
	}
	local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "reported" || !local.Entry.SamePreparationIdentity(entry) || local.Receipt.ValidateFor(entry) != nil || w.ActualReceipt == nil || qualification.CanonicalDigest(local.Receipt) != qualification.CanonicalDigest(w.ActualReceipt) {
		return nil, s, w, c, qualification.ErrUntrusted
	}
	return producer, s, w, c, nil
}
func (p Podman) reviewerReadUnchanged(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, delivery model.ChildProductDelivery, w qualification.ChildProductWitness, c qualification.ChildProductControl) error {
	_, _, next, selected, err := p.reviewerReadCurrent(ctx, box, entry, current, input, delivery)
	if err != nil || qualification.CanonicalDigest(next) != qualification.CanonicalDigest(w) || qualification.CanonicalDigest(selected) != qualification.CanonicalDigest(c) {
		return qualification.ErrUntrusted
	}
	return nil
}
func (p Podman) ApprovedCellProductReviewerSources(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, delivery model.ChildProductDelivery) (qualification.ReviewerSourceSelection, error) {
	_, _, w, c, err := p.reviewerReadCurrent(ctx, box, entry, current, input, delivery)
	if err != nil {
		return qualification.ReviewerSourceSelection{}, err
	}
	selection, err := c.ReviewerSources()
	if err != nil {
		return selection, err
	}
	return selection, p.reviewerReadUnchanged(ctx, box, entry, current, input, delivery, w, c)
}
func (p Podman) ReadCellProductReviewerArtifact(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject, delivery model.ChildProductDelivery, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage, client qualification.ReviewerArtifactTransport, lease string) (model.WorkflowObservationEnvelope, qualification.ReviewerArtifactCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var noRead qualification.ReviewerArtifactCapture
	if client == nil || lease == "" || !childFactsRootMatches(box, entry, root) {
		return empty, noRead, qualification.ErrUntrusted
	}
	producer, store, w, c, err := p.reviewerReadCurrent(ctx, box, entry, current, input, delivery)
	if err != nil {
		return empty, noRead, err
	}
	envelope, read, err := producer.ReadReviewerTargetArtifact(ctx, call, op, qualification.ChildWorkflowObservationWitness{Authority: store, Sandbox: box, Product: w, CurrentSnapshot: snapshot, SourceReadDelivery: &delivery, Workspace: qualification.TrustedWorkspace{HostRoot: root.HostRoot, ContainerRoot: root.ContainerRoot, WorkspaceDigest: root.Report.RootAttestation, Device: root.RootDevice, Inode: root.RootInode}},
		func(ctx context.Context, target, artifact json.RawMessage, execution string) (json.RawMessage, []byte, error) {
			detail, err := client.ReadWorkflowResult(ctx, target, lease)
			if err != nil {
				return nil, nil, err
			}
			body, err := client.FetchWorkflowArtifact(ctx, execution, artifact, lease)
			return detail, body, err
		})
	if err != nil {
		return empty, noRead, err
	}
	if err = p.reviewerReadUnchanged(ctx, box, entry, current, input, delivery, w, c); err != nil {
		return empty, noRead, err
	}
	return envelope, read, nil
}
func (p Podman) RetainCellProductReviewerArtifact(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, delivery model.ChildProductDelivery, envelope model.WorkflowObservationEnvelope, read qualification.ReviewerArtifactCapture, receipt model.WorkflowObservationReceipt) error {
	producer, _, w, c, err := p.reviewerReadCurrent(ctx, box, entry, current, input, delivery)
	if err != nil {
		return err
	}
	if err = producer.RetainReviewerArtifactRead(ctx, w, c, envelope, read, receipt); err != nil {
		return err
	}
	return p.reviewerReadUnchanged(ctx, box, entry, current, input, delivery, w, c)
}
func (p Podman) ReadCellProductReviewerReceipts(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, delivery model.ChildProductDelivery) (qualification.ReviewerReadOriginals, error) {
	producer, _, w, c, err := p.reviewerReadCurrent(ctx, box, entry, current, input, delivery)
	if err != nil {
		return qualification.ReviewerReadOriginals{}, err
	}
	originals, err := producer.ReadReviewerReceipts(ctx, w, c)
	if err != nil {
		return originals, err
	}
	return originals, p.reviewerReadUnchanged(ctx, box, entry, current, input, delivery, w, c)
}
