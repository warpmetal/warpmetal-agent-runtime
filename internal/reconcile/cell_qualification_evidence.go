package reconcile

import (
	"context"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type cellQualificationProducer interface {
	BeginCellQualificationEvidence(context.Context, model.Sandbox, model.CellServiceV3, qualification.TrustedWorkspace) error
	CompleteCellQualificationEvidence(context.Context, model.Sandbox, model.CellServiceV3, qualification.TrustedWorkspace, model.PreparedReceipt, model.CellServiceReportV1, []byte) error
}

func (r *Reconciler) cellQualificationEvidence(ctx context.Context, entry model.CellServiceV3, execution *state.LocalCellV3Execution) error {
	verifier, enabled := r.ManagedRuntime.(cellQualificationVerifier)
	if !enabled || !verifier.CellQualificationEnabled() {
		return nil
	}
	producer, ok := r.ManagedRuntime.(cellQualificationProducer)
	if !ok {
		return nil
	}
	box, e := r.Store.Sandbox(ctx, entry.SandboxID)
	if e != nil {
		return e
	}
	if box == nil {
		return errors.New("qualification evidence sandbox missing")
	}
	if product, ok := r.ManagedRuntime.(cellProductRuntime); ok {
		needed, err := product.NeedsCellProductControl(ctx, model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ImageDigest: box.ImageDigest, Cell: true}, entry)
		if err != nil {
			return err
		}
		// PRODUCT has separate original-byte/effect evidence; it cannot produce
		// shell2 qualification credit, even after a successful child terminal.
		if needed {
			return nil
		}
	}
	project, e := r.lookupCellProject(ctx, cellV2View(entry))
	if e != nil {
		return e
	}
	if project == nil {
		return errors.New("qualification evidence workspace missing")
	}
	workspace := qualification.TrustedWorkspace{HostRoot: project.HostRoot, ContainerRoot: project.ContainerRoot, WorkspaceDigest: entry.ExecutionGrant.WorkspaceDigest, Device: project.RootDevice, Inode: project.RootInode}
	sandbox := model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ImageDigest: box.ImageDigest, Cell: true}
	if execution == nil {
		return producer.BeginCellQualificationEvidence(ctx, sandbox, entry, workspace)
	}
	if execution.Phase != "terminal" || execution.Report.Child == nil || execution.Report.Child.Outcome == nil || *execution.Report.Child.Outcome != "succeeded" {
		return nil
	}
	operation, e := r.Store.CellV3Operation(ctx, entry.PreparationID)
	if e != nil {
		return e
	}
	if operation == nil || entry.ValidateExecutionAuthority(operation.Receipt) != nil {
		return errors.New("qualification evidence receipt changed")
	}
	return producer.CompleteCellQualificationEvidence(ctx, sandbox, entry, workspace, operation.Receipt, execution.Report, execution.EffectJSON)
}
