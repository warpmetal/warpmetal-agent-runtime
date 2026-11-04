package reconcile

import (
	"context"
	"errors"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type cellQualificationVerifier interface {
	CellQualificationEnabled() bool
	VerifyCellQualification(context.Context, model.Sandbox, model.CellServiceV3, string) (string, string, error)
}

type cellQualificationAuthorizationObserver interface {
	CaptureCellQualificationAuthorization(context.Context, model.Sandbox, model.CellServiceV3, model.PreparedReceipt, string) error
}

func (r *Reconciler) captureCellQualificationAuthorization(ctx context.Context, entry model.CellServiceV3, receipt model.PreparedReceipt) error {
	observer, ok := r.ManagedRuntime.(cellQualificationAuthorizationObserver)
	if !ok {
		return nil
	}
	box, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil || box == nil || box.Generation != entry.SandboxGeneration || box.ObservedGeneration != entry.SandboxGeneration || box.ObservedState != "running" {
		return errors.New("qualification header sandbox is not current")
	}
	local, err := r.Store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "reported" {
		return errors.New("qualification header requires acknowledged preparation")
	}
	return observer.CaptureCellQualificationAuthorization(ctx, model.Sandbox{ID: box.ID, Generation: box.Generation, ImageDigest: box.ImageDigest, Cell: true}, entry, receipt, local.WorktreeDir)
}

// verifyCellQualification joins the existing authoritative tuple and backend
// receipt/grant to the locally pinned policy. It creates no backend authority.
func (r *Reconciler) verifyCellQualification(ctx context.Context, entry model.CellServiceV3) error {
	if entry.DesiredState != "active" {
		return nil
	} // cancellation remains available
	verifier, ok := r.ManagedRuntime.(cellQualificationVerifier)
	pinned, err := r.Store.HasCellQualificationPin(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if pinned && (!ok || !verifier.CellQualificationEnabled()) {
		return errors.New("qualification pin requires retained fixture configuration")
	}
	if !ok {
		return nil
	}
	if !verifier.CellQualificationEnabled() {
		return nil
	}
	local, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return err
	}
	if local == nil {
		return errors.New("qualification sandbox missing")
	}
	if local.Generation != entry.SandboxGeneration || local.ObservedGeneration != entry.SandboxGeneration || local.ImageDigest == "" {
		return errors.New("qualification sandbox identity changed")
	}
	operation, err := r.Store.CellV3Operation(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if operation == nil {
		return errors.New("qualification preparation missing")
	}
	workspace := operation.WorktreeDir
	if workspace == "" {
		project, err := r.lookupCellProject(ctx, cellV2View(entry))
		if err != nil {
			return err
		}
		if project == nil {
			return errors.New("qualification workspace missing")
		}
		workspace = project.ContainerRoot
	}
	box := model.Sandbox{ID: local.ID, Generation: entry.SandboxGeneration, ImageDigest: local.ImageDigest, Cell: true}
	tupleDigest, policyDigest, err := verifier.VerifyCellQualification(ctx, box, entry, workspace)
	if err != nil {
		return err
	}
	if policyDigest == "" {
		return nil
	} // only explicit disabled operator path
	return r.Store.PinCellQualification(ctx, entry.PreparationID, tupleDigest, policyDigest)
}
