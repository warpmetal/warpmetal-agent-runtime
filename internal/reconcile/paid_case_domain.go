package reconcile

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type paidCaseDomainRuntime interface {
	PaidCaseDomainRequired(context.Context, model.Manifest) (bool, error)
	PreparePaidCaseDomainAdoption(context.Context, model.Manifest) (model.PaidCaseDomainAdoptionRequest, error)
	PreparePaidCaseDomainObservation(context.Context, model.Manifest, model.PaidCaseDomainAdoptionRequest) (model.PaidCaseDomainObservationRequest, error)
	FetchPaidCaseDomainOriginals(context.Context, model.Manifest, model.PaidCaseDomainAdoptionRequest, json.RawMessage, func(context.Context, string) ([]byte, error)) error
	AcceptPaidCaseDomainAdoption(context.Context, model.Manifest, model.PaidCaseDomainAdoptionRequest, json.RawMessage) (json.RawMessage, error)
	ConfirmPaidCaseDomainAcceptance(context.Context, model.Manifest, model.PaidCaseDomainAdoptionRequest, json.RawMessage, json.RawMessage) error
}
type paidCaseDomainControl interface {
	ObservePaidCaseDomain(context.Context, model.PaidCaseDomainObservationRequest) (json.RawMessage, error)
	PaidCaseDomainOriginal(context.Context, string) ([]byte, error)
	AdoptPaidCaseDomain(context.Context, model.PaidCaseDomainAdoptionRequest) (json.RawMessage, error)
	AcceptPaidCaseDomain(context.Context, model.PaidCaseDomainAcceptanceRequest) (json.RawMessage, error)
}

// Normal pre-credential/prebootstrap caller. These metadata POSTs neither grant
// execution nor replace installed trust/current policy/financial holds. A lost
// response or refused original stops this invocation; only explicit owning replay
// can resume FIRST originals, and acceptance alone cannot release physical cap1.
func (r *Reconciler) ensurePaidCaseDomain(ctx context.Context, current model.Manifest) error {
	runtime, ok := r.ManagedRuntime.(paidCaseDomainRuntime)
	if !ok {
		return nil
	} // Existing non-qualification runtimes have no paid path.
	required, err := runtime.PaidCaseDomainRequired(ctx, current)
	if err != nil || !required {
		return err
	}
	control, ok := r.ManagedControl.(paidCaseDomainControl)
	if !ok || r.Store == nil {
		return errors.New("paid domain owning bootstrap transport absent")
	}
	stable := func() bool {
		actual := r.currentAuthorityManifest()
		expected := model.WorkspaceDigest(current)
		return expected != "" && ctx.Err() == nil && actual.ServerID == current.ServerID && actual.DesiredRevision == current.DesiredRevision && model.WorkspaceDigest(actual) == expected
	}
	if !stable() {
		return errors.New("paid domain current manifest changed")
	}
	request, err := runtime.PreparePaidCaseDomainAdoption(ctx, current)
	if err != nil {
		return err
	}
	observation, err := runtime.PreparePaidCaseDomainObservation(ctx, current, request)
	if err != nil {
		return err
	}
	observed, err := control.ObservePaidCaseDomain(ctx, observation)
	if err != nil {
		return err
	}
	if model.WorkspaceDigest(observed) != model.WorkspaceDigest(observation.RuntimeReadback) {
		return errors.New("paid domain observation original changed")
	}
	if !stable() {
		return errors.New("paid domain scope changed after original observation")
	}
	adoption, err := control.AdoptPaidCaseDomain(ctx, request)
	if err != nil {
		return err
	}
	if !stable() {
		return errors.New("paid domain scope changed after backend mapping commit")
	}
	if err = runtime.FetchPaidCaseDomainOriginals(ctx, current, request, adoption, control.PaidCaseDomainOriginal); err != nil {
		return err
	}
	financialControl, fok := r.ManagedControl.(interface {
		PaidCaseFinancialOriginalIndex(context.Context, string) (json.RawMessage, error)
	})
	financialRuntime, rok := r.ManagedRuntime.(interface {
		AcquirePaidFinancialOriginals(context.Context, model.Manifest, model.PaidCaseDomainAdoptionRequest, json.RawMessage, json.RawMessage, func(context.Context, string) ([]byte, error)) error
	})
	if !fok || !rok {
		return errors.New("committed financial-original catalog consumer absent")
	}
	catalog, err := financialControl.PaidCaseFinancialOriginalIndex(ctx, request.DemandManifestDigest)
	if err != nil {
		return err
	}
	if err = financialRuntime.AcquirePaidFinancialOriginals(ctx, current, request, adoption, catalog, control.PaidCaseDomainOriginal); err != nil {
		return err
	}
	if !stable() {
		return errors.New("paid domain scope changed during original acquisition")
	}
	acceptance, err := runtime.AcceptPaidCaseDomainAdoption(ctx, current, request, adoption)
	if err != nil {
		return err
	}
	backendOriginal, err := control.AcceptPaidCaseDomain(ctx, model.PaidCaseDomainAcceptanceRequest{FormatVersion: 1, Acceptance: acceptance})
	if err != nil {
		return err
	}
	if !stable() {
		return errors.New("paid domain scope changed after acceptance commit")
	}
	return runtime.ConfirmPaidCaseDomainAcceptance(ctx, current, request, acceptance, backendOriginal)
}
