package containers

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Fixed private normal workflow supplier. Its implementation must re-read the
// owning authenticated committed F1 originals; no unsigned model/caller fields,
// SOURCE fixture, future activation or newly invented route is a default source.
// Full26 callback attachment remains the manager's integration decision.
type ChildAuthorizationIntentSource interface {
	ReadCurrentChildAuthorizationIntent(context.Context, string) (qualification.ChildAuthorizationIntent, error)
}

func (p Podman) ObserveCellProductAuthorization(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, source ChildAuthorizationIntentSource) (qualification.ChildEnvelope[qualification.ChildAuthorizationObservation], error) {
	var empty qualification.ChildEnvelope[qualification.ChildAuthorizationObservation]
	if source == nil || p.PhysicalStore == nil || entry.LifecyclePhase != "prepare" || entry.DesiredState != "active" || entry.SandboxID != box.ID || entry.SandboxGeneration != box.Generation || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return empty, qualification.ErrUntrusted
	}
	found := false
	for _, actual := range current.CellEntriesV3 {
		if reflect.DeepEqual(actual, entry) {
			found = true
		}
	}
	if !found {
		return empty, qualification.ErrUntrusted
	}
	local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "reported" || !reflect.DeepEqual(local.Entry, entry) || local.Receipt.ValidateFor(entry) != nil {
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
	original, err := source.ReadCurrentChildAuthorizationIntent(ctx, entry.PreparationID)
	if err != nil {
		return empty, err
	}
	selected, err := producer.PrepareChildAuthorization(ctx, store, box, w, local.Receipt, original, time.Now().UTC())
	if err != nil {
		return empty, err
	}
	request, _ := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": box.ID, "instance": entry.Instance, "profileId": entry.Profile.ProfileID, "authorizationIntent": original})
	out, _, err := p.ExecManagedSupervisor(ctx, box.ID, ManagedSupervisorChildHeader, request)
	if err != nil {
		return empty, err
	}
	var result struct {
		SchemaVersion     int                                         `json:"schemaVersion"`
		Command           string                                      `json:"command"`
		Status            string                                      `json:"status"`
		HeaderObservation qualification.ChildAuthorizationObservation `json:"headerObservation"`
	}
	if model.DecodeControllerTransportReceipt(out, "child-header", &result) != nil {
		return empty, qualification.ErrUntrusted
	}
	again, err := source.ReadCurrentChildAuthorizationIntent(ctx, entry.PreparationID)
	if err != nil || qualification.CanonicalDigest(again) != qualification.CanonicalDigest(original) || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return empty, qualification.ErrUntrusted
	}
	// Re-observe installed/current preparation and actual Runtime receipt before
	// FIRST signing. No final PRODUCT/activation publication is manufactured.
	next, err := producer.CurrentChildProductWitness(ctx, entry, current, input)
	now := time.Now().UTC()
	if err != nil {
		return empty, err
	}
	if _, err = producer.PrepareChildAuthorization(ctx, store, box, next, local.Receipt, again, now); err != nil {
		return empty, err
	}
	readback, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || readback == nil || !reflect.DeepEqual(readback, local) {
		return empty, qualification.ErrUntrusted
	}
	return producer.AttestChildAuthorization(result.HeaderObservation, selected, now)
}
