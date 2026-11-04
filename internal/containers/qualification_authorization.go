package containers

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

const ManagedSupervisorQualificationHeader ManagedSupervisorAction = "qualification-header"

func (p Podman) CaptureCellQualificationAuthorization(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, receipt model.PreparedReceipt, workspace string) error {
	if p.QualificationRoot == "" {
		return nil
	}
	if p.PhysicalStore == nil || entry.LifecyclePhase != "prepare" || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return qualification.ErrUntrusted
	}
	s, err := p.qualificationStore(ctx)
	if err != nil {
		return err
	}
	_, policy, _, err := s.SelectedPolicy(box, entry, workspace, time.Now().UTC())
	if err != nil {
		return err
	}
	if policy.FormatVersion != 4 {
		return nil
	}
	local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "reported" || !reflect.DeepEqual(local.Entry, entry) || !reflect.DeepEqual(local.Receipt, receipt) || receipt.ValidateFor(entry) != nil {
		return qualification.ErrUntrusted
	}
	if err = p.verifyQualificationImage(ctx, box.ID, policy.Run.Tuple.Sandbox.ConfigDigest); err != nil {
		return err
	}
	binary, err := qualification.SelfBinaryDigest()
	if err != nil || binary != policy.Run.Tuple.Runtime.BinarySHA256 {
		return qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	selected, err := producer.PrepareQualificationAuthorization(s, box, entry, receipt, workspace, time.Now().UTC())
	if err != nil {
		return err
	}
	request, err := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": box.ID, "instance": entry.Instance, "profileId": entry.Profile.ProfileID, "authorizationIntent": map[string]any{"preparationId": entry.PreparationID, "preparedReceipt": receipt}})
	if err != nil {
		return err
	}
	out, _, err := p.ExecManagedSupervisor(ctx, box.ID, ManagedSupervisorQualificationHeader, request)
	if err != nil {
		return err
	}
	var result struct {
		SchemaVersion     int                                                 `json:"schemaVersion"`
		Command           string                                              `json:"command"`
		Status            string                                              `json:"status"`
		HeaderObservation qualification.QualificationAuthorizationObservation `json:"headerObservation"`
	}
	if model.DecodeControllerTransportReceipt(out, "qualification-header", &result) != nil {
		return qualification.ErrUntrusted
	}
	if p.verifyQualificationMounts(ctx, box.ID) != nil {
		return qualification.ErrUntrusted
	}
	again, err := producer.PrepareQualificationAuthorization(s, box, entry, receipt, workspace, time.Now().UTC())
	if err != nil || !selected.Matches(again) {
		return qualification.ErrUntrusted
	}
	readback, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || !reflect.DeepEqual(readback, local) {
		return qualification.ErrUntrusted
	}
	_, err = producer.AttestQualificationAuthorization(result.HeaderObservation, selected, time.Now().UTC())
	return err
}
