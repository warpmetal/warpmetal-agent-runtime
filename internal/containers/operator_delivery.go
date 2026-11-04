package containers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// SAME protected Store.Paths/public anchor and registered producer; no operator
// key, configurable transport callback or unprotected manager-supplied path.
func (p Podman) ReadControllerGrantOriginal(ctx context.Context, prepared model.ControllerPreparedReceipt, w qualification.ControllerOutputWitness) (model.ControllerGrantEnvelope, error) {
	producer, current, err := p.controllerProducerWitness(ctx, w)
	if err != nil {
		return model.ControllerGrantEnvelope{}, err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return model.ControllerGrantEnvelope{}, err
	}
	return producer.ReadControllerGrantDelivery(store, current.Sandbox, current.Policy, prepared, current.ApprovedContext, time.Now().UTC())
}
func (p Podman) ReadControllerActivationOriginal(ctx context.Context, prepared model.ControllerPreparedReceipt, w qualification.ControllerOutputWitness) (api.ControllerActivationEnvelope, error) {
	var out api.ControllerActivationEnvelope
	producer, current, err := p.controllerProducerWitness(ctx, w)
	if err != nil {
		return out, err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return out, err
	}
	original, err := producer.ReadControllerActivationDelivery(store, current.Sandbox, current.Policy, prepared, current.ApprovedContext, time.Now().UTC())
	if err != nil {
		return out, err
	}
	return api.ControllerActivationEnvelope{Payload: original.Payload, KeyID: original.KeyID, Signature: original.Signature}, nil
}
func (p Podman) ExportControllerActivationHandoff(ctx context.Context, prepared model.ControllerPreparedReceipt, w qualification.ControllerOutputWitness, raw []byte) error {
	producer, _, err := p.controllerProducerWitness(ctx, w)
	if err != nil {
		return err
	}
	return producer.ExportControllerActivationHandoff(prepared.PreparationID, raw)
}

func (p Podman) AdoptPublishedControllerActivation(ctx context.Context, prepared model.ControllerPreparedReceipt, w qualification.ControllerOutputWitness, original api.ControllerActivationEnvelope) error {
	producer, current, err := p.controllerProducerWitness(ctx, w)
	if err != nil {
		return err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return err
	}
	return producer.AdoptPublishedControllerActivation(store, current.Sandbox, current.Policy, prepared, current.ApprovedContext, qualification.ChildEnvelope[qualification.ControllerActivation]{Payload: original.Payload, KeyID: original.KeyID, Signature: original.Signature}, time.Now().UTC())
}

func (p Podman) childDeliveryStore(ctx context.Context, box model.Sandbox) (qualification.Store, *qualification.Producer, error) {
	if err := p.verifyQualificationMounts(ctx, box.ID); err != nil {
		return qualification.Store{}, nil, err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return store, nil, err
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	return store, producer, err
}
func (p Podman) ReadChildPolicyOriginal(ctx context.Context, box model.Sandbox, h model.IntentHandle, preparedID, stage string, intent json.RawMessage) (json.RawMessage, error) {
	s, producer, err := p.childDeliveryStore(ctx, box)
	if err != nil {
		return nil, err
	}
	return producer.ReadChildPolicyDelivery(s, box, h, preparedID, stage, intent, time.Now().UTC())
}
func (p Podman) ReadChildActivationOriginal(ctx context.Context, box model.Sandbox, h model.IntentHandle, c qualification.RealCase, intent json.RawMessage) (json.RawMessage, error) {
	s, producer, err := p.childDeliveryStore(ctx, box)
	if err != nil {
		return nil, err
	}
	return producer.ReadChildActivationDelivery(s, box, h, c, intent, time.Now().UTC())
}
func (p Podman) ExportChildSigningIntent(ctx context.Context, box model.Sandbox, h model.IntentHandle, stage string, raw []byte) error {
	_, producer, err := p.childDeliveryStore(ctx, box)
	if err != nil {
		return err
	}
	return producer.ExportChildSigningIntent(h.HandleID, stage, raw)
}
