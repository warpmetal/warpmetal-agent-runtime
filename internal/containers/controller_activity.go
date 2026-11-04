package containers

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

func (p Podman) ObserveControllerAuthorization(ctx context.Context, receipt model.ControllerPreparedReceipt, w qualification.ControllerOutputWitness) (model.ControllerAuthorizationEnvelope, error) {
	producer, w, err := p.controllerProducerWitness(ctx, w)
	if err != nil {
		return model.ControllerAuthorizationEnvelope{}, err
	}
	parent := w.Parent.Parent
	call := map[string]any{"schemaVersion": 1, "sandboxId": parent.Owner.SandboxID, "instance": parent.Instance, "profileId": parent.Profile.ProfileID, "preparedReceipt": receipt, "policyDigest": qualification.CanonicalDigest(w.Policy)}
	raw, _ := json.Marshal(call)
	out, _, err := p.ExecManagedSupervisor(ctx, parent.Owner.SandboxID, ManagedSupervisorControllerHeader, raw)
	if err != nil {
		return model.ControllerAuthorizationEnvelope{}, err
	}
	var result struct {
		SchemaVersion     int                                      `json:"schemaVersion"`
		Command           string                                   `json:"command"`
		Status            string                                   `json:"status"`
		HeaderObservation model.ControllerAuthorizationObservation `json:"headerObservation"`
	}
	if model.DecodeControllerTransportReceipt(out, "controller-header", &result) != nil {
		return model.ControllerAuthorizationEnvelope{}, qualification.ErrUntrusted
	}
	return producer.AttestControllerAuthorization(result.HeaderObservation, receipt, w, time.Now().UTC())
}

// Same protected installed mounts and SAME producer. No manifest-supplied UID,
// test-key construction, signer callback or arbitrary trusted-node assertion.
func (p Podman) VerifyControllerPolicy(ctx context.Context, box model.Sandbox, digest string, w qualification.ControllerPolicyWitness) (qualification.ControllerPolicy, error) {
	var policy qualification.ControllerPolicy
	if p.QualificationRoot == "" {
		return policy, qualification.ErrUntrusted
	}
	if e := p.verifyQualificationMounts(ctx, box.ID); e != nil {
		return policy, e
	}
	store, e := p.qualificationStore(ctx)
	if e != nil {
		return policy, e
	}
	selected, source, e := store.ControllerSourceContinuation(box, digest)
	if e != nil {
		return policy, e
	}
	if len(source) != 0 {
		if e = p.enrollSourceContinuation(ctx, store, box, selected, source); e != nil {
			return policy, e
		}
	}
	policy, e = store.ReadControllerPolicy(box, digest, w, time.Now().UTC())
	if e != nil {
		return policy, e
	}
	manifest := box.ImageDigest[strings.LastIndex(box.ImageDigest, "@")+1:]
	if manifest != policy.Applicability.Sandbox.RegistryManifestDigest {
		return policy, qualification.ErrUntrusted
	}
	if e = p.verifyQualificationImage(ctx, box.ID, policy.Applicability.Sandbox.ConfigDigest); e != nil {
		return policy, e
	}
	actual, e := qualification.SelfBinaryDigest()
	if e != nil || actual != policy.Applicability.Runtime.BinarySHA256 {
		return policy, qualification.ErrUntrusted
	}
	return policy, nil
}
func (p Podman) ReadControllerActivation(ctx context.Context, box model.Sandbox, policy qualification.ControllerPolicy, receipt model.ControllerPreparedReceipt, retained bool) (qualification.ControllerActivation, error) {
	var activation qualification.ControllerActivation
	if e := p.verifyQualificationMounts(ctx, box.ID); e != nil {
		return activation, e
	}
	store, e := p.qualificationStore(ctx)
	if e != nil {
		return activation, e
	}
	if retained {
		return store.ReadControllerRetainedActivation(box, policy, receipt, time.Now().UTC())
	}
	return store.ReadControllerActivation(box, policy, receipt, time.Now().UTC())
}
func (p Podman) controllerProducerWitness(ctx context.Context, w qualification.ControllerOutputWitness) (*qualification.Producer, qualification.ControllerOutputWitness, error) {
	if _, e := p.VerifyControllerPolicy(ctx, w.Sandbox, qualification.CanonicalDigest(w.Policy), w.Installed); e != nil {
		return nil, w, e
	}
	store, e := p.qualificationStore(ctx)
	if e != nil {
		return nil, w, e
	}
	w.Authority = store
	producer, e := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	return producer, w, e
}
func (p Podman) AttestControllerPrepared(ctx context.Context, receipt model.ControllerPreparedReceipt, w qualification.ControllerOutputWitness) (model.ControllerPreparedEnvelope, error) {
	producer, w, e := p.controllerProducerWitness(ctx, w)
	if e != nil {
		return model.ControllerPreparedEnvelope{}, e
	}
	return producer.AttestControllerPrepared(receipt, w, time.Now().UTC())
}
func (p Podman) AttestControllerOutput(ctx context.Context, op model.ControllerOutputOperation, capture qualification.ControllerCapture, w qualification.ControllerOutputWitness) (model.ControllerOutputEnvelope, error) {
	producer, w, e := p.controllerProducerWitness(ctx, w)
	if e != nil {
		return model.ControllerOutputEnvelope{}, e
	}
	if !reflect.DeepEqual(op.Context, w.ApprovedContext) {
		return model.ControllerOutputEnvelope{}, qualification.ErrUntrusted
	}
	return producer.AttestControllerOutput(op, capture, w, time.Now().UTC())
}
