package qualification

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func sourceProcessReference(raw []byte, n physicalgate.NativeRegistration) model.SourceRegisteredProcess {
	c := n.Caller
	return model.SourceRegisteredProcess{SandboxID: c.SandboxID, SandboxGeneration: c.SandboxGeneration, NativeInstance: c.NativeInstance, NativeIdentityDigest: c.NativeIdentityDigest, RegistrationDigest: Digest(raw)}
}

// Normal preparation's independently verified metadata supplies lifetime/scope,
// but never a process identity. The registry alone supplies exact FIRST bytes and
// independently checks the actual current container and kernel before signing.
func (p *Producer) ObserveSourceRegisteredProcess(ctx context.Context, registry *physicalgate.ProcessRegistry, metadata []byte, target SourceTransportTarget, subject state.PhysicalSubject) (model.SourceProcessObservationRequest, error) {
	var empty model.SourceProcessObservationRequest
	m, _, err := p.ReadSourceTransportMetadata(ctx, metadata, target)
	if err != nil || registry == nil || registry.Store == nil || target.Scope.SandboxID != subject.SandboxID || target.Scope.SandboxGeneration != subject.SandboxGeneration || m.Applicability.SandboxID != subject.SandboxID || m.Applicability.SandboxGeneration != subject.SandboxGeneration {
		return empty, ErrUntrusted
	}
	raw, registration, err := registry.CurrentRegistrationOriginal(ctx, subject)
	if err != nil {
		return empty, err
	}
	if registration.Native.ExecutableDigest != m.Applicability.Native.BinarySHA256 {
		return empty, ErrUntrusted
	}
	now := time.Now().UTC()
	expires := now.Add(120 * time.Second)
	pm := childFields(m.ProfileMetadata)
	// Existing signed case/profile adoption/permission and qualification bound
	// the observation. Backend independently checks task/node/preparation lifetime
	// at POST; a local observation cannot supply or extend those owning leases.
	for _, limit := range []string{childString(childFields(childFields(m.LocalCase)["payload"]), "expiresAt"), childString(childFields(childFields(pm["adoption"])["payload"]), "expiresAt"), childString(childFields(childFields(pm["permission"])["payload"]), "expiresAt"), m.Qualification.ValidUntil} {
		bound, err := time.Parse(time.RFC3339Nano, limit)
		if err != nil || !now.Before(bound) {
			return empty, ErrUntrusted
		}
		if bound.Before(expires) {
			expires = bound
		}
	}
	var scope model.ControllerOwner
	if decodeClosed(childFields(childFields(m.LocalCase)["payload"])["scope"], &scope) != nil {
		return empty, ErrUntrusted
	}
	payload := model.SourceRegisteredProcessObservation{FormatVersion: 1, Purpose: "source_registered_process_observation", Scope: scope, CandidateInventoryDigest: childString(pm, "candidateInventoryDigest"), TargetKind: target.TargetKind, PreparationID: target.PreparationID, RegisteredProcess: sourceProcessReference(raw, registration), ObservedAt: now.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano)}
	if workflowcontract.ValidateSourceOriginal("registeredProcessObservation", canonicalBytes(payload)) != nil {
		return empty, ErrUntrusted
	}
	again, current, err := registry.CurrentRegistrationOriginal(ctx, subject)
	if err != nil || !bytes.Equal(raw, again) || !sameProduct(registration, current) {
		return empty, ErrUntrusted
	}
	if _, _, err = p.ReadSourceTransportMetadata(ctx, metadata, target); err != nil || ctx.Err() != nil || !time.Now().Before(expires) {
		return empty, ErrUntrusted
	}
	h := sha256.Sum256(canonicalBytes(payload))
	signature, err := ecdsa.SignASN1(rand.Reader, p.key, h[:])
	if err != nil {
		return empty, err
	}
	envelope := canonicalBytes(ChildEnvelope[model.SourceRegisteredProcessObservation]{Payload: payload, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(signature)})
	request := model.SourceProcessObservationRequest{FormatVersion: 1, Observation: envelope, RegistrationBase64: base64.StdEncoding.EncodeToString(raw)}
	if workflowcontract.ValidateSourceOriginal("processObservationRequest", canonicalBytes(request)) != nil {
		return empty, ErrUntrusted
	}
	for _, original := range [][]byte{raw, envelope} {
		if err = p.append(Digest(original)[7:], original); err != nil {
			return empty, err
		}
	}
	return request, nil
}

// Signature PLUS independently current process and owning control joins. The raw
// digest covers exactly eight fields, not the reference/timestamps/itself/grant.
func verifySourceCurrentControl(raw []byte, target SourceTransportTarget, candidate string, registered model.SourceRegisteredProcess, owning model.SourceControlOriginal, producer ProducerConfig, public []byte, now, lifetime time.Time) (model.SourceCurrentControlObservation, []byte, error) {
	var empty model.SourceCurrentControlObservation
	var response model.SourceCurrentControlResponse
	var envelope ChildEnvelope[model.SourceCurrentControlObservation]
	if workflowcontract.ValidateSourceOriginal("currentControlResponse", raw) != nil || decodeClosed(raw, &response) != nil ||
		workflowcontract.ValidateSourceOriginal("currentControlObservationEnvelope", response.Observation) != nil ||
		!bytes.Equal(response.Observation, canonicalBytes(response.Observation)) || Digest(public) != producer.KeySHA256 || verifyChildEnvelope(response.Observation, producer.KeyID, public) != nil || decodeClosed(response.Observation, &envelope) != nil {
		return empty, nil, ErrUntrusted
	}
	original, err := base64.StdEncoding.Strict().DecodeString(response.ControlBase64)
	if err != nil || base64.StdEncoding.EncodeToString(original) != response.ControlBase64 || workflowcontract.ValidateSourceOriginal("controlOriginal", original) != nil || !bytes.Equal(original, canonicalBytes(json.RawMessage(original))) {
		return empty, nil, ErrUntrusted
	}
	observation := envelope.Payload
	control := observation.CurrentControl
	// 12:08: only seven fields come from normal current rows. The eighth is the
	// independently signed SOURCE journal revision, never a public-counter alias.
	actual := control.SourceControlOriginal
	actual.ControlRevision = owning.ControlRevision
	if observation.Scope != target.Scope || observation.TargetKind != target.TargetKind || observation.PreparationID != target.PreparationID || observation.CandidateInventoryDigest != candidate || observation.RegisteredProcess != registered || control.ControlDigest != Digest(original) || !bytes.Equal(original, canonicalBytes(control.SourceControlOriginal)) || actual != owning || control.ControlRevision < 1 || control.ControlRevision < owning.ControlRevision {
		return empty, nil, ErrUntrusted
	}
	observed, oe := time.Parse(time.RFC3339Nano, control.ObservedAt)
	expires, ee := time.Parse(time.RFC3339Nano, control.ExpiresAt)
	if oe != nil || ee != nil || observed.After(now) || now.Sub(observed) > 120*time.Second || !observed.Before(expires) || !now.Before(expires) || expires.Sub(observed) > 120*time.Second || expires.After(lifetime) {
		return empty, nil, ErrUntrusted
	}
	return observation, original, nil
}

type SourceControlOriginalReader interface {
	SourceCurrentControl(context.Context, string, string) (json.RawMessage, error)
}

// Fixed authenticated backend reader and the SAME current registry. The normal
// owning caller supplies the actual seven-field row vector. ControlRevision is a
// minimum already-observed private SOURCE revision (zero before first observation),
// never a value reflected from a grant as the current owning seven-field vector.
func (p *Producer) ReadSourceCurrentControl(ctx context.Context, registry *physicalgate.ProcessRegistry, reader SourceControlOriginalReader, metadata []byte, target SourceTransportTarget, subject state.PhysicalSubject, owning model.SourceControlOriginal, lifetime time.Time) (model.SourceCurrentControlObservation, []byte, json.RawMessage, error) {
	var empty model.SourceCurrentControlObservation
	if reader == nil || registry == nil || registry.Store == nil || lifetime.IsZero() {
		return empty, nil, nil, ErrUntrusted
	}
	m, _, err := p.ReadSourceTransportMetadata(ctx, metadata, target)
	if err != nil {
		return empty, nil, nil, err
	}
	raw, registration, err := registry.CurrentRegistrationOriginal(ctx, subject)
	if err != nil || registration.Native.ExecutableDigest != m.Applicability.Native.BinarySHA256 {
		return empty, nil, nil, ErrUntrusted
	}
	public, err := p.paidPublic()
	if err != nil {
		return empty, nil, nil, err
	}
	var scope model.ControllerOwner
	if decodeClosed(childFields(childFields(m.LocalCase)["payload"])["scope"], &scope) != nil {
		return empty, nil, nil, ErrUntrusted
	}
	target.Scope = scope
	response, err := reader.SourceCurrentControl(ctx, target.TargetKind, target.PreparationID)
	if err != nil {
		return empty, nil, nil, err
	}
	observation, original, err := verifySourceCurrentControl(response, target, childString(childFields(m.ProfileMetadata), "candidateInventoryDigest"), sourceProcessReference(raw, registration), owning, p.config, public, time.Now(), lifetime)
	if err != nil {
		return empty, nil, nil, err
	}
	again, current, err := registry.CurrentRegistrationOriginal(ctx, subject)
	if err != nil || !bytes.Equal(raw, again) || !sameProduct(registration, current) {
		return empty, nil, nil, ErrUntrusted
	}
	if _, _, err = p.ReadSourceTransportMetadata(ctx, metadata, target); err != nil || ctx.Err() != nil {
		return empty, nil, nil, ErrUntrusted
	}
	var decoded model.SourceCurrentControlResponse
	if decodeClosed(response, &decoded) != nil {
		return empty, nil, nil, ErrUntrusted
	}
	for _, b := range [][]byte{raw, decoded.Observation, original} {
		if err = p.append(Digest(b)[7:], b); err != nil {
			return empty, nil, nil, err
		}
	}
	return observation, original, decoded.Observation, nil
}
