package qualification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Owning callers supply these originals independently of the published control.
// RetainedExposure is a financial-owner reference, NOT cash proof. This verifier
// neither admits OFFLINE nor replaces financial reconstruction, native authority
// checks, replay fencing, the current process reader or terminal completion.
type SourceLocalPublicationWitness struct {
	MetadataWitness                                                SourceTransportMetadataWitness
	Metadata, CurrentResponse, Admission, AuthorizationObservation json.RawMessage
	AuthorizationRoot, RetainedExposure                            json.RawMessage
	Owning                                                         model.SourceControlOriginal
	Registered                                                     model.SourceRegisteredProcess
	SessionID, InputID, AuthorizationSHA256                        string
}

type SourceLocalPublishedControl struct {
	FormatVersion  int                        `json:"formatVersion"`
	Purpose        string                     `json:"purpose"`
	EvidenceClass  string                     `json:"evidenceClass"`
	TargetKind     string                     `json:"targetKind"`
	PreparationID  string                     `json:"preparationId"`
	Selection      json.RawMessage            `json:"selection"`
	Admission      json.RawMessage            `json:"admission"`
	Activation     json.RawMessage            `json:"activation"`
	CurrentControl model.SourceCurrentControl `json:"currentControl"`
}

// Consume frozen57 outer signatures, preserving the exact existing native
// receipt/grant admission and original Authorization. HTTP wrapper formatting is
// not authority: signed envelopes and retained originals must remain canonical.
func VerifySourceLocalPublication(raw []byte, w SourceLocalPublicationWitness, now time.Time) (SourceLocalPublishedControl, error) {
	var empty, published SourceLocalPublishedControl
	if err := workflowcontract.ValidateSourceLocalGrant("localPublishedControl", raw); err != nil {
		return empty, fmt.Errorf("%w: SOURCE publication schema", ErrUntrusted)
	}
	// Native child grants have required nullable parent fields. The pinned
	// closed schema owns their shape; decodeClosed's non-null tree rule would
	// incorrectly reject those unchanged originals.
	if decode(raw, &published) != nil || w.MetadataWitness.Target.Phase != "execute" {
		return empty, fmt.Errorf("%w: SOURCE publication shape", ErrUntrusted)
	}
	m, err := VerifySourceTransportMetadata(w.Metadata, w.MetadataWitness, now)
	if err != nil || published.TargetKind != m.TargetKind || published.PreparationID != m.PreparationID {
		return empty, ErrUntrusted
	}
	authority := childFields(w.MetadataWitness.Authority)
	opID := childString(childFields(authority["operator"]), "keyId")
	for _, original := range []json.RawMessage{published.Selection, published.Activation} {
		if !bytes.Equal(original, canonicalBytes(original)) || verifyChildEnvelope(original, opID, w.MetadataWitness.OperatorPEM) != nil {
			return empty, fmt.Errorf("%w: SOURCE publication operator signature", ErrUntrusted)
		}
	}
	grant := childFields(childFields(published.Selection)["payload"])
	activation := childFields(childFields(published.Activation)["payload"])
	profile := childFields(m.ProfileMetadata)
	localCase := childFields(childFields(m.LocalCase)["payload"])
	receipt := childFields(m.PreparedReceipt)
	var scope model.ControllerOwner
	if decodeClosed(localCase["scope"], &scope) != nil || w.Registered.SandboxID != scope.SandboxID || w.Registered.SandboxGeneration != scope.SandboxGeneration {
		return empty, ErrUntrusted
	}
	// The registered process/current control come from their normal suppliers,
	// never the purported selection's own signed references.
	lifetime := mustChildTime(childString(localCase, "expiresAt"))
	for _, limit := range []string{m.Qualification.ValidUntil, childString(childFields(childFields(profile["adoption"])["payload"]), "expiresAt"), childString(childFields(childFields(profile["permission"])["payload"]), "expiresAt")} {
		at, e := time.Parse(time.RFC3339Nano, limit)
		if e != nil {
			return empty, ErrUntrusted
		}
		if at.Before(lifetime) {
			lifetime = at
		}
	}
	target := w.MetadataWitness.Target
	target.Scope = scope
	current, _, err := verifySourceCurrentControl(w.CurrentResponse, target, childString(profile, "candidateInventoryDigest"), w.Registered, w.Owning, w.MetadataWitness.Producer, w.MetadataWitness.ProducerPEM, now, lifetime)
	if err != nil || current.CurrentControl.DesiredState != "active" || !sameProduct(grant["registeredProcess"], w.Registered) {
		return empty, fmt.Errorf("%w: SOURCE publication current owner", ErrUntrusted)
	}
	for _, snapshot := range []json.RawMessage{grant["currentControl"], activation["currentControl"], canonicalBytes(published.CurrentControl)} {
		if !sourcePublicationControlCurrent(snapshot, current.CurrentControl, now, lifetime) {
			return empty, ErrUntrusted
		}
	}
	if !sameProduct(activation["currentControl"], published.CurrentControl) {
		return empty, ErrUntrusted
	}
	expected := map[string]any{
		"targetKind": m.TargetKind, "preparationId": m.PreparationID, "preparedTupleDigest": CanonicalDigest(m.PreparedTuple),
		"preparedReceiptDigest": childString(receipt, "preparedReceiptDigest"), "credentialId": childString(receipt, "credentialId"),
		"nativeCredentialId": childString(receipt, "nativeCredentialId"), "authorityDigest": Digest(w.MetadataWitness.Authority),
		"caseId": childString(authority, "caseId"), "localCaseEnvelopeDigest": CanonicalDigest(m.LocalCase), "entry": m.Entry,
		"candidateInventoryDigest": childString(profile, "candidateInventoryDigest"), "sourceTransportPermissionDigest": childString(profile, "sourceTransportPermissionDigest"),
		"scope": scope, "qualification": m.Qualification, "sessionId": w.SessionID, "inputId": w.InputID, "nativeGrant": m.Grant,
		"retainedExposure": w.RetainedExposure,
	}
	if childString(authority, "caseId") == "" || workflowcontract.ValidateSourceLocalGrant("retainedExposureRef", w.RetainedExposure) != nil {
		return empty, ErrUntrusted
	}
	for field, value := range expected {
		if !sameProduct(grant[field], value) {
			return empty, fmt.Errorf("%w: SOURCE publication selection binding", ErrUntrusted)
		}
	}
	native := childFields(m.Grant)
	if childString(grant, "grantId") != childString(native, "grantId") || !sourcePublicationNativeJoins(m, native, grant, authority, w) {
		return empty, ErrUntrusted
	}
	// Native admission is an independently retained original, not reconstructed
	// from a newly observed grant. No fields are added to the native wire.
	if workflowcontract.ValidateSourceLocalGrant("localAdmission", w.Admission) != nil || !bytes.Equal(w.Admission, canonicalBytes(w.Admission)) || !sameProduct(published.Admission, w.Admission) {
		return empty, fmt.Errorf("%w: SOURCE publication original admission", ErrUntrusted)
	}
	admission := childFields(w.Admission)
	if childString(admission, "targetKind") != m.TargetKind || !sameProduct(admission["preparedReceipt"], m.PreparedReceipt) || !sameProduct(admission["grant"], m.Grant) {
		return empty, ErrUntrusted
	}
	if workflowcontract.ValidateSourceLocalGrant("originalAuthorizationEnvelope", w.AuthorizationObservation) != nil || !bytes.Equal(w.AuthorizationObservation, canonicalBytes(w.AuthorizationObservation)) || verifyChildEnvelope(w.AuthorizationObservation, w.MetadataWitness.Producer.KeyID, w.MetadataWitness.ProducerPEM) != nil {
		return empty, fmt.Errorf("%w: SOURCE publication original Authorization signature", ErrUntrusted)
	}
	header := childFields(childFields(w.AuthorizationObservation)["payload"])
	if childString(header, "preparationId") != m.PreparationID || childString(header, "preparedReceiptDigest") != childString(receipt, "preparedReceiptDigest") || childString(header, "authorizationSha256") != w.AuthorizationSHA256 {
		return empty, ErrUntrusted
	}
	if m.TargetKind == "cell_session" {
		observed, e := time.Parse(time.RFC3339Nano, childString(header, "observedAt"))
		if childString(header, "purpose") != "child_product_authorization" || childString(header, "taskId") != scope.TaskID || childString(header, "nodeTokenHash") != w.MetadataWitness.Producer.NodeTokenHash || childWireAbsent(w.AuthorizationRoot) || !sameProduct(header["root"], w.AuthorizationRoot) || e != nil || observed.Before(mustChildTime(childString(grant, "issuedAt"))) || observed.After(mustChildTime(childString(activation, "issuedAt"))) {
			return empty, fmt.Errorf("%w: SOURCE publication child Authorization owner", ErrUntrusted)
		}
	} else if childString(header, "targetKind") != "controller_authorization" {
		return empty, ErrUntrusted
	}
	for field, value := range map[string]any{
		"targetKind": m.TargetKind, "preparationId": m.PreparationID, "grantId": childString(grant, "grantId"),
		"grantEnvelopeDigest": Digest(published.Selection), "admissionDigest": Digest(w.Admission),
		"preparedReceiptDigest": childString(receipt, "preparedReceiptDigest"), "sourceTransportPermissionDigest": grant["sourceTransportPermissionDigest"],
		"originalAuthorizationObservationDigest": Digest(w.AuthorizationObservation), "authorizationSha256": w.AuthorizationSHA256,
		"deadlineAt": grant["deadlineAt"], "expiresAt": grant["expiresAt"],
	} {
		if !sameProduct(activation[field], value) {
			return empty, fmt.Errorf("%w: SOURCE publication activation binding", ErrUntrusted)
		}
	}
	gi, ge := time.Parse(time.RFC3339Nano, childString(grant, "issuedAt"))
	ai, ae := time.Parse(time.RFC3339Nano, childString(activation, "issuedAt"))
	if ge != nil || ae != nil || ai.Before(gi) || !sourcePublicationWindow(grant, now, lifetime) || !sourcePublicationWindow(activation, now, lifetime) {
		return empty, ErrUntrusted
	}
	return published, nil
}

func sourcePublicationControlCurrent(raw []byte, current model.SourceCurrentControl, now, lifetime time.Time) bool {
	var control model.SourceCurrentControl
	if decodeClosed(raw, &control) != nil || control.SourceControlOriginal != current.SourceControlOriginal || control.ControlDigest != current.ControlDigest {
		return false
	}
	observed, oe := time.Parse(time.RFC3339Nano, control.ObservedAt)
	expires, ee := time.Parse(time.RFC3339Nano, control.ExpiresAt)
	return oe == nil && ee == nil && !observed.After(now) && now.Sub(observed) <= 120*time.Second && observed.Before(expires) && now.Before(expires) && expires.Sub(observed) <= 120*time.Second && !expires.After(lifetime)
}

func sourcePublicationWindow(value map[string]json.RawMessage, now, lifetime time.Time) bool {
	issued, ie := time.Parse(time.RFC3339Nano, childString(value, "issuedAt"))
	deadline, de := time.Parse(time.RFC3339Nano, childString(value, "deadlineAt"))
	expires, ee := time.Parse(time.RFC3339Nano, childString(value, "expiresAt"))
	controlExpiry, ce := time.Parse(time.RFC3339Nano, childString(childFields(value["currentControl"]), "expiresAt"))
	return ie == nil && de == nil && ee == nil && ce == nil && !issued.After(now) && now.Before(deadline) && !deadline.After(expires) && !expires.After(lifetime) && expires.Sub(issued) <= 120*time.Second && !expires.After(controlExpiry)
}

func sourcePublicationNativeJoins(m SourceTransportMetadata, native, grant, authority map[string]json.RawMessage, w SourceLocalPublicationWitness) bool {
	pt := childFields(m.PreparedTuple)
	nativeExpiry, ne := time.Parse(time.RFC3339Nano, childString(native, "expiresAt"))
	if ne != nil || mustChildTime(childString(grant, "expiresAt")).After(nativeExpiry) {
		return false
	}
	if m.TargetKind == "cell_session" {
		for _, field := range []string{"operationId", "controllerId", "controllerRevision", "authorityRevision", "attempt", "fence", "parentExecutionId", "parentPacketId", "packetId", "packetRevision", "configDigest", "profileDigest", "workspaceDigest"} {
			if !sameProduct(native[field], pt[field]) {
				return false
			}
		}
		return childString(native, "sessionId") == w.SessionID && childString(native, "inputId") == w.InputID && childString(native, "credentialBindingDigest") == CanonicalDigest(pt["credentialBinding"])
	}
	exposure := childFields(w.RetainedExposure)
	for field, value := range map[string]any{"preparationId": m.PreparationID, "reservationId": exposure["reservationId"], "caseId": authority["caseId"], "caseManifestDigest": authority["caseManifestDigest"], "policyDigest": grant["sourceTransportPermissionDigest"], "requestIndex": 1, "physicalIndex": m.Entry.LocalDeliveryOrdinal, "maxUsdMicros": exposure["reservedUsdMicros"], "deadlineAt": grant["deadlineAt"], "expiresAt": grant["expiresAt"]} {
		if !sameProduct(native[field], value) {
			return false
		}
	}
	return childString(childFields(pt["nativeRegistration"]), "nativeSessionId") == w.SessionID && childString(pt, "inputId") == w.InputID
}
