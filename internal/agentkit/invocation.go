package agentkit

// WP-211A installed-channel contract: the Runtime half of the in-cell
// invocation. The supervisor action `materialize-agent-kit` runs the packaged
// materializer inside the cell and returns one bounded, digest-bound envelope;
// this file builds the exact closed request and independently verifies the
// envelope against the compiled TEST adoption record. Production defaults are
// unchanged: the only adoption record is TEST-labelled and no Runtime path
// selects it unless the venue environment variable names it exactly.

import (
	"bytes"
	"encoding/json"
)

// BuildInvocation produces the closed supervisor request for an already-built
// materialization request. The declared image closure is the compiled TEST
// adoption record, never caller-supplied truth.
func BuildInvocation(request Request, venue Venue) (InvocationRequest, error) {
	var empty InvocationRequest
	if !validVenue(venue) || venue.AdoptionID == "" {
		return empty, errVenueDenied
	}
	if request.KitDigest == "" || request.MaterializationID == "" {
		return empty, refuse("agent_kit_request_invalid", "request")
	}
	if err := validateTarget(request.Target); err != nil {
		return empty, err
	}
	raw, err := canonicalJSON(request)
	if err != nil {
		return empty, refuse("agent_kit_request_invalid", "canonical request")
	}
	if len(raw) > 512*1024 {
		return empty, refuse("agent_kit_bounds_exceeded", "request")
	}
	invocation := InvocationRequest{
		SchemaVersion: 1,
		SandboxID:     request.Target.SandboxID,
		Instance:      invocationInstance,
		ProfileID:     invocationProfileID,
		ProjectRoot:   request.Target.ProjectRoot,
		AdoptionID:    venue.AdoptionID,
		ImageClosure: ImageClosure{
			ClosureVersion:         venue.ClosureVersion,
			ClosureDigest:          venue.ClosureDigest,
			MaterializerDigest:     venue.MaterializerDigest,
			SnapshotManifestDigest: venue.SnapshotManifestDigest,
			FileCount:              venue.ClosureFileCount,
			ByteCount:              venue.ClosureByteCount,
		},
		Request:        raw,
		TimeoutSeconds: invocationTimeoutSeconds,
	}
	return invocation, nil
}

// VerifyInvocation checks the supervisor envelope end to end: the closed
// request binding, the compiled adoption record, the measured closure the
// supervisor reported, the envelope digest, and finally the nested
// materialization receipt through VerifyReceipt.
func VerifyInvocation(request Request, venue Venue, raw []byte) (InvocationReceipt, error) {
	var empty InvocationReceipt
	if !validVenue(venue) || venue.AdoptionID == "" {
		return empty, errVenueDenied
	}
	if len(raw) == 0 || len(raw) > maxInvocationBytes {
		return empty, refuse("agent_kit_invocation_invalid", "size")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return empty, refuse("agent_kit_invocation_invalid", "shape")
	}
	required := []string{
		"schemaVersion", "command", "status", "ready", "sandboxId", "instance",
		"profileId", "adoptionId", "venue", "closure", "materialization",
		"receiptDigest",
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return empty, refuse("agent_kit_invocation_invalid", name)
		}
	}
	if err := requireStringField(fields, "command", invocationCommand); err != nil {
		return empty, err
	}
	if err := requireStringField(fields, "status", "ready"); err != nil {
		return empty, err
	}
	if err := requireStringField(fields, "profileId", invocationProfileID); err != nil {
		return empty, err
	}
	if err := requireStringField(fields, "sandboxId", request.Target.SandboxID); err != nil {
		return empty, err
	}
	if err := requireStringField(fields, "adoptionId", venue.AdoptionID); err != nil {
		return empty, err
	}
	if err := requireStringField(fields, "venue", venue.InstalledVenue); err != nil {
		return empty, err
	}
	var schemaVersion int
	if err := json.Unmarshal(fields["schemaVersion"], &schemaVersion); err != nil || schemaVersion != 1 {
		return empty, refuse("agent_kit_invocation_invalid", "schemaVersion")
	}
	var ready bool
	if err := json.Unmarshal(fields["ready"], &ready); err != nil || !ready {
		return empty, refuse("agent_kit_invocation_invalid", "ready")
	}
	envelopeDigest, err := validEnvelopeDigest(raw)
	if err != nil {
		return empty, err
	}
	var closure ImageClosure
	closureDecoder := json.NewDecoder(bytes.NewReader(fields["closure"]))
	closureDecoder.DisallowUnknownFields()
	if err := closureDecoder.Decode(&closure); err != nil {
		return empty, refuse("agent_kit_invocation_invalid", "closure")
	}
	expected := ImageClosure{
		ClosureVersion:         venue.ClosureVersion,
		ClosureDigest:          venue.ClosureDigest,
		MaterializerDigest:     venue.MaterializerDigest,
		SnapshotManifestDigest: venue.SnapshotManifestDigest,
		FileCount:              venue.ClosureFileCount,
		ByteCount:              venue.ClosureByteCount,
	}
	if closure.ClosureVersion != expected.ClosureVersion ||
		closure.ClosureDigest != expected.ClosureDigest ||
		closure.MaterializerDigest != expected.MaterializerDigest ||
		closure.SnapshotManifestDigest != expected.SnapshotManifestDigest ||
		closure.FileCount != expected.FileCount ||
		closure.ByteCount != expected.ByteCount {
		return empty, refuse("agent_kit_adoption_mismatch", "closure")
	}
	if closure.Measurer != "installed" && closure.Measurer != "source" {
		return empty, refuse("agent_kit_invocation_invalid", "measurer")
	}
	materialization, err := VerifyReceipt(request, fields["materialization"])
	if err != nil {
		return empty, err
	}
	return InvocationReceipt{
		Status:          "ready",
		Ready:           true,
		Command:         invocationCommand,
		SandboxID:       request.Target.SandboxID,
		Instance:        invocationInstance,
		ProfileID:       invocationProfileID,
		AdoptionID:      venue.AdoptionID,
		Venue:           venue.InstalledVenue,
		Materializer:    MaterializerVersion,
		Closure:         closure,
		Materialization: materialization,
		EnvelopeDigest:  envelopeDigest,
	}, nil
}

func requireStringField(fields map[string]json.RawMessage, name, expected string) error {
	var value string
	if err := json.Unmarshal(fields[name], &value); err != nil {
		return refuse("agent_kit_invocation_invalid", name)
	}
	if value != expected {
		return refuse("agent_kit_invocation_invalid", name)
	}
	return nil
}

// validEnvelopeDigest recomputes the supervisor receipt digest over the full
// envelope minus receiptDigest, using the same canonical JSON as the sandbox
// (sorted keys, compact separators, literal UTF-8, integer/float shortest form).
func validEnvelopeDigest(raw []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var tree map[string]any
	if err := decoder.Decode(&tree); err != nil {
		return "", refuse("agent_kit_invocation_invalid", "digest shape")
	}
	provided, ok := tree["receiptDigest"].(string)
	if !ok || !digestPattern.MatchString(provided) {
		return "", refuse("agent_kit_invocation_invalid", "receiptDigest")
	}
	delete(tree, "receiptDigest")
	recomputed, err := Digest(tree)
	if err != nil {
		return "", refuse("agent_kit_invocation_invalid", "digest")
	}
	if recomputed != provided {
		return "", refuse("agent_kit_receipt_digest_mismatch", "invocation")
	}
	return provided, nil
}

// CanonicalInvocation is the exact bytes the supervisor consumes; exported for
// cross-language parity tests and evidence capture.
func CanonicalInvocation(invocation InvocationRequest) ([]byte, error) {
	return canonicalJSON(invocation)
}
