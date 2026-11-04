package qualification

import (
	"encoding/json"
	"testing"
)

// Material persisted-authority rule not diagnosable at the unavailable installed
// boundary: advancing a selector must retain the FIRST whole operator envelopes,
// not merely equivalent payloads. These values are explicitly synthetic and do
// not claim schema/signature/native/qualification/provider acceptance.
func TestChildProductAdvanceRetainsFirstSignedPreparation(t *testing.T) {
	prior := ChildProductControl{Generation: ChildProductGeneration{Phase: "prepare", PreparationID: "prep"}}
	prior.Descriptor.PreparationID = "prep"
	prior.Descriptor.PreparedTupleDigest = "synthetic-tuple"
	prior.Descriptor.PreparationPolicyDigest = "synthetic-policy"
	prior.Generation.PreparationPolicy.Signature = "first-exact-signature"
	prior.Generation.Demand.Signature = "first-exact-demand-signature"
	next := prior
	next.Generation.Phase = "execute"
	if childProductAdvance(prior, next) != nil {
		t.Fatal("unchanged prepare envelope could not advance")
	}
	next.Generation.PreparationPolicy.Signature = "different-valid-signature-is-not-a-replacement"
	if childProductAdvance(prior, next) == nil {
		t.Fatal("first signed preparation envelope replaced")
	}
	next = prior
	next.Generation.Phase = "execute"
	next.Generation.Demand.Signature = "changed-demand-envelope"
	if childProductAdvance(prior, next) == nil {
		t.Fatal("first demand envelope replaced")
	}
	next = prior
	if childProductAdvance(prior, next) == nil {
		t.Fatal("prepare-to-prepare accepted as an execution advance")
	}
}

// Test-build-only constructor: no external production consumer can set the
// private SOURCE ancestor supplier via configuration, environment or wire.
func SourceBoundaryStoreForTest(root string, owner uint32) Store {
	return Store{Root: root, MappedUID: owner, ancestorUID: &owner}
}

func TestSourceCarrierPreservesOriginalAdmissionAndCannotPassLiveDescriptor(t *testing.T) {
	original := []byte(`{"original":"unchanged signed envelope"}`)
	fixture := []byte(`{"purpose":"source_installed_transport_fixture"}`)
	c := SourceTransportCarrier{FormatVersion: 1, Purpose: "source_installed_transport_selection", TargetKind: "cell_session", PreparationID: "source_preparation", AdmissionDigest: Digest(original), SourceTransportFixtureDigest: Digest(fixture)}
	raw := canonicalBytes(c)
	parsed, err := DecodeSourceTransportCarrier(raw)
	if err != nil || parsed != c {
		t.Fatal("closed source carrier", err)
	}
	if VerifySourceCarrierOriginals(c, original, fixture) != nil {
		t.Fatal("unchanged originals rejected")
	}
	if VerifySourceCarrierOriginals(c, append(original, ' '), fixture) == nil {
		t.Fatal("original envelope rewritten")
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	fields["live"] = true
	if _, err := DecodeSourceTransportCarrier(canonicalBytes(fields)); err == nil {
		t.Fatal("extra source field accepted")
	}
	if _, err := DecodeSourceTransportCarrier([]byte(`{"formatVersion":1,"formatVersion":1}`)); err == nil {
		t.Fatal("duplicate carrier keys")
	}
	var descriptor ChildProductDescriptor
	if decodeClosed(raw, &descriptor) == nil {
		t.Fatal("SOURCE carrier passed LIVE decoder")
	}
}
