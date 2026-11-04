package qualification

import (
	"bytes"
	"path/filepath"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// SOURCE-only protected selector. Never insert its reference into an original
// signed admission/envelope or accept it through the ordinary LIVE descriptor.
type SourceTransportCarrier struct {
	FormatVersion                int    `json:"formatVersion"`
	Purpose                      string `json:"purpose"`
	TargetKind                   string `json:"targetKind"`
	PreparationID                string `json:"preparationId"`
	AdmissionDigest              string `json:"admissionDigest"`
	SourceTransportFixtureDigest string `json:"sourceTransportFixtureDigest"`
}

func DecodeSourceTransportCarrier(raw []byte) (SourceTransportCarrier, error) {
	var c SourceTransportCarrier
	if len(raw) == 0 || len(raw) > 65536 || !utf8.Valid(raw) || decodeClosed(raw, &c) != nil || !bytes.Equal(raw, canonicalBytes(c)) || c.FormatVersion != 1 || c.Purpose != "source_installed_transport_selection" || (c.TargetKind != "cell_session" && c.TargetKind != "controller_activity") || !safeID.MatchString(c.PreparationID) || !hash.MatchString(c.AdmissionDigest) || !hash.MatchString(c.SourceTransportFixtureDigest) {
		return c, ErrUntrusted
	}
	return c, nil
}
func VerifySourceCarrierOriginals(c SourceTransportCarrier, admission, fixture []byte) error {
	if len(admission) == 0 || len(admission) > 512*1024 || len(fixture) == 0 || len(fixture) > 65536 || Digest(admission) != c.AdmissionDigest || Digest(fixture) != c.SourceTransportFixtureDigest {
		return ErrUntrusted
	}
	return nil
}

// Read originals only; this does NOT authenticate a SOURCE profile, issuer or
// grant. Normal signature/qualification/current control verification remains a
// separate mandatory owning join before creating an OFFLINE permit.
func (s Store) ReadSourceTransportOriginals(box model.Sandbox, preparation, target string) (SourceTransportCarrier, []byte, []byte, error) {
	var c SourceTransportCarrier
	tree, key, err := s.Paths(box.ID)
	if err != nil || !safeID.MatchString(preparation) {
		return c, nil, nil, ErrUntrusted
	}
	selector := filepath.Join(tree, "preparations", preparation+".json")
	if target == "controller_activity" {
		selector = filepath.Join(tree, "activations", "controller-"+preparation, "activation.json")
	}
	raw, err := s.read(selector, tree, key, 65536)
	if err != nil {
		return c, nil, nil, ErrUntrusted
	}
	c, err = DecodeSourceTransportCarrier(raw)
	if err != nil || c.PreparationID != preparation || c.TargetKind != target {
		return c, nil, nil, ErrUntrusted
	}
	admission, err := s.read(filepath.Join(tree, "blobs", c.AdmissionDigest[7:]), tree, key, 512*1024)
	if err != nil {
		return c, nil, nil, ErrUntrusted
	}
	fixture, err := s.read(filepath.Join(tree, "snapshots", c.SourceTransportFixtureDigest[7:], "source-transport-fixture.json"), tree, key, 65536)
	if err != nil || VerifySourceCarrierOriginals(c, admission, fixture) != nil {
		return c, nil, nil, ErrUntrusted
	}
	again, err := s.read(selector, tree, key, 65536)
	if err != nil || !bytes.Equal(raw, again) {
		return c, nil, nil, ErrUntrusted
	}
	return c, admission, fixture, nil
}
