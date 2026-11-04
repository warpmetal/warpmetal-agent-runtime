package qualification

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// These are the manager-frozen permission bytes, not a profile identity change,
// native grant, qualification, fixture trust supplied by a record, or RPC schema.
type SourceTransportProfile = model.ApprovedExpertiseProfile

type SourceTransportPermission struct {
	FormatVersion            int                    `json:"formatVersion"`
	Purpose                  string                 `json:"purpose"`
	CandidateInventoryDigest string                 `json:"candidateInventoryDigest"`
	Profile                  SourceTransportProfile `json:"profile"`
	FixtureKeySHA256         string                 `json:"fixtureKeySHA256"`
	Oracles                  []string               `json:"oracles"`
	IssuedAt                 string                 `json:"issuedAt"`
	ExpiresAt                string                 `json:"expiresAt"`
}

// Private owning inputs must come from independently adopted current profile and
// candidate/operator originals, NOT a fixture/permission's repeated fields. This
// reader does not adopt those inputs or establish installed-profile provenance.
type SourceTransportPermissionAuthority struct {
	PermissionDigest, CandidateInventoryDigest, OperatorKeySHA256, OperatorKeyID string
	Profile                                                                      SourceTransportProfile
}

func verifySourceTransportPermission(raw []byte, a SourceTransportPermissionAuthority, operatorPEM []byte, now time.Time) (SourceTransportPermission, error) {
	var envelope ChildEnvelope[SourceTransportPermission]
	if workflowcontract.Validate(workflowcontract.SourceLocalTransport, "permissionEnvelope", raw) != nil || !bytes.Equal(raw, canonicalBytes(json.RawMessage(raw))) || Digest(raw) != a.PermissionDigest || Digest(operatorPEM) != a.OperatorKeySHA256 || verifyChildEnvelope(raw, a.OperatorKeyID, operatorPEM) != nil || decodeClosed(raw, &envelope) != nil {
		return SourceTransportPermission{}, ErrUntrusted
	}
	p := envelope.Payload
	if !hash.MatchString(a.CandidateInventoryDigest) || !hash.MatchString(a.OperatorKeySHA256) || p.CandidateInventoryDigest != a.CandidateInventoryDigest || p.Profile != a.Profile ||
		p.FormatVersion != 1 || p.Purpose != "source_installed_transport_permission" || workflowcontract.Validate(workflowcontract.Producer, "approvedProfile", canonicalBytes(p.Profile)) != nil ||
		!hash.MatchString(p.FixtureKeySHA256) || p.FixtureKeySHA256 == a.OperatorKeySHA256 ||
		!reflect.DeepEqual(p.Oracles, []string{"http_cancel", "tool_cancel", "controller_deadline"}) {
		return SourceTransportPermission{}, ErrUntrusted
	}
	issued, ie := time.Parse(time.RFC3339Nano, p.IssuedAt)
	expires, ee := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if ie != nil || ee != nil || workflowcontract.Validate(workflowcontract.Producer, "time", canonicalBytes(p.IssuedAt)) != nil || workflowcontract.Validate(workflowcontract.Producer, "time", canonicalBytes(p.ExpiresAt)) != nil || issued.After(now) || !issued.Before(expires) || !now.Before(expires) {
		return SourceTransportPermission{}, ErrUntrusted
	}
	return p, nil
}

// ReadSourceTransportPermission reads the exact canonical SIGNED ENVELOPE in the
// existing blob namespace. Its digest includes the original signature, never just
// the payload or an implicitly detached copy. It does not select/adopt a fixture key,
// publish a profile/permission, unwrap LIVE authority, or authorize a transport.
// F1's normal approved-profile adapter still must supply the independent original
// reference; absence is an error, never a record-derived default.
func (s Store) ReadSourceTransportPermission(box model.Sandbox, a SourceTransportPermissionAuthority, now time.Time) (SourceTransportPermission, error) {
	var empty SourceTransportPermission
	tree, key, err := s.Paths(box.ID)
	if err != nil || !hash.MatchString(a.PermissionDigest) || !hash.MatchString(a.OperatorKeySHA256) {
		return empty, ErrUntrusted
	}
	pem, err := s.read(key, tree, key, 4096)
	if err != nil || Digest(pem) != a.OperatorKeySHA256 {
		return empty, ErrUntrusted
	}
	name := filepath.Join(tree, "blobs", a.PermissionDigest[7:])
	raw, err := s.read(name, tree, key, 65536)
	if err != nil {
		return empty, ErrUntrusted
	}
	p, err := verifySourceTransportPermission(raw, a, pem, now)
	if err != nil {
		return empty, ErrUntrusted
	}
	// Reverify the SAME original bytes/signature/key. A mutable reference or a
	// verified projection cannot replace the independently selected original.
	again, err := s.read(name, tree, key, 65536)
	currentKey, ke := s.read(key, tree, key, 4096)
	if err != nil || ke != nil || !bytes.Equal(raw, again) || !bytes.Equal(pem, currentKey) {
		return empty, ErrUntrusted
	}
	return p, nil
}
