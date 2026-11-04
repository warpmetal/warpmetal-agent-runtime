package qualification

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// r41 metadata is deliberately NOT a grant, admission, fixture or terminal proof.
type SourceTransportMetadata struct {
	FormatVersion         int                          `json:"formatVersion"`
	EvidenceClass         string                       `json:"evidenceClass"`
	TargetKind            string                       `json:"targetKind"`
	Phase                 string                       `json:"phase"`
	PreparationID         string                       `json:"preparationId"`
	ProfileMetadata       json.RawMessage              `json:"profileMetadata"`
	LocalCase             json.RawMessage              `json:"localCase"`
	Entry                 SourceLocalEntry             `json:"entry"`
	Applicability         Applicability                `json:"applicability"`
	Qualification         SourceTransportQualification `json:"qualification"`
	PreparedTuple         json.RawMessage              `json:"preparedTuple"`
	PreparedReceipt       json.RawMessage              `json:"preparedReceipt"`
	Grant                 json.RawMessage              `json:"grant"`
	GrantEnvelope         json.RawMessage              `json:"grantEnvelope"`
	BasisDigest           string                       `json:"basisDigest"`
	FixtureCredentialKind string                       `json:"fixtureCredentialKind"`
	ProviderRequests      int                          `json:"providerRequests"`
	ExecutionAuthority    bool                         `json:"executionAuthority"`
}
type SourceLocalEntry struct {
	Oracle                  string `json:"oracle"`
	TargetKind              string `json:"targetKind"`
	TargetID                string `json:"targetId"`
	SourceID                string `json:"sourceId"`
	RequestDigest           string `json:"requestDigest"`
	LocalPreparationOrdinal int    `json:"localPreparationOrdinal"`
	LocalDeliveryOrdinal    int    `json:"localDeliveryOrdinal"`
}
type SourceTransportQualification struct {
	QualificationID  string `json:"qualificationId"`
	TupleDigest      string `json:"tupleDigest"`
	EvidenceDigest   string `json:"evidenceDigest"`
	ActivationDigest string `json:"activationDigest"`
	ValidUntil       string `json:"validUntil"`
}

// Independent normal owning target, not a metadata-selected trust or native ID.
type SourceTransportTarget struct {
	TargetKind, PreparationID, Phase, TargetID, SourceID, RequestDigest string
	PreparedTuple                                                       json.RawMessage
	Scope                                                               model.ControllerOwner
}
type SourceTransportMetadataWitness struct {
	Authority                json.RawMessage
	OperatorPEM, ProducerPEM []byte
	Producer                 ProducerConfig
	Target                   SourceTransportTarget
}

func DecodeSourceTransportMetadata(raw []byte, target, preparation, phase string) (SourceTransportMetadata, error) {
	var m SourceTransportMetadata
	if err := workflowcontract.ValidateSourceTransportControl(raw); err != nil {
		return m, err
	}
	// The original schema checks closed shape (including required null phase
	// fields); RawMessage's null representation need not mirror a Go DTO tree.
	if err := decode(raw, &m); err != nil {
		return m, err
	}
	if m.TargetKind != target || m.PreparationID != preparation || m.Phase != phase {
		return m, ErrUntrusted
	}
	f := childFields(raw)
	delete(f, "basisDigest")
	if CanonicalDigest(f) != m.BasisDigest || (phase == "prepare" && (!childWireAbsent(m.PreparedReceipt) || !childWireAbsent(m.Grant) || !childWireAbsent(m.GrantEnvelope))) || (phase == "execute" && (childWireAbsent(m.PreparedReceipt) || childWireAbsent(m.Grant))) {
		return m, ErrUntrusted
	}
	return m, nil
}

// Verify metadata under independently protected operator AND registered producer
// trust and current target. No exporter can claim this is local grant authority.
func VerifySourceTransportMetadata(raw []byte, w SourceTransportMetadataWitness, now time.Time) (SourceTransportMetadata, error) {
	var empty SourceTransportMetadata
	a := childFields(w.Authority)
	if childString(a, "evidenceClass") != "source" || !bytesCanonical(w.Authority, json.RawMessage(w.Authority)) {
		return empty, ErrUntrusted
	}
	op, producer := childFields(a["operator"]), childFields(a["producer"])
	if childString(op, "keySHA256") != strings.TrimPrefix(Digest(w.OperatorPEM), "sha256:") || childString(producer, "keySHA256") != strings.TrimPrefix(w.Producer.KeySHA256, "sha256:") || w.Producer.KeySHA256 != Digest(w.ProducerPEM) || bytes.Equal(w.OperatorPEM, w.ProducerPEM) || childString(producer, "keyId") != w.Producer.KeyID || childString(producer, "nodeTokenHash") != w.Producer.NodeTokenHash {
		return empty, ErrUntrusted
	}
	m, err := DecodeSourceTransportMetadata(raw, w.Target.TargetKind, w.Target.PreparationID, w.Target.Phase)
	if err != nil || !sameProduct(m.PreparedTuple, w.Target.PreparedTuple) || m.Entry.TargetKind != w.Target.TargetKind || m.Entry.TargetID != w.Target.TargetID || m.Entry.SourceID != w.Target.SourceID || m.Entry.RequestDigest != w.Target.RequestDigest || m.Applicability.ServerID != w.Producer.ServerID {
		return empty, ErrUntrusted
	}
	pm := childFields(m.ProfileMetadata)
	profile := SourceTransportProfile{ProfileID: m.Applicability.Profile.ProfileID, ProfileRevision: m.Applicability.Profile.Revision, ProfileDigest: m.Applicability.Profile.ProfileDigest, BundleDigest: m.Applicability.Profile.BundleDigest}
	candidate := map[string]json.RawMessage{}
	for _, k := range []string{"backend", "native", "runtime", "sandbox", "profileBundleDigest"} {
		if a[k] == nil {
			return empty, ErrUntrusted
		}
		candidate[k] = a[k]
	}
	cd := CanonicalDigest(candidate)
	app := childFields(canonicalBytes(m.Applicability))
	for _, k := range []string{"backend", "native", "runtime", "sandbox"} {
		if !sameProduct(a[k], app[k]) {
			return empty, ErrUntrusted
		}
	}
	if childString(a, "profileBundleDigest") != profile.BundleDigest || !sameProduct(pm["profile"], profile) || childString(pm, "candidateInventoryDigest") != cd {
		return empty, ErrUntrusted
	}
	reference := childString(pm, "sourceTransportPermissionDigest")
	// HTTP formatting is not original storage formatting. Canonical envelope
	// bytes are joined unchanged to independently resolved originals below.
	permission, err := verifySourceTransportPermission(canonicalBytes(pm["permission"]), SourceTransportPermissionAuthority{PermissionDigest: reference, CandidateInventoryDigest: cd, OperatorKeySHA256: Digest(w.OperatorPEM), OperatorKeyID: childString(op, "keyId"), Profile: profile}, w.OperatorPEM, now)
	if err != nil || verifyChildEnvelope(pm["adoption"], w.Producer.KeyID, w.ProducerPEM) != nil {
		return empty, ErrUntrusted
	}
	ad := childFields(childFields(pm["adoption"])["payload"])
	observed, oe := time.Parse(time.RFC3339Nano, childString(ad, "observedAt"))
	expiry, ee := time.Parse(time.RFC3339Nano, childString(ad, "expiresAt"))
	issued, _ := time.Parse(time.RFC3339Nano, permission.IssuedAt)
	until, _ := time.Parse(time.RFC3339Nano, permission.ExpiresAt)
	if childString(ad, "candidateInventoryDigest") != cd || !sameProduct(ad["profile"], profile) || childString(ad, "sourceTransportPermissionDigest") != reference || oe != nil || ee != nil || observed.Before(issued) || observed.After(now) || !now.Before(expiry) || expiry.After(until) {
		return empty, ErrUntrusted
	}
	if verifyChildEnvelope(m.LocalCase, childString(op, "keyId"), w.OperatorPEM) != nil {
		return empty, ErrUntrusted
	}
	c := childFields(childFields(m.LocalCase)["payload"])
	var scope model.ControllerOwner
	if decode(c["scope"], &scope) != nil || scope.AccountID != m.Applicability.AccountID || scope.TaskID != m.Applicability.TaskID || scope.ServerID != w.Producer.ServerID || scope.SandboxID != m.Applicability.SandboxID || scope.SandboxGeneration != m.Applicability.SandboxGeneration {
		return empty, ErrUntrusted
	}
	expectedScope := w.Target.Scope
	// Child manifest omits account/task IDs. Those remain bound by the SAME
	// independently operator-signed case and registered node/normal GET, not a
	// fixture. Every scope field the manifest does own must match exactly.
	if expectedScope.AccountID == "" {
		expectedScope.AccountID = scope.AccountID
	}
	if expectedScope.TaskID == "" {
		expectedScope.TaskID = scope.TaskID
	}
	ci, ie := time.Parse(time.RFC3339Nano, childString(c, "issuedAt"))
	ce, xe := time.Parse(time.RFC3339Nano, childString(c, "expiresAt"))
	qe, qeerr := time.Parse(time.RFC3339Nano, m.Qualification.ValidUntil)
	if childString(c, "authorityDigest") != CanonicalDigest(w.Authority) || childString(c, "candidateInventoryDigest") != cd || childString(c, "sourceTransportPermissionDigest") != reference || childString(c, "tupleDigest") != CanonicalDigest(m.Applicability) || m.Qualification.TupleDigest != CanonicalDigest(m.Applicability) || scope != expectedScope || ie != nil || xe != nil || qeerr != nil || ci.After(now) || !ci.Before(ce) || !now.Before(ce) || ce.After(expiry) || ce.After(qe) {
		return empty, ErrUntrusted
	}
	var entries []SourceLocalEntry
	if decode(c["entries"], &entries) != nil {
		return empty, ErrUntrusted
	}
	seen := map[string]bool{}
	found := 0
	for _, e := range entries {
		if seen[e.TargetID] {
			return empty, ErrUntrusted
		}
		seen[e.TargetID] = true
		if e == m.Entry {
			found++
		}
	}
	pt := childFields(m.PreparedTuple)
	if found != 1 || !sameProduct(pt["credentialBinding"], m.Applicability.Connection) || !sameProduct(pt["authority"], map[string]string{"providerId": m.Applicability.Model.ProviderID, "modelId": m.Applicability.Model.ModelID, "authMode": m.Applicability.Model.AuthMode}) {
		return empty, ErrUntrusted
	}
	if m.Phase == "execute" {
		r := childFields(m.PreparedReceipt)
		if !sameProduct(r["preparedTuple"], m.PreparedTuple) || !safeID.MatchString(childString(r, "nativeCredentialId")) {
			return empty, ErrUntrusted
		}
		preimage := map[string]json.RawMessage{"preparedTuple": r["preparedTuple"], "credentialId": r["credentialId"], "nativeCredentialId": r["nativeCredentialId"]}
		if m.TargetKind == "controller_activity" {
			preimage["preparationId"] = r["preparationId"]
			// SOURCE57 signs the outer LOCAL selection, not the native grant.
			// Metadata never admits execution; a present legacy inner envelope
			// must still verify, but its absence is not missing grant authority.
			if childString(r, "preparationId") != m.PreparationID || (!childWireAbsent(m.GrantEnvelope) && (verifyChildEnvelope(m.GrantEnvelope, childString(op, "keyId"), w.OperatorPEM) != nil || !sameProduct(childFields(m.GrantEnvelope)["payload"], m.Grant))) {
				return empty, ErrUntrusted
			}
		}
		if childString(r, "bindingDigest") != CanonicalDigest(preimage) {
			return empty, ErrUntrusted
		}
		preimage["bindingDigest"] = r["bindingDigest"]
		if childString(r, "preparedReceiptDigest") != CanonicalDigest(preimage) || childString(childFields(m.Grant), "preparedReceiptDigest") != childString(r, "preparedReceiptDigest") {
			return empty, ErrUntrusted
		}
	}
	return m, nil
}

// Selection is owner-derived from the fixed signed case3, NEVER a plugin option.
// Absence preserves unrelated SOURCE13/LIVE paths; a malformed present file denies.
func (p *Producer) SourceTransportSelected(ctx context.Context, t SourceTransportTarget) (bool, error) {
	if p == nil || ctx.Err() != nil {
		return false, ErrUntrusted
	}
	name := "source-local-transport-case3.json"
	if _, err := os.Lstat(filepath.Join(p.config.EvidenceRoot, name)); os.IsNotExist(err) {
		return false, nil
	}
	raw, err := p.read(name, 65536)
	authority, ae := p.read("physical-gate-authority.json", 65536)
	operator, ke := p.read("physical-gate-operator.pem", 4096)
	a := childFields(authority)
	op := childFields(a["operator"])
	if err != nil || ae != nil || ke != nil || childString(a, "evidenceClass") != "source" || workflowcontract.Validate(workflowcontract.SourceLocalTransport, "localCaseEnvelope", raw) != nil || verifyChildEnvelope(raw, childString(op, "keyId"), operator) != nil || childString(op, "keySHA256") != strings.TrimPrefix(Digest(operator), "sha256:") || !bytesCanonical(raw, json.RawMessage(raw)) {
		return false, ErrUntrusted
	}
	c := childFields(childFields(raw)["payload"])
	var entries []SourceLocalEntry
	if childString(c, "authorityDigest") != Digest(authority) || decode(c["entries"], &entries) != nil {
		return false, ErrUntrusted
	}
	for _, e := range entries {
		if e.TargetKind == t.TargetKind && e.TargetID == t.TargetID && e.SourceID == t.SourceID {
			// This selects a DENIAL/metadata boundary only, never grants. A changed
			// request for an enrolled target must not fall through into a paid lane.
			return true, nil
		}
	}
	return false, nil
}

func (p *Producer) ReadSourceTransportMetadata(ctx context.Context, raw []byte, t SourceTransportTarget) (SourceTransportMetadata, SourceTransportMetadataWitness, error) {
	var empty SourceTransportMetadata
	var w SourceTransportMetadataWitness
	if p == nil || p.key == nil || ctx.Err() != nil {
		return empty, w, ErrUntrusted
	}
	w.Target = t
	w.Producer = p.config
	var err error
	w.Authority, err = p.read("physical-gate-authority.json", 65536)
	if err != nil || childString(childFields(w.Authority), "evidenceClass") != "source" {
		return empty, w, ErrUntrusted
	}
	w.OperatorPEM, err = p.read("physical-gate-operator.pem", 4096)
	if err != nil {
		return empty, w, ErrUntrusted
	}
	der, err := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	if err != nil {
		return empty, w, ErrUntrusted
	}
	w.ProducerPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	m, err := VerifySourceTransportMetadata(raw, w, time.Now())
	if err != nil {
		return empty, w, err
	}
	pm := childFields(m.ProfileMetadata)
	reference := childString(pm, "sourceTransportPermissionDigest")
	originals := map[string][]byte{"physical-gate-authority.json": w.Authority, "physical-gate-operator.pem": w.OperatorPEM}
	for name, expected := range map[string]json.RawMessage{reference[7:]: pm["permission"], "source-profile-adoption-" + m.Applicability.Profile.ProfileDigest[7:] + ".json": pm["adoption"], "source-local-transport-case3.json": m.LocalCase} {
		b, err := p.read(name, 65536)
		if err != nil || !bytes.Equal(b, canonicalBytes(expected)) {
			return empty, w, ErrUntrusted
		}
		originals[name] = b
	}
	for name, b := range originals {
		again, err := p.read(name, 65536)
		if err != nil || !bytes.Equal(b, again) || ctx.Err() != nil {
			return empty, w, ErrUntrusted
		}
	}
	return m, w, nil
}
