package qualification

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// The backend original and native publication are separate signed documents.
// Their distinct digests and serialization are retained throughout selection.
type QualificationPublication struct {
	Digest          string `json:"digest"`
	ContentBase64   string `json:"contentBase64"`
	SignatureBase64 string `json:"signatureBase64"`
}
type QualificationProducerIdentity struct {
	KeyID         string `json:"keyId"`
	KeySHA256     string `json:"keySHA256"`
	ServerID      string `json:"serverId"`
	NodeTokenHash string `json:"nodeTokenHash"`
}
type NativeQualificationActivation struct {
	FormatVersion            int                      `json:"formatVersion"`
	Mode                     string                   `json:"mode"`
	ProviderPolicyDigest     string                   `json:"providerPolicyDigest"`
	AccountingVersion        int                      `json:"accountingVersion"`
	Purpose                  string                   `json:"purpose"`
	SidecarPolicyDigest      string                   `json:"sidecarPolicyDigest"`
	SourcePolicyDigest       string                   `json:"sourcePolicyDigest"`
	SourceActivation         QualificationPublication `json:"sourceActivation"`
	AuthorizationObservation json.RawMessage          `json:"authorizationObservation"`
	IssuedAt                 string                   `json:"issuedAt"`
	ExpiresAt                string                   `json:"expiresAt"`
}
type QualificationActivation struct {
	Execution           Activation
	Native              *NativeQualificationActivation
	Publication         *QualificationPublication
	AuthorizationSHA256 string
	PhysicalAllocation  *DemandAllocation
}

func qualificationBase64(value string, maximum int) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) > maximum || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, ErrUntrusted
	}
	return raw, nil
}
func qualificationPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrUntrusted
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, ErrUntrusted
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok || ec.Curve.Params().Name != "P-256" {
		return nil, ErrUntrusted
	}
	return ec, nil
}
func (p QualificationPublication) verify(document, definition string, public []byte) ([]byte, error) {
	raw, err := qualificationBase64(p.ContentBase64, 32768)
	if err != nil || Digest(raw) != p.Digest || workflowcontract.Validate(document, definition, raw) != nil {
		return nil, ErrUntrusted
	}
	sig, err := qualificationBase64(p.SignatureBase64, 80)
	if err != nil {
		return nil, ErrUntrusted
	}
	key, err := qualificationPublicKey(public)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if !ecdsa.VerifyASN1(key, sum[:], sig) {
		return nil, ErrUntrusted
	}
	return raw, nil
}
func beforeOrEqual(a, b string) bool {
	x, e := time.Parse(time.RFC3339Nano, a)
	y, f := time.Parse(time.RFC3339Nano, b)
	return e == nil && f == nil && !x.After(y)
}

func (s Store) enrolledQualificationProducer() (QualificationProducerIdentity, error) {
	if s.sourceProducerIdentity != nil {
		return *s.sourceProducerIdentity, nil
	}
	p, err := NewProducer(s.ProducerConfig, s.ProducerServerID, s.ProducerNodeTokenHash)
	if err != nil {
		return QualificationProducerIdentity{}, err
	}
	c := p.config
	return QualificationProducerIdentity{c.KeyID, c.KeySHA256, c.ServerID, c.NodeTokenHash}, nil
}
func (s Store) verifyNativeBootstrap(raw []byte, b Bootstrap, public []byte, now time.Time) error {
	nativeContract, sourceContract, familyOK := qualificationFamily(b.Case)
	if !familyOK || workflowcontract.Validate(nativeContract, "nativeBootstrap3", raw) != nil || !b.Case.typed() || b.SourceBootstrap == nil || b.Producer == nil {
		return ErrUntrusted
	}
	source, err := b.SourceBootstrap.verify(sourceContract, "bootstrap3", public)
	if err != nil {
		return err
	}
	fields := childFields(source)
	if !live(b.ExpiresAt, now) || !beforeOrEqual(b.ExpiresAt, childString(fields, "expiresAt")) || !beforeOrEqual(childString(fields, "issuedAt"), b.ExpiresAt) || Digest(public) != b.Case.OperatorKeySHA256 || b.CampaignID != b.Case.CaseID || b.Ceilings.Requests != b.Case.ModelRequests || b.Ceilings.Preparations != b.Case.Preparations {
		return ErrUntrusted
	}
	ours := childFields(raw)
	for _, name := range []string{"campaignId", "sandboxId", "sandboxGeneration", "profileId", "profileDigest", "providerPolicyDigest", "accountingVersion"} {
		if !sameProduct(ours[name], fields[name]) {
			return ErrUntrusted
		}
	}
	if b.ImageDigest[strings.LastIndex(b.ImageDigest, "@")+1:] != childString(fields, "imageDigest") {
		return ErrUntrusted
	}
	sourceCase := childFields(fields["case"])
	for name, value := range map[string]string{"caseId": b.Case.CaseID, "caseManifestDigest": b.Case.CaseManifestDigest, "ledgerId": b.Case.LedgerID} {
		if childString(sourceCase, name) != value {
			return ErrUntrusted
		}
	}
	producer, err := qualificationBase64(b.ProducerPublicKeyBase64, 4096)
	if err != nil || Digest(producer) != b.Producer.KeySHA256 {
		return ErrUntrusted
	}
	if _, err = qualificationPublicKey(producer); err != nil {
		return err
	}
	enrolled, err := s.enrolledQualificationProducer()
	if err != nil || enrolled != *b.Producer || enrolled.KeySHA256 == Digest(public) {
		return ErrUntrusted
	}
	return nil
}
func flashQualificationBudget() Budget {
	b := RealBudget()
	b.PricingDigest = providerpolicy.FlashPricingDigest()
	return b
}

// qualificationNativeBudget selects the immutable qualification budget/pricing
// family pinned by the bundle. Both descriptor families share the same
// conservative flash pricing digest, but the selection is explicit and
// fail-closed so an unknown family never inherits legacy expectations.
func qualificationNativeBudget(c *RealCase) (Budget, bool) {
	if _, ok := qualificationProviderDescriptor(c); !ok {
		return Budget{}, false
	}
	return flashQualificationBudget(), true
}
func validNativeRun(b Bootstrap, p Policy) bool {
	if p.Run == nil || b.Case == nil {
		return false
	}
	budget, familyOK := qualificationNativeBudget(b.Case)
	policy, descriptorOK := qualificationProviderDescriptor(b.Case)
	if !familyOK || !descriptorOK {
		return false
	}
	budgetContract := workflowcontract.BudgetProvider
	if b.Case.FormatVersion == 5 {
		budgetContract = workflowcontract.BudgetParticipants
	}
	r, t, w := p.Run, p.Run.Tuple, p.Run.Workload
	if r.Purpose != "model_qualification_bootstrap" || !safeID.MatchString(r.QualificationID) || !safeID.MatchString(r.ReservationID) || !hash.MatchString(r.CreatePermitDigest) || r.TupleDigest != CanonicalDigest(t) || r.Budget != budget || t.CaseManifestDigest != b.Case.CaseManifestDigest || t.SandboxID != b.SandboxID || t.SandboxGeneration != b.SandboxGeneration || t.ServerID != b.Producer.ServerID || t.Profile.ProfileID != b.ProfileID || t.Profile.ProfileDigest != b.ProfileDigest || t.Connection.ProviderID != policy.ProviderID || t.Model.ProviderID != policy.ProviderID || t.Model.ModelID != policy.ModelID || t.Model.AuthMode != policy.AuthMode || t.Model.Endpoint != policy.Transport.URL || p.ProviderID != policy.ProviderID || p.ModelID != policy.ModelID || t.Sandbox.RegistryManifestDigest != b.ImageDigest[strings.LastIndex(b.ImageDigest, "@")+1:] || t.Sandbox.PluginDigest != b.PluginSHA256 || w.Revision != 1 || w.Tool != "shell" || w.TimeoutSeconds != 120 || !artifactName.MatchString(w.ArtifactRelativePath) {
		return false
	}
	return workflowcontract.Validate(budgetContract, "artifactApplicability2", canonicalBytes(t)) == nil
}
func (s Store) verifyNativePolicy(raw []byte, b Bootstrap, p Policy, public []byte, now time.Time) error {
	nativeContract, sourceContract, familyOK := qualificationFamily(b.Case)
	if !familyOK || workflowcontract.Validate(nativeContract, "nativePolicy4", raw) != nil || b.FormatVersion != 3 || p.SourcePolicy == nil || b.SourceBootstrap == nil || !validNativeRun(b, p) {
		return ErrUntrusted
	}
	// Bootstrap digest pins its exact signed native serialization, not a rewritten projection.
	tree, key, err := s.Paths(b.SandboxID)
	if err != nil {
		return err
	}
	bootRaw, err := s.signed(tree, key, "bootstrap", 32768)
	if err != nil || p.SidecarBootstrapDigest != Digest(bootRaw) || p.SourceBootstrapDigest != b.SourceBootstrap.Digest {
		return ErrUntrusted
	}
	source, err := p.SourcePolicy.verify(sourceContract, "policy4", public)
	if err != nil {
		return err
	}
	sourceBoot, err := b.SourceBootstrap.verify(sourceContract, "bootstrap3", public)
	if err != nil {
		return err
	}
	f, sb := childFields(source), childFields(sourceBoot)
	if !live(p.ExpiresAt, now) || !beforeOrEqual(p.ExpiresAt, b.ExpiresAt) || !beforeOrEqual(p.ExpiresAt, childString(f, "expiresAt")) || !beforeOrEqual(childString(f, "issuedAt"), p.ExpiresAt) {
		return ErrUntrusted
	}
	for k, value := range sb {
		if k == "formatVersion" || k == "case" || k == "issuedAt" || k == "expiresAt" {
			continue
		}
		if !sameProduct(value, f[k]) {
			return ErrUntrusted
		}
	}
	if !sameProduct(p.Preparations, f["preparations"]) {
		return ErrUntrusted
	}
	r, q := p.Run, childFields(f["run"])
	t := r.Tuple
	for k, value := range map[string]string{"qualificationId": r.QualificationID, "reservationId": r.ReservationID, "tupleDigest": r.TupleDigest, "permitDigest": r.CreatePermitDigest, "caseId": b.Case.CaseID, "caseManifestDigest": b.Case.CaseManifestDigest, "providerEndpoint": providerpolicy.Flash().Transport.URL} {
		if childString(q, k) != value {
			return ErrUntrusted
		}
	}
	if !sameProduct(r.Workload, q["workload"]) || !sameProduct(r.Budget, q["budget"]) || childString(f, "nativeVersion") != t.Native.Version || childString(f, "binaryDigest") != t.Native.BinarySHA256 || childString(f, "runtimeVersion") != t.Runtime.Version || !sameProduct(f["profileRevision"], t.Profile.Revision) || childString(f, "bundleDigest") != t.Profile.BundleDigest {
		return ErrUntrusted
	}
	return nil
}

// Legacy reader stays unchanged. Successor selection returns the original
// backend Activation2 plus its separately verified native publication.
func (s Store) ReadQualificationActivation(box model.Sandbox, b Bootstrap, p Policy, d Descriptor, now time.Time) (QualificationActivation, error) {
	if p.FormatVersion != 4 {
		a, err := s.ReadActivation(box, b, p, d, now)
		return QualificationActivation{Execution: a, AuthorizationSHA256: p.AuthorizationSHA256}, err
	}
	var out QualificationActivation
	current, err := s.Bootstrap(box, box.ImageDigest, now)
	if err != nil || !sameProduct(current, b) {
		return out, ErrUntrusted
	}
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return out, err
	}
	raw, err := s.signed(tree, key, "activations/"+d.PreparationID, 32768)
	if err != nil {
		return out, err
	}
	sig, err := s.read(filepath.Join(tree, "activations", d.PreparationID+".sig"), tree, key, 256)
	if err != nil {
		return out, err
	}
	public, err := s.read(key, tree, key, 4096)
	if err != nil {
		return out, err
	}
	policyRaw, err := s.signed(tree, key, "snapshots/"+d.PolicyDigest[7:]+"/policy", 32768)
	if err != nil || Digest(policyRaw) != d.PolicyDigest || !sameProduct(json.RawMessage(policyRaw), p) || s.verifyNativePolicy(policyRaw, b, p, public, now) != nil {
		return out, ErrUntrusted
	}
	publication := QualificationPublication{Digest(raw), base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(sig)}
	return s.verifyNativeActivation(publication, b, p, d, public, now)
}
func (s Store) verifyNativeActivation(pub QualificationPublication, b Bootstrap, p Policy, d Descriptor, public []byte, now time.Time) (QualificationActivation, error) {
	var out QualificationActivation
	nativeContract, sourceContract, familyOK := qualificationFamily(b.Case)
	if !familyOK {
		return out, ErrUntrusted
	}
	raw, err := pub.verify(nativeContract, "nativeActivation3", public)
	if err != nil {
		return out, err
	}
	var a NativeQualificationActivation
	if decodeClosed(raw, &a) != nil || b.Producer == nil || p.Run == nil || p.SourcePolicy == nil || len(p.Preparations) != 1 {
		return out, ErrUntrusted
	}
	source, err := a.SourceActivation.verify(sourceContract, "activation2", public)
	if err != nil {
		return out, err
	}
	var execution Activation
	if decodeClosed(source, &execution) != nil {
		return out, ErrUntrusted
	}
	producer, err := qualificationBase64(b.ProducerPublicKeyBase64, 4096)
	if err != nil || Digest(producer) != b.Producer.KeySHA256 || verifyChildEnvelope(a.AuthorizationObservation, b.Producer.KeyID, producer) != nil {
		return out, ErrUntrusted
	}
	if a.SidecarPolicyDigest != d.PolicyDigest || a.SourcePolicyDigest != p.SourcePolicy.Digest || execution.PolicyDigest != a.SourcePolicyDigest || !live(a.ExpiresAt, now) || a.ExpiresAt != execution.ExpiresAt || !beforeOrEqual(execution.IssuedAt, a.IssuedAt) || !beforeOrEqual(a.IssuedAt, a.ExpiresAt) || !beforeOrEqual(a.ExpiresAt, p.ExpiresAt) {
		return out, ErrUntrusted
	}
	r, prep := p.Run, p.Preparations[0]
	if b.Case == nil || execution.FormatVersion != 2 || execution.ProviderPolicyDigest != p.ProviderPolicyDigest || execution.AccountingVersion != 2 || execution.Purpose != r.Purpose || execution.QualificationID != r.QualificationID || execution.ReservationID != r.ReservationID || execution.CaseID != b.Case.CaseID || execution.CaseManifestDigest != b.Case.CaseManifestDigest || execution.TupleDigest != r.TupleDigest || execution.PreparationID != d.PreparationID || execution.PreparedTupleDigest != d.PreparedTupleDigest || execution.BudgetDigest != CanonicalDigest(r.Budget) || execution.PermitDigest != r.CreatePermitDigest || execution.DispatchStart+1 > b.Ceilings.Requests || execution.PreparationIndex > b.Ceilings.Preparations {
		return out, ErrUntrusted
	}
	i, ie := time.Parse(time.RFC3339Nano, a.IssuedAt)
	start, se := time.Parse(time.RFC3339Nano, execution.IssuedAt)
	end, ee := time.Parse(time.RFC3339Nano, execution.ExpiresAt)
	header := childFields(childFields(a.AuthorizationObservation)["payload"])
	observed, oe := time.Parse(time.RFC3339Nano, childString(header, "observedAt"))
	if ie != nil || se != nil || ee != nil || oe != nil || i.After(now.Add(30*time.Second)) || !start.Before(end) || end.Sub(start) > 120*time.Second || observed.After(i) || i.Sub(observed) > 5*time.Minute {
		return out, ErrUntrusted
	}
	for k, value := range map[string]string{"taskId": r.Tuple.TaskID, "nodeTokenHash": b.Producer.NodeTokenHash, "qualificationId": r.QualificationID, "preparationId": prep.PreparationID, "preparedTupleDigest": p.PreparedTupleDigest, "preparedReceiptDigest": execution.PreparedReceiptDigest, "nativeSessionId": prep.SessionID, "nativeInputId": prep.InputID} {
		if childString(header, k) != value {
			return out, ErrUntrusted
		}
	}
	out = QualificationActivation{Execution: execution, Native: &a, Publication: &pub, AuthorizationSHA256: childString(header, "authorizationSha256")}
	return out, nil
}
