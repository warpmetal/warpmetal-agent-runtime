package qualification

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func qualificationRootSourceProducer(t *testing.T, source, root string, expected QualificationProducerIdentity) *Producer {
	t.Helper()
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Fatal("root SOURCE gate requires real Linux root")
	}
	raw, err := os.ReadFile(source)
	var config ProducerConfig
	if err != nil || json.Unmarshal(raw, &config) != nil || (QualificationProducerIdentity{config.KeyID, config.KeySHA256, config.ServerID, config.NodeTokenHash}) != expected {
		t.Fatal("independent SOURCE producer configuration", err)
	}
	private, err := os.ReadFile(os.Getenv("WARPMETAL_QUALIFICATION_ROOT_PRIVATE_KEY"))
	if err != nil {
		t.Fatal("SOURCE private key mount unavailable")
	}
	config.KeyPath = filepath.Join(root, "producer.private.pem")
	config.EvidenceRoot = filepath.Join(root, "producer-evidence")
	if os.Mkdir(config.EvidenceRoot, 0700) != nil || os.WriteFile(config.KeyPath, private, 0600) != nil {
		t.Fatal("root producer private staging")
	}
	p, err := NewProducer(&config, expected.ServerID, expected.NodeTokenHash)
	if err != nil {
		t.Fatal("actual root NewProducer", err)
	}
	return p
}

// Actual Linux root signer, retained originals and owning import-tool verifier.
// Native output/artifact/report and pre-request clock are explicitly SOURCE
// suppliers; no signature, hook record or original timestamp is changed.
func testRootQualificationToolImport(t *testing.T, p *Producer, policy Policy, d Descriptor, selected QualificationActivation, o Observations, grant json.RawMessage) {
	t.Helper()
	root := filepath.Join(filepath.Dir(p.config.EvidenceRoot), "source-artifact-workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	owner := st.Sys().(*syscall.Stat_t)
	begin, err := time.Parse(time.RFC3339Nano, o.Requests[0].StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Begin(d, selected.Execution, policy.Run.Workload, root, uint64(owner.Dev), owner.Ino, begin); err != nil {
		t.Fatal("root baseline/source pre-request clock", err)
	}
	artifact := []byte("qualification")
	if Digest(artifact) != policy.Run.Workload.ExpectedArtifactSHA256 {
		t.Fatal("SOURCE artifact preimage not signed workload")
	}
	if err = os.WriteFile(filepath.Join(root, policy.Run.Workload.ArtifactRelativePath), artifact, 0600); err != nil {
		t.Fatal(err)
	}
	if CanonicalDigest(grant) != selected.Execution.GrantDigest {
		t.Fatal("original execution grant mismatch")
	}
	o.Blobs[selected.Execution.GrantDigest] = base64.StdEncoding.EncodeToString(canonicalBytes(grant))
	workspace := CanonicalDigest(map[string]string{"sourceWorkspace": "qualification-root-component"})
	id, err := p.AttestQualification(policy, d, selected, o, Digest([]byte("SOURCE terminal report; no native execution")), root, uint64(owner.Dev), owner.Ino, workspace, time.Now().UTC())
	if err != nil {
		t.Fatal("actual root qualification attestation", err)
	}
	raw, err := p.read(id[7:], 65536)
	var evidence qualificationCashEvidence
	if err != nil || decodeClosed(raw, &evidence) != nil {
		t.Fatal("retained attestation evidence", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	payload := childFields(raw)
	delete(payload, "producerAttestation")
	if err != nil || Digest(public) != p.config.KeySHA256 || verifyChildEnvelope(evidence.ProducerAttestation, p.config.KeyID, public) != nil || !sameProduct(childFields(evidence.ProducerAttestation)["payload"], payload) {
		t.Fatal("actual root producer signature or payload refused")
	}
	get := func(id string, limit int) ([]byte, error) {
		if !hash.MatchString(id) {
			return nil, ErrUntrusted
		}
		b, err := p.read(id[7:], limit)
		if err != nil || Digest(b) != id {
			return nil, ErrUntrusted
		}
		return b, nil
	}
	jsonGet := func(id string, limit int) (map[string]json.RawMessage, error) {
		b, e := get(id, limit)
		var v map[string]json.RawMessage
		if e != nil || decode(b, &v) != nil {
			return nil, ErrUntrusted
		}
		return v, nil
	}
	requests, responses := []map[string]json.RawMessage{}, []map[string]json.RawMessage{}
	for _, request := range evidence.Requests {
		a, e := jsonGet(request.RequestDigest, 32768)
		if e != nil {
			t.Fatal(e)
		}
		b, e := jsonGet(request.ResponseDigest, 262144)
		if e != nil {
			t.Fatal(e)
		}
		requests = append(requests, a)
		responses = append(responses, b)
	}
	if err = verifyQualificationCashTool(evidence, requests, responses, get, jsonGet); err != nil {
		t.Fatal("root signer evidence rejected by owning qualification tool import", err)
	}
	original, err := get(o.Tool.ObservationDigest, 262144)
	if err != nil || Digest(original) != o.Tool.ObservationDigest {
		t.Fatal("original hook observation lost")
	}
	again, err := p.AttestQualification(policy, d, selected, o, Digest([]byte("SOURCE terminal report; no native execution")), root, uint64(owner.Dev), owner.Ino, workspace, time.Now().UTC())
	if err != nil || again != id {
		t.Fatal("first root evidence replaced on replay", err)
	}
	t.Log("ROOT SOURCE signer→owning tool import; actual key ownership/append-only journal/file read; native/artifact/report/pre-request clock SOURCE; provider0; no full financial/backend import proof")
}
