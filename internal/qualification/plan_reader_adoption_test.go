package qualification

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Explicitly synthetic protected adoption/comparison supplier. No archive build,
// signature/key creation, installed adoption or source staging. Existing reader
// tests exercise the actual complete file read; this gate must stop BEFORE it.
func TestPlanReaderAdoptionMissingAndRunningMeasurementMismatch(t *testing.T) {
	for _, version := range []string{"0.1.52", "0.1.54-e2.1"} {
		t.Run(version, func(t *testing.T) { verifySyntheticPlanReaderAdoption(t, version) })
	}
}

func verifySyntheticPlanReaderAdoption(t *testing.T, version string) {
	op := syntheticPlanReadOperation([]byte("synthetic source"))
	current := model.Manifest{ServerID: "server", DesiredRevision: 7}
	op.RuntimeRevision = 7
	root, _ := filepath.EvalSymlinks(t.TempDir())
	j := testPlanReadJournal{root: root}
	producer := ProducerConfig{KeyID: "key", KeySHA256: op.Reader.Producer.KeySHA256, ServerID: "server", NodeTokenHash: strings.Repeat("b", 64)}
	measures, verifies := 0, 0
	measure := func() (string, error) { measures++; return SelfBinaryDigest() }
	verify := func(context.Context, PlanReaderAdoption) error { verifies++; return nil } // synthetic archive proof ONLY
	if _, err := verifyPlanReaderAdoption(context.Background(), op, current, producer, j.load, measure, verify); err == nil || measures != 0 || verifies != 0 {
		t.Fatal("missing independently selected adoption advanced")
	}
	put := func(name string, value any) PlanReaderEvidenceRef {
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return PlanReaderEvidenceRef{Name: name, Digest: Digest(raw), ByteCount: int64(len(raw))}
	}
	h := Digest([]byte("synthetic pin"))
	if err := os.WriteFile(filepath.Join(root, "plan-source-reader-trust-anchor.pem"), []byte("synthetic pin"), 0600); err != nil {
		t.Fatal(err)
	} // synthetic comparison bytes, NOT an actual PEM or trust/key adoption
	inventory := PlanReaderBuildInventory{FormatVersion: 1, Kind: "plan_source_reader_build_inventory",
		Build: PlanReaderBuildInputs{Version: version, Command: []string{"make", "build", "VERSION=" + version}, GoVersion: "synthetic-go-toolchain", GOOS: "linux", GOARCH: "amd64", CGOEnabled: 0, ModuleGraphDigest: h}}
	for _, path := range requiredPlanReaderInputs {
		inventory.Entries = append(inventory.Entries, PlanReaderInput{Path: path, Digest: h, ByteCount: 1})
	}
	op.Reader.ImplementationDigest = CanonicalDigest(inventory)
	candidate := []byte(`{"runtime":{"version":"` + version + `","source":"https://synthetic.invalid/runtime.tgz","archivePath":"/synthetic/runtime.tgz","archiveSHA256":"` + strings.TrimPrefix(h, "sha256:") + `","signaturePath":"/synthetic/runtime.sig"}}`)
	op.Reader.CandidateDescriptorDigest = Digest(candidate)
	if err := os.WriteFile(filepath.Join(root, "plan-source-reader-candidate.json"), candidate, 0600); err != nil {
		t.Fatal(err)
	}
	put("plan-source-reader-config.json", model.PlanSourceReaderConfig{FormatVersion: 1, TaskID: "task", NodeTokenHash: producer.NodeTokenHash, Reader: op.Reader})
	a := PlanReaderAdoption{FormatVersion: 1, Reader: op.Reader, TaskID: "task", ServerID: "server", NodeTokenHash: producer.NodeTokenHash,
		RuntimeRevision: 1, RuntimeVersion: version, CandidateDescriptorDigest: op.Reader.CandidateDescriptorDigest,
		RuntimeBinaryMember: "warpmetal-runtime-" + version + "-linux-amd64/warpmetald", RuntimeBinarySHA256: h, TrustAnchorDigest: h, AdoptedAt: "2026-10-12T00:00:00Z",
		RuntimeArchive: PlanReaderEvidenceRef{Name: "runtime.tgz", Digest: h, ByteCount: 1}, RuntimeSignature: PlanReaderEvidenceRef{Name: "runtime.sig", Digest: h, ByteCount: 1}}
	a.ImplementationInventory = put("inventory.json", inventory)
	v := PlanReaderArchiveVerification{FormatVersion: 1, Kind: "verified_runtime_archive", CandidateDescriptorDigest: a.CandidateDescriptorDigest, ArchiveSHA256: h,
		SignatureDigest: h, TrustAnchorDigest: h, RuntimeVersion: a.RuntimeVersion}
	a.ArchiveVerificationEvidence = put("archive-verification.json", v)
	a.ApprovedBuildEvidence = put("approved-build.json", PlanReaderApprovedBuild{FormatVersion: 1, Kind: "approved_reader_build", ImplementationDigest: op.Reader.ImplementationDigest,
		RuntimeVersion: a.RuntimeVersion, RuntimeArchiveSHA256: h, RuntimeBinaryMember: a.RuntimeBinaryMember, RuntimeBinarySHA256: h,
		ArchiveVerificationDigest: a.ArchiveVerificationEvidence.Digest, ApprovalReference: "synthetic-manager-approval"})
	a.RecordDigest = planReaderRecordDigest(a)
	put("plan-source-reader-adoption-"+a.RecordDigest[7:]+".json", a)
	put("plan-source-reader-current.json", planReaderCurrent{FormatVersion: 1, AdoptionDigest: a.RecordDigest})
	if _, err := verifyPlanReaderAdoption(context.Background(), op, current, producer, j.load, measure, verify); err == nil || measures != 1 || verifies != 1 {
		t.Fatalf("actual running measurement mismatch advanced, or comparison not reached: %v measurements=%d verifications=%d", err, measures, verifies)
	}
	// Historical adoption revision is NOT the operation's live Runtime revision.
	actual, err := SelfBinaryDigest()
	if err != nil {
		t.Fatal(err)
	}
	measure = func() (string, error) { return a.RuntimeBinarySHA256, nil } // explicit synthetic match; not installed evidence
	if actual == a.RuntimeBinarySHA256 {
		t.Fatal("synthetic pin unexpectedly actual binary")
	}
	if reader, err := verifyPlanReaderAdoption(context.Background(), op, current, producer, j.load, measure, verify); err != nil || reader != a.Reader {
		t.Fatalf("unchanged protected adoption across current revision: %v", err)
	}
	artifact := ArtifactIdentity{Version: version, ArchiveSHA256: a.RuntimeArchive.Digest, BinarySHA256: a.RuntimeBinarySHA256}
	if _, err := verifyCurrentPlanReaderArtifact(context.Background(), "task", nil, &artifact, current, producer, j.load, measure, verify); err != nil {
		t.Fatalf("child's exact admitted runtime artifact refused: %v", err)
	}
	for _, field := range []string{"version", "archive", "binary"} {
		foreign := artifact
		switch field {
		case "version":
			foreign.Version = "0.1.53"
		case "archive":
			foreign.ArchiveSHA256 = Digest([]byte("another archive"))
		case "binary":
			foreign.BinarySHA256 = Digest([]byte("another executable"))
		}
		if _, err := verifyCurrentPlanReaderArtifact(context.Background(), "task", nil, &foreign, current, producer, j.load, measure, verify); err == nil {
			t.Fatalf("child runtime %s disagreed with admitted candidate", field)
		}
	}
	current.DesiredRevision = 8
	if _, err := verifyPlanReaderAdoption(context.Background(), op, current, producer, j.load, measure, verify); err == nil {
		t.Fatal("historical adoption supplied live revision")
	}
	current.DesiredRevision = 7
	if err := os.WriteFile(filepath.Join(root, "plan-source-reader-candidate.json"), append(candidate, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPlanReaderAdoption(context.Background(), op, current, producer, j.load, measure, verify); err == nil {
		t.Fatal("canonicalized/changed original candidate reused")
	}
}
