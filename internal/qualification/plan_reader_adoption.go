package qualification

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Internal ROOT-private v1, frozen in the F3 handoff BEFORE implementation.
// These are not backend wire additions or operation-selectable adoption inputs.
type PlanReaderEvidenceRef struct {
	Name      string `json:"name"`
	Digest    string `json:"digest"`
	ByteCount int64  `json:"byteCount"`
}
type PlanReaderAdoption struct {
	FormatVersion               int                    `json:"formatVersion"`
	Reader                      model.PlanSourceReader `json:"reader"`
	TaskID                      string                 `json:"taskId"`
	ServerID                    string                 `json:"serverId"`
	NodeTokenHash               string                 `json:"nodeTokenHash"`
	RuntimeRevision             int64                  `json:"runtimeRevision"`
	RuntimeVersion              string                 `json:"runtimeVersion"`
	CandidateDescriptorDigest   string                 `json:"candidateDescriptorDigest"`
	RuntimeArchive              PlanReaderEvidenceRef  `json:"runtimeArchive"`
	RuntimeSignature            PlanReaderEvidenceRef  `json:"runtimeSignature"`
	TrustAnchorDigest           string                 `json:"trustAnchorDigest"`
	RuntimeBinaryMember         string                 `json:"runtimeBinaryMember"`
	RuntimeBinarySHA256         string                 `json:"runtimeBinarySHA256"`
	ImplementationInventory     PlanReaderEvidenceRef  `json:"implementationInventory"`
	ApprovedBuildEvidence       PlanReaderEvidenceRef  `json:"approvedBuildEvidence"`
	ArchiveVerificationEvidence PlanReaderEvidenceRef  `json:"archiveVerificationEvidence"`
	AdoptedAt                   string                 `json:"adoptedAt"`
	RecordDigest                string                 `json:"recordDigest"`
}
type planReaderCurrent struct {
	FormatVersion  int    `json:"formatVersion"`
	AdoptionDigest string `json:"adoptionDigest"`
}
type PlanReaderInput struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	ByteCount int64  `json:"byteCount"`
}
type PlanReaderBuildInputs struct {
	Version           string   `json:"version"`
	Command           []string `json:"command"`
	GoVersion         string   `json:"goVersion"`
	GOOS              string   `json:"goos"`
	GOARCH            string   `json:"goarch"`
	CGOEnabled        int      `json:"cgoEnabled"`
	ModuleGraphDigest string   `json:"moduleGraphDigest"`
}
type PlanReaderBuildInventory struct {
	FormatVersion int                   `json:"formatVersion"`
	Kind          string                `json:"kind"`
	Entries       []PlanReaderInput     `json:"entries"`
	Build         PlanReaderBuildInputs `json:"build"`
}
type PlanReaderApprovedBuild struct {
	FormatVersion             int    `json:"formatVersion"`
	Kind                      string `json:"kind"`
	ImplementationDigest      string `json:"implementationDigest"`
	RuntimeVersion            string `json:"runtimeVersion"`
	RuntimeArchiveSHA256      string `json:"runtimeArchiveSHA256"`
	RuntimeBinaryMember       string `json:"runtimeBinaryMember"`
	RuntimeBinarySHA256       string `json:"runtimeBinarySHA256"`
	ArchiveVerificationDigest string `json:"archiveVerificationDigest"`
	ApprovalReference         string `json:"approvalReference"`
}
type PlanReaderArchiveVerification struct {
	FormatVersion             int    `json:"formatVersion"`
	Kind                      string `json:"kind"`
	CandidateDescriptorDigest string `json:"candidateDescriptorDigest"`
	ArchiveSHA256             string `json:"archiveSHA256"`
	SignatureDigest           string `json:"signatureDigest"`
	TrustAnchorDigest         string `json:"trustAnchorDigest"`
	RuntimeVersion            string `json:"runtimeVersion"`
}

// Required connected seams, not a replacement for the COMPLETE approved
// inventory. Original protected approved lineage supplies completeness evidence.
var requiredPlanReaderInputs = func() []string {
	paths := []string{"Makefile", "cmd/warpmetald/main.go", "go.mod", "go.sum", "internal/api/plan_source.go", "internal/config/config.go",
		"internal/containers/plan_source.go", "internal/model/plan_source.go", "internal/qualification/plan_reader_adoption.go",
		"internal/qualification/plan_reader_archive.go", "internal/qualification/plan_source.go", "internal/qualification/producer.go",
		"internal/reconcile/plan_source.go", "internal/workflowcontract/contract.go", "internal/workflowcontract/schema/workspace-plan-genesis-v1.schema.json",
		"internal/workspacecatalog/plan_source.go", "packaging/install/install.sh", "packaging/systemd/warpmetald.service",
		"internal/workflowcontract/schema/workspace-child-product-v1.schema.json"}
	sort.Strings(paths)
	return paths
}()

func planReaderRecordDigest(a PlanReaderAdoption) string {
	raw, _ := json.Marshal(a)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "recordDigest")
	return CanonicalDigest(fields)
}
func evidenceName(name string) bool {
	return safeID.MatchString(name) && filepath.Base(name) == name && name != "." && name != ".."
}
func loadPlanReaderEvidence(load func(string, int) ([]byte, error), ref PlanReaderEvidenceRef, cap int) ([]byte, error) {
	if !evidenceName(ref.Name) || !hash.MatchString(ref.Digest) || ref.ByteCount < 1 || ref.ByteCount > int64(cap) {
		return nil, ErrUntrusted
	}
	raw, err := load(ref.Name, cap)
	if err != nil || int64(len(raw)) != ref.ByteCount || Digest(raw) != ref.Digest {
		return nil, ErrUntrusted
	}
	return raw, nil
}

// All injected functions below are PRIVATE source-test seams. Production uses
// SAME root-private Producer reads, actual archive verification and self inode.
func verifyPlanReaderAdoption(ctx context.Context, op model.PlanSourceReadOperation, current model.Manifest, producer ProducerConfig,
	load func(string, int) ([]byte, error), measure func() (string, error), verifyArchive func(context.Context, PlanReaderAdoption) error) (model.PlanSourceReader, error) {
	if op.Document.Owner.ServerID != current.ServerID || op.RuntimeRevision != current.DesiredRevision {
		return model.PlanSourceReader{}, ErrUntrusted
	}
	return verifyCurrentPlanReaderAdoption(ctx, op.Document.Owner.TaskID, &op.Reader, current, producer, load, measure, verifyArchive)
}

// Shared installed-artifact measurement, without creating a genesis operation,
// fence, source read or read credit for an unrelated PRODUCT consumer.
func verifyCurrentPlanReaderAdoption(ctx context.Context, taskID string, expected *model.PlanSourceReader, current model.Manifest, producer ProducerConfig,
	load func(string, int) ([]byte, error), measure func() (string, error), verifyArchive func(context.Context, PlanReaderAdoption) error) (model.PlanSourceReader, error) {
	return verifyCurrentPlanReaderArtifact(ctx, taskID, expected, nil, current, producer, load, measure, verifyArchive)
}

func verifyCurrentPlanReaderArtifact(ctx context.Context, taskID string, expected *model.PlanSourceReader, expectedRuntime *ArtifactIdentity, current model.Manifest, producer ProducerConfig,
	load func(string, int) ([]byte, error), measure func() (string, error), verifyArchive func(context.Context, PlanReaderAdoption) error) (model.PlanSourceReader, error) {
	var empty model.PlanSourceReader
	if ctx.Err() != nil || current.ServerID != producer.ServerID || !safeID.MatchString(taskID) || current.DesiredRevision < 1 {
		return empty, ErrUntrusted
	}
	raw, err := load("plan-source-reader-current.json", 65536)
	var pointer planReaderCurrent
	if err != nil || decodeClosed(raw, &pointer) != nil || pointer.FormatVersion != 1 || !hash.MatchString(pointer.AdoptionDigest) {
		return empty, ErrUntrusted
	}
	raw, err = load("plan-source-reader-adoption-"+pointer.AdoptionDigest[7:]+".json", 65536)
	var a PlanReaderAdoption
	if err != nil || decodeClosed(raw, &a) != nil || a.FormatVersion != 1 || a.RecordDigest != pointer.AdoptionDigest || planReaderRecordDigest(a) != a.RecordDigest {
		return empty, ErrUntrusted
	}
	raw, err = load("plan-source-reader-config.json", 65536)
	var config model.PlanSourceReaderConfig
	if err != nil || workflowcontract.Validate(workflowcontract.PlanGenesis, "readerConfig", raw) != nil || decodeClosed(raw, &config) != nil {
		return empty, ErrUntrusted
	}
	registered := model.WorkspaceRegisteredProducer{KeyID: producer.KeyID, KeySHA256: producer.KeySHA256, ServerID: producer.ServerID, NodeTokenHash: producer.NodeTokenHash}
	adoptedAt, err := time.Parse(time.RFC3339Nano, a.AdoptedAt)
	if err != nil || adoptedAt.After(time.Now()) || a.RuntimeRevision < 1 || (a.RuntimeVersion != "0.1.52" && a.RuntimeVersion != "0.1.54-e2.1") || a.TaskID != config.TaskID || a.TaskID != taskID ||
		a.ServerID != producer.ServerID || a.NodeTokenHash != producer.NodeTokenHash || config.NodeTokenHash != producer.NodeTokenHash || a.Reader.Producer != registered ||
		a.Reader != config.Reader || (expected != nil && a.Reader != *expected) || a.CandidateDescriptorDigest != a.Reader.CandidateDescriptorDigest ||
		!hash.MatchString(a.RuntimeBinarySHA256) || !hash.MatchString(a.TrustAnchorDigest) || !hash.MatchString(a.RuntimeArchive.Digest) ||
		!hash.MatchString(a.RuntimeSignature.Digest) || a.RuntimeArchive.ByteCount < 1 || a.RuntimeArchive.ByteCount > 256*1024*1024 ||
		a.RuntimeSignature.ByteCount < 1 || a.RuntimeSignature.ByteCount > 4096 || !evidenceName(a.RuntimeArchive.Name) || !evidenceName(a.RuntimeSignature.Name) ||
		a.RuntimeBinaryMember != "warpmetal-runtime-"+a.RuntimeVersion+"-linux-amd64/warpmetald" {
		return empty, ErrUntrusted
	}
	// A child must use the same admitted Runtime artifact, not merely a version
	// accepted elsewhere. Archive verification and running inode measurement below
	// remain mandatory for both the legacy release and this private candidate.
	if expectedRuntime != nil && *expectedRuntime != (ArtifactIdentity{Version: a.RuntimeVersion, ArchiveSHA256: a.RuntimeArchive.Digest, BinarySHA256: a.RuntimeBinarySHA256}) {
		return empty, ErrUntrusted
	}
	candidate, err := load("plan-source-reader-candidate.json", 65536)
	if err != nil || Digest(candidate) != a.CandidateDescriptorDigest || rejectDuplicates(candidate) != nil {
		return empty, ErrUntrusted
	}
	// Original descriptor remains F1-owned. Join ONLY its existing Runtime fields;
	// no binary/provenance/implementation field is inserted in that closed wire.
	var c map[string]json.RawMessage
	var runtime struct {
		Version       string `json:"version"`
		Source        string `json:"source"`
		ArchivePath   string `json:"archivePath"`
		ArchiveSHA256 string `json:"archiveSHA256"`
		SignaturePath string `json:"signaturePath"`
	}
	if json.Unmarshal(candidate, &c) != nil || decodeClosed(c["runtime"], &runtime) != nil || runtime.Version != a.RuntimeVersion || runtime.ArchiveSHA256 != strings.TrimPrefix(a.RuntimeArchive.Digest, "sha256:") || !strings.HasPrefix(runtime.Source, "https://") || runtime.ArchivePath == "" || runtime.SignaturePath == "" {
		return empty, ErrUntrusted
	}
	raw, err = loadPlanReaderEvidence(load, a.ImplementationInventory, 2*1024*1024)
	var inventory PlanReaderBuildInventory
	if err != nil || decodeClosed(raw, &inventory) != nil || CanonicalDigest(inventory) != a.Reader.ImplementationDigest || inventory.FormatVersion != 1 || inventory.Kind != "plan_source_reader_build_inventory" ||
		inventory.Build.Version != a.RuntimeVersion || !reflect.DeepEqual(inventory.Build.Command, []string{"make", "build", "VERSION=" + a.RuntimeVersion}) || inventory.Build.GOOS != "linux" || inventory.Build.GOARCH != "amd64" ||
		inventory.Build.CGOEnabled != 0 || inventory.Build.GoVersion == "" || len(inventory.Build.GoVersion) > 128 || !hash.MatchString(inventory.Build.ModuleGraphDigest) || len(inventory.Entries) > 8192 {
		return empty, ErrUntrusted
	}
	paths := make(map[string]bool)
	last := ""
	for _, f := range inventory.Entries {
		if f.Path <= last || filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path || f.Path == "." || strings.HasPrefix(f.Path, "../") || strings.ContainsAny(f.Path, "\\\x00") || !hash.MatchString(f.Digest) || f.ByteCount < 0 || f.ByteCount > 256*1024*1024 {
			return empty, ErrUntrusted
		}
		paths[f.Path] = true
		last = f.Path
	}
	for _, path := range requiredPlanReaderInputs {
		if !paths[path] {
			return empty, ErrUntrusted
		}
	}
	raw, err = loadPlanReaderEvidence(load, a.ArchiveVerificationEvidence, 65536)
	var verified PlanReaderArchiveVerification
	if err != nil || decodeClosed(raw, &verified) != nil || verified != (PlanReaderArchiveVerification{1, "verified_runtime_archive", a.CandidateDescriptorDigest, a.RuntimeArchive.Digest, a.RuntimeSignature.Digest, a.TrustAnchorDigest, a.RuntimeVersion}) {
		return empty, ErrUntrusted
	}
	raw, err = loadPlanReaderEvidence(load, a.ApprovedBuildEvidence, 65536)
	var build PlanReaderApprovedBuild
	if err != nil || decodeClosed(raw, &build) != nil || !safeID.MatchString(build.ApprovalReference) || build != (PlanReaderApprovedBuild{1, "approved_reader_build", a.Reader.ImplementationDigest, a.RuntimeVersion, a.RuntimeArchive.Digest, a.RuntimeBinaryMember, a.RuntimeBinarySHA256, a.ArchiveVerificationEvidence.Digest, build.ApprovalReference}) {
		return empty, ErrUntrusted
	}
	if verifyArchive(ctx, a) != nil || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	actual, err := measure()
	if err != nil || actual != a.RuntimeBinarySHA256 || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	// Never let a historical pointer become current across a deployment/config
	// change while the archive/self comparison was running.
	for _, selected := range []struct{ name, digest string }{
		{"plan-source-reader-current.json", CanonicalDigest(pointer)},
		{"plan-source-reader-config.json", CanonicalDigest(config)},
	} {
		raw, err := load(selected.name, 65536)
		var value any
		if err != nil || decode(raw, &value) != nil || CanonicalDigest(value) != selected.digest {
			return empty, ErrUntrusted
		}
	}
	candidate, err = load("plan-source-reader-candidate.json", 65536)
	if err != nil || Digest(candidate) != a.CandidateDescriptorDigest {
		return empty, ErrUntrusted
	}
	anchor, err := load("plan-source-reader-trust-anchor.pem", 4096)
	if err != nil || Digest(anchor) != a.TrustAnchorDigest {
		return empty, ErrUntrusted
	}
	return a.Reader, nil
}

func (p *Producer) InstalledPlanSourceReader(ctx context.Context, op model.PlanSourceReadOperation, current model.Manifest) (model.PlanSourceReader, error) {
	if op.Validate() != nil {
		return model.PlanSourceReader{}, ErrUntrusted
	}
	return verifyPlanReaderAdoption(ctx, op, current, p.config, p.read, SelfBinaryDigest, p.verifyPlanReaderArchive)
}
