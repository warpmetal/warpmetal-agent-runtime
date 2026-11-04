package agentkit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func compiledVenue(t *testing.T) Venue {
	t.Helper()
	venue, err := SelectVenue("TEST-wp211-kit-materialization")
	if err != nil || venue == nil {
		t.Fatalf("select venue: %v", err)
	}
	return *venue
}

// invocationFixture rebuilds the exact request the packaged supervisor consumed
// (from the invocation fixture itself), so the Go builder is compared against a
// real cross-language artifact rather than a hand-written expectation.
func invocationFixture(t *testing.T) (Request, Venue, []byte, map[string]json.RawMessage) {
	t.Helper()
	envelope := readFixture(t, "agent-kit-invocation-envelope.json")
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(envelope, &fields); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(readFixture(t, "agent-kit-invocation-document.json"), &document); err != nil {
		t.Fatalf("decode invocation document: %v", err)
	}
	var nested Request
	if err := json.Unmarshal(document["request"], &nested); err != nil {
		t.Fatalf("decode nested request: %v", err)
	}
	_ = fields
	var config map[string]json.RawMessage
	if err := json.Unmarshal(readFixture(t, "deepseek-agent-config.json"), &config); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	operation := model.WorkspaceApplicationOperation{
		ConfigurationID:       nested.Configuration.ConfigurationID,
		ConfigurationRevision: nested.Configuration.ConfigurationRevision,
		ConfigurationDigest:   nested.Configuration.ConfigurationDigest,
		Configuration: model.WorkspaceConfiguration{
			AgentSetup: config["agentSetup"],
		},
	}
	venue := compiledVenue(t)
	built, err := BuildRequest(operation, nested.Target, nested.SkillsSnapshot, venue)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return built, venue, envelope, fields
}

func canonicalOf(t *testing.T, value any) string {
	t.Helper()
	raw, err := canonicalJSON(value)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return string(raw)
}

func TestCompiledAdoptionRecordValues(t *testing.T) {
	venue := compiledVenue(t)
	want := map[string]string{
		"installedVenue":         "TEST-wp211a-installed-a",
		"adoptionId":             "WP211A-MAT-ADOPT-1",
		"closureVersion":         "warpmetal-agent-kit-content-v1",
		"closureDigest":          "sha256:e201054ea5cf80d6bbc8d3b68ea5bc7e9ed0fc7a0301689ae20837b30d7da965",
		"materializerDigest":     "sha256:98393bbf735f67052cccfea2321953e09240431e3e30b5d819020ead4d39e87a",
		"snapshotManifestDigest": "sha256:387d0ca5212174d1ddcb488c55a2f811ae98377f201aece46251fb6847f4a8aa",
	}
	got := map[string]string{
		"installedVenue":         venue.InstalledVenue,
		"adoptionId":             venue.AdoptionID,
		"closureVersion":         venue.ClosureVersion,
		"closureDigest":          venue.ClosureDigest,
		"materializerDigest":     venue.MaterializerDigest,
		"snapshotManifestDigest": venue.SnapshotManifestDigest,
	}
	for key, expected := range want {
		if got[key] != expected {
			t.Fatalf("compiled %s = %q, want %q", key, got[key], expected)
		}
	}
	if venue.ClosureFileCount != 220 || venue.ClosureByteCount != 1788358 {
		t.Fatalf("compiled closure size = %d/%d", venue.ClosureFileCount, venue.ClosureByteCount)
	}
}

// The Runtime-built invocation is canonically identical to the real document the
// packaged supervisor consumed to produce the retained envelope.
func TestBuildInvocationMatchesSupervisorDocument(t *testing.T) {
	built, venue, _, _ := invocationFixture(t)
	invocation, err := BuildInvocation(built, venue)
	if err != nil {
		t.Fatalf("build invocation: %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(readFixture(t, "agent-kit-invocation-document.json"), &document); err != nil {
		t.Fatalf("decode document fixture: %v", err)
	}
	got := canonicalOf(t, invocation)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("decode built invocation: %v", err)
	}
	var expected map[string]any
	if err := json.Unmarshal(readFixture(t, "agent-kit-invocation-document.json"), &expected); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	// The fixture document also carries the generated materializer request; the
	// builder must reproduce the whole document exactly (including request).
	if got != canonicalOf(t, expected) {
		t.Fatalf("built invocation differs from supervisor document\n got: %s\nwant: %s", got, canonicalOf(t, expected))
	}
	if invocation.TimeoutSeconds != 30 || invocation.Instance != "agent-kit" || invocation.ProfileID != "opencode" {
		t.Fatalf("invocation defaults: %+v", invocation)
	}
	if invocation.ImageClosure.ClosureDigest != venue.ClosureDigest {
		t.Fatalf("declared closure is not the compiled adoption record")
	}
}

func TestVerifyInvocationAcceptsRealSupervisorEnvelope(t *testing.T) {
	built, venue, envelope, _ := invocationFixture(t)
	result, err := VerifyInvocation(built, venue, envelope)
	if err != nil {
		t.Fatalf("verify invocation: %v", err)
	}
	if result.Status != "ready" || !result.Ready || result.Venue != "TEST-wp211a-installed-a" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Closure.ClosureDigest != venue.ClosureDigest ||
		result.Closure.FileCount != venue.ClosureFileCount ||
		result.Closure.ByteCount != venue.ClosureByteCount {
		t.Fatalf("closure drift: %+v", result.Closure)
	}
	if result.Closure.Measurer != "source" {
		t.Fatalf("expected qualification source measurer, got %q", result.Closure.Measurer)
	}
	if result.Materialization.Status != "ready" || result.Materialization.Actions["created"] != 13 {
		t.Fatalf("materialization receipt: %+v", result.Materialization)
	}
	if result.Materialization.Instruction.Path != "AGENTS.md" ||
		result.Materialization.Instruction.SHA256 == "" {
		t.Fatalf("agents.md fact missing")
	}
}

// resignEnvelope recomputes the supervisor-style envelope digest after a test
// mutation so a targeted check (not the digest check) is under test.
func resignEnvelope(t *testing.T, envelope []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(envelope))
	decoder.UseNumber()
	var tree map[string]any
	if err := decoder.Decode(&tree); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	mutate(tree)
	delete(tree, "receiptDigest")
	digest, err := Digest(tree)
	if err != nil {
		t.Fatalf("resign: %v", err)
	}
	tree["receiptDigest"] = digest
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return raw
}

func TestVerifyInvocationRefusesDrift(t *testing.T) {
	built, venue, envelope, _ := invocationFixture(t)

	tampered := append([]byte(nil), envelope...)
	tampered = []byte(replaceOnce(string(tampered), `"receiptDigest": "sha256:`, `"receiptDigest": "sha256:0`))
	if _, err := VerifyInvocation(built, venue, tampered); !hasCode(err, "agent_kit_receipt_digest_mismatch") {
		t.Fatalf("tampered digest must refuse, got %v", err)
	}

	closureDrift := resignEnvelope(t, envelope, func(tree map[string]any) {
		closure := tree["closure"].(map[string]any)
		closure["closureDigest"] = "sha256:" + strings.Repeat("0", 64)
	})
	if _, err := VerifyInvocation(built, venue, closureDrift); !hasCode(err, "agent_kit_adoption_mismatch") {
		t.Fatalf("closure drift must refuse, got %v", err)
	}

	adoptionDrift := resignEnvelope(t, envelope, func(tree map[string]any) {
		tree["adoptionId"] = "WP211A-MAT-ADOPT-9"
	})
	if _, err := VerifyInvocation(built, venue, adoptionDrift); !hasCode(err, "agent_kit_invocation_invalid") {
		t.Fatalf("adoption drift must refuse, got %v", err)
	}

	statusDrift := resignEnvelope(t, envelope, func(tree map[string]any) {
		tree["status"] = "failed"
		tree["ready"] = false
	})
	if _, err := VerifyInvocation(built, venue, statusDrift); !hasCode(err, "agent_kit_invocation_invalid") {
		t.Fatalf("failed envelope must refuse, got %v", err)
	}

	materializationDrift := resignEnvelope(t, envelope, func(tree map[string]any) {
		materialization := tree["materialization"].(map[string]any)
		materialization["kitDigest"] = "sha256:" + strings.Repeat("1", 64)
	})
	if _, err := VerifyInvocation(built, venue, materializationDrift); !hasCode(err, "agent_kit_receipt_invalid") &&
		!hasCode(err, "agent_kit_receipt_digest_mismatch") {
		t.Fatalf("materialization drift must refuse, got %v", err)
	}

	if _, err := VerifyInvocation(built, venue, append([]byte(nil), envelope[:100]...)); err == nil {
		t.Fatal("truncated envelope must refuse")
	}
	if _, err := VerifyInvocation(built, Venue{ID: "production"}, envelope); !hasCode(err, "agent_kit_venue_denied") {
		t.Fatalf("uncompiled venue must refuse, got %v", err)
	}
}

func TestBuildInvocationProductionDefaultSelectsNothing(t *testing.T) {
	request := fixtureRequest(t)
	operation := fixtureOperation(t, request)
	venue := compiledVenue(t)
	built, err := BuildRequest(operation, request.Target, request.SkillsSnapshot, venue)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, err := BuildInvocation(built, Venue{ID: "production"}); !hasCode(err, "agent_kit_venue_denied") {
		t.Fatalf("uncompiled venue must refuse, got %v", err)
	}
	if venue, err := SelectVenue(""); venue != nil || err != nil {
		t.Fatalf("production default must select nothing")
	}
}

func replaceOnce(value, old, new string) string {
	index := strings.Index(value, old)
	if index < 0 {
		return value
	}
	return value[:index] + new + value[index+len(old):]
}
