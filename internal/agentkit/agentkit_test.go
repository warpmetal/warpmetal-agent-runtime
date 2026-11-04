package agentkit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func fixtureRequest(t *testing.T) Request {
	t.Helper()
	var request Request
	if err := json.Unmarshal(fixture(t, "deepseek-agent-request.json"), &request); err != nil {
		t.Fatalf("decode request fixture: %v", err)
	}
	return request
}

func fixtureOperation(t *testing.T, request Request) model.WorkspaceApplicationOperation {
	t.Helper()
	var config map[string]json.RawMessage
	if err := json.Unmarshal(fixture(t, "deepseek-agent-config.json"), &config); err != nil {
		t.Fatalf("decode config fixture: %v", err)
	}
	kit, ok := config["agentSetup"]
	if !ok {
		t.Fatal("fixture config has no agentSetup")
	}
	return model.WorkspaceApplicationOperation{
		ConfigurationID:       request.Configuration.ConfigurationID,
		ConfigurationRevision: request.Configuration.ConfigurationRevision,
		ConfigurationDigest:   request.Configuration.ConfigurationDigest,
		Configuration: model.WorkspaceConfiguration{
			AgentSetup: kit,
		},
	}
}

func testVenue(t *testing.T) Venue {
	t.Helper()
	venue, err := SelectVenue("TEST-wp211-kit-materialization")
	if err != nil || venue == nil {
		t.Fatalf("select venue: %v", err)
	}
	return *venue
}

// The production default selects nothing: both an empty environment and an
// unknown id leave existing Runtime behaviour untouched / fail closed.
func TestSelectVenueProductionDefaultUnchanged(t *testing.T) {
	if venue, err := SelectVenue(""); venue != nil || err != nil {
		t.Fatalf("empty venue must select nothing: %v %v", venue, err)
	}
	if venue, err := SelectVenue("   "); venue != nil || err != nil {
		t.Fatalf("blank venue must select nothing: %v %v", venue, err)
	}
	for _, denied := range []string{"production", "WP211", "TEST-", "TEST-wp211-other"} {
		if venue, err := SelectVenue(denied); venue != nil || err == nil {
			t.Fatalf("venue %q must be denied", denied)
		} else {
			var typed *Error
			if !errors.As(err, &typed) || typed.Code != "agent_kit_venue_denied" {
				t.Fatalf("venue %q wrong error: %v", denied, err)
			}
		}
	}
	venue, err := SelectVenue("TEST-wp211-kit-materialization")
	if err != nil || venue == nil || venue.ID != "TEST-wp211-kit-materialization" {
		t.Fatalf("TEST venue must resolve exactly: %v %v", venue, err)
	}
}

// The Runtime-built request is byte-identical (canonical) to the request the
// packaged materializer consumed to produce the receipt fixture: a real
// cross-language contract check, not a hand-written expectation.
func TestBuildRequestMatchesMaterializerContract(t *testing.T) {
	request := fixtureRequest(t)
	operation := fixtureOperation(t, request)
	built, err := BuildRequest(operation, request.Target, request.SkillsSnapshot, testVenue(t))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if built.KitDigest != "sha256:808e50374237c506400bb25ac083632ec4d472dd44130f1e92efd4dce3962227" {
		t.Fatalf("kit digest mismatch: %s", built.KitDigest)
	}
	if built.MaterializationID != "akm_44edc1f2599f4e55047448f7d47f2479" {
		t.Fatalf("materialization id mismatch: %s", built.MaterializationID)
	}
	got, err := canonicalJSON(built)
	if err != nil {
		t.Fatalf("canonical built request: %v", err)
	}
	want, err := canonicalJSON(request)
	if err != nil {
		t.Fatalf("canonical fixture request: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("built request differs from the materializer contract\n got: %s\nwant: %s", got, want)
	}
}

func TestBuildRequestRefusesMissingOrInvalidKit(t *testing.T) {
	request := fixtureRequest(t)
	operation := fixtureOperation(t, request)

	noKit := operation
	noKit.Configuration.AgentSetup = nil
	if _, err := BuildRequest(noKit, request.Target, request.SkillsSnapshot, testVenue(t)); !hasCode(err, "agent_kit_kit_missing") {
		t.Fatalf("missing kit must refuse, got %v", err)
	}

	unknownField := operation
	unknownField.Configuration.AgentSetup = []byte(`{"agentInstructions":"x","unexpected":true}`)
	if _, err := BuildRequest(unknownField, request.Target, request.SkillsSnapshot, testVenue(t)); !hasCode(err, "agent_kit_kit_invalid") {
		t.Fatalf("unknown kit field must refuse, got %v", err)
	}

	secret := operation
	secret.Configuration.AgentSetup = []byte(`{"agentInstructions":"sk-` + strings.Repeat("a", 32) + `","models":{},"toolProviders":[],"skills":[],"runtime":{}}`)
	if _, err := BuildRequest(secret, request.Target, request.SkillsSnapshot, testVenue(t)); !hasCode(err, "agent_kit_secret_detected") {
		t.Fatalf("secret kit must refuse, got %v", err)
	}

	for name, pin := range map[string]SnapshotPin{
		"commit": {CatalogID: "warpmetal-skills", SourceRepo: "warpmetal/skills", ResolvedCommit: strings.Repeat("0", 40), ContentDigest: SnapshotContentDigest},
		"digest": {CatalogID: "warpmetal-skills", SourceRepo: "warpmetal/skills", ResolvedCommit: SnapshotCommit, ContentDigest: "sha256:" + strings.Repeat("0", 64)},
		"repo":   {CatalogID: "warpmetal-skills", SourceRepo: "other/skills", ResolvedCommit: SnapshotCommit, ContentDigest: SnapshotContentDigest},
	} {
		if _, err := BuildRequest(operation, request.Target, pin, testVenue(t)); !hasCode(err, "agent_kit_snapshot_pin_mismatch") {
			t.Fatalf("pin %s must refuse, got %v", name, err)
		}
	}

	badTarget := request.Target
	badTarget.ProjectRoot = "/etc"
	if _, err := BuildRequest(operation, badTarget, request.SkillsSnapshot, testVenue(t)); !hasCode(err, "agent_kit_project_root_invalid") {
		t.Fatalf("project root escape must refuse, got %v", err)
	}

	if _, err := BuildRequest(operation, request.Target, request.SkillsSnapshot, Venue{ID: "production"}); !hasCode(err, "agent_kit_venue_denied") {
		t.Fatalf("uncompiled venue must refuse, got %v", err)
	}
}

func TestVerifyReceiptAcceptsMaterializerOutput(t *testing.T) {
	request := fixtureRequest(t)
	operation := fixtureOperation(t, request)
	built, err := BuildRequest(operation, request.Target, request.SkillsSnapshot, testVenue(t))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	receipt, err := VerifyReceipt(built, fixture(t, "deepseek-agent-receipt.json"))
	if err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	if receipt.Status != "ready" || receipt.Instruction.Path != "AGENTS.md" {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if receipt.Skills[0].ContentDigest != skillPins["warpmetal-agent-sandbox"].ContentDigest {
		t.Fatalf("skill digest drift: %s", receipt.Skills[0].ContentDigest)
	}
	if receipt.NetworkUsed || receipt.SecretsPresent {
		t.Fatal("receipt claims network/secrets")
	}
}

// mutatedReceipt rewrites a receipt object and re-signs it so a targeted check
// (not the digest check) is the one under test.
func mutatedReceipt(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(fixture(t, "deepseek-agent-receipt.json"), &document); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	mutate(document)
	delete(document, "receiptDigest")
	signed, err := Digest(document)
	if err != nil {
		t.Fatalf("digest mutated receipt: %v", err)
	}
	document["receiptDigest"] = signed
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode mutated receipt: %v", err)
	}
	return raw
}

func TestVerifyReceiptRefusesDrift(t *testing.T) {
	request := fixtureRequest(t)
	operation := fixtureOperation(t, request)
	built, err := BuildRequest(operation, request.Target, request.SkillsSnapshot, testVenue(t))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	raw := fixture(t, "deepseek-agent-receipt.json")

	unsigned := strings.Replace(string(raw), `"receiptDigest": "`, `"receiptDigest": "sha256:0`, 1)
	if _, err := VerifyReceipt(built, []byte(unsigned)); !hasCode(err, "agent_kit_receipt_digest_mismatch") {
		t.Fatalf("tampered receipt digest must refuse, got %v", err)
	}
	failedStatus := mutatedReceipt(t, func(document map[string]any) {
		document["status"] = "failed"
		delete(document, "error")
	})
	if _, err := VerifyReceipt(built, failedStatus); !hasCode(err, "agent_kit_receipt_invalid") {
		t.Fatalf("failed receipt must refuse, got %v", err)
	}

	kitDrift := mutatedReceipt(t, func(document map[string]any) {
		document["kitDigest"] = "sha256:" + strings.Repeat("1", 64)
	})
	if _, err := VerifyReceipt(built, kitDrift); !hasCode(err, "agent_kit_receipt_invalid") {
		t.Fatalf("kit digest drift must refuse, got %v", err)
	}

	instructionDrift := mutatedReceipt(t, func(document map[string]any) {
		instruction := document["instruction"].(map[string]any)
		instruction["sha256"] = "sha256:" + strings.Repeat("0", 64)
	})
	if _, err := VerifyReceipt(built, instructionDrift); !hasCode(err, "agent_kit_instruction_mismatch") {
		t.Fatalf("instruction drift must refuse, got %v", err)
	}

	skillDrift := mutatedReceipt(t, func(document map[string]any) {
		skills := document["skills"].([]any)
		skills[0].(map[string]any)["contentDigest"] = "sha256:" + strings.Repeat("0", 64)
	})
	if _, err := VerifyReceipt(built, skillDrift); !hasCode(err, "agent_kit_skill_mismatch") {
		t.Fatalf("skill drift must refuse, got %v", err)
	}

	secretReceipt := mutatedReceipt(t, func(document map[string]any) {
		document["venue"] = "TEST-wp211-kit-materialization"
		document["materializationId"] = built.MaterializationID + "\u0000sk-" + strings.Repeat("a", 32)
	})
	if _, err := VerifyReceipt(built, secretReceipt); err == nil {
		t.Fatal("secret-bearing receipt must refuse")
	}

	wrongVenue := mutatedReceipt(t, func(document map[string]any) {
		document["venue"] = "TEST-other"
	})
	if _, err := VerifyReceipt(built, wrongVenue); !hasCode(err, "agent_kit_receipt_invalid") {
		t.Fatalf("venue drift must refuse, got %v", err)
	}

	unknownField := mutatedReceipt(t, func(document map[string]any) {
		document["unexpected"] = true
	})
	if _, err := VerifyReceipt(built, unknownField); !hasCode(err, "agent_kit_receipt_invalid") {
		t.Fatalf("unknown receipt field must refuse, got %v", err)
	}
}

func TestProductionDefaultHasNoKitMaterialization(t *testing.T) {
	// A v1 operation carries no agentSetup and no venue is selected by default:
	// the Runtime keeps the declared-only behaviour.
	operation := model.WorkspaceApplicationOperation{
		ConfigurationID: "cfg_v1", ConfigurationRevision: 1,
		ConfigurationDigest: "sha256:" + strings.Repeat("a", 64),
		Configuration:       model.WorkspaceConfiguration{FormatVersion: 1},
	}
	if venue, err := SelectVenue(""); venue != nil || err != nil {
		t.Fatalf("default venue: %v %v", venue, err)
	}
	if _, err := BuildRequest(operation, Target{}, SnapshotPin{}, testVenue(t)); !hasCode(err, "agent_kit_kit_missing") {
		t.Fatalf("v1 operation must have no materializable kit, got %v", err)
	}
}

func hasCode(err error, code string) bool {
	var typed *Error
	return errors.As(err, &typed) && typed.Code == code
}
