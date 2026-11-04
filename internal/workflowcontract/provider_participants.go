package workflowcontract

import "encoding/json"

// Exact immutable r2 closure has a separate compiler: predecessor resource IDs
// retain their original selected bytes in the legacy compiler.
const BudgetParticipants = "workspace-workflow-budget-v5.schema.json"
const ProviderParticipantAccounting = "workspace-provider-accounting-v4.schema.json"
const ProviderParticipantReadback = "workspace-provider-readback-v4.schema.json"
const ProviderParticipantOriginals = "workspace-provider-originals-v4.schema.json"

var participantDocuments = map[string]bool{
	"agent-workspace-owner-v1.schema.json":                   true,
	"agent-workspace-qualification-provider-v4.schema.json":  true,
	"agent-workspace-qualification-selection-v1.schema.json": true,
	"workspace-child-integrator-v3.schema.json":              true,
	"workspace-child-provider-v4.schema.json":                true,
	"workspace-child-reviewer-v3.schema.json":                true,
	"workspace-controller-advisory-v2.schema.json":           true,
	"workspace-controller-provider-v4.schema.json":           true,
	"workspace-controller-stage-v3.schema.json":              true,
	"workspace-first-task-provider-v4.schema.json":           true,
	"workspace-provider-accounting-v4.schema.json":           true,
	"workspace-provider-originals-v4.schema.json":            true,
	"workspace-provider-readback-v4.schema.json":             true,
	"workspace-qualification-access-v4.schema.json":          true,
	"workspace-qualification-native-v5.schema.json":          true,
	"workspace-qualification-provider-v4.schema.json":        true,
	"workspace-test-provider-operator-v3.schema.json":        true,
	"workspace-workflow-budget-v5.schema.json":               true,
	"workspace-workflow-manager-single-v3.schema.json":       true,
}
var participantPins = map[string]string{
	"agent-workspace-owner-v1.schema.json":                   "2e2d3df68de3c21b22967dd05a82d2d7969989c90e3fd1cc9cac4404c567c60a",
	"agent-workspace-qualification-provider-v4.schema.json":  "cb57e2e08dc0eadb391dea07c3ec0c9258331bd81d275e5c08038e6727a4c331",
	"agent-workspace-qualification-selection-v1.schema.json": "829df848e136f465b676478d03d1e0d9a6fa18283bf52091569e3275056535a3",
	"workspace-child-integrator-v3.schema.json":              "e173c551bef646f16cd1dcf57813d73c3b40075d0cef9767def87a93c900a678",
	"workspace-child-provider-v4.schema.json":                "018eee84cbec47e6a3255f4989e918153c6aa6d046d58ccd6cb0b0588aa47585",
	"workspace-child-reviewer-v3.schema.json":                "7f99a69aca8e9eccdc55d153423cde3beaafbced3366c5a252f08d9e7201239e",
	"workspace-controller-advisory-v2.schema.json":           "ef14cd7344897d7532a1183828eba3586cdd23080c67add063d3dd63a922b845",
	"workspace-controller-provider-v4.schema.json":           "c040080c6436540d5505ae413eef45def8fc8a36251772c6a55c695bcc394ea9",
	"workspace-controller-stage-v3.schema.json":              "2ff15c32dd6883799d5905ca4d666b7ba00667949e17a51674225bf5590f0121",
	"workspace-first-task-provider-v4.schema.json":           "1babc156ba41bae189a6fe6d581fbf80bbbd89179a70bad2ab06c08189b20b31",
	"workspace-provider-accounting-v4.schema.json":           "bf719aa5a96503322b66d6a0cbb2660c06ef8069f0ae8d58e28ad4f3940736ec",
	"workspace-provider-originals-v4.schema.json":            "034443e99004b45a16ada39afe2a4705473cb4195d9480fabddd2007a6b84f26",
	"workspace-provider-readback-v4.schema.json":             "563003ef3270a85f2f6cde5345bb7d068eb64583be3fd88d444d98ca63146ad4",
	"workspace-qualification-access-v4.schema.json":          "6bc8ef66662694a8aaa3690025e40a352825d1ce2fd569bfebd73af44cc3fff2",
	"workspace-qualification-native-v5.schema.json":          "85fbfda6eebae614c6de5cf53d89e798b553a7893f5b2d3db9efe7a16f4a9bfd",
	"workspace-qualification-provider-v4.schema.json":        "33f9bdafc152a02e4cabfe6e0b1c051db93680d1c31b8de174e20d10b543ac1d",
	"workspace-test-provider-operator-v3.schema.json":        "f187140119976f26e5f5adf58a5746a95be622a771ef94d03f9be987e7e6ab29",
	"workspace-workflow-budget-v5.schema.json":               "f26292a66dd304673b04c5bd229aa5cb876cf54aa0f58537797586c5a5e8d291",
	"workspace-workflow-manager-single-v3.schema.json":       "316483a4b784d36913cafcd116ff8a716193faa8d97eb8cad34023188ebb0677",
	"agent-workspace-configuration-v1.schema.json":           "182733ba61fe96d97a9aaf4a727409c866649014a172ac190d6654d0180cf73c",
	"agent-workspace-configuration-v2.schema.json":           "31fbbd96386e7bcce4c0ed89bcae82fb4b9730574ae8876a72e56d4178a448f6",
	"cell-lifecycle-v3.schema.json":                          "c3ae13167db27c13953da6ba608f18c6a7b6ef6137db1fa120287a9a172e05b7",
	"workspace-child-product-v1.schema.json":                 "8c73c2ff78ffaa2160246560c94ad25567d8b42833a896cdd8a740a554f907f4",
	"workspace-plan-genesis-v1.schema.json":                  "d052c5d863703645b4b7f395b2eb7a4fad0e544ebd9bf0b6f90ea62a3f7467aa",
	"workspace-qualification-native-v3.schema.json":          "8cf28601c51cf356596d4f7f970b4280143e109ad8f438bfb445392754a26edc",
	"workspace-qualification-observations-v2.schema.json":    "28ab5f38ee81c7a790c5a5ed474004c23e72885f42d94010c335c6d0f015d26e",
	"workspace-qualification-provider-v2.schema.json":        "55c7427a1016aac787026735b9b93f2a7eff1bec335244c1812c69af346a045f",
	"workspace-workflow-budget-v2.schema.json":               "e2b48556a7f27a5d85a2acf32ef981393cd629a64348114fd3a447c0baac05ea",
	"workspace-workflow-budget-v3.schema.json":               "e4e6850d744296937d1d5609f9738f2c8f3ade7cf3d0c3402cfa9198cdd4e130",
	"workspace-workflow-manager-v1.proposal.schema.json":     "1ff7c6b301eea395031c7c8acdc91bf7f131e08cc26503866fe06a141bb29459",
	"workspace-workflow-producer-v1.schema.json":             "60bf59da8175cf0e6aad2b282963bb43ff01ab06125f728958bf972dd80ff4af",
	"workspace-workflow-v1.schema.json":                      "13e5a8eea6a97698c8e57a29c734ace8d309c6d07d96cd3da6dd40c89273ef34",
}

func wireVersion(raw []byte) int {
	var h struct {
		FormatVersion int `json:"formatVersion"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return 0
	}
	return h.FormatVersion
}
func ValidateProviderAccounting(definition string, raw []byte) error {
	document := ProviderAccounting
	version := wireVersion(raw)
	if definition == "openingEnvelope" {
		var envelope struct{ Payload json.RawMessage }
		if json.Unmarshal(raw, &envelope) == nil {
			version = wireVersion(envelope.Payload)
		}
	}
	if version == 3 {
		document = ProviderParticipantAccounting
		switch definition {
		case "openingHandshake":
			definition = "openingHandshake3"
		case "openingEnvelope":
			definition = "backendOpeningEnvelope3"
		case "reservation":
			definition = "reservation3"
		case "settlement":
			definition = "settlement3"
		}
	}
	return Validate(document, definition, raw)
}
func ValidateProviderRuntimeReadback(raw []byte) error {
	return validateBounded(ProviderParticipantAccounting, "runtimeReadbackEnvelope3", raw, ProviderReadbackMaximum)
}
