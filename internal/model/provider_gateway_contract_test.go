package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// providerGatewayTestManifest returns a valid manifest carrying one running
// sandbox, so tests can attach provider gateway requirements and exercise the
// additive contract through the real manifest decoder and validator.
func providerGatewayTestManifest() Manifest {
	return Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: 1,
		ImageDigest:     testImageDigest("a"),
		Capacity:        Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []Sandbox{{
			ID:           "sbx_test12345",
			Name:         "worker",
			Size:         "small",
			Resources:    Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
			Lifetime:     "persistent",
			DesiredState: "running",
			Generation:   1,
		}},
	}
}

// providerGatewayTestRequirements returns one valid requirement with two
// declared tools.
func providerGatewayTestRequirements() []ProviderGatewayRequirement {
	return []ProviderGatewayRequirement{{
		RunID:        "run_github_0001",
		CredentialID: "conn_0123456789abcdefghijkl",
		ProviderID:   "github",
		Tools: []ProviderGatewayTool{
			{
				Name:        "list_repositories",
				Description: "List repositories visible to the connected account.",
				InputSchema: json.RawMessage(
					`{"type":"object","properties":{"owner":{"type":"string"}},"additionalProperties":false}`,
				),
			},
			{
				Name:        "read_file",
				InputSchema: json.RawMessage(`{"type":"object"}`),
			},
		},
	}}
}

func TestSandboxProviderGatewaysAbsentIsWireCompatible(t *testing.T) {
	manifest := providerGatewayTestManifest()
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "providerGateways") {
		t.Fatalf("absent provider gateways were emitted on the wire: %s", payload)
	}
	var decoded Manifest
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(decoded, manifest.ServerID, 0); err != nil {
		t.Fatalf("manifest without provider gateways did not validate: %v", err)
	}
	if len(decoded.Sandboxes) != 1 || decoded.Sandboxes[0].ProviderGateways != nil {
		t.Fatalf("absent provider gateways decoded as non-empty: %#v", decoded.Sandboxes)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(reencoded) != string(payload) {
		t.Fatalf("legacy manifest bytes changed on round-trip:\n got %s\nwant %s", reencoded, payload)
	}
}

func TestManifestAcceptsAndRoundTripsProviderGatewayRequirements(t *testing.T) {
	manifest := providerGatewayTestManifest()
	manifest.Sandboxes[0].ProviderGateways = providerGatewayTestRequirements()
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err != nil {
		t.Fatalf("valid provider gateways were rejected: %v", err)
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"providerGateways"`) {
		t.Fatalf("provider gateways missing from the wire body: %s", payload)
	}
	var decoded Manifest
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode manifest with provider gateways: %v", err)
	}
	if !reflect.DeepEqual(decoded.Sandboxes[0].ProviderGateways, manifest.Sandboxes[0].ProviderGateways) {
		t.Fatalf(
			"provider gateways did not round-trip:\n got %#v\nwant %#v",
			decoded.Sandboxes[0].ProviderGateways, manifest.Sandboxes[0].ProviderGateways,
		)
	}
	if err := ValidateManifest(decoded, manifest.ServerID, 0); err != nil {
		t.Fatalf("round-tripped manifest did not validate: %v", err)
	}
}

func TestValidateManifestRejectsInvalidProviderGatewayRequirements(t *testing.T) {
	tooManyRuns := make([]ProviderGatewayRequirement, MaxProviderGatewaysPerSandbox+1)
	for index := range tooManyRuns {
		tooManyRuns[index] = ProviderGatewayRequirement{
			RunID:        "run_" + strings.Repeat("a", index+1),
			CredentialID: "conn_0123456789abcdefghijkl",
			ProviderID:   "github",
			Tools:        []ProviderGatewayTool{{Name: "read", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		}
	}
	tooManyTools := make([]ProviderGatewayTool, MaxProviderGatewayTools+1)
	for index := range tooManyTools {
		tooManyTools[index] = ProviderGatewayTool{
			Name:        "tool_" + strings.Repeat("a", index+1),
			InputSchema: json.RawMessage(`{"type":"object"}`),
		}
	}
	duplicateTools := []ProviderGatewayTool{
		{Name: "read", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "read", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
	hugeSchema := json.RawMessage(
		`{"type":"object","description":"` + strings.Repeat("a", MaxProviderGatewayInputSchemaBytes) + `"}`,
	)
	longDescription := strings.Repeat("d", MaxProviderGatewayDescriptionBytes+1)
	invalidUTF8Description := string([]byte{0xff, 0xfe, 0xfd})

	tests := []struct {
		name         string
		requirements func([]ProviderGatewayRequirement) []ProviderGatewayRequirement
	}{
		{name: "too many gateways", requirements: func([]ProviderGatewayRequirement) []ProviderGatewayRequirement {
			return tooManyRuns
		}},
		{name: "empty run id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].RunID = ""
			return values
		}},
		{name: "unsafe run id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].RunID = "../escape"
			return values
		}},
		{name: "trailing slash run id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].RunID = "run/other"
			return values
		}},
		{name: "oversized run id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].RunID = "r" + strings.Repeat("a", 128)
			return values
		}},
		{name: "duplicate run id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values = append(values, values[0])
			return values
		}},
		{name: "missing credential id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].CredentialID = ""
			return values
		}},
		{name: "unsafe credential id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].CredentialID = "conn id with spaces"
			return values
		}},
		{name: "oversized credential id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].CredentialID = "c" + strings.Repeat("a", 128)
			return values
		}},
		{name: "missing provider id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].ProviderID = ""
			return values
		}},
		{name: "unsafe provider id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].ProviderID = "GitHub/../x"
			return values
		}},
		{name: "oversized provider id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].ProviderID = "p" + strings.Repeat("a", 63) + "z"
			return values
		}},
		{name: "unsafe connection id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].ConnectionID = "conn with spaces"
			return values
		}},
		{name: "oversized connection id", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].ConnectionID = "c" + strings.Repeat("a", 128)
			return values
		}},
		{name: "no tools", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools = nil
			return values
		}},
		{name: "too many tools", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools = tooManyTools
			return values
		}},
		{name: "missing tool name", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].Name = ""
			return values
		}},
		{name: "unsafe tool name", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].Name = "read/file"
			return values
		}},
		{name: "tool name with space", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].Name = "read file"
			return values
		}},
		{name: "oversized tool name", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].Name = "t" + strings.Repeat("a", 128)
			return values
		}},
		{name: "duplicate tool name", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools = duplicateTools
			return values
		}},
		{name: "oversized tool description", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].Description = longDescription
			return values
		}},
		{name: "invalid utf8 tool description", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].Description = invalidUTF8Description
			return values
		}},
		{name: "empty input schema", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].InputSchema = nil
			return values
		}},
		{name: "invalid json input schema", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].InputSchema = json.RawMessage(`{"type":`)
			return values
		}},
		{name: "null input schema", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].InputSchema = json.RawMessage(`null`)
			return values
		}},
		{name: "array input schema", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].InputSchema = json.RawMessage(`[{"type":"object"}]`)
			return values
		}},
		{name: "string input schema", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].InputSchema = json.RawMessage(`"{\"type\":\"object\"}"`)
			return values
		}},
		{name: "oversized input schema", requirements: func(values []ProviderGatewayRequirement) []ProviderGatewayRequirement {
			values[0].Tools[0].InputSchema = hugeSchema
			return values
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := providerGatewayTestManifest()
			base := make([]ProviderGatewayRequirement, len(providerGatewayTestRequirements()))
			copy(base, providerGatewayTestRequirements())
			base[0].Tools = append([]ProviderGatewayTool(nil), base[0].Tools...)
			manifest.Sandboxes[0].ProviderGateways = test.requirements(base)
			if err := ValidateManifest(manifest, manifest.ServerID, 0); err == nil {
				t.Fatal("invalid provider gateway requirement was accepted")
			}
		})
	}
}

func TestManifestDecoderRejectsUnknownProviderGatewayFields(t *testing.T) {
	base := `{
		"serverId":"srv_test12345",
		"desiredRevision":1,
		"imageDigest":"` + testImageDigest("a") + `",
		"capacity":{"cpuMillicores":1500,"memoryMiB":3072,"workspaceDiskGiB":30,"pids":512},
		"sandboxes":[{
			"id":"sbx_test12345","name":"worker","size":"small",
			"resources":{"cpuMillicores":500,"memoryMiB":1024,"workspaceDiskGiB":10,"pids":256},
			"lifetime":"persistent","desiredState":"running","generation":1,
			"providerGateways":%s
		}]
	}`
	validGateway := `[{
		"runId":"run_github_0001",
		"credentialId":"conn_0123456789abcdefghijkl",
		"providerId":"github",
		"tools":[{"name":"read","description":"Read.","inputSchema":{"type":"object"}}]
	}]`
	if err := json.Unmarshal([]byte(strings.Replace(base, "%s", validGateway, 1)), &Manifest{}); err != nil {
		t.Fatalf("valid provider gateways were rejected by the decoder: %v", err)
	}
	unknownCases := map[string]string{
		"secret on requirement": `[{
			"runId":"run_github_0001",
			"credentialId":"conn_0123456789abcdefghijkl",
			"providerId":"github",
			"secret":"sk-live-should-never-be-accepted",
			"tools":[{"name":"read","inputSchema":{"type":"object"}}]
		}]`,
		"envelope on requirement": `[{
			"runId":"run_github_0001",
			"credentialId":"conn_0123456789abcdefghijkl",
			"providerId":"github",
			"envelope":{"ciphertext":"AAAA"},
			"tools":[{"name":"read","inputSchema":{"type":"object"}}]
		}]`,
		"secret on tool": `[{
			"runId":"run_github_0001",
			"credentialId":"conn_0123456789abcdefghijkl",
			"providerId":"github",
			"tools":[{"name":"read","apiKey":"sk-live","inputSchema":{"type":"object"}}]
		}]`,
	}
	for name, gateways := range unknownCases {
		t.Run(name, func(t *testing.T) {
			payload := strings.Replace(base, "%s", gateways, 1)
			if err := json.Unmarshal([]byte(payload), &Manifest{}); err == nil {
				t.Fatal("manifest decoder accepted an unknown provider gateway field")
			}
		})
	}
}

func TestProviderGatewayRequirementEffectiveConnectionID(t *testing.T) {
	requirement := ProviderGatewayRequirement{
		RunID:        "run_github_0001",
		CredentialID: "conn_0123456789abcdefghijkl",
		ProviderID:   "github",
	}
	if got := requirement.EffectiveConnectionID(); got != requirement.CredentialID {
		t.Fatalf("effective connection id = %q, want the credential id", got)
	}
	requirement.ConnectionID = "conn_explicit_connection"
	if got := requirement.EffectiveConnectionID(); got != requirement.ConnectionID {
		t.Fatalf("effective connection id = %q, want the explicit connection id", got)
	}
}

func TestSameProviderGatewayRequirementsIgnoresSchemaWhitespace(t *testing.T) {
	left := providerGatewayTestRequirements()
	right := providerGatewayTestRequirements()
	right[0].Tools[0].InputSchema = json.RawMessage(
		"{\n  \"type\": \"object\",\n  \"properties\": {\"owner\": {\"type\": \"string\"}},\n  \"additionalProperties\": false\n}",
	)
	if !SameProviderGatewayRequirements(left, right) {
		t.Fatal("semantically identical requirements compared unequal")
	}
	right[0].Tools[0].Description = "changed"
	if SameProviderGatewayRequirements(left, right) {
		t.Fatal("changed requirement compared equal")
	}
	if SameProviderGatewayRequirements(left, right[:1]) {
		t.Fatal("different requirement count compared equal")
	}
}
