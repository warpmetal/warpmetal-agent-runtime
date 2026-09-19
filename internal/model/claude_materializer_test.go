package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const claudeLauncherMaterializerJSON = `{
	"kind":"npm-package-set",
	"artifacts":[
		{"id":"claude-wrapper","source":"https://registry.npmjs.org/@anthropic-ai/claude-code/-/claude-code-2.1.277.tgz","sha256":"sha256:3bf521e81cf84c654a335a58b301a3d2c35585a64762cfc146fb90a49c1b377e","format":"npm-tgz","sizeBytes":27539,"packageName":"@anthropic-ai/claude-code","packageVersion":"2.1.277","installAs":"@anthropic-ai/claude-code"},
		{"id":"claude-linux-x64","source":"https://registry.npmjs.org/@anthropic-ai/claude-code-linux-x64/-/claude-code-linux-x64-2.1.277.tgz","sha256":"sha256:0ac0d7e24e12fedd6de2507dd5ed8b1d16b686ef8e58839d976e72a09b380b2e","format":"npm-tgz","sizeBytes":104046180,"packageName":"@anthropic-ai/claude-code-linux-x64","packageVersion":"2.1.277","installAs":"@anthropic-ai/claude-code-linux-x64"}
	],
	"bins":[],
	"launchers":[{"bin":"claude","kind":"node-module","artifactId":"claude-wrapper","entrypoint":"cli-wrapper.cjs","environment":{"DISABLE_UPDATES":"1"}}]
}`

const antArchiveMaterializerJSON = `{
	"kind":"archive-binary",
	"artifact":{"id":"ant-linux-amd64","source":"https://github.com/anthropics/anthropic-cli/releases/download/v1.33.0/ant_1.33.0_linux_amd64.tar.gz","sha256":"sha256:937a93020b92260a9c1221fa25d79586245e67c368848a0b77b83e645da77f38","format":"tar-gz","sizeBytes":9471689},
	"bin":{"name":"ant","member":"ant"}
}`

func manifestWithMaterializerJSON(t *testing.T, profileID, materializer string) Manifest {
	t.Helper()
	payload := []byte(fmt.Sprintf(`{
		"serverId":"srv_test12345","desiredRevision":1,
		"imageDigest":"registry.example/sandbox@sha256:%s",
		"capacity":{"cpuMillicores":1500,"memoryMiB":3072,"workspaceDiskGiB":30,"pids":512},
		"sandboxes":[{"id":"sbx_test12345","name":"main","resources":{"cpuMillicores":500,"memoryMiB":1024,"workspaceDiskGiB":10,"pids":256},"lifetime":"persistent","desiredState":"running","generation":1}],
		"accessGrants":[],"setupOperations":[{
			"id":"setup-test12345","schemaVersion":1,"sandboxId":"sbx_test12345","sandboxGeneration":1,
			"profileId":%q,"profileRevision":1,"profileDigest":"sha256:%s",
			"materializer":%s
		}]
	}`, strings.Repeat("a", 64), profileID, strings.Repeat("b", 64), materializer))
	var manifest Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestValidateManifestAcceptsClosedClaudeLauncherAndPreservesItOnTheWire(t *testing.T) {
	manifest := manifestWithMaterializerJSON(t, "claude-code", claudeLauncherMaterializerJSON)
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err != nil {
		t.Fatalf("valid Claude npm launcher materializer was rejected: %v", err)
	}
	payload, err := json.Marshal(manifest.SetupOperations[0].Materializer)
	if err != nil {
		t.Fatal(err)
	}
	var got, want any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(claudeLauncherMaterializerJSON), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Claude launcher changed across runtime transport:\n got: %s\nwant: %s", payload, claudeLauncherMaterializerJSON)
	}
}

func TestValidateManifestAcceptsExactAntArchiveAndPreservesItOnTheWire(t *testing.T) {
	manifest := manifestWithMaterializerJSON(t, "claude-managed-ant", antArchiveMaterializerJSON)
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err != nil {
		t.Fatalf("valid ant archive-binary materializer was rejected: %v", err)
	}
	payload, err := json.Marshal(manifest.SetupOperations[0].Materializer)
	if err != nil {
		t.Fatal(err)
	}
	for _, exact := range []string{
		`"kind":"archive-binary"`,
		`"source":"https://github.com/anthropics/anthropic-cli/releases/download/v1.33.0/ant_1.33.0_linux_amd64.tar.gz"`,
		`"sha256":"sha256:937a93020b92260a9c1221fa25d79586245e67c368848a0b77b83e645da77f38"`,
		`"sizeBytes":9471689`,
		`"bin":{"name":"ant","member":"ant"}`,
	} {
		if !strings.Contains(string(payload), exact) {
			t.Fatalf("archive-binary wire payload is missing %s: %s", exact, payload)
		}
	}
}

func TestValidateManifestRejectsLauncherCommandsUnsafePathsAndArbitraryEnvironment(t *testing.T) {
	var base map[string]any
	if err := json.Unmarshal([]byte(claudeLauncherMaterializerJSON), &base); err != nil {
		t.Fatal(err)
	}
	mutations := []func(map[string]any){
		func(value map[string]any) { value["launchers"].([]any)[0].(map[string]any)["kind"] = "shell" },
		func(value map[string]any) {
			value["launchers"].([]any)[0].(map[string]any)["entrypoint"] = "../cli-wrapper.cjs"
		},
		func(value map[string]any) {
			value["launchers"].([]any)[0].(map[string]any)["environment"] = map[string]any{"NODE_OPTIONS": "--require=/tmp/payload.js"}
		},
		func(value map[string]any) {
			value["launchers"].([]any)[0].(map[string]any)["environment"] = map[string]any{"DISABLE_UPDATES": "0"}
		},
	}
	for index, mutate := range mutations {
		var candidate map[string]any
		encoded, _ := json.Marshal(base)
		if err := json.Unmarshal(encoded, &candidate); err != nil {
			t.Fatal(err)
		}
		mutate(candidate)
		materializer, _ := json.Marshal(candidate)
		manifest := manifestWithMaterializerJSON(t, "claude-code", string(materializer))
		if err := ValidateManifest(manifest, manifest.ServerID, 0); err == nil {
			t.Fatalf("unsafe Claude launcher mutation %d was accepted: %s", index, materializer)
		}
	}
}

func TestValidateManifestRejectsArchiveHooksAndNonExactMemberPaths(t *testing.T) {
	var base map[string]any
	if err := json.Unmarshal([]byte(antArchiveMaterializerJSON), &base); err != nil {
		t.Fatal(err)
	}
	mutations := []func(map[string]any){
		func(value map[string]any) { value["bin"].(map[string]any)["member"] = "../ant" },
		func(value map[string]any) { value["bin"].(map[string]any)["member"] = "bin/ant" },
	}
	for index, mutate := range mutations {
		var candidate map[string]any
		encoded, _ := json.Marshal(base)
		if err := json.Unmarshal(encoded, &candidate); err != nil {
			t.Fatal(err)
		}
		mutate(candidate)
		materializer, _ := json.Marshal(candidate)
		manifest := manifestWithMaterializerJSON(t, "claude-managed-ant", string(materializer))
		if err := ValidateManifest(manifest, manifest.ServerID, 0); err == nil {
			t.Fatalf("unsafe archive-binary mutation %d was accepted: %s", index, materializer)
		}
	}
}
