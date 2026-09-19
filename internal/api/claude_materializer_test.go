package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const apiClaudeLauncherMaterializer = `{"kind":"npm-package-set","artifacts":[{"id":"claude-wrapper","source":"https://registry.npmjs.org/@anthropic-ai/claude-code/-/claude-code-2.1.277.tgz","sha256":"sha256:3bf521e81cf84c654a335a58b301a3d2c35585a64762cfc146fb90a49c1b377e","format":"npm-tgz","sizeBytes":27539,"packageName":"@anthropic-ai/claude-code","packageVersion":"2.1.277","installAs":"@anthropic-ai/claude-code"},{"id":"claude-linux-x64","source":"https://registry.npmjs.org/@anthropic-ai/claude-code-linux-x64/-/claude-code-linux-x64-2.1.277.tgz","sha256":"sha256:0ac0d7e24e12fedd6de2507dd5ed8b1d16b686ef8e58839d976e72a09b380b2e","format":"npm-tgz","sizeBytes":104046180,"packageName":"@anthropic-ai/claude-code-linux-x64","packageVersion":"2.1.277","installAs":"@anthropic-ai/claude-code-linux-x64"}],"bins":[],"launchers":[{"bin":"claude","kind":"node-module","artifactId":"claude-wrapper","entrypoint":"cli-wrapper.cjs","environment":{"DISABLE_UPDATES":"1"}}]}`

const apiAntArchiveMaterializer = `{"kind":"archive-binary","artifact":{"id":"ant-linux-amd64","source":"https://github.com/anthropics/anthropic-cli/releases/download/v1.33.0/ant_1.33.0_linux_amd64.tar.gz","sha256":"sha256:937a93020b92260a9c1221fa25d79586245e67c368848a0b77b83e645da77f38","format":"tar-gz","sizeBytes":9471689},"bin":{"name":"ant","member":"ant"}}`

func apiManifestWithMaterializer(profileID, materializer string) string {
	return fmt.Sprintf(`{"serverId":"srv_example123","desiredRevision":1,"imageDigest":"registry.example/sandbox@sha256:%s","capacity":{"cpuMillicores":1000,"memoryMiB":2048,"workspaceDiskGiB":20,"pids":256},"sandboxes":[{"id":"sbx_test12345","name":"main","resources":{"cpuMillicores":500,"memoryMiB":1024,"workspaceDiskGiB":10,"pids":128},"lifetime":"persistent","expiresInSeconds":null,"startedAt":null,"expiresAt":null,"desiredState":"running","generation":1}],"accessGrants":[],"setupOperations":[{"id":"setup-test12345","schemaVersion":1,"sandboxId":"sbx_test12345","sandboxGeneration":1,"profileId":%q,"profileRevision":1,"profileDigest":"sha256:%s","materializer":%s}]}`, strings.Repeat("a", 64), profileID, strings.Repeat("b", 64), materializer)
}

func manifestClientForResponse(t *testing.T, response string) (Client, func()) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, response)
	}))
	return Client{Origin: server.URL, NodeToken: "rtn_test", HTTP: server.Client()}, server.Close
}

func TestClientStrictDecoderAcceptsClaudeLauncherAndAntArchiveContracts(t *testing.T) {
	tests := []struct {
		name         string
		profileID    string
		materializer string
	}{
		{"Claude launcher", "claude-code", apiClaudeLauncherMaterializer},
		{"ant archive", "claude-managed-ant", apiAntArchiveMaterializer},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, closeServer := manifestClientForResponse(t, apiManifestWithMaterializer(test.profileID, test.materializer))
			defer closeServer()
			if _, err := client.Manifest(context.Background()); err != nil {
				t.Fatalf("strict manifest decoder rejected valid %s contract: %v", test.name, err)
			}
		})
	}
}

func TestClientStrictDecoderRejectsExecutionControlsInNewMaterializers(t *testing.T) {
	unsafe := []struct {
		name         string
		profileID    string
		materializer string
	}{
		{"launcher command", "claude-code", strings.TrimSuffix(apiClaudeLauncherMaterializer, "}") + `,"command":["sh","-c","id"]}`},
		{"launcher hook", "claude-code", strings.Replace(apiClaudeLauncherMaterializer, `"environment":{"DISABLE_UPDATES":"1"}`, `"environment":{"DISABLE_UPDATES":"1"},"hook":"postinstall"`, 1)},
		{"archive command", "claude-managed-ant", strings.TrimSuffix(apiAntArchiveMaterializer, "}") + `,"command":["ant","beta:worker","poll"]}`},
		{"archive artifact package field", "claude-managed-ant", strings.Replace(apiAntArchiveMaterializer, `"sizeBytes":9471689`, `"sizeBytes":9471689,"packageName":"@anthropic-ai/claude-code"`, 1)},
	}
	for _, test := range unsafe {
		t.Run(test.name, func(t *testing.T) {
			client, closeServer := manifestClientForResponse(t, apiManifestWithMaterializer(test.profileID, test.materializer))
			defer closeServer()
			if _, err := client.Manifest(context.Background()); err == nil {
				t.Fatalf("strict manifest decoder accepted unknown execution control in %s", test.name)
			}
		})
	}
}
