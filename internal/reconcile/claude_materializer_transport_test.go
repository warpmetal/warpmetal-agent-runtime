package reconcile

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

const transportClaudeLauncher = `{"kind":"npm-package-set","artifacts":[{"id":"claude-wrapper","source":"https://registry.npmjs.org/@anthropic-ai/claude-code/-/claude-code-2.1.277.tgz","sha256":"sha256:3bf521e81cf84c654a335a58b301a3d2c35585a64762cfc146fb90a49c1b377e","format":"npm-tgz","sizeBytes":27539,"packageName":"@anthropic-ai/claude-code","packageVersion":"2.1.277","installAs":"@anthropic-ai/claude-code"}],"bins":[],"launchers":[{"bin":"claude","kind":"node-module","artifactId":"claude-wrapper","entrypoint":"cli-wrapper.cjs","environment":{"DISABLE_UPDATES":"1"}}]}`

const transportAntArchive = `{"kind":"archive-binary","artifact":{"id":"ant-linux-amd64","source":"https://github.com/anthropics/anthropic-cli/releases/download/v1.33.0/ant_1.33.0_linux_amd64.tar.gz","sha256":"sha256:937a93020b92260a9c1221fa25d79586245e67c368848a0b77b83e645da77f38","format":"tar-gz","sizeBytes":9471689},"bin":{"name":"ant","member":"ant"}}`

func TestClaudeMaterializersReachTheExistingClosedSetupExecutionUnchanged(t *testing.T) {
	tests := []struct {
		name         string
		profileID    string
		materializer string
	}{
		{"Claude launcher", "claude-code", transportClaudeLauncher},
		{"ant archive", "claude-managed-ant", transportAntArchive},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := setupManifest(1)
			manifest.SetupOperations[0].ProfileID = test.profileID
			var materializer model.SetupMaterializer
			if err := json.Unmarshal([]byte(test.materializer), &materializer); err != nil {
				t.Fatal(err)
			}
			manifest.SetupOperations[0].Materializer = materializer

			store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			engine := &fakeEngine{
				setupResult:  setupReceiptFor(setupOperationID, setupSandboxID, test.profileID, "ready"),
				setupInvoked: make(chan setupInvocation, 1),
			}
			reconciler := setupReconciler(t, store, engine)
			if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
				t.Fatal(err)
			}
			_, _ = awaitReportState(t, reconciler, "applying")
			if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
				t.Fatal(err)
			}
			invocation := awaitSetupInvocation(t, engine.setupInvoked)
			var request map[string]any
			if err := json.Unmarshal(invocation.request, &request); err != nil {
				t.Fatal(err)
			}
			var want any
			if err := json.Unmarshal([]byte(test.materializer), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(request["materializer"], want) {
				t.Fatalf("materializer changed before the fixed setup runner boundary:\n got: %s\nwant: %s", invocation.request, test.materializer)
			}
		})
	}
}
