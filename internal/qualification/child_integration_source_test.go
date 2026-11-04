package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func SourceIntegrationInstalledForTest(t *testing.T, w ChildProductWitness, prepareEntry model.CellServiceV3, prepare, execute ChildProductInstalledFacts) (ChildInstalledInputs, ChildInstalledInputs) {
	t.Helper()
	pre := w
	pre.Entry = prepareEntry
	pre.Assignment = nil
	pre.Binding = nil
	before, err := verifyChildInstalledInputs(prepare, pre, time.Now())
	if err != nil {
		t.Fatal("declared SOURCE observation2 preassignment parser", err)
	}
	after, err := verifyChildInstalledInputs(execute, w, time.Now())
	if err != nil {
		t.Fatal("declared SOURCE observation2 assignment parser", err)
	}
	wrong := execute
	wrong.Consumer.ChildProductSchemaSHA256 = "8a741172a3b1ab86738ada4e66062f4bc99ed9e968f5b66c206c8bcebd146532"
	if _, err = verifyChildInstalledInputs(wrong, w, time.Now()); err == nil {
		t.Fatal("integrator successor accepted base consumer pin")
	}
	t.Log("fresh declared SOURCE observation2 signatures/pins/null-to-assignment parsed; no actual installed qualification")
	return before, after
}

// Part of the same signed Store/TLS journey. The root mapping/result are
// declared SOURCE suppliers; this exercises the actual confined writer/reader,
// never a privileged Producer, signature, backend acceptance or native binary.
func SourceIntegrationStageForTest(t *testing.T, base string, w ChildProductWitness, c ChildProductControl, detail json.RawMessage, body []byte) {
	t.Helper()
	ctx := context.Background()
	target, err := c.IntegrationTarget()
	if err != nil {
		t.Fatal(err)
	}
	makeRoot := func(name string) TrustedWorkspace {
		host := filepath.Join(base, name)
		if os.MkdirAll(filepath.Join(host, filepath.Dir(target.Reference.Path)), 0700) != nil {
			t.Fatal("SOURCE target parent unavailable")
		}
		st, err := os.Stat(host)
		if err != nil {
			t.Fatal(err)
		}
		id := st.Sys().(*syscall.Stat_t)
		return TrustedWorkspace{HostRoot: host, ContainerRoot: filepath.Join(base, "work"), WorkspaceDigest: w.Root.Workspace.RootAttestation, Device: uint64(id.Dev), Inode: id.Ino}
	}
	makeJournal := func(name string) testPlanReadJournal {
		root := filepath.Join(base, name)
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		return testPlanReadJournal{root: root}
	}
	root := makeRoot("work")
	journal := makeJournal("integration-stage-originals")
	first, err := stageIntegrationTarget(ctx, w, c, root, detail, body, journal, uint32(os.Getuid()))
	if err != nil || first.SourceDevice == 0 || first.SourceInode == 0 {
		t.Fatal("SOURCE exact target staging refused", err)
	}
	replay, err := stageIntegrationTarget(ctx, w, c, root, detail, body, journal, uint32(os.Getuid()))
	if err != nil || replay != first {
		t.Fatal("SOURCE first stage replay changed", err)
	}
	if _, err = stageIntegrationTarget(ctx, w, c, root, detail, []byte("foreign target"), journal, uint32(os.Getuid())); err == nil {
		t.Fatal("foreign artifact admitted")
	}
	other := makeRoot("integration-conflicting-root")
	conflict := []byte("Different current content; do not overwrite\n")
	leaf := filepath.Join(other.HostRoot, target.Reference.Path)
	if os.WriteFile(leaf, conflict, 0600) != nil {
		t.Fatal("SOURCE conflict setup")
	}
	if _, err = stageIntegrationTarget(ctx, w, c, other, detail, body, makeJournal("integration-conflict-originals"), uint32(os.Getuid())); err == nil {
		t.Fatal("different existing target overwritten")
	}
	if got, err := os.ReadFile(leaf); err != nil || !bytes.Equal(got, conflict) {
		t.Fatal("denial changed current target bytes")
	}
	for _, scope := range c.Generation.Policy.Payload.SourceReads {
		if _, err := loadChildSourceOriginal(w, c, scope, journal.load, func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error {
			t.Fatal("missing own originals reached signature verification")
			return nil
		}); err == nil {
			t.Fatal("staging manufactured source-read credit")
		}
	}
	t.Log("SOURCE actual no-follow same-path stage and exact replay pass; foreign target/different existing content deny; no ROOT signature/read ACK or normal target acceptance")
}
