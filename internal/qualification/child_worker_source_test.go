package qualification

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Called only inside the existing fresh signed Store/native-file journey.
// Actual confined read/fence are exercised; no privileged Producer or successful
// signed read/ACK is fabricated. Their absence must still prevent credit.
func SourceWorkerReadJourneyForTest(t *testing.T, base string, w ChildProductWitness, current ChildProductControl) {
	t.Helper()
	refs, err := current.ApprovedWorkerSourceReads()
	if err != nil || len(refs) != 1 || len(current.Generation.Policy.Payload.SourceReads) != 1 {
		t.Fatal("published worker source selector absent", err)
	}
	scope := current.Generation.Policy.Payload.SourceReads[0]
	raw := []byte("SOURCE full worker Plan bytes\n")
	root := filepath.Join(base, "work")
	leaf := filepath.Join(root, refs[0].Reference.Path)
	if os.MkdirAll(filepath.Dir(leaf), 0700) != nil || os.WriteFile(leaf, raw, 0600) != nil {
		t.Fatal("SOURCE original provision failed")
	}
	st, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	id := st.Sys().(*syscall.Stat_t)
	workspace := TrustedWorkspace{HostRoot: root, ContainerRoot: root, WorkspaceDigest: w.Root.Workspace.RootAttestation, Device: uint64(id.Dev), Inode: id.Ino}
	journal := testPlanReadJournal{root: t.TempDir()}
	op := model.WorkflowCaptureOperation{OperationID: "wfop_worker_source", OperationDigest: Digest([]byte("explicit SOURCE read operation")), ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
	read, err := captureWorkflowSource(context.Background(), op, scope, workspace, journal)
	if err != nil || string(read.Bytes) != string(raw) || workerSourceInputMatches(w, current, scope, read.Bytes) != nil {
		t.Fatal("actual worker source/full original input join failed", err)
	}
	if _, err := loadWorkerSourceOriginal(w, current, scope, journal.load, func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error {
		t.Fatal("missing own original reached signature credit")
		return nil
	}); err == nil {
		t.Fatal("whole file read alone manufactured own read acknowledgement")
	}
	bad := w
	bad.Input = []byte("generic instructions without the full original source")
	if workerSourceInputMatches(bad, current, scope, read.Bytes) == nil {
		t.Fatal("missing source bytes in original firstText received read delivery credit")
	}
	t.Log("actual confined source read and retained bytes/fence pass; absent own signed first envelope/ACK denied; ROOT signing/admission not claimed")
}
