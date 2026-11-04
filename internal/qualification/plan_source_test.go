package qualification

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"golang.org/x/sys/unix"
)

// Actual local filesystem reader/fence/replay boundary. All authority, registered
// root and candidate identity are synthetic; the permitted component input file
// is NOT an installed approved project source. No signer/native/provider is run.
func TestPlanSourceFullReadContainmentAndNoRedispatch(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("\ufeffApproved source\r\nprivate complete bytes: π\n")
	if err = os.Mkdir(filepath.Join(root, "source"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "source", "plan.md"), content, 0600); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if unix.Stat(root, &st) != nil {
		t.Fatal("root stat")
	}
	w := TrustedWorkspace{HostRoot: root, Device: uint64(st.Dev), Inode: st.Ino}
	op := syntheticPlanReadOperation(content)
	op.Document.Source.ByteCount = len(content)
	op.Document.Source.Reference = model.ControllerPlanReference{Path: "source/plan.md", Status: "accepted", SourceDigest: Digest(content)}
	evidence, _ := filepath.EvalSymlinks(t.TempDir())
	journal := testPlanReadJournal{root: evidence}
	back, err := capturePlanSource(context.Background(), op, w, journal)
	if err != nil || back.ValidateBytes() != nil {
		t.Fatalf("whole actual source read: %v", err)
	}
	// Retained complete proof, not reopening source even after its removal.
	if err = os.Remove(filepath.Join(root, "source", "plan.md")); err != nil {
		t.Fatal(err)
	}
	prior, err := capturePlanSource(context.Background(), op, w, journal)
	if err != nil || model.WorkspaceDigest(prior) != model.WorkspaceDigest(back) {
		t.Fatal("replay re-read or changed immutable proof")
	}
	changed := op
	changed.OperationDigest = Digest([]byte("changed operation"))
	if _, err = capturePlanSource(context.Background(), changed, w, journal); err == nil {
		t.Fatal("operationId rebound")
	}
	// Symlink denies after fencing. Repairing the source cannot retry this unknown.
	op.OperationID = "synthetic_symlink"
	if err = os.Symlink(filepath.Join(root, "outside.md"), filepath.Join(root, "source", "plan.md")); err != nil {
		t.Fatal(err)
	}
	if _, err = capturePlanSource(context.Background(), op, w, journal); err == nil {
		t.Fatal("symlink read")
	}
	if err = os.Remove(filepath.Join(root, "source", "plan.md")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "source", "plan.md"), content, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = capturePlanSource(context.Background(), op, w, journal); err == nil {
		t.Fatal("unknown fenced operation redispatched")
	}
	for _, path := range []string{"../source/plan.md", "source/../source/plan.md", "/source/plan.md"} {
		if _, err = readPlanSourceFile(context.Background(), w, path, len(content), Digest(content)); err == nil {
			t.Fatal("unsafe containment accepted")
		}
	}
	wrong := w
	wrong.Inode++
	if _, err = readPlanSourceFile(context.Background(), wrong, "source/plan.md", len(content), Digest(content)); err == nil {
		t.Fatal("registered root drift")
	}
	if _, err = readPlanSourceFile(context.Background(), w, "source/plan.md", len(content)-1, Digest(content)); err == nil {
		t.Fatal("count+1 overflow not detected")
	}
}

func syntheticPlanReadOperation(content []byte) model.PlanSourceReadOperation {
	h := "sha256:" + strings.Repeat("a", 64)
	ref := model.ControllerPlanReference{Path: "source/plan.md", Status: "accepted", SourceDigest: Digest(content)}
	op := model.PlanSourceReadOperation{FormatVersion: 1, Kind: "owner_document_plan_read", OperationID: "synthetic_read", RuntimeRevision: 1, ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
		Document: model.PlanSourceDocument{FormatVersion: 1, Kind: "owner_plan_document", Plan: model.ControllerPlan{WorkID: "work_synthetic", WorkRevision: 1, ContentDigest: h, PlanRef: ref},
			Owner:     model.ControllerOwner{AccountID: "acct", TaskID: "task", ServerID: "server", SandboxID: "box", SandboxGeneration: 1, CellID: "cell", ControllerID: "controller", ControllerRevision: 1, AuthorityRevision: 1},
			Workspace: model.ManagedServiceWorkspaceV1{SelectionID: "selection", ProjectID: "project", WorkspaceEpoch: "epoch", ScopeRevision: 1, Designation: "team_project", RootAttestation: h},
			Source:    model.PlanSourceApproval{Reference: ref, ByteCount: len(content)}, TargetAuthority: json.RawMessage(`{"kind":"account_server","authorizationDigest":"` + h + `"}`)},
		Reader: model.PlanSourceReader{CaseID: "case", CaseManifestDigest: h, CandidateDescriptorDigest: h, ImplementationDigest: h, Producer: model.WorkspaceRegisteredProducer{KeyID: "key", KeySHA256: h, ServerID: "server", NodeTokenHash: strings.Repeat("b", 64)}}}
	digest := func(v any, field string) string {
		raw, _ := json.Marshal(v)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		delete(fields, field)
		return model.WorkspaceDigest(fields)
	}
	op.Document.DocumentDigest = digest(op.Document, "documentDigest")
	op.OperationDigest = digest(op, "operationDigest")
	return op
}

// Narrow private journal seam permits unprivileged source evidence while real
// Producer always uses its existing root-owned append-only storage. O_EXCL is
// exercised here, not mocked, including a deliberately torn reservation.
type testPlanReadJournal struct{ root string }

func (j testPlanReadJournal) load(name string, cap int) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(j.root, name))
	if len(b) > cap {
		return nil, ErrUntrusted
	}
	return b, err
}
func (j testPlanReadJournal) create(name string, b []byte) error {
	f, err := os.OpenFile(filepath.Join(j.root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	f.Close()
	return err
}

func TestPlanSourceUnknownTornFenceIsHeld(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	j := testPlanReadJournal{root: root}
	op := model.PlanSourceReadOperation{OperationID: "synthetic_torn", OperationDigest: Digest([]byte("op")), ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
	if err := j.create("plan-source-synthetic_torn-fence.json", []byte(`{"operationDigest":`)); err != nil {
		t.Fatal(err)
	}
	if _, err := capturePlanSource(context.Background(), op, TrustedWorkspace{}, j); err == nil {
		t.Fatal("torn reservation retried")
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Fatal("torn history overwritten")
	}
}
