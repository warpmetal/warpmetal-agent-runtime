package reconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type agentKitRuntime struct {
	calls    int
	envelope []byte
	err      error
}

func (r *agentKitRuntime) ExecManagedSupervisor(_ context.Context, _ string, action containers.ManagedSupervisorAction, _ []byte) ([]byte, []byte, error) {
	r.calls++
	if action != containers.ManagedSupervisorMaterializeAgentKit {
		return nil, nil, errAgentKitFixture("unexpected action")
	}
	return r.envelope, nil, r.err
}

func (r *agentKitRuntime) ExecManagedWorker(context.Context, string, containers.ManagedWorkerAction, []byte) ([]byte, []byte, error) {
	return nil, nil, errAgentKitFixture("unexpected worker exec")
}

type errAgentKitFixture string

func (e errAgentKitFixture) Error() string { return string(e) }

// agentKitFixtureOperation builds the application operation identity from the
// real Rung-A/B prepare fixture (same kit, target, digests).
func agentKitFixtureOperation(t *testing.T) model.WorkspaceApplicationOperation {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "agentkit", "testdata", "agent-kit-prepare-document.json"))
	if err != nil {
		t.Fatalf("read prepare document: %v", err)
	}
	var document struct {
		Request struct {
			Target struct {
				SandboxID         string `json:"sandboxId"`
				SandboxGeneration int64  `json:"sandboxGeneration"`
				ProjectRoot       string `json:"projectRoot"`
			} `json:"target"`
			Configuration struct {
				ConfigurationID       string `json:"configurationId"`
				ConfigurationRevision int64  `json:"configurationRevision"`
				ConfigurationDigest   string `json:"configurationDigest"`
			} `json:"configuration"`
			Kit json.RawMessage `json:"kit"`
		} `json:"request"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode prepare document: %v", err)
	}
	return model.WorkspaceApplicationOperation{
		OperationID:           "wfapp_wp211b_prepare0001",
		SandboxID:             document.Request.Target.SandboxID,
		SandboxGeneration:     document.Request.Target.SandboxGeneration,
		ConfigurationID:       document.Request.Configuration.ConfigurationID,
		ConfigurationRevision: document.Request.Configuration.ConfigurationRevision,
		ConfigurationDigest:   document.Request.Configuration.ConfigurationDigest,
		Configuration:         model.WorkspaceConfiguration{AgentSetup: document.Request.Kit},
	}
}

func TestStageControllerAgentKitCallSiteIsGatedAndIdempotent(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	envelope, err := os.ReadFile(filepath.Join("..", "agentkit", "testdata", "agent-kit-prepare-envelope.json"))
	if err != nil {
		t.Fatalf("read prepare envelope: %v", err)
	}
	runtime := &agentKitRuntime{envelope: envelope}
	reconciler := &Reconciler{Store: store, ManagedRuntime: runtime, Now: func() time.Time {
		return time.Date(2026, 10, 26, 18, 0, 0, 0, time.UTC)
	}}
	op := agentKitFixtureOperation(t)
	parent := model.ControllerParentIntent{
		Owner: model.ControllerOwner{
			AccountID: "account_wp211b", TaskID: "task_wp211b", ServerID: "srv_wp211b",
			SandboxID: op.SandboxID, SandboxGeneration: op.SandboxGeneration,
			CellID: "cell_wp211b", ControllerID: "controller_wp211b",
			ControllerRevision: 1, AuthorityRevision: 1,
		},
		Workspace: model.ManagedServiceWorkspaceV1{
			SelectionID: "sel_wp211b", ProjectID: "proj_wp211b", WorkspaceEpoch: "wpe_wp211b",
			ScopeRevision: 1, Designation: "team_project", RootAttestation: "sha256:" + strings.Repeat("a", 64),
		},
	}
	project := workspacecatalog.RegisteredProject{ContainerRoot: "/home/agent/projects/ws"}

	// Production default: the venue env is unset/empty, so nothing is selected.
	t.Setenv("WARPMETAL_RUNTIME_AGENT_KIT_VENUE", "")
	if err := reconciler.stageControllerAgentKit(context.Background(), op, parent, project); err != nil {
		t.Fatalf("production default must no-op: %v", err)
	}
	if runtime.calls != 0 {
		t.Fatal("production default must not exec the supervisor")
	}

	t.Setenv("WARPMETAL_RUNTIME_AGENT_KIT_VENUE", "TEST-wp211-kit-materialization")
	if err := reconciler.stageControllerAgentKit(context.Background(), op, parent, project); err != nil {
		t.Fatalf("prepare call site: %v", err)
	}
	if runtime.calls != 1 {
		t.Fatalf("expected one supervisor exec, got %d", runtime.calls)
	}
	records, err := store.AgentKitMaterializations(context.Background())
	if err != nil || len(records) != 1 {
		t.Fatalf("verified receipt must be persisted once: %d %v", len(records), err)
	}
	if records[0].AdoptionID != "WP211A-MAT-ADOPT-1" || records[0].Venue != "TEST-wp211a-installed-a" {
		t.Fatalf("persisted record adoption binding: %+v", records[0])
	}
	if records[0].ClosureDigest != "sha256:e201054ea5cf80d6bbc8d3b68ea5bc7e9ed0fc7a0301689ae20837b30d7da965" {
		t.Fatalf("persisted closure drift: %s", records[0].ClosureDigest)
	}
	// Retry is idempotent: retained verified record, no second exec, no duplicate.
	if err := reconciler.stageControllerAgentKit(context.Background(), op, parent, project); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if runtime.calls != 1 {
		t.Fatalf("idempotent retry must not re-exec, calls=%d", runtime.calls)
	}
	records, err = store.AgentKitMaterializations(context.Background())
	if err != nil || len(records) != 1 {
		t.Fatalf("idempotent retry must not duplicate: %d %v", len(records), err)
	}

	// V1 operation (no agentSetup) is a declared-only no-op even when selected.
	v1Operation := op
	v1Operation.OperationID = "wfapp_wp211b_v1operation"
	v1Operation.Configuration = model.WorkspaceConfiguration{FormatVersion: 1}
	if err := reconciler.stageControllerAgentKit(context.Background(), v1Operation, parent, project); err != nil || runtime.calls != 1 {
		t.Fatalf("v1 operation must no-op: err=%v calls=%d", err, runtime.calls)
	}

	// Unknown venue fails closed with a typed code.
	t.Setenv("WARPMETAL_RUNTIME_AGENT_KIT_VENUE", "production")
	err = reconciler.stageControllerAgentKit(context.Background(), op, parent, project)
	if code, ok := controllerAgentKitBlockedCode(err); !ok || code != "agent_kit_venue_denied" {
		t.Fatalf("unknown venue must fail closed, got %v", err)
	}
}
