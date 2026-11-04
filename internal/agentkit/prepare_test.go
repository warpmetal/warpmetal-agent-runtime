package agentkit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func readData(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

type prepareFixture struct {
	operation model.WorkspaceApplicationOperation
	owner     model.ControllerOwner
	workspace model.ManagedServiceWorkspaceV1
	project   string
	envelope  []byte
	venue     Venue
}

func loadPrepareFixture(t *testing.T) prepareFixture {
	t.Helper()
	var document struct {
		Request Request `json:"request"`
	}
	if err := json.Unmarshal(readData(t, "agent-kit-prepare-document.json"), &document); err != nil {
		t.Fatalf("decode prepare document: %v", err)
	}
	request := document.Request
	var config map[string]json.RawMessage
	if err := json.Unmarshal(readData(t, "deepseek-agent-config.json"), &config); err != nil {
		t.Fatalf("decode config fixture: %v", err)
	}
	venue, err := SelectVenue("TEST-wp211-kit-materialization")
	if err != nil || venue == nil {
		t.Fatalf("select venue: %v", err)
	}
	return prepareFixture{
		operation: model.WorkspaceApplicationOperation{
			OperationID:           "wfapp_wp211b_prepare0001",
			SandboxID:             request.Target.SandboxID,
			SandboxGeneration:     request.Target.SandboxGeneration,
			ConfigurationID:       request.Configuration.ConfigurationID,
			ConfigurationRevision: request.Configuration.ConfigurationRevision,
			ConfigurationDigest:   request.Configuration.ConfigurationDigest,
			Configuration:         model.WorkspaceConfiguration{AgentSetup: config["agentSetup"]},
		},
		owner: model.ControllerOwner{
			AccountID: "account_wp211b", TaskID: "task_wp211b", ServerID: "srv_wp211b",
			SandboxID: request.Target.SandboxID, SandboxGeneration: request.Target.SandboxGeneration,
			CellID: "cell_wp211b", ControllerID: "controller_wp211b",
			ControllerRevision: 1, AuthorityRevision: 1,
		},
		workspace: model.ManagedServiceWorkspaceV1{
			SelectionID:     request.Target.Workspace.SelectionID,
			ProjectID:       request.Target.Workspace.ProjectID,
			WorkspaceEpoch:  request.Target.Workspace.WorkspaceEpoch,
			ScopeRevision:   1,
			Designation:     "team_project",
			RootAttestation: request.Target.Workspace.RootAttestation,
		},
		project:  request.Target.ProjectRoot,
		envelope: readData(t, "agent-kit-prepare-envelope.json"),
		venue:    *venue,
	}
}

type fakeExec struct {
	mu       sync.Mutex
	calls    int
	action   containers.ManagedSupervisorAction
	request  []byte
	envelope []byte
	err      error
	block    bool
}

func (f *fakeExec) Exec(ctx context.Context, _ string, action containers.ManagedSupervisorAction, request []byte) ([]byte, []byte, error) {
	f.mu.Lock()
	f.calls++
	f.action = action
	f.request = append([]byte(nil), request...)
	envelope, err, block := f.envelope, f.err, f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	return envelope, nil, err
}

func (f *fakeExec) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeStoreKey struct {
	id                string
	sandboxID         string
	sandboxGeneration int64
}

type fakeStore struct {
	mu      sync.Mutex
	records map[fakeStoreKey]model.AgentKitMaterialization
}

func newFakeStore() *fakeStore {
	return &fakeStore{records: map[fakeStoreKey]model.AgentKitMaterialization{}}
}

func (s *fakeStore) AgentKitMaterialization(_ context.Context, id, sandboxID string, sandboxGeneration int64) (*model.AgentKitMaterialization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[fakeStoreKey{id, sandboxID, sandboxGeneration}]
	if !ok {
		return nil, nil
	}
	return &record, nil
}

func (s *fakeStore) PutAgentKitMaterialization(_ context.Context, record model.AgentKitMaterialization) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fakeStoreKey{record.MaterializationID, record.SandboxID, record.SandboxGeneration}
	if existing, ok := s.records[key]; ok {
		if existing.EnvelopeDigest != record.EnvelopeDigest ||
			existing.KitDigest != record.KitDigest ||
			existing.ClosureDigest != record.ClosureDigest {
			return false, ErrMaterializationConflict
		}
		return false, nil
	}
	s.records[key] = record
	return true, nil
}

func newPrepareMaterializer(exec *fakeExec, store *fakeStore) Materializer {
	now := time.Date(2026, 10, 26, 18, 0, 0, 0, time.UTC)
	return Materializer{Exec: exec.Exec, Store: store, Now: func() time.Time { return now }}
}

func prepareInput(fixture prepareFixture) PrepareInput {
	return PrepareInput{
		Operation:   fixture.operation,
		Owner:       fixture.owner,
		Workspace:   fixture.workspace,
		ProjectRoot: fixture.project,
	}
}

func TestPreparePersistsVerifiedReceiptAndIsIdempotent(t *testing.T) {
	fixture := loadPrepareFixture(t)
	exec := &fakeExec{envelope: fixture.envelope}
	store := newFakeStore()
	materializer := newPrepareMaterializer(exec, store)

	record, created, err := materializer.Prepare(context.Background(), prepareInput(fixture), fixture.venue)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if !created {
		t.Fatal("first prepare must create the verified record")
	}
	if exec.count() != 1 || exec.action != containers.ManagedSupervisorMaterializeAgentKit {
		t.Fatalf("exec binding: calls=%d action=%q", exec.count(), exec.action)
	}
	// The Runtime-built document must be the exact closed invocation the real
	// supervisor consumed (same canonical request, same materialization id).
	var fixtureDocument map[string]json.RawMessage
	if err := json.Unmarshal(readData(t, "agent-kit-prepare-document.json"), &fixtureDocument); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	var fixtureRequest Request
	if err := json.Unmarshal(fixtureDocument["request"], &fixtureRequest); err != nil {
		t.Fatalf("decode fixture request: %v", err)
	}
	if record.MaterializationID != fixtureRequest.MaterializationID {
		t.Fatalf("materialization id %q != %q", record.MaterializationID, fixtureRequest.MaterializationID)
	}
	if record.KitDigest != fixtureRequest.KitDigest || record.ClosureDigest != "sha256:e201054ea5cf80d6bbc8d3b68ea5bc7e9ed0fc7a0301689ae20837b30d7da965" {
		t.Fatalf("record digests: %+v", record)
	}
	if record.AdoptionID != "WP211A-MAT-ADOPT-1" || record.Venue != "TEST-wp211a-installed-a" {
		t.Fatalf("adoption binding: %+v", record)
	}
	if record.InstructionDigest == "" || len(record.SkillContentDigests) != 1 ||
		record.SkillContentDigests["warpmetal-agent-sandbox"] != "sha256:ce3d030c6526114581d4c57d10272134f2d5f90ca108761682253ffa9acda19a" {
		t.Fatalf("materialization facts: %+v", record)
	}
	if len(record.EnvelopeJSON) == 0 {
		t.Fatal("verified envelope bytes must be persisted")
	}
	if record.VerifiedAt != "2026-10-26T18:00:00Z" {
		t.Fatalf("verifiedAt: %q", record.VerifiedAt)
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("persisted record invalid: %v", err)
	}

	// Retry: the retained verified record is returned, the cell is not re-exec'd.
	retried, createdAgain, err := materializer.Prepare(context.Background(), prepareInput(fixture), fixture.venue)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if createdAgain || exec.count() != 1 {
		t.Fatalf("retry must be idempotent: created=%t calls=%d", createdAgain, exec.count())
	}
	if retried.MaterializationID != record.MaterializationID || retried.EnvelopeDigest != record.EnvelopeDigest {
		t.Fatalf("retained record drifted: %+v", retried)
	}
}

func TestPrepareV1OperationIsDeclaredOnlyNoOp(t *testing.T) {
	fixture := loadPrepareFixture(t)
	fixture.operation.Configuration = model.WorkspaceConfiguration{FormatVersion: 1}
	exec := &fakeExec{envelope: fixture.envelope}
	materializer := newPrepareMaterializer(exec, newFakeStore())
	record, created, err := materializer.Prepare(context.Background(), prepareInput(fixture), fixture.venue)
	if err != nil || created || record.MaterializationID != "" || exec.count() != 0 {
		t.Fatalf("v1 operation must be a declared-only no-op: record=%+v created=%t calls=%d err=%v",
			record, created, exec.count(), err)
	}
}

func TestPrepareProductionVenueSelectsNothing(t *testing.T) {
	fixture := loadPrepareFixture(t)
	exec := &fakeExec{envelope: fixture.envelope}
	materializer := newPrepareMaterializer(exec, newFakeStore())
	if venue, err := SelectVenue(""); venue != nil || err != nil {
		t.Fatalf("production default must select nothing")
	}
	_, _, err := materializer.Prepare(context.Background(), prepareInput(fixture), Venue{ID: "production"})
	if code, ok := PrepareErrorCode(err); !ok || code != PrepareUnavailable {
		t.Fatalf("uncompiled venue must refuse typed, got %v", err)
	}
}

func TestPrepareExecFailuresAreTyped(t *testing.T) {
	fixture := loadPrepareFixture(t)

	failing := &fakeExec{err: errors.New("podman exec failed: exit status 1")}
	if _, _, err := newPrepareMaterializer(failing, newFakeStore()).Prepare(context.Background(), prepareInput(fixture), fixture.venue); !hasPrepareCode(err, PrepareExecFailed) {
		t.Fatalf("exec failure must be typed, got %v", err)
	}

	blocking := &fakeExec{block: true}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err := newPrepareMaterializer(blocking, newFakeStore()).Prepare(ctx, prepareInput(fixture), fixture.venue)
	if !hasPrepareCode(err, PrepareExecTimeout) {
		t.Fatalf("deadline must be typed as exec timeout, got %v", err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("deadline did not bound the exec")
	}
}

func TestPrepareEnvelopeRefusals(t *testing.T) {
	fixture := loadPrepareFixture(t)
	for name, envelope := range map[string][]byte{
		"malformed":  []byte(`{"schemaVersion":1,`),
		"wrong-kind": []byte(`{"schemaVersion":1,"command":"start","status":"ready","ready":true}`),
		"empty":      {},
		"oversized":  []byte(strings.Repeat(" ", 65*1024)),
	} {
		exec := &fakeExec{envelope: envelope}
		_, _, err := newPrepareMaterializer(exec, newFakeStore()).Prepare(context.Background(), prepareInput(fixture), fixture.venue)
		if err == nil {
			t.Fatalf("%s envelope must refuse", name)
		}
		code, ok := PrepareErrorCode(err)
		if !ok || code != PrepareVerification && code != PrepareBoundsExceeded {
			t.Fatalf("%s envelope wrong code %q (%v)", name, code, err)
		}
	}
}

func TestPrepareVerifiesClosureAndReceipt(t *testing.T) {
	fixture := loadPrepareFixture(t)
	// Tamper the measured closure inside the real envelope; its wrapper digest
	// no longer matches and the prepared closure is a compiled adoption value.
	var envelope map[string]any
	if err := json.Unmarshal(fixture.envelope, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	closure := envelope["closure"].(map[string]any)
	closure["closureDigest"] = "sha256:" + strings.Repeat("0", 64)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode tampered envelope: %v", err)
	}
	exec := &fakeExec{envelope: tampered}
	_, _, err = newPrepareMaterializer(exec, newFakeStore()).Prepare(context.Background(), prepareInput(fixture), fixture.venue)
	if code, ok := PrepareErrorCode(err); !ok || code != PrepareVerification {
		t.Fatalf("closure drift must refuse typed, got %v", err)
	}
}

func TestPreparePersistenceConflictFailsClosed(t *testing.T) {
	fixture := loadPrepareFixture(t)
	exec := &fakeExec{envelope: fixture.envelope}
	store := newFakeStore()
	materializer := newPrepareMaterializer(exec, store)
	record, _, err := materializer.Prepare(context.Background(), prepareInput(fixture), fixture.venue)
	if err != nil {
		t.Fatalf("first prepare: %v", err)
	}
	// A retained record with the same identity but different evidence must not be
	// overwritten by a later prepare.
	conflicted := record
	conflicted.EnvelopeDigest = "sha256:" + strings.Repeat("1", 64)
	conflicted.EnvelopeJSON = []byte(`{"schemaVersion":1,"command":"materialize-agent-kit","status":"ready","ready":true}`)
	store.records[fakeStoreKey{record.MaterializationID, record.SandboxID, record.SandboxGeneration}] = conflicted
	if _, _, err := materializer.Prepare(context.Background(), prepareInput(fixture), fixture.venue); !hasPrepareCode(err, PreparePersistence) {
		t.Fatalf("persistence conflict must refuse typed, got %v", err)
	}
}

func hasPrepareCode(err error, code string) bool {
	got, ok := PrepareErrorCode(err)
	return ok && got == code
}

// TestPrepareDoesNotReuseAnotherWorkspacesRetainedEvidence proves the
// multi-workspace isolation at the prepare boundary: a second sandbox with the
// same deterministic materialization identity must not be handed the first
// sandbox's retained record; it re-executes the in-cell materializer (and would
// only accept an envelope bound to its own request).
func TestPrepareDoesNotReuseAnotherWorkspacesRetainedEvidence(t *testing.T) {
	fixture := loadPrepareFixture(t)
	exec := &fakeExec{envelope: fixture.envelope}
	store := newFakeStore()
	materializer := newPrepareMaterializer(exec, store)
	if _, created, err := materializer.Prepare(context.Background(), prepareInput(fixture), fixture.venue); err != nil || !created {
		t.Fatalf("first workspace prepare: created=%t err=%v", created, err)
	}
	other := fixture
	other.operation.SandboxID = "sbx_wp211b_other0002"
	other.owner.SandboxID = "sbx_wp211b_other0002"
	// The fixed fixture envelope is bound to the first workspace, so the second
	// prepare must reject it as verification drift rather than returning the
	// retained first-workspace record.
	if _, _, err := materializer.Prepare(context.Background(), prepareInput(other), fixture.venue); err == nil {
		t.Fatal("second workspace must not accept the first workspace's envelope")
	}
	if exec.count() != 2 {
		t.Fatalf("second workspace must execute the materializer again, calls=%d", exec.count())
	}
	if retained, _ := store.AgentKitMaterialization(context.Background(), "akm_"+strings.Repeat("0", 32), "sbx_wp211b_other0002", 1); retained != nil {
		t.Fatal("unrelated workspace must have no retained evidence")
	}
}
