package reconcile

// Extends the normal V3 execute journey with a freshly signed reviewer4/control5.
// Installed exports/adoption/native identity remain declared SOURCE suppliers;
// current prepared SQLite and actual node-auth TLS are real. No ROOT/run claim.
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
	"syscall"
)

type reviewerPreparedSourceControl struct {
	*workerExecuteSourceControl
	roleOperations int
}

func (c *reviewerPreparedSourceControl) WorkflowRoleEnrollmentOperation(ctx context.Context, call model.WorkflowRoleOperationRequest) (model.WorkflowRoleOperation, error) {
	c.roleOperations++
	return c.client.WorkflowRoleEnrollmentOperation(ctx, call)
}
func (c *reviewerPreparedSourceControl) EnrollWorkflowRole(ctx context.Context, p model.WorkflowRoleEnvelope) (model.WorkflowRoleEnrollment, error) {
	return c.client.EnrollWorkflowRole(ctx, p)
}

type reviewerPreparedSourceRuntime struct {
	*workerExecuteSourceRuntime
	identities, roleHTTP, enrollments, targetGets int
	op                                            model.WorkflowRoleOperation
	store                                         *state.Store
	originals                                     reviewerSourceOriginals
	bodies                                        map[string][]byte
}

func testCellV3PreparedReviewerOwnReadsBeforeDispatch(t *testing.T) {
	base, predecessor := os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE"), os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET")
	if base == "" || predecessor == "" || os.Getenv("WARPMETAL_REVIEWER_SCHEMA_SOURCE") == "" {
		t.Fatal("current reviewer SOURCE suppliers required")
	}
	root, err := os.MkdirTemp(base, "normal-reviewer-source-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE_PRIVATE_ARTIFACTS", root)
	packet := filepath.Join(root, "fixture.json")
	cmd := exec.Command("python3", "-B", "../qualification/testdata/child_product_boundary_fixture.py", "../workflowcontract/schema", predecessor, packet, "--flash-provider-boundary", "--reviewer-delivery-boundary")
	cmd.Env = append(os.Environ(), "WARPMETAL_REVIEWER_MANAGER_SOURCE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh current reviewer fixture: %v %s", err, out)
	}
	s := &workerExecuteSource{t: t, root: root, sourceNodeToken: "synthetic-node"}
	raw, err := os.ReadFile(packet)
	if err != nil || json.Unmarshal(raw, &s.fixture) != nil || !s.fixture.AuthoritySynthetic || s.fixture.LiveAuthorized {
		t.Fatal("fresh reviewer SOURCE classification", err)
	}
	var original struct {
		ReviewerOriginals      reviewerSourceOriginals
		ReviewerInstalledFacts struct {
			Prepare, Execute qualification.ChildProductInstalledFacts
		}
	}
	if json.Unmarshal(raw, &original) != nil {
		t.Fatal("reviewer installed SOURCE input")
	}
	s.delivery, err = model.DecodeChildProductDelivery(s.fixture.Execute)
	if err != nil {
		t.Fatal(err)
	}
	w := s.fixture.Witness
	entry := w.Entry
	var controlWire struct {
		Generation qualification.ChildProductGeneration
	}
	if json.Unmarshal(s.fixture.Execute, &controlWire) != nil || controlWire.Generation.FormatVersion != 5 || controlWire.Generation.Policy == nil || controlWire.Generation.Policy.Payload.FormatVersion != 4 || entry.Role != "reviewer" || entry.ExecutionGrant == nil || w.ActualReceipt == nil {
		t.Fatal("current q4/control5/ready grant selection")
	}
	a := qualification.ChildProductAuthorityFacts{OperatorKeyID: w.OperatorKeyID, QualifiedApplicability: w.QualifiedApplicability, Qualification: w.Qualification, Case: w.Case, Scope: w.Scope, Intent: w.Intent, Handle: w.Handle, Root: w.Root, SigningNotBefore: w.SigningNotBefore, ProductSigningNotBefore: w.ProductSigningNotBefore, ActivationSigningNotBefore: w.ActivationSigningNotBefore, AuthorizedUntil: w.AuthorizedUntil, AcceptedPreparationEnvelope: w.AcceptedPreparationEnvelope, AcceptedDemandEnvelope: w.AcceptedDemandEnvelope}
	l := qualification.ChildProductLifecycleFacts{ActualReceipt: w.ActualReceipt, Binding: w.Binding, Assignment: w.Assignment, Grant: w.Grant, Authorization: w.Authorization}
	s.facts, err = model.DecodeChildProductOriginalFacts(fixtureRaw(map[string]any{"formatVersion": 1, "preparationId": entry.PreparationID, "phase": "execute", "generationDigest": s.delivery.GenerationDigest(), "authority": a, "installed": original.ReviewerInstalledFacts.Execute, "lifecycle": l}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = qualification.DecodeOriginalChildProductFacts(s.facts); err != nil {
		t.Fatal("current SOURCE owner facts", err)
	}
	var runtime *reviewerPreparedSourceRuntime
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if runtime != nil && runtime.serve(rw, req) {
			return
		}
		if req.Method == "GET" && req.URL.Path == "/internal/runtime/workspace-workflow/child-preparations/"+entry.PreparationID+"/product-control" && req.Header.Get("Authorization") == "Bearer synthetic-node" && req.Header.Get("X-WarpMetal-Workflow-Lease") == "" {
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write(s.fixture.Execute)
			return
		}
		t.Errorf("unexpected reviewer SOURCE HTTP %s %s", req.Method, req.URL.Path)
		http.Error(rw, "refused", 403)
	}))
	defer server.Close()
	baseControl := &workerExecuteSourceControl{cellTestControl: &cellTestControl{instruction: model.ManagedServiceInstructionV1{InstructionRevision: entry.Instructions.InstructionRevision, InstructionDigest: entry.Instructions.InstructionDigest, Content: string(w.Input), ExpiresAt: time.Now().Add(time.Minute)}}, client: api.Client{Origin: server.URL, NodeToken: "synthetic-node", HTTP: server.Client()}, source: s}
	ctl := &reviewerPreparedSourceControl{workerExecuteSourceControl: baseControl}
	store, err := state.Open(filepath.Join(root, "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	ctx := context.Background()
	if err = store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: s.fixture.PrepareEntry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	if err = store.PutCellV3NativeContext(ctx, s.fixture.PrepareEntry, "ses_source_parent", work); err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: s.fixture.PrepareEntry, Phase: "reported", Receipt: *w.ActualReceipt, PreparedReceiptDigest: w.ActualReceipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	setup := model.SetupOperation{ID: entry.Profile.SetupOperationID, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration, ProfileID: entry.Profile.ProfileID, ProfileRevision: entry.Profile.ProfileRevision, ProfileDigest: entry.Profile.ProfileDigest}
	seedReadyProfile(t, store, setup)
	if err = store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ObservedGeneration: entry.SandboxGeneration, ObservedState: "running", ImageDigest: w.Applicability.Sandbox.RegistryManifestDigest}); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(work)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	service := entry.ServiceRegistrationID
	project := workspacecatalog.RegisteredProject{Report: model.ProjectCatalogReportV1{FormatVersion: 1, SelectionID: entry.Workspace.SelectionID, ProjectID: entry.Workspace.ProjectID, WorkspaceEpoch: entry.Workspace.WorkspaceEpoch, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration, ServiceRegistrationID: &service, Designation: "team_project", RootAttestation: entry.Workspace.RootAttestation, Availability: "available"}, HostRoot: work, ContainerRoot: work, ScopeRevision: entry.Workspace.ScopeRevision, RootDevice: uint64(stat.Dev), RootInode: stat.Ino}
	if err = store.PutManagedProject(ctx, state.LocalManagedProject{Phase: "ready", ServerID: w.Applicability.ServerID, Report: project.Report, HostRoot: work, ContainerRoot: work, ScopeRevision: project.ScopeRevision, RootDevice: project.RootDevice, RootInode: project.RootInode}); err != nil {
		t.Fatal(err)
	}
	outcome := "succeeded"
	response := jsonMap(t, managedCellResultV1{SchemaVersion: 1, Status: "applied", RuntimeContractVersion: model.CellExecutionContractVersion, OperationID: entry.LaunchOperationID, SessionID: entry.NativeSessionID, MessageID: entry.ExecutionGrant.InputID, State: "terminal", Outcome: &outcome, Attempt: entry.Attempt})
	response["guardReceipt"] = map[string]any{"formatVersion": 1, "sessionID": entry.NativeSessionID, "inboxID": entry.ExecutionGrant.InputID, "guardID": entry.ExecutionGrant.GrantID, "bindingDigest": w.ActualReceipt.BindingDigest, "state": "delivered", "admittedAt": 1, "availableAt": 2, "settledAt": nil, "refusalCode": nil, "logCursor": 2}
	runtime = &reviewerPreparedSourceRuntime{workerExecuteSourceRuntime: &workerExecuteSourceRuntime{cellTestRuntime: &cellTestRuntime{started: true, result: fixtureRaw(response)}, source: s}, store: store, originals: original.ReviewerOriginals, bodies: map[string][]byte{}}
	s.snapshot = fixtureRaw(map[string]any{"classification": "SOURCE prepared/current native identity; no native observation claim", "role": "reviewer", "bindingStatus": "pending", "executionStatus": "bound", "grantStatus": "issued", "nativeContextDigest": model.WorkspaceDigest(w.ActualReceipt), "managedServiceReceiptDigest": w.ActualReceipt.PreparedReceiptDigest})
	r := newCellReconciler(t, store, ctl, runtime)
	r.Now = time.Now
	r.ManagedCatalog = workerSourceCatalog{Catalog: &workspacecatalog.Catalog{State: store}, project: project}
	current := model.Manifest{ServerID: w.Applicability.ServerID, DesiredRevision: w.Root.RuntimeRevision, CellEntriesV3: []model.CellServiceV3{entry}}
	seedIntegratorSourceApplication(t, r, s, &current) // Existing role-neutral current app/parent SOURCE constructor.
	r.setCurrentAuthority(current)
	firstRoot, e1 := r.currentReviewerRegisteredRoot(ctx, entry)
	secondRoot, e2 := r.currentReviewerRegisteredRoot(ctx, entry)
	if e1 != nil || e2 != nil || !reflect.DeepEqual(firstRoot, secondRoot) || firstRoot.Report.ServiceRegistrationID == nil || firstRoot.Report.ServiceRegistrationID == secondRoot.Report.ServiceRegistrationID {
		t.Fatal("independent SQLite root value/pointer diagnostic", e1, e2)
	}
	_ = os.WriteFile(filepath.Join(root, "registered-root-value-diagnostic.json"), fixtureRaw(map[string]any{"equalCompleteValues": true, "independentDecodedPointers": true, "firstDigest": model.WorkspaceDigest(firstRoot), "secondDigest": model.WorkspaceDigest(secondRoot)}), 0600)

	err = r.reconcileCellServiceV3ExecuteCurrent(ctx, entry, &current)
	execution, readErr := store.CellV3Execution(ctx, entry.PreparationID)
	if err == nil || readErr != nil || execution != nil || len(runtime.calls) != 0 || s.adopted != 0 || s.selected != 1 {
		t.Fatal("missing own read supplier did not stop before claim", err, readErr)
	}
	selection, err := runtime.control().ReviewerSources()
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.Physical) != 2 {
		t.Fatal("expected exact packet/candidate source scopes")
	}
	for _, read := range selection.Physical {
		body := original.ReviewerOriginals.PacketBase64
		if read.Reference.Path == original.ReviewerOriginals.Reference.Path {
			body = original.ReviewerOriginals.CandidateBase64
		}
		if len(body) != read.ByteCount || model.RawPhysicalDigest(body) != read.Reference.SourceDigest {
			t.Fatal("SOURCE full physical bytes mismatch")
		}
		runtime.bodies[model.WorkspaceDigest(read.Reference)] = body
		leaf := filepath.Join(work, read.Reference.Path)
		if os.MkdirAll(filepath.Dir(leaf), 0700) != nil || os.WriteFile(leaf, body, 0600) != nil {
			t.Fatal("SOURCE physical provisioning")
		}
	}
	for _, raw := range w.SourceRoots {
		var source struct{ RegisteredSourceID string }
		_ = json.Unmarshal(raw, &source)
		if err = store.PutContinuitySource(ctx, state.LocalContinuitySource{Report: model.ContinuitySourceReportV1{FormatVersion: 1, RegisteredSourceID: source.RegisteredSourceID, Availability: "available", ProjectID: entry.Workspace.ProjectID, WorkspaceEpoch: entry.Workspace.WorkspaceEpoch, ScopeRevision: entry.Workspace.ScopeRevision, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration}, Root: work, Instance: entry.Instance, Lifecycle: "running", LifecycleRevision: 1}); err != nil {
			t.Fatal(err)
		}
	}
	s.allowRead = true
	runtime.onCall = func() {
		if runtime.enrollments != 1 || runtime.identities != 1 || s.retained != 3 || s.reports != 3 || runtime.targetGets != 2 {
			t.Fatal("SOURCE native prompt before own reviewer identity/read ACKs")
		}
	}
	err = r.reconcileCellServiceV3ExecuteCurrent(ctx, entry, &current)
	observed := map[string]any{"classification": "fresh signed reviewer4/control5; actual normal V3/SQLite/TLS/whole physical and separate private artifact bytes; SOURCE native/installed/signing suppliers, no ROOT proof", "roleOps": ctl.roleOperations, "roleHTTP": runtime.roleHTTP, "identities": runtime.identities, "enrollments": runtime.enrollments, "ownReadOperations": s.operations, "reads": s.reads, "proofs": s.proofs, "ACKs": s.reports, "retained": s.retained, "targetGETs": runtime.targetGets, "nativeSourceCalls": len(runtime.calls), "providers": 0, "rootRuns": 0}
	if err != nil {
		observed["error"] = err.Error()
	}
	_ = os.WriteFile(filepath.Join(root, "prepared-reviewer-normal-observation.json"), fixtureRaw(observed), 0600)
	if err != nil {
		t.Fatal("SOURCE prepared reviewer normal read/dispatch", err)
	}
	counts := func() []int {
		return []int{ctl.roleOperations, runtime.roleHTTP, runtime.identities, runtime.enrollments, s.operations, s.reads, s.proofs, s.reports, s.retained, runtime.targetGets, len(runtime.calls)}
	}
	want := []int{1, 1, 1, 1, 3, 3, 3, 3, 3, 2, 1}
	if model.WorkspaceDigest(counts()) != model.WorkspaceDigest(want) {
		t.Fatalf("SOURCE counts %v want %v", counts(), want)
	}
	locatorClaim, e := store.OwnedContinuationClaim(ctx, entry.PreparationID, "reviewer-source-original")
	var located reviewerSourceClaim
	if e != nil || model.DecodePhysicalClosed(locatorClaim, &located) != nil || !reflect.DeepEqual(located.Entry, entry) || located.GenerationDigest != s.delivery.GenerationDigest() || located.InputDigest != model.RawPhysicalDigest(w.Input) {
		t.Fatal("first reviewer source locator changed", e)
	}
	locatorRaw, e := store.OwnedContinuationResult(ctx, entry.PreparationID, "reviewer-source-original", locatorClaim)
	var index reviewerSourceOriginalIndex
	if e != nil || model.DecodePhysicalClosed(locatorRaw, &index) != nil || index.Base != located.base() || index.ClaimDigest != model.WorkspaceDigest(located) {
		t.Fatal("first reviewer source locator incomplete", e)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(filepath.Join(root, "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	r.Store = store
	runtime.store = store
	s.snapshot = fixtureRaw(map[string]any{"classification": "SOURCE terminal current snapshot after reviewer execution"})
	if err = r.reconcileCellServiceV3ExecuteCurrent(ctx, entry, &current); err != nil {
		t.Fatal("SOURCE same SQLite reopen", err)
	}
	if model.WorkspaceDigest(counts()) != model.WorkspaceDigest(want) {
		t.Fatal("SOURCE reopen repeated identity/read/dispatch", counts())
	}
	observed["sameSQLiteReopenNoRepeat"] = true
	_ = os.WriteFile(filepath.Join(root, "prepared-reviewer-normal-observation.json"), fixtureRaw(observed), 0600)
	t.Log("actual normal prepared reviewer own enrollment +3 first SOURCE read/ACKs +2 authenticated TLS original GETs before one SOURCE native dispatch; same SQLite reopen no repeated effects; ROOT custody/native unproved")
}
