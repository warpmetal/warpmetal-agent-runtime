package reconcile

// Same current app/declaration/accepted-action journey. Child preparation,
// adoption and native replies are fresh SOURCE suppliers; no protected custody,
// real native execution, backend acceptance or second worker result is claimed.
import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

func TestControllerCurrentLaterIntegratorTerminalThroughNormalReconcile(t *testing.T) {
	t.Setenv("WARPMETAL_CURRENT_STAGE_TERMINAL_SOURCE", "1")
	TestControllerCurrentAcceptedLaterIntentThroughNormalReconcile(t)
}

type currentStageTerminalSourceRuntime struct {
	*currentStageSourceRuntime
	terminal        *firstTaskChildTerminalRuntime
	observations    int
	completion      *currentStageCompletionSource
	review          *currentStageReviewCompletionSource
	priorSupervisor interface {
		ExecManagedSupervisor(context.Context, string, containers.ManagedSupervisorAction, []byte) ([]byte, []byte, error)
	}
}

func (s *currentStageTerminalSourceRuntime) ExecManagedSupervisor(ctx context.Context, box string, action containers.ManagedSupervisorAction, raw []byte) ([]byte, []byte, error) {
	if s.priorSupervisor != nil {
		var call struct{ Instance string }
		_ = json.Unmarshal(raw, &call)
		e := s.terminal.fixture.entry
		if call.Instance != e.Instance && call.Instance != model.ManagedServiceProcessInstance(e.Instance, e.ServiceGeneration) {
			return s.priorSupervisor.ExecManagedSupervisor(ctx, box, action, raw)
		}
	}
	return s.terminal.ExecManagedSupervisor(ctx, box, action, raw)
}
func (s *currentStageTerminalSourceRuntime) ObserveCellProductIntegration(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject, base json.RawMessage) (json.RawMessage, error) {
	s.observations++
	s.checkCompleted(ctx, box, entry, current, input, root, base)
	c := s.completion
	before, e := os.ReadFile(filepath.Join(c.root, "source-integration-before.body"))
	after, e2 := os.ReadFile(filepath.Join(c.root, "source-integration-after.body"))
	o := publicDeliveryMap(c.observation)
	if e != nil || e2 != nil || o["beforeDigest"] != model.RawPhysicalDigest(before) || o["afterDigest"] != model.RawPhysicalDigest(after) {
		c.t.Fatal("SOURCE current before/after observation changed", e, e2)
	}
	return append(json.RawMessage(nil), c.observation...), nil
}

func prepareCurrentStageTerminalSource(t *testing.T, j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, runtime *currentStageSourceRuntime, stage controllerStageOriginal, id string, selected model.ManagerIntentSelection, handle model.IntentHandle, intent map[string]any, resultClaim, resultRaw json.RawMessage) *currentStageTerminalSourceRuntime {
	t.Helper()
	ctx := context.Background()
	app := runtime.application
	parent := runtime.policy.ApplicationIdentity().Intent
	purpose := intent["purpose"].(string)
	childKind := map[string]string{"integrate": "integrator", "review": "reviewer"}[purpose]
	if childKind == "" || stage.Readout.AllocationName != "manager_"+purpose {
		t.Fatal("current SOURCE child purpose/allocation")
	}
	f := &firstTaskChildTerminalFixture{t: t, r: j.reconciler, handle: handle, selected: selected, backendState: "admitted", nativeState: "running", managerLease: "wfl_source_current_stage", ownerScopedProject: true}
	// Every current child identity is chosen before its receipt/binding/grant.
	f.entry = cellV3TestEntry(t)
	if purpose == "review" {
		f.entry.OperationID = "managed_source_current_reviewer"
		f.credentialID, f.nativeCredentialID = "cred_source_current_reviewer", "native_cred_source_current_reviewer"
	}
	prepare := sourceObject(intent["prepareBody"])
	f.entry.Role = prepare["role"].(string)
	f.entry.PreparationID = "source_current_" + childKind + "_preparation"
	f.entry.LaunchOperationID = prepare["operationId"].(string)
	f.entry.Instance = prepare["instance"].(string)
	launchDigest := sha256.Sum256([]byte(f.entry.LaunchOperationID))
	f.entry.NativeSessionID = "ses_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(launchDigest[:])
	f.entry.ServiceRegistrationID = "source_current_" + childKind + "_service"
	currentParent, e := j.reconciler.Store.ControllerParent(ctx, parent.ServiceRegistrationID)
	if e != nil || currentParent == nil || currentParent.Report.NativeRegistration == nil {
		t.Fatal("current SOURCE native parent", e)
	}
	f.entry.NativeProjectID = currentParent.Report.NativeRegistration.NativeProjectID
	publicDeliveryDecode(t, prepare["parentIdentity"], &f.entry.ParentIdentity)
	f.resultInput = string(fixtureRaw(map[string]any{"formatVersion": 1, "kind": "workspace_workflow_packet", "content": prepare["content"]}))
	f.entry.Instructions.InstructionDigest = model.RawPhysicalDigest([]byte(f.resultInput))
	authority := app.Dependencies.Roles[0].Projection.ModelSelection.Authority
	f.entry.Authority = &model.ManagedServiceV2Authority{ProviderID: authority.ProviderID, ModelID: &authority.ModelID, AuthMode: &authority.AuthMode}
	f.configureChildTerminalSource(t, j, parent, app)
	terminal := &firstTaskChildTerminalRuntime{firstTaskEnrollmentSourceRuntime: runtime.firstTaskEnrollmentSourceRuntime, fixture: f}
	next := &currentStageTerminalSourceRuntime{currentStageSourceRuntime: runtime, terminal: terminal}
	if j.reconciler.ManagedRuntime != nil {
		next.priorSupervisor, _ = j.reconciler.ManagedRuntime.(interface {
			ExecManagedSupervisor(context.Context, string, containers.ManagedSupervisorAction, []byte) ([]byte, []byte, error)
		})
	}
	j.reconciler.ManagedRuntime = next
	previous := native.sourceHTTP
	native.sourceHTTP = func(w http.ResponseWriter, r *http.Request) bool {
		if runtime.author != nil && runtime.author.serve(w, r) {
			return true
		}
		if next.review != nil && next.review.serve(w, r) {
			return true
		}
		if next.completion != nil && next.completion.serve(w, r) {
			return true
		}
		if f.serve(w, r) {
			return true
		}
		return previous(w, r)
	}
	err := j.reconciler.Reconcile(ctx, j.manifest)
	if purpose == "review" && os.Getenv("WARPMETAL_REFRESH_MODE") == "lost_refresh_ack" {
		runtime.author.assertRefreshUnknown(t, j, native, d, f, err, resultClaim, resultRaw)
		return nil
	}
	if err != nil {
		t.Fatal("later SOURCE preparation request", err)
	}
	if purpose == "review" && os.Getenv("WARPMETAL_CURRENT_STAGE_FACT_EXPIRY_SOURCE") == "1" {
		prior, ok := next.priorSupervisor.(*currentStageTerminalSourceRuntime)
		if !ok || prior.completion == nil {
			t.Fatal("SOURCE current integration predecessor missing")
		}
		c := prior.completion
		observed := map[string]any{"classification": "current case3/declaration4 normal accepted-parent child boundary; upstream author/result/native/installed SOURCE suppliers; no ROOT/native/backend acceptance claim", "newReviewStage": stage, "observedNow": j.reconciler.now().Format(time.RFC3339Nano), "snapshotDigest": model.WorkspaceDigest(prior.terminal.fixture.currentSnapshot()), "authorRefreshOperations": runtime.author.operations, "authorRefreshProofs": runtime.author.proofs, "authorRefreshReports": runtime.author.reports, "phase": "accepted_child", "settlementOperations": c.settlementOperations, "candidateOperations": c.candidateOperations, "childPrepare": f.prepares, "nativeSourcePrepares": f.nativePrepares, "originalIntegration": c.original}
		d.writeOriginal(t, filepath.Join(d.root, "current-stage-expired-dependency-observation.json"), fixtureRaw(observed), 0600)
		if c.settlementOperations < 2 || c.candidateOperations < 2 {
			t.Fatalf("normal current later child prepared before expired same-snapshot integration settlement/candidate refresh: settlement=%d candidate=%d childPrepare=%d", c.settlementOperations, c.candidateOperations, f.prepares)
		}
	}
	if f.prepares != 1 || f.nativePrepares != 0 {
		t.Fatal("later child did not await its manifest", f.prepares, f.nativePrepares)
	}
	receipt := f.preparedSourceReceipt()
	executionID := "source_child_execution"
	if purpose == "review" {
		executionID = "source_reviewer_execution"
	}
	binding := map[string]any{"workId": stage.Declared.Plan.WorkID, "workRevision": stage.Declared.Plan.WorkRevision, "bindingId": "source_" + childKind + "_binding", "bindingRevision": 1, "executionId": executionID, "preparationId": f.entry.PreparationID, "parentExecutionId": nil, "parentPacketId": nil, "packetId": f.entry.ParentIdentity.PacketID, "packetRevision": f.entry.ParentIdentity.PacketRevision, "attempt": f.entry.Attempt, "fence": f.entry.Fence, "serviceRegistrationId": f.entry.ServiceRegistrationID, "serviceGeneration": f.entry.ServiceGeneration, "sandboxGeneration": f.entry.SandboxGeneration, "nativeSessionId": f.entry.NativeSessionID, "nativeProjectId": f.entry.NativeProjectID, "nativeLocationDigest": model.WorkspaceDigest("SOURCE current integrator location"), "projectId": f.entry.Workspace.ProjectID, "workspaceEpoch": f.entry.WorkspaceEpoch, "selectionId": f.entry.Workspace.SelectionID, "scopeRevision": f.entry.Workspace.ScopeRevision, "rootAttestation": f.entry.Workspace.RootAttestation, "instructionRevision": f.entry.Instructions.InstructionRevision, "instructionDigest": f.entry.Instructions.InstructionDigest, "profileDigest": f.entry.Profile.ProfileDigest, "configDigest": f.entry.ConfigDigest}
	body := map[string]any{"formatVersion": 1, "requestId": selected.AssignmentRequestID, "binding": binding, "purpose": purpose, "plan": stage.Declared.Plan, "target": intent["target"]}
	f.actual = model.ActualPreparationAssociation{FormatVersion: 1, HandleID: handle.HandleID, Intent: handle.Intent, PreparationID: f.entry.PreparationID, PreparedReceipt: receipt, Binding: fixtureRaw(binding), AssignmentBody: fixtureRaw(body)}
	f.actual.AssociationDigest = fixtureDigestField(f.actual, "associationDigest")
	if err := f.actual.ValidateIntegrity(); err != nil {
		t.Fatal("fresh SOURCE integrator association", err)
	}
	f.assignment = fixtureRaw(map[string]any{"formatVersion": 1, "assignmentId": "source_" + childKind + "_assignment", "assignmentDigest": model.WorkspaceDigest(body), "executionId": executionID, "purpose": purpose, "plan": stage.Declared.Plan, "target": intent["target"], "createdAt": j.reconciler.now().Format(time.RFC3339Nano)})
	if purpose == "integrate" {
		next.completion = newCurrentStageCompletionSource(t, next, d.root, intent)
	}
	if purpose == "review" {
		for _, prior := range j.manifest.CellEntriesV3 {
			if prior.OperationID == f.entry.OperationID || prior.LaunchOperationID == f.entry.LaunchOperationID || prior.ServiceRegistrationID == f.entry.ServiceRegistrationID || prior.PreparationID == f.entry.PreparationID || prior.NativeSessionID == f.entry.NativeSessionID || prior.Instance == f.entry.Instance {
				t.Fatal("new SOURCE reviewer reused a child identity")
			}
			previous, e := j.reconciler.Store.CellV3Operation(ctx, prior.PreparationID)
			if e != nil || previous == nil || previous.Receipt.PreparedReceiptDigest == receipt.PreparedReceiptDigest || previous.Receipt.CredentialID == receipt.CredentialID || previous.Receipt.NativeCredentialID == receipt.NativeCredentialID {
				t.Fatal("new SOURCE reviewer prepared receipt identity", e)
			}
		}
		d.writeOriginal(t, filepath.Join(d.root, "current-stage-review-child-tuple-audit.json"), fixtureRaw(map[string]any{"classification": "fresh SOURCE identities before normal manifest acceptance; no installed/native proof", "entry": f.entry, "preparedReceipt": receipt, "binding": binding, "assignment": body, "allocationId": selected.AllocationID, "originalTarget": intent["target"], "candidate": intent["candidate"]}), 0600)
	}
	putCurrentStageSourceEntry(&j.manifest, f.entry)
	if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatal("normal later prepare/report/assignment", err)
	}
	if f.nativePrepares != 1 || f.assigns != 1 {
		t.Fatal("later current preparation/assignment did not traverse normal path", f.nativePrepares, f.assigns)
	}
	f.entry = cellV3TestExecute(t, f.entry, receipt)
	f.entry.ExecutionGrant.ExpiresAt = j.reconciler.now().Add(time.Minute).Format(time.RFC3339Nano)
	if purpose == "review" {
		f.entry.ExecutionGrant.GrantID = "grant_source_current_reviewer_execution"
	}
	putCurrentStageSourceEntry(&j.manifest, f.entry)
	f.admission = model.ChildAdmissionAssociation{FormatVersion: 1, HandleID: handle.HandleID, PreparationAssociationDigest: f.actual.AssociationDigest, Assignment: f.assignment, AllocationID: selected.AllocationID, ReservationID: "source_" + childKind + "_reservation", PolicyDigest: model.WorkspaceDigest("SOURCE current integrator product3 supplier"), ActivationDigest: model.WorkspaceDigest("SOURCE current integrator activation2 supplier"), Grant: *f.entry.ExecutionGrant}
	f.admission.AssociationDigest = fixtureDigestField(f.admission, "associationDigest")
	fixtureComplete(t, f.r, handle.HandleID, "adopt", map[string]any{"handleDigest": handle.HandleDigest, "preparedAssociationDigest": f.actual.AssociationDigest, "assignment": f.assignment, "policyDigest": f.admission.PolicyDigest, "grant": f.entry.ExecutionGrant}, f.admission)
	if purpose == "review" {
		next.review = newCurrentStageReviewCompletionSource(t, next, d.root, intent)
	}
	if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatal("later SOURCE running", err)
	}
	f.nativeState = "terminal"
	if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
		t.Fatal("later SOURCE terminal awaiting report", err)
	}
	report, err := f.r.Report(ctx, f.r.ServerID, "0.1.54-e2.1")
	if err != nil {
		t.Fatal(err)
	}
	control, ok := j.reconciler.ManagedControl.(interface {
		Report(context.Context, model.Report) error
	})
	if !ok {
		t.Fatal("normal report client absent")
	}
	if err = control.Report(ctx, report); err != nil {
		t.Fatal("actual authenticated SOURCE report", err)
	}
	if f.reports != 1 || f.backendDigest == nil {
		t.Fatal("terminal report was not acknowledged")
	}
	return next
}

func putCurrentStageSourceEntry(current *model.Manifest, entry model.CellServiceV3) {
	for i, v := range current.CellEntriesV3 {
		if v.PreparationID == entry.PreparationID {
			current.CellEntriesV3[i] = entry
			return
		}
	}
	current.CellEntriesV3 = append(current.CellEntriesV3, entry)
}

func runCurrentStageTerminalSource(t *testing.T, j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, runtime *currentStageSourceRuntime, stage controllerStageOriginal, id string, selected model.ManagerIntentSelection, handle model.IntentHandle, intent map[string]any, resultClaim, resultRaw json.RawMessage) {
	t.Helper()
	next := prepareCurrentStageTerminalSource(t, j, native, d, runtime, stage, id, selected, handle, intent, resultClaim, resultRaw)
	f := next.terminal.fixture
	app := runtime.application
	ctx := context.Background()
	var err error
	err = j.reconciler.Reconcile(ctx, j.manifest)
	claim, readErr := j.reconciler.Store.OwnedContinuationClaim(ctx, id, "children")
	if readErr != nil || len(claim) == 0 {
		t.Fatal("later terminal stage not retained", err, readErr)
	}
	original, readErr := j.reconciler.Store.OwnedContinuationResult(ctx, app.OperationID, "source-reported-result", resultClaim)
	if readErr != nil || string(original) != string(resultRaw) {
		t.Fatal("original worker result changed", readErr)
	}
	c := next.completion
	assertComplete := func() {
		t.Helper()
		if err != nil || next.observations != 2 || c.operations != 1 || c.proofs != 1 || c.acknowledgements != 1 || c.retained != 1 || c.settlementOperations != 1 || c.settlementProofs != 1 || c.settlementReports != 1 || c.candidateOperations != 1 || c.candidateProofs != 1 || c.candidateReports != 1 {
			t.Fatalf("normal integration/first ACK/candidate incomplete or repeated: error=%v read=%d operation=%d proof=%d ack=%d retained=%d settlement=%d/%d/%d candidate=%d/%d/%d", err, next.observations, c.operations, c.proofs, c.acknowledgements, c.retained, c.settlementOperations, c.settlementProofs, c.settlementReports, c.candidateOperations, c.candidateProofs, c.candidateReports)
		}
		original, e := j.reconciler.Store.OwnedContinuationResult(ctx, app.OperationID, "source-reported-result", resultClaim)
		if e != nil || string(original) != string(resultRaw) || f.nativeExecutes != 2 || f.prepares != 1 || f.nativePrepares != 1 || f.reports != 1 {
			t.Fatal("integration changed first result or repeated native/lifecycle work", e)
		}
		claim, e := j.reconciler.Store.OwnedContinuationClaim(ctx, id, "integration-complete")
		if e != nil || len(claim) == 0 {
			t.Fatal("normal candidate was not retained", e)
		}
		completed, e := j.reconciler.Store.OwnedContinuationResult(ctx, id, "integration-complete", claim)
		var done completedControllerIntegration
		if e != nil || model.DecodePhysicalClosed(completed, &done) != nil || model.WorkspaceDigest(done.Integration) != model.WorkspaceDigest(c.original) || done.Candidate.Receipt.ProofDigest != model.WorkspaceDigest(done.Candidate.Proof) {
			t.Fatal("normal stage lost first originals", e)
		}
	}
	assertComplete()
	if e := j.reconciler.Store.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := state.Open(j.databasePath)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	j.reconciler.Store, native.store = reopened, reopened
	j.reconciler.ManagedCatalog.(*workspacecatalog.Catalog).State = reopened
	err = j.reconciler.Reconcile(ctx, j.manifest)
	assertComplete()
	d.writeOriginal(t, filepath.Join(d.root, "current-stage-terminal-observation.json"), fixtureRaw(map[string]any{"classification": "current case3/declaration4 normal terminal coordinator; native/target/custody/paid SOURCE suppliers; actual TLS/state/original signatures", "prepares": f.prepares, "nativeSourcePrepares": f.nativePrepares, "nativeSourceCalls": f.nativeExecutes, "reports": f.reports, "integrationObservations": next.observations, "observationTLS": c.operations + c.proofs + c.acknowledgements, "candidateTLS": c.candidateOperations + c.candidateReports, "settlementTLS": c.settlementOperations + c.settlementReports, "sameSQLiteReopened": true, "originalWorkerResultUnchanged": true, "nativeExecutable": 0, "externalProvider": 0}), 0600)
	t.Log("retained current later terminal SOURCE boundary", d.root)
	if os.Getenv("WARPMETAL_CURRENT_STAGE_REVIEW_SOURCE") == "1" {
		runCurrentStageReviewerTerminalSource(t, j, native, d, next, stage, id, intent, resultClaim, resultRaw)
	}
}
