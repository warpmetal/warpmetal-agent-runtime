package reconcile

// Cumulative same-current-app SOURCE stage continuation. Actual integration
// originals remain unchanged; later parent/native/reviewer custody suppliers are
// explicitly SOURCE, separate from the signed prepared/read producer journey.
import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

func TestControllerCurrentReviewerTerminalThroughNormalReconcile(t *testing.T) {
	for _, mode := range []string{"valid", "malformed", "lost_ack"} {
		if !t.Run(mode, func(t *testing.T) {
			t.Setenv("WARPMETAL_REVIEW_TERMINAL_MODE", mode)
			t.Setenv("WARPMETAL_CURRENT_STAGE_REVIEW_SOURCE", "1")
			TestControllerCurrentLaterIntegratorTerminalThroughNormalReconcile(t)
		}) {
			t.FailNow()
		}
	}
}

func TestControllerCurrentLaterChildRefreshesExpiredDependencyFacts(t *testing.T) {
	for _, mode := range []string{"valid", "lost_refresh_ack"} {
		if !t.Run(mode, func(t *testing.T) {
			t.Setenv("WARPMETAL_CURRENT_STAGE_REVIEW_SOURCE", "1")
			t.Setenv("WARPMETAL_CURRENT_STAGE_FACT_EXPIRY_SOURCE", "1")
			t.Setenv("WARPMETAL_REVIEW_TERMINAL_MODE", "valid")
			t.Setenv("WARPMETAL_REFRESH_MODE", mode)
			TestControllerCurrentLaterIntegratorTerminalThroughNormalReconcile(t)
		}) {
			t.FailNow()
		}
	}
}

func runCurrentStageReviewerTerminalSource(t *testing.T, j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, integrator *currentStageTerminalSourceRuntime, oldStage controllerStageOriginal, oldID string, oldIntent map[string]any, resultClaim, resultRaw json.RawMessage) {
	t.Helper()
	ctx := context.Background()
	runtime := integrator.currentStageSourceRuntime
	app := runtime.application
	parent := runtime.policy.ApplicationIdentity().Intent
	now := j.reconciler.now()
	claim, e := j.reconciler.Store.OwnedContinuationClaim(ctx, oldID, "integration-complete")
	if e != nil || len(claim) == 0 {
		t.Fatal("current integration candidate absent", e)
	}
	completed, e := j.reconciler.Store.OwnedContinuationResult(ctx, oldID, "integration-complete", claim)
	var first completedControllerIntegration
	if e != nil || model.DecodePhysicalClosed(completed, &first) != nil {
		t.Fatal("first acknowledged integration/candidate", e)
	}
	if os.Getenv("WARPMETAL_CURRENT_STAGE_FACT_EXPIRY_SOURCE") == "1" {
		expires, e := time.Parse(time.RFC3339Nano, first.Candidate.Proof.Payload.NotAfter)
		if e != nil {
			t.Fatal(e)
		}
		advanced := expires.Add(time.Second)
		appEnd, e := time.Parse(time.RFC3339Nano, app.ExpiresAt)
		if e != nil || !advanced.Before(appEnd) {
			t.Fatal("expiry source application no longer current")
		}
		// This happens BEFORE the fresh review declaration/policy/intent is built.
		// All completed integrate originals stay byte-identical.
		j.reconciler.Now = func() time.Time { return advanced }
		now = advanced
		d.writeOriginal(t, filepath.Join(d.root, "current-stage-expired-candidate-original.json"), completed, 0600)
	}
	var original struct{ Observation map[string]json.RawMessage }
	publicDeliveryDecode(t, first.Integration.Proof.Payload.Request, &original)
	target := original.Observation["target"]
	oldTarget := fixtureRaw(oldIntent["target"])
	if model.WorkspaceDigest(target) != model.WorkspaceDigest(oldTarget) {
		t.Fatal("review target changed from original implement result")
	}
	candidate := map[string]any{"integration": model.WorkflowReceiptRef{ReceiptID: first.Integration.Receipt.ReceiptID, ReceiptDigest: first.Integration.Receipt.ReceiptDigest}, "afterDigest": publicDeliveryMap(original.Observation)["afterDigest"], "manifestDigest": model.WorkspaceDigest(original.Observation["artifacts"])}
	// Read exact already-retained SOURCE before/after files. They are not read
	// receipts; actual reviewer custody remains the independent prepared gate.
	before, e := os.ReadFile(filepath.Join(d.root, "source-integration-before.body"))
	after, e2 := os.ReadFile(filepath.Join(d.root, "source-integration-after.body"))
	if e != nil || e2 != nil || model.RawPhysicalDigest(after) != candidate["afterDigest"] {
		t.Fatal("retained target/candidate byte mismatch", e, e2)
	}
	var template struct {
		Context model.ControllerApprovedInputContext
	}
	raw, e := os.ReadFile(os.Getenv("WARPMETAL_CURRENT_STAGE_TEMPLATE"))
	if e != nil || json.Unmarshal(raw, &template) != nil {
		t.Fatal(e)
	}
	templateIntent := sourceObject(publicDeliveryMap(template.Context.Target)["intent"])
	contextText := sourceObject(sourceObject(templateIntent["prepareBody"])["content"])["context"].(string)
	start := "Complete actual approved plan bytes:\n"
	end := "\nComplete original target artifact"
	cut := strings.Index(contextText, end)
	if !strings.HasPrefix(contextText, start) || cut < 0 {
		t.Fatal("owning retained template plan bytes unavailable")
	}
	planBytes := []byte(contextText[len(start):cut])
	plan := sourceObject(oldIntent["plan"])
	ref := sourceObject(plan["planRef"])
	if model.RawPhysicalDigest(planBytes) != ref["sourceDigest"] {
		t.Fatal("original approved plan byte digest")
	}
	var published struct {
		Demand qualification.ChildEnvelope[qualification.DemandManifest]
	}
	raw, e = os.ReadFile(filepath.Join(d.root, "controller-provider-preexecution-source.json"))
	if e != nil || json.Unmarshal(raw, &published) != nil {
		t.Fatal(e)
	}
	var parentAllocation, childAllocation qualification.DemandAllocation
	parentFound, childFound := false, false
	if published.Demand.Payload.FormatVersion != 3 {
		t.Fatal("current SOURCE reviewer requires demand3")
	}
	for _, allocation := range published.Demand.Payload.AllocationList {
		switch allocation.Name {
		case "manager_review":
			if parentFound {
				t.Fatal("duplicate manager_review allocation")
			}
			parentAllocation, parentFound = allocation, true
		case "reviewer":
			if childFound {
				t.Fatal("duplicate reviewer allocation")
			}
			childAllocation, childFound = allocation, true
		}
	}
	if !parentFound || !childFound || parentAllocation.SourceID != parent.ServiceRegistrationID || childAllocation.SourceID == "" || parentAllocation.FirstPhysicalIndex != 11 || parentAllocation.PreparationOrdinal != 7 || childAllocation.FirstPhysicalIndex != 12 || childAllocation.PreparationOrdinal != 8 {
		t.Fatal("current full19 review allocation")
	}
	intent := publicDeliveryMap(oldIntent)
	intent["purpose"], intent["intentId"], intent["intentRevision"], intent["allocationId"] = "review", childAllocation.SourceID, 1, childAllocation.AllocationID
	intent["laneId"], intent["assignmentRequestId"], intent["grantRequestId"] = "lane_source_current_reviewer", "assign_source_current_reviewer", "grant_source_current_reviewer"
	intent["candidate"], intent["tools"], intent["notAfter"] = candidate, []any{}, now.Add(100*time.Second).Format(time.RFC3339Nano)
	intent["target"], intent["targetReceipt"] = json.RawMessage(target), json.RawMessage(resultRaw)
	prepare := sourceObject(intent["prepareBody"])
	prepare["role"], prepare["instance"], prepare["operationId"], prepare["requestId"], prepare["title"] = "reviewer", "source-current-reviewer", "operation_source_current_reviewer", "prepare_source_current_reviewer", "Explicit SOURCE independent review"
	content := sourceObject(prepare["content"])
	content["objective"] = "Independently assess the exact original document and integrated candidate."
	content["constraints"] = "Return exactly JSON with disposition and findings; approve requires empty findings. No Markdown or tools."
	content["context"] = "Approved full plan:\n" + string(planBytes) + "\nOriginal target document:\n" + string(before) + "\nCurrent candidate:\n" + string(after)
	packet := sourceObject(content["workflowPacket"])
	packet["packetId"], packet["laneId"], packet["budgetRef"] = "packet_source_current_reviewer", intent["laneId"], ref["path"].(string)+"#source-reviewer"
	packet["writeScope"] = map[string]any{"mode": "exclusive", "paths": []string{"output/review"}}
	sourceObject(prepare["parentIdentity"])["packetId"] = packet["packetId"]
	input := fixtureRaw(map[string]any{"formatVersion": 1, "kind": "workspace_workflow_packet", "content": content})
	launch := sha256.Sum256([]byte(prepare["operationId"].(string)))
	inputID := "msg_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(launch[:])
	intent["reviewInput"] = model.ReviewInputCompilation{InputID: inputID, InputDigest: model.RawPhysicalDigest(input), InputByteCount: len(input), Candidate: fixtureRaw(candidate), ManifestDigest: candidate["manifestDigest"].(string)}
	intent["packetContentDigest"], intent["prepareBodyDigest"] = model.WorkspaceDigest(packet), model.WorkspaceDigest(prepare)
	intent["lifecycleRequestDigest"] = model.RawPhysicalDigest(fixtureRaw(prepare))[7:]
	intent["intentDigest"] = fixtureDigestField(intent, "intentDigest")
	if e = workflowcontract.Validate(workflowcontract.Manager, "approvedWorkIntent", fixtureRaw(intent)); e != nil {
		t.Fatal("current SOURCE reviewer intent", e)
	}
	policy := publicDeliveryMap(runtime.policy)
	policy["allocationId"] = parentAllocation.AllocationID
	policy["expiresAt"] = now.Add(105 * time.Second).Format(time.RFC3339Nano)
	var typed qualification.ControllerPolicy
	publicDeliveryDecode(t, policy, &typed)
	text := "SOURCE manager_review: select only the separately declared reviewer for the original result and first acknowledged integration candidate."
	stageTarget := map[string]any{"kind": "manager_intent", "role": "manager", "resourceId": nil, "purpose": "review", "intent": intent}
	item := map[string]any{"serviceRegistrationId": parent.ServiceRegistrationID, "inputId": "msg_source_current_review", "inputText": text, "policyDigest": model.WorkspaceDigest(policy), "workflowRequestId": "request_source_current_review", "plan": plan, "target": stageTarget, "allocationId": parentAllocation.AllocationID, "preparationOrdinal": parentAllocation.PreparationOrdinal, "physicalIndex": parentAllocation.FirstPhysicalIndex}
	var oldEnvelope struct{ Payload json.RawMessage }
	publicDeliveryDecode(t, runtime.declaration, &oldEnvelope)
	declaration := publicDeliveryMap(oldEnvelope.Payload)
	oldInputs := declaration["inputs"].([]any)
	if len(oldInputs) != 1 || model.WorkspaceDigest(oldInputs[0]) != oldStage.Readout.DeclarationItemDigest {
		t.Fatal("prior declaration input changed")
	}
	declaration["inputs"] = append(oldInputs, item)
	if e = workflowcontract.Validate(workflowcontract.ManagerSingle, "inputDeclarationPayload4", fixtureRaw(declaration)); e != nil {
		t.Fatal("current cumulative declaration4", e)
	}
	envelope := sourceSigned(t, d.operator, "source_independent_operator", declaration)
	response := fixtureRaw(map[string]any{"formatVersion": 1, "applicationOperationId": app.OperationID, "applicationOperationDigest": app.OperationDigest, "serviceRegistrationId": parent.ServiceRegistrationID, "serviceGeneration": parent.ServiceGeneration, "caseId": typed.Case.CaseID, "caseManifestDigest": typed.Case.CaseManifestDigest, "demandManifestDigest": typed.Case.DemandManifestDigest, "allocationName": "manager_review", "item": item, "declarationItemDigest": model.WorkspaceDigest(item)})
	var readout model.ControllerStageReadout
	publicDeliveryDecode(t, response, &readout)
	oldPreparedRaw, e := j.reconciler.Store.OwnedContinuationResult(ctx, oldID, "parent-prepare", fixtureRaw(oldStage))
	var oldPrepared model.ControllerPreparedReceipt
	if e != nil || json.Unmarshal(oldPreparedRaw, &oldPrepared) != nil {
		t.Fatal("same parent preparation original", e)
	}
	prepared := sourceControllerPreparedShape(typed.NativeIdentity().Intent, app, oldPrepared.PreparedTuple.NativeRegistration, "msg_source_current_review", text)
	prepared.PreparationID = "source_accepted_manager_review"
	binding := map[string]any{"preparationId": prepared.PreparationID, "preparedTuple": prepared.PreparedTuple, "credentialId": prepared.CredentialID, "nativeCredentialId": prepared.NativeCredentialID}
	prepared.BindingDigest = model.WorkspaceDigest(binding)
	binding["bindingDigest"] = prepared.BindingDigest
	prepared.PreparedReceiptDigest = model.WorkspaceDigest(binding)
	contextBody := publicDeliveryMap(template.Context)
	for k, v := range map[string]any{"contextId": "context_source_current_review", "preparationId": prepared.PreparationID, "caseId": typed.Case.CaseID, "caseManifestDigest": typed.Case.CaseManifestDigest, "demandManifestDigest": typed.Case.DemandManifestDigest, "policyDigest": model.WorkspaceDigest(policy), "inputId": item["inputId"], "inputDigest": model.ControllerTextDigest(text), "workflowRequestId": item["workflowRequestId"], "plan": plan, "target": stageTarget, "declarationItemDigest": model.WorkspaceDigest(item), "allocationId": item["allocationId"], "preparationOrdinal": item["preparationOrdinal"], "physicalIndex": item["physicalIndex"], "identityAssociationDigest": typed.IdentityAssociation.AssociationDigest, "providerPolicyDigest": typed.ProviderPolicyDigest} {
		contextBody[k] = v
	}
	contextBody["contextDigest"] = fixtureDigestField(contextBody, "contextDigest")
	if e = workflowcontract.Validate(workflowcontract.ManagerSingle, "approvedContext4", fixtureRaw(contextBody)); e != nil {
		t.Fatal("new current review context4", e)
	}
	runtime.declaration = envelope
	runtime.readouts = map[string]model.ControllerStageReadout{"manager_integrate": oldStage.Readout, "manager_review": readout}
	runtime.policy = typed
	discovery := &laterControllerStageSource{t: t, path: "/internal/runtime/workspace-workflow/application-operations/" + app.OperationID + "/controller-inputs/" + parent.ServiceRegistrationID + "/manager_review", response: response}
	discoveryFallback := native.sourceHTTP
	native.sourceHTTP = func(w http.ResponseWriter, req *http.Request) bool {
		if discovery.serve(w, req) {
			return true
		}
		return discoveryFallback(w, req)
	}
	d.writeOriginal(t, filepath.Join(d.root, "current-stage-review-declaration.json"), envelope, 0600)
	d.writeOriginal(t, filepath.Join(d.root, "current-stage-review-policy.json"), sourceSigned(t, d.operator, "source_independent_operator", policy), 0600)
	d.writeOriginal(t, filepath.Join(d.root, "current-stage-review-response.json"), response, 0600)
	d.writeOriginal(t, filepath.Join(d.root, "current-stage-review-input.json"), input, 0600)
	accepted := seedCurrentStageAcceptedChildSource(t, j, native, d, runtime, readout, prepared, contextBody, policy, intent, discovery, resultClaim, resultRaw)
	next := prepareCurrentStageTerminalSource(t, j, native, d, runtime, accepted.Stage, accepted.ID, accepted.Selected, accepted.Handle, intent, resultClaim, resultRaw)
	if next == nil {
		return
	}
	f := next.terminal.fixture
	// Track the ordinary subsequent stage lookup, never submit a direct decision.
	c := next.review
	accepts := 0
	completionFallback := native.sourceHTTP
	native.sourceHTTP = func(w http.ResponseWriter, req *http.Request) bool {
		if strings.HasSuffix(req.URL.Path, "/manager_accept") {
			accepts++
		}
		return completionFallback(w, req)
	}
	err := j.reconciler.Reconcile(ctx, j.manifest)
	afterResult, e := j.reconciler.Store.OwnedContinuationResult(ctx, app.OperationID, "source-reported-result", resultClaim)
	afterCandidate, e2 := j.reconciler.Store.OwnedContinuationResult(ctx, oldID, "integration-complete", claim)
	if e != nil || e2 != nil || string(afterResult) != string(resultRaw) || string(afterCandidate) != string(completed) {
		t.Fatal("review changed original result/integration", e, e2)
	}
	childClaim, e := j.reconciler.Store.OwnedContinuationClaim(ctx, accepted.ID, "children")
	if e != nil || len(childClaim) == 0 {
		t.Fatal("reviewer terminal child history absent", err, e)
	}
	childRaw, e := j.reconciler.Store.OwnedContinuationResult(ctx, accepted.ID, "children", childClaim)
	var child controllerStageChildResult
	if e != nil || model.DecodePhysicalClosed(childRaw, &child) != nil || child.Progress.State != "completed" || len(child.Progress.Children) != 1 || f.reports != 1 || f.nativeExecutes != 2 || f.backendDigest == nil {
		t.Fatal("reviewer own normal terminal boundary absent", err, e)
	}
	observed := map[string]any{"classification": "same current app/case/cumulative declaration and normal Reconcile/TLS/SQLite; upstream manager acceptance/installed/native/own-read suppliers SOURCE, not protected custody", "declarationItems": 2, "reviewStageReads": discovery.reads, "reviewChildPrepares": f.prepares, "reviewNativeSourcePrepares": f.nativePrepares, "reviewNativeSourceCalls": f.nativeExecutes, "reviewTerminalReports": f.reports, "reviewerExecutionId": f.actualExecution(), "integratorExecutionId": integrator.terminal.fixture.actualExecution(), "originalResultUnchanged": true, "firstIntegrationCandidateUnchanged": true, "assessmentUploads": c.artifact.uploads, "reviewPOSTs": c.reviews, "managerAcceptDiscovery": accepts, "error": func() any {
		if err != nil {
			return err.Error()
		}
		return nil
	}(), "providers": 0, "nativeExecutable": 0, "rootRuns": 0}
	d.writeOriginal(t, filepath.Join(d.root, "current-stage-review-terminal-observation.json"), fixtureRaw(observed), 0600)
	mode := os.Getenv("WARPMETAL_REVIEW_TERMINAL_MODE")
	assertCompletion := func() {
		t.Helper()
		if mode == "malformed" {
			if err == nil || !strings.Contains(err.Error(), "reviewer assessment") || c.artifact.uploads != 0 || c.reviews != 0 || next.completion.settlementOperations != 0 || accepts != 0 {
				t.Fatal("malformed assessment caused effects", err, c.artifact.uploads, c.reviews, accepts)
			}
		} else {
			c.artifact.assertUploaded(t)
			if c.reviews != 1 || next.completion.settlementOperations != 1 || next.completion.settlementProofs != 1 || next.completion.settlementReports != 1 {
				t.Fatal("review/settlement missing or repeated", err, c.reviews)
			}
			if mode == "valid" {
				if err != nil || accepts == 0 {
					t.Fatal("valid reviewer completion did not progress to ordinary manager_accept discovery", err, accepts)
				}
				basis, e := j.reconciler.Store.OwnedContinuationClaim(ctx, accepted.ID, "review-complete")
				if e != nil || len(basis) == 0 {
					t.Fatal("review original not retained", e)
				}
				original, e := j.reconciler.Store.OwnedContinuationResult(ctx, accepted.ID, "review-complete", basis)
				var completedReview completedControllerReview
				if e != nil || model.DecodePhysicalClosed(original, &completedReview) != nil || model.WorkspaceDigest(completedReview.Receipt) != model.WorkspaceDigest(c.receipt) || model.WorkspaceDigest(completedReview.Request) != model.WorkspaceDigest(c.request) {
					t.Fatal("review first original changed", e)
				}
			} else if err == nil || accepts != 0 {
				t.Fatal("lost review ACK became success", err, accepts)
			}
		}
		first, e := j.reconciler.Store.OwnedContinuationResult(ctx, app.OperationID, "source-reported-result", resultClaim)
		candidate, e2 := j.reconciler.Store.OwnedContinuationResult(ctx, oldID, "integration-complete", claim)
		if e != nil || e2 != nil || string(first) != string(resultRaw) || string(candidate) != string(completed) || f.reports != 1 || f.nativeExecutes != 2 {
			t.Fatal("review replay changed original result/candidate/native work", e, e2)
		}
	}
	assertCompletion()
	if mode == "lost_ack" {
		f.effectStatus = "settled"
	}
	if e = j.reconciler.Store.Close(); e != nil {
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
	if mode == "lost_ack" && !errors.Is(err, state.ErrOwnedContinuationUnknown) {
		t.Fatal("changed snapshot/reopen bypassed first UNKNOWN", err)
	}
	assertCompletion()
	observed["sameSQLiteReopened"] = true
	observed["mode"] = mode
	observed["managerAcceptDiscovery"] = accepts
	d.writeOriginal(t, filepath.Join(d.root, "current-stage-review-completion-observation.json"), fixtureRaw(observed), 0600)
	t.Log("retained current reviewer completion SOURCE boundary", mode, d.root)
	if mode == "valid" && os.Getenv("WARPMETAL_CURRENT_ACCEPT_SOURCE") == "1" {
		runCurrentManagerAcceptSource(t, j, native, d, next, accepted.Stage, accepted.ID, c, candidate, resultClaim, resultRaw)
	}
}
