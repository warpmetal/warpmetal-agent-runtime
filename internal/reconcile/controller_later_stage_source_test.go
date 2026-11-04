package reconcile

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// This extends the existing normal TLS/SQLite/STATE journey, including its
// retained coding result and restart oracles. Upstream legacy parent/native
// suppliers remain SOURCE. The fresh declaration is a schema-valid SOURCE
// append, not a backend-issued or protected installed authority claim.
func TestOwnerFirstTaskReportedResultSelectsLaterManagerThroughNormalReconcile(t *testing.T) {
	t.Setenv("WARPMETAL_LATER_CONTROLLER_STAGE_SOURCE", "1")
	TestOwnerFirstTaskCompletedChildReportsDocumentThroughNormalReconcile(t)
}

type laterControllerStageSource struct {
	t        *testing.T
	path     string
	response json.RawMessage
	reads    int
}

func (s *laterControllerStageSource) serve(w http.ResponseWriter, req *http.Request) bool {
	if req.URL.Path != s.path {
		return false
	}
	if req.Method != "GET" || req.URL.RawQuery != "" || req.ContentLength > 0 || req.Header.Get("Authorization") != "Bearer rtn_source" || req.Header.Get("X-WarpMetal-Workflow-Lease") != "" {
		s.t.Fatal("later stage discovery changed current-node read contract")
	}
	s.reads++
	_, _ = w.Write(s.response)
	return true
}

func runLaterControllerStageSource(t *testing.T, f *firstTaskChildTerminalFixture, j *managerPolicyJourney) {
	t.Helper()
	ctx := context.Background()
	if f.completion == nil || f.completion.result == nil || f.completion.results != 1 {
		t.Fatal("later stage fixture requires actual preceding normal SOURCE result POST")
	}
	resultClaim, err := f.r.Store.OwnedContinuationClaim(ctx, f.entry.PreparationID, "completion-result")
	if err != nil || len(resultClaim) == 0 {
		t.Fatal("reported result claim missing", err)
	}
	resultOriginal, err := f.r.Store.OwnedContinuationResult(ctx, f.entry.PreparationID, "completion-result", resultClaim)
	if err != nil || workflowcontract.Validate(workflowcontract.Domain, "resultReceipt", resultOriginal) != nil {
		t.Fatal("reported result receipt missing", err)
	}
	var result map[string]any
	_ = json.Unmarshal(resultOriginal, &result)
	if result["state"] != "reported" {
		t.Fatal("native completion relabelled as accepted result")
	}
	initialClaim, err := f.r.Store.OwnedContinuationClaim(ctx, "firsttask_source", "initial-decision-original")
	var initial controllerInitialDecisionOriginal
	if err != nil || json.Unmarshal(initialClaim, &initial) != nil {
		t.Fatal("initial declaration original missing", err)
	}
	app, err := f.r.Store.WorkspaceApplication(ctx, initial.Manager.ApplicationOperationID)
	if err != nil || app == nil || !app.Applied {
		t.Fatal("later stage current accepted application missing", err)
	}
	// Copy only the existing unsigned fixture's construction shape. Every later
	// intent identity/body/digest below is new before any declaration signature;
	// no retained accepted envelope or original body is retagged.
	var target map[string]any
	_ = json.Unmarshal(fixtureRaw(f.deliveryParents["manager"].context.Target), &target)
	intent := target["members"].(map[string]any)["first"].(map[string]any)
	intent["intentId"], intent["purpose"], intent["allocationId"] = "source_later_integrator_intent", "integrate", "source_later_integrator_allocation"
	intent["target"] = map[string]any{"resultId": result["resultId"], "resultRevision": result["resultRevision"], "resultDigest": result["resultDigest"]}
	intent["targetReceipt"], intent["candidate"], intent["reviewInput"], intent["tools"] = result, nil, nil, []any{}
	intent["assignmentRequestId"], intent["grantRequestId"] = "source_later_integrator_assignment", "source_later_integrator_grant"
	intent["notAfter"] = f.r.now().Add(3 * time.Minute).Format(time.RFC3339Nano)
	prepare := intent["prepareBody"].(map[string]any)
	prepare["requestId"], prepare["operationId"], prepare["instance"] = "source_later_integrator_prepare", "source_later_integrator_launch", "source_later_integrator"
	content := prepare["content"].(map[string]any)
	content["objective"] = "SOURCE later manager integration of the exact reported document; no native execution claim."
	packet := content["workflowPacket"].(map[string]any)
	packet["packetId"] = "source_later_integrator_packet"
	prepare["parentIdentity"].(map[string]any)["packetId"] = packet["packetId"]
	intent["packetContentDigest"] = model.WorkspaceDigest(packet)
	intent["prepareBodyDigest"] = model.WorkspaceDigest(prepare)
	intent["lifecycleRequestDigest"] = model.RawPhysicalDigest(fixtureRaw(prepare))[7:]
	intent["intentDigest"] = fixtureDigestField(intent, "intentDigest")
	if err := workflowcontract.Validate(workflowcontract.Manager, "approvedWorkIntent", fixtureRaw(intent)); err != nil {
		t.Fatal("fresh later SOURCE intent shape", err)
	}
	item := map[string]any{"serviceRegistrationId": initial.Manager.ServiceRegistrationID, "inputId": "source_later_manager_integrate_input", "inputText": "SOURCE manager_integrate: select the independently declared integration of result_source_document.", "policyDigest": model.WorkspaceDigest("fresh SOURCE later manager policy, not installed"), "workflowRequestId": "source_later_manager_integrate_request", "plan": initial.DeclaredInput.Plan, "target": map[string]any{"kind": "manager_intent", "role": "manager", "resourceId": nil, "purpose": "integrate", "intent": intent}, "allocationId": "source_later_manager_integrate_allocation", "preparationOrdinal": 5, "physicalIndex": 8}
	if err := workflowcontract.Validate(workflowcontract.ManagerSingle, "approvedInputItem3", fixtureRaw(item)); err != nil {
		t.Fatal("fresh later SOURCE item shape", err)
	}
	caseID, caseDigest, demandDigest := "source_later_case", model.WorkspaceDigest("SOURCE later case"), model.WorkspaceDigest("SOURCE full19 demand not installed by this regression")
	declaration := map[string]any{"formatVersion": 4, "caseId": caseID, "caseManifestDigest": caseDigest, "demandManifestDigest": demandDigest, "declaredAt": f.r.now().Format(time.RFC3339Nano), "notAfter": f.r.now().Add(3 * time.Minute).Format(time.RFC3339Nano), "inputs": []any{initial.DeclaredInput, item}}
	if err := workflowcontract.Validate(workflowcontract.ManagerSingle, "inputDeclarationPayload4", fixtureRaw(declaration)); err != nil {
		t.Fatal("fresh SOURCE declaration4 append shape", err)
	}
	operator, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope := sourceSigned(t, operator, "source_later_operator", declaration)
	var signed struct {
		Payload   json.RawMessage
		Signature string
	}
	_ = json.Unmarshal(envelope, &signed)
	sig, _ := base64.StdEncoding.DecodeString(signed.Signature)
	sum := sha256.Sum256(signed.Payload)
	if !ecdsa.VerifyASN1(&operator.PublicKey, sum[:], sig) {
		t.Fatal("fresh SOURCE declaration signature changed")
	}
	response := fixtureRaw(map[string]any{"formatVersion": 1, "applicationOperationId": app.Operation.OperationID, "applicationOperationDigest": app.Operation.OperationDigest, "serviceRegistrationId": initial.Manager.ServiceRegistrationID, "serviceGeneration": initial.Manager.ServiceGeneration, "caseId": caseID, "caseManifestDigest": caseDigest, "demandManifestDigest": demandDigest, "allocationName": "manager_integrate", "item": item, "declarationItemDigest": model.WorkspaceDigest(item)})
	s := &laterControllerStageSource{t: t, path: "/internal/runtime/workspace-workflow/application-operations/" + app.Operation.OperationID + "/controller-inputs/" + initial.Manager.ServiceRegistrationID + "/manager_integrate", response: response}
	f.completion.later = s
	root, err := os.MkdirTemp(os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE"), "later-controller-source-")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("declaration-envelope.json", envelope)
	write("operator-public.pem", sourcePublicPEM(operator))
	write("discovery-response.json", response)
	write("reported-result-original.json", resultOriginal)
	write("initial-decision-original.json", initialClaim)
	t.Log("retained later-stage SOURCE append", root, "reported result; no backend issuer/protected ROOT/native authority")
	err = f.r.Reconcile(ctx, j.manifest)
	after, readErr := f.r.Store.OwnedContinuationResult(ctx, f.entry.PreparationID, "completion-result", resultClaim)
	if readErr != nil || !bytes.Equal(after, resultOriginal) || f.completion.results != 1 || f.nativePrepares != 1 || f.nativeExecutes != 2 {
		t.Fatal("later stage replaced/repeated the initial result or native work", readErr)
	}
	write("observation.json", fixtureRaw(map[string]any{"evidenceClass": "source", "reportedResultPosts": f.completion.results, "laterStageReads": s.reads, "nativePrepares": f.nativePrepares, "nativeExecuteObservations": f.nativeExecutes, "sameSQLiteReopened": true, "initialResultUnchanged": bytes.Equal(after, resultOriginal), "reconcileError": func() any {
		if err != nil {
			return err.Error()
		}
		return nil
	}(), "externalProviderRequests": 0}))
	if s.reads != 1 {
		t.Fatalf("normal later-stage discovery absent after reported coding result and SAME SQLite reopen: manager_integrate reads=%d resultPosts=%d reconcile=%v", s.reads, f.completion.results, err)
	}
}
