package reconcile

// Extends the existing accepted-app TLS/SQLite constructor. Upstream result and
// current installed authority are declared SOURCE suppliers; no legacy case is
// retagged, no initial first-task traversal or protected baseline is claimed.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type currentStageSourceRuntime struct {
	*firstTaskEnrollmentSourceRuntime
	policy      qualification.ControllerPolicy
	application model.WorkspaceApplicationOperation
	declaration json.RawMessage
	operator    *ecdsa.PublicKey
	readout     model.ControllerStageReadout
	readouts    map[string]model.ControllerStageReadout
	policyReads int
	author      *currentAuthorSource
}

// Filesystem/kernel ownership is explicitly a SOURCE supplier in this journey.
// The actual closed declaration verifier is exercised against these same signed
// public originals by the existing signed Store boundary, without a ROOT bypass.
func (s *currentStageSourceRuntime) ReadControllerDeclaredStage(_ context.Context, _ model.Manifest, parent model.ControllerParentIntent, got model.ControllerStageReadout) (qualification.ControllerDeclaredInput, error) {
	var envelope struct {
		Payload   json.RawMessage
		Signature string
	}
	var declaration struct {
		Inputs []qualification.ControllerDeclaredInput
	}
	var empty qualification.ControllerDeclaredInput
	if json.Unmarshal(s.declaration, &envelope) != nil || json.Unmarshal(envelope.Payload, &declaration) != nil || len(declaration.Inputs) < 1 || len(declaration.Inputs) > 8 || parent != s.policy.ApplicationIdentity().Intent {
		return empty, qualification.ErrUntrusted
	}
	sig, e := base64.StdEncoding.DecodeString(envelope.Signature)
	hash := sha256.Sum256(envelope.Payload)
	expected := s.readout
	if s.readouts != nil {
		var ok bool
		expected, ok = s.readouts[got.AllocationName]
		if !ok {
			return empty, qualification.ErrUntrusted
		}
	}
	if e != nil || !ecdsa.VerifyASN1(s.operator, hash[:], sig) || model.WorkspaceDigest(expected) != model.WorkspaceDigest(got) {
		return empty, qualification.ErrUntrusted
	}
	var match *qualification.ControllerDeclaredInput
	for _, v := range declaration.Inputs {
		if model.WorkspaceDigest(v) == got.DeclarationItemDigest {
			if match != nil {
				return empty, qualification.ErrUntrusted
			}
			copy := v
			match = &copy
		}
	}
	if match == nil {
		return empty, qualification.ErrUntrusted
	}
	return *match, nil
}

func (s *currentStageSourceRuntime) VerifyControllerPolicy(context.Context, model.Sandbox, string, qualification.ControllerPolicyWitness) (qualification.ControllerPolicy, error) {
	s.policyReads++
	return qualification.ControllerPolicy{}, ErrControllerActivityPending // No protected policy or native effect supplied.
}

func (s *currentStageSourceRuntime) ReadControllerFirstTaskApplicability(_ context.Context, _ model.Manifest, w qualification.ControllerPolicyWitness) (qualification.Applicability, error) {
	if w.Application.OperationDigest != s.application.OperationDigest || w.ApplicationConfigurationDigest != s.application.ConfigurationDigest || w.WorkspaceMaterializerDigest != s.application.MaterializerDigest || w.Identity.Intent.Owner != s.policy.ApplicationIdentity().Intent.Owner {
		return qualification.Applicability{}, qualification.ErrUntrusted
	}
	return s.policy.Applicability, nil // Independently checked SOURCE inventory, not a baseline.
}

func TestControllerCurrentLaterStageDiscoveryThroughNormalReconcile(t *testing.T) {
	if os.Getenv("WARPMETAL_CURRENT_STAGE_TEMPLATE") == "" {
		t.Skip("owning manager_integrate unsigned shape supplier required")
	}
	// Existing constructorAt is selected BEFORE application/profile/lease bytes.
	t.Setenv("WARPMETAL_CHILD_COMPLETION_SOURCE", "1")
	runControllerProviderPreExecutionSourceFixtureExport(t, func(j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, output map[string]any) {
		output = publicDeliveryMap(output)
		ctx := context.Background()
		now := j.reconciler.now()
		var app model.WorkspaceApplicationOperation
		publicDeliveryDecode(t, output["application"], &app)
		appExpiry, err := time.Parse(time.RFC3339Nano, app.ExpiresAt)
		if err != nil || !now.Before(appExpiry) {
			t.Fatal("current constructor did not create the application before signing")
		}
		parent := native.parents[0]
		if parent.Role != "manager" {
			t.Fatal("source manager missing")
		}
		var template struct {
			Context model.ControllerApprovedInputContext
		}
		raw, err := os.ReadFile(os.Getenv("WARPMETAL_CURRENT_STAGE_TEMPLATE"))
		if err != nil || json.Unmarshal(raw, &template) != nil || template.Context.FormatVersion != 4 {
			t.Fatal("actual current target construction shape", err)
		}
		target := publicDeliveryMap(template.Context.Target)
		intent := sourceObject(target["intent"])
		// Only unsigned shapes are reused. Every owner/identity/target is new
		// and SOURCE before any digest or signature; no accepted result is borrowed.
		plan := sourceObject(intent["plan"])
		plan["workId"], plan["workRevision"] = "work_source_current_stage", 1
		author, resultRaw := sourceCurrentAuthor(t, j, native, d, output, plan)
		var result map[string]any
		publicDeliveryDecode(t, resultRaw, &result)
		if workflowcontract.Validate(workflowcontract.Domain, "resultReceipt", fixtureRaw(result)) != nil {
			t.Fatal("fresh SOURCE reported result shape")
		}
		claim := fixtureRaw(map[string]any{"classification": "SOURCE upstream result supplier, not normal Runtime result proof", "applicationOperationDigest": app.OperationDigest})
		if err = j.reconciler.Store.ClaimOwnedContinuation(ctx, app.OperationID, "source-reported-result", claim); err != nil {
			t.Fatal(err)
		}
		if err = j.reconciler.Store.CompleteOwnedContinuation(ctx, app.OperationID, "source-reported-result", claim, resultRaw); err != nil {
			t.Fatal(err)
		}
		demand := sourceObject(sourceObject(output["demand"])["payload"])
		var allocation, childAllocation map[string]any
		for _, value := range demand["allocations"].([]any) {
			a := sourceObject(value)
			if a["name"] == "manager_integrate" {
				allocation = a
			}
			if a["name"] == "integrator" {
				childAllocation = a
			}
		}
		if allocation == nil || childAllocation == nil || allocation["sourceId"] != parent.ServiceRegistrationID {
			t.Fatal("current full demand stage owner absent")
		}
		intent["intentId"], intent["intentRevision"], intent["allocationId"] = childAllocation["sourceId"], 1, childAllocation["allocationId"]
		intent["laneId"], intent["assignmentRequestId"], intent["grantRequestId"] = "lane_source_current_integrator", "assign_source_current_integrator", "grant_source_current_integrator"
		intent["target"], intent["targetReceipt"] = map[string]any{"resultId": result["resultId"], "resultRevision": result["resultRevision"], "resultDigest": result["resultDigest"]}, result
		intent["notAfter"] = now.Add(110 * time.Second).Format(time.RFC3339Nano)
		intent["scope"] = map[string]any{"owner": parent.Owner, "configurationDigest": app.ConfigurationDigest, "approvedProfile": app.Dependencies.Roles[0].Projection.ApprovedProfile, "workspace": map[string]any{"designation": parent.Workspace.Designation, "selectionId": parent.Workspace.SelectionID, "projectId": parent.Workspace.ProjectID, "workspaceEpoch": parent.Workspace.WorkspaceEpoch, "rootAttestation": parent.Workspace.RootAttestation, "scopeRevision": parent.Workspace.ScopeRevision}}
		prepare := sourceObject(intent["prepareBody"])
		prepare["controllerId"], prepare["sandboxGeneration"], prepare["profile"] = parent.Owner.ControllerID, parent.Owner.SandboxGeneration, parent.Profile
		prepare["credentialBinding"], prepare["authority"] = app.Dependencies.Roles[0].Projection.ModelSelection.CredentialBinding, app.Dependencies.Roles[0].Projection.ModelSelection.Authority
		prepare["instance"], prepare["operationId"], prepare["requestId"] = "source-current-integrator", "operation_source_current_integrator", "prepare_source_current_integrator"
		prepare["workspaceSelection"] = map[string]any{"selectionId": parent.Workspace.SelectionID, "projectId": parent.Workspace.ProjectID, "workspaceEpoch": parent.Workspace.WorkspaceEpoch}
		content := sourceObject(prepare["content"])
		content["context"] = "Explicit SOURCE upstream document; this discovery gate grants no source-read or native credit."
		packet := sourceObject(content["workflowPacket"])
		packet["laneId"], packet["packetId"], packet["budgetRef"] = intent["laneId"], "packet_source_current_integrator", "docs/source-controller-plan.md#source-integrator"
		sourceObject(prepare["parentIdentity"])["packetId"] = packet["packetId"]
		intent["packetContentDigest"], intent["prepareBodyDigest"] = model.WorkspaceDigest(packet), model.WorkspaceDigest(prepare)
		intent["lifecycleRequestDigest"] = model.RawPhysicalDigest(fixtureRaw(prepare))[7:]
		intent["intentDigest"] = fixtureDigestField(intent, "intentDigest")
		if err = workflowcontract.Validate(workflowcontract.Manager, "approvedWorkIntent", fixtureRaw(intent)); err != nil {
			t.Fatal("new current SOURCE integrator intent", err)
		}
		basePolicy := sourceObject(sourceObject(sourceObject(output["parents"])["manager"])["policy"])["payload"]
		policy := publicDeliveryMap(basePolicy)
		policy["allocationId"], policy["expiresAt"] = allocation["allocationId"], now.Add(115*time.Second).Format(time.RFC3339Nano)
		var typed qualification.ControllerPolicy
		publicDeliveryDecode(t, policy, &typed)
		text := "SOURCE manager_integrate: select only the newly declared integration of the current reported SOURCE document."
		item := map[string]any{"serviceRegistrationId": parent.ServiceRegistrationID, "inputId": "msg_source_current_integrate", "inputText": text, "policyDigest": model.WorkspaceDigest(policy), "workflowRequestId": "request_source_current_integrate", "plan": plan, "target": target, "allocationId": allocation["allocationId"], "preparationOrdinal": allocation["preparationOrdinal"], "physicalIndex": allocation["firstPhysicalIndex"]}
		declaration := map[string]any{"formatVersion": 4, "caseId": typed.Case.CaseID, "caseManifestDigest": typed.Case.CaseManifestDigest, "demandManifestDigest": typed.Case.DemandManifestDigest, "declaredAt": now.Format(time.RFC3339Nano), "notAfter": now.Add(110 * time.Second).Format(time.RFC3339Nano), "inputs": []any{item}}
		if err = workflowcontract.Validate(workflowcontract.ManagerSingle, "inputDeclarationPayload4", fixtureRaw(declaration)); err != nil {
			t.Fatal("new current declaration4", err)
		}
		envelope := sourceSigned(t, d.operator, "source_independent_operator", declaration)
		var signed struct {
			Payload   json.RawMessage
			Signature string
		}
		_ = json.Unmarshal(envelope, &signed)
		sig, _ := base64.StdEncoding.DecodeString(signed.Signature)
		digest := sha256.Sum256(signed.Payload)
		if !ecdsa.VerifyASN1(&d.operator.PublicKey, digest[:], sig) || model.WorkspaceDigest(demand) != typed.Case.DemandManifestDigest {
			t.Fatal("current signed declaration/demand provenance")
		}
		response := fixtureRaw(map[string]any{"formatVersion": 1, "applicationOperationId": app.OperationID, "applicationOperationDigest": app.OperationDigest, "serviceRegistrationId": parent.ServiceRegistrationID, "serviceGeneration": parent.ServiceGeneration, "caseId": typed.Case.CaseID, "caseManifestDigest": typed.Case.CaseManifestDigest, "demandManifestDigest": typed.Case.DemandManifestDigest, "allocationName": "manager_integrate", "item": item, "declarationItemDigest": model.WorkspaceDigest(item)})
		var readout model.ControllerStageReadout
		publicDeliveryDecode(t, response, &readout)
		n := typed.NativeIdentity()
		var originalPrepared model.ControllerPreparedReceipt
		publicDeliveryDecode(t, sourceObject(sourceObject(output["parents"])["manager"])["prepared"], &originalPrepared)
		prepared := sourceControllerPreparedShape(n.Intent, app, originalPrepared.PreparedTuple.NativeRegistration, "msg_source_current_integrate", text)
		prepared.PreparationID = "source_accepted_manager_integrate"
		binding := map[string]any{"preparationId": prepared.PreparationID, "preparedTuple": prepared.PreparedTuple, "credentialId": prepared.CredentialID, "nativeCredentialId": prepared.NativeCredentialID}
		prepared.BindingDigest = model.WorkspaceDigest(binding)
		binding["bindingDigest"] = prepared.BindingDigest
		prepared.PreparedReceiptDigest = model.WorkspaceDigest(binding)
		contextBody := publicDeliveryMap(template.Context)
		for k, v := range map[string]any{"contextId": "context_source_current_integrate", "preparationId": prepared.PreparationID, "caseId": typed.Case.CaseID, "caseManifestDigest": typed.Case.CaseManifestDigest, "demandManifestDigest": typed.Case.DemandManifestDigest, "policyDigest": readout.Item, "inputId": item["inputId"], "inputDigest": model.ControllerTextDigest(text), "workflowRequestId": item["workflowRequestId"], "plan": plan, "target": target, "declarationItemDigest": model.WorkspaceDigest(item), "allocationId": item["allocationId"], "preparationOrdinal": item["preparationOrdinal"], "physicalIndex": item["physicalIndex"], "identityAssociationDigest": typed.IdentityAssociation.AssociationDigest, "providerPolicyDigest": typed.ProviderPolicyDigest} {
			contextBody[k] = v
		}
		contextBody["policyDigest"] = model.WorkspaceDigest(policy)
		contextBody["contextDigest"] = fixtureDigestField(contextBody, "contextDigest")
		if e := workflowcontract.Validate(workflowcontract.ManagerSingle, "approvedContext4", fixtureRaw(contextBody)); e != nil {
			t.Fatal("current SOURCE context4", e)
		}
		preparations, contexts := 0, 0
		s := &laterControllerStageSource{t: t, path: "/internal/runtime/workspace-workflow/application-operations/" + app.OperationID + "/controller-inputs/" + parent.ServiceRegistrationID + "/manager_integrate", response: response}
		native.sourceHTTP = func(w http.ResponseWriter, request *http.Request) bool {
			if author.serve(w, request) {
				return true
			}
			if s.serve(w, request) {
				return true
			}
			if strings.Contains(request.URL.Path, "/controller-inputs/") {
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`{"error":{"code":"controller_approved_context_pending"}}`))
				return true
			}
			if request.URL.Path == "/internal/runtime/workspace-workflow/controller-preparations" {
				var call api.ControllerPreparationRequest
				raw, e := io.ReadAll(request.Body)
				if e != nil || request.Method != "POST" || model.DecodePhysicalClosed(raw, &call) != nil || call.FormatVersion != 2 || call.ServiceRegistrationID != parent.ServiceRegistrationID || call.InputID != item["inputId"] || call.InputDigest != model.ControllerTextDigest(text) || call.ProviderPolicyDigest != typed.ProviderPolicyDigest {
					t.Error("current normal preparation2 request drift")
					w.WriteHeader(400)
					return true
				}
				preparations++
				_, _ = w.Write(fixtureRaw(api.ControllerPreparationResult{FormatVersion: 2, PreparationID: prepared.PreparationID, State: "native_admission_pending", PreparedTuple: &prepared.PreparedTuple, ApplicationConfigDigest: parent.ConfigDigest, ApplicationRoleAgentDigest: parent.RoleAgentDigest, IdentityAssociationDigest: typed.IdentityAssociation.AssociationDigest}))
				return true
			}
			if request.URL.Path == "/internal/runtime/workspace-workflow/controller-preparations/"+prepared.PreparationID+"/workflow-context" {
				if request.Method != "GET" || request.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_current_stage" {
					t.Error("current context4 SOURCE lease changed")
					w.WriteHeader(400)
					return true
				}
				contexts++
				_, _ = w.Write(fixtureRaw(contextBody))
				return true
			}
			if strings.HasSuffix(request.URL.Path, "/first-task") {
				// Initial consent/result traversal is the explicit upstream SOURCE
				// supplier here, not the old case2 owner1 fixture.
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"error":{"code":"workspace_first_task_not_found"}}`))
				return true
			}
			return false
		}
		runtime := &currentStageSourceRuntime{author: author, firstTaskEnrollmentSourceRuntime: &firstTaskEnrollmentSourceRuntime{&firstTaskSourceRuntime{native}}, policy: typed, application: app, declaration: envelope, operator: &d.operator.PublicKey, readout: readout}
		j.reconciler.ManagedRuntime = runtime
		witness, err := j.reconciler.controllerActivityCurrentWitness(ctx, parent.ServiceRegistrationID, typed.Applicability, false)
		if err != nil || typed.IdentityAssociation.ValidateAccepted(app, witness.Installed.Application.ApplicationID, witness.Installed.Application.ReceiptDigest, witness.Installed.WorkspaceMaterializerDigest, typed.NativeIdentity()) != nil {
			t.Fatal("current accepted application association", err)
		}
		selected, err := runtime.ReadControllerFirstTaskApplicability(ctx, j.manifest, witness.Installed)
		if err != nil || selected.FormatVersion != 2 || selected.ProviderPolicyDigest != typed.Case.ProviderPolicyDigest || typed.Case.FormatVersion != 3 {
			t.Fatal("current SOURCE eligibility absent", err)
		}
		d.writeOriginal(t, filepath.Join(d.root, "current-stage-declaration.json"), envelope, 0600)
		d.writeOriginal(t, filepath.Join(d.root, "current-stage-policy.json"), sourceSigned(t, d.operator, "source_independent_operator", policy), 0600)
		d.writeOriginal(t, filepath.Join(d.root, "current-stage-response.json"), response, 0600)
		d.writeOriginal(t, filepath.Join(d.root, "current-stage-reported-result.json"), resultRaw, 0600)
		d.writeOriginal(t, filepath.Join(d.root, "current-stage-public-proof.json"), fixtureRaw(map[string]any{"classification": "SOURCE public declarations; protected filesystem and native suppliers detached", "case": typed.Case, "demand": output["demand"], "operatorPublicPEM": d.operatorPEM, "parent": parent, "readout": readout, "declaration": json.RawMessage(envelope), "observedAt": now.Format(time.RFC3339Nano)}), 0600)
		// Upstream role enrollment is also an explicit SOURCE supplier here. The
		// ordinary attachment still checks the independently accepted current app.
		if e := j.reconciler.bindControllerFirstTaskAuthorityLocked(ctx, app.OperationID, "manager", selected, "wfl_source_current_stage"); e != nil {
			t.Fatal("SOURCE existing manager lease attachment", e)
		}
		if os.Getenv("WARPMETAL_CURRENT_STAGE_CHILD_SOURCE") == "1" {
			runCurrentStageAcceptedChildSource(t, j, native, d, runtime, readout, prepared, contextBody, policy, intent, s, claim, resultRaw)
			return
		}
		if err = j.reconciler.Store.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := state.Open(j.databasePath)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		j.reconciler.Store, native.store = reopened, reopened
		catalog, ok := j.reconciler.ManagedCatalog.(*workspacecatalog.Catalog)
		if !ok {
			t.Fatal("current SOURCE catalog changed")
		}
		catalog.State = reopened
		err = j.reconciler.Reconcile(ctx, j.manifest)
		firstErr := err
		if author.operations != 1 || author.proofs != 1 || author.reports != 1 || s.reads != 1 || preparations != 1 || contexts != 1 || runtime.policyReads != 1 || !errors.Is(err, ErrControllerActivityPending) {
			t.Fatalf("normal current stage failed to reach protected-policy boundary: reads=%d prepares=%d contexts=%d policy=%d err=%v", s.reads, preparations, contexts, runtime.policyReads, err)
		}
		if e := reopened.Close(); e != nil {
			t.Fatal(e)
		}
		reopened, err = state.Open(j.databasePath)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		j.reconciler.Store, native.store, catalog.State = reopened, reopened, reopened
		err = j.reconciler.Reconcile(ctx, j.manifest)
		if !errors.Is(err, state.ErrOwnedContinuationUnknown) || s.reads != 1 || preparations != 1 || contexts != 1 || runtime.policyReads != 1 {
			t.Fatalf("same stage redispatched after reopen: reads=%d prepares=%d contexts=%d policy=%d err=%v", s.reads, preparations, contexts, runtime.policyReads, err)
		}
		after, readErr := reopened.OwnedContinuationResult(ctx, app.OperationID, "source-reported-result", claim)
		if readErr != nil || !bytes.Equal(after, resultRaw) || native.attestCalls != 1 {
			t.Fatal("current source result/app original changed", readErr)
		}
		d.writeOriginal(t, filepath.Join(d.root, "current-stage-observation.json"), fixtureRaw(map[string]any{"classification": "SOURCE current app/case3/declaration4; upstream reported result and existing role lease detached", "eligibleCaseVersion": typed.Case.FormatVersion, "declarationVersion": 4, "phase": "before_parent", "authorRefreshOperations": author.operations, "authorRefreshProofs": author.proofs, "authorRefreshReports": author.reports, "stageReads": s.reads, "preparations": preparations, "contexts": contexts, "protectedPolicyReads": runtime.policyReads, "firstPending": firstErr.Error(), "sameSQLiteReopened": true, "sourceResultUnchanged": true, "reconcileError": func() any {
			if err != nil {
				return err.Error()
			}
			return nil
		}(), "nativeRuns": 0, "externalProviderRequests": 0}), 0600)
		t.Log("retained current normal-stage SOURCE boundary", d.root)
		if s.reads != 1 {
			t.Fatalf("normal current case3/declaration4 later-stage discovery absent: reads=%d reconcile=%v", s.reads, err)
		}
	})
}
