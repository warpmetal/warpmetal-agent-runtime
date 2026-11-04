package reconcile

// The upstream author's original records are explicit fresh SOURCE suppliers.
// They use the same accepted-parent and child constructors and canonical journal
// records as the normal journey, not a second history store or live authority.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type currentAuthorSource struct {
	t                           *testing.T
	f                           *firstTaskChildTerminalFixture
	native                      *parentSourceRuntime
	app                         model.WorkspaceApplicationOperation
	child                       ControllerFirstTaskChildResult
	first                       model.WorkflowFactsEnvelope
	ops                         map[string]model.WorkflowFactsOperation
	operations, proofs, reports int
}

func sourceCurrentAuthor(t *testing.T, j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, published map[string]any, plan map[string]any) (*currentAuthorSource, json.RawMessage) {
	t.Helper()
	ctx := context.Background()
	now := j.reconciler.now()
	raw, e := os.ReadFile(os.Getenv("WARPMETAL_CURRENT_INITIAL_TEMPLATE"))
	if e != nil {
		t.Fatal("current initial output4 SOURCE shape required", e)
	}
	var template map[string]any
	publicDeliveryDecode(t, json.RawMessage(raw), &template)
	app := model.WorkspaceApplicationOperation{}
	publicDeliveryDecode(t, published["application"], &app)
	localApp, e := j.reconciler.Store.WorkspaceApplication(ctx, app.OperationID)
	if e != nil || localApp == nil {
		t.Fatal(e)
	}
	allocations := map[string]map[string]any{}
	for _, a := range sourceObject(sourceObject(published["demand"])["payload"])["allocations"].([]any) {
		v := sourceObject(a)
		allocations[v["name"].(string)] = v
	}
	parent := native.parents[0]
	foreman := native.parents[1]
	initialContext := publicDeliveryMap(sourceObject(template["operation"])["context"])
	initialTarget := sourceObject(initialContext["target"])
	intent := sourceObject(initialTarget["intent"])
	coding := allocations["coding"]
	if coding == nil {
		t.Fatal("SOURCE coding allocation absent")
	}
	intent["intentId"], intent["intentRevision"], intent["allocationId"] = coding["sourceId"], 1, coding["allocationId"]
	intent["laneId"], intent["assignmentRequestId"], intent["grantRequestId"] = "lane_source_original_coding", "assignment_source_original_coding", "grant_source_original_coding"
	intent["plan"], intent["notAfter"] = plan, now.Add(110*time.Second).Format(time.RFC3339Nano)
	intent["scope"] = map[string]any{"owner": parent.Owner, "configurationDigest": app.ConfigurationDigest, "approvedProfile": app.Dependencies.Roles[0].Projection.ApprovedProfile, "workspace": map[string]any{"designation": parent.Workspace.Designation, "selectionId": parent.Workspace.SelectionID, "projectId": parent.Workspace.ProjectID, "workspaceEpoch": parent.Workspace.WorkspaceEpoch, "rootAttestation": parent.Workspace.RootAttestation, "scopeRevision": parent.Workspace.ScopeRevision}}
	prepare := sourceObject(intent["prepareBody"])
	prepare["controllerId"], prepare["sandboxGeneration"], prepare["profile"] = parent.Owner.ControllerID, parent.Owner.SandboxGeneration, parent.Profile
	prepare["authority"], prepare["credentialBinding"] = app.Dependencies.Roles[0].Projection.ModelSelection.Authority, app.Dependencies.Roles[0].Projection.ModelSelection.CredentialBinding
	prepare["instance"], prepare["operationId"], prepare["requestId"] = "source-original-coding", "operation_source_original_coding", "prepare_source_original_coding"
	prepare["workspaceSelection"] = map[string]any{"selectionId": parent.Workspace.SelectionID, "projectId": parent.Workspace.ProjectID, "workspaceEpoch": parent.Workspace.WorkspaceEpoch}
	content := sourceObject(prepare["content"])
	packet := sourceObject(content["workflowPacket"])
	packet["planRef"], packet["laneId"], packet["packetId"], packet["budgetRef"] = plan["planRef"], intent["laneId"], "packet_source_original_coding", "docs/source-controller-plan.md#source-coding"
	sourceObject(prepare["parentIdentity"])["packetId"] = packet["packetId"]
	intent["packetContentDigest"], intent["prepareBodyDigest"] = model.WorkspaceDigest(packet), model.WorkspaceDigest(prepare)
	intent["lifecycleRequestDigest"] = model.RawPhysicalDigest(fixtureRaw(prepare))[7:]
	intent["intentDigest"] = fixtureDigestField(intent, "intentDigest")
	if e = workflowcontract.Validate(workflowcontract.Manager, "approvedWorkIntent", fixtureRaw(intent)); e != nil {
		t.Fatal("current SOURCE implement intent", e)
	}
	lane := map[string]any{"laneId": intent["laneId"], "packetRefs": []any{map[string]any{"packetId": packet["packetId"], "packetRevision": packet["packetRevision"]}}, "requestedParallelism": 1, "writeScope": packet["writeScope"], "dependencies": []any{}, "reason": "SOURCE bounded original document"}
	advice := map[string]any{"formatVersion": 1, "adviceId": "source_original_advice", "adviceRevision": 1, "adviceDigest": model.WorkspaceDigest(map[string]any{"plan": plan, "lanes": []any{lane}}), "plan": plan, "createdAt": now.Format(time.RFC3339Nano)}
	initialTarget["advice"], initialTarget["resourceId"] = advice, advice["adviceId"]
	// Closed current parent records, constructed before signing. No stage alias.
	type parentOriginal struct {
		prepared model.ControllerPreparedReceipt
		declared qualification.ControllerDeclaredInput
		op       model.ControllerOutputOperation
		proof    model.ControllerOutputEnvelope
		action   json.RawMessage
	}
	originals := map[string]parentOriginal{}
	for _, p := range []model.ControllerParentIntent{foreman, parent} {
		name := "foreman"
		if p.Role == "manager" {
			name = "manager_initial"
		}
		var policy qualification.ControllerPolicy
		publicDeliveryDecode(t, sourceObject(sourceObject(sourceObject(published["parents"])[p.Role])["policy"])["payload"], &policy)
		policy.AllocationID = allocations[name]["allocationId"].(string)
		n := policy.NativeIdentity()
		local, e := j.reconciler.Store.ControllerParent(ctx, p.ServiceRegistrationID)
		if e != nil || local == nil {
			t.Fatal(e)
		}
		text := "Explicit SOURCE original " + name
		prep := sourceControllerPreparedShape(n.Intent, app, *local.Report.NativeRegistration, "msg_source_original_"+name, text)
		prep.PreparationID = "source_original_" + name + "_preparation"
		basis := map[string]any{"preparationId": prep.PreparationID, "preparedTuple": prep.PreparedTuple, "credentialId": prep.CredentialID, "nativeCredentialId": prep.NativeCredentialID}
		prep.BindingDigest = model.WorkspaceDigest(basis)
		basis["bindingDigest"] = prep.BindingDigest
		prep.PreparedReceiptDigest = model.WorkspaceDigest(basis)
		target := any(initialTarget)
		if p.Role == "orchestrator" {
			target = map[string]any{"kind": "advice", "role": "orchestrator", "resourceId": nil, "advice": nil}
		}
		var item qualification.ControllerDeclaredInput
		publicDeliveryDecode(t, map[string]any{"serviceRegistrationId": p.ServiceRegistrationID, "inputId": prep.PreparedTuple.InputID, "inputText": text, "policyDigest": model.WorkspaceDigest(policy), "workflowRequestId": "request_source_original_" + name, "plan": plan, "target": target, "allocationId": policy.AllocationID, "preparationOrdinal": allocations[name]["preparationOrdinal"], "physicalIndex": allocations[name]["firstPhysicalIndex"]}, &item)
		contextMap := publicDeliveryMap(initialContext)
		for k, v := range map[string]any{"contextId": "context_source_original_" + name, "preparationId": prep.PreparationID, "caseId": policy.Case.CaseID, "caseManifestDigest": policy.Case.CaseManifestDigest, "demandManifestDigest": policy.Case.DemandManifestDigest, "policyDigest": model.WorkspaceDigest(policy), "inputId": item.InputID, "inputDigest": model.ControllerTextDigest(text), "workflowRequestId": item.WorkflowRequestID, "plan": plan, "target": target, "declarationItemDigest": model.WorkspaceDigest(item), "allocationId": item.AllocationID, "preparationOrdinal": item.PreparationOrdinal, "physicalIndex": item.PhysicalIndex, "identityAssociationDigest": policy.IdentityAssociation.AssociationDigest, "providerPolicyDigest": policy.ProviderPolicyDigest} {
			contextMap[k] = v
		}
		contextMap["contextDigest"] = fixtureDigestField(contextMap, "contextDigest")
		var c model.ControllerApprovedInputContext
		publicDeliveryDecode(t, contextMap, &c)
		body := map[string]any{"formatVersion": 1, "requestId": item.WorkflowRequestID, "plan": plan, "lanes": []any{lane}, "reason": "SOURCE original task"}
		if p.Role == "manager" {
			body["choice"], body["expectedAdviceRevision"] = "adopt", 1
		}
		op, proof := sourceCurrentAcceptedParentOutput(t, j, native, d, app, policy, prep, c, item, body, name, template)
		action := fixtureRaw(advice)
		if p.Role == "manager" {
			ref := model.IntentRef{IntentID: intent["intentId"].(string), IntentRevision: 1, IntentDigest: intent["intentDigest"].(string)}
			handle := "source_original_coding_handle"
			action = fixtureRaw(model.IntentReceipt{FormatVersion: 2, ContextID: c.ContextID, OperationID: op.OperationID, AssociationDigest: model.WorkspaceDigest(map[string]any{"operationDigest": op.OperationDigest, "proofDigest": model.WorkspaceDigest(proof.Payload), "lineageDigest": model.WorkspaceDigest(op.Lineage), "body": op.Proposal.Body, "action": c.Target.Kind, "resource": advice["adviceId"]}), Member: model.IntentAcceptance{Intent: ref, Choice: "admit", DecisionDigest: model.WorkspaceDigest(body), Handle: &handle, ReceiptDigest: model.WorkspaceDigest("SOURCE original coding decision")}})
		}
		var env model.ControllerPreparedEnvelope
		publicDeliveryDecode(t, sourceSigned(t, native.key, app.Producer.KeyID, prep), &env)
		for stage, value := range map[state.ControllerActivityStage]any{state.ControllerNativePrepared: env, state.ControllerApprovedContext: controllerApprovedInput{Context: c, InputText: text}, state.ControllerPolicyVerified: policy, state.ControllerInstalledApplicability: policy.Applicability, state.ControllerOutputOperation: op, state.ControllerOutputEnvelope: proof, state.ControllerActionReceipt: json.RawMessage(action)} {
			if e = j.reconciler.Store.PinControllerActivityStage(ctx, prep.PreparationID, stage, fixtureRaw(value)); e != nil {
				t.Fatal(e)
			}
		}
		if _, e = j.reconciler.readControllerParentActionReceiptLocked(ctx, prep.PreparationID); e != nil {
			t.Fatal("fresh current SOURCE original parent", name, e)
		}
		originals[p.Role] = parentOriginal{prep, item, op, proof, action}
	}
	fParent, mParent := originals["orchestrator"], originals["manager"]
	owner := api.OwnerFirstTaskOriginal{FormatVersion: 2, FirstTaskID: "firsttask_source_current_author", SetupIntentID: app.SetupIntentID, RequestID: "source_original_owner_request", ApplicationID: localApp.ApplicationID, ApplicationOperationID: app.OperationID, ApplicationOperationDigest: app.OperationDigest, ConfigurationID: app.ConfigurationID, ConfigurationRevision: app.ConfigurationRevision, ConfigurationDigest: app.ConfigurationDigest, Owner: parent.Owner, InputText: fParent.declared.InputText, ParentActivityRequest: api.ControllerPreparationRequest{FormatVersion: 2, RequestID: fParent.declared.WorkflowRequestID, ServiceRegistrationID: foreman.ServiceRegistrationID, InputID: fParent.declared.InputID, InputDigest: model.ControllerTextDigest(fParent.declared.InputText), ModelSelection: *app.Dependencies.Roles[1].Projection.ModelSelection, ProviderPolicyDigest: providerpolicy.FlashDigest}, CreatedAt: now.Format(time.RFC3339Nano), StatusURL: "/internal/account/agent-workspace-setup-intents/" + app.SetupIntentID + "/tasks/firsttask_source_current_author"}
	owner.Parent.ServiceRegistrationID, owner.Parent.ServiceGeneration, owner.Parent.Role, owner.Parent.ConfigDigest, owner.Parent.DesiredRevision, owner.Parent.NativeRegistration = foreman.ServiceRegistrationID, foreman.ServiceGeneration, "orchestrator", foreman.ConfigDigest, foreman.DesiredRevision, fParent.prepared.PreparedTuple.NativeRegistration
	if workflowcontract.ValidateOwnerFirstTask("ownerFirstTaskOriginal", fixtureRaw(owner)) != nil {
		t.Fatal("current SOURCE first-task2 owner")
	}
	fixtureComplete(t, j.reconciler, owner.FirstTaskID, "owner-original", owner, owner)
	fixtureComplete(t, j.reconciler, owner.FirstTaskID, "parent-prepare", owner, fParent.prepared)
	decision := controllerInitialDecisionOriginal{owner, fParent.action, parent, mParent.declared}
	fixtureComplete(t, j.reconciler, owner.FirstTaskID, "initial-decision-original", decision, mParent.declared)
	fixtureComplete(t, j.reconciler, owner.FirstTaskID, "initial-decision-prepare", decision, mParent.prepared)
	var accepted model.ManagerActionReceipt
	publicDeliveryDecode(t, mParent.action, &accepted)
	selected, e := accepted.Select(mParent.op, "member")
	if e != nil {
		t.Fatal(e)
	}
	h := model.IntentHandle{FormatVersion: 1, HandleID: "source_original_coding_handle", Intent: selected.Ref, AssociationDigest: accepted.AssociationDigest(), ContextID: mParent.op.Context.ContextID, OperationID: mParent.op.OperationID, Owner: parent.Owner, RoleBindingID: mParent.op.RoleBindingID, RoleBindingRevision: 1, AllocationID: selected.AllocationID, NotAfter: selected.NotAfter}
	h.HandleDigest = fixtureDigestField(h, "handleDigest")
	f := &firstTaskChildTerminalFixture{t: t, r: j.reconciler, handle: h, selected: selected, backendState: "completed", nativeState: "terminal", ownerScopedProject: true, credentialID: "cred_source_original_coding", nativeCredentialID: "native_cred_source_original_coding"}
	f.entry = cellV3TestEntry(t)
	f.entry.OperationID = "managed_source_original_coding"
	f.entry.PreparationID = "source_original_coding_preparation"
	f.entry.LaunchOperationID = prepare["operationId"].(string)
	f.entry.Instance = prepare["instance"].(string)
	sum := sha256.Sum256([]byte(f.entry.LaunchOperationID))
	f.entry.NativeSessionID = "ses_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	f.entry.ServiceRegistrationID = "source_original_coding_service"
	f.entry.NativeProjectID = mParent.prepared.PreparedTuple.NativeRegistration.NativeProjectID
	publicDeliveryDecode(t, prepare["parentIdentity"], &f.entry.ParentIdentity)
	f.resultInput = string(fixtureRaw(map[string]any{"formatVersion": 1, "kind": "workspace_workflow_packet", "content": content}))
	f.entry.Instructions.InstructionDigest = model.RawPhysicalDigest([]byte(f.resultInput))
	a := app.Dependencies.Roles[0].Projection.ModelSelection.Authority
	f.entry.Authority = &model.ManagedServiceV2Authority{ProviderID: a.ProviderID, ModelID: &a.ModelID, AuthMode: &a.AuthMode}
	f.configureChildTerminalSource(t, j, parent, app)
	receipt := f.preparedSourceReceipt()
	if e = j.reconciler.Store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: f.entry, Phase: "pending"}); e != nil {
		t.Fatal(e)
	}
	local := state.LocalCellV3Operation{Entry: f.entry, Phase: "prepared", Receipt: receipt, ReceiptJSON: fixtureRaw(receipt), PreparedReceiptDigest: receipt.PreparedReceiptDigest, ParentSessionID: mParent.prepared.PreparedTuple.NativeRegistration.NativeSessionID, WorktreeDir: "/home/agent/projects/cell"}
	if e = j.reconciler.Store.UpdateCellV3Operation(ctx, local); e != nil {
		t.Fatal(e)
	}
	local.Phase = "reported"
	if e = j.reconciler.Store.UpdateCellV3Operation(ctx, local); e != nil {
		t.Fatal(e)
	}
	f.entry = cellV3TestExecute(t, f.entry, receipt)
	f.entry.ExecutionGrant.GrantID = "grant_source_original_coding_execution"
	f.entry.ExecutionGrant.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339Nano)
	if e = j.reconciler.Store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: f.entry, Phase: "pending"}); e != nil {
		t.Fatal(e)
	}
	binding := map[string]any{"workId": plan["workId"], "workRevision": plan["workRevision"], "bindingId": "source_original_coding_binding", "bindingRevision": 1, "executionId": "execution_source_current_stage", "preparationId": f.entry.PreparationID, "parentExecutionId": nil, "parentPacketId": nil, "packetId": f.entry.ParentIdentity.PacketID, "packetRevision": 1, "attempt": f.entry.Attempt, "fence": f.entry.Fence, "serviceRegistrationId": f.entry.ServiceRegistrationID, "serviceGeneration": f.entry.ServiceGeneration, "sandboxGeneration": f.entry.SandboxGeneration, "nativeSessionId": f.entry.NativeSessionID, "nativeProjectId": f.entry.NativeProjectID, "nativeLocationDigest": model.WorkspaceDigest("SOURCE original coding location"), "projectId": f.entry.Workspace.ProjectID, "workspaceEpoch": f.entry.WorkspaceEpoch, "selectionId": f.entry.Workspace.SelectionID, "scopeRevision": f.entry.Workspace.ScopeRevision, "rootAttestation": f.entry.Workspace.RootAttestation, "instructionRevision": f.entry.Instructions.InstructionRevision, "instructionDigest": f.entry.Instructions.InstructionDigest, "profileDigest": f.entry.Profile.ProfileDigest, "configDigest": f.entry.ConfigDigest}
	assignment := map[string]any{"formatVersion": 1, "requestId": selected.AssignmentRequestID, "binding": binding, "purpose": "implement", "plan": plan, "target": nil}
	f.actual = model.ActualPreparationAssociation{FormatVersion: 1, HandleID: h.HandleID, Intent: h.Intent, PreparationID: f.entry.PreparationID, PreparedReceipt: receipt, Binding: fixtureRaw(binding), AssignmentBody: fixtureRaw(assignment)}
	f.actual.AssociationDigest = fixtureDigestField(f.actual, "associationDigest")
	f.assignment = fixtureRaw(map[string]any{"formatVersion": 1, "assignmentId": "assignment_source_current_stage", "assignmentDigest": model.WorkspaceDigest(assignment), "executionId": f.actualExecution(), "purpose": "implement", "plan": plan, "target": nil, "createdAt": now.Format(time.RFC3339Nano)})
	f.admission = model.ChildAdmissionAssociation{FormatVersion: 1, HandleID: h.HandleID, PreparationAssociationDigest: f.actual.AssociationDigest, Assignment: f.assignment, AllocationID: selected.AllocationID, ReservationID: "reservation_source_original_coding", PolicyDigest: model.WorkspaceDigest("SOURCE original product2"), ActivationDigest: model.WorkspaceDigest("SOURCE original activation2"), Grant: *f.entry.ExecutionGrant}
	f.admission.AssociationDigest = fixtureDigestField(f.admission, "associationDigest")
	terminal := &firstTaskChildTerminalRuntime{firstTaskEnrollmentSourceRuntime: &firstTaskEnrollmentSourceRuntime{&firstTaskSourceRuntime{native}}, fixture: f}
	effect, _, e := terminal.ExecManagedSupervisor(ctx, f.entry.SandboxID, "cell", fixtureRaw(map[string]any{"instance": f.entry.Instance, "preparedReceipt": receipt, "executionGrant": f.entry.ExecutionGrant}))
	if e != nil {
		t.Fatal(e)
	}
	var n managedCellExecuteResultV3
	publicDeliveryDecode(t, json.RawMessage(effect), &n)
	report := j.reconciler.cancelledReport(cellV2View(f.entry), f.entry.Attempt, "ready", model.RawPhysicalDigest(effect))
	report.FormatVersion = 3
	report.Child = &model.ManagedCellChildV1{OperationID: n.OperationID, SessionID: n.SessionID, MessageID: n.MessageID, State: n.State, Attempt: n.Attempt, Outcome: n.Outcome}
	if e = j.reconciler.Store.PutCellV3Execution(ctx, f.entry, state.LocalCellV3Execution{PreparationID: f.entry.PreparationID, Grant: *f.entry.ExecutionGrant, Phase: "terminal", ParentSessionID: local.ParentSessionID, WorktreeDir: local.WorktreeDir, EffectJSON: effect, Report: report}); e != nil {
		t.Fatal(e)
	}
	f.backendDigest = &report.ReceiptDigest
	putCurrentStageSourceEntry(&j.manifest, f.entry)
	j.reconciler.setCurrentAuthority(j.manifest)
	child := ControllerFirstTaskChildResult{h, f.actualExecution(), f.actual.Binding, f.actual, f.admission, report, fixtureRaw(f.currentSnapshot())}
	canonical := ControllerFirstTaskResult{owner, mParent.prepared.PreparationID, accepted, "completed", []ControllerFirstTaskChildResult{child}}
	fixtureComplete(t, j.reconciler, owner.FirstTaskID, "result", controllerFirstTaskResultClaim(canonical), canonical)
	s := &currentAuthorSource{t: t, f: f, native: native, app: app, child: child, ops: map[string]model.WorkflowFactsOperation{}}
	result := s.seedCompletionOriginals(t, j, plan, d.root)
	fixtureComplete(t, j.reconciler, f.entry.PreparationID, "completion-origin", completedChildOrigin{"first_task", owner.FirstTaskID, f.entry.PreparationID, model.WorkspaceDigest(child.Binding)}, completedChildOrigin{"first_task", owner.FirstTaskID, f.entry.PreparationID, model.WorkspaceDigest(child.Binding)})
	d.writeOriginal(t, filepath.Join(d.root, "source-current-author-originals.json"), fixtureRaw(map[string]any{"classification": "fresh upstream SOURCE first-task2/context4/single receipt2/STATE/result history; no normal first-task/native/ROOT/backend acceptance claim", "owner": owner, "result": canonical, "receipt": json.RawMessage(result), "firstFacts": s.first}), 0600)
	return s, result
}

func (s *currentAuthorSource) seedCompletionOriginals(t *testing.T, j *managerPolicyJourney, plan map[string]any, root string) json.RawMessage {
	f := s.f
	now := f.r.now()
	source := &childCompletionSource{f: f}
	a := newChildCompletionArtifactSource(t, source)
	a.content = []byte("SOURCE original document\n")
	if e := os.WriteFile(a.path, a.content, 0600); e != nil {
		t.Fatal(e)
	}
	a.capture.Native.InputDigest = model.RawPhysicalDigest([]byte(f.resultInput))
	a.capture.Artifact.SourcePath = "source/coding-result.txt"
	a.capture.Artifact.Digest = model.RawPhysicalDigest(a.content)
	a.capture.Artifact.ByteCount = len(a.content)
	outcome := qualification.ChildWorkflowNativeCapture{Result: &a.capture, ApprovedSourceReferences: a.approved}
	metadata, e := childDocumentFromNative(a.capture.Terminal.Text, a.approved)
	if e != nil {
		t.Fatal(e)
	}
	artifactClaim := completedChildArtifactClaim(f.actual.Binding, a.capture, metadata)
	fixtureComplete(t, f.r, f.entry.PreparationID, "completion-artifact-outcome", artifactClaim, outcome)
	nativeRead := model.WorkflowReceiptRef{ReceiptID: "source_original_artifact_read", ReceiptDigest: model.WorkspaceDigest("SOURCE original artifact read")}
	upload := model.WorkflowArtifactReceipt{FormatVersion: 1, ArtifactID: "source_original_document_artifact", ExecutionID: f.actualExecution(), SourcePath: a.capture.Artifact.SourcePath, Purpose: "document", Digest: a.capture.Artifact.Digest, ByteCount: len(a.content), ContentType: "text/plain", NativeReadReceipt: fixtureRaw(nativeRead), CreatedAt: now.Format(time.RFC3339Nano)}
	upload.ArtifactReceiptDigest = fixtureDigestField(upload, "artifactReceiptDigest")
	if e = workflowcontract.Validate(workflowcontract.Domain, "artifactReceipt", fixtureRaw(upload)); e != nil {
		t.Fatal("SOURCE artifact receipt", e)
	}
	fixtureComplete(t, f.r, f.entry.PreparationID, "completion-artifact", artifactClaim, upload)
	result := map[string]any{"outcome": "completed", "mismatches": []any{}, "consumedRefs": []any{map[string]any{"reference": plan["planRef"], "readReceipt": map[string]any{"receiptId": "source_original_plan_read", "receiptDigest": model.WorkspaceDigest("SOURCE original plan read")}}}, "outputs": []any{map[string]any{"type": "document", "sourceRefs": metadata.SourceRefs, "method": metadata.Method, "output": map[string]any{"artifactId": upload.ArtifactID, "digest": upload.Digest, "byteCount": upload.ByteCount, "contentType": upload.ContentType}}}, "stateEvidence": []any{}, "effectReceipts": []any{}, "remainingWork": []any{}}
	request := map[string]any{"formatVersion": 1, "requestId": "source_original_result_request", "binding": f.actual.Binding, "assignmentId": "assignment_source_current_stage", "result": result}
	receipt := fixtureRaw(map[string]any{"formatVersion": 1, "resultId": "result_source_current_stage", "resultRevision": 1, "resultDigest": model.WorkspaceDigest(map[string]any{"binding": f.actual.Binding, "assignmentId": "assignment_source_current_stage", "result": result}), "assignmentId": "assignment_source_current_stage", "executionId": f.actualExecution(), "state": "reported", "createdAt": now.Format(time.RFC3339Nano)})
	if e = workflowcontract.Validate(workflowcontract.Domain, "resultRequest", fixtureRaw(request)); e != nil {
		t.Fatal(e)
	}
	fixtureComplete(t, f.r, f.entry.PreparationID, "completion-result", request, json.RawMessage(receipt))
	call := model.WorkflowFactsRequest{FormatVersion: 1, RequestID: "source_original_settlement", Binding: f.actual.Binding, Operation: model.WorkflowFactsSelector{Kind: "execution_settlement"}}
	op := model.WorkflowFactsOperation{FormatVersion: 1, OperationID: "wfop_source_original_settlement", Binding: call.Binding, Operation: call.Operation, Snapshot: s.child.BackendSnapshot, NodeTokenHash: s.app.Producer.NodeTokenHash, RuntimeRevision: j.manifest.DesiredRevision, ExpiresAt: now.Add(currentSourceFactsTTL()).Format(time.RFC3339Nano)}
	op.OperationDigest = fixtureDigestField(op, "operationDigest")
	s.first = s.signFacts(call, op, s.child.BackendSnapshot)
	stage := "completion-settlement-" + model.WorkspaceDigest(s.child.BackendSnapshot)[7:]
	fixtureComplete(t, f.r, f.entry.PreparationID, stage+"-operation", call, op)
	fixtureComplete(t, f.r, f.entry.PreparationID, stage+"-proof", op, s.first)
	fixtureComplete(t, f.r, f.entry.PreparationID, stage+"-report", s.first, model.WorkflowFactsReceipt{FormatVersion: 1, ProofID: "facts_source_original", ProofDigest: model.WorkspaceDigest(s.first), ExpiresAt: s.first.Payload.NotAfter})
	if e = os.WriteFile(filepath.Join(root, "source-original-author-artifact.body"), a.content, 0600); e != nil {
		t.Fatal(e)
	}
	return receipt
}

func (s *currentAuthorSource) signFacts(call model.WorkflowFactsRequest, op model.WorkflowFactsOperation, snapshot json.RawMessage) model.WorkflowFactsEnvelope {
	f := s.f
	stamp := f.r.now().Format(time.RFC3339Nano)
	var b struct{ NativeLocationDigest string }
	_ = json.Unmarshal(f.actual.Binding, &b)
	readback := map[string]any{"nativeSessionId": f.entry.NativeSessionID, "nativeRole": "worker", "snapshotDigest": model.WorkspaceDigest(snapshot), "quiescent": true, "effectsComplete": true, "descendantsComplete": true}
	native := model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: f.entry.ServiceRegistrationID, ServiceGeneration: f.entry.ServiceGeneration, NativeSessionID: f.entry.NativeSessionID, NativeProjectID: f.entry.NativeProjectID, NativeLocationDigest: b.NativeLocationDigest, Role: "worker", RootAttestation: f.entry.Workspace.RootAttestation, ObservedAt: stamp, Readback: fixtureRaw(readback)}
	readback["nativeReceiptDigest"] = model.WorkspaceDigest(native)
	payload := model.WorkflowFactsPayload{FormatVersion: 1, Purpose: "workspace_workflow_facts", RequestID: call.RequestID, TaskID: s.native.parents[0].Owner.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: model.WorkspaceDigest("source_current_receipt"), NativeReceipt: native, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Binding: call.Binding, Readback: fixtureRaw(readback)}
	var out model.WorkflowFactsEnvelope
	publicDeliveryDecode(s.t, sourceSigned(s.t, s.native.key, s.app.Producer.KeyID, payload), &out)
	return out
}
func (s *currentAuthorSource) serve(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/internal/runtime/workspace-workflow-observations/executions/"+s.child.ExecutionID+"/current-snapshot" || strings.Contains(r.URL.Path, s.f.entry.ServiceRegistrationID) && strings.HasSuffix(r.URL.Path, "/instructions") {
		return s.f.serve(w, r)
	}
	const prefix = "/internal/runtime/workspace-workflow-observations"
	if r.URL.Path != prefix+"/operations" && r.URL.Path != prefix+"/facts" {
		return false
	}
	var raw json.RawMessage
	if json.NewDecoder(r.Body).Decode(&raw) != nil {
		s.t.Fatal("SOURCE author facts body")
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	var selected struct {
		Binding json.RawMessage
		Payload struct{ Binding json.RawMessage }
	}
	_ = json.Unmarshal(raw, &selected)
	binding := selected.Binding
	if len(binding) == 0 {
		binding = selected.Payload.Binding
	}
	if model.WorkspaceDigest(binding) != model.WorkspaceDigest(s.child.Binding) {
		return false
	}
	if r.Method != "POST" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "" {
		s.t.Fatal("SOURCE author facts authority")
	}
	if r.URL.Path == prefix+"/operations" {
		var call model.WorkflowFactsRequest
		publicDeliveryDecode(s.t, raw, &call)
		s.operations++
		op := model.WorkflowFactsOperation{FormatVersion: 1, OperationID: "wfop_" + model.WorkspaceDigest(call)[7:], Binding: call.Binding, Operation: call.Operation, Snapshot: fixtureRaw(s.f.currentSnapshot()), NodeTokenHash: s.app.Producer.NodeTokenHash, RuntimeRevision: s.f.entry.DesiredRevision, ExpiresAt: s.f.r.now().Add(currentSourceFactsTTL()).Format(time.RFC3339Nano)}
		op.OperationDigest = fixtureDigestField(op, "operationDigest")
		s.ops[op.OperationID] = op
		_ = json.NewEncoder(w).Encode(op)
		return true
	}
	var proof model.WorkflowFactsEnvelope
	publicDeliveryDecode(s.t, raw, &proof)
	op, ok := s.ops[proof.Payload.OperationID]
	if !ok || proof.Payload.OperationDigest != op.OperationDigest {
		s.t.Fatal("SOURCE author first proof drift")
	}
	s.reports++
	if os.Getenv("WARPMETAL_REFRESH_MODE") == "lost_refresh_ack" && s.reports == 2 {
		http.Error(w, "SOURCE lost refresh ACK", 503)
		return true
	}
	_ = json.NewEncoder(w).Encode(model.WorkflowFactsReceipt{FormatVersion: 1, ProofID: "facts_" + op.OperationID, ProofDigest: model.WorkspaceDigest(proof), ExpiresAt: proof.Payload.NotAfter})
	return true
}

func (s *currentStageSourceRuntime) AttestCompletedCellWorkflowFacts(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, call model.WorkflowFactsRequest, op model.WorkflowFactsOperation, root workspacecatalog.RegisteredProject, base json.RawMessage, first model.WorkflowFactsEnvelope) (model.WorkflowFactsEnvelope, error) {
	a := s.author
	if a == nil || entry.PreparationID != a.f.entry.PreparationID || model.WorkspaceDigest(first) != model.WorkspaceDigest(a.first) || model.WorkspaceDigest(base) != model.WorkspaceDigest(a.f.currentSnapshot()) || string(input) != a.f.resultInput {
		return model.WorkflowFactsEnvelope{}, state.ErrControllerActivityConflict
	}
	if _, e := a.f.r.currentCompletedChildAuthority(ctx, controllerChildApplication{Owner: s.policy.ApplicationIdentity().Intent.Owner, ApplicationID: "wapp_source", ApplicationOperationID: a.app.OperationID, ApplicationOperationDigest: a.app.OperationDigest}, a.child, entry); e != nil {
		return model.WorkflowFactsEnvelope{}, e
	}
	a.proofs++
	return a.signFacts(call, op, base), nil
}

func (s *currentStageSourceRuntime) ExecManagedSupervisor(ctx context.Context, box string, action containers.ManagedSupervisorAction, raw []byte) ([]byte, []byte, error) {
	if s.author != nil {
		var call struct{ Instance string }
		_ = json.Unmarshal(raw, &call)
		f := s.author.f
		if call.Instance == f.entry.Instance || call.Instance == model.ManagedServiceProcessInstance(f.entry.Instance, f.entry.ServiceGeneration) {
			return (&firstTaskChildTerminalRuntime{firstTaskEnrollmentSourceRuntime: s.firstTaskEnrollmentSourceRuntime, fixture: f}).ExecManagedSupervisor(ctx, box, action, raw)
		}
	}
	return s.parentSourceRuntime.ExecManagedSupervisor(ctx, box, action, raw)
}
func (s *currentStageTerminalSourceRuntime) AttestCompletedCellWorkflowFacts(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, call model.WorkflowFactsRequest, op model.WorkflowFactsOperation, root workspacecatalog.RegisteredProject, base json.RawMessage, first model.WorkflowFactsEnvelope) (model.WorkflowFactsEnvelope, error) {
	if s.author != nil && entry.PreparationID == s.author.f.entry.PreparationID {
		return s.currentStageSourceRuntime.AttestCompletedCellWorkflowFacts(ctx, box, entry, current, input, call, op, root, base, first)
	}
	if entry.PreparationID != s.terminal.fixture.entry.PreparationID {
		if prior, ok := s.priorSupervisor.(completedChildFactsRuntime); ok {
			return prior.AttestCompletedCellWorkflowFacts(ctx, box, entry, current, input, call, op, root, base, first)
		}
		return model.WorkflowFactsEnvelope{}, state.ErrControllerActivityConflict
	}
	if model.WorkspaceDigest(first.Payload.Binding) != model.WorkspaceDigest(call.Binding) || first.Validate() != nil {
		return model.WorkflowFactsEnvelope{}, state.ErrControllerActivityConflict
	}
	snapshot := base
	if call.Operation.Kind == "integration_candidate" {
		snapshot = s.completion.snapshot(true)
	}
	return s.AttestCellWorkflowFacts(ctx, box, entry, current, input, call, op, root, snapshot)
}

func currentSourceFactsTTL() time.Duration {
	if os.Getenv("WARPMETAL_CURRENT_STAGE_FACT_EXPIRY_SOURCE") == "1" {
		return time.Minute
	}
	return 3 * time.Minute
}

func (s *currentAuthorSource) assertRefreshUnknown(t *testing.T, j *managerPolicyJourney, native *parentSourceRuntime, d *firstTaskPublicDeliveryFixture, reviewer *firstTaskChildTerminalFixture, first error, resultClaim, resultRaw json.RawMessage) {
	t.Helper()
	ctx := context.Background()
	if first == nil || s.operations != 2 || s.proofs != 2 || s.reports != 2 || reviewer.prepares != 0 || reviewer.nativePrepares != 0 {
		t.Fatal("lost refresh ACK crossed child boundary", first, s.operations, s.proofs, s.reports, reviewer.prepares)
	}
	check := func() {
		t.Helper()
		err := j.reconciler.Reconcile(ctx, j.manifest)
		if !errors.Is(err, state.ErrOwnedContinuationUnknown) {
			t.Fatal("refresh UNKNOWN escaped", err)
		}
		if s.operations != 2 || s.proofs != 2 || s.reports != 2 || reviewer.prepares != 0 || reviewer.nativePrepares != 0 {
			t.Fatal("UNKNOWN refresh repeated/new child effect")
		}
		old, e := j.reconciler.Store.OwnedContinuationResult(ctx, s.app.OperationID, "source-reported-result", resultClaim)
		if e != nil || string(old) != string(resultRaw) {
			t.Fatal("original author result drift", e)
		}
	}
	s.f.effectStatus = "settled"
	check()
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
	check()
	d.writeOriginal(t, filepath.Join(d.root, "current-stage-refresh-unknown.json"), fixtureRaw(map[string]any{"classification": "SOURCE actual local TLS lost report ACK; changed current author snapshot and same SQLite reopen", "operations": s.operations, "proofs": s.proofs, "reports": s.reports, "newChildPrepare": reviewer.prepares, "sameSQLiteReopened": true, "originalResultUnchanged": true, "firstError": first.Error(), "phase": "accepted_child", "providerNativeRootRuns": 0}), 0600)
}
