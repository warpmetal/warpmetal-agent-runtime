package reconcile

// Test-only export of the existing SOURCE document supplier. There is no native
// execution/output, backend authority, qualified model, or accepted result here.
import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func TestControllerPreExecutionSourceFixtureExport(t *testing.T) {
	if os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE") == "" || os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET") == "" {
		t.Skip("explicit SOURCE fixture destination and schema-valid context packet required")
	}
	runControllerParentSourceJourneyAccepted(t, false, false, nil, func(j *managerPolicyJourney, native *parentSourceRuntime, app model.WorkspaceApplicationOperation, parents []model.ControllerParentIntent) {
		j.reconciler.Now = func() time.Time { return time.Now().UTC() }
		raw, err := os.ReadFile(os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET"))
		if err != nil {
			t.Fatal(err)
		}
		var packet struct {
			Specimens []struct {
				Context map[string]any `json:"context"`
			} `json:"specimens"`
		}
		if json.Unmarshal(raw, &packet) != nil || len(packet.Specimens) < 2 {
			t.Fatal("SOURCE context packet missing")
		}
		base := packet.Specimens[1].Context
		f := &firstTaskChildTerminalFixture{t: t, r: j.reconciler, deliveryParents: map[string]firstTaskDeliveryParent{}}
		f.configurePublicDeliveryDocuments(t, native, app, base)
		d := f.delivery
		exported := map[string]any{}
		for _, parent := range parents {
			local, err := j.reconciler.Store.ControllerParent(context.Background(), parent.ServiceRegistrationID)
			if err != nil || local == nil || local.Report.NativeRegistration == nil {
				t.Fatal("SOURCE accepted parent absent", err)
			}
			text := "Explicit pre-execution SOURCE instruction; no native output supplied."
			prepared := sourceControllerPrepared(t, parent, app, *local.Report.NativeRegistration, "source_input_"+parent.Role, text)
			fields := publicDeliveryMap(base)
			fields["preparationId"], fields["inputId"], fields["inputDigest"] = prepared.PreparationID, prepared.PreparedTuple.InputID, prepared.PreparedTuple.InputDigest
			fields["contextId"], fields["workflowRequestId"] = "source_context_"+parent.Role, "source_request_"+parent.Role
			if parent.Role == "orchestrator" {
				fields["target"] = map[string]any{"kind": "advice", "role": "orchestrator", "resourceId": nil, "advice": nil}
			}
			fields["contextDigest"] = fixtureDigestField(fields, "contextDigest")
			var current model.ControllerApprovedInputContext
			publicDeliveryDecode(t, fields, &current)
			current = d.parentContext(t, parent, prepared, current)
			policy := d.policies[parent.Role]
			if profileSource := os.Getenv("WARPMETAL_CONTROLLER_PROFILE_SOURCE"); profileSource != "" {
				deriver, ok := any(policy.Identity).(interface {
					DeriveWM8NativeIdentity() (model.ControllerIdentity, error)
				})
				if !ok {
					t.Fatal("explicit application-to-native identity derivation is missing")
				}
				nativeIdentity, err := deriver.DeriveWM8NativeIdentity()
				if err != nil {
					t.Fatal(err)
				}
				command := exec.Command("python3", "-B", "-c", "import importlib.util,json,sys; s=importlib.util.spec_from_file_location('profile',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); a=json.load(sys.stdin); print(json.dumps(m.native_binding_identity(a['intent'],a['source'],a['projection']),sort_keys=True,separators=(',',':')))", profileSource)
				command.Stdin = bytes.NewReader(fixtureRaw(policy.Identity))
				nativeBytes, err := command.Output()
				if err != nil || model.WorkspaceDigest(json.RawMessage(nativeBytes)) != model.WorkspaceDigest(nativeIdentity) {
					t.Fatal("Runtime/Sandbox native identity derivation differs", err)
				}
				association := map[string]any{"formatVersion": 1, "normalization": "opencode-wm8-controller-v1", "application": policy.Application, "materializer": map[string]any{"declaredDigest": app.MaterializerDigest, "installedDigest": policy.Applicability.Profile.MaterializerDigest, "closureVersion": "warpmetal-workspace-content-v1"}, "applicationIdentity": policy.Identity, "applicationIdentityDigest": model.WorkspaceDigest(policy.Identity), "nativeIdentity": nativeIdentity, "nativeIdentityDigest": model.WorkspaceDigest(nativeIdentity)}
				association["associationDigest"] = model.WorkspaceDigest(association)
				if err := workflowcontract.Validate(workflowcontract.ControllerProvider, "controllerIdentityAssociation1", fixtureRaw(association)); err != nil {
					t.Fatal("paired identity owner schema", err)
				}
				var paired model.ControllerIdentityAssociation
				publicDeliveryDecode(t, association, &paired)
				if err := paired.ValidateAccepted(app, policy.Application.ApplicationID, policy.Application.ReceiptDigest, policy.Applicability.Profile.MaterializerDigest, nativeIdentity); err != nil {
					t.Fatal("paired identity accepted application join", err)
				}
				wrongNative := nativeIdentity
				wrongNative.Source.Source.NativeSessionID = "ses_wrong_source"
				if paired.ValidateAccepted(app, policy.Application.ApplicationID, policy.Application.ReceiptDigest, policy.Applicability.Profile.MaterializerDigest, wrongNative) == nil {
					t.Fatal("paired identity borrowed another native session")
				}
				if identitySource := os.Getenv("WARPMETAL_CONTROLLER_IDENTITY_SOURCE"); identitySource != "" {
					check := exec.Command("node", "--input-type=module", "-e", "import fs from 'node:fs'; import assert from 'node:assert/strict'; import {pathToFileURL} from 'node:url'; const {validateControllerIdentityAssociation:validate}=await import(pathToFileURL(process.argv[1]).href); const a=JSON.parse(fs.readFileSync(0,'utf8')); const result=validate(a); assert.equal(result.applicationIdentity,a.applicationIdentity); assert.equal(result.nativeIdentity,a.nativeIdentity); assert.equal(result.application,a.application); assert.equal(result.materializer,a.materializer); const wrong=structuredClone(a); wrong.nativeIdentity.source.source.nativeSessionId='ses_wrong_source'; assert.throws(()=>validate(wrong));", identitySource)
					check.Stdin = bytes.NewReader(fixtureRaw(association))
					if output, err := check.CombinedOutput(); err != nil {
						t.Fatalf("Sandbox paired identity consumer failed: %v\n%s", err, output)
					}
				}
				d.writeOriginal(t, filepath.Join(d.root, "identity-association-"+parent.Role+".json"), sourceSigned(t, d.operator, "source_independent_operator", association), 0600)
			}
			if err := policy.ValidateContext(current); err != nil {
				t.Fatal("SOURCE policy/context join", err)
			}
			f.deliveryParents[parent.Role] = firstTaskDeliveryParent{prepared: prepared, context: current, text: text}
			grant := model.ControllerActivityGrant{FormatVersion: 1, TargetKind: "controller_activity", GrantID: "source_grant_" + parent.Role, PreparationID: prepared.PreparationID, PreparedReceiptDigest: prepared.PreparedReceiptDigest, ReservationID: "source_reservation_" + parent.Role, CaseID: d.caseValue.CaseID, CaseManifestDigest: d.caseValue.CaseManifestDigest, PolicyDigest: current.PolicyDigest, RequestIndex: current.PhysicalIndex, PhysicalIndex: current.PhysicalIndex, MaxInputTokens: 1000, MaxOutputTokens: 1000, MaxUSDMicros: 2000, DeadlineAt: native.now().Add(110 * time.Second).Format(time.RFC3339Nano), ExpiresAt: native.now().Add(115 * time.Second).Format(time.RFC3339Nano)}
			var signed model.ControllerGrantEnvelope
			publicDeliveryDecode(t, sourceSigned(t, d.operator, "source_independent_operator", grant), &signed)
			d.grants[parent.Role] = signed
			activation := d.parentActivation(parent.Role)
			basis := publicDeliveryMap(activation)
			delete(basis, "authorizationSha256")
			delete(basis, "issuedAt")
			checked, err := qualification.ControllerActivationFromSigningBasis(fixtureRaw(basis), activation.IssuedAt, activation.AuthorizationSHA256, policy, current, native.now())
			if err != nil || checked.ValidateContext(policy, current) != nil {
				t.Fatal("SOURCE activation/context join", err)
			}
			for definition, value := range map[string]any{"controllerPolicy5": policy, "controllerActivation3": checked, "approvedContext2": current} {
				if err := workflowcontract.Validate(workflowcontract.Budget, definition, fixtureRaw(value)); err != nil {
					t.Fatal(definition, err)
				}
			}
			exported[parent.Role] = map[string]any{"policy": sourceSigned(t, d.operator, "source_independent_operator", policy), "context": current, "input": text, "prepared": prepared, "grant": signed, "activation": sourceSigned(t, d.operator, "source_independent_operator", checked)}
		}
		der, err := x509.MarshalPKCS8PrivateKey(d.operator)
		if err != nil {
			t.Fatal(err)
		}
		output := map[string]any{"classification": "pre-execution signed SOURCE documents", "authoritySynthetic": true, "liveAuthorized": false, "nativeExecutable": 0, "nativeOutputCaptures": 0, "providerRequests": 0, "application": app, "case": d.caseValue, "demand": sourceSigned(t, d.operator, "source_independent_operator", d.demand), "parents": exported, "operatorPublicPEM": d.operatorPEM, "operatorPrivatePEM": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}
		path := filepath.Join(d.root, "controller-preexecution-source.json")
		d.writeOriginal(t, path, fixtureRaw(output), 0600)
		t.Log("retained SOURCE pre-execution documents", path)
	}, false, true)
}
