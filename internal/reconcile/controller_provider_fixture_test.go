package reconcile

// Fresh SOURCE publication supplier for the additive provider contract. The
// accepted application is produced by the existing TLS/SQLite journey; installed
// artifacts, native preparation and financial authority remain named synthetic
// suppliers. No native output is invented, no old signed body is retagged.
import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func sourceObject(v any) map[string]any { return v.(map[string]any) }

func TestControllerProviderPreExecutionSourceFixtureExport(t *testing.T) {
	runControllerProviderPreExecutionSourceFixtureExport(t, nil)
}

func runControllerProviderPreExecutionSourceFixtureExport(t *testing.T, after func(*managerPolicyJourney, *parentSourceRuntime, *firstTaskPublicDeliveryFixture, map[string]any)) {
	seedPath := os.Getenv("WARPMETAL_PROVIDER_SOURCE_SHAPES")
	if seedPath == "" || os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE") == "" || os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET") == "" {
		t.Skip("explicit fresh provider SOURCE shape supplier and destination required")
	}
	selection := &model.WorkspaceModelSelection{Authority: model.CellPreparedAuthorityV3{ProviderID: "deepseek", ModelID: "deepseek-flash", AuthMode: "api_key"}, CredentialBinding: &model.CellCredentialBindingV3{ConnectionID: "source_flash_connection", ConnectionRevision: 1, ProviderID: "deepseek", AuthMode: "api_key"}}
	runControllerParentSourceJourneyAccepted(t, false, false, selection, func(j *managerPolicyJourney, native *parentSourceRuntime, app model.WorkspaceApplicationOperation, parents []model.ControllerParentIntent) {
		if after == nil {
			j.reconciler.Now = func() time.Time { return time.Now().UTC() }
		}
		now := native.now()
		stamp, expiry := now.Format(time.RFC3339Nano), now.Add(30*time.Minute).Format(time.RFC3339Nano)
		raw, err := os.ReadFile(os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET"))
		if err != nil {
			t.Fatal(err)
		}
		var predecessor map[string]any
		if json.Unmarshal(raw, &predecessor) != nil {
			t.Fatal("SOURCE context supplier missing")
		}
		base := sourceObject(sourceObject(predecessor["specimens"].([]any)[1])["context"])
		f := &firstTaskChildTerminalFixture{t: t, r: j.reconciler, deliveryParents: map[string]firstTaskDeliveryParent{}}
		f.configurePublicDeliveryDocumentBase(t, native, app, base)
		d := f.delivery
		raw, err = os.ReadFile(seedPath)
		if err != nil {
			t.Fatal(err)
		}
		var seed map[string]any
		if json.Unmarshal(raw, &seed) != nil || seed["authoritySynthetic"] != true || seed["liveAuthorized"] != false {
			t.Fatal("fresh declared SOURCE authority required")
		}
		authority, demand := sourceObject(seed["authority"]), sourceObject(seed["demand"])
		caseValue := sourceObject(authority["case"])
		caseID := "source_flash_" + filepath.Base(d.root)
		policyDigest := authority["providerPolicyDigest"]
		caseManifest := model.WorkspaceDigest(map[string]any{"classification": "declared SOURCE artifacts; no installed authority", "applicationOperationDigest": app.OperationDigest, "sourceRoot": d.root})
		for _, value := range []map[string]any{authority, demand, caseValue} {
			value["caseId"], value["caseManifestDigest"] = caseID, caseManifest
		}
		authority["evidenceRoot"] = d.evidence
		authority["operator"] = map[string]any{"keyId": "source_independent_operator", "keyPath": "/SOURCE/independent-operator-not-runtime.pem", "keySHA256": qualification.Digest(d.operatorPEM)[7:]}
		authority["producer"] = map[string]any{"keyId": app.Producer.KeyID, "keyPath": filepath.Join(d.root, "source-producer.pem"), "keySHA256": app.Producer.KeySHA256[7:], "nodeTokenHash": app.Producer.NodeTokenHash}
		authority["profileBundleDigest"] = app.Dependencies.Roles[0].Projection.ApprovedProfile.BundleDigest
		setupRecipeDigest := ""
		for _, setup := range j.manifest.SetupOperations {
			if setup.ID == parents[0].Profile.SetupOperationID && setup.Materializer.Bin != nil && setup.Materializer.Artifact != nil {
				setupRecipeDigest = model.WorkspaceDigest(setup.Materializer)
				authority["native"] = map[string]any{"version": setup.Materializer.Bin.Version, "binarySHA256": "sha256:" + strings.TrimPrefix(setup.Materializer.Bin.SHA256, "sha256:"), "archiveSHA256": "sha256:" + strings.TrimPrefix(setup.Materializer.Artifact.SHA256, "sha256:")}
			}
		}
		if setupRecipeDigest == "" {
			t.Fatal("independent current SOURCE setup recipe absent")
		}
		// New declared SOURCE candidate before any digest/signature is made.
		// Binary/archive hashes remain explicitly synthetic, never self proof.
		sourceObject(authority["runtime"])["version"] = "0.1.54-e2.1"
		if pluginSource := os.Getenv("WARPMETAL_CONTROLLER_PLUGIN_SOURCE"); pluginSource != "" {
			pluginBytes, err := os.ReadFile(pluginSource)
			if err != nil {
				t.Fatal(err)
			}
			sourceObject(authority["sandbox"])["pluginDigest"] = qualification.Digest(pluginBytes)
		}
		artifacts := map[string]any{}
		for _, name := range []string{"backend", "native", "runtime", "sandbox", "profileBundleDigest"} {
			artifacts[name] = authority[name]
		}
		inventory := sourceObject(authority["tupleInventory"])
		inventory["caseId"], inventory["candidateInventoryDigest"], inventory["observedAt"] = caseID, model.WorkspaceDigest(artifacts), stamp
		demand["candidateInventoryDigest"] = inventory["candidateInventoryDigest"]
		demand["declaredAt"], demand["notAfter"] = now.Add(-time.Second).Format(time.RFC3339Nano), expiry
		demand["accountScopeDigest"] = model.WorkspaceDigest(map[string]any{"classification": "SOURCE account scope", "accountId": parents[0].Owner.AccountID})
		parentByRole := map[string]model.ControllerParentIntent{}
		for _, p := range parents {
			parentByRole[p.Role] = p
		}
		parentFor := func(name string) model.ControllerParentIntent {
			if name == "foreman" || name == "followup" {
				return parentByRole["orchestrator"]
			}
			return parentByRole["manager"]
		}
		consumerByName := map[string]map[string]any{}
		seenConsumers := map[string]bool{}
		tuples := inventory["tuples"].([]any)
		for index, item := range tuples {
			tuple := sourceObject(item)
			a := sourceObject(tuple["applicability"])
			for _, name := range []string{"backend", "native", "runtime", "sandbox"} {
				a[name] = authority[name]
			}
			scope := publicDeliveryMap(parents[0].Owner)
			if index == 1 {
				scope["sandboxId"], scope["cellId"], scope["controllerId"] = "sbx_source_declared_peer", "cell_source_declared_peer", "controller_source_declared_peer"
			}
			for _, field := range []string{"accountId", "taskId", "serverId", "sandboxId", "sandboxGeneration"} {
				a[field] = scope[field]
			}
			a["caseManifestDigest"], a["connection"] = caseManifest, selection.CredentialBinding
			a["profile"] = map[string]any{"setupOperationId": parents[0].Profile.SetupOperationID, "profileId": parents[0].Profile.ProfileID, "revision": parents[0].Profile.ProfileRevision, "profileDigest": parents[0].Profile.ProfileDigest, "materializerDigest": setupRecipeDigest, "bundleDigest": authority["profileBundleDigest"]}
			sourceObject(a["model"])["adapterVersion"] = "source-controller-adapter"
			tuple["tupleDigest"] = model.WorkspaceDigest(a)
			var uniqueConsumers []any
			for _, consumerValue := range tuple["consumers"].([]any) {
				consumer := sourceObject(consumerValue)
				consumer["scope"], consumer["profile"], consumer["credentialBinding"], consumer["authority"] = scope, parents[0].Profile, selection.CredentialBinding, selection.Authority
				if index == 0 && consumer["kind"] == "parent" {
					p := parentFor(consumer["name"].(string))
					consumer["sourceId"], consumer["scope"], consumer["configurationDigest"] = p.ServiceRegistrationID, p.Owner, app.ConfigurationDigest
				} else {
					consumer["sourceId"] = "declared_" + consumer["name"].(string) + "_" + filepath.Base(d.root)
				}
				// Repeated stage allocations share one service consumer. Keep
				// their name lookup separately before immutable inventory signing.
				consumerByName[consumer["name"].(string)] = consumer
				id := consumer["sourceId"].(string)
				if !seenConsumers[id] {
					uniqueConsumers = append(uniqueConsumers, consumer)
					seenConsumers[id] = true
				}
			}
			tuple["consumers"] = uniqueConsumers
		}
		allocations := demand["allocations"].([]any)
		allocationByName := map[string]map[string]any{}
		for _, item := range allocations {
			a := sourceObject(item)
			name := a["name"].(string)
			index := 0
			if strings.HasPrefix(name, "peer_") {
				index = 1
			}
			tuple := sourceObject(tuples[index])
			a["tupleDigest"] = tuple["tupleDigest"]
			consumerName := name
			if name == "primary_access" {
				consumerName = "primary_qual"
			} else if name == "peer_access" {
				consumerName = "peer_qual"
			}
			c := consumerByName[consumerName]
			if c == nil {
				t.Fatal("SOURCE allocation consumer absent", name)
			}
			a["scope"], a["sourceId"] = c["scope"], c["sourceId"]
			a["scopeDigest"] = model.WorkspaceDigest(a["scope"])
			allocationByName[name] = a
		}
		demand["tupleInventoryDigest"] = model.WorkspaceDigest(inventory)
		caseValue["tupleInventoryDigest"], caseValue["demandManifestDigest"], caseValue["operatorKeySHA256"] = demand["tupleInventoryDigest"], model.WorkspaceDigest(demand), qualification.Digest(d.operatorPEM)
		for definition, value := range map[string]any{"authority3": authority, "demandManifest": demand, "typedCase": caseValue} {
			if err := workflowcontract.Validate(workflowcontract.BudgetProvider, definition, fixtureRaw(value)); err != nil {
				t.Fatal(definition, err)
			}
		}
		exported := map[string]any{}
		writeSigned := func(path string, payload any) {
			envelope := publicDeliveryMap(sourceSigned(t, d.operator, "source_independent_operator", payload))
			sig, err := base64.StdEncoding.DecodeString(envelope["signature"].(string))
			if err != nil {
				t.Fatal(err)
			}
			d.writeOriginal(t, path+".json", fixtureRaw(payload), 0400)
			d.writeOriginal(t, path+".sig", sig, 0400)
		}
		if os.Getenv("WARPMETAL_PROVIDER_STORE_GATE") == "1" {
			writeSigned(filepath.Join(d.tree, "snapshots", caseValue["demandManifestDigest"].(string)[7:], "demand"), demand)
			if err := os.Chmod(d.tree, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(d.tree, "revocations"), 0500); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(d.tree, 0500); err != nil {
				t.Fatal(err)
			}
		}
		for _, parent := range parents {
			w, err := j.reconciler.controllerActivityCurrentWitness(context.Background(), parent.ServiceRegistrationID, qualification.Applicability{}, false)
			if err != nil {
				t.Fatal("fresh accepted SOURCE application witness", err)
			}
			n, err := w.Installed.Identity.DeriveWM8NativeIdentity()
			if err != nil {
				t.Fatal(err)
			}
			association := map[string]any{"formatVersion": 1, "normalization": model.ControllerWM8Normalization, "application": w.Installed.Application, "materializer": map[string]any{"declaredDigest": app.MaterializerDigest, "installedDigest": w.Installed.WorkspaceMaterializerDigest, "closureVersion": "warpmetal-workspace-content-v1"}, "applicationIdentity": w.Installed.Identity, "applicationIdentityDigest": model.WorkspaceDigest(w.Installed.Identity), "nativeIdentity": n, "nativeIdentityDigest": model.WorkspaceDigest(n)}
			association["associationDigest"] = model.WorkspaceDigest(association)
			var paired model.ControllerIdentityAssociation
			publicDeliveryDecode(t, association, &paired)
			if err := paired.ValidateAccepted(app, w.Installed.Application.ApplicationID, w.Installed.Application.ReceiptDigest, app.MaterializerDigest, n); err != nil {
				t.Fatal(err)
			}
			name := "manager_initial"
			if parent.Role == "orchestrator" {
				name = "foreman"
			}
			a := allocationByName[name]
			policy := map[string]any{"formatVersion": 6, "targetKind": "controller_activity", "mode": "real_provider", "purpose": "controller_activity", "case": caseValue, "applicability": sourceObject(tuples[0])["applicability"], "allocationId": a["allocationId"], "expiresAt": expiry, "identityAssociation": association, "providerPolicyDigest": policyDigest, "accountingVersion": 2}
			text := "Explicit DeepSeek Flash SOURCE instruction; no native output or external call supplied."
			prepared := sourceControllerPreparedShape(n.Intent, app, *w.Parent.Report.NativeRegistration, "source_flash_input_"+parent.Role, text)
			current := publicDeliveryMap(base)
			for k, v := range map[string]any{"formatVersion": 3, "contextId": "source_context_" + parent.Role, "workflowRequestId": "source_request_" + parent.Role, "preparationId": prepared.PreparationID, "caseId": caseID, "caseManifestDigest": caseManifest, "demandManifestDigest": caseValue["demandManifestDigest"], "policyDigest": model.WorkspaceDigest(policy), "inputId": prepared.PreparedTuple.InputID, "inputDigest": prepared.PreparedTuple.InputDigest, "allocationId": a["allocationId"], "preparationOrdinal": a["preparationOrdinal"], "physicalIndex": a["firstPhysicalIndex"], "identityAssociationDigest": association["associationDigest"], "providerPolicyDigest": policyDigest} {
				current[k] = v
			}
			if parent.Role == "orchestrator" {
				current["target"] = map[string]any{"kind": "advice", "role": "orchestrator", "resourceId": nil, "advice": nil}
			}
			current["contextDigest"] = fixtureDigestField(current, "contextDigest")
			modelIndex := 1
			for _, item := range allocations {
				prior := sourceObject(item)
				if prior["lastPhysicalIndex"].(float64) < a["firstPhysicalIndex"].(float64) {
					modelIndex += int(prior["modelRequests"].(float64))
				}
			}
			grant := model.ControllerActivityGrant{FormatVersion: 1, TargetKind: "controller_activity", GrantID: "source_grant_" + parent.Role, PreparationID: prepared.PreparationID, PreparedReceiptDigest: prepared.PreparedReceiptDigest, ReservationID: "source_reservation_" + parent.Role, CaseID: caseID, CaseManifestDigest: caseManifest, PolicyDigest: current["policyDigest"].(string), RequestIndex: modelIndex, PhysicalIndex: int(a["firstPhysicalIndex"].(float64)), MaxInputTokens: 1000, MaxOutputTokens: 1000, MaxUSDMicros: 421000, DeadlineAt: now.Add(110 * time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(115 * time.Second).Format(time.RFC3339Nano)}
			signedGrant := sourceSigned(t, d.operator, "source_independent_operator", grant)
			activation := map[string]any{"formatVersion": 4, "targetKind": "controller_activity", "mode": "real_provider", "purpose": "controller_activity", "policyDigest": current["policyDigest"], "admission": map[string]any{"formatVersion": 1, "targetKind": "controller_activity", "preparedReceipt": prepared, "grant": grant}, "grantEnvelopeDigest": model.WorkspaceDigest(signedGrant), "authorizationSha256": model.WorkspaceDigest("source-header-" + parent.Role), "preparationIndex": a["preparationOrdinal"], "allocationId": a["allocationId"], "demandManifestDigest": caseValue["demandManifestDigest"], "contextDigest": current["contextDigest"], "issuedAt": stamp, "identityAssociationDigest": association["associationDigest"], "providerPolicyDigest": policyDigest, "accountingVersion": 2}
			for definition, value := range map[string]any{"controllerPolicy6": policy, "controllerActivation4": activation, "approvedContext3": current} {
				if err := workflowcontract.Validate(workflowcontract.ControllerProvider, definition, fixtureRaw(value)); err != nil {
					t.Fatal(definition, err)
				}
			}
			if os.Getenv("WARPMETAL_PROVIDER_STORE_GATE") == "1" {
				writeSigned(filepath.Join(d.tree, "snapshots", current["policyDigest"].(string)[7:], "policy"), policy)
				writeSigned(filepath.Join(d.tree, "activations", "controller-"+prepared.PreparationID, "activation"), activation)

			}
			exported[parent.Role] = map[string]any{"policy": sourceSigned(t, d.operator, "source_independent_operator", policy), "context": current, "input": text, "prepared": prepared, "grant": signedGrant, "activation": sourceSigned(t, d.operator, "source_independent_operator", activation), "sourceNativeSession": map[string]any{"id": n.Source.Source.NativeSessionID, "agent": n.Projection.NativeAgentID, "location": map[string]any{"directory": native.roots[parent.Instance], "projectId": n.Source.Source.NativeProjectID, "workspaceId": nil}}, "sourceAuthorizationHeader": string(fixtureRaw("source-header-" + parent.Role))}
		}
		der, err := x509.MarshalPKCS8PrivateKey(d.operator)
		if err != nil {
			t.Fatal(err)
		}
		output := map[string]any{"classification": "Fresh pre-execution signed SOURCE publication; declared artifacts, peer, qualifications, child allocations and native preparation are synthetic, not installed authority", "authoritySynthetic": true, "liveAuthorized": false, "nativeExecutable": 0, "nativeOutputCaptures": 0, "providerRequests": 0, "application": app, "authority": authority, "case": caseValue, "demand": sourceSigned(t, d.operator, "source_independent_operator", demand), "parents": exported, "operatorPublicPEM": d.operatorPEM, "operatorPrivatePEM": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}
		path := filepath.Join(d.root, "controller-provider-preexecution-source.json")
		d.writeOriginal(t, path, fixtureRaw(output), 0600)
		t.Log("retained fresh signed SOURCE provider publications", path)
		if after != nil {
			after(j, native, d, output)
		}
	}, false, true)
}
