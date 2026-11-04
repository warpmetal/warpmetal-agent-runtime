package qualification

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Same retained real-activation journey, extended through actual signed file
// selection. Only ancestor UID and enrolled configuration are SOURCE suppliers;
// signatures, bytes, no-follow/modes and native/source identities stay real.
func testSignedNativeQualificationSource(t *testing.T) {
	input := os.Getenv("WARPMETAL_QUALIFICATION_NATIVE_SOURCE")
	base := os.Getenv("WARPMETAL_RUNTIME_GATE_SOURCE_EVIDENCE")
	if os.Getenv("WARPMETAL_QUALIFICATION_ROOT_PRODUCER_SOURCE") != "" {
		base = os.Getenv("WARPMETAL_ROOT_SOURCE_EVIDENCE")
	}
	var packet struct {
		OperatorPublicPEM string                                                             `json:"operatorPublicPEM"`
		ProducerPublicPEM string                                                             `json:"producerPublicPEM"`
		Authority         json.RawMessage                                                    `json:"authority"`
		EnrolledProducer  *QualificationProducerIdentity                                     `json:"enrolledProducer,omitempty"`
		Publications      map[string]struct{ Digest, ContentBase64, SignatureBase64 string } `json:"publications"`
		PreparedReceipt   *model.PreparedReceipt                                             `json:"preparedReceipt"`
		ExecutionGrant    json.RawMessage                                                    `json:"executionGrant"`
	}
	raw, err := os.ReadFile(filepath.Join(input, "native-sidecars.json"))
	if err != nil || json.Unmarshal(raw, &packet) != nil {
		t.Fatal("native SOURCE packet", err)
	}
	var originals struct {
		Actual struct {
			ServerID     string                `json:"serverId"`
			CellServices []model.CellServiceV3 `json:"cellServices"`
		} `json:"actualExecuteManifestHTTP"`
		Blobs map[string]string `json:"blobs"`
	}
	raw, err = os.ReadFile(filepath.Join(input, "originals.json"))
	if err != nil || json.Unmarshal(raw, &originals) != nil || len(originals.Actual.CellServices) != 1 {
		t.Fatal("actual backend source entry", err)
	}
	bootBytes, _ := base64.StdEncoding.DecodeString(packet.Publications["bootstrap"].ContentBase64)
	policyBytes, _ := base64.StdEncoding.DecodeString(packet.Publications["policy"].ContentBase64)
	activationBytes, _ := base64.StdEncoding.DecodeString(packet.Publications["activation"].ContentBase64)
	var boot Bootstrap
	var policy Policy
	var activation struct {
		IssuedAt string `json:"issuedAt"`
	}
	if json.Unmarshal(bootBytes, &boot) != nil || json.Unmarshal(policyBytes, &policy) != nil || json.Unmarshal(activationBytes, &activation) != nil || policy.Run == nil {
		t.Fatal("source decoder")
	}
	at, err := time.Parse(time.RFC3339Nano, activation.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	independentProducer, sourceAllocation := qualificationNativeSourceParticipant(t, input, packet.Authority, packet.EnrolledProducer, []byte(packet.ProducerPublicPEM), []byte(packet.OperatorPublicPEM), boot, policy, originals.Actual.CellServices[0], originals.Actual.ServerID, at)
	root, err := os.MkdirTemp(base, "qualification-native3-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("RETAINED_SOURCE_ROOT", root)
	store := SourceBoundaryStoreForTest(root, uint32(os.Getuid()))
	store.sourceProducerIdentity = &independentProducer
	var rootProducer *Producer
	if source := os.Getenv("WARPMETAL_QUALIFICATION_ROOT_PRODUCER_SOURCE"); source != "" {
		rootProducer = qualificationRootSourceProducer(t, source, root, independentProducer)
		store = Store{Root: root, MappedUID: 0, ProducerConfig: &rootProducer.config, ProducerServerID: rootProducer.config.ServerID, ProducerNodeTokenHash: rootProducer.config.NodeTokenHash}
		at = time.Now().UTC()
	}
	box := model.Sandbox{ID: boot.SandboxID, Generation: boot.SandboxGeneration, ImageDigest: boot.ImageDigest, Cell: true}
	tree, key, err := store.Paths(box.ID)
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, raw []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0400); err != nil {
			t.Fatal(err)
		}
	}
	write(key, []byte(packet.OperatorPublicPEM))
	for label, pub := range packet.Publications {
		body, e := base64.StdEncoding.DecodeString(pub.ContentBase64)
		if e != nil || Digest(body) != pub.Digest {
			t.Fatal("source original", label)
		}
		sig, e := base64.StdEncoding.DecodeString(pub.SignatureBase64)
		if e != nil {
			t.Fatal(e)
		}
		name := "bootstrap"
		if label == "policy" {
			name = "snapshots/" + pub.Digest[7:] + "/policy"
		}
		if label == "activation" {
			name = "activations/" + policy.Preparations[0].PreparationID
		}
		write(filepath.Join(tree, name+".json"), body)
		write(filepath.Join(tree, name+".sig"), sig)
	}
	plugin, err := os.ReadFile(os.Getenv("WARPMETAL_QUALIFICATION_PLUGIN_SOURCE"))
	if err != nil || Digest(plugin) != boot.PluginSHA256 {
		t.Fatal("exact signed plugin source", err)
	}
	write(filepath.Join(tree, "plugin", "index.ts"), plugin)
	d := Descriptor{1, policy.Preparations[0].PreparationID, policy.PreparedTupleDigest, packet.Publications["policy"].Digest}
	write(filepath.Join(tree, "preparations", d.PreparationID+".json"), canonicalBytes(d))
	for digest, value := range originals.Blobs {
		body, e := base64.StdEncoding.DecodeString(value)
		if e != nil || Digest(body) != digest {
			t.Fatal("source blob", digest)
		}
		write(filepath.Join(tree, "blobs", digest[7:]), body)
	}
	if err = os.MkdirAll(filepath.Join(tree, "revocations"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = filepath.WalkDir(tree, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return os.Chmod(path, 0500)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	selectedBoot, err := store.Bootstrap(box, box.ImageDigest, at)
	if err != nil {
		t.Fatal("signed Bootstrap3 selection", err)
	}
	wrong := store
	wrong.sourceProducerIdentity = nil
	wrong.ProducerConfig = nil
	if _, err = wrong.Bootstrap(box, box.ImageDigest, at); err == nil {
		t.Fatal("sidecar producer self-enrollment accepted")
	}
	entry := originals.Actual.CellServices[0]
	_, selectedPolicy, selectedDescriptor, err := store.SelectedPolicy(box, entry, policy.Preparations[0].Workspace, at)
	if err != nil {
		t.Fatal("signed Policy4/current execute selection", err)
	}
	selected, err := store.ReadQualificationActivation(box, selectedBoot, selectedPolicy, selectedDescriptor, at)
	if err != nil || selected.Native == nil || selected.Execution.FormatVersion != 2 || selected.Execution.PolicyDigest == selectedDescriptor.PolicyDigest || selected.Publication.Digest != packet.Publications["activation"].Digest {
		t.Fatal("unchanged native/source activation join", err)
	}
	if packet.PreparedReceipt != nil {
		var original ChildEnvelope[QualificationAuthorizationObservation]
		if json.Unmarshal(selected.Native.AuthorizationObservation, &original) != nil {
			t.Fatal("original header envelope")
		}
		observedAt, err := time.Parse(time.RFC3339Nano, original.Payload.ObservedAt)
		if err != nil {
			t.Fatal(err)
		}
		// SOURCE pre-prepare view of the same immutable tuple; it supplies no new
		// authority and cannot sign. Real current-phase selection remains Podman.
		prepareEntry := entry
		prepareEntry.LifecyclePhase, prepareEntry.ExecutionGrant, prepareEntry.PreparedReceiptDigest = "prepare", nil, nil
		producer := &Producer{config: ProducerConfig{KeyID: independentProducer.KeyID, KeySHA256: independentProducer.KeySHA256, ServerID: independentProducer.ServerID, NodeTokenHash: independentProducer.NodeTokenHash}}
		current, err := producer.PrepareQualificationAuthorization(store, box, prepareEntry, *packet.PreparedReceipt, policy.Preparations[0].Workspace, observedAt)
		if err != nil || current.ValidateObservation(original.Payload, at) != nil {
			t.Fatal("signed pre-activation header context", err)
		}
		wrong := original.Payload
		wrong.NativeInputID = "msg_foreign"
		if current.ValidateObservation(wrong, at) == nil {
			t.Fatal("foreign native header admitted")
		}
		var outer struct {
			SchemaVersion     int                                   `json:"schemaVersion"`
			Command           string                                `json:"command"`
			Status            string                                `json:"status"`
			HeaderObservation QualificationAuthorizationObservation `json:"headerObservation"`
		}
		wire := canonicalBytes(map[string]any{"schemaVersion": 1, "command": "qualification-header", "status": "observed", "headerObservation": original.Payload})
		if model.DecodeControllerTransportReceipt(wire, "qualification-header", &outer) != nil {
			t.Fatal("closed qualification header consumer")
		}
		t.Log("SOURCE current signed policy+receipt header validation passed; protected root signer/durability remains Linux-only")
	}
	observations, err := os.ReadFile(os.Getenv("WARPMETAL_QUALIFICATION_OBSERVATIONS_SOURCE"))
	if err != nil {
		t.Fatal(err)
	}
	collected, err := ParseObservations(observations)
	if err != nil {
		t.Fatal("actual collector Observations2 decoder", err)
	}
	if sourceAllocation == nil {
		// Preserve the old collector's explicitly unsigned SOURCE projection.
		// The participant branch instead requires its original signed demand.
		selected.PhysicalAllocation = &DemandAllocation{Kind: "qualification", TupleDigest: policy.Run.TupleDigest, PreparationOrdinal: selected.Execution.PreparationIndex, ModelRequests: 2, FirstPhysicalIndex: 2, LastPhysicalIndex: 3}
	} else {
		selected.PhysicalAllocation = sourceAllocation
	}
	evidencePolicy, modelID, firstPhysical, err := qualificationObservationBinding(selectedPolicy, selectedDescriptor, selected, collected)
	if err != nil || evidencePolicy != selectedPolicy.SourcePolicy.Digest || modelID != "deepseek-flash" || firstPhysical != selected.PhysicalAllocation.FirstPhysicalIndex {
		t.Fatal("collector native/source evidence identities", err)
	}
	wrongObservations := collected
	wrongObservations.SourcePolicyDigest = selectedDescriptor.PolicyDigest
	if _, _, _, err = qualificationObservationBinding(selectedPolicy, selectedDescriptor, selected, wrongObservations); err == nil {
		t.Fatal("native/source policy digests conflated")
	}
	testQualificationToolProjectionSource(t, selectedPolicy, selectedDescriptor, selected, collected)
	if rootProducer != nil {
		testRootQualificationToolImport(t, rootProducer, selectedPolicy, selectedDescriptor, selected, collected, packet.ExecutionGrant)
	}
	t.Log("SOURCE actual signed originals+protected file reader; old clock frozen, enrolled identity/ancestor UID detached; native/provider calls0")
}

// Fixture preflight only. enrolled must come from the owning current backend
// producer_config(task,node), independently of both publication and inventory.
// No key is generated, and this does not bypass the subsequent Store selector.
func qualificationNativeSourceParticipant(t *testing.T, input string, authority json.RawMessage, enrolled *QualificationProducerIdentity, public, operator []byte, boot Bootstrap, policy Policy, entry model.CellServiceV3, server string, at time.Time) (QualificationProducerIdentity, *DemandAllocation) {
	t.Helper()
	fields := childFields(authority)
	if childInteger(fields, "formatVersion") != 5 {
		var old struct{ Producer ProducerConfig }
		if json.Unmarshal(authority, &old) != nil {
			t.Fatal("legacy SOURCE producer decoder")
		}
		// Preserve the original old19 supplier and digest convention exactly.
		return QualificationProducerIdentity{old.Producer.KeyID, "sha256:" + old.Producer.KeySHA256, server, old.Producer.NodeTokenHash}, nil
	}
	if workflowcontract.Validate(workflowcontract.BudgetParticipants, "authority5", authority) != nil || boot.Case == nil || boot.Case.FormatVersion != 5 || !sameProduct(fields["case"], *boot.Case) || CanonicalDigest(fields["participantInventory"]) != boot.Case.ParticipantInventoryDigest || enrolled == nil || enrolled.ServerID != server || Digest(public) != enrolled.KeySHA256 || boot.Producer == nil || *boot.Producer != *enrolled || policy.Run == nil {
		t.Fatal("authority5 SOURCE publication/independent enrolled producer mismatch")
	}
	if _, err := qualificationPublicKey(public); err != nil {
		t.Fatal("independent SOURCE producer public key", err)
	}
	publicationPublic, err := qualificationBase64(boot.ProducerPublicKeyBase64, 4096)
	if err != nil || !bytes.Equal(publicationPublic, public) {
		t.Fatal("SOURCE bootstrap public key differs from independently enrolled producer")
	}
	tuple := policy.Run.Tuple
	scope := model.ControllerOwner{AccountID: tuple.AccountID, TaskID: tuple.TaskID, ServerID: server, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration, CellID: entry.OwnerCellID, ControllerID: entry.ControllerID, ControllerRevision: entry.ControllerRevision, AuthorityRevision: entry.AuthorityRevision}
	if tuple.ServerID != server || tuple.SandboxID != entry.SandboxID || tuple.SandboxGeneration != entry.SandboxGeneration || boot.SandboxID != entry.SandboxID || boot.SandboxGeneration != entry.SandboxGeneration || policy.Run.TupleDigest != CanonicalDigest(tuple) {
		t.Fatal("SOURCE publication/actual execute task server scope mismatch")
	}
	var inventory struct{ Participants []json.RawMessage }
	if json.Unmarshal(fields["participantInventory"], &inventory) != nil {
		t.Fatal("SOURCE participant inventory decoder")
	}
	matches := 0
	for _, raw := range inventory.Participants {
		var part struct {
			ParticipantID, AccountID, TaskID, ServerID string
			Producer                                   struct{ KeyID, KeySHA256, NodeTokenHash, PublicKeyBase64 string }
			Scopes                                     []model.ControllerOwner
		}
		if json.Unmarshal(raw, &part) != nil {
			t.Fatal("SOURCE participant decoder")
		}
		identity := childFields(raw)
		delete(identity, "participantId")
		if CanonicalDigest(identity) != part.ParticipantID {
			t.Fatal("SOURCE participant identity digest")
		}
		for _, candidate := range part.Scopes {
			if candidate != scope {
				continue
			}
			matches++
			key, err := qualificationBase64(part.Producer.PublicKeyBase64, 4096)
			if err != nil || !bytes.Equal(key, public) || part.AccountID != scope.AccountID || part.TaskID != scope.TaskID || part.ServerID != scope.ServerID || part.Producer.KeyID != enrolled.KeyID || "sha256:"+part.Producer.KeySHA256 != enrolled.KeySHA256 || part.Producer.NodeTokenHash != enrolled.NodeTokenHash {
				t.Fatal("selected SOURCE participant differs from actual producer_config export")
			}
		}
	}
	if matches != 1 {
		t.Fatal("SOURCE task/server/full scope did not select exactly one enrolled participant")
	}
	demandRaw, err := os.ReadFile(filepath.Join(input, "demand-envelope.json"))
	var demand ChildEnvelope[DemandManifest]
	operatorFields := childFields(fields["operator"])
	if err != nil || workflowcontract.Validate(workflowcontract.BudgetParticipants, "demandManifestEnvelope", demandRaw) != nil || json.Unmarshal(demandRaw, &demand) != nil || Digest(operator) != boot.Case.OperatorKeySHA256 || verifyChildEnvelope(demandRaw, childString(operatorFields, "keyId"), operator) != nil || demand.Payload.validate(*boot.Case, at) != nil {
		t.Fatal("SOURCE original signed participant demand unavailable or mismatched", err)
	}
	var allocation *DemandAllocation
	for _, candidate := range demand.Payload.AllocationList {
		if candidate.Kind == "qualification" && candidate.Scope == scope && candidate.TupleDigest == policy.Run.TupleDigest {
			if allocation != nil {
				t.Fatal("ambiguous SOURCE qualification allocation")
			}
			copy := candidate
			allocation = &copy
		}
	}
	if allocation == nil || allocation.ModelRequests != 2 || allocation.AccessRequests != 0 || allocation.LastPhysicalIndex != allocation.FirstPhysicalIndex+1 {
		t.Fatal("SOURCE qualification has no exact signed two-request outer allocation")
	}
	return *enrolled, allocation
}

// Diagnose the collector-to-import contract before the separately gated root
// signer. This derives no signed evidence or authority; the artifact is SOURCE.
func testQualificationToolProjectionSource(t *testing.T, policy Policy, d Descriptor, selected QualificationActivation, o Observations) {
	t.Helper()
	blobs := map[string][]byte{}
	for id, value := range o.Blobs {
		raw, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || Digest(raw) != id {
			t.Fatal("original collector blob", err)
		}
		blobs[id] = raw
	}
	original := string(blobs[o.Tool.ObservationDigest])
	workspace := CanonicalDigest(map[string]string{"sourceWorkspace": "qualification-root-component"})
	observation, err := qualificationToolImportObservation(policy, d, selected, o, workspace, blobs)
	if err != nil {
		t.Fatal("SOURCE canonical tool projection", err)
	}
	if string(blobs[o.Tool.ObservationDigest]) != original || Digest(blobs[o.Tool.OutputDigest]) != o.Tool.OutputDigest {
		t.Fatal("hook original lost or backend output blob missing")
	}
	blobs[Digest(observation)] = observation
	artifact := []byte("qualification")
	if Digest(artifact) != policy.Run.Workload.ExpectedArtifactSHA256 {
		t.Fatal("SOURCE artifact differs from signed workload")
	}
	blobs[Digest(artifact)] = artifact
	terminal := canonicalBytes(map[string]string{"artifact": policy.Run.Workload.ArtifactRelativePath, "sha256": Digest(artifact)})
	blobs[Digest(terminal)] = terminal
	tool := qualificationCashTool{ToolCallID: o.Tool.CallID, Tool: "shell", ArgumentsDigest: o.Tool.ArgumentsDigest, WorkspaceDigest: workspace, ArtifactRelativePath: policy.Run.Workload.ArtifactRelativePath, ArtifactDigest: Digest(artifact), ArtifactSize: len(artifact), TerminalJSONDigest: Digest(terminal), ToolObservationDigest: Digest(observation)}
	fields := childFields(canonicalBytes(tool))
	delete(fields, "outcomeDigest")
	outcome := canonicalBytes(fields)
	tool.OutcomeDigest = Digest(outcome)
	blobs[tool.OutcomeDigest] = outcome
	get := func(id string, limit int) ([]byte, error) {
		b, ok := blobs[id]
		if !ok || len(b) > limit || Digest(b) != id {
			return nil, ErrUntrusted
		}
		return b, nil
	}
	jsonGet := func(id string, limit int) (map[string]json.RawMessage, error) {
		b, err := get(id, limit)
		var v map[string]json.RawMessage
		if err != nil || decode(b, &v) != nil {
			return nil, ErrUntrusted
		}
		return v, nil
	}
	requests, responses := []map[string]json.RawMessage{}, []map[string]json.RawMessage{}
	for _, r := range o.Requests {
		a, ae := jsonGet(r.RequestDigest, 32768)
		b, be := jsonGet(r.ResponseDigest, 262144)
		if ae != nil || be != nil {
			t.Fatal("original request/response missing")
		}
		requests, responses = append(requests, a), append(responses, b)
	}
	if err := verifyQualificationCashTool(qualificationCashEvidence{PreparationID: d.PreparationID, Requests: o.Requests, ToolOutcome: tool}, requests, responses, get, jsonGet); err != nil {
		t.Fatal("SOURCE projection rejected by owning tool import", err)
	}
	t.Log("SOURCE canonical10+derived output blob→owning tool import; original hook preserved; no root signer/native/provider/full financial import")
}
