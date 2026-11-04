package qualification

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Same signed control/actual file/loopback capture journey. This tests signature
// and historical/current predicates, not protected root custody or signing.
func SourceCompletedFactsHistoryForTest(t *testing.T, base string, w ChildProductWitness, control ChildProductControl, capture model.ChildNativeIntegrationCapture) {
	t.Helper()
	var packet struct {
		ProducerPrivatePEM, OperatorPEM []byte
		Execute                         json.RawMessage
	}
	raw, err := os.ReadFile(filepath.Join(base, "fixture.json"))
	if err != nil || json.Unmarshal(raw, &packet) != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(packet.ProducerPrivatePEM)
	if block == nil {
		t.Fatal("SOURCE producer key absent")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.(*ecdsa.PrivateKey)
	e := w.Entry
	now := time.Now().UTC()
	outcome := "succeeded"
	report := model.CellServiceReportV1{FormatVersion: 3, OperationID: e.OperationID, ActionRevision: e.ActionRevision, ObservedDesiredRevision: e.DesiredRevision, ServiceRegistrationID: e.ServiceRegistrationID, ServiceGeneration: e.ServiceGeneration, ObservedState: "ready", DesiredState: "active", OwnerCellID: e.OwnerCellID, OwnerRole: e.OwnerRole, OwnerGeneration: e.OwnerGeneration, SandboxID: e.SandboxID, SandboxGeneration: e.SandboxGeneration, Fence: e.Fence, Instance: e.Instance, Role: e.Role, NativeSessionID: e.NativeSessionID, NativeProjectID: e.NativeProjectID, WorkspaceEpoch: e.WorkspaceEpoch, Attempt: e.Attempt, ReceiptDigest: CanonicalDigest(capture), Child: &model.ManagedCellChildV1{OperationID: e.LaunchOperationID, SessionID: e.NativeSessionID, MessageID: capture.Native.InputID, State: "terminal", Attempt: e.Attempt, Outcome: &outcome}}
	nativeDigest := CanonicalDigest(map[string]any{"nativeSessionId": e.NativeSessionID, "nativeProjectId": e.NativeProjectID, "nativeLocationDigest": capture.Native.NativeLocationDigest, "workspaceEpoch": e.WorkspaceEpoch})
	snapshot := canonicalBytes(map[string]any{"executionState": "completed", "executionReceiptDigest": report.ReceiptDigest, "desiredState": "active", "desiredRevision": e.DesiredRevision, "managedServiceReceiptDigest": nativeDigest, "nativeContextDigest": nativeDigest, "role": e.Role, "grants": []any{map[string]any{"grantId": e.ExecutionGrant.GrantID, "state": "consumed", "fence": e.Fence, "attempt": e.Attempt}}, "children": []any{}, "effects": []any{}})
	original := childFactsOriginals{Native: ChildWorkflowNativeCapture{Integration: &capture}, Current: snapshot, Execution: &state.LocalCellV3Execution{PreparationID: e.PreparationID, Grant: *e.ExecutionGrant, Phase: "terminal", ParentSessionID: "ses_source_parent", WorktreeDir: filepath.Join(base, "work"), Report: report}}
	back := map[string]any{"nativeSessionId": e.NativeSessionID, "nativeRole": e.Role, "snapshotDigest": Digest(snapshot), "quiescent": true, "effectsComplete": true, "descendantsComplete": true}
	native := model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: "wfop_source_first_completed", OperationDigest: Digest([]byte("SOURCE first completed operation")), ServiceRegistrationID: e.ServiceRegistrationID, ServiceGeneration: e.ServiceGeneration, NativeSessionID: e.NativeSessionID, NativeProjectID: e.NativeProjectID, NativeLocationDigest: capture.Native.NativeLocationDigest, Role: e.Role, RootAttestation: w.Root.Workspace.RootAttestation, ObservedAt: now.Format(time.RFC3339Nano), Readback: canonicalBytes(back)}
	back["nativeReceiptDigest"] = CanonicalDigest(native)
	first := model.WorkflowFactsEnvelope{KeyID: w.Root.Producer.KeyID, Payload: model.WorkflowFactsPayload{FormatVersion: 1, Purpose: "workspace_workflow_facts", RequestID: "source_first_completed", TaskID: w.Applicability.TaskID, NodeTokenHash: w.Root.Producer.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: native.ObservedAt, NotAfter: now.Add(30 * time.Second).Format(time.RFC3339Nano), ManagedServiceReceiptDigest: nativeDigest, NativeReceipt: native, OperationID: native.OperationID, OperationDigest: native.OperationDigest, Binding: control.Generation.Policy.Payload.Binding, Readback: canonicalBytes(back)}}
	sum := sha256.Sum256(canonicalBytes(first.Payload))
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	first.Signature = base64.StdEncoding.EncodeToString(sig)
	evidence := canonicalBytes(original)
	for name, value := range map[string][]byte{"completed-first-source-envelope.json": canonicalBytes(first), "completed-first-source-originals.json": evidence} {
		if err = os.WriteFile(filepath.Join(base, name), value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	loaded, when, err := verifyCompletedFactsOriginal(first, evidence, &key.PublicKey, w.Root.Producer, e)
	if err != nil || !when.Equal(now) {
		t.Fatal("real SOURCE first signature/original", err)
	}
	historical, err := VerifyChildProductControl(packet.Execute, w, packet.OperatorPEM, when)
	if err != nil || !sameProduct(historical, control) {
		t.Fatal("original signed control at first signed observation", err)
	}
	expired, err := time.Parse(time.RFC3339Nano, e.ExecutionGrant.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	expired = expired.Add(time.Second)
	if _, err = VerifyChildProductControl(packet.Execute, w, packet.OperatorPEM, expired); err == nil {
		t.Fatal("active signed policy accepted after dispatch expiry")
	}
	h := ChildCompletedFactsHistory{first: first, originals: loaded, product: w, control: historical}
	current := model.ChildCompletedCapture{FormatVersion: 1, Purpose: "child_completed_state", PreparedReceipt: *w.ActualReceipt, Grant: *e.ExecutionGrant, Native: capture.Native, DatabaseDevice: 1, DatabaseInode: 2, ObservedAt: expired.Format(time.RFC3339Nano)}
	current.Session = model.ChildNativeSession{ID: e.NativeSessionID, ProjectID: e.NativeProjectID, ParentID: original.Execution.ParentSessionID, Directory: original.Execution.WorktreeDir, Agent: "warpmetal-managed"}
	current.Session.Model.ProviderID = e.Authority.ProviderID
	current.Session.Model.ID = *e.Authority.ModelID
	if _, _, _, err = completedNativeMatches(h, current, expired); err != nil {
		t.Fatal("completed historical/current SOURCE join", err)
	}
	for name, mutate := range map[string]func(*model.ChildCompletedCapture){"pending_input": func(c *model.ChildCompletedCapture) { c.Native.Current.PendingInboxIDs = []string{"foreign_pending"} }, "changed_input": func(c *model.ChildCompletedCapture) { c.Native.InputID = "foreign_input" }, "changed_fence": func(c *model.ChildCompletedCapture) { c.Grant.Fence = "foreign_fence" }} {
		bad := current
		mutate(&bad)
		if _, _, _, err = completedNativeMatches(h, bad, expired); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	bad := first
	bad.Payload.Binding = canonicalBytes(map[string]any{"foreign": "binding"})
	if _, _, err = verifyCompletedFactsOriginal(bad, evidence, &key.PublicKey, w.Root.Producer, e); err == nil {
		t.Fatal("altered signed binding accepted")
	}
	changed := original
	changed.Current = canonicalBytes(map[string]any{"changed": "snapshot"})
	if _, _, err = verifyCompletedFactsOriginal(first, canonicalBytes(changed), &key.PublicKey, w.Root.Producer, e); err == nil {
		t.Fatal("altered first original accepted")
	}
	bad = first
	bad.Signature = base64.StdEncoding.EncodeToString([]byte("wrong original signature"))
	if _, _, err = verifyCompletedFactsOriginal(bad, evidence, &key.PublicKey, w.Root.Producer, e); err == nil {
		t.Fatal("changed first signature accepted")
	}
	leaf := filepath.Join(base, "work", capture.Artifact.SourcePath)
	before, err := os.ReadFile(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(leaf, []byte("SOURCE later integrated mutable afterimage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = completedNativeMatches(h, current, expired); err != nil {
		t.Fatal("settlement reread mutable historical artifact", err)
	}
	if err = os.WriteFile(filepath.Join(base, "completed-historical-artifact.body"), before, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(base, "completed-current-source-observation.json"), canonicalBytes(current), 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("SOURCE real first signature/files + unchanged signed control historical validation; active expiry denial; changed binding/signature/original/fence/pending input denied; completed-state settlement predicate independent of mutable artifact. Protected ROOT producer unrun.")
}
