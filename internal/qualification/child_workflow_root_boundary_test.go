package qualification_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Explicit root-only continuation of the existing signed Store/native-file
// journey. NewProducer, private key ownership, real signature/replay journal and
// TLS client are real. Native DATA, installed identity and local lifecycle report
// are SOURCE suppliers; this does not claim a built Podman/normal-Reconcile run.
func TestChildWorkflowRoleProtectedRootSource(t *testing.T) {
	packet := os.Getenv("WARPMETAL_CHILD_ROLE_ROOT_PACKET")
	if packet == "" {
		t.Skip("requires manager-approved root-only SOURCE bundle")
	}
	if os.Geteuid() != 0 {
		t.Fatal("ROOT source gate must use real root ownership; no test bypass")
	}
	base := os.Getenv("WARPMETAL_ROOT_SOURCE_EVIDENCE")
	if !filepath.IsAbs(base) {
		t.Fatal("fresh root SOURCE evidence absent")
	}
	root, err := os.MkdirTemp(base, "child-role-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained ROOT_SOURCE_PRIVATE_ARTIFACTS", root)
	var f struct {
		AuthoritySynthetic bool                              `json:"authoritySynthetic"`
		LiveAuthorized     bool                              `json:"liveAuthorized"`
		Prepare            json.RawMessage                   `json:"prepare"`
		Execute            json.RawMessage                   `json:"execute"`
		Witness            qualification.ChildProductWitness `json:"witness"`
		PrepareEntry       model.CellServiceV3               `json:"prepareEntry"`
		OperatorPEM        []byte                            `json:"operatorPEM"`
		ProducerPrivatePEM []byte                            `json:"producerPrivatePEM"`
	}
	raw, err := os.ReadFile(packet)
	if err != nil || json.Unmarshal(raw, &f) != nil || !f.AuthoritySynthetic || f.LiveAuthorized || len(f.ProducerPrivatePEM) == 0 {
		t.Fatal("fresh SOURCE identity packet refused", err)
	}
	w := f.Witness
	proofRaw, err := os.ReadFile(os.Getenv("WARPMETAL_CHILD_ROLE_ROOT_CAPTURE"))
	if err != nil {
		t.Fatal(err)
	}
	capture, err := model.DecodeChildNativeResultCapture(proofRaw)
	if err != nil {
		t.Fatal(err)
	}
	store := qualification.Store{Root: filepath.Join(root, "control"), MappedUID: 0}
	tree, key, err := store.Paths(w.Applicability.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Dir(key), filepath.Join(tree, "preparations")} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(key, f.OperatorPEM, 0400); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{tree, filepath.Join(tree, "preparations")} {
		if err = os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
	}
	box := model.Sandbox{ID: w.Applicability.SandboxID, Generation: w.Applicability.SandboxGeneration, Cell: true}
	prepare, err := model.DecodeChildProductDelivery(f.Prepare)
	if err != nil {
		t.Fatal(err)
	}
	execute, err := model.DecodeChildProductDelivery(f.Execute)
	if err != nil {
		t.Fatal(err)
	}
	pw := w
	pw.Entry = f.PrepareEntry
	pw.ActualReceipt = nil
	pw.Grant = nil
	pw.Authorization = nil
	pw.AcceptedPreparationEnvelope = nil
	pw.AcceptedDemandEnvelope = nil
	if err = store.AdoptChildProduct(box, prepare, pw, time.Now()); err != nil {
		t.Fatal("root signed prepare", err)
	}
	if err = store.AdoptChildProduct(box, execute, w, time.Now()); err != nil {
		t.Fatal("root signed execute", err)
	}
	private := filepath.Join(root, "producer")
	if err = os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(private, "producer.pem")
	if err = os.WriteFile(keyPath, f.ProducerPrivatePEM, 0400); err != nil {
		t.Fatal(err)
	}
	registered := w.Root.Producer
	config := qualification.ProducerConfig{KeyID: registered.KeyID, KeyPath: keyPath, KeySHA256: registered.KeySHA256, EvidenceRoot: private, ServerID: registered.ServerID, NodeTokenHash: registered.NodeTokenHash}
	producer, err := qualification.NewProducer(&config, registered.ServerID, registered.NodeTokenHash)
	if err != nil {
		t.Fatal("actual protected NewProducer", err)
	}
	entry := w.Entry
	outcome := "succeeded"
	// Detached current lifecycle SOURCE supplier, independently corroborated by
	// the native consumed-grant/result capture. Never claim this as Runtime STATE.
	report := model.CellServiceReportV1{FormatVersion: 3, OperationID: entry.OperationID, ActionRevision: entry.ActionRevision, ObservedDesiredRevision: entry.DesiredRevision, ServiceRegistrationID: entry.ServiceRegistrationID, ObservedState: "ready", DesiredState: "active", OwnerCellID: entry.OwnerCellID, OwnerRole: entry.OwnerRole, OwnerGeneration: entry.OwnerGeneration, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration, ServiceGeneration: entry.ServiceGeneration, Fence: entry.Fence, Instance: entry.Instance, Role: entry.Role, NativeSessionID: capture.Native.SessionID, NativeProjectID: capture.Native.NativeProjectID, WorkspaceEpoch: entry.WorkspaceEpoch, Attempt: entry.Attempt, ReceiptDigest: qualification.Digest(proofRaw), Child: &model.ManagedCellChildV1{OperationID: entry.LaunchOperationID, SessionID: capture.Native.SessionID, MessageID: capture.Native.InputID, State: "terminal", Attempt: entry.Attempt, Outcome: &outcome}}
	native := map[string]any{"nativeSessionId": report.NativeSessionID, "nativeProjectId": report.NativeProjectID, "nativeLocationDigest": capture.Native.NativeLocationDigest, "workspaceEpoch": report.WorkspaceEpoch}
	nativeDigest := model.WorkspaceDigest(native)
	snapshot, _ := json.Marshal(map[string]any{"executionState": "completed", "executionReceiptDigest": report.ReceiptDigest, "desiredState": "active", "desiredRevision": entry.DesiredRevision, "managedServiceReceiptDigest": nativeDigest, "nativeContextDigest": nativeDigest, "role": "worker", "grants": []any{map[string]any{"grantId": w.Grant.GrantID, "state": "consumed", "fence": entry.Fence, "attempt": entry.Attempt}}, "children": []any{}, "effects": []any{}})
	var scope struct {
		Owner model.ControllerOwner `json:"owner"`
	}
	var binding struct {
		WorkID      string `json:"workId"`
		ExecutionID string `json:"executionId"`
	}
	if json.Unmarshal(w.Scope, &scope) != nil || json.Unmarshal(w.Binding, &binding) != nil {
		t.Fatal("owning scope")
	}
	o := scope.Owner
	subject := model.WorkflowRoleSubject{AccountID: o.AccountID, TaskID: o.TaskID, ServerID: o.ServerID, SandboxID: o.SandboxID, SandboxGeneration: o.SandboxGeneration, CellID: o.CellID, Role: "worker", ControllerID: o.ControllerID, ControllerRevision: o.ControllerRevision, AuthorityRevision: o.AuthorityRevision, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, WorkID: &binding.WorkID, ExecutionID: &binding.ExecutionID}
	op := model.WorkflowRoleOperation{FormatVersion: 1, OperationID: "wfroleop_root_child_source", Subject: subject, NativeContextDigest: nativeDigest, ManagedServiceReceiptDigest: nativeDigest, NodeTokenHash: registered.NodeTokenHash, ExpiresAt: time.Now().Add(90 * time.Second).UTC().Format(time.RFC3339Nano)}
	opRaw, _ := json.Marshal(op)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(opRaw, &fields)
	delete(fields, "operationDigest")
	op.OperationDigest = model.WorkspaceDigest(fields)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer synthetic-node" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "" {
			t.Error("node-only capture transport changed")
			rw.WriteHeader(403)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" && r.URL.Path == "/internal/runtime/workspace-workflow-observations/executions/"+binding.ExecutionID+"/current-snapshot" {
			_, _ = rw.Write(snapshot)
			return
		}
		if r.Method == "POST" && r.URL.Path == "/internal/runtime/workspace-workflow/enrollment-operations" {
			var call model.WorkflowRoleOperationRequest
			if json.NewDecoder(r.Body).Decode(&call) != nil || !reflect.DeepEqual(call.Subject, subject) {
				t.Error("role original changed")
				rw.WriteHeader(409)
				return
			}
			_ = json.NewEncoder(rw).Encode(op)
			return
		}
		t.Error("unexpected role source dispatch", r.Method, r.URL.Path)
		rw.WriteHeader(404)
	}))
	defer server.Close()
	client := api.Client{Origin: server.URL, NodeToken: "synthetic-node", HTTP: server.Client()}
	current, err := client.WorkflowCurrentSnapshot(context.Background(), binding.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	received, err := client.WorkflowRoleEnrollmentOperation(context.Background(), model.WorkflowRoleOperationRequest{FormatVersion: 1, RequestID: "role_root_source_operation", Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(filepath.Dir(packet), "work")
	stat, err := os.Stat(work)
	if err != nil {
		t.Fatal(err)
	}
	identity := stat.Sys().(*syscall.Stat_t)
	witness := qualification.ChildWorkflowRoleWitness{Authority: store, Sandbox: box, Product: w, ExecutionReport: report, ConsumedGrant: *w.Grant, CurrentSnapshot: current, Result: capture, Workspace: qualification.TrustedWorkspace{HostRoot: work, ContainerRoot: work, WorkspaceDigest: w.Root.Workspace.RootAttestation, Device: uint64(identity.Dev), Inode: uint64(identity.Ino)}}
	wrong := witness
	wrong.ExecutionReport.NativeSessionID = "ses_foreign_source"
	if _, err = producer.AttestChildWorkflowRole(received, wrong, time.Now()); err == nil {
		t.Fatal("foreign local execution signed")
	}
	envelope, err := producer.AttestChildWorkflowRole(received, witness, time.Now())
	if err != nil {
		t.Fatal("actual root child role signing", err)
	}
	replayed, err := producer.AttestChildWorkflowRole(received, witness, time.Now())
	if err != nil || !reflect.DeepEqual(replayed, envelope) {
		t.Fatal("first role envelope changed on replay", err)
	}
	block, _ := pem.Decode(w.ProducerPEM)
	if block == nil {
		t.Fatal("producer public PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	public := parsed.(*ecdsa.PublicKey)
	body, _ := model.WorkspaceCanonicalJSON(envelope.Payload)
	sum := sha256.Sum256(body)
	sig, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || !ecdsa.VerifyASN1(public, sum[:], sig) || envelope.Validate() != nil || !reflect.DeepEqual(envelope.Payload.Subject, subject) || calls != 2 {
		t.Fatal("actual role signature/transport join failed", err)
	}
	t.Log("actual root-only producer/key/journal/signature/replay and TLS2 GREEN; native/installed/lifecycle suppliers remain SOURCE, normal child enrollment not claimed")
}
