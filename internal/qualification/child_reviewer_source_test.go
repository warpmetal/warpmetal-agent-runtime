package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Same signed Store journey, now joined to the fixed reader's actual SQLite
// output. Operation/current backend rows remain declared SOURCE, unsigned and
// unaccepted. This deliberately calls no protected key or Producer signer.
func SourceReviewerPreparedForTest(t *testing.T, base string, store Store, box model.Sandbox, delivery model.ChildProductDelivery, w ChildProductWitness) {
	t.Helper()
	parent, directory := "ses_source_parent", filepath.Join(base, "work")
	session := map[string]any{"id": w.Entry.NativeSessionID, "projectId": w.Entry.NativeProjectID, "parentId": parent, "directory": directory, "agent": "warpmetal-managed", "model": map[string]any{"providerID": w.Entry.Authority.ProviderID, "id": *w.Entry.Authority.ModelID}}
	packet, output := filepath.Join(base, "prepared-native-source.json"), filepath.Join(base, "prepared-native-observation.json")
	if os.WriteFile(packet, canonicalBytes(map[string]any{"session": session, "receipt": w.ActualReceipt}), 0600) != nil {
		t.Fatal("SOURCE prepared selection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "python3", "-B", "testdata/reviewer_prepared_native.py", packet, output).CombinedOutput()
	if err != nil {
		t.Fatalf("SOURCE actual SQLite prepared reader: %v %s", err, raw)
	}
	raw, err = os.ReadFile(output)
	var native model.ChildPreparedCapture
	if err != nil || model.DecodePhysicalClosed(raw, &native) != nil {
		t.Fatal("SOURCE prepared observation")
	}
	st, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	identity := st.Sys().(*syscall.Stat_t)
	workspace := TrustedWorkspace{HostRoot: directory, ContainerRoot: directory, WorkspaceDigest: w.Root.Workspace.RootAttestation, Device: uint64(identity.Dev), Inode: identity.Ino}
	nativeDigest := CanonicalDigest(map[string]any{"nativeSessionId": native.Session.ID, "nativeProjectId": native.Session.ProjectID, "nativeLocationDigest": CanonicalDigest(map[string]any{"directory": directory, "projectId": native.Session.ProjectID, "workspaceId": nil}), "workspaceEpoch": w.Entry.Workspace.WorkspaceEpoch})
	var scope struct {
		Owner model.ControllerOwner `json:"owner"`
	}
	var binding struct {
		WorkID      string `json:"workId"`
		ExecutionID string `json:"executionId"`
	}
	if json.Unmarshal(w.Scope, &scope) != nil || json.Unmarshal(w.Binding, &binding) != nil {
		t.Fatal("SOURCE prepared current scope")
	}
	o := scope.Owner
	e := w.Entry
	subject := model.WorkflowRoleSubject{AccountID: o.AccountID, TaskID: o.TaskID, ServerID: o.ServerID, SandboxID: o.SandboxID, SandboxGeneration: o.SandboxGeneration, CellID: o.CellID, Role: "reviewer", ControllerID: o.ControllerID, ControllerRevision: o.ControllerRevision, AuthorityRevision: o.AuthorityRevision, ServiceRegistrationID: e.ServiceRegistrationID, ServiceGeneration: e.ServiceGeneration, NativeSessionID: e.NativeSessionID, WorkID: &binding.WorkID, ExecutionID: &binding.ExecutionID}
	op := model.WorkflowRoleOperation{FormatVersion: 1, OperationID: "wfroleop_source_prepared", Subject: subject, NativeContextDigest: nativeDigest, ManagedServiceReceiptDigest: nativeDigest, NodeTokenHash: w.Root.Producer.NodeTokenHash, ExpiresAt: e.ExecutionGrant.ExpiresAt}
	fields := childFields(canonicalBytes(op))
	delete(fields, "operationDigest")
	op.OperationDigest = CanonicalDigest(fields)
	snapshot := map[string]any{"executionState": "pending", "executionReceiptDigest": nil, "desiredState": "active", "desiredRevision": e.DesiredRevision, "managedServiceReceiptDigest": nativeDigest, "nativeContextDigest": nativeDigest, "role": "reviewer", "grants": []any{map[string]any{"grantId": e.ExecutionGrant.GrantID, "state": "issued", "fence": e.Fence, "attempt": e.Attempt}}, "children": []any{}, "effects": []any{}}
	selected := PreparedChildWorkflowRoleWitness{Authority: store, Sandbox: box, Product: w, Delivery: delivery, Receipt: *w.ActualReceipt, ParentSessionID: parent, CurrentSnapshot: canonicalBytes(snapshot), Workspace: workspace, Native: native}
	if _, err = preparedReviewerRolePayload(op, selected, time.Now()); err != nil {
		t.Fatal("SOURCE prepared reviewer tuple predicate", err)
	}
	wrong := selected
	wrong.Native.Session.ProjectID = "foreign"
	if _, err = preparedReviewerRolePayload(op, wrong, time.Now()); err == nil {
		t.Fatal("foreign actual native project admitted")
	}
	wrong = selected
	wrong.Native.Session.ParentID = "ses_other_parent"
	if _, err = preparedReviewerRolePayload(op, wrong, time.Now()); err == nil {
		t.Fatal("foreign actual native parent admitted")
	}
	snapshot["executionState"] = "running"
	snapshot["grants"] = []any{map[string]any{"grantId": e.ExecutionGrant.GrantID, "state": "consumed", "fence": e.Fence, "attempt": e.Attempt}}
	wrong = selected
	wrong.CurrentSnapshot = canonicalBytes(snapshot)
	if _, err = preparedReviewerRolePayload(op, wrong, time.Now()); err == nil {
		t.Fatal("consumed state relabeled prepared identity")
	}
	t.Log("SOURCE fixed SQLite prepared observation/current signed Store join; no backend role operation, protected signer or enrollment proof")
}

func SourceReviewerInstalledForTest(t *testing.T, w ChildProductWitness, entry model.CellServiceV3, prepare, execute ChildProductInstalledFacts) (ChildInstalledInputs, ChildInstalledInputs) {
	t.Helper()
	pre := w
	pre.Entry, pre.Assignment, pre.Binding = entry, nil, nil
	before, err := verifyChildInstalledInputs(prepare, pre, time.Now())
	if err != nil {
		t.Fatal("SOURCE observation3 before assignment", err)
	}
	after, err := verifyChildInstalledInputs(execute, w, time.Now())
	if err != nil {
		t.Fatal("SOURCE observation3 assigned reviewer", err)
	}
	wrong := execute
	wrong.Consumer.ChildProductSchemaSHA256 = "7a05be5f6af976d76e6b68495c6c31d10660348787dd62e5ea81525183e6062c"
	if _, err = verifyChildInstalledInputs(wrong, w, time.Now()); err == nil {
		t.Fatal("reviewer successor accepted prior pin")
	}
	return before, after
}

// Original backend fact transport must not import a local private read witness.
// This is the same fresh owning SOURCE tuple, with an explicit hostile extra.
func SourceReviewerOwnFieldsForTest(t *testing.T, w ChildProductWitness, installed ChildProductInstalledFacts, generation string, authority json.RawMessage, original []byte) {
	t.Helper()
	a := ChildProductAuthorityFacts{OperatorKeyID: w.OperatorKeyID, QualifiedApplicability: w.QualifiedApplicability,
		Qualification: w.Qualification, Case: w.Case, Scope: w.Scope, Intent: w.Intent, Handle: w.Handle, Root: w.Root,
		SigningNotBefore: w.SigningNotBefore, ProductSigningNotBefore: w.ProductSigningNotBefore, ActivationSigningNotBefore: w.ActivationSigningNotBefore,
		AuthorizedUntil: w.AuthorizedUntil, AcceptedPreparationEnvelope: w.AcceptedPreparationEnvelope, AcceptedDemandEnvelope: w.AcceptedDemandEnvelope}
	l := ChildProductLifecycleFacts{ActualReceipt: w.ActualReceipt, Binding: w.Binding, Assignment: w.Assignment, Grant: w.Grant, Authorization: w.Authorization}
	wire := map[string]any{"formatVersion": 1, "preparationId": w.Preparation.PreparationID, "phase": "execute", "generationDigest": generation, "authority": a, "installed": installed, "lifecycle": l}
	parse := func() error {
		f, err := model.DecodeChildProductOriginalFacts(canonicalBytes(wire))
		if err != nil {
			return err
		}
		_, _, _, err = DecodeOriginalChildProductFacts(f)
		return err
	}
	if err := parse(); err != nil {
		t.Fatal("original SOURCE fact baseline", err)
	}
	l.ArtifactReviewReads = []model.ArtifactReviewReadWitness{{Bytes: original, ArtifactAuthority: authority}}
	wire["lifecycle"] = l
	if err := parse(); err == nil {
		t.Fatal("backend original imported local ArtifactReviewReads before protected own custody")
	}
}

// Input/source foundation inside the same TLS signed Store journey. The backend
// target/lease and root registration are declared SOURCE; no ROOT signer runs.
func SourceReviewerInputsForTest(t *testing.T, base string, w ChildProductWitness, q ChildProductPolicy, detail, target, candidate, plan []byte,
	observe func(string, json.RawMessage, func(model.WorkflowCaptureOperation) string) ChildSourceReadOriginal) []model.ReviewReadWitness {
	t.Helper()
	if bytes.Equal(target, candidate) || len(target) == 0 || len(detail) == 0 {
		t.Fatal("SOURCE same-path originals missing")
	}
	var authority struct {
		Reference model.ControllerPlanReference `json:"reference"`
	}
	if json.Unmarshal(q.ArtifactReads[0], &authority) != nil || Digest(target) != authority.Reference.SourceDigest {
		t.Fatal("SOURCE target provenance")
	}
	host := filepath.Join(base, "work")
	if os.MkdirAll(filepath.Join(host, filepath.Dir(authority.Reference.Path)), 0700) != nil {
		t.Fatal("SOURCE root")
	}
	leaf := filepath.Join(host, authority.Reference.Path)
	if actual, err := os.ReadFile(leaf); err != nil || !bytes.Equal(actual, candidate) {
		t.Fatal("SOURCE candidate was not already present")
	}
	st, err := os.Stat(host)
	if err != nil {
		t.Fatal(err)
	}
	id := st.Sys().(*syscall.Stat_t)
	root := TrustedWorkspace{HostRoot: host, ContainerRoot: host, WorkspaceDigest: w.Root.Workspace.RootAttestation, Device: uint64(id.Dev), Inode: id.Ino}
	journalRoot := filepath.Join(base, "reviewer-source-foundation")
	if os.Mkdir(journalRoot, 0700) != nil {
		t.Fatal("SOURCE journal")
	}
	j := testPlanReadJournal{root: journalRoot}
	reads := []model.ReviewReadWitness{}
	for n, scope := range q.SourceReads {
		grant := childFields(scope.Grant)
		var ref model.ControllerPlanReference
		if decode(grant["reference"], &ref) != nil {
			t.Fatal("SOURCE reference")
		}
		expected := candidate
		if childString(grant, "use") == "review_packet_source" {
			expected = plan
			path := filepath.Join(host, ref.Path)
			if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, plan, 0600) != nil {
				t.Fatal("SOURCE packet")
			}
		} else if ref.Path != authority.Reference.Path {
			t.Fatal("SOURCE candidate no longer shares target path")
		}
		var read WorkflowSourceCapture
		observation := canonicalBytes(map[string]any{"type": "source_read", "reference": ref, "observedDigest": ref.SourceDigest, "byteCount": len(expected)})
		own := observe([]string{"review_plan", "review_candidate"}[n], observation, func(op model.WorkflowCaptureOperation) string {
			var err error
			read, err = captureWorkflowSource(context.Background(), op, scope, root, j)
			if err != nil || !bytes.Equal(read.Bytes, expected) {
				t.Fatal("actual SOURCE physical read", err)
			}
			return read.ObservedAt
		})
		reads = append(reads, model.ReviewReadWitness{Bytes: read.Bytes, SourceGrant: scope.Grant, NativeReceipt: canonicalBytes(own.Envelope.Payload.NativeReceipt), ReadReceipt: canonicalBytes(own.Receipt)})
	}
	if actual, err := os.ReadFile(leaf); err != nil || !bytes.Equal(actual, candidate) {
		t.Fatal("target fetch changed live candidate")
	}
	if len(w.ReviewReads) != 0 || len(w.ArtifactReviewReads) != 0 {
		t.Fatal("SOURCE fetch manufactured read ACK")
	}
	t.Log("real TLS target original remains distinct from actual same-path physical candidate; no protected producer read ACK")
	return reads
}

type sourceReviewerArtifactJournal struct{ testPlanReadJournal }

func (j sourceReviewerArtifactJournal) readArtifact(ctx context.Context, name string, count int, digest string) (reviewerPrivateRead, error) {
	st, err := os.Lstat(j.root)
	if err != nil {
		return reviewerPrivateRead{}, err
	}
	id := st.Sys().(*syscall.Stat_t)
	root := TrustedWorkspace{HostRoot: j.root, Device: uint64(id.Dev), Inode: id.Ino}
	read, err := readPlanSourceFile(ctx, root, name, count, digest)
	return reviewerPrivateRead{planFileRead: read, DirectoryDevice: root.Device, DirectoryInode: root.Inode}, err
}

// The one absent private custody capability is exercised here after actual
// signed selection; this source journal grants no ROOT signer/role authority.
func SourceReviewerCustodyForTest(t *testing.T, base string, w ChildProductWitness, c ChildProductControl, candidate []byte, fetch func(context.Context, json.RawMessage, json.RawMessage, string) (json.RawMessage, []byte, error), calls func() int,
	observe func(json.RawMessage, func(model.WorkflowCaptureOperation) string) ChildSourceReadOriginal, verify func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error) (json.RawMessage, []byte, model.ArtifactReviewReadWitness) {
	t.Helper()
	q := c.Generation.Policy.Payload
	a := childFields(q.ArtifactReads[0])
	artifact := childFields(a["artifact"])
	leaf := filepath.Join(base, "work", childString(childFields(a["reference"]), "path"))
	if Digest(candidate) == childString(artifact, "digest") || os.MkdirAll(filepath.Dir(leaf), 0700) != nil || os.WriteFile(leaf, candidate, 0600) != nil {
		t.Fatal("SOURCE same-path candidate")
	}
	observation := canonicalBytes(map[string]any{"type": "source_read", "reference": a["reference"], "observedDigest": childString(artifact, "digest"), "byteCount": childInteger(artifact, "byteCount")})
	root := filepath.Join(base, "reviewer-private-originals")
	if os.Mkdir(root, 0700) != nil {
		t.Fatal("SOURCE private journal")
	}
	j := sourceReviewerArtifactJournal{testPlanReadJournal{root: root}}
	var op model.WorkflowCaptureOperation
	var first ReviewerArtifactCapture
	original := observe(observation, func(selected model.WorkflowCaptureOperation) string {
		op = selected
		var err error
		first, err = captureReviewerArtifact(context.Background(), op, w, c, fetch, j)
		if err != nil || first.BodyDevice == 0 || first.BodyInode == 0 || calls() != 2 {
			t.Fatal("first actual private artifact read", err)
		}
		return first.ObservedAt
	})
	if verify(original.Envelope, original.Receipt) != nil {
		t.Fatal("SOURCE first signature/ACK")
	}
	if j.create("workflow-observation-"+op.OperationID+"-envelope.json", canonicalBytes(original.Envelope)) != nil || j.create("workflow-observation-receipt-"+original.Receipt.ReceiptID+".json", canonicalBytes(original)) != nil {
		t.Fatal("SOURCE first originals retention")
	}
	if err := retainReviewerArtifactOriginal(w, c, first, original, j, verify); err != nil {
		t.Fatal("private first ACK link", err)
	}
	witness, own, err := loadReviewerArtifactOriginal(context.Background(), w, c, j, verify)
	if err != nil || !bytes.Equal(witness.Bytes, first.Bytes) || !sameProduct(own, original) || !sameProduct(witness.ArtifactAuthority, q.ArtifactReads[0]) {
		t.Fatal("private first ACK read-only getter", err)
	}
	if err = retainReviewerArtifactOriginal(w, c, first, original, j, verify); err != nil {
		t.Fatal("private first ACK exact replay", err)
	}
	wrongACK := original
	wrongACK.Receipt.ExecutionID = "foreign_execution"
	if err = retainReviewerArtifactOriginal(w, c, first, wrongACK, j, verify); err == nil {
		t.Fatal("foreign receipt linked to private read")
	}
	replay, err := captureReviewerArtifact(context.Background(), op, w, c, fetch, j)
	if err != nil || !sameProduct(first, replay) || calls() != 2 {
		t.Fatal("private artifact replay changed original or fetched", err)
	}
	if actual, err := os.ReadFile(leaf); err != nil || !bytes.Equal(actual, candidate) {
		t.Fatal("private artifact read changed live candidate")
	}
	changed := c
	copyQ := q
	changed.Generation.Policy = &ChildEnvelope[ChildProductPolicy]{Payload: copyQ}
	copyAuthority := childFields(q.ArtifactReads[0])
	copyAuthority["assignmentId"] = json.RawMessage(`"foreign_assignment"`)
	changed.Generation.Policy.Payload.ArtifactReads = []json.RawMessage{canonicalBytes(copyAuthority)}
	if _, err = captureReviewerArtifact(context.Background(), op, w, changed, fetch, j); err == nil || calls() != 2 {
		t.Fatal("changed artifact authority admitted/refetched")
	}
	name := reviewerArtifactName(w, c, op)
	retained, err := j.load(name+"-detail.json", 65536)
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte(nil), first.Bytes...)
	if os.Rename(filepath.Join(root, name+"-body"), filepath.Join(root, name+"-original-retained")) != nil || os.WriteFile(filepath.Join(root, name+"-body"), body, 0600) != nil {
		t.Fatal("SOURCE replacement")
	}
	if _, err = captureReviewerArtifact(context.Background(), op, w, c, fetch, j); err == nil || calls() != 2 {
		t.Fatal("replaced private inode admitted/refetched")
	}
	if _, _, err = loadReviewerArtifactOriginal(context.Background(), w, c, j, verify); err == nil {
		t.Fatal("getter accepted replaced private inode")
	}
	partialRoot := filepath.Join(base, "reviewer-private-partial")
	if os.Mkdir(partialRoot, 0700) != nil {
		t.Fatal("SOURCE partial journal")
	}
	partial := sourceReviewerArtifactJournal{testPlanReadJournal{root: partialRoot}}
	claim, err := reviewerArtifactClaim(op, w, c)
	if err != nil || partial.create(name+"-claim.json", canonicalBytes(claim)) != nil {
		t.Fatal("SOURCE partial claim")
	}
	if _, err = captureReviewerArtifact(context.Background(), op, w, c, fetch, partial); err == nil || calls() != 2 {
		t.Fatal("partial first claim retried")
	}
	foreignRoot := filepath.Join(base, "reviewer-private-foreign")
	if os.Mkdir(foreignRoot, 0700) != nil {
		t.Fatal("SOURCE foreign journal")
	}
	foreign := sourceReviewerArtifactJournal{testPlanReadJournal{root: foreignRoot}}
	if _, err = captureReviewerArtifact(context.Background(), op, w, c, func(context.Context, json.RawMessage, json.RawMessage, string) (json.RawMessage, []byte, error) {
		return json.RawMessage(retained), []byte("altered original"), nil
	}, foreign); err == nil {
		t.Fatal("foreign artifact body retained")
	}
	t.Log("SOURCE first private artifact body/identity, exact zero-GET replay, foreign authority and replaced-file refusal")
	return retained, body, witness
}

// Detached SOURCE export only: exact first TLS/producer originals already
// observed above. The ROOT Enrich/publish path is deliberately not bypassed.
func SourceReviewerCustodyBundleForTest(t *testing.T, base string, w ChildProductWitness, c ChildProductControl) []byte {
	t.Helper()
	load := func(label string) ChildSourceReadOriginal {
		raw, err := os.ReadFile(filepath.Join(base, "source-observation-"+label+".json"))
		var own ChildSourceReadOriginal
		if err != nil || decode(raw, &own) != nil {
			t.Fatal("SOURCE first own read original", err)
		}
		return own
	}
	own := ReviewerReadOriginals{Physical: []ChildSourceReadOriginal{load("review_plan"), load("review_candidate")}, Artifact: load("reviewer_target")}
	bundle, err := reviewerCustodyOriginals(w, c, own)
	if err != nil {
		t.Fatal("SOURCE fixed bundle originals", err)
	}
	return canonicalBytes(bundle)
}

// Reopen the same actual private read/fence/ACK and prepared SQLite originals.
// Only the owning reader's explicit clock argument advances; no signed date,
// native event, current grant or retained byte is rewritten.
func SourceReviewerACKReopenForTest(t *testing.T, base string, store Store, box model.Sandbox, delivery model.ChildProductDelivery, w ChildProductWitness, verify func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error) {
	t.Helper()
	var c ChildProductControl
	if decode(delivery.Bytes(), &c) != nil {
		t.Fatal("SOURCE reopen control")
	}
	scope := c.Generation.Policy.Payload.SourceReads[0]
	raw, err := os.ReadFile(filepath.Join(base, "source-observation-review_plan.json"))
	var own ChildSourceReadOriginal
	if err != nil || decode(raw, &own) != nil || verify(own.Envelope, own.Receipt) != nil {
		t.Fatal("SOURCE first ACK", err)
	}
	j := testPlanReadJournal{root: filepath.Join(base, "reviewer-source-foundation")}
	// Explicit SOURCE counterpart of the existing private retained link. Producer
	// signature and node ACK are the actual first originals from this TLS journey.
	if j.create("workflow-observation-"+own.Envelope.Payload.OperationID+"-envelope.json", canonicalBytes(own.Envelope)) != nil || j.create("workflow-observation-receipt-"+own.Receipt.ReceiptID+".json", canonicalBytes(own)) != nil {
		t.Fatal("SOURCE ACK first retention")
	}
	link := reviewerNativeLink{EntryDigest: CanonicalDigest(w.Entry), GenerationDigest: delivery.GenerationDigest(), OperationID: own.Envelope.Payload.OperationID, ReceiptID: own.Receipt.ReceiptID, ScopeDigest: CanonicalDigest(scope)}
	if j.create("reviewer-native-"+w.Preparation.PreparationID+"-"+CanonicalDigest(scope.Grant)[7:]+".json", canonicalBytes(link)) != nil {
		t.Fatal("SOURCE link")
	}
	original, err := loadReviewerNativeRead(w, delivery.GenerationDigest(), scope, time.Now(), j.load, verify)
	if err != nil {
		t.Fatal("SOURCE first own receipt baseline", err)
	}
	before, err := os.ReadFile(filepath.Join(base, "prepared-native-source.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "python3", "-B", "testdata/reviewer_prepared_native.py", filepath.Join(base, "prepared-native-source.json"), filepath.Join(base, "prepared-native-reopened.json"), "--reopen").CombinedOutput()
	if err != nil {
		t.Fatalf("SOURCE same SQLite reopen: %v %s", err, output)
	}
	after, err := os.ReadFile(filepath.Join(base, "prepared-native-source.sqlite"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("SOURCE reopen changed native DATA")
	}
	expires, err := time.Parse(time.RFC3339Nano, own.Envelope.Payload.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	now := expires.Add(time.Nanosecond)
	reopenedStore := store
	if _, err = reopenedStore.ReadChildProduct(box, w.Preparation.PreparationID, w, now); err != nil {
		t.Fatal("current policy/grant/assignment was not live at historical read checkpoint", err)
	}
	reopenedJournal := testPlanReadJournal{root: j.root}
	replay, err := loadReviewerNativeRead(w, delivery.GenerationDigest(), scope, now, reopenedJournal.load, verify)
	if err != nil || !sameProduct(original, replay) {
		t.Fatal("independently ACKed historical physical read refused on same-state reopen", err)
	}
	missingACK := func(name string, limit int) ([]byte, error) {
		if name == "workflow-observation-receipt-"+own.Receipt.ReceiptID+".json" {
			return nil, os.ErrNotExist
		}
		return reopenedJournal.load(name, limit)
	}
	if _, err = loadReviewerNativeRead(w, delivery.GenerationDigest(), scope, now, missingACK, verify); err == nil {
		t.Fatal("unACKed expired read accepted")
	}
	t.Log("SOURCE same SQLite/private journals reopened unchanged; retained first ACK accepted after capture expiry only while current signed control remains live")
}
