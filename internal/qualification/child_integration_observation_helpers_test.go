package qualification

import (
	"context"
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func sourceIntegrationRoot(t *testing.T, base string, w ChildProductWitness) TrustedWorkspace {
	t.Helper()
	host := filepath.Join(base, "work")
	s, e := os.Stat(host)
	if e != nil {
		t.Fatal(e)
	}
	id := s.Sys().(*syscall.Stat_t)
	return TrustedWorkspace{HostRoot: host, ContainerRoot: host, WorkspaceDigest: w.Root.Workspace.RootAttestation, Device: uint64(id.Dev), Inode: id.Ino}
}

// Same actual confined reader/fence; authority/signatures remain SOURCE.
func SourceIntegrationReadForTest(t *testing.T, base string, w ChildProductWitness, c ChildProductControl, scope ChildSourceReadScope, op model.WorkflowCaptureOperation) WorkflowSourceCapture {
	t.Helper()
	root := sourceIntegrationRoot(t, base, w)
	j := testPlanReadJournal{root: filepath.Join(base, "integration-stage-originals")}
	grant := childFields(scope.Grant)
	ref := childFields(grant["reference"])
	if childString(grant, "use") == "integration_packet_source" {
		var packet struct {
			Originals struct {
				Packet []byte `json:"packetBase64"`
			} `json:"integrationOriginals"`
		}
		raw, e := os.ReadFile(filepath.Join(base, "fixture.json"))
		if e != nil || json.Unmarshal(raw, &packet) != nil {
			t.Fatal(e)
		}
		leaf := filepath.Join(root.HostRoot, childString(ref, "path"))
		if os.MkdirAll(filepath.Dir(leaf), 0700) != nil {
			t.Fatal("SOURCE source parent")
		}
		if e = os.WriteFile(leaf, packet.Originals.Packet, 0600); e != nil {
			t.Fatal(e)
		}
	}
	read, e := captureWorkflowSource(context.Background(), op, scope, root, j)
	if e != nil || childSourceInputMatches(w, c, scope, read.Bytes) != nil {
		t.Fatal("SOURCE exact confined input read", e)
	}
	return read
}
func SourceIntegrationCustodyForTest(t *testing.T, base string, w ChildProductWitness, c ChildProductControl, reads []ChildSourceReadOriginal, captures []WorkflowSourceCapture, verify func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error) []byte {
	t.Helper()
	j := testPlanReadJournal{root: filepath.Join(base, "integration-stage-originals")}
	if len(reads) != len(c.Generation.Policy.Payload.SourceReads) || len(reads) != len(captures) {
		t.Fatal("own read count")
	}
	for i, scope := range c.Generation.Policy.Payload.SourceReads {
		o := reads[i]
		r := captures[i]
		if verify(o.Envelope, o.Receipt) != nil || childSourceOriginalMatches(w, c, scope, r, o) != nil {
			t.Fatal("SOURCE first original join")
		}
		link := childSourceLink{EntryDigest: CanonicalDigest(w.Entry), GenerationDigest: c.Descriptor.GenerationDigest, InputID: w.Instructions.InputID, InputDigest: Digest(w.Input), ScopeDigest: CanonicalDigest(scope), OperationID: o.Envelope.Payload.OperationID, ReceiptID: o.Receipt.ReceiptID}
		for name, value := range map[string]any{childSourceLinkName(w, c, scope): link, "workflow-observation-receipt-" + o.Receipt.ReceiptID + ".json": o, "workflow-observation-" + o.Envelope.Payload.OperationID + "-envelope.json": o.Envelope} {
			if e := j.create(name, canonicalBytes(value)); e != nil {
				t.Fatal(e)
			}
		}
		actual, e := loadChildSourceOriginal(w, c, scope, j.load, verify)
		if e != nil || !sameProduct(actual, o) {
			t.Fatal("SOURCE first read/fence/signature/ACK reload", e)
		}
	}
	raw, e := j.load(integrationStageName(w, c)+".json", 65536)
	var stage integrationStage
	if e != nil || decode(raw, &stage) != nil {
		t.Fatal(e)
	}
	d := c.Generation.Policy.Payload.IntegrationDelivery
	return canonicalBytes(childIntegrationCustody{GenerationDigest: c.Descriptor.GenerationDigest, EntryDigest: CanonicalDigest(w.Entry), InputID: d.InputID, InputDigest: d.InputDigest, DeliveryPlanDigest: d.DeliveryPlanDigest, Stage: stage, SourceReads: reads})
}
func SourceIntegrationObservationForTest(t *testing.T, base string, w ChildProductWitness, c ChildProductControl, capture model.ChildNativeIntegrationCapture, verify func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error) json.RawMessage {
	t.Helper()
	j := testPlanReadJournal{root: filepath.Join(base, "integration-stage-originals")}
	name := integrationStageName(w, c)
	raw, e := j.load(name+".json", 65536)
	var stage integrationStage
	if e != nil || decode(raw, &stage) != nil {
		t.Fatal(e)
	}
	detail, e := j.load(name+"-target.json", 65536)
	if e != nil {
		t.Fatal(e)
	}
	before, e := j.load(name+"-target.body", 8192)
	if e != nil {
		t.Fatal(e)
	}
	reads := []ChildSourceReadOriginal{}
	for _, scope := range c.Generation.Policy.Payload.SourceReads {
		o, e := loadChildSourceOriginal(w, c, scope, j.load, verify)
		if e != nil {
			t.Fatal("retained own SOURCE ACK", e)
		}
		reads = append(reads, o)
	}
	root := sourceIntegrationRoot(t, base, w)
	got, e := integrationObservationValue(context.Background(), w, c, root, capture, stage, detail, before, reads)
	if e != nil {
		t.Fatal("closed current integration observation", e)
	}
	// The new request readout uses the same retained before originals and current
	// after read as the later attester. Source metadata/signature suppliers are
	// explicit; this never invokes or bypasses the protected Producer.
	loaded, proof, e := loadIntegrationObservation(context.Background(), w, c, root, capture, reads, j.load)
	if e != nil || !sameProduct(loaded, got) || len(proof) == 0 {
		t.Fatal("owner-derived SOURCE readout differs from current observation", e)
	}
	if _, _, e = loadIntegrationObservation(context.Background(), w, c, root, capture, reads, func(name string, bound int) ([]byte, error) {
		if name == integrationStageName(w, c)+"-target.body" {
			return nil, os.ErrNotExist
		}
		return j.load(name, bound)
	}); e == nil {
		t.Fatal("readout manufactured missing retained before-image")
	}
	if _, e = integrationObservationValue(context.Background(), w, c, root, capture, stage, detail, before, reads[:len(reads)-1]); e == nil {
		t.Fatal("missing own ACK accepted")
	}
	bad := stage
	bad.SourceDigest = Digest([]byte("foreign before"))
	if _, e = integrationObservationValue(context.Background(), w, c, root, capture, bad, detail, before, reads); e == nil {
		t.Fatal("foreign before accepted")
	}
	badCapture := capture
	badCapture.Artifact.Digest = Digest([]byte("foreign after"))
	if _, e = integrationObservationValue(context.Background(), w, c, root, badCapture, stage, detail, before, reads); e == nil {
		t.Fatal("foreign after accepted")
	}
	changed := c
	policy := *c.Generation.Policy
	policy.Payload = *(&c.Generation.Policy.Payload)
	changed.Generation.Policy = &policy
	policy.Payload.IntegrationDelivery = nil
	if _, e = integrationObservationValue(context.Background(), w, changed, root, capture, stage, detail, before, reads); e == nil {
		t.Fatal("changed current control accepted")
	}
	// The target writer must refuse the changed after-image; terminal verification
	// above succeeds by reading immutable before originals and the actual after.
	if _, e = stageIntegrationTarget(context.Background(), w, c, root, detail, before, j, uint32(os.Getuid())); e == nil {
		t.Fatal("after-image was mistaken for original target")
	}
	t.Log("closed SOURCE current target/before/after/own ACK checks pass; missing ACK/foreign before/after/current control deny")
	return loaded
}
