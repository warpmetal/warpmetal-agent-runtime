package qualification

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Extends the same closed real-qualification journey with the actual backend
// signed demand/capability and current readback, with only ancestor UID detached.
func testSignedQualificationAccessSource(t *testing.T) {
	input := os.Getenv("WARPMETAL_QUALIFICATION_ACCESS_SOURCE")
	read := func(name string) []byte {
		t.Helper()
		raw, e := os.ReadFile(filepath.Join(input, name))
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	var packet struct {
		OperatorPublicPEM string                                    `json:"operatorPublicPEM"`
		Publications      map[string]struct{ ContentBase64 string } `json:"publications"`
	}
	if json.Unmarshal(read("native-sidecars.json"), &packet) != nil {
		t.Fatal("sidecar SOURCE decode")
	}
	bb, _ := base64.StdEncoding.DecodeString(packet.Publications["bootstrap"].ContentBase64)
	pb, _ := base64.StdEncoding.DecodeString(packet.Publications["policy"].ContentBase64)
	var boot Bootstrap
	var policy Policy
	if json.Unmarshal(bb, &boot) != nil || json.Unmarshal(pb, &policy) != nil || boot.Case == nil || policy.Run == nil {
		t.Fatal("source scope")
	}
	var context model.QualificationAccessContext
	if model.DecodePhysicalClosed(read("access-context.json"), &context) != nil {
		t.Fatal("access2 decoder")
	}
	var demand struct {
		Payload   json.RawMessage `json:"payload"`
		Signature string          `json:"signature"`
	}
	if json.Unmarshal(read("demand-envelope.json"), &demand) != nil {
		t.Fatal("demand original")
	}
	at, e := time.Parse(time.RFC3339Nano, childString(childFields(demand.Payload), "declaredAt"))
	if e != nil {
		t.Fatal(e)
	}
	at = at.Add(time.Second)
	root, e := os.MkdirTemp(os.Getenv("WARPMETAL_RUNTIME_GATE_SOURCE_EVIDENCE"), "qualification-access2-")
	if e != nil {
		t.Fatal(e)
	}
	t.Log("RETAINED_SOURCE_ROOT", root)
	store := SourceBoundaryStoreForTest(root, uint32(os.Getuid()))
	box := model.Sandbox{ID: boot.SandboxID, Generation: boot.SandboxGeneration, Cell: true}
	tree, key, e := store.Paths(box.ID)
	if e != nil {
		t.Fatal(e)
	}
	write := func(path string, raw []byte) {
		t.Helper()
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, raw, 0400); e != nil {
			t.Fatal(e)
		}
	}
	write(key, []byte(packet.OperatorPublicPEM))
	dir := filepath.Join(tree, "snapshots", boot.Case.DemandManifestDigest[7:])
	sig, e := base64.StdEncoding.DecodeString(demand.Signature)
	if e != nil {
		t.Fatal(e)
	}
	write(filepath.Join(dir, "demand.json"), canonicalBytes(demand.Payload))
	write(filepath.Join(dir, "demand.sig"), sig)
	if e = filepath.WalkDir(tree, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return os.Chmod(path, 0500)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	capability := read("access-capability.json")
	if _, err := store.ReadTypedDemand(box, *boot.Case, at); err != nil {
		t.Fatal("original signed demand reader", err)
	}
	if err := context.Validate(context.QualificationID, at); err != nil {
		t.Fatal("current access2 at original demand time", err)
	}
	var envelope struct {
		Payload json.RawMessage `json:"payload"`
		KeyID   string          `json:"keyId"`
	}
	_ = json.Unmarshal(capability, &envelope)
	if err := verifyChildEnvelope(capability, envelope.KeyID, []byte(packet.OperatorPublicPEM)); err != nil {
		t.Fatal("original capability signature", err)
	}
	allocation, e := store.ApprovedPhysicalAccess(box, *boot.Case, context, policy.Run.Tuple, capability, at)
	if e != nil || allocation.Kind != "access" || allocation.FirstPhysicalIndex != 1 {
		t.Fatal("signed demand/access2 capability approval", e)
	}
	wrong := context
	wrong.TupleDigest = Digest([]byte("different current tuple"))
	if _, e = store.ApprovedPhysicalAccess(box, *boot.Case, wrong, policy.Run.Tuple, capability, at); e == nil {
		t.Fatal("foreign tuple access capability accepted")
	}
	t.Log("SOURCE actual backend-signed demand/capability; no enrollment, credentials, admission, native or provider execution")
}
