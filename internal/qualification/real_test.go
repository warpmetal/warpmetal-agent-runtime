package qualification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Unit exception: money rounding/closed activation drift must be repeatable on
// a non-root development host before the manager-gated packaged Linux boundary.
func TestRealActivationImmutableJoinAndConservativeBudget(t *testing.T) {
	if os.Getenv("WARPMETAL_SETUP_BOOTSTRAP_SOURCE") != "" {
		t.Run("setup_bootstrap_original", testSetupBootstrapOriginalSource)
	}
	if os.Getenv("WARPMETAL_QUALIFICATION_NATIVE_SOURCE") != "" {
		t.Run("signed_native3", testSignedNativeQualificationSource)
	}
	if os.Getenv("WARPMETAL_QUALIFICATION_ACCESS_SOURCE") != "" {
		t.Run("signed_access2", testSignedQualificationAccessSource)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	h := "sha256:" + strings.Repeat("a", 64)
	c := RealCase{CaseID: "case", CaseManifestDigest: h, LedgerID: SharedLedger, Requests: 6, Preparations: 3, USDMicros: 2526000, PricingDigest: PricingDigest(), OperatorKeySHA256: h}
	if !c.valid(Limits{3, 6, 1000, 32768, 262144, 0}) {
		t.Fatal("whole case invalid")
	}
	if RealBudget().USDMicros != 2*RequestMicros || (1047576*400000+1000*1600000+999999)/1000000 > RequestMicros {
		t.Fatal("hard context not covered")
	}
	p := Policy{ExpiresAt: now.Add(120 * time.Second).Format(time.RFC3339Nano), Run: &RealRun{Purpose: "model_qualification_bootstrap", QualificationID: "qual", ReservationID: "res", TupleDigest: h, Budget: RealBudget()}}
	b := Bootstrap{Case: &c, ExpiresAt: p.ExpiresAt}
	d := Descriptor{1, "prep", h, h}
	a := Activation{FormatVersion: 1, Mode: "real_provider", Purpose: p.Run.Purpose, QualificationID: "qual", ReservationID: "res", CaseID: "case", CaseManifestDigest: h, TupleDigest: h, PreparationID: "prep", PreparedTupleDigest: h, PreparedReceiptDigest: h, PolicyDigest: h, GrantID: "grant", GrantDigest: h, PermitDigest: h, AccessEvidenceDigest: h, BudgetDigest: CanonicalDigest(RealBudget()), DispatchStart: 5, PreparationIndex: 3, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: p.ExpiresAt}
	a.ExecutionID = "cellx_actual_backend"
	if !a.valid(b, p, d, now) {
		t.Fatal("exact activation denied")
	}
	for _, change := range []func(*Activation){func(x *Activation) { x.DispatchStart = 6 }, func(x *Activation) { x.PolicyDigest = "sha256:" + strings.Repeat("b", 64) }, func(x *Activation) { x.ReservationID = "other" }, func(x *Activation) { x.Purpose = "normal_execution" }, func(x *Activation) { x.ExpiresAt = now.Add(121 * time.Second).Format(time.RFC3339Nano) }} {
		x := a
		change(&x)
		if x.valid(b, p, d, now) {
			t.Fatal("activation drift accepted")
		}
	}
	data, _ := json.Marshal(a)
	var decoded Activation
	if decodeClosed(data, &decoded) != nil {
		t.Fatal("closed activation cannot decode")
	}
	missing := strings.Replace(string(data), `"formatVersion":1,`, "", 1)
	if decodeClosed([]byte(missing), &decoded) == nil {
		t.Fatal("missing required member accepted")
	}
	if decodeClosed([]byte(strings.Replace(string(data), `"mode":"real_provider"`, `"mode":null`, 1)), &decoded) == nil {
		t.Fatal("null authority accepted")
	}
}

func TestRealProducerConfinedReadbackAndMissingIdentity(t *testing.T) {
	// This host cannot provision root-only signer paths. Exercise actual openat
	// containment/inode checks here; protected-key attestation awaits Linux gate.
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(root)
	if e != nil {
		t.Fatal(e)
	}
	owner := st.Sys().(*syscall.Stat_t)
	f, e := confinedRoot(root, uint64(owner.Dev), owner.Ino)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	link := filepath.Join(t.TempDir(), "link")
	if e = os.Symlink(root, link); e != nil {
		t.Fatal(e)
	}
	if f, e = confinedRoot(link, uint64(owner.Dev), owner.Ino); e == nil {
		f.Close()
		t.Fatal("symlink workspace admitted")
	}
	if f, e = confinedRoot(root, uint64(owner.Dev), owner.Ino+1); e == nil {
		f.Close()
		t.Fatal("replacement root admitted")
	}
	if _, e = NewProducer(nil, "srv_node", strings.Repeat("a", 64)); e == nil {
		t.Fatal("missing node/key association accepted")
	}
	if CanonicalDigest(map[string]string{"command": "printf '<>&'"}) != Digest([]byte(`{"command":"printf '<>&'"}`)) {
		t.Fatal("canonical signing escapes different bytes than F1/Node")
	}
}
