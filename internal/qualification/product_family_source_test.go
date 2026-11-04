package qualification

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// TestQualificationFamilySelection pins the additive, fail-closed family
// selection used by the native SOURCE verifiers and keeps the legacy
// authority3/native-v3 pair unchanged.
func TestQualificationFamilySelection(t *testing.T) {
	for _, tc := range []struct {
		formatVersion int
		native        string
		source        string
		ok            bool
	}{
		{3, "workspace-qualification-native-v3.schema.json", "workspace-qualification-provider-v2.schema.json", true},
		{5, "workspace-qualification-native-v5.schema.json", "workspace-qualification-provider-v4.schema.json", true},
		{2, "", "", false},
		{4, "", "", false},
		{0, "", "", false},
	} {
		native, source, ok := qualificationFamily(&RealCase{FormatVersion: tc.formatVersion})
		if native != tc.native || source != tc.source || ok != tc.ok {
			t.Fatalf("family %d = (%q,%q,%v), want (%q,%q,%v)", tc.formatVersion, native, source, ok, tc.native, tc.source, tc.ok)
		}
		if _, ok := qualificationProviderDescriptor(&RealCase{FormatVersion: tc.formatVersion}); ok != tc.ok {
			t.Fatalf("descriptor family %d ok=%v, want %v", tc.formatVersion, ok, tc.ok)
		}
		if _, ok := qualificationNativeBudget(&RealCase{FormatVersion: tc.formatVersion}); ok != tc.ok {
			t.Fatalf("budget family %d ok=%v, want %v", tc.formatVersion, ok, tc.ok)
		}
	}
	if _, _, ok := qualificationFamily(nil); ok {
		t.Fatal("nil case family must fail closed")
	}
}

// TestAuthority5PacketStoreSelection proves the GREEN authority5 packet is
// selected and verified by the product Store through the new native-v5 /
// provider-v4 contracts, without changing any signature/schema/hash check.
// It is skipped unless the retained packet is available locally.
func TestAuthority5PacketStoreSelection(t *testing.T) {
	input := os.Getenv("WARPMETAL_QUALIFICATION_NATIVE_SOURCE")
	if input == "" {
		t.Skip("WARPMETAL_QUALIFICATION_NATIVE_SOURCE not set")
	}
	var packet struct {
		OperatorPublicPEM string                                                             `json:"operatorPublicPEM"`
		ProducerPublicPEM string                                                             `json:"producerPublicPEM"`
		Authority         json.RawMessage                                                    `json:"authority"`
		EnrolledProducer  *QualificationProducerIdentity                                     `json:"enrolledProducer,omitempty"`
		Publications      map[string]struct{ Digest, ContentBase64, SignatureBase64 string } `json:"publications"`
	}
	raw, err := os.ReadFile(filepath.Join(input, "native-sidecars.json"))
	if err != nil || json.Unmarshal(raw, &packet) != nil {
		t.Fatalf("native SOURCE packet: %v", err)
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
		t.Fatalf("actual backend source entry: %v", err)
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
	if boot.Case == nil || boot.Case.FormatVersion != 5 {
		t.Fatalf("expected authority5 native bundle, got case %+v", boot.Case)
	}
	at, err := time.Parse(time.RFC3339Nano, activation.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	independentProducer, _ := qualificationNativeSourceParticipant(t, input, packet.Authority, packet.EnrolledProducer, []byte(packet.ProducerPublicPEM), []byte(packet.OperatorPublicPEM), boot, policy, originals.Actual.CellServices[0], originals.Actual.ServerID, at)
	root, err := os.MkdirTemp(os.Getenv("HOME"), "authority5-product-family-")
	if err != nil {
		t.Fatal(err)
	}
	store := SourceBoundaryStoreForTest(root, uint32(os.Getuid()))
	store.sourceProducerIdentity = &independentProducer
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
			t.Fatalf("source original %s", label)
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
	pluginPath := os.Getenv("WARPMETAL_QUALIFICATION_PLUGIN_SOURCE")
	if pluginPath == "" {
		t.Skip("WARPMETAL_QUALIFICATION_PLUGIN_SOURCE not set")
	}
	plugin, err := os.ReadFile(pluginPath)
	if err != nil || Digest(plugin) != boot.PluginSHA256 {
		t.Fatalf("exact signed plugin source: %v", err)
	}
	write(filepath.Join(tree, "plugin", "index.ts"), plugin)
	d := Descriptor{1, policy.Preparations[0].PreparationID, policy.PreparedTupleDigest, packet.Publications["policy"].Digest}
	write(filepath.Join(tree, "preparations", d.PreparationID+".json"), canonicalBytes(d))
	for digest, value := range originals.Blobs {
		body, e := base64.StdEncoding.DecodeString(value)
		if e != nil || Digest(body) != digest {
			t.Fatalf("source blob %s", digest)
		}
		write(filepath.Join(tree, "blobs", digest[7:]), body)
	}
	if err := os.MkdirAll(filepath.Join(tree, "revocations"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(tree, func(path string, d os.DirEntry, e error) error {
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
	t.Cleanup(func() {
		_ = filepath.WalkDir(tree, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return nil
			}
			if d.IsDir() {
				return os.Chmod(path, 0700)
			}
			return os.Chmod(path, 0600)
		})
		_ = os.RemoveAll(root)
	})
	if nativeContract, sourceContract, familyOK := qualificationFamily(boot.Case); !familyOK {
		t.Fatal("family not selected")
	} else {
		t.Log("family", nativeContract, sourceContract)
		if err := workflowcontract.Validate(nativeContract, "nativeBootstrap3", bootBytes); err != nil {
			t.Log("nativeBootstrap3 validation error:", err)
		}
		if !boot.Case.typed() {
			t.Log("case typed() false")
		}
		if _, err := boot.SourceBootstrap.verify(sourceContract, "bootstrap3", []byte(packet.OperatorPublicPEM)); err != nil {
			t.Log("source bootstrap verify error:", err)
		}
	}
	selectedBoot, err := store.Bootstrap(box, box.ImageDigest, at)
	if err != nil {
		t.Fatalf("authority5 signed Bootstrap3 selection refused: %v", err)
	}
	_, selectedPolicy, selectedDescriptor, err := store.SelectedPolicy(box, originals.Actual.CellServices[0], policy.Preparations[0].Workspace, at)
	if err != nil {
		t.Fatalf("authority5 signed Policy4 selection refused: %v", err)
	}
	selected, err := store.ReadQualificationActivation(box, selectedBoot, selectedPolicy, selectedDescriptor, at)
	if err != nil || selected.Native == nil || selected.Publication.Digest != packet.Publications["activation"].Digest {
		t.Fatalf("authority5 native/source activation join refused: %v", err)
	}
}
