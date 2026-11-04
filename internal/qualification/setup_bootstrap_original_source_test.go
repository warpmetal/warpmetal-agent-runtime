package qualification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Extend the existing signed Store journey with the exact cold issuer bytes.
// Ancestor ownership is SOURCE-local; no installed or protected signer claim.
func testSetupBootstrapOriginalSource(t *testing.T) {
	input := os.Getenv("WARPMETAL_SETUP_BOOTSTRAP_SOURCE")
	var source struct {
		At, SandboxID, ImageDigest string
		Generation                 int64
	}
	raw, err := os.ReadFile(filepath.Join(input, "source.json"))
	if err != nil || json.Unmarshal(raw, &source) != nil {
		t.Fatal("source originals", err)
	}
	at, err := time.Parse(time.RFC3339Nano, source.At)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(filepath.Dir(input), "setup-bootstrap-store-source-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE store", root)
	store := SourceBoundaryStoreForTest(root, uint32(os.Getuid()))
	box := model.Sandbox{ID: source.SandboxID, Generation: source.Generation, ImageDigest: source.ImageDigest, Cell: true}
	tree, key, err := store.Paths(box.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Dir(key), tree, filepath.Join(tree, "plugin"), filepath.Join(tree, "snapshots"), filepath.Join(tree, "preparations"), filepath.Join(tree, "revocations")} {
		if err = os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for from, to := range map[string]string{"operator-public.pem": key, "bootstrap.json": filepath.Join(tree, "bootstrap.json"), "bootstrap.sig": filepath.Join(tree, "bootstrap.sig"), "plugin.ts": filepath.Join(tree, "plugin/index.ts"), "ca.pem": filepath.Join(tree, "ca.pem")} {
		body, err := os.ReadFile(filepath.Join(input, from))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(to, body, 0400); err != nil {
			t.Fatal(err)
		}
	}
	if err = filepath.WalkDir(tree, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0500)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	boot, err := store.Bootstrap(box, box.ImageDigest, at)
	if err != nil || boot.FormatVersion != 1 || boot.Mode != "" || boot.Case != nil || boot.Ceilings != Ceilings {
		t.Fatal("exact setup anchor refused", err)
	}
	if _, err = store.Bootstrap(box, "localhost/wrong@sha256:0000000000000000000000000000000000000000000000000000000000000000", at); err == nil {
		t.Fatal("different image admitted")
	}
	if _, err = store.Select(box, box.ImageDigest, model.CellServiceV3{PreparationID: "prep_missing"}, "/workspace/source", at); err == nil {
		t.Fatal("setup anchor admitted execution without policy/preparation")
	}
	for _, name := range []string{"snapshots", "preparations", "revocations"} {
		entries, err := os.ReadDir(filepath.Join(tree, name))
		if err != nil || len(entries) != 0 {
			t.Fatal("setup anchor manufactured execution state", name, err)
		}
	}
}
