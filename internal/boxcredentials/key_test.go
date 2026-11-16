package boxcredentials

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyStoreProtectsKeyAndReplacesAtomically(t *testing.T) {
	stateRoot := t.TempDir()
	store := newKeyStore(stateRoot, minimumKeyBits)
	key, generated, err := store.loadOrCreate()
	if err != nil {
		t.Fatalf("loadOrCreate() error = %v", err)
	}
	if !generated {
		t.Fatal("first loadOrCreate() did not generate a key")
	}
	if mode := fileMode(t, store.privateKeyPath()); mode != 0o600 {
		t.Fatalf("private key mode = %o, want 600", mode)
	}
	if mode := fileMode(t, store.directory); mode != 0o700 {
		t.Fatalf("key directory mode = %o, want 700", mode)
	}
	reloaded, generatedAgain, err := store.loadOrCreate()
	if err != nil {
		t.Fatalf("second loadOrCreate() error = %v", err)
	}
	if generatedAgain {
		t.Fatal("second loadOrCreate() regenerated the key")
	}
	if reloaded.Fingerprint() != key.Fingerprint() {
		t.Fatalf("reloaded fingerprint = %q, want %q", reloaded.Fingerprint(), key.Fingerprint())
	}

	replacement, err := generateKey(minimumKeyBits)
	if err != nil {
		t.Fatalf("generate replacement key: %v", err)
	}
	encoded, err := replacement.marshalPrivateKey()
	if err != nil {
		t.Fatalf("marshal replacement key: %v", err)
	}
	if err := atomicWriteFile(store.privateKeyPath(), encoded, 0o600); err != nil {
		t.Fatalf("atomic replacement: %v", err)
	}
	afterReplace, err := loadKey(store.privateKeyPath())
	if err != nil {
		t.Fatalf("load replaced key: %v", err)
	}
	if afterReplace.Fingerprint() != replacement.Fingerprint() {
		t.Fatalf("replaced key fingerprint = %q, want %q", afterReplace.Fingerprint(), replacement.Fingerprint())
	}
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		t.Fatalf("read key directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != privateKeyFileName {
		t.Fatalf("key directory entries = %v, want only %q", entries, privateKeyFileName)
	}

	// A failed atomic replacement must leave the previous complete key intact.
	if err := os.Chmod(store.directory, 0o500); err != nil {
		t.Fatalf("protect key directory: %v", err)
	}
	defer func() { _ = os.Chmod(store.directory, 0o700) }()
	if err := atomicWriteFile(store.privateKeyPath(), []byte("truncated"), 0o600); err == nil {
		t.Fatal("atomic replacement unexpectedly succeeded in a read-only directory")
	}
	preserved, err := loadKey(store.privateKeyPath())
	if err != nil {
		t.Fatalf("failed replacement corrupted the key: %v", err)
	}
	if preserved.Fingerprint() != replacement.Fingerprint() {
		t.Fatalf("failed replacement changed the key: %q", preserved.Fingerprint())
	}
}

func TestKeyStoreNeverRegeneratesOverMalformedKey(t *testing.T) {
	stateRoot := t.TempDir()
	store := newKeyStore(stateRoot, minimumKeyBits)
	if _, _, err := store.loadOrCreate(); err != nil {
		t.Fatalf("loadOrCreate() error = %v", err)
	}
	if err := os.WriteFile(store.privateKeyPath(), []byte("not a private key"), 0o600); err != nil {
		t.Fatalf("corrupt key file: %v", err)
	}
	if _, _, err := store.loadOrCreate(); err == nil {
		t.Fatal("loadOrCreate() unexpectedly replaced a malformed key")
	}
	content, err := os.ReadFile(store.privateKeyPath())
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if string(content) != "not a private key" {
		t.Fatalf("malformed key file was overwritten: %q", content)
	}
}

func TestPrivateKeyAndEnvelopeStoreRequireRootOnlyPermissions(t *testing.T) {
	stateRoot := t.TempDir()
	store := newKeyStore(stateRoot, minimumKeyBits)
	if _, _, err := store.loadOrCreate(); err != nil {
		t.Fatalf("loadOrCreate() error = %v", err)
	}
	if err := os.Chmod(store.privateKeyPath(), 0o644); err != nil {
		t.Fatalf("loosen key file: %v", err)
	}
	if _, err := loadKey(store.privateKeyPath()); err == nil {
		t.Fatal("loadKey() accepted a group/world-readable private key")
	}
	if err := os.Chmod(store.privateKeyPath(), 0o600); err != nil {
		t.Fatalf("restore key file mode: %v", err)
	}
	if _, err := loadKey(store.privateKeyPath()); err != nil {
		t.Fatalf("loadKey() failed after restoring mode: %v", err)
	}

	credentials := newCredentialStore(stateRoot)
	if err := credentials.replace(map[string]storedCredential{}); err != nil {
		t.Fatalf("persist envelope store: %v", err)
	}
	if mode := fileMode(t, credentials.path); mode != 0o600 {
		t.Fatalf("envelope store mode = %o, want 600", mode)
	}
	if err := os.Chmod(credentials.path, 0o640); err != nil {
		t.Fatalf("loosen envelope store: %v", err)
	}
	if _, _, err := credentials.load(testBoxID, "sha256:"); err == nil {
		t.Fatal("credentialStore.load() accepted a group-readable envelope file")
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", filepath.Base(path), err)
	}
	return info.Mode().Perm()
}

func TestProductionKeyStoreGeneratesRSAOAEP4096(t *testing.T) {
	if productionKeyBits != 4096 {
		t.Fatalf("productionKeyBits = %d, want 4096", productionKeyBits)
	}
	stateRoot := t.TempDir()
	store := newKeyStore(stateRoot, 0)
	key, generated, err := store.loadOrCreate()
	if err != nil {
		t.Fatalf("loadOrCreate() error = %v", err)
	}
	if !generated {
		t.Fatal("first loadOrCreate() did not generate the production key")
	}
	if bits := key.private.N.BitLen(); bits != productionKeyBits {
		t.Fatalf("generated key size = %d, want %d", bits, productionKeyBits)
	}
	jwk := key.PublicJWK()
	if jwk["kty"] != "RSA" || jwk["alg"] != Algorithm || jwk["e"] != "AQAB" || jwk["ext"] != true {
		t.Fatalf("public JWK = %#v", jwk)
	}
	for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, leaked := jwk[privateField]; leaked {
			t.Fatalf("public JWK leaked private field %q", privateField)
		}
	}
	if fingerprint := key.Fingerprint(); len(fingerprint) != len("sha256:")+64 || fingerprint[:7] != "sha256:" {
		t.Fatalf("fingerprint = %q", fingerprint)
	}
	for _, rendered := range []string{fmt.Sprintf("%v", key), fmt.Sprintf("%#v", key)} {
		if !strings.Contains(rendered, key.Fingerprint()) {
			t.Fatalf("rendered key does not identify its fingerprint: %s", rendered)
		}
		if strings.Contains(rendered, "PrivateKey") || strings.Contains(rendered, "rsa.PrivateKey") {
			t.Fatalf("rendered key leaked private components: %s", rendered)
		}
	}
	loaded, generatedAgain, err := store.loadOrCreate()
	if err != nil {
		t.Fatalf("reload() error = %v", err)
	}
	if generatedAgain || loaded.Fingerprint() != key.Fingerprint() {
		t.Fatal("production key was not stable across a reload")
	}
}
