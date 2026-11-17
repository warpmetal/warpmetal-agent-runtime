package boxcredentials

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
)

const (
	testNodeToken = "rtn_box_bridge_test_token"
	testBoxID     = "srv_boxbridge0001"
	testCredID    = "conn_aaaaaaaaaaaaaaaaaaaaaaaa"
)

type fakePlatform struct {
	t      *testing.T
	server *httptest.Server

	mu                     sync.Mutex
	registerCalls          int
	pullCalls              int
	registerJWKs           []map[string]any
	registeredFingerprints []string
	authorizations         []string

	registerStatus int
	registerCode   string
	pullStatus     int
	pullCode       string
	pullItems      func(fingerprint string) []control.ToolProviderCredentialDelivery
}

func newFakePlatform(t *testing.T) *fakePlatform {
	t.Helper()
	platform := &fakePlatform{t: t}
	platform.server = httptest.NewTLSServer(http.HandlerFunc(platform.handle))
	t.Cleanup(platform.server.Close)
	return platform
}

func (p *fakePlatform) client() control.Client {
	return control.Client{Origin: p.server.URL, NodeToken: testNodeToken, HTTP: p.server.Client()}
}

func (p *fakePlatform) handle(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	p.mu.Lock()
	p.authorizations = append(p.authorizations, request.Header.Get("Authorization"))
	p.mu.Unlock()
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/internal/runtime/box-encryption-key":
		p.handleRegister(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/internal/runtime/tool-provider-credentials":
		p.handlePull(writer)
	default:
		p.t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		http.Error(writer, "unexpected request", http.StatusNotFound)
	}
}

func (p *fakePlatform) handleRegister(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		PublicKeyJwk map[string]any `json:"publicKeyJwk"`
	}
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		p.t.Errorf("decode registration body: %v", err)
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	fingerprint, err := fingerprintFromJWK(body.PublicKeyJwk)
	if err != nil {
		p.t.Errorf("registration JWK is not a valid RSA public key: %v", err)
		http.Error(writer, "bad jwk", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.registerCalls++
	p.registerJWKs = append(p.registerJWKs, body.PublicKeyJwk)
	p.registeredFingerprints = append(p.registeredFingerprints, fingerprint)
	status, code := p.registerStatus, p.registerCode
	p.mu.Unlock()
	if status != 0 {
		writer.WriteHeader(status)
		_, _ = fmt.Fprintf(writer, `{"error":{"code":%q,"message":"refused"}}`, code)
		return
	}
	_, _ = fmt.Fprintf(
		writer,
		`{"boxId":%q,"keyFingerprint":%q,"algorithm":"RSA-OAEP-256","publicKeyJwk":{"kty":"RSA"},"revision":1,"registeredAt":"2026-11-16T00:00:00Z","rotatedAt":null}`,
		testBoxID,
		fingerprint,
	)
}

func (p *fakePlatform) handlePull(writer http.ResponseWriter) {
	p.mu.Lock()
	p.pullCalls++
	status, code := p.pullStatus, p.pullCode
	itemsFn := p.pullItems
	fingerprint := ""
	if len(p.registeredFingerprints) > 0 {
		fingerprint = p.registeredFingerprints[len(p.registeredFingerprints)-1]
	}
	p.mu.Unlock()
	if status != 0 {
		writer.WriteHeader(status)
		_, _ = fmt.Fprintf(writer, `{"error":{"code":%q,"message":"refused"}}`, code)
		return
	}
	items := []control.ToolProviderCredentialDelivery{}
	if itemsFn != nil {
		items = itemsFn(fingerprint)
	}
	if items == nil {
		items = []control.ToolProviderCredentialDelivery{}
	}
	payload, err := json.Marshal(struct {
		Items []control.ToolProviderCredentialDelivery `json:"items"`
	}{Items: items})
	if err != nil {
		p.t.Errorf("encode pull response: %v", err)
		http.Error(writer, "encode", http.StatusInternalServerError)
		return
	}
	_, _ = writer.Write(payload)
}

func (p *fakePlatform) setRegisterResult(status int, code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.registerStatus = status
	p.registerCode = code
}

func (p *fakePlatform) setPullResult(status int, code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pullStatus = status
	p.pullCode = code
}

func (p *fakePlatform) counts() (registers, pulls int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.registerCalls, p.pullCalls
}

func (p *fakePlatform) registrationFingerprints() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.registeredFingerprints...)
}

func (p *fakePlatform) registrationJWKs() []map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]map[string]any(nil), p.registerJWKs...)
}

func fingerprintFromJWK(jwk map[string]any) (string, error) {
	modulusValue, _ := jwk["n"].(string)
	exponentValue, _ := jwk["e"].(string)
	modulus, err := base64.RawURLEncoding.DecodeString(modulusValue)
	if err != nil || len(modulus) == 0 {
		return "", errors.New("invalid modulus")
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(exponentValue)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return "", errors.New("invalid exponent")
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 | int(value)
	}
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func testDelivery(fingerprint, credentialID, providerID string, overrides map[string]any) control.ToolProviderCredentialDelivery {
	fields := map[string]any{
		"formatVersion":  1,
		"algorithm":      EnvelopeAlgorithm,
		"boxId":          testBoxID,
		"keyFingerprint": fingerprint,
		"envelopeId":     "env_testEnvelope0001",
		"purpose":        Purpose,
		"wrappedKey":     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 512)),
		"iv":             base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 12)),
		"ciphertext":     base64.RawURLEncoding.EncodeToString([]byte("CIPHERTEXTMARKER")),
		"createdAt":      "2026-11-16T00:00:00Z",
	}
	for name, value := range overrides {
		if value == nil {
			delete(fields, name)
			continue
		}
		fields[name] = value
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return control.ToolProviderCredentialDelivery{
		CredentialID:   credentialID,
		ProviderID:     providerID,
		KeyFingerprint: fingerprint,
		Envelope:       raw,
	}
}

func defaultTestOptions(platform *fakePlatform, stateRoot string, logger *log.Logger) Options {
	return Options{
		Enabled:         true,
		StateDir:        stateRoot,
		Client:          platform.client(),
		BoxID:           testBoxID,
		PollInterval:    20 * time.Millisecond,
		Logger:          logger,
		keyBits:         minimumKeyBits,
		registerBackoff: 5 * time.Millisecond,
		requestTimeout:  2 * time.Second,
	}
}

func newTestManager(t *testing.T, options Options) *Manager {
	t.Helper()
	manager, err := New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return manager
}

// startManager runs the manager in the background and guarantees a clean,
// bounded stop when the test ends.
func startManager(t *testing.T, manager *Manager) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = manager.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-manager.Done():
		case <-time.After(10 * time.Second):
			t.Error("bridge did not stop within the shutdown budget")
		}
	})
	return cancel
}

func stopManager(t *testing.T, manager *Manager, cancel context.CancelFunc) {
	t.Helper()
	cancel()
	select {
	case <-manager.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("bridge did not stop within the shutdown budget")
	}
}

func waitForStatus(t *testing.T, manager *Manager, timeout time.Duration, condition func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		status := manager.Status()
		if condition(status) {
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("bridge status was never satisfied; last status: %s", status.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func TestDisabledManagerIsInert(t *testing.T) {
	platform := newFakePlatform(t)
	stateRoot := filepath.Join(t.TempDir(), "state")
	manager, err := New(Options{
		Enabled:  false,
		StateDir: stateRoot,
		Client:   platform.client(),
		BoxID:    testBoxID,
		Logger:   discardLogger(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := manager.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if state := manager.Status().State; state != StateDisabled {
		t.Fatalf("state = %q, want %q", state, StateDisabled)
	}
	if registers, pulls := platform.counts(); registers != 0 || pulls != 0 {
		t.Fatalf("disabled bridge made control-plane calls: registers=%d pulls=%d", registers, pulls)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, stateDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disabled bridge created a key directory: err = %v", err)
	}
}

func TestFirstBootRegistersKeyAndSecondBootReusesIt(t *testing.T) {
	platform := newFakePlatform(t)
	stateRoot := t.TempDir()

	first := newTestManager(t, defaultTestOptions(platform, stateRoot, discardLogger()))
	cancelFirst := startManager(t, first)
	firstStatus := waitForStatus(t, first, 15*time.Second, func(status Status) bool {
		return status.RegisteredAt.IsZero() == false && !status.LastPullAt.IsZero()
	})
	if firstStatus.State != StateActive {
		t.Fatalf("first boot state = %q, want active", firstStatus.State)
	}
	if firstStatus.KeyFingerprint == "" {
		t.Fatal("first boot did not report a key fingerprint")
	}
	stopManager(t, first, cancelFirst)

	keyPath := filepath.Join(stateRoot, stateDirectoryName, privateKeyFileName)
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if mode := keyInfo.Mode().Perm(); mode != 0o600 {
		t.Fatalf("private key mode = %o, want 600", mode)
	}
	directoryInfo, err := os.Stat(filepath.Join(stateRoot, stateDirectoryName))
	if err != nil {
		t.Fatalf("stat key directory: %v", err)
	}
	if mode := directoryInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("key directory mode = %o, want 700", mode)
	}
	loaded, err := loadKey(keyPath)
	if err != nil {
		t.Fatalf("loadKey() error = %v", err)
	}
	if loaded.Fingerprint() != firstStatus.KeyFingerprint {
		t.Fatalf("persisted key fingerprint = %q, want %q", loaded.Fingerprint(), firstStatus.KeyFingerprint)
	}

	second := newTestManager(t, defaultTestOptions(platform, stateRoot, discardLogger()))
	cancelSecond := startManager(t, second)
	secondStatus := waitForStatus(t, second, 15*time.Second, func(status Status) bool {
		// Wait for this boot's own pull, not only for the registration in front
		// of it, so the idempotent second boot is observed end to end.
		return !status.RegisteredAt.IsZero() && status.LastPullAt.After(firstStatus.LastPullAt)
	})
	stopManager(t, second, cancelSecond)
	if secondStatus.KeyFingerprint != firstStatus.KeyFingerprint {
		t.Fatalf("second boot fingerprint = %q, want %q", secondStatus.KeyFingerprint, firstStatus.KeyFingerprint)
	}

	registers, pulls := platform.counts()
	if registers != 2 {
		t.Fatalf("register calls = %d, want 2 (one idempotent registration per boot)", registers)
	}
	if pulls < 2 {
		t.Fatalf("pull calls = %d, want at least 2", pulls)
	}
	fingerprints := platform.registrationFingerprints()
	if len(fingerprints) != 2 || fingerprints[0] != fingerprints[1] || fingerprints[0] != firstStatus.KeyFingerprint {
		t.Fatalf("registrations = %v, want the same fingerprint twice", fingerprints)
	}
	jwks := platform.registrationJWKs()
	if len(jwks) != 2 {
		t.Fatalf("captured JWKs = %d, want 2", len(jwks))
	}
	for _, field := range []string{"kty", "n", "e", "alg", "ext"} {
		if _, ok := jwks[0][field]; !ok {
			t.Fatalf("registered JWK is missing %q", field)
		}
	}
	if jwks[0]["kty"] != "RSA" || jwks[0]["alg"] != Algorithm || jwks[0]["e"] != "AQAB" || jwks[0]["ext"] != true {
		t.Fatalf("registered JWK has unexpected values: %#v", jwks[0])
	}
	if jwks[0]["n"] != jwks[1]["n"] || jwks[0]["e"] != jwks[1]["e"] {
		t.Fatal("second boot registered a different public key")
	}
	if _, leaked := jwks[0]["d"]; leaked {
		t.Fatal("registration leaked private key material")
	}
}

func TestRotationRequiredIsBlockedAndPreservesKey(t *testing.T) {
	platform := newFakePlatform(t)
	stateRoot := t.TempDir()
	platform.setRegisterResult(http.StatusConflict, ReasonKeyRotationRequired)
	manager := newTestManager(t, defaultTestOptions(platform, stateRoot, discardLogger()))
	err := manager.Run(context.Background())
	if err == nil {
		t.Fatal("Run() succeeded despite a 409 rotation-required refusal")
	}
	status := manager.Status()
	if status.State != StateBlocked {
		t.Fatalf("state = %q, want %q", status.State, StateBlocked)
	}
	if status.Reason != ReasonKeyRotationRequired {
		t.Fatalf("reason = %q, want %q", status.Reason, ReasonKeyRotationRequired)
	}
	if status.KeyFingerprint == "" {
		t.Fatal("blocked status lost the local key fingerprint")
	}
	if _, pulls := platform.counts(); pulls != 0 {
		t.Fatalf("blocked bridge pulled credentials: pulls = %d", pulls)
	}
	keyPath := filepath.Join(stateRoot, stateDirectoryName, privateKeyFileName)
	preserved, err := loadKey(keyPath)
	if err != nil {
		t.Fatalf("rotation refusal destroyed the private key: %v", err)
	}
	if preserved.Fingerprint() != status.KeyFingerprint {
		t.Fatalf("preserved key fingerprint = %q, want %q", preserved.Fingerprint(), status.KeyFingerprint)
	}

	// The bridge must not invent a rotation: once the platform accepts the same
	// key again, a restart re-registers it unchanged.
	platform.setRegisterResult(0, "")
	restarted := newTestManager(t, defaultTestOptions(platform, stateRoot, discardLogger()))
	cancel := startManager(t, restarted)
	restartedStatus := waitForStatus(t, restarted, 15*time.Second, func(candidate Status) bool {
		return !candidate.RegisteredAt.IsZero()
	})
	stopManager(t, restarted, cancel)
	if restartedStatus.KeyFingerprint != status.KeyFingerprint {
		t.Fatalf("restart fingerint = %q, want unchanged %q", restartedStatus.KeyFingerprint, status.KeyFingerprint)
	}
	fingerprints := platform.registrationFingerprints()
	if len(fingerprints) != 2 || fingerprints[0] != fingerprints[1] {
		t.Fatalf("registrations = %v, want the same key on both attempts", fingerprints)
	}
}

func TestPullPersistsEnvelopesAndRestartRestoresThem(t *testing.T) {
	platform := newFakePlatform(t)
	stateRoot := t.TempDir()
	platform.pullItems = func(fingerprint string) []control.ToolProviderCredentialDelivery {
		return []control.ToolProviderCredentialDelivery{
			testDelivery(fingerprint, testCredID, "github", nil),
		}
	}
	first := newTestManager(t, defaultTestOptions(platform, stateRoot, discardLogger()))
	cancelFirst := startManager(t, first)
	firstStatus := waitForStatus(t, first, 15*time.Second, func(status Status) bool {
		return status.ActiveEnvelopeCount == 1 && !status.LastPullAt.IsZero()
	})
	if firstStatus.RejectedEnvelopeCount != 0 {
		t.Fatalf("unexpected rejected envelopes: %d", firstStatus.RejectedEnvelopeCount)
	}
	stopManager(t, first, cancelFirst)

	storePath := filepath.Join(stateRoot, stateDirectoryName, credentialStoreFileName)
	info, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("stat sealed credential store: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("sealed credential store mode = %o, want 600", mode)
	}
	stored := readStoredCredentials(t, storePath)
	if len(stored) != 1 {
		t.Fatalf("stored credentials = %d, want 1", len(stored))
	}
	if _, ok := stored[testCredID]; !ok {
		t.Fatalf("stored credentials = %v, want %q", stored, testCredID)
	}

	// A restart restores the cached active set even before the platform can
	// serve a new pull.
	platform.setPullResult(http.StatusInternalServerError, "internal_error")
	restarted := newTestManager(t, defaultTestOptions(platform, stateRoot, discardLogger()))
	cancelRestart := startManager(t, restarted)
	restartStatus := waitForStatus(t, restarted, 15*time.Second, func(status Status) bool {
		return !status.RegisteredAt.IsZero() && status.ActiveEnvelopeCount == 1
	})
	stopManager(t, restarted, cancelRestart)
	if restartStatus.KeyFingerprint != firstStatus.KeyFingerprint {
		t.Fatalf("restart fingerprint = %q, want %q", restartStatus.KeyFingerprint, firstStatus.KeyFingerprint)
	}
	if restartStatus.ActiveEnvelopeCount != 1 {
		t.Fatalf("restored active envelopes = %d, want 1", restartStatus.ActiveEnvelopeCount)
	}
}

func TestPullRevocationRemovesStaleEnvelope(t *testing.T) {
	platform := newFakePlatform(t)
	stateRoot := t.TempDir()
	var revoked atomic.Bool
	platform.pullItems = func(fingerprint string) []control.ToolProviderCredentialDelivery {
		if revoked.Load() {
			return nil
		}
		return []control.ToolProviderCredentialDelivery{
			testDelivery(fingerprint, testCredID, "github", nil),
		}
	}
	manager := newTestManager(t, defaultTestOptions(platform, stateRoot, discardLogger()))
	cancel := startManager(t, manager)
	waitForStatus(t, manager, 15*time.Second, func(status Status) bool {
		return status.ActiveEnvelopeCount == 1 && !status.LastPullAt.IsZero()
	})
	revoked.Store(true)
	waitForStatus(t, manager, 15*time.Second, func(status Status) bool {
		return status.ActiveEnvelopeCount == 0
	})
	stopManager(t, manager, cancel)
	stored := readStoredCredentials(t, filepath.Join(stateRoot, stateDirectoryName, credentialStoreFileName))
	if len(stored) != 0 {
		t.Fatalf("revoked envelope remained in the local store: %v", stored)
	}
}

func TestInvalidDeliveriesStayOutOfStoreAndNeverLeak(t *testing.T) {
	platform := newFakePlatform(t)
	stateRoot := t.TempDir()
	otherFingerprint := "sha256:" + strings.Repeat("b", 64)
	platform.pullItems = func(fingerprint string) []control.ToolProviderCredentialDelivery {
		valid := testDelivery(fingerprint, testCredID, "github", nil)
		return []control.ToolProviderCredentialDelivery{
			valid,
			testDelivery(fingerprint, "conn_bbbbbbbbbbbbbbbbbbbbbbbb", "github",
				map[string]any{"keyFingerprint": otherFingerprint}),
			testDelivery(fingerprint, "conn_cccccccccccccccccccccccc", "github",
				map[string]any{"boxId": "srv_otherbox00002"}),
			testDelivery(fingerprint, "conn_dddddddddddddddddddddddd", "github",
				map[string]any{"ciphertext": nil}),
			testDelivery(fingerprint, "conn_eeeeeeeeeeeeeeeeeeeeeeee", "github",
				map[string]any{"algorithm": "RSA-OAEP-256"}),
			control.ToolProviderCredentialDelivery{
				CredentialID:   "not-a-credential",
				ProviderID:     "github",
				KeyFingerprint: fingerprint,
				Envelope:       valid.Envelope,
			},
		}
	}
	var logBuffer bytes.Buffer
	manager := newTestManager(t, defaultTestOptions(platform, stateRoot, log.New(&logBuffer, "", 0)))
	cancel := startManager(t, manager)
	status := waitForStatus(t, manager, 15*time.Second, func(candidate Status) bool {
		return !candidate.LastPullAt.IsZero() && candidate.ActiveEnvelopeCount == 1
	})
	stopManager(t, manager, cancel)
	if status.RejectedEnvelopeCount != 5 {
		t.Fatalf("rejected envelopes = %d, want 5", status.RejectedEnvelopeCount)
	}
	if status.Reason != ReasonInvalidCredentialItems {
		t.Fatalf("reason = %q, want %q", status.Reason, ReasonInvalidCredentialItems)
	}
	stored := readStoredCredentials(t, filepath.Join(stateRoot, stateDirectoryName, credentialStoreFileName))
	if len(stored) != 1 {
		t.Fatalf("stored credentials = %d, want only the valid item", len(stored))
	}
	if _, ok := stored[testCredID]; !ok {
		t.Fatalf("stored credentials = %v, want %q", stored, testCredID)
	}

	logged := logBuffer.String()
	statusJSON, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	for _, secret := range []string{
		"CIPHERTEXTMARKER",
		base64.RawURLEncoding.EncodeToString([]byte("CIPHERTEXTMARKER")),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 512)),
		"PRIVATE KEY",
	} {
		if strings.Contains(logged, secret) {
			t.Fatalf("bridge logs leaked envelope or key material %q: %s", secret, logged)
		}
		if strings.Contains(string(statusJSON), secret) {
			t.Fatalf("bridge status leaked envelope or key material %q: %s", secret, statusJSON)
		}
	}
	for _, forbidden := range []string{"ciphertext", "wrappedKey", "privateKey"} {
		if strings.Contains(string(statusJSON), forbidden) {
			t.Fatalf("bridge status contains forbidden field %q: %s", forbidden, statusJSON)
		}
	}
}

func TestUnauthorizedRegistrationSurfacesWithoutToken(t *testing.T) {
	platform := newFakePlatform(t)
	stateRoot := t.TempDir()
	platform.setRegisterResult(http.StatusUnauthorized, ReasonRuntimeNodeUnauthorized)
	manager := newTestManager(t, defaultTestOptions(platform, stateRoot, discardLogger()))
	err := manager.Run(context.Background())
	if err == nil {
		t.Fatal("Run() succeeded despite a 401 node-token refusal")
	}
	if strings.Contains(err.Error(), testNodeToken) {
		t.Fatalf("auth error leaked the node token: %v", err)
	}
	status := manager.Status()
	if status.State != StateUnauthorized {
		t.Fatalf("state = %q, want %q", status.State, StateUnauthorized)
	}
	if status.Reason != ReasonRuntimeNodeUnauthorized {
		t.Fatalf("reason = %q, want %q", status.Reason, ReasonRuntimeNodeUnauthorized)
	}
	statusJSON, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	if strings.Contains(string(statusJSON), testNodeToken) {
		t.Fatalf("status leaked the node token: %s", statusJSON)
	}
	if _, pulls := platform.counts(); pulls != 0 {
		t.Fatalf("unauthorized bridge pulled credentials: pulls = %d", pulls)
	}
}

func TestRunStopsOnContextCancellation(t *testing.T) {
	t.Run("during registration backoff", func(t *testing.T) {
		platform := newFakePlatform(t)
		stateRoot := t.TempDir()
		platform.setRegisterResult(http.StatusServiceUnavailable, "service_unavailable")
		manager := newTestManager(t, defaultTestOptions(platform, stateRoot, discardLogger()))
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- manager.Run(ctx) }()
		deadline := time.Now().Add(10 * time.Second)
		for {
			registers, _ := platform.counts()
			if registers >= 1 {
				break
			}
			if time.Now().After(deadline) {
				cancel()
				t.Fatal("bridge never attempted registration")
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("Run() error = %v, want nil on cancellation", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("cancelled registration backoff did not stop the bridge")
		}
	})

	t.Run("during periodic pull wait", func(t *testing.T) {
		platform := newFakePlatform(t)
		stateRoot := t.TempDir()
		options := defaultTestOptions(platform, stateRoot, discardLogger())
		options.PollInterval = time.Hour
		manager := newTestManager(t, options)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- manager.Run(ctx) }()
		waitForStatus(t, manager, 15*time.Second, func(status Status) bool {
			return !status.LastPullAt.IsZero()
		})
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("Run() error = %v, want nil on cancellation", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("cancelled pull wait did not stop the bridge")
		}
	})
}

func readStoredCredentials(t *testing.T, path string) map[string]storedCredential {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sealed credential store: %v", err)
	}
	var document credentialDocument
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode sealed credential store: %v", err)
	}
	return document.Credentials
}
