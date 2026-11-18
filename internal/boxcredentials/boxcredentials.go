// Package boxcredentials implements the Runtime Box credential bridge
// (docs RUNTIME_BOX_CREDENTIAL_BRIDGE.md sections 2, 3, 4 and 8).
//
// Phase P1 generates one RSA-OAEP-256 keypair on first use, keeps the private
// key root-only under the Runtime state directory, registers only the public JWK
// with the existing node token, and periodically pulls the platform's active set
// of sealed tool-provider credential envelopes into a root-only local file.
//
// Phase P2 adds the opening primitive (OpenEnvelope and Manager.OpenCredential):
// it verifies every envelope binding and authenticity property and returns a
// short-lived Credential in memory. It never injects a credential into a tool
// process, never executes a provider tool, and never persists or logs plaintext.
// The bridge is inert unless explicitly enabled, so an existing production
// Runtime keeps its exact current behavior.
package boxcredentials

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
)

const (
	// StateDisabled is reported when the bridge is not configured.
	StateDisabled = "disabled"
	// StateStarting is the initial state of an enabled bridge before the key is
	// registered.
	StateStarting = "starting"
	// StateActive means the key is registered and pulls are succeeding.
	StateActive = "active"
	// StateBlocked means the platform refused this key and only a signed
	// rotation (not implemented in this phase) can unblock the Box.
	StateBlocked = "blocked"
	// StateUnauthorized means the node token was rejected and the Runtime must
	// re-enroll; credentials stay sealed and are re-fetched after enrollment.
	StateUnauthorized = "unauthorized"
	// StateError means the bridge is retrying a local or platform failure.
	StateError = "error"

	// ReasonKeyRotationRequired is the platform's 409 refusal code.
	ReasonKeyRotationRequired = "box_key_rotation_required"
	// ReasonRuntimeNodeUnauthorized is the platform's 401 refusal code.
	ReasonRuntimeNodeUnauthorized = "runtime_node_unauthorized"
	// ReasonPlatformUnavailable means a transient transport/server failure.
	ReasonPlatformUnavailable = "platform_unavailable"
	// ReasonKeyUnavailable means the platform has no active key for this Box.
	ReasonKeyUnavailable = "box_key_unavailable"
	// ReasonInvalidPlatformResponse means the platform violated the contract.
	ReasonInvalidPlatformResponse = "invalid_platform_response"
	// ReasonInvalidCredentialItems means one or more delivered items were
	// rejected and kept out of the local store.
	ReasonInvalidCredentialItems = "invalid_credential_items"
	// ReasonKeyStoreUnavailable means the root-only Box key could not be
	// loaded or persisted. The bridge must not silently replace a key.
	ReasonKeyStoreUnavailable = "key_store_unavailable"
	// ReasonCredentialStoreUnavailable means the sealed envelope file could not
	// be persisted. The previous complete file is retained.
	ReasonCredentialStoreUnavailable = "credential_store_unavailable"
)

const (
	defaultPollInterval    = time.Minute
	defaultRegisterBackoff = 2 * time.Second
	maxRegisterBackoff     = time.Minute
	defaultRequestTimeout  = 30 * time.Second
)

// Options configures the bridge. Enabled is the only production switch: every
// production caller leaves it false unless an operator opted in.
type Options struct {
	// Enabled starts the bridge. When false the Manager is inert.
	Enabled bool
	// StateDir is the Runtime state root (the same root as runtime.sqlite3).
	// The private key and envelope file live in a 0700 subdirectory.
	StateDir string
	// Client is the existing node-authenticated control-plane client.
	Client control.Client
	// BoxID is the public server id the platform authenticates as this Box.
	BoxID string
	// PollInterval is the bounded credential pull cadence.
	PollInterval time.Duration
	// Verifier optionally checks an owner-requested credential locally. Nil
	// means the bridge reports verification as unsupported, never as verified.
	Verifier Verifier
	// Logger receives secret-free status transitions. Nil uses log.Default().
	Logger *log.Logger

	// keyBits is test-only; production always generates productionKeyBits.
	keyBits         int
	registerBackoff time.Duration
	requestTimeout  time.Duration
}

// Status is the complete, secret-free bridge state. It can be logged or
// reported as-is: it contains no private key, envelope, ciphertext or token
// material.
type Status struct {
	Enabled               bool      `json:"enabled"`
	State                 string    `json:"state"`
	Reason                string    `json:"reason,omitempty"`
	BoxID                 string    `json:"boxId,omitempty"`
	KeyFingerprint        string    `json:"keyFingerprint,omitempty"`
	RegisteredAt          time.Time `json:"registeredAt,omitzero"`
	LastPullAt            time.Time `json:"lastPullAt,omitzero"`
	ActiveEnvelopeCount   int       `json:"activeEnvelopeCount"`
	RejectedEnvelopeCount int       `json:"rejectedEnvelopeCount,omitempty"`
}

// String renders the status for logs without exposing any secret material.
func (s Status) String() string {
	registeredAt, lastPullAt := "-", "-"
	if !s.RegisteredAt.IsZero() {
		registeredAt = s.RegisteredAt.UTC().Format(time.RFC3339)
	}
	if !s.LastPullAt.IsZero() {
		lastPullAt = s.LastPullAt.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf(
		"enabled=%t state=%s reason=%s boxId=%s fingerprint=%s registeredAt=%s lastPullAt=%s activeEnvelopes=%d rejectedEnvelopes=%d",
		s.Enabled, s.State, s.Reason, s.BoxID, s.KeyFingerprint,
		registeredAt, lastPullAt, s.ActiveEnvelopeCount, s.RejectedEnvelopeCount,
	)
}

// Manager owns one bridge run loop. It is safe to read Status concurrently.
type Manager struct {
	enabled         bool
	client          control.Client
	boxID           string
	pollInterval    time.Duration
	logger          *log.Logger
	registerBackoff time.Duration
	requestTimeout  time.Duration
	keyStore        *keyStore
	credentials     *credentialStore
	verifier        Verifier
	done            chan struct{}

	mu                 sync.Mutex
	status             Status
	lastLoggedActive   int
	lastLoggedRejected int
}

// New validates and constructs a bridge Manager. It performs no I/O: an
// enabled bridge only generates its key, reads state and calls the platform
// from Run.
func New(options Options) (*Manager, error) {
	manager := &Manager{
		done:               make(chan struct{}),
		lastLoggedActive:   -1,
		lastLoggedRejected: -1,
		status:             Status{Enabled: options.Enabled},
	}
	if !options.Enabled {
		manager.status.State = StateDisabled
		return manager, nil
	}
	if strings.TrimSpace(options.StateDir) == "" {
		return nil, errors.New("box credential bridge requires a state directory")
	}
	if options.BoxID == "" || !boxIDPattern.MatchString(options.BoxID) {
		return nil, errors.New("box credential bridge requires a valid Box id")
	}
	if options.Client.Origin == "" || options.Client.NodeToken == "" {
		return nil, errors.New("box credential bridge requires the node control-plane client")
	}
	pollInterval := options.PollInterval
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	requestTimeout := options.requestTimeout
	if requestTimeout <= 0 {
		requestTimeout = defaultRequestTimeout
	}
	registerBackoff := options.registerBackoff
	if registerBackoff <= 0 {
		registerBackoff = defaultRegisterBackoff
	}
	logger := options.Logger
	if logger == nil {
		logger = log.Default()
	}
	stateRoot := options.StateDir
	manager.enabled = true
	manager.client = options.Client
	manager.boxID = options.BoxID
	manager.pollInterval = pollInterval
	manager.logger = logger
	manager.registerBackoff = registerBackoff
	manager.requestTimeout = requestTimeout
	manager.keyStore = newKeyStore(stateRoot, options.keyBits)
	manager.credentials = newCredentialStore(stateRoot)
	manager.verifier = options.Verifier
	manager.status.State = StateStarting
	manager.status.BoxID = options.BoxID
	return manager, nil
}

// Run executes the bridge until the context is cancelled or the platform
// reports a terminal condition (rotation required, node unauthorized, invalid
// contract). It closes Done on return.
func (m *Manager) Run(ctx context.Context) error {
	defer close(m.done)
	if !m.enabled {
		return nil
	}
	key, generated, err := m.keyStore.loadOrCreate()
	if err != nil {
		m.setStatus(StateError, ReasonKeyStoreUnavailable)
		return fmt.Errorf("box credential bridge: %w", err)
	}
	fingerprint := key.Fingerprint()
	stored, rejected, err := m.credentials.load(m.boxID, fingerprint)
	if err != nil {
		m.setStatus(StateError, ReasonCredentialStoreUnavailable)
		return fmt.Errorf("box credential bridge: %w", err)
	}
	m.setLocalSnapshot(fingerprint, len(stored), rejected)
	if generated {
		m.logger.Printf("box credential bridge: generated box encryption key fingerprint=%s", fingerprint)
	}
	if err := m.register(ctx, key); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	if m.pull(ctx, fingerprint) {
		return nil
	}
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if m.pull(ctx, fingerprint) {
				return nil
			}
		}
	}
}

// Status returns a consistent, secret-free snapshot of the bridge state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// Done is closed when Run returns. It lets serve stop the bridge cleanly.
func (m *Manager) Done() <-chan struct{} {
	return m.done
}

// register pins the public key with the platform, retrying transient failures
// with bounded exponential backoff. 409/401/400 are terminal for this process:
// the bridge must not invent a key rotation or a different identity.
func (m *Manager) register(ctx context.Context, key *Key) error {
	backoff := m.registerBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		callCtx, cancel := context.WithTimeout(ctx, m.requestTimeout)
		view, err := m.client.RegisterBoxEncryptionKey(callCtx, key.PublicJWK())
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var responseError *control.ResponseError
			if errors.As(err, &responseError) {
				switch responseError.Status {
				case http.StatusConflict:
					m.setStatus(StateBlocked, reasonOr(responseError.Code, ReasonKeyRotationRequired))
					return errors.New("box credential bridge registration is blocked: box_key_rotation_required")
				case http.StatusUnauthorized:
					m.setStatus(StateUnauthorized, reasonOr(responseError.Code, ReasonRuntimeNodeUnauthorized))
					return errors.New("box credential bridge registration is unauthorized: runtime_node_unauthorized")
				case http.StatusBadRequest:
					m.setStatus(StateError, ReasonInvalidPlatformResponse)
					return fmt.Errorf(
						"box credential bridge registration was refused: %s",
						reasonOr(responseError.Code, ReasonInvalidPlatformResponse),
					)
				}
			}
			m.setStatus(StateError, ReasonPlatformUnavailable)
			if !m.wait(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, maxRegisterBackoff)
			continue
		}
		if view.BoxID != m.boxID || view.KeyFingerprint != key.Fingerprint() {
			m.setStatus(StateError, ReasonInvalidPlatformResponse)
			return errors.New("box credential bridge registration response does not match the local box key")
		}
		registeredAt := view.RegisteredAt
		if registeredAt.IsZero() {
			registeredAt = time.Now().UTC()
		}
		m.mu.Lock()
		m.status.State = StateActive
		m.status.Reason = ""
		m.status.KeyFingerprint = key.Fingerprint()
		m.status.RegisteredAt = registeredAt.UTC()
		status := m.status
		m.mu.Unlock()
		m.logger.Printf("box credential bridge: registered fingerprint=%s registeredAt=%s", status.KeyFingerprint, registeredAt.UTC().Format(time.RFC3339))
		return nil
	}
}

// pull fetches one active delivery set, validates every item against this Box
// and key, and atomically replaces the local sealed store. It returns true when
// the loop must stop (node token rejected).
func (m *Manager) pull(ctx context.Context, fingerprint string) bool {
	callCtx, cancel := context.WithTimeout(ctx, m.requestTimeout)
	deliveries, err := m.client.ToolProviderCredentials(callCtx)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return false
		}
		return m.notePullFailure(err)
	}
	accepted := make(map[string]storedCredential, len(deliveries))
	rejected := 0
	for _, delivery := range deliveries {
		credential, validationError := validateCredential(delivery, m.boxID, fingerprint)
		if validationError != nil {
			rejected++
			continue
		}
		if _, duplicate := accepted[credential.CredentialID]; duplicate {
			rejected++
			continue
		}
		accepted[credential.CredentialID] = credential
	}
	if err := m.credentials.replace(accepted); err != nil {
		m.setStatus(StateError, ReasonCredentialStoreUnavailable)
		return false
	}
	now := time.Now().UTC()
	m.mu.Lock()
	m.status.State = StateActive
	m.status.LastPullAt = now
	m.status.ActiveEnvelopeCount = len(accepted)
	m.status.RejectedEnvelopeCount = rejected
	if rejected > 0 {
		m.status.Reason = ReasonInvalidCredentialItems
	} else {
		m.status.Reason = ""
	}
	activeCount, rejectedCount, reason :=
		m.status.ActiveEnvelopeCount, m.status.RejectedEnvelopeCount, m.status.Reason
	m.mu.Unlock()
	m.verifyDeliveries(ctx, deliveries)
	if activeCount != m.lastLoggedActive || rejectedCount != m.lastLoggedRejected {
		m.logger.Printf("box credential bridge: pull activeEnvelopes=%d rejectedEnvelopes=%d reason=%s", activeCount, rejectedCount, reason)
		m.lastLoggedActive = activeCount
		m.lastLoggedRejected = rejectedCount
	}
	return false
}

func (m *Manager) notePullFailure(err error) bool {
	var responseError *control.ResponseError
	if errors.As(err, &responseError) {
		switch responseError.Status {
		case http.StatusUnauthorized:
			m.setStatus(StateUnauthorized, reasonOr(responseError.Code, ReasonRuntimeNodeUnauthorized))
			return true
		case http.StatusConflict:
			m.setStatus(StateError, reasonOr(responseError.Code, ReasonKeyUnavailable))
		case http.StatusBadRequest:
			m.setStatus(StateError, ReasonInvalidPlatformResponse)
		default:
			m.setStatus(StateError, ReasonPlatformUnavailable)
		}
		return false
	}
	m.setStatus(StateError, ReasonPlatformUnavailable)
	return false
}

func (m *Manager) setLocalSnapshot(fingerprint string, active, rejected int) {
	m.mu.Lock()
	m.status.KeyFingerprint = fingerprint
	m.status.ActiveEnvelopeCount = active
	m.status.RejectedEnvelopeCount = rejected
	m.mu.Unlock()
}

func (m *Manager) setStatus(state, reason string) {
	m.mu.Lock()
	changed := m.status.State != state || m.status.Reason != reason
	m.status.State = state
	m.status.Reason = reason
	status := m.status
	m.mu.Unlock()
	if changed {
		m.logger.Printf("box credential bridge: status %s", status.String())
	}
}

func (m *Manager) wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// knownReasons restricts the platform-supplied code that can reach Status and
// logs to the contract's small failure vocabulary. An unexpected code falls
// back to a local reason rather than echoing arbitrary remote text.
var knownReasons = map[string]struct{}{
	ReasonKeyRotationRequired:          {},
	ReasonRuntimeNodeUnauthorized:      {},
	ReasonKeyUnavailable:               {},
	"box_key_fingerprint_mismatch":     {},
	"invalid_box_key":                  {},
	"box_key_too_small":                {},
	"invalid_tool_credential_envelope": {},
	"rate_limited":                     {},
}

func reasonOr(code, fallback string) string {
	if _, ok := knownReasons[code]; ok {
		return code
	}
	return fallback
}
