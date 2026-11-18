package boxcredentials

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
)

const (
	// VerificationVerified means the provider accepted the credential at its
	// read-only status endpoint.
	VerificationVerified = "verified"
	// VerificationRejected means the provider refused the credential.
	VerificationRejected = "rejected"
	// VerificationUnsupported means the Box could not perform a safe check.
	VerificationUnsupported = "unsupported"

	// ReasonVerifierUnavailable means no reviewed verifier is configured.
	ReasonVerifierUnavailable = "verifier_unavailable"
	// ReasonCredentialOpenFailed means the sealed credential could not be
	// opened locally; the owner must reconnect it rather than retry forever.
	ReasonCredentialOpenFailed = "credential_open_failed"
	// ReasonVerifierError means the verifier failed without a provider verdict.
	ReasonVerifierError = "verifier_error"
	// ReasonInvalidVerificationResult means a verifier returned an unknown
	// outcome code.
	ReasonInvalidVerificationResult = "invalid_verification_result"
)

var (
	verificationRequestIDPattern = regexp.MustCompile(`^tpv_[A-Za-z0-9_-]{8,80}$`)
	verificationErrorCodePattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

// VerificationRequest is one owner-requested authentication check delivered
// alongside a sealed credential. RequestedAt is metadata only.
type VerificationRequest struct {
	RequestID   string
	RequestedAt time.Time
}

// VerificationResult is the closed outcome a Verifier may return. ErrorCode is
// a bounded, non-secret identifier; it is never provider output.
type VerificationResult struct {
	Outcome   string
	ErrorCode string
}

// Verifier runs one read-only provider status probe with an opened credential.
// Implementations must not persist, log or retain the credential. A nil
// verifier is treated as "verification unsupported", never as a provider
// rejection.
type Verifier interface {
	VerifyCredential(ctx context.Context, credential *Credential, request VerificationRequest) VerificationResult
}

// verifyDeliveries executes every pending verification request in a delivery
// snapshot, then reports a bounded result to the platform. Verification failures
// never fail the pull itself: the sealed envelope remains usable and the next
// pull retries an unreported request.
func (m *Manager) verifyDeliveries(ctx context.Context, deliveries []control.ToolProviderCredentialDelivery) {
	for _, delivery := range deliveries {
		if delivery.Verification == nil || ctx.Err() != nil {
			continue
		}
		requestID := strings.TrimSpace(delivery.Verification.RequestID)
		if !verificationRequestIDPattern.MatchString(requestID) {
			continue
		}
		result := m.verifyOne(ctx, delivery, requestID)
		if err := m.client.ReportToolProviderCredentialVerification(
			ctx,
			delivery.CredentialID,
			control.ToolProviderCredentialVerificationResult{
				RequestID: requestID,
				Outcome:   result.Outcome,
				ErrorCode: result.ErrorCode,
			},
		); err != nil && ctx.Err() == nil {
			m.logger.Printf("box credential bridge: verification report failed credential=%s outcome=%s", delivery.CredentialID, result.Outcome)
		}
	}
}

func (m *Manager) verifyOne(ctx context.Context, delivery control.ToolProviderCredentialDelivery, requestID string) VerificationResult {
	if m.verifier == nil {
		return VerificationResult{Outcome: VerificationUnsupported, ErrorCode: ReasonVerifierUnavailable}
	}
	credential, err := m.OpenCredential(delivery.CredentialID, OpenExpectations{})
	if err != nil {
		return VerificationResult{Outcome: VerificationUnsupported, ErrorCode: ReasonCredentialOpenFailed}
	}
	defer credential.Destroy()
	request := VerificationRequest{RequestID: requestID}
	if delivery.Verification.RequestedAt != "" {
		if parsed, parseErr := time.Parse(time.RFC3339, delivery.Verification.RequestedAt); parseErr == nil {
			request.RequestedAt = parsed.UTC()
		}
	}
	result := m.verifier.VerifyCredential(ctx, credential, request)
	switch result.Outcome {
	case VerificationVerified:
		return VerificationResult{Outcome: VerificationVerified}
	case VerificationRejected:
		return VerificationResult{Outcome: VerificationRejected, ErrorCode: boundedVerificationCode(result.ErrorCode, ReasonVerifierError)}
	case VerificationUnsupported:
		return VerificationResult{Outcome: VerificationUnsupported, ErrorCode: boundedVerificationCode(result.ErrorCode, ReasonVerifierUnavailable)}
	default:
		return VerificationResult{Outcome: VerificationUnsupported, ErrorCode: ReasonInvalidVerificationResult}
	}
}

func boundedVerificationCode(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || !verificationErrorCodePattern.MatchString(value) {
		return fallback
	}
	return value
}

var _ = errors.New
