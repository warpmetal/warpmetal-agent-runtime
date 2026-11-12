package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

const maxResponseBytes = 2 << 20

// Endpoint-private raw readers may need the response metadata as well as bytes.
// The common request path still owns authentication, redirects and wire limits.
type controlPlaneBytes struct {
	Bytes         []byte
	Status        int
	ContentType   string
	ContentDigest string
}

var managedServiceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Client struct {
	Origin    string
	NodeToken string
	HTTP      *http.Client
}

type ResponseError struct {
	Status int
	Code   string
	Detail map[string]any
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("control-plane response %d (%s)", e.Status, e.Code)
}

func ErrorCode(err error) string {
	var response *ResponseError
	if errors.As(err, &response) {
		return response.Code
	}
	return ""
}

func (c Client) ManagedServiceEndpoint() string { return c.Origin }

type Registration struct {
	ServerID          string          `json:"serverId"`
	SupervisorVersion string          `json:"supervisorVersion"`
	ImageDigest       string          `json:"imageDigest,omitempty"`
	HostKeys          []model.HostKey `json:"hostKeys"`
}

type Registered struct {
	ServerID    string    `json:"serverId"`
	NodeToken   string    `json:"nodeToken"`
	ExpiresAt   time.Time `json:"expiresAt"`
	ManifestURL string    `json:"manifestUrl"`
	ReportURL   string    `json:"reportUrl"`
}

func (c Client) Register(
	ctx context.Context,
	bootstrap string,
	registration Registration,
) (Registered, error) {
	var result Registered
	err := c.request(
		ctx,
		http.MethodPost,
		"/internal/runtime/register",
		bootstrap,
		registration,
		&result,
		false,
	)
	if err != nil {
		return Registered{}, err
	}
	if !strings.HasPrefix(result.NodeToken, "rtn_") || result.ServerID != registration.ServerID {
		return Registered{}, errors.New("registration response identity is invalid")
	}
	return result, nil
}

func (c Client) Manifest(ctx context.Context) (model.Manifest, error) {
	var result model.Manifest
	err := c.request(
		ctx,
		http.MethodGet,
		"/internal/runtime/manifest",
		c.NodeToken,
		nil,
		&result,
		true,
	)
	return result, err
}

// ReportCellPreparation posts one node-authenticated prepared receipt to the
// protected POST /internal/runtime/cell-preparation endpoint and returns the
// exact prepared view. It never creates an execution grant; only a separately
// authorized registered-manager grant transitions the manifest to execute.
func (c Client) ReportCellPreparation(ctx context.Context, report model.CellPreparationReport) (model.CellPreparationView, error) {
	var view model.CellPreparationView
	err := c.request(
		ctx,
		http.MethodPost,
		"/internal/runtime/cell-preparation",
		c.NodeToken,
		report,
		&view,
		true,
	)
	return view, err
}

// ReportAck is the ordered acceptance view of one Runtime report (P3/R2).
type ReportAck struct {
	Accepted         bool  `json:"accepted"`
	Replayed         bool  `json:"replayed"`
	ReportEpoch      int64 `json:"reportEpoch"`
	DesiredRevision  int64 `json:"desiredRevision"`
	AppliedRevision  int64 `json:"appliedRevision"`
	ResyncGeneration int64 `json:"resyncGeneration"`
}

func (c Client) Report(ctx context.Context, report model.Report) error {
	_, err := c.ReportAck(ctx, report)
	return err
}

// ReportAck posts one report and returns its ordered acceptance view (P3/R2).
func (c Client) ReportAck(ctx context.Context, report model.Report) (ReportAck, error) {
	var response ReportAck
	if err := c.request(
		ctx,
		http.MethodPost,
		"/internal/runtime/report",
		c.NodeToken,
		report,
		&response,
		false,
	); err != nil {
		return ReportAck{}, err
	}
	if !response.Accepted {
		return response, errors.New("control plane did not accept report")
	}
	return response, nil
}

// CellCredentialResult carries the V3 discriminated material and immutable lease
// identity, or the retained V2 APIKey envelope. Plaintext is never journaled; the caller
// forwards it to the native protected store, keyed by CredentialID so a rotated
// lease is a distinct connection (never a stale reuse). ConnectionID and
// ConnectionRevision are the account-owned connection identity the Runtime must
// validate against the manifest credentialBinding, never discard.
type CellCredentialResult struct {
	CredentialID       string          `json:"credentialId"`
	APIKey             string          `json:"apiKey"`
	ConnectionID       string          `json:"connectionId"`
	ConnectionRevision int64           `json:"connectionRevision"`
	Material           json.RawMessage `json:"material,omitempty"`
}

// CellCredential unseals one cell-owner provider credential for this node over
// the authenticated control-plane transport.
func (c Client) CellCredential(ctx context.Context, serviceRegistrationID string) (CellCredentialResult, error) {
	result, err := c.fetchCellCredential(ctx, serviceRegistrationID)
	if err != nil {
		return CellCredentialResult{}, err
	}
	if (result.APIKey == "" && len(result.Material) == 0) || result.CredentialID == "" {
		return CellCredentialResult{}, errors.New("cell credential response is empty")
	}
	if result.ConnectionID == "" || result.ConnectionRevision < 1 {
		return CellCredentialResult{}, errors.New("cell credential response has no connection lease identity")
	}
	return result, nil
}

// CellCredentialWithTimeout fetches the SAME immutable cell-credential lease
// under an explicit per-request transport deadline. The default control-plane
// client aborts every request at its own Timeout (30s when unwired), which is
// shorter than the control-plane budget an idempotent lease fetch is allowed to
// use; a slow-but-healthy backend (a 22s manifest refresh was measured through
// the same venue transport) therefore failed every attempt at the transport
// deadline while the backend answered 200 (R-WP120-1).
//
// The receiver is never mutated and the underlying Transport (TLS roots,
// connection pool) is shared, only the per-request Timeout differs, so the
// call cannot weaken any other endpoint's transport bound.
func (c Client) CellCredentialWithTimeout(ctx context.Context, serviceRegistrationID string, timeout time.Duration) (CellCredentialResult, error) {
	if timeout <= 0 {
		return c.CellCredential(ctx, serviceRegistrationID)
	}
	deadline := timeout
	base := c.HTTP
	if base == nil {
		base = &http.Client{}
	}
	clone := *base
	clone.Timeout = deadline
	c.HTTP = &clone
	return c.CellCredential(ctx, serviceRegistrationID)
}

// LegacyCellCredential preserves the V2 key-only lease envelope. Only the
// retained V2 path calls this; V3 requires CellCredential plus its material union
// and exact connection binding and never falls back to this method.
func (c Client) LegacyCellCredential(ctx context.Context, serviceRegistrationID string) (CellCredentialResult, error) {
	result, err := c.fetchCellCredential(ctx, serviceRegistrationID)
	if err != nil {
		return CellCredentialResult{}, err
	}
	if result.APIKey == "" || result.CredentialID == "" || len(result.Material) != 0 {
		return CellCredentialResult{}, errors.New("legacy cell credential response is invalid")
	}
	return result, nil
}

func (c Client) fetchCellCredential(ctx context.Context, serviceRegistrationID string) (CellCredentialResult, error) {
	var result CellCredentialResult
	if err := c.request(
		ctx,
		http.MethodPost,
		"/internal/runtime/cell-credential",
		c.NodeToken,
		map[string]string{"serviceRegistrationId": serviceRegistrationID},
		&result,
		false,
	); err != nil {
		return CellCredentialResult{}, err
	}
	return result, nil
}

// ManagedCredentialResult carries the account-owned provider connection
// credential a DeepSeek managed service delivers to the packaged supervisor's
// protected DSH credential file before its child is spawned. The plaintext key
// is transient: the caller forwards it once over the supervisor's closed
// one-shot credential command and never journals, reports or re-reads it.
// ConnectionID/ConnectionRevision identify the exact account connection and
// KeyFingerprint is safe diagnostic evidence only, never the key.
type ManagedCredentialResult struct {
	CredentialID       string `json:"credentialId"`
	APIKey             string `json:"apiKey"`
	ConnectionID       string `json:"connectionId"`
	ConnectionRevision int64  `json:"connectionRevision"`
	ProviderID         string `json:"providerId,omitempty"`
	ModelID            string `json:"modelId,omitempty"`
	AuthMode           string `json:"authMode,omitempty"`
	KeyFingerprint     string `json:"keyFingerprint,omitempty"`
}

// ManagedServiceCredential resolves one managed service's account-provider
// credential over the authenticated control-plane transport. A missing
// provider connection is the control plane's provider_credential_missing
// response (404); callers map it to the service's stable failure code.
func (c Client) ManagedServiceCredential(ctx context.Context, serviceRegistrationID string) (ManagedCredentialResult, error) {
	var result ManagedCredentialResult
	if err := c.request(
		ctx,
		http.MethodPost,
		"/internal/runtime/managed-credential",
		c.NodeToken,
		map[string]string{"serviceRegistrationId": serviceRegistrationID},
		&result,
		false,
	); err != nil {
		return ManagedCredentialResult{}, err
	}
	if result.CredentialID == "" || result.APIKey == "" || result.ConnectionID == "" || result.ConnectionRevision < 1 {
		return ManagedCredentialResult{}, errors.New("managed credential response is incomplete")
	}
	return result, nil
}

func (c Client) InsightPolicies(ctx context.Context) (model.InsightPolicyEnvelopeV1, error) {
	var result model.InsightPolicyEnvelopeV1
	err := c.request(ctx, http.MethodGet, "/internal/runtime/insights/policies", c.NodeToken, nil, &result, true)
	return result, err
}

func (c Client) SubmitInsightBatch(ctx context.Context, batch model.InsightBatchV1) (model.InsightBatchReceiptV1, error) {
	var result model.InsightBatchReceiptV1
	payload, err := json.Marshal(batch)
	if err != nil {
		return result, err
	}
	if len(payload) > 64*1024 {
		return result, errors.New("insights batch exceeds the allowed size")
	}
	err = c.request(ctx, http.MethodPost, "/internal/runtime/insights/batches", c.NodeToken, batch, &result, true)
	return result, err
}

func (c Client) ReserveInsightsManagerReview(
	ctx context.Context,
	request model.InsightsManagerReservationRequestV1,
) (model.InsightsManagerReservationV1, error) {
	var result model.InsightsManagerReservationV1
	payload, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	if len(payload) > 64*1024 {
		return result, errors.New("insights manager reservation exceeds the allowed size")
	}
	err = c.request(
		ctx,
		http.MethodPost,
		"/internal/runtime/insights/manager/reservations",
		c.NodeToken,
		request,
		&result,
		true,
	)
	return result, err
}

// GetInsightsManagerTarget performs the r1370 node-authorized canonical
// descriptor read: GET /internal/runtime/insights/manager/target with exactly
// findingId and registeredSourceId, no body, and a closed typed response.
func (c Client) GetInsightsManagerTarget(ctx context.Context, findingID string, registeredSourceID string) (model.InsightsManagerTargetEnvelopeV1, error) {
	var result model.InsightsManagerTargetEnvelopeV1
	query := url.Values{}
	query.Set("findingId", findingID)
	query.Set("registeredSourceId", registeredSourceID)
	path := "/internal/runtime/insights/manager/target?" + query.Encode()
	if err := c.request(ctx, http.MethodGet, path, c.NodeToken, nil, &result, true); err != nil {
		return model.InsightsManagerTargetEnvelopeV1{}, err
	}
	if result.FormatVersion != 1 || result.FindingID != findingID || result.FindingRevision < 1 ||
		result.Source.RegisteredSourceID != registeredSourceID || !validCanonicalTarget(result.Target) {
		return model.InsightsManagerTargetEnvelopeV1{}, errors.New("insights manager target response is invalid")
	}
	return result, nil
}

func validCanonicalTarget(target model.InsightsManagerTargetV1) bool {
	if (target.TaskID == nil) != (target.TaskAttempt == nil) || target.TaskAttempt != nil && *target.TaskAttempt < 1 {
		return false
	}
	work := target.WorkID != nil
	if work != (target.WorkRevision != nil) || work != (target.BindingID != nil) || work != (target.BindingRevision != nil) {
		return false
	}
	return !work || *target.WorkRevision >= 1 && *target.BindingRevision >= 1
}

func (c Client) SubmitInsightsManagerRunReport(
	ctx context.Context,
	report model.InsightsManagerRunReportV1,
) (model.InsightsManagerActivityV1, error) {
	var result model.InsightsManagerActivityV1
	payload, err := json.Marshal(report)
	if err != nil {
		return result, err
	}
	if len(payload) > 64*1024 {
		return result, errors.New("insights manager run report exceeds the allowed size")
	}
	err = c.request(
		ctx,
		http.MethodPost,
		"/internal/runtime/insights/manager/reports",
		c.NodeToken,
		report,
		&result,
		true,
	)
	if err == nil && (result.RunID != report.RunID || result.ReservationID != report.ReservationID ||
		result.Manual != report.Manual || !reflect.DeepEqual(result.Source, report.Source) ||
		!reflect.DeepEqual(result.Target, report.Target) || result.State != report.State) {
		return model.InsightsManagerActivityV1{}, errors.New("insights manager run report response identity is invalid")
	}
	return result, err
}

func (c Client) ManagedServiceEnrollment(ctx context.Context, serviceID string, request model.ManagedServiceFetchRequestV1) (model.ManagedServiceEnrollmentV1, error) {
	var result model.ManagedServiceEnrollmentV1
	if !managedServiceIDPattern.MatchString(serviceID) || request.ServiceRegistrationID != serviceID {
		return result, errors.New("managed service enrollment identity is invalid")
	}
	err := c.request(ctx, http.MethodPost, "/internal/runtime/agent-teams/managed-services/"+serviceID+"/enrollment", c.NodeToken, request, &result, true)
	if err != nil {
		return model.ManagedServiceEnrollmentV1{}, err
	}
	if !strings.HasPrefix(result.EnrollmentID, "tel_") || !strings.HasPrefix(result.EnrollmentToken, "ten_") || result.ExchangePath != "/internal/runtime/agent-teams/enrollments/exchange" || result.EnrollmentExpiresAt.IsZero() {
		return model.ManagedServiceEnrollmentV1{}, errors.New("managed service enrollment response is invalid")
	}
	return result, nil
}

func (c Client) ManagedServiceInstructions(ctx context.Context, serviceID string, request model.ManagedServiceFetchRequestV1) (model.ManagedServiceInstructionV1, error) {
	var result model.ManagedServiceInstructionV1
	if !managedServiceIDPattern.MatchString(serviceID) || request.ServiceRegistrationID != serviceID {
		return result, errors.New("managed service instruction identity is invalid")
	}
	err := c.request(ctx, http.MethodPost, "/internal/runtime/agent-teams/managed-services/"+serviceID+"/instructions", c.NodeToken, request, &result, true)
	if err != nil {
		return model.ManagedServiceInstructionV1{}, err
	}
	if result.InstructionRevision < 1 || len(result.Content) == 0 || len([]byte(result.Content)) > 32768 || strings.ContainsRune(result.Content, '\x00') || result.ExpiresAt.IsZero() || fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(result.Content))) != result.InstructionDigest {
		return model.ManagedServiceInstructionV1{}, errors.New("managed service instruction response is invalid")
	}
	return result, nil
}

func (c Client) request(
	ctx context.Context,
	method string,
	path string,
	token string,
	body any,
	result any,
	strict bool,
) error {
	return c.requestWithKey(ctx, method, path, token, body, result, strict, "")
}

func (c Client) requestWithKey(ctx context.Context, method, path, token string, body, result any, strict bool, idempotencyKey string) error {
	return c.requestWithWorkflowLease(ctx, method, path, token, body, result, strict, idempotencyKey, "")
}

func (c Client) requestWithWorkflowLease(ctx context.Context, method, path, token string, body, result any, strict bool, idempotencyKey, workflowLease string) error {
	return c.requestWithResponseLimit(ctx, method, path, token, body, result, strict, idempotencyKey, workflowLease, 0)
}

// A positive maximum is endpoint-selected and counts the WHOLE response wire,
// including whitespace, rather than the decoded JSON projection. Zero preserves
// the existing transport behavior/caps for every unrelated caller.
func (c Client) requestWithResponseLimit(ctx context.Context, method, path, token string, body, result any, strict bool, idempotencyKey, workflowLease string, maximum int) error {
	origin, err := url.Parse(c.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" {
		return errors.New("control-plane origin must be an absolute HTTPS URL")
	}
	origin.Path = path
	origin.RawQuery = ""
	if index := strings.IndexByte(path, '?'); index >= 0 {
		origin.Path, origin.RawQuery = path[:index], path[index+1:]
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, origin.String(), payload)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "warpmetald/1")
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if workflowLease != "" {
		request.Header.Set("X-WarpMetal-Workflow-Lease", workflowLease)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if workflowLease != "" {
		// Action authority cannot follow redirects or spread the independently
		// enrolled workflow lease to another host/path. Old request behavior stays
		// unchanged for callers without this additive protected action header.
		copy := *httpClient
		copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		httpClient = &copy
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("control-plane request failed: %w", err)
	}
	defer response.Body.Close()
	var limited io.Reader = io.LimitReader(response.Body, maxResponseBytes)
	if maximum > 0 {
		raw, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
		if err != nil {
			return fmt.Errorf("read control-plane response: %w", err)
		}
		if len(raw) > maximum {
			return errors.New("control-plane response exceeds endpoint wire cap")
		}
		limited = bytes.NewReader(raw)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var apiError struct {
			Error struct {
				Code   string         `json:"code"`
				Detail map[string]any `json:"detail"`
			} `json:"error"`
		}
		_ = json.NewDecoder(limited).Decode(&apiError)
		code := apiError.Error.Code
		if code == "" {
			code = "unexpected_status"
		}
		return &ResponseError{Status: response.StatusCode, Code: code, Detail: apiError.Error.Detail}
	}
	// Fixed private byte readers reuse the SAME origin/auth/redirect/response
	// boundary. Raw output requires an explicit endpoint cap, never JSON coercion.
	var raw *[]byte
	var metadata *controlPlaneBytes
	switch value := result.(type) {
	case *[]byte:
		raw = value
	case *controlPlaneBytes:
		raw, metadata = &value.Bytes, value
	}
	if raw != nil {
		if maximum <= 0 {
			return errors.New("raw control-plane response requires endpoint cap")
		}
		content, err := io.ReadAll(limited)
		if err != nil {
			return err
		}
		*raw = content
		if metadata != nil {
			metadata.Status = response.StatusCode
			metadata.ContentType = response.Header.Get("Content-Type")
			metadata.ContentDigest = response.Header.Get("X-Content-Digest")
		}
		return nil
	}
	decoder := json.NewDecoder(limited)
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(result); err != nil {
		return fmt.Errorf("decode control-plane response: %w", err)
	}
	if strict {
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			if err == nil {
				return errors.New("decode control-plane response: trailing JSON value")
			}
			return fmt.Errorf("decode control-plane response: %w", err)
		}
	}
	return nil
}
