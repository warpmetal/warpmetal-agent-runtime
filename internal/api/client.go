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

var managedServiceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Client struct {
	Origin    string
	NodeToken string
	HTTP      *http.Client
}

type ResponseError struct {
	Status int
	Code   string
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

func (c Client) Report(ctx context.Context, report model.Report) error {
	var response struct {
		Accepted bool `json:"accepted"`
	}
	if err := c.request(
		ctx,
		http.MethodPost,
		"/internal/runtime/report",
		c.NodeToken,
		report,
		&response,
		false,
	); err != nil {
		return err
	}
	if !response.Accepted {
		return errors.New("control plane did not accept report")
	}
	return nil
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
	origin, err := url.Parse(c.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" {
		return errors.New("control-plane origin must be an absolute HTTPS URL")
	}
	origin.Path = path
	origin.RawQuery = ""
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
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("control-plane request failed: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var apiError struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(limited).Decode(&apiError)
		code := apiError.Error.Code
		if code == "" {
			code = "unexpected_status"
		}
		return &ResponseError{Status: response.StatusCode, Code: code}
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
