package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

const maxResponseBytes = 2 << 20

type Client struct {
	Origin    string
	NodeToken string
	HTTP      *http.Client
}

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
		"/api/internal/runtime/register",
		bootstrap,
		registration,
		&result,
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
		"/api/internal/runtime/manifest",
		c.NodeToken,
		nil,
		&result,
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
		"/api/internal/runtime/report",
		c.NodeToken,
		report,
		&response,
	); err != nil {
		return err
	}
	if !response.Accepted {
		return errors.New("control plane did not accept report")
	}
	return nil
}

func (c Client) request(
	ctx context.Context,
	method string,
	path string,
	token string,
	body any,
	result any,
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
		return fmt.Errorf("control-plane response %d (%s)", response.StatusCode, code)
	}
	if err := json.NewDecoder(limited).Decode(result); err != nil {
		return fmt.Errorf("decode control-plane response: %w", err)
	}
	return nil
}
