package physicalgate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func (a *AccessRegistry) VerifyAdmissionOriginal(ctx context.Context, c Caller, id string, request model.PhysicalAdmitRequest) error {
	e, err := a.Enrollment(ctx, request.PreparationID)
	if err != nil || e.Caller != c || id != "pg_"+model.WorkspaceDigest(request)[7:] {
		return ErrPrerequisite
	}
	if _, err = a.Permit(ctx, c, request); err != nil {
		return err
	}
	original, err := a.Store.PhysicalFact(ctx, "probe_request_"+id)
	if err != nil || len(original) == 0 || len(original) > 65536 || accessRequestDigest(original, e.Context) != request.RequestDigest {
		return ErrPrerequisite
	}
	return verifyAccessRequestOriginal(original, e.Context)
}

// Exact constructed one-shot credentialed GET, not context metadata as wire proof.
func verifyAccessRequestOriginal(raw []byte, input model.QualificationAccessContext) error {
	reader := bufio.NewReader(bytes.NewReader(raw))
	r, err := http.ReadRequest(reader)
	if err != nil {
		return ErrPrerequisite
	}
	defer r.Body.Close()
	expected, err := url.Parse(accessEndpoint(input))
	if err != nil || expected.Host == "" || input.Request.Method != "GET" || input.Request.URL != expected.String() || r.Method != "GET" || r.Host != expected.Host || r.URL.RequestURI() != expected.RequestURI() || r.Proto != "HTTP/1.1" || !r.Close || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return ErrPrerequisite
	}
	if len(r.Header) != 5 || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("Connection")) != 1 || r.Header.Get("Connection") != "close" || len(r.Header.Values("Accept")) != 1 || len(r.Header.Values("Accept-Encoding")) != 1 || len(r.Header.Values("User-Agent")) != 1 || r.Header.Get("Accept") != "application/json" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("User-Agent") != "warpmetal-runtime-access" {
		return ErrPrerequisite
	}
	credential := r.Header.Get("Authorization")
	if !strings.HasPrefix(credential, "Bearer ") || len(credential) <= 7 || len(credential) > 4103 || strings.ContainsAny(credential[7:], "\r\n") {
		return ErrPrerequisite
	}
	if body, err := io.ReadAll(io.LimitReader(r.Body, 1)); err != nil || len(body) != 0 {
		return ErrPrerequisite
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		return ErrPrerequisite
	}
	return nil
}

const accessURL = "https://api.openai.com/v1/models/gpt-4.1-mini-2025-04-14"

// The version chooses an immutable owner descriptor, never an input URL.
func accessEndpoint(c model.QualificationAccessContext) string {
	if c.FormatVersion == 2 {
		if c.ProviderPolicyDigest != providerpolicy.FlashDigest || c.AccountingVersion != 2 {
			return ""
		}
		return providerpolicy.Flash().Access.URL
	}
	if c.FormatVersion == 1 {
		return accessURL
	}
	return ""
}
func accessProvider(c model.QualificationAccessContext) string {
	if c.FormatVersion == 2 && accessEndpoint(c) != "" {
		return providerpolicy.Flash().ProviderID
	}
	if c.FormatVersion == 1 {
		return "openai"
	}
	return ""
}
func accessRequestDigest(original []byte, c model.QualificationAccessContext) string {
	if c.FormatVersion == 2 {
		return model.RawPhysicalDigest(nil)
	}
	return model.RawPhysicalDigest(original)
}

// Secret-free original access evidence for the existing owning attester. This is
// NOT an attestation, signature, accepted qualification, new slot or dispatch ACK.
type AccessProbeResult struct {
	OperationID    string
	RequestDigest  string
	ResponseDigest string
	Response       []byte
	Settlement     model.PhysicalSettlement
	// Exact separately retained original JSON. The original five-field
	// completion and Settlement.EvidenceDigest are deliberately unchanged.
	Observation json.RawMessage
}
type AccessProbeObservation struct {
	FormatVersion     int    `json:"formatVersion"`
	Purpose           string `json:"purpose"`
	OperationID       string `json:"operationId"`
	RequestDigest     string `json:"requestDigest"`
	ResponseDigest    string `json:"responseDigest"`
	EvidenceDigest    string `json:"evidenceDigest"`
	ProviderRequestID string `json:"providerRequestId"`
	StartedAt         string `json:"startedAt"`
	CompletedAt       string `json:"completedAt"`
}

var accessProviderRequestID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`)

type accessCompletion struct {
	RequestDigest     string `json:"requestDigest"`
	ResponseDigest    string `json:"responseDigest"`
	ResponseByteCount int    `json:"responseByteCount"`
	HTTPStatus        int    `json:"httpStatus"`
	UsageUsdMicros    int64  `json:"usageUsdMicros"`
}

// Exactly one independently enrolled access probe, not a generic executor. No
// credentials, transport, endpoint or identity can be selected by the RPC/model.
func (a *AccessRegistry) RunProbe(ctx context.Context, preparationID, key string, connection model.CellCredentialBindingV3) (AccessProbeResult, error) {
	var empty AccessProbeResult
	if a == nil || a.Store == nil || !a.dispatch.TryLock() {
		return empty, ErrPrerequisite
	}
	defer a.dispatch.Unlock()
	e, err := a.Enrollment(ctx, preparationID)
	if err != nil || e.Connection != connection || connection.ProviderID != accessProvider(e.Context) || connection.AuthMode != "api_key" {
		return empty, ErrPrerequisite
	}
	actual, err := observeOwnAccessProcess()
	if err != nil || !reflect.DeepEqual(actual, e.Process) || !time.Now().Before(e.AuthorizedUntil) || e.Context.Validate(e.Context.QualificationID, time.Now()) != nil {
		return empty, ErrPrerequisite
	}
	a.mu.Lock()
	a.active = &e.Caller
	a.mu.Unlock()
	// A fresh nonpooled HTTP/1 transport cannot replay an idempotent GET on a
	// stale/reused connection. No redirects, automatic retries or provider fallback.
	transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	defer transport.CloseIdleConnections()
	return a.runProbe(ctx, e, key, HostSocket, transport)
}

// The normal caller above fixes socket and transport. Tests invoke this private
// boundary with explicitly detached local socket/network/authority suppliers.
func (a *AccessRegistry) runProbe(ctx context.Context, e AccessEnrollment, key, socket string, transport http.RoundTripper) (AccessProbeResult, error) {
	var empty AccessProbeResult
	endpoint := accessEndpoint(e.Context)
	if endpoint == "" || e.Context.Request.Method != "GET" || e.Context.Request.URL != endpoint || key == "" || len(key) > 4096 || strings.ContainsAny(key, "\r\n") {
		return empty, ErrPrerequisite
	}
	expires, err := time.Parse(time.RFC3339Nano, e.Context.ExpiresAt)
	if err != nil || !time.Now().Before(expires) {
		return empty, ErrPrerequisite
	}
	if e.AuthorizedUntil.Before(expires) {
		expires = e.AuthorizedUntil
	}
	if !time.Now().Before(expires) {
		return empty, ErrPrerequisite
	}
	if deadline := time.Now().Add(120 * time.Second); deadline.Before(expires) {
		expires = deadline
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return empty, err
	}
	request.Close = true
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "warpmetal-runtime-access")
	var original bytes.Buffer
	if request.Write(&original) != nil || original.Len() > 65536 {
		return empty, ErrPrerequisite
	}
	body := model.PhysicalAdmitRequest{Consumer: "access", PreparationID: e.Context.PreparationID, RequestIndex: 1, OuterPhysicalIndex: accessOuterIndex(e), AuthorityDigest: e.Context.AuthorityDigest, RequestDigest: accessRequestDigest(original.Bytes(), e.Context)}
	if body.Validate() != nil {
		return empty, ErrPrerequisite
	}
	id := "pg_" + model.WorkspaceDigest(body)[7:]
	// Private Runtime originals precede admission; no shared home/credentials.
	if err = a.Store.RetainPhysicalFact(ctx, "probe_request_"+id, original.Bytes()); err != nil {
		return empty, err
	}
	wire, _ := json.Marshal(body)
	ack, err := Call(ctx, socket, model.PhysicalRPCRequest{FormatVersion: 1, Action: "admit", OperationID: id, Body: wire})
	if err != nil || ack.Status != "admitted" || ack.Error != nil {
		return empty, ErrPrerequisite
	}
	startedAt := time.Now().UTC()
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("access redirect refused") }}).Do(request)
	if err != nil {
		return empty, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	completedAt := time.Now().UTC() // Actual body EOF/read completion in THIS request.
	if err != nil || len(raw) > 65536 || response.StatusCode != 200 || response.Request == nil || response.Request.URL.String() != endpoint || !accessContextResponseValid(raw, e.Context) {
		return empty, ErrPrerequisite
	}
	completion := accessCompletion{RequestDigest: body.RequestDigest, ResponseDigest: model.RawPhysicalDigest(raw), ResponseByteCount: len(raw), HTTPStatus: response.StatusCode, UsageUsdMicros: 0}
	metadata, _ := json.Marshal(completion)
	if err = a.Store.RetainPhysicalFact(ctx, "probe_response_"+id, raw); err != nil {
		return empty, err
	}
	if err = a.Store.RetainPhysicalFact(ctx, "probe_completion_"+id, metadata); err != nil {
		return empty, err
	}
	// Only this one safe response header leaves the private transport. Missing,
	// ambiguous or malformed IDs stay UNKNOWN; no follow-up GET or generated ID.
	ids := response.Header.Values("X-Request-Id")
	if len(ids) != 1 || !accessProviderRequestID.MatchString(ids[0]) || completedAt.Before(startedAt) || completedAt.After(expires) {
		return empty, ErrPrerequisite
	}
	observation, _ := json.Marshal(AccessProbeObservation{FormatVersion: 1, Purpose: "qualification_access_observation", OperationID: id, RequestDigest: completion.RequestDigest, ResponseDigest: completion.ResponseDigest, EvidenceDigest: model.RawPhysicalDigest(metadata), ProviderRequestID: ids[0], StartedAt: startedAt.Format(time.RFC3339Nano), CompletedAt: completedAt.Format(time.RFC3339Nano)})
	if err = a.Store.RetainPhysicalFact(ctx, "probe_observation_"+id, observation); err != nil {
		return empty, err
	}
	settlement := model.PhysicalSettlement{RequestDigest: completion.RequestDigest, ResponseDigest: completion.ResponseDigest, ResponseByteCount: completion.ResponseByteCount, HTTPStatus: 200, UsageUsdMicros: 0, EvidenceDigest: model.RawPhysicalDigest(metadata)}
	wire, _ = json.Marshal(settlement)
	ack, err = Call(ctx, socket, model.PhysicalRPCRequest{FormatVersion: 1, Action: "settle", OperationID: id, Body: wire})
	if err != nil || ack.Status != "settled" || ack.Error != nil {
		return empty, ErrPrerequisite
	}
	boundObservation, err := a.ReadProbeObservation(ctx, id)
	if err != nil {
		return empty, err
	}
	return AccessProbeResult{OperationID: id, RequestDigest: body.RequestDigest, ResponseDigest: completion.ResponseDigest, Response: raw, Settlement: settlement, Observation: boundObservation}, nil
}

// Existing private access-result owner readback, NOT an RPC/action or attester.
// Old/missing originals refuse; this reader never supplies a clock/request ID.
func (a *AccessRegistry) ReadProbeObservation(ctx context.Context, id string) (json.RawMessage, error) {
	if a == nil || a.Store == nil || !model.PhysicalIDValid(id) {
		return nil, ErrPrerequisite
	}
	o, err := a.Store.PhysicalOperation(ctx, id)
	if err != nil || o == nil || o.Permit.Request.Consumer != "access" || o.Phase != "settled" || o.Settlement == nil || a.VerifySettlement(ctx, Caller{SandboxID: o.Permit.Caller.SandboxID, SandboxGeneration: o.Permit.Caller.SandboxGeneration, NativeInstance: o.Permit.Caller.NativeInstance, NativeIdentityDigest: o.Permit.Caller.NativeIdentityDigest}, *o, *o.Settlement) != nil {
		return nil, ErrPrerequisite
	}
	raw, err := a.Store.PhysicalFact(ctx, "probe_observation_"+id)
	var observed AccessProbeObservation
	if err != nil || len(raw) > 2048 || model.DecodePhysicalClosed(raw, &observed) != nil || observed.FormatVersion != 1 || observed.Purpose != "qualification_access_observation" || observed.OperationID != id || observed.RequestDigest != o.Settlement.RequestDigest || observed.ResponseDigest != o.Settlement.ResponseDigest || observed.EvidenceDigest != o.Settlement.EvidenceDigest || !accessProviderRequestID.MatchString(observed.ProviderRequestID) {
		return nil, ErrPrerequisite
	}
	start, se := time.Parse(time.RFC3339Nano, observed.StartedAt)
	end, ee := time.Parse(time.RFC3339Nano, observed.CompletedAt)
	if se != nil || ee != nil || end.Before(start) || end.After(time.Now()) || end.Sub(start) > 120*time.Second {
		return nil, ErrPrerequisite
	}
	return append(json.RawMessage(nil), raw...), nil
}
func accessOuterIndex(e AccessEnrollment) int {
	var allocation struct {
		FirstPhysicalIndex int `json:"firstPhysicalIndex"`
	}
	if json.Unmarshal(e.Context.Allocation, &allocation) != nil {
		return 0
	}
	return allocation.FirstPhysicalIndex
}
func accessResponseValid(raw []byte) bool {
	var fields map[string]json.RawMessage
	if model.DecodePhysicalClosed(raw, &fields) != nil {
		return false
	}
	var id, kind string
	return json.Unmarshal(fields["id"], &id) == nil && json.Unmarshal(fields["object"], &kind) == nil && id == "gpt-4.1-mini-2025-04-14" && kind == "model"
}
func accessContextResponseValid(raw []byte, c model.QualificationAccessContext) bool {
	if c.FormatVersion != 2 {
		return accessResponseValid(raw)
	}
	if accessEndpoint(c) == "" {
		return false
	}
	var catalog struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}
	var fields map[string]json.RawMessage
	if model.DecodePhysicalClosed(raw, &fields) != nil || json.Unmarshal(raw, &catalog) != nil || catalog.Object != "list" {
		return false
	}
	count := 0
	for _, raw := range catalog.Data {
		var entry struct {
			ID     string `json:"id"`
			Object string `json:"object"`
		}
		if json.Unmarshal(raw, &entry) != nil {
			return false
		}
		if entry.ID == providerpolicy.Flash().Access.ExpectedModelID && entry.Object == "model" {
			count++
		}
	}
	return count == 1
}
func (a *AccessRegistry) VerifySettlement(ctx context.Context, c Caller, o state.PhysicalOperation, e model.PhysicalSettlement) error {
	if a == nil || a.Store == nil || o.Permit.Caller != c.Subject() || o.Permit.Request.Consumer != "access" || e.HTTPStatus != 200 || e.UsageUsdMicros != 0 {
		return ErrPrerequisite
	}
	input := model.QualificationAccessContext{FormatVersion: 1}
	input.Request.Method, input.Request.URL = "GET", accessURL
	if o.Permit.Case.AccountingVersion == 2 {
		enrolled, err := a.Enrollment(ctx, o.Permit.Request.PreparationID)
		if err != nil || enrolled.Caller != c || enrolled.Case != o.Permit.Case || enrolled.Context.FormatVersion != 2 || enrolled.Context.ProviderPolicyDigest != o.Permit.Case.ProviderPolicyDigest {
			return ErrPrerequisite
		}
		input = enrolled.Context
	}
	request, err := a.Store.PhysicalFact(ctx, "probe_request_"+o.OperationID)
	if err != nil || accessRequestDigest(request, input) != o.Permit.Request.RequestDigest || e.RequestDigest != o.Permit.Request.RequestDigest || verifyAccessRequestOriginal(request, input) != nil {
		return ErrPrerequisite
	}
	response, err := a.Store.PhysicalFact(ctx, "probe_response_"+o.OperationID)
	if err != nil || model.RawPhysicalDigest(response) != e.ResponseDigest || len(response) != e.ResponseByteCount || !accessContextResponseValid(response, input) {
		return ErrPrerequisite
	}
	raw, err := a.Store.PhysicalFact(ctx, "probe_completion_"+o.OperationID)
	var observed accessCompletion
	if err != nil || model.DecodePhysicalClosed(raw, &observed) != nil || model.RawPhysicalDigest(raw) != e.EvidenceDigest || observed != (accessCompletion{RequestDigest: e.RequestDigest, ResponseDigest: e.ResponseDigest, ResponseByteCount: e.ResponseByteCount, HTTPStatus: e.HTTPStatus, UsageUsdMicros: e.UsageUsdMicros}) {
		return ErrPrerequisite
	}
	if input.FormatVersion == 2 {
		observation, err := a.Store.PhysicalFact(ctx, "probe_observation_"+o.OperationID)
		var original AccessProbeObservation
		if err != nil || model.DecodePhysicalClosed(observation, &original) != nil || original.FormatVersion != 1 || original.Purpose != "qualification_access_observation" || original.OperationID != o.OperationID || original.RequestDigest != e.RequestDigest || original.ResponseDigest != e.ResponseDigest || original.EvidenceDigest != e.EvidenceDigest || !accessProviderRequestID.MatchString(original.ProviderRequestID) {
			return ErrPrerequisite
		}
		journal, _ := json.Marshal(o.Permit.Request)
		transport, _ := json.Marshal(map[string]string{"method": "GET", "url": accessEndpoint(input), "bodyDigest": e.RequestDigest})
		metadata, _ := json.Marshal(map[string]any{"formatVersion": 1, "providerRequestId": original.ProviderRequestID})
		return a.Store.RetainNativeSettlementOriginals(ctx, o.OperationID, c.Subject(), e, state.NativeSettlementOriginals{Journal: journal, Request: []byte{}, Response: response, Completion: raw, Transport: transport, ProviderRequestID: original.ProviderRequestID, ProviderResponse: metadata})
	}
	return nil
}
