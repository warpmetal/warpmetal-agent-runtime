package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type insightBackendFixture struct {
	Batch model.InsightBatchV1 `json:"batch"`
}

func TestInsightsNodeClientFetchesClosedPolicyAndPostsSanitizedBatch(t *testing.T) {
	payload, err := os.ReadFile("testdata/agent-insights-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture insightBackendFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2026, 9, 27, 18, 2, 0, 0, time.UTC)
	policy := model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{{
		SandboxID: fixture.Batch.SandboxID, Revision: fixture.Batch.PolicyRevision,
		Enabled: true, ExpiresAt: expires,
		Sources: []model.InsightPolicySourceV1{{
			RegisteredSourceID:    fixture.Batch.RegisteredSourceID,
			ServiceRegistrationID: fixture.Batch.ServiceRegistrationID,
			SandboxGeneration:     fixture.Batch.SandboxGeneration,
			ServiceGeneration:     fixture.Batch.ServiceGeneration,
			WorkspaceEpoch:        fixture.Batch.WorkspaceEpoch,
			NativeSessionID:       fixture.Batch.NativeSessionID,
		}},
	}}}
	wantReceipt := model.InsightBatchReceiptV1{BatchID: fixture.Batch.BatchID, Accepted: len(fixture.Batch.Findings), ThroughSequence: fixture.Batch.ThroughSequence}
	var observedBatch model.InsightBatchV1
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer rtn_insights" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("node authority headers = %#v", request.Header)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/internal/runtime/insights/policies":
			if request.Method != http.MethodGet || request.Body != http.NoBody {
				t.Fatalf("policy request = %s body=%#v", request.Method, request.Body)
			}
			_ = json.NewEncoder(writer).Encode(policy)
		case "/internal/runtime/insights/batches":
			if request.Method != http.MethodPost {
				t.Fatalf("batch request method = %s", request.Method)
			}
			body, readErr := io.ReadAll(io.LimitReader(request.Body, 64*1024+1))
			if readErr != nil || len(body) > 64*1024 {
				t.Fatalf("batch request bytes=%d err=%v", len(body), readErr)
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&observedBatch); err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"serverId", "command", "result", "prompt", "arguments", "url", "path"} {
				if bytes.Contains(body, []byte(`"`+forbidden+`"`)) {
					t.Fatalf("batch leaked %s: %s", forbidden, body)
				}
			}
			_ = json.NewEncoder(writer).Encode(wantReceipt)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := Client{Origin: server.URL, NodeToken: "rtn_insights", HTTP: server.Client()}
	gotPolicy, err := client.InsightPolicies(context.Background())
	if err != nil || !reflect.DeepEqual(gotPolicy, policy) {
		t.Fatalf("policy = %#v, %v", gotPolicy, err)
	}
	gotReceipt, err := client.SubmitInsightBatch(context.Background(), fixture.Batch)
	if err != nil || !reflect.DeepEqual(gotReceipt, wantReceipt) || !reflect.DeepEqual(observedBatch, fixture.Batch) {
		t.Fatalf("batch receipt/body = %#v/%#v, %v", gotReceipt, observedBatch, err)
	}
}

func TestInsightsNodeClientPreservesClosedConflictCodeForRecovery(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusConflict)
		_, _ = writer.Write([]byte(`{"error":{"code":"insights_source_conflict","message":"must not cross node boundary"}}`))
	}))
	defer server.Close()
	client := Client{Origin: server.URL, NodeToken: "rtn_conflict", HTTP: server.Client()}
	_, err := client.SubmitInsightBatch(context.Background(), model.InsightBatchV1{FormatVersion: 1, BatchID: "batch_conflict0001"})
	if ErrorCode(err) != "insights_source_conflict" || bytes.Contains([]byte(err.Error()), []byte("must not cross")) {
		t.Fatalf("closed conflict classification = %q / %v", ErrorCode(err), err)
	}
}
