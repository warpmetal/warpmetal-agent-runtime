package continuity

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type sandboxContinuationFixture struct {
	PrepareRequest    json.RawMessage `json:"prepareRequest"`
	PrepareReport     json.RawMessage `json:"prepareReport"`
	ReconcilePrepared json.RawMessage `json:"reconcilePrepared"`
	ReconcileConsumed json.RawMessage `json:"reconcileConsumed"`
}

func TestS2SandboxCanonicalPrepareAndRecoveryEnvelopes(t *testing.T) {
	payload, err := os.ReadFile("../api/testdata/agent-continuation-baseline-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture sandboxContinuationFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}

	var request continuationHelperRequest
	if err := decodeClosed(fixture.PrepareRequest, &request); err != nil {
		t.Fatalf("canonical prepare request is outside the Runtime helper contract: %v", err)
	}
	if request.Action != "prepare_continuation" || request.Instance == "" {
		t.Fatalf("canonical prepare request = %#v", request)
	}
	assertExactJSONRoundTrip(t, fixture.PrepareRequest, request)

	var report continuationRecoveryEnvelope
	if err := decodeClosed(fixture.ReconcilePrepared, &report); err != nil {
		t.Fatalf("canonical prepared wrapper is outside the Runtime recovery contract: %v", err)
	}
	if report.Status != "ready" || report.State != "prepared" || report.Consumption != nil || report.Release != nil ||
		!validReadyReport(request.ContinuationManifestV1, report.Report) {
		t.Fatalf("canonical prepared wrapper failed closed validation: %#v", report)
	}
	assertExactJSONRoundTrip(t, fixture.ReconcilePrepared, report)

	var consumed continuationRecoveryEnvelope
	if err := decodeClosed(fixture.ReconcileConsumed, &consumed); err != nil {
		t.Fatalf("canonical consumed wrapper is outside the Runtime recovery contract: %v", err)
	}
	if consumed.Status != "consumed" || consumed.State != "consumed" || !validConsumption(consumed.Consumption) ||
		consumed.Release != nil || !reflect.DeepEqual(consumed.Report, report.Report) {
		t.Fatalf("canonical consumed wrapper failed closed validation: %#v", consumed)
	}
	assertExactJSONRoundTrip(t, fixture.ReconcileConsumed, consumed)

	var prepareReport map[string]any
	if err := decodeClosed(fixture.PrepareReport, &prepareReport); err != nil {
		t.Fatal(err)
	}
	var embeddedReport map[string]any
	embedded, err := json.Marshal(report.Report)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeClosed(embedded, &embeddedReport); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prepareReport, embeddedReport) {
		t.Fatal("recovery wrapper did not preserve the exact immutable prepare report")
	}
}

func assertExactJSONRoundTrip(t *testing.T, expected json.RawMessage, value any) {
	t.Helper()
	actual, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var expectedValue, actualValue any
	if err := json.Unmarshal(expected, &expectedValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(actual, &actualValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectedValue, actualValue) {
		t.Fatalf("JSON contract drift\nexpected: %s\nactual:   %s", expected, actual)
	}
}
