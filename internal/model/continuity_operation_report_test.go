package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAcceptedContinuityOperationReportKeepsZeroCountsOnTheWire(t *testing.T) {
	report := ContinuityOperationReportV1{
		FormatVersion:  1,
		OperationID:    "op_test_capture",
		Action:         "capture_checkpoint",
		ScopeRevision:  1,
		BoundaryKind:   "task",
		Status:         "accepted",
		CheckpointID:   "checkpoint_test",
		CaptureID:      "capture_test",
		ManifestDigest: "sha256:" + strings.Repeat("a", 64),
		ReceiptDigest:  "sha256:" + strings.Repeat("b", 64),
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"checkpointId", "captureId", "manifestDigest", "bytes", "objectCount", "receiptDigest"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("accepted report omitted the required %q field: %s", key, payload)
		}
	}
	if fields["bytes"] != float64(0) || fields["objectCount"] != float64(0) {
		t.Fatalf("accepted report did not keep zero counters: %s", payload)
	}

	report.Status = "applying"
	report.CheckpointID = ""
	report.CaptureID = ""
	report.ManifestDigest = ""
	report.Bytes = 0
	report.ObjectCount = 0
	report.ReceiptDigest = ""
	payload, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	fields = map[string]any{}
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"checkpointId", "captureId", "manifestDigest", "bytes", "objectCount", "receiptDigest"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("applying report carried the accepted-only %q field: %s", key, payload)
		}
	}
}
