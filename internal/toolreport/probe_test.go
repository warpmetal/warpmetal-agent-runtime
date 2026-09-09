package toolreport

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

type fakeExecutor struct {
	sandboxIDs []string
	output     string
	err        error
}

func (f *fakeExecutor) ToolReport(
	_ context.Context,
	sandboxID string,
	stdout io.Writer,
) error {
	f.sandboxIDs = append(f.sandboxIDs, sandboxID)
	_, _ = io.WriteString(stdout, f.output)
	return f.err
}

const validReport = `[
  {"id":"codex","status":"available","version":"0.153.4"},
  {"id":"claude","status":"available","version":"2.1.263"},
  {"id":"cursor","status":"available","version":"2026.09.02-c22c1a3"}
]`

func TestProbeUsesConstantCommandAndReportsOnlyDesiredTools(t *testing.T) {
	executor := &fakeExecutor{output: validReport}
	got := Probe(context.Background(), executor, "sbx_test12345", []string{"cursor", "codex"})
	if !reflect.DeepEqual(executor.sandboxIDs, []string{"sbx_test12345"}) {
		t.Fatalf("probe sandbox IDs = %#v", executor.sandboxIDs)
	}
	if len(got) != 2 || got[0].ID != "cursor" || got[1].ID != "codex" ||
		got[0].Status != "available" || got[0].Version != "2026.09.02-c22c1a3" {
		t.Fatalf("selected observations = %#v", got)
	}
}

func TestProbeDoesNotExecuteWhenNothingIsSelected(t *testing.T) {
	executor := &fakeExecutor{output: validReport}
	got := Probe(context.Background(), executor, "sbx_test12345", nil)
	if len(executor.sandboxIDs) != 0 || len(got) != 0 {
		t.Fatalf("empty selection executed a probe or returned observations: %#v %#v", executor.sandboxIDs, got)
	}
}

func TestProbeRejectsUntrustedOrIncompleteOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{name: "malformed", output: `{"id":"codex"}`},
		{name: "unknown", output: `[{"id":"codex","status":"available"},{"id":"claude","status":"available"},{"id":"other","status":"available"}]`},
		{name: "duplicate", output: `[{"id":"codex","status":"available"},{"id":"codex","status":"available"},{"id":"cursor","status":"available"}]`},
		{name: "missing", output: `[{"id":"codex","status":"available"},{"id":"claude","status":"available"}]`},
		{name: "unknown field", output: `[{"id":"codex","status":"available","command":"curl example"},{"id":"claude","status":"available"},{"id":"cursor","status":"available"}]`},
		{name: "trailing", output: validReport + `{}`},
		{name: "bad status", output: `[{"id":"codex","status":"pending"},{"id":"claude","status":"available"},{"id":"cursor","status":"available"}]`},
		{name: "available error", output: `[{"id":"codex","status":"available","lastError":{"code":"unexpected"}},{"id":"claude","status":"available"},{"id":"cursor","status":"available"}]`},
		{name: "unsafe version", output: `[{"id":"codex","status":"available","version":"0.153.4 token"},{"id":"claude","status":"available"},{"id":"cursor","status":"available"}]`},
		{name: "unapproved error", output: `[{"id":"codex","status":"failed","lastError":{"code":"child_error","message":"arbitrary child output"}},{"id":"claude","status":"available"},{"id":"cursor","status":"available"}]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Probe(
				context.Background(),
				&fakeExecutor{output: test.output},
				"sbx_test12345",
				[]string{"codex", "claude"},
			)
			if len(got) != 2 {
				t.Fatalf("failure observations = %#v", got)
			}
			for _, item := range got {
				if item.Status != "failed" || item.LastError == nil ||
					item.LastError.Code != "tool_report_invalid" || item.Version != "" {
					t.Fatalf("unsafe output was not rejected: %#v", got)
				}
			}
		})
	}
}

func TestProbeBoundsOutputAndDoesNotExposeExecutionError(t *testing.T) {
	secret := "sensitive-child-output"
	tests := []fakeExecutor{
		{output: strings.Repeat("x", maxReportBytes+1)},
		{err: errors.New(secret)},
	}
	for _, executor := range tests {
		got := Probe(context.Background(), &executor, "sbx_test12345", []string{"cursor"})
		if len(got) != 1 || got[0].LastError == nil ||
			strings.Contains(got[0].LastError.Message, secret) {
			t.Fatalf("probe failure was not safely normalized: %#v", got)
		}
	}
}

func TestProbeSanitizesToolFailureAndPreservesSelectionOrder(t *testing.T) {
	executor := &fakeExecutor{output: `[
  {"id":"codex","status":"available","version":"0.153.4"},
  {"id":"claude","status":"failed","lastError":{"code":"version_mismatch","message":"tool version did not match manifest"}},
  {"id":"cursor","status":"available","version":"2026.09.02-c22c1a3"}
]`}
	got := Probe(context.Background(), executor, "sbx_test12345", []string{"claude", "cursor"})
	if !reflect.DeepEqual([]string{got[0].ID, got[1].ID}, []string{"claude", "cursor"}) ||
		got[0].LastError == nil || got[0].LastError.Code != "version_mismatch" ||
		got[1].Version == "" {
		t.Fatalf("tool result was not normalized: %#v", got)
	}
}
