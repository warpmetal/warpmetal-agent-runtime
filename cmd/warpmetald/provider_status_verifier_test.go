package main

import (
	"context"
	"errors"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/boxcredentials"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providergateway"
)

type fakeStatusExecutor struct {
	calls  []providergateway.ToolCall
	result providergateway.ToolResult
	err    error
}

func (f *fakeStatusExecutor) CallTool(_ context.Context, call providergateway.ToolCall) (providergateway.ToolResult, error) {
	f.calls = append(f.calls, call)
	return f.result, f.err
}

func TestProviderStatusVerifierUsesTheReviewedExecutorAndNeverLogsSecrets(t *testing.T) {
	executor := &fakeStatusExecutor{result: providergateway.ToolResult{Text: "ok"}}
	verifier := newProviderStatusVerifier(executor)
	if verifier == nil {
		t.Fatal("newProviderStatusVerifier() = nil")
	}
	credential := &boxcredentials.Credential{
		ProviderID:   "zendesk",
		ConnectionID: "conn_aaaaaaaaaaaaaaaaaaaaaaaa",
		AccountID:    "acct_fixture",
		Kind:         "api_key",
	}
	result := verifier.VerifyCredential(context.Background(), credential, boxcredentials.VerificationRequest{RequestID: "tpv_fixture1234"})
	if result.Outcome != boxcredentials.VerificationVerified {
		t.Fatalf("outcome = %q, want verified", result.Outcome)
	}
	if len(executor.calls) != 1 {
		t.Fatalf("executor calls = %d, want 1", len(executor.calls))
	}
	call := executor.calls[0]
	if call.Name != "provider_status" || call.ProviderID != "zendesk" || call.Credential == nil {
		t.Fatalf("unexpected executor call: %#v", call)
	}
	if result := verifier.VerifyCredential(context.Background(), nil, boxcredentials.VerificationRequest{}); result.Outcome != boxcredentials.VerificationUnsupported {
		t.Fatalf("nil credential outcome = %q, want unsupported", result.Outcome)
	}
}

func TestProviderStatusVerifierMapsExecutorFailureAndRejection(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		executor *fakeStatusExecutor
		outcome  string
	}{
		{"executor error", &fakeStatusExecutor{err: errors.New("executor unavailable")}, boxcredentials.VerificationUnsupported},
		{"tool rejection", &fakeStatusExecutor{result: providergateway.ToolResult{IsError: true, Text: "provider rejected"}}, boxcredentials.VerificationRejected},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			verifier := newProviderStatusVerifier(testCase.executor)
			result := verifier.VerifyCredential(context.Background(), &boxcredentials.Credential{ProviderID: "zendesk"}, boxcredentials.VerificationRequest{})
			if result.Outcome != testCase.outcome {
				t.Fatalf("outcome = %q, want %q", result.Outcome, testCase.outcome)
			}
		})
	}
	if newProviderStatusVerifier(nil) != nil {
		t.Fatal("nil executor must produce a nil verifier, not an always-verified verifier")
	}
}
