package manager

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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// This test-only exchange composes backend-issued pause/Resume manifests with
// the real persistent Coordinator.Apply and Coordinator.Reports boundary. The
// sandbox helper fixture keeps its own active/released receipt vocabulary;
// no report status or predecessor filtering is performed by this producer.
type managerTakeoverContractInput struct {
	Action          string                                 `json:"action"`
	StateDirectory  string                                 `json:"stateDirectory"`
	Now             time.Time                              `json:"now"`
	Policy          model.InsightsManagerPolicyManifestV1  `json:"policy"`
	Takeover        model.InsightsTakeoverManifestV1       `json:"takeover"`
	OffPolicy       *model.InsightsManagerPolicyManifestV1 `json:"offPolicy,omitempty"`
	RecommendPolicy *model.InsightsManagerPolicyManifestV1 `json:"recommendPolicy,omitempty"`
	Batch           *model.InsightBatchV1                  `json:"batch,omitempty"`
	BatchReceipt    *model.InsightBatchReceiptV1           `json:"batchReceipt,omitempty"`
	Review          *model.InsightsManagerReviewManifestV1 `json:"review,omitempty"`
	ControlOrigin   string                                 `json:"controlOrigin,omitempty"`
	NodeToken       string                                 `json:"nodeToken,omitempty"`
	HelperGateURL   string                                 `json:"helperGateURL,omitempty"`
}

type managerTakeoverContractOutput struct {
	HelperStatus          string                                `json:"helperStatus"`
	Phase                 string                                `json:"phase"`
	Policies              []model.InsightsManagerPolicyReportV1 `json:"insightsManagerPolicies"`
	Reviews               []model.InsightsManagerRunReportV1    `json:"insightsManagerReviews"`
	Takeovers             []model.InsightsTakeoverReportV1      `json:"insightsTakeovers"`
	Retained              []state.LocalManagerTakeover          `json:"retainedTakeovers"`
	FindingCached         bool                                  `json:"findingCached"`
	OffBatchReceipt       *model.InsightBatchReceiptV1          `json:"offBatchReceipt,omitempty"`
	AutomaticReservations int                                   `json:"automaticReservations"`
	ReviewRuns            int                                   `json:"reviewRuns"`
	RefusedAuthorities    []string                              `json:"refusedAuthorities"`
	HelperCalls           int                                   `json:"helperCalls"`
	HelperGateStatus      int                                   `json:"helperGateStatus"`
	Reports               []model.InsightsManagerRunReportV1    `json:"reports"`
	DispatchStarted       bool                                  `json:"dispatchStarted"`
	Error                 string                                `json:"error,omitempty"`
}

func TestManagerTakeoverContractProducer(t *testing.T) {
	inputPath := os.Getenv("WARPMETAL_MANAGER_CONTRACT_INPUT")
	outputPath := os.Getenv("WARPMETAL_MANAGER_CONTRACT_OUTPUT")
	if inputPath == "" && outputPath == "" {
		t.Skip("cross-repository manager producer is not requested")
	}
	if !filepath.IsAbs(inputPath) || !filepath.IsAbs(outputPath) {
		t.Fatal("manager producer input and output paths must be absolute")
	}
	payload, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var input managerTakeoverContractInput
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(input.StateDirectory) || input.Now.IsZero() {
		t.Fatal("manager producer needs an absolute state directory and clock")
	}
	if err := model.ValidateInsightsManagerPolicyManifest(input.Policy); err != nil {
		t.Fatalf("backend manager policy refused by Runtime validator: %v", err)
	}
	if input.Action == "review" {
		produceManagerReviewContract(t, input, outputPath)
		return
	}
	store, err := state.Open(filepath.Join(input.StateDirectory, "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if input.Action == "pause" {
		if input.OffPolicy == nil || input.RecommendPolicy == nil || input.Batch == nil || input.BatchReceipt == nil || input.OffPolicy.Mode != "off" || input.RecommendPolicy.Mode != "recommend" {
			t.Fatal("pause journey requires actual Off acknowledgement and subsequent Recommend policy")
		}
		fixture := loadManagerCoordinatorFixture(t)
		fixture.Policy = *input.OffPolicy
		fixture.Review.Source, fixture.Review.Target = input.Takeover.Source, input.Takeover.Target
		fixture.Review.PolicyRevision = input.Takeover.PolicyRevision
		fixture.Review.FindingID, fixture.Review.FindingRevision = input.Takeover.FindingID, input.Takeover.FindingRevision
		fixture.Review.ValidUntil, fixture.Review.ManagerProfile = input.Takeover.ValidUntil, input.Policy.ManagerProfile
		seedManagerCoordinatorPrerequisites(t, store, fixture)
	} else if input.Action != "resume" {
		t.Fatalf("unknown manager producer action %q", input.Action)
	}
	taskAuthority := state.LocalManagedTaskAuthority{
		ServiceRegistrationID: input.Takeover.Source.ServiceRegistrationID,
		ServiceGeneration:     input.Takeover.Source.ServiceGeneration,
		SandboxGeneration:     input.Takeover.Source.SandboxGeneration,
		TaskID:                input.Takeover.Target.TaskID,
		TaskAttempt:           input.Takeover.Target.TaskAttempt,
		Busy:                  input.Takeover.Target.TaskID != nil,
		ObservedAt:            input.Now,
	}
	if err := store.PutManagedTaskAuthority(ctx, taskAuthority); err != nil {
		t.Fatal(err)
	}
	helperAction, helperStatus := "acquire_intervention_hold", "active"
	if input.Action == "resume" {
		helperAction, helperStatus = "release_intervention_hold", "released"
	}
	helper := &fakeManagerHelper{outputs: map[string][]byte{
		helperAction: managerHoldReceipt(t, input.Takeover, helperAction, helperStatus, "none_pending"),
	}}
	control := &fakeManagerControl{}
	coordinator := &Coordinator{Store: store, Control: control, Helper: helper,
		Now: func() time.Time { return input.Now }}
	if input.Action == "pause" {
		if err := coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{*input.OffPolicy}}); err != nil {
			t.Fatal(err)
		}
		if err := coordinator.ObserveAcknowledgedInsightBatch(ctx, *input.Batch, *input.BatchReceipt); err != nil {
			t.Fatalf("actual backend-acknowledged Off finding batch: %v", err)
		}
		// A0-6 frozen contract: a genuinely backend-ACKed Off finding is
		// retained as observation evidence independently of the current Off
		// execution policy. Assert the exact accepted batch finding, source
		// identity, evidence window, journal generation and original
		// observation policy revision; retention alone must not authorize any
		// automatic review work.
		var accepted *model.InsightFindingV1
		for index := range input.Batch.Findings {
			if input.Batch.Findings[index].FindingID == input.Takeover.FindingID {
				accepted = &input.Batch.Findings[index]
			}
		}
		if accepted == nil {
			t.Fatalf("actual backend batch omitted the takeover finding %s", input.Takeover.FindingID)
		}
		finding, err := store.ManagerFinding(ctx, input.Takeover.FindingID)
		if err != nil || finding == nil || !finding.Acknowledged ||
			!reflect.DeepEqual(finding.Finding, *accepted) || !reflect.DeepEqual(finding.Source, input.Takeover.Source) ||
			finding.JournalGeneration != input.Batch.JournalGeneration || finding.PolicyRevision != input.OffPolicy.PolicyRevision {
			t.Fatalf("Off acknowledgement did not retain the exact accepted provenance: %#v %v", finding, err)
		}
		reservations, err := store.ManagerReservations(ctx)
		if err != nil || len(reservations) != 0 {
			t.Fatalf("Off acknowledgement created automatic reservations: %#v %v", reservations, err)
		}
		runs, err := store.ManagerRuns(ctx)
		if err != nil || len(runs) != 0 || len(helper.calls) != 0 || len(control.reservations) != 0 || len(control.reports) != 0 {
			t.Fatalf("Off acknowledgement performed manager/provider work: runs=%#v helper=%#v control=%#v %v", runs, helper.calls, control, err)
		}
		if err := coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{*input.RecommendPolicy}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := coordinator.ApplyPolicies(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{input.Policy}}); err != nil {
		t.Fatal(err)
	}
	var refused []string
	for _, test := range []struct {
		name   string
		change func(*model.InsightsTakeoverManifestV1)
	}{
		{"source", func(value *model.InsightsTakeoverManifestV1) { value.Source.ProfileRevision++ }},
		{"member", func(value *model.InsightsTakeoverManifestV1) { value.Target.MemberID = "tmem_foreignauthority0001" }},
		{"policy", func(value *model.InsightsTakeoverManifestV1) { value.PolicyRevision++ }},
		{"run generation", func(value *model.InsightsTakeoverManifestV1) { value.RunGeneration++ }},
		{"task", func(value *model.InsightsTakeoverManifestV1) {
			id, attempt := "task_foreignauthority0001", int64(1)
			value.Target.TaskID, value.Target.TaskAttempt = &id, &attempt
		}},
		{"Work binding", func(value *model.InsightsTakeoverManifestV1) {
			work, binding, revision := "work_foreignauthority0001", "binding_foreignauthority0001", int64(1)
			value.Target.WorkID, value.Target.WorkRevision = &work, &revision
			value.Target.BindingID, value.Target.BindingRevision = &binding, &revision
		}},
	} {
		foreign := input.Takeover
		test.change(&foreign)
		if err := model.ValidateInsightsTakeoverManifest(foreign); err != nil {
			t.Fatalf("%s mutation must reach local authority validation: %v", test.name, err)
		}
		if err := coordinator.Apply(ctx, model.Manifest{InsightsTakeovers: []model.InsightsTakeoverManifestV1{foreign}}); err == nil || len(helper.calls) != 0 {
			t.Fatalf("changed local takeover authority reached helper: %#v %v", foreign, err)
		}
		refused = append(refused, test.name)
	}
	if taskAuthority.TaskID != nil {
		stale := taskAuthority
		stale.ObservedAt = input.Now.Add(-121 * time.Second)
		if err := store.PutManagedTaskAuthority(ctx, stale); err != nil {
			t.Fatal(err)
		}
		if err := coordinator.Apply(ctx, model.Manifest{InsightsTakeovers: []model.InsightsTakeoverManifestV1{input.Takeover}}); err == nil || len(helper.calls) != 0 {
			t.Fatalf("stale task observation reached helper: %v", err)
		}
		if err := store.PutManagedTaskAuthority(ctx, taskAuthority); err != nil {
			t.Fatal(err)
		}
		refused = append(refused, "stale task observation")
	}
	if input.Action == "resume" {
		prior, err := store.ManagerTakeover(ctx, *input.Takeover.PredecessorOperationID)
		if err != nil || prior == nil || prior.Report == nil {
			t.Fatalf("predecessor unavailable: %#v %v", prior, err)
		}
		unsettled, report := *prior, *prior.Report
		report.Status, report.PendingInput.State = "unsettled", "unknown"
		unsettled.Report = &report
		if err := store.PutManagerTakeover(ctx, unsettled); err != nil {
			t.Fatal(err)
		}
		if err := coordinator.Apply(ctx, model.Manifest{InsightsTakeovers: []model.InsightsTakeoverManifestV1{input.Takeover}}); err == nil || len(helper.calls) != 0 {
			t.Fatalf("unsettled predecessor reached helper: %v", err)
		}
		if err := store.PutManagerTakeover(ctx, *prior); err != nil {
			t.Fatal(err)
		}
		refused = append(refused, "unsettled predecessor")
	}
	if err := coordinator.Apply(ctx, model.Manifest{
		InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{input.Policy},
		InsightsTakeovers:       []model.InsightsTakeoverManifestV1{input.Takeover},
	}); err != nil {
		t.Fatalf("actual owner takeover after Off acknowledgement (finding cache absent, no automatic/provider calls): %v", err)
	}
	if len(helper.calls) != 1 || helper.calls[0].Payload["action"] != helperAction {
		t.Fatalf("normal manager helper sequence = %#v", helper.calls)
	}
	policies, reviews, takeovers, err := coordinator.Reports(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	local, err := store.ManagerTakeover(ctx, input.Takeover.OperationID)
	if err != nil || local == nil {
		t.Fatalf("manager local intent unavailable: %#v %v", local, err)
	}
	retained, err := store.ManagerTakeovers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := store.ManagerFinding(ctx, input.Takeover.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	reservations, err := store.ManagerReservations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := store.ManagerRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	output := managerTakeoverContractOutput{HelperStatus: helperStatus, Phase: local.Phase,
		Policies: policies, Reviews: reviews, Takeovers: takeovers, Retained: retained,
		FindingCached: finding != nil, OffBatchReceipt: input.BatchReceipt,
		AutomaticReservations: len(reservations), ReviewRuns: len(runs), RefusedAuthorities: refused}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

// The real api.Client serializes and validates both reports. Only its transport
// is redirected to the explicit ephemeral loopback Flask consumer; no backend
// reviewing state or acknowledgment is synthesized by this producer.
type managerReviewLoopbackTransport struct {
	origin  *url.URL
	reports []model.InsightsManagerRunReportV1
}

func (transport *managerReviewLoopbackTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != "manager-contract.test" {
		return nil, fmt.Errorf("unexpected manager contract origin")
	}
	if request.URL.Path == "/internal/runtime/insights/manager/reports" {
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(payload))
		var report model.InsightsManagerRunReportV1
		if err := json.Unmarshal(payload, &report); err != nil {
			return nil, err
		}
		transport.reports = append(transport.reports, report)
	}
	local := request.Clone(request.Context())
	local.URL.Scheme, local.URL.Host = transport.origin.Scheme, transport.origin.Host
	local.Host = transport.origin.Host
	return http.DefaultTransport.RoundTrip(local)
}

type managerReviewGateHelper struct {
	gateURL    string
	gateStatus int
	workCalls  int
	helper     Helper
}

func (helper *managerReviewGateHelper) ExecManager(ctx context.Context, sandboxID string, payload []byte) ([]byte, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, helper.gateURL, nil)
	if err != nil {
		return nil, nil, err
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	helper.gateStatus = response.StatusCode
	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("start_report_before_helper: actual backend gate returned %d", response.StatusCode)
	}
	helper.workCalls++
	return helper.helper.ExecManager(ctx, sandboxID, payload)
}

func produceManagerReviewContract(t *testing.T, input managerTakeoverContractInput, outputPath string) {
	t.Helper()
	if input.Review == nil || input.Review.FindingEvidence == nil || input.NodeToken == "" {
		t.Fatal("review producer requires the actual backend-issued review and fixture node credential")
	}
	if err := model.ValidateInsightsManagerReviewManifest(*input.Review); err != nil {
		t.Fatal(err)
	}
	origin, err := url.Parse(input.ControlOrigin)
	if err != nil || origin.Scheme != "http" || origin.Hostname() != "127.0.0.1" || origin.Port() == "" ||
		origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		t.Fatal("review producer control origin must be an explicit ephemeral loopback HTTP fixture")
	}
	gate, err := url.Parse(input.HelperGateURL)
	if err != nil || gate.Scheme != origin.Scheme || gate.Host != origin.Host ||
		gate.Path != "/__manager_test__/review-permission" || gate.RawQuery != "" || gate.Fragment != "" || gate.User != nil {
		t.Fatal("review helper gate must be the same loopback consumer")
	}
	store, err := state.Open(filepath.Join(input.StateDirectory, "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fixture := loadManagerCoordinatorFixture(t)
	fixture.Policy, fixture.Review = input.Policy, *input.Review
	helperImplementation, initialCapability := managerReviewHelper(t, fixture, input)
	// The real backend manifest supplies canonical evidence. Recovery must not
	// depend on a fabricated local acknowledged finding or deleted outbox. The
	// optional process branch seeds its full capability once through the
	// validated store boundary instead of mutating a narrow fixture later.
	seedManagerCoordinatorPrerequisites(t, store, fixture, initialCapability...)
	ctx := context.Background()
	if err := store.PutManagedTaskAuthority(ctx, state.LocalManagedTaskAuthority{
		ServiceRegistrationID: input.Review.Source.ServiceRegistrationID, ServiceGeneration: input.Review.Source.ServiceGeneration,
		SandboxGeneration: input.Review.Source.SandboxGeneration, TaskID: input.Review.Target.TaskID,
		TaskAttempt: input.Review.Target.TaskAttempt, Busy: input.Review.Target.TaskID != nil, ObservedAt: input.Now,
	}); err != nil {
		t.Fatal(err)
	}
	transport := &managerReviewLoopbackTransport{origin: origin}
	control := api.Client{Origin: "https://manager-contract.test", NodeToken: input.NodeToken,
		HTTP: &http.Client{Transport: transport, Timeout: 10 * time.Second}}
	helper := &managerReviewGateHelper{gateURL: gate.String(), helper: helperImplementation}
	coordinator := &Coordinator{Store: store, Control: control, Helper: helper, Now: func() time.Time { return input.Now }}
	applyErr := coordinator.Apply(ctx, model.Manifest{InsightsManagerPolicies: []model.InsightsManagerPolicyManifestV1{input.Policy},
		InsightsManagerReviews: []model.InsightsManagerReviewManifestV1{*input.Review}})
	local, err := store.ManagerRun(ctx, input.Review.RunID)
	if err != nil || local == nil {
		t.Fatalf("review producer durable run missing: %#v %v", local, err)
	}
	finding, err := store.ManagerFinding(ctx, input.Review.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	output := managerTakeoverContractOutput{Phase: local.Phase, HelperCalls: helper.workCalls,
		HelperGateStatus: helper.gateStatus, Reports: transport.reports, DispatchStarted: local.DispatchStarted,
		FindingCached: finding != nil}
	if applyErr != nil {
		output.Error = applyErr.Error()
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

// managerReviewHelper selects the controlled in-process receipt branch by
// default and the optional actual helper-process adapter only when both frozen
// environment variables are present. It returns the optional full initial
// capability for the caller to seed once through the validated store boundary.
// Either branch stays behind the existing backend reviewing gate; the default
// branch and its oracles are unchanged.
func managerReviewHelper(t *testing.T, fixture managerCoordinatorFixture, input managerTakeoverContractInput) (Helper, []state.LocalManagerCapability) {
	t.Helper()
	source, adapter := os.Getenv("WARP_METAL_SANDBOX_SOURCE"), os.Getenv("WARPMETAL_MANAGER_PROCESS_ADAPTER")
	switch {
	case source == "" && adapter == "":
		return &fakeManagerHelper{reviewOutput: managerReviewReceipt(t, fixture, "start_review")}, nil
	case source == "" || adapter == "":
		t.Fatal("helper process adapter branch requires both WARP_METAL_SANDBOX_SOURCE and WARPMETAL_MANAGER_PROCESS_ADAPTER")
	default:
		if !filepath.IsAbs(source) || !filepath.IsAbs(adapter) {
			t.Fatal("helper process adapter source and adapter paths must be absolute")
		}
		return &managerProcessHelper{adapterPath: adapter, sandboxSource: source,
				exchangeDirectory: filepath.Join(input.StateDirectory, "exchange"), now: input.Now},
			[]state.LocalManagerCapability{managerProcessCapability(t, source, input)}
	}
	return nil, nil
}

// managerProcessCapability builds the full local helper capability for the
// activated process branch from the actual Sandbox fixture metadata, the
// installed manager-plugin digest, and the exact incoming review
// route/profile/recipe plus source/service revisions. It is never used by the
// controlled receipt branch.
func managerProcessCapability(t *testing.T, sandboxSource string, input managerTakeoverContractInput) state.LocalManagerCapability {
	t.Helper()
	if input.Review == nil {
		t.Fatal("helper process branch requires the backend-issued review manifest")
	}
	payload, err := os.ReadFile(filepath.Join(sandboxSource, "docs", "AGENT_MANAGER_SANDBOX_V1_FIXTURE.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		StartReviewRequest struct {
			Capability struct {
				NativeVersion        string `json:"nativeVersion"`
				NativeSourceRevision string `json:"nativeSourceRevision"`
				Protocol             string `json:"protocol"`
				NativeProtocol       string `json:"nativeProtocol"`
				ProviderID           string `json:"providerId"`
				ModelID              string `json:"modelId"`
				MaxInputTokens       int64  `json:"maxInputTokens"`
				MaxOutputTokens      int64  `json:"maxOutputTokens"`
				FinalRequestMaxBytes int64  `json:"finalRequestMaxBytes"`
				ToolsAllowed         bool   `json:"toolsAllowed"`
				MediaAllowed         bool   `json:"mediaAllowed"`
				HardOutputTokenLimit bool   `json:"hardOutputTokenLimit"`
			} `json:"capability"`
		} `json:"startReviewRequest"`
	}
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	plugin, err := os.ReadFile(filepath.Join(sandboxSource, "manager-plugin", "index.ts"))
	if err != nil {
		t.Fatal(err)
	}
	review := *input.Review
	capability := fixture.StartReviewRequest.Capability
	return state.LocalManagerCapability{
		RegisteredSourceID: review.Source.RegisteredSourceID, ServiceRegistrationID: review.Source.ServiceRegistrationID,
		ServiceGeneration: review.Source.ServiceGeneration, WorkspaceEpoch: review.Source.WorkspaceEpoch,
		NativeSessionID: review.Source.NativeSessionID, SandboxID: input.Policy.SandboxID,
		SandboxGeneration: review.Source.SandboxGeneration, ProfileRevision: review.Source.ProfileRevision,
		InstructionRevision: review.Source.InstructionRevision, NativeVersion: capability.NativeVersion,
		NativeSourceRevision: capability.NativeSourceRevision, Protocol: capability.Protocol,
		NativeProtocol: capability.NativeProtocol, ProviderID: capability.ProviderID, ModelID: capability.ModelID,
		ProviderRouteDigest: review.ProviderRouteDigest, RecipeIDs: []string{review.RecipeID},
		ManagerPluginDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(plugin)), ManagerProfile: review.ManagerProfile,
		MaxInputTokens: capability.MaxInputTokens, MaxOutputTokens: capability.MaxOutputTokens,
		FinalRequestMaxBytes: capability.FinalRequestMaxBytes, ToolsAllowed: capability.ToolsAllowed,
		MediaAllowed: capability.MediaAllowed, HardOutputTokenLimit: capability.HardOutputTokenLimit,
		Available: true,
	}
}

// managerProcessHelper launches the actual adapter child with a bounded
// context, writes the exact serialized coordinator request to its stdin, and
// returns the actual helper receipt stdout verbatim. Nothing rewrites the
// receipt: reservation/run/source identity and native project/location values
// stay helper-derived. Each action gets its own trace path inside
// StateDirectory/exchange; an existing trace is never overwritten.
type managerProcessHelper struct {
	adapterPath       string
	sandboxSource     string
	exchangeDirectory string
	now               time.Time
}

func (helper *managerProcessHelper) ExecManager(ctx context.Context, _ string, payload []byte) ([]byte, []byte, error) {
	var request struct {
		Action    string                                `json:"action"`
		Authority model.InsightsManagerReviewManifestV1 `json:"authority"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, nil, err
	}
	if request.Action != "start_review" {
		return nil, nil, fmt.Errorf("helper process adapter branch covers the start review producer action only")
	}
	tracePath, err := helper.tracePath(request.Action, request.Authority.RunID)
	if err != nil {
		return nil, nil, err
	}
	runContext, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	command := exec.CommandContext(runContext, "python3", helper.adapterPath, helper.sandboxSource,
		helper.now.UTC().Format(time.RFC3339Nano), tracePath)
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if err := command.Run(); err != nil {
		return nil, stderr.Bytes(), fmt.Errorf("helper process adapter failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func (helper *managerProcessHelper) tracePath(action, runID string) (string, error) {
	if err := os.MkdirAll(helper.exchangeDirectory, 0o700); err != nil {
		return "", err
	}
	base := fmt.Sprintf("%s-%s-helper-process-trace.json", action, runID)
	candidate := filepath.Join(helper.exchangeDirectory, base)
	for attempt := 1; ; attempt++ {
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
		candidate = filepath.Join(helper.exchangeDirectory,
			fmt.Sprintf("%s-%s-helper-process-trace.attempt-%d.json", action, runID, attempt))
	}
}
