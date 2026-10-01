package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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
		finding, err := store.ManagerFinding(ctx, input.Takeover.FindingID)
		if err != nil || finding != nil {
			t.Fatalf("Off acknowledgement changed review finding eligibility: %#v %v", finding, err)
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
