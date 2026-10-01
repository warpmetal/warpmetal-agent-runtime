package insights

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type managerAckObserver struct {
	batches  []model.InsightBatchV1
	receipts []model.InsightBatchReceiptV1
}

func (observer *managerAckObserver) ObserveAcknowledgedInsightBatch(_ context.Context, batch model.InsightBatchV1, receipt model.InsightBatchReceiptV1) error {
	observer.batches = append(observer.batches, batch)
	observer.receipts = append(observer.receipts, receipt)
	return nil
}

func TestManagerAutomaticReviewSeesFindingOnlyAfterExactBatchAcknowledgement(t *testing.T) {
	fixture := readSandboxInsightFixture(t)
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 18, 0, 30, 0, time.UTC)
	policy := currentInsightPolicy(now)
	seedInsightAuthority(t, store, policy, now)
	control := &fakeInsightControl{policy: model.InsightPolicyEnvelopeV1{Policies: []model.InsightPolicyV1{policy}}, loseAck: true}
	monitor := &fakeInsightMonitor{responses: []json.RawMessage{fixture.OpenResponse}}
	observer := &managerAckObserver{}
	collector := &Collector{Store: store, Control: control, Monitor: monitor, Lifecycle: &fakeInsightLifecycle{}, Manager: observer, Now: func() time.Time { return now }}
	if err := collector.RunOnce(context.Background()); err == nil {
		t.Fatal("injected lost ACK returned success")
	}
	if len(observer.batches) != 0 {
		t.Fatalf("unacknowledged finding reached manager reservation: %#v", observer.batches)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	collector = &Collector{Store: store, Control: control, Monitor: &fakeInsightMonitor{responses: []json.RawMessage{noChangeInsightResponse(t, fixture.OpenResponse)}}, Lifecycle: &fakeInsightLifecycle{}, Manager: observer, Now: func() time.Time { return now }}
	if err := collector.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(observer.batches) != 1 || len(observer.receipts) != 1 ||
		!reflect.DeepEqual(observer.batches[0], control.submissions[0]) || observer.receipts[0].BatchID != observer.batches[0].BatchID {
		t.Fatalf("manager ACK observation = %#v/%#v submissions=%#v", observer.batches, observer.receipts, control.submissions)
	}
}
