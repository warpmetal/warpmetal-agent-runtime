package state

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type managerStateFixture struct {
	Policy   model.InsightsManagerPolicyManifestV1 `json:"managerPolicyManifest"`
	Review   model.InsightsManagerReviewManifestV1 `json:"manualReviewManifest"`
	Takeover model.InsightsTakeoverManifestV1      `json:"takeoverManifest"`
}

func loadManagerStateFixture(t *testing.T) managerStateFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "manager", "testdata", "backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture managerStateFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestManagerIntentCapabilityTakeoverAndMappedSessionReopenExactly(t *testing.T) {
	fixture := loadManagerStateFixture(t)
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	capability := LocalManagerCapability{
		RegisteredSourceID:  fixture.Review.Source.RegisteredSourceID,
		ServiceGeneration:   fixture.Review.Source.ServiceGeneration,
		ProviderRouteDigest: fixture.Review.ProviderRouteDigest,
		Available:           true,
	}
	run := LocalManagerRun{Manifest: fixture.Review, Phase: "dispatching", Capability: capability}
	takeover := LocalManagerTakeover{Manifest: fixture.Takeover, Phase: "acquiring"}
	reservation := LocalManagerReservation{Request: model.InsightsManagerReservationRequestV1{
		FormatVersion: 1, ReservationID: "reservation_managerstate0001", RequestID: "req_managerstate0001",
		Source: fixture.Review.Source, Target: fixture.Review.Target,
	}, Phase: "pending"}
	taskID, attempt := "task_managerstate0001", int64(2)
	task := LocalManagedTaskAuthority{ServiceRegistrationID: fixture.Review.Source.ServiceRegistrationID,
		ServiceGeneration: fixture.Review.Source.ServiceGeneration, SandboxGeneration: fixture.Review.Source.SandboxGeneration,
		TaskID: &taskID, TaskAttempt: &attempt, Busy: true, ObservedAt: time.Date(2026, 9, 27, 18, 0, 0, 0, time.UTC)}
	if err := store.PutManagerCapability(context.Background(), capability); err != nil {
		t.Fatal(err)
	}
	if err := store.PutManagerRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if err := store.PutManagerTakeover(context.Background(), takeover); err != nil {
		t.Fatal(err)
	}
	if err := store.PutManagerReservation(context.Background(), reservation); err != nil {
		t.Fatal(err)
	}
	if err := store.PutManagedTaskAuthority(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	gotRun, err := reopened.ManagerRun(context.Background(), fixture.Review.RunID)
	if err != nil || !reflect.DeepEqual(gotRun, &run) {
		t.Fatalf("manager run = %#v, %v", gotRun, err)
	}
	gotTakeover, err := reopened.ManagerTakeover(context.Background(), fixture.Takeover.OperationID)
	if err != nil || !reflect.DeepEqual(gotTakeover, &takeover) {
		t.Fatalf("takeover = %#v, %v", gotTakeover, err)
	}
	if _, err := reopened.ManagerRunBySource(context.Background(), "manager_missing"); err != nil {
		t.Fatal(err)
	}
	gotTask, err := reopened.ManagedTaskAuthority(context.Background(), task.ServiceRegistrationID)
	if err != nil || !reflect.DeepEqual(gotTask, &task) {
		t.Fatalf("manager task authority = %#v, %v", gotTask, err)
	}
	gotReservation, err := reopened.ManagerReservation(context.Background(), reservation.Request.ReservationID)
	if err != nil || !reflect.DeepEqual(gotReservation, &reservation) {
		t.Fatalf("manager reservation = %#v, %v", gotReservation, err)
	}
}
