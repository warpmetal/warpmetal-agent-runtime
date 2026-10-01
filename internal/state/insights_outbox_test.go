package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func TestInsightOutboxReplayAndCursorAckAreAtomicAcrossSQLiteReopen(t *testing.T) {
	payload, err := os.ReadFile("../api/testdata/agent-insights-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Batch model.InsightBatchV1 `json:"batch"`
	}
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	wantCursor := InsightCursor{
		RegisteredSourceID: fixture.Batch.RegisteredSourceID,
		PolicyRevision:     fixture.Batch.PolicyRevision,
		WorkspaceEpoch:     fixture.Batch.WorkspaceEpoch,
		JournalGeneration:  fixture.Batch.JournalGeneration,
		ChangeSequence:     1,
		ThroughSequence:    fixture.Batch.ThroughSequence,
		Status:             fixture.Batch.Status,
	}
	item := InsightOutboxItem{Batch: fixture.Batch, BodyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NextCursor: wantCursor}
	if err := store.PutInsightOutbox(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	changed := item
	changed.Batch.ThroughSequence++
	if err := store.PutInsightOutbox(context.Background(), changed); !errors.Is(err, ErrInsightOutboxConflict) {
		t.Fatalf("changed replay error = %v, want ErrInsightOutboxConflict", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pending, err := reopened.InsightOutbox(context.Background())
	if err != nil || len(pending) != 1 || !reflect.DeepEqual(pending[0], item) {
		t.Fatalf("reopened immutable outbox = %#v, %v", pending, err)
	}
	receipt := model.InsightBatchReceiptV1{BatchID: fixture.Batch.BatchID, Accepted: len(fixture.Batch.Findings), ThroughSequence: fixture.Batch.ThroughSequence}
	if err := reopened.AcknowledgeInsightBatch(context.Background(), fixture.Batch.BatchID, receipt); err != nil {
		t.Fatal(err)
	}
	pending, err = reopened.InsightOutbox(context.Background())
	if err != nil || len(pending) != 0 {
		t.Fatalf("acked outbox = %#v, %v", pending, err)
	}
	cursor, err := reopened.InsightCursor(context.Background(), fixture.Batch.RegisteredSourceID)
	if err != nil || cursor == nil || !reflect.DeepEqual(*cursor, wantCursor) {
		t.Fatalf("atomic acknowledged cursor = %#v, %v", cursor, err)
	}
}

func TestInsightOutboxHasBoundedPendingCapacity(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for index := 0; index < 256; index++ {
		batch := model.InsightBatchV1{FormatVersion: 1, BatchID: fmt.Sprintf("batch_capacity_%04d", index)}
		if err := store.PutInsightOutbox(context.Background(), InsightOutboxItem{Batch: batch, BodyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err != nil {
			t.Fatalf("insert %d: %v", index, err)
		}
	}
	overflow := model.InsightBatchV1{FormatVersion: 1, BatchID: "batch_capacity_overflow"}
	if err := store.PutInsightOutbox(context.Background(), InsightOutboxItem{Batch: overflow, BodyDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}); !errors.Is(err, ErrInsightOutboxCapacity) {
		t.Fatalf("outbox overflow error = %v, want ErrInsightOutboxCapacity", err)
	}
}

func TestInsightOutboxTerminalRetirementPreservesBodyAndNeverAdvancesCursor(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	batch := model.InsightBatchV1{FormatVersion: 1, BatchID: "batch_retired0001", RegisteredSourceID: "source_retired0001"}
	cursor := InsightCursor{RegisteredSourceID: batch.RegisteredSourceID, PolicyRevision: 4, JournalGeneration: "journal_retired0001", ChangeSequence: 9}
	item := InsightOutboxItem{Batch: batch, BodyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NextCursor: cursor}
	if err := store.PutInsightOutbox(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if err := store.RetireInsightOutbox(context.Background(), batch.BatchID, "source_rotated"); err != nil {
		t.Fatal(err)
	}
	if err := store.RetireInsightOutbox(context.Background(), batch.BatchID, "source_rotated"); err != nil {
		t.Fatalf("identical retirement replay failed: %v", err)
	}
	if err := store.RetireInsightOutbox(context.Background(), batch.BatchID, "policy_superseded"); !errors.Is(err, ErrInsightOutboxConflict) {
		t.Fatalf("changed retirement replay = %v, want conflict", err)
	}
	pending, err := store.InsightOutbox(context.Background())
	if err != nil || len(pending) != 0 {
		t.Fatalf("retired pending batch = %#v %v", pending, err)
	}
	retired, err := store.InsightOutboxRetirements(context.Background())
	if err != nil || len(retired) != 1 || retired[0].Batch.BatchID != batch.BatchID || retired[0].BodyDigest != item.BodyDigest ||
		retired[0].Reason != "source_rotated" || !reflect.DeepEqual(retired[0].NextCursor, cursor) {
		t.Fatalf("retirement tombstone = %#v %v", retired, err)
	}
	if current, err := store.InsightCursor(context.Background(), batch.RegisteredSourceID); err != nil || current != nil {
		t.Fatalf("retirement advanced unacknowledged cursor = %#v %v", current, err)
	}
}
