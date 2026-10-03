package reconcile

import (
	"context"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Every source in the report is gated by the current manifest sandbox
// generation before the existing positive-ownership predicates. This is a
// focused report-projection regression over the existing source-observation
// journey: the fixture advances the authority sandbox generation and keeps one
// retained historical-generation source; the report must omit the retained
// source while the current-generation source stays. It does not execute a
// stop, run a full Reconcile, or replace the required full signed VPS
// acceptance.
func TestSourceObservationReportGatesSourcesByCurrentSandboxGeneration(t *testing.T) {
	ctx := context.Background()
	journey := newSourceObservationJourney(t)
	finishSourceID := journey.finish.registration.Binding.RegisteredSourceID
	retainedSourceID := journey.ba1b.registration.Binding.RegisteredSourceID

	finishSource, err := journey.store.ContinuitySource(ctx, finishSourceID)
	if err != nil || finishSource == nil {
		t.Fatalf("finish source = %#v, %v", finishSource, err)
	}
	sandboxID := finishSource.Report.SandboxID
	currentGeneration := finishSource.Report.SandboxGeneration

	authority := journey.manifest
	authority.Sandboxes = append([]model.Sandbox(nil), journey.manifest.Sandboxes...)
	advanced := false
	for index := range authority.Sandboxes {
		if authority.Sandboxes[index].ID == sandboxID {
			authority.Sandboxes[index].Generation = currentGeneration + 1
			advanced = true
		}
	}
	if !advanced {
		t.Fatalf("sandbox %s is absent from the manifest", sandboxID)
	}
	// The fixture authority transition: the current service source is moved to
	// the new generation; the independent retained observation keeps the
	// historical generation.
	finishSource.Report.SandboxGeneration = currentGeneration + 1
	if err := journey.store.PutContinuitySource(ctx, *finishSource); err != nil {
		t.Fatal(err)
	}
	retained, err := journey.store.ContinuitySource(ctx, retainedSourceID)
	if err != nil || retained == nil {
		t.Fatalf("retained source = %#v, %v", retained, err)
	}
	if retained.Report.SandboxGeneration != currentGeneration {
		t.Fatalf("setup: retained source generation = %d, want %d", retained.Report.SandboxGeneration, currentGeneration)
	}

	journey.reconciler.setCurrentAuthority(authority)
	report, err := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if err != nil {
		t.Fatalf("report construction failed: %v", err)
	}
	foundCurrent := false
	for _, source := range report.ContinuitySources {
		if source.RegisteredSourceID == retainedSourceID {
			t.Fatalf("retained old-generation source was emitted: %#v", source)
		}
		if source.RegisteredSourceID == finishSourceID && source.SandboxGeneration == currentGeneration+1 {
			foundCurrent = true
		}
	}
	if !foundCurrent {
		t.Fatalf("current-generation source was dropped: %#v", report.ContinuitySources)
	}
}
