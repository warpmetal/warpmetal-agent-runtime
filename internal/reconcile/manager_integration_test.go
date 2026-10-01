package reconcile

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type fakeManagerCoordinator struct {
	recoverCalls  int
	manifests     []model.Manifest
	policyApplies []model.Manifest
	policies      []model.InsightsManagerPolicyReportV1
	runs          []model.InsightsManagerRunReportV1
	takeovers     []model.InsightsTakeoverReportV1
}

func (manager *fakeManagerCoordinator) Recover(context.Context) error {
	manager.recoverCalls++
	return nil
}

func (manager *fakeManagerCoordinator) ApplyPolicies(_ context.Context, manifest model.Manifest) error {
	manager.policyApplies = append(manager.policyApplies, manifest)
	return nil
}

func (manager *fakeManagerCoordinator) Apply(_ context.Context, manifest model.Manifest) error {
	manager.manifests = append(manager.manifests, manifest)
	return nil
}

func (manager *fakeManagerCoordinator) Reports(context.Context, continuity.StaleSourceSet) ([]model.InsightsManagerPolicyReportV1, []model.InsightsManagerRunReportV1, []model.InsightsTakeoverReportV1, error) {
	return manager.policies, manager.runs, manager.takeovers, nil
}

func TestReconcilerWiresManagerManifestRecoveryAndSanitizedReports(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := &fakeManagerCoordinator{
		policies:  []model.InsightsManagerPolicyReportV1{{FormatVersion: 1}},
		runs:      []model.InsightsManagerRunReportV1{{FormatVersion: 1}},
		takeovers: []model.InsightsTakeoverReportV1{{FormatVersion: 1}},
	}
	reconciler := &Reconciler{Store: store, ServerID: "srv_managerwire0001", Manager: manager,
		Access:       access.Renderer{Path: filepath.Join(t.TempDir(), "authorized_keys")},
		HostCapacity: model.Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20}}
	manifest := model.Manifest{ServerID: reconciler.ServerID, DesiredRevision: 1,
		ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
		Capacity:    reconciler.HostCapacity,
	}
	if err := reconciler.Reconcile(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if manager.recoverCalls != 1 || len(manager.manifests) != 1 || manager.manifests[0].DesiredRevision != manifest.DesiredRevision {
		t.Fatalf("manager reconcile wiring = recover %d manifests %#v", manager.recoverCalls, manager.manifests)
	}
	if len(manager.policyApplies) != 1 || manager.policyApplies[0].DesiredRevision != manifest.DesiredRevision {
		t.Fatalf("early manager policy apply wiring = %#v", manager.policyApplies)
	}
	report, err := reconciler.Report(context.Background(), reconciler.ServerID, "test")
	if err != nil || len(report.InsightsManagerPolicies) != 1 || len(report.InsightsManagerReviews) != 1 || len(report.InsightsTakeovers) != 1 {
		t.Fatalf("manager report wiring = %#v, %v", report, err)
	}
}

var _ ManagerControl = (*fakeManagerCoordinator)(nil)
