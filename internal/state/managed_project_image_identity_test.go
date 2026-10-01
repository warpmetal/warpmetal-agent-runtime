package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// bindableManagedProjectRecord is the durable pre-A5 shape the one authorized
// image identity transition applies to: the ready, available, self-attesting
// team project with one nonzero recorded device carrying the exact anchor and
// project-root inodes and an exactly zero durable image identity.
func bindableManagedProjectRecord() LocalManagedProject {
	serviceID := "service_imageidentity0001"
	return LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: "selection_imageidentity0001", ProjectID: "project_imageidentity0001",
			WorkspaceEpoch: "epoch_imageidentity0001", SandboxID: "sbx_imageidentity00000001", SandboxGeneration: 2,
			ServiceRegistrationID: &serviceID, Designation: "team_project", Label: "team_imageidentity0001",
			Availability: "available", RootAttestation: "sha256:" + strings.Repeat("a", 64),
		},
		ServerID: "srv_imageidentity0001", TeamID: "team_imageidentity0001", MemberID: "tmem_imageidentity0001",
		AllocationDigest: "sha256:" + strings.Repeat("b", 64), ConfigDigest: "sha256:" + strings.Repeat("c", 64),
		Anchor: "/srv/workspace", HostRoot: "/srv/workspace/projects/team_imageidentity0001",
		ContainerRoot: "/home/agent/projects/team_imageidentity0001", Phase: "ready",
		AnchorDevice: 42, AnchorInode: 43, AnchorMount: "7", RootDevice: 42, RootInode: 44, RootMount: "7",
		ScopeRevision: 1, SupersededRootAttestation: "sha256:" + strings.Repeat("d", 64),
	}
}

func openBindStoreWithRecord(t *testing.T) (*Store, LocalManagedProject) {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	record := bindableManagedProjectRecord()
	if err := store.PutManagedProject(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	return store, record
}

func rawBindRow(t *testing.T, store *Store, selectionID string) map[string]string {
	t.Helper()
	var report, private, updatedAt string
	if err := store.db.QueryRowContext(context.Background(),
		`SELECT report_json, private_json, updated_at FROM managed_workspace_projects WHERE selection_id=?`,
		selectionID).Scan(&report, &private, &updatedAt); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"report_json": report, "private_json": private, "updated_at": updatedAt}
}

// TestBindManagedProjectImageIdentityIsTheZeroOnlyCompareAndWrite proves the
// store-owned properties of the narrow A25 admission path: the exact re-proven
// pre-A5 record binds exactly one field plus the ordinary write timestamp, any
// record that moved under the caller, left the bindable shape, already carries
// an identity, or carries a partial identity is refused byte-identically, and
// a store failure is surfaced as an error instead of a permissive result.
func TestBindManagedProjectImageIdentityIsTheZeroOnlyCompareAndWrite(t *testing.T) {
	ctx := context.Background()
	object := ManagedProjectImageIdentity{Device: 9, Inode: 10, Size: 11, ModifiedUnixNano: 12}

	t.Run("the exact zero-identity record binds only the identity and the ordinary timestamp", func(t *testing.T) {
		store, record := openBindStoreWithRecord(t)
		before := rawBindRow(t, store, record.Report.SelectionID)
		bound := record
		bound.ImageIdentity = object
		if err := store.BindManagedProjectImageIdentity(ctx, bound); err != nil {
			t.Fatal(err)
		}
		after := rawBindRow(t, store, record.Report.SelectionID)
		if before["report_json"] != after["report_json"] {
			t.Fatalf("the bind moved the published report: before=%s after=%s", before["report_json"], after["report_json"])
		}
		if before["updated_at"] == after["updated_at"] {
			t.Fatalf("the ordinary write timestamp did not move")
		}
		var beforeFields, afterFields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(before["private_json"]), &beforeFields); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(after["private_json"]), &afterFields); err != nil {
			t.Fatal(err)
		}
		for key, raw := range beforeFields {
			if key == "ImageIdentity" {
				continue
			}
			if !bytes.Equal(raw, afterFields[key]) {
				t.Fatalf("the bind moved durable field %s: before=%s after=%s", key, raw, afterFields[key])
			}
		}
		var storedImage ManagedProjectImageIdentity
		if err := json.Unmarshal(afterFields["ImageIdentity"], &storedImage); err != nil {
			t.Fatal(err)
		}
		if storedImage != object {
			t.Fatalf("bound identity = %#v, want %#v", storedImage, object)
		}
	})

	t.Run("a record that moved under the caller is refused byte-identically", func(t *testing.T) {
		store, record := openBindStoreWithRecord(t)
		before := rawBindRow(t, store, record.Report.SelectionID)
		stale := record
		stale.ImageIdentity = object
		stale.ConfigDigest = "sha256:" + strings.Repeat("e", 64)
		if err := store.BindManagedProjectImageIdentity(ctx, stale); !errors.Is(err, ErrManagedProjectConflict) {
			t.Fatalf("moved record = %v", err)
		}
		if after := rawBindRow(t, store, record.Report.SelectionID); !reflect.DeepEqual(before, after) {
			t.Fatalf("refused bind moved the durable row: before=%v after=%v", before, after)
		}
	})

	t.Run("an existing durable identity is never refreshed or replaced", func(t *testing.T) {
		store, record := openBindStoreWithRecord(t)
		if err := store.BindManagedProjectImageIdentity(ctx, func() LocalManagedProject {
			bound := record
			bound.ImageIdentity = object
			return bound
		}()); err != nil {
			t.Fatal(err)
		}
		before := rawBindRow(t, store, record.Report.SelectionID)
		refreshed := record
		refreshed.ImageIdentity = ManagedProjectImageIdentity{Device: 20, Inode: 21, Size: 22}
		if err := store.BindManagedProjectImageIdentity(ctx, refreshed); !errors.Is(err, ErrManagedProjectConflict) {
			t.Fatalf("identity refresh = %v", err)
		}
		if after := rawBindRow(t, store, record.Report.SelectionID); !reflect.DeepEqual(before, after) {
			t.Fatalf("refused refresh moved the durable row: before=%v after=%v", before, after)
		}
	})

	t.Run("a partial identity is refused", func(t *testing.T) {
		store, record := openBindStoreWithRecord(t)
		before := rawBindRow(t, store, record.Report.SelectionID)
		partial := record
		partial.ImageIdentity = ManagedProjectImageIdentity{Device: 9, Inode: 0, Size: 11}
		if err := store.BindManagedProjectImageIdentity(ctx, partial); !errors.Is(err, ErrManagedProjectConflict) {
			t.Fatalf("partial identity = %v", err)
		}
		if after := rawBindRow(t, store, record.Report.SelectionID); !reflect.DeepEqual(before, after) {
			t.Fatalf("refused partial identity moved the durable row: before=%v after=%v", before, after)
		}
	})

	t.Run("a record outside the ready available team shape is refused", func(t *testing.T) {
		store, record := openBindStoreWithRecord(t)
		outside := record
		outside.Phase = "observed"
		private, err := json.Marshal(outside)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx,
			`UPDATE managed_workspace_projects SET private_json=? WHERE selection_id=?`,
			private, record.Report.SelectionID); err != nil {
			t.Fatal(err)
		}
		before := rawBindRow(t, store, record.Report.SelectionID)
		bound := outside
		bound.ImageIdentity = object
		if err := store.BindManagedProjectImageIdentity(ctx, bound); !errors.Is(err, ErrManagedProjectConflict) {
			t.Fatalf("non-ready record = %v", err)
		}
		if after := rawBindRow(t, store, record.Report.SelectionID); !reflect.DeepEqual(before, after) {
			t.Fatalf("refused non-ready record moved the durable row: before=%v after=%v", before, after)
		}
	})

	t.Run("a store failure is surfaced instead of a permissive result", func(t *testing.T) {
		store, record := openBindStoreWithRecord(t)
		bound := record
		bound.ImageIdentity = object
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		err := store.BindManagedProjectImageIdentity(ctx, bound)
		if err == nil || errors.Is(err, ErrManagedProjectConflict) {
			t.Fatalf("closed store bind = %v", err)
		}
	})
}
