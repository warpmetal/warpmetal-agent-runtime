package state

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func TestManagedServiceCreationIntentAndRecoveryModeAreDurableAndImmutable(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	intent := LocalManagedService{
		Manifest: model.ManagedServiceV1{FormatVersion: 1, OperationID: "op_managed_start_0001", ActionRevision: 2, DesiredRevision: 1, ConfigDigest: "sha256:" + strings.Repeat("2", 64), DesiredState: "active", SessionMode: "create_initial", Identity: model.ManagedServiceIdentityV1{ServiceRegistrationID: "service_managedservice0001", SandboxID: "sbx_managedservice00000001", SandboxGeneration: 4, ExpectedServiceGeneration: 1}},
		Phase:    "creation_intent", ProcessInstance: "wmsup-default-0001", Port: 18443,
	}
	if err := store.PutManagedServiceIntent(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkManagedServiceCreationDispatched(context.Background(), intent.Manifest.Identity.ServiceRegistrationID, intent.Manifest.ConfigDigest); err != nil {
		t.Fatal(err)
	}
	store.Close()

	reopened, err := Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.ManagedService(context.Background(), intent.Manifest.Identity.ServiceRegistrationID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.CreationDispatched || got.RecoverySessionMode() != "lookup_only" {
		t.Fatalf("durable first creation fence = %#v", got)
	}
	// A fresh owner Start after Stop can still carry create_initial when the
	// backend never received a native receipt. The durable dispatch fence wins.
	for _, desired := range []string{"stopped", "active"} {
		intent.Manifest.ActionRevision++
		intent.Manifest.DesiredRevision++
		intent.Manifest.DesiredState = desired
		intent.Manifest.SessionMode = "lookup_only"
		if desired == "active" {
			intent.Manifest.SessionMode = "create_initial"
		}
		if err := reopened.PutManagedServiceIntent(context.Background(), intent); err != nil {
			t.Fatal(err)
		}
		got, err = reopened.ManagedService(context.Background(), intent.Manifest.Identity.ServiceRegistrationID)
		if err != nil || got == nil || !got.CreationDispatched || got.RecoverySessionMode() != "lookup_only" {
			t.Fatalf("Stop/Start cleared the durable creation fence: %#v %v", got, err)
		}
	}
	conflict := intent
	conflict.Manifest.ConfigDigest = "sha256:" + strings.Repeat("3", 64)
	if err := reopened.PutManagedServiceIntent(context.Background(), conflict); !errors.Is(err, ErrManagedServiceConflict) {
		t.Fatalf("config drift = %v", err)
	}
	if err := reopened.UpdateManagedService(context.Background(), intent.Manifest.Identity.ServiceRegistrationID, "retired", nil, ""); err != nil {
		t.Fatal(err)
	}
	next := conflict
	next.Manifest.ActionRevision++
	next.Manifest.DesiredRevision++
	next.Manifest.SessionMode = "lookup_only"
	next.Manifest.Identity.ExpectedServiceGeneration++
	next.ProcessInstance = "wmsup-default-0002"
	if err := reopened.PutManagedServiceIntent(context.Background(), next); err != nil {
		t.Fatalf("explicit retired generation rebind: %v", err)
	}
	got, err = reopened.ManagedService(context.Background(), next.Manifest.Identity.ServiceRegistrationID)
	if err != nil || got == nil || got.CreationDispatched || got.ServiceGeneration != 2 || got.RecoverySessionMode() != "lookup_only" {
		t.Fatalf("rebound generation = %#v %v", got, err)
	}
}

func TestManagedServiceTerminalReissueAdoptsLowerActionRevision(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	terminal := LocalManagedService{
		Manifest: model.ManagedServiceV1{FormatVersion: 1, OperationID: "op_live_run16_quiesce_0001", ActionRevision: 3, DesiredRevision: 2, ConfigDigest: "sha256:" + strings.Repeat("2", 64), DesiredState: "stopped", SessionMode: "lookup_only", Identity: model.ManagedServiceIdentityV1{ServiceRegistrationID: "service_terminalreissue0001", SandboxID: "sbx_terminalreissue000001", SandboxGeneration: 1, ExpectedServiceGeneration: 1}},
		Phase:    "stopped", ProcessInstance: "wmsup-default-0001", Port: 18443,
	}
	if err := store.PutManagedServiceIntent(context.Background(), terminal); err != nil {
		t.Fatal(err)
	}
	// A team-level stop re-issues a terminal operation whose team action
	// revision is lower than the retained record's. The retained terminal
	// record adopts it because the identity, config digest, process instance
	// and port all match and both sides target the same terminal state.
	reissue := terminal
	reissue.Manifest.OperationID = "op_live_l11_v8_stop_b"
	reissue.Manifest.ActionRevision = 2
	reissue.Manifest.DesiredRevision = 3
	if err := store.PutManagedServiceIntent(context.Background(), reissue); err != nil {
		t.Fatalf("terminal reissue = %v", err)
	}
	got, err := store.ManagedService(context.Background(), terminal.Manifest.Identity.ServiceRegistrationID)
	if err != nil || got == nil || got.Manifest.OperationID != "op_live_l11_v8_stop_b" ||
		got.Manifest.ActionRevision != 2 || got.Manifest.DesiredRevision != 3 {
		t.Fatalf("adopted terminal reissue = %#v %v", got, err)
	}
	// A desired-revision regression stays strict even for a terminal record.
	regressed := reissue
	regressed.Manifest.DesiredRevision = 1
	if err := store.PutManagedServiceIntent(context.Background(), regressed); !errors.Is(err, ErrManagedServiceConflict) {
		t.Fatalf("desired revision regression = %v", err)
	}
	// A same-action-revision re-issue with different content stays strict.
	sameRevision := reissue
	sameRevision.Manifest.OperationID = "op_live_other_stop_0002"
	if err := store.PutManagedServiceIntent(context.Background(), sameRevision); !errors.Is(err, ErrManagedServiceConflict) {
		t.Fatalf("same action revision drift = %v", err)
	}
	// Identity, config digest, process instance and port must all match.
	configDrift := reissue
	configDrift.Manifest.ConfigDigest = "sha256:" + strings.Repeat("7", 64)
	if err := store.PutManagedServiceIntent(context.Background(), configDrift); !errors.Is(err, ErrManagedServiceConflict) {
		t.Fatalf("config drift = %v", err)
	}
	portDrift := reissue
	portDrift.Port = 19443
	if err := store.PutManagedServiceIntent(context.Background(), portDrift); !errors.Is(err, ErrManagedServiceConflict) {
		t.Fatalf("port drift = %v", err)
	}
	identityDrift := reissue
	identityDrift.Manifest.Identity.SandboxID = "sbx_terminalreissue000002"
	if err := store.PutManagedServiceIntent(context.Background(), identityDrift); !errors.Is(err, ErrManagedServiceConflict) {
		t.Fatalf("identity drift = %v", err)
	}
	processDrift := reissue
	processDrift.ProcessInstance = "wmsup-default-0002"
	if err := store.PutManagedServiceIntent(context.Background(), processDrift); !errors.Is(err, ErrManagedServiceConflict) {
		t.Fatalf("process instance drift = %v", err)
	}
	// A re-issued operation for a different desired state keeps the strict
	// immutable revision guard.
	restart := reissue
	restart.Manifest.ActionRevision = 1
	restart.Manifest.DesiredRevision = 4
	restart.Manifest.DesiredState = "active"
	restart.Manifest.SessionMode = "create_initial"
	if err := store.PutManagedServiceIntent(context.Background(), restart); !errors.Is(err, ErrManagedServiceConflict) {
		t.Fatalf("non-terminal reissue = %v", err)
	}
	// A local record that has not converged terminal cannot adopt a lower
	// action revision either.
	if err := store.UpdateManagedService(context.Background(), terminal.Manifest.Identity.ServiceRegistrationID, "ready", nil, ""); err != nil {
		t.Fatal(err)
	}
	stale := reissue
	stale.Manifest.ActionRevision = 1
	if err := store.PutManagedServiceIntent(context.Background(), stale); !errors.Is(err, ErrManagedServiceConflict) {
		t.Fatalf("non-terminal local phase reissue = %v", err)
	}
}
