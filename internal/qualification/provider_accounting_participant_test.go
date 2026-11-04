package qualification_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Fixture preflight only: no synthetic enrolled identity is promoted to a
// protected registration. The producer and SQLite entry remain the actual
// owning opening/settlement implementations, and external schema validation is
// required before this fresh SOURCE packet may be invoked.
func checkAccountingParticipantSource(t *testing.T, authority json.RawMessage, producer qualification.ProducerConfig, participantID string) {
	t.Helper()
	var a struct {
		FormatVersion        int
		ParticipantInventory struct {
			FormatVersion int
			Participants  []json.RawMessage
		}
		Case struct{ ParticipantInventoryDigest string }
	}
	if json.Unmarshal(authority, &a) != nil || a.FormatVersion != 5 || a.ParticipantInventory.FormatVersion != 1 || len(a.ParticipantInventory.Participants) < 1 || len(a.ParticipantInventory.Participants) > 2 {
		t.Fatal("invalid explicit authority5 participant SOURCE fixture")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(authority, &fields)
	if model.WorkspaceDigest(fields["participantInventory"]) != a.Case.ParticipantInventoryDigest {
		t.Fatal("participant inventory digest fixture mismatch")
	}
	matches := 0
	for _, raw := range a.ParticipantInventory.Participants {
		var p struct {
			ParticipantID, AccountID, TaskID, ServerID string
			Producer                                   struct{ KeyID, KeySHA256, NodeTokenHash, PublicKeyBase64 string }
			Scopes                                     []model.ControllerOwner
		}
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("participant fixture shape")
		}
		var identity map[string]json.RawMessage
		_ = json.Unmarshal(raw, &identity)
		delete(identity, "participantId")
		if model.WorkspaceDigest(identity) != p.ParticipantID {
			t.Fatal("participant identity fixture digest")
		}
		if p.ParticipantID != participantID {
			continue
		}
		matches++
		public, err := base64.StdEncoding.Strict().DecodeString(p.Producer.PublicKeyBase64)
		if err != nil || len(public) > 4096 || qualification.Digest(public) != "sha256:"+strings.TrimPrefix(p.Producer.KeySHA256, "sha256:") || qualification.Digest(public) != producer.KeySHA256 {
			t.Fatal("participant public SOURCE key mismatch")
		}
		block, rest := pem.Decode(public)
		if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
			t.Fatal("participant public PEM fixture")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		key, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok || key.Curve.Params().Name != "P-256" || p.Producer.KeyID != producer.KeyID || p.Producer.NodeTokenHash != producer.NodeTokenHash || p.ServerID != producer.ServerID || len(p.Scopes) == 0 {
			t.Fatal("own SOURCE participant enrollment mismatch")
		}
		for _, scope := range p.Scopes {
			if scope.AccountID != p.AccountID || scope.TaskID != p.TaskID || scope.ServerID != p.ServerID {
				t.Fatal("participant SOURCE scope changed")
			}
		}
	}
	if matches != 1 {
		t.Fatal("own participant not selected exactly once")
	}
}

func exportAccountingReadbackSource(t *testing.T, p *qualification.Producer, store *state.Store, client api.Client, authority, demand json.RawMessage, operator []byte, root, name string) {
	t.Helper()
	ctx := context.Background()
	current, err := client.ProviderAccountingCurrent(ctx, model.WorkspaceDigest(authority))
	if err != nil {
		t.Fatal("actual current for independent readback", err)
	}
	first, err := p.ObserveProviderReadback(ctx, store, authority, demand, current, operator)
	if err != nil {
		t.Fatal("actual producer global/local readback", err)
	}
	again, err := p.ObserveProviderReadback(ctx, store, authority, demand, current, operator)
	if err != nil || string(first) != string(again) {
		t.Fatal("first readback signature changed", err)
	}
	if err = os.WriteFile(filepath.Join(root, name), first, 0600); err != nil {
		t.Fatal(err)
	}
}

func checkAccountingLocalRows(t *testing.T, store *state.Store, expected []int, participantID string) {
	t.Helper()
	anchor, err := store.PhysicalAnchor(context.Background())
	if err != nil || anchor == nil || expected == nil {
		t.Fatal("missing exact SOURCE local cut expectation", err)
	}
	history, err := store.PhysicalHistory(context.Background(), *anchor)
	if err != nil {
		t.Fatal("actual own physical history", err)
	}
	indices := make([]int, 0, len(history))
	for _, operation := range history {
		if operation.Permit.Case.ServerID != anchor.ServerID || operation.Permit.Case.TaskID != anchor.TaskID || operation.Permit.Provider == nil {
			t.Fatal("foreign or synthetic operation in own local cut")
		}
		var reservation struct {
			ParticipantID, PhysicalID string
			PhysicalIndex             int
		}
		if json.Unmarshal(operation.Permit.Provider.Reservation, &reservation) != nil || reservation.ParticipantID != participantID || reservation.PhysicalIndex != operation.Permit.Request.OuterPhysicalIndex || reservation.PhysicalID != model.WorkspaceDigest(map[string]any{"ledgerId": "model-qualification-and-product", "physicalIndex": reservation.PhysicalIndex}) {
			t.Fatal("local operation/reservation/participant mismatch")
		}
		indices = append(indices, reservation.PhysicalIndex)
	}
	if !reflect.DeepEqual(indices, expected) {
		t.Fatalf("actual local indices %v, expected %v; remote prefix must not create local operations", indices, expected)
	}
}
