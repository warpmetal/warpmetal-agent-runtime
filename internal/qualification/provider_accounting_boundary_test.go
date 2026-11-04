package qualification_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// A phase of the existing backend financial/qualification journey. The backend
// owns its real PG cut and independent key enrollment. This subprocess owns its
// actual SQLite cut and retains the FIRST producer signature. Root ownership is
// the explicitly detached test-build supplier; no provider/native proof implied.
func TestProviderAccountingFreshSQLiteBoundary(t *testing.T) {
	path := os.Getenv("WARPMETAL_PROVIDER_ACCOUNTING_SOURCE_PACKET")
	if path == "" {
		t.Skip("explicit fresh backend financial SOURCE packet required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var selected struct {
		Phase string `json:"phase"`
	}
	if json.Unmarshal(raw, &selected) == nil && selected.Phase == "gate" {
		runProviderAccountingGateSource(t, raw)
		return
	}
	if selected.Phase == "successor-family" {
		runProviderAccountingFamilySource(t, raw)
		return
	}
	var packet struct {
		Phase                   string                       `json:"phase"`
		Root                    string                       `json:"root"`
		Producer                qualification.ProducerConfig `json:"producer"`
		Authority               json.RawMessage              `json:"authority"`
		Demand                  json.RawMessage              `json:"demand"`
		BackendOpening          json.RawMessage              `json:"backendOpening"`
		OperatorPublicKeyBase64 string                       `json:"operatorPublicKeyBase64"`
		ParticipantID           string                       `json:"participantId"`
	}
	if json.Unmarshal(raw, &packet) != nil || packet.Phase != "opening" || !filepath.IsAbs(packet.Root) {
		t.Fatal("invalid explicit SOURCE phase")
	}
	if packet.ParticipantID != "" {
		checkAccountingParticipantSource(t, packet.Authority, packet.Producer, packet.ParticipantID)
	}
	producer, err := qualification.SourceAccountingProducerForTest(packet.Producer)
	if err != nil {
		t.Fatal("independently enrolled SOURCE producer unavailable")
	}
	public, err := base64.StdEncoding.DecodeString(packet.OperatorPublicKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(packet.Root, "runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	original, err := producer.ObserveProviderOpening(context.Background(), store, packet.Authority, packet.Demand, packet.BackendOpening, public)
	if err != nil {
		if packet.ParticipantID != "" {
			t.Fatal("AUTHORITY5_PARTICIPANT_OPENING_UNSUPPORTED: actual independently enrolled SOURCE key and fresh own SQLite refused authority5/backendOpening3", err)
		}
		t.Fatal("independent Runtime empty opening", err)
	}
	again, err := producer.ObserveProviderOpening(context.Background(), store, packet.Authority, packet.Demand, packet.BackendOpening, public)
	if err != nil || string(again) != string(original) {
		t.Fatal("first Runtime opening signature replaced", err)
	}
	if err = os.WriteFile(filepath.Join(packet.Root, "runtime-opening.json"), original, 0600); err != nil {
		t.Fatal(err)
	}
	if packet.ParticipantID != "" {
		var observed struct {
			Payload struct {
				FormatVersion        int
				ParticipantID        string
				BackendOpeningDigest string
			}
		}
		if json.Unmarshal(original, &observed) != nil || observed.Payload.FormatVersion != 3 || observed.Payload.ParticipantID != packet.ParticipantID || observed.Payload.BackendOpeningDigest != qualification.CanonicalDigest(packet.BackendOpening) {
			t.Fatal("own local opening lost exact participant/backend original")
		}
	}
	t.Log("actual independent SQLite empty observation; first producer signature retained; synthetic authority/root ownership; provider calls 0")
}
