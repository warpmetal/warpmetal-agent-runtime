package main

import (
	"encoding/base64"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func TestOrdinaryRuntimeConstructorWiresFixedSessionHandoffEngineAndDaemonHostPin(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], 11)
	blob := append([]byte{}, length[:]...)
	blob = append(blob, "ssh-ed25519"...)
	binary.BigEndian.PutUint32(length[:], 32)
	blob = append(blob, length[:]...)
	blob = append(blob, make([]byte, 32)...)
	gateway, err := newAccessGateway(store, containers.Podman{}, []model.HostKey{{
		PublicKey: "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if gateway.Store != store || gateway.Engine == nil || gateway.SessionHandoffEngine == nil ||
		gateway.HostKeyFingerprint == "" {
		t.Fatalf("ordinary Runtime omitted handoff authority: %+v", gateway)
	}
}
