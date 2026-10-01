package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func sessionHandoffFrame(t *testing.T, handoff model.SessionHandoffV1) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"protocol": "wm-team-control/1",
		"handoff":  handoff,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(1+len(payload)))
	frame[4] = 0x01
	copy(frame[5:], payload)
	return frame
}

func TestHandoffPrefacePreservesExactHelloAndFollowingBridgeBytes(t *testing.T) {
	target := model.SessionHandoffV1{
		FormatVersion: 1,
		Action:        "open_session",
		HandoffID:     "handoff_preface_test",
	}
	frame := sessionHandoffFrame(t, target)
	following := []byte("following-frame-bytes")
	reader := bufio.NewReader(bytes.NewReader(append(append([]byte{}, frame...), following...)))

	gotTarget, gotFrame, err := readSessionHandoffPreface(context.Background(), reader)
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget.HandoffID != target.HandoffID || !bytes.Equal(gotFrame, frame) {
		t.Fatalf("preface changed: target=%+v frame=%x", gotTarget, gotFrame)
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, following) {
		t.Fatalf("following bridge bytes changed: %q", rest)
	}
}

func TestHandoffPrefaceRejectsMalformedOrOversizedHello(t *testing.T) {
	for name, input := range map[string][]byte{
		"wrong_type":       {0, 0, 0, 3, 0x02, '{', '}'},
		"malformed_json":   {0, 0, 0, 2, 0x01, '{'},
		"oversized_length": {0, 1, 0, 1, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := readSessionHandoffPreface(context.Background(), bufio.NewReader(bytes.NewReader(input))); err == nil {
				t.Fatal("invalid HELLO was accepted")
			}
		})
	}
}

func TestHandoffPrefaceWithoutTargetPreservesLegacyTeamHello(t *testing.T) {
	payload := []byte(`{"protocol":"wm-team-control/1"}`)
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(1+len(payload)))
	frame[4] = 0x01
	copy(frame[5:], payload)
	reader := bufio.NewReader(bytes.NewReader(frame))
	target, gotFrame, err := readSessionHandoffPreface(context.Background(), reader)
	if err != nil {
		t.Fatal(err)
	}
	if target != nil || !bytes.Equal(gotFrame, frame) {
		t.Fatalf("legacy HELLO was changed: target=%+v frame=%x", target, gotFrame)
	}
}

func TestHandoffPrefaceReadHonorsDeadline(t *testing.T) {
	input, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, _, err := readSessionHandoffPreface(ctx, bufio.NewReader(input)); err == nil {
		t.Fatal("stalled preface was accepted")
	}
	if time.Since(started) > time.Second {
		t.Fatal("stalled preface ignored its deadline")
	}
}
