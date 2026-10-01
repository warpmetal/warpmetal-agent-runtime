package model

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type backendHandoffFixture struct {
	Finding backendHandoffDescriptor `json:"finding"`
	Work    backendHandoffDescriptor `json:"work"`
}

type backendHandoffDescriptor struct {
	FormatVersion int              `json:"formatVersion"`
	Capability    string           `json:"capability"`
	Reason        *string          `json:"reason"`
	Access        handoffAccess    `json:"access"`
	Handoff       SessionHandoffV1 `json:"handoff"`
}

type handoffAccess struct {
	RequiresLocalOwnerCredential bool   `json:"requiresLocalOwnerCredential"`
	RequiresPinnedHostKey        bool   `json:"requiresPinnedHostKey"`
	RequiresSandboxGrant         bool   `json:"requiresSandboxGrant"`
	Transport                    string `json:"transport"`
}

func TestActualBackendSessionHandoffFixtureIsAcceptedWithoutProjection(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "access", "testdata", "agent-session-handoff-v1.backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture backendHandoffFixture
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("backend fixture has trailing data: %v", err)
	}
	for name, descriptor := range map[string]backendHandoffDescriptor{
		"finding": fixture.Finding,
		"work":    fixture.Work,
	} {
		t.Run(name, func(t *testing.T) {
			if descriptor.FormatVersion != 1 || descriptor.Capability != "exact_session" ||
				descriptor.Reason != nil || descriptor.Access.Transport != "wm-team-control/1" ||
				!descriptor.Access.RequiresLocalOwnerCredential || !descriptor.Access.RequiresPinnedHostKey ||
				!descriptor.Access.RequiresSandboxGrant {
				t.Fatalf("unexpected backend descriptor: %+v", descriptor)
			}
			now := descriptor.Handoff.IssuedAt.Add(30 * time.Second)
			if err := ValidateSessionHandoffV1(descriptor.Handoff, now); err != nil {
				t.Fatalf("actual backend handoff was rejected: %v", err)
			}
		})
	}
	if fixture.Finding.Handoff.Work != nil {
		t.Fatal("finding unexpectedly requires Work")
	}
	if fixture.Work.Handoff.Work == nil {
		t.Fatal("Work descriptor omitted the exact binding")
	}
	if fixture.Finding.Handoff.Task != nil || fixture.Work.Handoff.Task != nil {
		t.Fatal("actual pre-task descriptors must retain null task")
	}
}

func TestSessionHandoffValidationClosesTimeAndNullablePairs(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "access", "testdata", "agent-session-handoff-v1.backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture backendHandoffFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	original := fixture.Finding.Handoff
	now := original.IssuedAt.Add(time.Second)
	tests := map[string]func(*SessionHandoffV1){
		"expired": func(value *SessionHandoffV1) { value.ExpiresAt = now.Add(-time.Nanosecond) },
		"future":  func(value *SessionHandoffV1) { value.IssuedAt = now.Add(time.Nanosecond) },
		"over_120_seconds": func(value *SessionHandoffV1) {
			value.ExpiresAt = value.IssuedAt.Add(120*time.Second + time.Nanosecond)
		},
		"partial_task": func(value *SessionHandoffV1) {
			value.Task = &SessionHandoffTaskV1{TaskID: "task_partial"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := original
			mutate(&value)
			if err := ValidateSessionHandoffV1(value, now); err == nil {
				t.Fatal("invalid handoff was accepted")
			}
		})
	}
}
