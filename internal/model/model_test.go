package model

import (
	"strings"
	"testing"
)

func testImageDigest(value string) string {
	return "registry.example/sandbox@sha256:" + strings.Repeat(value, 64)
}

func TestValidateManifestAcceptsFixedTemporarySandbox(t *testing.T) {
	seconds := 900
	manifest := Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: 1,
		ImageDigest:     testImageDigest("a"),
		Capacity:        Resources{CPUMillicores: 1500, MemoryMiB: 3072, WorkspaceDiskGiB: 30},
		Sandboxes: []Sandbox{
			{
				ID:               "sbx_test12345",
				Name:             "reviewer",
				Size:             "small",
				Resources:        Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256},
				Lifetime:         "temporary",
				ExpiresInSeconds: &seconds,
				DesiredState:     "running",
				Generation:       1,
			},
		},
	}
	if err := ValidateManifest(manifest, "srv_test12345", 0); err != nil {
		t.Fatal(err)
	}
}

func TestValidateManifestRejectsWrongServerOverCapacityAndDuplicateKey(t *testing.T) {
	manifest := Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: 2,
		ImageDigest:     testImageDigest("a"),
		Capacity:        Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10},
		Sandboxes: []Sandbox{
			{
				ID:           "sbx_test12345",
				Name:         "main",
				Resources:    Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20, PIDs: 256},
				Lifetime:     "persistent",
				DesiredState: "running",
				Generation:   1,
			},
		},
	}
	if err := ValidateManifest(manifest, "srv_other12345", 1); err == nil {
		t.Fatal("expected server identity rejection")
	}
	if err := ValidateManifest(manifest, manifest.ServerID, 1); err == nil {
		t.Fatal("expected capacity rejection")
	}
}

func TestValidateManifestRejectsMutableImageReference(t *testing.T) {
	manifest := Manifest{
		ServerID:        "srv_test12345",
		DesiredRevision: 1,
		ImageDigest:     "registry.example/sandbox:latest",
		Capacity:        Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10},
	}
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err == nil {
		t.Fatal("expected mutable image reference rejection")
	}
}
