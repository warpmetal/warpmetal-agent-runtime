package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCopySessionOutputReturnsRemoteStatusAndPreservesOutput(t *testing.T) {
	marker := "0123456789abcdef0123456789abcdef"
	payload := strings.Repeat("sandbox-output\n", 40)
	stream := payload + "\x00warpmetal-exit:" + marker + ":42\n"
	var output bytes.Buffer
	status, err := copySessionOutput(strings.NewReader(stream), &output, marker)
	if err != nil {
		t.Fatal(err)
	}
	if status != 42 {
		t.Fatalf("status = %d, want 42", status)
	}
	if output.String() != payload {
		t.Fatal("session output changed while removing the exit trailer")
	}
}

func TestCopySessionOutputDoesNotTrustAnotherMarker(t *testing.T) {
	marker := "0123456789abcdef0123456789abcdef"
	fake := "\x00warpmetal-exit:ffffffffffffffffffffffffffffffff:0\n"
	stream := fake + "\x00warpmetal-exit:" + marker + ":1\n"
	var output bytes.Buffer
	status, err := copySessionOutput(strings.NewReader(stream), &output, marker)
	if err != nil {
		t.Fatal(err)
	}
	if status != 1 || output.String() != fake {
		t.Fatalf("status/output = %d/%q", status, output.String())
	}
}

func TestCopySessionOutputRejectsMissingTrailerWithoutDroppingOutput(t *testing.T) {
	marker := "0123456789abcdef0123456789abcdef"
	var output bytes.Buffer
	status, err := copySessionOutput(strings.NewReader("plain output"), &output, marker)
	if err == nil || status != 1 {
		t.Fatalf("status/error = %d/%v, want 1/error", status, err)
	}
	if output.String() != "plain output" {
		t.Fatalf("output = %q", output.String())
	}
}
