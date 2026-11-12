package containers

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// openCodeWorkerRequest is the exact document the OpenCode managed-worker seam
// has always accepted: no profile field, so the strict OpenCode worker keeps
// validating its unchanged envelope.
const openCodeWorkerRequest = `{"schemaVersion":1,"command":"status","instance":"default","root":"/home/agent","allowInsecureLoopback":false,"requestTimeoutSeconds":30}`

func TestManagedWorkerInvocationSelectsDeepSeekProfile(t *testing.T) {
	request := []byte(`{"schemaVersion":1,"command":"status","instance":"default","root":"/home/agent","allowInsecureLoopback":false,"requestTimeoutSeconds":30}`)
	args, payload, err := ManagedWorkerInvocation("deepseek", request)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"/usr/bin/python3", "/usr/local/libexec/warpmetal-agent-teams/warpmetal_deepseek_team_worker.py"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("deepseek worker argv = %#v, want %#v", args, wantArgs)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("deepseek worker request = %s, %v", payload, err)
	}
	if document["profileId"] != "deepseek" {
		t.Fatalf("deepseek worker request omitted profileId: %s", payload)
	}
	if document["command"] != "status" || document["instance"] != "default" ||
		document["root"] != "/home/agent" || document["allowInsecureLoopback"] != false ||
		document["requestTimeoutSeconds"] != float64(30) {
		t.Fatalf("deepseek worker request changed a closed field: %s", payload)
	}
}

func TestManagedWorkerInvocationKeepsOpenCodeBytes(t *testing.T) {
	request := []byte(openCodeWorkerRequest)
	for _, profileID := range []string{"opencode", ""} {
		args, payload, err := ManagedWorkerInvocation(profileID, request)
		if err != nil {
			t.Fatal(err)
		}
		wantArgs := []string{"/usr/bin/python3", "/usr/local/libexec/warpmetal-agent-teams/warpmetal_team_worker.py"}
		if !reflect.DeepEqual(args, wantArgs) {
			t.Fatalf("%q worker argv = %#v, want %#v", profileID, args, wantArgs)
		}
		// The OpenCode worker validates its request strictly; the seam must
		// hand it exactly the bytes the producer built, with no profile field.
		if !bytes.Equal(payload, request) {
			t.Fatalf("%q worker request bytes changed: %s", profileID, payload)
		}
	}
}

func TestManagedWorkerInvocationDeepSeekRequestStaysBounded(t *testing.T) {
	if _, _, err := ManagedWorkerInvocation("deepseek", []byte(`not-json`)); err == nil {
		t.Fatal("malformed deepseek worker request was accepted")
	}
	request := append([]byte(`{"command":"status","pad":"`), bytes.Repeat([]byte("a"), managedWorkerRequestMaximum)...)
	request = append(request, []byte(`"}`)...)
	if _, _, err := ManagedWorkerInvocation("deepseek", request); err == nil {
		t.Fatal("oversized deepseek worker request was accepted")
	}
}
