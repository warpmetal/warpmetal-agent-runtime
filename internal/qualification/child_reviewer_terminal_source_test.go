package qualification

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Existing signed Store journey; actual frozen Sandbox reader consumes fresh
// SQLite. Provider/native DATA and current service remain detached SOURCE.
func SourceReviewerCompletedForTest(t *testing.T, base string, w ChildProductWitness, c ChildProductControl) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "python3", "-B", "testdata/reviewer_terminal_native.py", filepath.Join(base, "fixture.json"), base).CombinedOutput()
	if os.WriteFile(filepath.Join(base, "reviewer-terminal-source.log"), output, 0600) != nil {
		t.Fatal("SOURCE terminal log")
	}
	if err != nil {
		t.Fatalf("signed reviewer4 fixed native capture SOURCE: %v\n%s", err, output)
	}
	raw, err := os.ReadFile(filepath.Join(base, "reviewer-terminal-capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	captured, err := model.DecodeChildNativeReviewerCapture(raw)
	if err != nil {
		t.Fatal("SOURCE exact reviewer capture DTO", err)
	}
	q := c.Generation.Policy.Payload
	if captured.ValidateFor(w.Entry, c.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest, q.ReviewDelivery.AssessmentPath) != nil {
		t.Fatal("SOURCE completed reviewer owning native tuple")
	}
	native, role, responses, err := (ChildWorkflowNativeCapture{Reviewer: &captured}).completion(w.Entry, c)
	if err != nil || role != "reviewer" || len(responses) != 1 || responses[0] != captured.ProviderResponseDigest || !sameProduct(native, captured.Native) {
		t.Fatal("current signed reviewer4 completed capture refused", err)
	}
	changed := captured
	changed.Native.NativeProjectID = "foreign_project"
	if _, _, _, err = (ChildWorkflowNativeCapture{Reviewer: &changed}).completion(w.Entry, c); err == nil {
		t.Fatal("foreign reviewer native tuple accepted")
	}
	t.Log("SOURCE signed q4/current native SQLite completed assessment accepted; provider/native execution and protected service remain detached")
}
