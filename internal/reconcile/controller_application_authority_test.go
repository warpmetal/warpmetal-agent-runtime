package reconcile

import (
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// P7g: one Runtime node serves several workspaces whose application operations
// were accepted at different target runtime revisions, while the node-wide
// desired revision is a single scalar. A retained/applied operation accepted at
// an earlier revision must remain authority-valid when the node advances for
// another workspace; stale/unretained revisions still fail closed.
func TestApplicationRevisionCurrentAllowsRetainedEarlierTarget(t *testing.T) {
	cases := []struct {
		name     string
		target   int64
		desired  int64
		retained bool
		want     bool
	}{
		{"exact", 8, 8, false, true},
		{"retained earlier target", 4, 8, true, true},
		{"unretained earlier target", 4, 8, false, false},
		{"retained target ahead of node", 9, 8, true, false},
		{"unretained target ahead of node", 9, 8, false, false},
		{"retained same target", 8, 8, true, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := applicationRevisionCurrent(model.WorkspaceApplicationOperation{
				TargetRuntimeRevision: testCase.target,
			}, testCase.desired, testCase.retained)
			if got != testCase.want {
				t.Fatalf("applicationRevisionCurrent(target=%d desired=%d retained=%t)=%t want %t",
					testCase.target, testCase.desired, testCase.retained, got, testCase.want)
			}
		})
	}
}
