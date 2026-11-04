package containers

import (
	"errors"
	"strings"
	"testing"
)

func TestStageErrorPreservesSentinelAndAddsStage(t *testing.T) {
	base := errors.New("base refusal")
	err := stageError("bootstrap", base)
	if !errors.Is(err, base) {
		t.Fatal("stage wrapper did not preserve underlying error")
	}
	if !strings.Contains(err.Error(), "managed create stage bootstrap: base refusal") {
		t.Fatalf("unexpected stage text: %v", err)
	}
	if stageError("bootstrap", nil) != nil {
		t.Fatal("nil error must remain nil")
	}
}
