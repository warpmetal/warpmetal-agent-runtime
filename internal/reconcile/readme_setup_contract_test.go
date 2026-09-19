package reconcile

import (
	"os"
	"regexp"
	"testing"
)

func runtimeReadme(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func requireReadmeContract(t *testing.T, readme, expression, message string) {
	t.Helper()
	matched, err := regexp.MatchString("(?is)"+expression, readme)
	if err != nil {
		t.Fatalf("invalid documentation contract expression: %v", err)
	}
	if !matched {
		t.Error(message)
	}
}

func TestRuntimeReadmeDocumentsDurableSetupLifecycle(t *testing.T) {
	readme := runtimeReadme(t)
	requireReadmeContract(t, readme,
		`pending\s*(?:→|->)\s*applying\s*(?:→|->)\s*(?:ready|failed|cancelled).*(?:failed|cancelled)`,
		"README must document durable pending -> applying -> ready/failed/cancelled setup states")
	requireReadmeContract(t, readme,
		`one (?:setup )?operation per report cycle`,
		"README must document that only one setup operation executes per report cycle")
}

func TestRuntimeReadmeDocumentsSetupDeadlineAndRevisionGate(t *testing.T) {
	readme := runtimeReadme(t)
	requireReadmeContract(t, readme,
		`10[- ]minute[^\n]{0,100}(?:per-operation|per operation|each operation)`,
		"README must document the 10-minute per-operation setup bound")
	requireReadmeContract(t, readme,
		`applied revision[^\n]{0,160}(?:only|until)[^\n]{0,80}(?:all )?(?:setup )?operations?[^\n]{0,60}ready`,
		"README must document that applied revision advances only when all setup operations are ready")
}

func TestRuntimeReadmeLimitsCloudInitToRuntimeEnrollment(t *testing.T) {
	readme := runtimeReadme(t)
	requireReadmeContract(t, readme,
		`cloud-init[^\n]{0,180}(?:only|solely)[^\n]{0,120}(?:bootstrap|install)[^\n]{0,80}(?:and|then)[^\n]{0,80}enrol[^\n]{0,60}Runtime`,
		"README must document that cloud-init only bootstraps and enrolls Runtime")
	requireReadmeContract(t, readme,
		`cloud-init[^\n]{0,260}(?:does not|never)[^\n]{0,120}(?:provider tools?|AI CLI)[^\n]{0,100}(?:host root|as root)`,
		"README must document that cloud-init does not install provider tools as host root")
}
