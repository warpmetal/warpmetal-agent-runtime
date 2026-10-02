package containers

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestManagedServiceExecutionUsesOnlyPackagedSupervisorAndWorker(t *testing.T) {
	if _, _, err := (Podman{}).ExecManagedSupervisor(context.Background(), "sbx_test12345", ManagedSupervisorAction("shell"), []byte(`{}`)); err == nil {
		t.Fatal("arbitrary supervisor action was accepted")
	}
	if _, _, err := (Podman{}).ExecManagedWorker(context.Background(), "sbx_test12345", ManagedWorkerAction("shell"), []byte(`{}`)); err == nil {
		t.Fatal("arbitrary worker action was accepted")
	}

	source, err := os.ReadFile("podman.go")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "podman.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var literals []string
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv == nil || (function.Name.Name != "ExecManagedSupervisor" && function.Name.Name != "ExecManagedWorker") {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if ok && literal.Kind == token.STRING {
				if decoded, decodeErr := strconv.Unquote(literal.Value); decodeErr == nil {
					literals = append(literals, decoded)
				}
			}
			return true
		})
	}
	joined := " " + strings.Join(literals, " ") + " "
	for _, required := range []string{" /usr/local/bin/warpmetal-opencode-supervisor ", " /usr/bin/python3 ", " /usr/local/libexec/warpmetal-agent-teams/warpmetal_team_worker.py "} {
		if !strings.Contains(joined, required) {
			t.Fatalf("managed execution is missing fixed target %q: %#v", strings.TrimSpace(required), literals)
		}
	}
	for _, forbidden := range []string{"/bin/sh", "-c", "-lc"} {
		if strings.Contains(joined, " "+forbidden+" ") {
			t.Fatalf("managed execution contains shell control %q", forbidden)
		}
	}
}

func TestManagedSupervisorExposesFixedHandoffWorkspaceRegistration(t *testing.T) {
	if ManagedSupervisorRegisterHandoffWorkspace != ManagedSupervisorAction("register-handoff-workspace") {
		t.Fatalf("handoff workspace action = %q", ManagedSupervisorRegisterHandoffWorkspace)
	}
}

func TestManagedSupervisorExposesFixedProviderRebind(t *testing.T) {
	if ManagedSupervisorRebind != ManagedSupervisorAction("rebind") {
		t.Fatalf("provider rebind action = %q", ManagedSupervisorRebind)
	}
}
