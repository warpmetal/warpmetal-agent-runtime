package containers

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestPodmanExecManagerIsFixedBoundedPackagedExecution(t *testing.T) {
	method, exists := reflect.TypeOf(Podman{}).MethodByName("ExecManager")
	want := reflect.TypeOf(func(Podman, context.Context, string, []byte) ([]byte, []byte, error) { return nil, nil, nil })
	if !exists || method.Type != want {
		t.Fatalf("Podman.ExecManager = %v, %v; want %v", method.Type, exists, want)
	}
	if out, diagnostic, err := (Podman{}).ExecManager(context.Background(), "sbx_managerexec0001", make([]byte, 64*1024+1)); err == nil || len(out) != 0 || len(diagnostic) != 0 {
		t.Fatalf("oversized request crossed boundary: %d/%d %v", len(out), len(diagnostic), err)
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
		if !ok || function.Name.Name != "ExecManager" || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if value, ok := node.(*ast.BasicLit); ok && value.Kind == token.STRING {
				if decoded, decodeErr := strconv.Unquote(value.Value); decodeErr == nil {
					literals = append(literals, decoded)
				}
			}
			return true
		})
	}
	joined := strings.Join(literals, " ")
	for _, required := range []string{"exec", "-i", "/usr/local/libexec/warpmetal-capability-launcher", "/usr/local/bin/warpmetal-manager"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("fixed manager invocation missing %q: %v", required, literals)
		}
	}
}
