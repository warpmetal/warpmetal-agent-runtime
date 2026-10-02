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

func TestPodmanExposesOnlyFixedStructuredContinuityExecution(t *testing.T) {
	podman := reflect.TypeOf(Podman{})
	wantStructured := reflect.TypeOf(func(Podman, context.Context, string, []byte) ([]byte, []byte, error) {
		return nil, nil, nil
	})
	for _, methodName := range []string{"ExecContinuity"} {
		method, exists := podman.MethodByName(methodName)
		if !exists {
			t.Errorf("Podman.%s is missing; Runtime must use the fixed packaged helper instead of shell Exec", methodName)
			continue
		}
		if method.Type != wantStructured {
			t.Errorf("Podman.%s has type %s, want %s", methodName, method.Type, wantStructured)
		}
	}
}

func TestExecContinuityRejectsOversizedRequestBeforeContainerExecution(t *testing.T) {
	receipt, diagnostic, err := (Podman{}).ExecContinuity(context.Background(), "sbx_test12345", make([]byte, 64*1024+1))
	if err == nil || len(receipt) != 0 || len(diagnostic) != 0 {
		t.Fatalf("oversized request receipt=%d diagnostic=%d err=%v", len(receipt), len(diagnostic), err)
	}
}

func TestExecContinuityOwnsFixedHelperInvocationAndBounds(t *testing.T) {
	source, err := os.ReadFile("podman.go")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "podman.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var declaration *ast.FuncDecl
	for _, candidate := range parsed.Decls {
		if function, ok := candidate.(*ast.FuncDecl); ok && function.Recv != nil && function.Name.Name == "ExecContinuity" {
			declaration = function
			break
		}
	}
	if declaration == nil || declaration.Body == nil {
		t.Fatal("Podman.ExecContinuity implementation is missing")
	}
	var literals, identifiers []string
	ast.Inspect(declaration.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.BasicLit:
			if value.Kind == token.STRING {
				if decoded, decodeErr := strconv.Unquote(value.Value); decodeErr == nil {
					literals = append(literals, decoded)
				}
			}
		case *ast.Ident:
			identifiers = append(identifiers, value.Name)
		}
		return true
	})
	want := []string{"exec", "-i", "--user", "1000:1000", "--workdir", "/home/agent", "/usr/local/libexec/warpmetal-capability-launcher", "/usr/local/bin/warpmetal-continuity"}
	next := 0
	for _, literal := range literals {
		if next < len(want) && literal == want[next] {
			next++
		}
	}
	if next != len(want) {
		t.Fatalf("continuity invocation literals=%#v", literals)
	}
	joined := " " + strings.Join(identifiers, " ") + " "
	for _, required := range []string{" WithTimeout ", " continuityHelperTimeout ", " maxContinuityRequestBytes ", " maxContinuityReceiptBytes ", " maxContinuityDiagnosticBytes "} {
		if !strings.Contains(joined, required) {
			t.Fatalf("ExecContinuity is missing bound %q", strings.TrimSpace(required))
		}
	}
}
