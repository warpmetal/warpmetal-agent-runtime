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
	"unicode"
)

func setupExecMethod(t *testing.T) reflect.Method {
	t.Helper()
	typ := reflect.TypeOf(Podman{})
	method, exists := typ.MethodByName("ExecSetup")
	if !exists {
		t.Fatal("Podman.ExecSetup is missing; setup must not reuse the shell-oriented Exec seam")
	}
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	bytesType := reflect.TypeOf([]byte(nil))
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if method.Type.NumIn() != 4 || method.Type.In(1) != contextType ||
		method.Type.In(2).Kind() != reflect.String || method.Type.In(3) != bytesType ||
		method.Type.NumOut() != 3 || method.Type.Out(0) != bytesType ||
		method.Type.Out(1) != bytesType || method.Type.Out(2) != errorType {
		t.Fatalf("ExecSetup must be func(context.Context, string, []byte) ([]byte, []byte, error); got %s", method.Type)
	}
	return method
}

func TestExecSetupRejectsOversizedRequestBeforeContainerExecution(t *testing.T) {
	method := setupExecMethod(t)
	results := method.Func.Call([]reflect.Value{
		reflect.ValueOf(Podman{}),
		reflect.ValueOf(context.Background()),
		reflect.ValueOf("sbx_test12345"),
		reflect.ValueOf(make([]byte, 64*1024+1)),
	})
	if results[2].IsNil() {
		t.Fatal("an oversized setup request was accepted")
	}
	if results[0].Len() != 0 || results[1].Len() != 0 {
		t.Fatalf("oversized request returned output: receipt=%d diagnostic=%d", results[0].Len(), results[1].Len())
	}
}

func TestExecSetupOwnsFixedInvocationDeadlineAndOutputBounds(t *testing.T) {
	_ = setupExecMethod(t)
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
		function, ok := candidate.(*ast.FuncDecl)
		if ok && function.Recv != nil && function.Name.Name == "ExecSetup" {
			declaration = function
			break
		}
	}
	if declaration == nil || declaration.Body == nil {
		t.Fatal("Podman.ExecSetup implementation is missing")
	}
	var literals []string
	var identifiers []string
	ast.Inspect(declaration.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.BasicLit:
			if value.Kind == token.STRING {
				decoded, decodeErr := strconv.Unquote(value.Value)
				if decodeErr == nil {
					literals = append(literals, decoded)
				}
			}
		case *ast.Ident:
			identifiers = append(identifiers, value.Name)
		}
		return true
	})
	wantLiteralOrder := []string{
		"exec", "-i", "--user", "1000:1000", "--workdir", "/home/agent",
		"/usr/local/libexec/warpmetal-capability-launcher",
		"/usr/local/bin/warpmetal-setup-runner",
	}
	next := 0
	for _, literal := range literals {
		if next < len(wantLiteralOrder) && literal == wantLiteralOrder[next] {
			next++
		}
	}
	if next != len(wantLiteralOrder) {
		t.Fatalf("ExecSetup does not own the fixed structured podman argv; literals=%#v", literals)
	}
	for _, forbidden := range []string{"/bin/sh", "-lc", "-c"} {
		for _, literal := range literals {
			if literal == forbidden {
				t.Fatalf("ExecSetup contains forbidden shell control %q", forbidden)
			}
		}
	}
	joined := " " + strings.Join(identifiers, " ") + " "
	for _, required := range []string{
		" WithTimeout ", " setupOperationTimeout ", " maxSetupRequestBytes ",
		" maxSetupReceiptBytes ", " maxSetupDiagnosticBytes ",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("ExecSetup is missing required bound %q; identifiers=%s", strings.TrimSpace(required), joined)
		}
	}
	compact := strings.Map(func(character rune) rune {
		if unicode.IsSpace(character) {
			return -1
		}
		return character
	}, string(source))
	for _, bound := range []string{
		"maxSetupRequestBytes=64*1024",
		"maxSetupReceiptBytes=64*1024",
		"maxSetupDiagnosticBytes=16*1024",
		"setupOperationTimeout=10*time.Minute",
	} {
		if !strings.Contains(compact, bound) {
			t.Fatalf("Podman setup execution is missing exact bound %q", bound)
		}
	}
}
