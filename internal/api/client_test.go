package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func TestClientUsesPublishedRuntimeRoutes(t *testing.T) {
	t.Parallel()

	type requestExpectation struct {
		method        string
		path          string
		authorization string
		response      string
	}
	expected := []requestExpectation{
		{
			method:        http.MethodPost,
			path:          "/internal/runtime/register",
			authorization: "Bearer rtb_test",
			response:      `{"serverId":"srv_example123","nodeToken":"rtn_test","expiresAt":"2099-01-01T00:00:00Z","manifestUrl":"https://api.example/internal/runtime/manifest","reportUrl":"https://api.example/internal/runtime/report"}`,
		},
		{
			method:        http.MethodGet,
			path:          "/internal/runtime/manifest",
			authorization: "Bearer rtn_test",
			response:      `{"serverId":"srv_example123","desiredRevision":1,"sandboxes":[],"accessGrants":[]}`,
		},
		{
			method:        http.MethodPost,
			path:          "/internal/runtime/report",
			authorization: "Bearer rtn_test",
			response:      `{"accepted":true}`,
		},
	}
	requests := make([]requestExpectation, 0, len(expected))
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		index := len(requests)
		if index >= len(expected) {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
			http.Error(writer, "unexpected request", http.StatusInternalServerError)
			return
		}
		want := expected[index]
		requests = append(requests, requestExpectation{
			method:        request.Method,
			path:          request.URL.Path,
			authorization: request.Header.Get("Authorization"),
		})
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, want.response)
	}))
	defer server.Close()

	client := Client{
		Origin:    server.URL + "/ignored-prefix",
		NodeToken: "rtn_test",
		HTTP:      server.Client(),
	}
	ctx := context.Background()
	if _, err := client.Register(ctx, "rtb_test", Registration{ServerID: "srv_example123"}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if _, err := client.Manifest(ctx); err != nil {
		t.Fatalf("Manifest() error = %v", err)
	}
	if err := client.Report(ctx, model.Report{ServerID: "srv_example123"}); err != nil {
		t.Fatalf("Report() error = %v", err)
	}

	for index := range expected {
		expected[index].response = ""
	}
	if !reflect.DeepEqual(requests, expected) {
		t.Fatalf("requests = %#v, want %#v", requests, expected)
	}
}
