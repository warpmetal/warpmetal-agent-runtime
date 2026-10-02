package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type managedServiceFixture struct {
	SetupManifest            model.SetupOperation               `json:"setupManifest"`
	WorkspaceRequestManifest model.ManagedWorkspaceRequestV1    `json:"workspaceRequestManifest"`
	WorkspaceCatalogReport   model.ProjectCatalogReportV1       `json:"workspaceCatalogReport"`
	ServiceManifest          model.ManagedServiceV1             `json:"serviceManifest"`
	ServiceReport            model.ManagedServiceReportV1       `json:"serviceReport"`
	EnrollmentRequest        model.ManagedServiceFetchRequestV1 `json:"enrollmentRequest"`
	EnrollmentResponse       model.ManagedServiceEnrollmentV1   `json:"enrollmentResponse"`
	InstructionRequest       model.ManagedServiceFetchRequestV1 `json:"instructionRequest"`
	InstructionResponse      model.ManagedServiceInstructionV1  `json:"instructionResponse"`
}

func loadManagedServiceFixture(t *testing.T) managedServiceFixture {
	t.Helper()
	payload, err := os.ReadFile("testdata/agent-managed-service-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture managedServiceFixture
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestClientConsumesCanonicalManagedServiceManifest(t *testing.T) {
	fixture := loadManagedServiceFixture(t)
	response := apiManifestWithMaterializer("opencode", apiOpenCodeArchiveMaterializer)
	var body map[string]any
	if err := json.Unmarshal([]byte(response), &body); err != nil {
		t.Fatal(err)
	}
	body["managedWorkspaceRequests"] = []any{fixture.WorkspaceRequestManifest}
	body["managedServices"] = []any{fixture.ServiceManifest}
	payload, _ := json.Marshal(body)
	client, closeServer := manifestClientForResponse(t, string(payload))
	defer closeServer()
	manifest, err := client.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest.ManagedWorkspaceRequests, []model.ManagedWorkspaceRequestV1{fixture.WorkspaceRequestManifest}) ||
		!reflect.DeepEqual(manifest.ManagedServices, []model.ManagedServiceV1{fixture.ServiceManifest}) {
		t.Fatalf("managed manifest drifted: %#v", manifest)
	}
}

func TestManagedServiceNodeClientUsesClosedEnrollmentAndInstructionPaths(t *testing.T) {
	fixture := loadManagedServiceFixture(t)
	type observed struct {
		path string
		body model.ManagedServiceFetchRequestV1
	}
	var requests []observed
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer rtn_test" {
			t.Fatalf("request authority = %s %s", request.Method, request.Header.Get("Authorization"))
		}
		payload, err := io.ReadAll(io.LimitReader(request.Body, 64*1024+1))
		if err != nil || len(payload) > 64*1024 {
			t.Fatalf("request body = %d %v", len(payload), err)
		}
		var body model.ManagedServiceFetchRequestV1
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, observed{request.URL.Path, body})
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		if len(requests) == 1 {
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(fixture.EnrollmentResponse)
		} else {
			_ = json.NewEncoder(writer).Encode(fixture.InstructionResponse)
		}
	}))
	client := Client{Origin: server.URL, NodeToken: "rtn_test", HTTP: server.Client()}
	enrollment, err := client.ManagedServiceEnrollment(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture.EnrollmentRequest)
	if err != nil {
		t.Fatal(err)
	}
	instruction, err := client.ManagedServiceInstructions(context.Background(), fixture.ServiceManifest.Identity.ServiceRegistrationID, fixture.InstructionRequest)
	if err != nil {
		t.Fatal(err)
	}
	wantBase := "/internal/runtime/agent-teams/managed-services/" + fixture.ServiceManifest.Identity.ServiceRegistrationID
	if len(requests) != 2 || requests[0].path != wantBase+"/enrollment" || requests[1].path != wantBase+"/instructions" ||
		!reflect.DeepEqual(requests[0].body, fixture.EnrollmentRequest) || !reflect.DeepEqual(requests[1].body, fixture.InstructionRequest) ||
		!reflect.DeepEqual(enrollment, fixture.EnrollmentResponse) || !reflect.DeepEqual(instruction, fixture.InstructionResponse) {
		t.Fatalf("managed node exchange drifted: requests=%#v enrollment=%#v instruction=%#v", requests, enrollment, instruction)
	}
}
