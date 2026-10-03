package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type managerAPIContractFixture struct {
	ReservationRequest model.InsightsManagerReservationRequestV1 `json:"automaticReservationRequest"`
	Reservation        model.InsightsManagerReservationV1        `json:"automaticReservation"`
	RunReport          model.InsightsManagerRunReportV1          `json:"automaticReport"`
	ReportResponse     model.InsightsManagerActivityV1           `json:"automaticReportResponse"`
}

func TestManagerNodeClientReservesExactRequestAndSubmitsClosedReport(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "manager", "testdata", "backend-wire.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture managerAPIContractFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	var observedReservation model.InsightsManagerReservationRequestV1
	var observedReport model.InsightsManagerRunReportV1
	reportResponse := fixture.ReportResponse
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer rtn_manager" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("node authority headers = %#v", request.Header)
		}
		body, readErr := io.ReadAll(io.LimitReader(request.Body, 64*1024+1))
		if readErr != nil || len(body) > 64*1024 {
			t.Fatalf("manager body bytes=%d err=%v", len(body), readErr)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/internal/runtime/insights/manager/reservations":
			if request.Method != http.MethodPost {
				t.Fatalf("reservation method = %s", request.Method)
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&observedReservation); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(writer).Encode(fixture.Reservation)
		case "/internal/runtime/insights/manager/reports":
			if request.Method != http.MethodPost {
				t.Fatalf("report method = %s", request.Method)
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&observedReport); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(writer).Encode(reportResponse)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := Client{Origin: server.URL, NodeToken: "rtn_manager", HTTP: server.Client()}
	reservation, err := client.ReserveInsightsManagerReview(context.Background(), fixture.ReservationRequest)
	if err != nil || !reflect.DeepEqual(reservation, fixture.Reservation) || !reflect.DeepEqual(observedReservation, fixture.ReservationRequest) {
		t.Fatalf("reservation response/request = %#v/%#v, %v", reservation, observedReservation, err)
	}
	report, err := client.SubmitInsightsManagerRunReport(context.Background(), fixture.RunReport)
	if err != nil || !reflect.DeepEqual(report, fixture.ReportResponse) || !reflect.DeepEqual(observedReport, fixture.RunReport) {
		t.Fatalf("manager report response/request = %#v/%#v, %v", report, observedReport, err)
	}
	for name, mutate := range map[string]func(*model.InsightsManagerActivityV1){
		"run":         func(value *model.InsightsManagerActivityV1) { value.RunID += "_stale" },
		"reservation": func(value *model.InsightsManagerActivityV1) { value.ReservationID += "_stale" },
		"manual":      func(value *model.InsightsManagerActivityV1) { value.Manual = !value.Manual },
		"source": func(value *model.InsightsManagerActivityV1) {
			value.Source.ServiceGeneration++
		},
		"target": func(value *model.InsightsManagerActivityV1) {
			value.Target.MemberID += "_stale"
		},
		"state": func(value *model.InsightsManagerActivityV1) { value.State = "failed" },
	} {
		t.Run("rejects mismatched "+name, func(t *testing.T) {
			reportResponse = fixture.ReportResponse
			mutate(&reportResponse)
			if response, err := client.SubmitInsightsManagerRunReport(context.Background(), fixture.RunReport); err == nil || !reflect.DeepEqual(response, model.InsightsManagerActivityV1{}) {
				t.Fatalf("mismatched %s response was accepted: %#v, %v", name, response, err)
			}
		})
	}
}

// TestManagerTargetClientReadsClosedCanonicalDescriptor is the RED for the
// r1370 canonical descriptor read: GET
// /internal/runtime/insights/manager/target with exactly findingId and
// registeredSourceId, node bearer auth, no body, and a closed
// {formatVersion,findingId,findingRevision,source,target} response. The
// production client method is not implemented yet; it is located by reflection
// so the tree compiles and the missing method is the RED. Once implemented,
// the same journey proves the transport and closed-response validation.
func TestManagerTargetClientReadsClosedCanonicalDescriptor(t *testing.T) {
	const (
		findingID          = "finding_canon0001"
		registeredSourceID = "source_canon0001"
	)
	sourceJSON := `{"registeredSourceId":"source_canon0001","workspaceEpoch":"epoch_canon0001","nativeSessionId":"ses_canon0001","serviceRegistrationId":"service_canon0001","serviceGeneration":1,"sandboxGeneration":1,"profileRevision":1,"instructionRevision":1}`
	targetJSON := `{"teamId":"team_canon0001","memberId":"tmem_canon0001","taskId":"task_canon0001","taskAttempt":1,"workId":"work_canon0001","workRevision":1,"bindingId":"binding_canon0001","bindingRevision":1}`
	response := `{"formatVersion":1,"findingId":"` + findingID + `","findingRevision":3,"source":` + sourceJSON + `,"target":` + targetJSON + `}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/internal/runtime/insights/manager/target" {
			t.Fatalf("target request = %s %s", request.Method, request.URL.Path)
		}
		query := request.URL.Query()
		if len(query) != 2 || query.Get("findingId") != findingID || query.Get("registeredSourceId") != registeredSourceID {
			t.Fatalf("target query = %q", request.URL.RawQuery)
		}
		if request.Header.Get("Authorization") != "Bearer rtn_manager" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("node authority headers = %#v", request.Header)
		}
		if body, _ := io.ReadAll(io.LimitReader(request.Body, 1)); len(body) != 0 {
			t.Fatalf("target body = %q", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(response))
	}))
	defer server.Close()
	client := Client{Origin: server.URL, NodeToken: "rtn_manager", HTTP: server.Client()}
	envelope, err := client.GetInsightsManagerTarget(context.Background(), findingID, registeredSourceID)
	if err != nil {
		t.Fatalf("canonical target read = %v", err)
	}
	if envelope.FormatVersion != 1 || envelope.FindingID != findingID || envelope.FindingRevision != 3 ||
		envelope.Source.RegisteredSourceID != registeredSourceID ||
		envelope.Target.TaskID == nil || *envelope.Target.TaskID != "task_canon0001" ||
		envelope.Target.TaskAttempt == nil || *envelope.Target.TaskAttempt != 1 {
		t.Fatalf("canonical target envelope = %#v", envelope)
	}
	call := func() error {
		_, callErr := client.GetInsightsManagerTarget(context.Background(), findingID, registeredSourceID)
		return callErr
	}
	for name, mutate := range map[string]func(string) string{
		"finding": func(value string) string {
			return strings.Replace(value, `"findingId":"`+findingID+`"`, `"findingId":"finding_other0001"`, 1)
		},
		"source": func(value string) string {
			return strings.Replace(value, `"registeredSourceId":"`+registeredSourceID+`"`, `"registeredSourceId":"source_other0001"`, 1)
		},
		"unknown-field": func(value string) string {
			return strings.Replace(value, `,"target":`, `,"extraField":1,"target":`, 1)
		},
	} {
		t.Run("rejects "+name+" response", func(t *testing.T) {
			original := response
			response = mutate(response)
			defer func() { response = original }()
			if err := call(); err == nil {
				t.Fatalf("mismatched %s response was accepted", name)
			}
		})
	}
}
