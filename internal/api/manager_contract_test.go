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
