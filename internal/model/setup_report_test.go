package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeReportExposesSetupStatusDistinctFromDesiredInput(t *testing.T) {
	reportType := reflect.TypeOf(Report{})
	field, exists := reportType.FieldByName("SetupOperations")
	if !exists {
		t.Fatal("Runtime report is missing setupOperations status/receipt observations")
	}
	if field.Tag.Get("json") != "setupOperations" || field.Type.Kind() != reflect.Slice {
		t.Fatalf("SetupOperations has the wrong wire contract: %s %q", field.Type, field.Tag.Get("json"))
	}
	operationType := field.Type.Elem()
	if operationType.Kind() == reflect.Pointer {
		operationType = operationType.Elem()
	}
	if operationType.Kind() != reflect.Struct {
		t.Fatalf("setup report item is not a struct: %s", operationType)
	}
	wantFields := map[string]string{
		"ID": "id", "SandboxID": "sandboxId", "SandboxGeneration": "sandboxGeneration",
		"ProfileID": "profileId", "ProfileRevision": "profileRevision",
		"ProfileDigest": "profileDigest", "ReceiptDigest": "receiptDigest",
	}
	for name, tag := range wantFields {
		item, ok := operationType.FieldByName(name)
		if !ok || strings.Split(item.Tag.Get("json"), ",")[0] != tag {
			t.Fatalf("setup report field %s/%s is missing from %s", name, tag, operationType)
		}
	}
	if status, ok := operationType.FieldByName("Status"); ok {
		if strings.Split(status.Tag.Get("json"), ",")[0] != "status" {
			t.Fatalf("setup report status has the wrong JSON tag: %q", status.Tag.Get("json"))
		}
	} else {
		if state, ok := operationType.FieldByName("State"); !ok ||
			strings.Split(state.Tag.Get("json"), ",")[0] != "state" {
			t.Fatalf("setup report item %s exposes neither status nor state", operationType)
		}
	}
	hasError := false
	for _, name := range []string{"Error", "LastError", "ErrorCode"} {
		if _, ok := operationType.FieldByName(name); ok {
			hasError = true
		}
	}
	if !hasError {
		t.Fatalf("setup report item %s has no bounded error observation", operationType)
	}
	for _, forbidden := range []string{"Materializer", "Artifacts", "Environment", "Argv", "Command"} {
		if _, ok := operationType.FieldByName(forbidden); ok {
			t.Fatalf("setup report leaks desired/execution input through %s", forbidden)
		}
	}

	report := Report{}
	reflect.ValueOf(&report).Elem().FieldByName("SetupOperations").Set(
		reflect.MakeSlice(field.Type, 0, 0),
	)
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"setupOperations":[]`) {
		t.Fatalf("empty setup observations must be a JSON array: %s", payload)
	}
}
