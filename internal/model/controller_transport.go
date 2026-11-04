package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// Only the settled controller output carries retained native history. Metadata,
// prepare, prompt, header and every predecessor/child transport keep 64KiB.
// This is a transport bound, never input/model/workflow authority.
const ControllerOutputTransportMaximum = 4 * 1024 * 1024

// Internal R/S read-only classification, never native/public terminal evidence.
var ErrControllerOutputRunningPending = errors.New("exact bound controller input is running")

func ControllerTransportReceiptMaximum(command string) int {
	if command == "controller-output" {
		return ControllerOutputTransportMaximum
	}
	return 64 * 1024
}

// Closed per-command outer wire; payloads are subsequently validated by the
// selected native/preparation/root consumer. Do not add these fields to the
// legacy metadata decoder or infer successful authority from status flags.
func DecodeControllerTransportReceipt(raw []byte, command string, target any) error {
	bad := errors.New("controller transport receipt refused")
	status := ""
	payload := []string{}
	switch command {
	case "controller-prepare":
		status = "prepared"
		payload = []string{"preparedReceipt"}
	case "controller-prompt":
		status = "admitted"
		payload = []string{"nativeAdmission"}
	case "controller-header", "child-header", "qualification-header":
		status = "observed"
		payload = []string{"headerObservation"}
	case "controller-output":
		status = "observed"
		payload = []string{"nativeOutput", "nativeLog"}
	default:
		return bad
	}
	if len(raw) == 0 || len(raw) > ControllerTransportReceiptMaximum(command) || !utf8.Valid(raw) || rejectDuplicateJSONFields(raw) != nil {
		return bad
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return bad
	}
	var header struct {
		SchemaVersion int    `json:"schemaVersion"`
		Command       string `json:"command"`
		Status        string `json:"status"`
	}
	if json.Unmarshal(raw, &header) != nil || header.SchemaVersion != 1 || header.Command != command {
		return bad
	}
	if command == "controller-output" && header.Status == "pending" && len(fields) == 3 {
		return ErrControllerOutputRunningPending
	}
	if header.Status != status || len(fields) != 3+len(payload) {
		return bad
	}
	for _, key := range payload {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return bad
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return bad
	}
	return nil
}
