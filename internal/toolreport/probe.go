package toolreport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

const (
	maxReportBytes  = 16 * 1024
	maxVersionBytes = 128
	probeTimeout    = 15 * time.Second
)

var (
	knownTools  = map[string]bool{"codex": true, "claude": true, "cursor": true}
	safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	knownErrors = map[string]string{
		"tool_probe_failed":   "tool availability probe failed",
		"tool_report_failed":  "tool availability could not be verified",
		"tool_report_invalid": "tool availability report was invalid",
		"version_mismatch":    "tool version did not match manifest",
	}
)

type Executor interface {
	ToolReport(context.Context, string, io.Writer) error
}

// Probe invokes the image's single baked-in tool reporter and returns only the
// desired observations. Any execution or contract failure is converted into a
// bounded, non-sensitive failure for every desired tool.
func Probe(ctx context.Context, executor Executor, sandboxID string, desired []string) []model.CLIToolReport {
	if len(desired) == 0 {
		return []model.CLIToolReport{}
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var output limitedBuffer
	output.limit = maxReportBytes
	if err := executor.ToolReport(probeCtx, sandboxID, &output); err != nil {
		return failed(desired, "tool_report_failed", "tool availability could not be verified")
	}
	if output.overflow {
		return failed(desired, "tool_report_invalid", "tool availability report was invalid")
	}
	observed, err := parse(output.Bytes())
	if err != nil {
		return failed(desired, "tool_report_invalid", "tool availability report was invalid")
	}
	byID := make(map[string]model.CLIToolReport, len(observed))
	for _, item := range observed {
		byID[item.ID] = item
	}
	selected := make([]model.CLIToolReport, 0, len(desired))
	for _, id := range desired {
		item, ok := byID[id]
		if !ok {
			return failed(desired, "tool_report_invalid", "tool availability report was invalid")
		}
		selected = append(selected, item)
	}
	return selected
}

// MatchesDesired verifies that persisted observations are safe, valid, and in
// the exact desired order before they are reused or sent to the control plane.
func MatchesDesired(desired []string, observed []model.CLIToolReport) bool {
	if len(desired) != len(observed) {
		return false
	}
	for index, id := range desired {
		item := observed[index]
		if !knownTools[id] || item.ID != id || !validObservation(item) {
			return false
		}
	}
	return true
}

func parse(payload []byte) ([]model.CLIToolReport, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var observed []model.CLIToolReport
	if err := decoder.Decode(&observed); err != nil {
		return nil, err
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, err
	}
	if len(observed) != len(knownTools) {
		return nil, errors.New("tool report must contain the complete catalog")
	}
	seen := make(map[string]bool, len(observed))
	for index := range observed {
		item := &observed[index]
		if !knownTools[item.ID] || seen[item.ID] {
			return nil, errors.New("tool report identity is invalid")
		}
		seen[item.ID] = true
		switch item.Status {
		case "available":
		case "failed":
			if item.LastError == nil {
				item.LastError = &model.ItemError{
					Code: "tool_probe_failed", Message: knownErrors["tool_probe_failed"],
				}
			}
		default:
			return nil, errors.New("tool report status is invalid")
		}
		if !validObservation(*item) {
			return nil, errors.New("tool report observation is invalid")
		}
	}
	for id := range knownTools {
		if !seen[id] {
			return nil, errors.New("tool report is incomplete")
		}
	}
	return observed, nil
}

func validObservation(item model.CLIToolReport) bool {
	if item.Version != "" &&
		(len(item.Version) > maxVersionBytes || !safeVersion.MatchString(item.Version)) {
		return false
	}
	switch item.Status {
	case "available":
		return item.LastError == nil
	case "failed":
		if item.Version != "" || item.LastError == nil {
			return false
		}
		message, ok := knownErrors[item.LastError.Code]
		return ok && item.LastError.Message == message && len(item.LastError.Message) <= 160 &&
			!hasUnsafeText(item.LastError.Message)
	default:
		return false
	}
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("tool report contains trailing data")
	}
	return err
}

func failed(desired []string, code, message string) []model.CLIToolReport {
	result := make([]model.CLIToolReport, 0, len(desired))
	for _, id := range desired {
		result = append(result, model.CLIToolReport{
			ID:     id,
			Status: "failed",
			LastError: &model.ItemError{
				Code:    code,
				Message: message,
			},
		})
	}
	return result
}

func hasUnsafeText(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0
}

type limitedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedBuffer) Write(payload []byte) (int, error) {
	written := len(payload)
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return written, nil
	}
	if len(payload) > remaining {
		b.overflow = true
		payload = payload[:remaining]
	}
	_, _ = b.Buffer.Write(payload)
	return written, nil
}
