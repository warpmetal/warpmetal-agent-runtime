package reconcile

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// frozenBackendV21 is the frozen mirror of backend v21's registration-report
// schema validation and apply_registration_reports acceptance rules. Its
// constants (closed field sets, statuses, patterns, refusal messages) come from
// the frozen fixture, which was written directly from
// backend/warpmetal/continuity_node.py (read-only reference).
type frozenBackendV21 struct {
	fixture struct {
		Note          string `json:"note"`
		Source        string `json:"source"`
		FormatVersion int    `json:"formatVersion"`
		InvalidReport struct {
			Status  int    `json:"status"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"invalidReport"`
		ReportConflict struct {
			Status  int    `json:"status"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"reportConflict"`
		TerminalReceiptConflict         string `json:"terminalReceiptConflict"`
		RegistrationNotCurrentConflict  string `json:"registrationNotCurrentConflict"`
		ActiveCannotReportRevokedString string `json:"activeCannotReportRevokedConflict"`
		SourceSandboxConflict           string `json:"sourceSandboxConflict"`
		SourceRevisionConflict          string `json:"sourceRevisionConflict"`
		Registration                    struct {
			BaseFields               []string `json:"baseFields"`
			ObservedFields           []string `json:"observedFields"`
			FailedExtraFields        []string `json:"failedExtraFields"`
			DesiredStates            []string `json:"desiredStates"`
			ObservedStatuses         []string `json:"observedStatuses"`
			PositiveFields           []string `json:"positiveFields"`
			ReceiptDigestPattern     string   `json:"receiptDigestPattern"`
			SafeIdentifierPattern    string   `json:"safeIdentifierPattern"`
			SafeCodePattern          string   `json:"safeCodePattern"`
			SessionIdentifierPattern string   `json:"sessionIdentifierPattern"`
			NativeProjectPattern     string   `json:"nativeProjectPattern"`
			IdentityFields           []string `json:"identityFields"`
			BindingFields            []string `json:"bindingFields"`
		} `json:"registration"`
		ContinuitySource struct {
			Note             string   `json:"note"`
			Fields           []string `json:"fields"`
			PositiveFields   []string `json:"positiveFields"`
			Roles            []string `json:"roles"`
			Availabilities   []string `json:"availabilities"`
			FreshnessSeconds int      `json:"freshnessSeconds"`
			StaleReason      string   `json:"staleReason"`
		} `json:"continuitySource"`
	}
	receiptDigest     *regexp.Regexp
	safeIdentifier    *regexp.Regexp
	safeCode          *regexp.Regexp
	sessionIdentifier *regexp.Regexp
	nativeProject     *regexp.Regexp
}

// frozenBackendV21RegistrationRow is one durable backend registration row the
// frozen apply step decides against. Current reports the work/binding/source
// currency the backend derives; Availability is the derived wire availability.
type frozenBackendV21RegistrationRow struct {
	State             string
	DesiredState      string
	ContinuityEnabled bool
	ScopeRevision     float64
	ServiceGeneration int64
	ReceiptDigest     string
	ErrorCode         string
	Current           bool
	Availability      string
	Identity          map[string]any
	Binding           map[string]any
}

type frozenBackendV21Error struct {
	Status  int
	Code    string
	Message string
}

type frozenBackendV21Verdict struct {
	Accepted bool
	Error    *frozenBackendV21Error
}

func loadFrozenBackendV21(t *testing.T) *frozenBackendV21 {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "api", "testdata", "agent-runtime-report-backend-v21.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &frozenBackendV21{}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&backend.fixture); err != nil {
		t.Fatal(err)
	}
	if backend.fixture.FormatVersion != 1 || backend.fixture.InvalidReport.Status != 400 ||
		backend.fixture.ReportConflict.Status != 409 {
		t.Fatalf("frozen backend fixture identity drifted: %#v", backend.fixture)
	}
	backend.receiptDigest = regexp.MustCompile(backend.fixture.Registration.ReceiptDigestPattern)
	backend.safeIdentifier = regexp.MustCompile(backend.fixture.Registration.SafeIdentifierPattern)
	backend.safeCode = regexp.MustCompile(backend.fixture.Registration.SafeCodePattern)
	backend.sessionIdentifier = regexp.MustCompile(backend.fixture.Registration.SessionIdentifierPattern)
	backend.nativeProject = regexp.MustCompile(backend.fixture.Registration.NativeProjectPattern)
	return backend
}

func (backend *frozenBackendV21) invalid() frozenBackendV21Verdict {
	return frozenBackendV21Verdict{Error: &frozenBackendV21Error{
		Status: backend.fixture.InvalidReport.Status, Code: backend.fixture.InvalidReport.Code,
		Message: backend.fixture.InvalidReport.Message,
	}}
}

func (backend *frozenBackendV21) conflict(message string) frozenBackendV21Verdict {
	return frozenBackendV21Verdict{Error: &frozenBackendV21Error{
		Status: backend.fixture.ReportConflict.Status, Code: backend.fixture.ReportConflict.Code,
		Message: message,
	}}
}

func frozenClosedFields(value map[string]any, fields []string) bool {
	if len(value) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := value[field]; !ok {
			return false
		}
	}
	return true
}

func frozenNumberOne(value any) bool {
	number, ok := value.(float64)
	return ok && number == 1
}

func frozenPositiveNumber(value any) bool {
	number, ok := value.(float64)
	return ok && number >= 1 && number == math.Trunc(number)
}

func frozenContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (backend *frozenBackendV21) validateRegistrationIdentity(raw any) bool {
	identity, ok := raw.(map[string]any)
	if !ok || !frozenClosedFields(identity, backend.fixture.Registration.IdentityFields) {
		return false
	}
	for _, field := range []string{"workId", "projectId", "sandboxId", "workspaceEpoch"} {
		value, ok := identity[field].(string)
		if !ok || !backend.safeIdentifier.MatchString(value) {
			return false
		}
	}
	if !frozenPositiveNumber(identity["sandboxGeneration"]) || !frozenPositiveNumber(identity["expectedRevision"]) {
		return false
	}
	taskID, taskAttempt := identity["taskId"], identity["taskAttempt"]
	if (taskID == nil) != (taskAttempt == nil) {
		return false
	}
	if taskID != nil {
		value, ok := taskID.(string)
		if !ok || !backend.safeIdentifier.MatchString(value) || !frozenPositiveNumber(taskAttempt) {
			return false
		}
	}
	return true
}

func (backend *frozenBackendV21) validateRegistrationBinding(raw any) bool {
	binding, ok := raw.(map[string]any)
	if !ok || !frozenClosedFields(binding, backend.fixture.Registration.BindingFields) {
		return false
	}
	for _, field := range []string{"bindingId", "registeredSourceId", "serviceRegistrationId"} {
		value, ok := binding[field].(string)
		if !ok || !backend.safeIdentifier.MatchString(value) {
			return false
		}
	}
	session, ok := binding["nativeSessionId"].(string)
	if !ok || !backend.sessionIdentifier.MatchString(session) {
		return false
	}
	nativeProject, ok := binding["nativeProjectId"].(string)
	if !ok || !backend.nativeProject.MatchString(nativeProject) {
		return false
	}
	digest, ok := binding["nativeLocationDigest"].(string)
	if !ok || !backend.receiptDigest.MatchString(digest) {
		return false
	}
	return frozenPositiveNumber(binding["bindingRevision"])
}

// applyRegistrationReport runs the frozen validate_registration_reports then
// apply_registration_reports over the serialized report's registration array.
func (backend *frozenBackendV21) applyRegistrationReport(
	t *testing.T,
	reportJSON []byte,
	rows map[string]frozenBackendV21RegistrationRow,
) frozenBackendV21Verdict {
	t.Helper()
	items, verdict := backend.parseRegistrationReport(t, reportJSON)
	if verdict != nil {
		return *verdict
	}
	return backend.applyRegistrationItems(items, rows, func(row frozenBackendV21RegistrationRow) bool {
		return row.Current && row.Availability == "available"
	})
}

func (backend *frozenBackendV21) parseRegistrationReport(
	t *testing.T,
	reportJSON []byte,
) ([]map[string]any, *frozenBackendV21Verdict) {
	t.Helper()
	var document map[string]json.RawMessage
	if err := json.Unmarshal(reportJSON, &document); err != nil {
		t.Fatalf("report is not a JSON object: %v", err)
	}
	var rawItems []json.RawMessage
	if err := json.Unmarshal(document["continuityRegistrations"], &rawItems); err != nil {
		verdict := backend.invalid()
		return nil, &verdict
	}
	items := make([]map[string]any, 0, len(rawItems))
	seen := map[string]bool{}
	for _, raw := range rawItems {
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			verdict := backend.invalid()
			return nil, &verdict
		}
		status, ok := item["observedStatus"].(string)
		if !ok {
			verdict := backend.invalid()
			return nil, &verdict
		}
		fields := append(append([]string{}, backend.fixture.Registration.BaseFields...), backend.fixture.Registration.ObservedFields...)
		if status == "failed" {
			fields = append(fields, backend.fixture.Registration.FailedExtraFields...)
		}
		if !frozenClosedFields(item, fields) || !frozenNumberOne(item["formatVersion"]) {
			verdict := backend.invalid()
			return nil, &verdict
		}
		desired, ok := item["desiredState"].(string)
		if !ok || !frozenContains(backend.fixture.Registration.DesiredStates, desired) {
			verdict := backend.invalid()
			return nil, &verdict
		}
		if _, ok := item["continuityEnabled"].(bool); !ok {
			verdict := backend.invalid()
			return nil, &verdict
		}
		if !frozenPositiveNumber(item["scopeRevision"]) || !frozenPositiveNumber(item["serviceGeneration"]) {
			verdict := backend.invalid()
			return nil, &verdict
		}
		digest, ok := item["receiptDigest"].(string)
		if !ok || !backend.receiptDigest.MatchString(digest) {
			verdict := backend.invalid()
			return nil, &verdict
		}
		if !frozenContains(backend.fixture.Registration.ObservedStatuses, status) {
			verdict := backend.invalid()
			return nil, &verdict
		}
		if status == "failed" {
			lastError, ok := item["lastError"].(map[string]any)
			if !ok || !frozenClosedFields(lastError, []string{"code"}) {
				verdict := backend.invalid()
				return nil, &verdict
			}
			code, ok := lastError["code"].(string)
			if !ok || !backend.safeCode.MatchString(code) {
				verdict := backend.invalid()
				return nil, &verdict
			}
		}
		if !backend.validateRegistrationIdentity(item["identity"]) || !backend.validateRegistrationBinding(item["binding"]) {
			verdict := backend.invalid()
			return nil, &verdict
		}
		binding := item["binding"].(map[string]any)
		key := binding["bindingId"].(string) + "#" +
			strconv.FormatInt(int64(binding["bindingRevision"].(float64)), 10)
		if seen[key] {
			verdict := backend.invalid()
			return nil, &verdict
		}
		seen[key] = true
		items = append(items, item)
	}
	return items, nil
}

func (backend *frozenBackendV21) applyRegistrationItems(
	items []map[string]any,
	rows map[string]frozenBackendV21RegistrationRow,
	admissible func(frozenBackendV21RegistrationRow) bool,
) frozenBackendV21Verdict {
	for _, item := range items {
		binding := item["binding"].(map[string]any)
		key := binding["bindingId"].(string) + "#" +
			strconv.FormatInt(int64(binding["bindingRevision"].(float64)), 10)
		row, ok := rows[key]
		if !ok || row.DesiredState != item["desiredState"].(string) ||
			row.ContinuityEnabled != item["continuityEnabled"].(bool) ||
			row.ScopeRevision != item["scopeRevision"].(float64) ||
			!reflect.DeepEqual(row.Identity, item["identity"]) || !reflect.DeepEqual(row.Binding, item["binding"]) {
			return backend.conflict(backend.fixture.ReportConflict.Message)
		}
		status := item["observedStatus"].(string)
		expected := map[string]string{"verified": "verified", "revoked": "revoked", "failed": "failed"}[status]
		errorCode := ""
		if lastError, ok := item["lastError"].(map[string]any); ok {
			errorCode = lastError["code"].(string)
		}
		if row.State != "pending" {
			if row.State == expected && row.ReceiptDigest == item["receiptDigest"].(string) &&
				row.ServiceGeneration == int64(item["serviceGeneration"].(float64)) && row.ErrorCode == errorCode {
				continue
			}
			// A verified row may only refresh with another verified report for a
			// current, admissible tuple; every other terminal change conflicts.
			if row.State == "verified" && expected == "verified" && row.Current {
				continue
			}
			return backend.conflict(backend.fixture.TerminalReceiptConflict)
		}
		if status == "verified" && (!row.Current || row.DesiredState != "active" ||
			!row.ContinuityEnabled || !admissible(row)) {
			return backend.conflict(backend.fixture.RegistrationNotCurrentConflict)
		}
		if status == "revoked" && row.DesiredState != "revoked" {
			return backend.conflict(backend.fixture.ActiveCannotReportRevokedString)
		}
	}
	return frozenBackendV21Verdict{Accepted: true}
}

// frozenBackendV21SourceRow is one durable backend continuity-source row. The
// wire availability is derived from it exactly like _wire_source: an
// observation older than the freshness contract or one carrying a node-token
// hash from before the current authenticated context is published unavailable
// with the stale reason, regardless of the row's declared availability.
type frozenBackendV21SourceRow struct {
	Availability        string
	Reason              string
	LastObservedAt      time.Time
	NodeTokenHash       string
	ServiceGeneration   int64
	ScopeRevision       int64
	ProfileRevision     int64
	InstructionRevision int64
}

func frozenSourceKey(sandboxID, registeredSourceID string) string {
	return sandboxID + "|" + registeredSourceID
}

func frozenParseTimestamp(value any) (time.Time, bool) {
	text, ok := value.(string)
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || parsed.Location() == time.Local {
		return time.Time{}, false
	}
	return parsed, true
}

func (backend *frozenBackendV21) validateSourceItem(item map[string]any) bool {
	if !frozenClosedFields(item, backend.fixture.ContinuitySource.Fields) || !frozenNumberOne(item["formatVersion"]) {
		return false
	}
	for _, field := range []string{"registeredSourceId", "serviceRegistrationId", "projectId", "sandboxId", "workspaceEpoch"} {
		value, ok := item[field].(string)
		if !ok || !backend.safeIdentifier.MatchString(value) {
			return false
		}
	}
	session, ok := item["nativeSessionId"].(string)
	if !ok || !backend.sessionIdentifier.MatchString(session) {
		return false
	}
	nativeProject, ok := item["nativeProjectId"].(string)
	if !ok || !backend.nativeProject.MatchString(nativeProject) {
		return false
	}
	digest, ok := item["nativeLocationDigest"].(string)
	if !ok || !backend.receiptDigest.MatchString(digest) {
		return false
	}
	for _, field := range backend.fixture.ContinuitySource.PositiveFields {
		if !frozenPositiveNumber(item[field]) {
			return false
		}
	}
	role, ok := item["role"].(string)
	if !ok || !frozenContains(backend.fixture.ContinuitySource.Roles, role) {
		return false
	}
	availability, ok := item["availability"].(string)
	if !ok || !frozenContains(backend.fixture.ContinuitySource.Availabilities, availability) {
		return false
	}
	reason := item["reason"]
	if availability == "unavailable" {
		code, ok := reason.(string)
		if !ok || !backend.safeCode.MatchString(code) {
			return false
		}
	} else if reason != nil {
		return false
	}
	if _, ok := frozenParseTimestamp(item["lastObservedAt"]); !ok {
		return false
	}
	return true
}

// applyReport runs the frozen report pipeline in the backend's exact order:
// validate_source_reports, apply_sources (which commits freshness and the
// current authenticated node-token hash), then validate_registration_reports
// and apply_registration_reports against the updated source rows.
func (backend *frozenBackendV21) applyReport(
	t *testing.T,
	reportJSON []byte,
	registrations map[string]frozenBackendV21RegistrationRow,
	sources map[string]frozenBackendV21SourceRow,
	at time.Time,
	currentTokenHash string,
) (frozenBackendV21Verdict, map[string]frozenBackendV21SourceRow) {
	t.Helper()
	var document map[string]json.RawMessage
	if err := json.Unmarshal(reportJSON, &document); err != nil {
		t.Fatalf("report is not a JSON object: %v", err)
	}
	var rawSources []json.RawMessage
	if err := json.Unmarshal(document["continuitySources"], &rawSources); err != nil {
		return backend.invalid(), sources
	}
	items := make([]map[string]any, 0, len(rawSources))
	seen := map[string]bool{}
	for _, raw := range rawSources {
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			return backend.invalid(), sources
		}
		if !backend.validateSourceItem(item) {
			t.Logf("frozen backend v21 rejected source item: %s", raw)
			return backend.invalid(), sources
		}
		key := frozenSourceKey(item["sandboxId"].(string), item["registeredSourceId"].(string))
		if seen[key] {
			return backend.invalid(), sources
		}
		seen[key] = true
		items = append(items, item)
	}
	updated := make(map[string]frozenBackendV21SourceRow, len(sources))
	for key, row := range sources {
		updated[key] = row
	}
	for _, item := range items {
		key := frozenSourceKey(item["sandboxId"].(string), item["registeredSourceId"].(string))
		row, ok := updated[key]
		if !ok {
			return backend.conflict(backend.fixture.SourceSandboxConflict), sources
		}
		observedAt, _ := frozenParseTimestamp(item["lastObservedAt"])
		if int64(item["serviceGeneration"].(float64)) < row.ServiceGeneration ||
			int64(item["scopeRevision"].(float64)) < row.ScopeRevision ||
			int64(item["profileRevision"].(float64)) < row.ProfileRevision ||
			int64(item["instructionRevision"].(float64)) < row.InstructionRevision ||
			observedAt.Before(row.LastObservedAt) {
			return backend.conflict(backend.fixture.SourceRevisionConflict), sources
		}
		row.Availability = item["availability"].(string)
		row.Reason = ""
		if reason, ok := item["reason"].(string); ok {
			row.Reason = reason
		}
		row.LastObservedAt = observedAt
		row.NodeTokenHash = currentTokenHash
		row.ServiceGeneration = int64(item["serviceGeneration"].(float64))
		row.ScopeRevision = int64(item["scopeRevision"].(float64))
		row.ProfileRevision = int64(item["profileRevision"].(float64))
		row.InstructionRevision = int64(item["instructionRevision"].(float64))
		updated[key] = row
	}
	registrationItems, verdict := backend.parseRegistrationReport(t, reportJSON)
	if verdict != nil {
		return *verdict, updated
	}
	applied := backend.applyRegistrationItems(registrationItems, registrations, func(row frozenBackendV21RegistrationRow) bool {
		sourceRow, ok := updated[frozenSourceKey(row.Identity["sandboxId"].(string), row.Binding["registeredSourceId"].(string))]
		if !ok {
			return false
		}
		fresh := !sourceRow.LastObservedAt.Before(
			at.Add(-time.Duration(backend.fixture.ContinuitySource.FreshnessSeconds)*time.Second)) &&
			sourceRow.NodeTokenHash == currentTokenHash
		if !fresh {
			return false
		}
		return sourceRow.Availability == "available"
	})
	return applied, updated
}
