package model

// F1 revision12 ONE producer SHA4f9776e4…, actual F2 wrapper SHA7bbf709e….
// Native transport facts and normalized lineage never grant executable authority.
import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type ControllerPlanReference struct {
	Path         string `json:"path"`
	SourceDigest string `json:"sourceDigest"`
	Status       string `json:"status"`
}
type ControllerPlan struct {
	WorkID        string                  `json:"workId"`
	WorkRevision  int64                   `json:"workRevision"`
	ContentDigest string                  `json:"contentDigest"`
	PlanRef       ControllerPlanReference `json:"planRef"`
}
type ControllerWorkflowTarget struct {
	Kind       string           `json:"kind"`
	Role       string           `json:"role"`
	ResourceID *string          `json:"resourceId"`
	Advice     *json.RawMessage `json:"advice"`
	wire       json.RawMessage
}
type ControllerApprovedInputContext struct {
	IdentityAssociationDigest string                   `json:"identityAssociationDigest,omitempty"`
	ProviderPolicyDigest      string                   `json:"providerPolicyDigest,omitempty"`
	FormatVersion             int                      `json:"formatVersion"`
	ContextID                 string                   `json:"contextId"`
	ContextDigest             string                   `json:"contextDigest"`
	PreparationID             string                   `json:"preparationId"`
	CaseID                    string                   `json:"caseId"`
	CaseManifestDigest        string                   `json:"caseManifestDigest"`
	PolicyDigest              string                   `json:"policyDigest"`
	InputID                   string                   `json:"inputId"`
	InputDigest               string                   `json:"inputDigest"`
	WorkflowRequestID         string                   `json:"workflowRequestId"`
	Plan                      ControllerPlan           `json:"plan"`
	Target                    ControllerWorkflowTarget `json:"target"`
	DemandManifestDigest      string                   `json:"demandManifestDigest,omitempty"`
	DeclarationItemDigest     string                   `json:"declarationItemDigest,omitempty"`
	AllocationID              string                   `json:"allocationId,omitempty"`
	PreparationOrdinal        int                      `json:"preparationOrdinal,omitempty"`
	PhysicalIndex             int                      `json:"physicalIndex,omitempty"`
}
type ControllerWorkflowProposal struct {
	Target ControllerWorkflowTarget `json:"target"`
	Body   json.RawMessage          `json:"body"`
}
type ControllerEventRef struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Created int64  `json:"created"`
	Durable struct {
		AggregateID string `json:"aggregateID"`
		Seq         int64  `json:"seq"`
		Version     int64  `json:"version"`
	} `json:"durable"`
}
type ControllerTextPart struct {
	Ordinal int64              `json:"ordinal"`
	Started ControllerEventRef `json:"started"`
	Ended   ControllerEventRef `json:"ended"`
}
type ControllerOutputEventRefs struct {
	Enqueued         ControllerEventRef   `json:"enqueued"`
	ExecutionStarted ControllerEventRef   `json:"executionStarted"`
	Delivered        ControllerEventRef   `json:"delivered"`
	StepStarted      []ControllerEventRef `json:"stepStarted"`
	StepEnded        ControllerEventRef   `json:"stepEnded"`
	Terminal         ControllerEventRef   `json:"executionSucceeded"`
	TextParts        []ControllerTextPart `json:"textParts"`
}
type ControllerOutputLineage struct {
	ControllerActivity   ControllerActivity `json:"controllerActivity"`
	InputText            string             `json:"inputText"`
	ExecutionTerminalSeq int64              `json:"executionTerminalSeq"`
	TerminalAt           string             `json:"terminalAt"`
	TerminalOutcome      string             `json:"terminalOutcome"`
	AssistantMessageID   string             `json:"assistantMessageId"`
	AssistantAgentID     string             `json:"assistantAgentId"`
	AssistantModel       struct {
		ProviderID string `json:"providerID"`
		ID         string `json:"id"`
	} `json:"assistantModel"`
	AssistantCompletedAt string                    `json:"assistantCompletedAt"`
	AssistantFinish      string                    `json:"assistantFinish"`
	OutputText           string                    `json:"outputText"`
	OutputByteCount      int                       `json:"outputByteCount"`
	OutputDigest         string                    `json:"outputDigest"`
	EventRefs            ControllerOutputEventRefs `json:"eventRefs"`
}
type ControllerOutputNativeReadback struct {
	Data struct {
		ControllerOutput ControllerNativeOutput `json:"controllerOutput"`
	} `json:"data"`
}
type ControllerOutputOperationRequest struct {
	FormatVersion int                        `json:"formatVersion"`
	RequestID     string                     `json:"requestId"`
	ContextID     string                     `json:"contextId"`
	Lineage       ControllerOutputLineage    `json:"lineage"`
	Proposal      ControllerWorkflowProposal `json:"proposal"`
}
type ControllerOutputSubject struct {
	AccountID             string  `json:"account_id"`
	TaskID                string  `json:"task_id"`
	ServerID              string  `json:"server_id"`
	SandboxID             string  `json:"sandbox_id"`
	SandboxGeneration     int64   `json:"sandbox_generation"`
	CellID                string  `json:"cell_id"`
	Role                  string  `json:"role"`
	ControllerID          string  `json:"controller_id"`
	ControllerRevision    int64   `json:"controller_revision"`
	AuthorityRevision     int64   `json:"authority_revision"`
	ServiceRegistrationID string  `json:"service_registration_id"`
	ServiceGeneration     int64   `json:"service_generation"`
	NativeSessionID       string  `json:"native_session_id"`
	WorkID                *string `json:"work_id"`
	ExecutionID           *string `json:"execution_id"`
}
type ControllerOutputOperation struct {
	ApplicationRoleAgentDigest  string                         `json:"applicationRoleAgentDigest,omitempty"`
	ApplicationConfigDigest     string                         `json:"applicationConfigDigest,omitempty"`
	NativeRoleAgentDigest       string                         `json:"nativeRoleAgentDigest,omitempty"`
	NativeConfigDigest          string                         `json:"nativeConfigDigest,omitempty"`
	IdentityAssociationDigest   string                         `json:"identityAssociationDigest,omitempty"`
	ProviderPolicyDigest        string                         `json:"providerPolicyDigest,omitempty"`
	FormatVersion               int                            `json:"formatVersion"`
	Kind                        string                         `json:"kind"`
	OperationID                 string                         `json:"operationId"`
	OperationDigest             string                         `json:"operationDigest"`
	RequestID                   string                         `json:"requestId"`
	Context                     ControllerApprovedInputContext `json:"context"`
	RoleBindingID               string                         `json:"roleBindingId"`
	RoleBindingRevision         int64                          `json:"roleBindingRevision"`
	Subject                     ControllerOutputSubject        `json:"subject"`
	Workspace                   ManagedServiceWorkspaceV1      `json:"workspace"`
	RoleAgentDigest             string                         `json:"roleAgentDigest"`
	ConfigurationDigest         string                         `json:"configurationDigest"`
	ConfigDigest                string                         `json:"configDigest"`
	ManagedServiceReceiptDigest string                         `json:"managedServiceReceiptDigest"`
	Producer                    WorkspaceRegisteredProducer    `json:"producer"`
	Lineage                     ControllerOutputLineage        `json:"lineage"`
	Proposal                    ControllerWorkflowProposal     `json:"proposal"`
	ExpiresAt                   string                         `json:"expiresAt"`
}

// New paired versions carry both identities explicitly; legacy signed wires
// retain their original roleAgentDigest/configDigest fields unchanged.
func (o ControllerOutputOperation) MarshalJSON() ([]byte, error) {
	type wire ControllerOutputOperation
	raw, err := json.Marshal(wire(o))
	if err != nil || (o.FormatVersion != 3 && o.FormatVersion != 4) {
		return raw, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	delete(fields, "roleAgentDigest")
	delete(fields, "configDigest")
	return json.Marshal(fields)
}

type ControllerOutputReadback struct {
	FormatVersion         int                            `json:"formatVersion"`
	OperationID           string                         `json:"operationId"`
	OperationDigest       string                         `json:"operationDigest"`
	ServiceRegistrationID string                         `json:"serviceRegistrationId"`
	ServiceGeneration     int64                          `json:"serviceGeneration"`
	NativeSessionID       string                         `json:"nativeSessionId"`
	NativeProjectID       string                         `json:"nativeProjectId"`
	NativeLocationDigest  string                         `json:"nativeLocationDigest"`
	Role                  string                         `json:"role"`
	RootAttestation       string                         `json:"rootAttestation"`
	ObservedAt            string                         `json:"observedAt"`
	Lineage               ControllerOutputLineage        `json:"lineage"`
	NativeReadback        ControllerOutputNativeReadback `json:"nativeReadback"`
}
type ControllerOutputPayload struct {
	FormatVersion               int                      `json:"formatVersion"`
	Purpose                     string                   `json:"purpose"`
	RequestID                   string                   `json:"requestId"`
	TaskID                      string                   `json:"taskId"`
	NodeTokenHash               string                   `json:"nodeTokenHash"`
	BridgeVersion               string                   `json:"bridgeVersion"`
	IssuedAt                    string                   `json:"issuedAt"`
	NotAfter                    string                   `json:"notAfter"`
	ManagedServiceReceiptDigest string                   `json:"managedServiceReceiptDigest"`
	NativeReceipt               ControllerOutputReadback `json:"nativeReceipt"`
	OperationID                 string                   `json:"operationId"`
	OperationDigest             string                   `json:"operationDigest"`
}
type ControllerOutputEnvelope struct {
	Payload   ControllerOutputPayload `json:"payload"`
	KeyID     string                  `json:"keyId"`
	Signature string                  `json:"signature"`
}

func decodeControllerClosed(raw []byte, value any) error {
	if !utf8.Valid(raw) || len(raw) > 2*1024*1024 {
		return errors.New("invalid controller bytes")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	if err := decodeStrictCellJSON(raw, value); err != nil {
		return err
	}
	return requiredControllerFields(raw, reflect.TypeOf(value).Elem())
}

// Only the actual native Model.Ref variant is optional in this controller tree.
// Keep predecessor application/child required-field decoders unchanged.
func requiredControllerFields(raw json.RawMessage, typ reflect.Type) error {
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if string(raw) == "null" {
		if typ.Kind() == reflect.Pointer {
			return nil
		}
		return errors.New("null controller field")
	}
	if typ.Kind() == reflect.Pointer {
		return requiredControllerFields(raw, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.PkgPath != "" {
				continue
			}
			tag := strings.Split(f.Tag.Get("json"), ",")
			v, ok := fields[tag[0]]
			optional := len(tag) > 1 && tag[1] == "omitempty"
			if !ok {
				if optional {
					continue
				}
				return errors.New("missing controller field")
			}
			if optional && string(v) == "null" {
				return errors.New("null native variant")
			}
			if err := requiredControllerFields(v, f.Type); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		for _, v := range items {
			if err := requiredControllerFields(v, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
func (c *ControllerApprovedInputContext) UnmarshalJSON(raw []byte) error {
	type wire ControllerApprovedInputContext
	var w wire
	var version struct {
		FormatVersion int `json:"formatVersion"`
	}
	if err := json.Unmarshal(raw, &version); err != nil {
		return err
	}
	if version.FormatVersion == 2 || version.FormatVersion == 3 || version.FormatVersion == 4 {
		document, definition := workflowcontract.Budget, "approvedContext2"
		if version.FormatVersion == 3 {
			document, definition = workflowcontract.ControllerProvider, "approvedContext3"
		}
		if version.FormatVersion == 4 {
			document, definition = workflowcontract.ManagerSingle, "approvedContext4"
		}
		if err := workflowcontract.Validate(document, definition, raw); err != nil {
			return err
		}
		if err := decodeStrictCellJSON(raw, &w); err != nil {
			return err
		}
	} else if err := decodeControllerClosed(raw, &w); err != nil {
		return err
	}
	if version.FormatVersion == 1 {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		for _, key := range []string{"demandManifestDigest", "declarationItemDigest", "allocationId", "preparationOrdinal", "physicalIndex", "identityAssociationDigest", "providerPolicyDigest"} {
			if _, present := fields[key]; present {
				return errors.New("revision13 field in legacy context")
			}
		}
	}
	*c = ControllerApprovedInputContext(w)
	b, _ := json.Marshal(w)
	var m map[string]any
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	if d.Decode(&m) != nil {
		return errors.New("controller context bytes")
	}
	delete(m, "contextDigest")
	if (c.FormatVersion != 1 && c.FormatVersion != 2 && c.FormatVersion != 3 && c.FormatVersion != 4) || WorkspaceDigest(m) != c.ContextDigest || (c.FormatVersion == 1 && c.Target.Kind != "advice" && c.Target.Kind != "advice_decision") {
		return errors.New("controller context mismatch")
	}
	return nil
}
func (o *ControllerOutputOperation) UnmarshalJSON(raw []byte) error {
	type wire ControllerOutputOperation
	var w wire
	var version struct {
		FormatVersion int `json:"formatVersion"`
	}
	if err := json.Unmarshal(raw, &version); err != nil {
		return err
	}
	if version.FormatVersion == 1 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		for _, name := range []string{"applicationRoleAgentDigest", "applicationConfigDigest", "nativeRoleAgentDigest", "nativeConfigDigest", "identityAssociationDigest", "providerPolicyDigest"} {
			if _, present := fields[name]; present {
				return errors.New("paired identity in legacy controller output")
			}
		}
	}
	if version.FormatVersion == 2 || version.FormatVersion == 3 || version.FormatVersion == 4 {
		document, definition := workflowcontract.Budget, "controllerOutputOperation2"
		if version.FormatVersion == 3 {
			document, definition = workflowcontract.ControllerProvider, "controllerOutputOperation3"
		}
		if version.FormatVersion == 4 {
			document, definition = workflowcontract.ManagerSingle, "controllerOutputOperation4"
		}
		if err := workflowcontract.Validate(document, definition, raw); err != nil {
			return err
		}
		if err := decodeStrictCellJSON(raw, &w); err != nil {
			return err
		}
	} else if err := decodeControllerClosed(raw, &w); err != nil {
		return err
	}
	*o = ControllerOutputOperation(w)
	b, _ := json.Marshal(o)
	var m map[string]any
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	if d.Decode(&m) != nil {
		return errors.New("invalid controller operation")
	}
	delete(m, "operationDigest")
	if o.FormatVersion < 1 || o.FormatVersion > 4 || o.Context.FormatVersion != o.FormatVersion || o.Kind != "controller_output" || WorkspaceDigest(m) != o.OperationDigest {
		return errors.New("controller operation digest mismatch")
	}
	if o.FormatVersion >= 2 {
		proposal, err := ControllerProposal(o.Context, string(o.Proposal.Body))
		if err != nil || WorkspaceDigest(proposal) != WorkspaceDigest(o.Proposal) {
			return errors.New("revision13 operation proposal mismatch")
		}
	}
	return nil
}
func (r *ControllerOutputNativeReadback) UnmarshalJSON(raw []byte) error {
	type wire ControllerOutputNativeReadback
	var w wire
	if err := decodeControllerClosed(raw, &w); err != nil {
		return err
	}
	*r = ControllerOutputNativeReadback(w)
	return nil
}
