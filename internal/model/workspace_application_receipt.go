package model

import (
	"encoding/base64"
	"errors"
	"reflect"
	"time"
	"unicode/utf8"
)

type AppliedControllerRole struct {
	Binding            ApplicationRoleTarget       `json:"binding"`
	NativeRegistration ManagedNativeRegistrationV1 `json:"nativeRegistration"`
	NativeRoleReadback ControllerRoleReadback      `json:"nativeRoleReadback"`
}
type WorkspaceApplicationReadback struct {
	Operation              WorkspaceApplicationOperation `json:"operation"`
	AppliedRuntimeRevision int64                         `json:"appliedRuntimeRevision"`
	SetupReceipts          []ApplicationSetupReceipt     `json:"setupReceipts"`
	Profiles               []AppliedExpertiseProfile     `json:"profiles"`
	RoleBindings           []AppliedControllerRole       `json:"roleBindings"`
	Limits                 WorkspaceApplicationLimits    `json:"limits"`
	MaterializerDigest     string                        `json:"materializerDigest"`
	DependencyDigest       string                        `json:"dependencyDigest"`
}
type WorkspaceApplicationNativeReceipt struct {
	FormatVersion         int                          `json:"formatVersion"`
	OperationID           string                       `json:"operationId"`
	OperationDigest       string                       `json:"operationDigest"`
	ServiceRegistrationID string                       `json:"serviceRegistrationId"`
	ServiceGeneration     int64                        `json:"serviceGeneration"`
	NativeSessionID       string                       `json:"nativeSessionId"`
	NativeProjectID       string                       `json:"nativeProjectId"`
	NativeLocationDigest  string                       `json:"nativeLocationDigest"`
	Role                  string                       `json:"role"`
	RootAttestation       string                       `json:"rootAttestation"`
	ObservedAt            string                       `json:"observedAt"`
	Readback              WorkspaceApplicationReadback `json:"readback"`
}
type WorkspaceApplicationPayload struct {
	FormatVersion               int                               `json:"formatVersion"`
	Purpose                     string                            `json:"purpose"`
	RequestID                   string                            `json:"requestId"`
	TaskID                      string                            `json:"taskId"`
	NodeTokenHash               string                            `json:"nodeTokenHash"`
	BridgeVersion               string                            `json:"bridgeVersion"`
	IssuedAt                    string                            `json:"issuedAt"`
	NotAfter                    string                            `json:"notAfter"`
	ManagedServiceReceiptDigest string                            `json:"managedServiceReceiptDigest"`
	NativeReceipt               WorkspaceApplicationNativeReceipt `json:"nativeReceipt"`
	OperationID                 string                            `json:"operationId"`
	OperationDigest             string                            `json:"operationDigest"`
}
type WorkspaceApplicationEnvelope struct {
	Payload   WorkspaceApplicationPayload `json:"payload"`
	KeyID     string                      `json:"keyId"`
	Signature string                      `json:"signature"`
}

func (envelope *WorkspaceApplicationEnvelope) UnmarshalJSON(raw []byte) error {
	if !utf8.Valid(raw) || len(raw) > 2*1024*1024 {
		return errors.New("invalid application envelope bytes")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	type wire WorkspaceApplicationEnvelope
	var value wire
	if err := decodeStrictCellJSON(raw, &value); err != nil {
		return err
	}
	if err := requiredApplicationFields(raw, reflect.TypeOf(value)); err != nil {
		return err
	}
	result := WorkspaceApplicationEnvelope(value)
	if err := result.Validate(); err != nil {
		return err
	}
	*envelope = result
	return nil
}

func (readback WorkspaceApplicationReadback) validatePins() error {
	op := readback.Operation
	if err := op.Validate(); err != nil {
		return err
	}
	if readback.AppliedRuntimeRevision != op.TargetRuntimeRevision || !reflect.DeepEqual(readback.SetupReceipts, op.Dependencies.SetupReceipts) || !reflect.DeepEqual(readback.Profiles, op.Dependencies.Profiles) || !reflect.DeepEqual(readback.Limits, op.Limits) || readback.MaterializerDigest != op.MaterializerDigest || readback.DependencyDigest != op.DependencyDigest || len(readback.RoleBindings) != 2 {
		return errors.New("application full readback conflict")
	}
	for i, role := range readback.RoleBindings {
		dependency := op.Dependencies.Roles[i]
		n, r := role.NativeRegistration, role.NativeRoleReadback
		if role.Binding != op.RoleBindings[i] || !cellV3SafeIDPattern.MatchString(n.RegisteredSourceID) || n.WorkspaceEpoch != dependency.Workspace.WorkspaceEpoch || !cellNativeSessionIDPattern.MatchString(n.NativeSessionID) || !cellNativeProjectPattern.MatchString(n.NativeProjectID) || !setupDigestPattern.MatchString(n.NativeLocationDigest) || r.Role != role.Binding.Role || r.NativeAgentID != dependency.Projection.NativeAgentID || r.SessionAgentID != r.NativeAgentID || r.ParentSessionID != nil || r.RoleAgentDigest != WorkspaceDigest(dependency.Projection) {
			return errors.New("application role/native dependency conflict")
		}
	}
	if readback.RoleBindings[0].NativeRegistration.NativeSessionID == readback.RoleBindings[1].NativeRegistration.NativeSessionID {
		return errors.New("application parents borrowed session")
	}
	return nil
}

func (readback WorkspaceApplicationReadback) Validate(parents []ControllerParentIntent, reports []ControllerParentReport) error {
	op := readback.Operation
	if err := readback.validatePins(); err != nil {
		return err
	}
	if len(parents) != 2 || len(reports) != 2 {
		return errors.New("application incomplete parent witnesses")
	}
	for i, role := range readback.RoleBindings {
		if role.Binding != op.RoleBindings[i] {
			return errors.New("application role dependency conflict")
		}
		var parent *ControllerParentIntent
		var report *ControllerParentReport
		for j := range parents {
			if parents[j].ServiceRegistrationID == role.Binding.ServiceRegistrationID {
				if parent != nil {
					return errors.New("duplicate application parent")
				}
				parent = &parents[j]
			}
		}
		for j := range reports {
			if reports[j].ServiceRegistrationID == role.Binding.ServiceRegistrationID {
				if report != nil {
					return errors.New("duplicate application report")
				}
				report = &reports[j]
			}
		}
		if parent == nil || report == nil {
			return errors.New("application role not separately observed")
		}
		if _, err := op.ParentDependency(*parent); err != nil {
			return err
		}
		if err := report.ValidateReady(*parent); err != nil {
			return err
		}
		if !reflect.DeepEqual(role.NativeRegistration, *report.NativeRegistration) || !reflect.DeepEqual(role.NativeRoleReadback, *report.NativeRoleReadback) {
			return errors.New("application nested native readback conflict")
		}
	}
	return nil
}
func (payload WorkspaceApplicationPayload) Validate() error {
	op := payload.NativeReceipt.Readback.Operation
	n := payload.NativeReceipt
	if err := n.Readback.validatePins(); err != nil {
		return err
	}
	issued, e1 := time.Parse(time.RFC3339Nano, payload.IssuedAt)
	expiry, e2 := time.Parse(time.RFC3339Nano, payload.NotAfter)
	observed, e3 := time.Parse(time.RFC3339Nano, n.ObservedAt)
	opExpiry, e4 := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !expiry.After(issued) || expiry.Sub(issued) > 300*time.Second || expiry.After(opExpiry) || observed.Before(issued) || observed.After(expiry) || payload.FormatVersion != 1 || payload.Purpose != "workspace_workflow_application" || payload.BridgeVersion != "workspace-workflow-bridge-v1" || !cellV3SafeIDPattern.MatchString(payload.RequestID) || payload.TaskID != op.TaskID || payload.NodeTokenHash != op.Producer.NodeTokenHash || payload.OperationID != op.OperationID || payload.OperationDigest != op.OperationDigest || !setupDigestPattern.MatchString(payload.ManagedServiceReceiptDigest) || n.FormatVersion != 1 || n.OperationID != op.OperationID || n.OperationDigest != op.OperationDigest || n.Role != "manager" {
		return errors.New("application typed payload conflict")
	}
	if len(n.Readback.RoleBindings) != 2 {
		return errors.New("application payload incomplete roles")
	}
	manager := n.Readback.RoleBindings[0]
	if manager.Binding.Role != "manager" || n.ServiceRegistrationID != manager.Binding.ServiceRegistrationID || n.ServiceGeneration != manager.Binding.ServiceGeneration || n.NativeSessionID != manager.NativeRegistration.NativeSessionID || n.NativeProjectID != manager.NativeRegistration.NativeProjectID || n.NativeLocationDigest != manager.NativeRegistration.NativeLocationDigest || n.RootAttestation != op.Dependencies.Roles[0].Workspace.RootAttestation {
		return errors.New("application manager anchor conflict")
	}
	return nil
}
func (envelope WorkspaceApplicationEnvelope) Validate() error {
	if err := envelope.Payload.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(sig) < 64 || len(sig) > 80 || base64.StdEncoding.EncodeToString(sig) != envelope.Signature || envelope.KeyID != envelope.Payload.NativeReceipt.Readback.Operation.Producer.KeyID {
		return errors.New("application envelope key/signature conflict")
	}
	return nil
}
