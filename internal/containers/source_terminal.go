package containers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func (p Podman) SourceTerminalBeforeCancel(ctx context.Context, preparation string) error {
	if p.SourceTerminal == nil {
		return nil
	}
	return p.SourceTerminal.ForPreparation(ctx, preparation, true)
}
func (p Podman) SourceTerminalComplete(ctx context.Context, preparation string) error {
	if p.SourceTerminal == nil {
		return nil
	}
	return p.SourceTerminal.ForPreparation(ctx, preparation, false)
}

// Read-only observation through the EXISTING installed Supervisor/launcher and
// native GETs. All selectors are obtained from SAME admitted operation + Store,
// never a grant's registeredProcess PID or an arbitrary caller URL/file/command.
func (p Podman) ReadSourceNativeTerminal(ctx context.Context, o state.PhysicalOperation) (physicalgate.SourceNativeTerminal, error) {
	var empty physicalgate.SourceNativeTerminal
	if p.PhysicalStore == nil || p.PhysicalProcesses == nil || o.Permit.Offline == nil || p.verifyQualificationMounts(ctx, o.Permit.Caller.SandboxID) != nil {
		return empty, physicalgate.ErrPrerequisite
	}
	current, err := p.PhysicalStore.PhysicalOperation(ctx, o.OperationID)
	if err != nil || current == nil || !reflect.DeepEqual(current, &o) || o.Phase != "unknown" {
		return empty, physicalgate.ErrPrerequisite
	}
	if _, _, err = p.PhysicalProcesses.RegistrationOriginal(ctx, o.Permit.Caller); err != nil {
		return empty, err
	}
	basis, err := p.sourceTerminalInputBasis(ctx, o)
	if err != nil {
		return empty, err
	}
	raw, _ := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": o.Permit.Caller.SandboxID, "instance": o.Permit.Caller.NativeInstance, "profileId": "opencode", "nativeSessionId": o.Permit.Offline.Slot.SessionID, "nativeInputId": o.Permit.Offline.Slot.InputID, "oracle": o.Permit.Offline.Slot.Oracle})
	output, _, err := p.ExecManagedSupervisor(ctx, o.Permit.Caller.SandboxID, ManagedSupervisorSourceTerminalCapture, raw)
	if err != nil {
		return empty, err
	}
	var receipt struct {
		SchemaVersion int               `json:"schemaVersion"`
		Command       string            `json:"command"`
		Status        string            `json:"status"`
		Originals     map[string]string `json:"originals"`
	}
	count := 4
	if o.Permit.Offline.Slot.Oracle == "tool_cancel" {
		count = 5
	}
	if model.DecodePhysicalClosed(output, &receipt) != nil || receipt.SchemaVersion != 1 || receipt.Command != string(ManagedSupervisorSourceTerminalCapture) || receipt.Status != "observed" || len(receipt.Originals) != count {
		return empty, physicalgate.ErrPrerequisite
	}
	result := physicalgate.SourceNativeTerminal{Basis: basis}
	originals := map[string]*[]byte{"log": &result.Log, "guard": &result.Guard, "active": &result.Active, "inbox": &result.Inbox}
	if count == 5 {
		originals["tool"] = &result.ToolOriginals
	}
	for name, target := range originals {
		encoded, ok := receipt.Originals[name]
		if !ok {
			return empty, physicalgate.ErrPrerequisite
		}
		original, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(original) == 0 || len(original) > 65536 || base64.StdEncoding.EncodeToString(original) != encoded {
			return empty, physicalgate.ErrPrerequisite
		}
		*target = original
		digest := model.RawPhysicalDigest(original)
		if err = p.PhysicalStore.RetainPhysicalFact(ctx, "source_original_"+digest[7:], original); err != nil {
			return empty, err
		}
	}
	if p.verifyQualificationMounts(ctx, o.Permit.Caller.SandboxID) != nil {
		return empty, physicalgate.ErrPrerequisite
	}
	if _, _, err = p.PhysicalProcesses.RegistrationOriginal(ctx, o.Permit.Caller); err != nil {
		return empty, err
	}
	return result, nil
}

func (p Podman) sourceTerminalInputBasis(ctx context.Context, o state.PhysicalOperation) (physicalgate.SourceInputBasis, error) {
	var basis physicalgate.SourceInputBasis
	a := o.Permit.Offline.Slot
	if o.Permit.Request.Consumer == "product" {
		preparation, err := p.PhysicalStore.CellV3Operation(ctx, a.PreparationID)
		if err != nil || preparation == nil || preparation.Receipt.ValidateFor(preparation.Entry) != nil {
			return basis, physicalgate.ErrPrerequisite
		}
		execution, err := p.PhysicalStore.CellV3Execution(ctx, a.PreparationID)
		entry := preparation.Entry
		if err != nil || execution == nil || entry.ValidateExecutionAuthority(preparation.Receipt) != nil || entry.SandboxID != o.Permit.Caller.SandboxID || entry.SandboxGeneration != o.Permit.Caller.SandboxGeneration || entry.Instance != o.Permit.Caller.NativeInstance || entry.NativeSessionID != a.SessionID || execution.Grant.InputID != a.InputID || execution.Grant != *entry.ExecutionGrant || preparation.Receipt.PreparedReceiptDigest != a.PreparedReceiptDigest {
			return basis, physicalgate.ErrPrerequisite
		}
		basis.InputDigest = entry.Instructions.InstructionDigest
		basis.Admission, _ = json.Marshal(map[string]any{"formatVersion": 3, "targetKind": "cell_session", "preparedReceipt": preparation.Receipt, "grant": execution.Grant})
	} else if o.Permit.Request.Consumer == "parent" {
		raw, err := p.PhysicalStore.ControllerActivityStage(ctx, a.PreparationID, state.ControllerActivated)
		var activation qualification.ControllerActivation
		if err != nil || model.DecodePhysicalClosed(raw, &activation) != nil {
			return basis, physicalgate.ErrPrerequisite
		}
		receipt := activation.Admission.PreparedReceipt
		tuple := receipt.PreparedTuple
		if receipt.Validate() != nil || receipt.PreparationID != a.PreparationID || receipt.PreparedReceiptDigest != a.PreparedReceiptDigest || tuple.Owner.SandboxID != o.Permit.Caller.SandboxID || tuple.Owner.SandboxGeneration != o.Permit.Caller.SandboxGeneration || tuple.NativeRegistration.NativeSessionID != a.SessionID || tuple.InputID != a.InputID {
			return basis, physicalgate.ErrPrerequisite
		}
		basis.InputDigest = tuple.InputDigest
		basis.Admission, _ = json.Marshal(activation.Admission)
	} else {
		return basis, physicalgate.ErrPrerequisite
	}
	if model.WorkspaceDigest(json.RawMessage(basis.Admission)) != a.AdmissionDigest {
		return physicalgate.SourceInputBasis{}, physicalgate.ErrPrerequisite
	}
	return basis, nil
}
