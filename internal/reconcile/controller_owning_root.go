package reconcile

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// ReadControllerParentOwningRoot supplies BOTH owning parent callsites. The
// selector is an already retained preparation, not joined.outputBody, an event
// constructor, a new session or a signer. The installed Supervisor reads its
// original protected DATA0..cursor and capture.Verify checks original references.
// This read neither prompts nor submits an output action.
func (r *Reconciler) ReadControllerParentOwningRoot(ctx context.Context, id, role string) (model.ControllerOutputNativeReadback, error) {
	var empty model.ControllerOutputNativeReadback
	if r.Store == nil || (role != "orchestrator" && role != "manager") {
		return empty, ErrControllerActivityPending
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	raw, err := r.Store.ControllerActivityStage(ctx, id, state.ControllerNativePrepared)
	var prepared model.ControllerPreparedEnvelope
	if err != nil || json.Unmarshal(raw, &prepared) != nil {
		return empty, ErrControllerActivityPending
	}
	raw, err = r.Store.ControllerActivityStage(ctx, id, state.ControllerApprovedContext)
	var retained controllerApprovedInput
	if err != nil || json.Unmarshal(raw, &retained) != nil || retained.Context.PreparationID != id || !exactControllerText(retained.InputText, prepared.Payload.PreparedTuple.InputDigest) {
		return empty, ErrControllerActivityPending
	}
	raw, err = r.Store.ControllerActivityStage(ctx, id, state.ControllerInstalledApplicability)
	var installed qualification.Applicability
	if err != nil || json.Unmarshal(raw, &installed) != nil {
		return empty, ErrControllerActivityPending
	}
	w, err := r.controllerActivityWitness(ctx, prepared.Payload.PreparedTuple.ServiceRegistrationID, installed)
	if err != nil {
		return empty, err
	}
	runtime, ok := r.ManagedRuntime.(controllerActivityRuntime)
	if !ok || w.Parent.Parent.Role != role {
		return empty, ErrControllerActivityPending
	}
	w.Policy, err = runtime.VerifyControllerPolicy(ctx, w.Sandbox, retained.Context.PolicyDigest, w.Installed)
	if err != nil {
		return empty, err
	}
	if w.Policy.ValidatePreparedReceipt(prepared.Payload) != nil || w.Policy.ValidateContext(retained.Context) != nil {
		return empty, ErrControllerActivityPending
	}
	w.Activation, err = runtime.ReadControllerActivation(ctx, w.Sandbox, w.Policy, prepared.Payload, true)
	if err != nil || w.Activation.ValidateContext(w.Policy, retained.Context) != nil {
		return empty, ErrControllerActivityPending
	}
	capture, err := r.readControllerOwningCapture(ctx, w, retained.InputText)
	if err != nil {
		return empty, err
	}
	return capture.NativeOutput, nil
}

func (r *Reconciler) readControllerOwningCapture(ctx context.Context, w qualification.ControllerOutputWitness, input string) (qualification.ControllerCapture, error) {
	var empty qualification.ControllerCapture
	var receipt struct {
		SchemaVersion int                                  `json:"schemaVersion"`
		Command       string                               `json:"command"`
		Status        string                               `json:"status"`
		NativeOutput  model.ControllerOutputNativeReadback `json:"nativeOutput"`
		NativeLog     []json.RawMessage                    `json:"nativeLog"`
	}
	err := r.controllerTransport(ctx, w.Parent.Parent, containers.ManagedSupervisorControllerOutput, map[string]any{"admission": w.Activation.Admission}, &receipt)
	if errors.Is(err, model.ErrControllerOutputRunningPending) {
		return empty, ErrControllerFirstTaskPending
	}
	terminalErr := r.sourceTerminalComplete(ctx, w.Activation.Admission.PreparedReceipt.PreparationID)
	if err != nil || terminalErr != nil {
		// A verified SOURCE deadline terminal never masquerades as a successful
		// parent output. Its independent completion may only release physical cap1.
		return empty, errors.Join(err, terminalErr)
	}
	if receipt.SchemaVersion != 1 || receipt.Command != "controller-output" || receipt.Status != "observed" {
		return empty, ErrControllerActivityPending
	}
	capture := qualification.ControllerCapture{NativeOutput: receipt.NativeOutput, NativeLog: receipt.NativeLog}
	identity, _ := json.Marshal(w.Policy.NativeIdentity())
	if _, err := capture.Verify(input, identity, w.Activation.Admission); err != nil {
		return empty, err
	}
	return capture, nil
}
