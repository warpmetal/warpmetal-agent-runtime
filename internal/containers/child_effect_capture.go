package containers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// Independent current workflow snapshot is supplied by the owning protected
// lifecycle consumer; op.Snapshot reflection is not an implementation of it.
// Missing installed/current suppliers deny via CurrentChildProductWitness.
func (p Podman) ObserveCellProductEffect(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, currentSnapshot json.RawMessage) (model.WorkflowObservationEnvelope, error) {
	var empty model.WorkflowObservationEnvelope
	if p.verifyQualificationMounts(ctx, box.ID) != nil {
		return empty, qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return empty, err
	}
	w, err := producer.CurrentChildProductWitness(ctx, entry, current, input)
	if err != nil {
		return empty, err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return empty, err
	}
	if op.ValidateFor(call, p.QualificationNodeTokenHash, current.DesiredRevision, time.Now()) != nil || !op.MatchesCurrentSnapshot(currentSnapshot) {
		return empty, qualification.ErrUntrusted
	}
	var snapshot struct {
		Join json.RawMessage `json:"childToolCaptureJoin"`
	}
	if json.Unmarshal(op.Snapshot, &snapshot) != nil {
		return empty, qualification.ErrUntrusted
	}
	raw, _ := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": box.ID, "instance": entry.Instance, "profileId": entry.Profile.ProfileID, "captureJoin": snapshot.Join})
	output, _, err := p.ExecManagedSupervisor(ctx, box.ID, ManagedSupervisorChildEffectCapture, raw)
	if err != nil {
		return empty, err
	}
	if len(output) > 65536 {
		return empty, qualification.ErrUntrusted
	}
	var result struct {
		SchemaVersion int             `json:"schemaVersion"`
		Command       string          `json:"command"`
		Status        string          `json:"status"`
		Capture       json.RawMessage `json:"capture"`
	}
	if json.Unmarshal(output, &result) != nil || result.SchemaVersion != 1 || result.Command != "child-effect-capture" || result.Status != "observed" || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return empty, qualification.ErrUntrusted
	}
	return producer.AttestChildProductEffect(call, op, qualification.ChildWorkflowObservationWitness{Authority: store, Sandbox: box, Product: w, CurrentSnapshot: currentSnapshot}, result.Capture)
}

func (p Podman) RetainCellProductObservationReceipt(_ context.Context, envelope model.WorkflowObservationEnvelope, receipt model.WorkflowObservationReceipt) error {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	return producer.RetainChildObservationReceipt(envelope, receipt)
}

// Owning registered catalog resolves root independently; neither observation
// body nor signed policy chooses a host path/device/inode. Physical ROOT read
// precedes the unchanged artifact_read proof/report/upload chain.
func (p Podman) ReadCellProductArtifact(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, currentSnapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var noRead qualification.WorkflowSourceCapture
	if p.verifyQualificationMounts(ctx, box.ID) != nil || root.HostRoot == "" || root.ContainerRoot == "" || root.RootDevice == 0 || root.RootInode == 0 || root.Report.Availability != "available" || root.Report.SandboxID != box.ID || root.Report.SandboxGeneration != box.Generation || root.Report.ServiceRegistrationID == nil || *root.Report.ServiceRegistrationID != entry.ServiceRegistrationID || root.Report.SelectionID != entry.Workspace.SelectionID || root.Report.ProjectID != entry.Workspace.ProjectID || root.Report.WorkspaceEpoch != entry.Workspace.WorkspaceEpoch || root.Report.RootAttestation != entry.Workspace.RootAttestation || root.ScopeRevision != entry.Workspace.ScopeRevision {
		return empty, noRead, qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return empty, noRead, err
	}
	w, err := producer.CurrentChildProductWitness(ctx, entry, current, input)
	if err != nil {
		return empty, noRead, err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return empty, noRead, err
	}
	control, err := store.ReadChildProduct(box, entry.PreparationID, w, time.Now())
	if err != nil || control.Generation.Policy == nil {
		return empty, noRead, qualification.ErrUntrusted
	}
	q := control.Generation.Policy.Payload
	var originalAssessment []byte
	var originalResult *model.ChildNativeResultCapture
	var originalIntegration *model.ChildNativeIntegrationCapture
	if q.Purpose == "coding_worker" {
		capture, err := p.captureCellProductResult(ctx, box, entry, control)
		if err != nil {
			return empty, noRead, err
		}
		originalResult = &capture
	}
	if q.Purpose == "integrator" {
		capture, err := p.captureCellProductIntegration(ctx, box, entry, control)
		if err != nil {
			return empty, noRead, err
		}
		originalIntegration = &capture
	}
	if q.Purpose == "reviewer" {
		request, _ := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": box.ID, "instance": entry.Instance, "profileId": entry.Profile.ProfileID, "nativeSessionId": entry.NativeSessionID})
		output, _, err := p.ExecManagedSupervisor(ctx, box.ID, ManagedSupervisorReviewerCapture, request)
		if err != nil || len(output) > 65536 {
			return empty, noRead, qualification.ErrUntrusted
		}
		var result struct {
			SchemaVersion int    `json:"schemaVersion"`
			Command       string `json:"command"`
			Status        string `json:"status"`
			Capture       struct {
				GenerationDigest string `json:"generationDigest"`
				BindingDigest    string `json:"bindingDigest"`
				InputID          string `json:"owningInputId"`
				InputDigest      string `json:"inputDigest"`
				Path             string `json:"assessmentPath"`
				Digest           string `json:"assessmentDigest"`
				Count            int    `json:"assessmentBytes"`
				Base64           string `json:"assessmentBase64"`
			} `json:"capture"`
		}
		if json.Unmarshal(output, &result) != nil || result.SchemaVersion != 1 || result.Command != string(ManagedSupervisorReviewerCapture) || result.Status != "observed" || q.ReviewDelivery == nil || result.Capture.GenerationDigest != control.Descriptor.GenerationDigest || result.Capture.BindingDigest != qualification.CanonicalDigest(q.Binding) || result.Capture.InputID != q.Instructions.InputID || result.Capture.InputDigest != q.Instructions.InputDigest || result.Capture.Path != q.ReviewDelivery.AssessmentPath {
			return empty, noRead, qualification.ErrUntrusted
		}
		originalAssessment, err = base64.StdEncoding.Strict().DecodeString(result.Capture.Base64)
		if err != nil || len(originalAssessment) > 16384 || len(originalAssessment) != result.Capture.Count || qualification.Digest(originalAssessment) != result.Capture.Digest {
			return empty, noRead, qualification.ErrUntrusted
		}
		var observed struct {
			SourcePath string `json:"sourcePath"`
			Digest     string `json:"digest"`
			ByteCount  int    `json:"byteCount"`
		}
		if json.Unmarshal(call.Operation.Observation, &observed) != nil || observed.SourcePath != result.Capture.Path || observed.Digest != result.Capture.Digest || observed.ByteCount != result.Capture.Count {
			return empty, noRead, qualification.ErrUntrusted
		}
	}
	envelope, read, err := producer.ReadChildProductArtifact(ctx, call, op, qualification.ChildWorkflowObservationWitness{Authority: store, Sandbox: box, Product: w, CurrentSnapshot: currentSnapshot, OriginalAssessment: originalAssessment, OriginalResult: originalResult, OriginalIntegration: originalIntegration, Workspace: qualification.TrustedWorkspace{HostRoot: root.HostRoot, ContainerRoot: root.ContainerRoot, WorkspaceDigest: root.Report.RootAttestation, Device: root.RootDevice, Inode: root.RootInode}})
	if err != nil || p.verifyQualificationMounts(ctx, box.ID) != nil || (q.Purpose == "reviewer" && !bytes.Equal(read.Bytes, originalAssessment)) {
		return empty, noRead, qualification.ErrUntrusted
	}
	return envelope, read, nil
}

// The owning registered workspace/installed-script registry supplies root,
// independently of op/policy JSON. Read-only signed reviewer policy is consumed
// WITHOUT selector adoption; native dispatch still requires all separate reads.
func (p Podman) ReadCellProductSource(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root qualification.TrustedWorkspace, delivery model.ChildProductDelivery, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, currentSnapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var noRead qualification.WorkflowSourceCapture
	if delivery.PreparationID() != entry.PreparationID || root.HostRoot == "" || root.Device == 0 || root.Inode == 0 || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return empty, noRead, qualification.ErrUntrusted
	}
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return empty, noRead, err
	}
	w, err := producer.ChildProductSourceReadWitness(ctx, entry, current, input)
	if err != nil {
		return empty, noRead, err
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return empty, noRead, err
	}
	envelope, read, err := producer.ReadChildProductSource(ctx, call, op, qualification.ChildWorkflowObservationWitness{Authority: store, Sandbox: box, Product: w, CurrentSnapshot: currentSnapshot, Workspace: root, SourceReadDelivery: &delivery})
	if err != nil || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return empty, noRead, qualification.ErrUntrusted
	}
	return envelope, read, nil
}

func (p Podman) RetainCellProductReviewerRead(ctx context.Context, entry model.CellServiceV3, current model.Manifest, input []byte, delivery model.ChildProductDelivery, envelope model.WorkflowObservationEnvelope, read qualification.WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
	producer, err := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if err != nil {
		return err
	}
	w, err := producer.ChildProductSourceReadWitness(ctx, entry, current, input)
	if err != nil {
		return err
	}
	if p.PhysicalStore == nil {
		return qualification.ErrUntrusted
	}
	local, err := p.PhysicalStore.CellV3Operation(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "reported" || w.ActualReceipt == nil || qualification.CanonicalDigest(local.Receipt) != qualification.CanonicalDigest(*w.ActualReceipt) || local.Receipt.ValidateFor(entry) != nil {
		return qualification.ErrUntrusted
	}
	ref := childReviewerReference(envelope)
	for _, scope := range w.InstalledInputs.SourceReads {
		var grant struct {
			Reference json.RawMessage `json:"reference"`
		}
		if json.Unmarshal(scope.Grant, &grant) != nil {
			return qualification.ErrUntrusted
		}
		if qualification.CanonicalDigest(grant.Reference) == qualification.CanonicalDigest(ref) {
			return producer.RetainReviewerSourceRead(ctx, w, delivery, scope, envelope, read, receipt)
		}
	}
	return qualification.ErrUntrusted
}

func childReviewerReference(envelope model.WorkflowObservationEnvelope) json.RawMessage {
	var request struct {
		Observation struct {
			Reference json.RawMessage `json:"reference"`
		} `json:"observation"`
	}
	_ = json.Unmarshal(envelope.Payload.Request, &request)
	return request.Observation.Reference
}
