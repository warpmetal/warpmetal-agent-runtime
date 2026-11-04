package qualification

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Verify EXACT raw payloads rather than re-marshalling a partially projected DTO.
// This is a verifier, never a signer or a source of installed/current authority.
func verifyChildEnvelope(raw json.RawMessage, keyID string, publicPEM []byte) error {
	var e struct {
		Payload   json.RawMessage `json:"payload"`
		KeyID     string          `json:"keyId"`
		Signature string          `json:"signature"`
	}
	if decode(raw, &e) != nil || e.KeyID != keyID || !safeID.MatchString(keyID) {
		return ErrUntrusted
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(e.Signature)
	if err != nil || base64.StdEncoding.EncodeToString(sig) != e.Signature {
		return ErrUntrusted
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return ErrUntrusted
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ErrUntrusted
	}
	ec, ok := k.(*ecdsa.PublicKey)
	d := sha256.Sum256(canonicalBytes(e.Payload))
	if !ok || ec.Curve.Params().Name != "P-256" || !ecdsa.VerifyASN1(ec, d[:], sig) {
		return ErrUntrusted
	}
	return nil
}

func childProductAdvance(prior, next ChildProductControl) error {
	versionMatches := prior.Generation.FormatVersion == next.Generation.FormatVersion ||
		(prior.Generation.FormatVersion == 3 && next.Generation.FormatVersion == 4 && next.Generation.Policy != nil && next.Generation.Policy.Payload.FormatVersion == 3 && next.Generation.Policy.Payload.Purpose == "integrator") ||
		(prior.Generation.FormatVersion == 3 && next.Generation.FormatVersion == 5 && next.Generation.Policy != nil && next.Generation.Policy.Payload.FormatVersion == 4 && next.Generation.Policy.Payload.Purpose == "reviewer")
	if prior.Generation.Phase != "prepare" || next.Generation.Phase != "execute" || !versionMatches ||
		prior.Descriptor.PreparationID != next.Descriptor.PreparationID ||
		prior.Descriptor.PreparedTupleDigest != next.Descriptor.PreparedTupleDigest ||
		prior.Descriptor.PreparationPolicyDigest != next.Descriptor.PreparationPolicyDigest ||
		!sameProduct(prior.Generation.PreparationPolicy, next.Generation.PreparationPolicy) ||
		!sameProduct(prior.Generation.Demand, next.Generation.Demand) {
		return ErrUntrusted
	}
	return nil
}

// VerifyChildProductControl joins the frozen whole wire to separately supplied
// current facts. An absent witness is a denial, not a bootstrap/success-row seed.
// No slots are allocated, files written, credentials fetched or native leaves run.
func VerifyChildProductControl(raw []byte, w ChildProductWitness, operatorPEM []byte, now time.Time) (ChildProductControl, error) {
	return verifyChildProductControl(raw, w, operatorPEM, now, true)
}

// Only the operation-specific source reader below may use input-only reviewer
// verification. Store adoption/native dispatch ALWAYS uses the public strict gate.
func verifyChildProductControl(raw []byte, w ChildProductWitness, operatorPEM []byte, now time.Time, requireReviewReads bool) (ChildProductControl, error) {
	var empty, c ChildProductControl
	if _, err := model.DecodeChildProductDelivery(raw); err != nil || decode(raw, &c) != nil {
		return empty, ErrUntrusted
	}
	var wire struct {
		Generation    map[string]json.RawMessage `json:"generation"`
		Descriptor    json.RawMessage            `json:"descriptor"`
		FormatVersion int                        `json:"formatVersion"`
	}
	if decode(raw, &wire) != nil {
		return empty, ErrUntrusted
	}
	g, p, d := c.Generation, c.Generation.PreparationPolicy.Payload, c.Descriptor
	// Structural SOURCE parsing cannot promote a LIVE/original consumer. The
	// separately owning current witness selects the exact continuation explicitly.
	if !sameProduct(g.Demand.Payload.SourceContinuation, w.SourceContinuation) {
		return empty, ErrUntrusted
	}
	if (len(w.SourceContinuation) != 0 && w.InstalledInputs == nil) || (w.InstalledInputs != nil && verifyInstalledChildControl(g, *w.InstalledInputs) != nil) {
		return empty, ErrUntrusted
	}
	if len(w.SourceContinuation) != 0 {
		var selected SourceContinuation
		if decode(w.SourceContinuation, &selected) != nil || w.Qualification.QualificationID == selected.Predecessor.QualificationID || w.Preparation.PreparationID == selected.Predecessor.PreparationID {
			return empty, ErrUntrusted
		}
	}
	if (g.FormatVersion == 2) != (p.Case.FormatVersion == 2) || (g.FormatVersion == 3 || g.FormatVersion == 4 || g.FormatVersion == 5) != (p.Case.FormatVersion == 3) {
		return empty, ErrUntrusted
	}
	entryTuple, entryErr := w.Entry.PreparedTuple()
	if entryErr != nil || !sameProduct(entryTuple, p.Preparation.PreparedTuple) || w.Entry.PreparationID != p.Preparation.PreparationID ||
		w.Entry.NativeSessionID != p.Preparation.SessionID || "msg_"+strings.TrimPrefix(w.Entry.NativeSessionID, "ses_") != p.Preparation.InputID ||
		w.Entry.Instructions.InstructionRevision != p.Instructions.InstructionRevision || w.Entry.Instructions.InstructionDigest != p.Instructions.InstructionDigest {
		return empty, ErrUntrusted
	}
	if Digest(operatorPEM) != w.Case.OperatorKeySHA256 || !sameProduct(p.Case, w.Case) ||
		!sameProduct(p.Applicability, w.Applicability) || !sameProduct(w.Applicability, w.QualifiedApplicability) ||
		!sameProduct(p.Qualification, w.Qualification) || !live(w.Qualification.ValidUntil, now) ||
		!sameProduct(p.Scope, w.Scope) || !sameProduct(p.Intent, w.Intent) || !sameProduct(p.Handle, w.Handle) ||
		!sameProduct(p.Root, w.Root) || !hash.MatchString(w.Root.CandidateDescriptorDigest) || w.Root.RuntimeRevision < 1 ||
		!sameProduct(p.Preparation, w.Preparation) || !sameProduct(p.Instructions, w.Instructions) ||
		w.SigningNotBefore.IsZero() || w.AuthorizedUntil.IsZero() || !now.Before(w.AuthorizedUntil) ||
		g.Demand.Payload.validate(w.Case, now) != nil {
		return empty, ErrUntrusted
	}
	for _, name := range []string{"demand", "preparationPolicy"} {
		if verifyChildEnvelope(wire.Generation[name], w.OperatorKeyID, operatorPEM) != nil {
			return empty, ErrUntrusted
		}
	}
	if w.AcceptedPreparationEnvelope != nil && !sameProduct(w.AcceptedPreparationEnvelope, wire.Generation["preparationPolicy"]) ||
		w.AcceptedDemandEnvelope != nil && !sameProduct(w.AcceptedDemandEnvelope, wire.Generation["demand"]) {
		return empty, ErrUntrusted
	}
	issued, err := time.Parse(time.RFC3339Nano, p.IssuedAt)
	pe, xe := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil || xe != nil || issued.Before(w.SigningNotBefore) ||
		!childExpiry(p.ExpiresAt, issued, w.AuthorizedUntil, now, 300*time.Second) ||
		pe.After(mustChildTime(p.Qualification.ValidUntil)) || pe.After(mustChildTime(g.Demand.Payload.NotAfter)) || pe.After(mustChildTime(p.Handle.NotAfter)) {
		return empty, ErrUntrusted
	}
	if childAllocation(p, g.Demand.Payload) != nil || childPreparationBasis(p) != nil {
		return empty, ErrUntrusted
	}
	if p.Case.FormatVersion == 2 || p.Case.FormatVersion == 3 {
		allocation, err := g.Demand.Payload.allocation(p.Reservation.AllocationID)
		if err != nil || allocation.TupleDigest != CanonicalDigest(w.QualifiedApplicability) {
			return empty, ErrUntrusted
		}
	}
	intentTools := childFields(p.Intent)["tools"]
	if !sameProduct(intentTools, p.ToolRequirements) {
		return empty, ErrUntrusted
	}
	if len(w.Input) != p.Instructions.InputByteCount || !model.ControllerTextValid(string(w.Input)) || Digest(w.Input) != p.Instructions.InputDigest {
		return empty, ErrUntrusted
	}
	if g.Phase == "prepare" {
		// The closed schema enforces null policy/binding/activation/observation.
		// Even a valid signature cannot authorize a prompt from this generation.
		return c, nil
	}
	if w.AcceptedPreparationEnvelope == nil || w.AcceptedDemandEnvelope == nil || w.ActualReceipt == nil ||
		w.Grant == nil || w.Authorization == nil || w.ProductSigningNotBefore.IsZero() || w.ActivationSigningNotBefore.IsZero() ||
		g.Policy == nil || g.PolicyBinding == nil || g.Activation == nil || g.AuthorizationObservation == nil {
		return empty, ErrUntrusted
	}
	for _, name := range []string{"policy", "policyBinding", "activation"} {
		if verifyChildEnvelope(wire.Generation[name], w.OperatorKeyID, operatorPEM) != nil {
			return empty, ErrUntrusted
		}
	}
	if Digest(w.ProducerPEM) != p.Root.Producer.KeySHA256 || verifyChildEnvelope(wire.Generation["authorizationObservation"], p.Root.Producer.KeyID, w.ProducerPEM) != nil {
		return empty, ErrUntrusted
	}
	q, binding, a, observation := g.Policy.Payload, g.PolicyBinding.Payload, g.Activation.Payload, g.AuthorizationObservation.Payload
	if verifyChildProductPolicyBasis(p, q, binding, w.ActualReceipt, w.Binding, w.Assignment, w.ProductSigningNotBefore, now) != nil {
		return empty, ErrUntrusted
	}
	qi, _ := time.Parse(time.RFC3339Nano, q.IssuedAt)
	assignment := childFields(q.Assignment)
	assignmentDigest := childString(assignment, "assignmentDigest")
	if !sameProduct(a.Grant, *w.Grant) || !sameProduct(observation, *w.Authorization) || !sameProduct(observation.Root, p.Root) ||
		observation.TaskID != p.Applicability.TaskID || observation.NodeTokenHash != p.Root.Producer.NodeTokenHash ||
		observation.PreparationID != p.Preparation.PreparationID || observation.PreparedReceiptDigest != q.PreparedReceipt.PreparedReceiptDigest ||
		a.CaseID != p.Case.CaseID || a.CaseManifestDigest != p.Case.CaseManifestDigest || a.DemandManifestDigest != p.Case.DemandManifestDigest ||
		a.AllocationID != p.Reservation.AllocationID || a.Intent != q.Intent || a.PreparationID != p.Preparation.PreparationID ||
		a.PreparationPolicyDigest != d.PreparationPolicyDigest || a.PreparedTupleDigest != d.PreparedTupleDigest ||
		a.PreparedReceiptDigest != q.PreparedReceipt.PreparedReceiptDigest || a.AssignmentDigest != assignmentDigest || a.PolicyDigest != CanonicalDigest(q) ||
		a.PolicyBindingDigest != CanonicalDigest(binding) || !sameProduct(a.Reservation, p.Reservation) ||
		a.GrantDigest != CanonicalDigest(*w.Grant) || a.AuthorizationObservationDigest != CanonicalDigest(g.AuthorizationObservation) ||
		a.AuthorizationSHA256 != observation.AuthorizationSHA256 ||
		a.Grant.PreparedReceiptDigest != a.PreparedReceiptDigest || a.Grant.InputID != p.Preparation.InputID ||
		w.Entry.PreparationID != a.PreparationID || w.Entry.ExecutionGrant == nil || !sameProduct(*w.Entry.ExecutionGrant, a.Grant) ||
		w.Entry.ValidateExecutionAuthority(*w.ActualReceipt) != nil {
		return empty, ErrUntrusted
	}
	ai, ae := time.Parse(time.RFC3339Nano, a.IssuedAt)
	observed, oe := time.Parse(time.RFC3339Nano, observation.ObservedAt)
	if ae != nil || oe != nil || ai.Before(qi) || ai.Before(w.ActivationSigningNotBefore) || observed.Before(w.ActivationSigningNotBefore) || observed.After(ai) ||
		!childExpiry(a.ExpiresAt, ai, w.AuthorizedUntil, now, 120*time.Second) ||
		mustChildTime(a.ExpiresAt).After(mustChildTime(q.ExpiresAt)) || mustChildTime(a.ExpiresAt).After(mustChildTime(binding.ExpiresAt)) ||
		mustChildTime(a.ExpiresAt).After(mustChildTime(a.Grant.ExpiresAt)) || !live(a.Grant.ExpiresAt, now) {
		return empty, ErrUntrusted
	}
	if childReadAndToolScopes(p, q, w, now, requireReviewReads) != nil {
		return empty, ErrUntrusted
	}
	return c, nil
}

// Shared immutable policy/prepared/assignment basis, not a grant or activation
// validator. Each normal consumer supplies its independently owned current floor.
func verifyChildProductPolicyBasis(p ChildPreparationPolicy, q ChildProductPolicy, binding ChildPolicyBinding, receipt *model.PreparedReceipt, actualBinding, assignment json.RawMessage, notBefore, now time.Time) error {
	qi, qe := time.Parse(time.RFC3339Nano, q.IssuedAt)
	if qe != nil || qi.Before(mustChildTime(p.IssuedAt)) || qi.Before(notBefore) || !childExpiry(q.ExpiresAt, qi, mustChildTime(p.ExpiresAt), now, 300*time.Second) ||
		q.Purpose != p.Purpose || !sameProduct(q.Case, p.Case) || q.Intent != p.Handle.Intent ||
		!sameProduct(q.Scope, p.Scope) || !sameProduct(q.Root, p.Root) || !sameProduct(q.Applicability, p.Applicability) ||
		!sameProduct(q.Qualification, p.Qualification) || !sameProduct(q.Reservation, p.Reservation) ||
		!sameProduct(q.Budget, p.Budget) || !sameProduct(q.Workload, p.Workload) || !sameProduct(q.Instructions, p.Instructions) ||
		!sameProductReceipt(receipt, q.PreparedReceipt) || !sameProduct(q.PreparedReceipt.PreparedTuple, p.Preparation.PreparedTuple) ||
		!sameProduct(q.Binding, actualBinding) || !sameProduct(q.Assignment, assignment) || childActualBinding(p, q) != nil {
		return ErrUntrusted
	}
	assignmentDigest := childString(childFields(q.Assignment), "assignmentDigest")
	if !hash.MatchString(assignmentDigest) || binding.PolicyDigest != CanonicalDigest(q) || !sameProduct(binding.Case, p.Case) ||
		binding.AllocationID != p.Reservation.AllocationID || binding.Intent != q.Intent || binding.PreparedReceiptDigest != q.PreparedReceipt.PreparedReceiptDigest ||
		binding.AssignmentDigest != assignmentDigest || binding.ModelRequests != p.Budget.ModelRequests || binding.USDMicros != p.Budget.USDMicros ||
		!live(binding.ExpiresAt, now) || mustChildTime(binding.ExpiresAt).After(mustChildTime(q.ExpiresAt)) {
		return ErrUntrusted
	}
	return nil
}

// Signed controls cannot replace independently observed installed inputs.
func verifyInstalledChildControl(g ChildProductGeneration, inputs ChildInstalledInputs) error {
	if !sameProduct(g.PreparationPolicy.Payload.Workload, inputs.Workload) {
		return ErrUntrusted
	}
	if g.Phase == "execute" {
		if g.Policy == nil {
			return ErrUntrusted
		}
		p := g.Policy.Payload
		if !sameProduct(p.Workload, inputs.Workload) || !sameProduct(p.SourceReads, inputs.SourceReads) || !sameProduct(p.ArtifactReads, inputs.ArtifactReads) || !sameProduct(p.Tools, inputs.Tools) || !sameProduct(p.ReviewDelivery, inputs.ReviewDelivery) || !sameProduct(p.IntegrationDelivery, inputs.IntegrationDelivery) {
			return ErrUntrusted
		}
	} else if g.Phase != "prepare" {
		return ErrUntrusted
	}
	return nil
}

func mustChildTime(v string) time.Time { t, _ := time.Parse(time.RFC3339Nano, v); return t }
func childFields(raw json.RawMessage) map[string]json.RawMessage {
	var out map[string]json.RawMessage
	_ = json.Unmarshal(raw, &out)
	return out
}
func childString(v map[string]json.RawMessage, key string) string {
	var s string
	_ = json.Unmarshal(v[key], &s)
	return s
}

func childAllocation(p ChildPreparationPolicy, d DemandManifest) error {
	a, err := d.allocation(p.Reservation.AllocationID)
	scope := childFields(p.Scope)
	sourceID := p.Root.RegisteredSourceID
	if d.FormatVersion == 2 || d.FormatVersion == 3 {
		sourceID = p.Handle.Intent.IntentID
	}
	if err != nil || a.Kind != p.Purpose || !sameProduct(a.Scope, scope["owner"]) || a.ScopeDigest != CanonicalDigest(p.Scope) ||
		a.SourceID != sourceID || p.Reservation.DemandManifestDigest != p.Case.DemandManifestDigest || p.Reservation.LedgerID != p.Case.LedgerID ||
		a.PreparationOrdinal != p.Reservation.PreparationOrdinal || a.FirstPhysicalIndex != p.Reservation.FirstPhysicalIndex || a.LastPhysicalIndex != p.Reservation.LastPhysicalIndex ||
		a.ModelRequests != p.Reservation.ModelRequests || a.AccessRequests != p.Reservation.AccessRequests || a.USDMicros != p.Reservation.USDMicros ||
		p.Budget.ModelRequests != a.ModelRequests || p.Budget.Turns != a.ModelRequests || p.Budget.InputTokens != a.ModelRequests*1047576 ||
		p.Budget.OutputTokens != a.ModelRequests*1000 || p.Budget.USDMicros != a.USDMicros || p.Budget.PricingDigest != p.Case.PricingDigest ||
		len(p.Workload.Requests) != a.ModelRequests {
		return ErrUntrusted
	}
	for i, r := range p.Workload.Requests {
		if r.RequestIndex != i+1 || r.PhysicalIndex != a.FirstPhysicalIndex+i {
			return ErrUntrusted
		}
		if i == len(p.Workload.Requests)-1 {
			if r.ToolChoice != "none" || r.ToolKind != nil || r.NativeToolName != nil {
				return ErrUntrusted
			}
		} else if p.Workload.Kind == "business3" {
			kind := "mcp_read"
			if i == 1 {
				kind = "script_run"
			}
			if r.ToolChoice != "exact" || r.ToolKind == nil || *r.ToolKind != kind || r.NativeToolName == nil || *r.NativeToolName != p.Workload.NativeToolNames[i] {
				return ErrUntrusted
			}
		} else if r.ToolChoice != "approved_native_tools" || r.ToolKind == nil || *r.ToolKind != "native" || r.NativeToolName != nil {
			return ErrUntrusted
		}
	}
	return nil
}

func childPreparationBasis(p ChildPreparationPolicy) error {
	authority := model.CellPreparedAuthorityV3{ProviderID: "openai", ModelID: RealModel, AuthMode: "api_key"}
	endpoint := RealEndpoint
	if p.FormatVersion == 2 {
		descriptor := providerpolicy.Flash()
		if p.Case.FormatVersion != 3 || p.ProviderPolicyDigest != providerpolicy.FlashDigest || p.AccountingVersion != descriptor.Accounting.Version || p.Applicability.ProviderPolicyDigest != p.ProviderPolicyDigest {
			return ErrUntrusted
		}
		authority = model.CellPreparedAuthorityV3{ProviderID: descriptor.ProviderID, ModelID: descriptor.ModelID, AuthMode: descriptor.AuthMode}
		endpoint = descriptor.Transport.URL
	}
	t := p.Preparation.PreparedTuple
	td, err := t.Digest()
	scope, intent := childFields(p.Scope), childFields(p.Intent)
	if err != nil || td != p.Preparation.PreparedTupleDigest || p.Instructions.InputID != p.Preparation.InputID ||
		t.CredentialBinding != p.Applicability.Connection ||
		t.ProfileDigest != p.Applicability.Profile.ProfileDigest || t.SandboxID != p.Applicability.SandboxID || t.SandboxGeneration != p.Applicability.SandboxGeneration ||
		t.Authority != authority ||
		p.Applicability.Model.Endpoint != endpoint || p.Applicability.Model.ModelID != authority.ModelID || p.Applicability.Model.ProviderID != authority.ProviderID || p.Applicability.Model.AuthMode != authority.AuthMode ||
		!sameProduct(scope["workspace"], p.Root.Workspace) || !sameProduct(intent["scope"], p.Scope) ||
		childString(intent, "intentDigest") != p.Handle.Intent.IntentDigest || childString(intent, "intentId") != p.Handle.Intent.IntentID ||
		childString(intent, "allocationId") != p.Reservation.AllocationID || mustChildTime(p.ExpiresAt).After(mustChildTime(childString(intent, "notAfter"))) {
		return ErrUntrusted
	}
	return nil
}

func childActualBinding(p ChildPreparationPolicy, q ChildProductPolicy) error {
	b, a, intent := childFields(q.Binding), childFields(q.Assignment), childFields(p.Intent)
	t := q.PreparedReceipt.PreparedTuple
	expected := map[string]any{"preparationId": p.Preparation.PreparationID, "nativeSessionId": p.Preparation.SessionID,
		"serviceRegistrationId": t.ServiceRegistrationID, "serviceGeneration": t.ServiceGeneration, "sandboxGeneration": t.SandboxGeneration,
		"attempt": t.Attempt, "fence": t.Fence, "packetId": t.PacketID, "packetRevision": t.PacketRevision,
		"parentExecutionId": t.ParentExecutionID, "parentPacketId": t.ParentPacketID, "profileDigest": t.ProfileDigest, "configDigest": t.ConfigDigest,
		"instructionRevision": p.Instructions.InstructionRevision, "instructionDigest": p.Instructions.InstructionDigest,
		"projectId": p.Root.Workspace.ProjectID, "workspaceEpoch": p.Root.Workspace.WorkspaceEpoch, "selectionId": p.Root.Workspace.SelectionID,
		"scopeRevision": p.Root.Workspace.ScopeRevision, "rootAttestation": p.Root.Workspace.RootAttestation}
	for key, value := range expected {
		if !sameProduct(b[key], value) {
			return ErrUntrusted
		}
	}
	if !sameProduct(b["executionId"], a["executionId"]) || !sameProduct(a["plan"], intent["plan"]) ||
		!sameProduct(a["target"], intent["target"]) || !sameProduct(a["purpose"], intent["purpose"]) {
		return ErrUntrusted
	}
	return nil
}

func childReadAndToolScopes(p ChildPreparationPolicy, q ChildProductPolicy, w ChildProductWitness, now time.Time, requireReviewReads bool) error {
	if q.FormatVersion == 4 {
		if verifyReviewerArtifactSelection(p, q, w, now) != nil {
			return ErrUntrusted
		}
	} else if len(q.ArtifactReads) != 0 || len(w.ArtifactReviewReads) != 0 {
		return ErrUntrusted
	}
	if q.FormatVersion == 3 {
		if verifyIntegrationProductInput(p, q, w, now) != nil {
			return ErrUntrusted
		}
	} else if q.IntegrationDelivery != nil {
		return ErrUntrusted
	}
	a := childFields(q.Assignment)
	readDigests := map[string]bool{}
	for _, read := range q.SourceReads {
		grant, root := childFields(read.Grant), childFields(read.Root)
		if !sameProduct(grant["binding"], q.Binding) || !sameProduct(root["binding"], q.Binding) ||
			!sameProduct(grant["assignmentId"], a["assignmentId"]) || !sameProduct(root["assignmentId"], a["assignmentId"]) ||
			!sameProduct(grant["use"], root["use"]) || childString(grant, "rootGrantDigest") != CanonicalDigest(read.Root) ||
			!live(childString(grant, "expiresAt"), now) || !live(childString(root, "expiresAt"), now) ||
			w.SourceRoots[CanonicalDigest(read.Root)] == nil ||
			!sameProduct(read.Root, w.SourceRoots[CanonicalDigest(read.Root)]) {
			return ErrUntrusted
		}
		readDigests[CanonicalDigest(read.Grant)] = true
	}
	for i, tool := range q.Tools {
		if i >= len(p.ToolRequirements) || tool.EffectOrdinal != i || tool.NativeToolName != p.Workload.NativeToolNames[i] ||
			w.InstalledTools[tool.NativeToolName] == nil || !sameProduct(tool.InstalledWitness, w.InstalledTools[tool.NativeToolName]) {
			return ErrUntrusted
		}
		approval, requirement, witness := childFields(tool.Approval), childFields(p.ToolRequirements[i]), childFields(tool.InstalledWitness)
		if childString(approval, "definitionDigest") != CanonicalDigest(tool.Definition) ||
			childString(witness, "candidateDescriptorDigest") != p.Root.CandidateDescriptorDigest ||
			childString(witness, "registryManifestDigest") != p.Applicability.Sandbox.RegistryManifestDigest ||
			childString(witness, "imageConfigDigest") != p.Applicability.Sandbox.ConfigDigest ||
			childString(witness, "pluginDigest") != p.Applicability.Sandbox.PluginDigest ||
			childString(witness, "materializerDigest") != p.Applicability.Profile.MaterializerDigest ||
			childString(requirement, "kind") != tool.Kind || childString(requirement, "definitionDigest") != CanonicalDigest(tool.Definition) ||
			childString(requirement, "approvalDigest") != CanonicalDigest(tool.Approval) {
			return ErrUntrusted
		}
		definition := childFields(tool.Definition)
		if !sameProduct(definition["interpreter"], witness["interpreter"]) {
			return ErrUntrusted
		}
		for _, id := range tool.InputReads {
			if !readDigests[id] {
				return ErrUntrusted
			}
		}
		if tool.Kind == "script_run" {
			if tool.ScriptRead == nil || !readDigests[*tool.ScriptRead] || childString(requirement, "dataScopeDigest") != childString(approval, "inputDataScopeDigest") {
				return ErrUntrusted
			}
		} else if tool.DataScopeDigest == nil || *tool.DataScopeDigest != childString(requirement, "dataScopeDigest") {
			return ErrUntrusted
		}
	}
	if q.Purpose == "reviewer" {
		for _, read := range w.ReviewReads {
			if !readDigests[CanonicalDigest(read.SourceGrant)] {
				return ErrUntrusted
			}
		}
		if q.ReviewDelivery == nil || !sameProduct(q.ReviewDelivery.Binding, q.Binding) || !sameProduct(q.ReviewDelivery.Assignment, q.Assignment) ||
			q.ReviewDelivery.Intent != q.Intent || q.ReviewDelivery.InputID != p.Instructions.InputID ||
			w.ReviewCompilation == nil || !sameProduct(*w.ReviewCompilation, childFields(p.Intent)["reviewInput"]) ||
			model.VerifyReviewerInput(*w.ReviewCompilation, *q.ReviewDelivery, string(w.Input), now) != nil {
			return ErrUntrusted
		}
		if requireReviewReads && model.VerifyReviewerDeliveryOriginals(*w.ReviewCompilation, *q.ReviewDelivery, string(w.Input), w.ReviewReads, w.ArtifactReviewReads, now) != nil {
			return ErrUntrusted
		}
	}
	return nil
}

// Authenticated node's full signed generation permits ONLY initial reviewer
// ROOT reads before native admission. This does not publish/advance a selector,
// grant, prepare, dispatch, accept qualification, write a home or credit delivery.
func (s Store) ChildProductSourceReadPolicy(box model.Sandbox, delivery model.ChildProductDelivery, w ChildProductWitness, now time.Time) (ChildProductPolicy, error) {
	var empty ChildProductPolicy
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return empty, err
	}
	public, err := s.read(key, tree, key, 4096)
	if err != nil {
		return empty, err
	}
	c, err := verifyChildProductControl(delivery.Bytes(), w, public, now, false)
	if err != nil || c.Generation.Phase != "execute" || c.Generation.Policy == nil || c.Generation.Policy.Payload.Purpose != "reviewer" || delivery.PreparationID() != w.Preparation.PreparationID || c.Generation.PreparationPolicy.Payload.Applicability.SandboxID != box.ID || c.Generation.PreparationPolicy.Payload.Applicability.SandboxGeneration != box.Generation {
		return empty, ErrUntrusted
	}
	selector := tree + "/preparations/" + delivery.PreparationID() + ".json"
	raw, err := s.read(selector, tree, key, 65536)
	var d ChildProductDescriptor
	if err != nil || workflowcontract.ValidateChildProduct("controlDescriptor", raw) != nil || decode(raw, &d) != nil || d.FormatVersion != 2 || d.PreparationID != c.Descriptor.PreparationID || d.PreparedTupleDigest != c.Descriptor.PreparedTupleDigest || d.PreparationPolicyDigest != c.Descriptor.PreparationPolicyDigest {
		return empty, ErrUntrusted
	}
	var delivered struct {
		Generation json.RawMessage `json:"generation"`
	}
	if json.Unmarshal(delivery.Bytes(), &delivered) != nil {
		return empty, ErrUntrusted
	}
	priorDigest, err := s.verifyChildProductPrepareSnapshot(tree, key, c, delivered.Generation)
	if err != nil || (d.Phase == "prepare" && d.GenerationDigest != priorDigest) || (d.Phase == "execute" && d.GenerationDigest != c.Descriptor.GenerationDigest) || (d.Phase != "prepare" && d.Phase != "execute") {
		return empty, ErrUntrusted
	}
	again, err := s.read(selector, tree, key, 65536)
	if err != nil || !bytes.Equal(raw, again) {
		return empty, ErrUntrusted
	}
	return c.Generation.Policy.Payload, nil
}

// One authoritative reconstruction of the FIRST whole prepare envelopes. Both
// strict dispatch and read-only reviewer consumption require the retained copy.
func (s Store) verifyChildProductPrepareSnapshot(tree, key string, c ChildProductControl, generation json.RawMessage) (string, error) {
	priorFields := childFields(generation)
	priorFields["phase"] = json.RawMessage(`"prepare"`)
	if c.Generation.FormatVersion == 4 || c.Generation.FormatVersion == 5 {
		// This successor changes only the execute authority. The first signed
		// preparation remains generation3 and must already exist unchanged.
		priorFields["formatVersion"] = json.RawMessage(`3`)
	}
	for _, name := range []string{"policy", "policyBinding", "activation", "authorizationObservation"} {
		priorFields[name] = json.RawMessage(`null`)
	}
	priorBytes := canonicalBytes(priorFields)
	priorDigest := Digest(priorBytes)
	stored, err := s.read(tree+"/product/snapshots/"+priorDigest[7:]+"/control.json", tree, key, 512*1024)
	if err != nil || !bytes.Equal(stored, priorBytes) {
		return "", ErrUntrusted
	}
	prior := ChildProductControl{FormatVersion: c.FormatVersion, Descriptor: c.Descriptor}
	prior.Descriptor.Phase, prior.Descriptor.PolicyDigest, prior.Descriptor.GenerationDigest = "prepare", nil, priorDigest
	if decode(stored, &prior.Generation) != nil || validateChildGeneration(prior.Generation, stored) != nil || childProductAdvance(prior, c) != nil {
		return "", ErrUntrusted
	}
	return priorDigest, nil
}

// ReadChildProduct uses ONLY descriptor2 under the existing mounted control tree.
// Both canonical generations must already have been published by the authorized
// store consumer; this reader cannot turn an HTTP response into installed facts.
func (s Store) ReadChildProduct(box model.Sandbox, preparation string, w ChildProductWitness, now time.Time) (ChildProductControl, error) {
	var empty ChildProductControl
	if !safeID.MatchString(preparation) {
		return empty, ErrUntrusted
	}
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return empty, ErrUntrusted
	}
	raw, err := s.read(tree+"/preparations/"+preparation+".json", tree, key, 65536)
	if err != nil || workflowcontract.ValidateChildProduct("controlDescriptor", raw) != nil {
		return empty, ErrUntrusted
	}
	var d ChildProductDescriptor
	if decode(raw, &d) != nil || d.PreparationID != preparation {
		return empty, ErrUntrusted
	}
	generation, err := s.read(tree+"/product/snapshots/"+d.GenerationDigest[7:]+"/control.json", tree, key, 512*1024)
	if err != nil || Digest(generation) != d.GenerationDigest {
		return empty, ErrUntrusted
	}
	publicPEM, err := s.read(key, tree, key, 4096)
	if err != nil {
		return empty, ErrUntrusted
	}
	var header struct {
		FormatVersion int `json:"formatVersion"`
	}
	if json.Unmarshal(generation, &header) != nil {
		return empty, ErrUntrusted
	}
	delivery := canonicalBytes(map[string]any{"formatVersion": header.FormatVersion, "descriptor": d, "generation": json.RawMessage(generation)})
	c, err := VerifyChildProductControl(delivery, w, publicPEM, now)
	if err != nil || c.Generation.PreparationPolicy.Payload.Applicability.SandboxID != box.ID ||
		c.Generation.PreparationPolicy.Payload.Applicability.SandboxGeneration != box.Generation {
		return empty, ErrUntrusted
	}
	if c.Generation.Phase == "execute" {
		// Reconstruct only the closed prior prepare generation, never an actual
		// receipt/grant. Its FIRST whole signed envelopes must already be retained
		// in the same protected store; a standalone execute download cannot skip it.
		if _, err := s.verifyChildProductPrepareSnapshot(tree, key, c, generation); err != nil {
			return empty, ErrUntrusted
		}
	}
	// Selectors can advance concurrently; stale prepare/execute selection cannot
	// escape a reread, nor can noncanonical stored bytes become signed authority.
	again, err := s.read(tree+"/preparations/"+preparation+".json", tree, key, 65536)
	if err != nil || !bytes.Equal(again, raw) || !bytes.Equal(generation, canonicalBytes(json.RawMessage(generation))) {
		return empty, ErrUntrusted
	}
	return c, nil
}
