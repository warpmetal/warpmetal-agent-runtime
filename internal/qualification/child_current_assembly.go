package qualification

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"golang.org/x/sys/unix"
)

// Independently provisioned consumer pin; the producer observation signs its
// digest but cannot create/adopt/replace this separate installed consumer.
type ChildProductConsumerPin struct {
	Profile                  json.RawMessage  `json:"profile"`
	Native                   ArtifactIdentity `json:"native"`
	Runtime                  ArtifactIdentity `json:"runtime"`
	Sandbox                  json.RawMessage  `json:"sandbox"`
	AdapterVersion           string           `json:"adapterVersion"`
	EvidenceClass            string           `json:"evidenceClass"`
	ChildProductSchemaSHA256 string           `json:"childProductSchemaSHA256"`
	BudgetSchemaSHA256       string           `json:"budgetSchemaSHA256"`
}
type ChildInstalledInputs struct {
	Workload       ChildWorkload             `json:"workload"`
	SourceReads    []ChildSourceReadScope    `json:"sourceReads"`
	ArtifactReads  json.RawMessage           `json:"artifactReads,omitempty"`
	Tools          []ChildToolScope          `json:"tools"`
	ReviewDelivery *model.ReviewDeliveryPlan `json:"reviewDelivery"`
	// Preserve absent legacy1 versus the required explicit null in observation2.
	IntegrationDelivery json.RawMessage `json:"integrationDelivery,omitempty"`
}

// EXACT F1 child_product_inputs.OBSERVATION_FIELDS, not a new producer envelope.
type ChildInstalledInputObservation struct {
	FormatVersion       int                  `json:"formatVersion"`
	Purpose             string               `json:"purpose"`
	EvidenceClass       string               `json:"evidenceClass"`
	ConfigDigest        string               `json:"configDigest"`
	TaskID              string               `json:"taskId"`
	NodeTokenHash       string               `json:"nodeTokenHash"`
	PreparationID       string               `json:"preparationId"`
	IntentDigest        string               `json:"intentDigest"`
	PreparedTupleDigest string               `json:"preparedTupleDigest"`
	ApplicabilityDigest string               `json:"applicabilityDigest"`
	Root                ChildRootScope       `json:"root"`
	AssignmentDigest    *string              `json:"assignmentDigest"`
	ConsumerDigest      string               `json:"consumerDigest"`
	Inputs              ChildInstalledInputs `json:"inputs"`
	ObservedAt          string               `json:"observedAt"`
	NotAfter            string               `json:"notAfter"`
}
type ChildProductInstalledFacts struct {
	EvidenceClass string                  `json:"evidenceClass"`
	ConfigDigest  string                  `json:"configDigest"`
	Applicability Applicability           `json:"applicability"`
	ProducerPEM   []byte                  `json:"producerPEM"`
	Consumer      ChildProductConsumerPin `json:"consumer"`
	Observation   json.RawMessage         `json:"observation"`
}

// Current owning acceptance/window/qualification facts, independently exported
// from existing owners. Not extracted from a signed product/preparation policy.
type ChildProductAuthorityFacts struct {
	OperatorKeyID               string
	QualifiedApplicability      Applicability
	Qualification               ChildQualificationPin
	Case                        RealCase
	Scope                       json.RawMessage
	Intent                      json.RawMessage
	Handle                      model.IntentHandle
	Root                        ChildRootScope
	SigningNotBefore            time.Time
	ProductSigningNotBefore     time.Time
	ActivationSigningNotBefore  time.Time
	AuthorizedUntil             time.Time
	AcceptedPreparationEnvelope json.RawMessage
	AcceptedDemandEnvelope      json.RawMessage
	SourceContinuation          json.RawMessage `json:"SourceContinuation,omitempty"`
}
type ChildProductLifecycleFacts struct {
	ActualReceipt       *model.PreparedReceipt
	Binding             json.RawMessage
	Assignment          json.RawMessage
	Grant               *model.CellExecutionGrantV3
	Authorization       *ChildAuthorizationObservation
	ReviewReads         []model.ReviewReadWitness
	ArtifactReviewReads []model.ArtifactReviewReadWitness `json:"ArtifactReviewReads,omitempty"`
	ReviewCompilation   *model.ReviewInputCompilation
}

func childWireAbsent(raw json.RawMessage) bool { return len(raw) == 0 || string(raw) == "null" }

func childLifecycleHasPreparedFacts(f ChildProductLifecycleFacts) bool {
	return f.ActualReceipt != nil || !childWireAbsent(f.Binding) || !childWireAbsent(f.Assignment) || f.Grant != nil || f.Authorization != nil
}

func verifyChildInstalledInputs(f ChildProductInstalledFacts, w ChildProductWitness, now time.Time) (ChildInstalledInputs, error) {
	var empty ChildInstalledInputs
	pin := f.Consumer
	budgetDocument, err := childFactBudgetContract(f.EvidenceClass, w.SourceContinuation)
	if err != nil {
		return empty, err
	}
	selectedChild := workflowcontract.ChildProduct
	integrator := false
	reviewer := false
	if w.Case.FormatVersion == 3 {
		if len(w.SourceContinuation) != 0 || w.Case.ProviderPolicyDigest != providerpolicy.FlashDigest || w.Case.AccountingVersion != 2 || workflowcontract.Validate(workflowcontract.BudgetProvider, "typedCase", canonicalBytes(w.Case)) != nil {
			return empty, ErrUntrusted
		}
		budgetDocument = workflowcontract.BudgetProvider
		purpose := childString(childFields(w.Intent), "purpose")
		if purpose == "integrate" {
			selectedChild = workflowcontract.ChildIntegrator
			integrator = true
		} else if purpose == "implement" || purpose == "review" {
			selectedChild = workflowcontract.ChildProvider
			if pin.ChildProductSchemaSHA256 == workflowcontract.SupplierSHA256(workflowcontract.ChildIntegrator) {
				selectedChild = workflowcontract.ChildIntegrator
			}
		} else {
			return empty, ErrUntrusted
		}
		if pin.ChildProductSchemaSHA256 == workflowcontract.SupplierSHA256(workflowcontract.ChildReviewer) {
			selectedChild = workflowcontract.ChildReviewer
			reviewer = purpose == "review"
		}
	}
	if len(w.SourceContinuation) != 0 {
		if _, err := sourceContinuationOpening(w.SourceContinuation, w.Case); err != nil {
			return empty, err
		}
	}
	profile := canonicalBytes([]any{w.Entry.Profile.ProfileRevision, w.Entry.Profile.ProfileDigest})
	if (f.EvidenceClass != "source" && f.EvidenceClass != "live") || pin.EvidenceClass != f.EvidenceClass || !hash.MatchString(f.ConfigDigest) ||
		!sameProduct(pin.Profile, json.RawMessage(profile)) || !sameProduct(pin.Native, w.Applicability.Native) || !sameProduct(pin.Runtime, w.Applicability.Runtime) || !sameProduct(pin.Sandbox, w.Applicability.Sandbox) ||
		pin.AdapterVersion == "" || pin.AdapterVersion == "team-adapter-1" || pin.ChildProductSchemaSHA256 != workflowcontract.SupplierSHA256(selectedChild) ||
		pin.BudgetSchemaSHA256 != workflowcontract.SupplierSHA256(budgetDocument) || Digest(w.ProducerPEM) != w.Root.Producer.KeySHA256 ||
		verifyChildEnvelope(f.Observation, w.Root.Producer.KeyID, w.ProducerPEM) != nil {
		return empty, ErrUntrusted
	}
	var envelope ChildEnvelope[ChildInstalledInputObservation]
	if decode(f.Observation, &envelope) != nil {
		return empty, ErrUntrusted
	}
	q := envelope.Payload
	version := 1
	if reviewer {
		version = 3
		if workflowcontract.ValidateChildReviewer("installedInputEnvelope", f.Observation) != nil {
			return empty, ErrUntrusted
		}
	} else if len(q.Inputs.ArtifactReads) != 0 {
		return empty, ErrUntrusted
	} else if integrator {
		version = 2
		if workflowcontract.ValidateChildIntegrator("installedInputEnvelope", f.Observation) != nil {
			return empty, ErrUntrusted
		}
	} else if len(q.Inputs.IntegrationDelivery) != 0 {
		return empty, ErrUntrusted
	}
	issued, ie := time.Parse(time.RFC3339Nano, q.ObservedAt)
	expiry, ee := time.Parse(time.RFC3339Nano, q.NotAfter)
	assignment := childString(childFields(w.Assignment), "assignmentDigest")
	if q.FormatVersion != version || q.Purpose != "child_product_installed_inputs" || q.EvidenceClass != f.EvidenceClass || q.ConfigDigest != f.ConfigDigest ||
		q.TaskID != w.Applicability.TaskID || q.NodeTokenHash != w.Root.Producer.NodeTokenHash || q.PreparationID != w.Preparation.PreparationID ||
		q.IntentDigest != childString(childFields(w.Intent), "intentDigest") || q.PreparedTupleDigest != w.Preparation.PreparedTupleDigest || q.ApplicabilityDigest != CanonicalDigest(w.Applicability) ||
		!sameProduct(q.Root, w.Root) || q.ConsumerDigest != CanonicalDigest(pin) || ie != nil || ee != nil || issued.After(now) || !now.Before(expiry) || !issued.Before(expiry) || expiry.Sub(issued) > 300*time.Second ||
		(assignment == "" && q.AssignmentDigest != nil) || (assignment != "" && (q.AssignmentDigest == nil || *q.AssignmentDigest != assignment)) {
		return empty, ErrUntrusted
	}
	if workflowcontract.Validate(workflowcontract.ChildProduct, "workload", canonicalBytes(q.Inputs.Workload)) != nil || q.Inputs.SourceReads == nil || q.Inputs.Tools == nil {
		return empty, ErrUntrusted
	}
	if assignment == "" && (len(q.Inputs.SourceReads) != 0 || len(q.Inputs.Tools) != 0 || q.Inputs.ReviewDelivery != nil || !childWireAbsent(q.Inputs.IntegrationDelivery)) {
		return empty, ErrUntrusted
	}
	if reviewer {
		if len(q.Inputs.IntegrationDelivery) != 0 {
			return empty, ErrUntrusted
		}
		var artifacts []json.RawMessage
		if decode(q.Inputs.ArtifactReads, &artifacts) != nil || artifacts == nil ||
			(assignment == "" && len(artifacts) != 0) || (assignment != "" && len(artifacts) != 1) {
			return empty, ErrUntrusted
		}
		if assignment != "" {
			d := q.Inputs.ReviewDelivery
			var compilation model.ReviewInputCompilation
			if d == nil || d.FormatVersion != 2 || decode(childFields(w.Intent)["reviewInput"], &compilation) != nil ||
				model.VerifyReviewerInput(compilation, *d, string(w.Input), now) != nil || !sameProduct(d.Binding, w.Binding) ||
				!sameProduct(d.Assignment, w.Assignment) || d.Intent != w.Handle.Intent || d.InputID != w.Instructions.InputID {
				return empty, ErrUntrusted
			}
		}
	}
	if integrator && assignment != "" {
		var d model.IntegrationDeliveryPlan
		if decode(q.Inputs.IntegrationDelivery, &d) != nil || model.VerifyIntegrationInput(d, w.Input, now) != nil || !sameProduct(d.Binding, w.Binding) || !sameProduct(d.Assignment, w.Assignment) || d.Intent != w.Handle.Intent || d.InputID != w.Instructions.InputID || d.InputDigest != w.Instructions.InputDigest || d.InputByteCount != w.Instructions.InputByteCount {
			return empty, ErrUntrusted
		}
	}
	for _, scope := range q.Inputs.SourceReads {
		var err error
		if reviewer {
			err = workflowcontract.ValidateChildReviewer("physicalSourceScope", canonicalBytes(scope))
		} else if integrator {
			err = workflowcontract.ValidateChildIntegrator("integrationSourceScope", canonicalBytes(scope))
		} else {
			err = workflowcontract.Validate(workflowcontract.ChildProduct, "sourceReadScope", canonicalBytes(scope))
		}
		if err != nil {
			return empty, ErrUntrusted
		}
		for _, wire := range []json.RawMessage{scope.Root, scope.Grant} {
			at, err := time.Parse(time.RFC3339Nano, childString(childFields(wire), "expiresAt"))
			if err != nil || at.After(expiry) || !now.Before(at) {
				return empty, ErrUntrusted
			}
		}
	}
	for _, tool := range q.Inputs.Tools {
		if workflowcontract.Validate(workflowcontract.ChildProduct, "toolScope", canonicalBytes(tool)) != nil {
			return empty, ErrUntrusted
		}
		fields := childFields(tool.InstalledWitness)
		for k, v := range map[string]string{"registryManifestDigest": w.Applicability.Sandbox.RegistryManifestDigest, "imageConfigDigest": w.Applicability.Sandbox.ConfigDigest, "pluginDigest": w.Applicability.Sandbox.PluginDigest, "materializerDigest": w.Applicability.Profile.MaterializerDigest, "candidateDescriptorDigest": w.Root.CandidateDescriptorDigest} {
			if childString(fields, k) != v {
				return empty, ErrUntrusted
			}
		}
	}
	return q.Inputs, nil
}

// Assembly reads three distinct protected owning suppliers twice. It never
// accepts a policy/control argument, supplies empty history or seeds any row.
func assembleChildProductCurrent(ctx context.Context, entry model.CellServiceV3, input []byte, load func(string, int) ([]byte, error), now time.Time) (ChildProductWitness, [][]byte, error) {
	w, originals, err := assembleChildProductOwnerFacts(ctx, entry, input, load, now)
	if err != nil || verifyReviewerFinalFacts(w, now) != nil {
		return ChildProductWitness{}, nil, ErrUntrusted
	}
	return w, originals, nil
}

// Owning backend facts alone are uncredited. This private assembly is used only
// for original export and the existing pre-admission reviewer ROOT-read boundary.
// Current publication/admission always uses the strict wrapper above.
func assembleChildProductOwnerFacts(ctx context.Context, entry model.CellServiceV3, input []byte, load func(string, int) ([]byte, error), now time.Time) (ChildProductWitness, [][]byte, error) {
	var empty ChildProductWitness
	if ctx.Err() != nil || !safeID.MatchString(entry.PreparationID) || load == nil {
		return empty, nil, ErrUntrusted
	}
	names := []string{"child-product-authority-" + entry.PreparationID + ".json", "child-product-installed-" + entry.PreparationID + ".json", "child-product-lifecycle-" + entry.PreparationID + ".json"}
	var a ChildProductAuthorityFacts
	var installed ChildProductInstalledFacts
	var life ChildProductLifecycleFacts
	values := []any{&a, &installed, &life}
	originals := make([][]byte, 3)
	for i, name := range names {
		raw, err := load(name, 512*1024)
		if err != nil || decode(raw, values[i]) != nil || !bytesCanonical(raw, values[i]) {
			return empty, nil, ErrUntrusted
		}
		originals[i] = raw
	}
	tuple, err := entry.PreparedTuple()
	if err != nil {
		return empty, nil, err
	}
	tupleDigest, err := tuple.Digest()
	if err != nil {
		return empty, nil, err
	}
	id := "msg_" + strings.TrimPrefix(entry.NativeSessionID, "ses_")
	w := ChildProductWitness{OperatorKeyID: a.OperatorKeyID, Applicability: installed.Applicability, QualifiedApplicability: a.QualifiedApplicability, Qualification: a.Qualification, Case: a.Case, Scope: a.Scope, Intent: a.Intent, Handle: a.Handle, Root: a.Root, ProducerPEM: installed.ProducerPEM, Preparation: ChildPreparationSelection{PreparationID: entry.PreparationID, PreparedTuple: tuple, PreparedTupleDigest: tupleDigest, SessionID: entry.NativeSessionID, InputID: id}, Instructions: ChildInstructionPin{InstructionRevision: entry.Instructions.InstructionRevision, InstructionDigest: entry.Instructions.InstructionDigest, InputID: id, InputDigest: Digest(input), InputByteCount: len(input)}, ActualReceipt: life.ActualReceipt, Binding: life.Binding, Assignment: life.Assignment, Grant: life.Grant, Authorization: life.Authorization, SigningNotBefore: a.SigningNotBefore, ProductSigningNotBefore: a.ProductSigningNotBefore, ActivationSigningNotBefore: a.ActivationSigningNotBefore, AuthorizedUntil: a.AuthorizedUntil, InstalledTools: map[string]json.RawMessage{}, SourceRoots: map[string]json.RawMessage{}, Input: input, ReviewReads: life.ReviewReads, ArtifactReviewReads: life.ArtifactReviewReads, ReviewCompilation: life.ReviewCompilation, Entry: entry, AcceptedPreparationEnvelope: a.AcceptedPreparationEnvelope, AcceptedDemandEnvelope: a.AcceptedDemandEnvelope}
	if !model.ControllerTextValid(string(input)) || len(input) == 0 || !sameProduct(w.Applicability, w.QualifiedApplicability) || !now.Before(w.AuthorizedUntil) ||
		(entry.LifecyclePhase == "prepare" && childLifecycleHasPreparedFacts(life)) ||
		(entry.LifecyclePhase == "execute" && (life.ActualReceipt == nil || life.ActualReceipt.ValidateFor(entry) != nil || life.Grant == nil || !sameProduct(life.Grant, entry.ExecutionGrant) || life.Authorization == nil)) {
		return empty, nil, ErrUntrusted
	}
	w.SourceContinuation = a.SourceContinuation
	inputs, err := verifyChildInstalledInputs(installed, w, now)
	if err != nil {
		return empty, nil, err
	}
	w.InstalledInputs = &inputs
	w.InstalledFactsDigest = Digest(originals[1])
	for _, scope := range inputs.SourceReads {
		key := CanonicalDigest(scope.Root)
		if old, ok := w.SourceRoots[key]; ok && !sameProduct(old, scope.Root) {
			return empty, nil, ErrUntrusted
		}
		w.SourceRoots[key] = scope.Root
	}
	for _, tool := range inputs.Tools {
		if _, found := w.InstalledTools[tool.NativeToolName]; found {
			return empty, nil, ErrUntrusted
		}
		w.InstalledTools[tool.NativeToolName] = tool.InstalledWitness
	}
	for i, name := range names {
		again, err := load(name, 512*1024)
		if err != nil || string(again) != string(originals[i]) || ctx.Err() != nil {
			return empty, nil, ErrUntrusted
		}
	}
	return w, originals, nil
}

// Publish only after the SAME complete installed reader/archive/self check. The
// independent SOURCE fixture may exercise assembly, not turn SOURCE into LIVE.
func (p *Producer) PublishCurrentChildProductWitness(ctx context.Context, entry model.CellServiceV3, current model.Manifest, input []byte) error {
	if p == nil || rootPrivate(p.config.EvidenceRoot, true) != nil {
		return ErrUntrusted
	}
	lockPath := filepath.Join(p.config.EvidenceRoot, "child-product-current-publication.lock")
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if rootPrivate(lockPath, false) != nil || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return ErrUntrusted
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	w, _, err := assembleChildProductCurrent(ctx, entry, input, p.read, time.Now())
	if err != nil {
		return err
	}
	if err = p.verifyChildProductCurrentInstallation(ctx, w, entry, current, input); err != nil {
		return err
	}
	name := "child-product-current-" + entry.PreparationID + ".json"
	raw := canonicalBytes(w)
	if _, statErr := os.Lstat(filepath.Join(p.config.EvidenceRoot, name)); statErr == nil {
		prior, err := p.read(name, 512*1024)
		if err != nil {
			return err
		}
		if string(prior) == string(raw) {
			return nil
		}
		var old ChildProductWitness
		if decode(prior, &old) != nil || old.Entry.LifecyclePhase != "prepare" || entry.LifecyclePhase != "execute" || !sameProduct(old.Handle, w.Handle) || !sameProduct(old.Preparation, w.Preparation) || !sameProduct(old.Instructions, w.Instructions) || !sameProduct(old.Applicability, w.Applicability) || !sameProduct(old.AcceptedPreparationEnvelope, w.AcceptedPreparationEnvelope) || !sameProduct(old.AcceptedDemandEnvelope, w.AcceptedDemandEnvelope) || !sameProduct(old.SourceContinuation, w.SourceContinuation) || !sameProduct(old.Case, w.Case) || !sameProduct(old.Scope, w.Scope) || !sameProduct(old.Intent, w.Intent) || !sameProduct(old.Root, w.Root) || !sameProduct(old.Qualification, w.Qualification) || !sameProduct(old.QualifiedApplicability, w.QualifiedApplicability) || old.OperatorKeyID != w.OperatorKeyID || !sameProduct(old.ProducerPEM, w.ProducerPEM) || !old.SigningNotBefore.Equal(w.SigningNotBefore) || !old.AuthorizedUntil.Equal(w.AuthorizedUntil) {
			return ErrUntrusted
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	if len(raw) > 512*1024 {
		return ErrUntrusted
	}
	digest := Digest(raw)[7:]
	if err = p.append("child-product-current-"+entry.PreparationID+"-"+digest+".json", raw); err != nil {
		return err
	}
	stage := "child-product-current-publication-" + digest + ".json"
	// A previous staged-but-unpublished record is interrupted/UNKNOWN, not a
	// replacement permission. Every staged original is retained on failure.
	if err = p.create(stage, raw); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err = os.Rename(filepath.Join(p.config.EvidenceRoot, stage), filepath.Join(p.config.EvidenceRoot, name)); err != nil {
		return err
	}
	d, err := os.Open(p.config.EvidenceRoot)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
