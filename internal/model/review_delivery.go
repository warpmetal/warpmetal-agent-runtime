package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type ReviewInputCompilation struct {
	InputID        string          `json:"inputId"`
	InputDigest    string          `json:"inputDigest"`
	InputByteCount int             `json:"inputByteCount"`
	Candidate      json.RawMessage `json:"candidate"`
	ManifestDigest string          `json:"manifestDigest"`
}
type ReviewByteSpan struct {
	Kind                    string                  `json:"kind"`
	Reference               ControllerPlanReference `json:"reference"`
	Artifact                json.RawMessage         `json:"artifact"`
	RootGrantDigest         string                  `json:"rootGrantDigest,omitempty"`
	ArtifactAuthorityDigest string                  `json:"artifactAuthorityDigest,omitempty"`
	Encoding                string                  `json:"encoding"`
	ByteCount               int                     `json:"byteCount"`
	Offset                  int                     `json:"offset"`
	Length                  int                     `json:"length"`
}
type ReviewDeliveryPlan struct {
	FormatVersion      int              `json:"formatVersion"`
	DeliveryPlanID     string           `json:"deliveryPlanId"`
	DeliveryPlanDigest string           `json:"deliveryPlanDigest"`
	Intent             IntentRef        `json:"intent"`
	Binding            json.RawMessage  `json:"binding"`
	Assignment         json.RawMessage  `json:"assignment"`
	Target             json.RawMessage  `json:"target"`
	Candidate          json.RawMessage  `json:"candidate"`
	InputID            string           `json:"inputId"`
	InputDigest        string           `json:"inputDigest"`
	InputByteCount     int              `json:"inputByteCount"`
	Spans              []ReviewByteSpan `json:"spans"`
	AssessmentPath     string           `json:"assessmentPath"`
	NotAfter           string           `json:"notAfter"`
}

// Bytes are from an actual complete protected root read, not author compilation
// credit. Current root/signature/receipt verification remains the producer's job;
// this integrity consumer cannot mint a source-read or delivery receipt.
type ReviewReadWitness struct {
	Bytes         []byte
	SourceGrant   json.RawMessage
	NativeReceipt json.RawMessage
	ReadReceipt   json.RawMessage
}

// Immutable target reads have their own authority and custody. The target's
// path describes authorship; it is never a live workspace SourceGrant.
type ArtifactReviewReadWitness struct {
	Bytes             []byte
	ArtifactAuthority json.RawMessage
	NativeReceipt     json.RawMessage
	ReadReceipt       json.RawMessage
}

// Input compilation integrity can be checked before actual preparation/ROOT
// reads. It conveys NO reviewer-read, native delivery or dispatch credit.
func VerifyReviewerInput(compilation ReviewInputCompilation, plan ReviewDeliveryPlan, firstText string, now time.Time) error {
	bad := errors.New("review byte delivery refused")
	for _, value := range []struct {
		name  string
		value any
	}{{"reviewInputCompilation", compilation}, {"reviewDeliveryPlan", plan}} {
		raw, err := json.Marshal(value.value)
		if err != nil {
			return bad
		}
		if value.name == "reviewDeliveryPlan" && plan.FormatVersion == 2 {
			err = workflowcontract.ValidateChildReviewer(value.name, raw)
		} else {
			err = workflowcontract.Validate(workflowcontract.Manager, value.name, raw)
		}
		if err != nil {
			return bad
		}
	}
	if !ControllerTextValid(firstText) || plan.InputID != compilation.InputID || plan.InputDigest != compilation.InputDigest || plan.InputByteCount != compilation.InputByteCount ||
		len(firstText) != plan.InputByteCount || fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(firstText))) != plan.InputDigest || !sameWorkflowFact(plan.Candidate, compilation.Candidate) {
		return bad
	}
	expires, err := time.Parse(time.RFC3339Nano, plan.NotAfter)
	if err != nil || !now.Before(expires) {
		return bad
	}
	raw, _ := json.Marshal(plan)
	fields := workflowObject(raw)
	delete(fields, "deliveryPlanDigest")
	if WorkspaceDigest(fields) != plan.DeliveryPlanDigest {
		return bad
	}
	binding, assignment := workflowObject(plan.Binding), workflowObject(plan.Assignment)
	if workflowString(assignment["purpose"]) != "review" || !sameWorkflowFact(assignment["target"], plan.Target) || !sameWorkflowFact(assignment["executionId"], binding["executionId"]) {
		return bad
	}
	ordered := append([]ReviewByteSpan(nil), plan.Spans...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	end := 0
	for _, span := range ordered {
		if span.Offset < end || span.Offset+span.Length > len(firstText) {
			return bad
		}
		end = span.Offset + span.Length
		if _, err := reviewSpanInputBytes(span, firstText); err != nil {
			return bad
		}
	}
	return nil
}

func reviewSpanInputBytes(span ReviewByteSpan, firstText string) ([]byte, error) {
	bad := errors.New("review span bytes refused")
	if span.Offset < 0 || span.Length < 0 || span.Offset+span.Length > len(firstText) || span.ByteCount < 0 || span.ByteCount > 16384 || span.Reference.Status == "unavailable" {
		return nil, bad
	}
	fragment := []byte(firstText)[span.Offset : span.Offset+span.Length]
	var decoded string
	if json.Unmarshal(append(append([]byte{'"'}, fragment...), '"'), &decoded) != nil || len(decoded) != span.ByteCount || !utf8.ValidString(decoded) || fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(decoded))) != span.Reference.SourceDigest {
		return nil, bad
	}
	canonical, err := WorkspaceCanonicalJSON(decoded)
	if err != nil || string(canonical[1:len(canonical)-1]) != string(fragment) {
		return nil, bad
	}
	return []byte(decoded), nil
}

// VerifyReviewerDelivery never appends/reformats the immutable firstText. It
// requires separate WHOLE original ROOT reads and reviewer-bound settled
// observations. Input-only integrity NEVER satisfies this native admission gate.
func VerifyReviewerDelivery(compilation ReviewInputCompilation, plan ReviewDeliveryPlan, firstText string, reads []ReviewReadWitness, now time.Time) error {
	bad := errors.New("review byte delivery refused")
	if VerifyReviewerInput(compilation, plan, firstText, now) != nil || len(reads) != len(plan.Spans) {
		return bad
	}
	ids := map[string]bool{}
	for i, span := range plan.Spans {
		if verifyReviewPhysicalRead(compilation, plan, firstText, span, reads[i], now) != nil || !uniqueReviewReceipt(ids, reads[i].ReadReceipt) {
			return bad
		}
	}
	return nil
}

func verifyReviewPhysicalRead(compilation ReviewInputCompilation, plan ReviewDeliveryPlan, firstText string, span ReviewByteSpan, read ReviewReadWitness, now time.Time) error {
	bad := errors.New("review byte delivery refused")
	assignment := workflowObject(plan.Assignment)
	if len(read.Bytes) != span.ByteCount || !utf8.Valid(read.Bytes) || len(read.Bytes) > 16384 || span.Reference.Status == "unavailable" {
		return bad
	}
	originalDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(read.Bytes))
	if originalDigest != span.Reference.SourceDigest {
		return bad
	}
	expected, err := reviewSpanInputBytes(span, firstText)
	if err != nil || !bytes.Equal(expected, read.Bytes) {
		return bad
	}
	if workflowcontract.Validate(workflowcontract.Manager, "useSpecificSourceGrant", read.SourceGrant) != nil ||
		workflowcontract.Validate(workflowcontract.Producer, "nativeReceipt", read.NativeReceipt) != nil ||
		workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", read.ReadReceipt) != nil {
		return bad
	}
	grant := workflowObject(read.SourceGrant)
	use := map[string]string{"packet_source": "review_packet_source", "target_artifact": "review_target_artifact", "candidate_source": "review_candidate_source"}[span.Kind]
	ref, _ := json.Marshal(span.Reference)
	if use == "" || workflowString(grant["use"]) != use || !sameWorkflowFact(grant["binding"], plan.Binding) || !sameWorkflowFact(grant["assignmentId"], assignment["assignmentId"]) ||
		!sameWorkflowFact(grant["reference"], ref) || !sameWorkflowFact(grant["artifact"], span.Artifact) || workflowInteger(grant["byteCount"]) != int64(span.ByteCount) ||
		workflowString(grant["rootGrantDigest"]) != span.RootGrantDigest || workflowString(grant["manifestDigest"]) != compilation.ManifestDigest {
		return bad
	}
	grantExpiry, err := time.Parse(time.RFC3339Nano, workflowString(grant["expiresAt"]))
	if err != nil || !now.Before(grantExpiry) {
		return bad
	}
	if span.Kind == "candidate_source" && !sameWorkflowFact(grant["candidate"], plan.Candidate) {
		return bad
	}
	if string(span.Artifact) != "null" {
		artifact := workflowObject(span.Artifact)
		if workflowString(artifact["digest"]) != originalDigest || workflowInteger(artifact["byteCount"]) != int64(len(read.Bytes)) {
			return bad
		}
	}
	return verifyReviewReadReceipt(plan, span, read.Bytes, read.NativeReceipt, read.ReadReceipt)
}

func verifyReviewReadReceipt(plan ReviewDeliveryPlan, span ReviewByteSpan, body []byte, nativeRaw, receiptRaw json.RawMessage) error {
	bad := errors.New("review byte delivery refused")
	if workflowcontract.Validate(workflowcontract.Producer, "nativeReceipt", nativeRaw) != nil || workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", receiptRaw) != nil {
		return bad
	}
	binding, native, receipt := workflowObject(plan.Binding), workflowObject(nativeRaw), workflowObject(receiptRaw)
	ref, _ := json.Marshal(span.Reference)
	originalDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	if workflowString(native["role"]) != "reviewer" || !sameWorkflowFact(native["nativeSessionId"], binding["nativeSessionId"]) ||
		!sameWorkflowFact(native["nativeProjectId"], binding["nativeProjectId"]) ||
		!sameWorkflowFact(native["serviceRegistrationId"], binding["serviceRegistrationId"]) || !sameWorkflowFact(native["serviceGeneration"], binding["serviceGeneration"]) ||
		!sameWorkflowFact(native["nativeLocationDigest"], binding["nativeLocationDigest"]) || !sameWorkflowFact(native["rootAttestation"], binding["rootAttestation"]) ||
		!sameWorkflowFact(receipt["executionId"], binding["executionId"]) || workflowString(receipt["status"]) != "settled" {
		return bad
	}
	readback := workflowObject(native["readback"])
	observation := workflowObject(readback["observation"])
	if !sameWorkflowFact(readback["binding"], plan.Binding) {
		return bad
	}
	kind := workflowString(observation["type"])
	if kind == "source_read" {
		if !sameWorkflowFact(observation["reference"], ref) || workflowString(observation["observedDigest"]) != originalDigest {
			return bad
		}
	} else if kind == "artifact_read" {
		if workflowString(observation["sourcePath"]) != span.Reference.Path || workflowString(observation["digest"]) != originalDigest {
			return bad
		}
	} else {
		return bad
	}
	if workflowInteger(observation["byteCount"]) != int64(len(body)) || workflowString(receipt["type"]) != kind {
		return bad
	}
	return nil
}

func uniqueReviewReceipt(ids map[string]bool, raw json.RawMessage) bool {
	id := workflowString(workflowObject(raw)["receiptId"])
	if id == "" || ids[id] {
		return false
	}
	ids[id] = true
	return true
}

// VerifyReviewerDeliveryOriginals keeps immutable artifact custody separate
// from physical workspace reads. Both still require this reviewer's own ACKs.
func VerifyReviewerDeliveryOriginals(compilation ReviewInputCompilation, plan ReviewDeliveryPlan, firstText string, reads []ReviewReadWitness, artifacts []ArtifactReviewReadWitness, now time.Time) error {
	bad := errors.New("review byte delivery refused")
	if plan.FormatVersion == 1 {
		if len(artifacts) != 0 {
			return bad
		}
		return VerifyReviewerDelivery(compilation, plan, firstText, reads, now)
	}
	if plan.FormatVersion != 2 || VerifyReviewerInput(compilation, plan, firstText, now) != nil || len(artifacts) != 1 || len(reads)+1 != len(plan.Spans) {
		return bad
	}
	ids := map[string]bool{}
	physical, target := 0, 0
	for _, span := range plan.Spans {
		if span.Kind == "target_artifact" {
			target++
			if target != 1 || verifyReviewArtifactRead(compilation, plan, firstText, span, artifacts[0], now) != nil || !uniqueReviewReceipt(ids, artifacts[0].ReadReceipt) {
				return bad
			}
		} else {
			if physical >= len(reads) || span.ArtifactAuthorityDigest != "" || verifyReviewPhysicalRead(compilation, plan, firstText, span, reads[physical], now) != nil || !uniqueReviewReceipt(ids, reads[physical].ReadReceipt) {
				return bad
			}
			physical++
		}
	}
	if target != 1 || physical != len(reads) {
		return bad
	}
	return nil
}

func verifyReviewArtifactRead(compilation ReviewInputCompilation, plan ReviewDeliveryPlan, firstText string, span ReviewByteSpan, read ArtifactReviewReadWitness, now time.Time) error {
	bad := errors.New("review byte delivery refused")
	if workflowcontract.ValidateChildReviewer("artifactAuthority", read.ArtifactAuthority) != nil || span.RootGrantDigest != "" || WorkspaceDigest(json.RawMessage(read.ArtifactAuthority)) != span.ArtifactAuthorityDigest || len(read.Bytes) > 8192 {
		return bad
	}
	a, assignment := workflowObject(read.ArtifactAuthority), workflowObject(plan.Assignment)
	ref, _ := json.Marshal(span.Reference)
	artifact := workflowObject(a["artifact"])
	if !sameWorkflowFact(a["binding"], plan.Binding) || !sameWorkflowFact(a["assignmentId"], assignment["assignmentId"]) || !sameWorkflowFact(a["target"], plan.Target) || !sameWorkflowFact(a["candidate"], plan.Candidate) || !sameWorkflowFact(a["reference"], ref) || !sameWorkflowFact(a["artifact"], span.Artifact) || workflowString(a["manifestDigest"]) != compilation.ManifestDigest || workflowInteger(artifact["byteCount"]) != int64(span.ByteCount) || span.ByteCount != len(read.Bytes) || workflowString(artifact["digest"]) != span.Reference.SourceDigest {
		return bad
	}
	expires, err := time.Parse(time.RFC3339Nano, workflowString(a["expiresAt"]))
	if err != nil || !now.Before(expires) {
		return bad
	}
	expected, err := reviewSpanInputBytes(span, firstText)
	if err != nil || !bytes.Equal(expected, read.Bytes) {
		return bad
	}
	// This rootless authority is consumed only by the existing source_read
	// proof, whose native root describes the reviewer execution context.
	native := workflowObject(read.NativeReceipt)
	if workflowString(workflowObject(workflowObject(native["readback"])["observation"])["type"]) != "source_read" {
		return bad
	}
	return verifyReviewReadReceipt(plan, span, read.Bytes, read.NativeReceipt, read.ReadReceipt)
}
