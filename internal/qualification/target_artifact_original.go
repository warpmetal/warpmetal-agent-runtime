package qualification

import (
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Owning single document/analysis target, shared by same-path integration staging
// and immutable reviewer storage. This verifies provenance/bytes, never a root.
func verifyTargetArtifactOriginal(target, binding, artifact, detail json.RawMessage, body []byte) error {
	if workflowcontract.Validate(workflowcontract.Domain, "resultDetail", detail) != nil {
		return ErrUntrusted
	}
	f := childFields(detail)
	receipt := childFields(f["receipt"])
	pin := childFields(target)
	result := childFields(f["result"])
	if !sameProduct(f["binding"], binding) || !sameProduct(receipt["executionId"], childFields(binding)["executionId"]) || !sameProduct(f["assignmentId"], receipt["assignmentId"]) ||
		childString(receipt, "state") != "reported" || childString(result, "outcome") != "completed" ||
		childString(pin, "resultDigest") != CanonicalDigest(map[string]any{"binding": f["binding"], "assignmentId": f["assignmentId"], "result": f["result"]}) {
		return ErrUntrusted
	}
	for _, key := range []string{"resultId", "resultRevision", "resultDigest"} {
		if !sameProduct(pin[key], receipt[key]) {
			return ErrUntrusted
		}
	}
	// Selected normal lane is one document/analysis result with one complete
	// output artifact. No invented coding/Git result or generalized file upload.
	var outputs []json.RawMessage
	if json.Unmarshal(result["outputs"], &outputs) != nil || len(outputs) != 1 {
		return ErrUntrusted
	}
	output := childFields(outputs[0])
	kind := childString(output, "type")
	if (kind != "document" && kind != "analysis") || !sameProduct(output["output"], artifact) {
		return ErrUntrusted
	}
	for _, key := range []string{"stateEvidence", "mismatches", "remainingWork"} {
		var values []json.RawMessage
		if json.Unmarshal(result[key], &values) != nil || len(values) != 0 {
			return ErrUntrusted
		}
	}

	fields := childFields(artifact)
	if len(body) < 1 || len(body) > 8192 || int64(len(body)) != childInteger(fields, "byteCount") || Digest(body) != childString(fields, "digest") {
		return ErrUntrusted
	}
	return nil
}
