package qualification

import (
	"encoding/json"
	"time"
)

// The native hook original and the backend evidence projection are different
// records. Validate the complete original first, then derive the exact existing
// ten-field import observation. Its original bytes stay in the same blob set.
func qualificationToolImportObservation(policy Policy, d Descriptor, selected QualificationActivation, o Observations, workspaceDigest string, blobs map[string][]byte) ([]byte, error) {
	if policy.FormatVersion != 4 || len(policy.Preparations) != 1 || len(o.Requests) != 2 || !hash.MatchString(workspaceDigest) {
		return nil, ErrUntrusted
	}
	raw := blobs[o.Tool.ObservationDigest]
	var original map[string]json.RawMessage
	if decode(raw, &original) != nil || len(original) != 12 || Digest(raw) != o.Tool.ObservationDigest {
		return nil, ErrUntrusted
	}
	var basis struct {
		FormatVersion         int    `json:"formatVersion"`
		AssistantMessageID    string `json:"assistantMessageId"`
		InputID               string `json:"inputId"`
		CallID                string `json:"callId"`
		CalledSeq             int64  `json:"calledSeq"`
		PreparedReceiptDigest string `json:"preparedReceiptDigest"`
		GrantDigest           string `json:"grantDigest"`
	}
	if decodeClosed(original["nativeBasis"], &basis) != nil || basis.FormatVersion != 1 || basis.InputID != policy.Preparations[0].InputID || basis.CallID != o.Tool.CallID || basis.CalledSeq < 1 || !safeID.MatchString(basis.AssistantMessageID) || basis.AssistantMessageID == basis.InputID || basis.PreparedReceiptDigest != selected.Execution.PreparedReceiptDigest || basis.GrantDigest != selected.Execution.GrantDigest {
		return nil, ErrUntrusted
	}
	projection := childFields(canonicalBytes(o.Tool))
	delete(projection, "observationDigest")
	delete(original, "nativeBasis") // local decoded view only; raw blob is unchanged.
	if !sameProduct(original, projection) {
		return nil, ErrUntrusted
	}
	var arguments any
	output := canonicalBytes(o.Tool.ModelOutput)
	if decode([]byte(o.Tool.Arguments), &arguments) != nil || CanonicalDigest(arguments) != o.Tool.ArgumentsDigest || !sameProduct(blobs[o.Tool.ArgumentsDigest], canonicalBytes(arguments)) || Digest(output) != o.Tool.OutputDigest {
		return nil, ErrUntrusted
	}
	if prior, ok := blobs[o.Tool.OutputDigest]; ok && Digest(prior) != o.Tool.OutputDigest {
		return nil, ErrUntrusted
	}
	start, se := time.Parse(time.RFC3339Nano, o.Tool.StartedAt)
	end, ee := time.Parse(time.RFC3339Nano, o.Tool.CompletedAt)
	first, fe := time.Parse(time.RFC3339Nano, o.Requests[0].CompletedAt)
	second, xe := time.Parse(time.RFC3339Nano, o.Requests[1].StartedAt)
	if se != nil || ee != nil || fe != nil || xe != nil || start.After(end) || end.Before(first) || end.After(second) {
		return nil, ErrUntrusted
	}
	// The collector retains modelOutput inside the complete hook original.
	// Backend import also reads that value by digest, so derive its canonical
	// blob from the validated original without rewriting any collected bytes.
	blobs[o.Tool.OutputDigest] = output
	return canonicalBytes(map[string]any{"preparationId": d.PreparationID, "toolCallId": o.Tool.CallID, "tool": "shell", "argumentsDigest": o.Tool.ArgumentsDigest, "workspaceDigest": workspaceDigest, "exitCode": o.Tool.Exit, "truncated": o.Tool.Truncated, "timedOut": o.Tool.Timeout, "outputDigest": o.Tool.OutputDigest, "observedAt": o.Tool.CompletedAt}), nil
}
