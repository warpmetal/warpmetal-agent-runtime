package qualification

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// The fixed Sandbox reader supplies original completed native bytes; the ROOT
// producer independently rereads signed current control and its owning scope.
// This only permits the subsequent separate whole-file artifact read.
func childResultArtifactAllowed(w ChildWorkflowObservationWitness, q ChildProductPolicy, path, digest string, count int64) bool {
	if !childCompletionPolicy(q) {
		return false
	}
	current, err := w.Authority.ReadChildProduct(w.Sandbox, w.Product.Preparation.PreparationID, w.Product, time.Now())
	if err != nil || current.Generation.Policy == nil || !sameProduct(current.Generation.Policy.Payload, q) {
		return false
	}
	var artifact model.ChildNativeFileSnapshot
	switch q.Purpose {
	case "coding_worker":
		capture := w.OriginalResult
		if capture == nil || q.Workload.Kind != "coding2" || q.Workload.TerminalOutput != "result" || capture.ValidateFor(w.Product.Entry, current.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest) != nil {
			return false
		}
		artifact = capture.Artifact
	case "integrator":
		capture := w.OriginalIntegration
		if capture == nil || q.Workload.Kind != "integration2" || q.Workload.TerminalOutput != "integration_candidate" || capture.ValidateFor(w.Product.Entry, current.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest) != nil {
			return false
		}
		artifact = capture.Artifact
		if q.FormatVersion == 3 {
			if q.IntegrationDelivery == nil {
				return false
			}
			found := false
			for _, span := range q.IntegrationDelivery.Spans {
				if span.Kind == "target_artifact" && capture.Before.SourcePath == span.Reference.Path && capture.Before.Digest == span.Reference.SourceDigest && capture.Before.ByteCount == span.ByteCount {
					found = true
				}
			}
			if !found {
				return false
			}
		}
	default:
		return false
	}
	if artifact.SourcePath != path || artifact.Digest != digest || int64(artifact.ByteCount) != count {
		return false
	}
	var intent struct {
		PrepareBody struct {
			Content struct {
				Packet struct {
					WriteScope struct {
						Mode  string   `json:"mode"`
						Paths []string `json:"paths"`
					} `json:"writeScope"`
				} `json:"workflowPacket"`
			} `json:"content"`
		} `json:"prepareBody"`
	}
	if json.Unmarshal(w.Product.Intent, &intent) != nil || intent.PrepareBody.Content.Packet.WriteScope.Mode != "exclusive" {
		return false
	}
	for _, root := range intent.PrepareBody.Content.Packet.WriteScope.Paths {
		if root != "" && (path == root || strings.HasPrefix(path, root+"/")) {
			return true
		}
	}
	return false
}
