package qualification

import (
	"encoding/base64"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
)

// The selected protected sidecar supplies authority; collector observations can
// only report it. Backend policy identity is distinct from native policy identity.
func qualificationObservationBinding(policy Policy, d Descriptor, selected QualificationActivation, o Observations) (string, string, int, error) {
	a := selected.Execution
	if policy.FormatVersion != 4 {
		if selected.Native != nil || o.FormatVersion != 1 || o.Activation == nil || o.PolicyDigest != d.PolicyDigest || !sameProduct(*o.Activation, a) {
			return "", "", 0, ErrUntrusted
		}
		return d.PolicyDigest, RealModel, a.DispatchStart, nil
	}
	allocation := selected.PhysicalAllocation
	if selected.Native == nil || selected.Publication == nil || o.FormatVersion != 2 || o.Activation != nil || o.NativeActivation == nil || !sameProduct(*o.NativeActivation, *selected.Publication) || policy.SourcePolicy == nil || o.SourcePolicyDigest != policy.SourcePolicy.Digest || o.SidecarPolicyDigest != d.PolicyDigest || a.PolicyDigest != o.SourcePolicyDigest || selected.Native.SidecarPolicyDigest != d.PolicyDigest || selected.Native.SourcePolicyDigest != o.SourcePolicyDigest || allocation == nil || allocation.Kind != "qualification" || policy.Run == nil || allocation.TupleDigest != policy.Run.TupleDigest || allocation.PreparationOrdinal != a.PreparationIndex || allocation.ModelRequests != 2 || allocation.AccessRequests != 0 || allocation.LastPhysicalIndex != allocation.FirstPhysicalIndex+1 {
		return "", "", 0, ErrUntrusted
	}
	if len(o.Requests) != 2 {
		return "", "", 0, ErrUntrusted
	}
	for index, r := range o.Requests {
		wire, err := base64.StdEncoding.Strict().DecodeString(o.Blobs[r.WireResponseDigest])
		if err != nil || Digest(wire) != r.WireResponseDigest {
			return "", "", 0, ErrUntrusted
		}
		id, cost, err := physicalgate.ProviderResponseUsage(policy.ProviderPolicyDigest, wire, r.HTTPStatus)
		if err != nil || id != r.ResponseID || cost != r.ActualUSDMicros || r.PhysicalIndex != allocation.FirstPhysicalIndex+index {
			return "", "", 0, ErrUntrusted
		}
	}
	return o.SourcePolicyDigest, providerpolicy.Flash().ModelID, allocation.FirstPhysicalIndex, nil
}

// Caller has joined Store signatures and current installed/native facts; this
// preserves both original activation forms through the existing owning signer.
func (p *Producer) AttestQualification(policy Policy, d Descriptor, selected QualificationActivation, o Observations, terminalReportDigest, root string, device, inode uint64, workspaceDigest string, now time.Time) (string, error) {
	return p.attestQualification(policy, d, selected, o, terminalReportDigest, root, device, inode, workspaceDigest, now)
}

func qualificationRequestCost(r RequestObservation, flash bool) (int64, bool) {
	if !flash {
		return cost(r)
	}
	p := providerpolicy.Flash()
	if r.InputTokens < 0 || r.InputTokens > int64(p.Request.InputTokenUpperBound) || r.OutputTokens < 0 || r.OutputTokens > int64(p.Request.MaxOutputTokens) || r.CachedInputTokens < 0 || r.CachedInputTokens > r.InputTokens {
		return 0, false
	}
	return (r.InputTokens*p.Accounting.InputMicrosPerMillion + r.OutputTokens*p.Accounting.OutputMicrosPerMillion + 999999) / 1000000, true
}
