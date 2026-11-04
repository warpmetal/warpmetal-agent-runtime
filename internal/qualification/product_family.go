package qualification

import (
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// qualificationFamily selects the immutable signed contract family for a
// decoded native qualification bundle.
//
// It is additive and fail-closed:
//   - formatVersion 3 keeps the original native-v3/provider-v2 resources and
//     behavior byte-identical;
//   - formatVersion 5 selects the already-embedded authority5 family
//     (native-v5/provider-v4), whose pins live in the participant registry;
//   - any other family returns ok=false so callers refuse.
func qualificationFamily(c *RealCase) (nativeContract, sourceContract string, ok bool) {
	if c == nil {
		return "", "", false
	}
	switch c.FormatVersion {
	case 3:
		return workflowcontract.QualificationNative, workflowcontract.QualificationPublicationProvider, true
	case 5:
		return workflowcontract.QualificationNativeAuthority5,
			workflowcontract.QualificationPublicationProviderAuthority5, true
	default:
		return "", "", false
	}
}

// qualificationProviderDescriptor returns the exact immutable provider
// descriptor pinned by the bundle family. Unknown families fail closed.
func qualificationProviderDescriptor(c *RealCase) (providerpolicy.Descriptor, bool) {
	if c == nil {
		return providerpolicy.Descriptor{}, false
	}
	switch c.FormatVersion {
	case 3:
		return providerpolicy.Select(providerpolicy.FlashDigest)
	case 5:
		return providerpolicy.Select(providerpolicy.ParticipantDigest)
	default:
		return providerpolicy.Descriptor{}, false
	}
}
