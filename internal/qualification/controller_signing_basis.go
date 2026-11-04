package qualification

import (
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// ControllerActivationFromSigningBasis joins the committed backend basis to a
// separately verified CURRENT context and ROOT header observation. It never
// signs or publishes. The owning reconciler validates the complete context via
// Policy.ValidateContext before this seam; the backend cannot supply issuedAt or
// manufacture authorizationSha256 here. Each activation/context version keeps
// its existing policy-selected meaning.
func ControllerActivationFromSigningBasis(raw []byte, notBefore, authorization string, p ControllerPolicy, c model.ControllerApprovedInputContext, now time.Time) (ControllerActivation, error) {
	var empty, a ControllerActivation
	if len(raw) == 0 || len(raw) > 65536 || decode(raw, &a) != nil || !hash.MatchString(authorization) {
		return empty, ErrUntrusted
	}
	// Comparing the closed, version-selected representation catches omitted
	// required fields as well as unsigned extra fields and backend header/time.
	var fields map[string]json.RawMessage
	if decode(canonicalBytes(a), &fields) != nil {
		return empty, ErrUntrusted
	}
	delete(fields, "authorizationSha256")
	delete(fields, "issuedAt")
	if CanonicalDigest(fields) != CanonicalDigest(json.RawMessage(raw)) {
		return empty, ErrUntrusted
	}
	a.AuthorizationSHA256, a.IssuedAt = authorization, notBefore
	if a.validate(p, now) != nil || c.PolicyDigest != a.PolicyDigest || c.CaseID != p.Case.CaseID || c.CaseManifestDigest != p.Case.CaseManifestDigest {
		return empty, ErrUntrusted
	}
	if a.ValidateContext(p, c) != nil {
		return empty, ErrUntrusted
	}
	return a, nil
}
