package continuity

import (
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// handoffSourceRegistrationFirstFalseClause mirrors the exact conjunction
// order of handoffSourceRegistrationExact for evidence purposes only: the A45
// RED proof pins that the historical finish predecessor / current successor
// pair fails the conjunction first on the binding revision and then on the
// scope revision before any other fence is consulted.
func handoffSourceRegistrationFirstFalseClause(registration *state.LocalContinuityRegistration, binding model.ContinuationBindingRefV1, manifest model.ContinuationHandoffManifestV1) string {
	switch {
	case registration == nil:
		return "registration"
	case registration.ObservedStatus != "verified":
		return "observedStatus"
	case !registration.Manifest.ContinuityEnabled:
		return "continuityEnabled"
	case registration.Manifest.DesiredState != "active":
		return "desiredState"
	case registration.Manifest.Binding.BindingRevision != binding.BindingRevision:
		return "bindingRevision"
	case registration.Manifest.ScopeRevision != binding.ScopeRevision:
		return "scopeRevision"
	case registration.ServiceGeneration != binding.ServiceGeneration:
		return "serviceGeneration"
	case !sameS2Identity(registration.Manifest.Identity, manifest.Identity):
		return "identity"
	case !sameS2Binding(registration.Manifest.Binding, binding):
		return "binding"
	default:
		return ""
	}
}

// TestHandoffSourceRegistrationExactClauseOrder characterizes the pre-existing
// exactness conjunction the ready handoff source re-observation uses: the
// stored handoff binding is the historical predecessor (binding revision 1,
// scope 2), and the local durable successor (binding revision 2, scope 3) fails
// first on the binding revision; once only the revision matches, the next false
// clause is the scope revision; only the exact predecessor tuple passes. The
// walker must agree with the production conjunction for every shape.
func TestHandoffSourceRegistrationExactClauseOrder(t *testing.T) {
	predecessor := model.ContinuationBindingRefV1{
		BindingID: "binding_finish_rev1_00001", BindingRevision: 1, ScopeRevision: 2,
		ServiceRegistrationID: "service_finish_rev1_00001", ServiceGeneration: 1,
		RegisteredSourceID: "source_finish_rev1_00001", NativeSessionID: "ses_finish_rev1_00001",
		NativeProjectID:      "0123456789abcdef0123456789abcdef01234567",
		NativeLocationDigest: "sha256:" + strings.Repeat("a", 64),
	}
	registrationIdentity := model.ContinuityIdentityV1{
		WorkID: "work_finish_rev1_00001", ProjectID: "project_finish_rev1_00001",
		SandboxID: "sbx_managedservice00000001", WorkspaceEpoch: "epoch_finish_rev1_00001",
		SandboxGeneration: 2, ExpectedRevision: 1,
	}
	manifest := model.ContinuationHandoffManifestV1{
		FormatVersion: 1, OperationID: "op_finish_handoff0001",
		Identity: model.ContinuationIdentityV1{
			WorkID: registrationIdentity.WorkID, ProjectID: registrationIdentity.ProjectID,
			SandboxID: registrationIdentity.SandboxID, WorkspaceEpoch: registrationIdentity.WorkspaceEpoch,
			SandboxGeneration: registrationIdentity.SandboxGeneration, ExpectedRevision: registrationIdentity.ExpectedRevision,
		},
		Binding: predecessor,
	}
	successor := func(revision, scope int64) *state.LocalContinuityRegistration {
		return &state.LocalContinuityRegistration{
			Manifest: model.ContinuityRegistrationV1{
				FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: scope,
				Identity: registrationIdentity,
				Binding: model.ContinuityBindingV1{
					BindingID: predecessor.BindingID, BindingRevision: revision,
					RegisteredSourceID: predecessor.RegisteredSourceID, ServiceRegistrationID: predecessor.ServiceRegistrationID,
					NativeSessionID: predecessor.NativeSessionID, NativeProjectID: predecessor.NativeProjectID,
					NativeLocationDigest: predecessor.NativeLocationDigest,
				},
			},
			ObservedStatus: "verified", ServiceGeneration: 1,
		}
	}
	cases := []struct {
		name   string
		value  *state.LocalContinuityRegistration
		clause string
		exact  bool
	}{
		{name: "predecessor_revision_retained_scope_advanced", value: successor(2, 3), clause: "bindingRevision"},
		{name: "revision_equal_scope_advanced", value: successor(1, 3), clause: "scopeRevision"},
		{name: "revision_advanced_scope_retained", value: successor(2, 2), clause: "bindingRevision"},
		{name: "exact_predecessor", value: successor(1, 2), exact: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			exact := handoffSourceRegistrationExact(test.value, predecessor, manifest)
			clause := handoffSourceRegistrationFirstFalseClause(test.value, predecessor, manifest)
			t.Logf("first false clause %q exact %v", clause, exact)
			if exact != test.exact || clause != test.clause {
				t.Fatalf("exactness = %v clause = %q, want %v/%q", exact, clause, test.exact, test.clause)
			}
			if (clause == "") != exact {
				t.Fatalf("clause walker disagrees with the production conjunction: clause %q exact %v", clause, exact)
			}
		})
	}
}
