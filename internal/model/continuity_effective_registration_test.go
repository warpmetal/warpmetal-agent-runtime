package model

import (
	"strings"
	"testing"
)

// continuityEffectiveRegistration builds one registration tuple for the
// resolution table: the identity and every binding field are shared, so only
// the desired state, binding revision, scope and native-location fence vary.
func continuityEffectiveRegistration(desiredState string, revision, scope int64, nativeDigest string) ContinuityRegistrationV1 {
	return ContinuityRegistrationV1{
		FormatVersion: 1, DesiredState: desiredState, ContinuityEnabled: desiredState == "active",
		ScopeRevision: scope,
		Identity: ContinuityIdentityV1{
			WorkID: "work_effective0001", ProjectID: "project_effective0001",
			SandboxID: "sbx_effective0000000001", WorkspaceEpoch: "epoch_effective0001",
			SandboxGeneration: 2, ExpectedRevision: 1,
		},
		Binding: ContinuityBindingV1{
			BindingID: "binding_effective0001", BindingRevision: revision,
			RegisteredSourceID: "source_effective0001", ServiceRegistrationID: "service_effective0001",
			NativeSessionID: "ses_effective0001", NativeProjectID: "0123456789abcdef0123456789abcdef01234567",
			NativeLocationDigest: nativeDigest,
		},
	}
}

// TestEffectiveContinuityRegistrationsResolvesOnlyTheValidatedSuccession is the
// A46 resolution matrix: a single entry is its own effective registration, the
// one revoked-predecessor/active-successor pair admitted by the validated
// manifest semantics resolves to the active successor in either manifest order,
// and every unsupported duplicate shape fails closed before any write.
func TestEffectiveContinuityRegistrationsResolvesOnlyTheValidatedSuccession(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	predecessor := continuityEffectiveRegistration("revoked", 1, 2, digest)
	successor := continuityEffectiveRegistration("active", 2, 2, digest)
	scopeAdvancedSuccessor := continuityEffectiveRegistration("active", 2, 3, digest)
	revisionJumped := continuityEffectiveRegistration("active", 3, 2, digest)
	reversedPredecessor := continuityEffectiveRegistration("revoked", 3, 2, digest)
	foreignFence := continuityEffectiveRegistration("active", 2, 2, "sha256:"+strings.Repeat("b", 64))
	secondActive := continuityEffectiveRegistration("active", 3, 2, digest)
	secondRevoked := continuityEffectiveRegistration("revoked", 3, 2, digest)
	thirdEntry := continuityEffectiveRegistration("active", 3, 3, digest)
	cases := []struct {
		name       string
		input      []ContinuityRegistrationV1
		wantLength int
		wantRev    int64
		wantErr    bool
	}{
		{name: "single_active", input: []ContinuityRegistrationV1{successor}, wantLength: 1, wantRev: 2},
		{name: "single_revoked", input: []ContinuityRegistrationV1{predecessor}, wantLength: 1, wantRev: 1},
		{name: "pair_backend_order", input: []ContinuityRegistrationV1{predecessor, successor}, wantLength: 1, wantRev: 2},
		{name: "pair_reversed_order", input: []ContinuityRegistrationV1{successor, predecessor}, wantLength: 1, wantRev: 2},
		{name: "pair_scope_advanced", input: []ContinuityRegistrationV1{predecessor, scopeAdvancedSuccessor}, wantLength: 1, wantRev: 2},
		{name: "two_active", input: []ContinuityRegistrationV1{successor, secondActive}, wantErr: true},
		{name: "two_revoked", input: []ContinuityRegistrationV1{predecessor, secondRevoked}, wantErr: true},
		{name: "revision_jump", input: []ContinuityRegistrationV1{predecessor, revisionJumped}, wantErr: true},
		{name: "reversed_relation", input: []ContinuityRegistrationV1{reversedPredecessor, successor}, wantErr: true},
		{name: "inconsistent_fence", input: []ContinuityRegistrationV1{predecessor, foreignFence}, wantErr: true},
		{name: "three_entries", input: []ContinuityRegistrationV1{predecessor, successor, thirdEntry}, wantErr: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			effective, err := EffectiveContinuityRegistrations(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("unsupported shape resolved instead of failing closed: %#v", effective)
				}
				if len(effective) != 0 {
					t.Fatalf("unsupported shape returned an effective registration: %#v", effective)
				}
				return
			}
			if err != nil || len(effective) != test.wantLength {
				t.Fatalf("resolution = %#v, %v; want %d entries", effective, err, test.wantLength)
			}
			if len(effective) == 1 && effective[0].Binding.BindingRevision != test.wantRev {
				t.Fatalf("effective revision = %d, want %d", effective[0].Binding.BindingRevision, test.wantRev)
			}
		})
	}
}
