package continuity

import (
	"math"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// TestHandoffSourceScopeAdvanceWithinOneGuard pins the zero, negative,
// one-step and overflow relations of the guarded source-scope predicate that
// owner decision A27 admits without a store: only an exact one-step successor
// of a representable nonzero binding ever qualifies.
func TestHandoffSourceScopeAdvanceWithinOneGuard(t *testing.T) {
	cases := []struct {
		name     string
		binding  int64
		observed int64
		want     bool
	}{
		{"zero binding never advances", 0, 1, false},
		{"negative binding never advances", -1, 0, false},
		{"exact scope is not an advance", 2, 2, false},
		{"one step up", 1, 2, true},
		{"one step up from two", 2, 3, true},
		{"two steps up", 2, 4, false},
		{"regression", 2, 1, false},
		{"zero observed", 1, 0, false},
		{"maximal binding has no successor", math.MaxInt64, math.MaxInt64 - 1, false},
		{"maximal binding is not an advance", math.MaxInt64, math.MaxInt64, false},
		{"last representable step", math.MaxInt64 - 1, math.MaxInt64, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := handoffSourceScopeAdvanceWithinOne(testCase.binding, testCase.observed); got != testCase.want {
				t.Fatalf("withinOne(%d, %d) = %v, want %v", testCase.binding, testCase.observed, got, testCase.want)
			}
		})
	}
}

// TestHandoffSourceScopeAdvanceRecordsRefusesUnrepresentableOrUnalignedScopes
// pins the durable-records predicate's guards without a store: an overflowed or
// zero binding relation and a service scope that did not advance in lockstep
// with the source row are never proven, even when a project is available.
func TestHandoffSourceScopeAdvanceRecordsRefusesUnrepresentableOrUnalignedScopes(t *testing.T) {
	maximalBinding := model.ContinuationBindingRefV1{ScopeRevision: math.MaxInt64}
	if handoffSourceScopeAdvanceRecords(maximalBinding,
		model.ContinuationIdentityV1{},
		state.LocalContinuitySource{Report: model.ContinuitySourceReportV1{ScopeRevision: math.MaxInt64 - 1}},
		state.LocalManagedService{Manifest: model.ManagedServiceV1{Workspace: model.ManagedServiceWorkspaceV1{ScopeRevision: math.MaxInt64}}},
		&state.LocalManagedProject{Phase: "ready"}) {
		t.Fatal("maximal binding without a representable successor was proven")
	}
	zeroBinding := model.ContinuationBindingRefV1{}
	if handoffSourceScopeAdvanceRecords(zeroBinding,
		model.ContinuationIdentityV1{},
		state.LocalContinuitySource{Report: model.ContinuitySourceReportV1{ScopeRevision: 1}},
		state.LocalManagedService{Manifest: model.ManagedServiceV1{Workspace: model.ManagedServiceWorkspaceV1{ScopeRevision: 1}}},
		&state.LocalManagedProject{Phase: "ready"}) {
		t.Fatal("zero binding was proven as an advance")
	}
	// The source may advance one step, but the same service generation must
	// carry the advanced workspace scope itself; a service whose scope did not
	// move in lockstep is never proven.
	binding := model.ContinuationBindingRefV1{ScopeRevision: 2}
	source := state.LocalContinuitySource{Report: model.ContinuitySourceReportV1{ScopeRevision: 3}}
	if handoffSourceScopeAdvanceRecords(binding, model.ContinuationIdentityV1{}, source,
		state.LocalManagedService{Manifest: model.ManagedServiceV1{Workspace: model.ManagedServiceWorkspaceV1{ScopeRevision: 2}}},
		&state.LocalManagedProject{Phase: "ready"}) {
		t.Fatal("service scope that did not advance with the source was proven")
	}
}
