package reconcile

import (
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func TestPreservedIdleBoundaryKeepsOnlyTheSameLiveIncarnation(t *testing.T) {
	desired := model.ManagedServiceV1{Identity: model.ManagedServiceIdentityV1{
		Role: "worker", ServiceRegistrationID: "service_test", ExpectedServiceGeneration: 2,
	}}
	previous := &state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			ServiceRegistrationID: "service_test", ServiceGeneration: 2,
			NativeSessionID: "ses_same",
		},
		NoAdmittedExecution: true,
	}
	if !preservedIdleBoundary(desired, previous, "ses_same") {
		t.Fatal("a matching verified idle boundary must survive a service lease renewal")
	}
	if preservedIdleBoundary(desired, previous, "ses_other") {
		t.Fatal("a different native session must not inherit the idle boundary")
	}
	differentGeneration := *previous
	differentGeneration.Report.ServiceGeneration = 3
	if preservedIdleBoundary(desired, &differentGeneration, "ses_same") {
		t.Fatal("a different service generation must not inherit the idle boundary")
	}
	notIdle := *previous
	notIdle.NoAdmittedExecution = false
	if preservedIdleBoundary(desired, &notIdle, "ses_same") {
		t.Fatal("a non-idle source must not be preserved as idle")
	}
	if preservedIdleBoundary(desired, nil, "ses_same") {
		t.Fatal("a first observation must not claim an idle boundary")
	}
	manager := model.ManagedServiceV1{Identity: model.ManagedServiceIdentityV1{Role: "manager"}}
	if !preservedIdleBoundary(manager, nil, "ses_same") {
		t.Fatal("manager sources are idle by construction")
	}
}
