package containers

import (
	"reflect"
	"testing"
)

func TestManagedSupervisorLauncherSelectsDeepSeekProfile(t *testing.T) {
	request := []byte(`{"schemaVersion":1,"profileId":"deepseek","instance":"foreman"}`)
	got := managedSupervisorLauncher(ManagedSupervisorStatus, request)
	want := []string{deepseekSupervisorPath, "status"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("status launcher = %#v, want %#v", got, want)
	}
	got = managedSupervisorLauncher(ManagedSupervisorCredential, request)
	want = []string{deepseekSupervisorPath, "credential"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credential launcher = %#v, want %#v", got, want)
	}
}

func TestManagedSupervisorLauncherKeepsOpenCodeForOtherProfiles(t *testing.T) {
	for _, request := range [][]byte{
		[]byte(`{"schemaVersion":1,"profileId":"opencode"}`),
		[]byte(`{"schemaVersion":1}`),
		[]byte(`not-json`),
	} {
		got := managedSupervisorLauncher(ManagedSupervisorStatus, request)
		want := []string{opencodeSupervisorPath, "status"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("launcher for %s = %#v, want %#v", request, got, want)
		}
	}
}

func TestManagedSupervisorLauncherDeepSeekUnsupportedActionFallsBack(t *testing.T) {
	request := []byte(`{"profileId":"deepseek"}`)
	got := managedSupervisorLauncher(ManagedSupervisorControllerPrepare, request)
	want := []string{opencodeSupervisorPath, "controller-prepare"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unsupported deepseek action = %#v, want %#v", got, want)
	}
}
