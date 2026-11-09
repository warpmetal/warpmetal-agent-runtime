package containers

import (
	"reflect"
	"testing"
)

func TestManagedSupervisorLauncherSelectsDeepSeekProfile(t *testing.T) {
	request := []byte(`{"schemaVersion":1,"profileId":"deepseek","instance":"foreman"}`)
	for _, action := range []ManagedSupervisorAction{
		ManagedSupervisorEnroll, ManagedSupervisorStart, ManagedSupervisorRestart, ManagedSupervisorStatus,
		ManagedSupervisorStop, ManagedSupervisorDrain, ManagedSupervisorCredential, ManagedSupervisorRebind,
		ManagedSupervisorRegisterSource, ManagedSupervisorControllerPrepare, ManagedSupervisorControllerPrompt,
		ManagedSupervisorMaterializeProfile, ManagedSupervisorControllerHeader, ManagedSupervisorControllerOutput,
	} {
		got := managedSupervisorLauncher(action, request)
		want := []string{"/usr/local/bin/warpmetal-deepseek-supervisor", string(action)}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s launcher = %#v, want %#v", action, got, want)
		}
	}
}

func TestManagedSupervisorLauncherKeepsOpenCodeForOtherProfiles(t *testing.T) {
	for _, request := range [][]byte{
		[]byte(`{"schemaVersion":1,"profileId":"opencode"}`),
		[]byte(`{"schemaVersion":1}`),
		[]byte(`not-json`),
	} {
		got := managedSupervisorLauncher(ManagedSupervisorStatus, request)
		want := []string{"/usr/local/bin/warpmetal-opencode-supervisor", "status"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("launcher for %s = %#v, want %#v", request, got, want)
		}
	}
}

func TestManagedSupervisorLauncherDeepSeekUnsupportedActionFallsBack(t *testing.T) {
	request := []byte(`{"profileId":"deepseek"}`)
	for _, action := range []ManagedSupervisorAction{ManagedSupervisorChildHeader, ManagedSupervisorChildEffectCapture, ManagedSupervisorCell} {
		got := managedSupervisorLauncher(action, request)
		want := []string{"/usr/local/bin/warpmetal-opencode-supervisor", string(action)}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unsupported deepseek action %s = %#v, want %#v", action, got, want)
		}
	}
}
