package containers

import (
	"reflect"
	"slices"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func TestCreateArgumentsKeepRootlessIdentityAndIsolation(t *testing.T) {
	arguments := createArguments(
		"warpmetal-sbx_example123",
		model.Sandbox{Resources: model.Resources{
			CPUMillicores: 750,
			MemoryMiB:     1024,
			PIDs:          256,
		}},
		"/var/lib/warpmetal-workspaces/sandboxes/sbx_example123/workspace",
		"registry.example/agent@sha256:example",
	)
	wantPairs := [][2]string{
		{"--pull", "missing"},
		{"--user", "1000:1000"},
		{"--userns", "keep-id:uid=1000,gid=1000"},
		{"--memory", "1024m"},
		{"--memory-swap", "1024m"},
		{"--pids-limit", "256"},
		{"--cgroup-parent", "warpmetal-podman.service"},
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges"},
		{"--network", "slirp4netns:allow_host_loopback=false"},
	}
	for _, pair := range wantPairs {
		found := false
		for index := 0; index+1 < len(arguments); index++ {
			if arguments[index] == pair[0] && arguments[index+1] == pair[1] {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing hardened Podman arguments %q %q: %#v", pair[0], pair[1], arguments)
		}
	}
	for _, forbidden := range []string{"--privileged", "--network=host", "--pid=host"} {
		if slices.Contains(arguments, forbidden) {
			t.Fatalf("unsafe Podman argument %q was present", forbidden)
		}
	}
}

func TestPodmanInvocationUsesPinnedLocalRuntime(t *testing.T) {
	got := podmanInvocation("runtime-user", "/srv/runtime", false, "create", "sandbox")
	want := []string{
		"-u", "runtime-user", "--", "env",
		"HOME=/srv/runtime",
		"XDG_RUNTIME_DIR=/run/warpmetal-podman",
		"/usr/bin/podman", "--runroot", "/run/warpmetal-podman/containers",
		"--runtime", "runc", "--cgroup-manager", "cgroupfs",
		"create", "sandbox",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("local invocation mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestPodmanInvocationUsesPrivateServiceForLifecycle(t *testing.T) {
	got := podmanInvocation("runtime-user", "/srv/runtime", true, "start", "sandbox")
	want := []string{
		"-u", "runtime-user", "--", "env",
		"HOME=/srv/runtime",
		"XDG_RUNTIME_DIR=/run/warpmetal-podman",
		"/usr/bin/podman", "--remote", "--url", "unix:///run/warpmetal-podman/podman.sock",
		"start", "sandbox",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remote invocation mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}
