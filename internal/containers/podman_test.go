package containers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
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
		{"--cgroup-parent", "/system.slice/warpmetal-podman.service"},
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges"},
		{"--label", imageDigestLabel + "=registry.example/agent@sha256:example"},
		{"--network", "slirp4netns:allow_host_loopback=false"},
		{"--volume", "/var/lib/warpmetal-workspaces/sandboxes/sbx_example123/workspace:/home/agent:rw,nodev,nosuid,Z"},
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

type fakeContainer struct {
	digest  string
	running bool
}

type fakePodman struct {
	containers map[string]fakeContainer
	calls      []string
	failOnce   map[string]int
}

func (f *fakePodman) run(
	_ context.Context,
	remote bool,
	args ...string,
) (string, error) {
	call := strings.Join(args, " ")
	if remote {
		call = "remote " + call
	}
	f.calls = append(f.calls, call)
	failKey := args[0]
	if args[0] == "rename" && strings.HasSuffix(args[1], "-image-backup") {
		failKey = "restore"
	}
	if f.failOnce[failKey] > 0 {
		f.failOnce[failKey]--
		return "injected failure", errors.New("injected failure")
	}
	switch args[0] {
	case "pull":
		return args[1], nil
	case "container":
		name := args[len(args)-1]
		container, exists := f.containers[name]
		if !exists {
			return "", errors.New("no such container")
		}
		if args[1] == "inspect" {
			if container.digest == "" {
				return "<no value>\n", nil
			}
			return container.digest + "\n", nil
		}
		return "", nil
	case "stop":
		name := args[len(args)-1]
		container, exists := f.containers[name]
		if !exists {
			return "no such container", errors.New("not found")
		}
		container.running = false
		f.containers[name] = container
		return name, nil
	case "start":
		name := args[len(args)-1]
		container, exists := f.containers[name]
		if !exists {
			return "no such container", errors.New("not found")
		}
		container.running = true
		f.containers[name] = container
		return name, nil
	case "rename":
		container, exists := f.containers[args[1]]
		if !exists {
			return "no such container", errors.New("not found")
		}
		if _, exists := f.containers[args[2]]; exists {
			return "name already exists", errors.New("conflict")
		}
		delete(f.containers, args[1])
		f.containers[args[2]] = container
		return args[2], nil
	case "create":
		name := argumentValue(args, "--name")
		label := argumentValue(args, "--label")
		digest := strings.TrimPrefix(label, imageDigestLabel+"=")
		if name == "" || digest == label {
			return "invalid create arguments", errors.New("invalid create arguments")
		}
		f.containers[name] = fakeContainer{digest: digest}
		return name, nil
	case "rm":
		name := args[len(args)-1]
		delete(f.containers, name)
		return name, nil
	default:
		return "", fmt.Errorf("unexpected fake Podman command: %v", args)
	}
}

func argumentValue(args []string, option string) string {
	for index := range args {
		if args[index] == option && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}

func replacementSandbox() model.Sandbox {
	return model.Sandbox{
		ID: "sbx_example123",
		Resources: model.Resources{
			CPUMillicores: 750,
			MemoryMiB:     1024,
			PIDs:          256,
		},
	}
}

func TestReplacePrePullsAndSwapsContainerAfterTargetStarts(t *testing.T) {
	name := containerName("sbx_example123")
	original := "registry.example/agent@sha256:" + strings.Repeat("a", 64)
	target := "registry.example/agent@sha256:" + strings.Repeat("b", 64)
	fake := &fakePodman{
		containers: map[string]fakeContainer{name: {digest: original, running: true}},
		failOnce:   map[string]int{},
	}
	podman := Podman{runCommand: fake.run}
	if err := podman.Replace(
		context.Background(),
		replacementSandbox(),
		"/workspace",
		target,
		true,
	); err != nil {
		t.Fatal(err)
	}
	got, exists := fake.containers[name]
	if !exists || got.digest != target || !got.running {
		t.Fatalf("target container did not replace source: %#v", fake.containers)
	}
	if _, exists := fake.containers[name+"-image-backup"]; exists {
		t.Fatalf("completed backup was not removed: %#v", fake.containers)
	}
	pullIndex := slices.Index(fake.calls, "pull "+target)
	stopIndex := slices.Index(fake.calls, "stop --time 10 "+name)
	if pullIndex < 0 || stopIndex < 0 || pullIndex > stopIndex {
		t.Fatalf("source was stopped before target pull: %#v", fake.calls)
	}
}

func TestReplacePullFailureLeavesSourceRunning(t *testing.T) {
	name := containerName("sbx_example123")
	original := "registry.example/agent@sha256:" + strings.Repeat("a", 64)
	target := "registry.example/agent@sha256:" + strings.Repeat("b", 64)
	fake := &fakePodman{
		containers: map[string]fakeContainer{name: {digest: original, running: true}},
		failOnce:   map[string]int{"pull": 1},
	}
	err := (Podman{runCommand: fake.run}).Replace(
		context.Background(), replacementSandbox(), "/workspace", target, true,
	)
	if !errors.Is(err, ErrImagePullFailed) {
		t.Fatalf("pull failure was not classified: %v", err)
	}
	if !fake.containers[name].running || len(fake.calls) != 1 {
		t.Fatalf("pull failure disrupted source: %#v %#v", fake.containers, fake.calls)
	}
}

func TestReplaceStartFailureRollsBackSource(t *testing.T) {
	name := containerName("sbx_example123")
	original := "registry.example/agent@sha256:" + strings.Repeat("a", 64)
	target := "registry.example/agent@sha256:" + strings.Repeat("b", 64)
	fake := &fakePodman{
		containers: map[string]fakeContainer{name: {digest: original, running: true}},
		failOnce:   map[string]int{"start": 1},
	}
	err := (Podman{runCommand: fake.run}).Replace(
		context.Background(), replacementSandbox(), "/workspace", target, true,
	)
	if err == nil || errors.Is(err, ErrImageRollbackFailed) {
		t.Fatalf("expected replacement error with successful rollback: %v", err)
	}
	got := fake.containers[name]
	if got.digest != original || !got.running || len(fake.containers) != 1 {
		t.Fatalf("source container was not restored: %#v", fake.containers)
	}
}

func TestReplaceReportsRollbackFailure(t *testing.T) {
	name := containerName("sbx_example123")
	original := "registry.example/agent@sha256:" + strings.Repeat("a", 64)
	target := "registry.example/agent@sha256:" + strings.Repeat("b", 64)
	fake := &fakePodman{
		containers: map[string]fakeContainer{name: {digest: original, running: true}},
		failOnce:   map[string]int{"create": 1, "restore": 1},
	}
	err := (Podman{runCommand: fake.run}).Replace(
		context.Background(), replacementSandbox(), "/workspace", target, true,
	)
	if !errors.Is(err, ErrImageRollbackFailed) {
		t.Fatalf("rollback failure was not classified: %v", err)
	}
}

func TestReplaceResumesTargetStartedBeforeBackupCleanup(t *testing.T) {
	name := containerName("sbx_example123")
	original := "registry.example/agent@sha256:" + strings.Repeat("a", 64)
	target := "registry.example/agent@sha256:" + strings.Repeat("b", 64)
	fake := &fakePodman{
		containers: map[string]fakeContainer{
			name:                   {digest: target},
			name + "-image-backup": {digest: original},
		},
		failOnce: map[string]int{},
	}
	if err := (Podman{runCommand: fake.run}).Replace(
		context.Background(), replacementSandbox(), "/workspace", target, true,
	); err != nil {
		t.Fatal(err)
	}
	if got := fake.containers[name]; got.digest != target || !got.running ||
		len(fake.containers) != 1 {
		t.Fatalf("replacement did not resume safely: %#v", fake.containers)
	}
}

func TestReplaceResumesAfterSourceRename(t *testing.T) {
	name := containerName("sbx_example123")
	original := "registry.example/agent@sha256:" + strings.Repeat("a", 64)
	target := "registry.example/agent@sha256:" + strings.Repeat("b", 64)
	fake := &fakePodman{
		containers: map[string]fakeContainer{
			name + "-image-backup": {digest: original, running: false},
		},
		failOnce: map[string]int{},
	}
	if err := (Podman{runCommand: fake.run}).Replace(
		context.Background(), replacementSandbox(), "/workspace", target, true,
	); err != nil {
		t.Fatal(err)
	}
	if got := fake.containers[name]; got.digest != target || !got.running ||
		len(fake.containers) != 1 {
		t.Fatalf("rename-boundary recovery did not converge: %#v", fake.containers)
	}
}

func TestReplaceRejectsAmbiguousTwoSourceContainers(t *testing.T) {
	name := containerName("sbx_example123")
	original := "registry.example/agent@sha256:" + strings.Repeat("a", 64)
	stale := "registry.example/agent@sha256:" + strings.Repeat("c", 64)
	target := "registry.example/agent@sha256:" + strings.Repeat("b", 64)
	fake := &fakePodman{
		containers: map[string]fakeContainer{
			name:                   {digest: original, running: true},
			name + "-image-backup": {digest: stale, running: false},
		},
		failOnce: map[string]int{},
	}
	err := (Podman{runCommand: fake.run}).Replace(
		context.Background(), replacementSandbox(), "/workspace", target, true,
	)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous replacement state was not rejected: %v", err)
	}
	if got := fake.containers[name]; got.digest != original || !got.running ||
		len(fake.containers) != 2 {
		t.Fatalf("ambiguous state was mutated: %#v", fake.containers)
	}
}

func TestReplaceRetriesBackupCleanup(t *testing.T) {
	name := containerName("sbx_example123")
	original := "registry.example/agent@sha256:" + strings.Repeat("a", 64)
	target := "registry.example/agent@sha256:" + strings.Repeat("b", 64)
	fake := &fakePodman{
		containers: map[string]fakeContainer{name: {digest: original, running: true}},
		failOnce:   map[string]int{"rm": 1},
	}
	podman := Podman{runCommand: fake.run}
	if err := podman.Replace(
		context.Background(), replacementSandbox(), "/workspace", target, true,
	); err == nil {
		t.Fatal("expected backup cleanup failure")
	}
	if got := fake.containers[name]; got.digest != target || !got.running {
		t.Fatalf("usable target was not retained after cleanup failure: %#v", fake.containers)
	}
	if err := podman.Replace(
		context.Background(), replacementSandbox(), "/workspace", target, true,
	); err != nil {
		t.Fatal(err)
	}
	if len(fake.containers) != 1 {
		t.Fatalf("cleanup retry did not converge: %#v", fake.containers)
	}
}

func TestReplacePreservesStoppedState(t *testing.T) {
	name := containerName("sbx_example123")
	original := "registry.example/agent@sha256:" + strings.Repeat("a", 64)
	target := "registry.example/agent@sha256:" + strings.Repeat("b", 64)
	fake := &fakePodman{
		containers: map[string]fakeContainer{name: {digest: original}},
		failOnce:   map[string]int{},
	}
	if err := (Podman{runCommand: fake.run}).Replace(
		context.Background(), replacementSandbox(), "/workspace", target, false,
	); err != nil {
		t.Fatal(err)
	}
	if got := fake.containers[name]; got.digest != target || got.running {
		t.Fatalf("stopped state changed during replacement: %#v", fake.containers)
	}
}

func TestPodmanInvocationUsesPinnedLocalRuntime(t *testing.T) {
	got := podmanInvocation("runtime-user", "/srv/runtime", false, "create", "sandbox")
	want := []string{
		"-u", "runtime-user", "--", "env",
		"HOME=/srv/runtime",
		"XDG_RUNTIME_DIR=/run/warpmetal-podman",
		"/usr/bin/podman", "--runroot", "/run/warpmetal-podman/containers",
		"--runtime", "crun", "--cgroup-manager", "cgroupfs",
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

func TestPodmanInvocationUsesPrivateServiceForExec(t *testing.T) {
	got := podmanInvocation(
		"runtime-user",
		"/srv/runtime",
		true,
		"exec", "-i", "sandbox", "/bin/sh", "-lc", "id",
	)
	want := []string{
		"-u", "runtime-user", "--", "env",
		"HOME=/srv/runtime",
		"XDG_RUNTIME_DIR=/run/warpmetal-podman",
		"/usr/bin/podman", "--remote", "--url", "unix:///run/warpmetal-podman/podman.sock",
		"exec", "-i", "sandbox", "/bin/sh", "-lc", "id",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remote exec invocation mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestPodmanExecCarriesFixedToolReporterThroughPrivateService(t *testing.T) {
	got := execArguments(
		"sbx_example123",
		"/usr/local/bin/warpmetal-agent-tool-report",
		false,
	)
	want := []string{
		"exec", "-i", "warpmetal-sbx_example123", "/bin/sh", "-lc",
		"/usr/local/bin/warpmetal-agent-tool-report",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tool reporter escaped the fixed exec boundary: %#v", got)
	}
}
