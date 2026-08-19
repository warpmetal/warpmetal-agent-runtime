package containers

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type Engine interface {
	Ensure(context.Context, model.Sandbox, string, string) error
	Start(context.Context, string) error
	Stop(context.Context, string) error
	Restart(context.Context, string) error
	Remove(context.Context, string) error
	Exec(context.Context, string, string, bool, io.Reader, io.Writer, io.Writer) error
}

type Podman struct {
	RuntimeUser string
}

const (
	podmanRuntimeDirectory = "/run/warpmetal-podman"
	podmanRunRoot          = "/run/warpmetal-podman/containers"
	podmanSocket           = "unix:///run/warpmetal-podman/podman.sock"
)

func (p Podman) Ensure(
	ctx context.Context,
	sandbox model.Sandbox,
	workspace string,
	imageDigest string,
) error {
	name := containerName(sandbox.ID)
	exists := p.run(ctx, nil, "container", "exists", name) == nil
	if !exists {
		args := createArguments(name, sandbox, workspace, imageDigest)
		if err := p.run(ctx, nil, args...); err != nil {
			return err
		}
	}
	return p.Start(ctx, sandbox.ID)
}

func (p Podman) Start(ctx context.Context, id string) error {
	return p.runRemote(ctx, "start", containerName(id))
}

func (p Podman) Stop(ctx context.Context, id string) error {
	err := p.run(ctx, nil, "stop", "--time", "10", containerName(id))
	if err != nil && !strings.Contains(err.Error(), "no such container") {
		return err
	}
	return nil
}

func (p Podman) Restart(ctx context.Context, id string) error {
	return p.runRemote(ctx, "restart", "--time", "10", containerName(id))
}

func (p Podman) Remove(ctx context.Context, id string) error {
	err := p.run(ctx, nil, "rm", "--force", "--time", "10", containerName(id))
	if err != nil && !strings.Contains(err.Error(), "no such container") {
		return err
	}
	return nil
}

func (p Podman) Exec(
	ctx context.Context,
	id string,
	command string,
	tty bool,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) error {
	args := []string{"exec", "-i"}
	if tty {
		args = append(args, "-t")
	}
	args = append(args, containerName(id), "/bin/sh")
	if command == "" {
		args = append(args, "-l")
	} else {
		args = append(args, "-lc", command)
	}
	return p.runStreams(ctx, stdin, stdout, stderr, args...)
}

func (p Podman) run(ctx context.Context, stdin io.Reader, args ...string) error {
	var output strings.Builder
	err := p.runStreams(ctx, stdin, &output, &output, args...)
	return podmanError(args, output.String(), err)
}

func (p Podman) runRemote(ctx context.Context, args ...string) error {
	var output strings.Builder
	err := p.runRemoteStreams(ctx, nil, &output, &output, args...)
	return podmanError(args, output.String(), err)
}

func podmanError(args []string, output string, err error) error {
	if err != nil {
		message := strings.TrimSpace(output)
		if len(message) > 300 {
			message = message[:300]
		}
		return fmt.Errorf("podman %s failed: %s: %w", args[0], message, err)
	}
	return nil
}

func (p Podman) runStreams(
	ctx context.Context,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	args ...string,
) error {
	return p.runAsRuntimeUser(ctx, false, stdin, stdout, stderr, args...)
}

func (p Podman) runRemoteStreams(
	ctx context.Context,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	args ...string,
) error {
	return p.runAsRuntimeUser(ctx, true, stdin, stdout, stderr, args...)
}

func (p Podman) runAsRuntimeUser(
	ctx context.Context,
	remote bool,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	args ...string,
) error {
	runtimeUser := p.RuntimeUser
	if runtimeUser == "" {
		runtimeUser = "warpmetal-runtime"
	}
	identity, err := user.Lookup(runtimeUser)
	if err != nil {
		return fmt.Errorf("lookup runtime user: %w", err)
	}
	argv := podmanInvocation(runtimeUser, identity.HomeDir, remote, args...)
	cmd := exec.CommandContext(ctx, "/usr/sbin/runuser", argv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func podmanInvocation(runtimeUser, home string, remote bool, args ...string) []string {
	argv := []string{
		"-u", runtimeUser, "--", "env",
		"HOME=" + home,
		"XDG_RUNTIME_DIR=" + podmanRuntimeDirectory,
	}
	if remote {
		argv = append(argv, "/usr/bin/podman", "--remote", "--url", podmanSocket)
	} else {
		argv = append(
			argv,
			"/usr/bin/podman", "--runroot", podmanRunRoot,
			"--runtime", "runc", "--cgroup-manager", "cgroupfs",
		)
	}
	return append(argv, args...)
}

func createArguments(
	name string,
	sandbox model.Sandbox,
	workspace string,
	imageDigest string,
) []string {
	memory := strconv.Itoa(sandbox.Resources.MemoryMiB) + "m"
	cpu := fmt.Sprintf("%.3f", float64(sandbox.Resources.CPUMillicores)/1000)
	return []string{
		"create",
		"--name", name,
		"--pull", "missing",
		"--read-only",
		"--user", "1000:1000",
		"--userns", "keep-id:uid=1000,gid=1000",
		"--cpus", cpu,
		"--memory", memory,
		"--memory-swap", memory,
		"--pids-limit", strconv.Itoa(sandbox.Resources.PIDs),
		"--cgroup-parent", "warpmetal-podman.service",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--network", "slirp4netns:allow_host_loopback=false",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
		"--volume", workspace + ":/home/agent:rw,nodev,nosuid",
		"--workdir", "/home/agent",
		"--entrypoint", "/bin/sh",
		imageDigest,
		"-c", "trap : TERM INT; sleep infinity & wait",
	}
}

func containerName(id string) string { return "warpmetal-" + id }
