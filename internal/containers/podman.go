package containers

import (
	"context"
	"errors"
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
	Replace(context.Context, model.Sandbox, string, string, bool) error
	Start(context.Context, string) error
	Stop(context.Context, string) error
	Restart(context.Context, string) error
	Remove(context.Context, string) error
	Exec(context.Context, string, string, bool, io.Reader, io.Writer, io.Writer) error
}

var (
	ErrImagePullFailed     = errors.New("sandbox image pull failed")
	ErrImageRollbackFailed = errors.New("sandbox image rollback failed")
)

type Podman struct {
	RuntimeUser      string
	runCommand       func(context.Context, bool, ...string) (string, error)
	runStreamCommand func(context.Context, bool, io.Reader, io.Writer, io.Writer, ...string) error
}

const (
	podmanRuntimeDirectory = "/run/warpmetal-podman"
	podmanRunRoot          = "/run/warpmetal-podman/containers"
	podmanSocket           = "unix:///run/warpmetal-podman/podman.sock"
	podmanCgroupParent     = "/system.slice/warpmetal-podman.service"
	imageDigestLabel       = "io.warpmetal.image-digest"
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

// Replace changes only the immutable container root filesystem. The workspace
// remains mounted from the same host path. The desired image is pulled before
// the current workload is stopped, and the old container is retained under a
// deterministic backup name until the replacement reaches its desired state.
// The deterministic names also make every crash boundary safe to resume.
func (p Podman) Replace(
	ctx context.Context,
	sandbox model.Sandbox,
	workspace string,
	imageDigest string,
	running bool,
) error {
	name := containerName(sandbox.ID)
	backup := name + "-image-backup"
	if err := p.run(ctx, nil, "pull", imageDigest); err != nil {
		return fmt.Errorf("%w: %v", ErrImagePullFailed, err)
	}

	currentExists := p.containerExists(ctx, name)
	backupExists := p.containerExists(ctx, backup)
	if currentExists {
		currentDigest, err := p.containerImageDigest(ctx, name)
		if err != nil {
			return err
		}
		if currentDigest == imageDigest {
			if err := p.setContainerState(ctx, name, running); err != nil {
				if backupExists {
					return p.rollbackReplacement(ctx, name, backup, running, err)
				}
				return err
			}
			if backupExists {
				if err := p.removeContainer(ctx, backup); err != nil {
					return fmt.Errorf("remove completed image backup: %w", err)
				}
			}
			return nil
		}
		if backupExists {
			return errors.New("podman image replacement state is ambiguous")
		}
		if err := p.stopContainer(ctx, name); err != nil {
			return err
		}
		if err := p.run(ctx, nil, "rename", name, backup); err != nil {
			if restoreErr := p.setContainerState(ctx, name, running); restoreErr != nil {
				return errors.Join(
					ErrImageRollbackFailed,
					err,
					fmt.Errorf("restore container state: %w", restoreErr),
				)
			}
			return err
		}
		backupExists = true
	}

	args := createArguments(name, sandbox, workspace, imageDigest)
	if err := p.run(ctx, nil, args...); err != nil {
		if backupExists {
			return p.rollbackReplacement(ctx, name, backup, running, err)
		}
		return err
	}
	if err := p.setContainerState(ctx, name, running); err != nil {
		if backupExists {
			return p.rollbackReplacement(ctx, name, backup, running, err)
		}
		return err
	}
	if backupExists {
		if err := p.removeContainer(ctx, backup); err != nil {
			return fmt.Errorf("remove completed image backup: %w", err)
		}
	}
	return nil
}

func (p Podman) rollbackReplacement(
	ctx context.Context,
	name string,
	backup string,
	running bool,
	replaceErr error,
) error {
	var rollbackErrs []error
	if p.containerExists(ctx, name) {
		if err := p.removeContainer(ctx, name); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("remove failed replacement: %w", err))
		}
	}
	if p.containerExists(ctx, backup) {
		if err := p.run(ctx, nil, "rename", backup, name); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("restore backup name: %w", err))
		}
	} else {
		rollbackErrs = append(rollbackErrs, errors.New("replacement backup is missing"))
	}
	if len(rollbackErrs) == 0 {
		if err := p.setContainerState(ctx, name, running); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("restore backup state: %w", err))
		}
	}
	if len(rollbackErrs) != 0 {
		return errors.Join(
			ErrImageRollbackFailed,
			replaceErr,
			errors.Join(rollbackErrs...),
		)
	}
	return replaceErr
}

func (p Podman) containerExists(ctx context.Context, name string) bool {
	return p.run(ctx, nil, "container", "exists", name) == nil
}

func (p Podman) containerImageDigest(ctx context.Context, name string) (string, error) {
	output, err := p.runOutput(
		ctx,
		false,
		"container",
		"inspect",
		"--format",
		`{{ index .Config.Labels "`+imageDigestLabel+`" }}`,
		name,
	)
	if err != nil {
		return "", err
	}
	digest := strings.TrimSpace(output)
	if digest == "<no value>" {
		return "", nil
	}
	return digest, nil
}

func (p Podman) setContainerState(ctx context.Context, name string, running bool) error {
	if running {
		return p.runRemote(ctx, "start", name)
	}
	return p.stopContainer(ctx, name)
}

func (p Podman) stopContainer(ctx context.Context, name string) error {
	err := p.run(ctx, nil, "stop", "--time", "10", name)
	if err != nil && !strings.Contains(err.Error(), "no such container") {
		return err
	}
	return nil
}

func (p Podman) removeContainer(ctx context.Context, name string) error {
	err := p.run(ctx, nil, "rm", "--force", "--time", "10", name)
	if err != nil && !strings.Contains(err.Error(), "no such container") {
		return err
	}
	return nil
}

func (p Podman) Start(ctx context.Context, id string) error {
	return p.runRemote(ctx, "start", containerName(id))
}

func (p Podman) Stop(ctx context.Context, id string) error {
	return p.stopContainer(ctx, containerName(id))
}

func (p Podman) Restart(ctx context.Context, id string) error {
	return p.runRemote(ctx, "restart", "--time", "10", containerName(id))
}

func (p Podman) Remove(ctx context.Context, id string) error {
	return p.removeContainer(ctx, containerName(id))
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
	args := execArguments(id, command, tty)
	// Execute through the private Podman service so the OCI process is born
	// inside the delegated warpmetal-podman.service cgroup hierarchy. A local
	// Podman client launched by warpmetald runs in a sibling systemd cgroup and
	// cannot migrate the exec process across that cgroup v2 delegation boundary.
	return p.runCommandStreams(ctx, true, stdin, stdout, stderr, args...)
}

func execArguments(id, command string, tty bool) []string {
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
	return args
}

func (p Podman) run(ctx context.Context, stdin io.Reader, args ...string) error {
	if p.runCommand != nil {
		output, err := p.runCommand(ctx, false, args...)
		return podmanError(args, output, err)
	}
	var output strings.Builder
	err := p.runStreams(ctx, stdin, &output, &output, args...)
	return podmanError(args, output.String(), err)
}

func (p Podman) runRemote(ctx context.Context, args ...string) error {
	if p.runCommand != nil {
		output, err := p.runCommand(ctx, true, args...)
		return podmanError(args, output, err)
	}
	var output strings.Builder
	err := p.runRemoteStreams(ctx, nil, &output, &output, args...)
	return podmanError(args, output.String(), err)
}

func (p Podman) runOutput(
	ctx context.Context,
	remote bool,
	args ...string,
) (string, error) {
	if p.runCommand != nil {
		output, err := p.runCommand(ctx, remote, args...)
		return output, podmanError(args, output, err)
	}
	var output strings.Builder
	var err error
	if remote {
		err = p.runRemoteStreams(ctx, nil, &output, &output, args...)
	} else {
		err = p.runStreams(ctx, nil, &output, &output, args...)
	}
	return output.String(), podmanError(args, output.String(), err)
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

func (p Podman) runCommandStreams(
	ctx context.Context,
	remote bool,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	args ...string,
) error {
	if p.runStreamCommand != nil {
		return p.runStreamCommand(ctx, remote, stdin, stdout, stderr, args...)
	}
	if remote {
		return p.runRemoteStreams(ctx, stdin, stdout, stderr, args...)
	}
	return p.runStreams(ctx, stdin, stdout, stderr, args...)
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
			"--runtime", "crun", "--cgroup-manager", "cgroupfs",
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
		"--cgroup-parent", podmanCgroupParent,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--label", imageDigestLabel + "=" + imageDigest,
		"--network", "slirp4netns:allow_host_loopback=false",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
		"--volume", workspace + ":/home/agent:rw,nodev,nosuid,Z",
		"--workdir", "/home/agent",
		"--entrypoint", "/bin/sh",
		imageDigest,
		"-c", "trap : TERM INT; sleep infinity & wait",
	}
}

func containerName(id string) string { return "warpmetal-" + id }
