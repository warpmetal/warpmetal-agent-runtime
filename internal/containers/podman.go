package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/setupsource"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type Engine interface {
	Ensure(context.Context, model.Sandbox, string, string) error
	Replace(context.Context, model.Sandbox, string, string, bool) error
	// Recreate performs a controlled replacement that forces a re-create even
	// when the image digest is unchanged, for the legacy->cell transition (so
	// an existing running box is re-created with the SA9 witness hook applied).
	Recreate(context.Context, model.Sandbox, string, string, bool) error
	Start(context.Context, string) error
	Stop(context.Context, string) error
	Restart(context.Context, string) error
	Remove(context.Context, string) error
	Preflight(context.Context, string) error
	ExecSetup(context.Context, string, []byte) ([]byte, []byte, error)
	Exec(context.Context, string, string, bool, SessionInput, io.Writer, io.Writer) error
	// ObserveCellWitness verifies the running cell container's CURRENT mount
	// namespace actually carries the reviewed childless procfs witness. It is
	// the only source of observed cell readiness; the desired cell flag alone
	// is never accepted. It proves PREREQUISITE witness availability, not
	// worker private-proc isolation (the live gate's oracle), and it does not
	// distinguish a fresh procfs from a non-recursive parent-proc bind.
	ObserveCellWitness(context.Context, string) (bool, error)
	// VerifyCellLifecycle re-runs the fail-closed SA9 capability negotiation
	// (trusted immutable hook storage plus the pinned Podman/crun precreate
	// support) WITHOUT creating, starting, or replacing a container. The
	// reconcile adopt path uses it before it treats an already-running
	// container as a cell, so readiness is never committed on a host that
	// could not create the witness in the first place.
	VerifyCellLifecycle(context.Context) error
}

type ManagedSupervisorAction string

const (
	ManagedSupervisorEnroll             ManagedSupervisorAction = "enroll"
	ManagedSupervisorStart              ManagedSupervisorAction = "start"
	ManagedSupervisorMaterializeProfile ManagedSupervisorAction = "materialize-profile"
	// WP-211B: the packaged agent-kit materializer action. Same fixed supervisor
	// binary and capability launcher, same no-shell argv contract; gated by a
	// compiled TEST adoption record and receives only a bounded closed request.
	ManagedSupervisorMaterializeAgentKit      ManagedSupervisorAction = "materialize-agent-kit"
	ManagedSupervisorRestart                  ManagedSupervisorAction = "restart"
	ManagedSupervisorRebind                   ManagedSupervisorAction = "rebind"
	ManagedSupervisorCredential               ManagedSupervisorAction = "credential"
	ManagedSupervisorStatus                   ManagedSupervisorAction = "status"
	ManagedSupervisorRegisterSource           ManagedSupervisorAction = "register-source"
	ManagedSupervisorRegisterHandoffWorkspace ManagedSupervisorAction = "register-handoff-workspace"
	ManagedSupervisorDrain                    ManagedSupervisorAction = "drain"
	ManagedSupervisorStop                     ManagedSupervisorAction = "stop"
	ManagedSupervisorControllerPrepare        ManagedSupervisorAction = "controller-prepare"
	ManagedSupervisorControllerPrompt         ManagedSupervisorAction = "controller-prompt"
	ManagedSupervisorControllerOutput         ManagedSupervisorAction = "controller-output"
	ManagedSupervisorControllerHeader         ManagedSupervisorAction = "controller-header"
	ManagedSupervisorChildHeader              ManagedSupervisorAction = "child-header"
	ManagedSupervisorSourceTerminalCapture    ManagedSupervisorAction = "source-terminal-capture"
	ManagedSupervisorChildEffectCapture       ManagedSupervisorAction = "child-effect-capture"
	ManagedSupervisorReviewerCapture          ManagedSupervisorAction = "reviewer-assessment-capture"
	// ManagedSupervisorCell is the trusted cell controller boundary. It runs
	// OUTSIDE the bwrap jail with credentials and network and dispatches to the
	// SA4 adapter (runner/warpmetal_cell_adapter.py: create_child -> bind_workspace
	// -> admit_first_step, and observe/recover/classify_child). It is never the
	// credential-less jailed tool entrypoint (runner/warpmetal_cell_tool.py).
	ManagedSupervisorCell ManagedSupervisorAction = "cell"
	// ManagedSupervisorPrepare is the formatVersion 3 prepare-only cell command.
	// It runs the SAME trusted cell adapter OUTSIDE the bwrap jail and returns a
	// safe prepared receipt WITHOUT a prompt grant; it never takes the launch
	// path (no admit_first_step). V2 same-pass launch is never a v3 fallback.
	ManagedSupervisorPrepare ManagedSupervisorAction = "prepare"
)

// ManagedCellAdapterPath is the installed trusted SA4 cell adapter. It runs
// outside the bwrap jail with credentials and network; it is never the jailed,
// credential-less tool entrypoint (warpmetal_cell_tool.py).
const ManagedCellAdapterPath = "/usr/local/libexec/warpmetal-agent-cells/warpmetal_cell_adapter.py"

type ManagedWorkerAction string

const (
	ManagedWorkerExecute   ManagedWorkerAction = "execute"
	ManagedWorkerReconcile ManagedWorkerAction = "reconcile"
	ManagedWorkerStatus    ManagedWorkerAction = "status"
)

type SessionBridgeEngineV1 struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type SessionBridgeGrantV1 struct {
	SchemaVersion      int                   `json:"schemaVersion"`
	GrantID            string                `json:"grantId"`
	ServerID           string                `json:"serverId"`
	SandboxID          string                `json:"sandboxId"`
	Generation         int64                 `json:"generation"`
	Instance           string                `json:"instance"`
	ProfileID          string                `json:"profileId"`
	ProfileDigest      string                `json:"profileDigest"`
	HostKeyFingerprint string                `json:"hostKeyFingerprint"`
	Engine             SessionBridgeEngineV1 `json:"engine"`
	AllowedPaths       []string              `json:"allowedPaths"`
	AllowedMethods     []string              `json:"allowedMethods"`
	IssuedAt           time.Time             `json:"issuedAt"`
	ExpiresAt          time.Time             `json:"expiresAt"`
	// Capability is empty for the legacy exact-session grant, preserving its
	// wire bytes, and "foreman_chat" for the additive advisory chat grant.
	Capability string               `json:"capability,omitempty"`
	Chat       *SessionBridgeChatV1 `json:"chat,omitempty"`
}

// SessionBridgeChatV1 is the host-generated policy for one Foreman chat
// bridge. The bridge re-resolves the exact native session and enforces these
// bounds authoritatively; the connector enforces the same values locally.
type SessionBridgeChatV1 struct {
	Protocol              string `json:"protocol"`
	MaxQuestionBytes      int    `json:"maxQuestionBytes"`
	MaxReplyBytes         int    `json:"maxReplyBytes"`
	MaxQuestionsPerMinute int    `json:"maxQuestionsPerMinute"`
	MaxConcurrent         int    `json:"maxConcurrent"`
	HandoffID             string `json:"handoffId"`
	NativeSessionID       string `json:"nativeSessionId"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	ProjectID             string `json:"projectId"`
	WorkspaceEpoch        string `json:"workspaceEpoch"`
	// Advisory is the additive read-only admission scope for the Foreman chat
	// prompt. It is issued by the Runtime from the exact controller-parent
	// receipt; the bridge presents it to the native controller guard for chat
	// questions only. It carries no tool, review, decision, mutation or takeover
	// capability and expires with the 120-second chat consent.
	Advisory *ForemanChatAdvisoryV1 `json:"advisory,omitempty"`
	// Qualification is the venue-scoped, host-generated qualification client
	// configuration. The bridge presents the signed controller policy and a
	// per-preparation activation to the image-owned verifier. It is disabled by
	// default (`nil`) and never owner-controlled.
	Qualification *ForemanChatQualificationV1 `json:"qualification,omitempty"`
}

// ForemanChatQualificationV1 is the closed qualification client configuration
// for one Foreman chat grant. The Runtime supplies the venue paths and the
// signed policy digest; the bridge reads only and never writes the tree.
type ForemanChatQualificationV1 struct {
	FormatVersion int    `json:"formatVersion"`
	Tree          string `json:"tree"`
	Key           string `json:"key"`
	PolicyDigest  string `json:"policyDigest"`
	Broker        string `json:"broker"`
}

const (
	ForemanChatQualificationFormat = 1
	// ForemanChatAdvisoryModel is the single model authority the installed
	// qualification plugin admits for real-provider controller activity. The
	// Foreman advisory projection must equal it (there is no per-owner rewrite
	// and no post-hoc native model switch).
	ForemanChatAdvisoryModelID = "gpt-4.1-mini-2025-04-14"
)

// ForemanChatAdvisoryV1 is the closed read-only scope the bridge may turn into
// the one native controller prompt admission for the consented Foreman chat.
// Every field is re-derived from the exact controller-parent identity at handoff
// time; no caller-supplied scope is accepted.
type ForemanChatAdvisoryV1 struct {
	FormatVersion         int       `json:"formatVersion"`
	Capability            string    `json:"capability"`
	AdmissionID           string    `json:"admissionId"`
	ServerID              string    `json:"serverId"`
	SandboxID             string    `json:"sandboxId"`
	SandboxGeneration     int64     `json:"sandboxGeneration"`
	Instance              string    `json:"instance"`
	NativeSessionID       string    `json:"nativeSessionId"`
	ServiceRegistrationID string    `json:"serviceRegistrationId"`
	ServiceGeneration     int64     `json:"serviceGeneration"`
	Role                  string    `json:"role"`
	RoleBindingID         string    `json:"roleBindingId"`
	HandoffID             string    `json:"handoffId"`
	IssuedAt              time.Time `json:"issuedAt"`
	ExpiresAt             time.Time `json:"expiresAt"`
	// Projection and RoleAgentDigest are the exact controller-parent projection
	// the Runtime adopted and signed. The bridge hashes the same object to the
	// same roleAgentDigest before it will present any qualification admission;
	// the signed policy must match both. Worker/manager projections are never
	// emitted here.
	Projection      *model.ControllerRoleProjection `json:"projection"`
	RoleAgentDigest string                          `json:"roleAgentDigest"`
}

const (
	ForemanChatCapability         = "foreman_chat"
	ForemanChatAdvisoryCapability = "foreman_chat_read_only"
	ForemanChatProtocol           = "wm-foreman-chat/1"
	ForemanChatQuestionBytes      = 16 * 1024
	ForemanChatReplyBytes         = 1024 * 1024
	ForemanChatQuestionsPerMinute = 6
	ForemanChatMaxConcurrent      = 1
)

type SessionHandoffLaunch struct {
	Grant      SessionBridgeGrantV1
	HelloFrame []byte
}

type SessionHandoffEngine interface {
	ExecSessionHandoff(context.Context, string, SessionHandoffLaunch, SessionInput, io.Writer, io.Writer) error
}

type SessionInput interface {
	io.Reader
	// InterruptRead must guarantee that a currently blocked Read returns.
	InterruptRead() error
}

type ContainerState string

const (
	ContainerRunning ContainerState = "running"
	ContainerPaused  ContainerState = "paused"
	ContainerStopped ContainerState = "stopped"
)

var (
	ErrImagePullFailed     = errors.New("sandbox image pull failed")
	ErrImageRollbackFailed = errors.New("sandbox image rollback failed")
)

type Podman struct {
	RuntimeUser       string
	PhysicalStore     *state.Store
	PhysicalProcesses *physicalgate.ProcessRegistry
	PhysicalAccess    *physicalgate.AccessRegistry
	SourceTerminal    *physicalgate.SourceTerminalConsumer
	// QualificationRoot is operator configuration only, empty by default.
	// It is independent of the SA9 witness hook directory.
	QualificationRoot          string
	QualificationProducer      *qualification.ProducerConfig
	QualificationServerID      string
	QualificationNodeTokenHash string
	// HooksDir is the trusted SA9 hook storage directory the engine configures
	// for both the delegated Podman service and the cell create path. Empty
	// selects the packaged CellHookDirectory; tests and non-default
	// installations may override it. It must equal the directory the
	// warpmetal-podman-service is started with, and verifyCellLifecycle fails
	// closed when the installed hook there is not the reviewed allowlisted
	// configuration.
	HooksDir string
	// CellLifecycle overrides the packaged SA9 hook storage and allowlisted
	// profile. Empty selects DefaultCellLifecycle; tests and non-default
	// installations may set it.
	CellLifecycle *CellLifecycle
	// SetupTestSource is operator-only configuration for the setup runner's
	// default-off test-venue source gate (WP-60). It is empty in production,
	// so ExecSetup adds no gate environment. When enabled, ExecSetup adds
	// exactly the mode and exact-URL allowlist environment to the setup
	// runner process. The setup request JSON can never influence it.
	SetupTestSource  *setupsource.Config
	runCommand       func(context.Context, bool, ...string) (string, error)
	runStreamCommand func(context.Context, bool, SessionInput, io.Writer, io.Writer, ...string) error
	// networkHelperPIDs is a narrow test seam for the rootless network-helper
	// cleanup on stop/remove. Production leaves it nil and observes the live
	// container's conmon/netns footprint in /proc.
	networkHelperPIDs func(context.Context, string) []networkHelperProcess
	// helperProcesses is the narrow test seam for the read-only /proc process
	// view used by network-helper attribution. Production leaves it nil.
	helperProcesses helperProcessTable
	// killProcess is the narrow test seam for signal delivery; production uses
	// syscall.Kill.
	killProcess func(int, syscall.Signal) error
}

// networkHelperProcess identifies one rootless network helper (slirp4netns or
// pasta) that must not outlive the cell it serves. StartTime is the /proc stat
// start time (field 22), used to refuse a recycled PID; zero means the identity
// could not be read and the process is only signalled when it still exists.
type networkHelperProcess struct {
	PID       int
	StartTime uint64
	Comm      string
	State     string
}

const (
	podmanRuntimeDirectory       = "/run/warpmetal-podman"
	podmanRunRoot                = "/run/warpmetal-podman/containers"
	podmanSocket                 = "unix:///run/warpmetal-podman/podman.sock"
	podmanCgroupParent           = "/system.slice/warpmetal-podman.service"
	imageDigestLabel             = "io.warpmetal.image-digest"
	maxSetupRequestBytes         = 64 * 1024
	maxSetupReceiptBytes         = 64 * 1024
	maxSetupDiagnosticBytes      = 16 * 1024
	setupOperationTimeout        = 10 * time.Minute
	continuityHelperTimeout      = 30 * time.Second
	maxContinuityRequestBytes    = 64 * 1024
	maxContinuityReceiptBytes    = 64 * 1024
	maxContinuityDiagnosticBytes = 16 * 1024
	monitorHelperTimeout         = 5 * time.Second
	maxMonitorRequestBytes       = 64 * 1024
	maxMonitorReceiptBytes       = 256 * 1024
	maxMonitorDiagnosticBytes    = 16 * 1024
	managerHelperTimeout         = 4 * time.Minute
	maxManagerRequestBytes       = 64 * 1024
	maxManagerReceiptBytes       = 64 * 1024
	maxManagerDiagnosticBytes    = 16 * 1024
	nestedPreflightTimeout       = 30 * time.Second
	nestedSandboxPreflightMarker = "warpmetal-nested-sandbox-preflight-v1"
	capabilityLauncherPath       = "/usr/local/libexec/warpmetal-capability-launcher"
)

// New images own the launcher on the read-only root. Legacy pinned images keep
// their ordinary shell behavior. User shell options/commands are separate argv
// and are never incorporated into the fixed dispatch program.
const capabilityLauncherDispatch = `if [ -x /usr/local/libexec/warpmetal-capability-launcher ]; then
exec /usr/local/libexec/warpmetal-capability-launcher /bin/sh "$@"
fi
exec /bin/sh "$@"`

const nestedSandboxPreflightScript = `set -eu
grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status
grep -Eq '^CapBnd:[[:space:]]+0+$' /proc/self/status
grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
test -r /proc/self/status
probe=$(mktemp -d /home/agent/.warpmetal-nested-sandbox-preflight.XXXXXX)
trap 'rm -rf -- "$probe"' EXIT HUP INT TERM
printf '%s\n' workspace-ok > "$probe/workspace"
test "$(cat "$probe/workspace")" = workspace-ok
if (umask 077 && : > /etc/warpmetal-nested-sandbox-preflight) 2>/dev/null; then
  exit 41
fi
printf '%s\n' ` + nestedSandboxPreflightMarker

func (p Podman) Ensure(
	ctx context.Context,
	sandbox model.Sandbox,
	workspace string,
	imageDigest string,
) error {
	// A cell sandbox must never launch without the reviewed SA9 witness: the
	// capability negotiation is fail-closed, with no silent no-witness fallback.
	if sandbox.Cell {
		if err := p.verifyCellLifecycle(ctx, p.cellLifecycle()); err != nil {
			return err
		}
	}
	name := containerName(sandbox.ID)
	args, err := p.managedCreateArguments(ctx, name, sandbox, workspace, imageDigest)
	if err != nil {
		return err
	}
	exists := p.run(ctx, nil, "container", "exists", name) == nil
	if !exists {
		if err := p.run(ctx, nil, args...); err != nil {
			return err
		}
	} else if p.QualificationRoot != "" {
		if err := p.verifyQualificationMounts(ctx, sandbox.ID); err != nil {
			return err
		}
	}
	return p.Start(ctx, sandbox.ID)
}

// Replace changes only the immutable container root filesystem. The workspace
// remains mounted from the same host path. The exact immutable image is ensured before
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
	return p.replaceContainer(ctx, sandbox, workspace, imageDigest, running, false)
}

// Recreate performs the same controlled replacement as Replace but forces a
// re-create even when the image digest is unchanged. It is the legitimate
// controller-authorized transition for a legacy box enabled as a cell: the
// existing running container is stopped, retained under a deterministic backup
// name, and re-created with the SA9 witness hook applied, preserving the
// workspace and rolling back to the backup on failure. It is never an unsafe
// reset and never abandons the workspace.
func (p Podman) Recreate(
	ctx context.Context,
	sandbox model.Sandbox,
	workspace string,
	imageDigest string,
	running bool,
) error {
	return p.replaceContainer(ctx, sandbox, workspace, imageDigest, running, true)
}

func (p Podman) replaceContainer(
	ctx context.Context,
	sandbox model.Sandbox,
	workspace string,
	imageDigest string,
	running bool,
	force bool,
) error {
	if sandbox.Cell {
		if err := p.verifyCellLifecycle(ctx, p.cellLifecycle()); err != nil {
			return err
		}
	}
	name := containerName(sandbox.ID)
	backup := name + "-image-backup"
	args, err := p.managedCreateArguments(ctx, name, sandbox, workspace, imageDigest)
	if err != nil {
		return err
	}
	if err := p.run(ctx, nil, "image", "exists", imageDigest); err != nil {
		if err := p.run(ctx, nil, "pull", imageDigest); err != nil {
			return fmt.Errorf("%w: %v", ErrImagePullFailed, err)
		}
	}

	currentExists := p.containerExists(ctx, name)
	backupExists := p.containerExists(ctx, backup)
	if currentExists && backupExists {
		// Both the current container and its deterministic backup exist: a prior
		// replacement was interrupted after the new container was created but
		// before the backup was removed. Verify the current container is the
		// intended ready replacement before dropping the backup — never by the
		// annotation class alone.
		if force && sandbox.Cell {
			if err := p.setContainerState(ctx, name, true); err != nil {
				return err
			}
		}
		ready, err := p.verifyReplacementReady(ctx, sandbox, name, imageDigest, force)
		if err != nil {
			return err
		}
		if ready {
			if err := p.setContainerState(ctx, name, running); err != nil {
				return err
			}
			if err := p.removeContainer(ctx, backup); err != nil {
				return fmt.Errorf("remove completed image backup: %w", err)
			}
			return nil
		}
		if force && sandbox.Cell {
			// A forced cell transition that is not verified ready rolls back to
			// the retained legacy backup (never strands a not-ready container).
			return p.rollbackReplacement(ctx, name, backup, running, errors.New("replacement not verified ready"))
		}
		return errors.New("podman image replacement state is ambiguous")
	}
	if currentExists {
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
		// For a forced cell transition, do not drop the rollback backup until the
		// recreated container is verified as the intended ready target (image
		// matches AND the witness is actually mounted) — the annotation alone
		// identifies a class, not a unique replacement. A not-ready recreation
		// rolls back to the retained legacy container instead of stranding it.
		if force && sandbox.Cell {
			ready, err := p.ObserveCellWitness(ctx, sandbox.ID)
			if err != nil || !ready {
				return p.rollbackReplacement(ctx, name, backup, running, errors.New("cell witness unavailable after recreation"))
			}
		}
		if err := p.removeContainer(ctx, backup); err != nil {
			return fmt.Errorf("remove completed image backup: %w", err)
		}
	}
	return nil
}

// verifyReplacementReady reports whether the current container is the intended
// ready replacement before its deterministic backup is dropped. The image
// digest must match the target, and for a forced cell transition the container
// must additionally carry the allowlisted annotation AND have the witness
// actually mounted (a live observation, not the annotation class alone). The
// caller must ensure the container is running before the witness check.
func (p Podman) verifyReplacementReady(ctx context.Context, sandbox model.Sandbox, name, imageDigest string, force bool) (bool, error) {
	currentDigest, err := p.containerImageDigest(ctx, name)
	if err != nil {
		return false, err
	}
	if currentDigest != imageDigest {
		return false, nil
	}
	if !force || !sandbox.Cell {
		return true, nil
	}
	return p.ObserveCellWitness(ctx, sandbox.ID)
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
	name := containerName(id)
	helpers := p.observeNetworkHelpers(ctx, name)
	stopErr := p.stopContainer(ctx, name)
	cleanupErr := p.terminateNetworkHelpers(ctx, helpers)
	return errors.Join(stopErr, cleanupErr)
}

func (p Podman) Restart(ctx context.Context, id string) error {
	return p.runRemote(ctx, "restart", "--time", "10", containerName(id))
}

// InspectState, Pause, and Unpause form the deliberately closed lifecycle
// seam used by continuity capture. They accept only a validated sandbox ID and
// always use the private rootless Podman service.
func (p Podman) InspectState(ctx context.Context, id string) (ContainerState, error) {
	output, err := p.runOutput(
		ctx, true, "container", "inspect", "--format", "{{.State.Status}}", containerName(id),
	)
	if err != nil {
		return "", err
	}
	switch strings.TrimSpace(output) {
	case "running":
		return ContainerRunning, nil
	case "paused":
		return ContainerPaused, nil
	case "created", "configured", "exited", "stopped":
		return ContainerStopped, nil
	default:
		return "", errors.New("podman returned an unknown container state")
	}
}

func (p Podman) Pause(ctx context.Context, id string) error {
	return p.runRemote(ctx, "pause", containerName(id))
}

func (p Podman) Unpause(ctx context.Context, id string) error {
	return p.runRemote(ctx, "unpause", containerName(id))
}

func (p Podman) Remove(ctx context.Context, id string) error {
	name := containerName(id)
	helpers := p.observeNetworkHelpers(ctx, name)
	removeErr := p.removeContainer(ctx, name)
	cleanupErr := p.terminateNetworkHelpers(ctx, helpers)
	return errors.Join(removeErr, cleanupErr)
}

// Preflight is a credential-free readiness oracle for the immutable nested
// Bubblewrap helper. It runs only fixed Runtime-owned argv as UID/GID 1000
// inside the already hardened Agent Box. Readiness fails unless Bubblewrap can
// create its nested namespaces while inheriting the already-isolated outer
// procfs, write only the approved workspace, and remains unable to write the
// read-only image root. Inheriting procfs matches Codex's documented
// restrictive-container fallback when a nested procfs mount is unavailable.
func (p Podman) Preflight(ctx context.Context, id string) error {
	preflightContext, cancel := context.WithTimeout(ctx, nestedPreflightTimeout)
	defer cancel()
	output, err := p.runOutput(
		preflightContext,
		true,
		"exec", "-i", "--user", "1000:1000", "--workdir", "/home/agent",
		containerName(id), capabilityLauncherPath, "/usr/local/libexec/warpmetal-bwrap",
		"--die-with-parent", "--new-session",
		"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--unshare-cgroup-try", "--uid", "1000", "--gid", "1000",
		"--ro-bind", "/", "/",
		"--bind", "/home/agent", "/home/agent",
		"--ro-bind", "/proc", "/proc", "--dev", "/dev",
		"--tmpfs", "/tmp", "--chdir", "/home/agent",
		"--clearenv", "--setenv", "HOME", "/home/agent",
		"--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
		"/bin/sh", "-ec", nestedSandboxPreflightScript,
	)
	if err != nil {
		return fmt.Errorf("nested sandbox preflight: %w", err)
	}
	if strings.TrimSpace(output) != nestedSandboxPreflightMarker {
		return errors.New("nested sandbox preflight returned an invalid completion marker")
	}
	return nil
}

func (p Podman) Exec(
	ctx context.Context,
	id string,
	command string,
	tty bool,
	stdin SessionInput,
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

type prefixedSessionInput struct {
	io.Reader
	input SessionInput
}

func (i prefixedSessionInput) InterruptRead() error { return i.input.InterruptRead() }

// setupRequestInput adapts the bounded setup request reader to the shared
// stream seam. Setup execution is not interactive, so an interrupt is a no-op.
type setupRequestInput struct{ io.Reader }

func (setupRequestInput) InterruptRead() error { return nil }

// ExecSessionHandoff is the only Runtime path to the managed Team bridge. Its
// typed launch is entirely host-generated; neither an owner command nor shell
// text can influence the executable or argv.
func (p Podman) ExecSessionHandoff(
	ctx context.Context,
	id string,
	launch SessionHandoffLaunch,
	input SessionInput,
	stdout io.Writer,
	stderr io.Writer,
) error {
	grant := launch.Grant
	wantMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	if len(launch.HelloFrame) < 5 || len(launch.HelloFrame) > 64*1024 ||
		grant.SchemaVersion != 1 || grant.SandboxID != id || grant.Generation < 1 ||
		grant.GrantID == "" || grant.ServerID == "" || grant.Instance == "" ||
		grant.ProfileID != "opencode" || grant.ProfileDigest == "" ||
		grant.HostKeyFingerprint == "" || grant.Engine.Host != "127.0.0.1" ||
		grant.Engine.Port < 1 || grant.Engine.Port > 65535 || grant.IssuedAt.IsZero() ||
		grant.ExpiresAt.IsZero() || !grant.ExpiresAt.After(grant.IssuedAt) ||
		len(grant.AllowedPaths) != 1 || grant.AllowedPaths[0] != "/api" ||
		grant.Capability == "" && len(grant.AllowedMethods) != len(wantMethods) {
		return errors.New("invalid session handoff launch")
	}
	if grant.Capability == "" {
		for index := range wantMethods {
			if grant.AllowedMethods[index] != wantMethods[index] {
				return errors.New("invalid session handoff method policy")
			}
		}
	}
	if grant.Capability != "" {
		// Additive Foreman chat launch. Only the fixed POST chat path is
		// permitted, and the host-generated chat policy must be the frozen
		// packet-A policy bound to this exact sandbox and target.
		chat := grant.Chat
		wantChatMethods := []string{"GET", "POST"}
		var advisory *ForemanChatAdvisoryV1
		if chat != nil {
			advisory = chat.Advisory
		}
		if grant.Capability != "foreman_chat" || chat == nil || chat.Qualification == nil ||
			!validForemanChatQualification(chat.Qualification) ||
			chat.Protocol != ForemanChatProtocol ||
			chat.MaxQuestionBytes != ForemanChatQuestionBytes || chat.MaxReplyBytes != ForemanChatReplyBytes ||
			chat.MaxQuestionsPerMinute != ForemanChatQuestionsPerMinute ||
			chat.MaxConcurrent != ForemanChatMaxConcurrent ||
			chat.HandoffID == "" || !strings.HasPrefix(chat.NativeSessionID, "ses_") ||
			chat.ServiceRegistrationID == "" || chat.ServiceGeneration < 1 ||
			chat.ProjectID == "" || chat.WorkspaceEpoch == "" ||
			advisory == nil || advisory.FormatVersion != 1 ||
			advisory.Capability != ForemanChatAdvisoryCapability ||
			!strings.HasPrefix(advisory.AdmissionID, "fca_") ||
			advisory.ServerID != grant.ServerID || advisory.SandboxID != grant.SandboxID ||
			advisory.SandboxGeneration != grant.Generation || advisory.Instance != grant.Instance ||
			advisory.NativeSessionID != chat.NativeSessionID ||
			advisory.ServiceRegistrationID != chat.ServiceRegistrationID ||
			advisory.ServiceGeneration != chat.ServiceGeneration ||
			advisory.Role != "orchestrator" || advisory.RoleBindingID == "" ||
			advisory.HandoffID != chat.HandoffID ||
			advisory.Projection == nil || advisory.RoleAgentDigest != model.WorkspaceDigest(*advisory.Projection) ||
			advisory.Projection.NativeAgentID != "warpmetal-controller-orchestrator" ||
			advisory.Projection.ToolsDisabled != true || advisory.Projection.MCPDisabled != true ||
			advisory.Projection.ModelSelection == nil ||
			advisory.Projection.ModelSelection.Authority != (model.CellPreparedAuthorityV3{ProviderID: "openai", ModelID: ForemanChatAdvisoryModelID, AuthMode: "api_key"}) ||
			advisory.Projection.ModelSelection.CredentialBinding == nil ||
			advisory.IssuedAt.IsZero() || advisory.ExpiresAt.IsZero() ||
			!advisory.IssuedAt.Equal(grant.IssuedAt) || !advisory.ExpiresAt.Equal(grant.ExpiresAt) ||
			!slices.Equal(grant.AllowedMethods, wantChatMethods) {
			return errors.New("invalid Foreman chat launch")
		}
	}
	grantJSON, err := json.Marshal(grant)
	if err != nil || len(grantJSON) > 16*1024 {
		return errors.New("invalid session handoff grant")
	}
	executionContext, cancel := context.WithDeadline(ctx, grant.ExpiresAt)
	defer cancel()
	stdin := prefixedSessionInput{
		Reader: io.MultiReader(bytes.NewReader(launch.HelloFrame), input),
		input:  input,
	}
	args := []string{
		"exec", "-i", "--user", "1000:1000", "--workdir", "/home/agent",
		"--env", "WM_TEAM_BRIDGE_GRANT=" + string(grantJSON), containerName(id),
		capabilityLauncherPath, "/usr/bin/python3",
		"/usr/local/libexec/warpmetal-agent-teams/warpmetal_team_bridge.py", "helper",
	}
	return p.runCommandStreams(executionContext, true, stdin, stdout, stderr, args...)
}

// validForemanChatQualification keeps the qualification client configuration a
// closed, host-generated shape: absolute venue paths, an explicit signed policy
// digest, and a broker outside the read-only tree.
func validForemanChatQualification(value *ForemanChatQualificationV1) bool {
	if value == nil || value.FormatVersion != ForemanChatQualificationFormat ||
		!absoluteConversationPath(value.Tree) || !absoluteConversationPath(value.Key) ||
		!absoluteConversationPath(value.Broker) || value.Tree == value.Key ||
		strings.HasPrefix(value.Key, strings.TrimSuffix(value.Tree, "/")+"/") ||
		len(value.PolicyDigest) != 71 || !strings.HasPrefix(value.PolicyDigest, "sha256:") {
		return false
	}
	for _, character := range value.PolicyDigest[7:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func absoluteConversationPath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.Contains(value, "//") &&
		!strings.Contains(value, "/../") && !strings.HasSuffix(value, "/..") &&
		!strings.ContainsAny(value, " \t\r\n")
}

// ForemanChatQualificationFromEnv parses the optional venue configuration. It
// is never a product default: an empty value leaves Foreman chat unconfigured
// and the handoff refuses before any bridge process exists.
func ForemanChatQualificationFromEnv(raw string) (*ForemanChatQualificationV1, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var value ForemanChatQualificationV1
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("invalid Foreman chat qualification configuration")
	}
	if !validForemanChatQualification(&value) {
		return nil, errors.New("invalid Foreman chat qualification configuration")
	}
	return &value, nil
}

func execArguments(id, command string, tty bool) []string {
	args := []string{"exec", "-i"}
	if tty {
		args = append(args, "-t")
	}
	args = append(args, containerName(id), "/bin/sh", "-c", capabilityLauncherDispatch, "warpmetal-shell")
	if command == "" {
		args = append(args, "-l")
	} else {
		args = append(args, "-lc", command)
	}
	return args
}

// ExecSetup is the only container execution path available to setup
// reconciliation. The caller can select a sandbox and provide JSON stdin, but
// cannot influence the executable, argv, uid, working directory, timeout,
// output limits, or the test-venue source gate environment.
func (p Podman) ExecSetup(
	ctx context.Context,
	id string,
	request []byte,
) ([]byte, []byte, error) {
	if len(request) == 0 || len(request) > maxSetupRequestBytes {
		return nil, nil, errors.New("setup request exceeds the allowed size")
	}
	// The default-off test-venue gate is operator configuration on this
	// Runtime instance, never request data. A requested-but-invalid gate fails
	// closed here, before any container execution.
	gateEnvironment, err := p.SetupTestSource.Environment()
	if err != nil {
		return nil, nil, fmt.Errorf("setup test source: %w", err)
	}
	executionContext, cancel := context.WithTimeout(ctx, setupOperationTimeout)
	defer cancel()
	receipt := &boundedBuffer{maximum: maxSetupReceiptBytes}
	diagnostic := &boundedBuffer{maximum: maxSetupDiagnosticBytes}
	args := []string{"exec", "-i", "--user", "1000:1000", "--workdir", "/home/agent"}
	for _, variable := range gateEnvironment {
		args = append(args, "--env", variable)
	}
	args = append(args,
		containerName(id), "/usr/local/libexec/warpmetal-capability-launcher",
		"/usr/local/bin/warpmetal-setup-runner",
	)
	err = p.runCommandStreams(
		executionContext,
		true,
		setupRequestInput{bytes.NewReader(request)},
		receipt,
		diagnostic,
		args...,
	)
	if receipt.overflow || diagnostic.overflow {
		err = errors.Join(err, errors.New("setup runner output exceeds the allowed size"))
	}
	if err != nil {
		return receipt.Bytes(), diagnostic.Bytes(), err
	}
	return receipt.Bytes(), diagnostic.Bytes(), nil
}

func (p Podman) ExecContinuity(ctx context.Context, id string, request []byte) ([]byte, []byte, error) {
	if len(request) == 0 || len(request) > maxContinuityRequestBytes {
		return nil, nil, errors.New("continuity request exceeds the allowed size")
	}
	executionContext, cancel := context.WithTimeout(ctx, continuityHelperTimeout)
	defer cancel()
	receipt := &boundedBuffer{maximum: maxContinuityReceiptBytes}
	diagnostic := &boundedBuffer{maximum: maxContinuityDiagnosticBytes}
	err := p.runRemoteStreams(executionContext, bytes.NewReader(request), receipt, diagnostic,
		"exec", "-i", "--user", "1000:1000", "--workdir", "/home/agent",
		containerName(id), "/usr/local/libexec/warpmetal-capability-launcher",
		"/usr/local/bin/warpmetal-continuity")
	if receipt.overflow || diagnostic.overflow {
		err = errors.Join(err, errors.New("continuity helper output exceeds the allowed size"))
	}
	return receipt.Bytes(), diagnostic.Bytes(), err
}

// ExecMonitor is the only Runtime path to the packaged metadata exporter.
func (p Podman) ExecMonitor(ctx context.Context, id string, request []byte) ([]byte, []byte, error) {
	if len(request) == 0 || len(request) > maxMonitorRequestBytes {
		return nil, nil, errors.New("monitor request exceeds the allowed size")
	}
	executionContext, cancel := context.WithTimeout(ctx, monitorHelperTimeout)
	defer cancel()
	receipt := &boundedBuffer{maximum: maxMonitorReceiptBytes}
	diagnostic := &boundedBuffer{maximum: maxMonitorDiagnosticBytes}
	err := p.runRemoteStreams(executionContext, bytes.NewReader(request), receipt, diagnostic,
		"exec", "-i", "--user", "1000:1000", "--workdir", "/home/agent",
		containerName(id), capabilityLauncherPath, "/usr/local/bin/warpmetal-monitor")
	if receipt.overflow || diagnostic.overflow {
		err = errors.Join(err, errors.New("monitor exporter output exceeds the allowed size"))
	}
	return receipt.Bytes(), diagnostic.Bytes(), err
}

// ExecManager is the only Runtime path to the packaged manager helper. The
// sandbox ID and bounded JSON stdin are the only caller-controlled inputs;
// executable, argv, uid, working directory, deadline, and output bounds are
// fixed here.
func (p Podman) ExecManager(ctx context.Context, id string, request []byte) ([]byte, []byte, error) {
	if len(request) == 0 || len(request) > maxManagerRequestBytes {
		return nil, nil, errors.New("manager request exceeds the allowed size")
	}
	executionContext, cancel := context.WithTimeout(ctx, managerHelperTimeout)
	defer cancel()
	receipt := &boundedBuffer{maximum: maxManagerReceiptBytes}
	diagnostic := &boundedBuffer{maximum: maxManagerDiagnosticBytes}
	err := p.runRemoteStreams(executionContext, bytes.NewReader(request), receipt, diagnostic,
		"exec", "-i", "--user", "1000:1000", "--workdir", "/home/agent",
		containerName(id), "/usr/local/libexec/warpmetal-capability-launcher", "/usr/local/bin/warpmetal-manager")
	if receipt.overflow || diagnostic.overflow {
		err = errors.Join(err, errors.New("manager helper output exceeds the allowed size"))
	}
	return receipt.Bytes(), diagnostic.Bytes(), err
}

// managedSupervisorLauncher selects the packaged supervisor for one closed
// action. The request is bounded and already validated by the caller; only the
// closed profileId field may select the DeepSeek/ACP supervisor. Unknown or
// missing profiles stay on the existing OpenCode supervisor.
func managedSupervisorLauncher(action ManagedSupervisorAction, request []byte) []string {
	var envelope struct {
		ProfileID string `json:"profileId"`
	}
	if len(request) > 0 && json.Unmarshal(request, &envelope) == nil && envelope.ProfileID == "deepseek" {
		switch action {
		case ManagedSupervisorEnroll, ManagedSupervisorStart, ManagedSupervisorRestart, ManagedSupervisorStatus,
			ManagedSupervisorStop, ManagedSupervisorDrain, ManagedSupervisorCredential, ManagedSupervisorRebind,
			ManagedSupervisorRegisterSource, ManagedSupervisorControllerPrepare, ManagedSupervisorControllerPrompt,
			ManagedSupervisorMaterializeProfile, ManagedSupervisorControllerHeader, ManagedSupervisorControllerOutput:
			return []string{"/usr/local/bin/warpmetal-deepseek-supervisor", string(action)}
		}
	}
	return []string{"/usr/local/bin/warpmetal-opencode-supervisor", string(action)}
}

func (p Podman) ExecManagedSupervisor(ctx context.Context, id string, action ManagedSupervisorAction, request []byte) ([]byte, []byte, error) {
	switch action {
	case ManagedSupervisorEnroll, ManagedSupervisorStart, ManagedSupervisorRestart, ManagedSupervisorRebind, ManagedSupervisorCredential,
		ManagedSupervisorStatus, ManagedSupervisorRegisterSource, ManagedSupervisorRegisterHandoffWorkspace, ManagedSupervisorDrain,
		ManagedSupervisorControllerPrepare, ManagedSupervisorControllerPrompt, ManagedSupervisorControllerOutput, ManagedSupervisorControllerHeader, ManagedSupervisorChildHeader, ManagedSupervisorChildEffectCapture, ManagedSupervisorChildResultCapture, ManagedSupervisorChildIntegrationCapture, ManagedSupervisorChildPreparedCapture, ManagedSupervisorChildCompletedCapture, ManagedSupervisorReviewerCapture, ManagedSupervisorSourceTerminalCapture,
		ManagedSupervisorQualificationHeader, ManagedSupervisorStop, ManagedSupervisorCell, ManagedSupervisorPrepare, ManagedSupervisorMaterializeProfile,
		ManagedSupervisorMaterializeAgentKit:
	default:
		return nil, nil, errors.New("unsupported managed supervisor action")
	}
	maximum := 64 * 1024
	if action == ManagedSupervisorMaterializeProfile {
		// Complete immutable content through the same fixed Supervisor, not a
		// command/URL/import executor. Retained launch/activity limits unchanged.
		maximum = 2 * 1024 * 1024
	}
	if action == ManagedSupervisorMaterializeAgentKit {
		// Bounded closed invocation document (WP-211A channel contract): the
		// nested materializer request alone is bounded to 512 KiB by the
		// supervisor; the outer document adds only the adoption/closure facts.
		maximum = 640 * 1024
	}
	if len(request) == 0 || len(request) > maximum {
		return nil, nil, errors.New("managed supervisor request exceeds the allowed size")
	}
	executionTimeout := 5 * time.Minute
	if action == ManagedSupervisorMaterializeAgentKit {
		// Offline local file work with a 30 s in-channel deadline; the exec
		// binding keeps a tighter outer kill so a wedged cell cannot hold the
		// reconcile pass. The child receives no network or credential use here.
		executionTimeout = 90 * time.Second
	}
	executionContext, cancel := context.WithTimeout(ctx, executionTimeout)
	defer cancel()
	receipt := &boundedBuffer{maximum: model.ControllerTransportReceiptMaximum(string(action))}
	diagnostic := &boundedBuffer{maximum: 16 * 1024}
	// The member supervisor actions run the packaged supervisor. The cell action
	// and the v3 prepare action run the trusted SA4 cell adapter (create_child ->
	// bind_workspace -> admit_first_step, and observe/recover/classify_child) as
	// an unjailed python3 process with credentials and network. Neither runs the
	// credential-less bwrap tool entrypoint; prepare never admits a first step.
	launcherCommand := managedSupervisorLauncher(action, request)
	if action == ManagedSupervisorCell || action == ManagedSupervisorPrepare {
		launcherCommand = []string{"/usr/bin/python3", ManagedCellAdapterPath}
	}
	args := append([]string{"exec", "-i", "--user", "1000:1000", "--workdir", "/home/agent", containerName(id), capabilityLauncherPath}, launcherCommand...)
	err := p.runRemoteStreams(executionContext, bytes.NewReader(request), receipt, diagnostic, args...)
	if receipt.overflow || diagnostic.overflow {
		err = errors.Join(err, errors.New("managed supervisor output exceeds the allowed size"))
	}
	if err != nil {
		return receipt.Bytes(), diagnostic.Bytes(), err
	}
	if err := p.registerSupervisorPhysicalProcess(ctx, id, receipt.Bytes()); err != nil {
		return receipt.Bytes(), diagnostic.Bytes(), err
	}
	return receipt.Bytes(), diagnostic.Bytes(), nil
}

func (p Podman) ExecManagedWorker(ctx context.Context, id string, action ManagedWorkerAction, request []byte) ([]byte, []byte, error) {
	var envelope struct {
		Command string `json:"command"`
	}
	if len(request) == 0 || len(request) > 256*1024 || json.Unmarshal(request, &envelope) != nil || envelope.Command != string(action) {
		return nil, nil, errors.New("managed worker request is invalid")
	}
	var timeout time.Duration
	switch action {
	case ManagedWorkerExecute:
		timeout = 35 * time.Minute
	case ManagedWorkerReconcile, ManagedWorkerStatus:
		timeout = 2 * time.Minute
	default:
		return nil, nil, errors.New("unsupported managed worker action")
	}
	executionContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	receipt := &boundedBuffer{maximum: 64 * 1024}
	diagnostic := &boundedBuffer{maximum: 16 * 1024}
	args := []string{"exec", "-i", "--user", "1000:1000", "--workdir", "/home/agent", containerName(id), "/usr/local/libexec/warpmetal-capability-launcher", "/usr/bin/python3", "/usr/local/libexec/warpmetal-agent-teams/warpmetal_team_worker.py"}
	err := p.runRemoteStreams(executionContext, bytes.NewReader(request), receipt, diagnostic, args...)
	if receipt.overflow || diagnostic.overflow {
		err = errors.Join(err, errors.New("managed worker output exceeds the allowed size"))
	}
	if err != nil {
		return receipt.Bytes(), diagnostic.Bytes(), err
	}
	return receipt.Bytes(), diagnostic.Bytes(), nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

func (w *boundedBuffer) Write(content []byte) (int, error) {
	remaining := w.maximum - w.buffer.Len()
	if remaining <= 0 {
		w.overflow = true
		return len(content), nil
	}
	if len(content) > remaining {
		w.overflow = true
		_, _ = w.buffer.Write(content[:remaining])
		return len(content), nil
	}
	_, _ = w.buffer.Write(content)
	return len(content), nil
}

func (w *boundedBuffer) Bytes() []byte {
	return append([]byte(nil), w.buffer.Bytes()...)
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
	stdin SessionInput,
	stdout io.Writer,
	stderr io.Writer,
	args ...string,
) error {
	if p.runStreamCommand != nil {
		return p.runStreamCommand(ctx, remote, stdin, stdout, stderr, args...)
	}
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
	configureProcessGroupCancellation(cmd)
	return runProcessStreams(cmd, stdin, stdout, stderr)
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
	configureProcessGroupCancellation(cmd)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func configureProcessGroupCancellation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
}

func runProcessStreams(
	cmd *exec.Cmd,
	stdin SessionInput,
	stdout io.Writer,
	stderr io.Writer,
) error {
	childInput, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = childInput.Close()
		return err
	}

	inputPumpDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(childInput, stdin)
		inputPumpDone <- copyErr
		_ = childInput.Close()
	}()

	waitErr := cmd.Wait()
	_ = childInput.Close()
	pumpCompletedBeforeInterrupt := false
	var pumpErr error
	select {
	case pumpErr = <-inputPumpDone:
		pumpCompletedBeforeInterrupt = true
	default:
	}
	interruptErr := stdin.InterruptRead()
	if !pumpCompletedBeforeInterrupt {
		pumpErr = <-inputPumpDone
	}
	if waitErr != nil {
		return waitErr
	}
	if !pumpCompletedBeforeInterrupt {
		pumpErr = nil
	}
	return errors.Join(pumpErr, interruptErr)
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
	return createArgumentsWithLifecycle(name, sandbox, workspace, imageDigest, DefaultCellLifecycle())
}

// createArgumentsWithLifecycle builds the immutable Podman create argv. A
// legacy Team/member sandbox (sandbox.Cell == false) is byte-for-byte
// unchanged. A cell sandbox additionally names the trusted hook storage with
// the explicit `--hooks-dir` persistent flag and carries the exact allowlisted
// lifecycle annotation, so the packaged `precreate` config hook injects the
// fixed childless procfs witness at container creation. Exactly one of each is
// emitted per create, so reconciler re-create cannot accumulate duplicates.
func createArgumentsWithLifecycle(
	name string,
	sandbox model.Sandbox,
	workspace string,
	imageDigest string,
	lifecycle CellLifecycle,
) []string {
	memory := strconv.Itoa(sandbox.Resources.MemoryMiB) + "m"
	cpu := fmt.Sprintf("%.3f", float64(sandbox.Resources.CPUMillicores)/1000)
	arguments := []string{
		"create",
	}
	if sandbox.Cell {
		arguments = append(arguments,
			"--hooks-dir", lifecycle.Directory,
			"--annotation", CellLifecycleAnnotationKey+"="+lifecycle.Profile,
		)
	}
	return append(arguments,
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
		"--label", imageDigestLabel+"="+imageDigest,
		"--network", "slirp4netns:allow_host_loopback=false",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
		"--volume", workspace+":/home/agent:rw,nodev,nosuid,Z",
		"--workdir", "/home/agent",
		"--entrypoint", "/bin/sh",
		imageDigest,
		"-c", capabilityLauncherDispatch, "warpmetal-shell", "-c", "trap : TERM INT; sleep infinity & wait",
	)
}

func containerName(id string) string { return "warpmetal-" + id }
