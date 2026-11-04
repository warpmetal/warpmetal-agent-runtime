package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// SA9 childless-procfs witness.
//
// A formatVersion 2 cell worker must keep its own PID namespace with its own
// procfs, but a fresh `mount("proc", ...)` inside the worker's nested
// bubblewrap jail is refused by the kernel (`mount_too_revealing` /
// `mnt_already_visible`) because the container's `/proc` carries inherited
// MNT_LOCKED submounts. The reviewed fix is a Podman `precreate` configuration
// hook that appends one fixed childless `proc` mount to the cell container's
// OCI config, so crun mounts it at container creation, *before* the UID-1000 /
// empty-capability payload transition, at a destination outside every worker
// bind source.
//
// These constants are the single reviewed source of truth for the annotation
// allowlist, the hook storage and the exact witness mount. A precreate hook
// cannot run as an exec hook in the runtime namespaces (those are not the
// container mount namespace), so this is deliberately a config transformation.
const (
	// CellWitnessMountDestination is the fixed witness mount destination. It is
	// outside every worker bind source and is never mapped by the cell bwrap
	// jail, so no worker tool path can reach it.
	CellWitnessMountDestination = "/warpmetal-proc-witness"
	// CellLifecycleAnnotationKey and CellLifecycleProfile are the exact OCI
	// annotation the reviewed cell sandbox lifecycle sets. The packaged hook's
	// `when.annotations` matches only this profile, so the hook never applies to
	// a legacy Team/member sandbox or an unrelated host container.
	CellLifecycleAnnotationKey = "io.warpmetal.cell.lifecycle"
	CellLifecycleProfile       = "sa9-proc-witness-v1"
	// CellHookDirectory is the trusted, root/control-owned hook storage. The
	// podman runtime user only reads it; the container/worker never can.
	CellHookDirectory      = "/usr/libexec/warpmetal-agent-runtime/hooks"
	CellHookConfigName     = "sa9-precreate-hook.json"
	CellHookExecutableName = "sa9-precreate-hook.py"
)

// cellWitnessMount is the exact reviewed OCI mount, matching
// packaging/sa9/sa9-precreate-hook.py byte-for-field.
var cellWitnessMount = map[string]any{
	"destination": CellWitnessMountDestination,
	"type":        "proc",
	"source":      "proc",
	"options":     []any{"rw", "nosuid", "nodev", "noexec", "relatime"},
}

// cellWitnessAnnotationFormat is the podman `inspect --format` template that
// prints the container's lifecycle annotation (empty when absent).
const cellWitnessAnnotationFormat = `{{ index .Config.Annotations "` + CellLifecycleAnnotationKey + `" }}`

// cellWitnessIdentityFormat resolves the container's immutable ID and its
// lifecycle annotation in ONE atomic inspect, so the follow-up exec can target
// the same container object by ID (never the mutable name, which can race a
// replacement between two separate lookups).
const cellWitnessIdentityFormat = `{{.ID}}|` + cellWitnessAnnotationFormat

// CellLifecycle names the reviewed SA9 hook storage and the single allowlisted
// profile. Production uses DefaultCellLifecycle; tests and non-default
// installations may override it.
type CellLifecycle struct {
	Directory string
	Profile   string
}

// DefaultCellLifecycle is the packaged SA9 hook storage and allowlisted profile.
func DefaultCellLifecycle() CellLifecycle {
	return CellLifecycle{Directory: CellHookDirectory, Profile: CellLifecycleProfile}
}

func (p Podman) cellLifecycle() CellLifecycle {
	if p.CellLifecycle != nil {
		return *p.CellLifecycle
	}
	directory := p.HooksDir
	if directory == "" {
		directory = CellHookDirectory
	}
	return CellLifecycle{Directory: directory, Profile: CellLifecycleProfile}
}

// applyCellWitnessMount appends exactly one childless procfs witness to a
// proposed OCI runtime config when the container carries the allowlisted cell
// lifecycle annotation. It is idempotent (an existing witness destination is a
// byte-exact no-op) and passes a non-allowlisted config through unchanged. It
// is the Go mirror of the packaged hook, used by tests.
func applyCellWitnessMount(config []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(config))
	decoder.UseNumber()
	var spec map[string]any
	if err := decoder.Decode(&spec); err != nil {
		return nil, fmt.Errorf("invalid OCI config: %w", err)
	}
	if spec == nil {
		return nil, errors.New("invalid OCI config: not a JSON object")
	}
	annotations, _ := spec["annotations"].(map[string]any)
	if value, _ := annotations[CellLifecycleAnnotationKey].(string); value != CellLifecycleProfile {
		return config, nil
	}
	mounts := []any{}
	if existing, ok := spec["mounts"]; ok {
		list, ok := existing.([]any)
		if !ok {
			return nil, errors.New("invalid OCI config: mounts is not a list")
		}
		mounts = list
	}
	for _, raw := range mounts {
		if mount, ok := raw.(map[string]any); ok && mount["destination"] == CellWitnessMountDestination {
			return config, nil
		}
	}
	spec["mounts"] = append(mounts, cloneMount(cellWitnessMount))
	modified, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("encode OCI config: %w", err)
	}
	return modified, nil
}

func cloneMount(mount map[string]any) map[string]any {
	cloned := make(map[string]any, len(mount))
	for key, value := range mount {
		if list, ok := value.([]any); ok {
			cloned[key] = append([]any(nil), list...)
			continue
		}
		cloned[key] = value
	}
	return cloned
}

// VerifyCellLifecycle re-runs the fail-closed SA9 capability negotiation
// without touching any container. It is the adopt-path counterpart of the
// create-time gate: a running container is only treated as an observed cell
// when the host still carries the reviewed immutable hook storage and the
// pinned Podman/crun precreate support. It never creates or starts a
// container and never observes readiness by itself.
func (p Podman) VerifyCellLifecycle(ctx context.Context) error {
	return p.verifyCellLifecycle(ctx, p.cellLifecycle())
}

// verifyCellLifecycle is the fail-closed capability negotiation for a cell
// launch. If the hook storage is not immutable/allowlisted, or the pinned
// Podman/crun do not support `precreate` + `--hooks-dir`, the cell launch is
// refused. There is no silent no-witness fallback.
func (p Podman) verifyCellLifecycle(ctx context.Context, lifecycle CellLifecycle) error {
	if err := verifyCellHookStorage(lifecycle); err != nil {
		return fmt.Errorf("cell lifecycle hook storage: %w", err)
	}
	podmanVersion, err := p.runOutput(ctx, false, "version", "--format", "{{.Version}}")
	if err != nil {
		return fmt.Errorf("probe podman version for cell lifecycle: %w", err)
	}
	if !versionAtLeast(podmanVersion, [3]int{4, 9, 3}) {
		return fmt.Errorf("cell lifecycle unsupported: podman %q lacks precreate + --hooks-dir", strings.TrimSpace(podmanVersion))
	}
	crunVersion, err := p.runOutput(ctx, false, "info", "--format", "{{.Host.OCIRuntime.Version}}")
	if err != nil {
		return fmt.Errorf("probe crun version for cell lifecycle: %w", err)
	}
	if !versionAtLeast(crunVersion, [3]int{1, 14, 1}) {
		return fmt.Errorf("cell lifecycle unsupported: crun %q cannot mount the pre-transition witness", strings.TrimSpace(crunVersion))
	}
	return nil
}

// verifyCellHookStorage enforces that the hook storage is immutable and that
// the installed hook config is the exact reviewed allowlisted configuration.
func verifyCellHookStorage(lifecycle CellLifecycle) error {
	if lifecycle.Directory == "" || lifecycle.Profile != CellLifecycleProfile {
		return errors.New("cell lifecycle configuration is incomplete or not the reviewed profile")
	}
	directory, err := os.Lstat(lifecycle.Directory)
	if err != nil {
		return err
	}
	if !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real directory", lifecycle.Directory)
	}
	if directory.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group or world writable", lifecycle.Directory)
	}
	executablePath := filepath.Join(lifecycle.Directory, CellHookExecutableName)
	executable, err := os.Lstat(executablePath)
	if err != nil {
		return err
	}
	if !executable.Mode().IsRegular() || executable.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is not an immutable regular file", executablePath)
	}
	if executable.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", executablePath)
	}
	configPath := filepath.Join(lifecycle.Directory, CellHookConfigName)
	configInfo, err := os.Lstat(configPath)
	if err != nil {
		return err
	}
	if !configInfo.Mode().IsRegular() || configInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is not an immutable regular file", configPath)
	}
	if os.Geteuid() == 0 {
		if stat, ok := directory.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
			return fmt.Errorf("%s is not root-owned", lifecycle.Directory)
		}
		if stat, ok := configInfo.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
			return fmt.Errorf("%s is not root-owned", configPath)
		}
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var config struct {
		Version string `json:"version"`
		Hook    struct {
			Path string `json:"path"`
		} `json:"hook"`
		When struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"when"`
		Stages []string `json:"stages"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return fmt.Errorf("%s is not a valid hook config: %w", configPath, err)
	}
	if config.Version != "1.0.0" || filepath.Base(config.Hook.Path) != CellHookExecutableName {
		return fmt.Errorf("%s is not the reviewed hook config", configPath)
	}
	hasPrecreate := false
	for _, stage := range config.Stages {
		if stage == "precreate" {
			hasPrecreate = true
		}
	}
	if !hasPrecreate {
		return fmt.Errorf("%s does not declare the precreate stage", configPath)
	}
	pattern, ok := config.When.Annotations[CellLifecycleAnnotationKey]
	if !ok {
		return fmt.Errorf("%s does not allowlist %s", configPath, CellLifecycleAnnotationKey)
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil || !compiled.MatchString(CellLifecycleProfile) {
		return fmt.Errorf("%s does not allowlist the reviewed profile", configPath)
	}
	return nil
}

var versionNumberPattern = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// versionAtLeast reports whether the first semantic version in text is at
// least want. A missing version is never considered supported.
func versionAtLeast(text string, want [3]int) bool {
	match := versionNumberPattern.FindStringSubmatch(text)
	if match == nil {
		return false
	}
	for index := range want {
		value, err := strconv.Atoi(match[index+1])
		if err != nil {
			return false
		}
		if value != want[index] {
			return value > want[index]
		}
	}
	return true
}

// cellWitnessReady parses a container `/proc/self/mountinfo` snapshot and
// reports whether a childless procfs witness is actually mounted at the fixed
// destination. It requires (a) a procfs (fstype `proc`) is mounted at the
// destination and (b) the witness mount has NO descendant mounts (the
// `mnt_already_visible` "childless procfs witness" predicate).
//
// It deliberately does NOT claim to distinguish a fresh `mount -t proc` from a
// non-recursive bind of the parent `/proc` on these fields alone: a bind mount
// retains the fstype=proc AND source=proc labels and appears childless, so
// mountinfo cannot reject it. That distinction rests on the trusted OCI
// creation provenance (the precreate hook injects `type=proc,source=proc`,
// never `type=bind`) and the frozen hardening that denies every in-container
// principal mount capability; worker private-proc isolation is proven by the
// live gate, not this observation. This is a PREREQUISITE witness-availability
// check, not an isolation proof.
func cellWitnessReady(mountinfo string) bool {
	var witnessID string
	witnessIsProc := false
	var parentIDs []string
	for _, line := range strings.Split(mountinfo, "\n") {
		if line == "" {
			continue
		}
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		leftFields := strings.Fields(left)
		if len(leftFields) < 5 {
			continue
		}
		rightFields := strings.Fields(right)
		if len(rightFields) == 0 {
			continue
		}
		mountID := leftFields[0]
		parentID := leftFields[1]
		mountpoint := leftFields[4]
		fstype := rightFields[0]
		parentIDs = append(parentIDs, parentID)
		if mountpoint == CellWitnessMountDestination {
			witnessID = mountID
			witnessIsProc = fstype == "proc"
		}
	}
	if witnessID == "" || !witnessIsProc {
		return false
	}
	// Childless: no mount in the namespace may have the witness as its parent.
	for _, parentID := range parentIDs {
		if parentID == witnessID {
			return false
		}
	}
	return true
}

// ObserveCellWitness verifies the running cell container's CURRENT mount
// namespace actually carries the reviewed childless procfs witness. It never
// infers readiness from the desired cell flag, hook-file presence, or a create
// request. A missing/foreign annotation, an absent/replaced/childed witness, or
// a failed read all return ready=false (fail closed); only a container that
// carries the exact allowlisted lifecycle profile AND an actual childless
// procfs mount at the fixed destination returns true. The error result is
// always nil: an unobservable witness returns ready=false rather than an error,
// so it never fails the enclosing sandbox reconcile and simply keeps cell
// admission blocked until a later reconcile observes it.
func (p Podman) ObserveCellWitness(ctx context.Context, id string) (bool, error) {
	name := containerName(id)
	// 1. Resolve the container's immutable ID and lifecycle annotation in a
	// single atomic inspect, then gate on the exact allowlisted profile.
	out, err := p.runOutput(ctx, true, "inspect", "--format", cellWitnessIdentityFormat, name)
	if err != nil {
		return false, nil
	}
	containerID, annotation, ok := strings.Cut(strings.TrimSpace(out), "|")
	if !ok || strings.TrimSpace(containerID) == "" || annotation != CellLifecycleProfile {
		return false, nil
	}
	// 2. Read the SAME container's mount namespace by immutable ID (not name),
	// so a replacement between inspect and exec cannot skew the observation.
	mountinfo, err := p.runOutput(ctx, true, "exec", "--user", "1000:1000", containerID, "/bin/cat", "/proc/self/mountinfo")
	if err != nil {
		return false, nil
	}
	return cellWitnessReady(mountinfo), nil
}
