package containers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	networkHelperTermGrace = 2 * time.Second
	networkHelperKillGrace = 1 * time.Second
	maxHelperTreeDepth     = 8
)

// networkHelperNames are the rootless network helper process names this
// Runtime owns. Podman 4.9 creates slirp4netns for the cell's fixed
// `--network slirp4netns:...`; a host configured for pasta uses the same
// lifecycle boundary.
var networkHelperNames = map[string]bool{
	"slirp4netns": true,
	"pasta":       true,
}

// helperProcessTable is the read-only host process view used to attribute a
// slirp4netns/pasta helper to one cell. Production reads /proc; the narrow
// interface exists so the cross-cell safety properties can be exercised with a
// fake two-cell process table on any platform.
type helperProcessTable interface {
	PIDs() ([]int, error)
	Identity(pid int) (networkHelperProcess, error)
	NetnsInode(pid int) (uint64, bool)
	Cgroup(pid int) (string, error)
	Argv(pid int) ([]string, error)
	Children(pid int) ([]int, error)
	NetnsPathInode(path string) (uint64, bool)
	SelfNetnsInode() (uint64, bool)
}

// procHelperProcessTable is the production /proc implementation.
type procHelperProcessTable struct{}

func (p Podman) helperProcessTable() helperProcessTable {
	if p.helperProcesses != nil {
		return p.helperProcesses
	}
	return procHelperProcessTable{}
}

func (procHelperProcessTable) PIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func (procHelperProcessTable) Identity(pid int) (networkHelperProcess, error) {
	return readProcessIdentity(pid)
}

func (procHelperProcessTable) NetnsInode(pid int) (uint64, bool) {
	return processNetnsInode(pid)
}

func (procHelperProcessTable) Cgroup(pid int) (string, error) {
	payload, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	return string(payload), err
}

func (procHelperProcessTable) Argv(pid int) ([]string, error) {
	payload, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return nil, err
	}
	return splitCommandLine(payload), nil
}

func (procHelperProcessTable) Children(pid int) ([]int, error) {
	return processChildPIDs(pid)
}

func (procHelperProcessTable) NetnsPathInode(path string) (uint64, bool) {
	return pathNetnsInode(path)
}

func (procHelperProcessTable) SelfNetnsInode() (uint64, bool) {
	return processNetnsInode(os.Getpid())
}

func splitCommandLine(payload []byte) []string {
	var argv []string
	for _, field := range strings.Split(string(payload), "\x00") {
		if field != "" {
			argv = append(argv, field)
		}
	}
	return argv
}

// observeNetworkHelpers captures the live network helpers associated with the
// named container BEFORE its conmon is torn down.
//
// Attribution is per-container and fail-closed:
//   - an uninspectable container (no ID) has no kill scope;
//   - conmon's network namespace is never used: conmon stays in the host
//     namespace, which every cell and every helper shares (WP-64 evidence),
//     so it would attribute every helper on the host to every cell;
//   - a container that shares the host/observer namespace is never attributed
//     by namespace either;
//   - a helper carrying any association with another RUNNING container is
//     excluded even when the target association also matches;
//   - a helper with no exact association (same-named process, shared cgroup
//     parent only) is left alone.
func (p Podman) observeNetworkHelpers(ctx context.Context, name string) []networkHelperProcess {
	if p.networkHelperPIDs != nil {
		return p.networkHelperPIDs(ctx, name)
	}
	table := p.helperProcessTable()
	scope := p.containerHelperScope(ctx, name)
	if scope.ID == "" {
		return nil
	}
	targetNetns, netnsUsable := targetContainerNetns(scope, table)
	conmonVerified := false
	if scope.ConmonPid > 1 {
		if identity, err := table.Identity(scope.ConmonPid); err == nil {
			conmonVerified = identity.Comm == "conmon" && identity.State != "Z"
		}
	}
	descendants := map[int]bool{}
	if conmonVerified {
		collectProcessTree(table, scope.ConmonPid, descendants, 0)
	}
	// Container-netns attribution additionally requires an authoritative list
	// of running peers: without it a shared namespace cannot be ruled out, so
	// only per-container evidence (helper netns path, cgroup scope, argv ID,
	// verified conmon) is used and the shared-inode signal is disabled.
	peers, peersKnown := p.runningPeerContainers(ctx, scope.ID, table)
	if !peersKnown {
		netnsUsable = false
	}
	pids, err := table.PIDs()
	if err != nil {
		return nil
	}
	var helpers []networkHelperProcess
	for _, pid := range pids {
		if pid <= 1 || pid == scope.Pid || pid == scope.ConmonPid {
			continue
		}
		identity, err := table.Identity(pid)
		if err != nil || !networkHelperNames[identity.Comm] || identity.State == "Z" {
			continue
		}
		if helperOwnedByOtherContainer(pid, peers, table) {
			continue
		}
		if helperOwnedByContainer(pid, scope.ID, targetNetns, netnsUsable, descendants, table) {
			helpers = append(helpers, identity)
		}
	}
	return helpers
}

type containerHelperScope struct {
	ID        string
	Pid       int
	ConmonPid int
}

func (p Podman) containerHelperScope(ctx context.Context, name string) containerHelperScope {
	output, err := p.runOutput(ctx, true, "container", "inspect", "--format",
		"{{.Id}}|{{.State.Pid}}|{{.State.ConmonPid}}", name)
	if err != nil {
		return containerHelperScope{}
	}
	parts := strings.Split(strings.TrimSpace(output), "|")
	if len(parts) != 3 {
		return containerHelperScope{}
	}
	var scope containerHelperScope
	scope.ID = strings.TrimSpace(parts[0])
	scope.Pid, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
	scope.ConmonPid, _ = strconv.Atoi(strings.TrimSpace(parts[2]))
	return scope
}

// targetContainerNetns returns the container's network namespace inode and
// whether it may be used for attribution. A namespace shared with the Runtime
// (host-netns container) is not discriminating and is refused; an unknown host
// namespace is refused too, so the caller never falls back to a host-wide match.
func targetContainerNetns(scope containerHelperScope, table helperProcessTable) (uint64, bool) {
	if scope.Pid <= 1 {
		return 0, false
	}
	inode, ok := table.NetnsInode(scope.Pid)
	if !ok || inode == 0 {
		return 0, false
	}
	self, ok := table.SelfNetnsInode()
	if !ok || self == 0 || self == inode {
		return 0, false
	}
	return inode, true
}

// helperOwnedByContainer reports whether the helper has an exact, exclusive
// association with the target container. Substring/prefix matches are
// deliberately gone: a cgroup component must name the container's scope and an
// argv token must be the full container ID.
func helperOwnedByContainer(
	pid int,
	id string,
	targetNetns uint64,
	netnsUsable bool,
	descendants map[int]bool,
	table helperProcessTable,
) bool {
	if netnsUsable {
		if inode, ok := table.NetnsInode(pid); ok && inode == targetNetns {
			return true
		}
	}
	if targetNetns != 0 {
		if inode, ok := helperNetnsPathInode(pid, table); ok && inode == targetNetns {
			return true
		}
	}
	if descendants[pid] {
		// Only populated from a conmon PID whose process identity was verified.
		return true
	}
	if cgroup, err := table.Cgroup(pid); err == nil && cgroupNamesContainer(cgroup, id) {
		return true
	}
	if argv, err := table.Argv(pid); err == nil && argvNamesContainer(argv, id) {
		return true
	}
	return false
}

// helperOwnedByOtherContainer is the negative guard. Any evidence tying the
// helper to another running cell wins over every positive signal, so a shared
// namespace, a shared cgroup scope, or a stale/recycled association can never
// turn one cell's stop into another cell's outage.
func helperOwnedByOtherContainer(pid int, peers []peerContainer, table helperProcessTable) bool {
	if len(peers) == 0 {
		return false
	}
	helperNetns, hasNetns := table.NetnsInode(pid)
	pathInode, hasPath := helperNetnsPathInode(pid, table)
	cgroup, cgroupErr := table.Cgroup(pid)
	argv, argvErr := table.Argv(pid)
	for _, peer := range peers {
		if peer.Pid <= 1 {
			continue
		}
		if peer.Netns != 0 && hasNetns && helperNetns == peer.Netns {
			return true
		}
		if peer.Netns != 0 && hasPath && pathInode == peer.Netns {
			return true
		}
		if cgroupErr == nil && cgroupNamesContainer(cgroup, peer.ID) {
			return true
		}
		if argvErr == nil && argvNamesContainer(argv, peer.ID) {
			return true
		}
	}
	return false
}

type peerContainer struct {
	ID    string
	Pid   int
	Netns uint64
}

// runningPeerContainers lists the other live containers so a candidate helper
// can be checked against every cell, not only the target. A failed listing
// reports false so the caller can disable namespace attribution (fail closed).
func (p Podman) runningPeerContainers(
	ctx context.Context,
	targetID string,
	table helperProcessTable,
) ([]peerContainer, bool) {
	// --no-trunc is required: the ps reporter truncates {{.ID}} to 12 chars
	// otherwise, and a short ID cannot be compared exactly with a cgroup scope.
	output, err := p.runOutput(ctx, true, "container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}|{{.Pid}}")
	if err != nil {
		return nil, false
	}
	var peers []peerContainer
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) != 2 {
			continue
		}
		id := strings.TrimSpace(parts[0])
		pid, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if id == "" || id == targetID || err != nil || pid <= 1 {
			continue
		}
		netns, _ := table.NetnsInode(pid)
		peers = append(peers, peerContainer{ID: id, Pid: pid, Netns: netns})
	}
	return peers, true
}

// cgroupNamesContainer accepts only a cgroup path component that is exactly
// the container's systemd/cgroupfs scope. The shared
// `/system.slice/warpmetal-podman.service` parent and short-ID prefixes are
// never matches.
func cgroupNamesContainer(cgroup, id string) bool {
	if id == "" {
		return false
	}
	for _, raw := range strings.Split(strings.TrimSpace(cgroup), "/") {
		component := strings.TrimSuffix(strings.TrimSpace(raw), ".scope")
		if component == id {
			return true
		}
		for _, prefix := range []string{"libpod-conmon-", "libpod-", "crio-"} {
			if strings.HasPrefix(component, prefix) && strings.TrimPrefix(component, prefix) == id {
				return true
			}
		}
	}
	return false
}

// argvNamesContainer accepts only an exact full container ID token (or
// --cid=<full id>). Prefixes are not accepted: a 12-character prefix is not a
// container identity and may appear in unrelated argv.
func argvNamesContainer(argv []string, id string) bool {
	if id == "" {
		return false
	}
	for _, arg := range argv {
		if arg == id || arg == "--cid="+id {
			return true
		}
	}
	return false
}

// helperNetnsPathInode resolves the `--netns-type=path <path>` (or
// `--netns <path>`) argument a rootless helper was started with. slirp4netns
// and pasta run in the host namespace, so this path is the per-cell handle: its
// inode must match the target container's netns inode.
func helperNetnsPathInode(pid int, table helperProcessTable) (uint64, bool) {
	argv, err := table.Argv(pid)
	if err != nil {
		return 0, false
	}
	path, ok := netnsPathArgument(argv)
	if !ok {
		return 0, false
	}
	return table.NetnsPathInode(path)
}

func netnsPathArgument(argv []string) (string, bool) {
	for index, arg := range argv {
		switch {
		case arg == "--netns-type=path":
			if index+1 < len(argv) {
				return argv[index+1], true
			}
		case arg == "--netns-type" && index+2 < len(argv) && argv[index+1] == "path":
			return argv[index+2], true
		case strings.HasPrefix(arg, "--netns="):
			return strings.TrimPrefix(arg, "--netns="), true
		case arg == "--netns" && index+1 < len(argv):
			return argv[index+1], true
		}
	}
	return "", false
}

func collectProcessTree(table helperProcessTable, pid int, found map[int]bool, depth int) {
	if depth >= maxHelperTreeDepth {
		return
	}
	children, err := table.Children(pid)
	if err != nil {
		return
	}
	for _, child := range children {
		if found[child] {
			continue
		}
		found[child] = true
		collectProcessTree(table, child, found, depth+1)
	}
}

func processChildPIDs(pid int) ([]int, error) {
	tasks, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/task")
	if err != nil {
		return nil, err
	}
	var children []int
	for _, task := range tasks {
		payload, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/task/" + task.Name() + "/children")
		if err != nil {
			continue
		}
		for _, field := range strings.Fields(string(payload)) {
			child, err := strconv.Atoi(field)
			if err == nil && child > 1 {
				children = append(children, child)
			}
		}
	}
	return children, nil
}

func processNetnsInode(pid int) (uint64, bool) {
	if pid <= 0 {
		return 0, false
	}
	return pathNetnsInode("/proc/" + strconv.Itoa(pid) + "/ns/net")
}

func pathNetnsInode(path string) (uint64, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Ino, true
}

// terminateNetworkHelpers kills every captured helper that is still the same
// process. Already-dead or recycled PIDs are success, never an error, so a
// repeated stop of an already-stopped cell is idempotent. SIGTERM is followed
// by a bounded wait and then SIGKILL; a helper that survives both is a real
// containment failure and is reported.
func (p Podman) terminateNetworkHelpers(ctx context.Context, helpers []networkHelperProcess) error {
	var failures []error
	for _, helper := range helpers {
		if err := p.terminateNetworkHelper(ctx, helper); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (p Podman) terminateNetworkHelper(ctx context.Context, helper networkHelperProcess) error {
	if helper.PID <= 1 {
		return nil
	}
	matches, err := p.helperStillMatches(helper)
	if err != nil {
		return fmt.Errorf("observe network helper %d: %w", helper.PID, err)
	}
	if !matches {
		return nil
	}
	kill := p.killProcess
	if kill == nil {
		kill = syscall.Kill
	}
	if err := kill(helper.PID, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("terminate network helper %d: %w", helper.PID, err)
	}
	if p.waitHelperExit(ctx, helper, networkHelperTermGrace) {
		return nil
	}
	if err := kill(helper.PID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("kill network helper %d: %w", helper.PID, err)
	}
	if p.waitHelperExit(ctx, helper, networkHelperKillGrace) {
		return nil
	}
	return fmt.Errorf("network helper %d survived SIGKILL", helper.PID)
}

func (p Podman) waitHelperExit(ctx context.Context, helper networkHelperProcess, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		matches, err := p.helperStillMatches(helper)
		if err != nil || !matches {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (p Podman) helperStillMatches(helper networkHelperProcess) (bool, error) {
	if helper.StartTime == 0 {
		err := syscall.Kill(helper.PID, 0)
		if errors.Is(err, syscall.ESRCH) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	identity, err := p.helperProcessTable().Identity(helper.PID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if identity.StartTime != helper.StartTime || identity.State == "Z" {
		return false, nil
	}
	if helper.Comm != "" && identity.Comm != helper.Comm {
		return false, nil
	}
	return true, nil
}

// readProcessIdentity reads the stable identity of one live process from
// /proc: its command name and start time (stat field 22). The start time makes
// a later signal safe against PID recycling.
func readProcessIdentity(pid int) (networkHelperProcess, error) {
	identity := networkHelperProcess{PID: pid}
	comm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return identity, err
	}
	identity.Comm = strings.TrimSpace(string(comm))
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return identity, err
	}
	// The comm field is parenthesized and may contain spaces; everything after
	// the final ')' is the fixed stat tail whose first field is state (3) and
	// whose twentieth (field 22) is the start time.
	text := string(stat)
	end := strings.LastIndexByte(text, ')')
	if end < 0 || end+2 >= len(text) {
		return identity, fmt.Errorf("malformed process stat for pid %d", pid)
	}
	fields := strings.Fields(text[end+2:])
	if len(fields) < 20 {
		return identity, fmt.Errorf("short process stat for pid %d", pid)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return identity, fmt.Errorf("parse process start time for pid %d: %w", pid, err)
	}
	identity.StartTime = start
	identity.State = fields[0]
	return identity, nil
}
