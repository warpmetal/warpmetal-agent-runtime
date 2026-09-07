# Nested Private Procfs Capability and Nico Agent Activation Plan

## Project details

- Objective: let a WarpMetal Agent Runtime sandbox execute Nico's approved
  nested Bubblewrap boundary with a new PID namespace and a newly mounted
  procfs, without weakening the host, Runtime, or model-process isolation
  contracts.
- Target users and use cases: Nico administrators dispatching autonomous coding
  work to the persistent `nico-coder` and `nico-qa` sandboxes on the existing
  production VPS.
- Success measures:
  - the exact Nico Bubblewrap plus Landlock boundary succeeds on Ubuntu 24.04;
  - the model process is PID 1 in its inner namespace and `/proc/self` agrees;
  - a live outer Runtime process is absent from the inner procfs;
  - generic unprivileged user-namespace creation remains restricted;
  - normal seccomp, no-new-privileges, dropped capabilities, rootless identity,
    non-host networking, read-only root, and missing host runtime sockets remain;
  - Runtime installation preserves all pre-existing Docker workloads, protected
    packages, the private Podman service, and existing sandbox processes;
  - refreshing the two Nico sandboxes preserves their API IDs, grants,
    persistent workspaces, and lifetime while changing only the expected OCI
    process identity;
  - Nico completes one real coder -> publisher -> pull request -> QA task before
    autonomous/self-improvement flags are enabled.
- Scope:
  - `warpmetal-agent-sandbox`: reuse and verify the already signed image's
    root-owned, non-writable Codex Bubblewrap helper at its exact immutable path;
  - `warpmetal-agent-runtime`: install a narrowly attached AppArmor policy,
    select the required AppArmor starting state for newly created sandboxes,
    preserve all other container restrictions, and package/test the policy;
  - `warpmetal_frontend`: pin the signed Runtime candidate and existing signed
    image digest, and extend the
    existing guarded amd64 acceptance canary;
  - `nico`: strengthen the exact boundary oracle, fail closed during runner
    installation, correct operations/planning documentation, deploy the runner,
    and activate agents gradually.
- Non-goals:
  - no host-wide sysctl relaxation;
  - no `seccomp=unconfined`, privileged container, added capability, host PID or
    network namespace, Docker/Podman socket mount, manual systemd/cgroup edit, or
    ad-hoc host profile installation;
  - no inherited `/proc` bind and no weakening of Nico's Landlock boundary;
  - no automatic merging of agent pull requests;
  - no arm64 production claim without a separate live arm64 canary.
- Constraints and compatibility:
  - implementation branches start at Runtime v0.1.24 commit `18f1f6d` and the
    current signed sandbox-image main commit `20a7078`;
  - Ubuntu 24.04 is the live capability target; existing Debian 12, AlmaLinux 9,
    and Rocky Linux 9 coexistence behavior must remain green;
  - official WarpMetal CLI and signed immutable artifacts are the only allowed
    Runtime/sandbox mutation path;
  - production claims, autonomy, and self-improvement remain disabled until the
    corresponding gates pass.
- Dependencies:
  - official AppArmor restricted-Bubblewrap policy semantics;
  - signed sandbox image publication;
  - signed Runtime v0.1.25 prerelease and production metadata;
  - a disposable acceptance sandbox on the existing amd64 acceptance VPS;
  - Nico source publisher, model proxy, webhook, worker, and QA control-plane
    features already deployed default-off.
- Current-state evidence:
  - Runtime v0.1.24 is ready on Nico and preserves its nine Docker workloads;
  - both persistent sandboxes connect as UID/GID 1000 and propagate exit 37;
  - the approved Nico runner fails before Codex starts with
    `bwrap: Can't mount proc on /newroot/proc: Operation not permitted`;
  - the rejected inherited-proc experiment leaks stat-probeable outer PIDs and
    is isolated in an unmerged Nico worktree;
  - signed image digest
    `sha256:c3fefa156c491c31db48c3799e21a15438f2c5c452555e49b7c37815b5aee5ba`
    contains the executable
    `/opt/warpmetal-agent-tools/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap`
    as UID/GID 0, mode 0555, and reports `bubblewrap built for Codex`;
  - claims were rolled back to `false`; both worker processes are stopped.

## Requirements and acceptance

| ID | Requirement or risk | Observable acceptance criterion | Verification level |
|---|---|---|---|
| R1 | Preserve a real private procfs | `--unshare-pid --as-pid-1 --proc /proc` succeeds; inner `/proc/self` equals the caller's inner PID; a live outer PID is `ENOENT` | unit, integration, live end-to-end |
| R2 | Narrow privilege grant | Only the fixed root-owned Bubblewrap path receives the setup policy; generic `unshare` and alternate Bubblewrap paths cannot mount procfs | inspection, live negative test |
| R3 | Preserve outer sandbox hardening | UID/GID 1000, read-only root, cap-drop ALL, no-new-privileges, default seccomp, private PID namespace, non-host network, and absent host runtime sockets all hold | unit, live inspection |
| R4 | Safe Runtime installation | Nine Docker identities/processes/health, protected packages, Docker/containerd services, Podman service identity, and existing sandbox identities are unchanged across install and rollback | live end-to-end |
| R5 | Trusted image supply chain | The exact Codex Bubblewrap helper is root-owned, mode 0555, and present in the signed immutable all-tools image digest | artifact inspection, signature verification |
| R6 | Recoverable sandbox refresh | Existing Nico sandbox API IDs, grants, markers, persistent lifetime, and workspace data survive image refresh; only expected OCI IDs/PIDs/start times change | live end-to-end |
| R7 | Fail-closed Nico installer | The exact no-credential production Bubblewrap plus Landlock oracle runs before any worker installation or claim | unit, target integration |
| R8 | Autonomous pipeline readiness | One bounded admin task produces a reviewed plan, implementation PR/comment, exact-head CI, independent QA/API-or-UI evidence, and ready-to-merge state | production end-to-end |
| R9 | Staged self-improvement | Flags advance one at a time with health/task rollback checks; human merge remains required | production end-to-end, inspection |
| R10 | No secret exposure | Keys/tokens never appear in command arguments, logs, task chat, artifacts, or PR comments | tests, log inspection |

## Architecture

- System context and boundaries:
  - the host AppArmor policy is installed by the signed Runtime installer;
  - Runtime container-create arguments remain unchanged, so existing and future
    rootless sandboxes retain the same OCI restrictions;
  - AppArmor attaches an upstream-style setup profile only when the exact
    immutable Codex Bubblewrap executable is invoked, and stacks a
    capability-denying child profile after Bubblewrap execs the model process;
  - Nico's Landlock helper remains the inner filesystem boundary and grants no
    whole-procfs access.
- Components and responsibilities:
  - the existing signed all-tools sandbox image owns the exact Codex helper path
    and its immutable provenance;
  - Runtime owns host policy installation/loading, container-create arguments,
    release packaging, and coexistence checks;
  - frontend owns exact signed release/image metadata and the disposable live
    canary workflow;
  - Nico owns the production boundary arguments/oracle and task orchestration.
- Interfaces and contracts:
  - fixed executable path:
    `/opt/warpmetal-agent-tools/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap`;
  - Runtime release archive includes the versioned AppArmor policy and installer;
  - no Runtime HTTP API schema change is planned;
  - existing sandbox refresh API/CLI semantics remain the lifecycle boundary.
- Data flow and persistence:
  - the Runtime installer writes the reviewed host policy, loads it when AppArmor
    is active, then verifies postconditions before restarting only `warpmetald`;
  - existing sandboxes are not recreated during supervisor upgrades and policy
    attachment applies on the next exact helper exec;
  - a later explicit refresh replaces OCI containers transactionally while the
    workspace volume, API resource, grants, and lifetime persist.
- Failure modes and recovery:
  - missing AppArmor parser/profile support fails closed on an AppArmor-restricted
    Ubuntu target before new-capability activation;
  - candidate image/Runtime/canary failures keep production metadata and Nico
    flags unchanged;
  - Runtime binary rollback uses the exact prior signed artifact and deletes all
    candidate-created disposable sandboxes before downgrade; v0.1.24 cannot
    unload a v0.1.25-installed host policy, so that narrowly attached policy is
    explicitly treated as dormant retained state, not as a completed policy
    rollback;
  - full capability rollback switches the control-plane sandbox image back to
    the prior digest and refreshes any candidate-image sandboxes through the
    official CLI; the retained profile has no matching immutable executable in
    that prior image and remains inert until a separately supported signed
    removal path exists;
  - Nico sandbox refresh failure uses existing transactional image rollback and
    must not alter Docker or protected packages.
- Authentication and authorization:
  - owner-key access is used only by the official WarpMetal CLI;
  - coder and QA retain distinct grants;
  - Nico's exact-admin gate controls dispatch, protected-file authorization, and
    feature activation; agents cannot merge.
- Security and privacy:
  - no credentials are included in capability probes;
  - tokens are supplied through existing stdin-only transports and redacted by
    the worker/publisher log contracts;
  - the AppArmor policy follows the upstream restricted-Bubblewrap split between
    setup and capability-denied descendants.
- Error handling, logging, and observability:
  - failures use stable safe codes for profile install/load, capability oracle,
    image refresh, and invariants; logs include version, sandbox ID, revision,
    phase, and outcome, never credential values;
  - workers remain stopped and claims false on any failed prerequisite.
- Deployment, migration, and rollback:
  - verify existing signed image -> Runtime candidate -> acceptance
    rollback/forward canary -> stable metadata -> Nico supervisor upgrade ->
    explicit two-sandbox refresh to the already signed all-tools image ->
    Nico deploy -> bounded task canary -> staged flags.

## Documentation and API contracts

- Canonical plan: this file, owned by the cross-repository coordinator.
- Runtime operator/security docs: `README.md`, `SECURITY.md`, and installer tests.
- Sandbox image contract: `README.md`, `Containerfile`, and `test-image.sh`.
- Nico operator and architecture docs:
  `docs/AGENT_ENGINEERING_ACTIVATION_PLAN.md`,
  `docs/AGENT_ENGINEERING_PIPELINE_PLAN.md`, and
  `docs/AGENT_ENGINEERING_OPERATIONS.md`.
- Frontend canary contract: existing acceptance workflow and driver scripts.
- Public API changes: not applicable; no HTTP/JSON schema is added. Existing
  signed-release metadata and sandbox refresh interfaces are reused.

| Capability or interface | Required document / contract | Owner | Verification | Status |
|---|---|---|---|---|
| Restricted nested Bubblewrap | Runtime README/security + this decision record | Runtime | policy inspection + live oracle | pending |
| Trusted Bubblewrap binary | Sandbox README/image tests | Image | build + ownership/path checks | pending |
| Signed artifact selection | Frontend acceptance workflow | Frontend | exact digest/signature checks | pending |
| Nico runner boundary | Nico plans/operations | Nico | unit + target oracle | pending |
| HTTP API | No schema change | Runtime | diff inspection | not applicable |

## Error handling and logging

- Error taxonomy: unsupported host policy, profile install/load failure, Runtime
  release verification failure, workload drift, capability-oracle failure,
  refresh rollback failure, model/worker failure, publication failure, and QA
  rejection remain distinct.
- Retry policy: bounded retries only; capability or invariant failures are not
  retried indefinitely and keep activation flags false.
- Log schema: timestamp, safe event code, version/digest, server/sandbox/task ID,
  desired/applied revision, phase, duration, and result.
- Secret handling: never log private keys, grant secrets, model tokens, GitHub
  tokens, raw environment, task credentials, or application configuration.
- Retention/access: use existing restricted Runtime and Nico operational logs;
  no new credential-bearing artifact is created.

| Error or event | External behavior | Log level and safe fields | Recovery / alert | Verification |
|---|---|---|---|---|
| AppArmor unsupported or profile rejected | installation/canary stops | error; distro, kernel, policy path, safe code | keep prior metadata/flags | negative installer tests |
| Host workload drift | guarded install stops | error; resource class/count only | investigate; no workaround | existing coexistence matrix |
| Nested procfs oracle fails | sandbox not activated | error; sandbox ID, stage, exit code | delete disposable candidate or rollback refresh | live sensitivity/positive tests |
| Sandbox refresh fails | original sandbox restored or fail-closed | error; sandbox ID, digest, stage | verify workspace/grant and stop | existing rollback tests + live canary |
| Agent pipeline fails | task pauses/waits for admin | warning/error; task/lease/phase | keep later flags off | bounded production canary |

## Authentication and authorization

- Principals: WarpMetal account owner, Runtime supervisor, per-sandbox SSH grant,
  Nico exact administrator, coder worker, QA worker, publisher, and model proxy.
- Trust boundaries: GitHub OIDC/signed artifacts, official CLI owner-key channel,
  per-agent grant, Nico admin session, and one-time model leases.
- Credential lifecycle: reuse existing owner identity and distinct sandbox grants;
  no secret copying into source or task artifacts; existing rotation/revocation
  mechanisms remain authoritative.

| Principal / role | Resource or action | Allowed / denied | Enforcement point | Verification |
|---|---|---|---|---|
| WarpMetal owner | guarded install/refresh | allowed with explicit CLI confirmation | control plane + SSH owner key | audit log + revision equality |
| Coder grant | coder sandbox only | allowed; QA/owner denied | sandbox gateway grant | cross-grant negative check |
| QA grant | QA sandbox only | allowed; coder/owner denied | sandbox gateway grant | cross-grant negative check |
| Nico admin | dispatch/pause/authorize | allowed | exact-admin web/API gate | existing auth tests + canary |
| Agent workers | merge/protected changes/secrets | denied unless narrowly authorized; merge always denied | policy/publisher/GitHub | task and PR audit |

## Decisions

| Decision | Options considered | Choice and evidence | Consequences |
|---|---|---|---|
| Procfs shape | new procfs; inherited bind; no procfs | preserve new procfs; bind leaks stat-probeable outer PIDs and violates frozen Nico boundary | Runtime must support the mount |
| Userns host policy | disable Ubuntu restriction; broad unconfined container; exact-path restricted setup policy | exact product path plus upstream restricted-Bubblewrap setup/child split; host-wide relaxation forbidden | packaging and live policy tests required |
| Binary source | mutable workspace install; generic distro path; exact signed-image Codex helper | exact root-owned helper in the existing signed all-tools image | no new image build; Nico still needs an explicit refresh from its older image |
| Upgrade proof | refresh existing sandboxes during install; preserve them and use disposable canary | preserve existing sandboxes; prove capability on a fresh candidate | refresh is a later explicit lifecycle phase |
| Release | mutable artifacts; signed prerelease then promotion | signed immutable prerelease, rollback/forward canary, then promote same assets | version candidate is v0.1.25 |

## Assumption ledger

| ID | Assumption or unknown | Impact if false | Status | Evidence or resolution |
|---|---|---|---|---|
| A1 | An exact executable attachment profile applies from the existing rootless `crun (unconfined)` context and permits Bubblewrap setup under Ubuntu's restricted-userns policy while stacking a capability-denied child under no-new-privileges | high | unresolved | must pass the disposable Ubuntu 24.04 live oracle before production promotion |
| A2 | Leaving Podman container-create arguments exactly unchanged preserves supported-distro behavior while the policy is installed only on active restricted-AppArmor hosts | high | unresolved | four-distro privileged coexistence CI and focused exact-argument tests |
| A3 | Runtime can install/load the profile without adding/replacing AppArmor packages or restarting the private Podman service | high | unresolved | installer plan/postcondition tests and live service-identity comparison |
| A4 | Explicit refresh preserves API IDs, grants, workspace markers, and persistent lifetime | high | verified for existing refresh implementation, must be reverified live | Runtime v0.1.24 refresh tests and prior release evidence |
| A5 | Nico main's `--proc` runner logic remains the approved functional shape | high | verified | independent contract audit of commit `87c817c` |
| A6 | Production metadata can be canaried and rolled back using exact signed artifacts without rebuilding them | high | verified, procedure must be rerun | v0.1.24 release history and release audit |

## Test strategy

- Unit: exact image path/ownership/version, Podman arguments, forbidden arguments,
  existing-container no-recreate behavior, installer profile decisions, and Nico
  exact command/oracle assertions.
- Contract: release archive contents, exact AppArmor attachment/child transition,
  no Runtime API change, source digest and runner manifest parity.
- Integration: four supported distro coexistence jobs; AppArmor-enabled Ubuntu
  policy load and negative generic-unshare checks.
- End-to-end: sensitivity failure before the candidate policy, positive
  disposable sandbox on the candidate, invariant-preserving binary rollback,
  and forward positive again. The canary must report that binary downgrade does
  not remove the installed host policy and must not claim a second sensitivity
  failure. Full capability rollback uses the prior image as described above;
  then Nico refresh and a real task verify the production path.
- Local macOS skips do not satisfy Linux or target Runtime behavior.

## Threat and failure model

| Trust boundary, asset, or failure mode | Threat / failure | Intended control or recovery | Verification |
|---|---|---|---|
| Host userns restriction | broad bypass exposes kernel attack surface | exact-path setup profile; capability-denied descendants; generic unshare denial | policy review + live negative test |
| Inner process view | inherited procfs leaks outer workers | new PID namespace and new procfs; live outer PID ENOENT | live oracle |
| Runtime install | Docker/package/service disruption | existing guarded snapshots and no-removal/no-upgrade policy | four-distro CI + live byte comparison |
| Sandbox refresh | workspace/grant loss | transactional replacement and persistent API resource | rollback tests + live markers |
| Artifact supply chain | mutable or substituted binary/profile | pinned base/image, immutable digest, signed Runtime archives, independent verification | CI/signature/archive inspection |
| Agent credentials | output or artifact exfiltration | stdin-only secrets, redaction scanner, bounded output, separate grants | tests + canary log inspection |

## Master phase map

| Phase | Testable outcome | Requirements / risks | Dependencies | Exit criteria | Status |
|---|---|---|---|---|---|
| P0 | Architecture and rollout gate frozen | R1-R10, A1-A6 | independent audits | canonical plan reviewed; no rejected bind work included | completed |
| P1 | Existing signed image contains trusted Bubblewrap | R2, R5, R10 | signed image | exact digest/path/owner/mode/version verified | completed |
| P2 | Runtime candidate packages and loads the restricted policy safely | R1-R4, R10, A1-A3 | P1 path contract | PR reviewed; full CI green on merge commit | in_progress |
| P3 | Signed v0.1.25 prerelease and frontend canary contract ready | R1-R5, R10 | P1-P2 | signatures verified; exact metadata/canary code reviewed | pending |
| P4 | Rollback/forward amd64 acceptance canary passes | R1-R6, R10, A1-A4 | P3 | pre-policy sensitivity, positive capability, preservation, explicit retained-policy binary rollback, and forward gates pass | pending |
| P5 | Stable production Runtime/image and Nico sandbox refresh | R1-R7, R10 | P4 | stable assets; Nico upgrade plus both explicit refreshes verified | pending |
| P6 | Nico code/deploy and real autonomous task pass | R7-R10 | P5 | full gates, deploy, coder/publisher/QA canary, staged flags | pending |

## Active phase subplan

### Phase header

- Phase ID and outcome: P2, signed Runtime candidate that safely installs and
  loads the exact-path restricted-Bubblewrap policy.
- Covered requirement and assumption IDs: R1-R4, R10; A1-A3.
- Entry criteria: Runtime worktree is isolated at v0.1.24 commit `18f1f6d`; the
  exact signed-image helper path is verified; the upstream setup/child profile
  pattern and no-host-wide-relaxation decision are frozen; user authorized the
  cross-project Runtime change on 2026-09-07.
- Exit criteria: reviewed profile and transactional installer logic are packaged
  in the release archive; Podman arguments are byte-for-byte unchanged; focused,
  race, vet, installer, and four-distro coexistence gates pass on the exact merge
  commit.
- Dependencies and risks: A1-A3 remain blocked for production until P4 live
  proof; P2 may build a signed candidate but cannot promote it.
- Baseline test state: origin/main/v0.1.24 gates were green; the new tests must
  first prove sensitivity to a missing/conflicting policy.
- Required documentation and API-contract changes: Runtime README/security,
  installer error contract, release-archive contents; no public API change.
- Coordinating owner: primary Nico activation coordinator.
- Fresh recovery reviewer available: yes; a non-implementing agent will review
  the complete P2 boundary.

### Phase assumption check

| Assumption ID | Check or probe | Evidence | Result | Plan change |
|---|---|---|---|---|
| A1 | Compare the exact-path profile with upstream's setup/stacked capability-denied-child pattern; prove path attachment and one allowed nesting on disposable Ubuntu 24.04 | upstream AppArmor profile lines 12-72; signed-image path inspection | unresolved | permit isolated candidate implementation only; block promotion until P4 |
| A2 | Preserve the exact current `createArguments` list and exercise supported distros | v0.1.24 source plus four-distro matrix | unresolved | add exact forbidden/unchanged assertions; no AppArmor OCI override |
| A3 | Parse-before-install, load only the new file, never restart AppArmor/Podman, require both loaded profiles exactly once in enforce mode, and retain/restore exact prior file metadata plus loaded/unloaded state on failure | installer architecture audit and recovery review | unresolved | signed no-atime/no-follow copy and comparison helper plus source-stability and inherited-xattr checks, parser-read timestamp restoration, transactional mismatch, mode, backup/restore failure, partial-load, aggregate-failure, and workload postcondition checks |

### Entry-gate decision

- Implementation authorized: yes.
- Decision evidence: explicit user approval (`Yes`, 2026-09-07), independent
  Nico boundary audit, and independent Runtime release audit.
- Unresolved low-impact defaults and consequences: none. A1 is high impact and
  blocks promotion, but not creation of the isolated candidate needed to test it.
- Error/logging requirements reviewed: yes; stable safe errors and redaction are
  defined above.
- Authentication/authorization requirements reviewed: yes; no authority or API
  expansion is introduced.
- Documentation/API requirements reviewed: yes; docs mapped above; API change is
  not applicable.
- Decision timestamp or plan revision: 2026-09-07, revision 3.

### Subparts

| Subpart | Deliverable and owner boundary | Dependencies | Interfaces / likely files | Documentation / API impact | Acceptance and oracle | Focused + regression checks | Parallel-safe | Status |
|---|---|---|---|---|---|---|---|---|
| P2.S1 | Add exact-path upstream-style setup and capability-denied child AppArmor policy | P1 | `packaging/apparmor/warpmetal-agent-runtime-bwrap` | README/security | exact attachment only; child has no capabilities; deeper namespace/proc mount denied | parser/static policy tests + live P4 | yes | completed locally; live proof pending P4 |
| P2.S2 | Add transactional conditional policy installation/loading without service or package mutation | P2.S1 | `packaging/install/install.sh`, `install_test.sh` | installer errors/recovery | parse first; exact file load; sysctl unchanged; failure restores prior policy and preserves workloads | shell/unit/coexistence tests | no | completed locally; CI pending |
| P2.S3 | Package policy/oracle and freeze unchanged OCI restrictions | P2.S1 | `release.yml`, `podman_test.go`, canary helper | release contents | archive complete; `createArguments` unchanged; forbidden broad options absent | Go/release structural tests | yes | completed locally; CI pending |
| P2.S4 | Full Runtime verification and independent scope/security review | P2.S1-S3 | repository-wide | plan verification log | exact head green on all supported distros; reviewer APPROVE | full commands below | no | independent review approved; exact-head CI pending |

### Test matrix

| Requirement / risk | Behavior or invariant | Test level | Oracle defined before code | Command or procedure |
|---|---|---|---|---|
| R1 | exact nested procfs and PID-local view | live integration | yes | P4 exact Bubblewrap plus Landlock oracle with live outer sentinel |
| R2 | only exact helper receives setup permission; descendant/deeper attempt denied | policy + live negative | yes | parser inspection and P4 generic/third-nesting negative controls |
| R3 | current OCI restrictions remain exact | unit + live inspection | yes | focused `internal/containers` assertions and P4 host inspection |
| R4 | installer never drifts workloads/packages/services | integration | yes | existing four-distro coexistence suite plus P4 snapshots |
| R10 | no credentials or raw environment in probes/logs | inspection | yes | fixture-only oracle and diff/log review |

### Frozen phase-gate command manifest

```sh
git diff --check
test -z "$(gofmt -l .)"
sh -n packaging/install/install.sh
sh -n packaging/install/coexistence_container_test.sh
sh packaging/install/install_test.sh
go test -race ./internal/containers ./internal/...
go test -race ./...
go vet ./...
```

The exact merge commit must also pass every privileged existing-workload job on
Ubuntu 24.04, Debian 12, AlmaLinux 9, and Rocky Linux 9. Additions are allowed;
removing a frozen invariant requires a fresh review and plan update.

### Sequence and integration

1. Implement P2 policy and installer/release integration in one isolated Runtime
   branch; do not alter container-create arguments.
2. Run focused and full local gates, then obtain an independent security/scope
   review and exact-head CI.
3. Merge and tag Runtime only after the exact signed-image path contract remains
   frozen.
4. Frontend metadata/canary changes consume the Runtime artifact and the existing
   immutable image digest.
5. Production promotion, Nico mutations, and feature flags remain blocked until
   P4 completes.

## Verification log

### Subpart gate

| Subpart | Review result | Commands and results | Independent behavior check | Residual risk | Final status |
|---|---|---|---|---|---|
| P1 | coordinator verified | pulled exact amd64 digest; container inspection reported exact path, UID/GID 0, mode 0555, and `bubblewrap built for Codex` | immutable image inspection | AppArmor capability unproven until P4 | verified |
| P2.S1-S3 | final fresh recovery reviewer approved; hosted tests exposed and corrected unprivileged parser-cache access and strict-atime `cp` behavior | Ubuntu 24.04 root and UID/GID 1000 gates: cache-free profile parse, real signed-helper transaction tests, installer tests, and ShellCheck passed; Go 1.25: formatting, `go test -race ./...`, `go vet ./...`, and amd64/arm64 helper builds passed | full diff review confirmed exact attachment, capability-denied child, unchanged Podman create arguments, signed no-atime/no-follow exact metadata copy/rollback, and signed archive inclusion | live restricted-userns behavior remains blocked on P4 | verified locally; exact-head CI rerun pending |

### Integrated phase gate

- Acceptance criteria checked: local P2 criteria passed; exact-head hosted matrix
  remains pending.
- Full commands and results: Ubuntu 24.04 shell/AppArmor/installer/ShellCheck
  gate passed; Go 1.25 formatting, race suite, vet, and amd64/arm64 helper builds
  passed; `git diff --check` passed.
- Cross-subpart behavior checked: fresh independent reviewer returned APPROVE for
  the complete Runtime diff.
- Error-path and log-safety evidence: backup, staged restore, final restore,
  timestamp restoration, partial profile load, and aggregate rollback failures
  are exercised without credential-bearing output.
- Authentication and authorization evidence: no interface change; pending diff
  inspection.
- Documentation and API-contract parity evidence: README, SECURITY, release
  archive, and installer error contracts reviewed; no public API change.
- Architecture and scope review: independent APPROVE; no sysctl, AppArmor
  service, Podman service, Docker, package, or OCI-argument mutation added.
- Assumptions added or changed: none after revision 1.
- Limitations or unrun checks: live AppArmor capability intentionally deferred to
  P4 and remains a production blocker.
- Phase status: in progress.

## Project completion record

- Final acceptance evidence: pending.
- Full relevant regression evidence: pending.
- Delivered architecture and operational notes: pending.
- Delivered API contracts, reference documentation, and parity evidence: no
  public API change planned; pending final inspection.
- Error/logging controls and verification: pending.
- Authentication/authorization controls and verification: pending.
- Known residual risks: no arm64 live canary is in scope; arm64 artifacts remain
  build/test-only until separately exercised.
- Remaining assumptions or untested behavior: A1-A3 pending.
