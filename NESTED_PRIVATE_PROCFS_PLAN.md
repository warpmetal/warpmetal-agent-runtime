# Nested Private Procfs Capability and Agent Sandbox Activation Plan

## Project details

- Objective: let a WarpMetal Agent Runtime sandbox execute an approved nested
  Bubblewrap boundary with a new PID namespace and a newly mounted procfs,
  without weakening the host, Runtime, or inner-process isolation contracts.
  Nico is the first production consumer and acceptance workload, not the owner
  or limit of the capability.
- Target users and use cases: any WarpMetal owner operating a verified workload
  that launches the signed, exact-path Bubblewrap helper inside an Agent Runtime
  sandbox and needs per-attempt process/filesystem isolation. Examples include
  read-only planning, bounded repository implementation, and independent QA.
  Nested private procfs is an optional host-scoped capability, not a default
  requirement for every Agent Runtime user or an intrinsic requirement of an
  AI CLI, GitHub access, or subagent delegation.
- Success measures:
  - the exact Nico Bubblewrap plus Landlock boundary succeeds on Ubuntu 24.04;
  - the model process is PID 1 in its inner namespace and `/proc/self` agrees;
  - a live outer Runtime process is absent from the inner procfs;
  - generic unprivileged user-namespace creation remains restricted;
  - an explicit signed disable operation restores the host's exact pre-enable
    AppArmor file and loaded/unloaded state after the forward canary;
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
    root-owned, non-writable Bubblewrap helper at its exact immutable path, and
    document the planning, coding, and QA boundaries it can support;
  - `warpmetal-agent-runtime`: preserve existing AppArmor policy state by
    default; explicitly enable or disable a narrowly attached host policy on an
    amd64 nested-Bubblewrap host; preserve all other container restrictions; and
    package/test the policy and reversible transaction;
  - `agent-kit`: expose the explicit lifecycle through CLI 0.8.7, explain the
    default and host scope in CLI help, and keep the bundled WarpMetal skill and
    references aligned;
  - `warpmetal_frontend`: pin the signed Runtime candidate and existing signed
    image digest, extend the existing guarded amd64 acceptance canary, and add
    the capability contract and examples to the public `/agent-runtime` and
    `/docs` pages, canonical `llms.txt` source, and backend mirror;
  - `nico`: strengthen the exact boundary oracle, fail closed during runner
    installation, correct operations/planning documentation, deploy the runner,
    and activate agents gradually.
- Non-goals:
  - no host-wide sysctl relaxation;
  - no `seccomp=unconfined`, privileged container, added capability, host PID or
    network namespace, Docker/Podman socket mount, manual systemd/cgroup edit, or
    ad-hoc host profile installation;
  - no inherited `/proc` bind and no weakening of Nico's Landlock boundary;
  - no claim that enablement is per-user or per-sandbox: every same-owner
    sandbox on an enabled Runtime host that contains the trusted exact helper
    path can invoke the policy;
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
| R11 | Explicit host-scoped lifecycle | Default install/upgrade preserves existing disk and kernel policy state; `--nested-private-procfs enable` installs/loads it only on amd64; `disable` unloads/removes it and restores a pre-existing destination safely | unit, integration, recovery inspection |
| R12 | Product-wide documentation and discovery | Runtime, sandbox-image, CLI help/README/skill, public `/agent-runtime` and `/docs` pages, and `llms.txt` explain who needs the capability, why nested Bubblewrap is used, the planning/coding/QA examples, the exact version/action contract, host scope, and when to preserve or disable it | documentation contract, CLI test, frontend route/backend tests, inspection |

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
    canary workflow plus the canonical LLM-facing machine contract;
  - agent-kit owns CLI validation, signed-bundle compatibility, human help, and
    the bundled agent skill/reference contract;
  - each consumer owns its inner boundary arguments and oracle; Nico owns the
    first production boundary and task orchestration.
- Interfaces and contracts:
  - fixed executable path:
    `/opt/warpmetal-agent-tools/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap`;
  - Runtime release archive includes the versioned AppArmor policy and installer;
  - the signed installer accepts `--nested-private-procfs
    preserve|enable|disable`, defaulting to `preserve`; this is a host-level
    administrative operation, not a sandbox manifest field;
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
  - recovery phase P2R replaces that temporary retained-policy limitation with
    an explicit signed disable transaction and durable transaction evidence;
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
    setup and capability-denied descendants;
  - the Runtime host cannot bind AppArmor pathname attachment to one sandbox or
    verify image signatures from policy alone. The authenticated backend remains
    the trusted image-selection boundary and must select the reviewed immutable
    coding image. Host enablement grants the exact-path setup transition to all
    same-owner sandboxes on that host containing that path.
- Error handling, logging, and observability:
  - failures use stable safe codes for profile install/load, capability oracle,
    image refresh, and invariants; logs include version, sandbox ID, revision,
    phase, and outcome, never credential values;
  - workers remain stopped and claims false on any failed prerequisite.
- Deployment, migration, and rollback:
  - verify existing signed image -> Runtime candidate -> acceptance
    rollback/forward/disable canary -> stable metadata -> Nico supervisor
    upgrade -> explicit two-sandbox refresh to the already signed all-tools
    image -> Nico deploy -> bounded task canary -> staged flags.

## Documentation and API contracts

- Canonical plan: this file, owned by the cross-repository coordinator.
- Runtime operator/security docs: `README.md`, `SECURITY.md`, and installer tests.
- Sandbox image contract: `README.md`, `Containerfile`, and `test-image.sh`.
- CLI and agent guidance: agent-kit `src/cli.js`, `README.md`, and the source and
  packaged WarpMetal skill/reference mirrors.
- LLM-facing machine contract: frontend `content/llms.md`, served by
  `app/llms.txt/route.ts`, plus `backend/public/llms.txt`.
- Public human documentation: frontend `app/agent-runtime/page.tsx`,
  `app/docs/page.tsx`, and localized `messages/*.json` content.
- Nico operator and architecture docs:
  `docs/AGENT_ENGINEERING_ACTIVATION_PLAN.md`,
  `docs/AGENT_ENGINEERING_PIPELINE_PLAN.md`, and
  `docs/AGENT_ENGINEERING_OPERATIONS.md`.
- Frontend canary contract: existing acceptance workflow and driver scripts.
- Public API changes: not applicable; no HTTP/JSON schema is added. Existing
  signed-release metadata and sandbox refresh interfaces are reused.

| Capability or interface | Required document / contract | Owner | Verification | Status |
|---|---|---|---|---|
| Restricted nested Bubblewrap | Runtime README/security + this decision record | Runtime | policy inspection + live oracle | current; live P4 pending |
| Trusted Bubblewrap binary and use-case examples | Sandbox README/image tests | Image | build + ownership/path checks + doc inspection | current |
| CLI lifecycle and operator examples | CLI help/README + WarpMetal skill/reference mirrors | agent-kit | CLI tests + mirror parity | current |
| Public capability overview and reference | `/agent-runtime` + `/docs` + localized messages | Frontend | rendered HTML tests in all supported locales | current |
| LLM-facing discovery contract | `content/llms.md` + `backend/public/llms.txt` | Frontend | route/backend tests + phrase parity | current |
| Signed artifact selection | Frontend acceptance workflow | Frontend | exact digest/signature checks | pending |
| First consumer boundary | Nico plans/operations | Nico | unit + target oracle | pending live activation |
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
| Policy activation | install on every restricted-AppArmor host; per-sandbox toggle; explicit host toggle | default `preserve`, explicit signed `enable`/`disable`; AppArmor pathname attachment cannot truthfully provide per-sandbox isolation without a separate outer profile/API design | hosts without nested Bubblewrap receive no policy mutation; enabled dedicated hosts grant all same-owner matching-path sandboxes |
| Consumer scope | Nico-only feature; coding-only feature; general nested-Bubblewrap capability | general capability with Nico as the first acceptance consumer; need is determined by the inner isolation boundary rather than the agent brand, task category, GitHub use, or subagent use | product docs must use capability-based language and concrete planning/coding/QA examples |

## Assumption ledger

| ID | Assumption or unknown | Impact if false | Status | Evidence or resolution |
|---|---|---|---|---|
| A1 | An exact executable attachment profile applies from the existing rootless `crun (unconfined)` context and permits Bubblewrap setup under Ubuntu's restricted-userns policy while stacking a capability-denied child under no-new-privileges | high | unresolved | must pass the disposable Ubuntu 24.04 live oracle before production promotion |
| A2 | Leaving Podman container-create arguments exactly unchanged preserves supported-distro behavior while the policy is installed only on active restricted-AppArmor hosts | high | unresolved | four-distro privileged coexistence CI and focused exact-argument tests |
| A3 | Runtime can install/load the profile without adding/replacing AppArmor packages or restarting the private Podman service | high | unresolved | installer plan/postcondition tests and live service-identity comparison |
| A4 | Explicit refresh preserves API IDs, grants, workspace markers, and persistent lifetime | high | verified for existing refresh implementation, must be reverified live | Runtime v0.1.24 refresh tests and prior release evidence |
| A5 | Nico main's `--proc` runner logic remains the approved functional shape | high | verified | independent contract audit of commit `87c817c` |
| A6 | Production metadata can be canaried and rolled back using exact signed artifacts without rebuilding them | high | verified, procedure must be rerun | v0.1.24 release history and release audit |
| A7 | Every restricted-AppArmor Runtime host needs nested private procfs and may receive the policy during an ordinary install/upgrade | high | false | independent recovery review found the capability is required only for workloads that create the nested private-procfs boundary; unconditional install expands scope and can fail unrelated installs |
| A8 | Exact-path attachment can enforce a per-sandbox or per-user grant | high | false | AppArmor pathname attachment is host-scoped; all same-owner sandboxes containing the trusted path can invoke it |
| A9 | Nested private procfs is a Nico-only or coding-user-only feature | high | false | owner decision: any verified Agent Runtime workload may use the trusted Bubblewrap boundary; Nico remains the first production canary |

## Test strategy

- Unit: exact image path/ownership/version, Podman arguments, forbidden arguments,
  existing-container no-recreate behavior, installer profile decisions, and Nico
  exact command/oracle assertions.
- Contract: release archive contents, exact AppArmor attachment/child transition,
  no Runtime API change, source digest and runner manifest parity, CLI help/skill
  mirror parity, and frontend/backend LLM contract parity.
- Integration: four supported distro coexistence jobs; AppArmor-enabled Ubuntu
  policy load and negative generic-unshare checks.
- End-to-end: sensitivity failure before the candidate policy, positive
  disposable sandbox on the candidate, invariant-preserving binary rollback,
  forward positive again, and explicit signed disable. The canary must report
  that binary downgrade does not remove the installed host policy and must not
  claim a second sensitivity failure. The final disable stage must prove the
  nested procfs attempt is denied again and the exact pre-enable file and
  loaded/unloaded state are restored; then Nico refresh and a real task verify
  the production path.
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
| P2 | Runtime candidate packages and loads the restricted policy safely | R1-R4, R10, A1-A3 | P1 path contract | PR reviewed; full CI green on exact PR head | completed |
| P2R | Runtime policy lifecycle is explicit, default-off, architecture-gated, and reversibly recoverable | R2-R4, R10-R11, A2-A3, A7-A8 | P2 recovery review | default preserve is mutation-free; explicit amd64 enable is idempotent; disable unloads/removes Runtime policy and restores any displaced prior file/state; interruption evidence is durable; tests/docs green | completed |
| P2D | General capability documentation is discoverable and example-driven | R11-R12, A7-A9 | P2R interface | Runtime and sandbox docs, CLI help/skill, public pages, and both LLM contract sources agree on purpose, examples, versions, actions, host scope, and non-goals; repository gates pass | completed |
| P3 | Signed v0.1.25 prerelease, CLI 0.8.7, and five-stage frontend canary contract ready | R1-R5, R10-R12 | P1-P2R, P2D | exact heads pass CI/review; signed Runtime and npm CLI releases are independently verified; frontend workflow is available on its default branch | completed |
| P4 | Rollback/forward/disable amd64 acceptance canary passes | R1-R6, R10-R11, A1-A4 | P3 | pre-policy sensitivity, positive capability, preservation, retained-policy binary rollback, forward, and exact disable/restore gates pass | in_progress |
| P5 | Stable production Runtime/image and Nico sandbox refresh | R1-R7, R10 | P4 | stable assets; Nico upgrade plus both explicit refreshes verified | pending |
| P6 | Nico code/deploy and real autonomous task pass | R7-R10 | P5 | full gates, deploy, coder/publisher/QA canary, staged flags | pending |

## Active phase subplan

### Release-readiness phase P3 header

- Phase ID and outcome: P3, publish the exact reviewed Runtime and CLI
  candidates and make the hardened five-stage private-procfs acceptance
  workflow executable from the frontend repository's default branch.
- Covered requirement and assumption IDs: R1-R5, R10-R12; A1-A3, A6-A9.
- Entry criteria: P1, P2, P2R, and P2D are complete locally; all five feature
  branches have merged current `origin/main`; the owner authorized plan
  execution, repository integration, signed candidate publication, and the
  later disposable-VPS gate on 2026-09-07.
- Exit criteria: Runtime, agent-kit, frontend, image-contract, and cross-repo
  gates pass on exact post-merge heads; fresh review approves the release and
  canary boundary; Runtime PR #23 includes the recovery/documentation commits,
  merges, and produces an immutable signed v0.1.25 prerelease; agent-kit merges
  and publishes npm `warpmetal@0.8.7`; the frontend workflow includes ordered
  `sensitivity -> candidate -> rollback -> forward -> disable` behavior, exact
  artifact pins, replay-safe cleanup, and a final policy absence/restoration
  oracle, then merges with green CI so the workflow is dispatchable.
- Dependencies and risks: GitHub Actions/release and npm publication authority;
  production deployment associated with merging the frontend default branch;
  exact v0.1.24/v0.1.25 hashes and signatures; no VPS, Runtime, sandbox, key, or
  payment mutation is allowed in P3. A missing release credential or failed
  exact-head gate blocks the phase without substituting a local tarball.
- Baseline test state: post-`origin/main` baselines are green on the exact local
  heads. Runtime `a53be817372459af2b2741c7ade72fbaa25654fb` passed the Linux
  Go 1.25 race/vet/cross-build, policy, installer, preserve-execution, and
  unchanged-OCI gates. Agent-kit `7e1cf0d` passed check, 73 tests, package dry
  run, and all three source/package mirror comparisons. Frontend `87c2476`
  passed 11 focused canary tests, shell syntax/ShellCheck, build, 116 tests,
  lint with only three existing translation warnings, and 45 backend surface
  tests. The signed amd64 image digest and helper path, mode, SBOM, SLSA
  provenance, and Cosign-v3 signature verified. Hosted PR, exact merge-commit,
  and release gates have since passed for Runtime, agent-kit, and image docs;
  frontend integration remains the final P3 gate.
- Required documentation and API-contract changes: update this living plan and
  the frontend canary/operator documentation for the explicit disable stage.
  Existing public Runtime pages, CLI help, skill mirrors, and LLM text already
  describe preserve/enable/disable. No HTTP/JSON API schema change is planned.
- Coordinating owner: primary managed-plan executor; only the primary Site owner
  edits the frontend checkout and performs repository/release effects.
- Fresh recovery reviewer available: yes; a non-implementing subagent will audit
  the exact release/canary diff and evidence before P3 closes.

### Release-readiness phase P3 assumption check

| Assumption ID | Check or probe | Evidence | Result | Plan change |
|---|---|---|---|---|
| A6 | Confirm exact immutable releases can be selected without rebuilding | v0.1.24 release history, absent v0.1.25/CLI 0.8.7 collisions, and current canary signature/hash checks | verified for design; rerun required | retain signed prerelease and exact-hash gate |
| A7-A9 | Reconfirm policy default, host scope, and general consumer boundary | merged implementation/docs and owner decision | verified/false as recorded | no design change; keep all-tools image for this rollout |
| P3.A1 | Confirm every feature branch contains current `origin/main` before work | merge-base/HEAD inspection on Runtime, agent-kit, frontend, image, and Nico worktrees | verified | record exact heads before baseline and repeat before each later phase branch change |
| P3.A2 | Confirm Runtime v0.1.25 and CLI 0.8.7 are not already published | GitHub release lookup and npm registry query on 2026-09-07 | verified | P3 must publish both; do not overwrite an existing artifact |
| P3.A3 | Confirm explicit disable can be exercised without a new Runtime API | Runtime installer lifecycle and agent-kit `runtime install` flag contract | verified locally | add a fifth canary stage using signed v0.1.25 and verify exact restoration |
| P3.A4 | Confirm the frontend default-branch merge may publish public docs | existing test/build/deploy workflow and repository history | verified | treat deployment as an authorized, observable P3 external effect; stop if CI/deploy fails |
| P3.A5 | Confirm the documented sandbox architectures match the published image index | signed index contains one linux/amd64 manifest plus its attestation; image workflow builds amd64 only; corrected Runtime README now distinguishes it from multi-architecture Runtime archives | verified after correction | keep the sandbox-image claim amd64-only and verify both Runtime release architectures |

### Release-readiness phase P3 entry-gate decision

- Implementation authorized: yes for P3; Runtime, agent-kit, image-doc, and
  frontend integration/publication passed their fresh exact-head hosted CI,
  independent review, deployment, and live documentation gates.
- Decision evidence: owner authorization is present; all five branches contain
  current `origin/main`; the post-merge Runtime, agent-kit, frontend, and image
  baselines above passed; Runtime v0.1.25 is an unpromoted signed prerelease and
  npm `warpmetal@0.8.7` is published and independently registry-probed.
- Unresolved low-impact defaults and consequences: none.
- Error/logging requirements reviewed: yes; retain bounded stage evidence and
  exclude tokens, private keys, environment dumps, and raw child output.
- Authentication/authorization requirements reviewed: yes; GitHub/npm release
  credentials stay in their existing protected workflows, and later VPS access
  remains owner-key plus pinned-host-key only.
- Documentation/API requirements reviewed: yes; canary/operator docs and this
  plan change, while public HTTP/JSON schemas remain unchanged.
- Decision timestamp or plan revision: 2026-09-07, release revision 8.

### Release-readiness phase P3 subparts

| Subpart | Deliverable and owner boundary | Dependencies | Interfaces / likely files | Documentation / API impact | Acceptance and oracle | Focused + regression checks | Parallel-safe | Status |
|---|---|---|---|---|---|---|---|---|
| P3.S1 | Five-stage canary and exact disable/restore oracle; primary Site owner only | P2R lifecycle | frontend workflow, driver, host helper, canary tests, backend operator README | canary operations/recovery docs; no API schema | ordered stages; candidate-only enable; v0.1.25 disable runs even when binary already current; a durable disable-attempt marker makes interruption before/after policy removal replay safe; final nested procfs denial and exact prior policy state; cleanup replay safe | focused Node canary tests, shell syntax/ShellCheck, full frontend/backend gates | no | completed, independently approved, and integrated |
| P3.S2 | Exact Runtime branch and sandbox-image documentation integration plus immutable signed v0.1.25 prerelease | post-merge Runtime/image gates, P3.S1 frozen artifact interface | Runtime PR #23 and release assets; sandbox-image README branch/PR | release notes, architecture-accurate image docs, and plan evidence; no API schema | both PR exact heads green/reviewed; merge commits green; sandbox docs land without image rebuild; Runtime tag produces exactly amd64 and arm64 archive/signature/checksum triplets whose checksums, Cosign signatures, architectures, and required membership verify; prerelease remains unpromoted | Runtime frozen gate, image doc/digest inspection, hosted distro checks, six-asset archive/signature inspection | yes after P3.S1 interface freeze | completed; release artifacts independently reproduced and approved |
| P3.S3 | Exact agent-kit integration and npm `warpmetal@0.8.7` publication | post-merge agent-kit gate | agent-kit branch/PR, package/release workflow, CLI/skill mirrors | CLI help/README/skill references | source/package mirrors identical; package dry run exact; PR/merge CI green; registry tarball/version contains the nested lifecycle contract | check, 73+ tests, pack dry run, installed-package help probe | yes after interface freeze | completed; merged, published, and independently registry-probed |
| P3.S4 | Frontend exact-head integration, public docs deployment, and cross-release readiness packet | P3.S1-S3 | frontend PR #104/default workflow, public pages/LLM text, production acceptance secrets metadata | public docs deployment and canary runbook | PR/default CI and deploy succeed; live pages/LLM contract match source; workflow verifies exact v0.1.24/v0.1.25 assets, CLI 0.8.7, image digest, and release public key without exposing secrets | full frontend/backend gates, route probes, workflow contract tests, exact metadata inspection | no | completed and independently approved |

- Inputs and outputs: reviewed post-main-merge source heads and protected release
  workflows produce immutable Runtime/CLI artifacts plus one default-branch
  canary workflow; P4 consumes only their verified versions, hashes, signatures,
  image digest, and credential-free scripts.
- Non-goals: P3 creates no VPS, performs no wallet/payment action, installs no
  Runtime, generates no key, and changes no Nico runtime state or flags.
- Edge and failure cases: pre-existing tag/package, merge conflict, stale PR
  head, failed CI, missing signing/publish credential, partially published
  release, frontend deploy failure, duplicate/replayed disable, absent versus
  displaced prior policy, and cleanup interruption.
- Integration responsibility: the primary manager merges and publishes in the
  recorded order after inspecting each exact diff and gate. Subagents may review
  or run bounded checks but may not edit the Site checkout or perform releases.
- Evidence to retain: exact commits, PR/check URLs, release asset hashes and
  signatures, npm version/tarball identity, workflow/deploy run IDs, clean
  worktree state, and redacted contract-test output.

### Release-readiness phase P3 test matrix

| Requirement / risk | Behavior or invariant | Test level | Oracle defined before code | Command or procedure |
|---|---|---|---|---|
| R11/A3 | explicit disable restores exact prior AppArmor state | contract + live-ready simulation | yes | durable `disable-attempt` marker is written after exact-policy verification and before install, accepts loaded/absent state on replay, and is retired only after completed-stage publication; focused canary assertions plus P4 host `verify-policy-absent`/exact displaced-state check |
| R1-R2 | disable removes only the grant and returns nested procfs to exact denial | contract + P4 end-to-end | yes | fifth-stage sensitivity oracle and generic/alternate/deeper negative controls |
| R3-R4 | release/canary changes do not alter OCI arguments, services, packages, workloads, or existing sandbox access | regression + P4 snapshot | yes | Runtime exact-argument/coexistence gates and before/after canary snapshots |
| R5/R10 | only signed exact artifacts are consumed without secret output | supply-chain / inspection | yes | SHA-256, Cosign, archive membership, npm pack/install, log/redaction inspection |
| R12 | CLI, public docs, skill mirrors, and LLM text agree on versions/actions/scope | documentation contract | yes | mirror comparison, rendered routes, backend surface tests, cross-repo phrase check |
| A6 | release selection and rollback never rebuild or replace immutable assets | release integration | yes | verify tag/asset identity before and after canary readiness; fail on pre-existing mismatched artifact |
| A6/R5 | tag workflows accept broad `v*` refs and repositories lack automated main protection | release integration | yes | before each tag, fetch `main` and tags; prove the intended reviewed merge SHA equals current remote `main`, has successful exact-commit CI, matches strict `vMAJOR.MINOR.PATCH`, and has no tag/registry/release collision; after Runtime publication require exactly six assets and verify both architecture triplets |

### Release-readiness phase P3 frozen command manifest

```sh
# Every repository before changes and before integration
git fetch origin main
git merge --no-edit origin/main
git status --short
git diff --check

# Runtime exact-head gate (Linux Go 1.25 environment)
test -z "$(gofmt -l .)"
sh packaging/apparmor/profile_test.sh
sh packaging/install/apparmor_policy_test.sh
sh packaging/install/install_test.sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/warpmetal-policy-metadata
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/warpmetal-policy-metadata

# Agent kit exact-head gate
npm run check
npm test
npm pack --dry-run
cmp skills/warpmetal/SKILL.md plugins/warpmetal/skills/warpmetal/SKILL.md
cmp skills/warpmetal/references/runtime.md plugins/warpmetal/skills/warpmetal/references/runtime.md
cmp skills/warpmetal/references/cli-reference.md plugins/warpmetal/skills/warpmetal/references/cli-reference.md

# Frontend/canary exact-head gate
node --test tests/runtime-private-procfs-canary.test.mjs
bash -n scripts/runtime-private-procfs-canary-driver.sh
bash -n scripts/runtime-private-procfs-canary-host.sh
bash -n scripts/runtime-private-procfs-oracle.sh
npm test
npm run lint
(cd backend && python3 -m pytest -q tests/test_surface.py)

# Image and cross-repository contract
sh -n test-image.sh
# Re-pull and independently verify the pinned amd64 digest/signature before P4.

# External exact-head evidence
# Require green PR and merge-commit CI, immutable Runtime v0.1.25 assets and
# signatures, npm warpmetal@0.8.7 pack/install probe, frontend default-branch
# workflow/deploy success, and a final clean-worktree/cross-contract inspection.

# Exact pre-tag gate in each release repository. Replace RELEASE_SHA and TAG
# only with the recorded reviewed merge commit and strict semantic-version tag.
git fetch origin main --tags
test "$(git rev-parse "$RELEASE_SHA")" = "$(git rev-parse origin/main)"
[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
test -z "$(git tag --list "$TAG")"
# Query GitHub Actions for successful exact-RELEASE_SHA default-branch CI and
# query the target registry/release again before creating the annotated tag.
# Runtime post-release: require exactly six assets, then independently verify
# amd64 and arm64 archives, checksum files, detached Cosign signatures,
# executable architecture, and required archive membership.
```

### Release-readiness phase P3 sequence and integration

1. Merge current `origin/main` into every feature branch and record exact heads.
2. Run fresh post-merge baselines; update this entry decision to `yes` only if
   the frozen gates and release interfaces remain valid.
3. Implement and verify P3.S1 in the frontend worktree under the primary Site
   owner, then obtain a read-only independent canary/security review.
4. Push and integrate Runtime/image P3.S2 and agent-kit P3.S3 only after their
   exact post-merge heads pass; publish and independently verify v0.1.25 and
   0.8.7.
5. Rebase-by-merge current `main` again if it advanced, integrate frontend
   P3.S4, verify default-branch CI/deployment and public documentation, and
   freeze the exact P4 input packet.
6. Do not create or mutate a VPS until P3 is completed and the human gives the
   required immediate confirmation for the priced test server, Runtime install,
   temporary sandbox/key operations, and cleanup actions.

### Release-readiness phase P3 verification evidence

- P3.S1 local implementation gate, frontend commit
  `f1bbe72301140c460566968f79a04016d7917e9f`: Bash syntax and
  ShellCheck pass for the driver, host helper, and oracle; the focused canary
  contract passes 11/11; full frontend build and 116/116 tests pass; lint has
  zero errors and the same three pre-existing translation-script warnings; the
  backend surface gate passes 45/45; `git diff --check` passes.
- The fifth stage consumes the signed v0.1.25 candidate, writes and syncs a
  metadata-bound disable-attempt marker after exact-policy verification, always
  invokes CLI 0.8.7 with `--nested-private-procfs disable`, validates the CLI
  result, accepts loaded or absent policy only on marker-backed replay, proves
  the exact proc-mount denial under Runtime 0.1.25, verifies no policy lifecycle
  residue remains, compares the final `absent` classification to the frozen
  sensitivity baseline, and retires the marker only after completed-stage
  publication.
- Independent P3.S1 canary/security review: the first review correctly rejected
  a missing directory durability barrier between completed-stage rename and
  marker retirement. Follow-up commit
  `4bcf6f16e6abedb5157d86371fc0083bdefe558f` syncs pending content, publishes
  the rename, syncs the checkpoint directory, then removes and syncs the marker
  deletion. Review P3-S1-review-02 approved the fix after an in-memory negative
  control proved the regression assertion rejects removal of the middle
  barrier. Per owner direction, this branch remains local until every other P3
  repository is integrated; current `main` will be merged into it again before
  push and its complete gate will rerun.
- P3.S2 independent Runtime/image review approved after requiring both Runtime
  architecture triplets and the explicit reviewed-main pre-tag gate. Sandbox
  documentation PR #3 merged as commit
  `f54f23ef3173fadd43cf3fe3fdf264817a72c7e6`; path filtering correctly avoided
  an image rebuild, and the pre-existing immutable signed image remains the P4
  input.
- Runtime PR exact-head run `34161817818` passed the workload-drift denial and
  all four distro coexistence jobs, but its main test job correctly failed when
  the new root-owned durable lifecycle fixture was invoked as the unprivileged
  hosted runner. The source lifecycle gate had passed in the root Linux
  baseline. CI and release verification now invoke that fixture through
  passwordless `sudo` while explicitly retaining the setup-Go `PATH`, matching
  the real root-only installer contract; exact-head review and hosted rerun are
  required before merge.
- Independent correction review P3-S2-ci-fix-review-01 approved Runtime commit
  `95d989315ddfb33f7c3ebd157784b5852abb7467`; approval is limited to the
  root-execution workflow correction and a fresh exact-head hosted run remains
  mandatory.
- The first correction rerun `34162212194` passed all four distro jobs and the
  workload-drift job and passed the now-root lifecycle step. It then exposed
  that `install_test.sh` transitively reruns the same root-owned lifecycle
  fixture. CI and release now invoke the installer structure test through the
  identical bounded `sudo env "PATH=$PATH"` boundary as well. Independent
  review P3-S2-ci-fix-review-02 approved commit
  `a82a0d44634039b65845469fa28226aca417cbb7`; exact-head PR run `34162494532`
  then passed all six required checks.
- Runtime PR #23 merged as
  `da08e6ec41eeac8a3d762aa44a17bada37390798`. Exact merge-commit CI run
  `34162644110` passed the test, workload-drift, and all four distro coexistence
  jobs. The strict-semver, current-`origin/main`, exact-CI, and collision gates
  passed immediately before annotated tag `v0.1.25`, which peels to that merge
  commit. Release run `34162774318` passed verify, both architecture builds,
  and publish; the resulting non-draft prerelease contains exactly six assets.
- Independent local release inspection downloaded all assets and verified both
  published checksum files and both detached signatures with the committed
  public key and checksum-verified Cosign v2.5.3. Each archive contains exactly
  the 13 required members and five static Linux executables of the expected
  architecture. Archive SHA-256 values are
  `ad4aa7159fe9111df65aa7ce6695135a0e3e8691a8f24967c7264795a2573067`
  for amd64 and
  `cf7308e0264a6b116e2f4235bf8562c207202ff9a4ee9e7ca7c2c3005f8c4269`
  for arm64. The prerelease remains unpromoted for P4.
- Independent release review P3-S2-release-review-01 reproduced the exact tag,
  workflow, release-state, asset-count, checksum, detached-signature,
  archive-membership, static-linking, and architecture checks and approved
  frontend integration with no release-contract or security blocker. The
  annotated Git tag itself is not signed; that was not an acceptance
  requirement because both immutable archives carry verified detached Cosign
  signatures.
- P3.S3 independent review approved agent-kit head `7e1cf0d`. PR #31 passed
  both Node 20/22 jobs and merged as
  `fbdc417651f2d07d184e00823be0c3a19cb3b414`; exact-main ancestry, CI, strict
  tag shape, and collision gates passed before annotated tag `v0.8.7`. Publish
  workflow run `34161645892` passed all gates and npm reported accepted
  publication with 22 files and shasum
  `17e47b71b139392c03a62782867db7cbfaadc2b9`. Registry propagation completed:
  `latest` resolves to 0.8.7, the published integrity is
  `sha512-tb4g07J8vciEvbMuYx/SyU3eAb/yTmGWmM7P+KoLvP1HCmrr6TR+NVIEyAzjab6AmCrPdrP0/wX0ahkaAKcRHQ==`,
  and a disposable local install reports version 0.8.7 and the exact
  `--nested-private-procfs <preserve|enable|disable>` help contract.
- Immediately before frontend integration, current frontend `origin/main`
  `17e03d1a98e91250136bfbafc512b7e431e7428a` was merged into the feature
  branch. The one conflict in `backend/tests/test_surface.py` was resolved by
  retaining both the private-procfs public-document contract and the newer
  OpenAPI idempotency/root-SSH invariant. Exact merge head
  `52a7be3219c26fcfa0a1b69ce0e3968335841d76` passed the production build,
  137/137 frontend tests, 11/11 focused canary tests, Ruff, 46/46 backend
  surface tests, Bash syntax, ShellCheck, actionlint, and diff checks. Lint had
  zero errors and the same three pre-existing translation-script warnings.
- Independent P3.S4 review reproduced those gates, verified both conflict
  sides, and approved the five-stage, artifact-verification, durable-disable,
  host-snapshot, credential-boundary, documentation, and API-parity contracts
  with no findings. PR #104 exact-head run `34163979456` passed before merge.
- Frontend PR #104 merged as
  `ce3c0bed8a91db41f6051638164c964deea7b075`. Default-branch workflow run
  `34164210354` completed successfully on that exact SHA: test, four-image
  publication, blue-green production deployment, admin promotion, bounded
  x402-header verification, and IndexNow all passed. The deployed acceptance
  workflow SHA-256
  `39b860b4b054941b10ce3387e499ce825c6de080af569e3eabf3aa77001a5e14`
  matches the file at the exact merge commit.
- Live HTTPS probes after deployment returned 200 for `/agent-runtime`,
  `/docs`, `/llms.txt`, and `api.warpmetal.com/llms.txt`. They contain the
  required optional host-scoped capability, CLI 0.8.7/Runtime 0.1.25,
  preserve/enable/disable lifecycle, planning/coding/independent-QA examples,
  and the statement that GitHub access, an AI CLI, and subagent delegation
  alone do not require it. The shared nested-capability machine contract is
  byte-identical across both live LLM endpoints. A final fetch confirmed
  frontend `origin/main` still equals the deployed merge commit.
- P3 integrated phase gate: all four subparts are integrated, immutable release
  and deployment evidence is exact-head bound, documentation/API surfaces are
  current, no live VPS/key/Runtime/sandbox mutation occurred, and no secrets
  were exposed. Phase status: completed at release revision 9.

### Live acceptance phase P4 header

- Phase ID and outcome: P4, prove on one disposable amd64 Ubuntu 24.04 VPS that
  the signed Runtime can move through `sensitivity -> candidate -> rollback ->
  forward -> disable` while preserving host workloads and restoring the exact
  pre-enable AppArmor state.
- Covered requirement and assumption IDs: R1-R6, R10-R11; A1-A4, A6, A8.
- Entry criteria: P3 is complete; the signed Runtime v0.1.24 baseline, signed
  v0.1.25 prerelease, npm CLI 0.8.7, pinned amd64 sandbox image, and deployed
  workflow are immutable and independently verified. A read-only live preflight
  must report purchasing readiness, current `agent` plan inventory, exact OS
  name, and monthly price before any key or server mutation.
- Exit criteria: the operator creates exactly one monthly acceptance VPS with a
  six-hour durable test expiry and three medium Runtime sandboxes; the VPS host
  key is enrolled out of band before SSH; all five stages pass in order with
  exact artifact pins and host snapshots; each stage's temporary small sandbox,
  two distinct access keys/grants, sessions, and workspace are revoked/deleted;
  final policy state equals the frozen initial absent state; the acceptance task
  is cancelled and provider absence is verified without guessing through an
  ambiguous outcome.
- Dependencies and risks: production operator credentials and environment
  approval; live `agent` plan availability and current price; exact
  `Ubuntu 24.04 (VPS)` catalog name; monthly billing may not be prorated or
  refunded by early cancellation; owner and per-sandbox SSH key generation;
  trusted provider/console host-key enrollment; Runtime installation and
  explicit host-policy mutation; one-hour temporary workspace expiry is
  irreversible and does not replace explicit cleanup; cancellation may enter
  manual review and must not be retried as though compute were absent.
- Baseline test state: P3 exact-head release, source, hosted CI, production
  deploy, and live public-document gates are green. P4.R1 is merged and
  deployed from frontend merge commit
  `6da3f0ab35eab8136ecfa11c88ccdd2a1d79003d`; its exact-head and
  default-branch gates are green, and a fresh deployed-main read-only preflight
  passed. No P4 server exists yet and no P4 key, payment, Runtime, sandbox,
  policy, grant, or cancellation mutation has been attempted.
- Required documentation and API-contract changes: this plan records the quote,
  confirmation, task/server IDs, stage runs, bounded safe evidence, cleanup,
  and residuals. No public HTTP/JSON schema or product documentation change is
  expected unless live behavior disproves the published contract.
- Coordinating owner: primary managed-plan executor. The deployed production
  workflow is the only mutation path; a separate non-implementing verifier
  reviews exact run evidence before promotion.
- Fresh recovery reviewer available: yes; two non-implementing reviewers
  approved P4.R1 independently. A fresh non-implementing verifier will review
  the live P4 evidence after all mutations stop.

### Live acceptance phase P4 assumption check

| Assumption ID | Check or probe | Evidence | Result | Plan change |
|---|---|---|---|---|
| A1 | Run exact signed nested-procfs positive/negative oracle under Ubuntu restricted user namespaces | candidate and forward stages | unresolved | blocks Runtime promotion until both positive stages pass |
| A2-A3 | Compare frozen workload/package/service/OCI snapshots across every stage and exact policy lifecycle state | sensitivity baseline plus per-stage canary evidence | unresolved live; hosted gates verified | stop on any drift; do not weaken snapshots |
| A4 | Reconnect to an existing sandbox through a new stage-specific grant before and after Runtime install while preserving its resource and workspace marker | every staged run | unresolved live | stop on ID, grant, marker, lifetime, or exit-code drift |
| A6 | Re-download and verify exact signed v0.1.24/v0.1.25 amd64 assets plus deployed metadata before each stage | protected workflow verification step | verified for P3; rerun required | no mutable or locally rebuilt artifact may substitute |
| A8 | Confirm the enabled policy is host-scoped but only the signed exact helper attaches; generic, alternate, and deeper attempts remain denied | candidate and forward negative controls | unresolved live | stop on any broader grant |
| P4.A1 | The production acceptance operator can obtain a current read-only quote without creating a prepared order, key, payment, or provider resource | workflow runs `34166139308` and deployed-main refresh `34175259049`, `action=preflight`, plan `agent` | verified | freeze the exact quote and require fresh owner confirmation before mutation |
| P4.A2 | The deployed workflow has all protected metadata and credentials needed for exact signed stages and replay-safe cleanup | P3 deploy, P4.R1 default-branch deploy run `34173873657`, and workflow/source parity | verified for dispatch; live signed-stage use required | use only the default-branch production workflow |
| P4.A3 | A trusted provider or console channel is available to enroll the exact new VPS host key before the private-procfs workflow opens SSH | operator runbook and deployment-host pin contract | unresolved | after creation, stop before stage dispatch if enrollment cannot be independently established |
| P4.A4 | The five canary stages can select their signed Runtime artifact without changing the process-global production `RUNTIME_*` tuple | P4.R1 task-scoped selector, bootstrap version/digest binding, registration mismatch rejection, DB constraint, and ordinary-user regression coverage | resolved in P4.R1 | use only operator-set exact signed selectors on live `is_test` tasks; clear on completion, expiry, and cancellation |
| P4.A5 | Order-time three-sandbox intent yields a ready v0.1.24 supervisor and running baseline sandboxes before sensitivity starts | P4.R1 trusted-host preparation and root/non-root replay harness | resolved in P4.R1 | sensitivity must run the replay-safe signed-v0.1.24 preparation and require exactly three running medium sandboxes before freezing the baseline |
| P4.A6 | An arbitrary owner-supplied existing VPS can replace the disposable production acceptance task | production workflow, operator task/selector checks, bootstrap/registration binding, canary checkpoint, and cancellation contract | false | an external VPS may support a separately authorized non-gating host inspection, but P4.S1-P4.S3 still require a provisioned live `is_test` task unless a new adoption contract is designed and reviewed |

### Live acceptance phase P4 entry-gate decision

- Implementation authorized: the read-only preflight and repository recovery
  are completed. Priced VPS creation, owner/sandbox key
  generation, Runtime installation, temporary sandbox creation, policy
  enable/disable, access grants/revocation, sandbox deletion, and final server
  cancellation remain unauthorized until the owner confirms the exact fresh
  quote and lifecycle effects immediately before the create dispatch.
- Decision evidence: owner authorized plan execution and asked to begin live VPS
  testing; managed-plan and WarpMetal safety contracts require the separate
  immediate mutation confirmation after live discovery.
- Unresolved low-impact defaults and consequences: hostname will use a unique
  acceptance-only DNS label chosen after the quote; the workflow's six-hour
  test expiry is retained. The exact monthly price and OS spelling are not
  defaults and must come from preflight.
- Error/logging requirements reviewed: yes; retain bounded IDs, stage labels,
  exact digests, safe status, and failure codes only. Never print or inspect the
  owner token, private keys, Runtime bootstrap, access tokens, full environment,
  payment envelopes, or raw secret-bearing output.
- Authentication/authorization requirements reviewed: yes; protected GitHub
  environment to deployment host, out-of-band host-key enrollment, owner-only
  host SSH, and distinct sandbox-specific grants remain mandatory.
- Documentation/API requirements reviewed: yes; the public Runtime bootstrap
  request and response remain unchanged. P4.R1 adds only nullable internal test
  metadata, protected operator commands, and deployment-runbook coverage. Any
  live discrepancy reopens P2/P3 instead of editing the oracle to pass.
- Decision timestamp or plan revision: 2026-09-08, release revision 12.

### Live acceptance phase P4 subparts

| Subpart | Deliverable and owner boundary | Dependencies | Interfaces / likely files | Documentation / API impact | Acceptance and oracle | Focused + regression checks | Parallel-safe | Status |
|---|---|---|---|---|---|---|---|---|
| P4.S0 | Read-only current quote and readiness packet | P3 | production operator `action=preflight`, plan `agent` | plan evidence only | current purchasing readiness, exact OS, capacity, and monthly price; no key/order/resource mutation | inspect exact workflow run/logs and absence of create step | no | completed |
| P4.R1 | Recover task-scoped signed artifact selection and establish a stable baseline-preparation path | P4.S0, false P4.A4-P4.A5 | backend Runtime/operator state and migration; acceptance workflow/driver/tests/runbook | internal operator contract and recovery docs; public bootstrap/OpenAPI stay unchanged | only live `is_test` tasks may receive an exact verified override; normal users retain global metadata; stage changes use fresh checkpoint-bound bootstrap keys while prior idempotent responses remain immutable; registration must report the selected version; sensitivity prepares v0.1.24 with `preserve`, nine Docker sentinels, and exactly three running medium sandboxes through trusted SSH | backend unit/DB/operator/security tests, canary contract tests, full frontend/backend gates, migration upgrade/downgrade, independent review, exact-head CI/deploy | no | completed; merged, deployed, and independently approved |
| P4.S1 | One acceptance VPS plus trusted owner access and initial Runtime resources | P4.R1 and fresh owner confirmation | `action=create`, unique hostname, exact OS/price cap, six-hour expiry, three medium sandboxes | operator evidence only | one task/server, key-only SSH, out-of-band pinned host key, ready state, active term, correct OS/amd64, then task-scoped baseline preparation proves v0.1.24 and three expected sandboxes | create/inspect runs, trusted-host-key precondition, bounded state inspection, baseline prepare run | no | pending |
| P4.S2 | Ordered five-stage signed private-procfs canary | P4.S1 | `action=canary-private-procfs`, exact task/hostname/stage and artifact hashes | plan evidence only | all stage-specific positive, negative, preservation, rollback, forward, disable, and cleanup oracles pass in order | workflow signature/metadata gate, stage logs, host snapshots, replay-safe cleanup | no | pending |
| P4.S3 | Final cancellation, absence verification, and independent review | P4.S2 | `action=cancel` then read-only inspection/provider reconciliation | plan and promotion packet | cancellation terminal and no billable compute ambiguity; no temporary grants/sandboxes/runner files/policy residue; fresh verifier approves | exact workflow evidence, safe log review, independent whole-phase audit | no | pending |

### Live acceptance phase P4.R1 frozen recovery design

- Store the test selector as an all-null or all-populated nullable tuple on
  `PurchaseTask`: version, credential-free HTTPS Runtime release URL, lowercase
  SHA-256, bounded detached signature, and SHA-256 of the configured signing
  public key. A database constraint permits a populated tuple only when
  `is_test=true`; these fields never enter public task/admin projections,
  OpenAPI, or ordinary logs.
- Add protected operator-only set, inspect, and clear commands. Set requires an
  exact confirmation binding task ID, version, and digest; an existing,
  unexpired operator test task; a provisioned active-term server; enabled
  Runtime; strict version/digest/signature validation; the exact WarpMetal
  GitHub amd64 release URL matching the version; and a signing-key digest equal
  to the configured trusted Runtime public key. Arbitrary keys, URLs, versions,
  non-test tasks, expired tasks, and partial selectors fail before mutation.
- Resolve the effective artifact only after the bootstrap transaction locks and
  revalidates the current task. Valid test selectors use the same globally
  configured signing public key; normal tasks always use the stable global
  artifact. A malformed, expired, or key-mismatched populated selector fails
  closed instead of silently falling back.
- Keep `POST /runtime/bootstrap` request/response and Agent Kit 0.8.7 unchanged.
  Bind the selected version and digest into each one-use bootstrap row and
  require registration to report the selected version. Preserve existing
  idempotency records: replay of an old key returns its original response, while
  each canary checkpoint uses a new key and receives the current selector.
- The protected workflow already verifies both signed releases. It writes only
  the chosen credential-free descriptor to a mode-0600 temporary file, invokes
  the operator selector for the exact test task immediately before the official
  CLI install, and clears/verifies absence in an `always()` cleanup. Cancellation
  and expiry clear the selector as defense in depth. Audit events contain only
  task ID, version, artifact digest, and signing-key digest—never the signature,
  key body, bootstrap, owner token, or environment.
- Sensitivity enrolls the host key through the independent trusted channel,
  installs Docker and all nine sentinels, selects and installs signed v0.1.24
  with `preserve` from `pending_install`, and waits for exactly the three ordered
  persistent medium sandboxes to run before freezing the host and existing-
  sandbox oracle. It does not create the generic canary's fourth persistent
  sandbox and never uses `ssh-keyscan` as trust evidence.

### Live acceptance phase P4 test matrix

| Requirement / risk | Behavior or invariant | Test level | Oracle defined before action | Command or procedure |
|---|---|---|---|---|
| R1-R2/A1/A8 | only the exact signed helper gets one private-procfs nesting; generic/alternate/deeper controls fail | live end-to-end | yes | candidate and forward canary stages plus negative controls |
| R3-R4/A2-A3 | OCI restrictions, nine Docker workloads, packages, services, and existing sandboxes remain exact | live snapshot | yes | compare frozen sensitivity host baseline after every stage |
| R6/A4 | existing sandbox ID, marker, persistent lifetime, and behavior survive install transitions | live integration | yes | stage-specific grant/connect before and after install; exit 37 |
| R10 | no credential or unbounded diagnostic exposure | workflow/log inspection | yes | inspect bounded stage markers and secret-redaction behavior only |
| R11 | sensitivity begins absent; candidate enables; rollback retains policy; forward remains enabled; disable restores exact absent state | live lifecycle | yes | ordered stage checkpoint and exact final `post-disable-v0125-denied` oracle |
| Billing/cleanup | only one approved monthly VPS exists and is cancelled; ephemeral stage resources are removed | live operator/lifecycle | yes | exact task/hostname binding, per-stage cleanup, cancel/inspect reconciliation |

### Live acceptance phase P4 frozen command manifest

```text
1. Dispatch production acceptance workflow with action=preflight and plan=agent.
2. Inspect exact preflight run; freeze purchasing readiness, OS name, capacity,
   monthly price, and absence of mutation.
3. Complete P4.R1 so the test task, not the global production metadata, selects
   the signed stage artifact and sensitivity has an explicit stable baseline.
4. Obtain immediate explicit owner confirmation for every priced/destructive
   lifecycle effect before action=create.
5. Dispatch action=create once with the confirmed hostname, OS, six-hour expiry,
   exact max monthly price, and three medium sandboxes; inspect to ready.
6. Enroll and verify the exact VPS host key out of band; prepare the v0.1.24
   baseline with `preserve` before any private-procfs stage.
7. Dispatch sensitivity, candidate, rollback, forward, and disable separately,
   in order, with the exact baseline/candidate SHA-256 values.
8. Inspect every run for its exact stage success line, host snapshot equality,
   signed metadata, and temporary resource cleanup before advancing.
9. Dispatch cancel once, reconcile to terminal provider absence, and perform an
   independent whole-phase review before promoting Runtime v0.1.25.
```

### Live acceptance phase P4 sequence and integration

1. P4.S0 froze the live quote, then the entry audit exposed false P4.A4-P4.A5.
2. P4.R1 and its independent recovery gate are complete; obtain the owner's
   fresh explicit approval before creating any billable resource.
3. Complete P4.S1 serially; do not start a canary until the trusted-host-key and
   initial-resource checks pass.
4. Run P4.S2 strictly in stage order. A failed stage stops progression and
   enters cleanup/recovery without weakening or skipping its oracle.
5. Run P4.S3 even after a failed stage when safe cleanup is possible. Treat
   manual review or ambiguous provider state as a blocker, not proof of absence.
6. Record exact evidence, obtain independent approval, and only then advance to
   P5 promotion and Nico work.

### Live acceptance phase P4 recovery log

- P4.S0 workflow run `34166139308` succeeded on deployed commit
  `ce3c0bed8a91db41f6051638164c964deea7b075`. Only request validation,
  pinned deployment-host setup, and the read-only operator preflight ran; the
  create, inspect, Runtime, sandbox, grant, cancellation, and receipt steps were
  skipped. The live account-specific `agent` quote is monthly `$15.00` in LAX2,
  OGB1, or TPA2; exact target OS `Ubuntu 24.04 (VPS)` is available.
- Independent public discovery with WarpMetal CLI 0.8.6 was read-only and is
  compatible with the skill's 0.7.8 minimum. Health reported `status=ok` and
  `purchasingReady=true`. The `agent` plan supports Runtime on Ubuntu 24.04 and
  has 3500 millicores, 7168 MiB, and 70 GiB of workspace capacity. Three medium
  sandboxes consume 3000 millicores, 6144 MiB, and 60 GiB; one stage-local
  temporary small sandbox consumes the exact remainder. The canary itself will
  install and verify published CLI 0.8.7.
- Entry reconciliation then disproved P4.A4 and P4.A5. Backend
  `runtime._artifact()` reads one process-global `RUNTIME_RELEASE_*` tuple and
  every bootstrap returns it; CLI 0.8.7 installs only that returned artifact.
  The driver nevertheless requires v0.1.24 metadata for sensitivity/rollback
  and v0.1.25 for candidate/forward/disable. Global secret flips would expose
  the prerelease or rollback to unrelated owners and are rejected. Separately,
  order-time sandbox intent begins with no registered supervisor or running
  sandbox, while sensitivity currently snapshots and connects before its
  install branch. No VPS or key was created. P4.R1 is now the required recovery
  gate before immediate owner confirmation.
- P4.R1 recovery landed in frontend PR #107 from exact head
  `1d39a1b7b355287519c628ff953a8a298658e5ff` and merged as
  `6da3f0ab35eab8136ecfa11c88ccdd2a1d79003d`. The branch was merged with
  current `origin/main` before every edit and again immediately before
  integration. Recovery commits added the missing operator-command coverage
  (`9da3289d2cbe97a631ad1d159e38159122234fbb`), removed the UTC-midnight test
  race (`078cb17a4c3c66dc6daa0e3d1cc9c4ca47b5a58e`), routed both preparation
  recovery paths through the production validator so UID 1000 replay succeeds
  (`75e993117f434448890d21ddf7824b4b9e2ef58c`), and added a direct production
  ownership/mode/symlink security oracle
  (`1d39a1b7b355287519c628ff953a8a298658e5ff`).
- Exact-head PR workflow `34173254408` passed Ruff, Alembic upgrade, 1815
  backend tests with one skip and 87.59% statement/74.02% branch coverage, all
  139 Node tests including the Linux root/non-root preparation replay, admin
  build, and all 30 admin tests. Local Linux replay passed all 14 crash
  boundaries as root and UID 1000; the focused UID 1000 Node gate passed 13/13;
  Bash syntax, ShellCheck, `git diff --check`, and the full local build/test gate
  passed. Two independent non-implementing reviews approved the exact head: one
  verified ownership, exact-file cleanup, and replay recovery; the other
  verified test-only selector isolation, exact signed metadata, bootstrap and
  registration binding, operator authorization/cleanup, baseline preparation,
  and the unchanged public OpenAPI/Agent Kit/global-user contract.
- Default-branch workflow `34173873657` succeeded for merge commit
  `6da3f0ab35eab8136ecfa11c88ccdd2a1d79003d`: test completed in 4m12s,
  all four production images published in 2m51s, and the 17m22s deploy passed
  database migration, blue-green service promotion, admin promotion, bounded
  production x402 header verification, and IndexNow notification. No new
  Runtime, CLI, or sandbox image release was required; the recovery consumes
  the already verified signed Runtime v0.1.24/v0.1.25 and existing signed
  all-tools image.
- The fresh deployed-main read-only preflight, workflow run `34175259049` on
  exact merge commit `6da3f0ab35eab8136ecfa11c88ccdd2a1d79003d`, passed. The live `agent`
  quote remains monthly `$15.00` in LAX2, OGB1, or TPA2, and exact OS
  `Ubuntu 24.04 (VPS)` remains available with SSH-key and cloud-init support.
  Checkout, release verification, create, inspect, canary, selector cleanup,
  cancellation, and receipt reconciliation were all skipped; no priced or
  destructive lifecycle action occurred. P4.S1 remains pending fresh explicit
  owner confirmation.
- The owner then offered an existing VPS as the test target. Read-only access
  discovery confirmed that its SSH host key is already pinned locally, but the
  default and dedicated Ubuntu identities were rejected; the CLI's safe state
  listing did not map the address to a known server identity. No private key,
  SSH configuration secret, host data, or external state was read or changed.
- Two fresh non-implementing reviews rejected treating an arbitrary existing
  VPS as a P4.S1-P4.S3 substitute. The production canary has no existing-IP
  adoption input: task-scoped artifact selection requires a live, unexpired
  `is_test` `PurchaseTask`, provider-backed device, active term, and enabled
  `ServerRuntime`; bootstrap and registration bind the exact task/server and
  selected artifact; sensitivity requires the three control-plane-created
  sandboxes; and final cleanup is task/provider cancellation with verified
  absence. Bypassing those boundaries would lose the ordinary-user isolation,
  artifact-binding, provisioning, preservation, grant, expiry, and cleanup
  evidence that P4 exists to prove.
- Reuse also has broader preservation risk than the disposable design. Runtime
  installation writes binaries, systemd and Runtime SSH files, may install
  packages, starts the private Podman service, and restarts `warpmetald`; the
  preparation path installs Docker when needed and creates nine fixed-name
  sentinels plus a network. Its preservation oracle covers the defined Runtime
  processes and running Docker workloads, not every arbitrary service, stopped
  container, network, volume, image, or application-level invariant. Policy
  enablement is host-scoped, and the rollback stage deliberately retains it
  until the final signed disable.
- An owner-supplied host may therefore be used only for an explicitly
  authorized, non-gating read-only/static feasibility probe unless it can first
  be uniquely proven to be the intended dedicated WarpMetal acceptance
  `is_test` task. A true external-host substitution would require a separate
  reviewed adoption contract, complete workload baseline, approved maintenance
  window, non-cancellation restoration criteria, and retained full
  control-plane canary. P4.S1 remains pending without mutation.

### Live acceptance phase P4.R1 verification log

- Acceptance criteria checked: test-only all-null/all-populated selector state,
  exact signed version/key/URL/digest validation, bootstrap version/digest
  binding, registration mismatch failure, global stable artifact behavior for
  ordinary users, operator-only set/inspect/clear, expiry/cancellation cleanup,
  and replay-safe fresh-host baseline preparation all passed.
- Cross-subpart behavior checked: the deployed operator workflow selects a
  signed artifact only for a live authorized test task, uses a new
  checkpoint-bound bootstrap for each stage, preserves old idempotent results,
  requires the registered Runtime version to match, and clears the selector in
  the guarded lifecycle. The public bootstrap schema, OpenAPI, Agent Kit 0.8.7,
  Runtime releases, and signed sandbox image are unchanged.
- Error-path and log-safety evidence: partial preparation state is owned by
  root, mode 0600, a regular non-symlink, and exact-file cleanup refuses foreign
  or malformed state. Both root and UID 1000 replay traversed all 14 crash
  boundaries. Selector input rejects partial tuples, arbitrary or mismatched
  metadata, non-test/expired tasks, and registration-version mismatch without
  printing credentials, signatures, bootstrap values, or private keys.
- Authentication and authorization evidence: selector mutation is reachable
  only through protected operator commands with exact task/version/digest
  confirmation and a live `is_test` task. No customer-facing enable option or
  per-user toggle was added; the capability remains an explicit host lifecycle
  choice while the canary artifact selector is task-scoped and internal.
- Independent review: two fresh read-only reviewers returned approval on exact
  head `1d39a1b7b355287519c628ff953a8a298658e5ff`; exact-head CI, merge, production
  deploy, and deployed-main preflight all passed. P4.R1 status: completed at
  release revision 11. Revision 12 records that an arbitrary existing VPS is
  not a valid substitute. The unresolved risks are now the intended live kernel,
  preservation, host-key, billing, and cleanup oracles in P4.S1-P4.S3.

### Documentation phase P2D header

- Phase ID and outcome: P2D, make the nested-private-procfs capability
  understandable and discoverable for any qualifying Agent Runtime workload.
- Covered requirement and assumption IDs: R11-R12; A7-A9.
- Entry criteria: the preserve/enable/disable interface is implemented and
  independently approved; the owner confirmed Bubblewrap remains part of the
  current isolation architecture and clarified that the capability is not
  Nico-only.
- Exit criteria: Runtime and sandbox-image documentation explains why the inner
  boundary exists and gives planning, coding, and QA examples; CLI help, README,
  and skill/reference mirrors show the exact lifecycle; public `/agent-runtime`
  and `/docs` pages plus `llms.txt` and its backend mirror carry the same
  capability-based guidance; documentation tests and repository regressions pass.
- Dependencies and risks: CLI 0.8.7 and Runtime 0.1.25 remain unreleased; live
  capability behavior remains gated by P4. Documentation must not imply that
  GitHub operations, a particular agent brand, or subagent delegation requires
  the feature, and must not describe a host-scoped policy as per-sandbox.
- Baseline test state: Runtime, agent-kit, frontend, and Nico gates passed before
  this documentation phase; the sandbox image branch is clean at `864cf6f`.
- Required documentation and API-contract changes: Runtime README/security and
  this plan; sandbox README; agent-kit CLI help/README/skill/reference mirrors;
  frontend public pages, localized message dictionaries, and canonical and
  backend-mirror LLM text. Public HTTP/JSON API change is not applicable because
  these are documentation surfaces, not API schemas.
- Coordinating owner: cross-repository documentation coordinator.
- Fresh recovery reviewer available: no fresh reviewer required for this
  documentation-only phase; behavior remains protected by existing executable
  tests and P4 live acceptance.

### Documentation phase P2D assumption check

| Assumption ID | Check or probe | Evidence | Result | Plan change |
|---|---|---|---|---|
| A7 | Determine whether ordinary Runtime installs need the feature | default preserve implementation and owner discussion | false | explain that need is driven by nested Bubblewrap use |
| A8 | Determine whether activation can be documented per sandbox | exact-path AppArmor policy and shared Runtime owner | false | state host scope everywhere and recommend separate hosts when necessary |
| A9 | Determine whether Nico owns or limits the capability | owner clarification and Runtime-level interface | false | describe a general capability; retain Nico only as the first acceptance consumer |

### Documentation phase P2D entry-gate decision

- Implementation authorized: yes.
- Decision evidence: owner requested the documentation update and explicitly
  requested CLI and LLM-text coverage on 2026-09-07.
- Unresolved low-impact defaults and consequences: none; examples will use
  planning, coding, and QA while stating that other verified nested-Bubblewrap
  workloads may qualify.
- Error/logging requirements reviewed: yes; preserve the documented stable
  installer error contract and do not add credentials or host details to examples.
- Authentication/authorization requirements reviewed: yes; only the existing
  owner-authorized Runtime installation may change host policy. Documentation
  does not expand access.
- Documentation/API requirements reviewed: yes; all canonical and mirrored
  surfaces are listed above. HTTP/JSON API changes are not applicable.
- Decision timestamp or plan revision: 2026-09-07, documentation revision 5.

### Documentation phase P2D subparts

| Subpart | Deliverable and owner boundary | Dependencies | Interfaces / likely files | Documentation / API impact | Acceptance and oracle | Focused + regression checks | Parallel-safe | Status |
|---|---|---|---|---|---|---|---|---|
| P2D.S1 | General Runtime and image explanation with planning/coding/QA examples | R11 interface | Runtime README/SECURITY/plan; sandbox README | human architecture and security guidance | purpose, examples, limits, and disposable-sandbox alternative are accurate | phrase/contract inspection; Runtime and image existing gates | yes | completed |
| P2D.S2 | CLI and agent-facing lifecycle guidance | CLI 0.8.7 branch | CLI help/README; source and packaged skill/reference mirrors | executable help and agent instructions | help and docs show preserve/enable/disable, version floor, host scope, examples, and non-goals | CLI help assertion; full agent-kit test/package gates; mirror comparison | yes | completed |
| P2D.S3 | Public human and LLM documentation | frontend branch | public pages; localized messages; `content/llms.md`; `backend/public/llms.txt`; frontend tests | public human and machine documentation | public pages and both LLM contracts contain matching purpose, examples, lifecycle, and scope language | rendered-page/route/backend tests + phrase parity | yes | completed |
| P2D.S4 | Cross-repository documentation parity | P2D.S1-S3 | all documentation surfaces | no API schema change | no Nico-only/coding-only/subagent-only requirement claim; exact versions/actions agree | targeted search, diff check, full relevant regressions | no | completed |

### Documentation phase P2D test matrix

| Requirement / risk | Behavior or invariant | Test level | Oracle defined before code | Command or procedure |
|---|---|---|---|---|
| R12/A9 | capability is general and need is workload-based | documentation contract | yes | all canonical surfaces say nested Bubblewrap/private procfs; no surface says Nico or coding users are the exclusive audience |
| R12 | planning, coding, and QA examples explain the enforced boundary | documentation contract | yes | Runtime, sandbox, CLI/skill, and LLM text cover read-only planning, single-workspace coding, and independent QA |
| R11-R12 | exact lifecycle and compatibility remain aligned | CLI/contract | yes | preserve default; explicit enable/disable; CLI >=0.8.7 and Runtime >=0.1.25; amd64 enable; host scope |
| R12 | public and backend LLM text remain aligned | integration | yes | targeted phrase comparison plus frontend rendered-route and backend surface tests |
| R12 | public human documentation remains available and localized | integration | yes | `/agent-runtime` and `/docs` render the explanation, examples, lifecycle, and activation command in English, Spanish, and Portuguese |
| R10 | examples contain no real identifiers or credentials | inspection | yes | placeholder-only command review and existing secret/surface tests |

### Documentation phase P2D frozen command manifest

```sh
# Each repository
git diff --check

# Runtime
sh packaging/apparmor/profile_test.sh
sh packaging/install/apparmor_policy_test.sh
sh packaging/install/install_test.sh

# Agent sandbox
sh -n test-image.sh

# Agent kit
npm run check
npm test
npm pack --dry-run

# Frontend and llms.txt
npm test
npm run lint
python -m unittest backend.tests.test_surface
```

### Documentation phase P2D sequence and integration

1. Generalize the Runtime decision record and explain the security boundary in
   Runtime and sandbox-image documentation.
2. Update CLI help, README, and both copies of the bundled skill/reference.
3. Update the canonical frontend LLM text and backend mirror with the same
   examples and operational contract.
4. Run focused contract assertions, full relevant regressions, cross-repository
   phrase/version/action inspection, and record the results before P3.

### Recovery phase P2R header

- Phase ID and outcome: P2R, recover the disproved default-install design with
  an explicit host-scoped policy lifecycle that is off by default and safely
  reversible.
- Covered requirement and assumption IDs: R2-R4, R10-R11; A2-A3, A7-A8.
- Entry criteria: PR #23 exact-head CI is green; independent review recorded A7
  and A8 as false; the installer interface is frozen as
  `--nested-private-procfs preserve|enable|disable` with default `preserve`;
  Runtime-only recovery implementation is authorized.
- Exit criteria: default installs do not inspect, parse, load, unload, create,
  replace, or remove Runtime AppArmor policy state; explicit enable is amd64
  only and idempotent; explicit disable restores any pre-existing destination
  and loaded state; interrupted transactions retain durable recovery evidence;
  focused tests and the full Runtime phase gate pass.
- Dependencies and risks: the backend remains the authenticated trusted
  image-selection boundary; this phase adds no sandbox manifest/API field and
  cannot offer per-sandbox policy isolation.
- Baseline test state: exact head `9459b08` passes current Linux unit, race, vet,
  profile, installer, policy transaction, and four-distro hosted gates; live
  restricted-AppArmor behavior remains P4.
- Required documentation and API-contract changes: README, SECURITY, installer
  CLI/error contract, and this plan. Public HTTP/JSON API changes are not
  applicable.
- Coordinating owner: Runtime recovery implementer, with the parent coordinator
  retaining cross-repository integration.
- Fresh recovery reviewer available: yes; parent coordinator will assign an
  independent verifier after the Runtime diff is returned.

### Recovery phase P2R assumption check

| Assumption ID | Check or probe | Evidence | Result | Plan change |
|---|---|---|---|---|
| A7 | Compare unconditional installer behavior with the first Nico consumer and the general capability boundary | `install.sh` automatically mutates policy on restricted Ubuntu although only workloads creating nested private procfs need it | false | default becomes `preserve`; only explicit enable/disable may mutate policy |
| A8 | Determine whether exact-path attachment identifies a sandbox | profile attaches by filesystem path and Runtime sandboxes share the same owner/image path | false | document host scope; do not invent a per-sandbox claim or manifest flag |
| A2 | Preserve container/package behavior | existing exact create-argument and coexistence gates are green | verified for implementation | keep policy operation after package/workload gate and leave container arguments unchanged |
| A3 | Recover policy state safely | current EXIT rollback is process-failure safe but `/run` evidence and retained downgrade policy are insufficient for explicit disable/crash recovery | false for recovered lifecycle | add a durable root-only transaction journal/backup and explicit recovery before new policy operations |

### Recovery phase P2R entry-gate decision

- Implementation authorized: yes.
- Decision evidence: parent recovery assignment and frozen installer interface,
  2026-09-07.
- Unresolved low-impact defaults and consequences: none; non-amd64 explicit
  enable fails closed, while preserve and disable remain available for recovery.
- Error/logging requirements reviewed: yes; preserve existing stable safe errors
  and add distinct invalid-mode, unsupported-architecture, and recovery errors
  without logging file contents or credentials.
- Authentication/authorization requirements reviewed: yes; only the existing
  root-required, authenticated signed Runtime install path may request the host
  operation. Backend image selection remains a trusted boundary.
- Documentation/API requirements reviewed: yes; installer CLI documentation is
  required, HTTP/JSON API change is not applicable.
- Decision timestamp or plan revision: 2026-09-07, recovery revision 4.

### Recovery phase P2R subparts

| Subpart | Deliverable and owner boundary | Dependencies | Interfaces / likely files | Documentation / API impact | Acceptance and oracle | Focused + regression checks | Parallel-safe | Status |
|---|---|---|---|---|---|---|---|---|
| P2R.S1 | Explicit preserve/enable/disable lifecycle with durable recovery and amd64 gate | frozen interface | installer and AppArmor policy helper | installer errors/recovery | preserve makes no policy calls; enable loads exact policy idempotently; disable restores prior file/state; stale transaction recovers before mutation | expanded policy transaction tests | no | completed; independent review approved |
| P2R.S2 | Packaging and operator/security documentation parity | P2R.S1 | README, SECURITY, release/install structural tests | host scope, image trust, amd64, recovery | docs describe actual default and scope without per-sandbox claim | structural/doc inspection | no | completed; independent review approved |
| P2R.S3 | Integrated Runtime recovery gate | P2R.S1-S2 | repository-wide | plan verification evidence | all focused/full gates pass; diff preserves OCI/package/workload invariants | shell, race, vet, cross-build, exact diff inspection | no | completed; independent review approved |

### Recovery phase P2R test matrix

| Requirement / risk | Behavior or invariant | Test level | Oracle defined before code | Command or procedure |
|---|---|---|---|---|
| R11/A7 | omitted/default preserve does not mutate policy | unit + structure | yes | fake parser/metadata operation log remains empty; existing state byte/kernel-state identical |
| R11 | explicit enable is amd64-only and idempotent | unit + integration | yes | amd64 enable twice reaches exact candidate/enforce state; non-amd64 fails before mutation |
| R11 | explicit disable reverses enable and restores displaced state | unit + recovery | yes | loaded/unloaded pre-existing file fixtures restore exact content/metadata/kernel state |
| R11/A3 | interrupted transaction is recoverable | recovery | yes | durable journal fixture survives invocation boundary and is consumed before the next operation |
| R2/A8 | scope is host-wide but exact-path/child restrictions remain | inspection + live P4 | yes | static profile test plus explicit docs; no sandbox/API toggle claim |
| R3-R4 | OCI, packages, and workloads are unchanged | regression | yes | exact Podman args, installer structure, four-distro CI |

### Recovery phase P2R frozen command manifest

```sh
git diff --check
test -z "$(gofmt -l .)"
sh -n packaging/install/install.sh
sh -n packaging/install/warpmetal-apparmor-policy.sh
sh -n packaging/apparmor/nested-private-procfs-oracle.sh
sh packaging/apparmor/profile_test.sh
sh packaging/install/apparmor_policy_test.sh
sh packaging/install/install_test.sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/warpmetal-policy-metadata
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/warpmetal-policy-metadata
```

### Recovery phase P2R sequence and integration

1. Implement and test the local installer/policy lifecycle without changing
   container arguments or HTTP manifests.
2. Align operator/security docs and structural release assertions.
3. Run the complete Runtime gate and return the uncommitted diff for fresh
   independent review; live capability promotion remains P4.

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
| A2 | Preserve the exact current `createArguments` list and exercise supported distros | v0.1.24 source plus four-distro matrix | verified for P2 | exact forbidden/unchanged assertions and Ubuntu 24.04, Debian 12, AlmaLinux 9, Rocky Linux 9 hosted coexistence jobs passed; live host remains P4 |
| A3 | Parse-before-install, load only the new file, never restart AppArmor/Podman, require both loaded profiles exactly once in enforce mode, and retain/restore exact prior file metadata plus loaded/unloaded state on failure | installer architecture audit and recovery review | verified for P2 | signed no-atime/no-follow copy and comparison helper, source-stability/inherited-xattr checks, parser-read timestamp restoration, failure tests, and hosted install/drift gates passed; live host remains P4 |

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
| P2.S4 | Full Runtime verification and independent scope/security review | P2.S1-S3 | repository-wide | plan verification log | exact head green on all supported distros; reviewer APPROVE | full commands below | no | completed |

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

- Acceptance criteria checked: P2 local and exact-head hosted criteria passed.
- Full commands and results: Ubuntu 24.04 shell/AppArmor/installer/ShellCheck
  gate passed; Go 1.25 formatting, race suite, vet, and amd64/arm64 helper builds
  passed; `git diff --check` passed.
- Cross-subpart behavior checked: fresh independent reviewer returned APPROVE for
  the complete Runtime diff; exact head `39dbb82` passed GitHub Actions run
  `34143505512`.
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
- Phase status: completed. P4 remains the required live capability gate before
  production promotion.

### Documentation phase P2D verification log

- Runtime and image documentation: Runtime README/SECURITY and the signed-image
  README now describe the inner boundary, planning/coding/QA examples, exact
  wrapper trust, version/action contract, host scope, and the disposable
  per-attempt Runtime-sandbox alternative. Runtime's full Go 1.25 Linux gate and
  the image test script syntax check passed.
- CLI and agent guidance: CLI help, README, source skill/references, and packaged
  plugin mirrors agree on CLI 0.8.7, Runtime 0.1.25, preserve/enable/disable,
  amd64 enablement, general workload scope, and examples. The source/package
  mirrors compare byte-for-byte; `npm run check`, 73 tests, and
  `npm pack --dry-run` passed.
- Public human documentation: `/agent-runtime` and `/docs` render the rationale,
  examples, exact activation command, lifecycle, and scope in English, Spanish,
  and Portuguese. Frontend build and 108 tests passed; lint reported zero errors
  and the same three unrelated existing warnings.
- Public machine documentation: the canonical `content/llms.md` and backend
  `public/llms.txt` carry byte-identical capability sections. Frontend route
  assertions and all 45 backend surface tests passed.
- Cross-repository parity: targeted inspection found planning, coding, QA,
  preserve, enable, disable, host scope, CLI 0.8.7, and Runtime 0.1.25 in every
  required surface. Documentation states that need is determined by nested
  Bubblewrap, not Nico, GitHub, an AI CLI, or subagent delegation.
- API/authentication/error impact: no public HTTP/JSON schema or authorization
  change. The existing owner-authorized install and stable safe error contract
  remain authoritative.
- Residual: documentation is locally complete, but publication remains coupled
  to the reviewed branch/release rollout and P4 live capability canary.
- Phase status: completed.

### Recovery phase P2R verification log

- Local implementation status: preserve/enable/disable lifecycle, durable
  activation baseline, atomic in-progress transaction, amd64 enable gate,
  legacy-candidate adoption/removal, documentation, and installer structure are
  implemented. No HTTP/JSON API was added.
- Focused behavior evidence: Linux tests prove preserve does not touch missing
  bundle/parser/state paths; non-amd64 enable fails before durable-state or
  parser mutation; enable is policy-idempotent; disable restores loaded and
  unloaded pre-existing files with exact metadata; ordinary EXIT rollback and a
  later explicit operation recover interrupted transactions; and an interrupted
  disable after baseline movement restores both the candidate and baseline.
- Independent behavior check: invoking the real installer entry point in a
  linux/arm64 container returns only
  `runtime_nested_private_procfs_architecture_unsupported` before host/package
  mutation.
- Recovery review correction: the preserve EXIT path now uses an explicit
  `warpmetal_apparmor_policy_initialized` guard instead of relying on a
  top-level no-op rollback definition. A disposable privileged Ubuntu 24.04
  test executes the real default-preserve installer through its locked-install
  failure path and proves it emits only `runtime_install_in_progress`, invokes
  no policy rollback, and removes its `/run/warpmetal-install.*` state.
- Full local gate: `git diff --check`, Go formatting, shell syntax, profile
  tests, expanded AppArmor transaction tests, installer structural tests,
  `go test -race ./...`, `go vet ./...`, and linux amd64/arm64 metadata-helper
  cross-builds passed in a Go 1.25 Linux container. Host ShellCheck at warning
  severity also passed.
- Documentation/API parity: README and SECURITY describe default preserve,
  host scope, amd64-only enable, trusted backend image selection, explicit
  disable, and durable recovery. Installer contract is
  `--nested-private-procfs preserve|enable|disable`; public HTTP/JSON API remains
  not applicable.
- Independent review: the parent verifier re-ran the Go 1.25 Linux gate,
  privileged default-preserve execution, frontend contract suite, Nico runner
  suite, and agent-kit package gate. A separate frontend verifier confirmed the
  Runtime/release/canary contract, and a separate agent-kit verifier found and
  then approved the recovery-error priority and exact bundle validation fixes.
- Residual gate: P2R is complete. Live AppArmor kernel behavior remains the
  separate P4 production-promotion blocker; power-loss recovery is consumed by
  the next explicit enable/disable rather than a boot-time recovery unit.

## Project completion record

- Final acceptance evidence: pending.
- Full relevant regression evidence: pending.
- Delivered architecture and operational notes: nested-Bubblewrap capability
  rationale, examples, lifecycle, scope, and alternatives are complete locally;
  production activation notes remain pending P4-P6.
- Delivered API contracts, reference documentation, and parity evidence: no
  public API schema change; Runtime/image docs, CLI help/skill references,
  localized public pages, and LLM machine contracts passed P2D parity checks.
- Error/logging controls and verification: pending.
- Authentication/authorization controls and verification: pending.
- Known residual risks: no arm64 live canary is in scope; arm64 artifacts remain
  build/test-only until separately exercised.
- Remaining assumptions or untested behavior: A1-A3 pending.
