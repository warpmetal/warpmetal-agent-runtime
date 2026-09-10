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
  - `agent-kit`: expose the explicit lifecycle through CLI 0.8.7, add
    self-contained managed first-use SSH host-key trust in CLI 0.8.8, explain
    both contracts in CLI help, and keep the bundled WarpMetal skill and
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
  - signed Runtime v0.1.25 prerelease for the frozen private-procfs canary and
    a separately verified signed Runtime v0.1.26 release for automatic Runtime
    ordering and selected-CLI readiness reporting;
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
| R13 | Safe first-use SSH trust without provider-console access | On the first owner-authenticated connection for an exact server trust epoch, CLI 0.8.8 or the protected canary may trust the first observed Ed25519 host key once, atomically pin it, and reconnect strictly before any bootstrap or payload transfer; every replay is strict and any mismatch, malformed pin, unexpected IP, failed reload, or ambiguous state fails without replacing the pin | unit, contract, local SSH integration, protected live end-to-end |
| R14 | Missing-pin incident recovery cannot become a reusable trust reset | The one existing acceptance canary may consume one exact-task recovery reservation after a protected diagnostic proves its pin missing; only when a later protected diagnostic proves that reservation failed before durable host-key capture may one separately authorized, globally one-off replacement reservation be created. Both reservations are durable before their allowed host-key observation/first-contact SSH and neither may repeat it after claim; P4.R8's bounded preclaim banner-readiness connections send no application bytes and cannot perform key exchange or capture a host key. Successful publication is followed by strict replay, and both paths are unavailable to ordinary users or any other task/device | unit, contract, concurrency, failure-recovery, protected live end-to-end |
| R15 | Automatic Runtime ordering requires the first complete signed supervisor contract | Runtime v0.1.26 directly invokes the fixed image-owned CLI reporter without a shell, reports the selected Codex/Claude/Cursor observations for the matching desired generation, preserves the existing private-procfs and generic exec behavior, and is the minimum version advertised for automatic bootstrap and CLI reporting | unit, migration, race, release-asset, four-distro integration, live end-to-end |
| R16 | Public ordering must fail closed until the exact candidate is proven on every advertised OS | Production `agentRuntime.supported` remains false until the exact signed v0.1.26 tuple has passed fresh order-time cloud-init canaries on AlmaLinux 9, Debian 12, Rocky Linux 9, and Ubuntu 24.04; activation verifies the tuple cryptographically and catalog eligibility before and after traffic switch | contract, workflow, provider canary, deployment, public smoke |

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
  a server-ID and trust-epoch scoped first-use SSH pin, per-agent grant, Nico
  admin session, and one-time model leases. TOFU authenticates continuity after
  the first observation; it does not provide provider attestation against an
  active attacker on that first connection.
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
| Release | mutable artifacts; signed prerelease then promotion | retain signed immutable v0.1.25 for the frozen private-procfs canary; integrate selected-CLI reporting and publish signed immutable v0.1.26, verify it on every advertised automatic-ordering OS, then promote the same assets | v0.1.26 is required for ordering; do not retag v0.1.25 or rebuild assets during promotion |
| Policy activation | install on every restricted-AppArmor host; per-sandbox toggle; explicit host toggle | default `preserve`, explicit signed `enable`/`disable`; AppArmor pathname attachment cannot truthfully provide per-sandbox isolation without a separate outer profile/API design | hosts without nested Bubblewrap receive no policy mutation; enabled dedicated hosts grant all same-owner matching-path sandboxes |
| Consumer scope | Nico-only feature; coding-only feature; general nested-Bubblewrap capability | general capability with Nico as the first acceptance consumer; need is determined by the inner isolation boundary rather than the agent brand, task category, GitHub use, or subagent use | product docs must use capability-based language and concrete planning/coding/QA examples |
| Initial VPS host trust | mandatory provider-console enrollment; blind network scan; authenticated trust on first use with optional console pre-seed | trust the first host key observed during one harmless owner-key-authenticated SSH connection for an exact server trust epoch, then atomically pin and require strict matching; retain protected console enrollment as an optional stronger pre-seed and forbid `ssh-keyscan` | ordinary users do not need Hivelocity access; first-connection MITM remains an explicit accepted residual; mismatch bypass and generic pin reset remain forbidden |
| Missing protected canary pin | abandon the canary; infer the old key; generic reset; incident-bound recovery with one proven-pre-capture replacement | do not claim restoration because the original public fingerprint was not retained; the first internal recovery is permanently consumed, but after P4.R7 proved its candidate durably empty and the owner explicitly authorized continuing on the same VPS, permit one globally one-off replacement claim in a separate state namespace after a non-trusting SSH-banner readiness gate | this is another accepted first-contact MITM window for one canary, not an ordinary-user reset or new trust epoch; banner failure consumes nothing, but any failure after the replacement claim is terminal unless a canonical candidate/pin permits strict-only replay |

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
| A10 | Ordinary WarpMetal users can obtain a provider-console-authenticated VPS host key before using the CLI | high | false | owner decision: users will not have Hivelocity access; the supported default must use first-observed-key trust once and preserve strict pin continuity afterward |
| A11 | Cancelling an operator test task immediately destroys the provider device | medium | false | Hivelocity cancellation stops future billing but retains the device through its already-created term; the cleanup oracle is terminal task state plus unambiguous successful provider cancellation, while `hasProviderDevice=true` and powered compute may remain until provider retirement |
| A12 | The cancelled acceptance task cannot be reused while its paid provider device remains live | high | false as stated; direct reuse is still blocked | `cancelled` is an intentionally manageable Runtime/SSH state only while the control-plane term is active, but this task's six-hour `test_expires_at` and capped `term_ends_at` both expired at `2026-09-08T07:33:04.758006Z`; reuse requires a protected one-time continuation lease for this exact task/device without changing cancellation or billing state |
| A13 | The original successful protected TOFU retained an immutable public host-key fingerprint or canonical pin digest that can authenticate a replacement pin | high | false | GitHub run `34198472527` proves the exact trust step succeeded on deployed commit `7ae91ba5`, but its retained job log, check output, and artifact inventory contain no helper fingerprint/digest output; Runtime never registered and the protected diagnostic found the only pin missing, so continuity cannot be reconstructed |
| A14 | A bounded non-trusting TCP SSH-banner check can prevent another known-listener-absent authority consumption | medium | verified as a design constraint; live result unresolved | two consecutive bounded `SSH-2.0-` identifications may establish readiness without key exchange, authentication, host-key capture, or claim creation, but cannot eliminate the race between readiness and the later SSH attempt; failure must stop without an automatic retry |
| A15 | Current Runtime main may be retagged as v0.1.26 to enable ordering | high | false | v0.1.25 main lacks selected-CLI reporting; v0.1.26 must merge `codex/all-tools-runtime-report` with current main and correct the reporter execution boundary |
| A16 | The existing task-scoped artifact selector can prove order-time v0.1.26 cloud-init without enabling public ordering | high | false | it is limited to historical v0.1.24/v0.1.25 and is persisted after provider creation; add a protected create path that binds the signed v0.1.26 tuple in the initial task transaction |
| A17 | One Ubuntu canary is sufficient while four OS rows are advertised as Runtime-capable | high | false | use one fresh disposable order-time canary for each advertised OS, sequentially and stop on first failure; billed provider creation requires a separate exact aggregate-cost authorization |

## Test strategy

- Unit: exact image path/ownership/version, Podman arguments, forbidden arguments,
  existing-container no-recreate behavior, installer profile decisions, and Nico
  exact command/oracle assertions.
- Contract: release archive contents, exact AppArmor attachment/child transition,
  no Runtime API change, source digest and runner manifest parity, CLI help/skill
  mirror parity, frontend/backend LLM contract parity, and first-use trust
  ordering that forbids bootstrap or payload delivery before atomic pinning.
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
| First SSH connection | an active attacker presents the first observed host key and becomes the durable pin | bind TOFU to the exact authenticated API server ID/IP and owner key, perform only `ssh true`, pin once per authorized trust epoch, then reconnect strictly before bootstrap; optional console pre-seed remains available | local two-host-key integration, protected canary, mismatch/no-overwrite and no-bootstrap-before-pin tests |
| Later SSH connection or host reload | key substitution, blind reset, or stale pin weakens continuity | strict managed `UserKnownHostsFile`; no accept-new when a pin exists; only a successful authenticated reload operation that declares host-key refresh may create a new trust epoch | replay/mismatch tests and reload state-machine tests |
| Cancelled-test continuation | a generic reopen path silently restores access, extends billing, trusts a new host, or reuses a different provider device | one protected fixed-deadline extension for the exact cancelled pending-install test shape; current provider/DB/record/key/pin binding plus strict SSH before DB change; state remains cancelled and final cancel replay closes the lease | operator DB/provider negative tests, workflow/helper behavioral tests, live inspect/strict probe/replay/final closure |
| Missing protected pin recovery | repeated blind TOFU, an inferred old key, a crash that silently renews first-contact authority, or reuse for another task/device | exact one-task/source-bound P4.R6 reservation plus at most one globally one-off P4.R8 replacement only after protected proof that P4.R6 captured no key; readiness precedes P4.R8 state, each claim precedes its sole first-contact SSH, all replay is strict-only or terminal, and completion records only safe fingerprint/digest metadata with no lease/lifecycle mutation | backend global uniqueness/concurrency tests, readiness packet and executable crash-boundary matrix, two-host-key negative oracle, protected live recovery and strict replay |

## Master phase map

| Phase | Testable outcome | Requirements / risks | Dependencies | Exit criteria | Status |
|---|---|---|---|---|---|
| P0 | Architecture and rollout gate frozen | R1-R10, A1-A6 | independent audits | canonical plan reviewed; no rejected bind work included | completed |
| P1 | Existing signed image contains trusted Bubblewrap | R2, R5, R10 | signed image | exact digest/path/owner/mode/version verified | completed |
| P2 | Runtime candidate packages and loads the restricted policy safely | R1-R4, R10, A1-A3 | P1 path contract | PR reviewed; full CI green on exact PR head | completed |
| P2R | Runtime policy lifecycle is explicit, default-off, architecture-gated, and reversibly recoverable | R2-R4, R10-R11, A2-A3, A7-A8 | P2 recovery review | default preserve is mutation-free; explicit amd64 enable is idempotent; disable unloads/removes Runtime policy and restores any displaced prior file/state; interruption evidence is durable; tests/docs green | completed |
| P2D | General capability documentation is discoverable and example-driven | R11-R12, A7-A9 | P2R interface | Runtime and sandbox docs, CLI help/skill, public pages, and both LLM contract sources agree on purpose, examples, versions, actions, host scope, and non-goals; repository gates pass | completed |
| P3 | Signed v0.1.25 prerelease, CLI 0.8.7, and five-stage frontend canary contract ready | R1-R5, R10-R12 | P1-P2R, P2D | exact heads pass CI/review; signed Runtime and npm CLI releases are independently verified; frontend workflow is available on its default branch | completed |
| P3O | Signed Runtime v0.1.26 and automatic-ordering activation | R3-R5, R10, R15-R16, A15-A17 | P3; source/release work may proceed independently of P4 | current Runtime main and selected-CLI reporting are merged and reviewed; the exact signed v0.1.26 prerelease passes release verification and four fresh order-time OS canaries; the same assets are promoted/configured; production catalog aggregate support is true and public smoke passes | in_progress; P3O.S1-S3 complete, protected v0.1.26 ordering path deployed, billed live matrix pending exact aggregate-cost approval |
| P4 | Rollback/forward/disable amd64 acceptance canary passes | R1-R6, R10-R11, R13-R14, A1-A4, A10, A13 | P3 | first-use trust or its one authorized incident recovery is safely pinned, pre-policy sensitivity, positive capability, preservation, retained-policy binary rollback, forward, and exact disable/restore gates pass | in_progress |
| P5 | Stable nested-private-procfs production activation and Nico sandbox refresh on v0.1.26 | R1-R7, R10 | P3O, P4 | exact v0.1.26 assets remain stable; Nico upgrade plus both explicit refreshes verified | pending |
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

### Automatic-ordering release phase P3O header

- Phase ID and outcome: P3O, integrate selected-CLI reporting with current
  Runtime main, publish and verify the exact signed v0.1.26 release, prove its
  initial cloud-init path on every OS currently advertised as Runtime-capable,
  and activate the unchanged release tuple for public ordering.
- Covered requirement and assumption IDs: R3-R5, R10, R15-R16; A15-A17.
- Entry criteria: Runtime `origin/main` is signed v0.1.25 commit
  `da08e6ec41eeac8a3d762aa44a17bada37390798`; selected-CLI reporting is on
  clean branch `codex/all-tools-runtime-report` at
  `e0d342c36f07ea0e15a4de9ab65bf0bcaad51b54`; v0.1.26 does not exist; the
  existing signed sandbox-image digest remains immutable; source integration
  and release work are owner-authorized. Billed provider orders, production
  secret/config mutation, and a paid public order retain their separate gates.
- Exit criteria: v0.1.26 is tagged only from the reviewed Runtime main merge,
  its six release assets verify independently, each advertised OS passes a
  fresh order-time candidate canary using that exact tuple, production deploy
  verifies and configures the same tuple, `/catalog` reports aggregate support,
  and unpaid plus separately authorized paid public-order smoke passes.
- Dependencies and risks: P3 is complete. Runtime source/release work is
  independent of the incident-bound P4 host. Frontend/backend/operator/public
  work is deliberately last. The P4 v0.1.24/v0.1.25 evidence, trust state,
  lifecycle journals, and existing VPS are never reused or reinterpreted.
- Baseline test state: both current Runtime main and the reporting branch pass
  `go test -race ./...` in disposable Go 1.25 containers; the host lacks Go,
  so formatting, vet, privileged installer/AppArmor gates, hosted coexistence,
  and exact-merge CI remain mandatory and are not yet claimed.
- Required documentation and API-contract changes: Runtime README/SECURITY and
  release notes; internal protected ordering runbook/workflow; CLI-reporting
  minimum supervisor version `0.1.26` in catalog/OpenAPI/public docs/LLM text.
  Nested-private-procfs documentation remains `v0.1.25+` and the P4 historical
  selector remains v0.1.24/v0.1.25.
- Coordinating owner: parent manager. One Runtime implementer owns the direct
  reporter correction; fresh non-implementing reviewers own diff and release
  verification; a separate frontend implementer starts only after the signed
  Runtime release is verified.

### Automatic-ordering release phase P3O assumption check

| Assumption ID | Check or probe | Evidence | Result | Plan change |
|---|---|---|---|---|
| A15 | Compare v0.1.25 main with the reporting feature and checkout gate | main lacks `internal/toolreport`; product aggregate support requires supervisor `>=0.1.26` | false | merge current main into the reporting branch, correct it, then tag only the reviewed merge on main |
| P3O.A1 | Determine whether the reporting helper is reached through a trusted fixed execution path | current probe calls generic `Engine.Exec`, whose Podman implementation uses `/bin/sh -lc`; the sandbox user owns its login profile | unsafe as implemented | add a dedicated direct reporter method with exact image-owned argv, fixed sanitized child environment, and no shell, profile, PATH lookup, tty, attached/transmitted stdin, caller arguments, or caller/desired-state-supplied environment |
| A16 | Trace the existing test selector relative to provider creation | the selector is historical-version allowlisted and written after a test VPS exists | false | add a protected create action that stores the exact verified candidate tuple in the initial task transaction before worker claim/provider cloud-init |
| A17 | Compare advertised OS eligibility with order-time evidence | AlmaLinux 9, Debian 12, Rocky Linux 9, and Ubuntu 24.04 all advertise Runtime support | false | require one fresh sequential canary per OS or narrow the advertised OS set before activation |
| P3O.A2 | Determine whether publishing alone enables checkout | production catalog derives aggregate support from the configured signed Runtime tuple | false | keep checkout disabled through release and canaries; activate only through reviewed production configuration/deploy |

### Automatic-ordering release phase P3O entry-gate decision

- Implementation authorized: yes for plan maintenance, Runtime source
  integration, review, PR, and signed v0.1.26 prerelease publication. The
  owner's instruction that v0.1.26 is needed for ordering is the decision
  evidence. This does not silently authorize provider charges, production
  secret changes, or payment.
- Unresolved high-impact gates: exact aggregate monthly cost for up to four
  fresh VPSs; exact production configuration mutation; paid public order. Run
  read-only quote/preflight first and request those bounded authorities at the
  point they become necessary.
- Error/logging requirements reviewed: yes. Reporter output is bounded and
  strictly parsed; child stderr and raw execution/provider errors are not
  exposed; workflows emit no signature, public-key material, credentials, or
  raw provider body.
- Authentication/authorization requirements reviewed: yes. The candidate
  create action is protected, main-only, exact-release-bound, confirmation- and
  idempotency-bound, and unavailable to public callers. Ordinary checkout stays
  fail-closed until production activation.
- Documentation/API requirements reviewed: yes. Public catalog/OpenAPI/LLM
  surfaces must advertise `0.1.26` for selected-CLI reporting only. No public
  field is added; existing readiness fields change value only after activation.
- Decision timestamp or plan revision: 2026-09-09, ordering revision 1.

### Automatic-ordering release phase P3O subparts

| Subpart | Deliverable and owner boundary | Dependencies | Interfaces / likely files | Documentation / API impact | Acceptance and oracle | Focused + regression checks | Parallel-safe | Status |
|---|---|---|---|---|---|---|---|---|
| P3O.S1 | Merge current Runtime main and correct trusted CLI-report execution | frozen entry hashes | `internal/containers`, `internal/toolreport`, reconcile/state/model and tests; Runtime README/SECURITY | Runtime internal contract; no HTTP schema | exact `podman exec warpmetal-<id> /usr/local/bin/warpmetal-agent-tool-report`, without `-i`; fixed sanitized child environment; no attached/transmitted stdin, login shell/profile/PATH/caller argument, or caller/desired-state environment injection; bounded stdout, discarded stderr, normalized errors; generic `Engine.Exec` and private-procfs behavior unchanged | direct-argv negative tests, migration/legacy state, focused race, full race/vet, installer/AppArmor/coexistence, four hosted distros | no | completed: main merged before implementation and PR; security/correctness blockers fixed; two final reviews approved; PR #22 head/merge CI green and merged as `bdcd05b` |
| P3O.S2 | Review, merge, publish, and independently verify signed v0.1.26 prerelease | P3O.S1 | Runtime PR/default branch, annotated tag, release workflow and committed `cosign.pub` | release notes and exact six-asset contract | tag points to exact reviewed main merge and has both v0.1.25 main and reporting commit as ancestors; amd64/arm64 archives, checksums, detached signatures, static architectures, exact 13 regular files plus the root directory, and embedded supervisor `0.1.26` verify; release stays prerelease | exact-head/merge CI, download/re-hash/Cosign, archive membership, embedded version; live registration/report is P3O.S4 | no | completed: annotated tag/release exact, run `34412218346` green, six assets independently verified, prerelease retained |
| P3O.S3 | Add protected pre-activation candidate create path, frontend work last | verified P3O.S2 assets | backend Runtime/operator, protected acceptance workflow, tests/runbook | internal operator only; no public eligibility change | protected workflow downloads the exact official v0.1.26 archive and verifies its digest and Cosign signature with the committed release key before protected create; backend exact-binds and durably persists that verified tuple with one minimal all-three-CLI sandbox before worker claim or provider mutation; confirmation/idempotency bind hostname, OS, version, artifact and request digests | state/order/concurrency/mismatch/redaction tests, workflow contract, full backend/site/Admin gates, main merge before implementation and PR | no | completed: frontend main `122f7d5` merged before implementation and was still current immediately before PR; branch commit `48fd6c2`, PR #140, merge `f9e8499`; exact-head run `34420708151` and exact-main run `34421199832` green; production deploy succeeded; public eligibility unchanged |
| P3O.S4 | Run exact supported-OS order-time Runtime matrix | P3O.S3, explicit aggregate-cost authority | one fresh disposable smallest viable VPS per advertised OS; unique host key and task | private acceptance evidence only | exact OS/cloud-init; task/provider ready; registration before 45-minute deadline; supervisor 0.1.26 and artifact digest exact; desired/observed generation equal; signed image exact; sandbox running; three CLI observations present; owner SSH; cancellation and no-renewal reconcile, while provider service may remain through its prepaid term unless deletion is supported and separately authorized | protected workflow, safe logs, per-OS independent review; sequential stop-on-first-failure | no | in recovery: transport is proved, but live prepare exposed an undeclared deployment-host `jq` dependency; complete the full remote-command contract audit and one comprehensive recovery before any further deploy or prepare; never use the P4 VPS |
| P3O.S5 | Activate exact production tuple and public catalog | P3O.S4 | deployment workflow/secrets, blue-green script, catalog/OpenAPI/docs/LLM minimum | selected-CLI minimum becomes 0.1.26; no nested-private-procfs version rewrite | workflow cryptographically verifies tuple before upload; candidate and two post-switch catalog reads show product support true and all four OS flags true; failure leaves old slot public and restores prior tuple before retry | deploy workflow tests, backend/site/Admin/full gates, production deploy and catalog probes | no | pending; requires explicit production-config authority |
| P3O.S6 | Public ordering smoke | P3O.S5 | public order preparation and one smallest paid Ubuntu order | validates existing public contract | unpaid preparation returns 201 with frozen Runtime intent and performs no checkout/payment/provider action; separately authorized paid order reaches Runtime 0.1.26 and all-three-CLI readiness | API/checkout smoke, payment/provider reconciliation, independent final review | no | pending; paid portion requires separate amount/payment authority |

### Automatic-ordering release phase P3O test matrix

| Requirement / risk | Behavior or invariant | Test level | Oracle defined before code | Command or procedure |
|---|---|---|---|---|
| R15/P3O.A1 | untrusted sandbox profile or desired state cannot forge CLI-report readiness | unit + container integration | yes | assert exact direct argv without `-i`, no attached/transmitted stdin, and fixed sanitized child environment; forbid shell/profile/PATH/tty/caller-argument or caller/desired-state environment injection; mutate `.profile` and desired-state fixtures and prove neither can affect the report command |
| R15 | selected CLI observations bind to desired generation and survive legacy DB upgrade | unit + migration + race | yes | strict JSON/version/status catalog, legacy empty defaults, interrupted migration/reconcile, desired-command injection negatives |
| R3-R5 | v0.1.25 private-procfs and ordinary interactive exec remain unchanged | regression + hosted | yes | exact generic Exec args, installer/policy/oracle suites, four-distro coexistence and workload-drift jobs |
| R15 | release is immutable and correctly signed for both architectures | supply chain | yes | tag/main ancestry, six assets, checksum and Cosign verification, architecture, 13-member archive, embedded version |
| R16/A16 | candidate artifact controls initial order-time cloud-init before public activation | contract + concurrency + live | yes | initial-transaction descriptor binding, worker-claim race tests, exact four-OS protected canary |
| R16/A17 | public eligibility matches proven OS set and exact production tuple | deploy + public end-to-end | yes | candidate/pre-switch and two post-switch catalog assertions, unpaid prepare, separately authorized paid Ubuntu smoke |
| R10 | no secrets/signatures/provider bodies leak | test + log inspection | yes | sentinel redaction, allowlisted output, release/deploy/live log review |

### Automatic-ordering release phase P3O frozen command manifest

```sh
# Runtime exact branch and merge gates, in a Linux Go 1.25 environment.
git diff --check
test -z "$(gofmt -l .)"
sh -n packaging/install/install.sh
sh -n packaging/install/warpmetal-apparmor-policy.sh
sh -n packaging/apparmor/nested-private-procfs-oracle.sh
sh -n packaging/install/preserve_execution_test.sh
sh -n packaging/install/coexistence_container_test.sh
sh packaging/apparmor/profile_test.sh
sudo env "PATH=$PATH" sh packaging/install/apparmor_policy_test.sh
sudo env "PATH=$PATH" sh packaging/install/install_test.sh
go test -race ./internal/toolreport ./internal/containers ./internal/reconcile ./internal/state ./internal/api
go test -race ./...
go vet ./...

# Hosted exact-head and merge gates.
# Require all current Runtime CI, all four privileged distro coexistence jobs,
# workload-drift jobs, and independent exact-diff approval.

# Release verification.
# Require the annotated v0.1.26 tag to peel to the exact reviewed main merge;
# verify both required ancestors, six assets, checksums, detached Cosign
# signatures with committed cosign.pub, static architectures, exact 13-member
# archive contract, and embedded/reporting supervisor version 0.1.26.

# Frontend/backend gates after Runtime release verification only.
# Run focused Runtime/operator/database/workflow tests, Ruff, compileall,
# actionlint, migration-to-head, full backend, full site/build/lint, Admin build
# and tests, OpenAPI/LLM mirror checks, exact-head CI, and blue-green deployment.
```

The Runtime release workflow currently promises checksum files and detached
Cosign signatures, not Runtime SBOM or provenance assets. Do not claim or test
for artifacts outside that contract. The separately pinned sandbox image keeps
its existing SBOM/provenance/signature contract and immutable digest.

### Automatic-ordering release phase P3O sequence and integration

1. On the clean reporting branch, fetch and assert the frozen heads, then merge
   current Runtime `origin/main` before any implementation. Never rebase. If
   main changed or a conflict/semantic uncertainty appears, stop and review it;
   never overwrite newer main behavior.
2. Implement only the direct fixed reporter boundary and combined semantic
   corrections. Run the frozen local/hosted gates and two independent reviews.
3. Merge current main again immediately before the Runtime PR. After exact-head
   and exact-merge CI, merge the PR; tag only that Runtime main merge v0.1.26,
   publish it as a prerelease, and independently verify all assets.
4. Only after release verification, merge current frontend main before the
   bounded protected candidate-create implementation. Keep public frontend,
   CLI, OpenAPI, LLM, and deploy changes last; merge main again before its PR.
5. Run a read-only provider quote. After exact aggregate-cost approval, execute
   the four OS canaries sequentially and stop on first failure. Do not reuse or
   mutate the incident-bound P4 VPS.
6. After the matrix and explicit production-config authority, promote the same
   release assets, configure the exact production tuple, deploy with fail-closed
   catalog assertions, and verify aggregate support. Do not lower the v0.1.26
   gate to make checkout appear enabled.
7. Run unpaid order preparation, then request separate exact payment/VPS-budget
   authority for the final public paid smoke. Record independent final review.

P3O can proceed while P4 listener recovery remains pending because automatic
Runtime installation uses the default `preserve` policy mode and does not
activate nested private procfs. P4 remains the mandatory gate for enabling that
optional host capability and for Nico's refresh; none of its incident evidence
or authority is consumed by P3O.

#### P3O.S1-S2 integration and release checkpoint

- The manager first fetched and merged Runtime `origin/main` at signed v0.1.25
  commit `da08e6ec41eeac8a3d762aa44a17bada37390798` into clean reporting branch
  `codex/all-tools-runtime-report` at
  `e0d342c36f07ea0e15a4de9ab65bf0bcaad51b54`. Merge commit `08c152d` had no
  textual conflict; an independent semantic review approved the combined
  README, SECURITY, Podman, private-procfs, and reporting base.
- Independent security review blocked the original feature because generic
  `Engine.Exec` used `/bin/sh -lc`, allowing the sandbox owner's writable login
  profile to forge the fixed reporter output. Commit `861544f` adds a dedicated
  `Engine.ToolReport`: private Podman service, nil stdin, discarded stderr, and
  exact direct argv `exec`, validated container name, fixed absolute reporter.
  Generic interactive Exec remains behaviorally exact.
- The same review found that CLI selection changes were compared with observed
  rather than persisted desired generation. The final implementation rejects a
  changed selection unless it advances beyond persisted `local.Generation`;
  an interrupted generation-2/observed-generation-1 regression proves rejection
  before ToolReport, Exec, restart, or state mutation.
- CI and release verification now run
  `packaging/install/tool_report_execution_test.sh` against exact signed image
  digest
  `sha256:c3fefa156c491c31db48c3799e21a15438f2c5c452555e49b7c37815b5aee5ba`.
  The real image remains root-owned/mode-0555 at the reporter path and reports
  Codex `0.153.4`, Claude `2.1.263`, and Cursor `2026.09.02-c22c1a3`. Its prior
  keyless signature, SPDX SBOM, and SLSA provenance were independently
  reverified. The hostile-profile oracle uses a writable home, fake PATH tools,
  `ENV`/`BASH_ENV`, and an inert desired payload under no network; only the exact
  three-tool JSON appears and no hostile marker executes.
- Manager and independent gates passed: focused and full `go test -race`, full
  `go vet`, repository formatting/diff checks, real-image oracle, shell syntax,
  AppArmor/profile/installer preservation tests, and two final exact-diff
  reviews. Immediately before PR, current main was fetched and already current;
  no conflict or newer behavior was overwritten. PR #22 exact-head run
  `34411712311` passed all six jobs. It merged as exact Runtime main commit
  `bdcd05ba61063257ab429072f9aface917b078da`; exact-main run `34411897605`
  passed the same six jobs.
- A fresh pre-tag reviewer proved v0.1.26 absent, verified main and all required
  ancestors, and returned `APPROVE_TAG_V0_1_26`. Annotated tag `v0.1.26` peels
  exactly to `bdcd05b`. Release run `34412218346` passed source verification,
  both signed static builds, and publication. The release is a non-draft
  prerelease with exactly six assets; no asset was rebuilt or replaced.
- Independent post-release verification returned
  `APPROVE_V0_1_26_RELEASE`. Each archive contains the exact 13 regular files
  plus its root directory, no links or unsafe paths, the expected executable
  modes, correct static amd64/arm64 ELF architecture, and embedded version
  `0.1.26`. Checksums and detached key-based Cosign signatures verify against
  committed `cosign.pub`; tlog absence is expected because the established
  workflow signs blobs with `--tlog-upload=false`.
- Verified asset SHA-256 values:
  - amd64 archive
    `f4b1fd76f67cc01385a1309eaf38e2aaca5b5eb90254df1b0549a02a45040791`,
    checksum asset
    `951c26ad4186c7911c8ff802958288b1607557344e918fa3953bb85bb1598ebd`,
    signature asset
    `af6ff2b239a8f2e681d443c858ac3d0e7b1559a4491194450306989d0e7a7d18`;
  - arm64 archive
    `881b5fb81fca1e371fc6794b7074d3c010d8baca95b3b499a577d9877cd54ec5`,
    checksum asset
    `b0b94243d0a0d2e0ca0a16e83466b0c17753be5941d38b1c774fa72d947411dd`,
    signature asset
    `8dabfbeb26c677c3f21f875a5f8e23ea2c0eaa875d59dc8919e5f547a549b12d`.
- P3O.S1-S3 are complete. The release stays a prerelease and production
  ordering remains disabled. P3O.S4 may run the protected four-OS matrix only
  after a fresh read-only quote and exact aggregate-cost approval; it cannot
  change public eligibility, production configuration, or the P4 incident
  state.

#### P3O.S3 frozen protected ordering-canary design

- Baseline and ownership: frontend branch
  `codex/nested-private-procfs-canary` and `origin/main` both resolved to
  `122f7d5669e824428cd176d72b968f19825f4ec8` before implementation, with no
  conflict or user change overwritten. The parent manager remains integration
  owner. One frontend/backend implementer owns only Runtime/operator,
  acceptance-workflow, focused test, and internal runbook files. Fresh
  non-implementing reviewers own the security/concurrency and exact-diff gates.
  Public site, catalog, OpenAPI, CLI, LLM text, production Runtime secrets,
  deploy activation, and the P4 incident remain non-goals.
- Exact internal names: workflow actions and operator commands are
  `prepare-runtime-ordering-canary` and
  `create-runtime-ordering-canary`; implementation functions use the matching
  `prepare_runtime_ordering_canary` and `create_runtime_ordering_canary`
  names. Runtime uses
  `validate_runtime_ordering_canary_artifact_descriptor`. These are protected
  internal operator surfaces, not public HTTP or CLI contracts.
- Exact order shape: plan `standard`; one exact certified OS supplied from the
  existing four-OS allowlist; a unique DNS-label hostname; one to 24 hours;
  the read-only live monthly quote bounded by the explicitly approved maximum;
  and exactly one `runtime-ordering-canary` sandbox with `size=small`,
  `lifetime=persistent`, and
  `cliTools=[codex,claude,cursor]`. Callers cannot supply or vary the Runtime
  sandbox batch. Read-only provider catalog/quote GETs may precede task
  authorization; provider SSH-key, compute, lifecycle, payment, and other
  mutations may not.
- Exact Runtime tuple: version `0.1.26`; official amd64 URL; archive SHA-256
  `f4b1fd76f67cc01385a1309eaf38e2aaca5b5eb90254df1b0549a02a45040791`;
  detached-signature asset SHA-256
  `af6ff2b239a8f2e681d443c858ac3d0e7b1559a4491194450306989d0e7a7d18`;
  normalized configured PEM SHA-256
  `405804fc07d382e314363569616cd4cff756546db54c5f556b73bda538be9d79`.
  The committed PEM file including its terminal newline has SHA-256
  `42fa456b1eaba7c87d87b7039b92366b4736fda53e3ac19fdfb8d707d0916390`.
  `TEST_RUNTIME_ARTIFACT_VERSIONS` remains exactly `{0.1.24,0.1.25}`;
  stored `0.1.26` candidate descriptors route through the new exact validator.
- Release identity gate: release ID `385886185`, tag `v0.1.26`, non-draft
  prerelease, target `main`; annotated tag object
  `322f279cea08fe49dd9a53e54ae9f984dda7020d` peels to exact Runtime main
  commit `bdcd05ba61063257ab429072f9aface917b078da`. The workflow requires the
  exact six asset names, API digests, and sizes recorded by the release, plus
  archive/checksum/signature downloads over HTTPS, exact checksum-file content,
  decoded protected-key hashes, and quiet detached Cosign verification before
  prepare or create can reach the deployment host. The existing
  `RUNTIME_RELEASE_PUBLIC_KEY_BASE64` secret is reused; raw signature, PEM,
  owner token, provider response bodies, and raw command failures never enter
  logs or outputs.
- Request and confirmation: the request allows only `planId`, `hostname`,
  `osName`, `sshPublicKey`, optional `locationName`, `expiresInHours`, `reason`,
  `maxMonthlyPriceUsd`, and the exact `runtimeArtifact` descriptor. Canonical
  JSON includes the SSH public key and full descriptor. The workflow computes
  the canonical request SHA-256 and exact OS-name SHA-256. The owner-supplied
  create confirmation is
  `CREATE-RUNTIME-ORDERING-CANARY:<hostname>:<os-name-sha256>:0.1.26:<archive-sha256>:<canonical-request-sha256>`.
  The prepare action creates or reuses only the hostname-bound deployment-host
  SSH identity and returns safe hashes plus that confirmation; it creates no
  task, payment, provider key, or compute. The create action never synthesizes
  or weakens the confirmation.
- Secure transport: prepare and create stay main-only in the protected
  `production` environment under non-cancelling `warpmetal-production`
  concurrency and exact-SHA checkout. Create writes the canonical envelope as
  a mode-`0600` regular non-symlink file beneath a unique owner-mode-`0700`
  deployment-host run directory, rechecks owner/type/mode/size/digest, and
  pipes it on stdin to the backend. Signature/key material never appears in
  argv or environment. An exact `always()` cleanup removes only that transient
  run directory after result capture; the durable hostname key and private
  redacted task-result record remain acceptance evidence.
- Atomicity and idempotency: both ordinary and ordering-canary create use the
  existing `operator-test-server` advisory-lock/idempotency namespace keyed by
  hostname so the two paths cannot race. The full canonical request digest is
  the replay discriminator. Under that lock, candidate create also rejects a
  pre-existing task hostname after replay expiry. One database transaction
  creates the `test_authorized/not_started` `PurchaseTask` with all five exact
  selector fields, enabled `pending_server` `ServerRuntime`, one exact sandbox,
  safe events, and encrypted owner-token replay record. A worker can observe
  none of them before commit and all of them after commit. Candidate selectors
  cannot be replaced or manually cleared through the historical P4 operator
  commands; cancellation and expiry retain their existing transactional
  cleanup behavior.
- Frozen negative oracles: any field, URL, version, archive/signature/key
  digest, canonical signature, request digest, confirmation, hostname/OS,
  release identity, asset membership, checksum, key, or Cosign mismatch fails
  before create. Injected transaction rollback leaves zero task, Runtime,
  sandbox, event, and idempotency rows. Identical concurrent creates yield one
  task and encrypted owner-token replay; drift conflicts. An injected worker
  claim during the uncommitted transaction sees nothing; after commit its
  bootstrap binds `0.1.26` and the exact archive digest before any provider
  mutation. Bomb provider mutators prove the operator action never invokes
  them. Public catalog support remains false and public/API/config source files
  remain byte-unchanged.
- Baseline evidence: focused Agent Runtime unit tests passed 142 tests; focused
  Ruff passed; the
  existing workflow parsed as YAML. `test_commerce_db.py` collected but skipped
  all 150 tests because no local `DATABASE_URL` was configured, so PostgreSQL
  migration/concurrency tests remain an unwaived implementation and CI gate.
- Frozen implementation gate: focused Runtime/operator/unit tests; PostgreSQL
  initial/replay/rollback/concurrency/worker-race tests; workflow behavioral
  tests for verification order, main-only controls, secure transport, failure
  short-circuit, and redaction; Ruff, compileall, actionlint and ShellCheck;
  migration-to-head; complete backend coverage gate; root lint/test; site build;
  Admin build/test; `git diff --check`; public/config scope-diff inspection;
  two independent final reviews; merge current frontend main again immediately
  before PR, stopping on conflict; exact-head and exact-merge CI.
- Review evidence: Kepler returned `APPROVE_FROZEN_S3_WORKFLOW` after verifying
  the release and protected workflow boundary. Leibniz returned
  `APPROVE_FROZEN_S3_BACKEND` after tracing task claim, Runtime bootstrap,
  schema reuse, and the atomic transaction. The manager resolved their
  idempotency-scope suggestions in favor of the shared existing scope because
  it uniquely prevents ordinary create and candidate create from authorizing
  the same hostname concurrently.
- Implementation authorized: yes for this bounded code, test, internal runbook,
  branch/PR, and CI work. No provider charge, protected workflow dispatch,
  production configuration mutation, deploy, public activation, or P4 VPS
  lifecycle action is authorized by this decision.
- Completion evidence: frontend implementation commit
  `48fd6c2615d8fa8bad3783e897bbd7ee0604515f` merged through PR #140 as
  `f9e84990928e1034915b11a633a07686f8c1b3fd`. Exact-head run
  `34420708151` passed; exact-main run `34421199832` passed test, image
  publication, and production deployment. Local complete backend regression
  passed 2,501 tests with one skip; coverage passed at 88.19% statements and
  75.28% branches; root build/tests passed 247 tests with zero failures.
  Actionlint, Ruff, compileall, YAML parsing, Admin gates, and diff checks
  passed. Independent final reviews approved the workflow digest/signature
  contract, backend authorization/idempotency boundary, and full integration.
- Recovery evidence: the manager corrected newline-bearing workflow JSON
  hashing, rejected ordinary request shapes before shared idempotency replay,
  and suppressed both protected backend stderr streams so provider response
  bodies cannot reach GitHub logs. Executable regressions cover all three
  findings. Post-deploy production catalog inspection still reports
  `agentRuntime.supported=false` for every product while the four advertised OS
  rows remain cloud-init/Runtime capable, and default-branch workflow source
  exposes both protected v0.1.26 actions.
- First live P3O.S4 recovery: exact release verification passed in protected
  prepare run `34426792761`, but the action failed before its transient remote
  marker, backend operator call, task write, or provider-capable path. Cleanup
  proved `directory=not_created`, so no VPS or charge was possible; at most the
  hostname-bound deployment-host keypair was created. Two independent reviews
  localized the failure to the first SSH identity block. A restrictive
  `umask 077` reproduces the missing contract: `ssh-keygen` safely creates both
  the private and public key files as mode `0600`, while the workflow required
  the public half to be exactly `0644`. Recovery is bounded to accepting public
  key mode `0600` or `0644` while retaining regular-file, non-symlink, owner,
  single-link, derivation, comment, and private-key-`0600` checks, plus an
  executable restrictive-umask identity test. Merge current frontend main
  before implementation and again immediately before PR; stop on any conflict,
  pass focused/full workflow gates and independent review, deploy exact main,
  then rerun prepare only. Create remains blocked until the prepare result is
  exact and the owner supplies its complete confirmation. Read-only preflight
  run `34427217782` independently proved the deployment/backend/provider read
  path healthy, Ubuntu 24.04 still eligible, location `OGB1`, and a live monthly
  provider quote of `$10.0`, within the separately authorized `$15` cap.
- Second live P3O.S4 recovery: PR `#141` merged the first identity-mode fix as
  frontend main `dd08151`; exact-head run `34428221628` and exact-main test,
  publication, and deployment run `34428717953` passed. Protected prepare run
  `34430416247` nevertheless failed before the same transient marker, again
  proving zero backend, task, worker, provider, or billable reachability. The
  first recovery modeled hardened `umask 077` (`0600`) and the conventional
  `022` result (`0644`) but omitted the common hardened `027` public-key result
  (`0640`). Do not guess through another live retry. Supersede the narrow mode
  oracle with exactly `0600`, `0640`, or `0644`, all on an owner-owned regular
  single-link public file paired with an exact private-`0600` key and matching
  derivation/comment. Add allowlisted identity-stage failure categories that
  suppress raw SSH/tool/path/key/UID/mode output, retain success stdout as only
  the canonical public record, and keep the transient marker after identity
  success. Validate existing `keys`/`tasks` children are real, non-symlink, and
  current-user-owned before normalizing only those owned child directories to
  `0700`; never chown, delete, replace, or repair key bytes. The executable
  matrix must cover `022`/`027`/`077`, directory creation/normalization and
  unsafe refusal, all key shape/metadata/derivation/comment failures, output
  pollution, exact redaction, and no marker/backend reachability on failure.
  Merge current frontend main before implementation and again immediately
  before PR, obtain independent security and behavioral approval, deploy exact
  main, and rerun prepare only once.
- Third live P3O.S4 recovery: PR `#142` merged the categorical identity guard
  as frontend main `f698eaa`; exact-head run `34431794627` and exact-main test,
  publication, and deployment run `34432284452` passed. The one bounded prepare
  run `34433993866` again stopped before the marker with the new safe category
  `key_derivation`, proving zero backend/task/provider/billing reachability. A
  post-run review found a real test-oracle defect: production compared raw
  `ssh-keygen -y` output with a stored public record normalized to two fields,
  while the test shim itself pre-normalized `-y` output. An implementation that
  preserves the comment in derived output therefore fails every valid pair even
  when key type and bytes match. Recovery must reuse the existing hostname and
  keypair, normalize both derived and stored records independently to exactly
  key type plus Base64 bytes, require each source record to be present and
  canonical, compare only those cryptographic fields, and retain the separate
  exact one-line outer comment check. Remove the masking normalization from the
  shim and add a sensitivity fixture where raw derived output includes the
  expected comment; a true mismatched key must still return only
  `key_derivation`. No second keypair, key-byte repair/removal, new hostname,
  task, provider action, or VPS is authorized. Merge current frontend main
  before implementation and immediately before PR, obtain two independent
  reviews, deploy exact main, then run one prepare-only reuse attempt.
- Fourth P3O.S4 recovery implementation checkpoint: frontend commit
  `f4db664797447cf01c579420e8df1480a9460ebc` replaces the asymmetric raw-versus-
  normalized comparison with independent single-record Ed25519 validation and
  type-plus-Base64 normalization of both derived and stored records. It retains
  the separate exact outer hostname-comment check, emits the stored public
  record unchanged, and does not repair or rewrite any key bytes. The test shim
  now passes default `ssh-keygen -y` output through unmodified; a real Linux
  Ed25519 key produced three fields and failed the legacy comparison while
  passing the corrected comparison. Comment-bearing success, cryptographic
  mismatch, multiline refusal, redacted `key_derivation`, no marker/backend
  reachability, and byte preservation all passed in the focused Linux harness.
  The local complete frontend gate passed 252 tests (211 pass, 41 expected
  skips, zero failures); Actionlint, YAML parsing, and diff checks passed. Two
  independent reviewers approved the exact two-file diff with no material
  bounded-recovery finding. PR, exact-head CI, exact-main deployment, and the
  single prepare-only reuse attempt remain pending. Merge current frontend main
  again immediately before the PR and stop on any conflict.
- Fourth live P3O.S4 recovery result: PR `#143` merged the independently
  approved correction as frontend main
  `8c409668695ae3992a1ae131cd0b4dc4bbdbfffa`. Exact-head run
  `34476709621` and exact-main test, publication, and deployment run
  `34477400653` passed. Protected prepare run `34480024931` then passed the
  complete SSH identity stage and created only its transient request directory,
  but stopped in the second deployment-host SSH wrapper with
  `bash: line 7: $6: unbound variable`. OpenSSH did not preserve the empty
  prepare confirmation as a positional argument, shifting the following
  request and transport digests left. The failure occurred before request-file
  shape/hash validation, deployment locking, backend operator invocation,
  task creation, worker/provider reachability, or billing. Cleanup returned
  `runtime_ordering_canary_request_cleanup directory=removed`; therefore no
  task, server, VPS, provider mutation, or charge occurred and no transient
  request directory remains. The key-derivation correction is verified by
  progression beyond its former failure point. The plan's single live retry is
  consumed. P3O.S4 is blocked pending a newly reviewed argument-transport
  recovery decision and explicit authority for any further protected prepare
  attempt; do not guess, dispatch, or order around this gate.
- Fifth P3O.S4 recovery decision: three independent read-only audits of exact
  frontend main `8c409668695ae3992a1ae131cd0b4dc4bbdbfffa` returned
  `GO_ONLY_TRANSPORT_FIX`. They traced the complete request construction,
  raw-file and canonical-JSON digest contracts, exact Runtime v0.1.26 tuple,
  one-small-sandbox capacity, backend prepare/create branches, response
  validation, and cleanup. No additional deterministic source defect or
  backend, Runtime-release, image, catalog, API, or public-document change was
  found. The sole blocker is OpenSSH's shell reparse dropping the empty prepare
  confirmation argument. Recovery must carry an exact nonempty tagged prepare
  sentinel, require exactly six remote arguments before dereference, validate
  the action/hostname/digest/wire-value grammar, translate the sentinel to an
  empty backend confirmation only for prepare, and preserve the exact nonempty
  create confirmation byte-for-byte. Cross-mode or malformed values must fail
  before request inspection, locking, or backend invocation. A new executable
  harness must model OpenSSH's joined remote-command serialization and prove
  prepare/create routing, digest preservation, fail-closed malformed inputs,
  redaction, zero backend reachability on rejection, and exact transient
  cleanup. The owner's 2026-09-10 instruction `ok fix it` authorizes this
  bounded workflow/test correction, branch commit, review, and PR preparation.
  It does not authorize another protected prepare dispatch, provider mutation,
  billable create, production configuration change, or public activation.
  Frontend and Runtime-plan branches were merged with their current mains
  before implementation; both completed without conflict.
- Fifth P3O.S4 recovery implementation checkpoint: frontend commit
  `5c077788de8ef484623e857b3eeb31205beb3b69` transports the exact nonempty
  prepare sentinel, preserves the create confirmation, validates all six
  shell-safe remote fields before dereference or request access, and makes the
  existing request metadata/digest refusals explicit. The extracted production
  stage now runs through a dedicated SSH join-and-remote-shell-reparse harness
  for both actions. It rejects empty/shifted/extra argv, cross-mode values,
  invalid action/hostname/hash grammar, raw and canonical hash drift, and
  invalid JSON before backend reachability; a corrupted-copy case retains the
  exact `directory=removed` cleanup result. Local focused tests passed 13/13;
  the same focused suite passed 13/13 in the signed Linux amd64 all-tools image;
  the complete frontend gate passed 255 tests (214 pass, 41 expected platform
  skips, zero failures); backend Agent Runtime units passed 147/147; Actionlint,
  YAML parsing, lint with zero errors and five pre-existing warnings, scope,
  and diff checks passed. Independent reviewers returned
  `APPROVE_TRANSPORT_FIX` and `APPROVE_TRANSPORT_INTEGRATION`, finding no
  backend, Runtime, catalog, API, documentation, configuration, or public-
  surface drift. Frontend main was fetched and merged again immediately before
  PR with no conflict. PR `#144` exact-head run `34485998166` passed, and the
  PR merged as `aa3957aa4448179ea2a6e841d4a74ce81803482a`.
- Fifth P3O.S4 recovery deployment checkpoint: merged-main workflow run
  `34486809861` completed successfully for exact head
  `aa3957aa4448179ea2a6e841d4a74ce81803482a`: test, image publication, and
  production blue-green deploy all passed. A read-only post-deploy probe
  returned healthy purchasing dependencies. The public catalog intentionally
  remains fail closed at `agentRuntime.supported=false` and minimum supervisor
  `0.1.25`, while all four OS entries still report `cloudInit=true` and
  `agentRuntimeSupported=true`; this source-only recovery neither activates
  ordering nor changes the signed release/configuration tuple. The protected
  live prepare remains unexecuted and separately gated.
- Fifth P3O.S4 protected prepare authority: the owner's 2026-09-10 instruction
  `ok do it`, immediately after the exact prepare-only scope was restated,
  authorizes one dispatch from exact frontend main
  `aa3957aa4448179ea2a6e841d4a74ce81803482a` with action
  `prepare-runtime-ordering-canary`, plan `standard`, existing hostname and
  identity `runtime-126-ubuntu-0910-a`, exact OS `Ubuntu 24.04 (VPS)`, location
  `OGB1`, six-hour acceptance lifetime, and maximum monthly price `$15`.
  WarpMetal CLI `0.8.8` reports purchasing ready; the fresh Standard catalog
  reports `$15`, cloud-init and per-OS Runtime eligibility true for Ubuntu, and
  aggregate Runtime support still false. This prepare is non-billable and may
  create or reuse only the deployment-host identity plus its self-cleaning
  transient request directory; it cannot create a task, provider key, server,
  VPS, payment, or charge. Dispatch exactly once and stop on any failure or
  ambiguity. Billable create, payment, provider mutation, production Runtime
  tuple activation, and public ordering remain outside this authority.
- Fifth P3O.S4 protected prepare result: exact-main run `34490369337` passed
  request validation, signed Runtime v0.1.26 verification, deployment-host SSH
  identity reuse, nonempty-sentinel transport, exactly-six-argument validation,
  request file metadata and raw transport digest verification. It then failed
  at the remote canonical digest check with `jq: command not found`, before the
  deployment lock, active-backend resolution, backend operator invocation,
  task/provider reachability, payment, or billing. Cleanup returned exact
  `runtime_ordering_canary_request_cleanup directory=removed`; no transient
  request directory remains and no task, provider key, server, VPS, payment, or
  charge was created. The transport correction is thereby live-proved, but the
  focused harness masked an undeclared host dependency by always supplying
  `jq`. Do not patch and retry one command at a time. Before another deploy,
  enumerate every executable used by both remote wrappers, compare it with the
  deployment-host prerequisite contract, remove avoidable dependencies, add a
  fail-closed prerequisite gate for all remaining dependencies, and execute the
  extracted production path on Linux with a deliberately minimal remote PATH.
  Require independent source, host-contract, and test-oracle approval. This
  prepare authority is consumed; another live dispatch remains separately
  gated after the comprehensive recovery is merged and deployed.
- Sixth P3O.S4 recovery decision: three independent read-only reviews returned
  `APPROVE_FIX_DIRECTION`. The exact remote command inventory is SSH/SFTP and
  Bash; GNU `stat`, `id`, `install`, `cat`, `sha256sum`, `cut`, `rm`, and
  `rmdir`; `ssh-keygen`; `awk`; `flock`; Docker with Compose v2; `python3`; and
  the deployed executable `resolve-active-service.sh`, whose own dependencies
  are `/usr/bin/env`, `grep`, and `sed`. Live run `34490369337` plus its cleanup
  proved every command through raw-digest verification. Exact-main production
  deployment independently proves `flock`, Python, Docker/Compose v2, and the
  resolver/active-backend path. `jq` alone is undeclared and absent. This
  matches the earlier blue-green host contract in
  `PUBLIC_BLUE_GREEN_DEPLOYMENT_PLAN.md`, which deliberately replaced host
  `jq` with Python stdlib after live preflight evidence.
- The comprehensive source recovery must keep runner-side `jq`, replace only
  the remote canonical digest operation with Python's exact backend byte
  contract (`json.dumps` with sorted keys, compact separators, UTF-8, and
  `ensure_ascii=False`, then SHA-256), and compare without emitting request
  contents. It must add one early, fixed-category, fail-closed prerequisite and
  capability gate for every remaining remote executable, Compose v2, and the
  deployed resolver before creating the transient request directory or
  reaching the backend. The extracted production harness must run on Linux
  with an intentionally minimal remote PATH that contains no `jq`; prove both
  actions, Unicode canonical parity, all accepted OS/lifetime/location shapes,
  malformed JSON and digest drift, each missing prerequisite, zero backend
  reachability, redaction, and exact cleanup. Update the protected-operator
  runbook; no backend, Runtime release, public API/catalog/configuration, public
  documentation, VPS, payment, or x402 change is in scope. Merge frontend main
  again immediately before PR and deploy only after the complete focused,
  minimal-Linux, backend, and regression command gates pass. Another live
  prepare retry remains separately gated.
- Sixth P3O.S4 recovery implementation checkpoint: frontend commit
  `9affe92a55c47a9bb76ebcbbee00813d1e5c706e` removes remote `jq`, preserves
  runner-side request construction, computes the remote canonical digest with
  the backend's exact Python stdlib byte contract, and adds one redacted host-
  contract preflight before identity or request-directory creation. The gate
  checks the complete declared executable set, `/usr/bin/env`, Compose major
  version 2 or later, regular readable `deployment.env`, and the regular
  executable resolver's exact active-backend output. The internal runbook now
  documents this boundary and SSH/SFTP separately. The extracted production
  harness uses only its explicit remote command directory, contains no `jq`,
  and separately proves a poisoned `jq` is never invoked. Executable cases
  remove every declared command individually; reject Compose failure, v1, and
  malformed versions; reject resolver execution/output/file-shape failures;
  reject deployment-file shape failures and SCP failure; and prove zero lock
  or backend reachability plus exact cleanup. Both actions, all four supported
  OS names, one- and 24-hour bounds, absent/ASCII/Unicode location forms,
  OpenSSH join/reparse, digest drift, invalid JSON, confirmation handling, and
  redaction remain covered. Manager reruns passed focused 19/19 locally and
  19/19 in the signed Linux amd64 all-tools image, full frontend 261 tests
  (220 pass, 41 expected platform skips, zero failures), backend Agent Runtime
  147/147, Actionlint, YAML parsing, Node syntax, diff checks, and lint with
  zero errors/five pre-existing warnings. Per the owner's direction, this
  recovery gate is based on executable tests rather than another prose-only
  subagent code-review round. No live action or persistent disposable resource
  was created. The local official WarpMetal CLI was separately upgraded from
  0.8.8 to 0.8.9; its next health read reported public
  `purchasingReady=false` because `x402Readiness=false`, so no public purchase
  or payment flow may start until that independent readiness condition clears.
- Sixth P3O.S4 recovery merge and deployment checkpoint: PR `#145` exact-head
  workflow run `34494506040` passed the complete test job for frontend commit
  `9affe92a55c47a9bb76ebcbbee00813d1e5c706e`; its publish and deploy jobs were
  correctly skipped for the pull request. GitHub reported the PR clean and
  mergeable, and it merged to main as
  `a704a87ec8bf081d42e6bc1427aec1e7507bfd30`. Exact-main workflow run
  `34495562909` then passed test, immutable image publication, production
  blue-green service deployment, admin promotion, and the bounded production
  x402-header probe. A post-deploy read-only check with official WarpMetal CLI
  `0.8.9` returned service `ok`, every dependency true, and
  `purchasingReady=true`. The refreshed catalog intentionally remains fail
  closed at product-level `agentRuntime.supported=false`, while all four OS
  entries retain `cloudInit=true` and `agentRuntimeSupported=true`; minimum
  supervisor version remains `0.1.25`. No prepare, task, provider key, VPS,
  payment, or charge was created by this recovery deployment. The previous
  one-shot prepare authority remains consumed; a new explicit prepare-only
  authorization is required before the protected internal no-customer-payment
  acceptance flow is retried.
- Seventh P3O.S4 protected prepare authority: the owner's 2026-09-10 instruction
  `ok do it`, given immediately after the manager stated that a fresh explicit
  authorization was required, authorizes exactly one protected
  `prepare-runtime-ordering-canary` retry from deployed frontend main
  `a704a87ec8bf081d42e6bc1427aec1e7507bfd30`. The fixed request remains plan
  `standard`, hostname/identity `runtime-126-ubuntu-0910-a`, exact OS
  `Ubuntu 24.04 (VPS)`, location `OGB1`, six-hour acceptance lifetime, and
  maximum monthly price `$15`. The prepare is non-billable and cannot create a
  task, provider key, server, VPS, payment, or charge. Dispatch once after a
  fresh CLI/health/catalog/default-branch gate and stop on any failure or
  ambiguity. Candidate create and all provider/billing mutation remain outside
  this authority and require a separate confirmation derived from a successful
  prepare result.
- Seventh P3O.S4 protected prepare result: exact deployed-main workflow run
  `34499126005` completed successfully for head
  `a704a87ec8bf081d42e6bc1427aec1e7507bfd30`. It verified the immutable signed
  Runtime v0.1.26 release, passed the complete deployment-host prerequisite
  contract, reused the exact hostname-bound identity, validated the canonical
  request, and returned status `runtime_ordering_canary_prepared` with request
  SHA-256
  `e5c9da200d13441c5ae8c6431147ccdeb8488c156c7c8fe9f91e85e21aebcfc9`.
  Its exact create confirmation is
  `CREATE-RUNTIME-ORDERING-CANARY:runtime-126-ubuntu-0910-a:7ac8e2d7722f32c7314c09fc162e681e87d4854eb2223633c2b6d9be5087598e:0.1.26:f4b1fd76f67cc01385a1309eaf38e2aaca5b5eb90254df1b0549a02a45040791:e5c9da200d13441c5ae8c6431147ccdeb8488c156c7c8fe9f91e85e21aebcfc9`.
  Cleanup returned exact `directory=removed`, and the workflow's monthly-create
  step was skipped. No task, provider key, server, VPS, payment, or charge was
  created. A post-run read-only probe returned service `ok`, every dependency
  true, `purchasingReady=true`, Standard `$15`, Ubuntu cloud-init and per-OS
  Runtime eligibility true, and aggregate public Runtime support still false.
  This one-shot prepare authority is consumed. Executing the confirmation will
  atomically create a real internal `test_authorized` provider task and may
  order one real Standard Ubuntu VPS without a customer x402 payment; it
  remains separately gated by explicit owner authority.
- Resource ledger addition: manager-created local file
  `/tmp/runtime-prepare-run-34499126005.json` contains only safe GitHub run
  metadata, is not used by the workflow or product, and is a later cleanup
  candidate. Retain it until project completion and the separately confirmed
  cleanup phase.

### Live acceptance phase P4 header

- Phase ID and outcome: P4, prove on one disposable amd64 Ubuntu 24.04 VPS that
  the signed Runtime can move through `sensitivity -> candidate -> rollback ->
  forward -> disable` while preserving host workloads and restoring the exact
  pre-enable AppArmor state.
- Covered requirement and assumption IDs: R1-R6, R10-R11, R13-R14; A1-A4,
  A6, A8, A10, A13.
- Entry criteria: P3 is complete; the signed Runtime v0.1.24 baseline, signed
  v0.1.25 prerelease, npm CLI 0.8.7, pinned amd64 sandbox image, and deployed
  workflow are immutable and independently verified. A read-only live preflight
  must report purchasing readiness, current `agent` plan inventory, exact OS
  name, and monthly price before any key or server mutation.
- Exit criteria: the operator creates exactly one monthly acceptance VPS with a
  six-hour durable test expiry and three medium Runtime sandboxes; the VPS host
  key is learned exactly once through the protected owner-key-authenticated TOFU
  path, atomically pinned, and strictly reverified before bootstrap; all five
  stages pass in order with exact artifact pins and host snapshots; each stage's
  temporary small sandbox, two distinct access keys/grants, sessions, and
  workspace are revoked/deleted; final policy state equals the frozen initial
  absent state; the acceptance task reaches terminal cancellation with
  unambiguous future-billing cancellation. Provider compute may remain through
  the already-created paid term and is reconciled without treating that expected
  retention as a failed cancellation or a reason to retry.
- Dependencies and risks: production operator credentials and environment
  approval; live `agent` plan availability and current price; exact
  `Ubuntu 24.04 (VPS)` catalog name; monthly billing may not be prorated or
  refunded by early cancellation; owner and per-sandbox SSH key generation;
  accepted first-connection TOFU risk and strict later host-key continuity;
  Runtime installation and explicit host-policy mutation; one-hour temporary workspace expiry is
  irreversible and does not replace explicit cleanup; cancellation may enter
  manual review and must not be retried as though compute were absent.
- Baseline test state: P3 exact-head release, source, hosted CI, production
  deploy, and live public-document gates are green. P4.R1 is merged and
  deployed from frontend merge commit
  `6da3f0ab35eab8136ecfa11c88ccdd2a1d79003d`; its exact-head and
  default-branch gates are green. P4.R2 is merged and deployed from frontend
  merge commit `ae64f8539450b78fe68214c87b8cc31c94f03ba8`; PR exact-head CI,
  main tests/publication/deployment, an independent merge-tree audit, and a
  fresh deployed-main read-only task inspection are green but its provider-
  console-first assumption is superseded by P4.R3. The sole approved P4 test
  task is now terminally cancelled after proving live TOFU and strict replay.
  Runtime remained `pending_install`, desired/applied revision remained `1/0`,
  the failed-run selector and guarded deployment-host directory are cleared,
  and no second server, payment retry, Runtime installation, sandbox, policy,
  or grant mutation exists. Provider compute may remain powered through the
  already-created term under the verified cancellation contract. The last live
  inspection found it powered `ON`, while the six-hour operator authorization
  and capped control-plane term have since expired. Local official CLI 0.8.8 is
  installed, but the acceptance owner identity and recovery credential remain
  correctly isolated on the protected deployment host.
- Required documentation and API-contract changes: this plan records the quote,
  confirmation, task/server IDs, stage runs, bounded safe evidence, cleanup,
  and residuals. CLI 0.8.8 help/README/skill references and the public Runtime,
  docs, localized message, canonical `llms.txt`, and backend LLM mirror surfaces
  must explain managed first-use trust, strict later matching, reload epochs,
  optional console pre-seeding, and the first-connection MITM residual. No
  Runtime HTTP/JSON schema change is planned.
- Coordinating owner: primary managed-plan executor. The deployed production
  workflow is the only mutation path; a separate non-implementing verifier
  reviews exact run evidence before promotion.
- Fresh recovery reviewer available: yes; two non-implementing reviewers
  approved P4.R1 independently, two separate security/contract reviewers
  approved P4.R2 before integration, and a fresh verifier approved its exact
  merge and deployed-main evidence. Fresh CLI and protected-canary security
  reviewers are required for P4.R3, and a fresh non-implementing verifier will
  review the live P4 evidence after all mutations stop.

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
| P4.A3 | A trusted provider or console channel is available to enroll the exact new VPS host key before the private-procfs workflow opens SSH | operator runbook, deployment-host pin contract, and Hivelocity's authenticated one-time VPS console | false as a required ordinary-user dependency: the console exists but users will not have Hivelocity access | replace the mandatory console gate with exact-task owner-authenticated first-use trust; retain console enrollment only as an optional stronger pre-seed |
| P4.A4 | The five canary stages can select their signed Runtime artifact without changing the process-global production `RUNTIME_*` tuple | P4.R1 task-scoped selector, bootstrap version/digest binding, registration mismatch rejection, DB constraint, and ordinary-user regression coverage | resolved in P4.R1 | use only operator-set exact signed selectors on live `is_test` tasks; clear on completion, expiry, and cancellation |
| P4.A5 | Order-time three-sandbox intent yields a ready v0.1.24 supervisor and running baseline sandboxes before sensitivity starts | P4.R1 trusted-host preparation and root/non-root replay harness | resolved in P4.R1 | sensitivity must run the replay-safe signed-v0.1.24 preparation and require exactly three running medium sandboxes before freezing the baseline |
| P4.A6 | An arbitrary owner-supplied existing VPS can replace the disposable production acceptance task | production workflow, operator task/selector checks, bootstrap/registration binding, canary checkpoint, and cancellation contract | false | an external VPS may support a separately authorized non-gating host inspection, but P4.S1-P4.S3 still require a provisioned live `is_test` task unless a new adoption contract is designed and reviewed |
| P4.A7 | An existing operator path can place console-authenticated public host keys into the protected deployment-host pin without direct deployment-host SSH | deployed P4.R2 protected workflow, enrollment script, contract tests, and independent reviews | resolved in P4.R2 | use only the exact task/hostname/device-bound protected enrollment action; never accept a console URL, credential, fingerprint-only value, or network scan as the key source |
| P4.A8 | The official CLI already supports a self-contained first-use host-key path for a fresh VPS | agent-kit 0.8.7 source audit of login, install, SSH/SCP, and canary pin mounting | false: login is API-only and install is strict against ambient `~/.ssh/known_hosts` | add managed server-ID/trust-epoch TOFU in CLI 0.8.8; the frozen 0.8.7 canary may use the protected P4.R3 pin mounted into the CLI container |
| P4.A9 | The same cancelled acceptance task can resume immediately because provider compute remains powered | source audit plus post-cancel run `34198926210` | false for direct use; recoverable without a new VPS | backend and drivers accept `cancelled` only with an active control-plane term; add P4.R4 to extend this exact expired test/term deadline once after revalidating provider compute and the existing strict owner-key pin |
| P4.A10 | The TOFU-established protected pin still exists after cancellation, guarded cleanup, and later production deployments | protected diagnostic run `34255110640` | false: exact task/provider binding passed but the task-derived pin path classified `missing` | stop P4 before SSH or lease mutation; no TOFU rerun, reset, replacement, or repair is authorized for missing trust state |
| P4.A11 | The exact original host fingerprint or canonical pin digest can be recovered from immutable safe evidence and used to prove continuity without another first-contact decision | successful TOFU run `34198472527`, its retained job log/check output/artifact inventory, Runtime state, and diagnostic run `34255110640` | false: the step success is immutable but no fingerprint/digest was retained; Runtime remained uninstalled and the protected pin is missing | do not infer or claim restoration; P4.R6 may consume one explicitly authorized second trust event for only this exact canary, with durable pre-SSH reservation and fail-closed incomplete replay |

### Live acceptance phase P4 entry-gate decision

- Implementation authorized: the read-only preflight and repository recovery
  are completed. After the owner chose a new disposable VPS instead of the
  offered existing host, the owner explicitly approved the previously
  disclosed full live lifecycle. Exactly one test VPS and its protected owner
  SSH identity were created within the `$15.00` monthly provider-cost ceiling.
  The same approval covers the guarded Runtime installation, sandbox-specific
  keys, temporary sandbox expiry/deletion, policy enable/disable, grants and
  revocation, and final server cancellation. Each later mutation remains
  conditional on its frozen state and trust oracle; no retry is authorized on
  an ambiguous result.
- Authorization state: the one-VPS authorization was exercised and future
  billing was terminally cancelled. The owner subsequently directed continued
  testing on that same still-live VPS and authorized required software upgrades.
  This authorizes the bounded P4.R4 continuation and previously disclosed
  Runtime/sandbox/policy canary on the same device. After P4.R5 proved the pin
  missing and the owner was told that continuation required a separately
  designed and reviewed second first-contact trust event, the owner said
  `continue`; that authorizes only P4.R6's exact one-shot recovery for this task
  and provider device. It does not authorize a new order, payment, renewal,
  provider reactivation, replacement VPS, generic host-key reset, ordinary-user
  reset option, or direct/ad-hoc host mutation.
- Replacement-trust authorization: after P4.R7 proved the consumed P4.R6
  candidate durably empty, the owner answered `Yes run it on VPs` to the
  explicit choice of authorizing a separately designed new first-contact trust
  event on the same VPS. This authorizes P4.R8 implementation and one protected
  live replacement dispatch for only the frozen task/device. It does not
  authorize rerunning P4.R6 or generic TOFU, more than one post-claim
  `accept-new`, a new VPS/order/payment/renewal, provider power/reload,
  lease/Runtime/sandbox/grant/policy mutation, or weakening strict replay.
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
  environment to deployment host, exact control-plane task/server/IP binding,
  owner-key-only harmless first SSH, atomic host pin, strict later SSH, and
  distinct sandbox-specific grants remain mandatory. Provider-console
  enrollment remains optional and higher assurance.
- Documentation/API requirements reviewed: yes; the public Runtime bootstrap
  request and response remain unchanged. P4.R1 adds only nullable internal test
  metadata, protected operator commands, and deployment-runbook coverage. Any
  live discrepancy reopens P2/P3 instead of editing the oracle to pass.
- Decision timestamp or plan revision: 2026-09-08, release revision 23.

### Live acceptance phase P4 subparts

| Subpart | Deliverable and owner boundary | Dependencies | Interfaces / likely files | Documentation / API impact | Acceptance and oracle | Focused + regression checks | Parallel-safe | Status |
|---|---|---|---|---|---|---|---|---|
| P4.S0 | Read-only current quote and readiness packet | P3 | production operator `action=preflight`, plan `agent` | plan evidence only | current purchasing readiness, exact OS, capacity, and monthly price; no key/order/resource mutation | inspect exact workflow run/logs and absence of create step | no | completed |
| P4.R1 | Recover task-scoped signed artifact selection and establish a stable baseline-preparation path | P4.S0, false P4.A4-P4.A5 | backend Runtime/operator state and migration; acceptance workflow/driver/tests/runbook | internal operator contract and recovery docs; public bootstrap/OpenAPI stay unchanged | only live `is_test` tasks may receive an exact verified override; normal users retain global metadata; stage changes use fresh checkpoint-bound bootstrap keys while prior idempotent responses remain immutable; registration must report the selected version; sensitivity prepares v0.1.24 with `preserve`, nine Docker sentinels, and exactly three running medium sandboxes through trusted SSH | backend unit/DB/operator/security tests, canary contract tests, full frontend/backend gates, migration upgrade/downgrade, independent review, exact-head CI/deploy | no | completed; merged, deployed, and independently approved |
| P4.R2 | Recover a protected deployment-host enrollment path for console-authenticated host keys | P4.R1, partially resolved P4.A3, false P4.A7 | acceptance workflow/tests/runbook only | internal operator workflow; public API and ordinary-user behavior unchanged | accept one console-copied OpenSSH public host key for the exact live test task/hostname; derive and verify current IP/task state on the deployment host; atomically create the non-symlink mode-0600 pin under a mode-0700 directory; byte-identical replay succeeds and every mismatch refuses overwrite; log only fingerprint and file digest | workflow contract tests, shell syntax, exact-head CI/deploy, independent review | no | completed; PR #108 exact head, merge tree, default-branch deployment, fresh task inspection, and three independent reviews approved |
| P4.R3 | Replace mandatory provider-console trust with safe first-use trust for the protected canary and ordinary CLI users | false P4.A3/P4.A8, completed P4.R2 | agent-kit host-trust/state/installer/CLI/tests/docs first; frontend protected workflow/driver/tests/operator and public docs last | CLI 0.8.8 plus public human/LLM trust contract; no Runtime HTTP schema | first harmless owner-key SSH for an exact server trust epoch may accept only Ed25519 into an isolated candidate; atomic no-overwrite pin precedes bootstrap; immediate and all later SSH is strict; existing mismatch and unauthorized epoch change fail closed; optional console pre-seed remains | local two-host-key SSH integration, filesystem/race/error tests, agent-kit full gate and release, frontend focused/full gates, two fresh security reviews, exact-head CI/deploy | no | completed at revision 19; PR #110 deployed and protected live TOFU plus immediate strict replay passed on the sole acceptance VPS |
| P4.R4 | Reauthorize the exact cancelled-but-provider-live acceptance task without reopening billing | false P4.A9, completed cleanup recovery, owner same-VPS direction | backend operator/service plus protected acceptance workflow/helper/tests/runbook; existing task/server/device/key/pin only | internal operator contract and recovery docs; no public API/schema or ordinary-user behavior change | exact fixed UTC deadline; current cancelled test, prior successful cancellation, provider `ON` and exact bindings, selector null, pending-install revision `1/0` and three intended medium sandboxes, protected task record, owner identity, existing pin, and strict SSH all pass before atomically setting only `test_expires_at` and `term_ends_at`; exact replay succeeds, different extension is forever refused; final cancel replay closes access | backend DB/provider tests, executable helper failure matrix, workflow contract tests, full frontend/backend gate, independent security review, exact-head CI/deploy, protected live inspect/extend/replay | no | deployed; first live extension failed closed on existing-pin validation before SSH/operator mutation, and bounded recovery is active |
| P4.R5 | Diagnose protected acceptance-pin drift without changing trust state | failed P4.R4 live attempt and independently closed mutation ambiguity | protected exact task/server/hostname/device-bound workflow/helper plus focused tests/runbook | internal operator diagnostic only; no public API, CLI, LLM, Runtime, image, or ordinary-user behavior change | under the production and deployment locks, revalidate the exact task/provider binding and report only safe pin predicate classifications from no-follow descriptor metadata/canonical validation; never print key bytes/path, perform SSH/TOFU/enrollment, change pin metadata/content/inode, or call a mutation operator | behavioral classification/TOCTOU/security tests, Bash/ShellCheck/actionlint, full gates, independent review, exact-head CI/deploy, one protected diagnostic run | no | completed and independently approved; exact live result `missing` blocks P4 under the frozen trust contract |
| P4.R6 | Consume one incident-bound same-VPS re-trust after the protected pin was proven missing | false P4.A10-P4.A11, completed P4.R5, explicit owner continuation | internal backend reservation/completion events; protected acceptance workflow/helper/tests/runbook; exact existing task/server/device/key only | internal canary recovery and operator runbook only; no public API, CLI, LLM, Runtime, image, or ordinary-user behavior change | exact task/server/hostname/device and original-trust/diagnostic run IDs; missing pin and unchanged cancelled/provider-ON/pending-install/three-sandbox baseline; durable unique reservation before network contact; at most one owner-key Ed25519 `true` observation; incomplete replay uses only the exact persisted candidate/pin or fails permanently; atomic no-overwrite publication, immediate strict replay, safe completion event; no lease/lifecycle/provider/payment mutation | backend uniqueness/concurrency/provider tests, executable crash-boundary and two-key matrix, workflow contract tests, full frontend/backend gate, two independent security reviews, exact-head CI/deploy, protected live recovery and strict replay | no | blocked and permanently exhausted under its frozen authority: the one authorized first-contact run failed before durable host-key capture, its claim remains consumed, strict replay is ineligible, and no retry is permitted |
| P4.R7 | Classify the consumed recovery state without network contact or mutation | failed-closed P4.R6 run and unchanged post-run baseline | one exact protected workflow/helper using the existing backend recovery inspector and deployment-host recovery files | internal operator runbook only; no public API, CLI, LLM, Runtime, image, or ordinary-user behavior change | hard-bind failed run `34285138720`; require exact claimed backend state, attempted journal, absent journal residue, stable missing final pin, and descriptor-stable candidate classification; report only whether no durable host key was captured, a canonical Ed25519 key was captured, or state is ambiguous/exhausted | workflow/helper contract, backend binding matrix, filesystem/type/mode/owner/link/swap matrix, Linux no-listener and rejected-auth fixtures, zero-mutation snapshots, Python 3.8/Bash/ShellCheck/actionlint/full frontend gates, two independent reviews, exact-head CI/deploy, one protected read-only run | no | completed; PR #126 exact-head CI and deployed main passed, live run `34293354294` classified `pre_durable_host_key_capture` with strict replay ineligible, and post-run inspect `34293421043` proved zero task/provider/Runtime/payment drift |
| P4.R8 | Replace the proven-pre-capture exhausted claim with one globally one-off same-VPS trust event | completed P4.R7, verified owner authorization, A14, and one exact completed listener recovery from a separately reviewed post-P4.R14 recovery phase | dedicated append-only backend claim/completion events and migration; separate descriptor-bound deployment-host state; protected workflow/helper/tests/runbook; exact existing task/server/device/key only | internal canary recovery and operator runbook only; no public API, CLI, LLM, Runtime, image, or ordinary-user recovery behavior | hard-bind the full P4.R6/P4.R7 evidence chain and one independently reviewed listener-recovery proof; preserve old backend/filesystem state; two bounded SSH banners before state; globally one-off claim committed before exactly one Ed25519-only owner-key `accept-new true`; durable candidate/pin publication, immediate strict replay, safe completion; preclaim readiness failure consumes nothing, any post-claim empty/ambiguous state is terminal, canonical state is strict-only | global uniqueness/concurrency/migration/provider tests; focused FIFO, lock, durability, banner, crash, strict-replay, and old-state invariants; existing P4.R6 real-OpenSSH evidence; Python 3.8/Bash/ShellCheck/actionlint/full gates; two independent reviews; exact-head CI/deploy; one protected live end-to-end run | no | blocked pending a separately frozen, reviewed, completed listener-recovery phase and new explicit live-attempt authority; P4.R14 is complete, P4.R9/P4.R11/P4.R13 are terminally unavailable, and every old journal must remain unchanged |
| P4.R9 | Reconcile the one ambiguous acceptance-host reboot response without another provider mutation | authorized guarded reboot run `34313748796`, unchanged post-run baseline, live journal `1/0/0` | incident-bound backend provider lookup/operator event recovery plus protected workflow/tests/runbook; exact existing task/server/device and reboot time window only | internal canary recovery and operator runbook only; no public API, CLI, LLM, Runtime, image, ordinary-user behavior, or reusable provider-task recovery | query only the provider's read-only numeric/latest-task and exact-UUID surfaces; require two stable newest-task reads plus exact UUID corroboration for the owned device, `reboot_vm` metadata, frozen creation interval, and terminal success; bind `force=true` causally to the durable one-shot claim and exact deployed caller; append the existing provider-accepted and completion evidence idempotently; issue zero provider POSTs and preserve every lifecycle field; missing, unstable, mismatched, failed, nonterminal, or malformed evidence stops | provider mutation spy; malformed/unstable/mismatch/time/action/device/client/terminal-state matrices; concurrency/idempotency; exact journal transition tests; full frontend/backend gates; two independent reviews; exact-head CI/deploy; one protected live reconcile and fresh inspect | no | terminally unavailable under the frozen oracle: P4.R10 found no matching provider reboot task, and journal state remains claim-only; do not retry |
| P4.R10 | Classify the rejected live provider task without exposing provider data or changing state | exhausted P4.R9 live attempt, journal `1/0/0`, two independent recovery reviews | one incident-bound backend diagnostic plus protected workflow/tests/runbook; exact existing task/server/device only | internal canary diagnosis only; no public API, UI, CLI, LLM, Runtime, image, ordinary-user behavior, or reusable diagnostic | replay up to the same three ordered provider GETs (numeric device, exact UUID when the first UUID is canonical, numeric device) after proving the exact claim-only journal and unchanged recovery baseline; emit only per-stage allowlisted predicate categories plus task/projection stability classes for response shape, UUID, device, positive client, metadata, creation window, update ordering, and result class; never emit raw UUID/client/metadata/timestamps/provider error; issue zero provider mutations and zero database/event/lifecycle/trust writes | provider mutation/write spies; full malformed/category/redaction/binding/stage/stability matrix; workflow main/exact-input contract; focused/full regressions; two independent reviews; merge current main before PR; exact-head CI/deploy; one protected live diagnosis | no | completed: deployed main run `34332349353` found one stable older metadata-mismatched task across all three reads, with no provider or local mutation |
| P4.R11 | Establish a fresh auditable OFF-to-ON listener recovery after Hivelocity lost the original reboot task | completed P4.R10, exact reboot journal `1/0/0`, explicit owner shutdown/boot approval | incident-bound provider VPS stop/start adapters; separate append-only shutdown and boot journals plus migration; protected workflow/tests/runbook; exact existing task/server/device only | internal canary recovery only; no public API, UI, CLI, LLM, Runtime, image, ordinary-user behavior, or reusable power-cycle feature | preserve the old reboot journal and P4.R8 state; claim before one forced stop POST, validate/persist/poll only its exact `stop_vm` task to terminal success and compute OFF; then claim before one start POST, validate/persist/poll only its newer exact `start_vm` task to terminal success, compute ON, and two zero-write SSH banners; claim-only replay is GET-only and never repeats a POST; any ambiguity stops | provider mutation-count and ordering spies; exact task/metadata/client/time/result matrices; journal uniqueness/concurrency/crash replay; OFF-before-boot and ON/banner completion; old-state immutability; focused/full regressions; two independent reviews; merge main before implementation and before PR; exact-head CI/deploy; one protected live power cycle and fresh inspect | no | blocked at shutdown `1/0/0` and boot `0/0/0`: live P4.R12 run `34372246548` found only a stable successful `stop_vm` task created before the durable claim window while compute is `ON`; it cannot prove the claimed stop or authorize boot, and another stop requires a new explicit owner decision plus separate design/review |
| P4.R12 | Classify the claim-only P4.R11 shutdown failure without another lifecycle mutation | deployed P4.R11, old reboot `1/0/0`, shutdown `1/0/0`, boot `0/0/0`, P4.R8 unclaimed, two independent recovery reviews | one incident-bound backend diagnostic and protected workflow action; exact existing task/server/device and failed live run IDs only | internal acceptance diagnosis only; no public API, UI, CLI, LLM, Runtime, image, ordinary-user behavior, or reusable provider diagnostic | re-prove the exact immutable baseline and stored shutdown claim/account digest; perform one exact compute GET plus numeric task, conditional canonical UUID, and numeric task GETs; emit only allowlisted identity/power, UUID/device/client, exact stop metadata, claim-window, update, result, and stability classes; emit no raw provider value or error; write no event/database/lifecycle state and expose no POST | provider mutation and database snapshot spies; malformed/category/redaction/binding/stage/stability/power matrix; focused/full regressions; two independent reviews; merge current main before implementation and again before PR; exact-head CI/deploy; one protected live diagnosis | no | completed: PR `#136` merged/deployed at `24b83016`; live read-only run `34372246548` proved compute `ON` and one fully stable successful exact `stop_vm` task created before the claim window; three independent reviewers confirmed this negative result closes diagnosis but cannot recover P4.R11 |
| P4.R13 | Execute the newly authorized one-shot replacement power cycle without rewriting P4.R11 evidence | completed P4.R12, exact old journals, P4.R8 unclaimed, compute `ON`, explicit owner approval for one additional stop and conditional start | six new globally unique append-only recovery events plus migration; incident-bound backend state machine; protected workflow/tests/internal runbook; exact same task/server/device only | internal canary recovery only; no public API, UI, CLI, LLM, Runtime, image, ordinary-user behavior, generic retry, or reusable lifecycle feature | preserve reboot `1/0/0`, P4.R11 shutdown `1/0/0`, boot `0/0/0`, and P4.R8 unclaimed; capture a stable P4.R12-equivalent pre-window task watermark; commit one recovery-shutdown claim before at most one forced stop POST; accept only a distinct/newer exact in-window `stop_vm` task; require stable terminal success and exact compute OFF before committing a recovery-boot claim; issue at most one start POST; accept only a distinct/newer in-window `start_vm` task with the same client; require stable terminal success, exact compute ON, and two zero-write SSH banners; claim-only replay is GET-only and never repeats either POST | global uniqueness/migration up-down; exact binding/baseline/watermark/task/time/client/result/power matrices; lost-response and malformed-direct-response reconciliation; concurrent claim/race/crash replay; old-journal/P4.R8 immutability; focused/full regressions; two independent design and implementation reviews; merge current main before implementation and again before PR; exact-head CI/deploy; fresh inspect, one protected live recovery, and post-cycle inspect | no | implementation/release complete; the sole stop run and sole permitted GET-only replay both ended claim-only with invalid provider-task evidence, so shutdown is `1/0/0`, boot is `0/0/0`, no start ran, and P4.R13 is terminally closed pending read-only P4.R14 diagnosis |
| P4.R14 | Diagnose the terminal P4.R13 recovery-shutdown task evidence without further lifecycle mutation | exact deployed P4.R13 SHA and runs, recovery shutdown `1/0/0`, recovery boot `0/0/0`, immutable old journals, P4.R8 unclaimed | incident-only backend read command, protected workflow route, tests, and internal plan/runbook evidence | internal canary diagnosis only; no public API, UI, CLI, LLM, Runtime, image, ordinary-user behavior, journal mutation, or lifecycle authority | retire the P4.R13 workflow/CLI route; bind exact incident and stored P4.R13 claim/watermark/account/original-claim state; issue compute plus numeric/exact/numeric provider GETs only; emit safe classifications; revalidate the entire baseline before stdout; never issue stop, start, reboot, reload, SSH, polling, an event append, or any provider write request, and never authorize recovery | exact binding/state/digest/drift matrices; provider GET order/failure/stability/redaction; database zero-mutation and provider write-request spies; retired-P4.R13 reachability; focused/full regressions; two independent reviews; current-main merge before implementation and again before PR; exact-head CI/deploy; one protected live diagnostic | no | completed: PR `#138` merged at `122f7d5`, exact deployment run `34396989738` passed, and sole live run `34399716626` found compute `ON` plus the same stable pre-claim watermark task on all three reads; no attributable P4.R13 stop exists and no lifecycle follow-up is authorized |
| P4.R15A | Prove only listener readiness before asking for another P4.R8 trust attempt | completed P4.R14, exact unchanged incident baseline, P4.R8 unclaimed | one incident-only read-only backend verifier, deployment-host helper, protected workflow/tests/runbook; exact existing task/server/device and frozen run IDs only | internal canary diagnosis only; no public API, UI, CLI, LLM, Runtime, image, trust, lifecycle, or ordinary-user behavior | strict existing trust reaches the deployment host; the helper sends zero bytes to the acceptance VPS, performs at most three literal-IPv4 TCP/22 connections in 15 seconds, requires two consecutive bounded printable `SSH-2.0-` banners, holds the existing deployment lock read-only/no-follow, proves the final pin and exact P4.R8 path remain absent before and after, and revalidates the exact backend/provider-ON baseline before emitting only ready/not_ready | lock/type/mode/owner/link/race matrix; banner bounds and zero-send oracle; exact pre/post verifier and provider-GET count; zero local mutation and zero client-issued provider write/lifecycle requests, while GET behavior remains provider-opaque; workflow binding/redaction; focused/full regressions; two independent reviews; main merge before implementation and PR; exact-head CI/deploy; one protected diagnostic | no | design frozen and independently approved; implementation pending; it never unlocks P4.R8, which still requires fresh explicit owner authority after a ready result and before P4.R8 integration or dispatch |
| P4.S1 | One acceptance VPS plus trusted owner access and initial Runtime resources | P4.R3, P4.R4, P4.R8, P4.R14, and a completed separately reviewed listener-recovery phase | existing exact cancelled task/server/device, six-hour continuation lease, three medium sandbox intents | operator evidence plus exact recovery event and strict pin metadata | same single server, key-only strict SSH with the recovered pin, cancelled state plus bounded active term, correct OS/amd64, then task-scoped baseline preparation proves v0.1.24 and three expected sandboxes | recovery/strict-replay/inspect/lease runs, bounded state inspection, baseline prepare run | no | P4.R14 is complete; blocked on a separately frozen and completed listener recovery, fresh inspection, P4.R8, and a new fixed lease deadline; P4.R6/P4.R9/P4.R11/P4.R13 remain unavailable |
| P4.S2 | Ordered five-stage signed private-procfs canary | P4.S1 | `action=canary-private-procfs`, exact task/hostname/stage and artifact hashes | plan evidence only | all stage-specific positive, negative, preservation, rollback, forward, disable, and cleanup oracles pass in order | workflow signature/metadata gate, stage logs, host snapshots, replay-safe cleanup | no | blocked on P4.S1 trusted access and baseline preparation |
| P4.S3 | Final cancellation, provider reconciliation, and independent review | P4.S2 | `action=cancel` then read-only inspection/provider reconciliation | plan and promotion packet | cancellation terminal and no future-billing ambiguity; provider compute may remain through the already-created term; no temporary grants/sandboxes/runner files/policy residue; fresh verifier approves | exact workflow evidence, safe log review, independent whole-phase audit | no | failed-attempt cancellation and guarded cleanup are complete and replay-verified; final whole-phase cleanup/review remains pending P4.S2 |

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

### Live acceptance phase P4.R2 frozen recovery design

- Keep provider-console interaction human and out of band. The workflow accepts
  exactly one complete OpenSSH server public-key line copied from the console;
  it must never accept or retrieve the one-time console URL, provider/API or OS
  credentials, a fingerprint without the key body, or `ssh-keyscan` output.
- Bind the action to the exact task ID and hostname. On the protected deployment
  host, inspect the current task and require an operator-authorized test task in
  `ready`, an active term, the expected hostname and Ubuntu OS, a syntactically
  valid current IPv4 address, and the same provider-backed server/device.
- Hold the existing deployment lock; require the parent directory to be a real
  mode-0700 directory; parse and validate an allowed OpenSSH key type and base64
  body; construct the pin with the control-plane-reported IP; and create it
  atomically as a regular mode-0600 file. Refuse symlinks, unexpected entries,
  or any non-identical existing file. An exact byte-identical replay is the only
  permitted idempotent success.
- Logs contain only the task/hostname binding, public algorithm/fingerprint,
  and pin-file digest. Public HTTP/JSON contracts, Runtime state, sandbox state,
  payment/provider state, and ordinary-user behavior remain unchanged.
- Tests freeze the action/input validation, absence of `ssh-keyscan`, task/IP
  derivation, active-test gates, lock and file-mode checks, mismatch refusal,
  exact replay, bounded logging, and private-procfs driver consumption. Merge
  current `main` into the frontend branch before edits and again before final
  integration, then require exact-head CI, production deploy, and a fresh
  read-only task inspection before using the action.

### Live acceptance phase P4.R3 frozen recovery design

- Preserve P4.R2 `enroll-host-key` as an optional stronger console-authenticated
  pre-seed. Add a separate protected `trust-host-key-tofu` path for the normal
  case where the user cannot access Hivelocity. Its exact confirmation binds the
  task ID, hostname, and provider device ID. It never accepts submitted host-key
  bytes and never invokes `ssh-keyscan`.
- Under the deployment lock, re-derive the live test task, permanent server,
  device, literal public IPv4, expected FQDN, ready state, active term, test
  expiry, Ubuntu 24.04 image, power state, acceptance tags, and protected task
  record. Validate the exact ordering private-key path as owner-only, mode 0600,
  regular, non-symlink, single-link storage; validate the separately stored
  public key and require its fingerprint to equal the task's ordering-key
  fingerprint. Pass the private-key path only to SSH; never inspect or print its
  contents.
- When no pin exists, retain one isolated empty mode-0600 same-directory
  candidate across bounded readiness retries and run only `root@<exact-IP>
  true` with the exact owner key, `-F /dev/null`,
  `StrictHostKeyChecking=accept-new`, candidate `UserKnownHostsFile`, disabled
  global known hosts, hashing, host-key updates, DNS verification, agents,
  proxies, forwarding, local commands, passwords, and keyboard-interactive
  authentication, and forced Ed25519 host keys. Successful public-key
  authentication is mandatory. No bootstrap, bundle, token, or other payload
  exists yet.
- Re-inspect the complete task/server/device/IP tuple after authentication.
  Validate exactly one canonical literal-IP Ed25519 entry; fsync and publish it
  atomically without overwrite into the protected pin path. A losing race may
  succeed only for byte-identical valid content. Symlinks, hard links,
  malformed or foreign entries, unexpected ownership/modes, and every mismatch
  fail without replacing the prior pin.
- Immediately repeat the harmless owner-key SSH with
  `StrictHostKeyChecking=yes` and the published pin. Existing-pin replay starts
  directly at this strict step. Retain the pin if a later action fails. Both
  live-canary drivers consume only the protected pin and use strict checking;
  remove any remaining generic-canary `ssh-keyscan` path.
- CLI 0.8.8 implements the same state-scoped contract under the WarpMetal state
  directory using server ID and a canonical trust epoch, not mutable hostname
  or ambient `~/.ssh/known_hosts`. It establishes and strictly rechecks the pin
  before requesting `/runtime/bootstrap`; every SCP/SSH uses the same explicit
  strict pin. The existing `--confirm INSTALL` authorizes the install and first-
  use trust; output reports the safe algorithm/fingerprint and whether trust was
  first observed or matched. There is no accept-new, ignore-mismatch, or generic
  reset option.
- The canonical CLI pin path is
  `${WARPMETAL_HOME:-~/.config/warpmetal}/ssh/known-hosts/<serverId>/<trustEpoch>.known_hosts`:
  owner-owned mode-0700 directories and a regular non-symlink mode-0600 file.
  Expected agent-kit changes are `src/host-trust.js`, `src/cli.js`,
  `src/installer.js`, `src/state.js`, package version/check metadata, focused
  host-trust/CLI/installer/runtime/state tests, README, and all source/plugin
  WarpMetal skill and runtime/safety/CLI-reference mirrors.
- A successful authenticated reload operation whose impact explicitly requires
  owner-host-key refresh may advance once to an operation-ID-bound trust epoch
  while retaining the old pin. Failed, manual-review, unknown, or externally
  initiated reload state never erases or replaces trust. A separate exact-
  operation recovery contract is required before ordinary users can recover a
  reload initiated outside local CLI state.
- Implement and release agent-kit first after merging current `main`; require a
  local disposable two-host-key SSH oracle, focused/full package gates, mirror
  parity, exact-head CI, and fresh security review. Then implement frontend and
  public/OpenAPI/LLM text last after merging current frontend `main`, merge
  `main` again before final integration, and require focused/full gates, fresh
  security review, exact-head CI/deploy, and deployed contract inspection.
- Expected frontend changes are the protected acceptance workflow and host-key
  helper, both live-canary drivers, focused host-trust/canary tests, backend
  operator runbook, public OpenAPI guidance, English/Spanish/Portuguese message
  sources, canonical `content/llms.md`, backend `public/llms.txt`, and their
  rendered/parity tests. Existing page components should remain unchanged when
  their localized message keys already render the new contract.
- The accepted residual is explicit: an active attacker on the first connection
  can become the durable pin and could receive the later Runtime bootstrap.
  Owner-key authentication proves the user to the endpoint; it does not attest
  the endpoint. Optional provider-console enrollment is the stronger path, and
  a future provision-time authenticated guest-key registration would remove
  this TOFU residual.

### Live acceptance phase P4.R4 frozen same-device continuation design

- Add one internal operator command and protected production-workflow action,
  `extend-cancelled-test-lease`. Inputs are the exact task ID, server ID,
  hostname, provider device ID, and a fixed second-precision UTC deadline. The
  confirmation string includes every input. The deadline must be in the future,
  no more than 24 hours from the command, and no later than
  `term_starts_at + 30 days`, matching the existing monthly-term calculation.
- This is not a generic cancelled-server resume feature. Require the exact P4
  baseline: `is_test=true`, state `cancelled`, failure null, provider request
  `complete`, prior successful `instance_cancelled`, exact device/server/IP/OS,
  a null test-artifact selector, Runtime `pending_install`, desired/applied
  revision `1/0`, no node token, and exactly the three intended persistent
  medium sandboxes. Refuse ready, expired, cancellation-pending, installed,
  degraded, mismatched, foreign, or partially mutated shapes.
- Read the provider compute record without invoking any mutation and require the
  exact device, service, FQDN, literal IP, Ubuntu 24.04 image, powered `ON`
  state, and both `warpmetal` and `acceptance-test` tags. Revalidate the
  protected task record, mode-0600 owner identity, mode-0600 existing Ed25519
  pin, task ordering-key fingerprint, and exact server/device/IP tuple. Run
  only strict `root@<exact-IP> true` with the existing key and pin before the
  backend write. Do not rerun TOFU or replace/reset the pin.
- Under the database transaction, recheck the complete task/Runtime/sandbox
  shape and the provider observation before atomically setting only
  `test_expires_at` and `term_ends_at` to the fixed deadline. Keep state
  `cancelled`; never change provider, payment, order, service, renewal, owner,
  Runtime, sandbox, artifact, or credential state. Write one bounded audit event
  containing only IDs and the deadline.
- Exactly one continuation event may exist. Byte-identical replay for the same
  bindings/deadline returns the original result without extending it or adding
  an event. Any different deadline or binding is permanently refused, including
  after the lease expires. Final protected `cancel` replay clears any selector,
  caps both deadlines at the current time, revokes management tokens, and logs
  bounded lease closure without calling provider cancellation again.
- Tests must prove the success/replay path, exact one-event invariant, every
  binding/state/provider/pin/SSH/Runtime/sandbox/deadline failure, no provider
  mutation, no state reopening, no credential logging, no TOFU, and final
  closure. Documentation impact is limited to this plan and the internal
  operator runbook; public API/OpenAPI, CLI, public/LLM text, Runtime releases,
  and sandbox image are unchanged.
- Implementation authorized: yes for the fail-closed internal recovery after
  the owner explicitly directed reuse of the same still-live VPS and approved
  required upgrades. Live invocation remains gated on a fresh protected inspect
  reporting the exact provider device powered `ON`; any drift stops without a
  replacement, renewal, payment, or relaxed check. Coordinating owner is the
  primary managed-plan executor, with a separate implementer and fresh security
  verifier available.

### Live acceptance phase P4 test matrix

| Requirement / risk | Behavior or invariant | Test level | Oracle defined before action | Command or procedure |
|---|---|---|---|---|
| R1-R2/A1/A8 | only the exact signed helper gets one private-procfs nesting; generic/alternate/deeper controls fail | live end-to-end | yes | candidate and forward canary stages plus negative controls |
| R3-R4/A2-A3 | OCI restrictions, nine Docker workloads, packages, services, and existing sandboxes remain exact | live snapshot | yes | compare frozen sensitivity host baseline after every stage |
| R6/A4 | existing sandbox ID, marker, persistent lifetime, and behavior survive install transitions | live integration | yes | stage-specific grant/connect before and after install; exit 37 |
| R10 | no credential or unbounded diagnostic exposure | workflow/log inspection | yes | inspect bounded stage markers and secret-redaction behavior only |
| P4.A3/P4.A7/P4.A8 | first observed key may be trusted only once for the exact owner-authenticated task epoch; console pre-seed remains optional | workflow and CLI security/integration | yes | actual SSH A pins; strict A replay succeeds; unexpected B fails with pin byte-identical and zero bootstrap calls; only an authenticated successful reload epoch may permit one B first-use; enrollment tests retain stronger pre-seed coverage |
| P4.A9 | expired cancelled task may receive exactly one bounded continuation without billing or trust reset | operator/workflow/provider integration | yes | fixed-deadline action verifies exact provider-live pending-install shape and strict existing pin before changing only both lease deadlines; exact replay succeeds and every different extension fails |
| P4.A10-P4.A11/A14/R14 | missing canary pin recovery and its proven-pre-capture replacement never become a reusable reset | backend/workflow security, crash recovery, live end-to-end | yes | immutable P4.R6 and globally one-off P4.R8 claims commit before their allowed accept-new SSH; P4.R8 readiness precedes its claim; every post-claim replay is strict against retained canonical state or permanently refuses; completion records safe digest/fingerprint; another task, binding, attempt, key, or missing completed pin fails |
| R11 | sensitivity begins absent; candidate enables; rollback retains policy; forward remains enabled; disable restores exact absent state | live lifecycle | yes | ordered stage checkpoint and exact final `post-disable-v0125-denied` oracle |
| Billing/cleanup | only one approved monthly VPS exists and is cancelled; ephemeral stage resources are removed | live operator/lifecycle | yes | exact task/hostname binding, per-stage cleanup, cancel/inspect reconciliation |

### Live acceptance phase P4 frozen command manifest

```text
1. Preserve the exhausted P4.R6 claim, completed P4.R7 proof, claim-only reboot
   and P4.R11 shutdown journals, and terminal P4.R13 state: recovery shutdown
   `1/0/0`, recovery boot `0/0/0`, no start issued, and P4.R8 unclaimed. Never
   dispatch P4.R13 again.
2. Merge, review, test, and deploy P4.R14. Its release retires the P4.R13
   workflow and operator CLI routes before exposing the new exact-incident
   GET-only diagnostic. Dispatch P4.R14 once and require only allowlisted
   classifications plus zero WarpMetal/local mutation and zero client-issued
   provider write-method/lifecycle request.
3. Independently review the P4.R14 output. Only if it yields sufficient exact
   stop-task and `OFF` evidence, freeze, implement, review, and deploy a separate
   reconciliation phase before using the already conditional start authority.
   Inconclusive evidence remains blocked. Another stop is forbidden.
4. After a separately reviewed listener recovery completes, dispatch a fresh
   protected inspection and require the exact immutable journals, provider
   `ON`, and P4.R8 still unclaimed.
5. Invoke P4.R8 once. Require the full exact evidence chain,
   immutable old state, two bounded non-trusting SSH banners before state, the
   globally one-off committed claim, one owner-key Ed25519 `accept-new true`,
   atomic durable pin publication, strict replay, and immutable safe completion
   evidence. Banner failure consumes nothing and stops; every post-claim replay
   is strict-only or permanently refuses.
6. After successful P4.R8 and a fresh protected inspect, obtain an exact new fixed deadline and
   invoke `extend-cancelled-test-lease` once with that fixed six-hour UTC
   deadline, then inspect and replay it exactly. Require state still cancelled,
   both deadlines equal, one audit event, strict existing-pin SSH, and no
   order/payment/renewal/provider/Runtime/sandbox mutation.
7. Complete P4.R1 so the test task, not the global production metadata, selects
   the signed stage artifact and sensitivity has an explicit stable baseline.
8. Do not create, pay, renew, reactivate provider billing, generate a key,
   reload or power the server, or run any generic trust reset. The only possible
   later lifecycle action is the already conditional start after exact P4.R14
   evidence and a new frozen/reviewed/deployed reconciliation path; another stop
   is forbidden. Reuse only the already protected owner identity and the exact
   P4.R8 pin after its explicitly accepted first-contact residual.
9. Prepare the v0.1.24 baseline with `preserve` on the same exact VPS before any
   private-procfs policy stage.
10. Dispatch sensitivity, candidate, rollback, forward, and disable separately,
   in order, with the exact baseline/candidate SHA-256 values.
11. Inspect every run for its exact stage success line, host snapshot equality,
   signed metadata, and temporary resource cleanup before advancing.
12. Replay protected cancel after all stage cleanup to close the continuation
   lease without a second provider cancellation. Inspect expired deadlines,
   terminal task, null selector, and unambiguous prior provider cancellation,
   then perform an independent whole-phase review before promoting Runtime
   v0.1.25. Provider compute may remain powered through its already-created term.
```

### Live acceptance phase P4 sequence and integration

1. P4.S0 froze the live quote, then the entry audit exposed false P4.A4-P4.A5.
2. P4.R1 and its independent recovery gate are complete; the owner approved and
   the workflow created exactly one bounded billable resource.
3. P4.R6 is exhausted, P4.R7 is complete, and P4.R9, P4.R11, and P4.R13 are
   terminally unavailable. Preserve all their journals, complete P4.R14, and
   use its evidence only to decide whether to freeze a separate listener-
   recovery phase. Only after that phase completes may P4.R8, P4.R4 re-entry,
   and P4.S1 resume on that same resource. Do not start a canary until the
   replacement pin strictly matches its immutable completion event, a newly
   confirmed fixed continuation deadline is active, and the initial-resource
   checks pass. Never retry the expired failed deadline or issue another stop.
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
  control-plane canary. At revision 12, P4.S1 remained pending without mutation.
- The owner subsequently selected and explicitly approved the previously
  disclosed new-disposable-VPS lifecycle. Protected workflow run `34177014854`
  on deployed main commit `6da3f0ab35eab8136ecfa11c88ccdd2a1d79003d`
  created exactly one monthly `agent` test authorization for hostname
  `private-procfs-canary-20260908`, exact OS `Ubuntu 24.04 (VPS)`, six-hour
  expiry, three medium sandbox intents, and hard monthly provider-cost ceiling
  `$15.00`. The protected owner token remains stored only on the deployment
  host. The safe task/server identifiers are
  `task_bRE4vSeF8tE0a_bOLwq2FdTz` and
  `srv_ZvQaOP05rGycwcX4vcKBTQnN`.
- Initial read-only inspection run `34177051572` observed one accepted LAX2
  provider order and device in `provisioning`, with Runtime `pending_server`,
  three desired sandboxes, no public task IP, and no active term. The provider
  projection simultaneously reported a failed AVS preauthorization. No retry,
  replacement order, or second payment was attempted.
- Read-only inspection run `34177278166` then observed the same task as `ready`
  with `failure=null`, provider request `complete`, an active term from
  `2026-09-08T01:35:17.716044Z` through the test expiry
  `2026-09-08T07:33:04.758006Z`, and Runtime `pending_install` at desired/applied
  revision `1/0` with exactly three desired sandboxes. The provider device is
  powered on, but its projection still reports `Charge Failed` from the AVS
  check. That contradictory billing evidence is retained as a residual and
  forbids any duplicate create or charge attempt; the present device remains
  the sole acceptance resource.
- A fresh read-only reinspection in run `34177885511` confirmed the same task
  remains `ready` with `failure=null`, the same active term, provider request
  `complete`, device power `ON`, Runtime `pending_install`, desired/applied
  revision `1/0`, and three desired sandboxes. No lifecycle mutation was
  dispatched by that run.
- P4.S1 is paused at the pre-SSH trust boundary. The canary will not scan and
  trust the network host key. A provider- or console-authenticated host key must
  be enrolled into the protected deployment-host path before any owner SSH,
  Runtime installation, or sandbox mutation.
- A fresh independent provider-interface review found that Hivelocity documents
  an authenticated `POST /api/v2/vps/{deviceId}/console` operation that returns
  a one-time VPS console URL, but no VPS API field or event/serial-log endpoint
  that returns a server SSH host key. The documented `sshKeyIds` are client
  login keys, not server identity. Therefore P4.A3 can use the provider console
  as its out-of-band root only after binding the session to the expected device
  and IP and displaying `/etc/ssh/ssh_host_*_key.pub` inside the guest. The URL
  is credential-like and must never be logged. Guest console access may still
  require an unavailable OS credential, and console output is not a
  cryptographically signed provider attestation; those remain stop conditions.
  Network `ssh-keyscan` output may not substitute for the console evidence.
- A read-only attempt to open the provider dashboard reached the Hivelocity
  login boundary; no authenticated in-app session or connected Chrome session
  was available. No credential was requested, read, entered, or transmitted.
  The owner must authenticate the retained provider tab before the exact VPS
  console can supply the missing out-of-band evidence.
- P4.R2 implementation was isolated to the acceptance workflow, protected-host
  enrollment script, operator runbook, and contract tests. The frontend branch
  was fast-forwarded to current `main` before the edit and merged `main` again
  before commit. Commit `a28dae75e17f256a2c73759f18af0fd7a9e36256`
  passed local syntax, ShellCheck, actionlint, diff, 19 focused runnable tests,
  145/146 full Node tests with the existing macOS Bash-3 skip, and 68 backend
  deployment/admin tests. Separate contract and security reviewers approved.
- Frontend PR #108 exact-head run `34180566125` passed and merged as
  `ae64f8539450b78fe68214c87b8cc31c94f03ba8`. PR head and merge have the
  identical tree `20d69422b2245bf1a346f43a0fcc15033aff444b`; the merge parents
  are exactly prior main and the PR head, and only the four intended files
  changed. Default-branch run `34180810995` attempt 2 passed 1,815 backend
  tests with one skip, frontend/admin gates, four-image publication, blue-green
  service deployment, admin promotion, and the bounded production x402 check.
  Attempt 1's only failure was an unchanged commerce-database assertion that
  passed on attempt 2; it is retained as a separate nondeterministic-test
  residual rather than attributed to P4.R2.
- Fresh deployed-main read-only inspection run `34182422911` confirmed the same
  sole test task remains `ready` with `failure=null`, provider request
  `complete`, device power `ON`, the same active term and Ubuntu image, Runtime
  `pending_install`, desired/applied revision `1/0`, and exactly three desired
  sandboxes. The AVS/charge projection contradiction remains unchanged. No SSH,
  Runtime, sandbox, policy, grant, payment, or cancellation mutation occurred.
- The owner then rejected provider-console access as a product prerequisite:
  ordinary WarpMetal users will never have Hivelocity access and the plan must
  trust the first observed host key. Revision 15 therefore marks mandatory
  console trust false, accepts the bounded first-contact MITM residual, retains
  P4.R2 only as an optional stronger pre-seed, and inserts P4.R3 before further
  live mutation. All first-use paths must authenticate with the exact ordering
  owner key, perform only a harmless command, atomically pin before bootstrap,
  and immediately reconnect strictly; all later mismatches remain fatal.
- Independent read-only CLI review proved version 0.8.7 cannot perform this
  ordinary-user flow: `server login` is API-only, while `runtime install`
  requests bootstrap before strict SSH against ambient known-hosts. The frozen
  canary may still use 0.8.7 after the protected driver pins and mounts the host
  key. CLI 0.8.8 is the required self-contained product recovery and must land
  before the frontend/public-document portion of P4.R3, which remains last.
- Agent-kit CLI 0.8.8 landed after current `main` was confirmed at
  `fbdc417651f2d07d184e00823be0c3a19cb3b414`. Reviewed implementation commit
  `337beea2bb4539926e4d377ad265bc9b32b7af1e` passed PR #32 exact-head CI run
  `34188665036`, merged as
  `7440deaa3dfe8182832884cad54be01319eed473`, and passed main run
  `34188724913`. Annotated tag `v0.8.8` points to that merge, and publish run
  `34188766432` completed the provenance-signed public npm publication with
  package shasum `ccad9f6061bdbb970b6f8659838abcf55056982a`; independent registry
  visibility remains a post-publication observation rather than a reason to
  repeat the publish.
- The final CLI gate requires an exact client-generated OpenSSH authentication
  result bound to the current API IP/port; a real hostile endpoint that
  authenticated with `none` while injecting a publickey phrase in its SSH
  software banner was rejected. After first SSH and before durable publication,
  CLI re-inspects the API tuple and requires exact server ID, eligible state,
  public IP, and owner-key fingerprint. Drift deletes the candidate, publishes
  no pin, and makes zero bootstrap requests. Atomic publication, immediate
  strict replay, later strict SSH/SCP, and operation-bound reload epochs remain
  unchanged.

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

### Live acceptance phase P4.R2 verification log

- Acceptance criteria checked: the protected action accepts only one canonical,
  comment-free ED25519 public-host-key line and an exact task/hostname/device
  confirmation; the deployment-host script re-derives and binds the current
  ready test task, server, provider device, IP, OS, power, tags, and active term.
- Filesystem and replay evidence: the shared deployment lock, owner/mode and
  non-symlink checks, mode-0700 pin directory, mode-0600 candidate/pin, atomic
  hard-link no-overwrite publication, exact byte-identical replay, mismatch
  refusal, and candidate/pin/parent fsync paths passed focused tests. Existing
  pin, task-record, and pin-directory symlink cases fail closed.
- Error-path and log-safety evidence: malformed, multiline, commented, private,
  noncanonical, non-ED25519, mismatched task/server/provider/state, and foreign
  filesystem inputs fail before publication. Logs are limited to safe bindings,
  public algorithm/fingerprint, file digest, and replay state. Neither the
  workflow nor its consumer invokes `ssh-keyscan` or relaxes strict host-key
  checking.
- Authentication and authorization evidence: the workflow runs only through
  the protected production environment and can validate and bind submitted key
  bytes, but cannot prove how a human obtained them. Authenticated provider-
  console observation was the revision-14 provenance gate; a structurally valid
  network-scanned or attacker-supplied key was forbidden even though software
  cannot distinguish its source. Revision 15 preserves this route as optional
  higher assurance and moves the default path to the separately reviewed P4.R3
  owner-authenticated first-use contract.
- Independent review: pre-integration contract and security reviewers approved,
  then a fresh read-only verifier reproduced exact merge-tree identity, intended
  file scope, PR CI, default-branch test/publication/deployment, and the unrelated
  attempt-1 flake classification. P4.R2 status: completed at release revision
  14. Revision 15 supersedes the mandatory provider-console dependency but not
  P4.R2's implementation or security properties. P4.S1 remains stopped before
  SSH until P4.R3 safely establishes and strictly replays the exact first-
  observed pin.

### Live acceptance phase P4.R3 agent-kit verification log

- Acceptance criteria checked: CLI 0.8.8 uses the exact owner identity, an
  isolated Ed25519 candidate, one harmless first-use SSH, post-authentication API
  tuple reinspection, atomic no-overwrite publication, and immediate strict
  replay before requesting Runtime bootstrap. All installer SSH and SCP inherit
  the explicit managed pin and disabled ambient trust, passwords, agents,
  proxies, X11, and forwarding.
- Error-path evidence: real OpenSSH A-first-use/A-strict-replay/B-mismatch
  integration retained the original pin; a real malicious SSH software-banner
  and `none`-authentication endpoint failed before reinspection/publication; API
  IP drift after owner-authenticated SSH left no pin and made zero bootstrap
  requests. Symlink, hard-link, ownership/mode, malformed-key, race, fsync,
  timeout, and reload-epoch tests passed.
- Package/documentation evidence: `npm run check`, 88/88 full tests, 4/4 plugin
  tests, `npm pack --dry-run`, `git diff --check`, and byte-identical source and
  packaged skill/reference mirrors passed. README/help/skill text documents the
  accepted first-contact MITM and state-deletion residual, strict continuity,
  mismatch prohibition, and optional stronger console pre-seed.
- Independent review: two final non-implementing reviewers returned APPROVE on
  the stable diff after independently reproducing the hostile-banner and API-
  drift cases. PR #32, main CI, tag `v0.8.8`, and publish workflow all passed.
  P4.R3 remains in progress only for the deliberately last frontend protected
  TOFU path, strict live-driver conversion, operator/public/OpenAPI/LLM text,
  deployed verification, and fresh final reviews.

### Live acceptance phase P4.R3 frontend verification log

- Integration order: the frontend branch was fast-forwarded from `main` before
  implementation and `origin/main` was fetched and merged again immediately
  before the final gate; it was already up to date. The intended stable diff was
  committed as `6060dac3b5159b08955ad22d088344e45c3c93ad`.
- Acceptance criteria checked: the protected TOFU action binds the exact task,
  hostname, provider device, API server/IP/state/term, and owner identity; rejects
  submitted host-key bytes; retains one isolated Ed25519 candidate across bounded
  retries; requires exact public-key authentication; reinspects the full tuple;
  publishes atomically without overwrite; and completes immediate strict replay
  before either canary driver may bootstrap. Existing mismatches remain fatal.
- Driver and package evidence: both live drivers contain no `ssh-keyscan`, require
  the protected canonical literal-IP pin, use CLI 0.8.8, preseed its exact
  server-ID/trust-epoch state path, and require `hostKeyTrust.state` to be
  `matched`. The signed all-tools sandbox-image policy and digest are unchanged.
- Public contract evidence: English, Spanish, and Portuguese Runtime/docs pages,
  canonical and backend LLM text, operator runbook, and description-only OpenAPI
  text disclose the accepted first-contact MITM residual, strict continuity,
  fatal mismatch behavior, operation-bound reload epochs, and optional stronger
  Hivelocity-console preseeding without requiring console access for ordinary
  users. Nested private procfs remains optional, host-scoped, workload-based, and
  independent of Nico, coding, GitHub, CLI brand, or subagent use.
- Local and review gates: 155 frontend tests passed with one expected macOS
  Bash-4 skip; 47 backend public-surface tests, Ruff, ShellCheck, actionlint,
  Bash syntax, OpenAPI synchronization, and diff checks passed; ESLint reported
  zero errors and three pre-existing warnings. Three independent non-implementing
  reviewers approved the workflow/security, CLI/public-doc, and whole-plan
  contracts; the hostile-banner and API-drift cases were reproduced.
- Release evidence: frontend PR #109 exact-head run `34192534162` passed and
  merged as `2f60a16612703715bbb2407a616e9cf8eb298779`; default-branch run
  `34192826912` passed test, publication, and production deployment. Live
  `/agent-runtime`, `/docs`, `/llms.txt`, and
  `https://api.warpmetal.com/openapi.json` each returned the deployed trust
  contract. P4.R3 is complete at release revision 17; P4.S1 may now begin with
  one protected first-use trust operation on the existing acceptance VPS.

### Live acceptance phase P4.R3 Python 3.8 recovery log

- Failed gate: fresh inspect run `34194782588` verified the single existing
  acceptance task as ready and unexpired with the exact server, provider device,
  public IP, Ubuntu 24.04 image, powered-on state, owner fingerprint, and three
  desired sandboxes. Protected TOFU run `34194865239` then failed closed with
  `task_binding_failed` before SSH, candidate creation, pin publication,
  bootstrap, Runtime installation, or sandbox mutation. It was not retried.
- Root cause: the deployment host uses Python 3.8, while the host-side validation
  heredocs evaluated Python 3.9 PEP-585 built-in generic annotations such as
  `tuple[datetime, str]`. Python raised `TypeError` before the JSON predicates;
  suppressed parser stderr was intentionally reduced to the stable safe error.
  Reconstruction from the read-only inspect and protected create records proved
  every declared binding predicate true.
- Recovery boundary: remove only incompatible annotations from all host-executed
  enrollment, TOFU, live-canary, and private-procfs validation heredocs. Preserve
  every trust predicate, SSH option, owner/API reinspection, publication rule,
  strict replay, and log field. Add a static no-built-in-generic guard and select
  Python 3.8 immediately before the complete `npm test` gate, after backend
  Python 3.12 migrations, Ruff, and coverage.
- Verification: local full frontend gate passed 156 tests with one expected
  macOS Bash-4 skip; focused host-trust/canary gate passed 30 tests with the same
  skip; Bash syntax, ShellCheck, actionlint, diff checks, and lint with zero
  errors passed. Two independent recovery reviewers approved the stable six-file
  diff and confirmed no security behavior changed.
- Integration: recovery commit `763950e642935b9e500418a2f0115e3150189f38`
  passed PR #110 exact-head run `34196016590`, including the full TOFU happy path
  under Python 3.8, and merged as
  `7ae91ba5745ba9f1ee436ae932d604f16a6f8d95`. Default-branch production run
  `34196415129` passed its test, publication, and production deployment jobs.
- Live recovery: fresh inspect run `34198424369` re-established the exact ready,
  unexpired Ubuntu 24.04 task/device/IP tuple with Runtime `pending_install`,
  three desired sandboxes, and desired/applied revision `1/0`. Protected TOFU
  run `34198472527` then passed. The helper can exit successfully only after its
  exact-task owner-key probe, atomic Ed25519 pin publication, and immediate
  strict replay have all succeeded; no bootstrap or Runtime mutation is part of
  that action. P4.R3 is therefore complete at revision 19.
- Failed P4.S1 gate: sensitivity run `34198567199` verified the immutable signed
  v0.1.24 artifact and set the task-scoped selector, then stopped at driver line
  37 while checking deployment-host commands. Correlation with the already
  passing TOFU dependencies isolates the undeclared `jq` dependency. The driver
  exited before task/artifact binding, checkpoint creation, VPS SSH, bootstrap,
  Runtime installation, sandbox creation, or policy mutation. Stage progression
  stopped; candidate, rollback, forward, and disable were not dispatched.
- Cleanup evidence: the failed run's backend artifact-clear operation succeeded
  and reported `selectedArtifact=null` and `cleared=true`. Its subsequent exact
  run-directory removal failed closed because the ownership marker remained.
  Independent review found that the cleanup-side `docker compose exec` lacked
  `</dev/null`, allowing Docker to consume the remainder of the remote
  `bash -s` input after the successful clear. Recovery therefore had to replace
  the three `jq` uses with Python 3.8-compatible JSON handling, name any missing
  command, redirect container stdin, prove post-clear marker removal in tests,
  and remove only the validated failed-run marker/directory under the deployment
  lock.
- Safety stop: exact cancel run `34198721496` passed. Post-cancel inspect run
  `34198926210` verified task state `cancelled`, Runtime still
  `pending_install`, desired/applied revision `1/0`, and no Runtime mutation.
  Provider cancellation is unambiguous, but the device remains powered through
  the already-created term by the provider contract; it is not a new billing
  attempt. No replacement server, payment, or duplicate order was created.
  The deployment-host recovery below is reviewed, merged, deployed, and
  replay-verified. Revision 20 initially treated the cancelled task as
  non-reusable and required a replacement; the owner correction and revision-21
  source audit supersede that conclusion with bounded P4.R4 same-device reuse.

### Live acceptance phase P4.S1 deployment-host recovery log

- Implementation: frontend commits `df38d8e` and `5e83d1c` removed the
  deployment-host `jq` dependency in favor of exact Python 3.8-compatible JSON
  construction and validation, named any missing command, and redirected
  container stdin for selector clear and verification. The protected
  `cleanup-private-procfs-run` action is bound to an exact task ID, numeric run
  ID, and confirmation string under the production deployment lock. It requires
  a null selector, a mode-0600 task-bound marker, exact ownership/modes and file
  types, and a closed entry allowlist before removing only the known files and
  empty directory; absent-directory replay succeeds without mutation.
- Verification and review: the stabilized frontend gate passed 158 tests with
  one expected macOS Bash-4 skip, the complete deployment workflow test file
  passed 42 tests, and the backend count update passed the full hosted backend
  suite. Build, Bash syntax, ShellCheck, actionlint, Python 3.8 grammar, and diff
  checks passed; lint had zero errors and three pre-existing unrelated warnings.
  Three independent non-implementing reviewers approved the exact JSON parity,
  cleanup security contract, behavioral failure matrix, and final exact head.
- Integration: the first PR check `34201363279` correctly caught the existing
  deployment resolver-count assertion after the new protected action increased
  the count from seven to eight. The one-line expectation correction introduced
  no production behavior change. PR #111 exact head
  `5e83d1c65affe9f02b92677e4c77e71f68f32eae` then passed run
  `34201690826` and merged as
  `d2ad70251cd87628cfdcc046ccce1240abebbe09`. Default-branch run
  `34202077886` passed its test, image-publication, and production-deployment
  jobs.
- Cleanup replay: protected run `34204247814` verified the exact task selector
  remained null and removed only
  `warpmetal/acceptance/runs/34198567199/private-procfs`, reporting
  `private_procfs_run_cleanup run=34198567199 selected=false directory=removed`.
  Exact replay run `34204327245` passed with
  `private_procfs_run_cleanup run=34198567199 selected=false directory=absent`.
  The failed attempt is fully reconciled: no temporary deployment-host files,
  task-scoped artifact selector, Runtime install, sandbox, policy, or grant
  remains. No replacement VPS, duplicate order, or payment was created.
- Fresh post-mutation verification independently confirmed the PR/head/merge
  chain, all three successful default/protected runs, both cleanup oracles, and
  that unrelated create, canary, artifact-clear, cancel, and reconcile steps
  were skipped in the cleanup actions. Workflow inventory still contains
  exactly one successful server-create run, no payment reconcile, and no later
  canary; post-cancel state remains `cancelled`, `pending_install`, revision
  `1/0`, with provider power retained through the paid term as expected.
- Gate status: the recovery implementation and early P4.S3 cleanup are complete
  at release revision 20. Revision 21 confirms the cancelled state itself is
  supported while a control-plane term is active, but this task's capped term
  and test authorization expired. P4.S1-P4.S3 now depend on P4.R4's exact
  same-device continuation lease; no replacement VPS is required or authorized.
  Runtime v0.1.24/v0.1.25 and the signed all-tools sandbox image remain
  unchanged.

### Live acceptance phase P4.R4 same-device correction log

- Owner decision: continue on provider device `69097` and server
  `srv_ZvQaOP05rGycwcX4vcKBTQnN`, which remain the sole acceptance resource;
  upgrade required tooling but do not order another VPS. The local official CLI
  was upgraded from 0.8.6 to the reviewed published 0.8.8. It correctly cannot
  read deployment-host credentials or identity state, so live operations remain
  restricted to the protected production workflow.
- Source audit: `has_active_server_term`, SSH authentication, Runtime enable,
  sandbox creation, bootstrap, both canary drivers, and explicit regression
  tests intentionally accept `cancelled` during an active control-plane term.
  Direct reuse is currently blocked only because both `test_expires_at` and the
  test-capped `term_ends_at` expired at `2026-09-08T07:33:04.758006Z`.
  Renewal rejects cancelled tasks and is forbidden because it could introduce
  billing ambiguity; no supported resume/adoption command currently exists.
- Trust reuse: cancellation did not delete the protected task record, ordering
  owner key, or atomically published Ed25519 pin. No reload, host-key epoch
  change, or host mutation occurred. P4.R4 must strictly authenticate the same
  task/server/device/IP with that existing key and pin before its database-only
  lease update; any mismatch is fatal and TOFU must not run again.
- Entry evidence: protected inspect run `34228195328` passed after waiting for
  unrelated default-branch deployment `34227368757`. It reports the exact task
  still `cancelled`, failure null, zero payment attempts, the same server/IP,
  expired equal test/term deadlines, Runtime `pending_install`, desired/applied
  `1/0`, and three desired sandboxes. Provider compute remains powered `ON` with
  exact device `69097`, service `315175`, FQDN, Ubuntu 24.04 image, literal IP,
  monthly period, and acceptance tags. No mutation step ran. P4.R4's live entry
  assumption is verified; the lease action itself remains gated on reviewed,
  merged, and deployed code.
- Implementation: frontend commit `eb63a108d8feffccce2a284b0c2898d22cb851b5`
  added the internal one-shot lease event/index, exact operator and provider
  baseline checks, protected workflow action, strict-pin helper, cancellation
  closure behavior, recovery runbook, and executable failure/replay coverage.
  It changes no public API or OpenAPI contract, ordinary-user CLI or LLM text,
  Agent Runtime release, sandbox image, or all-tools image contents.
- Safety closure: the final baseline requires the exact cancelled test with no
  failure, charge, payment attempt, selected artifact, Runtime mutation, or
  sandbox drift; exact expired/equal deadlines; the original provider device,
  service, FQDN, IP, OS, power state, and required tags; the protected ordering
  owner identity; and the existing canonical Ed25519 IP pin. A harmless strict
  SSH probe and a second exact binding inspection precede the database-only
  update. Exact replay is idempotent; another deadline or binding is refused.
  Final cancel replay closes both deadlines, revokes task access/bootstrap
  tokens, clears the selector and Runtime node token, and never repeats provider
  cancellation for this already-cancelled task.
- Verification: the final PostgreSQL backend suite passed `2083` tests with one
  skip and met the branch gate at 88.12% statement and 75.02% branch coverage;
  migration clean upgrade/downgrade/re-upgrade passed; site tests passed `174`
  with one expected macOS-only Bash 4 skip; admin tests passed `52`; Ruff,
  compileall, Bash syntax, ShellCheck, actionlint, and diff checks passed. The
  five lint warnings are pre-existing current-main pricing/translation warnings.
  Independent backend and workflow/security reviewers both returned APPROVE,
  including concurrent identical and competing database calls and the nine-case
  executable protected-helper matrix.
- Integration: immediately before PR integration, frontend `main` was merged
  again and was already current, with no conflicts or overwritten changes. PR
  `#115` exact-head run `34236306309` passed; merge commit
  `bb327e075db86fc3be4f89c4f703bf357847ed27` was deployed by default-branch run
  `34237060167`, whose test, publication, blue-green deployment, production
  verification, and notification jobs all passed. P4.R4 is therefore deployed;
  its protected live inspect, one mutation, exact replay, and final closure are
  still pending and no VPS action has yet been dispatched from this revision.
- Fresh live entry gate: deployed-main protected inspect run `34239907292` at
  merge head `bb327e075db86fc3be4f89c4f703bf357847ed27` passed and only its
  read-only inspection step ran. It reconfirmed task `task_bRE4vSeF8tE0a_bOLwq2FdTz`
  and server `srv_ZvQaOP05rGycwcX4vcKBTQnN` are still `cancelled` with failure
  null, zero checkout/payment attempts, and equal expired deadlines
  `2026-09-08T07:33:04.758006Z`; Runtime remains `pending_install` at desired/
  applied revision `1/0` with three desired sandboxes. Provider compute is still
  the exact device `69097`, service `315175`, FQDN, Ubuntu 24.04 image, literal
  IP `23.227.167.104`, required tags, and power `ON`. No create, payment,
  renewal, lease, SSH, Runtime, sandbox, artifact, or cancellation mutation ran.
- Failed-closed live extension gate: protected run `34240330089` used the fixed
  deadline `2026-09-08T20:45:15Z` and passed workflow input validation, pinned
  deployment-host setup, and exact helper routing, then refused with
  `invalid_existing_pin`. The refusal occurs in the helper's local protected-pin
  validation before owner-key VPS SSH or the backend lease operator. The same
  stable reason covers both initial existence/type/nonempty/mode/owner/link-count
  checks and later canonical-content validation; timing suggests the early group
  but does not prove it. No retry is authorized while the exact failed predicate
  remains unknown.
- Ambiguity closure: immediate protected read-only inspect run `34240408968`
  passed and reconfirmed both task deadlines are still the original expired
  `2026-09-08T07:33:04.758006Z`; task, zero-payment, provider `ON`, Runtime
  `pending_install` revision `1/0`, and three-sandbox intent are unchanged. The
  attempt therefore made no lease, provider, SSH, Runtime, sandbox, artifact,
  order, payment, renewal, or cancellation mutation. Recovery must diagnose
  metadata without reading key bytes, rerunning TOFU, resetting/replacing the
  pin, or weakening strict verification.

### Live acceptance phase P4.R5 frozen pin-diagnostic recovery design

- Add a separate protected `diagnose-acceptance-host-pin` action rather than
  turning the mutation-capable extension into a diagnostic. Bind its exact
  confirmation to task ID, server ID, hostname, and provider device ID. Retain
  the production environment, global production concurrency, and deployment
  lock. The action must run no TOFU, enrollment, extension, canary, cancellation,
  payment, renewal, provider mutation, or VPS SSH path.
- Reuse the exact read-only task/provider binding parser from P4.R4 before
  diagnosing the task-derived pin path. Inspect the final component with
  `lstat` and a no-follow file descriptor, compare initial path, pre-read
  descriptor, post-read descriptor, and final path identity and mutable metadata
  to close swaps and same-inode rewrites, and classify only: missing,
  symlink/wrong type, empty, wrong mode, wrong owner, multiple links, malformed
  canonical literal-IP Ed25519 pin, healthy, or the fail-closed
  `path_identity_unstable`. Stable classifications require two consistent path
  observations; the unstable result is the only allowed report when observations
  disagree and is never eligible for recovery. Output only the classification
  and safe booleans/numeric metadata plus public fingerprint/digest when a stable
  pin is canonical; never output the key line, key material, task record/token,
  private-key path/content, or SSH logs.
- Diagnosis is read-only and cannot repair even an apparently safe mode or
  interrupted-publication condition. A mode-only normalization may be designed
  only after the live classification proves all content/inode/owner/link/binding
  predicates healthy except restrictive mode, and it must preserve bytes,
  digest, inode, and strict trust. Missing, wrong type, empty, wrong owner,
  malformed content, or unexplained links remain blocked. An exact two-link
  orphan candidate requires separate prior-digest/inode evidence and review.
- Add executable fixtures for every classification, including unreadable
  owner-owned wrong modes and `path_identity_unstable`; actual interleaved
  same-inode rewrite detection; descriptor/path-swap defense; descriptor-verified
  nonblocking deployment-lock contention; Linux atime and all other inode/byte
  metadata preservation; exact confirmation/routing; output redaction; and proof
  that no diagnostic branch invokes SSH or a backend/provider mutation. Also
  close the independently found enrollment consistency gap by enforcing nonempty
  and single-link candidates/existing/final pins without changing enrollment
  semantics. Require independent recovery approval before integration.

### Live acceptance phase P4.R6 frozen one-shot re-trust recovery design

- This is not restoration of the original pin. Protected TOFU run
  `34198472527` proves that a trust event succeeded on exact deployed commit
  `7ae91ba5745ba9f1ee436ae932d604f16a6f8d95`, but its retained job log, check
  output, and artifact inventory contain no host fingerprint or canonical file
  digest. Runtime never registered host keys, and diagnostic run `34255110640`
  proved the only protected pin is missing. The owner explicitly accepted the
  disclosed consequence by saying `continue`: one second first-contact trust
  event, with the same MITM residual, for this canary only.
- Add a separate protected `recover-missing-acceptance-host-pin` action. Hard
  bind source, inputs, and confirmation to task
  `task_bRE4vSeF8tE0a_bOLwq2FdTz`, server
  `srv_ZvQaOP05rGycwcX4vcKBTQnN`, hostname
  `private-procfs-canary-20260908`, provider device `69097`, service `315175`,
  literal IP `23.227.167.104`, original trust run `34198472527`, missing-pin
  diagnostic run `34255110640`, and the explicit phrase
  `ACCEPT-SECOND-FIRST-CONTACT`. No other task, run, device, IP, service, or
  confirmation is eligible, and the action accepts no submitted host key.
- Add immutable internal task events for `claimed` and `completed`, each with a
  database-enforced one-row-per-task uniqueness constraint. The protected helper
  first revalidates the exact expired cancelled task, successful prior provider
  cancellation, zero-payment/null-selector state, provider `ON` observation,
  Runtime `pending_install` revision `1/0`, three exact persistent medium
  intents, absence of any reload operation/event, original equal expired
  deadlines, protected task record, owner identity/public fingerprint, correct
  pin directory, stable missing final pin, and absence of foreign recovery
  entries. It writes and fsyncs the exact local recovery directory, empty
  deterministic candidate, and prepared journal before the claim, then the
  backend atomically commits the exact `claimed` event before any network
  contact. Claim detail binds every identifier, evidence-run ID, owner
  fingerprint, original deadline, and expected baseline. A different or
  malformed existing event refuses.
- Persist and fsync an exact task-bound journal plus deterministic isolated
  mode-0600 candidate. Only the process that newly created the backend claim may
  publish and fsync an `attempted` journal state and invoke exactly one owner-key
  `root@23.227.167.104 true` SSH attempt with `-F /dev/null`, Ed25519-only
  `StrictHostKeyChecking=accept-new`, the isolated candidate as the only known-
  hosts file, and ambient hosts, DNS verification, updates, agents, proxies,
  forwarding, local commands, passwords, keyboard-interactive authentication,
  and X11 disabled. Never use `ssh-keyscan`, print SSH diagnostics, or send a
  bootstrap, bundle, token, command payload, or other host mutation.
- Every invocation after an existing `claimed` event never invokes `accept-new`,
  even if the first process crashed before starting SSH. It may continue only by
  validating and strictly authenticating against the exact already-written
  candidate or published pin. A claimed attempt with missing, empty, malformed,
  foreign, ownership/mode/link, journal, or binding state is permanently
  exhausted and closes the canary. A crash after final hard-link publication
  may remove only the exact same-inode deterministic candidate after validating
  both names; no other link or entry is repairable.
- Re-inspect the complete backend/provider/task tuple after authentication,
  atomically publish the canonical literal-IP Ed25519 candidate without
  overwrite, fsync it and its directory, and immediately repeat the harmless
  SSH with strict checking. Re-inspect the complete tuple again after strict
  success. Only then may the backend append the
  exact `completed` event containing the public algorithm, fingerprint, file
  digest, bindings, and source run IDs. A completed replay requires the current
  pin to match that event and performs only strict SSH. A missing or mismatched
  pin after completion can never claim or observe another key.
- The recovery action performs no lease extension, order, payment, renewal,
  provider mutation/reactivation, Runtime install, sandbox/grant operation,
  cancellation, reload, or generic trust reset. P4.R4 remains a separately
  dispatched action after a fresh inspection and a newly owner-confirmed fixed
  deadline; its failed expired deadline is never retried or silently replaced.
  Documentation impact is limited to this plan and the internal backend
  operator runbook. Public API/OpenAPI, CLI, LLM text, Runtime/image artifacts,
  and ordinary-user behavior remain unchanged.
- Tests freeze backend claim/completion validation, provider and baseline
  predicates, immutable uniqueness and concurrent claims, exact-event replay,
  every journal/candidate/pin crash boundary, the pre-SSH attempted durability
  barrier, actual A-observe/A-strict/B-mismatch behavior, no second `accept-new`,
  no-overwrite publication, incomplete/completed replay, output redaction,
  lock contention, Python 3.8 compatibility, and static absence of every
  forbidden lifecycle call. Two fresh non-implementing security reviewers and
  a new exact-head CI/deployment gate are required before one protected live
  dispatch.

### Live acceptance phase P4.R5 verification and CI-recovery log

- Implementation commit `e684dd6` added the separate protected diagnostic
  action and read-only helper, secure descriptor-based deployment locking,
  exact cancelled-task/provider/runtime/sandbox binding, bounded safe
  classifications, and the enrollment single-link/nonempty consistency checks.
  The helper holds the lock throughout observation and compares initial path,
  pre-read descriptor, post-read descriptor, and final path identity and mutable
  metadata before reporting any stable classification.
- The full local gate passed 2,088 PostgreSQL backend tests with one skip and
  the branch-coverage threshold, 183 site tests with one expected macOS Bash-4
  skip, 53 admin tests, Ruff, migrations, lint with only five pre-existing
  warnings, Bash syntax, ShellCheck, actionlint, and diff checks. Two independent
  reviewers approved the diagnostic contract and security boundary on native
  and Linux/Python 3.8 environments.
- PR #117 exact-head run `34247868945` passed and the implementation merged as
  `0a60b238394a19d1a078735a9ff141199dd88288`. Default-branch run
  `34248510162` stopped before publication/deployment because the concurrent
  same-inode rewrite fixture did not reliably overlap the intentionally narrow
  production observation window. No production diagnostic failure or external
  mutation occurred.
- Test-only commit `7da936e` replaces that probabilistic writer with a
  fixture-scoped Python import interceptor that performs one real same-inode,
  same-size, fsynced rewrite after the first real `lstat`, then returns the
  pre-rewrite observation. The production helper remains unchanged and must
  deterministically classify `path_identity_unstable`. The diagnostic suite
  passed repeatedly on native and Linux amd64, including Python 3.8, and both
  independent reviewers approved the exact recovery.
- PR #119 exact-head run `34249905479` passed the backend, site, diagnostic,
  and lint gates, then stopped before publication/deployment in the unchanged
  admin visual test while waiting for a new pricing preview. A fresh independent
  audit proved the PR branch has a byte-identical `admin` tree to its main base,
  reproduced the timeout locally, and identified a pre-existing harness race:
  the test observes the successful pricing-version confirmation before the
  asynchronous refresh clears the production `busy` state, immediately submits
  the form, and production correctly ignores the request while busy.
- Bounded recovery: do not rerun the failed gate blindly and do not alter
  production pricing behavior or any pricing oracle. Change only the admin
  visual harness to wait until the existing preview control is present and
  enabled after the version-11 confirmation before submitting the next preview.
  Reproduce the formerly failing sequence, rerun the complete admin and frontend
  gates, obtain fresh independent review, and require a new exact-head PR run.
- Test-only recovery commit `6f94ba9` now waits for the actual enabled
  `Preview complete policy` control and clicks it. Five consecutive focused
  visual runs, the full 53-test admin suite, the full 183-pass/one expected-skip
  site suite, the eight-test diagnostic suite, lint with zero errors, and diff
  checks passed. The fresh independent recovery reviewer approved the exact
  two-test-file branch diff and confirmed that a stuck production `busy` state,
  failed preview, or failed edit-invalidation oracle still fails the test. At
  that local gate, a new exact-head PR run remained required before integration.
- PR #119 exact-head run `34251863726` passed on commit
  `6f94ba9220369e358d35d11c9171ef8e41926b6f`. Immediately before integration,
  frontend `origin/main` was fetched and merged again; it was already current
  and no conflict or overwrite occurred. PR #119 then merged as
  `bbc7968c6651d9ea761686d4d250bd0a78fc639a`. Exact-merge production run
  `34252494243` passed on that merge: test completed in 5m39s, four-image
  publication in 3m6s, and production deployment in 15m33s. The protected
  read-only diagnostic may now run once; no mutation or lease retry is yet
  authorized by its deployment success.
- Protected diagnostic run `34255110640` executed exactly once on deployed main
  `bbc7968c6651d9ea761686d4d250bd0a78fc639a`. Its exact task, server, hostname,
  provider device, cancelled baseline, provider observation, Runtime state, and
  three-sandbox intent binding passed. The bounded result was
  `classification=missing`, `exists=false`, `links=0`,
  `path_identity_stable=true`, and `canonical=false`. The action succeeded
  because diagnosis, not pin health, is its contract; it invoked no VPS SSH,
  TOFU, enrollment, lease, provider, Runtime, sandbox, payment, renewal, or
  cancellation mutation. Missing trust state is an explicit stop condition and
  is ineligible for mode-only or orphan-link recovery. P4 progression is stopped
  pending fresh independent verification of the exact run and an owner decision
  on whether to close this VPS canary or authorize a separately designed trust
  recovery with new evidence.
- Fresh whole-gate verifier `P4-R5-live-missing-verification-01` approved the
  exact merge/deploy/run chain and independently confirmed the two consistent
  no-follow observations, complete task/provider baseline, skipped mutation
  steps, and read-only backend/provider calls. Source and historical-run review
  found that normal deployment never targets the protected pin directory,
  guarded cleanup removed only the exact failed run directory, cancellation is
  backend-only, and successful TOFU cleanup removes only its hidden candidate.
  No audited path establishes why the canonical pin disappeared. P4.R5 is
  completed as a diagnostic, while P4 itself is blocked pending the owner choice
  to close this canary or separately authorize a new, reviewed trust-recovery
  design that explicitly accepts another first-contact trust event.

### Live acceptance phase P4.R6 authorization and design-review log

- The owner was told that a missing pin could not be restored under the prior
  contract and that continuation required a separately designed, reviewed
  re-trust path accepting another first-contact trust event. The owner's next
  instruction was `continue`. This authorizes exactly one P4.R6 attempt for the
  already cancelled and provider-live canary; it does not authorize a general
  reset, another VPS, payment, renewal, lease mutation, or a retry after
  ambiguous first-contact state.
- Read-only evidence review reconfirmed original protected TOFU run
  `34198472527` succeeded on exact commit
  `7ae91ba5745ba9f1ee436ae932d604f16a6f8d95`, but the retained job log contains
  no final fingerprint/digest output, the check output is empty, and the run has
  zero artifacts. Repository and plan history contain only the output template,
  not the observed value. Backend `sshFingerprint` is the owner login-key
  fingerprint, Runtime host keys remain empty because installation never began,
  and provider/task projections contain no server host-key identity. Therefore
  P4.A11 is false and the recovery must not claim continuity with the first pin.
- Fresh non-implementing reviewer `P4-R6-design-audit-01` returned `APPROVE WITH
  MANDATORY CONTROLS`: hard-bind the exact task/server/hostname/device/service/IP
  and both evidence-run IDs; explicitly acknowledge
  `ACCEPT-SECOND-FIRST-CONTACT`; commit an immutable unique backend claim before
  the one allowed `accept-new`; persist candidate/journal state; make every
  invocation after an existing claim strict-only; record a separate safe
  completion event; and refuse permanently on empty/ambiguous state or a later
  missing completed pin. It independently confirmed that no prior public host
  fingerprint/digest is recoverable.
- Entry gate: implementation is authorized at release revision 23, with the
  primary manager retaining plan and integration ownership. Frontend changes
  remain deliberately last. Current frontend `main` must be fetched and merged
  before the first edit and again immediately before PR integration; any
  conflict stops for owner direction. One bounded implementer may own the
  frontend diff, followed by two fresh non-implementing security/behavior
  reviewers. No live workflow dispatch occurs until exact-head CI, merge,
  production deployment, and a fresh read-only baseline inspection pass.
- First implementation gate: the bounded implementation passed its focused
  backend/operator suite, mocked Linux helper suite, site regression suite,
  migration cycle, Ruff, Bash syntax, ShellCheck, actionlint, and diff checks,
  but both fresh independent reviewers rejected promotion. This is a recovery
  of the implementation and executable oracle, not a change to the one-shot
  architecture or live authority. No production workflow was dispatched.
- Filesystem-security recovery controls are mandatory. Durably anchor creation
  of the per-task recovery directory by fsyncing its parent before the backend
  claim; prove the final pin is still stably absent with descriptor-relative,
  no-follow observations immediately before claim, including prepared-state
  replay; exclusively create and path-stably validate candidate, journal,
  journal-temporary, lock, and pin objects with owner/mode/type/link checks;
  reconcile an allowed journal-temporary crash residue only from the exact
  backend state; and avoid rewriting a valid completed journal on replay.
  Publication must fsync the final pin and containing directory before unlinking
  the exact same-inode candidate, then fsync the candidate directory. Every
  ambiguity, unexpected link, path swap, owner/mode change, or foreign entry is
  a permanent refusal and can never reopen `accept-new`.
- Backend/key-binding recovery controls are mandatory. Validate that claim and
  completion responses echo every frozen task, server, hostname, device,
  service, IP, original-run, diagnostic-run, deadline, and owner-fingerprint
  binding, not only status and pin metadata. Derive a public key from the
  selected private owner identity with `ssh-keygen -y`, fingerprint that
  protected derived public value without printing it, and prove it matches the
  task-authorized public-key fingerprint before either SSH mode. Recovery events
  have database-enforced one-row-per-task uniqueness and are append-only through
  the trusted operator path; a direct database owner remains inside the trusted
  boundary, so the plan does not claim a database trigger prevents that owner
  from updating or deleting rows.
- Executable evidence must no longer rely only on fake `ssh`, `flock`, or Docker
  shims. A Linux gate must run an isolated real OpenSSH daemon and the production
  helper against host key A for first observation and strict replay, then host
  key B for deterministic mismatch, while proving the exact owner private/public
  identity is used. Add crash-barrier and recovery tests for every durable
  transition; pin/journal/candidate/lock symlink and swap tests; owner, mode,
  type, and link-count matrices; completed and incomplete replay residue; and
  exact completion-response binding failures. Fresh filesystem-security and
  backend-contract reviewers must independently approve the corrected diff and
  executable oracle before exact-head CI or any live action.
- Second implementation gate: the corrected descriptor-bound helper and expanded
  real-OpenSSH/failure matrix passed the manager's native, Linux, PostgreSQL,
  migration, coverage, lint, and static gates, but the fresh filesystem reviewer
  found one remaining durability defect before promotion. A fully written
  `journal.json.new` crash residue was renamed into place and followed by a
  recovery-directory fsync without first fsyncing the held residue file. A
  process replay could therefore succeed while a later power loss exposed
  non-durable or corrupt journal bytes. No exact fault-injection assertion
  covered that barrier. Keep integration and live dispatch blocked; add the
  missing held-file fsync before rename, an executable fault/trace oracle for
  that ordering, then repeat the full affected gates and obtain fresh
  non-implementing approval. The same review also requires executable coverage
  for recovery-parent/task-directory creation, candidate file/directory,
  prepared/attempted/completed journal file/rename/directory barriers, pin
  appearance across the claim boundary, active lock-path replacement,
  `journal.json.new` type/mode/owner/link violations, and cleanup failure with
  strict-only replay. Temporary work cleanup must be part of successful outcome
  rather than silently suppressed. The runbook must explicitly treat the
  deployment UID, root, and their PATH-resolved `docker`, `ssh`, and
  `ssh-keygen` command environment as trusted; the descriptor checks do not
  claim isolation from hostile same-UID code. The fresh backend-contract review
  approved the operator scope after independent PostgreSQL lock probes showed
  child payment/reload inserts serialize behind the task-row lock and exact
  competing claims/completions produce one durable event.
- Final local recovery gate: the helper now fsyncs and revalidates a held complete
  `journal.json.new` before rename, makes allowlisted descriptor-bound temporary
  cleanup fatal, and emits success only after cleanup. The executable suite now
  covers all 13 directory/candidate/journal barriers, the full-residue promotion
  order and replacement race, pin appearance across claim, active lock
  replacement, `journal.json.new` metadata/type/link violations, and cleanup
  failure followed by strict-only replay. Manager gates passed the full site
  build and 209 tests (189 pass, 20 expected platform skips), 22 Linux recovery
  tests, a Python 3.8 compile, and a privileged 23-test real-OpenSSH run. Both
  fresh non-implementing reviewers returned `APPROVE`: the filesystem reviewer
  found no remaining TOCTOU outside the documented trusted deployment-UID/root
  boundary, and the backend reviewer independently passed 164 PostgreSQL tests,
  migration downgrade/upgrade, two-direction child-insert lock probes, unique
  event inspection, and the real A/A/B SSH oracle. Integration remains blocked
  only on the owner-required fresh `main` merge, post-merge tests, exact-head CI,
  production deployment, and the single protected live dispatch.
- Pre-PR integration gate: reviewed recovery commit `5a79d30` was created with a
  clean worktree. Frontend `origin/main` was fetched at `f287710` and merged
  cleanly as `97ecd7f`; no conflict or manual side selection occurred, and the
  merge touched only the newer Admin/checkout files outside P4.R6. On that exact
  merge head, Ruff, Bash syntax, ShellCheck, actionlint, diff checks, and lint
  passed with five pre-existing warnings; the site build and 210 tests passed
  with 190 passes and 20 expected platform skips; all 54 Admin tests passed; a
  fresh PostgreSQL database migrated to sole head `0037_host_pin_recovery`,
  downgraded to `0036`, re-upgraded, and passed 2,117 backend tests with one skip
  plus the 88.16% statement/75.12% branch gate; and the privileged Linux
  recovery suite passed 23/23 with the real isolated OpenSSH oracle. Exact-head
  hosted CI remains required before integration.
- P4.R6 integration and deployment gate: PR #125 exact head
  `97ecd7fedddc737bb26e165d99a8c15baa2557b8` passed hosted run
  `34281057996`. Immediately before integration, frontend `origin/main` was
  fetched again at `f287710`; it was unchanged, the branch remained cleanly
  mergeable, and no conflict or overwrite occurred. PR #125 merged as exact
  commit `1f651d5b0fb82222f0363156ec6433a679bfbc12`. Default-branch run
  `34281680792` passed test and four-image publication. Its first deploy attempt
  failed closed during candidate soak after a successful HTTP health response
  did not satisfy the complete readiness predicate; it occurred before nginx
  validation or public promotion, stopped the green services, restored the
  previous worker, and reported rollback success. Migration
  `0037_host_pin_recovery` remained applied. Twelve subsequent public health
  probes reported database, worker, compute inventory, refill notifications,
  and purchasing ready. One independently approved rerun of only the failed
  deploy job then passed on the same immutable merge: candidate soak, public
  verification, the five-minute rollback window, commit/drain, exact-release
  Admin promotion, bounded x402 header verification, and IndexNow all
  succeeded. No acceptance recovery workflow ran during either deployment, so
  the one-shot host trust authority remained unused.
- Fresh deployed-main recovery entry gate: protected read-only inspect run
  `34284706432` passed on exact merge
  `1f651d5b0fb82222f0363156ec6433a679bfbc12`, and only the inspection path ran.
  It reconfirmed the exact cancelled task/server/hostname, failure null, zero
  payment attempts, equal original expired deadlines
  `2026-09-08T07:33:04.758006Z`, Runtime `pending_install` at desired/applied
  revision `1/0` with three desired sandboxes, and provider device `69097`,
  service `315175`, IP `23.227.167.104`, and power `ON`. It performed no VPS
  SSH, pin, lease, provider, payment, Runtime, sandbox, renewal, or cancellation
  mutation. The next authorized external effect is the single exact P4.R6
  protected recovery dispatch; no blind retry is permitted after ambiguous
  first-contact state.
- Live P4.R6 first-contact result: the single exact recovery workflow run
  `34285138720` passed input validation, deployment-host pinning, and exact-main
  checkout, then failed closed with only
  `acceptance_host_pin_recovery_refused reason=first_contact_failed`. By the
  reviewed implementation order, the unique backend claim and durable
  `attempted` journal precede that SSH probe, so the second-first-contact
  authority is consumed and cannot be reopened. No final pin publication or
  completion event can precede this failure point. Protected read-only inspect
  run `34285327999` then reconfirmed unchanged cancelled/equal-deadline,
  zero-payment, provider-ON, Runtime revision `1/0`, and three-desired-sandbox
  state. Protected no-follow pin diagnostic run `34285408543` reported the
  canonical path still stably `missing` with zero links. No retry is authorized.
  The remaining ambiguity is deliberately narrower: SSH may have failed before
  receiving any host key, leaving the bound candidate empty, or it may have
  persisted one canonical candidate before owner authentication/command
  failure. Before requesting any new authority, add and independently review a
  read-only, exact-incident recovery-state diagnostic that reports only backend
  claim/completion state plus journal/candidate/pin classifications, never key
  bytes, SSH, TOFU, lease/provider/Runtime/sandbox/payment mutation, or a path
  that can create a missing claim.
- P4.R7 read-only recovery-state design gate: two fresh non-implementing
  reviewers approved a separate action with mandatory controls. It is bound to
  the same fixed task/server/hostname/device/service/IP, original trust run,
  missing-pin diagnostic run, original deadline, and failed recovery run
  `34285138720`; its exact confirmation is
  `DIAGNOSE-ACCEPTANCE-HOST-PIN-RECOVERY:task_bRE4vSeF8tE0a_bOLwq2FdTz:srv_ZvQaOP05rGycwcX4vcKBTQnN:private-procfs-canary-20260908:69097:34285138720`.
  The workflow retains the production environment and global production lock,
  rejects any submitted host-key value, and connects only to the already pinned
  deployment host. The helper must require, no-follow open, metadata/path
  revalidate, and nonblockingly lock the existing deployment lock without
  creating it. It may call only the existing read-only backend command
  `inspect-acceptance-host-pin-recovery`, before and after filesystem
  observation, requiring byte-equivalent exact `claimed` results with no
  completion.
- P4.R7 filesystem oracle is read-only and descriptor-bound. Existing
  `acceptance`, `host-pin-recovery`, exact task, and `trusted-known-hosts`
  directories must be owner-owned mode 0700. The exact recovery directory may
  contain only `journal.json`, `journal.json.new`, and
  `candidate.known_hosts`; a foreign entry is reported without its name.
  Journal classification is `missing|prepared|attempted|completed|malformed_or_mismatched|metadata_invalid|path_identity_unstable`;
  journal-new classification is
  `absent|present_complete|present_partial|metadata_invalid|path_identity_unstable`;
  candidate classification is
  `missing|empty|canonical_ed25519|malformed|metadata_invalid|path_identity_unstable`.
  Validate regular type, exact owner/mode 0600, one link, bounded contents,
  stable initial/held/final metadata, exact journal candidate device/inode
  equality without printing either value, canonical literal-IP Ed25519 data,
  and a stably missing final pin. The diagnostic performs no SSH/TCP probe,
  fsync, rename, unlink, cleanup, reconciliation, TOFU, strict replay, claim,
  completion, pin publication, or task/lease/provider/Runtime/sandbox/payment
  mutation.
- P4.R7 output is allowlisted. Exact claimed + attempted + empty candidate +
  identity match + absent journal-new + stably missing pin maps to
  `failure_class=pre_durable_host_key_capture` and
  `strict_replay_eligible=false`. Replacing empty with a canonical Ed25519
  candidate maps to `failure_class=host_key_captured_post_key_failure` and
  `strict_replay_eligible=true`; only its public algorithm, fingerprint, and
  file digest may accompany that result. Every other combination maps to
  `failure_class=ambiguous_or_exhausted` and false eligibility. Never print key
  bytes/base64, raw journal JSON, paths, UID/inode, owner token or keys, provider
  payload, environment, or SSH diagnostics. A canonical candidate proves only
  host-key capture, not continuity with the missing original pin or successful
  owner authentication. Required executable evidence covers exact workflow
  routing/binding, backend response mutation, all file metadata/type/link/swap
  cases, foreign entries, zero byte/inode/timestamp/event mutation,
  nonblocking/replaced lock, real Linux no-listener and rejected-auth setup
  fixtures while the diagnostic executes zero SSH, output redaction, Python 3.8
  grammar, Bash/ShellCheck/actionlint, full regressions, and two fresh reviews.
- P4.R7 implementation evidence: the frontend branch was first fast-forwarded
  to exact deployed `main` commit
  `1f651d5b0fb82222f0363156ec6433a679bfbc12` without conflict. The protected
  workflow now exposes only the exact incident-bound diagnostic, rejects
  submitted host-key bytes, retains the production environment/global lock,
  and dispatches a new deployment-host helper with failed run `34285138720`.
  The helper opens existing directories and the existing deployment lock with
  no-follow descriptors, uses nonblocking opens/locking, calls only the existing
  backend recovery inspector twice, and requires byte-identical exact claimed
  results. It observes journal, pending journal, and candidate twice across the
  second backend read and requires equal bytes plus device/inode/type/mode/
  owner/link/size/mtime/ctime metadata; any cross-window rewrite becomes
  `ambiguous_or_exhausted`. Review found and implementation corrected both a
  same-inode content-rewrite TOCTOU gap and a FIFO-open blocking gap before live
  use. A behavioral workflow oracle also found that separate `[[ ... ]]`
  commands could let an earlier failed fixed binding be masked by a later
  successful command under Bash `errexit`; the new action now uses one explicit
  compound exact-binding predicate with `|| exit 2`.
- P4.R7 executable evidence: Bash syntax, ShellCheck, actionlint,
  `git diff --check`, Python 3.8 grammar, Ruff, frontend lint, frontend build,
  the complete 221-test frontend suite, admin build, and all 54 admin tests
  pass locally (only pre-existing lint warnings remain). The focused native
  suite passes with expected macOS skips. A Linux container executes the
  recovery-state, backend-field, wrong-type/mode/owner/link, symlink/FIFO,
  foreign-entry, final-pin, lock contention/replacement, cross-window rewrite,
  redaction, and zero-byte/inode/timestamp/directory-entry mutation oracles.
  A privileged isolated Linux network run passes all 34 recovery tests with
  zero skips, proving both a no-listener empty candidate and a canonical host
  key captured before rejected owner authentication, followed in each case by
  a diagnostic trace containing zero SSH executions. Exact-head CI/deploy and
  the one protected production diagnostic remain gated on two final independent
  approvals and a fresh merge of `main`.
- P4.R7 final review gate: the independent filesystem/security verifier and
  backend/workflow-contract verifier both returned `APPROVE` with no blockers
  after the corrections and full executable matrix landed. They independently
  confirmed exact incident binding, no-create/no-follow/nonblocking observation,
  double backend reads, cross-window byte/metadata stability, stable missing-pin
  proof, redaction, zero diagnostic SSH or lifecycle mutation, accurate internal
  documentation, and `main` ancestry. No reviewer edited files or dispatched a
  live action.
- P4.R7 integration and deployment gate: frontend PR #126 used exact reviewed
  head `9a2026cec6d7d117ef875f5b19ee40b1f13c5507`. Immediately before the PR,
  `origin/main` was fetched and merged; it was already current at
  `1f651d5b0fb82222f0363156ec6433a679bfbc12`, so no conflict or manual side
  selection occurred. Exact-head workflow run `34291090496` passed. PR #126
  merged as `520b0ba5fa02073519b6e2092c2e6da112c48c09`. Default-branch run
  `34291570919` passed the 6m01s test job, four-image publication in 3m07s, and
  the 15m03s production deployment, including migration, blue-green service
  promotion, Admin promotion, bounded x402 header verification, and IndexNow.
- P4.R7 protected live diagnostic run `34293354294` executed once on exact
  deployed merge `520b0ba5fa02073519b6e2092c2e6da112c48c09`. Only validation,
  pinned deployment-host setup, checkout, and the diagnostic step ran. It
  reported the exact backend claim as `claimed`, journal as `attempted`,
  `journal.json.new` absent, candidate empty and identity-matched to the
  journal, final pin missing, no foreign entries, and stable recovery state.
  The resulting classification is `pre_durable_host_key_capture` with
  `strict_replay_eligible=false`. No VPS SSH/TCP probe, first-contact retry,
  strict replay, pin publication, lease, provider, payment, Runtime, sandbox,
  renewal, cancellation, or other lifecycle mutation ran.
- Post-diagnostic protected read-only inspect run `34293421043` passed on the
  same exact deployed merge. It reconfirmed the task is cancelled with failure
  null, zero checkout and payment attempts, the unchanged equal expired
  deadlines `2026-09-08T07:33:04.758006Z`, Runtime `pending_install` at
  desired/applied revision `1/0` with three desired sandboxes, provider request
  complete, and the same device `69097`, service `315175`, IP
  `23.227.167.104`, Ubuntu 24.04 image, and power `ON`. The diagnostic therefore
  changed no task, provider, Runtime, sandbox, payment, or billing state.
- P4.R7 completes with a fail-closed terminal result. The stable missing pin is
  a real live incident, while crash/barrier and adversarial TOCTOU triggers are
  lower-frequency but material correctness/security conditions. Review found
  and corrected an actual missing held-file fsync, same-inode rewrite window,
  FIFO blocking path, and Bash exact-binding masking defect before deployment.
  Because the live candidate is empty, P4.R6 has no host key that can be reused
  strictly and its consumed first-contact authority cannot be retried. Any
  further trust event on this VPS requires a new explicit owner decision and a
  separately frozen, reviewed recovery contract.
- Two fresh non-implementing live-evidence reviewers independently returned
  `APPROVE`. The first verified that the diagnostic emitted one allowlisted
  result, every mutation-capable workflow step was skipped, and the complete
  post-run inspection is byte-identical to pre-run inspect `34285327999`
  (canonical digest prefix `76bd1ce9`). The second independently confirmed the
  observed missing-pin incident, the corrected durability/TOCTOU defects, the
  live empty-candidate classification, and the documented residual trust in the
  deployment UID/root command environment. Neither reviewer edited files,
  dispatched workflows, contacted the VPS, or changed external state.

### Live acceptance phase P4.R8 frozen replacement-trust design

- Scope and authorization: P4.R8 exists only for task
  `task_bRE4vSeF8tE0a_bOLwq2FdTz`, server
  `srv_ZvQaOP05rGycwcX4vcKBTQnN`, hostname
  `private-procfs-canary-20260908`, provider device `69097`, service `315175`,
  and IP `23.227.167.104`. It binds original trust run `34198472527`,
  missing-pin run `34255110640`, exhausted recovery run `34285138720`,
  pre-capture diagnostic run `34293354294`, post-diagnostic inspect run
  `34293421043`, and original deadline `2026-09-08T07:33:04.758006Z`.
  The dispatch confirmation is exactly
  `ACCEPT-NEW-FIRST-CONTACT-AFTER-EMPTY-CANDIDATE:task_bRE4vSeF8tE0a_bOLwq2FdTz:srv_ZvQaOP05rGycwcX4vcKBTQnN:private-procfs-canary-20260908:69097:315175:23.227.167.104:34198472527:34255110640:34285138720:34293354294:34293421043:2026-09-08T07:33:04.758006Z`.
  The owner's `Yes run it on VPs` authorizes implementation and one protected
  live dispatch on this same device. It never authorizes P4.R6 replay, generic
  TOFU/reset, another VPS/order/payment/renewal, provider power/reload, or any
  lease, Runtime, sandbox, grant, selector, policy, or cancellation mutation.
- Backend state is a new dedicated append-only pair,
  `operator_acceptance_host_pin_retrust_claimed` and
  `operator_acceptance_host_pin_retrust_completed`. Each event type receives a
  globally unique partial index so the whole deployment can create at most one
  replacement claim and completion. Do not add a caller-selected attempt
  number, generic recovery sequence, mutable recovery table, or change/delete
  the old P4.R6 events. The claim and completion detail includes every frozen
  binding above, `parentFailureClass=pre_durable_host_key_capture`,
  `parentStrictReplayEligible=false`, owner-key fingerprint, frozen task/
  Runtime/sandbox state, and the exact P4.R6 claim event ID plus SHA-256 of its
  canonical JSON detail.
- Add a dedicated read-only `inspect-acceptance-host-pin-retrust` operator
  command. It validates the exact baseline and parent claim but never creates
  an event, and returns only exact `unclaimed|claimed|completed` state plus the
  safe frozen bindings and optional completion evidence. The helper must call
  it before any P4.R8 filesystem creation and again across state transitions;
  lost-response/crash replay begins from this inspector and cannot infer an
  unclaimed state or invoke a fresh claim path. The P4.R6 inspector and events
  remain unchanged.
- Both backend mutation operations lock, in order and in one transaction, the
  task row, Runtime row, and every existing sandbox row, then revalidate the
  exact cancelled test baseline: failure null, provider request complete,
  successful prior cancellation, zero checkout/payment attempts, null test artifact selector,
  equal original expired deadlines, no reload or lease-extension event/
  operation, Runtime `pending_install` revision `1/0`, and exactly the three
  desired persistent medium planner/builder/reviewer sandboxes. Provider access
  is read-only and must report the exact powered-`ON` device/service/FQDN/IP/OS/
  tags. Require exactly one byte-equivalent P4.R6 claim, no P4.R6 completion,
  and no existing mismatched P4.R8 event. Only a newly committed P4.R8 claim
  permits first contact. Lost responses return exact `claimed_replay`, never
  new authority. Completion repeats the locked checks, requires the exact claim,
  validates only canonical Ed25519 fingerprint/digest evidence, appends once,
  and permits only byte-identical replay.
- The protected workflow retains the production environment and global
  `warpmetal-production` concurrency group, rejects any host-key input, checks
  out exact deployed `main`, and reaches the VPS only through the already
  pinned deployment host. The helper obtains the existing deployment lock
  without creating/replacing it and validates all existing directories, task
  record, owner key/public key, old recovery state, and missing final pin through
  no-follow held descriptors. It derives the public key from the held private
  key descriptor with `ssh-keygen -y`, proves its fingerprint matches the task,
  and never reads or emits private-key bytes. The old P4.R6 backend rows,
  journal, candidate, directory entries, bytes, inodes, and timestamps are
  immutable forensic evidence throughout P4.R8.
- Before creating P4.R8 filesystem or backend state, run at most three bounded
  raw IPv4 TCP connections to `23.227.167.104:22`, requiring two consecutive
  `SSH-2.0-` identification lines within 15 seconds total. Each connection reads
  at most 1 KiB/four lines, sends zero bytes, performs no SSH key exchange,
  authentication, or host-key capture, and never logs the untrusted banner.
  Failure reports only `listener_not_ready`, consumes no claim, runs no SSH,
  and receives no automatic workflow retry. This is readiness evidence only;
  it neither authenticates the VPS nor removes the banner-to-SSH race.
- After readiness and a second exact baseline/old-state validation, create and
  fsync a separate
  `$HOME/warpmetal/acceptance/host-pin-retrust/<task-id>` directory, exclusive
  empty `candidate.known_hosts`, and `prepared` journal. Commit the globally
  one-off backend claim, write/fsync/rename the `attempted` journal, then perform
  exactly one `ssh root@23.227.167.104 true` using the held owner identity,
  isolated candidate, Ed25519-only `accept-new`, `/dev/null` SSH config and
  global hosts, disabled DNS/update/agent/proxy/forwarding/password/KBI/X11/TTY,
  one connection attempt, and bounded timeouts. Never use `ssh-keyscan`, SCP,
  a payload, ambient known hosts, or a shell other than forced `true`.
- Directory and journal durability ordering is explicit. Fsync `acceptance`
  immediately after creating the `host-pin-retrust` parent; fsync that parent
  after creating the task directory; fsync the empty candidate and task
  directory before claim; for every `prepared`, `attempted`, and `completed`
  journal transition, fsync the held complete journal-temporary file before
  rename and fsync the task directory after rename; and fsync the task
  directory after unlinking the exact candidate. Revalidate held/path identity,
  contents, type, mode, owner, and link count across every barrier.
- Successful first contact must prove exact public-key authentication from the
  bounded SSH diagnostic, validate and fsync one canonical literal-IP Ed25519
  candidate, revalidate all bindings and immutable old state, hard-link it
  without overwrite into the final pin path, fsync the pin and both directories,
  unlink only the exact same-inode candidate, and immediately run strict
  `true`. Revalidate the final pin, state, and old evidence before appending the
  safe completion and durably recording `completed`. Temporary cleanup is
  descriptor-bound, allowlisted, and fatal on failure. Output includes only
  exact public IDs, algorithm, fingerprint, digest, and state; never key bytes,
  journal JSON, paths, UID/inodes, banners, provider payload, environment, or
  SSH diagnostics.
- Terminal behavior is immutable. Preclaim banner failure consumes nothing.
  After claim, an empty/missing/malformed/ambiguous candidate permanently
  exhausts P4.R8 and replay executes zero `accept-new`; a canonical candidate
  or exact published pin permits strict-only continuation. A completed event
  with missing/mismatched pin permanently refuses. P4.R6 remains exhausted even
  after P4.R8 succeeds. A successful P4.R8 restores only strict host trust;
  P4.R4's fixed lease extension remains a later separate protected action.
- Frozen verification includes Alembic upgrade/downgrade and global uniqueness;
  exact binding/confirmation/response keys; parent-event digest and absence of
  old completion; claim/completion concurrency and row-lock races with payment,
  reload, lease, Runtime, and sandbox writes; provider mutation spies; complete
  directory/file/type/mode/owner/link/symlink/FIFO/swap/same-inode/crash-barrier
  coverage; immutable old-state and zero-lifecycle-delta snapshots; Python 3.8,
  Ruff, Bash syntax, ShellCheck, actionlint, full frontend/backend/Admin gates;
  and a privileged Linux network suite. The network suite covers refused,
  timeout, garbage, oversized and delayed banners with zero claim/SSH; proves
  banner probes send no application bytes; listener loss after readiness;
  Ed25519 A first contact/A strict replay/A-to-B mismatch; rejected owner auth
  with strict-only candidate replay; exact owner authentication; and zero
  `ssh-keyscan`, SCP, payload, secret, or diagnostic leakage.
- Entry gate: implementation is authorized at plan revision following
  `77eaf85`. The frontend branch was fetched and fast-forwarded to exact current
  `origin/main` `520b0ba5fa02073519b6e2092c2e6da112c48c09` before any frontend edit,
  with no conflict or manual side selection. Two fresh read-only design
  reviewers independently approved the dedicated global event pair, immutable
  P4.R6 evidence, preclaim banner readiness, one post-claim `accept-new`, strict
  replay, terminal behavior, and test matrix. One bounded implementer owns the
  frontend/backend/workflow/helper/test/runbook diff; two different fresh
  non-implementing reviewers must approve the final exact diff and executable
  gates. Immediately before opening a PR, fetch and merge current `main` again;
  any conflict stops for owner direction. No live contact occurs until exact-
  head CI, merge, production deployment, and a fresh read-only baseline inspect
  pass.

#### P4.R8 local implementation and review checkpoint

- Plan revision `e303d20` was committed and pushed before implementation. The
  frontend branch was fast-forwarded to `origin/main`
  `520b0ba5fa02073519b6e2092c2e6da112c48c09` before the first edit.
- The first independent review rejected live use for concrete defects: Python
  JSON equality admitted boolean/integer confusion, fingerprint checks were not
  canonical, pre-existing FIFO opens could block, the helper could create the
  deployment lock, the workflow did not require `main`, and candidate fsync
  followed rather than preceded the second backend inspection. One bounded
  recovery corrected every defect and added direct regressions.
- Stable post-recovery focused evidence passed: 108 backend DB/unit tests and
  16/16 Linux helper/workflow tests with zero skips, plus Ruff, Python
  compilation, Bash syntax, ShellCheck, actionlint, and `git diff --check`.
  Before the bounded fixes, the same integrated branch also passed 2,136 full
  backend tests with the coverage gate at 88.18% statements and 75.22%
  branches, 195 frontend tests plus build, and 54 Admin tests plus build; the
  exact-head hosted gate must repeat those suites. Five unrelated lint warnings
  remain unchanged. Two fresh non-implementing reviewers returned APPROVE.
- At the owner's direction to stop repeating speculative micro-edge expansion,
  P4.R8 does not add a second real-`sshd` A/A/B laboratory or a broader fsync-
  fault/symlink-swap matrix before this canary. The unchanged P4.R6 real-
  OpenSSH evidence, focused P4.R8 Linux oracles, exact-head hosted CI, and the
  authorized one-shot live P4.R8 execution form the proportional gate. This is
  an explicit evidence-scope adjustment, not a relaxation of the runtime trust,
  durability, terminal-state, or no-mutation contracts.
- No VPS, workflow, provider, payment, lease, Runtime, sandbox, or trust state
  was contacted or changed during implementation and local verification.
- The required second merge of current frontend `main` reported already up to
  date with no conflict. Exact-head PR run `34302886024` passed on attempt 2 at
  `6b9cbefe942054c51aafdce7019197a33649adc2`; attempt 1's sole failure was the
  unrelated existing Admin visual-browser error `Inspected target navigated or
  closed`, while all other gates passed and the same 54-test Admin suite had
  passed locally. PR #127 then merged without branch drift as
  `26c4e8ee4ac0bc2c61dc82a55610cfb97b754fd8`. Exact-merge production run
  `34303779250` passed tests and image publication, applied migration `0038`,
  then failed catalog readiness on one public API `curl` timeout and recorded a
  successful automatic rollback. Immediate official-CLI health and catalog
  probes were green across database, worker, compute inventory, and pricing.
  A fresh recovery reviewer is classifying whether one exact failed-job retry
  is safe; no live VPS action has begun.
- The fresh deploy-recovery reviewer returned `APPROVE_RETRY`: migration `0038`
  is additive and idempotent, rollback restored the prior public release and
  worker, and repeated read-only health probes were green. The one permitted
  failed-job retry of run `34303779250` then passed deploy, Admin promotion,
  the bounded x402 header check, and notification on exact merge commit
  `26c4e8ee4ac0bc2c61dc82a55610cfb97b754fd8`.
- Fresh protected inspect `34305995332` passed the frozen task/server/device/IP,
  provider-`ON`, zero-payment, `pending_install`, revision-`1/0`, three-sandbox
  baseline. The sole authorized P4.R8 run `34306043072` then failed with only
  `acceptance_host_pin_retrust_refused reason=listener_not_ready`. Per the
  frozen contract it was not retried. Post-failure protected inspect
  `34306150411` reports the same task/provider/Runtime/payment baseline; a fresh
  recovery reviewer is verifying the exact preclaim classification and next
  safe stop condition.
- The fresh live-failure reviewer returned `APPROVE_CLASSIFICATION`. Exact
  source ordering places `listener_not_ready` before the retrust directory,
  backend claim, and first `accept-new` SSH; executable tests prove this result
  creates no claim/state and sends zero bytes over at most three bounded TCP/22
  banner connections. The reviewer independently matched post-failure inspect
  `34306150411` to the frozen lifecycle baseline. P4.R8 is therefore blocked on
  external SSH-listener readiness, not consumed or terminal internally. The
  single authorized dispatch is finished: do not rerun unless the listener is
  restored and the owner gives new explicit attempt authority.
- Owner recovery authority: the owner's explicit `Ok do it` on 2026-09-08
  authorizes exactly one guarded reboot of the same existing provider device
  `69097` / server `srv_ZvQaOP05rGycwcX4vcKBTQnN`, followed by exactly one new
  P4.R8 dispatch only after the reboot reaches a terminal success state and a
  fresh protected inspection reconfirms the frozen task/server/device/IP and
  lifecycle baseline. Because the existing `canary-reboot` path requires the
  missing strict host pin and a working SSH session, add a narrowly bound
  deployment-host operator action that validates the frozen cancelled-task
  baseline, the unconsumed P4.R8 state, the provider's exact device/service/IP,
  and an exact confirmation before requesting the provider reboot. Its terminal
  provider evidence is narrowly defined as the partner VPS reboot response's
  canonical task UUID, durably recorded after the single forced-reboot POST,
  reaching terminal `Success` through GET-only polling, followed by the exact
  device returning powered `ON` and two SSH banners; this does not overclaim an
  observed boot-ID change. An ambiguous or failed provider result stops
  recovery. P4.R8 cannot claim without the byte-exact reboot completion and
  repeats its own two-banner preclaim gate as the final SSH-readiness oracle.
- Recovery attempt bounds and non-goals: do not reload, reinstall, replace,
  order, pay, renew, extend a lease, run P4.R6, alter Runtime or sandbox intent,
  or reset trust. The reboot is expected to preserve disk and host-key state,
  but P4.R8 must still establish the missing pin through its already reviewed
  exact first-contact contract. The single newly authorized P4.R8 run remains
  preclaim-safe if the SSH listener is not ready; a second listener failure or
  any post-claim failure stops with no retry loop and requires a new owner
  decision.

#### P4.R9 guarded reboot response reconciliation checkpoint

- The incident-only reboot implementation passed focused and full local gates,
  PostgreSQL integration tests, and two independent non-implementing reviews.
  PR #129 merged to `main` as `a049a2a`; exact-main production deployment run
  `34311162928` completed successfully. Protected pre-reboot inspection run
  `34313614790` reconfirmed the frozen task/server/device/IP and lifecycle
  baseline.
- The one authorized guarded reboot action ran exactly once as
  `34313748796`. It acquired its durable one-off claim, made the sole forced
  reboot POST, and then exited through the generic provider failure path in
  about five seconds. No reboot POST has been replayed. Three immediate
  zero-write TCP probes then independently observed the OpenSSH 9.6 banner on
  the previously unavailable listener, and protected post-run inspection
  `34313875167` proved the task, provider power, Runtime, sandbox, payment, and
  cancellation baseline unchanged.
- Two independent reviewers classified the generic failure as occurring after
  the claim and before durable provider acceptance or completion, but chat or
  SSH evidence was insufficient to choose the exact journal state. A new
  count-only, single-statement database inspector was therefore implemented
  and verified with no provider access or mutation. PR #130 merged as
  `84cd779`; production deployment `34315511170` passed its complete gate.
  Protected live inspection `34317315460` returned exactly
  `claimCount=1`, `providerAcceptedCount=0`, `completionCount=0` and otherwise
  preserved the frozen baseline.
- Assumption update: the earlier recovery design assumed the reboot POST's
  canonical provider task UUID would be durably recorded whenever the provider
  accepted the operation. Live evidence disproves that assumption for an
  ambiguous/lost POST response. The claim correctly prevents another POST, but
  the existing replay has no provider task UUID to poll and cannot progress.
- Initial design review correctly rejected an oracle based only on the public
  Hivelocity OpenAPI: it does not document numeric selection/tie semantics,
  metadata grammar, timestamp wire format, or persisted `force`. The locally
  available Hivelocity `core.hivelocity.net` source at commit `5bab690` has the
  same relevant file blobs as `origin/staging` and supplies the missing
  implementation evidence. Numeric `/network/status/{deviceId}` checks device
  ownership, returns the newest task ordered by creation descending, and then
  requires the task client to equal the authenticated current client. Task
  timestamps serialize as Unix seconds. VPS task creation persists metadata
  exactly `{"name":"reboot_vm","device_id":69097}` while passing `force` only
  to the asynchronous worker. Relevant frozen source blobs are network
  controller `0c5008b`, task service `57ce623`, schema `386ae54`, VPS controller
  `e7be73e`, and VPS task implementation `cd27220`.
- GitHub's immutable run record fixes the provider-call step to
  `2026-09-09T05:09:35Z` through `05:09:40Z`. The matching creation interval is
  the half-open five-second-cushioned window `[2026-09-09T05:09:30Z,
  2026-09-09T05:09:45Z)`, Unix seconds `[1788930570,1788930585)`. The exact
  deployed source and durable global claim prove WarpMetal reached at most one
  `reboot_vps(69097, force=True)` call in that interval. Provider metadata need
  only prove `reboot_vm` on device `69097`; `force=true` is deliberately bound
  causally to that one-shot local caller rather than invented as provider data.
- P4.R9 is the only authorized implementation scope. It may use only three
  provider reads in order: newest task for numeric device `69097`, that task's
  exact canonical UUID, then numeric device `69097` again. All three projections
  must be byte-equivalent for task UUID, device/client, parsed exact metadata,
  created/updated timestamps, and terminal `Success`. The numeric endpoint's
  ownership checks plus the exact task's provider account/config boundary bind
  client identity; the positive client integer is persisted only in the
  existing accepted event. The stable task, unchanged exact compute baseline,
  and two zero-write SSH banners permit the existing provider-accepted and
  completion events to be appended idempotently in transaction-safe order.
  Missing, unstable, mismatched, failed, nonterminal, malformed, or read-error
  evidence stops without event or lifecycle mutation.
- Evidence-scope decision: the provider surface cannot enumerate an older
  second identical reboot in the 15-second interval or prove `force` from task
  metadata. Requiring those provider-side facts would make the already-issued
  operation permanently unrecoverable without improving the actual safety
  invariant. Safety is instead provided by the globally durable pre-POST claim,
  exact deployed sole `force=True` caller, three stable owned-device task reads,
  exact compute identity, terminal success, current listener readiness, and
  P4.R8's independent preclaim banner gate. A hypothetical separate provider
  actor issuing an identical same-device reboot inside that interval is a
  recorded residual attribution ambiguity, not authority for another mutation
  and not a host-key trust bypass. This proportional adjustment follows the
  owner's direction to stop expanding low-probability edges while preserving
  double-mutation, lifecycle, and trust controls.
- Frozen non-goals and authority: zero provider POSTs; no second reboot, reload,
  order, payment, renewal, lease extension, Runtime/sandbox/grant/policy/trust
  mutation, P4.R6 retry, or P4.R8 dispatch before terminal reconciliation plus
  a fresh baseline inspection. The capability remains internal to this one
  acceptance incident and is not exposed to ordinary users or public APIs.
- Revised entry gate: implementation authorized by the owner's existing guarded-reboot
  and continuation direction because this path performs no new provider
  mutation and is necessary to finish the exact already-authorized operation.
  `main` was merged into the frontend working branch first and fast-forwarded
  without conflict to `84cd779`. One bounded implementer owns the backend,
  workflow, tests, and internal runbook diff. Separate read-only design and
  provider-contract reviewers must review the lookup/matching oracle; their
  initial rejection and the resulting evidence-scope correction are retained;
  two fresh non-implementing reviewers must approve the final exact diff and
  evidence before merge. Merge current `main` again immediately before opening
  a PR and stop for owner direction on any conflict. The phase gate is focused
  provider/operator tests, PostgreSQL incident tests, Ruff, Python compilation,
  workflow/security contract tests, full project regressions, exact-head CI,
  production deploy, one protected live reconciliation, and fresh protected
  inspection.
- P4.R9 implementation evidence: frontend/backend commit `cc874f8` adds the
  incident-only main-bound reconciliation action, strict numeric-device then
  exact-UUID then numeric-device provider reads, journaled GET-only crash
  recovery, final exact compute/listener verification, redacted output, and no
  public or ordinary-user surface. The branch was merged with current
  `origin/main` again after the implementation commit; it was already current
  at `84cd779`, so there was no conflict or main-side overwrite.
- P4.R9 verification evidence: Ruff, Python compilation, YAML parsing, and
  `git diff --check` passed. Focused non-database tests passed `182`; the fresh
  PostgreSQL 17 incident suite passed `45` with zero skips; the full backend
  suite passed `2215` with one unrelated environment-dependent skip; the full
  public-site build/test gate passed `196` with `41` documented platform skips;
  and the admin gate passed `54` plus its production build. A final reviewer
  found and the manager reproduced a real Bash `errexit` masking defect in the
  first workflow draft; the exact binding was combined into one fail-closed
  conditional and executable mismatch tests were added. Two independent
  non-implementing reviewers then returned `APPROVE_FINAL_EXACT_DIFF` on the
  corrected diff and evidence.
- P4.R9 merge and production evidence: exact-head PR #131 CI run
  `34321926726` passed at `cc874f8`; PR #131 merged as
  `88c2b20e94f6b65a73f0505cb082d18af69b901a`. Production run `34322363841`
  passed test, image publication, and deployment on its third attempt. Attempt
  1 hit the already-seen Admin visual-browser flake; attempt 2 passed that gate
  but rolled back safely after a public frontend probe timeout; the failed-job
  retry then passed the full deploy soak without a source change.
- The sole protected P4.R9 live reconciliation, run `34325544490`, stopped in
  about four seconds with `Acceptance host reboot reconciliation provider task
  is invalid`. The rejection occurred in the read-only strict provider-task
  projection before any provider-accepted event could commit. No provider POST,
  reboot, trust action, Runtime/sandbox change, payment, or lifecycle mutation
  is reachable from this reconciliation path. Fresh protected inspection run
  `34325601665` succeeded and returned exactly `claimCount=1`,
  `providerAcceptedCount=0`, `completionCount=0`; `inspect-task` emitted no
  additional JSON, so it did not establish a fresh lifecycle baseline.
- Independent recovery review therefore blocks P4.R8. The live provider record
  violates at least one frozen projection predicate (canonical task/device/client,
  exact metadata, creation/update time, or terminal `Success`), but the deliberately
  redacted generic failure does not identify which one. A retry would encounter
  the same evidence and is not authorized. Any continuation requires a newly
  reviewed, read-only characterization that reveals only safe predicate classes,
  followed by an explicit owner decision if the oracle itself must change.

#### P4.R10 rejected provider-task characterization checkpoint

- Scope is limited to identifying which frozen P4.R9 read stage or predicate
  rejected the live provider evidence. The diagnostic
  must first re-prove the exact task/server/hostname/device binding, unchanged
  P4.R6/P4.R8 recovery baseline, unclaimed retrust state, and reboot journal
  `claim=1`, `providerAccepted=0`, `completion=0`. A mismatch stops before provider
  access.
- The only provider operations replay the frozen read order: numeric device,
  exact UUID when the first UUID is canonical, then numeric device again. The
  diagnostic performs at most three GETs and no other provider call. Output is
  an allowlisted JSON classification for each stage: read
  `success|failed|not_attempted`; response `object|invalid`;
  task UUID `canonical|invalid`; device `exact|mismatch|invalid`; client
  `positive_integer|invalid`; metadata `exact|mismatch|invalid`; creation
  `within_window|before_window|after_window|invalid`; update
  `ordered|before_creation|invalid`; and result
  `success|pending|failure|other|invalid`. It also emits only
  `same|different|not_comparable` task-identity and full-projection stability
  classes. A noncanonical first UUID skips only the exact stage and still permits
  the second numeric read; a provider-read exception marks that stage `failed`
  and stops later reads. Provider values and failure text are never printed,
  persisted, or added to an event.
- The command and protected workflow are hard-bound to this incident and current
  `main`; they expose no public or ordinary-user surface. Tests must prove three
  ordered GETs for a canonical first UUID, two numeric GETs with the exact stage
  `not_attempted` for a noncanonical first UUID, bounded provider-read failure,
  zero POST/power/reboot calls, zero database writes/events, exact redaction, and
  fail-closed binding/state behavior. Two non-implementing reviewers approve the
  design and exact diff before the usual focused/full gates, second merge of
  current `main`, PR/CI/production deploy, and one live diagnostic dispatch.
- Diagnosis cannot itself authorize a P4.R9 replay, a relaxed provider result,
  P4.R8, or any VPS/trust/Runtime/lifecycle action. If it identifies a failed
  terminal task, deciding whether independent compute/listener evidence can
  establish the already-issued reboot requires a new oracle and explicit owner
  approval.
- P4.R10 implementation commit `17db3b1` adds only the incident-bound backend
  diagnostic, protected workflow action, internal runbook, and tests. Focused
  Python/workflow tests passed `207`; fresh PostgreSQL 17 incident tests passed
  `58`; affected Node workflow tests passed `25`; Ruff, compilation, YAML,
  static no-write call-graph, and diff checks passed. Full local gates passed
  backend `2260` with one environment-dependent skip, public `196` with `41`
  platform-dependent skips plus build, and Admin `54` plus build. Two independent
  non-implementing reviewers approved both the design and exact diff.
- Current `main` was merged before implementation as a conflict-free fast-forward
  to `88c2b20`, then fetched and merged again immediately before PR creation; it
  was already current and produced no conflict or overwrite. PR #132 exact-head
  run `34329243758` passed at `17db3b1`; the PR merged cleanly as
  `f448bdd9dc750bbd2a5b3028aaca8ed9d0473910`. Exact-merge production run
  `34329859852` passed test, four-image publication, blue-green deployment and
  soak, Admin promotion, and final bounded probes without retry.
- The sole protected live P4.R10 dispatch, run `34332349353`, succeeded. All
  numeric/exact/numeric reads returned the same stable canonical task with exact
  device, positive client, ordered update, and terminal `Success`; all three
  classified metadata `mismatch` and creation `before_window`. This proves the
  provider's newest visible record is an older unrelated task, not the authorized
  reboot. The diagnostic's successful entry gate re-proved journal `1/0/0`, and
  its reviewed call graph performs no provider or local mutation. P4.R9 cannot
  complete under its frozen oracle and P4.R8 remains blocked.

#### P4.R11 provider shutdown/boot recovery design

- Owner authority and purpose: on 2026-09-09 the owner explicitly directed the
  exact existing VPS to be powered off and brought back through the Hivelocity
  API. This is not a second reboot after boot; it is one OFF-to-ON power cycle
  replacing the unavailable reboot proof. The expected interruption is accepted.
  No reload, disk erase, order, payment, renewal, replacement VPS, lease,
  Runtime, sandbox, grant, policy, host-key, or cancellation mutation is
  authorized. The local WarpMetal CLI is version `0.8.8` but has no credential
  for this protected acceptance server, so execution remains confined to the
  credentialed production workflow/backend provider adapter and never handles a
  provider secret or ad-hoc raw HTTP request.
- Provider contract evidence: private Hivelocity source commit `5bab690` matches
  the relevant staged implementation. VPS-specific `POST /vps/{device}/stop`
  with `{"force":true}` and `POST /vps/{device}/start` each create and return a
  `NetworkTask`; exact metadata is `{"name":"stop_vm","device_id":69097}` or
  `{"name":"start_vm","device_id":69097}`. The task base records only terminal
  `Success`, `Failure`, or bounded `Failure: ...`; network task GETs provide
  canonical UUID, device, authenticated positive client, metadata, creation,
  update, and result. Frozen source blobs are VPS controller `e7be73e`, VPS task
  implementation `cd27220`, task base `2e1fcc1`, device controller `d153dc0`,
  device service `c0eb6bb`, and network controller `0c5008b`. The generic
  `/device/{device}/power` response is rejected for this incident because it
  returns only power status and does not directly expose the task UUID.
  A newly-created `Pending` task may have a null update timestamp; the oracle
  accepts that shape only until exact-UUID polling reaches `Success`, which
  requires a finite update timestamp no earlier than creation.
- State machine: add separate globally unique append-only
  `claimed -> provider_accepted -> completed` event chains for shutdown and
  boot. Both phases hard-bind the exact task, server, hostname, provider
  device/service/IP, failed reboot run `34313748796`, failed reconciliation run
  `34325544490`, characterization run `34332349353`, original deadline, old
  reboot journal `1/0/0`, unclaimed P4.R8 state, and frozen cancelled/
  zero-payment/null-selector/Runtime-`pending_install`-`1/0`/three-sandbox
  baseline. The shutdown claim commits before the sole stop POST. Boot cannot
  claim until shutdown has exact terminal success and compute is exactly `OFF`;
  its claim commits before the sole start POST. A claim without accepted task
  may only reconcile through the bounded latest-task and exact-UUID GETs and
  can never repeat that phase's POST. Completed replay is GET-only and
  idempotent. Each claim stores a 90-second creation window: 15 seconds of
  backward provider clock skew plus the provider client's 35-second
  connect/read timeout and bounded processing margin. The caller refuses its
  POST if that stored window has already expired. A non-secret digest of the
  provider routing-account key makes account drift fail closed.
- Provider-task oracle: validate the direct POST task and bounded
  numeric-device -> exact-UUID -> numeric-device projections for canonical and
  stable task UUID, exact device, one positive consistent client, exact phase
  metadata, creation inside the phase's durably recorded request window,
  ordered update time, and only terminal exact `Success`; the boot task must
  retain the shutdown task's provider client identity. Shutdown completion
  additionally requires the exact compute binding at power `OFF`. Boot task must
  be a distinct newer UUID; completion additionally requires the exact compute
  binding at power `ON` plus two consecutive bounded zero-write `SSH-2.0-`
  banners. Provider failure, malformed/unstable/mismatched evidence, task
  `Failure`, timeout, or baseline drift stops without advancing. A failed or
  ambiguous shutdown never sends boot unless exact terminal shutdown and `OFF`
  are established; an ambiguous boot can leave the VPS off and requires a new
  owner decision rather than a second start POST.
- Trust integration: the original reboot journal remains byte-equivalent at
  claim/accepted/completed `1/0/0`; P4.R9 never runs again and gains no synthetic
  completion. P4.R8 claim/completion accepts either the old exact reboot
  completion or exact completed P4.R11 shutdown and boot evidence while still
  requiring the old journal `1/0/0` in the P4.R11 branch. This changes only the
  listener-recovery prerequisite. P4.R8 retains its own two-banner preclaim
  gate, globally one-off claim, sole Ed25519 `accept-new`, durable atomic pin,
  and immediate strict replay without relaxation.
- Verification and integration gate: provider mutation-count/order spies; task
  UUID/client/metadata/time/result and POST-lost-response matrices; globally
  unique event and concurrent claim tests; claim-only GET reconciliation;
  OFF-before-boot and ON-plus-banner completion; old reboot/P4.R6/P4.R7/P4.R8
  immutability; migrations; Ruff/compile/YAML/Bash/ShellCheck/actionlint;
  focused and complete backend/frontend/Admin regressions; two fresh exact-diff
  reviews; merge current frontend `main` before implementation and again before
  PR; exact-head CI, merge, production deploy, one protected live power cycle,
  and a fresh protected inspection before any P4.R8 dispatch. Public docs,
  OpenAPI, CLI, LLM text, Runtime, sandbox image, and ordinary-user behavior are
  not affected.
- Entry gate: implementation authorized. The first required `main` merge was a
  conflict-free fast-forward to deployed commit `f448bdd` before edits. Two
  independent non-implementing reviewers approved the VPS-specific stop/start
  task interface, separate one-shot journals, GET-only replay, immutable old
  reboot evidence, and completed cycle as an alternative P4.R8 prerequisite.
  One bounded implementer owns the backend/provider/workflow/internal-runbook
  and test diff; two non-implementing reviewers must approve the exact result.
  No provider mutation occurs before those gates, a second clean `main` merge,
  exact-head CI, and deployment.
- Implementation gate: backend commit `9779ab3` implements the task-returning
  stop/start adapters, migration, six globally unique journal events,
  account/client/time-bound state machine, P4.R8 prerequisite integration,
  protected workflow, count-only inspection, internal runbook, and negative/race
  tests. The exact final pre-merge backend suite passed `2288` tests with one
  environment skip; Ruff, compile, migration, actionlint, build, and lint passed.
  The frontend suite passed `196` tests with 41 environment skips before the
  second merge, then `197` with 41 environment skips after it. Reviewers Kepler
  and Leibniz independently approved the exact final diff after the Pending
  null-update, account/client binding, 90-second window, concurrent-claim, and
  old-reconciler TOCTOU fixes. The required second `main` merge was conflict-free
  at `6f9cdca`; it made no backend source change. PR, exact-head CI/deploy, live
  P4.R11 dispatch, and fresh inspection remain open.

#### P4.R12 claim-only shutdown diagnostic checkpoint

- PR `#133` passed exact-head CI, merged as `aef9d2a`, and its production test,
  publish, and deploy jobs completed successfully in run `34358189868` before
  the first live P4.R11 action.
- The sole authorized shutdown dispatch `34361100741` committed the P4.R11
  shutdown claim and then received a provider exception. Protected inspection
  `34361745939` proved the old reboot journal remains `1/0/0`, shutdown is
  exactly `1/0/0`, and boot is exactly `0/0/0`. Required replay
  `34361869096` was GET-only and rejected the numeric provider-task response as
  invalid; it issued neither another stop nor any start. Do not invoke the
  P4.R11 power-cycle action again until a reviewed recovery explicitly permits
  it.
- Two independent reviewers concluded that the most likely response is the
  stable older P4.R10 task, whose creation precedes the shutdown claim window
  and whose metadata is not `stop_vm`; a newly created failed stop task or
  provider/source drift remains possible. Current evidence cannot distinguish
  those cases and cannot authorize boot.
- Freeze P4.R12 as a read-only, incident-only diagnostic. It must hard-bind the
  exact task/server/hostname/device and failed run IDs, re-prove P4.R8
  unclaimed plus the exact old reboot/shutdown/boot journal states, and retain
  the stored shutdown request window and provider-account digest. It performs
  at most one compute GET followed by numeric task, conditional exact UUID,
  and numeric task GETs through the same provider account.
- Output is limited to classifications: compute identity and `ON`, `OFF`, or
  other power; response/object and canonical UUID; exact device and positive
  client; exact `stop_vm` metadata; creation before, within, or after the
  durable claim window; null/ordered/invalid update; pending, success, failure,
  or other result; and task-identity/full-projection stability. It emits no raw
  UUID, client, metadata, timestamp, provider error, credential, or response
  body. It writes no database/event state and provides no provider POST or
  lifecycle/Runtime/sandbox/payment/trust mutation.
- Implementation commit `01ad256` adds the protected action, backend classifier,
  internal runbook, and executable contracts. The first implementation review
  identified a real provider-read/local-journal TOCTOU: valid provider evidence
  could otherwise be emitted after the required local state changed. The
  corrected diagnostic performs locked post-read revalidation of the complete
  incident baseline and provider-account digest, byte-identical shutdown claim
  and request window, old reboot `1/0/0`, shutdown `1/0/0`, boot `0/0/0`, and
  P4.R8-unclaimed state before emitting any classification. Its PostgreSQL race
  test advances the shutdown journal while a provider GET is paused and proves
  refusal with empty output and zero provider mutations.
- Local verification passed Ruff, compileall, actionlint, diff checking, `240`
  focused backend unit/workflow tests, `25` Node workflow tests, and the `19`
  P4.R12 PostgreSQL tests. The full frontend suite passed `198` tests with `41`
  environment skips, and the admin build plus all `54` admin tests passed. Two
  unrelated fleet tests fail without a database URL on both this diff and its
  exact pre-change baseline; with PostgreSQL, both files pass all `95` tests.
  Kepler and Leibniz independently approved the corrected implementation.
- The required second merge of current `main` was conflict-free at `dbe71a3`
  and changed only the unrelated `MANUAL_CHECKOUT_FRONTEND_PLAN.md`. Exact
  post-merge verification passed all `2330` database-backed backend tests with
  one environment skip, all `198` frontend tests with `41` environment skips,
  the admin build and all `54` admin tests, Ruff, compileall, actionlint, lint
  with no errors, and diff checking.
- PR `#136` passed exact-head CI run `34368572182`, merged as
  `24b83016addb4a12e7ff192abf11ed1045499e60`, and production run
  `34369351193` completed successfully at that exact SHA: test, publish, and
  deploy all passed, satisfying the deployment prerequisite for the protected
  live P4.R12 diagnosis.
- Protected live P4.R12 run `34372246548` completed successfully at the same
  exact deployed SHA. Compute was exactly bound and `ON`. Its numeric, exact,
  and repeated numeric task reads returned the same fully stable canonical
  task projection with exact device, positive client, exact `stop_vm` metadata,
  ordered update, and terminal success, but its creation classified
  `before_window`. It therefore is not evidence that the claimed P4.R11 stop
  was accepted. The run made no lifecycle or local-state mutation.
- Kepler, Leibniz, and Copernicus independently reviewed that allowlisted live
  result and all returned `BLOCK`: close P4.R12 as completed, retain P4.R11 at
  shutdown `1/0/0` and boot `0/0/0`, do not append recovery evidence, do not
  boot or replay P4.R11, and keep P4.R8 plus downstream P4.S1-P4.S3 blocked.
  Another stop request requires a new explicit owner decision and a separately
  frozen, reviewed one-shot recovery that preserves every existing journal.
- If P4.R12 proves one stable exact stop task inside the claim window with
  terminal `Success` and exact compute `OFF`, a separately reviewed GET-only
  recovery may append acceptance/completion for the existing claim and only
  then permit the already authorized boot phase. Any older/missing/failed or
  unstable task, or any state lacking that exact proof, leaves P4.R11 blocked;
  another stop request or relaxed boot oracle requires a new explicit owner
  decision.

#### P4.R13 newly authorized one-shot replacement power-cycle design

- Scope and authority: after the negative P4.R12 result, the owner explicitly
  authorized one additional stop request on the same VPS and a start only after
  verified `OFF`. This authorizes at most one `POST /vps/69097/stop` with
  `force=true` and, only after the stop completes under this oracle, at most one
  `POST /vps/69097/start`. It does not authorize reboot, generic device power,
  reload, a replacement VPS, payment, renewal, Runtime, sandbox, trust, or
  public-product mutation.
- Preserve forensic history. The old reboot journal remains exactly `1/0/0`,
  P4.R11 shutdown remains `1/0/0`, P4.R11 boot remains `0/0/0`, and P4.R8
  remains unclaimed. Do not append the new task to P4.R11's expired request
  window and do not reinterpret the P4.R12 classification. Add six distinct,
  globally unique P4.R13 event types: recovery shutdown and recovery boot,
  each with claimed, provider-accepted, and completed states. A reversible
  migration and matching model indexes enforce one global chain; every explicit
  PostgreSQL index name must remain within the 63-byte identifier limit.
- Hard-bind the protected main-only action and backend command to the exact
  task, server, hostname, device `69097`, service, public IP, frozen P4.R12
  evidence merge `24b83016addb4a12e7ff192abf11ed1045499e60`, failed P4.R11 run
  `34361100741`, inspect `34361745939`, GET-only replay `34361869096`, and
  P4.R12 run `34372246548`. The P4.R13 implementation SHA is unknown until its
  exact-head release gate and must be verified there before live dispatch. Each
  event privately binds the unchanged provider account digest and the canonical
  detail digest plus database identity of the original P4.R11 shutdown claim.
  No raw provider body or error is printed.
- Before the recovery-shutdown claim, re-prove the complete locked incident
  baseline and exact old journal counts, then use the same provider account for
  one exact compute GET and stable numeric-task, canonical exact-task, and
  repeated numeric-task GETs. Compute must be exactly bound, tagged, and `ON`;
  the task projection must be the stable terminal-success exact `stop_vm`
  pre-window shape established by P4.R12. Store its canonical identity,
  projection digest, client, and creation/update values privately as the
  pre-request watermark. Re-lock and revalidate the complete local baseline
  before committing the new shutdown claim and its bounded 90-second request
  window.
- Only the transaction owner that inserted the recovery-shutdown claim may
  issue the one forced stop POST after the claim commits. A direct response is
  accepted only when it is a canonical exact-device task whose positive client
  exactly matches the stored watermark/provider-account client, with an exact
  `stop_vm` task created inside the new window and distinct from and newer
  than the watermark. If the response is lost or malformed, the same invocation
  or any replay may use only stable numeric/exact/numeric GETs applying the same
  client equality to find that same qualifying new task; it never repeats the
  POST. Terminal stability checks retain that client binding. A crash after
  claim but before POST consumes the authorization.
- Persist provider acceptance only after locked revalidation of the immutable
  incident, original claim identity/detail digest, watermark, account digest,
  and current recovery state. Poll only the accepted UUID. Completion requires
  terminal `Success`, ordered finite timestamps, a stable terminal
  numeric/exact/numeric projection, and an independent exact compute GET showing
  `OFF`, followed by the same locked revalidation before appending completion.
  Power state without exact task proof never authorizes boot.
- Recovery boot is a separate P4.R13 journal. It may claim only after recovery
  shutdown is exactly `1/1/1`, the old journals are still unchanged, P4.R8 is
  unclaimed, and a fresh exact compute GET reports `OFF`. After committing the
  claim, which durably binds the recovery-shutdown completion event identity and
  canonical detail digest, perform a second exact `OFF` GET before the sole
  start POST. Accept only a canonical exact-device, exact-`start_vm` task inside
  its own window that is distinct from and newer than the recovery shutdown task
  and has the same positive provider client. Lost or malformed response recovery
  is GET-only and never repeats start.
- Recovery-boot completion requires its exact UUID to reach terminal `Success`,
  a stable terminal numeric/exact/numeric projection, exact compute `ON`, and
  two consecutive zero-write OpenSSH banners, followed by locked revalidation.
  A completed replay performs zero provider or local mutation. Claimed-only or
  accepted replay is GET-only; any expired, missing, failed, malformed,
  mismatched, unstable, or state-drifted evidence stops permanently.
- Update count-only protected inspection and P4.R8's internal listener-recovery
  prerequisite to recognize only the exact completed P4.R13 alternative while
  proving the old journals remain at `1/0/0`, `1/0/0`, and `0/0/0`. P4.R8 keeps
  its existing two-banner preclaim and one-shot trust contract and runs only as
  a later separate dispatch. Extend the existing aggregate inspection query with
  recovery-shutdown and recovery-boot counts only; expose no event detail. Once
  either P4.R13 claim exists, the old P4.R11 action and P4.R12 diagnostic must
  refuse before provider access or output so stale paths cannot confuse or alter
  the replacement evidence.
- Before freezing this phase, the frontend branch fast-forwarded without
  conflict to current `main` at
  `24b83016addb4a12e7ff192abf11ed1045499e60`; the Runtime plan branch was
  already current. Kepler and Leibniz independently approved the exact final
  six-event design after the command-manifest, client-binding, evidence-SHA,
  index-length, completion-digest, aggregate-inspection, and stale-path fixes.
- Required local gates: migration upgrade/downgrade and global uniqueness;
  binding, confirmation, baseline, original-claim digest, watermark, account,
  task UUID/device/metadata/client/time/result, power, listener, and redaction
  matrices; direct, lost, and malformed response recovery; crash-before-POST;
  concurrent claim and completion races; strict stop-before-start ordering;
  old-journal and P4.R8 immutability; claim-only/accepted/completed replays;
  focused and full backend/frontend/admin regressions; and two independent
  implementation reviews.
- Required release/live gates: current `main` was merged before this design;
  merge it again immediately before PR without overwriting conflicts; require
  exact-head CI and production deployment; run one fresh protected inspect;
  dispatch P4.R13 once; if it is claim-only, replay may be dispatched only to
  exercise its proven GET-only path; then inspect for old journals unchanged,
  recovery shutdown `1/1/1`, recovery boot `1/1/1`, provider `ON`, and P4.R8
  unclaimed before P4.R8. No live provider mutation occurs before all preceding
  gates and two independent approvals pass.

#### P4.R13 local implementation and review checkpoint

- The bounded implementation adds the six globally unique recovery events,
  reversible `0041_host_recovery_cycle` migration, protected main-only workflow
  action, count-only inspection, P4.R8 prerequisite extension, and internal
  operator runbook. It reuses the existing provider stop/start and task-read
  adapters; no Runtime, sandbox, image, public documentation, CLI, LLM text, or
  public frontend surface changed in this subpart.
- The first implementation review found no production-code defect but blocked
  promotion because the novel P4.R13 wiring lacked explicit negative and
  start-boundary coverage. The same bounded implementer added 19 PostgreSQL
  cases for watermark identity/device/client/metadata/result/update/stability
  and persisted digest mismatch; provider-account, original-claim, and shutdown
  completion drift; boot lost-response and failed discovery; crash-before-start
  permanent GET-only refusal; accepted exact-UUID replay; and concurrent start
  claim and completion. Every case proves exact provider mutation counts,
  recovery event counts, immutable old reboot/P4.R11 journals, and P4.R8 still
  unclaimed.
- Verification is green: the expanded incident database suite passed `129`;
  the full backend suite passed `2376` with one expected skip on a fresh
  PostgreSQL database; the site suite passed `198` with `41` expected skips out
  of `239`; the Admin production build and `54` tests passed; Ruff, compileall,
  actionlint, root ESLint with zero errors, `git diff --check`, and the sole
  Alembic-head check passed. Migration `0041 -> 0040 -> 0041` succeeded.
- Kepler and Leibniz independently returned `APPROVE_FINAL_EXACT_DIFF` after the
  correction. They confirmed claim-before-POST, GET-only claimed/accepted
  replay, stable exact-task and client attribution, the two independent `OFF`
  gates before start, exact one-start concurrency, completion idempotence,
  journal immutability, count-only output, and redaction. No live provider call,
  SSH, workflow dispatch, commit, or deployment occurred during implementation
  or review.
- The reviewed frontend implementation was committed as `7fb7dbe`. Immediately
  before PR creation, current `main` was fetched and merged again in both the
  frontend and Runtime plan repositories; both were already current, so there
  was no conflict and no `main` change to overwrite. Because the merge was a
  no-op, the approved and fully tested tree is unchanged.
- Release completed through PR `#137`, merged as
  `5f86baf99b4cfc017211940ebe0a9f4d362b0646`. Exact-head CI and production run
  `34382341038` passed, and the deployment reported that exact SHA. Protected
  preflight inspect `34384986161` showed the immutable old journals at reboot
  `1/0/0`, shutdown `1/0/0`, boot `0/0/0`, recovery shutdown and boot both
  `0/0/0`; read-only provider diagnostic `34385215817` independently showed
  exact bound compute `ON` and the stable pre-window watermark.
- The sole authorized P4.R13 dispatch `34385315340` committed recovery shutdown
  `1/0/0` and then rejected the provider task as invalid. The only permitted
  byte-identical replay `34385759794` exercised the claim-only GET path and
  rejected the provider task identically; it could not and did not repeat the
  stop POST. Post-run inspect `34385858403` showed recovery shutdown `1/0/0`,
  recovery boot `0/0/0`, and every old journal unchanged. The stop authority and
  replay are exhausted, no start occurred, and P4.R13 must never be dispatched
  again.

#### P4.R14 terminal recovery-shutdown diagnostic design

- Scope and non-authority: P4.R14 is one incident-only, protected, main-only,
  GET-only diagnostic named
  `diagnose-acceptance-host-recovery-shutdown-task`. It exists only to classify
  why P4.R13 could not validate provider task evidence. Its implementation must
  remove/disable `recover-acceptance-host-power-cycle` from the workflow choices,
  workflow dispatch, operator CLI parser, and operator dispatch so the old path
  refuses before provider access or stdout. It cannot call P4.R13, append
  acceptance/completion, authorize another stop or replay, authorize a start,
  or relax the P4.R13 oracle. It performs zero WarpMetal/local database, event,
  Runtime, sandbox, payment, trust, task, SSH, or host mutation and issues zero
  provider write-method or lifecycle request.
- Hard-bind the workflow and command to task
  `task_bRE4vSeF8tE0a_bOLwq2FdTz`, server
  `srv_ZvQaOP05rGycwcX4vcKBTQnN`, hostname
  `private-procfs-canary-20260908`, device `69097`, service `315175`, IP
  `23.227.167.104`, deployed P4.R13 SHA
  `5f86baf99b4cfc017211940ebe0a9f4d362b0646`, and runs `34384986161`,
  `34385215817`, `34385315340`, `34385759794`, and `34385858403`. One exact
  confirmation string must contain that complete binding. Require both
  `refs/heads/main` and `ref_name=main`, exact inputs, and empty host-key input
  in one fail-closed workflow branch.
- Before provider access, lock and validate the complete incident baseline:
  old reboot `1/0/0`, old shutdown `1/0/0`, old boot `0/0/0`; recovery shutdown
  exactly `1/0/0`, recovery boot exactly `0/0/0`; and P4.R8 unclaimed. Require
  exactly one P4.R13 shutdown claim with its unchanged database identity and
  canonical-detail digest; unchanged provider-account digest and original
  P4.R11 claim identity/detail digest; the exact stored 90-second request
  window; and a valid persisted watermark with canonical UUID, projection
  digest, positive client, ordered finite timestamps, and exact old `stop_vm`
  projection. Capture the validated local snapshot and claim identity/detail
  for the post-read check.
- Using only the claim-bound provider account, perform exactly: one compute GET,
  first numeric latest-task GET for device `69097`, an exact UUID GET only if
  the first result has a canonical UUID, then a second numeric latest-task GET.
  A noncanonical first UUID skips only the exact read. A provider exception
  classifies that stage as failed and stops all later reads. There is no polling,
  retry, SSH, listener probe, POST, start, stop, reboot, reload, create, delete,
  or generic provider-write path.
- The Hivelocity implementation behind both task-status GET routes calls
  `finish_expired_tasks()`, which can change an expired provider-side `Pending`
  task to `Failure:*` and commit that provider-internal bookkeeping. P4.R14
  cannot promise absolute provider-state immutability while using these GETs;
  its frozen guarantee is zero client-issued provider write-method/lifecycle
  request and zero WarpMetal/local mutation. A returned `failure` classification
  may have been materialized by that GET-side timeout behavior and is diagnostic,
  never authority.
- Emit one JSON object made only from this exact vocabulary. `read` is
  `success|failed|not_attempted`; `response` is
  `object|invalid|not_attempted`; `taskUuid` is
  `canonical|invalid|not_attempted`; `device` and compute `binding` are
  `exact|mismatch|invalid|not_attempted`; `client` is
  `positive_integer|invalid|not_attempted`; `clientVsWatermark` and
  `identityVsWatermark` are `same|different|not_comparable`; `metadata` is
  `exact_stop_vm|mismatch|invalid|not_attempted`; `creationVsClaimWindow` is
  `before|within|after|invalid|not_attempted`; `creationVsWatermark` is
  `newer|not_newer|invalid|not_attempted`; `update` is
  `ordered|null|invalid|not_attempted`; `result` is
  `pending|success|failure|other|invalid|not_attempted`; task-identity and
  full-projection stability are `same|different|not_comparable`; and compute
  `power` is `ON|OFF|other|not_attempted`. Exact `Failure` or a value beginning
  `Failure:` maps to `failure`; any other string not equal to `Success` or
  `Pending` maps to `other`; a non-string non-null result maps to `invalid`.
  Never print a UUID, client, timestamp, request window, metadata, event ID,
  digest, account key, raw compute field, provider body/error, exception text,
  host key, or credential.
- After all reads, reacquire the established task-to-Runtime-to-sandboxes locks
  and revalidate the byte-identical complete baseline, local snapshot, claim,
  watermark, account, journals, and P4.R8 state. Any concurrent drift exits
  before stdout. Provider instability may only appear as a safe classification;
  it is never converted into recovery evidence.
- Required tests cover every command/workflow binding mismatch including both
  main-ref values and nonempty host-key input; all journal, claim, detail,
  watermark, account, original-claim, window, and post-read drift failures;
  exact GET order/count, conditional exact GET, exception-stop behavior, every
  compute/task/stability enum, and sentinel redaction. Database snapshots and
  SQL/event-write spies must prove zero insert/update/delete; provider spies
  must fail on stop/start/reboot/reload/create/delete/generic write methods;
  SSH, listener, payment, lifecycle, claim, completion, and recovery functions
  must fail if reached. Tests must also prove the retired P4.R13 workflow and CLI
  path are unreachable before provider access/output. Run focused
  PostgreSQL/workflow/unit tests, Ruff, compileall, actionlint, full
  backend/site/Admin regressions, migration-head checks, and two independent
  exact-diff reviews.
- Decision semantics are evidence-only. Stable distinct, newer, same-client,
  in-window exact `stop_vm` terminal success plus exact compute `OFF` may support
  proposing a separately reviewed reconciliation phase under the already
  conditional start authority. An unchanged watermark with compute `ON`
  suggests no attributable new stop task. Pending, failed, mismatched, unstable,
  malformed, or contradictory evidence remains inconclusive. P4.R14 itself
  never names or outputs an eligibility/authorization decision. Any oracle
  change needs a new reviewed phase and explicit owner decision; another stop is
  forbidden.
- Before freezing this design, the frontend branch fast-forwarded without
  conflict to current `main` at `5f86baf99b4cfc017211940ebe0a9f4d362b0646`;
  the Runtime plan branch was already current. Kepler and Leibniz independently
  returned `APPROVE_FROZEN_P4_R14` for this exact read sequence, state binding,
  retired P4.R13 route, truthful provider-GET side-effect boundary, fixed enum
  vocabulary, redaction contract, local zero-mutation proof, and non-authority
  rule. Implementation, review, release, and live dispatch remain gated.

#### P4.R14 implementation and final-review checkpoint

- The bounded implementation is committed as `0d817f4`. It retires the P4.R13
  action from the protected workflow choice, validation/checkout/job routing,
  operator CLI parser, and operator dispatch, so the old command cannot reach
  provider access or stdout. It adds only the exact P4.R14 operator function,
  protected main-only workflow action, internal backend runbook text, and their
  focused database/workflow/CLI tests; no public UI, public API, Runtime,
  sandbox, image, public documentation, CLI product, or LLM surface changed.
- The diagnostic validates the frozen P4.R13 claim-only baseline before reads,
  performs only compute plus numeric/conditional-exact/numeric GETs, classifies
  the fixed enum grammar, and locks/revalidates the full snapshot before its
  single JSON stdout object. The exact zero-write test bombs the generic
  provider request path, every public provider mutation method, operator
  lifecycle/payment/claim/completion entry points, event writes, and SSH; SQL
  write listeners and complete database snapshots independently prove no local
  insert/update/delete.
- Independent verification passed: focused P4.R14 PostgreSQL tests passed `63`;
  the final incident PostgreSQL file passed `193`; workflow/operator unit tests
  passed `210`; the complete backend suite passed `2441` with one expected skip
  on a fresh PostgreSQL database; the full site build/test suite passed `198`
  with `41` expected skips out of `239`; Admin build and `54` tests passed. Ruff,
  compileall, actionlint, `git diff --check`, and migration-to-head all passed.
  A final test-only mutation-spy expansion and runbook clarification were
  rechecked by the affected PostgreSQL test and all static gates; production
  code remained byte-identical after the full regression runs.
- Kepler first blocked on incomplete generic/provider/operator mutation bombs
  and an ambiguous lease-replay sentence. Copernicus made only those bounded
  test/runbook corrections. Kepler and Leibniz then independently returned
  `APPROVE_FINAL_EXACT_DIFF` for the exact committed tree. Neither verifier made
  edits or live/provider/SSH/workflow/Git actions.
- Immediately before PR creation, both repositories fetched and merged current
  `main` again; both were already current and there was no conflict or newer
  `main` change to overwrite. The exact reviewed frontend head
  `0d817f41200050dd6cabdc29060597d538c93e7a` and this plan branch are pushed.
  Release remains gated on PR exact-head CI, exact production deployment, and
  one protected P4.R14 live diagnostic. No lifecycle request, SSH, workflow
  dispatch, or provider read occurred during implementation or review.
- PR `#138` run `34391742087` passed the backend, Ruff, and lint gates but found
  one stale site-test regex: the runbook now names the safe replay as the exact
  `extend-cancelled-test-lease` action and explicitly says that rule does not
  apply to P4.R14. The test-only correction at `7525e13` asserts both clauses
  and tolerates the adjacent Markdown line reflow; it changes no production
  path. The direct file passed `9/9`, the full local site build/test passed
  `198` with `41` expected skips out of `239`, `git diff --check` passed, and
  Kepler and Leibniz independently returned `APPROVE_TEST_ONLY_FIX`. The branch
  was still current with `main` and had no conflicts before this correction was
  committed and pushed. Exact-head CI is pending.
- The corrected head passed exact CI run `34393118845`, but `main` then advanced
  to `6221325` through PR `#139`. It was merged into the branch without textual
  conflicts. Independent semantic review caught two newly introduced mutable
  fields that the frozen incident baseline did not yet bind:
  `PurchaseTask.hosted_checkout_replacement_used` and
  `ServerRuntime.automatic_install_deadline`. Commit `8613d89` now requires
  them to remain exactly `false` and `null`, respectively, under both initial
  and locked post-read validation, and covers initial mismatch plus concurrent
  drift. A fresh PostgreSQL instance upgraded through migration `0043` and
  passed all `31` affected tests; the merged workflow/operator unit set passed
  `219`, the lease test passed `9`, and Ruff, compileall, and diff checks passed.
  Kepler and Leibniz independently returned `APPROVE_POST_MAIN_CORRECTION`; a
  final fetch found `main` unchanged, and exact-head CI run `34394844207` is
  queued for `8613d896d5e086685ec9b915882c2f15f3a797fb`.
- Exact-head CI run `34394844207` passed. PR `#138` merged as
  `122f7d5669e824428cd176d72b968f19825f4ec8`, and production run
  `34396989738` passed its merge-SHA tests, four image publications, migration,
  blue-green candidate soak, rollback-observation window, Admin promotion, and
  final production checks.
- The sole P4.R14 live diagnostic run `34399716626` completed successfully on
  that exact deployed merge. Compute was exactly `ON`. Numeric-first, exact-
  UUID, and numeric-second task reads were fully stable and all classified the
  same canonical, exact-device, exact-`stop_vm`, terminal-success task as the
  pre-claim watermark: client and identity were `same`, creation was `before`
  the P4.R13 claim window and `not_newer` than the watermark, update ordering
  was valid, task identity was `same`, and the full projection was `same`.
  Therefore no attributable P4.R13 stop task was created or discovered, the
  frozen `OFF` threshold was not met, and no start, stop, P4.R13 replay,
  P4.R14 retry, or P4.R8 dispatch is authorized. Kepler independently returned
  PASS for P4.R14 completion; Leibniz independently confirmed the next gate is
  blocked pending a separately frozen/reviewed listener-recovery phase and new
  explicit live-attempt authority.

#### P4.R15A frozen listener-readiness diagnostic design

- Scope and exact binding: add only the protected main-only action
  `diagnose-acceptance-host-listener-readiness`, bound to deployed frontend SHA
  `122f7d5669e824428cd176d72b968f19825f4ec8`, failed P4.R8 run
  `34306043072`, post-run inspect `34306150411`, deployment run
  `34396989738`, P4.R14 run `34399716626`, task
  `task_bRE4vSeF8tE0a_bOLwq2FdTz`, server
  `srv_ZvQaOP05rGycwcX4vcKBTQnN`, hostname
  `private-procfs-canary-20260908`, provider device `69097`, service `315175`,
  and literal IPv4 `23.227.167.104`. The action requires an empty
  `host_public_key_base64` input and exact full-SHA/main-ref validation.
- Network authority: the workflow may make one control-plane SSH connection to
  the already-trusted deployment host using strict existing host trust; it may
  not use accept-new or discover/change that trust. The deployment-host helper
  may not invoke SSH, SCP, SFTP, `ssh-keyscan`, or any host-key exchange,
  authentication, host-key capture, or trust operation against the acceptance
  VPS. It performs only literal-IPv4 TCP listener reads, transmits zero bytes,
  creates at most three connections in one 15-second global window, reads at
  most 1 KiB/four lines from each, and succeeds only after two consecutive
  printable lines beginning exactly `SSH-2.0-`.
- Filesystem authority: open the existing deployment, acceptance, trusted-pin,
  and P4.R8 parent paths by descriptor with no-follow type/owner/mode/link
  checks. Open the pre-existing `.deployment.lock` read-only with `O_NOFOLLOW`,
  validate it, and take the established nonblocking exclusive advisory lock;
  never create/truncate it with shell redirection. Before the first backend
  verifier and after the second, prove descriptor-stably absent exactly the
  final trusted pin
  `acceptance/trusted-known-hosts/private-procfs-canary-20260908` and the P4.R8
  path `acceptance/host-pin-retrust/task_bRE4vSeF8tE0a_bOLwq2FdTz`; the latter
  parent may be securely absent or securely opened. The helper creates no
  candidate, journal, pin, key, known-hosts, temporary, or work file.
- Backend authority: the helper calls one exact internal verifier before and
  after the network probe. Each call validates and snapshots under the existing
  task-to-Runtime-to-sandboxes lock order; requires the frozen cancelled task,
  provider account/binding, `hosted_checkout_replacement_used=false`,
  `automatic_install_deadline=null`, Runtime pending-install desired/applied
  `1/0`, exact three medium sandbox intents, P4.R8 unclaimed, old reboot
  `1/0/0`, P4.R11 shutdown `1/0/0`, boot `0/0/0`, P4.R13 recovery shutdown
  `1/0/0`, recovery boot `0/0/0`, and the exact P4.R13/P4.R14 claim/watermark
  evidence; performs exactly one compute GET through the bound account; requires
  exact device/service/IP and compute `ON`; then locks and revalidates the same
  snapshot/account. Across the diagnostic there are exactly two verifier calls
  and at most two compute GETs. No event, SQL write, claim, completion, SSH,
  payment, Runtime/sandbox, or lifecycle function is allowed. Tests can prove
  zero client-issued provider write/lifecycle requests; provider GET internals
  remain opaque and must not be described as physically side-effect-free.
- Output and failure: only after successful post-verification and final stable
  absence checks may stdout contain one fixed object with
  `listenerReadiness` equal to `ready` or `not_ready`. Any binding, baseline,
  filesystem, lock, backend, compute, network, redaction, or concurrency error
  exits with no stdout. Never emit a provider body/error, raw field, path,
  key/fingerprint, signature, account identifier, event identifier, task UUID,
  client, timestamp, request window, or internal exception.
- Tests: exact workflow choice and binding, main/full-SHA, empty host-key input,
  strict deployment-host SSH, acceptance-host SSH-family command bombs, lock
  contention and descriptor swap/type/owner/mode/link matrices, absent-to-present
  races, pre/post verifier failures, exact two-call/two-GET ceiling, full
  database snapshot and SQL-write spies, provider write/lifecycle method bombs,
  bounded banner variants, zero transmitted bytes, no filesystem creation, and
  safe stdout/stderr redaction. Run focused PostgreSQL/workflow/helper tests,
  Ruff, compileall, Bash syntax, ShellCheck, actionlint, full backend/site/Admin
  gates, migration-head checks, and two independent exact-diff reviews.
- Decision semantics: `not_ready` stops and supports only a separately designed
  provider/support recovery proposal. `ready` proves only listener readiness,
  not identity, and never unlocks P4.R8. After a ready result, implementation or
  dispatch of any later P4.R8 trust attempt requires a fresh explicit owner
  approval. P4.R15A consumes no P4.R8 claim and never changes any old incident
  journal. A zero-write diagnostic is intentionally replayable in code, but the
  plan authorizes one protected live dispatch only.
- Review evidence: Leibniz returned `APPROVE_FROZEN_P4_R15A`; Kepler approved
  the exact SSH/input/SHA/lock corrections; Copernicus returned
  `APPROVE_FEASIBILITY` for the bounded helper/backend/workflow surface. No
  implementation or live mutation has occurred.

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
