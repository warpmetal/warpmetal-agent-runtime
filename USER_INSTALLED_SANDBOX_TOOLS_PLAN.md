# User-installed sandbox tools plan

Status: active managed execution

## Project details

- Objective: ship WarpMetal Agent Runtime sandboxes as signed, hardened base
  environments without Codex CLI, Claude Code, Cursor CLI, or Gemini CLI
  preinstalled or configured.
  Ordering selects sandbox capacity only. After connecting, each owner installs
  and authenticates only the tools they want in the persistent sandbox home.
  Add a token-free CLI adapter that installs one concrete, hardened OpenSSH
  alias per sandbox grant so ordinary `ssh <alias>` clients and Codex Desktop
  can use the existing forced gateway without receiving a VPS owner identity,
  a host shell, a sandbox SSH daemon, or a new public port.
- Target users and use cases: all Agent Runtime users, including users who want
  a general development sandbox, users who install one AI CLI, and users who
  install several CLIs that share one outer Runtime sandbox with their child
  processes and subagents.
- Success measures:
  - the signed image contains none of the four documented AI CLIs, their pinned
    packages, Cursor archive, vendor configuration, tool manifest, or WarpMetal
    tool reporter;
  - a non-root user can install executables beneath persistent `/home/agent`
    without `sudo` or a writable container root, and those executables remain
    on `PATH` after sandbox restart/recreation with the same workspace;
  - new order, sandbox-create, catalog, CLI, UI, OpenAPI, and public-doc
    contracts contain no AI-CLI selection or preinstallation promise;
  - public documentation gives separate, current, user-owned install,
    authentication, sandbox/approval, update, and removal guidance for Codex,
    Claude Code, Cursor CLI, and Gemini CLI without treating them as catalog
    features or readiness requirements;
  - order-time Hivelocity cloud-init still verifies and installs signed Runtime
    v0.1.26 before reconciling the requested sandboxes;
  - production instant ordering exposes an enabled Agent Runtime sandbox
    control for every eligible plan and certified live-cloud-init OS after the
    exact v0.1.26 plus signed base-image tuple passes its release gate;
  - the selected sandbox count, sizes, names, lifetimes, resource limits,
    grants, restart, deletion, and image refresh behavior remain intact;
  - obsolete nested Bubblewrap/AppArmor implementation is removed from future
    Runtime and CLI releases without changing immutable v0.1.25/v0.1.26 assets.
  - CLI v0.8.10 installs a concrete OpenSSH alias from an already-pinned,
    token-free connection profile and sandbox-specific key; interactive and
    one-shot SSH remain forced into exactly the assigned sandbox;
  - alias installation, explicit refresh, and cleanup preserve unrelated SSH
    configuration, use private atomic files, fail closed on collisions or a
    changed host pin, and never print profile/key/host-key contents;
  - Codex Desktop discovers and uses the alias after Codex is installed and
    authenticated inside the CLI-free sandbox; Cursor IDE support is claimed
    only if its current Remote SSH workflow passes the same boundary.
- Scope:
  - `warpmetal-agent-sandbox`: remove the bundled AI CLIs and their manifest,
    reporter, validation code, and fixed-version copy; retain general shell,
    Git, SSH, Node/npm, Python, browser-QA dependencies, and outer hardening;
    expose a conventional persistent user-local executable path without
    configuring any vendor CLI or package-manager preference;
  - `warpmetal-agent-runtime`: remove future nested-private-procfs packaging
    and installation code. Keep selected-tool reconciliation only where it is
    demonstrably required to preserve already-created legacy sandboxes;
  - `agent-kit`: preserve its already capacity-only sandbox request contract,
    remove nested-policy activation guidance, accept catalog/sandbox responses
    without tool metadata, and update source/plugin skill references with the
    four optional user-installed CLI examples; add the hardened local OpenSSH
    alias install/refresh/remove flow; retain exact compatibility for immutable
    v0.1.25/v0.1.26 bundles and add the stripped future bundle shape;
  - `warpmetal_frontend`: last, remove tool selection from request/catalog/UI,
    update schemas and public docs, preserve internal legacy-row handling, pin
    the new signed base image, and retain v0.1.26 cloud-init provisioning;
  - acceptance: validate locally first, then on the existing test VPS, and use
    only the already-authorized unpaid test-order path for a fresh order smoke.
- Non-goals:
  - no arbitrary image, cloud-init, command, mount, environment, or raw resource
    input from checkout;
  - no automatic provider login, credential injection, vendor configuration,
    version choice, update, or uninstall;
  - no host-wide privilege relaxation and no nested Bubblewrap guarantee;
  - no sandbox SSH daemon, sandbox-specific public port, VPS owner identity,
    host-shell escape, forwarding exception, or client-side `RemoteCommand`;
  - no automatic mutation of existing user sandboxes merely to remove a legacy
    preinstalled tool;
  - no removal of Playwright/browser testing support in this change.
- Constraints and compatibility:
  - merge current `main` into every implementation branch before edits and
    again immediately before opening its pull request; never resolve a conflict
    by overwriting newer `main` work without owner direction;
  - Runtime v0.1.26 and CLI v0.8.9 releases are immutable; the new command
    requires a separately tested CLI v0.8.10 release;
  - production cloud-init's exact v0.1.26 archive-member allowlist must retain
    the four inert nested-policy files present in that signed archive;
  - CLI 0.8.9 and Runtime v0.1.26 already work when `cliTools` is empty: Runtime
    does not invoke the image reporter for an empty selection;
  - existing database columns/rows for selected tools may remain as a private
    migration compatibility layer until legacy sandboxes are retired; new
    public requests must not create them;
  - deployment, release publication, PR merge, and production traffic changes
    occur only after their automated gates and the required authority.
- Dependencies:
  - a new signed `linux/amd64` base image digest;
  - provider-compatible cloud-init and signed Runtime v0.1.26;
  - validated production configuration for both the approved Runtime artifact
    and approved sandbox-image digest before catalog activation;
  - the existing test VPS and its protected SSH trust path;
  - official provider installation/configuration instructions for the four
    user-installed CLI examples.
- Current-state evidence:
  - the current signed image bakes Codex 0.153.4, Claude Code 2.1.263, Cursor
    2026.09.02, a `warpmetal.agent-tools.v1` manifest, and a reporter;
  - Gemini CLI is not currently baked into the image or selectable in ordering;
  - Runtime v0.1.26 calls the reporter only for a non-empty desired tool list;
  - checkout/catalog currently expose `cliTools`, `tools`, `toolManifest`, and
    `allToolsInstalled`; the order parser accepts per-sandbox `cliTools`;
  - production currently reports OS-level Runtime compatibility but aggregate
    product `agentRuntime.supported: false`, so instant checkout keeps the
    sandbox control disabled;
  - cloud-init invokes v0.1.26 `install.sh` without a nested-policy flag and is
    independent of CLI selection;
  - the outer Podman sandbox remains read-only except for persistent
    `/home/agent` and `/tmp`, so user installations must target the home volume.

## Requirements and acceptance

| ID | Requirement or risk | Observable acceptance criterion | Verification level |
|---|---|---|---|
| R1 | No baked/configured AI CLIs | `codex`, `claude`, `agent`, `cursor-agent`, and `gemini` are absent in a fresh image; package, Cursor archive, manifest, reporter, and vendor system-config files are absent | image integration, artifact inspection |
| R2 | User-installable persistent tools | UID 1000 installs a local fixture beneath an explicitly chosen home prefix without `sudo`; executable/config bytes survive restart/recreate on the same home volume | image integration, live end-to-end |
| R3 | Capacity-only order contract | New order and sandbox-create requests contain name, size, lifetime/expiry only; `cliTools` is rejected as an unsupported field and the UI renders no tool selector | unit, OpenAPI contract, browser |
| R4 | Stable sandbox image selection | Every new sandbox reconciles to the configured signed base-image digest even without a selected tool | backend/runtime integration |
| R5 | Cloud-init preserved | Hivelocity create receives valid cloud-init that downloads, verifies, and installs signed Runtime v0.1.26 and reaches runtime/sandbox ready | unit, contract, unpaid live order |
| R6 | Legacy safety | Existing rows with an old tool selection and old desired image are not silently rebound or mutated; immutable releases remain installable | migration/compatibility tests |
| R7 | Nested implementation retired | Future Runtime bundles contain no AppArmor/bwrap helper/policy/oracle and new CLI/public docs expose no nested enable option | release artifact, CLI, docs |
| R8 | Outer isolation preserved | UID/GID 1000, read-only root, writable home, cap-drop ALL, no-new-privileges, default seccomp, non-host network, no runtime socket | image/runtime integration, live inspection |
| R9 | Tool ownership/authentication | WarpMetal neither installs/configures AI tools nor receives provider credentials; installs, configuration, login, updates, and removal happen after SSH connection | API/docs inspection, log redaction |
| R10 | Lifecycle unchanged | create, access grant, concurrent sessions, restart with workspace continuity, revoke, refresh, and delete remain functional | Runtime regression, live end-to-end |
| R11 | Four accurate optional-tool guides | Public and agent guidance separately covers Codex, Claude Code, Cursor CLI, and Gemini CLI using current official sources, explains the outer sandbox, and makes no installation/readiness guarantee | docs contract, link/source inspection, rendered HTML/LLM parity |
| R12 | Instant ordering activated | Production `/catalog` reports `agentRuntime.supported: true` for eligible plans and `agentRuntimeSupported: true` for certified live-cloud-init OSes; checkout enables sandbox selection and an unpaid test order provisions v0.1.26 plus the signed base image | catalog/API/UI contract, deployment smoke, unpaid live order |
| R13 | Standard OpenSSH alias | `warpmetal sandbox access install-ssh --connection-file <profile> --identity <key> --alias <alias>` installs a concrete discoverable alias and `ssh <alias>` plus `ssh <alias> '<command>'` enter only the assigned sandbox | CLI unit/integration, live SSH |
| R14 | Local trust/config safety | The CLI revalidates the closed token-free profile and every API fingerprint, requires a safe regular sandbox identity, writes one dedicated known-hosts file and config fragment atomically at owner-only modes, refuses unsafe aliases/paths/collisions/accidental overwrite, and returns only safe metadata and paths in JSON | CLI unit/security tests |
| R15 | Explicit refresh and cleanup | Exact reinstall is idempotent; any managed endpoint, identity, or host-pin change fails closed unless the caller supplies `--confirm REFRESH`; refresh consumes an already-refreshed profile without silently observing/trusting a network key; removal requires `--confirm REMOVE` and preserves unrelated aliases/config | CLI unit/integration |
| R16 | Gateway boundary unchanged | Generated config includes `IdentitiesOnly yes`, strict pinned known hosts, disabled password/keyboard-interactive auth, `ClearAllForwardings yes`, no agent/X11 forwarding or local commands, and no `RemoteCommand`; wrong/revoked keys, host shell, SFTP/SCP/forwarding, stale pins, and active revoked sessions are denied or terminated by existing Runtime controls | exact-config test, Runtime tests, live SSH |
| R17 | Codex Desktop compatibility | A concrete alias is visible through OpenSSH, direct SSH succeeds, and Codex Desktop can start the remote Codex app server after the user installs/authenticates Codex so `codex` is on the sandbox login-shell PATH | official-contract inspection, local resolver test, live/manual app smoke |
| R18 | Truthful client/tool guidance | CLI help/README, source and plugin skills, Runtime operator docs, public docs, and machine-readable docs show interactive and one-shot Codex/Claude/Cursor CLI use, provider authentication in the sandbox, distinct keys/grants per sandbox, refresh/removal, and the tested Cursor IDE result without weakening forwarding controls | docs/parity tests, official-source audit, live compatibility |

## Architecture

- System context and boundaries: cloud-init installs the signed supervisor on
  the VPS. The supervisor creates one rootless Podman container per sandbox from
  the configured signed base image. The container is the security boundary for
  all user tools and any subagents they launch.
- Components and responsibilities:
  - image owns general-purpose prerequisites and user-local install defaults;
  - Runtime owns container lifecycle, resource isolation, workspace persistence,
    grants, and image pinning, not AI-tool installation;
  - backend owns capacity validation, signed artifact/image configuration,
    Hivelocity cloud-init, and public contracts;
  - UI/CLI collect sandbox capacity and lifecycle intent only;
  - users and tool vendors own installation, update, authentication, and tool
    behavior after connecting.
- Interfaces and contracts:
  - public sandbox request fields: `name`, `size`, optional `lifetime`, optional
    `expiresInSeconds`; `cliTools` is no longer accepted;
  - catalog Runtime fields: `supported`, `capacity`, `sizes`, and
    `temporaryLifetime`; no tool inventory or preinstallation boolean;
  - aggregate support is true only when the plan has capacity and production
    has the approved signed Runtime v0.1.26 artifact plus the approved signed
    CLI-free image digest; OS eligibility additionally requires the provider's
    live `cloudInit: true` signal;
  - internal Runtime manifest retains global `imageDigest` and sandbox resource,
  lifecycle, generation, and optional explicit refresh digest fields;
  - legacy tool fields remain private compatibility data only while required.
  - the local SSH adapter consumes only connection profile v1, an absolute
    sandbox identity path, and one concrete alias. It neither calls the API nor
    consumes an owner token. It writes a managed include at the beginning of
    `~/.ssh/config`, one `~/.ssh/warpmetal.d/<alias>.conf` fragment, and one
    `~/.ssh/warpmetal.d/<alias>.known_hosts` file. All three files are private
    and updated with create-exclusive staging plus atomic rename; the include
    is activated last on first install.
  - the generated host block contains the profile host/port, fixed
    `warpmetal-sandbox` user, sandbox identity, dedicated known-hosts path,
    `IdentitiesOnly yes`, `StrictHostKeyChecking yes`,
    `PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
    `ChallengeResponseAuthentication no`, `ClearAllForwardings yes`,
    `ForwardAgent no`, `ForwardX11 no`, and `PermitLocalCommand no`. It omits
    `RemoteCommand` and `RequestTTY`, allowing both interactive shells and
    client-supplied exec commands to reach the server-side forced command.
- Data flow and persistence: user-local binaries, configuration, and credentials
  live under `/home/agent`, which is the persistent workspace volume. Container
  root remains read-only and replaceable. `/home/agent/.local/bin` is on PATH,
  but WarpMetal does not write npm, Codex, Claude, Cursor, or Gemini
  configuration.
  Users explicitly choose a home-local install prefix and all tool settings.
- Failure modes and recovery:
  - invalid/unknown `cliTools` fails with the standard unsupported-field error;
  - a user tool download/install failure changes no Runtime desired state;
  - image publication or canary failure leaves production on the old digest;
  - v0.1.26 cloud-init verification retains its exact legacy archive list;
  - the one test host with an enabled nested policy is cleaned once using the
    signed v0.1.26 disable path before that compatibility path is retired.
  - a concrete alias already present in any non-managed SSH config fails before
    writes. Existing managed files with exact content are an idempotent replay;
    changed profile, host key, endpoint, identity, or generated fragment fails
    closed until the caller repeats the install with `--confirm REFRESH`.
    Refresh never discovers a host key from the network: the owner first runs
    the authenticated `sandbox access refresh` profile flow, reviews its safe
    fingerprint metadata, then explicitly replaces the local pin.
- Authentication and authorization: VPS owner and per-sandbox SSH grants remain
  unchanged. AI-provider authentication happens inside the assigned sandbox;
  WarpMetal stores no AI-provider token and does not authorize tool actions.
  The installed alias uses only the sandbox-specific identity; it never falls
  back to other agent keys because `IdentitiesOnly yes` is mandatory. Each
  sandbox/client receives a distinct key and grant so revocation remains exact.
- Security and privacy: no credentials in image layers, cloud-init, order data,
  Runtime manifests/reports, logs, or public task responses. User-installed code
  runs with the existing UID, capabilities, seccomp, network, filesystem, and
  cgroup restrictions.
- Error handling, logging, and observability: remove tool-probe readiness/error
  claims for new sandboxes. Retain stable Runtime lifecycle errors and bounded,
  credential-free logs. Installation failures are ordinary in-sandbox command
  failures and must not be reported as supervisor readiness failures.
- Deployment, migration, and rollback: publish and sign base image; deploy
  capacity-only contracts with the new digest while still provisioning Runtime
  v0.1.26; activate instant ordering only after the exact tuple passes; roll
  back by disabling aggregate catalog support and restoring the previous
  configured image/catalog deployment without modifying workspace volumes.

## Documentation and API contracts

- Image/operator docs: sandbox `README.md` and image tests.
- Runtime operator/security docs: Runtime `README.md`, `SECURITY.md`, release
  artifact tests.
- CLI docs: agent-kit help, README, source/plugin skill mirrors.
- SSH-client docs: install, exact replay, authenticated profile refresh plus
  explicit alias refresh, removal, interactive `ssh <alias>`, and one-shot
  `ssh <alias> '<command>'` examples. Codex Desktop is documented from the
  official concrete-alias/login-shell contract. Cursor IDE is marked supported
  only after an actual Remote SSH test; otherwise docs state the forwarding
  limitation and show Cursor Agent CLI inside the sandbox.
- Canonical API: `backend/public/openapi.json`, generated by
  `scripts/sync-openapi-agent-runtime.mjs` and checked for drift.
- Public docs: `/agent-runtime`, `/docs`, localized `messages/{en,es,pt}.json`,
  `content/llms.md`, and byte-identical `backend/public/llms.txt`.
- Migration guidance: existing sandboxes are not silently refreshed; new
  sandboxes contain no AI CLI; users install tools after connecting.
- Four optional-tool guides, each with an explicit ownership boundary:
  - Codex: user chooses a home-local install method, login, approvals, and the
    `--sandbox danger-full-access` option or equivalent user config when relying
    on WarpMetal's outer sandbox. WarpMetal writes no Codex config.
  - Claude Code: user installs to a home-local prefix, starts its interactive
    authentication, and chooses its permission mode. WarpMetal does not enable
    any permission-bypass flag.
  - Cursor CLI: user runs the current official installer after inspection,
    retains its files below home, authenticates with the current vendor command,
    and owns updates/removal.
  - Gemini CLI: user installs to a home-local npm prefix, authenticates with the
    chosen Google method, and normally leaves Gemini's optional Docker/Podman
    sandbox disabled because WarpMetal exposes no host container-engine socket.
    Approval mode remains user-owned.
- Canonical official sources to revalidate immediately before docs are written:
  - OpenAI Codex getting started: <https://help.openai.com/en/articles/11096431>
  - Anthropic Claude Code setup: <https://docs.anthropic.com/en/docs/claude-code/getting-started>
  - Cursor CLI installation: <https://docs.cursor.com/en/cli/installation>
  - Gemini CLI installation/auth/sandbox: <https://github.com/google-gemini/gemini-cli/tree/main/docs>

| Capability or interface | Required document / contract | Owner | Verification | Status |
|---|---|---|---|---|
| Base image and home install path | sandbox README | image | image test + inspection | completed |
| Capacity-only request/catalog | OpenAPI + checkout docs | frontend/backend | schema drift + API tests | pending |
| Runtime v0.1.26 cloud-init | backend/deploy docs | backend | cloud-init exactness tests | current, regression required |
| Instant-order activation | catalog/checkout/deploy runbook | frontend/backend | production catalog + checkout + unpaid-order smoke | pending |
| Legacy compatibility | migration/operator docs | backend/Runtime/CLI | fixture tests | pending |
| Four user install/config/auth examples | public docs + llms + agent-kit skill | frontend/agent-kit | locale/render/parity/source-link tests | pending |
| Concrete sandbox SSH alias | CLI help/README + source/plugin skills + Runtime/public docs/llms | agent-kit/runtime/frontend | exact output, path/mode/collision tests, rendered parity, live SSH | pending |
| Codex Desktop and Cursor compatibility | public docs + machine docs + CLI/skill references | frontend/agent-kit | official source audit and actual client smoke | pending |

## Error handling and logging

| Error or event | External behavior | Log level and safe fields | Recovery / alert | Verification |
|---|---|---|---|---|
| `cliTools` supplied to new request | HTTP/CLI validation error, no write | info: request/task correlation and code only | remove field and retry | API/CLI negative test |
| base image unavailable | existing `runtime_image_unavailable`, no reconcile | error: task/server IDs and digest metadata, no token | restore/pin signed digest | backend tests |
| user tool install/config/auth fails | shell/tool exit only; Runtime remains ready | no new control-plane event | user retries/follows current vendor docs | live bounded test |
| cloud-init Runtime install fails | existing attention-required flow | existing safe Runtime install codes | no payment/order replay unless existing rules permit | cloud-init/order tests |
| Runtime/image activation tuple missing or mismatched | catalog remains unsupported and checkout stays disabled | error: safe version/digest/config component only | correct signed configuration and rerun activation gate | catalog/config tests |
| unsafe alias/path or unmanaged alias collision | exit 2 before any write | no log; bounded stable reason and safe path only | choose a safe unique alias/path | CLI negative tests |
| managed alias content differs | exit 2; preserve every existing byte unless `--confirm REFRESH` | no profile, host key, or private-key content; safe alias/path only | authenticate profile refresh, review safe fingerprint out-of-band, explicitly refresh | CLI mutation tests |
| stale host pin after VPS reload | OpenSSH host-key failure; no fallback trust | OpenSSH bounded error only | refresh the authenticated profile, then explicitly refresh alias | local/live SSH |
| revoked or wrong sandbox key | access denied; active revoked session terminated | Runtime stable grant/session code, no key material | create a new grant/key if authorized | Runtime/live SSH |

## Authentication and authorization

- Applicability: unchanged and required for VPS owner, Runtime node, and
  per-sandbox grant boundaries.
- New authority: none. Tool installation is performed by authenticated sandbox
  users as UID 1000 and cannot write the container root.
- Local alias installation is token-free and grants no new server authority. It
  materializes already-issued profile data and a caller-owned sandbox key into
  OpenSSH files. Authenticated API access remains required to issue/revoke the
  grant or refresh the connection profile after a reload/key rotation.
- Denials: unauthorized/cross-owner sandbox access, invalid/revoked grant, and
  expired node token retain existing behavior and tests.
- Secrets: provider tokens live only in persistent sandbox home files or process
  environment chosen by the user; docs must warn against order/cloud-init use.

## Decisions

| Decision | Options considered | Choice and evidence | Consequences |
|---|---|---|---|
| Tool delivery | bake all, selectable bake, user install | user install; owner direction and persistent home boundary | smaller neutral image; user controls version/update |
| Sandbox boundary | nested bwrap or one outer container | one outer rootless Podman sandbox | no nested AppArmor feature or guarantee |
| Tool configuration | image-owned defaults or user-owned settings | no vendor or package-manager settings in the image | users must configure install prefix, sandbox, approvals, login, and updates |
| Install location | root/global, home-local, custom image | user-selected path beneath persistent home | works with read-only root and survives replacement |
| Legacy records | drop/mutate, reject all, private compatibility | preserve old rows/image pins; create no new selections | temporary internal compatibility code remains |
| Launch Runtime | require new Runtime or use v0.1.26 empty selection | keep signed v0.1.26 for launch | cloud-init path stays proven while future code is simplified |
| Gemini status | add as supported/preinstalled/selectable or document as optional | optional user-installed example only | no catalog/API/readiness expansion |
| Instant-order activation | enable early or after exact tuple acceptance | enable only after v0.1.26, signed CLI-free image, cloud-init, and lifecycle gates pass | current disabled state is temporary but remains fail-closed until verified |
| SSH integration | custom wrapper only, new sandbox sshd, owner key, or standard alias over forced gateway | standard concrete alias over the existing forced gateway | ordinary OpenSSH and Codex Desktop work without expanding server authority |
| Managed SSH files | edit arbitrary blocks, overwrite config, or private managed include | prepend one stable include, separate per-alias fragment/pin, exact replay plus explicit refresh/remove | bounded reversible local changes; collisions and drift fail closed |
| Cursor IDE | relax forwarding/SFTP restrictions or test honestly | preserve all restrictions; claim IDE support only on a passing current-client test | headless `agent` remains documented when Remote SSH is incompatible |

## Assumption ledger

| ID | Assumption or unknown | Impact if false | Status | Evidence or resolution |
|---|---|---|---|---|
| A1 | v0.1.26 skips reporter for empty `cliTools` | high | verified | `toolreport.Probe` returns immediately and reconciler handles empty desired list |
| A2 | `/home/agent` is writable/persistent and root is read-only | high | verified | Runtime Podman create arguments mount the workspace at `/home/agent:rw` with `--read-only` |
| A3 | Hivelocity accepts existing generated cloud-init | high | verified baseline; regression pending | current focused backend cloud-init tests pass and prior live order reached Runtime |
| A4 | all four provider installers can target a user-chosen path beneath home | medium | partly verified; executable tests pending | npm explicit prefix works for Codex/Claude/Gemini; Cursor documents `~/.local/bin` |
| A5 | no active production row requires new selected-tool readiness | high | unresolved | must be checked read-only before deployment; compatibility retained regardless |
| A6 | new image can omit reporter with v0.1.26 empty selections | high | verified in source; artifact/live pending | reporter invocation is conditional on non-empty desired list |
| A7 | current instant-order disablement is the aggregate product gate rather than OS cloud-init incompatibility | high | verified from production catalog evidence | OS rows are true while product `agentRuntime.supported` is false |
| A8 | Codex Desktop discovers concrete aliases and launches remote `codex` through the login shell | high | verified from official OpenAI documentation on 2026-09-11 | concrete `~/.ssh/config` alias, working `ssh <alias>`, and remote `codex` on PATH are explicit prerequisites |
| A9 | Runtime v0.1.26 already maps both empty interactive sessions and client-supplied commands through one grant-specific forced command | high | source-verified; live alias test pending | gateway passes `SSH_ORIGINAL_COMMAND` and TTY state only to the assigned sandbox; no host-shell route exists |
| A10 | Codex can be installed into persistent home and appear on the sandbox login-shell PATH without changing the CLI-free image | high | prior existing-VPS install verified; Desktop smoke pending | image keeps `/home/agent/.local/bin` on PATH and the user owns installation/authentication |
| A11 | Cursor Remote SSH can work without dynamic forwarding, SFTP, or SCP | medium | unresolved; expected false from current extension invocation evidence | current extension commonly launches `ssh -T -D`; actual test must decide documentation, never policy relaxation |
| A12 | OpenSSH follows the managed include and resolves the exact hardened options before later wildcard defaults | high | executable local resolver test pending | test `ssh -G <alias>` against real generated files and fail if any required option is absent or overridden |

## Test strategy

- Write image tests first that require AI commands/artifacts/config absent and a
  UID 1000 local fixture install using an explicit persistent-home prefix;
  current image must
  fail those assertions before Containerfile changes.
- Write Runtime/release tests first for a stripped future bundle and absence of
  nested policy behavior; current source/archive shape must fail.
- Write agent-kit tests first for no selection/nested option plus version-aware
  old/new Runtime bundle validation; current CLI help/parser must fail.
- Write backend/frontend contract tests first for capacity-only requests/catalog
  and image readiness independent of tool observations; current API/UI must fail.
- Keep and run cloud-init, paid/test-order, Runtime registration, lifecycle,
  resource, auth, revocation, redaction, locale, OpenAPI, and llms parity suites.
- Add an activation contract proving absent or mismatched Runtime/image
  configuration keeps support false, the exact approved tuple makes support
  true, checkout becomes selectable, and sandbox intent is accepted before
  payment.
- Add CLI tests before implementation for closed profile/fingerprint parsing,
  safe concrete aliases, private regular identity requirements, exact OpenSSH
  rendering and `ssh -G` resolution, atomic 0700/0600 modes, no partial writes,
  unmanaged and managed collisions, exact replay, explicit changed-pin refresh,
  safe JSON, and remove behavior preserving unrelated configuration.
- Add Runtime/integration tests before any gateway edit for interactive and
  one-shot commands, wrong/revoked keys, active-session revocation, stale host
  pins, host-shell denial, SFTP/SCP behavior, and local/remote/dynamic
  forwarding denial. Existing green tests may prove no Runtime code is needed.
- Manual exceptions: signed registry publication, protected VPS SSH, Hivelocity
  provisioning, current vendor download, and interactive provider login cannot
  be fully modeled locally. Run installation/version checks once through the
  frozen live procedure after automated green; do not automate real account
  login or store credentials as acceptance evidence.

## Threat and failure model

| Trust boundary, asset, or failure mode | Threat / failure | Intended control or recovery | Verification |
|---|---|---|---|
| user installs remote code | installer compromises sandbox | outer isolation, non-root, no host socket, user choice | boundary inspection |
| persistent credentials | copied into image/log/order | home-only storage and redaction | artifact/log tests |
| stale client sends `cliTools` | false expectation that tool is installed | explicit validation error; no write | API/CLI negative test |
| old selected sandbox | automatic image rebind removes tools | preserve old desired digest/row | migration test |
| new image with old Runtime | missing reporter causes readiness failure | send empty desired selection; readiness ignores probes | integration test |
| cloud-init contract drift | paid/test VPS lacks Runtime | exact artifact verification and Hivelocity request tests | local + unpaid live order |
| user enables another nested container sandbox | missing Docker/Podman socket or unsafe socket request | docs say outer Runtime sandbox is the boundary and never mount a host runtime socket | image/runtime negative test + docs |
| stale vendor command | public instructions stop working | link to canonical vendor docs, revalidate during release, avoid baked version claims | one bounded live install/version check |
| ordering activated with partial configuration | paid/test order cannot create a sandbox | exact Runtime/image tuple gate plus post-deploy catalog and checkout smoke | config, API, UI, and unpaid live order |
| alias injects OpenSSH directives or path escapes | client options/identity redirected | closed alias grammar, absolute normalized managed paths, quote/percent/newline rejection, regular-file checks | CLI negative tests |
| attacker replaces managed file with symlink | write outside managed directory or weaken pin | lstat each component, private directory ownership/modes, create-exclusive temp, atomic rename, refuse symlinks/non-regular files | CLI filesystem tests |
| changed API host key silently accepted | MITM after reload/rotation | profile fingerprint validation plus explicit `sandbox access refresh` and `install-ssh --confirm REFRESH`; never `accept-new`/keyscan | CLI/local/live stale-pin tests |
| unrelated SSH config is damaged | other hosts stop working or inherit sandbox constraints | prepend one stable global include, per-alias fragment, preserve bytes/mode, remove only owned files | CLI integration tests |
| GUI client requests forwarding/subsystem | boundary weakened or IDE partially works | client clears forwarding and sshd/authorized key deny it; document actual result instead of enabling it | exact config, Runtime, live Codex/Cursor tests |

## Master phase map

| Phase | Testable outcome | Requirements / risks | Dependencies | Exit criteria | Status |
|---|---|---|---|---|---|
| P0 | Architecture, compatibility, branches, and gates are frozen | all | audits and current source | assumptions checked; plan authorized | completed |
| P1 | Signed-image source is a user-installable base with no AI CLIs or vendor config | R1,R2,R8,R9 | P0 + renewed execution authorization | red/green image tests and full image build pass | completed |
| P2 | Runtime/agent-kit future code removes nested policy and tool-reporting surfaces while preserving immutable-release and legacy-record compatibility | R6,R7,R10 | P1 contract | Runtime and agent-kit gates green | completed |
| P3 | Backend/order/API uses capacity-only sandboxes, preserves v0.1.26 cloud-init, and validates the exact Runtime/image activation tuple | R3-R6,R9,R10,R12 | P1 digest/interface, P2 compatibility | backend/OpenAPI/order/config gates green | completed |
| P4 | Frontend, public docs, CLI/LLM text document four optional user-installed tools; frontend remains last | R3,R7,R9,R11 | P1-P3 | UI/locale/render/docs gates green | completed |
| P5 | Integrated release, live acceptance, production activation, and standard per-sandbox SSH make instant-order sandboxes usable by terminal agents and compatible clients | R1-R18 | P1-P4 plus explicit release/deploy authority | signed artifacts, existing-VPS canary, certified-OS gates, production catalog/UI smoke, one unpaid test order, CLI v0.8.10 alias gates, and truthful Codex/Cursor compatibility evidence | pending |

## Active phase subplan

### Completed P3 phase header

- Phase ID and outcome: P3, make backend ordering and Runtime APIs
  capacity-only, pin every new sandbox to the configured CLI-free image,
  preserve immutable v0.1.26 cloud-init, and fail closed until the approved
  Runtime/image tuple is configured.
- Covered requirements and assumptions: R3-R6,R9,R10,R12; existing database
  tool columns remain a passive compatibility layer and signed v0.1.26 remains
  the only production bootstrap release for this launch.
- Entry criteria: P1 and P2 are automated-green and reviewed; the frontend
  branch fetched `origin/main` and `git merge --no-edit origin/main` reported
  `Already up to date` before P3 test edits.
- Exit criteria: new order and sandbox-create contracts reject `cliTools`; new
  rows have empty legacy tool state and an immutable configured image pin;
  public catalog, sandbox, manifest, and OpenAPI surfaces omit tool inventory
  and readiness; legacy v0.1.26 report fields are accepted but ignored;
  existing rows retain old tool/image data; and aggregate ordering support is
  true only for the exact signed v0.1.26 artifact plus an explicitly approved
  matching CLI-free image digest.
- Dependencies and risks: the new image digest cannot be approved for
  production until P1 publication/signature/SBOM/provenance gates pass; schema
  consumers remain strict until P4, so P3 is not independently deployable;
  provider cloud-init's v0.1.26 archive-member allowlist is immutable.
- Baseline test state: the backend still exposes tool catalog/response/OpenAPI
  fields, accepts per-sandbox `cliTools`, binds image readiness to the obsolete
  all-tools image and observations, and gates aggregate support on a broadly
  valid Runtime artifact without checking the configured image.
- Required documentation/API changes: canonical OpenAPI is updated in P3 after
  behavior is green; public UI, localized docs, LLM text, and optional vendor
  examples remain deferred to P4.
- Coordinating owner: primary Codex manager.
- Fresh final reviewer available: yes, only after the automated P3 gate passes.
- Declared manual-check exceptions: no live/VPS, publication, deployment, or
  production catalog checks in P3.

### Entry-gate decision

- Implementation authorized: yes, by the owner's explicit
  `managed-plan-execution` instruction on 2026-09-10.
- Decision evidence: the owner approved execution of the revised plan after
  confirming CLI-free images, user-owned tool configuration, four optional
  documentation guides, and required instant-order activation.
- Error/logging requirements reviewed: yes.
- Authentication/authorization requirements reviewed: yes, unchanged.
- Documentation/API requirements reviewed: yes, public/frontend work last.
- Decision timestamp: 2026-09-10 plan revision.

### P3 subparts

| Subpart | Deliverable and owner boundary | Dependencies | Interfaces / likely files | Documentation / API impact | Acceptance and oracle | Tests first + expected red | Green checks | Parallel-safe | Status |
|---|---|---|---|---|---|---|---|---|---|
| P3.S1-A | Capacity-only runtime/catalog tests | P2 | `backend/tests/test_agent_runtime_unit.py` | no docs before green | no tool fields; new pins; legacy report/state compatibility; exact tuple | current APIs expose and enforce tools | focused pytest file/selectors | yes | verified |
| P3.S1-B | Order/database compatibility tests | P2 | `backend/tests/test_commerce_db.py` | no docs before green | pre-payment rejection/no write, replay stability, legacy-row preservation, tool-independent readiness | current order path accepts tools and conditionally pins image | focused pytest selectors | yes | verified |
| P3.S1-C | OpenAPI/cloud-init/operator tests | P2 | `backend/tests/test_surface.py`, existing provider/operator tests | no generated contract before green | capacity-only schema, exact v0.1.26 Hivelocity payload, capacity-only canary with absent-tool oracle | current schema/canary expose bundled tools | focused pytest selectors | yes | verified |
| P3.S2 | Implement capacity-only backend and passive legacy tolerance | P3.S1 red | `backend/warpmetal/runtime.py`, routes/commerce only if required | public response behavior | new requests/rows/manifests omit tools; old rows never rebound; old report key ignored | P3.S1 semantic reds | focused then full backend gate | no | verified |
| P3.S3 | Enforce ordering activation and preserve cloud-init/canary | P3.S1 red | Runtime config gate, provider/operator scripts only as required | deployment config contract | exact v0.1.26 plus separately approved matching image digest; unchanged provider create/cloud-init; five CLI names absent | P3.S1 semantic reds | focused then full backend/script gate | no | verified |
| P3.S4 | Synchronize canonical OpenAPI and backend operator docs | P3.S2,P3.S3 | generator, generated JSON, backend/deploy docs | API/config only; public marketing docs remain P4 | generated contract has no tool selection/inventory and documents activation configuration | schema drift test red | OpenAPI drift + full backend gate | no | verified |

### P3 test-first matrix

| Requirement / risk | Behavior | Test path | Expected red failure | Red command | Green/gate command |
|---|---|---|---|---|---|
| R3 | Orders and sandbox-create accept capacity/lifecycle fields only; explicit `cliTools` returns `unknown_fields` before a write | unit + database API tests | current parser accepts `cliTools` | focused Python selectors | backend full gate |
| R4 | Every new sandbox pins the configured immutable image without tool selection | unit + database tests | current pin is conditional on selected tools | focused Python selectors | backend full gate |
| R6 | Existing tool/image columns remain byte-for-byte stable and legacy v0.1.26 `cliTools` reports are ignored | database/report tests | current report validates and writes observations | focused Python selectors | backend full gate |
| R5,R10 | Hivelocity cloud-init and Runtime v0.1.26 exact archive contract remain unchanged | provider/order tests | regression-only; any drift fails | focused provider/order selectors | backend full gate |
| R12 | Catalog support fails closed unless exact signed v0.1.26 and configured image match a separate approval pin | unit/surface config tests | current gate ignores image and permits later compatible versions | focused Python selectors | backend full gate |
| R3,R9 | Catalog, public sandbox, manifest, and OpenAPI omit tool inventory/readiness/preinstallation claims | unit/surface/schema tests | current public contracts expose tool fields | focused Python selectors + generator check | backend full gate |

### Frozen P3 phase-gate command manifest

Backend/API:

```sh
python -m pytest backend/tests/test_agent_runtime_unit.py backend/tests/test_commerce_db.py backend/tests/test_surface.py
python -m ruff check backend/warpmetal backend/tests/test_agent_runtime_unit.py backend/tests/test_commerce_db.py backend/tests/test_surface.py
node scripts/sync-openapi-agent-runtime.mjs --check
python -m pytest backend/tests
git diff --check
```

### Sequence and integration

1. Fetch and merge current frontend/backend `origin/main` before tests; stop on
   conflict rather than replacing newer main work.
2. Run P3.S1-A/B/C tests-only work in parallel on disjoint test files and record
   one focused semantic-red result from each packet.
3. Implement P3.S2/S3 against those frozen tests, then run the three focused
   files together once.
4. Update the OpenAPI generator/generated file and backend/deploy configuration
   text, then run the frozen full P3 gate once.
5. After automated green, run one fresh read-only P3 review. Accepted findings
   receive one test-first remediation cycle without repeated review loops.
6. Commit P3 as a checkpoint but do not deploy or open the coordinated frontend
   PR yet. Merge current main again before P4; frontend/public docs remain last.

### Active P4 phase header

- Phase ID and outcome: P4, make instant checkout and the public catalog
  capacity-only, remove obsolete nested-policy surfaces, and publish accurate
  user-owned setup guidance for Codex, Claude Code, Cursor CLI, and Gemini CLI.
- Covered requirements and assumptions: R3,R7,R9,R11,R12; the frontend consumes
  the P3 capacity-only catalog atomically, Runtime v0.1.26 remains the cloud-init
  target, and user tool installation begins only after sandbox access succeeds.
- Entry criteria: P3 is committed at frontend/backend commit `55af6bc`; the
  branch fetched `origin/main` and the required explicit pre-P4 merge reported
  `Already up to date` on 2026-09-10.
- Exit criteria: checkout enables Agent Runtime for a supported product and
  eligible OS, renders only sandbox count/name/size/lifetime controls, and emits
  no `cliTools`; catalog decoding rejects obsolete tool inventory; public pages
  and LLM text contain no preinstallation or nested-policy promise and provide
  four separate optional tool guides; obsolete nested-only workflows, scripts,
  and tests are absent while generic host-trust/reboot recovery remains.
- Baseline state: frontend catalog decoding still requires signed all-tools
  metadata, checkout still stores and submits tool selections, localized public
  pages still promise three preinstalled CLIs and document nested Bubblewrap,
  and branch-only nested canary/repair assets remain in the repository.
- Documentation/API requirements: update `/agent-runtime`, `/docs`, all three
  locale dictionaries, `content/llms.md`, and byte-identical
  `backend/public/llms.txt`; preserve external links to current official vendor
  setup/auth/configuration guidance and state that WarpMetal neither configures
  provider credentials nor changes approval modes.
- Coordinating owner: primary Codex manager. Tests are written first by three
  bounded subagents on disjoint files; implementation follows only after the
  semantic reds are inspected. One fresh read-only final review follows the
  automated gate, with no repeated review loop.
- Declared manual-check exceptions: browser rendering uses the built worker;
  publication, deployment, production activation, and the unpaid live order
  remain P5 and require their existing explicit authority.

### P4 subparts

| Subpart | Deliverable and owner boundary | Interfaces / likely files | Acceptance and oracle | Tests first + expected red | Green checks | Parallel-safe | Status |
|---|---|---|---|---|---|---|---|
| P4.S1-A | Capacity-only catalog/checkout tests | `tests/manual-checkout.test.mjs`, `tests/order-preparation.test.mjs`, `tests/checkout-lifecycle.test.mjs`, `tests/public-catalog.test.mjs`, `tests/checkout-ui.test.mjs` | supported product + eligible OS enables sandbox selection; requests carry only capacity/lifecycle; obsolete catalog fields fail strict decode | current fixtures and assertions require `cliTools`, versions, manifest, and UI selections | focused Node files | yes | semantic red verified |
| P4.S1-B | Localized and rendered public-doc tests | `tests/i18n-parity.test.mjs`, `tests/rendered-html.test.mjs` | no all-tools/nested copy; four distinct current optional guides; ownership/approval boundary; checkout renders capacity-only | current copy requires preinstalled tools and nested guidance | build + focused Node files | yes | semantic red verified |
| P4.S1-C | LLM parity and obsolete nested-surface absence tests | new or existing source-contract Node test, nested canary tests only as migration input | `content/llms.md` equals `backend/public/llms.txt`; no nested workflow/input/script/test surface; generic trust/reboot retained | current files and text contain nested activation and preinstall promises | focused source-contract test + Actionlint | yes | semantic red verified |
| P4.S2 | Implement catalog/checkout/UI capacity-only contract | `app/catalog-contract.ts`, `app/checkout/checkout-contract.ts`, `app/checkout/checkout-lifecycle.ts`, `app/checkout/checkout-commands.ts`, `app/checkout/ManualCheckout.tsx`, `app/checkout/CheckoutConnect.tsx` | P4.S1-A green without weakening strict unknown-field handling; ready-sandbox decoding uses the P3 public shape and connect guidance has no bundled-tool inventory | P4.S1-A semantic reds | focused Node + type/build | no | verified |
| P4.S3 | Replace public docs and localized copy with four user-installed guides | `app/agent-runtime/page.tsx`, `app/docs/page.tsx`, `messages/{en,es,pt}.json`, locale generators if authoritative | P4.S1-B green; official URLs and safe ownership language present | P4.S1-B semantic reds | build + render/i18n tests | no | verified |
| P4.S4 | Update LLM/operator text and remove obsolete nested-only repository surfaces | `content/llms.md`, `backend/public/llms.txt`, `backend/README.md`, `deploy/README.md`, `.github/workflows/acceptance-test-server.yml`, nested-only scripts/tests | P4.S1-C green; byte parity; no nested action/enable/oracle remains; generic host-trust/reboot history is retained | P4.S1-C semantic reds | source contracts + Actionlint + full tests | no | verified |

### P4 test-first matrix

| Requirement / risk | Behavior | Test path | Expected red failure | Green/gate command |
|---|---|---|---|---|
| R3,R12 | Supported plan plus certified OS enables capacity-only sandbox controls and emits no tool selector/field | checkout/catalog/unit render tests | current decoder and UI require tool metadata/selections | focused checkout/catalog Node files |
| R3,R6 | Obsolete public catalog tool fields are rejected while task polling tolerates legacy private data only where required | contract/lifecycle tests | current fixtures expose tool inventory publicly | focused contract/lifecycle Node files |
| R7 | No nested activation input, workflow action, driver/oracle, repair test, or public guidance remains | source-contract test | current branch contains nested-only surfaces | source contract + Actionlint |
| R9,R11 | Four separate optional install/auth/config/update/removal guides retain user ownership and make no preinstall/auth/approval promise | i18n, rendered HTML, LLM parity | current docs promise three installed tools and nested policy | build + i18n/render/LLM tests |
| R5,R10 | Frontend/doc cleanup does not alter v0.1.26 cloud-init, lifecycle, host trust, reboot, or recovery contracts | existing full Node/backend suites | regression-only | full repository gate |

### Frozen P4 phase-gate command manifest

```sh
npm run build
node --experimental-strip-types --test tests/*.test.mjs
npm run lint
python -m pytest backend/tests
python -m ruff check backend/warpmetal backend/tests
node scripts/sync-openapi-agent-runtime.mjs --check
actionlint .github/workflows/deploy.yml .github/workflows/acceptance-test-server.yml
cmp -s content/llms.md backend/public/llms.txt
git diff --check
```

### P4 sequence and integration

1. Run P4.S1-A/B/C tests-only work in parallel on disjoint test files. Inspect
   semantic-red evidence before authorizing any P4 production edit.
2. Integrate the frozen tests, resolving only contradictory test ownership in
   the manager; do not make product assertions pass by loosening strict decode.
3. Implement P4.S2 first, then P4.S3 and P4.S4. Public UI/docs remain the last
   production edits in the cross-repository program.
4. Run focused green checks, then the frozen full P4 gate once. Run one fresh
   read-only final review and one bounded remediation cycle only if needed.
5. Commit the P4 checkpoint. Fetch and merge current `origin/main` once more;
   stop on conflict. Do not deploy, release, order, or open a request before the
   final integrated gate and required authority.

### Active P5 release and instant-order activation gate

- Phase ID and outcome: P5, merge the four verified requests, publish and bind
  the exact signed CLI-free image to the existing immutable Runtime v0.1.26,
  deploy the atomic capacity-only contract, certify the existing VPS by OS
  reload, and create exactly one unpaid test-code order.
- Entry criteria: P1-P4 complete; image PR #4, Runtime PR #25, agent-kit PR #36,
  and frontend PR #148 are mergeable and green; frontend CI passed in 8m34s;
  the user explicitly authorized all six P5 effects after they were enumerated.
- External effects authorized: merge all four PRs; allow the image main-push
  publication; set the exact image-digest configuration; deploy production;
  destructively reload the already-designated acceptance VPS through the four
  certified OSes; and create exactly one order through the unpaid test-code
  path. No x402 payment, wallet authorization, paid order, additional VPS, or
  unrelated resource mutation is authorized.
- Rollback boundary: if publication verification, deployment health, catalog
  support, checkout UI, any OS reload/canary, or the single unpaid order fails,
  set aggregate Runtime support false and keep instant-order sandboxes disabled
  before diagnosis. Never publish a replacement v0.1.26 artifact.
- Coordinating owner: primary Codex manager. Three bounded read-only specialists
  first confirm image publication, deployment configuration, and the exact live
  procedure. Mutations then run serially in dependency order with evidence
  recorded after every irreversible boundary.
- 2026-09-11 authority update: implementation, local tests, and bounded checks
  on the already-provisioned test VPS remain authorized. The owner's later
  direction, "do not deploy yet," supersedes prior deployment authority for the
  current increment. Do not merge a pull request, publish CLI v0.8.10, deploy
  frontend/backend, order another VPS, reload an OS, or make a payment until
  that hold is explicitly lifted.

### P5 subparts

| Subpart | Outcome | Gate before mutation | Status |
|---|---|---|---|
| P5.S1 | Merge image PR #4; verify new signed amd64 digest, source revision, SBOM, provenance, and P1 evidence | clean/green PR plus release audit | completed |
| P5.S2 | Merge Runtime PR #25 and agent-kit PR #36 without republishing immutable v0.1.26 or claiming a new CLI release | clean/green PRs plus source review | completed |
| P5.S3 | Set exact runtime/order image configuration, merge frontend PR #148, and verify atomic backend/frontend deployment | exact digest verified; rollback-to-false ready | completed |
| P5.S4 | Verify production health, four-field catalog support, certified OS flags, checkout enablement, and no tool selector | deployment green | completed |
| P5.S5 | Reuse exactly one existing VPS and guarded reload flow for the four certified OSes; verify v0.1.26, CLI absence, capacity lifecycle, SSH trust, and recovery | live identity/task binding and destructive approval already verified | pending |
| P5.S6 | Create exactly one unpaid test-code order with Runtime sandbox intent and verify Hivelocity cloud-init plus ready CLI-free sandbox | production/UI/catalog and existing-VPS matrix green | pending |
| P5.S7 | Ship CLI v0.8.10 source for a hardened concrete sandbox SSH alias, prove existing Runtime gateway behavior, reconcile all human/machine docs, and record actual Codex Desktop/Cursor compatibility | frozen tests-only packet, existing test VPS, no production deployment | pending |

### Active P5.S7 standard SSH alias subplan

- Phase ID and outcome: P5.S7, turn one already-pinned connection profile and
  sandbox-specific identity into a normal concrete OpenSSH alias while keeping
  the existing v0.1.26 server-side forced gateway as the only execution path.
- Covered requirements and assumptions: R13-R18 and A8-A12. R1 remains a hard
  invariant: the image is still CLI-free. The Codex compatibility check installs
  Codex into persistent `/home/agent` as the sandbox user, authenticates only if
  a human session is available, and confirms the login shell sees `codex`.
- Entry criteria: agent-kit and Runtime branches have fetched and fast-forwarded
  to current `origin/main` without conflicts; official OpenAI and Cursor sources
  have been read; production deployment is held; the existing v0.1.26 sandbox
  and grant path are available for bounded non-destructive acceptance.
- Exit criteria: all frozen local tests pass; exact generated OpenSSH config is
  resolver-verified; Runtime source tests and live SSH prove interactive/exec,
  wrong/revoked keys, active revocation, stale pins, host-shell and forwarding
  denial; Codex Desktop result is recorded; Cursor IDE is either proven without
  relaxing policy or documented incompatible with verified headless CLI use;
  CLI/runtime/public/machine docs agree; required version bump is recorded.
- Baseline state: CLI v0.8.9 only creates temporary known-hosts state for
  `sandbox connect`; it has no persistent alias install/remove command. Runtime
  v0.1.26 already has one fixed `warpmetal-sandbox` account, authorized-key
  forced commands, grant/session revocation, password/keyboard-interactive
  denial, and forwarding denial. Frontend commit `80287de` correctly explains
  agent dispatch but currently says Codex Desktop and Cursor cannot use the
  profile; that copy must be reconciled only after CLI/runtime gates are green.
- Required documentation/API changes: CLI help/README; both source skill and
  plugin skill mirrors plus their CLI/Runtime references; Runtime README and
  SECURITY boundary text; frontend `/agent-runtime`, `/docs`, `content/index.md`,
  `content/llms.md`, byte-identical backend `llms.txt`, and rendered tests. No
  backend API/OpenAPI change is expected because the connection profile already
  supplies every required field and the command is token-free/local-only.
- Error/logging requirements reviewed: yes. JSON may contain only alias,
  server/sandbox/grant IDs, operation state, and absolute config/known-hosts/
  identity paths. It must not contain host, port, username, profile bytes,
  public host keys, host-key fingerprints, private-key bytes, or tokens.
- Authentication/authorization requirements reviewed: yes. Grant creation,
  refresh, and revocation retain existing authenticated API paths. Alias install
  and remove are local transformations and add no server authority.
- Implementation authorized: yes, by the explicit 2026-09-11 delegation to add
  and implement this requirement end-to-end. Merge, publication, and production
  deployment remain held by the later owner instruction.
- Coordinating owner: primary Codex manager. Tests-only producer lineages must
  finish before any production implementation packet. A different lineage must
  perform the single final review after all automated gates are green.
- Declared manual exceptions: provider/AI login is not automated or captured;
  Codex Desktop and Cursor GUI smoke may be manual but must retain command logs
  and client/version/result evidence. No boundary is relaxed to make a GUI pass.

| Subpart | Deliverable / owner boundary | Dependencies | Likely files | Tests-first red / oracle | Green gate | Parallel-safe | Status |
|---|---|---|---|---|---|---|---|
| P5.S7-A | CLI tests-only contract for install/exact replay/refresh/remove, validation, atomicity, modes, safe JSON, and `ssh -G` | frozen plan | agent-kit `test/connection.test.js`, `test/runtime.test.js`, new focused test only if needed | v0.8.9 lacks command/export/files; semantic failures only | focused Node tests, full `npm test`, `npm run check`, `npm pack --dry-run` | yes | tests_red |
| P5.S7-B | Runtime tests-only proof for forced interactive/exec, wrong/revoked grants, active revocation, stale pins, host-shell/subsystem/forwarding denial | frozen plan | existing Go/unit and packaging tests; new harness only where behavior is not executable | current coverage gaps fail; existing green behavior is retained | focused `go test`, install/sshd scripts, full `go test ./...` | yes | verified |
| P5.S7-C | Compatibility/docs tests-only contract using official sources and `80287de` | frozen plan | agent-kit README/skills tests; Runtime docs; frontend rendered/llms tests last | current docs say alias unsupported and omit install/refresh/remove/accurate Cursor result | link/parity/render/help/skill mirrors | yes, research first; frontend edit last | tests_red |
| P5.S7-D | Implement token-free local SSH alias manager and CLI dispatch | A red accepted | agent-kit `src/connection.js`, new focused module, `src/cli.js`, package/check list | exact A assertions | A gates green; no Runtime/API call | no | verified |
| P5.S7-E | Implement only Runtime changes proven necessary by B | B red accepted | Runtime access/gateway/sshd only if a real behavior gap exists | exact B assertions | B gates green; v0.1.26 compatibility preserved | no | verified; no production change |
| P5.S7-F | Update CLI/Runtime docs and skill mirrors; record v0.8.10 requirement | D/E green | README/help/skills/references/package metadata | C assertions | docs/parity/package gates | yes after interfaces freeze | verified |
| P5.S7-G | Bounded live alias, lifecycle, Codex, and Cursor compatibility on existing VPS | local gates green | no repository production code | frozen command/result ledger | exact live matrix; no deploy/reload/payment | no | pending |
| P5.S7-H | Merge current main into frontend branch, reconcile `80287de`, update public/machine docs, and run final review | A-G green | frontend docs/tests only plus any already-held signature fix | rendered/llms red | full proportional frontend gate and one fresh review | no | pending |

P5.S7 frozen test and live matrix:

| Requirement / risk | Required assertion before implementation | Expected current result | Final oracle |
|---|---|---|---|
| R13,R14 | exact alias grammar; closed profile; fingerprints recomputed; regular private identity; exact hardened host block; include precedence; 0700 directory and 0600 files; no secrets in JSON | command/module absent | focused CLI tests plus `ssh -G` resolved options |
| R14,R15 | refuse symlink/non-regular paths, unsafe percent/newline paths, unmanaged concrete alias collision, partial writes, and changed managed bytes; exact replay succeeds; `--confirm REFRESH` and `--confirm REMOVE` are required for mutation | command/module absent | byte/mode snapshots before and after injected failures |
| R16 | no `RemoteCommand`/`RequestTTY`; password and keyboard-interactive disabled; interactive shell and supplied command route to sandbox; wrong and revoked keys denied; active session ends; stale pin fails; `ssh root@host` is never derived; `-L`, `-R`, `-D`, agent/X11, SFTP and SCP cannot escape the sandbox boundary | core Runtime behavior largely green but end-to-end gaps remain | Runtime unit/package tests plus live OpenSSH exit/output proof |
| R17 | concrete alias appears in OpenSSH resolution and Codex Desktop; sandbox login shell resolves `codex`; remote app-server start reaches only sandbox | alias absent | `ssh -G`, `ssh <alias>`, installed Codex PATH, Desktop connection/version evidence |
| R18 | `ssh <alias>` / one-shot `codex exec`, `claude -p`, and `agent -p`; sandbox-owned auth; distinct keys/grants; refresh/remove; accurate Cursor IDE status in every doc surface | docs omit command and say alias unavailable | exact rendered/help/llms/skill parity tests plus source links |

P5 release-audit findings accepted before deployment:

- The existing deployment is not atomic for this catalog-schema transition:
  it replaces the worker and waits for catalog refreshes before the new
  frontend/backend cutover. The new worker can therefore write the four-field
  snapshot while the old strict frontend still requires the legacy tool
  fields. P5.S3 is blocked until a test-covered rollout preserves checkout
  availability throughout that transition.
- The existing digest validation is fail-closed but is not an operator rollback
  control: removing or mismatching the ordering digest aborts deployment before
  it changes live containers. P5.S3 must add and test a supported way to restore
  aggregate Runtime support to false before production activation.
- The existing acceptance workflow is bound to Ubuntu, the prior task, and the
  prior image. P5.S5 requires a protected generic task-bound OS reload/exercise
  route using CLI 0.8.9 and one operation-bound TOFU state directory before the
  approved four-OS matrix can run. These findings do not authorize another VPS
  or a paid order.

P5 remediation and rollout sequence (test-first, one bounded cycle):

1. Freeze three disjoint red contracts before production edits: a private
   legacy-compatible stored catalog plus strict four-field public projection;
   an optional exact-match ordering approval pin whose empty value is a
   deployable disabled state; and a protected generic task-bound OS
   reload/install/exercise path using CLI 0.8.9.
2. Keep the worker-first coordinator but make its stored catalog a transition
   bridge parseable by the currently live frontend. The new backend must remove
   all bridge-only tool fields at the public `/catalog` boundary. Because the
   approval pin remains absent, the first schema deployment must stay disabled.
3. Configure the verified CLI-free base image digest while leaving the ordering
   approval pin absent, merge the corrected frontend request only after one
   more current-`main` merge, and verify the deployed four-field catalog and
   selector-free UI remain disabled.
4. Set the approval pin to the same verified digest and dispatch the same exact
   `main` release. Verify the aggregate gate becomes true without a schema
   transition. Rollback is the inverse supported operation: remove the approval
   pin and dispatch that same release, which must publish `supported: false`.
5. Only after activation smoke passes, run the generic existing-VPS four-OS
   matrix serially and then the single already-authorized unpaid test-code
   order. Never issue a second reload for an exit-8 pending operation, and never
   enter any x402 payment path.

### P5 instant-order activation procedure

This gate is detailed again immediately before deployment and cannot be waived:

1. Verify the new CLI-free image digest, signature, source revision, SBOM,
   provenance, platform, and P1 test evidence.
2. Verify production Runtime metadata identifies the existing immutable signed
   v0.1.26 artifact and its exact checksum/signature. There is no replacement
   or republished “new v0.1.26.”
3. Configure the approved image digest and deploy the capacity-only backend and
   frontend contract together so strict catalog consumers never see a partial
   schema.
4. Fetch production `/catalog` and assert every eligible product reports
   `agentRuntime.supported: true`; assert each certified live-cloud-init OS
   reports `cloudInit: true` and `agentRuntimeSupported: true`.
5. Open instant checkout and assert the Agent Runtime control is enabled after
   an eligible OS is selected, no tool selector exists, and the user can choose
   sandbox count/sizes before payment.
6. Use the authorized unpaid test code for exactly one order. Assert the
   Hivelocity request contains the reviewed cloud-init, Runtime v0.1.26
   registers, the requested sandbox reaches ready on the new image, and none of
   the four documented AI CLIs is preinstalled.
7. Through the existing one-VPS reload procedure, run the same exact tuple on
   each advertised OS without purchasing additional servers.
8. On any failed check, restore aggregate support to false and keep instant
   checkout disabled; do not leave a partially eligible ordering path.

## Verification log

- P0 audit evidence:
  - all implementation branches fetched current `main`; Runtime already contains
    `origin/main` `2e0d202`, agent-kit equals `cd78308`, and image equals
    `f54f23e` before implementation;
  - current image baseline built as local image ID `sha256:656fb5df43b2...`
    and its existing full image test passed, proving Codex/Claude/Cursor and the
    reporter are present before the removal;
  - Runtime audit proved v0.1.26 returns before reporter execution for an empty
    tool selection and ordinary Podman creation has no AI-CLI dependency;
  - agent-kit audit proved CLI v0.8.9 already rejects `cliTools` in sandbox
    specifications and needs no launch-path selection change;
  - frontend audit mapped the public `cliTools`/catalog/UI/OpenAPI/readiness
    surface, cloud-init independence, and legacy idempotency constraints;
  - owner clarified that the image must not install or configure any vendor
    CLI, including Codex sandbox or approval defaults. Users own those settings.
- P0 final status: completed. The revised plan includes four optional tool
  guides and no WarpMetal-owned vendor configuration. P1 tests-only edits are
  authorized; production edits remain gated on manager-approved red evidence.
- P1 entry evidence: image branch fetched and merged current `origin/main`
  `f54f23e`; Git reported `Already up to date` before test work.
- P1.S1 tests-only checkpoint (`P1.S1-tests-attempt-01`): `test-image.sh`
  and an offline local npm CLI fixture were added without production edits.
  Static shell, JavaScript, fixture metadata/output, and `git diff --check`
  checks passed. The sole command
  `sh test-image.sh warpmetal-agent-sandbox:pre-user-install-baseline` exited 1
  in 0.556855042s with
  `unexpected preinstalled command: codex -> /usr/local/bin/codex`. This is the
  intended R1 product-behavior red, so P1.S2 production implementation is now
  authorized against the frozen tests. No rerun was performed.
- P1.S2/S3 implementation checkpoint
  (`P1.S2-S3-implementation-attempt-01`): the amd64 image built once as
  `warpmetal-agent-sandbox:test-amd64`, image ID
  `sha256:792eb06b71dbceb224a5b14caef0045b2acab2007b081a08c03c2449bd20fb3a`.
  Shell syntax passed and the static CLI-free/base-tool contract passed. The
  sole image test then exited 226 because npm's local-directory install linked
  back to the read-only fixture bind mount and its required bin-file chmod
  returned `EROFS`. This is a genuine fixture-packaging defect, not a product
  failure: the test must pack the same fixture into tmpfs and install the
  resulting tarball before the existing built image is rerun. No production
  rebuild or production edit is authorized for that correction.
- P1.S1 fixture correction (`P1.S1-fixture-correction-attempt-01`) changed only
  the test oracle to pack the read-only source fixture into container tmpfs and
  install the local tarball offline under the explicit home prefix. Static
  checks and `git diff --check` passed; the sole rerun against unchanged image
  ID `sha256:792eb06b71dbceb224a5b14caef0045b2acab2007b081a08c03c2449bd20fb3a`
  exited 0 in 5.820599875s. CLI/artifact absence, base tools, user-local npm
  installation, real Chromium mobile/desktop rendering, and outer restrictions
  passed.
- Fresh final review (`P1-final-review-01`) rejected P1 with two accepted
  findings: prove executable/config persistence in a second container using the
  same home volume, and prevent documentation/test-fixture-only main pushes
  from publishing and signing an unchanged image. Remediation must first add
  those deterministic assertions and record the release-trigger red before the
  workflow-only production correction. No second review loop is planned.
- P1 review-remediation tests checkpoint
  (`P1-review-remediation-tests-attempt-01`): shell syntax and
  `git diff --check` passed. The sole image-test run exited 1 in 8.112076041s
  only after a first restricted container installed the local fixture and wrote
  a fixed config sentinel, and a second fresh restricted container reused the
  same home volume to verify the executable/output and exact config hash. The
  final host assertion then reported that main-branch `push.paths` contained
  `.dockerignore`, `README.md`, browser/tests/fixtures, and the workflow in
  addition to `Containerfile`. This is the intended release-safety red. The
  ownership-labelled test volume was verified and removed by the test trap;
  no persistent resource remains. A workflow-only correction is authorized;
  image source, image artifact, and tests remain frozen.
- P1 final status: completed. The workflow-only correction reduced main
  `push.paths` to `Containerfile` while retaining broad pull-request validation,
  workflow dispatch, build/test, SBOM, provenance, publication, and Cosign.
  The sole post-correction image test exited 0 in 8.5312815s against unchanged
  amd64 image ID
  `sha256:792eb06b71dbceb224a5b14caef0045b2acab2007b081a08c03c2449bd20fb3a`;
  static absence/base-tool checks, offline user-local install, real Chromium,
  two-container executable/config persistence, root restrictions, and release-
  path assertion all passed. `git diff --check` passed. The labelled volume was
  verified and removed by the trap. One final review was completed and both
  accepted findings are covered; no second review loop is required.
- P2 entry status: in progress. Runtime and agent-kit fetched current
  `origin/main` and each explicit `git merge --no-edit origin/main` reported
  `Already up to date`; parallel tests-only packets are now authorized.
- P1 repository checkpoint: image commit `cc5ed8a` was created, current
  `origin/main` was fetched and merged again without conflicts, the branch was
  pushed normally (no force), and image PR
  <https://github.com/warpmetal/warpmetal-agent-sandbox/pull/4> was opened.
  No image artifact was published or deployed.
- P1 pull-request CI: PR 4 `test` passed in 50s and `publish` correctly skipped
  on the pull-request event.
- P2.S1-R tests-only checkpoint: added a focused raw-manifest/legacy-SQLite
  reconcile oracle and future-release structure oracle. Static formatting,
  shell syntax, and `git diff --check` passed. The single focused Go run failed
  because current Runtime invoked the reporter once, emitted `cliTools`, and
  changed legacy columns from the seeded Claude/generation-1 observation to a
  Codex/generation-2 failure; the companion capacity lifecycle had no separate
  failure. The single shell run failed because
  `cmd/warpmetal-policy-metadata` remains. These are intended product reds;
  P2.S2-R production implementation is authorized.
- P2.S1-C tests-only checkpoint: only `test/cli.test.js`,
  `test/installer.test.js`, and `test/runtime.test.js` changed. Static checks
  passed. The single focused run completed 52 tests: 42 passed and 10 failed
  for current nested help/option/action output and the current rule that rejects
  stripped 0.1.27/0.2.0/1.0.0 bundles. Capacity-only operations with tool-free
  responses, explicit `cliTools` rejection, exact legacy bundles, and fail-
  closed missing/extra/symlink cases passed. These are intended product reds;
  P2.S2-C production implementation is authorized.
- P2.S2-C/S3 agent-kit checkpoint: nested CLI/installer behavior and error
  mappings were removed; exact legacy v0.1.25/v0.1.26 versus stripped future
  bundle validation is implemented; nested help and source/plugin references
  were removed without a version bump. `npm run check`, 52/52 focused tests,
  91/91 full tests, `npm pack --dry-run --ignore-scripts`, mirror parity, and
  `git diff --check` passed. No package, artifact, or external resource was
  created.
- P2.S2-R initial implementation checkpoint: formatting/static checks and the
  frozen future-release structure oracle passed. The first focused Go command
  stopped at compile time on one unused `errors` import left by removal of the
  obsolete tool tests, so no full Runtime gate ran. Manager inspection also
  rejected deletion of `README.md` and `SECURITY.md`: P2 requires those files
  to be rewritten for the outer-sandbox model. A tests-only correction may
  remove the unused import and add a narrow documentation contract, then must
  record the expected missing-doc red before documentation production work.
- P2.S2-R test-correction checkpoint: the unused test import was removed;
  static checks passed; the focused legacy/passive-lifecycle Go oracle now
  passes. The documentation/source/release shell oracle ran once and failed on
  the first missing required fact: `README.md` did not explicitly state that
  sandbox processes run as UID/GID 1000. Both rewritten documents were present,
  so this is the intended P2.S3 content red. Documentation-only correction and
  then the frozen full Runtime gate are authorized.
- P2.S3/Runtime final implementation checkpoint: README and SECURITY now state
  the outer rootless Podman boundary, UID/GID 1000, read-only root, persistent
  `/home/agent`, no host runtime socket, and user ownership of tools. The frozen
  doc/source/release contract passed. The full gate passed once: gofmt clean,
  every retained packaging shell script parsed, installer structure passed,
  `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, and
  `git diff --check` all passed. A production-only forbidden-surface scan found
  no remaining nested/AppArmor/tool-reporter path or reference. P2 is automated-
  green across Runtime and agent-kit; one fresh final review is pending.
- P2 final review (`P2-final-review-01`) completed one read-only pass across
  both repositories with zero actionable correctness, security, compatibility,
  or test-oracle findings and approved P2. P2 final status: completed.
- P2 repository checkpoints: Runtime commit `c57b959` and agent-kit commit
  `4b7c7a0` were created. Each repository fetched and explicitly merged current
  `origin/main` again with `Already up to date`, then pushed normally without
  force. Runtime PR <https://github.com/warpmetal/warpmetal-agent-runtime/pull/25>
  and agent-kit PR <https://github.com/warpmetal/agent-kit/pull/36> are open.
  The first Runtime PR-create call returned a transient GitHub GraphQL error,
  created no PR, and one checked retry succeeded. No artifact was released or
  deployed.
- P2 pull-request CI checkpoint: Runtime PR 25 passed its main test job, the
  existing Docker drift guard, and the existing package gates on AlmaLinux 9,
  Debian 12, Rocky Linux 9, and Ubuntu 24.04. Agent-kit PR 36 passed both Node
  20 and Node 22 jobs. Image PR 4 remains green with its test job passed and
  publication correctly skipped. No artifact was published or deployed.
- P3 entry checkpoint: frontend/backend branch
  `codex/nested-private-procfs-canary` fetched current `origin/main` and the
  explicit pre-edit merge reported `Already up to date`. Three disjoint
  tests-only packets are running for runtime/catalog, database/order, and
  OpenAPI/cloud-init/operator contracts; no P3 production or frontend file is
  authorized until their semantic-red evidence is inspected.
- P3.S1-A tests-only checkpoint: `backend/tests/test_agent_runtime_unit.py`
  parsed cleanly and `git diff --check` passed. Its sole file run produced 16
  intended failures and 117 passes in 1.49s. Reds cover unknown `cliTools`,
  unconditional creation pins, exact activation tuple, tool-independent
  readiness, private legacy fields, manifest/report compatibility, capacity-
  only catalog, and OpenAPI removal. Implementation is authorized.
- P3.S1-B tests-only checkpoint: the agent's first focused database command was
  correctly classified inconclusive because all 10 selected tests skipped when
  `DATABASE_URL` was absent. The manager started a dedicated disposable local
  PostgreSQL 17 container, migrated through revision 0043, and reran that exact
  focused selection against a real database. It produced 10 intended product
  failures in 2.25s for canary tools, missing creation pins, accepted legacy
  request fields, tool-dependent readiness, public fields, and refresh origin.
  This is valid semantic-red evidence; implementation is authorized.
- P3.S1-C tests-only checkpoint: the single focused surface run produced 12
  intended failures, 7 passing controls, and 56 deselections in 1.50s. The
  immutable v0.1.26 cloud-init/provider contract and all four OS eligibility
  controls passed. Reds cover stale OpenAPI/catalog fields, generic unknown-
  field behavior, capacity-only canary, and all eight activation-tuple drift
  cases. Implementation is authorized without changing cloud-init.
- P3.S2/S3/S4 implementation checkpoint: backend sandbox validation and public
  responses are capacity-only; every new row receives the configured immutable
  image pin; legacy tool columns are passive and legacy v0.1.26 report keys are
  accepted but ignored; readiness uses lifecycle, generation, and image
  convergence only. The protected unpaid canary requests one capacity-only
  sandbox and freezes the five absent command names. OpenAPI removes every tool
  schema/property. Deployment requires a separate immutable ordering image pin
  equal to the configured image, while Runtime metadata must match the exact
  existing v0.1.26 artifact/signature/key constants.
- P3 focused correction checkpoint: the first combined run found only three
  fixture/generator mismatches: a PEM fixture hashed an unnormalized trailing
  newline, a legacy-row assertion expected ignored observation data to be
  erased, and regeneration omitted two existing Runtime summary fields. Those
  exact test/generator defects were corrected. The next focused run passed 208
  unit/surface tests and 10 database selections; the frozen full three-file
  gate then passed all 366 tests in 14.32s.
- P3 automated gate: Ruff, OpenAPI generator drift, Actionlint, and
  `git diff --check` passed. The one frozen full backend run completed with
  2,508 passed and 1 skipped in 144.75s against the disposable PostgreSQL 17
  database. No frontend, deployment, release, or live resource was changed.
- P3 final review (`P3-final-review-01`) completed one fresh read-only pass and
  produced one consolidated accepted set: ordinary bootstrap issuance must
  revalidate the exact approved v0.1.26 artifact/image tuple to close the
  catalog-to-provisioning TOCTOU; protected canary authorization must bind and
  recheck the immutable sandbox image digest; the ordering driver must replace
  bundled-tool and nested-bwrap assertions with capacity-only state plus the
  five-command absence oracle; and the strict internal Runtime report schema
  must retain a deprecated, bounded, ignored exact-v0.1.26 `cliTools`
  compatibility property. These are launch-path compatibility and integrity
  defects, so all four findings are accepted for the single permitted review
  remediation cycle. No second review pass will run.
- P3 review-remediation tests checkpoint: three disjoint tests-only packets
  were inspected and accepted. The Runtime selector produced 5 intended drift
  failures and 2 passing controls: changed Runtime version, artifact digest,
  signature, signing key, or configured image reached bootstrap issuance
  instead of failing before writes, while the exact ordinary tuple and
  task-scoped operator artifact remained valid. The database selector produced
  one intended failure because the protected canary rejected the new exact
  `sandboxImageDigest` before preparation; its frozen oracle also requires
  prepare/result/event/row binding, drift rejection before any write or payment,
  and exact idempotent replay. The surface selector produced one intended
  failure because `RuntimeSandboxReport.cliTools` was absent, and two Node
  selectors failed because the live driver still required bundled tool fields
  and versions, lacked the five-command absence probe/evidence, and retained
  nested bwrap/private-procfs machinery in the ordering exercise. Static syntax
  and `git diff --check` passed. One consolidated production correction is now
  authorized against these frozen oracles.
- P3 review-remediation implementation checkpoint A/B: ordinary bootstrap
  issuance now calls one exact approved artifact/image configuration helper
  before writes; its focused selector passed 7 tests and its full Runtime unit
  file passed all 140 tests. The protected canary now binds the exact immutable
  image through request, confirmation, result, audit event, and created row,
  validates live equality before a new mutation, and permits only an already
  recorded exact idempotent replay after later configuration drift. Its exact
  database selector passed, and all five relevant canary tests passed. The
  first full commerce-file run exposed two old ordinary-provisioning fixtures
  that still generated arbitrary broadly compatible signatures; those fixtures
  were corrected to use the exact signed v0.1.26 descriptor and matching image
  approval, and the two affected selectors then passed. Ruff and scoped diff
  checks pass. The OpenAPI/driver correction and integrated gate remain pending.
- P3 review-remediation implementation checkpoint C: the internal OpenAPI
  schema now retains a deprecated and bounded v0.1.26 `cliTools` report field
  that the control plane ignores, while every public order/catalog/sandbox
  contract remains capacity-only. The exhaustive installed-host driver now
  validates the exact sandbox image/lifecycle state, proves `codex`, `claude`,
  `agent`, `cursor-agent`, and `gemini` are absent, and exercises planning,
  coding, QA, restart persistence, access revocation, and denied reconnect
  without any nested-Bubblewrap policy transition or oracle. Its local
  real-wrapper harness passed all 15 tests, including every durable
  interruption/replay boundary and an already-revoked replay guard.
- P3 final remediation gate: the three focused backend files passed 373 tests;
  Runtime unit plus the exact OpenAPI surface selector passed 141 tests; Ruff,
  generated OpenAPI drift, Actionlint, and `git diff --check` passed. The one
  consolidated full backend rerun passed 2,515 tests with 1 skip in 150.36s.
  P3 is complete. Per the frozen review policy, no second agent review was run.
  No frontend, deployment, release, order, or live resource was changed.
- P4 entry checkpoint: P3 was committed as frontend/backend commit `55af6bc`.
  The branch fetched current `origin/main`, and the required pre-P4 merge
  reported `Already up to date` with no conflict. Three disjoint tests-only
  packets then froze frontend/catalog, rendered/localized documentation, and
  LLM/nested-surface removal contracts before any P4 implementation.
- P4.S1-A tests-only checkpoint: five focused Node files ran 86 tests with 56
  passing controls and 30 intended semantic failures. The reds show that the
  current frontend rejects the four-field capacity-only catalog, still accepts
  and emits `cliTools`, still requires tool fields in public sandbox responses,
  and still renders selector/readiness code. Price, SSH, polling, cancellation,
  and connection-safety controls stayed green. The manager added explicit
  frozen probes rejecting `cliTools` in a saved/order sandbox and rejecting
  `cliTools`/`observedCliTools` in a public sandbox response.
- P4.S1-B tests-only checkpoint: i18n ran 3 tests with 1 pass and 2 intended
  failures; five selected existing-build render tests all failed on the stale
  product behavior. The frozen contract requires capacity-only checkout copy,
  distinct Codex/Claude/Cursor/Gemini guides in each locale, user-owned install,
  authentication, configuration, approval, update, and removal choices, outer
  Runtime sandbox and persistent-home guidance, and no nested-policy copy.
- P4.S1-C tests-only checkpoint: the dedicated source-contract run produced 1
  passing control and 2 intended failures, and the focused backend LLM test
  produced 1 intended failure. Byte parity already passes. Reds identify the
  old three-tool/preinstallation text, seven obsolete nested-only files, dead
  ordering-repair driver/workflow paths, and published nested install flags.
  Generic host-trust, reboot, power-cycle, recovery, and Runtime v0.1.26
  references are explicitly retained. P4 implementation is authorized.
- P4.S2/S3/S4 implementation checkpoint: the frontend now strictly consumes
  the four-field capacity-only Runtime catalog; checkout emits only sandbox
  count, name, size, and lifetime; public sandbox decoding rejects obsolete
  tool fields; and the selector/readiness/login UI is gone. Public Runtime and
  docs pages in English, Spanish, and Portuguese plus the byte-identical LLM
  guides now describe minimal CLI-free sandboxes and four separate optional
  user-installed Codex, Claude Code, Cursor CLI, and Gemini CLI flows. User
  ownership of credentials, approval mode, configuration, update, and removal
  is explicit. The obsolete nested-only workflow actions, drivers, oracles, and
  tests are removed while the generic host-trust, reboot, recovery, v0.1.26
  ordering, application-placement, capacity, expiry, and lifecycle guidance is
  retained.
- P4 focused green checkpoint: the consolidated checkout/catalog/i18n/render
  and source-contract set passed 127 Node tests; the focused backend guide test
  passed; build, Ruff, OpenAPI drift, Actionlint, shell syntax, LLM byte parity,
  and diff hygiene passed. The first full gate exposed one coherent stale-test
  cluster: three deleted workflow actions changed exact action/resolver counts,
  one deleted nested driver remained in a source list, the exhaustive ordering
  test still required the removed feature branch, the ordering harness had not
  incorporated P3's immutable sandbox-image pin, and one assertion required the
  retired CLI-tools constant. A bounded read-only subagent audit classified
  these as test-contract drift and found no production defect.
- P4 bounded remediation checkpoint: the stale tests were aligned without
  changing production behavior and strengthened to carry the immutable image
  digest through the canonical request, confirmation, SSH transport, fake
  backend results, and malformed-field checks. The five affected Node files,
  exact backend resolver test, Ruff, Actionlint, and diff hygiene passed. The
  single full rerun then passed the complete Node suite and 2,515 backend tests
  with 1 skip in 213.42 seconds. Build and lint were green; lint reported only
  five pre-existing warnings. One fresh read-only final review remains before
  the P4 checkpoint commit.
- P4 manager CLI-pin checkpoint: a final scoped search found the retained
  generic connect canary still installed CLI 0.8.8 even though the frozen
  ordering/live-test version is 0.8.9. A new source regression assertion failed
  for that exact pin, then passed after changing only the two install/version
  lines to 0.8.9. The source-contract plus exhaustive live-driver tests passed
  18 tests, and shell syntax plus diff hygiene passed. No full backend rerun is
  warranted for this shell-only version-pin correction.
- P4 final review (`P4-final-review-01`) completed one fresh read-only pass and
  returned zero findings. It explicitly verified strict capacity-only checkout
  and eligibility gating, absence of public tool inventory/selectors, all four
  user-owned optional guides, removal of nested-only repository surfaces,
  preservation of v0.1.26 cloud-init/order/trust/recovery behavior, byte parity,
  and the final 0.8.9 live-canary pin. P4 is complete and authorized for its
  checkpoint commit; no second review pass will run.
- P4 checkpoint/PR: committed frontend/backend integration as `5f54940`
  (`feat: make sandbox tooling user installed`). The branch fetched current
  `origin/main` immediately before request creation and reported `Already up to
  date` with no conflict. It was pushed and opened as frontend PR #148. Image
  PR #4, Runtime PR #25, and agent-kit PR #36 are open, mergeable, clean, and
  green. Frontend PR #148 completed its full CI job green in 8m34s, including
  backend branch coverage, Ruff, lint, complete Node tests, and admin build and
  tests; publish and deploy correctly skipped for the pull request. All four
  requests are ready for the separately authorized P5 merge/release sequence.
  No PR was merged, no artifact was published, no deployment ran, and no live
  resource changed.
- Disposable resources created by implementation: local image/tag
  `warpmetal-agent-sandbox:test-amd64` at image ID
  `sha256:792eb06b71dbceb224a5b14caef0045b2acab2007b081a08c03c2449bd20fb3a`;
  retain through P1 verification and do not remove without cleanup approval.
  P3 also created local disposable container
  `warpmetal-user-tools-p3-postgres` on `127.0.0.1:55435` solely for database
  gates; stop it after P3/P4 verification or request cleanup confirmation if it
  is still useful for the final gate.
- P5.S1 release checkpoint: image PR #4 merged as
  `3897a59c011abd678e10d55c25e759f3f1a1b963`. Exact main-push workflow run
  `34552134400` passed both test and publish jobs. The immutable image index is
  `ghcr.io/warpmetal/warpmetal-agent-sandbox@sha256:c2d391a1b7342920ddeb71ddc803a8a1fff29742354b03eb10490b73ffd5a7b4`
  and contains exactly one `linux/amd64` manifest plus one attestation manifest.
  Cosign v3.0.6 was downloaded to a disposable directory and verified against
  the checksum embedded in the exact pinned installer action. Independent
  keyless verification bound the signature to the image digest, repository,
  `image.yml@refs/heads/main`, push event, and merge SHA. The downloaded
  attestations matched their registry blob digests: the SPDX-2.3 SBOM contains
  462 packages, and the SLSA v1 provenance binds the amd64 manifest to the exact
  repository, main ref, push event, revision, and workflow run. P5.S1 is
  complete; this digest is verified but not yet configured in production.
- P5.S2 source-merge checkpoint: immediately before mutation Runtime PR #25 and
  agent-kit PR #36 were mergeable, clean, green, and each zero commits behind
  current `main`. Runtime merged as `566854a193427909a91651dc01e844a366054c5f`
  and its exact main CI run `34552537063` passed the Go gate, Docker drift gate,
  and package-preservation gates on AlmaLinux 9, Debian 12, Rocky Linux 9, and
  Ubuntu 24.04. Agent-kit merged as
  `19a29ab4577569db7c1a3904af17e8c260a6a539` and exact main CI run
  `34552540894` passed Node 20 and Node 22. Neither merge published or changed
  Runtime v0.1.26 or CLI 0.8.9. P5.S2 is complete.
- P5 remediation tests-only checkpoint: three disjoint new test files were
  inspected after their agents completed. The database-backed catalog rollout
  gate produced four intended failures: disabled and approved worker snapshots
  lack the exact legacy parse bridge, and both false/true bridge snapshots leak
  legacy fields through the new public projection. The executable deployment
  validation gate produced two intended failures and six passing controls:
  empty ordering approval is currently rejected and still marked required,
  while exact/malformed/mismatch/missing-base cases, unconditional env output,
  dispatchability, and concurrency already behave as expected. The generic VPS
  matrix source gate produced five intended failures because both protected
  actions and the task-bound driver are absent; it freezes the four OSes,
  destructive confirmation, one reload call plus exit-8 reconciliation,
  operation-bound TOFU, CLI 0.8.9, Runtime v0.1.26, exact digest, isolation,
  planning/coding/QA persistence, workspace erasure, and revocation evidence.
  Syntax, Ruff, and diff hygiene passed. These are the accepted semantic reds;
  one implementation cycle is authorized, with no live mutation yet.
- P5 rollout-remediation implementation checkpoint: the catalog worker now
  persists one exact legacy parse bridge for the still-live frontend while the
  new public catalog strips Runtime metadata to the four capacity-only fields.
  The ordering approval digest is optional only when empty, so production can
  deploy the schema with ordering disabled; any nonempty approval remains an
  immutable digest that must byte-match the required base image. Deployment
  documentation freezes the disabled-first activation and same-release
  rollback procedures. The protected acceptance workflow now exposes generic,
  task-bound reload and sandbox-exercise actions for the four certified OSes.
  Its durable driver pins CLI 0.8.9 and Runtime v0.1.26, resumes an existing
  reload operation, establishes operation-bound first-use trust followed by a
  strict replay, validates the exact immutable image and CLI-free outer
  isolation, exercises planning/coding/QA workspace persistence across a
  restart, revokes the temporary grant, and proves reconnection is denied.
- P5 rollout-remediation automated gate: the focused catalog database tests
  passed 4 tests, deployment-control tests passed 8, and matrix source tests
  passed 5. The wider backend selection passed 300 tests and the wider live
  contract selection passed 57. The final complete backend gate passed 2,527
  tests with 1 expected skip in 153.90s. The first complete Node run identified
  only two stale exact workflow-action counts after the two new protected
  actions; both focused files passed 17 tests after their expectations changed
  from 27 to 29. The full Node/build rerun then passed all 287 tests (247 pass,
  40 environment-dependent skips) in 60.78s. Ruff, Actionlint, all repository
  shell syntax, ShellCheck for the new driver, generated OpenAPI drift, LLM
  source/served byte parity, frontend lint, and diff hygiene passed; lint has
  five pre-existing warnings and no errors. The branch remains zero commits
  behind the fetched `origin/main`. It is ready for the required final fetch,
  commit/push, PR CI, and disabled-first production rollout.
- P5 rollout-remediation branch checkpoint: committed the bounded correction as
  frontend/backend commit `414d430` and fetched `origin/main` again immediately
  afterward. The branch is clean, contains current main (18 commits ahead and
  zero behind), and pushed normally to existing PR #148 without force. The
  updated PR test run is in progress. A read-only production secret-name audit
  confirms `RUNTIME_ORDERING_SANDBOX_IMAGE_DIGEST` is absent, preserving the
  required disabled-first rollout state; no production secret value, deploy,
  or live resource has changed yet.
- P5 disabled-rollout start: updated only the production
  `RUNTIME_SANDBOX_IMAGE_DIGEST` secret to the verified CLI-free image digest;
  a second secret-name audit confirmed the independent ordering approval remains
  absent. PR #148 was still clean, green, mergeable, and zero commits behind
  current main immediately before it merged as
  `7c3beea21026959573408502c0b1c79c8da31a5c`. Exact main run `34554818525`
  has started. Ordering must remain disabled until this run finishes and the
  four-field production catalog/UI are verified.
- P5 disabled-rollout failure checkpoint: main run `34554818525` passed the
  complete test job and published all four release images, and deployment
  accepted the empty approval pin. The inactive green candidate then recorded
  one `api:not_ready` response after 207 seconds of its 360-second soak. The
  coordinator stopped the candidate, restored the previous worker release,
  observed a fresh worker/catalog cycle, preserved the active blue route, and
  reported rollback success. Live `/health` is fully ready and purchasing-ready;
  ordering remains disabled. No retry is authorized until the exact candidate
  readiness dependency is diagnosed and reproduced. Read-only production
  preflight run `34556307417` is now gathering bounded post-rollback evidence.
- P5 candidate-soak diagnosis checkpoint: the read-only preflight run
  `34556307417` passed and found the active release healthy, the inactive
  candidate stopped cleanly, 25 database connections against a 100-connection
  limit, no waits, restarts, OOMs, worker errors, or connection rejections, and
  zero failures across 60 frontend plus 30 API probes. Two independent
  test-based reviews reconstructed the failed deploy: the candidate passed its
  direct gates, then exactly one HTTP-200 health response failed the strict
  predicate after 207 seconds. Database failure would have produced HTTP 503;
  refill readiness is static; therefore a stale worker heartbeat is the only
  plausible changing dependency, with malformed JSON/parser failure retained
  as a lower-probability ambiguity. The current candidate probe turns one
  sample into a permanent failure while the public probe already allows a
  bounded 120-second worker restart grace, and rollback replaces the worker
  before preserving decisive evidence. No catalog/coexistence defect was
  reproduced: nine catalog/heartbeat/readiness tests and four focused
  coordinator tests passed, and the old/new worker implementation is
  byte-identical.
- P5 candidate-soak remediation decision: before another deploy, freeze
  deterministic harness oracles that (1) tolerate a candidate response whose
  serving dependencies are ready but worker is false when it recovers inside
  the existing 120-second bound, (2) fail closed when worker unready persists
  through that bound, (3) distinguish invalid health JSON from worker-only
  unready, and (4) emit safe pre-rollback worker state and recent logs without
  container environment or secret output. Production edits remain unauthorized
  until the manager inspects the expected red failures. After the automated
  gate is green, run one bounded non-routing deployment-host validation before
  dispatching another full deploy. Ordering approval remains absent throughout.
- P5 candidate-soak tests-only checkpoint: four executable coordinator-harness
  tests were added without production edits and independently rerun by the
  manager. The focused command failed all four in 7.35 seconds for the intended
  semantics: a transient worker-only response immediately rolls back; sustained
  worker unready stops after three candidate calls rather than the 120-second
  bound; malformed HTTP-200 JSON is mislabeled `not_ready`; and rollback starts
  without worker image/running/restart/log evidence. `git diff --check` passes.
  These reds are accepted and authorize one bounded production correction in
  `deploy/deploy-blue-green.sh` plus matching operational documentation. They
  do not authorize ordering activation or another deployment yet.
- P5 non-routing host-validation design: the safe validation mode will start
  only the inactive candidate backend/frontend at the target immutable release,
  keep the existing singleton worker and public Nginx route unchanged, run the
  exact 360-second candidate/public probe soak, stop the candidate, and prove
  worker identity plus route state are unchanged before removing its durable
  transaction record. It must skip migrations, provider bootstrap, worker
  replacement, promotion, payment/order calls, and all Nginx installation.
  A protected main-only workflow dispatch with exact release confirmation will
  stage and run this mode on the production deployment host. A second normal
  worker is explicitly forbidden because it could claim real production work.
  Tests for success, fail-closed cleanup, skipped mutation/cutover operations,
  and workflow guards must be red before this validation mode is implemented.
- P5 candidate-soak correction checkpoint: the accepted production correction
  now validates JSON separately, keeps candidate serving dependencies strict,
  gives only worker-only unready responses the existing fixed 120-second grace,
  resets that timer on recovery, and fails closed when the bound expires.
  Candidate-soak failure captures validated worker identity/image/runtime state
  plus at most 100 recent application log lines before rollback replaces it;
  it never inspects container environment or renders Compose configuration.
  The four frozen behavior tests pass, the full coordinator suite passes 46
  tests in 88.26 seconds, and Bash syntax, ShellCheck, and diff hygiene pass.
  The deployment runbook documents the new policy and diagnostic. This code is
  locally verified but uncommitted and undeployed pending the non-routing host
  validation test contract and integrated gate.
- P5 non-routing host-validation tests-only checkpoint: two executable
  coordinator harness tests and one workflow source-contract test were added
  without production edits. The manager reran them: both coordinator tests
  failed semantically because the current path promotes on success and performs
  migration/worker/provider work on failure; the workflow test failed because
  the protected candidate-only workflow is absent. Python/Node syntax and diff
  hygiene pass. The red contracts are accepted and authorize one minimal
  candidate-only coordinator branch, its guarded main-only production workflow,
  and matching runbook text. No deployment, ordering activation, or order is
  authorized by this checkpoint.
- P5 non-routing host-validation implementation checkpoint: the coordinator
  now has an exclusive boolean candidate-only mode fixed at 360 seconds. It
  records the existing worker and active-route invariants, pulls/starts only the
  inactive backend/frontend, runs the shared candidate/public probes, stops the
  candidate, re-proves public health plus exact worker/route/protected-service
  state, and only then removes transaction/staging. Migration, worker recreate,
  provider bootstrap/invoice readiness, Nginx installation, promotion, and
  commerce/order paths are skipped. Interrupted mode is journaled as
  `MODE=CANDIDATE_ONLY` for the existing recovery entry point. A dedicated
  manual-only, main-only production workflow requires an exact published SHA
  and `CANARY-PRODUCTION-CANDIDATE:<sha>:360`, uses the pinned deployment host,
  and does not rewrite application secrets. Focused Python tests pass 2/2, the
  workflow contract passes 1/1, all 48 coordinator tests pass, related Node
  tests pass 100 with 40 environment skips, and Actionlint, Bash syntax,
  ShellCheck, and diff hygiene pass. `deploy.yml` remains unchanged and no live
  action has run.
- P5.S3 remediation integrated automated gate: with the retained disposable
  PostgreSQL configuration and Alembic at head, the complete backend suite
  passed 2,533 tests with 1 expected skip in 193.39 seconds. The complete
  frontend build/test gate passed 288 tests total (248 pass, 40 declared
  environment-dependent skips). Ruff, Actionlint, Bash syntax, ShellCheck,
  generated OpenAPI drift, Node syntax, and diff hygiene pass. Frontend lint
  has the same five pre-existing warnings and zero errors. The first backend
  invocation without `DATABASE_URL` produced the two already-documented fleet
  handler failures and 1,164 database skips; no oracle or code changed, and the
  correctly configured complete rerun is green. The single final integrated
  read-only review is now authorized; no second review cycle will be opened.
- P5.S3 single final review disposition: the reviewer returned one complete set
  with two accepted P1 release blockers. First, the candidate workflow embeds
  GitHub ref expressions directly in Bash before later secret-bearing steps;
  a valid hostile ref can therefore become shell source. The fix must move the
  main-only decision to a job-level expression and forbid untrusted/context
  interpolation in `run:` bodies. Second, candidate-only recovery journals only
  release/slot/mode while exact worker identity/state, route bytes, and
  protected-service state remain process-local; after interruption it could
  accept changed state and delete the journal. The fix must atomically persist
  hashes/identities before candidate mutation and make candidate-only recovery
  stop only the inactive pair, compare the durable snapshot exactly, never
  repair active services, and retain the journal on mismatch. Both findings are
  accepted for one consolidated test-first remediation. No second review pass
  will follow; the full automated gate must be rerun after remediation.
- P5.S3 final-review remediation red checkpoint: the workflow test now requires
  a job-level main guard and extracts every `run:` block to reject direct
  `github.*`/`inputs.*` shell interpolation; it fails twice against the unsafe
  workflow while the original safety contract still passes. Three compact
  coordinator tests (six parameterized cases) require one complete atomically
  promoted pre-mutation journal, no-repair successful interrupted recovery,
  and fail-closed journal retention for worker identity/restart, same-slot route
  byte, or protected-singleton drift. All six fail for the expected missing
  snapshot/proof behavior. The manager inspected and reproduced both red sets.
  One consolidated production correction is authorized with disjoint workflow
  and coordinator ownership; test oracles are frozen.
- P5.S3 final-review remediation green checkpoint: the manual candidate-only
  workflow now has a job-level `main` guard, passes GitHub/input values only
  through environment variables, and contains no direct context interpolation
  in shell bodies. Before any candidate pull/start, the coordinator writes and
  fsyncs a distinct temporary journal containing the exact worker identity and
  state hash, active-route presence and byte hash, and protected-service
  identity hash, then atomically promotes and directory-fsyncs it. Interrupted
  candidate-only recovery stops only the inactive pair and succeeds only after
  exact worker, route, protected-service, local-health, and public-health proof;
  any mismatch retains the journal and performs no repair. The focused
  deployment/recovery suite passes 54/54. The complete post-remediation backend
  suite passes 2,539 tests with 1 expected skip in 217.60 seconds. The complete
  frontend/integration suite passes 290 tests total (250 pass, 40 declared
  environment-dependent skips). Ruff, Actionlint, Bash syntax, ShellCheck,
  generated OpenAPI drift, Node syntax, and diff hygiene pass; frontend lint
  has the same five pre-existing warnings and zero errors. The requested single
  final review is closed and no second review loop will be opened.
- P5.S3 controlled rollout sequence: after one final fetch and merge of current
  `origin/main` with conflicts escalated rather than overwritten, open and pass
  the remediation PR. Merge it with `[skip deploy]` in the merge subject so the
  ordinary main workflow validates the merge but does not publish or deploy.
  From the newly merged main workflow, run the protected candidate-only canary
  for already-published release
  `7c3beea21026959573408502c0b1c79c8da31a5c` with the exact 360-second
  confirmation. Only after that non-routing production-host canary passes,
  manually dispatch the ordinary main deployment to publish/deploy the current
  main SHA. Keep `RUNTIME_ORDERING_SANDBOX_IMAGE_DIGEST` absent through this
  disabled-first deployment and catalog/UI verification; enable it with the
  already verified image digest only after all pre-activation gates pass.
- P5.S3 remediation merge checkpoint: immediately before PR creation,
  `origin/main` remained `7c3beea21026959573408502c0b1c79c8da31a5c` and the branch
  contained it with no conflict (`git merge origin/main` reported already up
  to date). Remediation commit `5ead8e681d26134a507e35ceeacc246b6c347cb4`
  was pushed without force. PR #149 passed its complete required `test` job in
  run `34561383151` (publish/deploy skipped) and merged cleanly as
  `a9d00a42940f42cdbadb385857b5f4adc84be978`. Its merge subject contains
  `[skip deploy]`; main validation run `34562020545` is in progress and must
  prove publication/deployment stayed skipped before the host canary dispatch.
- P5.S3 main validation attempt 1: backend coverage, Ruff, lint, the complete
  290-test Node suite, and admin build passed; publish and deploy were skipped.
  One unrelated admin visual-browser case failed when Chromium closed its
  inspection target (`Inspected target navigated or closed`), leaving 53/54
  admin tests green. The identical tree passed that case in PR run
  `34561383151`, so no product correction is authorized. One bounded rerun of
  the failed main job (run `34562020545`, attempt 2) is in progress; a repeated
  failure will stop rollout rather than begin a speculative fix loop.
- P5.S3 main validation final: run `34562020545` attempt 2 passed every test,
  build, and admin visual gate in 8m30s. Its publish and deploy jobs remained
  skipped, confirming the `[skip deploy]` boundary; attempt 1 was the bounded
  transient browser failure documented above. Protected candidate-only run
  `34563144766` is now dispatched from `main` for already-published release
  `7c3beea21026959573408502c0b1c79c8da31a5c` with the exact 360-second
  confirmation. Ordering remains disabled and no ordinary deployment has run.
- P5.S3 candidate-only canary failure boundary: run `34563144766` passed input,
  pinned-host, and artifact-staging steps but the single remote canary step did
  not terminate. It exceeded the declared 20-minute job limit; after a bounded
  platform-finalization grace, the manager canceled it and GitHub finalized it
  at 25 minutes with the explicit maximum-execution-time annotation. No job log
  was yet available. Immediate public `/health` remained `ok` with database,
  worker, compute inventory, SSH proof, and refill notifications true; public
  `/catalog` remained on the old 0.1.25/preinstalled-tool manifest with all OS
  compatibility flags true and aggregate Runtime support false. No ordinary
  deployment or activation is authorized. Protected recovery run `34564766201`
  is dispatched once: if the durable candidate-only journal exists it may stop
  only the inactive pair and must prove the exact snapshot; if no journal
  exists it must fail before host mutation.
- P5.S3 timed-out canary state proof: protected recovery `34564766201` reached
  the host and failed before mutation because `deployment.transaction` was
  already absent. Read-only preflight `34564878403` then passed in 1m35s:
  active slot blue remained on backend/frontend release `8f433317...`, the
  inactive green backend was stopped with exit 0, database identity/start time
  and `warpmetal_postgres_data` volume remained stable, no OOM/restart/health or
  connection-error signatures were present, and 60/60 frontend plus 30/30 API
  probes passed. This proves candidate cleanup and production preservation.
- P5.S3 SSH-EOF remediation red checkpoint: the test specialist reproduced the
  live process lifecycle locally. Stopping a background probe signals only its
  subshell PID; when that shell is waiting on a child, the child survives and
  retains inherited stdout/stderr, so the coordinator exits and deletes the
  journal while SSH never observes EOF. The new deterministic test forces that
  child state and fails in 3.62 seconds with `probe descendant retained the SSH
  stdout/stderr channel`, while confirming the coordinator itself exited. The
  red is accepted for one minimal process-group termination/reap correction.
  Current `origin/main` (`a9d00a4...`) was fast-forwarded into the same branch
  before production implementation, with no conflict.
- P5.S3 SSH-EOF remediation green checkpoint: public and candidate probes now
  start under Bash job control in distinct process groups. Startup verifies via
  Python 3 that each group ID equals the direct probe PID and differs from the
  coordinator group before the identifier is trusted. Shutdown TERM-signals
  the complete group, waits a bounded two-second grace, KILLs any survivor, and
  reaps the direct child; it refuses unsafe or coordinator-group identifiers.
  The frozen live-hang regression passes in 2.38 seconds under manager rerun;
  the test specialist's complete coordinator run passes 55/55 in 103.45
  seconds. Ruff, Bash syntax, ShellCheck, candidate-workflow tests 3/3,
  Actionlint, and diff hygiene pass. `deploy.yml` and all catalog, checkout,
  Runtime, image, worker, and ordering code are unchanged.
- P5.S3 SSH-EOF remediation merge checkpoint: fix commit
  `9367d34693ecc07440c4b8c246d861109e3f60c2` was created after the main
  fast-forward, followed by another fresh fetch/merge that reported already up
  to date. PR #150 passed its required complete CI run `34565543096` in 7m58s
  and merged cleanly with `[skip deploy]` as
  `0a8f813e2ecc22ce5bba9f1b74e3858c8e3ff171`. Its main validation run
  `34600021069` passed every backend, frontend, and admin gate in 10m04s;
  publication and deployment were skipped as required by the merge marker.
  Corrected protected candidate-only run `34600055636` then acquired the
  shared production lock and is exercising the already-published
  `7c3beea...` images without routing traffic. It passed in 7m07s, including
  clean bounded probe-group teardown and normal SSH stream closure. This clears
  the non-routing production-host gate for the ordinary main deployment;
  ordering activation remains a later, separate gate.
- P5.S3 disabled ordinary deployment start: manual main run `34601582566` was
  dispatched at exact head `0a8f813e2ecc22ce5bba9f1b74e3858c8e3ff171`
  after the corrected canary passed. The ordering-approval secret remains
  absent, so this run can publish and deploy the release but cannot expose
  selectable Runtime sandboxes.
- P5.S3 disabled ordinary deployment failure boundary: run `34601582566`
  passed the complete 9m58s test job and published all four application images
  in 2m57s. The green candidate passed 363 seconds of candidate soak, pricing
  parity and public verification, and was promoted. At 111 seconds of the
  post-promotion rollback window, one public API probe timed out with curl exit
  28; the coordinator failed closed and restored the prior blue route, stopped
  green, recreated the worker, and proved worker readiness. Current public
  `/health` is `ok` and the refreshed `/catalog` still exposes the old 0.1.25
  tool-manifest schema with `supported: false`, proving that 0.1.26 and ordering
  are not live. Read-only production preflight `34604105708` was dispatched to
  prove stable rollback state before any bounded retry decision.
- P5.S3 post-rollback evidence and next bounded gate: read-only preflight
  `34604105708` passed in 1m24s on active blue release `8f433317...`: the
  database identity/start time and `warpmetal_postgres_data` volume remained
  stable, stopped green had exit 0 with no restart/OOM/health/database error
  signatures, and 60/60 local frontend plus 30/30 local API probes passed.
  Failure analysis found the main coordinator permanently records the first
  transport error, while tests cover only worker-readiness grace and persistent
  curl failure—not ready, one API timeout, then ready. Tests-only work now
  freezes isolated-timeout recovery and sustained-timeout rollback. Because the
  earlier successful canary used target release `7c3beea...`, newly published
  release `0a8f813...` is separately under non-routing canary run `34604527682`
  before any next ordinary deployment. That canary passed in 7m18s with clean
  candidate teardown, proving the exact newly published images on the
  production host without routing traffic or mutating singleton services.
- P5.S3 isolated public-timeout remediation red/green checkpoint: two new
  deterministic coordinator tests froze ready -> one API curl exit 28 -> ready
  as recoverable, and repeated API transport timeouts as fail-closed with prior
  route/image/worker restoration and journal removal. Before implementation the
  focused pair was 1 failed/1 passed in 6.16s. Continuous public frontend/API
  probes now make exactly one immediate confirmation request with the same
  three-second bound before recording a transport failure; candidate/direct
  probes and successfully transported malformed/not-ready health responses
  remain strict. The pair passes 2/2 and adjacent probe/rollback tests pass 4/4;
  Bash, ShellCheck and diff hygiene pass. The first full coordinator gate found
  only the stale source-count contract (seven host-local calls after adding the
  two confirmations versus the old expected five); that assertion is being
  aligned and the complete gate rerun before commit.
- P5.S3 isolated-timeout remediation branch checkpoint: after the stale
  source-contract count was aligned to the two intentional confirmation curls,
  the exact failed test passed, the full coordinator suite passed 57/57 in
  124.88s, deployment workflow contracts passed 22/22, and Ruff, Bash,
  ShellCheck, Actionlint, and diff hygiene all passed. Fresh `origin/main`
  fetch/merge checks immediately before commit and again before PR creation
  both reported already up to date with no conflicts. Commit
  `2f36d6fdf77c50225f4cb4ce168802a3b6e1b2a1` was pushed without force and PR
  #151 is open cleanly against exact base `0a8f813...`; its complete CI run is
  `34605502343`. That run passed every test and skipped publish/deploy. A final
  fresh main merge check reported already up to date and PR #151 remained
  cleanly mergeable. It merged with `[skip deploy]` as
  `fe72615f0fcd3e9bbe6680c0c92aa824af6a2b41`; main validation run
  `34606529462` passed every gate, with publication and deployment skipped.
  Final non-routing canary `34607537432` uses the merged coordinator at
  `fe72615...` against the already-published target release `0a8f813...` before
  the next ordinary deployment. It passed in 7m06s with clean candidate
  teardown and normal SSH closure. Production contains
  `RUNTIME_SANDBOX_IMAGE_DIGEST` but still does not contain the independent
  `RUNTIME_ORDERING_SANDBOX_IMAGE_DIGEST` activation secret. Ordinary main run
  `34608303785` is dispatched at exact head `fe72615...` for the disabled-first
  publication/deployment. It passed test, published all four images, completed
  the candidate soak, promotion and five-minute rollback window, promoted admin
  services, and finished green. Production `/health` was fully ready and all
  four catalog products exposed only `capacity`, `sizes`, `supported`, and
  `temporaryLifetime`; all four certified OSes retained `cloudInit: true` and
  `agentRuntimeSupported: true`, while aggregate support remained false. Browser
  smoke confirmed the disabled pre-activation sandbox control, self-install
  copy, and absence of any tool selector. The independent ordering secret was
  then set to exact verified digest
  `ghcr.io/warpmetal/warpmetal-agent-sandbox@sha256:c2d391a1b7342920ddeb71ddc803a8a1fff29742354b03eb10490b73ffd5a7b4`,
  and activation deployment `34611222463` was dispatched against the unchanged
  exact main head `fe72615...`.
- P5.S3/P5.S4 activation completion checkpoint: activation run `34611222463`
  passed the complete test, publication, candidate soak, promotion, rollback
  window, admin, and public request gates, but the fresh catalog correctly
  remained fail-closed because the production Runtime release secrets still
  described the prior release. Their last-update timestamps predated the
  immutable v0.1.26 publication while the signing key and two image pins were
  current. The exact seven-value v0.1.26 tuple was independently reconstructed
  from release `385886185`, verified by archive/checksum hashes, P-256 signature
  verification, pinned normalized public-key hash, registry digest inspection,
  focused tests (8/8), and execution of the real application support gate. The
  complete tuple was then applied together. The branch was fast-forwarded from
  fresh `origin/main` without conflict before final main deployment
  `34614456719` at exact head
  `fe72615f0fcd3e9bbe6680c0c92aa824af6a2b41`. That run passed test in 7m47s,
  published all four application images in 3m20s, completed the full blue/green
  soak and rollback window, promoted admin services, and finished success.
  Fresh production `/health` reports every dependency ready and
  `purchasingReady: true`. Fresh `/catalog` reports `supported: true` for
  standard, agent, build, and heavy, exposes exactly `capacity`, `sizes`,
  `supported`, and `temporaryLifetime`, and retains `cloudInit: true` plus
  `agentRuntimeSupported: true` for AlmaLinux 9, Debian 12, Rocky Linux 9, and
  Ubuntu 24.04. In the real checkout, selecting Standard plus Ubuntu 24.04
  enabled the optional Runtime checkbox; enabling it exposed only count, size,
  lifetime, and per-agent overrides. No Codex, Claude, Cursor, Gemini, or other
  tool selector was present. P5.S3 and P5.S4 are complete; P5.S5 and P5.S6
  remain the only release acceptance gates.
- P5.S5 first live-matrix failure boundary: protected AlmaLinux reload run
  `34617345922` passed its workflow request validation but failed before the
  driver and before any Hivelocity mutation. The SSH client flattened the
  remote `bash -s --` argv into shell text without quoting, so the exact OS
  value `AlmaLinux 9 (VPS)` was parsed remotely and Bash rejected `(`. No
  power-off, reload, Runtime install, or sandbox mutation occurred. A focused
  regression packet must now execute the real wrapper/remote-shell argv path
  for all four certified OS names and the colon-bearing digest/confirmation,
  then a minimal wrapper fix and full workflow contract gates must pass before
  the protected reload is retried.
- P5.S5 Pay-stage cancellation addition: before PR #152 is merged, add one
  owner-authorized, idempotent cancellation mutation and a Pay-stage action for
  an order that the server can prove remains unpaid. The mutation must fail
  closed after payment, provider work, a signed or ambiguous payment attempt,
  or an unverified active charge. A prepared order with no upstream charge may
  cancel directly; an issued hosted charge may cancel only after an exact
  management lookup proves every bound charge expired and definitively
  unsettled. The server must linearize cancellation against payment state,
  retain correlation evidence, prevent provider fulfillment, and return the
  authoritative cancelled task. Only then may the browser clear the current
  tab's checkout session and return to Configure. The action belongs on Pay,
  including the expired-link state shown by the requester; it remains absent
  for paid, provisioning, ready, ambiguous, unknown, or merely active-pending
  states. Freeze backend race/authorization/idempotency/OpenAPI tests and
  executable frontend request/response/session tests before implementation.
- P5.S5 Pay-cancellation red checkpoint: the tests-only packet changes four
  files and adds no production code. The focused Node gate is 40 pass / 3
  semantic red: the exact cancellation request builder, validated cancellation
  executor/session clear, and accessible controls in both expired Pay panels do
  not exist. The focused PostgreSQL gate is 13 semantic red / 1 incidental
  wrong-owner pass because the route is absent; it covers two independently
  bound charge lookups, capability-only clearing, local safety refusals,
  upstream pending/settled/ambiguous/unavailable refusals, replay, closed body,
  authorization, and a late finalized payment quarantined in manual review with
  provider work untouched. The OpenAPI selector is red because
  `/tasks/{id}/cancel` is absent. Ruff, Python compilation, and diff hygiene
  pass. This red packet is accepted for one bounded implementation.
- P5.S5 Pay-cancellation green checkpoint: the owner-only cancellation route,
  exact OpenAPI contract, strict browser request/response handling, and Cancel
  order controls in both expired Pay panels are implemented. Active payment
  links remain non-cancellable because x402api exposes no public charge-revoke
  operation; every bound charge must instead be proven expired and definitively
  unsettled before cancellation. A final executable race test exposed and then
  closed one real interleaving: hosted-checkout replacement and cancellation
  now share the same task-scoped advisory guard, while the UI disables and
  rejects cancellation during replacement. Focused checkout tests pass 46/46,
  lint has zero errors (five pre-existing warnings), and the final fresh
  PostgreSQL suite passes 2,560 tests with one declared skip and zero failures
  in 253.60s. Statement and branch coverage gates pass at 88.28% and 75.39%.
  The branch must still merge fresh `origin/main`, update PR #152, pass CI, and
  deploy once before live P5.S5/P5.S6 acceptance resumes.
- P5.S5 merged/deployed and Python-floor checkpoint: PR #152 merged as
  `e761835db095db837f4b48fc4dcf7bc9844689fc`; production run `34624371670`
  passed tests, published all four application images, completed blue/green
  candidate soak and rollback observation, promoted admin services, and passed
  final smoke checks. Independent `/health`, `/catalog`, OpenAPI, and rendered
  checkout probes confirm purchasing ready, Runtime ordering enabled for every
  product and certified OS, the cancellation contract served, and Cancel order
  deployed. The first protected AlmaLinux retry `34627240342` then proved SSH
  argv preservation but failed its initial deployment-host binding check before
  Hivelocity mutation because that host runs Python 3.8 and `datetime.UTC`
  requires Python 3.11. A tests-only gate covers all two embedded Python blocks:
  both parse at the 3.8 feature floor, and the executable inspection oracle was
  red only for the missing `UTC` export. The bounded fix uses `timezone.utc`.
  Both blocks execute successfully in `python:3.8.20-slim`; the full site and
  workflow suite passes 295 total / 255 pass / 40 declared skips / zero fail,
  and Bash, ShellCheck, Actionlint, and diff hygiene pass. No VPS reload occurred
  in either failed attempt. This compatibility increment must pass a fresh PR,
  merge, and deployment before the same protected reload is retried.
- P5.S5 expired-lease continuation gate: PR #153 merged its test-harness-only
  Python 3.8 correction as `18ebe675bf9b7be218ddeb8dcf8d9e2d0ffc9f77`;
  main validation run `34628767626` passed and intentionally skipped application
  publication/deployment. Protected AlmaLinux retry `34628799627` then refused
  before any Hivelocity write because the exact operator test term had expired.
  Read-only inspection run `34629822177` proved device `69152` remains powered
  on and exactly bound, with zero checkout/payment history, but task
  `task_PT9aEIBCVIldPIQN59116hKl` is cancelled and its equal test/term deadline
  is `2026-09-10T22:03:52.196183Z`. The existing one-shot cancelled-test lease
  extension is intentionally limited to a different historical pristine
  three-sandbox baseline; it must not be dispatched or loosened. Owner direction
  then explicitly rejected another deployment for test-only bookkeeping and
  required direct VPS validation first. The proposed continuation test packet
  was stopped and removed without production edits. On the existing directly
  accessible Ubuntu 24.04 VPS `94.26.27.86`, the exact signed CLI-free sandbox
  digest `sha256:c2d391a1b7342920ddeb71ddc803a8a1fff29742354b03eb10490b73ffd5a7b4`
  pulled as Linux amd64 and passed the production isolation shape: UID/GID 1000,
  read-only root, writable persistent home, no host Podman/Docker socket, no
  Bubblewrap, no Codex/Claude/Cursor/Gemini executable, required development
  tools present, outbound HTTPS, and independent planning/coding/QA child work.
  A home-local executable, configuration, and workspace survived both restart
  and complete container recreation. The documented npm installs for Codex,
  Claude Code, and Gemini and official home-local installers for Codex, Claude,
  and Cursor all completed without root or authentication; their executables
  and help/version entry points survived restart and recreation. The v0.1.26
  amd64 archive downloaded on the VPS, matched SHA-256
  `f4b1fd76f67cc01385a1309eaf38e2aaca5b5eb90254df1b0549a02a45040791`,
  passed detached signature verification, and contained all required members
  plus the expected immutable legacy nested-policy members. The installer was
  deliberately not run without a valid authenticated bootstrap because that
  would create a half-registered host, not a valid acceptance result. All
  disposable containers, workspace files, tool installs, archive files, and
  the pulled image were then removed from the VPS. No PR, merge, deployment,
  Hivelocity mutation, order, payment, or production state change occurred.
- P5.S5/P5.S6 fresh order and signature checkpoint: the one authorized unpaid
  order created task `task_CHhXuC95ikMhXQHodnhQ94nW`, server
  `srv_JHr4edWj6FbbcFcWU6k0PKc1`, device `69167`, and VPS
  `runtime-126-e2e-20260911-a` at `104.129.171.187`. Its production cloud-init
  exposed a real detached-signature decoding defect: the provider decoded the
  Base64-wrapped `.sig` response once, leaving 96 bytes of Base64 text instead
  of the 71-byte DER signature OpenSSL requires. A protected same-VPS rerun of
  a corrected `/run` copy succeeded without reload, reboot, payment, or another
  order; Runtime v0.1.26 installed with exact artifact SHA-256
  `f4b1fd76f67cc01385a1309eaf38e2aaca5b5eb90254df1b0549a02a45040791`.
  Inspection run `34635890508` proved Runtime ready and one sandbox ready at
  revision 1/1 with zero payment attempts. Lifecycle run `34635952583` proved
  CLI-free sandbox create/restart/grant/revoke and denied reconnect. The narrow
  production fix is commit `9fde718` on frontend PR #154, with 77 focused
  backend tests, 53 Runtime/order/workflow tests, and 296 total site tests green;
  two full local PostgreSQL failures reproduce unchanged on clean main. The
  temporary live harness was reverted. PR #154 is intentionally held unmerged
  and undeployed under the owner's later deployment pause.
- P5.S7 planning/baseline checkpoint: official OpenAI documentation confirms
  Codex Desktop discovers concrete aliases from `~/.ssh/config`, resolves them
  with OpenSSH, requires `ssh <alias>` to work, and launches the remote Codex
  app server through the remote login shell with `codex` on PATH. Current
  official Cursor CLI documentation confirms interactive `agent` and
  headless `agent -p`; current Cursor Remote SSH evidence includes an
  `ssh -T -D ... bash --login -c bash` launch, so IDE compatibility remains
  deliberately unclaimed pending the actual test. Agent-kit and Runtime
  branches fetched and fast-forwarded to current `origin/main` without
  conflicts before test edits. Clean baselines are agent-kit `npm test` 91/91
  and Runtime Go 1.25 in Docker `go test ./...` all packages green. The local
  host has OpenSSH 9.6p1, ChatGPT Desktop with bundled Codex CLI 0.150.0-alpha.8,
  Cursor.app, and Anysphere Remote SSH 1.1.14, allowing the later bounded client
  smoke. Three disjoint tests-only packets are now authorized; production code
  remains blocked until their red evidence is inspected.
- P5.S7-B existing-Runtime proof: tests-only changes in
  `internal/access/access_test.go` and
  `cmd/warpmetal-sandbox-gateway/main_test.go` execute the actual private
  gateway request path. Empty interactive commands, client commands,
  `internal-sftp`, OpenSSH `sftp-server`, and SCP requests all reach only the
  assigned sandbox ID; unknown/revoked grants never call container execution;
  active revocation cancels execution, waits for session exit, and denies
  replay. Packaged sshd retains public-key-only authentication and disables
  TCP/stream-local/agent/X11/tunnel forwarding; the gateway contains no host
  shell or alternate client-trust path. These assertions were green on current
  source rather than semantic red, which is accepted because P5.S7 introduces
  no intended Runtime behavior. Docker Go 1.25 focused, focused race, installer,
  full `go test ./...`, gofmt, and diff hygiene all pass. No Runtime production
  change or Runtime version bump is justified; stale-pin refusal remains in the
  local CLI packet.
- P5.S7-C docs-contract red checkpoint: one new agent-kit test file adds no
  documentation or production code. The focused help/README/source-skill/
  plugin-skill run is 5 existing pass and 4 expected semantic failures; the
  four new tests alone are 0 pass / 4 fail. Missing contracts are
  `install-ssh`, authenticated profile refresh followed by explicit alias
  refresh, confirmed removal, interactive/one-shot SSH and Codex/Claude/Cursor
  CLI entry points, sandbox-owned provider authentication, distinct key and
  grant per sandbox, Codex Desktop concrete alias and login-shell PATH, and
  unchanged owner-key/host-shell/forwarding denials. Source/plugin byte parity
  remains green and diff hygiene passes. Official OpenAI evidence supports the
  Desktop contract; official Cursor docs support only interactive/headless CLI,
  so Cursor IDE remains unclaimed pending P5.S7-G.
- P5.S7-A CLI red checkpoint: one new focused test file adds no production or
  documentation code. Syntax and diff hygiene pass; its focused result is 12
  total, one closed-profile/fingerprint assertion green and 11 deterministic
  semantic failures. Ten failures identify the absent `src/ssh-alias.js`
  contract and the CLI failure is the exact unknown
  `sandbox access install-ssh` command. The accepted tests freeze the private
  `~/.ssh/warpmetal.d` layout, injection-safe concrete alias, exact hardened
  block without `BatchMode`, `IdentityAgent`, `RemoteCommand`, or `RequestTTY`,
  first-precedence OpenSSH resolution, 0700/0600 modes, safe regular identity,
  symlink/non-regular/collision refusal with no partial writes, byte/inode-exact
  replay, explicit REFRESH/REMOVE behavior, and local-only safe JSON. Production
  implementation P5.S7-D is now authorized against these assertions.
- P5.S7-D/F local green checkpoint: agent-kit now exposes local-only
  `sandbox access install-ssh` and `remove-ssh`, writes a dedicated pinned
  known-hosts file and concrete managed fragment, and reports only safe IDs,
  operation, alias, and paths. The package version is now 0.8.10; no Runtime
  version bump is needed. The first focused implementation run exposed one
  incorrect OpenSSH 9.6 test assumption: with `ControlMaster no`, `ssh -G` may
  omit `controlpath` even though the exact fragment contains `ControlPath none`.
  The corrected oracle retains the exact-fragment requirement and rejects any
  resolved non-`none` control path. A single bounded adversarial follow-up found
  seven real local safety gaps: missing-target removal could strip a pre-existing
  include, unmarked/orphan artifacts could be overwritten or removed, paths
  containing spaces were rejected, and a literal included user config collision
  was missed. Those cases were fixed without changing the security boundary.
  A bounded follow-up added wildcard and recursive user-Include collision
  detection and updated every Cursor example to the current official
  `agent` / `agent -p` entry points. The final focused alias/help/docs result
  is 34/34 green. Full agent-kit `npm test` is 125/125 green; `npm run check`,
  source/plugin byte parity,
  `npm pack --dry-run`, and diff hygiene pass. The package dry-run contains the
  new module and reports version 0.8.10.
- P5.S7-E/F Runtime green checkpoint: Runtime production remains unchanged.
  README and SECURITY now explain that the alias is only a client view of the
  existing locked `warpmetal-sandbox` account and forced grant gateway, with no
  sandbox sshd, new port, owner key, host shell, forwarding relaxation, or
  client `RemoteCommand`. Focused gateway and access tests, the race run,
  full Go 1.25 `go test ./...`, future-release packaging contract, and diff
  hygiene pass. Runtime remains the immutable signed v0.1.26 already live.
- P5.S7 Codex discovery inspection: the installed ChatGPT Desktop build's local
  discovery implementation parses `~/.ssh/config`, recursively follows
  `Include` directives and globs, collects concrete `Host` aliases, and resolves
  each with `ssh -G -F`. Therefore the dedicated concrete fragment behind the
  absolute first-precedence managed Include satisfies the documented discovery
  shape without duplicating or overwriting the Host block in the main config.
  Live remote-app startup still remains part of P5.S7-G.
