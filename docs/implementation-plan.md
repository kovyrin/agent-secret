# Implementation Plan: Agent Secret Broker

Source: [Product Requirements](prd.md)

## Epic Status Values

- `Not started`: no implementation work has begun.
- `In progress`: work is underway, but the epic definition of done is not met.
- `Blocked`: work cannot continue until a named dependency is resolved.
- `Complete`: the epic definition of done is met and verified.

## Assumptions

- The project is a standalone repository and should not depend on unrelated
  external project code, scripts, credentials, or runtime assumptions.
- When Go code is added, its module path is `github.com/kovyrin/agent-secret`
  from the first implementation commit.
- Go is the default language for the CLI, daemon, policy engine, socket API, and
  CLI-owned process supervision.
- SwiftUI/AppKit is the default choice for the native macOS approval app. V1
  starts as a minimal real `.app` bundle launched on demand, with a stable app
  boundary that can later grow into a menu bar app.
- The native approver uses Apple's Unified Logging through `os.Logger` for
  non-secret troubleshooting events.
- macOS is the only supported v1 platform.
- 1Password remains the only secret backend for v1.
- Default secret delivery is environment variable injection through
  `agent-secret exec`.
- Session mode and credential helpers come after the `exec` path is proven.
- Live 1Password tests require explicit opt-in configuration and must not print
  values.
- V1 is private dogfood first, with standalone structure and docs.
- The first real dogfood workflows are Terraform and Ansible commands that need
  scoped credentials.
- A generic `op-secrets.yml`-style config-driven secret sync flow is a candidate
  follow-on dogfood workflow.
- The first implementation accepts explicit `--secret ALIAS=op://...` mappings
  only. Config-file mapping support is deferred.
- Delivery order is env-only `agent-secret exec` first, then ephemeral Unix
  socket reads for tools or wrappers that cannot consume env vars cleanly.
- V1 approval binds to command shape, cwd, delivery mode, TTL, and exact secret
  refs. Max-read policy is session/socket-only, not part of env-mode `exec`.
  `--repo`, repo-root binding, and git commit binding are out of scope for v1.
  Delivery mode is implicit env-mode `exec` in MVP and is not shown in the
  approval UI, but it remains in the policy/reuse key so future delivery modes
  cannot reuse env approvals.
- For `agent-secret exec`, `--cwd` sets the child working directory, defaults to
  the caller's current cwd, and is part of the approval/reuse key.
- `--reason` is required for every `agent-secret exec`, including reused
  invocations, and must match exactly for reusable approval reuse.
- Reasons are trimmed free text, must be non-empty after trimming, and are capped
  at 240 characters.
- The validated trimmed reason is the single reason string used for approval
  display, reuse matching, and audit; raw pre-trim input is not retained.
- Missing, blank, or over-limit reasons fail before approval UI,
  reusable-approval lookup, SDK access, or child spawn.
- `agent-secret exec` TTL defaults to 2 minutes and is bounded to 10 seconds
  through 10 minutes.
- TTL starts when the daemon receives the request. Queued requests can expire
  before they are shown and fail closed without 1Password access or secret
  delivery.
- Command approvals are one-shot by default, with optional same-command reuse
  for the requested TTL and at most 3 matching uses after the base path works.
- Reusable approval is chosen only by the operator in the approval UI; the CLI
  has no `--reuse` request or hint flag.
- Approval is always required for secret access in v1; there is no
  `--require-approval=false` or approval bypass flag.
- Matching reusable approvals bypass the approval prompt queue because they do
  not require UI. They still must pass match, TTL, use-count, audit,
  cache/fetch, and payload-delivery checks.
- The daemon is part of v1, but hidden behind the CLI. `agent-secret` starts it
  on demand and users should not manage it manually.
- The CLI starts a separate `agent-secretd` process, waits for socket readiness,
  and the daemon remains alive after the wrapped command exits.
- If the daemon disconnects or restarts while `agent-secret exec` is waiting for
  approval, reusable approval validation, fetch, audit, or payload delivery, the
  CLI fails closed with a daemon-disconnected error. It does not auto-reconnect,
  recreate the request, or transparently restart the daemon for that in-flight
  request.
- The daemon does not spawn, supervise, signal, or wait for `exec` children.
  It owns approval, 1Password access, reusable approval/session state, secret
  cache, and audit. `agent-secret exec` owns child process spawning, waiting, and
  stdout/stderr passthrough.
- MVP `exec` uses the single per-user daemon socket for request, approval result,
  approved environment payload delivery, and command lifecycle reporting. It does
  not create one-shot secret-payload sockets or file descriptors.
- The native approver app also uses the single per-user daemon socket. The daemon
  launches or activates the app; the app connects back, fetches pending approval
  metadata, and submits its decision. Approval IPC does not use stdin/stdout,
  argv/env payloads, or temp files.
- The daemon accepts `approval.response` only from the approver process launched
  or activated for that request, verified by socket peer PID and executable
  identity. Request ID and nonce are required but not sufficient by themselves.
- The daemon stays alive until manually stopped or user logout. Normal use is
  automatic, but `agent-secret daemon status/start/stop` exists for
  troubleshooting.
- No operational state persists beyond the append-only audit log. Approvals,
  sessions, counters, nonces, sockets, and cached values are memory-only and are
  cleared on daemon stop.
- `agent-secret daemon stop` does not track, signal, or manage already-spawned
  child processes; it stops daemon-owned state only.
- `agent-secret daemon stop` attempts one best-effort `daemon_stop` audit event,
  but shutdown does not wait on or fail because of that event.
- Normal agent requests use approval-first semantics: no 1Password SDK fetch or
  ref existence check happens before local broker approval.
- Executable path resolution happens before approval and before any 1Password
  SDK access; unresolved executables fail closed with no prompt. Resolution uses
  the requesting CLI process environment at request time, including the caller's
  `PATH`, and stores the resolved absolute executable path for approval,
  execution, audit, and reuse matching.
- Approved refs are all-or-nothing in v1; one fetch failure prevents any secret
  delivery.
- After approval, approved refs are fetched with bounded concurrency. Fetch
  order does not affect delivery, cache updates, or audit semantics; one failed
  fetch drops the whole attempt and prevents `agent-secret exec` from spawning
  the child.
- Duplicate `op://` refs are fetched once per unique ref, then fanned out to all
  approved aliases for delivery and cache lookup.
- V1 accepts arbitrary `op://` refs shown in the approval prompt. No allowlist
  or policy file is part of v1.
- Aliases are required in v1; env delivery uses the alias as the env var name.
- Aliases must match `[A-Z_][A-Z0-9_]*`.
- Audit logs store full `op://` refs in v1, never secret values, and must be
  current-user-only by default.
- Audit logs use `~/Library/Logs/agent-secret/audit.jsonl` on macOS in v1; there
  is no CLI audit-path override.
- The broker must never print secret values to stdout/stderr and must never
  write secret values to disk.
- `agent-secret --help` and subcommand help are part of the MVP interface and
  should be detailed enough for coding agents to understand safe usage without
  reading the PRD.
- Go linting must be wired into project lint and pre-commit paths before the
  first Go implementation files land.
- The default approval UI stays compact: reason, command, cwd, optional resolved
  command binary, refs, and approval duration. Audit/debug metadata and implicit
  env-mode delivery details stay out of the prompt by default.
- Reusable approvals keep approved secret values in daemon memory until TTL,
  max-use exhaustion, or daemon stop. Sessions also clear on explicit destroy
  when session commands are implemented.
- V1 has no reusable approval list/destroy commands. Manual early clearing of
  reusable approvals is done with `agent-secret daemon stop`.
- Policy/session objects are value-free. Reusable approval and session raw
  values live only in a separate daemon-owned in-memory `SecretCache` keyed by
  approval/session ID plus unique ref; audit writers and approval view models
  must never receive cache entries. `agent-secret exec` may hold approved values
  transiently in memory only while preparing and supervising the child process.
- While reusable values are cached and valid, the daemon must not call the SDK
  again for those refs.
- `--force-refresh` refetches values for a matching reusable approval and
  updates the cache after an all-or-nothing successful fetch. A refresh-backed
  request consumes one reusable use when the daemon sends the approved
  environment payload to `agent-secret exec`.
- Reusable use count is consumed when the daemon sends an approved environment
  payload to `agent-secret exec`, because the values have left daemon memory.
  Failures before payload delivery do not consume a use. Failures after payload
  delivery, including CLI spawn failure, `command_started` audit failure,
  immediate child exit, or non-zero child exit, still consume a use.
- If the daemon disconnects after payload delivery and after child spawn,
  `agent-secret exec` lets the child continue, preserves stdout/stderr passthrough
  and child exit code, prints one non-secret stderr warning after the child exits,
  and reports that daemon-owned completion audit could not be written.

## Non-Goals

- No dependency on external app code, deployment scripts, credentials, or
  runtime services.
- No Linux, Windows, remote agent, or cloud service support in v1.
- No replacement for 1Password storage.
- No `op read` fallback path.
- No private macOS APIs or Accessibility-permission hacks for approval UI.
- No `--no-native-ui` or terminal approval fallback path in v1.
- No raw secret output in default flows.
- No command that prints secret values to stdout or stderr.
- No disk-backed secret delivery, including temporary credential files.
- No policy-file language until the broker, approval, and `exec` paths work.
- No allowlist implementation in v1.
- No broad `--secret-config` implementation in the first `exec` milestone;
  project-local `--profile` support covers named ref bundles.
- No reusable approval management commands in v1 beyond `agent-secret daemon
  stop`.
- No public-release polish such as notarized installers, contribution process,
  or broad support docs until the private dogfood loop works.

## Epic 1: Standalone Project Scaffold

Status: Complete

### Epic 1 Acceptance Criteria

- The repository is self-contained and documents its standalone boundary.
- Future build outputs and runtime artifacts are ignored inside the repository.
- The PRD and implementation plan are linted and free of external-project-only
  assumptions.
- Project lint/pre-commit paths will include future Go files.
- Placeholder commands are documented but no unvalidated dependencies are added.

### Epic 1 Definition Of Done

- Markdownlint passes for all Markdown files.
- The project lint scripts are ready to lint future Go modules before
  implementation code lands.
- `git status -sb` shows only intentional scaffold files.
- The README clearly states that host projects are consumers, not dependencies.

### Epic 1 Risks And Mitigations

- Risk: the project quietly starts relying on external project scripts.
- Mitigation: keep a local `AGENTS.md` boundary and create local commands before
  relying on them in implementation work.

### Epic 1 Tasks

#### Task 1: Create the isolated docs scaffold

- Goal: create the standalone planning scaffold without coupling it to a host
  project.
- Preconditions/inputs: source PRD and standalone repository boundary.
- Failing test/check: `npx --yes markdownlint-cli '**/*.md'` fails before the
  docs exist or if the docs violate lint rules.
- Implementation:
  - create `README.md`
  - create `AGENTS.md`
  - create `docs/prd.md`
  - create `docs/implementation-plan.md`
  - create `.gitignore`
- Verification:
  - `npx --yes markdownlint-cli '**/*.md'`
  - `git status -sb`

#### Task 2: Document initial code layout and repository boundary

- Goal: commit an initial code layout that matches the repository boundary while
  leaving research-sensitive internals adjustable.
- Preconditions/inputs: PRD architecture decisions and v1 language choices.
- Failing test/check: a short architecture note lists the selected module
  layout, repository boundary, and why rejected alternatives were skipped.
- Implementation:
  - document `github.com/kovyrin/agent-secret` as the Go module path
  - document the approver as a minimal SwiftUI/AppKit `.app` bundle launched on
    demand, with stable protocol and bundle boundaries for later menu bar
    expansion
  - document how the repository boundary preserves import paths
- Verification:
  - `npx --yes markdownlint-cli docs/*.md`

#### Task 3: Wire Go lint gates before implementation code

- Goal: make Go linting a prerequisite for the first Go source files instead of
  a cleanup task after code exists.
- Preconditions/inputs: project lint command and pre-commit behavior.
- Failing test/check: pre-commit lint would skip a future `go.mod` or changed
  Go file.
- Implementation:
  - ensure project lint discovers `go.mod`, `go.sum`, `.go` files, and future
    Go lint config files
  - require the current repo Go lint suite, including `gofmt` and `go vet`, to
    pass before Go implementation PRs are considered ready
  - add any future Go lint tools, such as `golangci-lint` or `staticcheck`, to
    this same script path before relying on them in code review
- Verification:
  - `go test ./...`
  - project lint command

## Epic 2: Research Spikes

Status: Complete

Spike harnesses are implemented for all four Epic 2 surfaces. Local non-secret
tests pass, and live 1Password SDK resolution has been verified with a
test-only metadata-only integration run. The manual foreground smoke initially
showed Finder could cover the alert; after raising the alert window explicitly,
the prompt was visually confirmed in front. See
[Epic 2 Spike Notes](epic-2-spikes.md).

### Epic 2 Acceptance Criteria

- The 1Password Go SDK can resolve a test-only `op://` ref without printing the
  value.
- Swift can show a foreground approval prompt when launched from CLI or daemon
  context.
- Go can gather reliable peer credential data on macOS. A local C probe on
  macOS 26.3 with the macOS 26.2 SDK verified peer UID/GID, PID, executable
  path, and cwd over Unix sockets; the Go implementation should fail closed if
  equivalent checks cannot be implemented.
- A mock `exec` wrapper can inject synthetic values into a child process,
  preserve exit code, and propagate interrupts to the child.

### Epic 2 Definition Of Done

- Each spike has a small runnable program or test.
- Each spike records observed behavior and failure modes.
- Live tests are opt-in and use test-only refs.
- No spike logs or fixtures contain secret values.

### Epic 2 Risks And Mitigations

- Risk: SDK or macOS behavior differs from the PRD assumptions.
- Mitigation: complete these spikes before building the daemon contract.

### Epic 2 Tasks

#### Task 1: Prove 1Password Go SDK resolution

- Goal: confirm the official SDK and desktop-app auth behavior.
- Preconditions/inputs: a test-only `op://` reference supplied through local
  opt-in configuration.
- Failing test/check: `go test -tags integration ./...` includes a skipped live
  test that fails when explicitly enabled and SDK resolution cannot complete.
- Implementation:
  - create a minimal Go module and SDK wrapper
  - add a live integration test gated by an environment variable containing the
    test ref
  - print only length, hash, or metadata in test output
  - record prompt cadence and error behavior in docs
- Verification:
  - `go test ./...`
  - `AGENT_SECRET_LIVE_REF="op://..." go test -tags integration ./...`

#### Task 2: Prove foreground Swift approval

- Goal: verify a native approval helper can get user attention without private
  APIs.
- Preconditions/inputs: mock approval request JSON.
- Failing test/check: a Swift UI smoke command exits non-zero unless the helper
  accepts mock request input and returns approve, deny, or timeout.
- Implementation:
  - create the smallest viable SwiftUI/AppKit `.app` bundle
  - keep the app launch-on-demand only for v1, but preserve stable app,
    protocol, and view-model boundaries so it can later become a menu bar app
  - show a foreground window with mock request data
  - return a structured decision through a mock daemon socket, matching the v1
    app-connects-back flow
  - document launch behavior when another app is active
- Verification:
  - `cd approver && swift test`
  - manual smoke: launch the helper while another app is focused and record
    the result

#### Task 3: Implement strict macOS Unix socket peer credentials

- Goal: enforce peer UID, GID, PID, executable, and cwd checks for session/socket
  reads on macOS.
- Preconditions/inputs: local server and client test binaries.
- Failing test/check: a Go test or smoke command fails until the server captures
  peer UID/GID, peer PID, executable path, and cwd, rejects missing metadata, and
  rejects mismatched expected peer policy.
- Implementation:
  - create a Unix socket server/client pair
  - inspect peer credentials through public APIs equivalent to `getpeereid`,
    `LOCAL_PEERPID`, `LOCAL_PEERCRED`, `proc_pidpath`, and
    `PROC_PIDVNODEPATHINFO`
  - require same UID and expected peer PID/executable/cwd policy for
    session/socket reads
  - fail closed if required peer metadata is unavailable or mismatched
- Verification:
  - `go test ./...`
  - `go test -run PeerCred -v ./...`

#### Task 4: Prove mock `exec` wrapper behavior

- Goal: validate child-only secret delivery and process behavior before
  connecting 1Password.
- Preconditions/inputs: synthetic secret values supplied by test code.
- Failing test/check: tests fail until the wrapper injects values only into the
  child process, preserves exit status, forwards interrupts to the child, and
  writes metadata-only audit events.
- Implementation:
  - create a CLI-owned process supervisor package
  - add tests for env injection, exit code propagation, signal forwarding,
    approval/TTL cleanup, and audit redaction
  - use test-only helpers that assert synthetic env delivery without printing
    the synthetic values
- Verification:
  - `go test ./...`

## Epic 3: Core Request, Policy, And Audit Packages

Status: Complete

### Epic 3 Completion Notes

- Added pure Go request validation for required trimmed reasons, exact
  `op://` refs, executable resolution, cwd normalization, TTL bounds, delivery
  mode safety, env alias conflicts, and queued-request expiry checks.
- Added memory-only policy primitives for reusable approvals, exact reuse keys,
  use-count consumption semantics, session/socket capability handles, nonce
  checks, max-read enforcement, explicit destroy, and a separate value-holding
  `SecretCache`.
- Added metadata-only JSONL audit writing with fixed macOS path
  `~/Library/Logs/agent-secret/audit.jsonl`, current-user-only file modes,
  reusable-approval audit adapter support, and canary tests proving event shapes
  do not carry secret values.
- Verified with `go test ./...`.

### Epic 3 Acceptance Criteria

- Request validation rejects missing, blank, or over-240-character reasons,
  invalid `op://` ref syntax, TTLs outside 10 seconds through 10 minutes for
  `exec`, and unsafe delivery combinations.
- Policy enforcement covers exact refs, TTL, delivery mode, request nonce, and
  max reads only for session/socket handles.
- Audit events are structured and never contain secret values.
- The core packages can be tested without 1Password or Swift.

### Epic 3 Definition Of Done

- Unit tests cover happy paths, denial paths, expiration, session/socket max
  reads, and audit redaction.
- The package interfaces are small enough to keep SDK, UI, and process
  supervision swappable in tests.
- `go test ./...` passes.

### Epic 3 Risks And Mitigations

- Risk: policy logic becomes tangled with SDK and UI code.
- Mitigation: keep pure request, policy, and audit packages with fake
  collaborators.

### Epic 3 Tasks

#### Task 1: Define request and secret reference models

- Goal: represent the broker request contract in Go.
- Preconditions/inputs: PRD request fields and CLI examples.
- Failing test/check: unit tests for valid requests, missing reason, blank
  reason after trimming, over-240-character reason, duplicate aliases, missing
  aliases, invalid alias names, invalid `op://` ref syntax, missing TTL defaults,
  TTL below 10 seconds or above 10 minutes for `exec`, TTL starting at daemon
  request receipt, queued request expiry before prompt display, rejection of
  `--max-reads` for env-mode `exec`, and invalid session/socket max reads. Tests
  also cover executable path resolution failure, successful `PATH`-based
  resolution using the caller environment, slash path resolution relative to cwd,
  and duplicate refs with different aliases as a valid request.
- Implementation:
  - add request structs
  - parse and validate `op://` refs without resolving them
  - resolve and normalize executable path from caller request-time context,
    command shape, cwd, TTL, delivery mode, and session/socket max reads when
    applicable
  - leave repo root and git metadata out of the v1 request model
- Verification:
  - `go test ./...`

#### Task 2: Implement policy sessions and capabilities

- Goal: enforce TTL, max reads, approved refs, and nonce binding.
- Preconditions/inputs: request model exists.
- Failing test/check: tests for expired sessions, exhausted reads, mismatched
  handles, mismatched nonce, mismatched executable path, mismatched command shape
  for reusable approval, mismatched `--override-env` state, mismatched overridden
  aliases, max-use exhaustion, payload-delivery use consumption, CLI spawn
  failure after payload delivery still consuming a use, immediate child exit
  still consuming a use, non-zero child exit still consuming a use, post-spawn
  `command_started` audit failure still consuming a use, CLI disconnect after
  payload delivery still consuming a use, pre-payload failure not consuming a
  use, approval reuse audit events, destroyed sessions, and value-free
  policy/session serialization even when the
  `SecretCache` contains canary values.
- Implementation:
  - add in-memory session store
  - add capability handle generation
  - track per-handle read counts
  - model one-shot approval as the default reuse policy
  - add optional same-command reuse keyed by stated reason, resolved executable
    path, exact argv array, cwd, exact aliases and refs, delivery mode,
    `--override-env` state, exact overridden aliases, requested TTL, and a 3-use
    limit; requester PID/process identity stays audit-only for MVP `exec` reuse;
    if `PATH` later resolves the same argv to a different executable, reuse must
    miss
  - skip approval UI on reusable approval match and emit `approval_reused`
    metadata with remaining TTL and remaining use count before fetch or payload
    delivery; fail closed if writing that audit event fails
  - bypass the single-active-approval queue for reusable approval matches,
    including `--force-refresh`, because no approval prompt is needed
  - add a memory-only `SecretCache` for reusable approvals and sessions, keyed
    by approval/session ID plus unique ref
  - keep secret values out of policy objects, audit event inputs, and approval
    view-model inputs
- Verification:
  - `go test ./...`

#### Task 3: Implement metadata-only audit writer

- Goal: produce useful audit events without leaking values.
- Preconditions/inputs: request and session events.
- Failing test/check: tests fail if event JSON contains known synthetic secret
  values, if audit files have permissive modes, or if callers can override the
  audit path. Tests fail unless audit events store the same validated trimmed
  reason used by approval/reuse and do not retain raw pre-trim input.
  Request-flow tests fail until unwritable or insecure audit logs stop the
  request before approval UI or SDK access.
- Implementation:
  - add JSONL event types
  - add `command_starting`, `exec_client_disconnected_after_payload`,
    `command_started` with child PID, and command completion events with exit
    code or signal
  - redact or omit secret values by type
  - use `~/Library/Logs/agent-secret/audit.jsonl` as the fixed macOS audit path
  - create audit files with current-user-only permissions
  - make audit writability/security checks a pre-approval gate
  - add tests with synthetic canary secret values
- Verification:
  - `go test ./...`

## Epic 4: CLI And `exec` Process Supervision

Status: Complete

### Epic 4 Completion Notes

- Added `agent-secret` and `agent-secretd` Go entrypoints.
- Added detailed top-level, `exec`, `daemon`, and `doctor` help for coding
  agents.
- Added strict `exec` parsing for required `--reason`, repeated
  `--secret ALIAS=op://...`, `--` argv boundary, TTLs, `--override-env`, and
  `--force-refresh`; `--json`, shell-string command input, and `--reuse` are
  rejected. Added `--only` for profile alias subsets.
- Added project-local `agent-secret.yml` / `.agent-secret.yml` profile loading
  for named secret bundles, config `default_profile`, profile default reasons,
  profile default TTLs, config/profile/secret account defaults, and nested
  profile includes.
- Added a single-socket JSON protocol for `request.exec`, `command.started`,
  `command.completed`, daemon status, and daemon stop.
- Added per-user daemon socket discovery, stale-socket cleanup, on-demand daemon
  start, readiness wait, explicit daemon status/start/stop commands, and tests
  that prove the daemon remains alive after startup until explicitly stopped.
- Added a mockable daemon broker that proves approval-before-fetch ordering,
  denial-before-fetch behavior, all-or-nothing fetch failure, duplicate-ref
  deduplication, empty-string value delivery, reusable approval cache reuse,
  `--force-refresh`, audit preflight before approval/SDK access, and value-free
  audit events.
- Wired `agent-secret exec` to request approved env payloads from the daemon and
  then spawn the child itself with stdout/stderr passthrough and child exit-code
  propagation.
- The product daemon currently fails closed for real `exec` requests because
  native approval and real approver IPC are Epic 5. Epic 4 proves the exec path
  with mock approver/resolver tests and the real daemon lifecycle with binary
  smoke tests.
- Verified with `go test ./...`, `go test -tags integration ./...`,
  `go build ./cmd/agent-secret ./cmd/agent-secretd`, lint, and manual binary
  smoke commands.

### Epic 4 Acceptance Criteria

- `agent-secret exec` accepts reason, refs, TTL, and a command; `--max-reads` is
  reserved for session/socket reads.
- The broker approval step occurs before any 1Password fetch.
- The daemon never spawns the child process.
- The child process receives approved secrets through `agent-secret exec`; the
  parent agent receives no raw values from `agent-secret` output.
- The first implementation supports environment injection only.
- The CLI starts or connects to the per-user daemon automatically; users do not
  manage daemon lifecycle for normal `exec` use.
- Denial, timeout, SDK failure, and child failure are handled clearly.

### Epic 4 Definition Of Done

- CLI parser tests and process supervisor tests pass.
- Mock SDK and mock approver tests prove fetch-after-approval ordering.
- Daemon startup/connect tests prove `agent-secret exec` can use the hidden
  daemon path.
- A live opt-in smoke can run a harmless command with a test-only ref.
- `go test ./...` passes.

### Epic 4 Risks And Mitigations

- Risk: command execution leaks values through broker output.
- Mitigation: test stdout, stderr, and audit output with synthetic canary
  values. `agent-secret exec` has no `--json` mode in MVP and must not capture,
  wrap, summarize, or reformat child stdout/stderr.

### Epic 4 Tasks

#### Task 1: Add CLI parser and command envelope

- Goal: turn user input into validated request objects.
- Preconditions/inputs: request model exists.
- Failing test/check: parser tests for required `--reason`, `--secret` mappings,
  `--profile` mappings, `default_profile` mappings, config/profile/secret
  account defaults, `--` command boundary, daemon subcommands, TTL parsing,
  rejection of `--json` for `exec`, and rejection of shell-string command
  input, `--override-env` parsing, and `--force-refresh` parsing. Parser tests
  reject any `--reuse` request/hint flag. Parser/request tests prove missing,
  blank, or over-limit reasons stop before approval UI, reusable-approval
  lookup, SDK access, or child spawn. Help tests fail until
  `agent-secret --help` and `agent-secret exec --help` include purpose, safety
  rules, commands, flags, examples, daemon behavior, audit-log location, exit
  behavior, and no real secret values. Reuse tests fail unless reused
  invocations include the same exact reason.
- Implementation:
  - choose a small CLI parsing library or standard-library parser
  - parse `exec`, `doctor`, and initial debug commands
  - implement detailed top-level and subcommand help modeled after
    `agent-browser --help`, optimized for agent self-discovery rather than terse
    flag-only output
  - include examples for Terraform/Ansible-style `exec`, `doctor`, daemon
    management, explicit shell usage, `--override-env`, and `--force-refresh`
  - accept commands only as argv after `--`, with no broker shell-string parser
  - do not implement any command that prints secret values
- Verification:
  - `go test ./...`

#### Task 2: Add hidden daemon startup and connection

- Goal: make the daemon part of v1 without exposing daemon management to users.
- Preconditions/inputs: request model and socket server protocol exist.
- Failing test/check: tests fail until `agent-secret exec` starts the daemon
  when it is not running, connects to an existing daemon when it is running, and
  reports a clear fail-closed error when startup fails. A lifecycle test proves
  the daemon remains alive after the wrapped command exits and can be stopped
  explicitly. Stop tests assert immediate shutdown clears active reusable
  approval/session state without signaling already-spawned child processes.
  Disconnect tests fail until an in-flight pre-payload request fails closed with
  a daemon-disconnected error and does not auto-reconnect or recreate the
  request.
  Command-channel tests reject wrong-UID peers, malformed envelopes, bad protocol
  versions, and nonce mismatches, without requiring CLI PID/executable/cwd
  validation for MVP `exec`. Protocol tests prove `request.exec` returns approved
  env values over the single daemon socket only after approval, all-or-nothing
  fetch, and `command_starting` audit success, and prove those values are not
  logged.
- Implementation:
  - add per-user socket discovery
  - add on-demand `agent-secretd` process start from the CLI
  - detach daemon lifecycle from the invoking CLI process
  - wait for daemon socket readiness before sending the request
  - fail closed on daemon disconnect before payload delivery; do not auto-reconnect
    or recreate the in-flight request
  - validate same UID, protocol version, message type, and request nonce on the
    daemon command channel
  - keep `request.exec` request, approved env payload response, child PID report,
    and completion report on the single daemon socket
  - do not add one-shot secret-payload sockets or file descriptors in MVP
  - implement `agent-secret daemon status`
  - implement `agent-secret daemon start`
  - implement immediate `agent-secret daemon stop`
  - attempt best-effort `daemon_stop` audit on stop without delaying shutdown
  - add startup timeout and stale socket cleanup behavior
  - keep daemon lifecycle details out of normal command output unless there is
    an error
- Verification:
  - `go test ./...`

#### Task 3: Implement approval-before-fetch flow

- Goal: guarantee the broker never fetches secrets before local approval.
- Preconditions/inputs: mock approver and mock SDK.
- Failing test/check: an ordering test fails if the SDK mock is called before
  approval or after denial. Reuse tests fail unless an approved reusable command
  uses cached in-memory values without a second SDK call during the TTL/use-count
  window, unless `--force-refresh` is used. Resolver tests fail until approved
  refs are fetched with bounded concurrency, successful partial results are
  discarded on any failure, and the CLI receives no values or spawn permission
  after a partial fetch failure. Resolver tests also fail until empty-string
  values are treated as successful resolutions and delivered as empty env vars,
  while missing, unreadable, unauthorized, or unresolved refs still fail closed.
  Duplicate-ref tests fail until identical `op://` refs are fetched once and
  fanned out to each approved alias.
- Implementation:
  - add an approver interface
  - add a secret resolver interface
  - implement bounded concurrent ref resolution after approval, deduplicating
    identical refs before fetch
  - preserve empty-string secret values as valid resolved values
  - wire daemon-owned approval/fetch/cache/audit to CLI-owned spawn and cleanup
  - keep ref existence and metadata checks out of the normal pre-approval path
  - treat any approved-ref fetch failure as a fail-closed request with no values
    returned to the CLI wrapper and no child process spawn
  - populate the reusable approval/session cache only after all approved refs
    are fetched successfully
  - implement `--force-refresh` as all-or-nothing refetch for matching reusable
    approvals, emit a refresh audit event, and consume one use when the daemon
    sends the approved environment payload to `agent-secret exec`
- Verification:
  - `go test ./...`

#### Task 4: Preserve command behavior

- Goal: make `agent-secret exec` behave like the wrapped command where possible.
- Preconditions/inputs: CLI-owned process supervisor exists.
- Failing test/check: tests for exit code propagation, signal-based exit status,
  non-zero child exits without broker-added stderr, interrupt forwarding to the
  child process group, repeated interrupt forwarding without escalation to
  `SIGKILL`, no wrapper-enforced kill timeout when a child keeps ignoring
  forwarded interrupts, stdout/stderr passthrough, cwd enforcement, env
  collision failure, `--override-env`
  behavior, cleanup after approval timeout or process exit, one-shot TTL expiry
  before spawn failing closed, CLI disconnect after payload delivery, and
  one-shot or reusable approval TTL expiring while a child continues running.
  Tests also fail until explicit `command_started` audit write failure after
  spawn terminates the child and returns failure, while daemon disconnect after
  spawn lets the child continue, appends one non-secret stderr warning after
  child exit, and returns the child exit code.
- Implementation:
  - request approved environment payloads over the single daemon socket and never
    spawn unless the daemon confirms approval, fetch, and `command_starting`
    audit success
  - treat reusable approvals as spent once the approved environment payload is
    delivered, even if the CLI later fails before spawning the child
  - if the CLI disconnects after payload delivery before reporting
    `command_started`, make the daemon record
    `exec_client_disconnected_after_payload`, clear one-shot daemon-held values,
    leave reusable cached values intact, and avoid child-process killing or
    process-tree inference because the daemon has no child PID
  - spawn child with scoped environment additions
  - set the child working directory from `--cwd`, defaulting to caller cwd
  - inherit the parent environment by default
  - create or target a child process group when possible so interrupts can be
    forwarded to the wrapped command tree
  - fail closed when an approved alias collides with parent env unless
    `--override-env` is set
  - preserve stdout and stderr streams
  - do not attempt to redact or sanitize child process output
  - treat non-zero child exits as normal child completion; return the child's
    status without printing broker error text solely because the child failed
  - require daemon-owned `command_starting` before spawn and fail closed if it
    cannot be written
  - report `command_started` with child PID to the daemon after successful spawn
  - if the daemon is reachable and reports that `command_started` cannot be
    written after spawn, send `SIGTERM`, wait 2 seconds, send `SIGKILL` if still
    running, and fail closed
  - if the daemon disconnects after child spawn, let the child continue, preserve
    stdout/stderr passthrough, append one non-secret stderr warning after child
    exit, return the child exit code, and report that completion audit could not
    be written
  - after killing a child due to `command_started` audit failure, attempt a
    best-effort failure/termination audit event without delaying termination
  - report completion status to the daemon, but never child stdout/stderr
  - on interrupt or termination signal to `agent-secret exec`, forward the signal
    to the child process group when available, otherwise to the child process
  - forward repeated interrupts the same way and keep waiting; do not escalate to
    `SIGKILL` because of a second interrupt
  - do not enforce a wrapper kill timeout when the child ignores forwarded
    interrupts indefinitely; keep waiting so the wrapper can observe child exit
    and run cleanup/audit when possible
  - after forwarding a signal, wait for the child to exit, run normal cleanup,
    report completion when possible, and return the child's signal-based exit
    status
  - return the child exit code or signal-based exit status
  - clear CLI-held one-shot in-memory secrets after command exit and ensure the
    daemon clears its one-shot copies
  - fail closed without spawning the child if one-shot TTL expires before spawn
  - keep reusable approval values in daemon memory until TTL, max-use
    exhaustion, or daemon stop
  - keep session values in daemon memory until TTL, read-count exhaustion, daemon
    stop, or explicit session destroy
  - treat env-mode TTL expiry as an approval/cache cleanup event, not as a
    reason to kill an already-running child process
- Verification:
  - `go test ./...`

## Epic 5: Native Approver Integration

Status: Complete

### Epic 5 Completion Notes

- Added shared sanitized approval request/decision JSON fixtures decoded by
  both Go and Swift tests.
- Added daemon approval socket messages `approval.pending` and
  `approval.decision` on the same per-user daemon socket as CLI requests.
- Added a FIFO `SocketApprover` that launches the native approver on demand,
  exposes one active approval at a time, preserves original request TTLs while
  queued, expires queued requests before display, and routes reusable approval
  matches around the queue through the existing policy path.
- Added request ID, nonce, peer PID, and executable identity validation for
  approval fetch and decision submission. Stale or mismatched decisions are
  rejected.
- Added Swift socket client support for the approver app. Approval IPC now uses
  daemon socket messages instead of stdin/stdout, argv/env payloads, or temp
  files in the product path.
- Wired `agent-secretd` to use the official 1Password SDK lazily after approval
  with `my.1password.com` as the built-in default account, plus `OP_ACCOUNT`,
  `AGENT_SECRET_1PASSWORD_ACCOUNT`, or `--account` as optional account
  overrides, preserving approval-before-fetch ordering.
- Added a redacted Swift approval view model showing reason, command, cwd,
  resolved binary, refs, time remaining, override warning, reusable-use limit,
  and memory-caching note without request IDs, nonces, or secret values.
- Added a minimal `.app` bundle build script for the approver while preserving
  the SwiftPM executable target used by tests and smoke runs.
- Verified with `go test ./...`, `go test -tags integration ./...`,
  `cd approver && swift test`, `cd approver && ./scripts/build-app.sh`,
  `swift run agent-secret-approver-smoke`, lint, and non-interactive approver
  fixture smoke. The AppKit foregrounding path is unchanged from the Epic 2
  manual foreground smoke.

### Epic 5 Acceptance Criteria

- The daemon can expose a structured approval request to the Swift helper over
  the single per-user daemon socket.
- The helper displays request context without values.
- The helper shows compact time remaining until the request TTL expires.
- The helper returns approve, deny, or timeout with request ID and nonce.
- Responses from any process other than the launched or activated approver
  process are rejected, even if they include a valid request ID and nonce.
- Stale or mismatched responses are rejected.
- Approval IPC uses the same daemon socket as CLI requests; it does not use
  stdin/stdout, argv/env payloads, or temp files.
- Approver launch failure or timeout fails closed with no terminal fallback and
  no retry loop.
- Approval timeout is the request TTL; there is no separate approval prompt
  timeout.
- Native approver is the only v1 approval path for secret access.
- The daemon has at most one active approval prompt. Concurrent
  approval-requiring requests queue FIFO behind the active prompt instead of
  opening multiple windows or failing with a busy error.
- Queued requests keep the TTL clock from original daemon receipt and can expire
  before display.
- The native approver emits non-secret diagnostics to Apple's Unified Logging
  for lifecycle, foregrounding, daemon-socket IPC, decision, timeout, and error
  troubleshooting.

### Epic 5 Definition Of Done

- Contract tests cover request and response JSON over the daemon socket protocol.
- Swift tests cover view-model formatting and redaction.
- Swift logging tests or smoke hooks prove logging calls do not include canary
  secret values or environment payloads.
- A manual smoke confirms foreground behavior.
- The approver launches on demand from the daemon for v1.
- The approver is a minimal real `.app` bundle, not a throwaway helper, and its
  protocol/view-model boundary can support later menu bar lifecycle.

### Epic 5 Risks And Mitigations

- Risk: UI work slows the broker prototype.
- Mitigation: keep fake approver interfaces for automated tests while the native
  helper is being hardened; do not add a user-facing approval bypass flag.

### Epic 5 Tasks

#### Task 1: Define approval protocol fixtures

- Goal: keep Go and Swift request/response payloads in sync.
- Preconditions/inputs: PRD approval payload fields.
- Failing test/check: Go and Swift fixture tests fail unless both sides parse
  the same sample approval request and response.
- Implementation:
  - add sanitized JSON fixtures
  - add Go parser tests
  - add Swift decoder tests
  - include nonce and request ID validation cases
- Verification:
  - `go test ./...`
  - `cd approver && swift test`

#### Task 2: Build approval view model and redaction tests

- Goal: display enough context while never rendering secret values.
- Preconditions/inputs: approval fixtures.
- Failing test/check: Swift tests fail if canary secret values appear in any
  rendered view-model text.
- Implementation:
  - create a request view model
  - show reason, alias plus full refs, full command argv, cwd, optional
    resolved executable path, approval duration, and compact time remaining
  - make approval request fields read-only; approvers can approve once, allow
    same-command reuse, or deny, but cannot edit the requester reason or mutate
    request metadata before approval
  - show a concise environment override warning only when `--override-env` will
    replace existing variables
  - keep requester metadata, daemon path, approver path, request IDs, nonces,
    and other audit/debug fields out of the default view model
  - add `Approve once`, `Allow same command for <ttl>`, `Deny`, and TTL-expired
    decisions
  - keep denial as a single action with no operator-note field; audit records the
    denied request metadata only
  - show the 3-use limit and memory-caching note for the reusable approval
    action
  - add a small logging adapter around `os.Logger` with stable subsystem and
    category names, and keep log inputs value-free
- Verification:
  - `cd approver && swift test`

#### Task 3: Connect daemon to approver app

- Goal: request approval over the single per-user daemon socket.
- Preconditions/inputs: Go approval interface and Swift helper exist.
- Failing test/check: integration test with a fake app client on the daemon
  socket fails until the daemon handles request fetch, approve, deny, TTL expiry,
  launch failure, malformed response cases, peer PID/executable mismatches, and
  stale or mismatched nonce rejection. Concurrency tests fail until multiple
  approval-requiring requests are serialized through one active prompt and a
  strict FIFO queue rather than concurrent windows, busy errors, or
  earliest-expiring-first ordering. Queue tests also fail until a queued request
  that expires before display fails closed without 1Password access. Reusable
  approval matches must bypass the queue while still enforcing reusable match,
  TTL, use-count, audit, and fetch/cache checks.
- Implementation:
  - add daemon socket endpoints for pending approval request fetch and decision
    submission
  - add a single-active-approval FIFO queue in the daemon
  - start request TTL at daemon receipt, not prompt display
  - expire queued requests before display when their TTL elapses
  - route reusable approval matches around the approval queue
  - add launch-on-demand behavior for the app
  - record the expected approver peer identity for the request
  - ensure approval metadata never contains secret values
  - log non-secret app lifecycle, activation, socket connection, pending request,
    decision submission, timeout, and error events to Unified Logging
  - do not pass approval request data through stdin/stdout, argv/env, or temp files
  - bind responses to request ID, nonce, peer PID, and executable identity
- Verification:
  - `go test ./...`
  - manual smoke with the native helper

## Epic 6: Daemon And Session Model

Status: Not started

### Epic 6 Acceptance Criteria

- A hidden per-user daemon owns reusable approval/session state and local socket
  endpoints.
- `session create`, `session list`, `session destroy`, and `with-session` work.
- Handles cannot be resolved after TTL, max-read exhaustion, or destroy.
- Handles cannot be resolved when macOS peer UID, PID, executable path, or cwd
  is missing or mismatched.
- Sessions approve a bounded set of refs and allow those refs to be read in any
  order the approved workflow needs.
- Socket directories and files use restrictive permissions.

### Epic 6 Definition Of Done

- Unit tests cover the session store and socket server.
- Integration tests cover local socket request flow with fake SDK and approver.
- `go test ./...` passes.

### Epic 6 Risks And Mitigations

- Risk: session mode expands the leak surface before `exec` is stable.
- Mitigation: keep session value reads behind wrappers or ephemeral Unix sockets
  and never expose console secret output.

### Epic 6 Tasks

#### Task 1: Expand daemon socket server

- Goal: support reusable approvals and sessions behind the per-user Unix socket.
- Preconditions/inputs: core request and policy packages.
- Failing test/check: socket tests fail until the server accepts valid request
  envelopes, rejects malformed versions, rejects wrong-UID peers, and cleans
  stale sockets. Strict PID/executable/cwd checks are tested with session/socket
  value reads, not MVP `exec`.
- Implementation:
  - add socket directory setup with mode `0700`
  - add JSON message envelopes
  - add graceful startup and shutdown
- Verification:
  - `go test ./...`

#### Task 2: Add session commands

- Goal: support bounded multi-command workflows.
- Preconditions/inputs: daemon server and session store.
- Failing test/check: CLI and daemon tests for create, list, destroy, expired
  session, and exhausted handles.
- Implementation:
  - implement `session create`
  - implement `session list`
  - implement `session destroy`
  - return handles, not values
- Verification:
  - `go test ./...`

#### Task 3: Add `with-session`

- Goal: run subsequent commands without handing values to the agent.
- Preconditions/inputs: session commands exist.
- Failing test/check: tests fail until `with-session` injects only approved
  session secrets into the child and rejects expired, destroyed, or peer-policy
  mismatched sessions.
- Implementation:
  - resolve handles internally through the daemon
  - enforce strict macOS peer validation before resolving handles
  - reuse the CLI-owned process supervisor
  - preserve command exit behavior
- Verification:
  - `go test ./...`

## Epic 7: Hardening And Daily-Use Packaging

Status: Not started

### Epic 7 Acceptance Criteria

- `doctor` reports useful local health checks.
- Failure modes fail closed with clear messages.
- LaunchAgent and helper startup are documented or implemented.
- Audit logs are inspectable directly as JSONL files without a CLI viewer.
- Local run/install notes exist as convenience docs only, with no v1 trust-path
  policy.

### Epic 7 Definition Of Done

- `doctor` tests cover healthy and unhealthy local configurations.
- A daily-use smoke checklist exists.
- Codesigning and notarization are explicitly not required for private dogfood
  and are documented as pre-public-distribution work.

### Epic 7 Risks And Mitigations

- Risk: public distribution needs stronger binary identity than private dogfood.
- Mitigation: defer signing/notarization and installation-integrity guidance to
  the release path; v1 does not police local execution paths.

### Epic 7 Tasks

#### Task 1: Implement `doctor`

- Goal: make local setup problems obvious.
- Preconditions/inputs: daemon, approver, socket, audit, and SDK components.
- Failing test/check: tests for daemon unavailable then started on demand,
  daemon startup failure, approver unavailable, approver non-secret health-check
  failure, unwritable audit path, unsafe socket permissions, SDK/client
  availability, desktop-app auth trigger/readiness, and a guard proving `doctor`
  does not resolve any `op://` ref.
- Implementation:
  - start the daemon on demand using the same path as normal commands
  - report resulting daemon status
  - launch/probe approver through a non-secret health-check request over the
    daemon socket
  - check socket directory permissions
  - check audit log path
  - run SDK/client availability and desktop-app auth readiness checks, allowing
    desktop auth prompt if needed but never resolving any `op://` ref or fetching
    arbitrary secrets
- Verification:
  - `go test ./...`
  - `bin/agent-secret doctor`

#### Task 2: Document release path

- Goal: prepare for daily use and future public distribution.
- Preconditions/inputs: working CLI, daemon, and approver.
- Failing test/check: docs lint fails until release notes exist and command
  examples use project-local paths.
- Implementation:
  - document that v1 does not enforce or warn on binary install paths
  - document that private dogfood does not require codesigning or notarization
  - document codesigning/notarization expectations before wider distribution
  - document standalone repository release checklist
- Verification:
  - `npx --yes markdownlint-cli '**/*.md'`

## Dependencies / Parallelization

- Epic 1 is the starting point.
- Epic 2 blocks real SDK, UI, and daemon design decisions.
- Epic 3 can start after the request fields from Epic 2 are confirmed.
- Epic 4 depends on Epic 3 and can use fake approver and fake SDK interfaces.
- Epic 5 can run in parallel with Epic 4 once approval fixtures are defined.
- The first dogfood target is Epic 4 plus Epic 5: env-only `exec`, hidden daemon
  startup, and reusable same-command approvals.
- Epic 6 depends on the first working `exec` plus reusable approval path. It
  should not block initial Terraform/Ansible dogfood.
- Epic 7 should follow the first working `exec` path, then broaden after
  sessions land.

## Testing Strategy

- Default to fast unit tests for request validation, policy, audit redaction,
  CLI parsing, and process supervision.
- Treat help output as a tested interface: snapshot or golden tests should prove
  top-level and `exec` help contain the expected agent-oriented sections,
  examples, and safety statements without real secret-looking values.
- Keep SDK, macOS UI, and socket peer behavior behind opt-in integration tests
  or documented manual smokes.
- Use fake approver and fake secret resolver interfaces for most daemon and CLI
  tests.
- Use synthetic canary secret values in tests to prove values do not appear in
  broker output, audit logs, rendered UI text, help output, or app logging
  adapters.
- Run Go tests with `go test ./...`.
- Run project lint and pre-commit-equivalent lint after Go files exist.
- Run Swift tests from `approver` after the approver scaffold exists.

## Integration Tests (Opt-In)

- 1Password SDK live tests require a test-only `op://` ref and must print only
  hash, length, or metadata.
- macOS foreground approval smoke requires a logged-in GUI session.
- Peer credential tests may skip the whole check on unsupported platforms. On
  the supported current macOS target, missing UID, PID, executable path, or cwd
  metadata is a failing result, not a best-effort skip.
- End-to-end `exec` smoke should run a harmless command first, then a real local
  workflow such as `terraform plan` or `ansible-playbook --check` only after the
  broker path is stable.
- A config-driven secret sync smoke should use a sanitized test mapping shaped
  like `op-secrets.yml`, not a real project mapping.

## Dogfood Smoke Order

1. Terraform plan:
   `terraform plan`
2. Ansible check flow:
   `ansible-playbook site.yml --check`
3. Non-mutating config validation:
   `make validate`
4. Sanitized credential sync:
   `bin/setup-op-secrets --dry-run`

The first three smokes should prove approval, fetch, env delivery, audit, and
cleanup without intentional infrastructure mutation. Credential sync is a later
dogfood step because it may write to a project-managed encrypted or managed
secret store.

## Fixtures

- Approval protocol fixtures should be sanitized JSON with inert `op://` refs.
- SDK error fixtures should be captured from real SDK errors when possible and
  scrubbed of personal vault or item names unless the user explicitly approves.
- Audit redaction tests should use synthetic canary values that are safe to
  commit.
- No fixture may contain raw secrets, tokens, private keys, or credential files.
