# Product Requirements: Agent Secret Broker

Status: draft.

## Summary

Agent Secret Broker is a local, macOS-first system for letting coding agents use
1Password-backed secrets without making the agent a trusted secret holder. The
agent requests exact secret references with a reason and a bounded policy. A
local broker presents a native approval prompt, fetches approved secrets through
the official 1Password SDK, and delivers them through constrained execution or
short-lived capabilities.

The first user is a local developer running coding agents such as Codex, Claude
Code, Cursor agent, or similar tools. The first practical workflow is running
local infrastructure commands, such as Terraform, that need credentials from
1Password.

## V1 Product Stance

V1 is a private dogfood tool first and a standalone project second. Success
means the tool is safe and useful for real local agent workflows before it is
polished for public distribution.

Open-source readiness is a design constraint, not a release gate. The project
should keep clean boundaries, avoid external runtime dependencies, and maintain
honest docs, but it can defer public-package polish such as notarized installers,
contributor docs, broad platform support, and long-term support promises.

When Go code is added, the module path should be
`github.com/kovyrin/agent-secret`. That keeps imports, examples, and docs
aligned with the intended standalone repository.

## Product Thesis

1Password should remain the storage and account-authentication source of truth.
Agent Secret Broker should provide the missing local policy boundary for
agent-initiated access.

1Password answers: is this trusted local integration allowed to access the
user's 1Password account right now?

Agent Secret Broker answers: is this specific agent request allowed to use these
exact secret references for this stated reason, command, TTL, and delivery
surface? In MVP, the delivery surface is implicit env-mode `exec`; it is kept in
policy and reuse keys but not shown in the approval prompt.

## Goals

- Show a focused native macOS approval prompt before any broker-level secret
  fetch.
- In the default prompt, show only the decision-critical fields: reason, command
  or workflow, resolved command binary when useful, requested secret aliases and
  refs, and approval duration/reuse policy.
- Use the official 1Password SDK for normal operation.
- Never print secret values to the console or return them to the agent.
- Support command execution through `agent-secret exec` as the default delivery
  mode.
- Support short-lived sessions, opaque per-secret handles, and credential-helper
  integrations after the `exec` path is proven.
- Keep secret values in memory only by default.
- Enforce TTL, requested refs, command, cwd, UID, strict macOS peer/process
  checks for session/socket reads, and max reads only for session/socket reads.
- Write metadata-only audit logs that never include secret values.
- Keep the trusted core small enough to audit.
- Keep this project independent from external project code and runtime
  assumptions.

## Non-Goals

- Replace 1Password as the secret store.
- Reverse-engineer private 1Password desktop protocols.
- Shell out to `op read` as a fallback secret resolver.
- Build a cloud service or remote agent access path in v1.
- Build a general enterprise secret manager.
- Sync approvals across machines.
- Guarantee safety against a fully compromised local user account.
- Prevent a third-party tool from leaking a secret after the broker intentionally
  delivers that secret to the tool.
- Provide a true system-modal macOS prompt through private APIs.
- Make agents directly trusted secret holders.
- Depend on external project code, services, credentials, or deployment
  tooling.
- Require a local allowlist or policy file in v1. The approval prompt is the
  policy boundary.
- Write secret values to disk, including temporary credential files.

## Primary Use Cases

### Use Case 1: Run Terraform Or Ansible With Scoped Credentials

An agent runs:

```bash
agent-secret exec \
  --reason "Run Terraform plan for staging" \
  --secret AWS_ACCESS_KEY_ID="op://Example/AWS Staging/access_key_id" \
  --secret AWS_SECRET_ACCESS_KEY="op://Example/AWS Staging/secret_access_key" \
  --ttl 2m \
  -- terraform plan
```

`agent-secret exec` asks the daemon for local approval. The daemon fetches only
the approved refs from 1Password and returns an approved environment payload to
the CLI over the single per-user daemon socket. The CLI starts `terraform plan`
with scoped environment variables, waits for the command to exit, and clears its
one-shot in-memory copies. If the user approved same-command reuse, the daemon
keeps those values in memory only until the approval TTL or use limit is
exhausted.

The same v1 path should support Ansible commands that need environment-provided
credentials, inventory access tokens, SSH-related variables, or cloud provider
credentials. Terraform and Ansible are the first real dogfood workflows.

### Use Case 2: Multi-Step Deployment Session

An agent requests a short session for a bounded workflow such as:

```bash
terraform plan
terraform apply
ansible-playbook site.yml --check
```

The user approves once for a TTL. The broker returns a session ID or opaque
handles, and subsequent commands must run through broker wrappers such as
`agent-secret with-session`.

### Use Case 3: Config-Driven Secret Sync

Some local projects keep a checked-in mapping from logical credential keys to
1Password vault, item, and field metadata, then run a sync helper to write those
values into the project's own encrypted or managed secret store. The broker
feature should stay generic and should not depend on any one consumer project.

The first dogfood-ready config workflow is project-local profiles. A checked-in
`agent-secret.yml` file names reusable secret bundles while still storing only
`op://` refs and metadata. If `default_profile` is set, the caller can omit
`--profile` when no explicit `--secret` flags are provided:

```yaml
version: 1

account: my.1password.com
default_profile: terraform-cloudflare

profiles:
  terraform-cloudflare:
    account: Fixture
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
      PREVIEW_TOKEN:
        ref: op://Example/Preview/token
        account: Fixture Preview

  ansible-with-dns:
    include:
      - terraform-cloudflare
    reason: Run Ansible playbook with DNS secrets
    secrets:
      ANSIBLE_BECOME_PASSWORD: op://Example/Ansible/password
```

`account` is optional and may be set at the top level, profile level, or secret
level. The precedence is per-secret `account`, then profile `account`, then
top-level `account`, then `OP_ACCOUNT` / `AGENT_SECRET_1PASSWORD_ACCOUNT`, then
`my.1password.com`.

Profiles may include other profiles. Includes are resolved in order; later
includes and the selected profile override earlier secrets with the same alias.
This keeps common secret bundles reusable without introducing a separate config
concept.

The caller runs the normal `exec` path with the default or named profile:

```bash
agent-secret exec -- terraform plan
agent-secret exec --profile terraform-cloudflare -- terraform plan
```

The broker approves the declared refs before the wrapped command runs, avoids
printing values, and lets CLI `--reason`, `--ttl`, and additional `--secret`
flags override or extend a named profile for one-off use. Additional explicit
secrets inherit the loaded profile account. `--only` can filter profile-loaded
aliases for dynamic subsets before one-off `--secret` refs are added. Explicit
`--secret`-only invocations do not load `default_profile`.

### Use Case 4: Git Credential Helper

Git invokes a credential helper that talks to the broker. The broker returns the
token only to that helper invocation under an approved policy, not to the agent.

### Use Case 5: Future Signing Or SSH Operations

Where possible, future versions should prefer operations over raw key export,
such as ssh-agent-like signing.

## High-Level Architecture

```text
agent / Codex
  -> agent-secret CLI
      -> agent-secretd local broker daemon
          -> agent-secret-approver.app
          -> 1Password official SDK
          -> in-memory approval/session/secret cache
          -> Unix domain socket API
          -> metadata-only audit log
      -> wrapped child command in exec mode
```

## Component Responsibilities

### `agent-secret` CLI

- Collect structured requests from agents and users.
- Talk to `agent-secretd` over a local Unix domain socket.
- Provide `exec`, daemon management, and `doctor` commands in MVP; add
  `session` and `with-session` commands after the `exec` path is proven.
- Never print raw secret values.
- In `exec` mode, resolve the executable path and cwd, request an approved
  environment payload from the daemon, spawn the child process, wait for it, and
  report child lifecycle metadata back to the daemon.
- Preserve the target command's exit code or signal-based exit status in `exec`
  mode.
- Hold approved secret values only transiently in memory while preparing the
  child environment.

### `agent-secretd` Daemon

- Own all security policy and enforcement.
- Own all communication with the 1Password SDK.
- Store reusable approval and session secret values in memory only.
- Return approved secret payloads to trusted CLI wrappers over the single
  per-user daemon socket.
- Never spawn, supervise, signal, or wait for `exec` child processes.
- Enforce TTL, refs, command, cwd, peer UID, strict macOS peer/process checks
  for session/socket reads, and max reads only for session/socket reads.
- Expose a local Unix domain socket API.
- Emit metadata-only audit events.
- Request decisions from the macOS approver app.

The daemon should run as a per-user local daemon, not a privileged system daemon.
V1 should use it from day one so reusable approvals have shared state. The user
should not have to think about daemon lifecycle: `agent-secret` starts the daemon
on demand, connects to it, and reports clear errors if startup fails. A later
version can install it as a `launchd` LaunchAgent.

For v1, `agent-secret` should start a separate `agent-secretd` process when no
healthy daemon is available. The daemon must detach from the invoking CLI,
publish its Unix socket, and remain alive after the wrapped command exits so
same-command reusable approvals can be used by later invocations.

If the daemon disconnects or restarts while `agent-secret exec` is waiting for
approval, reusable approval validation, fetch, audit, or payload delivery, the
CLI must fail closed with a clear daemon-disconnected error. It must not
auto-reconnect, recreate the request, or transparently restart the daemon for
that in-flight request. The user can rerun the command, which creates a fresh
request and approval path.

The v1 daemon should stay alive until manually stopped or until the user logs
out. Approvals and secret values still expire internally. Users do not need to
manage the daemon for normal use, but the CLI should provide explicit daemon
management commands for troubleshooting: `agent-secret daemon status`,
`agent-secret daemon start`, and `agent-secret daemon stop`.

`agent-secret daemon stop` is immediate in v1. It stops the daemon, cancels
active approvals and sessions, clears daemon memory, stops accepting new work,
and exits. It does not track, signal, or manage already-spawned child processes;
those processes continue under normal OS process semantics. Before stopping, the
daemon should attempt one best-effort `daemon_stop` audit event. Failure to
write that event must not block or delay shutdown.

The daemon must not persist operational state beyond the append-only audit log.
Reusable approvals, sessions, use counters, cached secret values, approval
nonces, and socket paths are memory-only. Stopping the daemon clears that state;
the already-written audit log remains as history.

### `agent-secret-approver.app`

- Present a native macOS approval UI.
- Bring approval prompts to the foreground using public macOS APIs.
- Show request context without showing secret values.
- Connect to the same per-user daemon socket to fetch pending approval metadata
  and return approve, deny, or timeout decisions.
- Emit non-secret diagnostics to macOS Unified Logging for troubleshooting.
- Launch on demand from the daemon for v1.
- Optionally become a menu bar app after the basic prompt is reliable.

The v1 approver should be a minimal real macOS `.app` bundle built with
SwiftUI/AppKit, not a throwaway command-line alert helper. It should have a
stable app boundary, request view model, approval protocol, and bundle identity
so it can later grow into a full menu bar app with status, settings,
launch-at-login, and stronger signing/notarization without replacing the
approval integration.

The approver must not fetch secrets, store secrets, or independently enforce
secret policy.
The approver should use Apple's Unified Logging (`os.Logger`) with a stable
subsystem such as `com.kovyrin.agent-secret.approver` and categories for
lifecycle, IPC, UI, decisions, and errors. These logs are for troubleshooting
foregrounding, socket connection, timeout, and decision submission problems.
They must never include secret values, raw child output, or environment payloads;
prefer request IDs, event types, durations, and redacted error metadata that can
be correlated with the metadata-only audit log.

For v1 approval IPC, the daemon launches or activates the `.app`, and the app
connects back to the single per-user daemon socket. The app fetches pending
approval request metadata and submits the decision over that socket. Approval IPC
must not use stdin/stdout, argv/env payloads, or temp files.

Only the approver process launched or activated for the request may submit
`approval.response`. The daemon must verify the socket peer PID and executable
identity for the approver response and fail closed if it cannot verify that the
response came from that approver process.

## Core Security Model

Agents request capabilities. They should never receive raw secret values from
broker output. V1 delivers values only through child processes launched by
`agent-secret exec` using environment variables. Approved values cross from the
daemon to the trusted CLI wrapper over the single per-user daemon socket and
must never be printed to the console. Later versions may allow controlled reads
through ephemeral Unix sockets, but still must not print secrets to the console.

Each approved request or session should bind these fields:

- request ID and optional session ID
- requester UID, PID, process name, executable path, and parent PID when known
  for audit/debug metadata only
- cwd, with `--cwd` defaulting to the caller's current cwd for `exec`
- stated reason
- exact command argv and resolved executable path when applicable
- exact requested secret refs and aliases
- TTL and expiration time
- max reads per secret for session/socket reads when applicable
- delivery mode, implicit env-mode `exec` for MVP
- approval timestamp and nonce
- reuse policy: one-shot by default, or same-command reuse with a short TTL and
  max-use count

The broker rejects access if the session is expired, the requested handle is not
approved, the read count is exhausted, the peer UID mismatches, the command or
cwd policy mismatches, the nonce is invalid, or the request was denied or
canceled.

For `agent-secret exec`, `--cwd` is operational. It sets the child process
working directory, defaults to the caller's current cwd when omitted, and is part
of the approval and reusable-approval match key. A reusable approval for the
same argv in one directory must not apply to the same argv in a different
directory.

V1 does not accept `--repo`, does not bind repository root into approval or
reuse, and does not enforce repository commit binding. Future versions may record
git metadata as audit-only context when useful, but v1 keeps repo state out of
the approval model.

Command approvals are one-shot by default. After the base path works, the UI can
offer a short reusable approval such as "allow this same command for 10
minutes." Same-command reuse is intentionally strict in v1: it must match the
stated reason, resolved executable path, exact argv array, cwd, exact aliases
and refs, delivery mode, `--override-env` state, exact overridden aliases, TTL,
and max-use count. Requester PID/process identity is audit-only for MVP `exec`
reuse. The match must not permit a different reason, new refs, a different
executable path, a different argv, a different cwd, a different delivery mode,
or different environment override behavior.

`--reason` is required for every `agent-secret exec` invocation, including
invocations that reuse an existing approval. A reused approval only matches when
the new request's reason is exactly the same as the originally approved reason.
Reasons are free text, trimmed before validation, and must be non-empty after
trimming. V1 should cap the trimmed reason at 240 characters: long enough for a
useful sentence or short paragraph, short enough to keep the approval prompt
scannable. Missing, blank, or over-limit reasons fail during CLI/request
validation before approval UI, reusable-approval lookup, or 1Password access.
The validated trimmed reason is the only reason string stored in approval state,
reuse keys, and audit events. V1 does not store a separate raw pre-trim copy.

`agent-secret exec` TTL is configurable but bounded. The default is 2 minutes,
the minimum is 10 seconds, and the maximum is 10 minutes. TTL is part of the
reusable approval match key. A reusable approval uses the requested `--ttl`
rather than a separate fixed duration, still capped at 10 minutes and still
limited to 3 matching uses.
TTL starts when the daemon receives the request, not when an approval prompt is
shown. If a request waits in the approval queue long enough to expire, it fails
closed without being shown, without contacting 1Password, and without delivering
secrets.

The default reusable approval option should use the request's actual TTL with at
most 3 matching uses. "Approve once" remains the default action.
The CLI must not provide a flag or hint that requests reusable approval. Reuse is
chosen only by the operator in the approval UI, so agents cannot nudge the
operator toward broader approval.
The CLI also must not provide a flag that bypasses approval. Approval is always
required for secret access in v1.
When a matching reusable approval exists, `agent-secret exec` should skip the
approval UI and run immediately. The daemon must record an `approval_reused`
audit event with remaining TTL and remaining use count before any fetch or
secret delivery to the CLI wrapper. If that audit event cannot be written
securely, the reused request fails closed.
Reusable approval matches do not enter the approval prompt queue because they do
not require UI. They still must pass reusable approval match, TTL, use count,
audit, cache/fetch, and payload-delivery checks before any values leave the
daemon. `--force-refresh` on a matching reusable approval also bypasses the
approval queue, but still refetches only after the reusable approval and audit
checks pass.

For reusable approvals and sessions, the daemon should keep approved secret
values in memory for the approval/session lifetime so repeated command
invocations do not require repeated 1Password or Touch ID authorization. For
one-shot approvals, TTL bounds the approval/fetch/secret-delivery/spawn window
before the child starts. After the child is spawned, one-shot values clear from
daemon and CLI wrapper memory when the wrapped command exits. Reusable approvals
clear values when the TTL expires, the 3-use limit is exhausted, or the daemon
is stopped. V1 has no reusable approval list/destroy command; `agent-secret
daemon stop` is the manual way to clear reusable approvals early. Sessions may
have explicit destroy when session commands are implemented.

Policy/session objects must remain value-free. They may store request IDs,
session IDs, refs, aliases, TTL, use counts, read counts, delivery mode,
approval metadata, and cache keys, but never raw secret values. Reusable and
session secret values live only in a daemon-owned in-memory `SecretCache` keyed
by approval/session ID plus unique `op://` ref. One-shot exec values may pass
through `agent-secret exec` memory only long enough to create and supervise the
child environment. Audit writers, approval view models, and policy serializers
must consume value-free policy objects, not cache entries.

While reusable values are cached and valid, the daemon must not call the
1Password SDK again for those refs.
If a 1Password item changes during the reusable approval window, the cached
value wins until the approval expires unless the caller passes `--force-refresh`.
`--force-refresh` requires the same reusable approval match, refetches all
approved refs from 1Password, updates the in-memory cache only after a
successful all-or-nothing fetch, and records an audit event.
If refresh succeeds and the daemon returns an approved environment payload to
`agent-secret exec`, it consumes one of the reusable approval's 3 uses.
A reusable approval use is consumed when the daemon sends an approved
environment payload to `agent-secret exec`, because the values have left daemon
memory. Failures before payload delivery, including `approval_reused` audit
failure, `command_starting` audit failure, or fetch failure, do not consume a
use. Failures after payload delivery, including CLI spawn failure, immediate
child exit, non-zero exit, or later `command_started` audit failure, still
consume the use.

Broker approval must happen before any 1Password SDK fetch or ref validation
against 1Password in the normal path. If a ref is wrong, the user may approve the
request and then see a fail-closed fetch error. That tradeoff is acceptable for
v1 because the rule is simpler to reason about: no contact with 1Password for an
agent request before local broker approval.

Executable path resolution happens before approval and before any 1Password SDK
access. Resolution uses the requesting CLI process environment at request time:
if `argv[0]` contains a slash, resolve it as a path relative to the requested
cwd when needed; otherwise search the caller's `PATH`. If `argv[0]` cannot be
resolved to an executable path, the request fails closed with a clear error and
no approval prompt.

The resolved absolute executable path is the path `agent-secret exec` executes,
may show as the command binary in approval UI, stores in audit metadata, and
includes in the reusable approval match key. A long-lived daemon must not
accidentally use its own stale `PATH` for this decision; the CLI must resolve
before submitting the request. If `PATH` changes later, a new request is
resolved again and only reuses an approval if the resolved executable path still
matches exactly.

Approved refs are all-or-nothing in v1. If any approved ref fails to fetch, the
daemon must return no secret payload and `agent-secret exec` must not spawn the
child process.

After approval, the daemon should fetch approved refs with bounded concurrency.
Fetch ordering must not affect policy: the command receives secrets only after
every approved ref resolves successfully. If any fetch fails, the daemon drops
the successful values from that attempt, records metadata-only failure details,
does not update reusable/session caches, and returns no values to the CLI
wrapper.
An empty string returned by 1Password for an approved ref is a successful
resolution, not a fetch failure. For env-mode `exec`, it is delivered as an
environment variable set to the empty string. Missing, unreadable, unauthorized,
or otherwise unresolved refs still fail closed.
V1 should not depend on a native SDK bulk-resolution API; the resolver interface
can still adopt one later if it preserves the same bounded, all-or-nothing
semantics.

If the approved request contains the same `op://` ref under multiple aliases,
the daemon should fetch that unique ref once and fan the resolved value out to
each approved alias. This preserves duplicate refs as an aliasing feature while
avoiding extra SDK calls or repeated 1Password authorization prompts.

V1 allows arbitrary `op://` refs requested by the agent, as long as they are
shown clearly in the approval prompt. There is no allowlist or policy file in
v1; adding one should require a later explicit product decision.

Aliases are required in v1. For environment delivery, the alias is the
environment variable name. The broker should not infer aliases from 1Password
item or field names in normal flows.

Alias names must use strict uppercase environment-variable syntax:
`[A-Z_][A-Z0-9_]*`. Examples include `AWS_ACCESS_KEY_ID`,
`CLOUDFLARE_API_TOKEN`, and `AWS_SHARED_CREDENTIALS_FILE`.
Duplicate aliases are invalid. Duplicate refs are allowed when different aliases
need the same value. Duplicate refs are deduplicated for fetch and cache
purposes, then expanded back to the approved alias set for delivery.

Peer PID and executable checks are mandatory for session/socket reads on
supported macOS versions. A local probe on macOS 26.3 with the macOS 26.2 SDK
confirmed that a Unix socket server can obtain peer UID/GID, peer PID,
executable path, and cwd using public Darwin APIs (`getpeereid`,
`LOCAL_PEERPID`, `LOCAL_PEERCRED`, `proc_pidpath`, and
`PROC_PIDVNODEPATHINFO`). If those fields cannot be obtained or do not match
the approved session policy, the daemon must fail closed rather than silently
falling back to weaker checks.

`agent-secret exec` remains the strongest initial mode because the trusted CLI
wrapper controls environment injection and child lifecycle while the daemon owns
approval, fetch, cache, and audit policy. Future session/socket reads should
also be strict on macOS now that the required peer metadata is available.

## Secret Storage Rules

- Store reusable approval and session secret values only in daemon memory by
  default.
- Let `agent-secret exec` hold approved values transiently in memory only while
  preparing and supervising the child process.
- Keep policy/session objects value-free; only `SecretCache` and transient
  `agent-secret exec` env assembly may hold raw values.
- Never write secret values to disk.
- Never include secret values in console output, logs, UI, or audit events.
- Clear one-shot secret values from daemon and CLI wrapper memory when the
  command exits or the request fails.
- Clear reusable approval values when TTL expires, max uses are exhausted, or
  the daemon stops.
- Clear session values when TTL expires, read counts are exhausted, the daemon
  stops, or the session is destroyed.

## Audit Log Requirements

Audit logs should include:

- timestamp
- event type
- request ID and session ID
- requester metadata
- validated trimmed reason
- refs and aliases
- approval or denial, without an operator note field in v1
- approval reuse, including remaining TTL and remaining use count
- TTL and session/socket max reads when applicable
- delivery mode
- `command_starting` before child spawn
- `exec_client_disconnected_after_payload` when approved values were delivered
  to `agent-secret exec` but it disconnects before reporting a child PID
- `command_started` after successful child spawn, including child PID
- command completion, including exit code or signal
- read counts
- expiration and cleanup events
- errors

Audit logs must never include:

- secret values
- decrypted credentials
- generated environment files
- 1Password item field values
- child stdout or stderr

For v1 private dogfood, audit logs store full `op://` refs so local debugging is
straightforward. This records vault, item, and field names as metadata, but never
secret values. Logs must be current-user-only by default.
V1 uses a fixed per-user macOS audit log at
`~/Library/Logs/agent-secret/audit.jsonl` and does not accept a CLI audit-path
override. The daemon owns audit path selection, creates directories/files with
current-user-only permissions, and fails closed if audit logging is required but
not writable. Audit log writability is a pre-approval gate: if the daemon cannot
open the fixed log securely, it must fail the request before showing approval UI
or contacting 1Password.
For `exec`, audit logging remains daemon-owned but child spawning remains
CLI-owned. Before the daemon returns an approved environment payload, it must
write `command_starting`; if that write fails, it returns no values and
`agent-secret exec` must not spawn. For reusable approvals, the daemon consumes
the use as part of returning the approved payload. After successful spawn,
`agent-secret exec` reports the child PID to the daemon, which writes
`command_started`. If the daemon is reachable and reports that
`command_started` cannot be written securely after spawn, `agent-secret exec`
must immediately send `SIGTERM`, wait 2 seconds, send `SIGKILL` if the child is
still running, ask the daemon to clear eligible cached values, and fail closed.
After termination, the CLI may ask the daemon to write a best-effort
failure/termination audit event, but that attempt must not delay termination or
change the fail-closed outcome. Completion records exit code or signal when the
child was allowed to run.

If the daemon disconnects after payload delivery and after the child has been
spawned, `agent-secret exec` must let the child continue. It preserves child
stdout/stderr passthrough and returns the child exit code. It must not kill the
child, reconnect, recreate the request, or restart the daemon for that in-flight
command. Because daemon-owned audit is unavailable, command completion audit may
be missing. After the child exits, the CLI prints one non-secret warning line to
stderr, then returns the child exit code.

If the daemon sends an approved environment payload and the CLI disconnects
before reporting `command_started`, the daemon records
`exec_client_disconnected_after_payload`, clears one-shot daemon-held values, and
does not try to kill or infer any child process. The reusable use was already
consumed at payload delivery. Reusable cached values remain available until TTL,
3-use exhaustion, or daemon stop; the disconnect does not clear that reusable
cache by itself. Without a child PID, the daemon has no reliable or approved
process-supervision role.

## Delivery Modes

### Delivery Sequence

The dogfood sequence is:

1. env-only `agent-secret exec`;
2. ephemeral Unix socket reads for tools or wrappers that cannot consume
   environment variables cleanly;
3. sessions, credential helpers, file descriptors, and config-driven mapping
   after the first two delivery paths are solid.

Config-driven secret sync remains important, but it should not block the first
delivery path unless it can be expressed through explicit env mappings.

### Mode 1: CLI-Supervised `exec` With Environment Injection

The daemon approves and fetches secrets. `agent-secret exec` receives the
approved environment payload over the single per-user daemon socket, spawns the
target command, injects values into that child process, and waits for exit. The
daemon never spawns the child. For one-shot exec, TTL bounds the pre-spawn
approval/fetch/delivery window and values clear from daemon and CLI wrapper
memory after the command exits. Reusable approvals keep values in daemon memory
until their TTL or use limit is exhausted. This is the default v1 mode.

For env-mode `exec`, TTL is not a process lifetime limit. If a child process is
already running when a one-shot or reusable approval expires, neither the daemon
nor `agent-secret exec` kills that child just because the TTL elapsed. The secret
values have already been delivered into the child environment, so v1 treats
cleanup as an in-memory broker/wrapper concern and lets the wrapped command
finish naturally.

The child process inherits the parent environment by default, and
`agent-secret exec` overlays approved secret aliases onto that environment.

If an approved alias already exists in the parent environment, v1 should fail
closed unless the caller passes `--override-env`.
When `--override-env` is used, the approval prompt should show a concise warning
only if approved aliases will replace existing environment variables.

Pros:

- The parent agent never receives raw values from broker output.
- `agent-secret exec` controls the child PID and reports it to daemon-owned
  audit.
- Command lifecycle stays in the CLI wrapper instead of the daemon.

Limitations:

- Environment variables can still be exposed by child process behavior, crash
  reporters, debuggers, or subprocesses.

### Mode 2: Session Handles

The broker creates a short-lived session and returns handles instead of values.
Handles are only useful with the session socket, matching peer credentials,
remaining read count, and unexpired policy.

Future session value reads should happen through ephemeral Unix sockets or
equivalent local IPC and must never print values to stdout/stderr.
Unlike same-command reuse, sessions should approve a bounded set of refs for a
session lifetime and allow those approved refs to be read in whatever order the
approved workflow needs, subject to TTL, max-read, peer, and destroy policy.
On macOS, session/socket reads must fail closed unless the daemon can validate
same UID, peer PID, executable path, cwd, session/capability nonce, TTL, and
read count against the approved session.

### Mode 3: `with-session`

The agent receives a session ID but must wrap each command:

```bash
agent-secret with-session asess_123 -- terraform apply
```

The wrapper asks the daemon to resolve approved secrets and injects them only
into the child process.

### Mode 4: Credential Helpers

Future helpers can support existing tool protocols such as Git credential
helper, AWS `credential_process`, Docker credential helper, Kubernetes exec
credential plugin, and SSH-agent-like signing.

### Mode 5: File Descriptor or Pipe Delivery

For tools that support stdin, file descriptors, or pipes, the broker can avoid
environment variables and disk.

### No Console Resolve Or Disk Delivery

The broker must not provide a command that prints secret values to stdout or
stderr. It must also not write secret values to disk, including temporary
credential files. Debugging that requires seeing a secret value should use
1Password directly outside the broker.

The broker does not sanitize child process stdout or stderr. In `exec` mode, the
wrapped command's output passes through unchanged. The broker's own output must
never contain secret values, but an approved child command can still leak secrets
if it prints its environment or otherwise exposes received credentials.
A non-zero wrapped-command exit is not a broker error. `agent-secret exec`
returns the child's exit code or signal-based status without adding broker text
to stderr solely because the child failed; completion metadata belongs in audit.
If the daemon disappears after the child has already started, `agent-secret exec`
may append one non-secret stderr warning after the child exits to say completion
audit could not be written. It still returns the child exit code and must not
insert diagnostics into stdout.

When `agent-secret exec` receives an interrupt or termination signal while the
child is running, it forwards that signal to the child process group when
available, otherwise to the child process. It waits for the child to exit, runs
normal cleanup and audit reporting when possible, and returns the child's
signal-based exit status.
Repeated interrupts are forwarded again the same way. V1 does not escalate to
`SIGKILL` just because a second interrupt arrives, and it does not exit the
wrapper while leaving the child unobserved.
If the child ignores forwarded interrupts indefinitely, `agent-secret exec` does
not enforce its own kill timeout in v1. It continues waiting for the child so it
can preserve normal process-supervisor semantics; the operator can still kill the
wrapped process externally.

`agent-secret exec` does not support `--json` in MVP. The broker must not wrap,
buffer, capture, summarize, or reformat child stdout/stderr. Broker output should
stay minimal and human-readable, and structured detail belongs in the audit log.

## Approval UX

The approval prompt should appear before the 1Password Touch ID or password
prompt whenever possible. The approver should activate itself, request user
attention, and show a foreground window through public macOS APIs.

The default approval prompt is intentionally compact. It should show:

- reason
- full command argv exactly as it will be executed, with no omitted arguments
- cwd as compact command context
- resolved executable path as the command binary when useful
- secret aliases and full `op://` refs
- approval duration, including one-shot vs reusable requested-TTL / 3-use choice
- compact time remaining, such as `expires in 1m 42s`, because request TTL is
  also the approval prompt timeout
- a concise environment override warning only when `--override-env` will replace
  existing variables
- actions: `Approve once`, `Allow same command for <ttl> / 3 uses`, and `Deny`

The prompt should not show requester metadata, daemon path, approver path, git
metadata, delivery-mode internals, request IDs, nonces, or other audit fields by
default. Those belong in audit logs, debug output, or `doctor`, not in the
operator's approval decision.

The prompt must not show raw secret values.
The approval prompt is read-only with respect to the request. The approver can
approve once, allow same-command reuse, or deny, but cannot edit the requester
reason, command, cwd, refs, TTL, or any other request field. If the reason is
wrong or insufficient, the correct action is deny and rerun with a better
`--reason`.
Denial is a simple v1 action and does not ask for or store an operator note.
The audit event records the denied request metadata.

Long commands may use scrollable or expandable UI, but the approval data must
include the full argv exactly.

Secret rows should show both alias and full ref, for example
`CLOUDFLARE_API_TOKEN -> op://Example/Cloudflare API Token/password`.
The `Approve once` action should be the default highlighted approval action.
The reusable action should show its 3-use limit and clearly state that approved
values stay in daemon memory for up to the requested TTL or 3 matching uses.
In operator-facing UI, say "uses" rather than "runs." A use means approved
values were delivered to `agent-secret exec`; a failed spawn after delivery still
spends one use.

Each approval response must include the request ID and nonce. The daemon must
reject stale, duplicated, or mismatched responses.
Approval requests and responses travel over the single per-user daemon socket.
The approver receives metadata only; it never receives secret values.
The daemon accepts `approval.response` only from the approver process launched or
activated for that request, verified by socket peer PID and executable identity.
Matching request ID and nonce are required but not sufficient by themselves.

If the approver cannot be launched, the request fails closed immediately. If the
approver does not answer before the request TTL expires, the request fails
closed. V1 should not fall back to a terminal prompt and should not retry-launch
in a loop; approver launch failures are treated as real errors to fix.
There is no `--no-native-ui` mode in v1; the native approver is the only
approval path for secret access.

The daemon shows at most one approval prompt at a time. Approval-requiring
requests that arrive while another prompt is active are queued until the active
prompt is approved, denied, or times out. V1 does not open multiple simultaneous
approval windows and does not fail a request with a busy error just because
another approval is active.
Queued requests keep their original request receipt time and TTL. A queued
request that expires before reaching the front of the queue fails closed without
being shown.
The approval queue is strict FIFO. A later request with a shorter remaining TTL
does not jump ahead; it may expire in the queue.
Requests that match an existing reusable approval are not approval-requiring for
queue purposes and do not wait behind an active prompt.

## CLI V1

Global options:

```text
--reason string              Required. Trimmed, non-empty, max 240 characters.
--ttl duration               Exec default: 2m. Exec bounds: 10s to 10m.
--cwd path                   Child working directory. Default: caller cwd.
--override-env               Allow approved secret aliases to replace existing
                             env vars.
--force-refresh              Refetch values for a matching reusable approval.
```

Deferred session and socket-read option:

```text
--max-reads integer          Session/socket only. Default: 1.
```

MVP commands:

```bash
agent-secret exec [options] -- command [args...]
agent-secret daemon status
agent-secret daemon start
agent-secret daemon stop
agent-secret doctor
```

Deferred session commands:

```bash
agent-secret session create [options]
agent-secret with-session asess_123 -- command [args...]
agent-secret session list
agent-secret session destroy asess_123
```

There is no audit viewer command in MVP. Operators can inspect the JSONL audit
file directly at `~/Library/Logs/agent-secret/audit.jsonl`.

There are no reusable approval management commands in v1. In particular,
`agent-secret approvals list` and `agent-secret approvals destroy <id>` are out
of scope. If the operator wants to clear reusable approvals before TTL or 3-use
exhaustion, they use `agent-secret daemon stop`, which clears daemon memory.

`agent-secret --help` must be detailed enough for an agent to run it and know
what to do without reading the PRD. Model it after dense agent-oriented CLIs such
as `agent-browser --help`: include a one-paragraph purpose statement, command
groups, all flags, safety rules, approval/reuse behavior, exit-code behavior,
daemon behavior, audit-log location, environment-variable delivery notes,
examples for Terraform/Ansible-style `exec`, `doctor`, daemon management, and
clear statements that the tool never prints secret values and does not support
raw resolve. Subcommand help, especially `agent-secret exec --help`, should give
focused examples and explain required `--reason`, `--secret ALIAS=op://...`,
`--profile`, `default_profile`, project profile config, config-level `account`,
profile-level `account`, secret-level `account`, `--ttl`, `--cwd`,
`--override-env`, and `--force-refresh`.

`exec` accepts only argv after `--`. The CLI does not parse shell command
strings. If shell behavior is required, the caller must make it explicit, for
example `agent-secret exec ... -- sh -lc 'terraform plan'`; the approval UI then
shows that full argv.

The first implementation accepts explicit `--secret ALIAS=op://...` mappings
and project-local `--profile NAME` or `default_profile` mappings from
`agent-secret.yml` or `.agent-secret.yml`, with optional account defaults and
per-secret account overrides. A broader `--secret-config` mapping mode remains
deferred.

`doctor` should use the same on-demand daemon startup path as normal commands,
then report the resulting daemon status. It should launch/probe the native
approver using a non-secret health check, not a real approval request. It should
also verify 1Password SDK/client availability, desktop-app auth state,
desktop-app integration availability, socket directory permissions, and audit log
writability. It may trigger the 1Password desktop authentication flow so it can
verify readiness, but it must stop before item/ref access. It must not resolve
any `op://` ref, fetch arbitrary secrets, or print secret values.

## Socket API V1

Use JSON messages over Unix domain sockets first. MVP uses the single per-user
daemon socket for CLI request, approver request fetch/decision, approval result,
approved environment payload delivery, and command lifecycle reporting. It does
not create one-shot secret-payload sockets or file descriptors.

Recommended macOS paths:

```text
$TMPDIR/agent-secret/daemon.sock
$TMPDIR/agent-secret/sessions/asess_123.sock
```

MVP requirements:

- socket directory mode `0700`
- current-user access only
- MVP `exec` command-channel validation requires same-user daemon access plus a
  valid request envelope, protocol version, message type, and request nonce.
  The protocol is designed for CLI-owned child spawning through `agent-secret
  exec`, but v1 does not require strict CLI PID/executable/cwd validation.
- `request.exec` responses may contain approved env values only after approval,
  successful all-or-nothing fetch, and `command_starting` audit success. Those
  values must never be logged by client, server, protocol tracing, or tests.
- the approver connects to the same daemon socket to receive approval metadata
  and submit decisions; approval IPC must not use stdin/stdout, argv/env, or temp
  files
- `approval.response` is accepted only from the approver process launched or
  activated for that request, verified by socket peer PID and executable identity
- stale socket cleanup on startup
- request envelopes with protocol version and message type

Deferred session socket requirements:

- randomized private session paths
- strict peer UID, PID, executable path, cwd, session/capability nonce, TTL, and
  read-count validation

MVP endpoint types:

- `request.exec`
- `approval.request`
- `approval.response`

Deferred session endpoint types:

- `session.create`
- `session.resolve`
- `session.destroy`

`session.resolve` should be internal to wrappers by default and must never be
logged with values.

## 1Password SDK Assumptions To Validate

The broker should use the official 1Password Go SDK and desktop-app
authentication. Research must confirm:

- exact package and API names
- how to resolve `op://` refs
- whether concurrent ref resolution is safe and how SDK calls are authenticated
- whether metadata can be read without values
- whether SDK calls are grouped or repeatedly prompt
- how long desktop auth remains warm
- error types for locked, denied, missing, or unauthorized refs
- whether the SDK offers any scope controls beyond account authorization
- whether SDK metadata or existence checks are available for future diagnostics

1Password's desktop prompt is not treated as item-level policy. The broker must
enforce exact-ref policy itself.

There is no planned `op read` fallback. If SDK integration fails, the SDK spike
fails and the design should be revisited rather than silently switching to the
CLI path this tool is meant to replace.

## macOS Implementation Notes

- Use public macOS APIs only.
- Avoid private APIs and Accessibility-permission hacks.
- Prefer a per-user LaunchAgent after the on-demand v1 works.
- Private dogfood does not require codesigning or notarization. Build and run
  locally first; signed binaries, notarization, and a hardened Swift app are
  pre-public-distribution work.
- Consider mutual identity checks between daemon and approver where practical.

## MVP Scope

MVP must include:

- Go CLI
- Go daemon or daemon mode, started on demand by the CLI
- Swift macOS approval app with foreground prompt
- official 1Password Go SDK integration
- `exec` mode with environment injection
- required `--reason`
- refs displayed before fetch
- TTL policy for `exec`
- one-shot approval plus optional same-command reuse for requested TTL and 3 uses
- metadata-only audit log
- socket directory permission checks and same-UID daemon command-channel
  validation
- detailed `agent-secret --help` and subcommand help for agent self-discovery
- `doctor` command
- Go lint/pre-commit coverage for this repository before Go implementation
  starts

MVP should include:

- child lifecycle and child PID audit tests for CLI-spawned `exec` commands
- denial and timeout behavior
- redaction-safe structured logs

MVP can defer:

- session creation with opaque handles
- `with-session` wrapper
- strict session/socket peer validation, which is required when session/socket
  reads are implemented but does not block env-only `exec`
- menu bar presence for the approver
- Git credential helper
- AWS `credential_process`
- SSH-agent-like mode
- file descriptor mode
- codesigning and notarization automation
- policy file system
- team sharing
- Linux support
- Windows support

## Milestones

### Milestone 0: Research Spikes

Deliverables:

- Minimal Go program resolving one test-only `op://` ref through the 1Password
  SDK without printing the value.
- Notes on observed desktop auth and Touch ID behavior.
- Go Unix socket peer credential proof of concept on macOS.
- Swift app proof of concept that reliably foregrounds an approval window.

Exit criteria:

- One test secret can be read through the SDK after desktop approval.
- The Swift approval window appears when launched from CLI or daemon context.
- Peer credential capture and fail-closed limits are documented.

### Milestone 1: `exec` And Reusable Approval Prototype

Deliverables:

- `agent-secret exec`
- hidden daemon startup
- native approval UI
- 1Password fetch after approval
- child process env injection
- one-shot approval
- same-command reusable approval for requested TTL and 3 uses
- in-memory cleanup after one-shot command exit or reusable approval expiry
- metadata-only audit log

Exit criteria:

- A local Terraform-style command can run with broker-provided environment
  variables.
- The same exact command can be approved for reuse and rerun without another
  approval prompt during the requested-TTL or 3-use window.
- Broker output does not print secret values.
- Approval UI shows reason, refs, command, cwd, optional command binary, and
  approval duration without audit/debug noise.

### Milestone 2: Sessions And Unix Socket Reads

Deliverables:

- session create, list, and destroy
- opaque handles
- `with-session` wrapper
- ephemeral Unix socket reads for approved session refs
- TTL and max-read enforcement
- strict macOS peer validation for UID, PID, executable path, and cwd

Exit criteria:

- A multi-command workflow can be approved once and executed through wrappers.
- Approved session refs can be read in whatever order the workflow needs without
  console output or disk writes.
- Expired sessions cannot be used.
- Peer metadata failures or mismatches fail closed.
- Max-read policy works.

### Milestone 3: Hardening

Deliverables:

- LaunchAgent install and uninstall flow
- socket cleanup
- better process metadata display
- pre-public signing/notarization plan
- UI spoofing mitigations
- integration tests

Exit criteria:

- The tool is safe enough for daily local use by one developer on macOS.
- Common failure modes fail closed with clear messages.

### Milestone 4: Credential Helpers

Deliverables:

- Git credential helper
- AWS `credential_process`
- optional Docker or Kubernetes helpers

Exit criteria:

- Common tools can request credentials without exposing values to the agent.

## Acceptance Criteria

### Approval Prompt Criteria

- Given an agent requests secrets with a reason, the macOS approval window
  appears in the foreground.
- The prompt includes reason, refs, command, cwd, optional command binary, and
  approval duration.
- Denying the prompt prevents any 1Password secret fetch.
- Approving the prompt allows only the displayed refs.

### Secret Access Criteria

- The broker never contacts 1Password or fetches secrets before local broker
  approval in the normal secret-access path.
- The broker fetches only approved refs.
- The broker never writes secret values to logs.
- The daemon and CLI wrapper clear one-shot secret values from their own memory
  when the command exits.
- For one-shot env-mode `exec`, TTL expiry before child spawn fails closed
  without launching the child.
- The daemon clears reusable approval values when the TTL expires, max uses are
  exhausted, or the daemon stops. V1 has no explicit reusable approval
  list/destroy command.
- The daemon clears session values when the TTL expires, read counts are
  exhausted, the daemon stops, or the session is destroyed.
- For env-mode `exec`, TTL expiry does not kill an already-running child
  process.

### `exec` Mode Criteria

- The child command receives configured environment variables.
- The parent agent does not receive raw values from broker output.
- The wrapped child command's stdout/stderr pass through unchanged.
- `agent-secret exec` returns the child exit status, including signal-based exit
  status after interrupts; any broker-owned metadata is non-secret.

### CLI Help Criteria

- `agent-secret --help` explains purpose, safety model, command groups, flags,
  examples, daemon behavior, audit-log location, and exit behavior in enough
  detail for coding agents to use the tool correctly.
- `agent-secret exec --help` includes concrete `--reason`,
  `--secret ALIAS=op://...`, Terraform/Ansible-style examples, and notes about
  approval, reusable approvals, env delivery, stdout/stderr passthrough, and the
  absence of raw secret output.
- Help output must not contain real vault, item, field, token, or credential
  values.

### Diagnostics Criteria

- The macOS approver writes non-secret troubleshooting events to Apple's Unified
  Logging with stable subsystem/category names.
- Approver logs include lifecycle, foregrounding, daemon-socket IPC, timeout,
  denial, approval, and error events without secret values or environment
  payloads.

### Session Mode Criteria

- Session create returns handles only.
- Handles cannot be resolved after TTL.
- Handles cannot be resolved more than the allowed read count.
- On macOS, handle resolution fails closed if peer UID, PID, executable path, or
  cwd cannot be obtained or does not match the approved session policy.
- Destroying a session invalidates all handles.

### Audit Criteria

- V1 `exec` logs approval request, approval grant, approval denial, approval
  timeout, reusable approval reuse/refresh, secret fetch attempt, secret fetch
  failure, command start/start-complete/completion, post-payload disconnect, and
  daemon stop events.
- Future handle/session delivery APIs must add expiry and destroy audit events
  before those APIs are considered complete.
- Logs contain refs and aliases but no values.
- Logs are readable only by the current user by default.

### Failure Criteria

- If the approver is unavailable, the daemon attempts to launch it.
- If approval does not arrive before the request TTL expires, the request fails
  closed.
- If 1Password is locked or denied, the request fails closed.
- If one ref fetch fails, no partial secret set is delivered by default.
- If the daemon disconnects before payload delivery, `agent-secret exec` fails
  closed with a clear daemon-disconnected error. It does not auto-reconnect or
  recreate the request.
- If the daemon disconnects after payload delivery and after child spawn,
  `agent-secret exec` lets the child continue, preserves stdout/stderr
  passthrough, prints one non-secret stderr warning after the child exits, and
  returns the child exit code.
- If `agent-secret exec` disconnects after payload delivery but before
  `command_started`, the daemon records `exec_client_disconnected_after_payload`,
  clears one-shot daemon-held values, and does not try to kill or infer a child
  process. Reusable cached values are not cleared by this event alone.
- If a child process exits, cleanup runs.
- If a reusable approval expires while a child is still running, the command is
  allowed to finish and broker-held cached values are cleared.

## Success Metrics

- User can understand why each secret request is happening.
- Default workflows never require console secret output.
- Broker-generated logs contain zero secret values.
- Approval appears before the 1Password prompt in normal flows.
- Terraform and Ansible dogfood workflows work end to end through `exec`.
- A config-driven secret sync workflow is either supported or explicitly
  designed as the next dogfood target.
- Session expiration and max-read tests pass reliably.

Initial dogfood smokes should run in this order:

1. `terraform plan`
2. `ansible-playbook site.yml --check`
3. `make validate`
4. `bin/setup-op-secrets --dry-run`

## Implementation Details To Verify

- Confirm exact 1Password Go SDK package names, desktop-app auth behavior, error
  types, and concurrency behavior on current macOS versions. The v1 design
  assumes the official SDK path; there is no planned `op read` fallback.
