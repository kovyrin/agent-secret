# Threat Model

Status: living review contract.

Last reviewed: 2026-05-03.

## Purpose

This document defines the threat model used to review Agent Secret for
vulnerabilities. Security reviews should cite this document, state which
revision or date they used, and classify findings as violations, gaps, or
proposed changes to this model.

This is not a proof that the system is safe. It is the shared checklist and
set of assumptions reviewers use so each pass starts from the same standard.

## Product Scope

Agent Secret is a local macOS-first broker for short-lived access to
1Password-backed secrets. The first supported delivery mode is CLI-supervised
`exec` with environment injection:

1. The CLI validates a request and connects to the per-user daemon.
2. The daemon shows a native approval prompt before resolving secrets.
3. The daemon resolves exactly the approved 1Password refs.
4. The daemon returns an approved environment payload to the trusted CLI.
5. The CLI starts the child process with those environment variables.
6. The daemon records value-free audit metadata.

Other delivery modes are out of scope for the current implementation.

## Assets

The model protects these assets:

- Raw 1Password secret values.
- Secret refs, aliases, and account scope.
- Approval decisions and reusable approval state.
- Approval request metadata shown to the operator.
- CLI-to-daemon protocol messages and environment payloads.
- Daemon-to-approver protocol messages and decisions.
- Audit log integrity and value-free audit contents.
- Installed app bundle, CLI symlink, and bundled skill.
- Release DMGs, checksums, code signatures, and notarization identity.

Secret refs and aliases are metadata, not raw secret values. They can still be
sensitive and must be handled intentionally.

## Trusted Components

These components may enforce security policy:

- The signed Agent Secret app bundle.
- The bundled `agent-secret` CLI.
- The bundled `agent-secretd` daemon helper app.
- The shipped native approver app executable.
- The official 1Password SDK and 1Password Desktop integration.
- Apple code-signing, Gatekeeper, and notarization checks.
- The local operating system's Unix socket peer credential APIs.

Trust in Agent Secret binaries should be tied to concrete executable identity
and, for production builds, the expected Apple Developer Team ID.

## Untrusted Inputs

These inputs must not be trusted without validation:

- Any same-UID local process.
- Unix socket paths and any process listening on them.
- Shell environment variables.
- Project directories, temp directories, and writable command paths.
- Project config files and env files.
- Symlinks and existing filesystem objects.
- GitHub release assets until provenance is checked.
- Daemon-supplied error text displayed by the approver.
- Child processes after secrets are intentionally delivered.

## Attacker Capabilities

The primary attacker is a same-UID local process. It can:

- Bind or replace user-writable Unix socket paths.
- Connect to daemon or approver sockets.
- Race file replacement in writable directories.
- Create symlinks and preexisting files in user-writable locations.
- Control shell environment variables.
- Provide malicious project configs or env files.
- Launch or point tools at fake local sockets.
- Try to make review or install tooling accept wrong release artifacts.

The model also considers compromised release assets, such as a replaced DMG and
matching checksum file on the release page.

## Security Goals

Agent Secret must meet these goals:

- Raw secret values are never printed, logged, or written to disk by Agent
  Secret.
- The daemon never resolves secrets before a valid approval or reusable approval
  match.
- Approval is bound to the displayed reason, command argv, resolved executable,
  executable identity, cwd, secret refs, account scope, TTL, and override
  behavior.
- Reusable approvals expire at their TTL, consume uses correctly, and clear
  cached raw values when exhausted, expired, or rolled back.
- The daemon accepts exec and stop requests only from trusted Agent Secret CLI
  executables.
- The CLI accepts secret-bearing responses only from a trusted Agent Secret
  daemon.
- The native approver renders requests only from a trusted Agent Secret daemon.
- Protocol frames have size, version, type, timeout, nonce, and request ID
  checks appropriate to their lifecycle phase.
- Every secret delivery attempt has value-free audit metadata before raw values
  are delivered to a child process.
- Audit failure before payload delivery prevents child process execution.
- Audit logs are opened as Agent Secret-owned regular files, not arbitrary
  symlink targets.
- Installer and release tooling copy only artifacts from the expected project
  signer and expected bundle identifiers.
- Documentation and help text describe the security contract that the code
  actually enforces.

## Non-Goals

The model does not try to defend against:

- Root, kernel, hypervisor, or physical-access attackers.
- A fully compromised user account that can tamper with all user files and
  running processes.
- A malicious child process after the operator intentionally approves delivery
  of secrets to that process.
- 1Password Desktop or the official 1Password SDK returning the wrong value.
- Apple notarization or Developer ID infrastructure being compromised.
- Secrets exposed by downstream tools once the approved child receives them.
- Defense-in-depth hardening that materially increases product complexity
  without protecting a stated asset, trust boundary, or security goal in this
  document.

These non-goals do not excuse avoidable local trust-boundary mistakes. They only
define where Agent Secret stops claiming protection.

## Scope and Complexity Discipline

This model is also a guardrail against over-hardening. Agent Secret should stay
small enough that reviewers can understand the trust boundaries and reason about
the secret path end to end.

Security findings should be release-blocking only when they identify concrete
product harm inside this model. A same-UID local process is in scope when it can
cross a stated boundary, such as impersonating a daemon socket, replacing an
approved executable, or causing the installer to trust the wrong artifact. The
same attacker capability should not justify unbounded hardening of every helper
tool, parser, shell snippet, or test fixture unless that component is part of a
documented trust decision.

Prefer these outcomes when fixing findings:

- Delete or simplify code when a lower-level invariant already covers the risk.
- Enforce the trust boundary closest to the asset being protected.
- Keep one focused regression per invariant instead of many tests for the same
  hypothetical attack shape.
- Move non-release-blocking hardening ideas to the backlog when the product
  contract is already satisfied.

## Trust Boundaries

### CLI to Daemon Socket

The CLI sends request metadata and receives secret-bearing environment payloads.

Required checks:

- The socket directory is private and owner-controlled.
- The CLI authenticates the daemon peer before accepting responses.
- The daemon authenticates exec and stop peers before serving those requests.
- Responses carrying request state are versioned and correlated by request ID
  and nonce.
- Context cancellation and timeouts do not leave a client hung forever.

### Daemon to Native Approver

The daemon launches the native approver and waits for a decision.

Required checks:

- The daemon validates the approver executable and launched peer.
- The approver validates the daemon peer before displaying metadata.
- Approval decisions include request ID and nonce.
- Approval requests expire in daemon policy and UI behavior.
- Daemon-supplied error text is sanitized before display.

### Daemon to 1Password

The daemon resolves approved refs through 1Password Desktop integration.

Required checks:

- Secret refs and account scope are validated before resolution.
- Ref resolution starts only after approval.
- Partial fetch failures cancel outstanding fetches and are audited.
- Raw values stay in memory only for the approved delivery or reuse window.
- Cached values are keyed by ref and account.

### CLI to Child Process

The CLI injects approved values into the child environment.

Required checks:

- The child command is argv, not a shell string.
- The approved executable identity is verified immediately before launch.
- Mutable executable paths are rejected or launched atomically.
- Existing env values are not overwritten unless the request says so.
- Signals and terminal foreground state are handled without losing audit state.

### Audit Filesystem

The daemon writes value-free JSONL audit metadata.

Required checks:

- The audit directory is private and owner-controlled.
- The audit log is a regular file owned by the user.
- Symlinked audit paths are rejected.
- Audit events do not include raw secret values.
- Required audit failure before payload delivery blocks execution.

### Release and Install

Release tooling builds app bundles and DMGs. Install tooling copies them into
place and installs symlinks.

Required checks:

- Tag releases require Developer ID signing and notarization inputs.
- The installer verifies checksums, signatures, Gatekeeper, notarization,
  expected Team ID, and expected bundle IDs.
- Local unsigned install paths require explicit opt-in.
- Install and uninstall scripts refuse dangerous path overrides.
- App bundle metadata matches the runtime trust assumptions.

## Review Checklist

Each security review should explicitly walk these questions:

- Can a same-UID process impersonate either side of a socket?
- Can an environment variable replace a trusted binary, account, or socket?
- Can a path be swapped, symlinked, or chmodded outside Agent Secret ownership?
- Can a secret be fetched, cached, reused, or delivered outside approval scope?
- Can a timeout, cancellation, or disconnect lose required audit state?
- Can an attacker make the UI show misleading command, account, or secret scope?
- Can daemon or approver protocol responses skip version or correlation checks?
- Can release or installer checks accept artifacts from the wrong signer?
- Can docs or help text promise stronger behavior than the code enforces?
- Do tests cover the trust boundary, not only the happy path?

## Finding Severity

Use these priorities for review findings:

- P1: likely secret disclosure, unauthorized approval bypass, or release
  compromise under this model.
- P2: exploitable trust-boundary violation, meaningful policy bypass,
  persistent audit integrity issue, or strong availability failure in the
  secret path.
- P3: hardening gap, confusing failure mode, stale security contract, or local
  footgun that can damage trust in the product.

Severity should describe concrete product harm, not generic security anxiety.

## Review Finding Ledger

This document is the stable review contract, not the live issue tracker.
Current open findings live in GitHub issues named `ASR-NNN`. Historical review
reports may be archived outside the product repository when they describe
findings that have since been fixed.

When a review produces a finding, the finding should map to one of the trust
boundaries above, or it should propose an explicit update to this threat model.
Fix status, PR links, and closure evidence belong in the GitHub issue and PR
history rather than in this model.
