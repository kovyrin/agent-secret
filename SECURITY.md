# Security Policy

## Supported Versions

Agent Secret is pre-1.0 software. Until the first stable release, security fixes
target the latest published release and current `main`.

The supported runtime scope is narrow:

- macOS on Apple Silicon.
- 1Password Desktop integration through the official 1Password SDK.
- CLI-supervised `agent-secret exec` with environment injection.

Linux, Windows, session handles, credential helpers, automatic updates, and
alternative secret backends are not supported security surfaces yet.

## Reporting A Vulnerability

Use GitHub private vulnerability reporting:

<https://github.com/kovyrin/agent-secret/security/advisories/new>

Do not open a public issue with exploit details, raw secret values, private
vault names, real `op://` secret references, credentials, crash dumps that may
contain environment variables, or screenshots that reveal sensitive metadata.

If private vulnerability reporting is unavailable, open a minimal public issue
that says you have a security report and need a private contact path. Include no
technical details beyond the affected component.

## What To Include

Useful reports include:

- Affected version, commit, or release tag.
- macOS version and hardware architecture.
- Whether the build was a signed release, local dev build, or custom artifact.
- The trust boundary involved, using `docs/threat-model.md` when possible.
- Reproduction steps using synthetic references or test-only 1Password items.
- Expected impact, especially whether raw secret values can be fetched,
  delivered, logged, persisted, or sent to the wrong process.

## Response Expectations

There is no guaranteed SLA before 1.0. The expected maintainer flow is:

1. Acknowledge the report after it is seen.
2. Triage whether it is inside the supported threat model.
3. Prepare a fix, mitigation, or documentation correction.
4. Release and document the fix when the issue affects a published release.

Reports outside the current scope may still be useful, but they may be treated
as hardening or roadmap work instead of release-blocking vulnerabilities.

## Security Scope

Agent Secret is a local approval and execution broker. It is not a sandbox.

In scope:

- Same-UID processes crossing a documented socket, executable identity, install,
  release artifact, audit, approval, or secret-delivery boundary.
- Fetching a secret before local approval.
- Delivering a secret outside the displayed command, cwd, account, or secret
  reference scope.
- Logging, printing, or persisting raw secret values.
- Accepting release artifacts from the wrong signer, bundle ID, or notarization
  state.

Out of scope:

- Root, kernel, hypervisor, physical-access, or fully compromised user-session
  attackers.
- A malicious approved child process after the operator intentionally delivered
  secrets to it.
- 1Password Desktop or the official 1Password SDK returning the wrong value.
- Downstream tools leaking secrets after receiving approved environment
  variables.

See `docs/threat-model.md` for the review contract used by this repository.
