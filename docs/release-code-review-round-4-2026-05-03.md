# Release Code Review Round 4 - 2026-05-03

Baseline reviewed: `origin/main` at `4404283`.

Threat model used: `docs/threat-model.md`, last reviewed 2026-05-03.

Reviewer stance: hostile same-UID local process, hostile project directory,
hostile inherited environment, hostile release asset replacement, and accidental
operator misuse.

## Executive Summary

The previous review findings ASR-021 through ASR-027 look materially addressed
on the current main branch. The latest code now enforces release signing inputs
for tag builds, checks installed Team ID and bundle IDs, validates daemon and
approver socket peers, captures and re-verifies executable identity, hardens
audit and uninstall symlink behavior, and updates release documentation.

This pass did not find a new P1/P2 approval bypass or direct raw-secret leak.
It did find four P3 hardening gaps where code still falls short of the newly
checked-in threat model:

- ASR-028: daemon socket directory validation follows symlinks.
- ASR-029: Go client responses have no protocol frame size bound.
- ASR-030: structured error responses bypass request ID and nonce correlation.
- ASR-031: installer production trust roots are still environment-overridable.

These are worth fixing because this project now has an explicit model that says
socket paths, symlinks, protocol frames, release assets, and environment
variables are hostile inputs. None of the issues below invalidates the recent
same-UID peer-authentication work, but all of them are places where the code is
still relying on convention or caller discipline instead of enforcing the
boundary.

## Review Method

This pass walked the threat-model checklist across:

- Go daemon socket setup, protocol handling, peer validation, broker state,
  policy/cache, audit writer, CLI manager, exec wrapper, request validation, and
  file identity code.
- Swift approver transport, daemon peer validation, socket protocol client,
  approval presenter, expiration logic, and UI decision bindings.
- Release, install, uninstall, bundle, GitHub Actions, and smoke-test scripts.
- Tests that claim to cover the trust boundaries above.

Validation commands run during this pass:

```bash
mise run lint:go
mise run lint:swift
mise run test:smoke
```

All three completed successfully on the reviewed tree.

## New Findings

### ASR-028: Daemon Socket Directory Validation Follows Symlinks

Priority: P3

Threat-model mapping:

- Untrusted inputs include symlinks and existing filesystem objects.
- The CLI-to-daemon boundary requires the socket directory to be private and
  owner-controlled.
- The checklist explicitly asks whether a path can be swapped, symlinked, or
  chmodded outside Agent Secret ownership.

Relevant code:

- `internal/daemon/socket.go:48-78` prepares the default or custom socket
  directory.
- `internal/daemon/socket.go:60-68` uses `os.MkdirAll` and `os.Chmod` for the
  default socket directory.
- `internal/daemon/socket.go:80-97` validates custom socket parents with
  `os.Stat`, which follows symlinks.
- `internal/daemon/socket_test.go:25-87` covers private default directories and
  permissive custom directories, but not symlinked parents.

Problem:

The audit writer was recently hardened with `os.Lstat`, explicit symlink
rejection, and no-follow opens. The daemon socket directory did not get the same
treatment. `rejectInsecureSocketDirectory` calls `os.Stat`, so a symlinked
socket parent is validated as the symlink target. The default path is worse:
if `~/Library/Application Support/agent-secret` already exists as a symlink,
`os.Chmod(dir, 0700)` chmods the target directory.

A same-UID process can pre-create a symlink at the managed socket directory or
at a custom socket parent. The daemon can then place its socket in the target
directory and, for the default path, chmod that target. This is not currently a
raw-secret bypass because the CLI and daemon now authenticate peer executable
identity. It is still a filesystem-boundary violation: the code says it owns a
private Agent Secret socket directory, but it may actually be operating through
a user-controlled symlink target.

Impact:

- Confusing daemon placement and denial of service when a symlink points at an
  unexpected private directory.
- Chmod side effects on a same-user directory outside Agent Secret ownership.
- A test gap exactly at the boundary the threat model says reviewers should
  check.

Recommended fix:

- Validate the final socket parent with `os.Lstat` and reject symlinks for both
  default and custom socket paths.
- For the default path, avoid chmodding a preexisting symlink target. Create the
  managed directory when absent, then lstat and chmod only a real directory at
  that exact path.
- Consider sharing the audit directory hardening pattern instead of maintaining
  two subtly different filesystem validators.

Suggested tests:

- `TestListenUnixRejectsSymlinkDefaultSocketDirectoryWithoutChmodTarget`
- `TestListenUnixRejectsSymlinkCustomSocketParent`
- `TestValidateSocketDirectoryRejectsSymlinkParent`

### ASR-029: Go Client Responses Have No Protocol Frame Size Bound

Priority: P3

Threat-model mapping:

- Protocol frames require size, version, type, timeout, nonce, and request ID
  checks appropriate to their lifecycle phase.
- Unix socket paths and any process listening on them are untrusted inputs until
  peer identity is validated.

Relevant code:

- `internal/daemon/protocol.go:12-13` defines a 1 MiB default protocol frame
  limit.
- `internal/daemon/protocol.go:100-135` implements bounded newline frame reads.
- `internal/daemon/server.go:348-355` uses that bounded reader on the daemon.
- `approver/Sources/AgentSecretApprover/UnixSocketLineTransport.swift` has a
  Swift response frame bound.
- `internal/daemon/client.go:57-62` constructs a raw `json.Decoder` over the
  Unix connection.
- `internal/daemon/client.go:129-138` decodes the response without a maximum
  frame size.

Problem:

The daemon side and Swift approver side have explicit protocol frame size
limits, but the Go CLI client does not. It waits for a JSON value from
`json.Decoder.Decode` and only validates the envelope after the decode has
completed.

Peer validation makes this less severe than the old fake-daemon issue, because
a random same-UID process should no longer be able to impersonate the trusted
daemon to the production CLI. Still, the protocol contract is inconsistent. If
the trusted endpoint misbehaves, or if a test/dev mode disables validation, the
client can consume an unbounded response before it gets to version, type,
request ID, or nonce validation.

Impact:

- Memory exhaustion or long stalls in the CLI from an oversized response frame.
- Inconsistent protocol behavior between daemon, Swift client, and Go client.
- Missing regression coverage for a threat-model requirement that already has a
  shared Go helper.

Recommended fix:

- Give `Client` a `bufio.Reader` and use the same bounded newline-frame reader
  that the server uses.
- Keep the current context cancellation and deadline behavior around the bounded
  read.
- Treat oversized daemon responses as protocol errors before JSON decoding.

Suggested tests:

- A fake daemon writes more than `DefaultMaxProtocolFrameBytes` and the Go
  client returns `ErrProtocolFrameSize`.
- A valid response at the limit still succeeds.
- Context cancellation still closes the client while it is waiting for a
  response line.

### ASR-030: Structured Error Responses Bypass Request ID and Nonce Correlation

Priority: P3

Threat-model mapping:

- Protocol responses carrying request state must be versioned and correlated by
  request ID and nonce.
- The checklist explicitly asks whether daemon or approver protocol responses
  can skip version or correlation checks.

Relevant code:

- `internal/daemon/client.go:139-156` validates version/type, handles
  `TypeError`, and only then checks request ID and nonce for success responses.
- `approver/Sources/AgentSecretApprover/SocketDaemonClient.swift:88-99` treats
  `error` headers as daemon errors before payload-specific correlation.
- `approver/Sources/AgentSecretApprover/SocketDaemonClient.swift:122-130`
  decodes daemon errors without validating the envelope request ID or nonce.
- `approver/Tests/AgentSecretApproverTests/SocketDaemonClientTests.swift`
  covers success-response request ID and nonce mismatches, but not mismatched
  error envelopes.

Problem:

Both protocol clients validate correlation for successful responses, but not
for structured error responses. In Go, `roundTrip` returns `ProtocolError`
immediately when `resp.Type == TypeError`, before comparing `resp.RequestID`
and `resp.Nonce` to the active request. In Swift, `readOKEnvelope` validates the
protocol version, detects `type == "error"`, and throws the decoded daemon
error before any request-specific correlation checks happen.

This is not a direct secret delivery flaw: error responses do not carry secret
payloads, and the current connection flow is sequential. It is still a protocol
integrity gap. A stale, unrelated, or confused error frame can be accepted as
the answer to the active operation, which makes diagnostics and state machines
less trustworthy precisely when something went wrong.

Impact:

- Stale error frames can be attributed to the wrong request.
- A future multi-request or reconnect flow could inherit weaker guarantees for
  negative responses than positive ones.
- Tests currently assert the happy-path correlation boundary but not the error
  path.

Recommended fix:

- For request types with non-empty request ID and nonce, validate correlation
  before returning structured daemon errors.
- Keep an explicit exception for intentionally uncorrelated requests such as
  `daemon.status` and the initial `approval.pending` request.
- Make this rule visible in code with one helper that validates both success and
  error envelopes for correlated request phases.

Suggested tests:

- Go client: `request.exec`, `command.started`, and `command.completed` reject
  mismatched error-envelope request IDs or nonces.
- Swift client: `submit(_:)` rejects mismatched error-envelope request IDs or
  nonces.
- Swift client: `fetchPendingRequest()` keeps its current behavior for
  uncorrelated pre-payload daemon errors.

### ASR-031: Installer Production Trust Roots Are Environment-Overridable

Priority: P3

Threat-model mapping:

- Shell environment variables are untrusted inputs.
- Release and install tooling must copy only artifacts from the expected project
  signer and expected bundle identifiers.
- Local unsigned install paths require explicit opt-in.

Relevant code:

- `install.sh:4-18` reads repository URL, GitHub API URL, unsigned mode,
  notarization requirement, expected Team ID, and expected bundle IDs from the
  ambient environment.
- `install.sh:87-108` skips DMG code-signature, Gatekeeper, and stapler checks
  when `AGENT_SECRET_ALLOW_UNSIGNED_INSTALL=1`.
- `install.sh:119-126` compares signatures against environment-controlled
  `AGENT_SECRET_EXPECTED_TEAM_ID`.
- `README.md:211-217` documents production verification and local unsigned
  overrides.
- `scripts/test-install.sh:241-288` tests wrong Team ID and unsigned override,
  but not that production trust roots are pinned against ambient environment.

Problem:

The installer now has strong checks, but the values that define those checks are
still mutable through ordinary environment variables. A normal-looking
production install can be redirected to a different GitHub host or repo, made to
expect a different Team ID or bundle ID, or told to skip identity verification
entirely, all without changing the command line.

Some configurability is useful for local testing and forks. The problem is that
ambient environment is part of the attacker-controlled input set in the threat
model. The production installer should not let stray shell state redefine the
project's release trust root. Development install modes should be explicit and
visibly unsafe.

Impact:

- A polluted shell or CI environment can make the installer trust artifacts from
  a different signer or source.
- The README claim that maintainer releases use Team ID `B6L7QLWTZW` is weaker
  than it sounds because the installer accepts a different expected team from
  the environment.
- Tests validate the presence of checks, but not the immutability of production
  trust roots.

Recommended fix:

- Keep destination path overrides such as `AGENT_SECRET_APP_DIR`,
  `AGENT_SECRET_BIN_DIR`, and `AGENT_SECRET_SKILLS_DIR`.
- Pin production trust roots in the default installer path: repo, GitHub host,
  GitHub API host, expected Team ID, and expected bundle IDs.
- Move fork/local behavior behind an explicit flag or a single
  `AGENT_SECRET_INSTALL_DEV_MODE=1` style switch that prints a loud message and
  requires local artifacts instead of network downloads.
- Do not let `AGENT_SECRET_ALLOW_UNSIGNED_INSTALL=1` skip production network
  artifact verification unless development mode is also explicit.

Suggested tests:

- Default installer ignores or rejects `AGENT_SECRET_EXPECTED_TEAM_ID=BADTEAM`.
- Default installer ignores or rejects expected bundle ID overrides.
- Default installer refuses unsigned mode for network downloads.
- Local development mode can still install a local unsigned DMG when explicitly
  requested.

## Previous Findings Verification

### ASR-021: Installer Does Not Pin Release Signer or Bundle Identity

Status: addressed.

Evidence:

- `install.sh:87-178` verifies DMG signature, Team ID, Gatekeeper, stapler,
  mounted app bundle ID, daemon helper bundle ID, and bundled CLI signature.
- `scripts/test-install.sh:241-273` rejects failed signature checks, wrong Team
  IDs, wrong app bundle IDs, and wrong daemon bundle IDs.

Remaining caveat:

ASR-031 above narrows this: the checks exist, but their production trust roots
are still environment-overridable.

### ASR-022: Approved Executable Path Can Be Swapped Before Spawn

Status: addressed for the reviewed threat model.

Evidence:

- `internal/request/request.go:188-195` captures executable identity and rejects
  mutable executables unless explicitly allowed.
- `internal/request/request.go:131-133` requires executable identity during
  daemon-side request validation.
- `internal/execwrap/execwrap.go:63-70` verifies the captured identity and
  mutable-executable policy immediately before spawning.
- `internal/execwrap/execwrap_test.go` includes replacement and mutable
  executable coverage.

Residual design tradeoff:

The launch is still path-based rather than descriptor-based, but the default
policy rejects mutable locations and verifies identity before `exec`. That is a
reasonable v1 fix unless the project chooses to pursue `fexecve`-style launch
semantics later.

### ASR-023: Readiness Can Be Reported Against an Untrusted Socket

Status: addressed.

Evidence:

- `internal/daemon/manager.go:126-128` connects through
  `ConnectWithPeerValidator`.
- `internal/daemon/client.go:34-43` validates the daemon peer before returning a
  client.
- `internal/daemon/manager.go:135-155` waits for authenticated status, not just
  any socket response.

### ASR-024: Swift Approver Trusts Any Socket It Is Pointed At

Status: addressed.

Evidence:

- `approver/Sources/AgentSecretApprover/UnixSocketLineTransport.swift`
  validates the daemon peer before frame exchange.
- `approver/Sources/AgentSecretApprover/TrustedDaemonPeerValidator.swift:194-213`
  checks trusted executable path, file identity, and configured Team ID.
- `approver/Tests/AgentSecretApproverTests/DaemonPeerValidationTests.swift`
  covers trusted and untrusted peer validation behavior.

### ASR-025: Audit Log Opening Follows Symlinks and Can Append Elsewhere

Status: addressed.

Evidence:

- `internal/audit/audit.go:195-227` uses `os.Lstat` and rejects symlinked audit
  directories.
- `internal/audit/audit.go:229-249` rejects symlinked and non-regular audit log
  paths.
- `internal/audit/audit.go:252-255` opens with `O_NOFOLLOW`.
- `internal/audit/audit_test.go` includes symlinked directory and symlinked log
  coverage.

### ASR-026: Uninstall Can Recursively Delete Environment-Selected Paths

Status: addressed.

Evidence:

- `uninstall.sh:89-125` requires explicit opt-in for custom path overrides,
  rejects broad and malformed paths, and refuses symlinked directories.
- `scripts/test-uninstall.sh` includes broad path, relative path, dot segment,
  symlink, and unrelated symlink coverage.

### ASR-027: Release Documentation Overstates What Runs

Status: addressed.

Evidence:

- `.github/workflows/ci.yml:93-119` now verifies release signing environment,
  imports the Developer ID certificate, and builds releases with
  `--require-production-signing`.
- `scripts/check-release-signing-env.sh:15-30` fails tag releases without the
  required signing and notarization settings.
- `README.md:211-217` and `docs/macos-distribution-plan.md:113-118` now describe
  installer identity checks and local unsigned exceptions.
- `scripts/test-release-docs.sh` is included in smoke testing.

## Non-Findings Checked

These areas were rechecked and did not produce new findings in this pass:

- The daemon no longer applies the short protocol read timeout while waiting for
  a valid approval decision or for a long-running command to complete
  (`internal/daemon/server.go:208-245` and `internal/daemon/server.go:358-367`).
- Pressing Return no longer approves access. Deny is the default action, and
  approve buttons have no default keyboard shortcut.
- Production Swift code no longer uses `MainActor.assumeIsolated`; the remaining
  reference is a test string used to assert the entrypoint stays clean.
- Resolver initialization no longer serializes all accounts behind one global
  setup lock.
- Partial secret fetch failure now cancels outstanding fetches and records
  value-free failure metadata.
- Release tag builds no longer publish ad-hoc unsigned artifacts as successful
  production releases.

## Suggested Fix Order

1. ASR-028, because socket directory symlink handling is closest to a local
   filesystem trust boundary.
2. ASR-029, because the Go client can reuse existing protocol-frame code.
3. ASR-030, because it is a small protocol-client correction in both Go and
   Swift.
4. ASR-031, because it requires a product decision on how explicit the
   development installer mode should be.
