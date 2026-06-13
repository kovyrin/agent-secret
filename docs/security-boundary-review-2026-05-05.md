# Public Release Security Boundary Review

Review date: 2026-05-05.

Review target: public-release preparation after `v0.0.7` release-candidate
changes on `main`.

Review contract: `docs/threat-model.md`.

Conclusion: no unresolved release-blocking findings were identified in this
review. The remaining public-release blocker is clean-machine install, upgrade,
and uninstall evidence for the `v0.0.7` candidate.

## Scope

This review covered the shipped macOS Apple Silicon surface:

- `agent-secret exec` with environment injection.
- Per-user daemon socket.
- Native macOS approval app.
- 1Password Desktop SDK resolution after approval.
- Reusable same-command approvals.
- Metadata-only audit log.
- Release DMG, install, and uninstall trust checks.

This review did not cover unshipped bounded sessions, `with-session`, credential
helpers, Linux, Windows, automatic updates, or alternative secret backends.

## Boundary Walk

### CLI To Daemon Socket

Status: pass.

Evidence reviewed:

- `internal/daemon/socket` enforces private socket directory expectations.
- `internal/daemon/peertrust` and `internal/daemon/control` authenticate daemon
  and CLI peers before secret-bearing responses or control operations.
- Protocol envelopes carry version, request ID, nonce, and typed payloads.
- Server tests cover peer validation, daemon retirement, disconnect behavior,
  and malformed protocol paths.

Residual risk:

- A fully compromised user session remains out of scope. Same-UID processes are
  handled only at the documented socket and executable identity boundaries.

### Daemon To Native Approver

Status: pass.

Evidence reviewed:

- The daemon launches the bundled app path and validates approver executable
  identity.
- The approver validates the daemon peer before rendering approval metadata.
- Approval decisions include request ID and nonce.
- Approval expiration is enforced by controller and daemon behavior, not only by
  SwiftUI button state.
- Daemon-supplied error text is sanitized before display.

Residual risk:

- The approval window uses public macOS foregrounding APIs. It is not a true
  system-modal prompt, which is documented as out of scope.

### Trusted Executable Identity

Status: pass.

Evidence reviewed:

- Production wiring constructs explicit peer validators in `cmd/agent-secretd`.
- File identity and signature checks live in focused trust packages with unit
  tests.
- The CLI verifies approved executable identity immediately before child spawn.
- The daemon records its executable identity at startup and retires after the
  installed daemon executable is replaced; `agent-secret exec` retries once when
  retirement happens before child spawn.

Residual risk:

- The first upgrade from a pre-auto-retire daemon still needs one manual daemon
  stop or process exit because old code cannot self-retire. Future upgrades use
  the new daemon self-check path.

### Symlink And Path Handling

Status: pass.

Evidence reviewed:

- Request validation uses strict path resolution on trust paths.
- Install and uninstall scripts refuse broad, relative, and symlinked custom
  roots unless explicit custom-path opt-in is provided.
- Uninstall verifies expected bundle identifiers and Developer ID Team ID before
  removing app bundles unless explicit force flags are set.
- Audit paths require private directories and regular files.

Residual risk:

- Local development mode intentionally allows unsigned local artifacts behind
  explicit development flags. That path is not a production install promise.

### Release Artifact Verification

Status: pass.

Evidence reviewed:

- Tag-triggered releases require production signing and notarization inputs.
- The installer verifies checksum, DMG signature, expected Team ID, Gatekeeper
  assessment, notarization ticket, mounted app bundle ID, daemon bundle ID, and
  bundled CLI signature before copying.
- Release docs require local verification of DMG signature, Team ID, stapling,
  Gatekeeper, `hdiutil verify`, mounted app identity, and draft release notes.
- Production release trust roots are pinned to the expected repository, Team ID,
  bundle IDs, notarization mode, and GitHub release host.

Residual risk:

- Public release readiness still needs one clean-machine human DMG and uninstall
  drill for the exact `v0.0.7` candidate.

### Audit Redaction And Fail-Closed Delivery

Status: pass.

Evidence reviewed:

- Audit event types carry secret references, aliases, accounts, commands,
  decisions, timing, and child status, not raw secret values.
- Audit tests reject accidental value-bearing fields.
- Broker paths write required audit metadata before payload delivery; audit
  failure before payload delivery blocks child execution.
- Live verification prints only non-secret metadata such as length and hash.

Residual risk:

- `op://` references, aliases, and account names are metadata but can still be
  sensitive. This is documented in the threat model and README limitations.

### Approval Expiry, Cancellation, Timeout, And Disconnect

Status: pass.

Evidence reviewed:

- Approval expiration is enforced before display and at decision handling.
- Pending approvals can time out without 1Password access.
- Denial and timeout prevent secret fetch.
- CLI disconnect before payload delivery fails closed.
- Disconnect after child spawn is audited as best effort while the child exit
  behavior remains under CLI supervision.
- Reusable approval use accounting consumes a use only after payload delivery.

Residual risk:

- `exec` TTL bounds approval and spawn, not already-running child lifetime.
  That is documented product behavior.

## Release Readiness Notes

Before public announcement:

1. Cut and publish the `v0.0.7` candidate from current `main`.
2. Run clean-machine human DMG install, unattended install/upgrade, and uninstall
   checks against `v0.0.7`.
3. Keep the `SECURITY.md`, `CONTRIBUTING.md`, README support boundaries, and
   limitations aligned with the shipped surface.
