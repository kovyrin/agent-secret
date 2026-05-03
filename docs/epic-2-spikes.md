# Epic 2 Spike Notes

Status: complete.

Date: 2026-04-28

## Summary

Epic 2 now has runnable spike code for the four risky surfaces:

- 1Password Go SDK client construction and opt-in live resolution
- native macOS approval request/decision flow
- strict macOS Unix socket peer metadata capture
- CLI-owned `exec` process supervision

The local non-secret tests pass. The live 1Password read remains opt-in because
it requires a test-only secret reference and account name, but it has been
verified once against a test account with metadata-only test output. The
first manual foreground smoke showed Finder could still cover the alert, so the
AppKit activation path was tightened and re-tested successfully.

## 1Password Go SDK

Files:

- `internal/opresolver/resolver.go`
- `internal/opresolver/resolver_test.go`
- `internal/opresolver/integration_test.go`

Observed API shape:

- module: `github.com/1password/onepassword-sdk-go`
- pinned version: `v0.4.0`
- client constructor: `onepassword.NewClient`
- desktop auth option: `onepassword.WithDesktopAppIntegration(accountName)`
- integration identity option: `onepassword.WithIntegrationInfo(name, version)`
- secret resolver: `client.Secrets().Resolve(ctx, ref)`
- bulk resolver exists as `client.Secrets().ResolveAll(ctx, refs)`

The official developer docs mention a Go secret-reference validation helper, but
`go doc` against `v0.4.0` and `v0.4.1-beta.1` did not expose a
`ValidateSecretReference` symbol. The spike therefore keeps a small broker-side
syntax check for `op://vault/item[/section]/field` and leaves any future SDK
validation helper as an optional replacement if it becomes public.

Live test command:

```bash
AGENT_SECRET_LIVE_REF="op://Example Vault/Example Item/token" \
go test -tags integration ./...
```

Set `OP_ACCOUNT` or `AGENT_SECRET_1PASSWORD_ACCOUNT` only when you want to force
a specific 1Password account instead of `my.1password.com`.

The live test logs only value length and SHA-256 metadata. It does not print the
secret value. On 2026-04-28, this passed against a test account after
1Password desktop app SDK integration was enabled.

## Swift Approver

Files:

- `approver/Package.swift`
- `approver/Sources/AgentSecretApprover`
- `approver/Sources/AgentSecretApproverApp`
- `approver/Sources/AgentSecretApproverSmoke`
- `approver/Tests/AgentSecretApproverTests`

The Swift package defines stable request, decision, presenter, daemon-client,
and logger boundaries. The app target can run a mock request/decision flow
without receiving secret values. The AppKit presenter uses public APIs:

- `NSApplication.shared`
- `setActivationPolicy(.regular)`
- `NSRunningApplication.current.activate`
- `NSWindow.orderFrontRegardless()`
- `requestUserAttention(.criticalRequest)`
- `NSAlert.runModal()`

The approver logs only event names and request IDs through Apple's Unified
Logging using subsystem `com.kovyrin.agent-secret.approver`.

Local verification uses the active Xcode developer directory:

```bash
cd approver && swift test
swift run agent-secret-approver-smoke
```

The smoke executable returns `approver-smoke-ok` and verifies that structured
decisions contain request ID, nonce, decision, and reuse count only. It does not
encode secret refs or aliases in the response.

Manual foreground smoke command:

```bash
cd approver && swift run agent-secret-approver
```

Run it while another app is focused to confirm the approval window gets
attention. Passing `--mock-decision approve|reuse|deny|timeout` intentionally
uses the noninteractive path.

Observed foreground behavior:

- On 2026-04-28, a smoke launched after activating Finder showed the approval
  alert behind a Finder window. The presenter now raises the alert window to
  modal-panel level and orders it front regardless. A follow-up smoke showed the
  approval alert in front of Finder.

## macOS Peer Credentials

Files:

- `internal/peercred/peercred.go`
- `internal/peercred/peercred_darwin.go`
- `internal/peercred/peercred_test.go`
- `internal/peercred/peercred_unsupported.go`

The Darwin spike captures peer metadata from accepted Unix socket connections
using public APIs:

- `getpeereid`
- `LOCAL_PEERPID`
- `LOCAL_PEERCRED`
- `proc_pidpath`
- `PROC_PIDVNODEPATHINFO`

The test validates same UID, GID, PID, executable path, and cwd for a local
Unix socket client in the same process. Missing metadata and policy mismatches
fail closed. Non-Darwin builds return an explicit unsupported error.

## Exec Wrapper

Files:

- `internal/execwrap/execwrap.go`
- `internal/execwrap/process_darwin.go`
- `internal/execwrap/process_other.go`
- `internal/execwrap/execwrap_test.go`

The process supervisor spike proves:

- approved aliases are overlaid only in the child environment
- existing parent environment aliases fail closed unless override is enabled
- child stdout/stderr are passed through caller-provided writers
- non-zero child exit codes are preserved as child results, not broker errors
- interrupts are forwarded to the child process group on macOS
- metadata-only audit events contain aliases and command metadata, not values

The tests use synthetic canary values and assert those values do not appear in
audit JSON.

## Verification Run

Commands run locally:

```bash
go test ./...
go test -tags integration ./...
go test -run PeerCred -v ./...
cd approver && swift test
cd approver && swift run agent-secret-approver-smoke
```

The live 1Password test requires 1Password desktop app SDK integration to be
enabled before the SDK client can connect.
