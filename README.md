# Agent Secret Broker

Agent Secret Broker is a local, macOS-first secret access broker for coding
agents. It lets an agent request exact 1Password-backed secrets with a stated
reason, a bounded command or session, and a short policy window. A trusted local
broker shows the user a native approval prompt, fetches only the approved
secrets through the official 1Password SDK, and avoids returning raw values to
the agent by default.

This repository is designed as a standalone open-source project.

## Status

Planning scaffold, research spikes, Epic 3 core Go packages, the Epic 4
CLI/daemon/exec path, and the Epic 5 native approver socket integration are in
place. Session/socket secret reads are next.

## Current Documents

- [Product Requirements](docs/prd.md)
- [Implementation Plan](docs/implementation-plan.md)
- [Code Layout](docs/code-layout.md)
- [Epic 2 Spike Notes](docs/epic-2-spikes.md)

## Project Boundary

- Code and docs for this project live in this repository.
- Do not import code, scripts, configuration, credentials, or runtime helpers
  from unrelated external projects.
- Keep examples generic or explicitly marked as examples. Do not include real
  secret values, private vault contents, or personal 1Password item names.
- Prefer standard Go, Swift, and macOS APIs over external project tooling.

## Intended Shape

```text
agent-secret/
  cmd/agent-secret/              # Go CLI
  cmd/agent-secretd/             # Go daemon
  internal/                      # Go broker, policy, socket, audit packages
  approver/                      # Swift macOS approval helper
  docs/                          # Product, architecture, and implementation docs
```

The code layout is documented in
[Code Layout](docs/code-layout.md). Research spikes may refine package
internals, but the repository boundary and module path should remain stable.

## Current Verification

The current project-local checks are:

```bash
mise run setup
mise run lint
mise run build
```

The underlying commands are:

```bash
scripts/lint.sh
go test ./...
go test -tags integration ./...
go build ./cmd/agent-secret ./cmd/agent-secretd
cd approver && swift test
cd approver && ./scripts/build-app.sh
swift run agent-secret-approver-smoke
```

The integration test skips unless `AGENT_SECRET_LIVE_REF` and
`AGENT_SECRET_1PASSWORD_ACCOUNT` point at a test-only 1Password reference.

## Development Toolchain

The project uses `mise` as the toolchain entrypoint. Install `mise`, then run:

```bash
mise run setup
```

This installs the pinned Go, Node/npm/npx, and shellcheck versions from
`mise.toml`, installs npm dependencies from `package-lock.json`, and configures
the repository's tracked pre-commit hook.
Swift, `codesign`, `iconutil`, and `sips` still come from the macOS/Xcode
command line tools.

Project scripts run through `mise` by default, so these work from a normal
shell after setup:

```bash
scripts/lint.sh
scripts/lint-go.sh
mise run lint:swift
scripts/lint-smart.sh --staged
```

## Development Install

To use the current development build from any project on the same machine:

```bash
./scripts/dev-install.sh
```

By default this installs:

- `agent-secret`, `agent-secretd`, and an `agent-secret-approver` shim into
  `~/.local/bin`.
- `AgentSecretDaemon.app` and `AgentSecretApprover.app` into
  `~/Applications`.

Override the install locations with `--bin-dir`, `--app-dir`,
`AGENT_SECRET_INSTALL_BIN_DIR`, or `AGENT_SECRET_INSTALL_APP_DIR`.

Set `AGENT_SECRET_1PASSWORD_ACCOUNT` in the shell that will run
`agent-secret exec`; the daemon inherits that value when it auto-starts.
On macOS, `agent-secret` starts the daemon through `AgentSecretDaemon.app` so
1Password sees the SDK caller as Agent Secret instead of the terminal or agent
desktop app that launched the CLI.

## Default Safety Posture

- 1Password remains the source of truth for storage and account authentication.
- The broker enforces request-level policy: exact refs, reason, command, cwd,
  TTL, max reads, and delivery mode.
- Default delivery is CLI-supervised `exec` mode.
- Raw secret output is not provided.
- Audit logs contain metadata only and never secret values.
- The macOS approver should also emit non-secret diagnostics to Apple Unified
  Logging for local troubleshooting.
- `agent-secret --help` should be detailed enough for coding agents to discover
  safe usage without reading these docs.
- Future Go code must be covered by project lint and pre-commit paths.
- Integration tests must use real captured API and OS error shapes, but captured
  fixtures must not contain secret values.
