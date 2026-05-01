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
- [Configuration Reference](docs/configuration.md)
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

The integration test skips unless `AGENT_SECRET_LIVE_REF` points at a test-only
1Password reference. Set `OP_ACCOUNT` or `AGENT_SECRET_1PASSWORD_ACCOUNT` only
when you want to force a specific 1Password account instead of
`my.1password.com`. Project config accounts override those defaults for the
secrets that declare them.

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
mise format
scripts/lint.sh
scripts/lint-go.sh
mise exec -- golangci-lint run --timeout 5m
mise run lint:swift
mise run lint:shell
mise run lint:toml
mise run lint:secrets
mise run lint:vuln
scripts/lint-smart.sh --staged
mise run test:race
mise run test:coverage
```

## Development Install

To use the current development build from any project on the same machine:

```bash
mise dev:install
```

By default this installs:

- `agent-secret`, `agent-secretd`, and an `agent-secret-approver` shim into
  `~/.local/bin`.
- `AgentSecretDaemon.app` and `AgentSecretApprover.app` into
  `~/Applications`.

Override the install locations with `--bin-dir`, `--app-dir`,
`AGENT_SECRET_INSTALL_BIN_DIR`, or `AGENT_SECRET_INSTALL_APP_DIR`. To pass
one-off flags, run `./scripts/dev-install.sh` directly.

By default, `agent-secret` uses the personal 1Password sign-in address
`my.1password.com`. Set `OP_ACCOUNT` or `AGENT_SECRET_1PASSWORD_ACCOUNT` in the
shell that will run `agent-secret exec` only when you want to force a specific
account; the daemon inherits that value when it auto-starts. Project config can
also set `account` globally, per profile, or per secret, and those config values
take precedence for the affected secret refs.
On macOS, `agent-secret` starts the daemon through `AgentSecretDaemon.app` so
1Password sees the SDK caller as Agent Secret instead of the terminal or agent
desktop app that launched the CLI.

## Command Usage

The main command is `exec`, which asks the daemon for approved secrets and then
runs the child process:

```bash
agent-secret exec [flags] -- COMMAND [ARG...]
```

Common forms:

```bash
agent-secret exec --reason "Terraform plan" \
  --secret CLOUDFLARE_API_TOKEN=op://Example/Cloudflare/token \
  -- terraform plan

agent-secret exec -- terraform plan

agent-secret exec --profile terraform-cloudflare -- terraform plan
```

Current `exec` flags:

- `--reason TEXT`: reason shown to the approver. Required unless the selected
  profile provides `reason`.
- `--secret ALIAS=op://vault/item[/section]/field`: explicit secret mapping.
  Repeat for multiple secrets.
- `--profile NAME`: load a named project profile.
- `--only ALIAS[,ALIAS...]`: filter loaded profile secrets to selected aliases.
  Repeat to add more aliases.
- `--config PATH`: use a specific config file instead of upward discovery.
- `--cwd DIR`: run the child process from `DIR`.
- `--ttl DURATION`: approval TTL. Defaults to profile `ttl` or `2m`; allowed
  range is `10s` through `10m`.
- `--override-env`: allow approved aliases to replace existing child
  environment variables.
- `--force-refresh`: for reusable approvals, refetch approved refs before
  delivery.

The command to run must appear after `--` as argv. `agent-secret exec` has no
`--json` mode and does not parse shell strings.

Daemon management and diagnostics:

```bash
agent-secret daemon status
agent-secret daemon start
agent-secret daemon stop
agent-secret doctor
```

## Project Profiles

Projects can keep reusable secret bundles in `agent-secret.yml` or
`.agent-secret.yml`. The file contains only 1Password refs and metadata, never
resolved values. `agent-secret exec --profile NAME` discovers the config from
the current directory or a parent. If `default_profile` is set, `agent-secret
exec -- COMMAND` uses that profile when no `--profile` or `--secret` flags are
provided.

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

  ansible:
    include:
      - terraform-cloudflare
    reason: Run Ansible playbook
    secrets:
      ANSIBLE_BECOME_PASSWORD: op://Example/Ansible/password
      CADDY_TOKEN: op://Example/Caddy/token
```

Profiles may include other profiles with `include`. Included profiles are
resolved in order; later includes and the selected profile override earlier
secrets with the same alias. The selected profile's `reason` and `ttl` become
request defaults. Its `account` applies to its own secrets and CLI `--secret`
additions. Included secrets keep the account selected by the profile that
defined them unless the selected profile overrides that secret alias.

`account` is optional. The precedence is per-secret `account`, then profile
`account`, then top-level `account`, then `OP_ACCOUNT` /
`AGENT_SECRET_1PASSWORD_ACCOUNT`, then `my.1password.com`.

Run a profile with:

```bash
agent-secret exec -- terraform plan
agent-secret exec --profile terraform-cloudflare -- terraform plan
agent-secret exec --profile ansible --only CADDY_TOKEN,POSTGRES_PASSWORD -- \
  ansible-playbook site.yml
```

`--secret` flags can be combined with a profile for one-off additional refs; in
that mode, explicit secrets inherit the loaded profile account. Explicit
`--secret`-only invocations do not load `default_profile`. CLI `--reason` and
`--ttl` override profile defaults. `--only` filters profile-loaded aliases
before one-off `--secret` refs are added.

See [Configuration Reference](docs/configuration.md) for the full config schema,
discovery rules, account precedence, and command reference.

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
