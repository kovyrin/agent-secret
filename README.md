# Agent Secret

Agent Secret is a local macOS approval broker for coding-agent secrets. It lets
an agent request exact 1Password refs, shows you a native approval prompt with
the command and reason, then injects approved values only into that child
process.

## Install

Requirements:

- macOS on Apple Silicon.
- 1Password desktop app with Developer Tools integration enabled.
- 1Password CLI signed in to the account that owns the refs you want to use.

Install the latest signed and notarized release:

```bash
version="$(
  curl -fsSL https://api.github.com/repos/kovyrin/agent-secret/releases/latest |
    awk -F'"' '/"tag_name":/ { print $4; exit }'
)"
test -n "$version"
base_url="https://raw.githubusercontent.com/kovyrin/agent-secret"
curl -fsSL "$base_url/${version}/install.sh" |
  AGENT_SECRET_VERSION="$version" sh
```

Then verify the install:

```bash
agent-secret doctor
```

The installer copies `Agent Secret.app` into `/Applications`, installs
`~/.local/bin/agent-secret`, installs the bundled Codex skill at
`~/.agents/skills/agent-secret`, and runs diagnostics. If `~/.local/bin` is not
on your shell `PATH`, the installer prints a copy-pasteable command to add it.

You can also install manually from the DMG on the
[latest GitHub Release](https://github.com/kovyrin/agent-secret/releases/latest):
open the DMG, drag `Agent Secret.app` into `/Applications`, open the app, and
click `Install Command Line Tool`.

## Quick Start

Run a command with an explicitly approved secret:

```bash
agent-secret exec --reason "Run Terraform plan" \
  --secret CLOUDFLARE_API_TOKEN=op://Example/Cloudflare/token \
  -- terraform plan
```

Use a project profile:

```bash
agent-secret exec --profile terraform-cloudflare -- terraform plan
```

Inspect item metadata without revealing values:

```bash
agent-secret item describe "op://Example Infra/Database Credentials"
agent-secret item describe --format env-refs --prefix DATABASE \
  "op://Example Infra/Database Credentials"
```

## What You Approve

![Agent Secret approval prompt](docs/images/approval-request.png)

The approval UI emphasizes the reason for the request, the command, the working
directory, the approval scope, the requested aliases, and the exact 1Password
refs. Secret values are not shown in the UI and are not returned to the agent.

Metadata inspection has its own approval prompt:

![Agent Secret item metadata request prompt](docs/images/item-metadata-request.png)

## Project Profiles

Projects can store reusable secret mappings in `agent-secret.yml` or
`.agent-secret.yml`. The file contains 1Password refs and request metadata only,
never resolved values.

```yaml
version: 1
account: my.1password.com
default_profile: terraform-cloudflare

profiles:
  terraform-cloudflare:
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
```

With `default_profile`, this works from the project directory:

```bash
agent-secret exec -- terraform plan
```

See [Configuration Reference](docs/configuration.md) for includes, account
precedence, env-file migration, and the full schema.

## Commands

- `agent-secret exec -- COMMAND [ARG...]`: run a command with approved secrets.
- `agent-secret item describe REF`: inspect 1Password item fields without
  values.
- `agent-secret doctor`: print non-secret setup diagnostics.
- `agent-secret daemon status|start|stop`: inspect or control the per-user
  daemon.
- `agent-secret install-cli`: repair the command symlink for the current user.
- `agent-secret skill-install`: repair the bundled coding-agent skill symlink.

Run `agent-secret --help` or `agent-secret exec --help` for the full command
reference.

## Security Model

Agent Secret is a local approval broker, not a sandbox. The approved child
process receives the secret in its environment and can use or leak it like any
other process with that value.

What Agent Secret does protect:

- Project configs and command flags carry `op://` refs, not resolved values.
- The daemon fetches only refs approved for the current request.
- Audit logs contain metadata only, not raw secret values.
- Reusable approvals are bounded by command, cwd, refs, account, TTL, and use
  count.
- Reusable cached values are kept in daemon memory and cleared when their scope
  is replaced, refreshed, expired, or when the daemon stops.

Out of scope:

- Root, the kernel, a compromised macOS user session, a compromised 1Password
  app, or a malicious approved child process.
- Hiding env vars from the operating-system APIs needed to launch the approved
  child process.
- Cross-platform secret management, background updates, session handles,
  credential helpers, file-descriptor delivery, or socket value reads.

Read [Threat Model](docs/threat-model.md) for the detailed model and review
ledger.

## Uninstall

Uninstall the latest release:

```bash
version="$(
  curl -fsSL https://api.github.com/repos/kovyrin/agent-secret/releases/latest |
    awk -F'"' '/"tag_name":/ { print $4; exit }'
)"
test -n "$version"
base_url="https://raw.githubusercontent.com/kovyrin/agent-secret"
curl -fsSL "$base_url/${version}/uninstall.sh" | sh
```

By default, uninstall removes the app, command symlink, skill symlink, and known
application support files. It leaves `~/Library/Logs/agent-secret` audit logs in
place unless `AGENT_SECRET_REMOVE_AUDIT_LOGS=1` is set.

## Development

Use `mise` as the project toolchain entrypoint:

```bash
mise run setup
mise run lint
mise run build
mise run test:smoke
```

Install the current development build on this machine:

```bash
mise dev:install
```

The dev installer places the app in `~/Applications/Agent Secret.app` by
default and refreshes the CLI and skill symlinks. It is for local development;
use the release installer above for normal installs.

## Maintainer Notes

- Release notes come from [Changelog](CHANGELOG.md).
- The maintainer release checklist lives in
  [Release Process](docs/release-process.md).
- Release artifacts are GitHub Releases backed by signed and notarized macOS
  DMGs.
- Tag-triggered GitHub releases require production signing and notarization.

Local release-candidate artifact build:

```bash
scripts/release/build-release.sh v0.0.0-dev
```

## Documentation

- [Configuration Reference](docs/configuration.md)
- [Threat Model](docs/threat-model.md)
- [Release Process](docs/release-process.md)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
