# Agent Secret

Agent Secret is a local macOS approval broker for coding-agent secrets. It lets
an agent request exact secret references, shows you a native approval
prompt with the command and reason, then injects approved values only into that
child process.

Website: <https://agent-secret.sh>

## Install

Requirements:

- macOS on Apple Silicon.
- At least one supported secret provider:
  - 1Password desktop app signed in, unlocked, and with Developer Tools
    integration enabled.
  - Bitwarden Secrets Manager with the official Bitwarden-signed `bws` CLI
    installed at `/opt/homebrew/bin/bws` or `/usr/local/bin/bws`, plus a local
    access token alias stored with Agent Secret.

Install the latest signed and notarized release with Homebrew:

```bash
brew tap kovyrin/agent-secret https://github.com/kovyrin/agent-secret
brew install --cask agent-secret
agent-secret skill-install
agent-secret doctor
```

Upgrade later with:

```bash
brew update
brew upgrade --cask agent-secret
```

The Homebrew cask installs `Agent Secret.app` into `/Applications` and links the
bundled `agent-secret` command into Homebrew's `bin` directory. `skill-install`
adds or repairs the bundled Codex skill symlink for the current user.

You can also install without Homebrew:

<!-- markdownlint-disable MD013 -->

```bash
curl -fsSL https://github.com/kovyrin/agent-secret/releases/latest/download/install.sh | sh
```

<!-- markdownlint-enable MD013 -->

Then verify the install:

```bash
agent-secret doctor
```

The unattended installer copies `Agent Secret.app` into `/Applications`, installs
`~/.local/bin/agent-secret`, installs the bundled Codex skill at
`~/.agents/skills/agent-secret`, and runs diagnostics. If `~/.local/bin` is not
on your shell `PATH`, the installer prints a copy-pasteable command to add it.

You can also install manually from the DMG on the
[latest GitHub Release](https://github.com/kovyrin/agent-secret/releases/latest):
open the DMG, drag `Agent Secret.app` into `/Applications`, open the app, and
click `Install Command Line Tool`.

## Enable 1Password SDK Integration

Agent Secret uses the 1Password desktop app SDK integration. In 1Password, open
`Settings -> Developer`, then under `Integrate with the 1Password SDKs` enable
`Integrate with other apps`. If the Developer section is hidden, enable
`Show 1Password Developer experience` first.

![1Password Developer settings with SDK integration enabled](docs/images/1password-sdk-integration.png)

## Enable Bitwarden Secrets Manager

Install the official `bws` CLI, then store a local token alias in the macOS
Keychain:

```bash
agent-secret bitwarden secrets-manager token install --alias work
```

The install command prompts for the token with hidden terminal input. For
scripts, pipe the token with `--from-stdin`.

Bitwarden refs use `bws://<secret-uuid>` or
`bws://<source-alias>/<secret-uuid>`. Project configs can define
`sources.bitwarden` entries to map source aliases to token aliases. Agent
Secret v1 supports official Bitwarden cloud endpoints only and invokes `bws`
with a temporary state-disabled config pinned to `https://vault.bitwarden.com`.
It does not resolve `bws` from the daemon `PATH`; helper binaries must be at a
fixed common path and either live under a stable system-owned path or be signed
by Bitwarden Inc.

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

Validate what an agent is about to request without prompting or running the
child:

```bash
agent-secret exec --dry-run --json --profile terraform-cloudflare -- terraform plan
```

Use an existing reusable approval without opening a new prompt:

```bash
agent-secret exec --reuse-only --profile terraform-cloudflare -- terraform plan
```

Approve a bounded multi-command session and run commands through the wrapper:

```bash
agent-secret session create --profile terraform-cloudflare --bind-parent \
  --max-reads 2 --json=compact
agent-secret with-session astok_123 --only CLOUDFLARE_API_TOKEN -- terraform plan
agent-secret with-session astok_123 \
  --only CLOUDFLARE_API_TOKEN,STATE_TOKEN \
  -- terraform apply
agent-secret session list
agent-secret session destroy asid_123
```

Keep the `session_token` returned by `session create` for `with-session`.
Use the `session_id` returned by `session create` or shown by `session list`
for inspection and cleanup. `session list` never shows session tokens.
Session tokens are accepted only from the approved requester process tree. Use
`--bind-parent` when a shell wrapper creates the session inside command
substitution and later calls `with-session` from the parent shell.
Advanced wrappers can use `--bind-ancestor N` up to `3`, but only ancestors of
the current `agent-secret` process are accepted. If wrapper depth varies across
different agents, repeat `--bind-ancestor-name NAME`; Agent Secret matches the
nearest eligible ancestor executable basename in the allowed set and does not
search arbitrary PIDs.

Inspect item metadata without revealing values:

```bash
agent-secret item describe "op://Example Infra/Database Credentials"
agent-secret item describe --format env-refs --prefix DATABASE \
  "op://Example Infra/Database Credentials"
```

Inspect the agent-facing CLI surface or project profiles:

```bash
agent-secret agent-context --json
agent-secret profile list --json
agent-secret profile show --json terraform-cloudflare
```

## GCP Quick Start

Agent Secret can also broker short-lived Google Cloud access for approved
`gcloud` commands without writing user credentials into `~/.config/gcloud` or
Application Default Credentials.

GCP support requires Google-side IAM setup first: a narrow service account and
a Token Creator binding that lets the human Google account mint short-lived
tokens for that service account. Agent Secret release builds use a bundled
Google OAuth Desktop client for local login, so normal operators do not need to
create, export, or share OAuth client JSON. Start with
[GCP Integration](docs/gcp.md) before using these commands.

Log in a local Google bootstrap alias:

```bash
agent-secret gcp auth login \
  --google-account work \
  --expected-email you@example.com
```

Then add a GCP profile to `agent-secret.yml`:

```yaml
version: 1

profiles:
  beta-logs:
    reason: Inspect beta Cloud Run errors
    ttl: 10m
    gcp:
      google_account: work
      project: fixture-beta
      service_account: agent-beta-logs@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
```

Run one command:

```bash
agent-secret gcp exec --profile beta-logs -- \
  gcloud logging read 'severity>=ERROR' --project fixture-beta --limit=5
```

Or approve a multi-command session:

```bash
handle="$(agent-secret gcp session create --profile beta-logs --json |
  jq -r .session_handle)"

agent-secret gcp with-session "$handle" -- \
  gcloud services list --enabled --project fixture-beta --limit=10

agent-secret gcp session destroy "$handle"
```

## What You Approve

![Agent Secret approval prompt](docs/images/approval-request.png)

The approval UI emphasizes the reason for the request, the command, the working
directory, the approval scope, the requested aliases, and the exact secret
references. Secret values are not shown in the UI and are not returned to the
agent.

Metadata inspection has its own approval prompt:

![Agent Secret item metadata request prompt](docs/images/item-metadata-request.png)

## Project Profiles

Projects can store reusable secret mappings in `agent-secret.yml` or
`.agent-secret.yml`. The file contains secret references and request metadata
only, never resolved values.

```yaml
version: 1
default_profile: terraform-cloudflare

profiles:
  terraform-cloudflare:
    reason: Terraform DNS management
    ttl: 10m
    session:
      bind: parent
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
      STATE_TOKEN: op://Example/Terraform State/token
```

With `default_profile`, this works from the project directory:

```bash
agent-secret exec -- terraform plan
```

See [Configuration Reference](docs/configuration.md) for includes, account
precedence, env-file migration, and the full schema.

## Commands

- `agent-secret exec -- COMMAND [ARG...]`: run a command with approved secrets.
- `agent-secret session create|list|destroy`: manage bounded background-helper
  sessions.
- `agent-secret with-session SESSION_TOKEN -- COMMAND [ARG...]`: run one command
  with secrets from an approved session and requester process tree. Add
  `--only ALIAS[,ALIAS...]` to inject a per-command subset of the approved
  session bag.
- `agent-secret gcp exec|session|with-session|auth`: run commands with approved
  short-lived GCP access tokens.
- `agent-secret item describe REF`: inspect 1Password item fields without
  values.
- `agent-secret agent-context --json`: print a machine-readable command and
  config discovery schema for coding agents.
- `agent-secret profile list|show`: inspect project profiles without resolving
  values.
- `agent-secret doctor`: print non-secret setup diagnostics.
- `agent-secret repair`: inspect and repair Agent Secret background helper
  state.
- `agent-secret daemon status|start|stop`: run low-level daemon diagnostics.
- `agent-secret install-cli`: repair the command symlink for the current user
  and try to refresh the local background helper.
- `agent-secret skill-install`: repair the bundled coding-agent skill symlink.

Run `agent-secret --help` or `agent-secret exec --help` for the full command
reference.

## Security Model

Agent Secret is a local approval broker, not a sandbox. The approved child
process receives the secret in its environment and can use or leak it like any
other process with that value.

What Agent Secret does protect:

- Project configs and command flags carry `op://` or `bws://` references and
  GCP identity metadata, not resolved secret values or access tokens.
- The background helper fetches only secrets approved for the current request.
- GCP commands receive short-lived service-account tokens through broker-owned
  token files and isolated Cloud SDK configuration.
- Audit logs contain metadata only, not raw secret values.
- Reusable approvals are bounded by command, cwd, secret references, account or
  token alias, TTL, and use count.
- Reusable cached values are kept in Agent Secret's background helper memory and
  cleared when their scope is replaced, refreshed, expired, or when the helper
  stops.

Out of scope:

- Root, the kernel, a compromised macOS user session, a compromised provider
  app or helper, or a malicious approved child process.
- Hiding env vars from the operating-system APIs needed to launch the approved
  child process.
- Creating or managing GCP IAM, policing `gcloud` arguments, hiding approved
  GCP access from the approved child process, cross-platform secret management,
  background updates, credential helpers, file-descriptor delivery, arbitrary
  long-lived shells, or raw socket value reads.

Read [Threat Model](docs/threat-model.md) for the detailed model and review
ledger. Use the [Security Policy](SECURITY.md) for private vulnerability
reporting.

## Known Limitations

The launch build is intentionally narrow:

- macOS on Apple Silicon only.
- 1Password Desktop and Bitwarden Secrets Manager only; no other providers yet.
- Sessions are bounded by requester process tree or explicit ancestor binding,
  cwd, TTL, read count, aliases, background-helper memory, and
  `agent-secret with-session`. Named ancestor binding still matches only the
  current process ancestry; no arbitrary PID binding or long-lived interactive
  shells.
- No writing, updating, or rotating secrets yet.
- No GCP Secret Manager or GCP token minting support yet.
- No sandbox guarantee after you approve a child process.

## Uninstall

Uninstall the latest release:

<!-- markdownlint-disable MD013 -->

```bash
curl -fsSL https://github.com/kovyrin/agent-secret/releases/latest/download/uninstall.sh | sh
```

<!-- markdownlint-enable MD013 -->

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
- [Session E2E Validation](docs/session-e2e-validation.md)
- [GCP Integration](docs/gcp.md)
- [Threat Model](docs/threat-model.md)
- [Release Process](docs/release-process.md)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
