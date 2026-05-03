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
place. The macOS app bundle, development installer, local DMG builder,
unattended install/uninstall scripts, and optional release signing hooks are in
place on the distribution PR. Session/socket secret reads are next.

## Current Documents

- [Changelog](CHANGELOG.md)
- [Product Requirements](docs/prd.md)
- [Threat Model](docs/threat-model.md)
- [Implementation Plan](docs/implementation-plan.md)
- [Configuration Reference](docs/configuration.md)
- [macOS Distribution Plan](docs/macos-distribution-plan.md)
- [Release Process](docs/release-process.md)
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
  approver/                      # Swift macOS approval/setup app
  docs/                          # Product, architecture, and implementation docs
```

The code layout is documented in
[Code Layout](docs/code-layout.md). Research spikes may refine package
internals, but the repository boundary and module path should remain stable.

## Current Verification

The default local checks match pull request CI:

```bash
mise run setup
mise run lint
mise run build
mise run test:smoke
```

`mise run lint` runs the normal static and test gates:

```bash
scripts/lint.sh
go test ./...
go test -race ./...
scripts/check-go-coverage.sh
govulncheck ./...
gitleaks dir . --redact --no-banner
shellcheck scripts/*.sh approver/scripts/*.sh
actionlint .github/workflows/*.yml
swiftlint lint --strict --no-cache
npx --no-install markdownlint '**/*.md'
cd approver && swift test
```

`mise run build` runs the app bundle build:

```bash
scripts/build-app-bundle.sh
```

`mise run test:smoke` runs the non-secret install, uninstall, release
configuration, release version, release docs, and approver smoke checks:

```bash
AGENT_SECRET_IN_MISE=1 scripts/test-install.sh
AGENT_SECRET_IN_MISE=1 scripts/test-uninstall.sh
AGENT_SECRET_IN_MISE=1 scripts/test-release-signing-env.sh
AGENT_SECRET_IN_MISE=1 scripts/test-release-version.sh
AGENT_SECRET_IN_MISE=1 scripts/test-release-docs.sh
cd approver && swift run agent-secret-approver-smoke
```

The approver smoke executable can also be run directly:

```bash
swift run agent-secret-approver-smoke
```

Live 1Password integration tests are intentionally opt-in and are not part of
normal pull request CI. Run them only with a test-only reference and Desktop App
Integration enabled:

```bash
AGENT_SECRET_LIVE_REF="op://Test Vault/Test Item/token" \
  go test -tags integration ./...
```

Set `OP_ACCOUNT` or `AGENT_SECRET_1PASSWORD_ACCOUNT` only when you want to
force a specific 1Password account instead of `my.1password.com`. Project
config accounts override those defaults for the secrets that declare them.

Release artifact verification is separate from pull request CI. For a local
release-candidate check, run:

```bash
scripts/build-release.sh v0.0.0-dev
```

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

## Install From A Release

The intended macOS install shape is one app bundle:

```text
/Applications/Agent Secret.app
  Contents/MacOS/Agent Secret
  Contents/Library/Helpers/AgentSecretDaemon.app
  Contents/Resources/bin/agent-secret
  Contents/Resources/skills/agent-secret
```

The command-line entry point is a user-level symlink:

```text
~/.local/bin/agent-secret -> /Applications/Agent Secret.app/Contents/Resources/bin/agent-secret
```

The bundled coding-agent skill is installed as a user-level symlink:

```text
~/.agents/skills/agent-secret -> /Applications/Agent Secret.app/Contents/Resources/skills/agent-secret
```

Human install flow:

1. Download `Agent-Secret-vX.Y.Z-macos-arm64.dmg` from GitHub Releases.
2. Open the DMG and drag `Agent Secret.app` into `/Applications`.
3. Open `Agent Secret.app`.
4. Click `Install Command Line Tool`.
5. Run:

   ```bash
   agent-secret doctor
   ```

Unattended install and upgrade use the same script:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/kovyrin/agent-secret/main/install.sh | sh
```

Useful installer environment variables:

```bash
AGENT_SECRET_VERSION=v0.3.1
AGENT_SECRET_APP_DIR="$HOME/Applications"
AGENT_SECRET_BIN_DIR="$HOME/.local/bin"
AGENT_SECRET_SKILLS_DIR="$HOME/.agents/skills"
```

The unattended installer verifies the DMG checksum, DMG code signature,
Developer ID Team ID, Gatekeeper assessment, notarization ticket, mounted app
bundle ID, daemon helper bundle ID, and bundled CLI signature before copying
anything into place. Maintainer releases are expected to use Team ID
`B6L7QLWTZW`. For local unsigned test artifacts only, set
`AGENT_SECRET_ALLOW_UNSIGNED_INSTALL=1`. For signed but intentionally unstapled
local artifacts, set `AGENT_SECRET_REQUIRE_NOTARIZATION=0`.

Unattended uninstall:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/kovyrin/agent-secret/main/uninstall.sh | sh
```

By default uninstall removes the app, CLI symlink, skill symlink, and known
application support files, but leaves `~/Library/Logs/agent-secret` audit logs
in place. Set `AGENT_SECRET_REMOVE_AUDIT_LOGS=1` to remove those logs too.
Custom support or audit paths require
`AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1`; the script refuses broad,
relative, symlinked, or non-`agent-secret` directory targets.

## Development Install

To use the current development build from any project on the same machine:

```bash
mise dev:install
```

By default this installs:

- `~/Applications/Agent Secret.app`.
- `~/.local/bin/agent-secret` as a symlink into the app bundle.
- `~/.agents/skills/agent-secret` as a symlink to the bundled Agent Secret
  skill.

Override the install locations with `--bin-dir`, `--app-dir`,
`AGENT_SECRET_INSTALL_BIN_DIR`, or `AGENT_SECRET_INSTALL_APP_DIR`. To pass
one-off flags, run `./scripts/dev-install.sh` directly. The dev installer also
removes the old split-app development artifacts if they are present and repairs
the command path even when it was left behind as an older regular binary.

By default, `agent-secret` uses the personal 1Password sign-in address
`my.1password.com`. Set `OP_ACCOUNT` or `AGENT_SECRET_1PASSWORD_ACCOUNT` in the
shell that will run `agent-secret exec` only when you want to force a specific
account; the daemon inherits that value when it auto-starts. Project config can
also set `account` globally, per profile, or per secret, and those config values
take precedence for the affected secret refs. On macOS, `agent-secret` starts
the daemon through the nested `AgentSecretDaemon.app` inside `Agent Secret.app`
so 1Password sees the SDK caller as Agent Secret instead of the terminal or
agent desktop app that launched the CLI.

Local release artifact build:

```bash
scripts/build-release.sh v0.0.0-dev
```

That produces a DMG and `checksums.txt` in `dist/`. Local builds are ad-hoc
signed unless Developer ID signing and notarization settings are present, which
makes the local command useful for layout, checksum, and installer smoke checks.

Tag pushes matching `v*` run the GitHub release workflow and attach artifacts
to a draft GitHub Release. Tag-triggered GitHub releases require production
signing: CI runs `scripts/check-release-signing-env.sh`, imports the Developer
ID certificate, and then calls `scripts/build-release.sh "$GITHUB_REF_NAME"
--require-production-signing`. Missing certificate, Developer ID identity,
`AGENT_SECRET_NOTARIZE=1`, or notary credentials fail the tag workflow instead
of publishing ad-hoc artifacts.

The maintainer release checklist is documented in
[Release Process](docs/release-process.md), and release notes are copied from
the matching section in [Changelog](CHANGELOG.md).

Developer ID signing and notarization are optional for local release-candidate
builds and required for this repository's tag-triggered maintainer releases:

```bash
AGENT_SECRET_CODESIGN_IDENTITY="Developer ID Application: Example, Inc. (TEAMID)"
AGENT_SECRET_CODESIGN_ENTITLEMENTS=path/to/entitlements.plist
AGENT_SECRET_NOTARIZE=1
AGENT_SECRET_NOTARY_KEY="$(cat AuthKey_KEYID.p8)"
AGENT_SECRET_NOTARY_KEY_ID=KEYID
AGENT_SECRET_NOTARY_ISSUER_ID=ISSUER_UUID
scripts/check-release-signing-env.sh
scripts/build-release.sh v0.3.1 --require-production-signing
```

`AGENT_SECRET_NOTARY_KEY` may also point at a local `.p8` file. Notarization is
only attempted when `AGENT_SECRET_NOTARIZE=1`; without Apple Developer ID and
App Store Connect API key credentials, local release artifacts remain ad-hoc
signed.

For this repository's maintainer releases, the current Developer ID identity is:

```text
Developer ID Application: Oleksiy Kovyrin (B6L7QLWTZW)
```

GitHub release signing also needs the Developer ID certificate exported from
Keychain Access as a password-protected `.p12` and saved as secrets:

```bash
identity="Developer ID Application: Oleksiy Kovyrin (B6L7QLWTZW)"
base64 -i AgentSecretDeveloperID.p12 | gh secret set AGENT_SECRET_CODESIGN_CERT_P12_BASE64
gh secret set AGENT_SECRET_CODESIGN_CERT_PASSWORD --body "$P12_PASSWORD"
gh secret set AGENT_SECRET_CODESIGN_IDENTITY --body "$identity"
gh secret set AGENT_SECRET_NOTARIZE --body "1"
gh secret set AGENT_SECRET_NOTARY_KEY < AuthKey_KEYID.p8
gh secret set AGENT_SECRET_NOTARY_KEY_ID --body "KEYID"
gh secret set AGENT_SECRET_NOTARY_ISSUER_ID --body "ISSUER_UUID"
```

The CI release job imports the `.p12` into a temporary keychain before signing
and deletes that keychain after the release artifact step.

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

agent-secret exec --reason "Run legacy dotenv deploy" \
  --env-file .env.deploy \
  -- npm run deploy
```

Current `exec` flags:

- `--reason TEXT`: reason shown to the approver. Required unless the selected
  profile provides `reason`.
- `--secret ALIAS=op://vault/item[/section]/field-or-text-file`: explicit
  secret mapping. Repeat for multiple secrets.
- `--env-file PATH`: load dotenv-style `KEY=VALUE` entries. Values starting
  with `op://` become approved secret refs; other values are passed to the
  child process as plain environment entries. Repeat for multiple files.
- `--profile NAME`: load a named project profile.
- `--only ALIAS[,ALIAS...]`: filter loaded profile secrets and env-file secret
  refs to selected aliases. Repeat to add more aliases. Deliberate one-off
  `--secret` refs are not filtered.
- `--account ACCOUNT`: default 1Password account for refs that do not already
  have a config/profile account.
- `--config PATH`: use a specific config file instead of upward discovery.
- `--cwd DIR`: run the child process from `DIR`.
- `--ttl DURATION`: approval TTL. Defaults to profile `ttl` or `2m`; allowed
  range is `10s` through `10m`.
- `--override-env`: allow approved aliases to replace existing child
  environment variables.
- `--force-refresh`: for reusable approvals, refetch approved refs before
  delivery.
- `--allow-mutable-executable`: permit a command whose executable file or
  parent directory is writable by the current user. Without this explicit
  opt-in, `exec` rejects project-local and temp executables that can be swapped
  after approval.

The command to run must appear after `--` as argv. `agent-secret exec` has no
`--json` mode and does not parse shell strings.

1Password file attachments and Document items are supported when the SDK can
resolve them as text. For example, a ref such as
`op://Example/GitHub App/key.pem` injects the file contents into the alias env
var, preserving multiline text such as PEM keys. Agent Secret does not write the
value to a temp file and does not print it. Binary attachments with NUL bytes
are not supported by env-var delivery.

Daemon management and diagnostics:

```bash
agent-secret daemon status
agent-secret daemon start
agent-secret daemon stop
agent-secret doctor
agent-secret install-cli
agent-secret skill-install
```

`agent-secret install-cli` installs or repairs the `agent-secret` symlink for
the current user. It refuses to replace an unrelated regular file unless
`--force` is passed.

`agent-secret skill-install` installs or repairs the bundled coding-agent skill
for the current user:

```bash
agent-secret skill-install
agent-secret skill-install --skills-dir "$HOME/.agents/skills"
agent-secret skill-install --force
```

The skill covers general Agent Secret usage, profiles, env files, safe
verification, and migration from direct 1Password CLI usage. It is bundled in
the app so upgrades keep the installed skill in sync with the installed CLI.

## Project Profiles

Projects can keep reusable secret bundles in `agent-secret.yml` or
`.agent-secret.yml`. The file contains only 1Password refs and metadata, never
resolved values. `agent-secret exec --profile NAME` discovers the config from
the current directory or a parent. If `default_profile` is set, `agent-secret
exec -- COMMAND` uses that profile when no `--profile`, `--secret`, or
`--env-file` flags are provided.

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
`account`, then top-level `account`, then CLI `--account`, then `OP_ACCOUNT` /
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
`--ttl` override profile defaults. CLI `--account` supplies a default account
for refs that do not already have a config/profile account. `--only` filters
profile-loaded aliases and env-file secret refs before one-off `--secret` refs
are added.

`--env-file` is the migration path for commands that currently use
`op run --env-file`. It parses dotenv-style entries before approval. Secret refs
such as `TOKEN=op://Example/Service/token` are requested from the daemon, while
plain entries such as `RAILS_ENV=production` are passed only to the child
process. Later env files override earlier files. Env-file keys override the
caller environment for that child, and env-file secret aliases are removed from
the base child environment before approved values are injected. `--only` can be
used with env files to request a subset of their `op://` refs, for example when
one file contains both beta and production refs.

See [Configuration Reference](docs/configuration.md) for the full config schema,
discovery rules, account precedence, and command reference.

## Security Model

Agent Secret is designed to keep raw secret values away from coding agents while
still letting a human approve narrowly scoped commands. It is a local broker, not
a sandbox. The approved child process receives the secret and can use, print, or
forward it like any other process environment value.

### Trusted Components

- 1Password remains the source of truth for secret storage and account
  authentication.
- `agent-secretd` owns approvals, policy checks, 1Password SDK access, and
  reusable in-memory secret cache entries.
- The native macOS approver is trusted UI. It shows the command name, full
  command details, working directory, reason, requested refs, TTL, and reusable
  approval scope before a value is fetched.
- The CLI is a trusted launcher. In `exec` mode it asks the daemon for approved
  values, starts the child process, and passes stdout/stderr through unchanged.

### What Is Protected

- Project config and command flags contain 1Password refs only, never resolved
  values.
- Audit logs contain metadata only: command, cwd, reason, aliases, refs, policy
  decision, PID, exit status, and timing. They never contain secret values.
- The daemon and CLI disable core dumps on startup with `RLIMIT_CORE=0`. Child
  commands launched through `agent-secret exec` inherit that no-core-dump limit.
- Reusable approval cache values are stored in daemon memory backed by anonymous
  `mmap`, pinned with `mlock`, and zeroed before `munlock`/`munmap`.
- Reusable approvals fail closed if the daemon cannot put a cached secret into
  locked memory. The daemon does not silently fall back to a plain Go string
  cache.
- Cached values are cleared when their reusable approval scope is replaced,
  cleared, refreshed, or when the daemon stops.

### Remaining Plaintext Boundaries

Some plaintext copies are still unavoidable in the current `exec` design:

- The 1Password Go SDK returns resolved values as Go strings.
- The daemon protocol currently serializes approved env values to the CLI.
- `exec.Cmd.Env` ultimately needs `KEY=value` strings so the operating system
  can give the child process its environment.
- Once the child starts, the child process and its descendants can read the
  approved environment values.

The locked-memory cache reduces the lifetime and swap/core-dump exposure of
daemon-held reusable values. It does not make Go string copies, JSON protocol
payloads, or child-process environments magically secret.

### Out Of Scope

- A compromised macOS user session, root account, kernel, 1Password app, or
  approved child process can still exfiltrate secrets.
- Agent Secret does not police what an approved command does after launch.
- Agent Secret does not hide values from the operating system APIs required to
  create the approved child environment.
- Agent Secret does not persist approval state or secret values. The audit log is
  the only durable state.

## Default Safety Posture

- Default delivery is CLI-supervised `exec` mode.
- Raw secret output is not provided by the broker.
- The macOS approver emits non-secret diagnostics to Apple Unified Logging for
  local troubleshooting.
- `agent-secret --help` is detailed enough for coding agents to discover safe
  usage without reading these docs.
- Future Go code must be covered by project lint and pre-commit paths.
- Integration tests must use real captured API and OS error shapes, but captured
  fixtures must not contain secret values.
