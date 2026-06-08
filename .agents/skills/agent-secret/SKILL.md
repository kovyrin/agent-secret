---
name: agent-secret
description: Use Agent Secret safely in a project, including 1Password and Bitwarden Secrets Manager refs, project profiles, env-file use, migration, and verification without exposing secret values.
---

# Agent Secret

Use this skill when a project needs secrets through Agent Secret, when an agent
needs to understand how to run `agent-secret`, or when migrating direct
1Password or Bitwarden Secrets Manager CLI usage to Agent Secret.

## Goals

- Run commands with narrowly approved secrets without printing values.
- Keep secret refs in command flags, env files, or `agent-secret.yml`; never
  store resolved values.
- Use project-local profiles for repeated multi-secret workflows.
- Use bounded sessions when a short workflow needs approved secrets in
  different per-command combinations.
- Migrate direct provider CLI usage to `agent-secret exec` while preserving
  command behavior.
- Inspect 1Password item metadata when field names are unknown, without
  revealing secret values.
- Verify real behavior with safe checks that do not leak secrets.

## Safety Rules

- Do not run `op` or `bws` unless the user explicitly asks for a diagnostic
  that requires the provider CLI.
- Never echo, log, diff, commit, or write resolved secret values.
- Never ask the user to paste a Bitwarden access token into chat, an issue, or
  a pull request. Use interactive token install instead.
- Avoid `env`, `printenv`, `set`, shell tracing (`set -x`), and debug logs in
  secret-backed runs.
- Do not add long-lived plaintext `.env` files as a shortcut.
- Do not commit rendered files that contain secrets.
- Do not treat sessions as a raw secret-read API. Run each command through
  `agent-secret with-session`.
- Do not run long-lived interactive shells under a session. Use bounded
  `with-session` invocations for specific commands.
- Keep secret aliases stable and descriptive, such as
  `CLOUDFLARE_API_TOKEN`, `DATABASE_URL`, or `ANSIBLE_BECOME_PASSWORD`.
- Keep reasons human-readable. They are shown in the approval UI and audit log.
- Preserve stdout and stderr behavior. `agent-secret exec` passes both through
  unchanged.

## General Use

Confirm the tool is available:

```bash
agent-secret --help
agent-secret agent-context --json
agent-secret doctor
```

Run a single-secret command:

```bash
agent-secret exec \
  --reason "Terraform DNS management" \
  --secret CLOUDFLARE_API_TOKEN=op://Example/Cloudflare/token \
  -- terraform plan
```

Run a command with a Bitwarden Secrets Manager secret:

```bash
agent-secret exec \
  --reason "Deploy with Bitwarden-managed API token" \
  --secret API_TOKEN=bws://work/<secret-uuid> \
  -- deploy-tool
```

Run a command with a project profile:

```bash
agent-secret exec --profile terraform-cloudflare -- terraform plan
```

If the project has `default_profile`, the profile can be implicit:

```bash
agent-secret exec -- terraform plan
```

Inspect project profiles without resolving values:

```bash
agent-secret profile list --json
agent-secret profile show --json terraform-cloudflare
```

Validate a request without prompting, resolving values, or spawning the child:

```bash
agent-secret exec --dry-run --json --profile terraform-cloudflare -- terraform plan
```

Use an existing reusable approval without opening a new prompt:

```bash
agent-secret exec --reuse-only --profile terraform-cloudflare -- terraform plan
```

Approve a bounded multi-command session:

```bash
agent-secret session create --profile terraform-cloudflare --max-reads 3
agent-secret with-session asess_123 --only CLOUDFLARE_API_TOKEN -- \
  terraform plan
agent-secret with-session asess_123 \
  --only CLOUDFLARE_API_TOKEN,STATE_TOKEN \
  -- terraform apply
agent-secret session destroy asess_123
```

Use sessions when the user approves a bag of secrets once and later commands
need different subsets. `session create` accepts the same config, profile,
env-file, and `--secret` inputs as `exec`, then returns only an opaque session
ID. The daemon keeps resolved values in memory until TTL, read count, explicit
destroy, or daemon stop clears them. `with-session` injects every approved alias
by default; add `--only ALIAS[,ALIAS...]` to deliver only the aliases needed by
that child command. Unknown aliases fail before the child process starts.

Use a shell only when the shell is the command you actually want approved:

```bash
agent-secret exec \
  --reason "Run deploy wrapper" \
  --secret TOKEN=op://Example/Deploy/token \
  -- sh -c 'deploy-tool --token-env TOKEN'
```

The wrapped command must appear after `--` as argv. Agent Secret does not parse
shell strings. Normal `exec` does not have JSON output because child
stdin/stdout/stderr pass through unchanged; only `exec --dry-run --json`
returns JSON.

## Provider Setup

For 1Password refs, make sure the 1Password desktop app is signed in, unlocked,
and has Developer Tools SDK integration enabled. `agent-secret doctor` reports
non-secret diagnostic state.

For Bitwarden Secrets Manager refs, install the official Bitwarden-signed `bws`
CLI, then install a local token alias in Agent Secret:

```bash
agent-secret bitwarden secrets-manager token status --alias work
agent-secret bitwarden secrets-manager token install --alias work
```

The install command prompts with hidden terminal input. For non-interactive
setup scripts, pipe the token to the stdin-only install form:

```bash
agent-secret bitwarden secrets-manager token install --alias work --from-stdin
```

Do not echo the token or put it in shell history. The approved child command
receives only the resolved secret value, never the Bitwarden access token.

## Project Profiles

Create `agent-secret.yml` or `.agent-secret.yml` at the project root when a
command needs repeated access to more than one secret.

```yaml
version: 1

account: my.1password.com
default_profile: terraform

sources:
  bitwarden:
    work-secrets:
      token_alias: work

profiles:
  cloudflare:
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token

  ansible-base:
    reason: Run Ansible playbook
    ttl: 10m
    secrets:
      ANSIBLE_BECOME_PASSWORD: op://Example/Ansible/password

  ansible-caddy:
    include:
      - ansible-base
    reason: Update Caddy config
    ttl: 10m
    secrets:
      CADDY_TOKEN: op://Example/Caddy/token

  deploy:
    reason: Deploy with Bitwarden-managed API token
    ttl: 10m
    secrets:
      API_TOKEN:
        ref: bws://<secret-uuid>
        source: work-secrets
```

Use nested profiles to avoid duplicated secret lists. Use `--only` when a
wrapper needs a subset of a larger profile:

```bash
agent-secret exec --profile ansible --only CADDY_TOKEN,POSTGRES_PASSWORD -- \
  ansible-playbook site.yml --tags caddy
```

Sessions can also start from a profile and project config. Prefer a profile
when the same approved bag is reused by several short commands, then project a
smaller child environment with `with-session --only` for each command.

Account precedence is per-secret `account`, profile `account`, top-level
`account`, CLI `--account`, `OP_ACCOUNT` / `AGENT_SECRET_1PASSWORD_ACCOUNT`,
then the default personal 1Password desktop account, falling back to the only
active desktop account for single-account users. Prefer config accounts over
shell environment when a project needs a specific 1Password account. Use
`--account` for one-off wrappers or env-file migrations that should not require
a project config yet.

`account` is only for 1Password account selection. For Bitwarden Secrets
Manager, use a `sources.bitwarden` entry and refer to it with `source` or with a
source-qualified ref such as `bws://work-secrets/<secret-uuid>`. `source` is
Agent Secret terminology for a configured place to resolve a secret ref; it is
not a Bitwarden UI object.

Bare `bws://<secret-uuid>` refs are valid only when there is a single
unambiguous Bitwarden Secrets Manager source. If a profile config has multiple
Bitwarden sources, set `source` on the secret or use
`bws://<source-alias>/<secret-uuid>`. If no project source is configured, a bare
Bitwarden ref can use the single locally installed token alias; multiple local
token aliases require the source-qualified form.

## Env Files

Use `--env-file` as the migration path for commands that currently use
`op run --env-file`.

```bash
agent-secret exec --reason "Deploy application" --env-file .env.deploy -- \
  npm run deploy
```

Entries whose values start with `op://` or `bws://` become approved secret refs.
Other entries are passed only to the child command as plain environment
variables. Later `--env-file` values override earlier files.

Use `--only` when one env file contains refs for multiple command surfaces:

```bash
agent-secret exec \
  --reason "Deploy beta" \
  --account example.1password.com \
  --env-file .env.deploy.op \
  --only VERCEL_DEPLOY_HOOK_URL_BETA,VERCEL_TOKEN \
  -- npm run deploy:beta
```

`--only` filters profile and env-file secret refs. It does not filter deliberate
one-off `--secret` flags. If an env file has no `op://` or `bws://` refs, skip
Agent Secret and run the command directly instead of using it as a generic
dotenv runner.

## Text File Secrets

1Password file attachments and Document items are supported when the child
expects text contents in an environment variable:

```bash
agent-secret exec \
  --reason "Deploy with GitHub App key" \
  --secret PRIVATE_KEY=op://Example/GitHub\ App/key.pem \
  -- deploy-tool
```

Multiline text such as PEM keys and JSON blobs is preserved in the env var.
Agent Secret does not create a temp file for the value and does not print it.
Do not migrate binary attachments this way; env vars cannot carry NUL bytes. If
the existing script expects a file path, prefer passing contents to its
env-first path and let the approved child process create any temp file it
already owns.

Bitwarden Secrets Manager v1 resolves secret values only. It does not provide
an Agent Secret file-attachment mode.

## Item Metadata Inspection

Use `agent-secret item describe` when you know the 1Password item but need a
secret-safe list of fields before choosing exact `op://` refs. This is for
metadata only: labels, IDs, types, sections, and canonical refs are shown, but
values are not returned.

Describe an item:

```bash
agent-secret item describe \
  --reason "Inspect deploy credential fields" \
  "op://Example Infra/Production Deploy Token"
```

The command accepts item-level refs such as `op://Vault/Item` and
`op://Vault/Item/*`. Do not use field refs for inspection; use the output to
choose exact refs for `agent-secret exec`.

Ask for env-ready aliases when wiring a profile or wrapper:

```bash
agent-secret item describe \
  --format env-refs \
  --prefix DEPLOY \
  --reason "Inspect deploy credential fields" \
  "op://Example Infra/Production Deploy Token/*"
```

Prefer project config account discovery. Use `--account` only when the project
does not already define the intended account or when an explicit one-off
override is needed. Do not fall back to `op item get` unless the user explicitly
asks for that diagnostic.

There is no equivalent Agent Secret metadata inspection command for Bitwarden
Secrets Manager in v1. Use the Bitwarden UI or existing non-secret project docs
to identify the secret UUID; do not call `bws secret get` just to discover or
verify a value.

## Migrating From Provider CLIs

Inventory direct provider CLI usage:

```bash
rg -n '\bop\b|op://|1Password' .
rg -n 'ONEPASSWORD|OP_ACCOUNT|OP_SERVICE_ACCOUNT|OP_CONNECT' .
rg -n '\bbws\b|bws://|BWS_ACCESS_TOKEN|BITWARDEN' .
```

Classify each call site:

- `op read` or `$(op read ...)`: replace with an env alias delivered by
  `agent-secret exec`.
- `op run -- COMMAND`: replace with `agent-secret exec --profile NAME --
  COMMAND`.
- `op run --env-file FILE -- COMMAND`: replace with `agent-secret exec
  --env-file FILE -- COMMAND`; add `--reason` unless a profile supplies it.
- `op inject`: convert the template inputs to env aliases or ask the user
  before writing rendered secret-bearing files.
- Secret loader scripts: replace their internals with `agent-secret exec` or
  remove them when a profile can express the same secret set.
- Static `op://` catalogs: keep them as references only if they are useful
  documentation; they are not instructions to call `op`.
- `bws secret get` value loaders: replace with an env alias delivered by
  `agent-secret exec`.
- Scripts that export `BWS_ACCESS_TOKEN`: replace token handling with a local
  Agent Secret token alias and keep the Bitwarden token out of child commands.
- Static `bws://` catalogs: keep them as references only if they are useful
  documentation; they are not instructions to call `bws`.

Pick the smallest useful migration surface first: a plan, dry-run, deploy, or
validation command that already expects env vars and can be verified without
printing secrets.

Replace command substitution:

```bash
# Before
CLOUDFLARE_API_TOKEN="$(op read op://Example/Cloudflare/token)" terraform plan

# After
agent-secret exec \
  --reason "Terraform DNS management" \
  --secret CLOUDFLARE_API_TOKEN=op://Example/Cloudflare/token \
  -- terraform plan
```

Replace direct Bitwarden value loading with an approved env alias:

```bash
agent-secret exec \
  --reason "Deploy with Bitwarden-managed API token" \
  --secret API_TOKEN=bws://work/<secret-uuid> \
  -- deploy-tool
```

Replace `op run`:

```bash
# Before
op run -- ansible-playbook site.yml

# After
agent-secret exec --profile ansible -- ansible-playbook site.yml
```

Replace `op run --env-file`:

```bash
# Before
op run --env-file .env.deploy -- npm run deploy

# After
agent-secret exec --reason "Deploy application" --env-file .env.deploy -- \
  npm run deploy
```

Replace loader scripts by keeping the child command under Agent Secret:

```bash
#!/usr/bin/env bash
set -euo pipefail

exec agent-secret exec --profile deploy -- "$@"
```

Do not replace a direct secret read with a command that prints the value. Agent
Secret intentionally has no raw `read` command for secret values.

Do not migrate Bitwarden Password Manager `bw` vault automation to `bws://`.
Agent Secret v1 supports Bitwarden Secrets Manager only.

## Verification

Before reporting success, prove the migrated path works:

- Run the project lint or shellcheck path for edited scripts.
- Run `agent-secret exec` against the actual command when it has a safe dry-run,
  plan, validation, or no-op mode.
- Verify that the command consumed the intended environment variable without
  printing the secret. Prefer real command output, exit status, logs, or
  metadata over `env`.
- For profile changes, test at least one full-profile invocation and any
  `--only` wrapper that filters aliases.
- For session workflows, test `session create`, `session list`, at least one
  full `with-session` invocation, any `with-session --only` subsets, and
  session exhaustion or `session destroy`.
- For `--env-file` migrations, test that the real command receives both a
  secret-backed variable and at least one plain env-file variable without
  printing either secret value.
- If approval UI appears, confirm the requested command, reason, refs, and TTL
  match the migration.

Safe presence checks are acceptable only when they do not print values:

```bash
agent-secret exec \
  --reason "Check token presence" \
  --secret TOKEN=op://Example/Service/token \
  -- sh -c 'test -n "${TOKEN:-}"'
```

For smoke tests where presence is not enough, print only bounded metadata such
as length and a short hash:

```bash
agent-secret exec \
  --reason "Check Bitwarden secret delivery" \
  --secret TOKEN=bws://work/<secret-uuid> \
  -- /usr/bin/python3 -c '
import hashlib, os
v = os.environ["TOKEN"].encode()
digest = hashlib.sha256(v).hexdigest()[:12]
print(f"len={len(v)} sha256={digest}")
'
```

## Troubleshooting

- `agent-secret doctor` shows non-secret local diagnostics.
- `agent-secret daemon status` confirms whether the daemon is running.
- `agent-secret daemon stop` clears daemon-owned in-memory approvals and cached
  values.
- `agent-secret bitwarden secrets-manager token status --alias ALIAS` checks
  whether a Bitwarden token alias exists without printing the token.
- `agent-secret bitwarden secrets-manager token install --alias ALIAS`
  reinstalls a Bitwarden token alias with hidden input. Use it when Keychain
  access requires repair.
- `agent-secret skill-install` installs or repairs this skill in
  `~/.agents/skills/agent-secret`.
- If Bitwarden resolution says the `bws` CLI is unavailable, install the
  official Bitwarden-signed `bws` CLI or fix the system-owned helper path.
- If a bare `bws://<secret-uuid>` ref is ambiguous, add a project
  `sources.bitwarden` entry and set `source`, or use
  `bws://<source-alias>/<secret-uuid>`.
- If the approval UI shows the wrong command or reason, fix the wrapper before
  approving.
- If a command has no safe way to prove consumption without printing a value,
  stop and ask for a safer verification path.

## Handoff

When done, report:

- Files changed.
- Commands migrated.
- Secret aliases and `op://` or `bws://` refs involved, never resolved values.
- Verification commands and outcomes.
- Any call sites intentionally left on direct provider CLI access and why.
