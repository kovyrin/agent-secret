---
name: agent-secret
description: Use Agent Secret safely in a project, including general command execution, project profiles, env-file use, 1Password migration, and verification without exposing secret values.
---

# Agent Secret

Use this skill when a project needs secrets through Agent Secret, when an agent
needs to understand how to run `agent-secret`, or when migrating direct
1Password CLI usage to Agent Secret.

## Goals

- Run commands with narrowly approved secrets without printing values.
- Keep secret refs in command flags, env files, or `agent-secret.yml`; never
  store resolved values.
- Use project-local profiles for repeated multi-secret workflows.
- Migrate direct `op` usage to `agent-secret exec` while preserving command
  behavior.
- Verify real behavior with safe checks that do not leak secrets.

## Safety Rules

- Do not run `op` unless the user explicitly asks for a diagnostic that requires
  it.
- Never echo, log, diff, commit, or write resolved secret values.
- Avoid `env`, `printenv`, `set`, shell tracing (`set -x`), and debug logs in
  secret-backed runs.
- Do not add long-lived plaintext `.env` files as a shortcut.
- Do not commit rendered files that contain secrets.
- Keep secret aliases stable and descriptive, such as
  `CLOUDFLARE_API_TOKEN`, `DATABASE_URL`, or `ANSIBLE_BECOME_PASSWORD`.
- Keep reasons human-readable. They are shown in the approval UI and audit log.
- Preserve stdout and stderr behavior. `agent-secret exec` passes both through
  unchanged.

## General Use

Confirm the tool is available:

```bash
agent-secret --help
agent-secret doctor
```

Run a single-secret command:

```bash
agent-secret exec \
  --reason "Terraform DNS management" \
  --secret CLOUDFLARE_API_TOKEN=op://Example/Cloudflare/token \
  -- terraform plan
```

Run a command with a project profile:

```bash
agent-secret exec --profile terraform-cloudflare -- terraform plan
```

If the project has `default_profile`, the profile can be implicit:

```bash
agent-secret exec -- terraform plan
```

Use a shell only when the shell is the command you actually want approved:

```bash
agent-secret exec \
  --reason "Run deploy wrapper" \
  --secret TOKEN=op://Example/Deploy/token \
  -- sh -c 'deploy-tool --token-env TOKEN'
```

The wrapped command must appear after `--` as argv. Agent Secret does not parse
shell strings and does not have an `exec --json` mode.

## Project Profiles

Create `agent-secret.yml` or `.agent-secret.yml` at the project root when a
command needs repeated access to more than one secret.

```yaml
version: 1

account: my.1password.com
default_profile: terraform

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
```

Use nested profiles to avoid duplicated secret lists. Use `--only` when a
wrapper needs a subset of a larger profile:

```bash
agent-secret exec --profile ansible --only CADDY_TOKEN,POSTGRES_PASSWORD -- \
  ansible-playbook site.yml --tags caddy
```

Account precedence is per-secret `account`, profile `account`, top-level
`account`, CLI `--account`, `OP_ACCOUNT` / `AGENT_SECRET_1PASSWORD_ACCOUNT`,
then the Agent Secret default. Prefer config accounts over shell environment
when a project needs a specific 1Password account. Use `--account` for one-off
wrappers or env-file migrations that should not require a project config yet.

## Env Files

Use `--env-file` as the migration path for commands that currently use
`op run --env-file`.

```bash
agent-secret exec --reason "Deploy application" --env-file .env.deploy -- \
  npm run deploy
```

Entries whose values start with `op://` become approved secret refs. Other
entries are passed only to the child command as plain environment variables.
Later `--env-file` values override earlier files.

Use `--only` when one env file contains refs for multiple command surfaces:

```bash
agent-secret exec \
  --reason "Deploy beta" \
  --account fixture.1password.com \
  --env-file .env.deploy.op \
  --only VERCEL_DEPLOY_HOOK_URL_BETA,VERCEL_TOKEN \
  -- npm run deploy:beta
```

`--only` filters profile and env-file secret refs. It does not filter deliberate
one-off `--secret` flags. If an env file has no `op://` refs, skip Agent Secret
and run the command directly instead of using it as a generic dotenv runner.

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

## Migrating From 1Password CLI

Inventory direct 1Password usage:

```bash
rg -n '\bop\b|op://|1Password' .
rg -n 'ONEPASSWORD|OP_ACCOUNT|OP_SERVICE_ACCOUNT|OP_CONNECT' .
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

## Troubleshooting

- `agent-secret doctor` shows non-secret local diagnostics.
- `agent-secret daemon status` confirms whether the daemon is running.
- `agent-secret daemon stop` clears daemon-owned in-memory approvals and cached
  values.
- `agent-secret skill-install` installs or repairs this skill in
  `~/.agents/skills/agent-secret`.
- If the approval UI shows the wrong command or reason, fix the wrapper before
  approving.
- If a command has no safe way to prove consumption without printing a value,
  stop and ask for a safer verification path.

## Handoff

When done, report:

- Files changed.
- Commands migrated.
- Secret aliases and `op://` refs involved, never resolved values.
- Verification commands and outcomes.
- Any call sites intentionally left on direct 1Password access and why.
