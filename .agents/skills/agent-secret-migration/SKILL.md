---
name: agent-secret-migration
description: Migrate a project from direct 1Password CLI usage to Agent Secret. Use when replacing op, op run, op run --env-file, op read, exported secret variables, or repeated secret wrapper scripts with agent-secret exec, project profiles, env-file migration, and safe verification.
---

# Agent Secret Migration

Use this skill when a project currently touches 1Password directly and should
move to Agent Secret.

## Goal

Replace direct secret reads with human-approved `agent-secret exec` flows while
preserving the existing command behavior. The target state is:

- Agents do not run `op`.
- Agents do not print or write secret values.
- Repeated multi-secret commands use project-local `agent-secret.yml` profiles.
- Existing `op run --env-file` workflows move to `agent-secret exec
  --env-file` when that keeps the migration smaller and safer.
- One-off single-secret commands may use explicit `--secret ALIAS=op://...`
  flags.
- Commands still receive secrets as environment variables only inside the
  approved child process.

## First Pass

1. Confirm `agent-secret` is available:

   ```bash
   agent-secret --help
   agent-secret doctor
   ```

2. Inventory direct 1Password usage:

   ```bash
   rg -n '\bop\b|op://|1Password' .
   rg -n 'ONEPASSWORD|OP_ACCOUNT|OP_SERVICE_ACCOUNT|OP_CONNECT' .
   ```

3. Classify each call site:

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

4. Pick the smallest useful migration surface first: a plan/dry-run/deploy
   command that already expects env vars and can be verified without printing
   secrets.

## Config Profiles

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
wrapper needs a subset of a large profile:

```bash
agent-secret exec --profile ansible --only CADDY_TOKEN,POSTGRES_PASSWORD -- \
  ansible-playbook site.yml --tags caddy
```

Account precedence is per-secret `account`, profile `account`, top-level
`account`, CLI `--account`, `OP_ACCOUNT` / `AGENT_SECRET_1PASSWORD_ACCOUNT`,
then the Agent Secret default. Prefer config accounts over shell environment
when the project needs a specific 1Password account. Use `--account` for
one-off wrappers or env-file migrations that should not require a project
config yet; it also works with profiles whose config does not already name an
account.

## Replacement Patterns

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

Replace `op read` for a text file attachment or Document item when the child
expects the file contents in an environment variable:

```bash
# Before
PRIVATE_KEY="$(op read op://Example/GitHub App/key.pem)" deploy-tool

# After
agent-secret exec \
  --reason "Deploy with GitHub App key" \
  --secret PRIVATE_KEY=op://Example/GitHub\ App/key.pem \
  -- deploy-tool
```

This is text-secret support. Multiline text such as PEM keys and JSON blobs is
preserved in the env var. Do not migrate binary attachments this way; env vars
cannot carry NUL bytes. If the existing script expects a file path, prefer
passing contents to its env-first path and let the approved child process create
any temp file it already owns.

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

In env files, entries whose values start with `op://` become approved secret
refs. Other entries are passed only to the child command as plain environment
variables. Later `--env-file` values override earlier files, matching the usual
dotenv migration expectation.

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
and run the command directly instead of using Agent Secret as a generic dotenv
runner.

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
  --secret TOKEN=op://Example/Service/token \
  -- sh -c 'test -n "${TOKEN:-}"'
```

Avoid `env`, `printenv`, `set`, shell tracing (`set -x`), or debug logs that can
emit secret values.

## Guardrails

- Do not run `op` unless the user explicitly asks for a diagnostic that requires
  it.
- Never echo, log, diff, commit, or write resolved secret values.
- Do not commit rendered files that contain secrets.
- Do not add long-lived plaintext `.env` files as a migration shortcut.
- Keep secret aliases stable and descriptive: `CLOUDFLARE_API_TOKEN`,
  `DATABASE_URL`, `ANSIBLE_BECOME_PASSWORD`.
- Keep reasons human-readable. They are shown in the approval UI and audit log.
- Prefer `ttl: 10m` for deploy or infrastructure workflows that involve
  several related subprocesses; use shorter TTLs for simple one-command checks.
- Preserve stdout/stderr behavior. `agent-secret exec` passes both through
  unchanged.
- Follow the host project's git and test rules. Commit only when the user asks.
