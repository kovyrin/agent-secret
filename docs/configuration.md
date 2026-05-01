# Configuration

Agent Secret can run from explicit CLI flags or from a project-local config
file. The config file stores only 1Password references and policy metadata. It
must never contain resolved secret values.

## Config File Discovery

`agent-secret exec` discovers config files upward from the current working
directory. The first matching file wins:

- `agent-secret.yml`
- `.agent-secret.yml`

Use `--config PATH` to point at a specific file.

## Minimal Profile Config

```yaml
version: 1
default_profile: terraform-cloudflare

profiles:
  terraform-cloudflare:
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
```

With `default_profile`, the command can omit `--profile`:

```bash
agent-secret exec -- terraform plan
```

The same profile can still be selected explicitly:

```bash
agent-secret exec --profile terraform-cloudflare -- terraform plan
```

## Full Config Example

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
    ttl: 10m
    secrets:
      ANSIBLE_BECOME_PASSWORD: op://Example/Ansible/password
      CADDY_TOKEN: op://Example/Caddy/token
```

## Config Fields

Top-level fields:

- `version`: required. Must be `1`.
- `account`: optional default 1Password account for all profiles in the file.
- `default_profile`: optional profile name used when `exec` has no `--profile`,
  no explicit `--secret`, and no `--env-file`.
- `profiles`: required map of profile names to profile definitions.

Profile fields:

- `reason`: optional if `--reason` is provided on the CLI.
- `ttl`: optional approval TTL, such as `90s`, `2m`, or `10m`.
- `account`: optional 1Password account override for all secrets in a profile.
- `include`: optional list of profile names to merge before this profile.
- `secrets`: map of environment aliases to 1Password references. Required
  unless `include` contributes at least one secret.

## Profile Includes

Profiles can include other profiles to avoid repeating common secret bundles:

```yaml
profiles:
  terraform-cloudflare:
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token

  ansible:
    secrets:
      ANSIBLE_BECOME_PASSWORD: op://Example/Ansible/password

  ansible-with-dns:
    include:
      - ansible
      - terraform-cloudflare
    reason: Run Ansible playbook with DNS changes
```

Includes are resolved in order. Later included profiles override earlier
secrets with the same alias, and the selected profile overrides all included
profiles. `reason` and `ttl` also follow that order: the last included value is
used unless the selected profile sets its own value.

Each included secret keeps the account chosen by the profile that defined it.
If the selected profile needs a different account or ref for a secret, redeclare
that alias in its own `secrets` map.

Secret entries can be scalar references:

```yaml
secrets:
  TOKEN: op://Example/Item/token
```

Secret entries can also be objects when one secret needs its own account:

```yaml
secrets:
  TOKEN:
    ref: op://Example/Item/token
    account: Fixture Preview
```

Aliases must look like environment variable names, for example
`CLOUDFLARE_API_TOKEN`.

## Account Precedence

Agent Secret chooses the account for each secret independently:

1. Secret-level `account`.
2. Profile-level `account`.
3. Top-level `account`.
4. CLI `--account`.
5. `OP_ACCOUNT` or `AGENT_SECRET_1PASSWORD_ACCOUNT`.
6. Built-in default `my.1password.com`.

The account is part of the secret identity used for resolution, reusable
approval matching, and in-memory caching. The same `op://` reference in two
different accounts is treated as two different secrets.

## Exec Command Options

`agent-secret exec` accepts only argv after `--`; it does not parse shell
strings.

```bash
agent-secret exec [flags] -- COMMAND [ARG...]
```

Current flags:

- `--reason TEXT`: human-readable reason shown in the approval UI. Required
  unless the selected profile provides `reason`.
- `--secret ALIAS=op://vault/item[/section]/field`: explicit secret mapping.
  Repeat for multiple secrets.
- `--env-file PATH`: load dotenv-style `KEY=VALUE` entries. Values starting
  with `op://` become approved secret refs; other values are passed to the
  child process as plain environment entries. Repeat for multiple files.
- `--profile NAME`: load a named profile from the project config.
- `--only ALIAS[,ALIAS...]`: filter loaded profile secrets and env-file secret
  refs to selected aliases. Repeat to add more aliases. Deliberate one-off
  `--secret` refs are not filtered.
- `--account ACCOUNT`: default 1Password account for refs that do not already
  have a config/profile account.
- `--config PATH`: use a specific config file.
- `--cwd DIR`: run the child process from `DIR`.
- `--ttl DURATION`: approval TTL. Defaults to profile `ttl` or `2m`; allowed
  range is `10s` through `10m`.
- `--override-env`: allow approved secret aliases to replace existing
  environment variables in the child process.
- `--force-refresh`: when a reusable approval matches, refetch approved refs
  before delivering them to the child.
- `-h`, `--help`: print detailed `exec` help.

Unsupported by design:

- `--json`: `exec` passes stdin, stdout, and stderr through unchanged.
- `--reuse`: reusable approvals are chosen in the approval UI.

Explicit `--secret` flags may be combined with `--profile` for one-off
additional refs. In that mode, explicit secrets inherit the loaded profile
account. `--only` filters profile-loaded aliases and env-file secret refs
before one-off `--secret` refs are added. Explicit `--secret`-only invocations
do not load `default_profile`.

`--env-file` may be combined with `--profile` or `--secret`. It is intended for
migrating `op run --env-file` workflows without rewriting every caller at once:

```bash
agent-secret exec --reason "Deploy from env file" --env-file .env.deploy -- \
  npm run deploy
```

Each env file is parsed before approval. Entries whose values start with
`op://` become secret refs. Other entries are plain child-process environment
variables and are never sent to the daemon. Later env files override earlier
files. Env-file keys override the caller environment for the child process, and
env-file secret aliases are removed from the base child environment before
approved values are injected. Use `--only` with env files when one file contains
refs for multiple command surfaces, such as beta and production deploy refs.

## Other Commands

Daemon management:

```bash
agent-secret daemon status
agent-secret daemon start
agent-secret daemon stop
```

Diagnostics:

```bash
agent-secret doctor
```

`doctor` prints non-secret setup diagnostics. It should not require or resolve
real secret values.
