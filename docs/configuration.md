# Configuration

Agent Secret can run from explicit CLI flags or from a project-local config
file. The config file stores secret references, source metadata, and policy
metadata. It must never contain resolved secret values or provider access
tokens.

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
default_profile: terraform-cloudflare

profiles:
  terraform-cloudflare:
    account: Example Corp
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
      PREVIEW_TOKEN:
        ref: op://Example/Preview/token
        account: Example Preview

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
- `sources`: optional map of named non-1Password secret sources.
- `default_profile`: optional profile name used when `exec` has no `--profile`,
  no explicit `--secret`, and no `--env-file`.
- `profiles`: required map of profile names to profile definitions.

Profile fields:

- `reason`: optional if `--reason` is provided on the CLI.
- `ttl`: optional approval TTL, such as `90s`, `2m`, or `10m`.
- `account`: optional 1Password account override for all secrets in a profile.
- `include`: optional list of profile names to merge before this profile.
- `secrets`: map of environment aliases to secret references. Required
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
If the selected profile needs a different account or reference for a secret,
redeclare that alias in its own `secrets` map.

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
    account: Example Preview
```

For Bitwarden Secrets Manager, object entries can set `source` instead:

```yaml
secrets:
  TOKEN:
    ref: bws://be8e0ad8-d545-4017-a55a-b02f014d4158
    source: work-secrets
```

Aliases must look like environment variable names, for example
`CLOUDFLARE_API_TOKEN`.

## Bitwarden Secrets Manager Sources

Bitwarden support uses the official `bws` CLI and a local macOS Keychain token
alias. Agent Secret v1 uses official Bitwarden cloud endpoints only and invokes
`bws` with a temporary state-disabled config pinned to
`https://vault.bitwarden.com`. It looks for `bws` at fixed common paths such as
`/opt/homebrew/bin/bws` and `/usr/local/bin/bws`. It does not resolve the helper
from the daemon `PATH`; helper binaries must either live under a stable
system-owned path or be signed by Bitwarden Inc. Install a token alias before
using Bitwarden refs:

```bash
agent-secret bitwarden secrets-manager token install --alias work
```

The install command prompts for the token with hidden terminal input. For
scripts, pipe the token with `--from-stdin`.

Project configs can declare one or more Bitwarden Secrets Manager sources:

```yaml
version: 1
sources:
  bitwarden:
    work-secrets:
      kind: secrets_manager
      token_alias: work

profiles:
  deploy:
    reason: Deploy application
    secrets:
      API_TOKEN: bws://be8e0ad8-d545-4017-a55a-b02f014d4158
```

`source` is Agent Secret terminology. It means the local Agent Secret
configuration used to resolve a secret reference. For Bitwarden Secrets
Manager, a source points at one local token alias.

Supported Bitwarden ref forms:

- `bws://<secret-uuid>`
- `bws://<source-alias>/<secret-uuid>`

If a project config has exactly one Bitwarden source, bare
`bws://<secret-uuid>` refs use it. If multiple project sources are configured,
the secret must set `source` or use the source-qualified ref form. When no
project source is configured, direct CLI and env-file refs can infer the single
local token alias installed in Keychain; multiple local token aliases require a
source-qualified ref.

The source alias and token alias are part of the secret identity used for
approval matching and in-memory caching. The access token itself is never sent
to the child process.

## Account Precedence

Agent Secret chooses the account for each secret independently:

1. Secret-level `account`.
2. Profile-level `account`.
3. Top-level `account`.
4. CLI `--account`.
5. `OP_ACCOUNT` or `AGENT_SECRET_1PASSWORD_ACCOUNT`.
6. The default personal 1Password desktop account, or the only active desktop
   account for single-account users.

The account is part of the secret identity used for resolution, reusable
approval matching, and in-memory caching. The same `op://` reference in two
different accounts is treated as two different secrets. Agent Secret does not
call the 1Password CLI for account discovery; with no override, it reads only
non-secret local 1Password desktop account metadata and auto-selects the active
personal account. If no personal account is present, it auto-selects only when
exactly one active desktop account is present.

## Exec Command Options

`agent-secret exec` accepts only argv after `--`; it does not parse shell
strings.

```bash
agent-secret exec [flags] -- COMMAND [ARG...]
```

Current flags:

- `--reason TEXT`: human-readable reason shown in the approval UI. Required
  unless the selected profile provides `reason`.
- `--secret ALIAS=REF`: explicit secret mapping. `REF` can be an `op://` or
  `bws://` reference. Repeat for multiple secrets.
- `--env-file PATH`: load dotenv-style `KEY=VALUE` entries. Values starting
  with `op://` or `bws://` become approved secret references; other values are
  passed to the child process as plain environment entries. Repeat for multiple
  files.
- `--profile NAME`: load a named profile from the project config.
- `--only ALIAS[,ALIAS...]`: filter loaded profile secrets and env-file secret
  references to selected aliases. Repeat to add more aliases. Deliberate
  one-off `--secret` references are not filtered.
- `--account ACCOUNT`: default 1Password account for references that do not
  already have a config/profile account.
- `--config PATH`: use a specific config file.
- `--cwd DIR`: run the child process from `DIR`.
- `--ttl DURATION`: approval TTL. Defaults to profile `ttl` or `2m`; allowed
  range is `10s` through `10m`.
- `--override-env`: allow approved secret aliases to replace existing
  environment variables in the child process.
- `--force-refresh`: when a reusable approval matches, refetch approved secrets
  before delivering them to the child.
- `--dry-run`: validate the request and print preflight output without starting
  the background helper, prompting for approval, resolving values, or spawning
  the child.
- `--reuse-only`: use an existing matching reusable approval or fail without
  opening a new approval prompt.
- `--allow-mutable-executable`: allow a user-owned or writable executable path
  after surfacing that trust-boundary warning in the approval UI.
- `--json`: print machine-readable preflight output. Only valid with
  `--dry-run`.
- `-h`, `--help`: print detailed `exec` help.

Unsupported by design:

- `--reuse`: reusable approvals are chosen in the approval UI.

Explicit `--secret` flags may be combined with `--profile` for one-off
additional references. In that mode, explicit secrets inherit the loaded
profile account. `--only` filters profile-loaded aliases and env-file secret
references before one-off `--secret` references are added. Invocations with
explicit `--secret` or `--env-file` sources do not load `default_profile`
unless `--profile` is provided, but still inherit a discovered or explicit
config's top-level `account`.

`--env-file` may be combined with `--profile` or `--secret`. It is intended for
migrating `op run --env-file` workflows without rewriting every caller at once:

```bash
agent-secret exec --reason "Deploy from env file" --env-file .env.deploy -- \
  npm run deploy
```

Each env file is parsed before approval. Entries whose values start with
`op://` or `bws://` become secret references. Other entries are plain child-process
environment variables and are never sent to the daemon. Later env files
override earlier files. Env-file keys override the caller environment for the
child process, and env-file secret aliases are removed from the base child
environment before approved values are injected. Use `--only` with env files
when one file contains references for multiple command surfaces, such as beta
and production deploy secrets.

1Password file attachments and Document items are supported as text
references. Use the same shape as `op read`, for example
`op://Example/GitHub App/key.pem`.
The resolved file contents are injected into the alias environment variable
with multiline text preserved. Agent Secret does not create a temp file for the
value and env-var delivery does not support binary attachments with NUL bytes.

## Session Commands

Sessions approve one bag of secret references, keep the resolved values in
Agent Secret's background helper memory, and let later child commands consume
that bag only through `agent-secret with-session`. Use them for bounded
workflows where a user
approves several secrets once and subsequent commands need those secrets in
different combinations.

```bash
agent-secret session create [flags]
agent-secret with-session SESSION_ID [--cwd DIR] \
  [--only ALIAS[,ALIAS...]] [--allow-mutable-executable] -- COMMAND [ARG...]
agent-secret session list [--json]
agent-secret session destroy [--json] SESSION_ID
```

`session create` accepts the same secret-source flags as `exec`:

- `--reason TEXT`
- `--secret ALIAS=REF`
- `--env-file PATH`
- `--profile NAME`
- `--only ALIAS[,ALIAS...]`
- `--account ACCOUNT`
- `--config PATH`
- `--cwd DIR`
- `--ttl DURATION`
- `--override-env`
- `--json`

It also accepts `--max-reads COUNT`, which limits the number of successful
`with-session` reads. The default is `1`; the allowed range is `1` through
`20`.

For example, approve a project profile plus a one-off CLI reference, then use
different aliases for different commands:

```bash
agent-secret session create \
  --profile terraform-cloudflare \
  --secret STATE_TOKEN=op://Example/Terraform\ State/token \
  --max-reads 3 \
  --json

agent-secret with-session asess_123 --only CLOUDFLARE_API_TOKEN -- \
  terraform plan

agent-secret with-session asess_123 \
  --only CLOUDFLARE_API_TOKEN,STATE_TOKEN \
  -- terraform apply
```

`session create` returns the opaque session ID needed by `with-session`, plus
non-secret metadata. It does not print secret values. `session list` reports
active-session metadata without session IDs or working directories, so listing
cannot be used to discover another workflow's `with-session` handle. Without
`--only`, `with-session` injects every approved session alias into that child
process. With `--only`, it injects only the requested approved aliases. If any
requested alias was not in the approved session, Agent Secret fails before
spawning the child command.

`with-session` accepts `--cwd DIR`, `--only ALIAS[,ALIAS...]`, and
`--allow-mutable-executable`. The `--cwd` value defaults to the caller's current
directory and must match the session working directory.

Sessions are background-helper-memory only. They expire when TTL passes, the
read count is exhausted, `agent-secret session destroy SESSION_ID` succeeds, or
the helper stops. V1 sessions intentionally do not expose raw socket value
reads, credential-helper protocols, or long-lived interactive shells.

## Agent-Friendly Introspection

Agents can ask Agent Secret for a machine-readable summary of the current CLI
surface:

```bash
agent-secret agent-context --json
```

The output includes command names, flags, output formats, safety conventions,
config discovery filenames, and any profiles found in the current project. It
does not resolve secret references or print secret values.

Use `--config PATH` when the config is not discoverable from the current
directory:

```bash
agent-secret agent-context --config ./agent-secret.yml --json
```

## Profile Inspection

Use `profile list` and `profile show` when an agent needs to discover available
project profiles without parsing YAML itself:

```bash
agent-secret profile list --json
agent-secret profile show --json terraform-cloudflare
```

If `profile show` is called without a profile name, it shows the config's
`default_profile`. Output contains resolved aliases, secret references, account
metadata, reason, TTL, and includes. It never fetches or prints secret values.

Text output is available for humans:

```bash
agent-secret profile list
agent-secret profile show terraform-cloudflare
```

## Item Metadata Inspection

Use `agent-secret item describe` when an agent has an item-level reference but
does not know which field labels are available yet:

```bash
agent-secret item describe "op://Example Infra/Database Credentials"
agent-secret item describe --format env-refs --prefix DATABASE \
  "op://Example Infra/Database Credentials"
```

The command accepts `op://vault/item` and `op://vault/item/*`. It requires local
approval, performs one metadata lookup, and prints no field values. Output may
include item title, category, field labels, field IDs, field types, section
names, concealment flags, account, and canonical field references.

Formats:

- `text`: human-readable metadata table.
- `json`: machine-readable item metadata.
- `env-refs`: shell-quoted `ALIAS='op://...'` field-reference mappings.

`--account` overrides account selection for this inspection command. Without
`--account`, the command uses the discovered project config account, then
environment account overrides, then default desktop account detection.

## Other Commands

Background helper repair:

```bash
agent-secret repair [--json]
```

Low-level daemon diagnostics:

```bash
agent-secret daemon status [--json]
agent-secret daemon start [--json]
agent-secret daemon stop [--json]
```

Diagnostics:

```bash
agent-secret doctor [--json]
```

`doctor` prints non-secret setup diagnostics. It should not require or resolve
real secret values.

CLI installation:

```bash
agent-secret version [--json]
agent-secret install-cli [--json]
agent-secret install-cli --bin-dir "$HOME/.local/bin"
agent-secret install-cli --force
```

`install-cli` creates or repairs the user-level `agent-secret` command symlink.
After a successful install, it also tries to refresh the local background
helper. Helper repair failures are warnings; rerun `agent-secret repair` if the
helper needs manual attention.
It leaves an existing target symlink in place, refuses directories, and replaces
an existing regular file or different symlink only when `--force` is passed.

Skill installation:

```bash
agent-secret skill-install [--json]
agent-secret skill-install --skills-dir "$HOME/.agents/skills"
agent-secret skill-install --force
```

`skill-install` creates or repairs the user-level Agent Secret coding-agent
skill symlink:

```text
~/.agents/skills/agent-secret -> /Applications/Agent Secret.app/Contents/Resources/skills/agent-secret
```

The bundled skill covers general usage, project profiles, env-file use, safe
verification, and migration from direct 1Password CLI access.
The installer leaves an existing target symlink in place, refuses directories,
and replaces an existing regular file or different symlink only when `--force`
is passed.
