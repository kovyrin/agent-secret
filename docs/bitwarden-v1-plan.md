# Bitwarden Secrets Manager V1 Plan

Status: draft planning note.

Last reviewed: 2026-06-06.

Tracking issue: [#294](https://github.com/kovyrin/agent-secret/issues/294).

Related provider work:
[#285](https://github.com/kovyrin/agent-secret/pull/285).

## Decision

Agent Secret should add Bitwarden support first as a Bitwarden Secrets Manager
secret-value resolver. It should not start with Bitwarden Password Manager vault
parity.

The first supported Bitwarden reference should be an exact Secrets Manager
secret ID:

```text
bws://<uuid>
```

There is no resource-type path segment in v1. The `bws` scheme already means
Bitwarden Secrets Manager, and v1 only resolves one Bitwarden resource type:
secret values. If Agent Secret later needs to address other Bitwarden resources,
that should be a deliberate v2 grammar decision rather than a v1 placeholder.

That bare ref form is valid whenever Agent Secret can infer exactly one
Bitwarden Secrets Manager source configuration for the request. If more than
one Bitwarden Secrets Manager source could satisfy the ref, the user must
disambiguate with a source-qualified ref or a profile secret mapping:

```text
bws://work-secrets/<uuid>
```

"Source" is the user-facing Agent Secret term in this plan. It means a
configured place Agent Secret can read secrets from. For Bitwarden Secrets
Manager, the source alias points at one local token alias and, optionally,
custom API and identity endpoints.

The resolver should use an operator-installed Bitwarden Secrets Manager access
token stored under Agent Secret control in macOS Keychain. The approved child
command must never receive that access token. It should receive only the
approved secret values through the existing `agent-secret exec` environment
delivery path.

The initial runtime should prefer a user-installed `bws` CLI adapter over
embedding Bitwarden's Go SDK. The SDK path needs an explicit license and
packaging decision before Agent Secret links or redistributes Bitwarden SDK
artifacts.

## Product Shape

Bitwarden support should extend normal `agent-secret exec`:

```bash
agent-secret exec --profile deploy -- deploy-tool
```

Bitwarden-specific commands should be setup and diagnostics commands,
not a separate command execution mode:

```bash
agent-secret bitwarden secrets-manager token install --alias work
agent-secret bitwarden secrets-manager token status --alias work
agent-secret bitwarden secrets-manager token remove --alias work
agent-secret doctor bitwarden
```

This is intentionally different from the GCP provider shape in #285. GCP
brokers short-lived cloud capabilities and sessions, so it needs
`agent-secret gcp exec` and session surfaces. Bitwarden Secrets Manager is a
secret-value source, so it should feed the existing approval-backed environment
injection path.

## Why Secrets Manager First

Bitwarden has two relevant products with different trust boundaries.

Bitwarden Secrets Manager has machine-account access tokens, explicit secret
IDs, projects, a `bws secret get <secret-id>` path, and SDK/CLI surfaces
designed for automation. That fits Agent Secret's existing model:

- parse a concrete reference before approval;
- show value-free metadata to the operator;
- fetch only after approval;
- inject values into the approved child environment;
- write value-free audit records;
- reuse cached values only inside the approval TTL and policy scope.

Bitwarden Password Manager vault automation depends on `bw` CLI unlock state,
`BW_SESSION`, or `bw serve`. The session key can decrypt vault data, and
`bw serve` exposes a local Vault Management API. Those surfaces do not match
the current 1Password Desktop integration boundary and should not be presented
as equivalent in v1.

Bitwarden terms used by this plan:

- machine account: a Bitwarden Secrets Manager identity used for automation;
- access token: the credential Agent Secret stores locally in Keychain and uses
  only to call Bitwarden after approval;
- project: a Bitwarden grouping mechanism for Secrets Manager secrets;
- secret: a Bitwarden Secrets Manager record containing a key, value, metadata,
  and a stable secret ID.

Agent Secret terms used by this plan:

- source: a configured secret source, such as 1Password or Bitwarden Secrets
  Manager. This is Agent Secret terminology, not Bitwarden terminology; do not
  expect to find "source" as a Bitwarden object in the Bitwarden UI or docs;
- source alias: a local label, such as `work-secrets`, that selects a
  source configuration;
- account: the existing 1Password account selector; v1 should not reuse this
  field for Bitwarden;
- token alias: a local Keychain label, such as `work`, for a Bitwarden access
  token.

## V1 Scope

V1 should include:

- exact `bws://<uuid>` reference parsing;
- source-qualified `bws://<source-alias>/<uuid>` parsing for
  ambiguous source sets;
- provider-aware request, approval, audit, cache, and reuse identity;
- Keychain-backed storage for Bitwarden Secrets Manager access token aliases;
- a composite resolver that routes `op://` to 1Password and `bws://` to
  Bitwarden Secrets Manager;
- a CLI-backed `bws` adapter that invokes a user-installed `bws` binary after
  approval;
- project config support for top-level Bitwarden source aliases;
- dry-run and approval output that shows source, secret ID, token alias, and
  delivered env alias without resolving values;
- `agent-secret exec --profile ...` support for Bitwarden Secrets Manager refs;
- offline tests with a fake Bitwarden resolver and fake `bws` executable;
- one opt-in live smoke path for a synthetic test-only Bitwarden secret.

V1 should not include:

- Bitwarden Password Manager vault item support;
- `bw serve`;
- `bws run`;
- secret lookup by name or key;
- project-wide secret sync;
- wildcard refs;
- list/search APIs in normal `exec` resolution;
- bundling or linking Bitwarden SDK or CLI artifacts;
- profile-level source defaults;
- silently choosing between multiple same-source configurations;
- storing `BWS_ACCESS_TOKEN`, `BW_SESSION`, or secret values in project config;
- commands that print Bitwarden token material or secret values.

## Reference Model

The current request layer is still `op://`-shaped. V1 Bitwarden work should
introduce a provider-aware secret reference model before adding the resolver.

Internal parsed refs should carry:

- raw ref, as supplied by the user;
- provider, such as `onepassword` or `bitwarden-secrets-manager`;
- kind, initially `secret_value`;
- display ref for approval UI and audit;
- policy ref for cache and reusable approval matching;
- provider-specific parsed fields.

For Bitwarden Secrets Manager v1:

```text
raw:        bws://<secret-uuid>
provider:   bitwarden-secrets-manager
kind:       secret_value
policy_ref: bws://<secret-uuid>
secret_id:  <secret-uuid>
```

When the ref includes a source alias:

```text
raw:            bws://work-secrets/<secret-uuid>
source_alias:   work-secrets
provider:       bitwarden-secrets-manager
kind:           secret_value
policy_ref:     bws://work-secrets/<secret-uuid>
secret_id:      <secret-uuid>
```

Only UUID secret IDs are accepted. Human-readable names are display metadata
only and must not be policy identity in v1.

## Source Identity

The cache, reusable approval, audit, and resolver identity must distinguish:

- provider;
- source alias;
- 1Password account or Bitwarden token alias;
- self-hosted API and identity endpoint profile;
- normalized reference;
- delivered environment alias.

Source inference rules should be strict:

- `op://...` refs route to 1Password.
- `bws://<uuid>` refs first consider Bitwarden Secrets Manager sources from the
  selected project config.
- if the selected project config has exactly one Bitwarden Secrets Manager
  source, use it.
- if the selected project config has no Bitwarden Secrets Manager source and
  exactly one Bitwarden Secrets Manager token alias is installed locally,
  synthesize a default official Bitwarden source from that token alias.
- `bws://<source-alias>/<uuid>` refs route to the named Bitwarden
  Secrets Manager source.
- a bare `bws://<uuid>` ref fails before approval when zero or multiple
  Bitwarden Secrets Manager sources are available after applying the fallback
  rule above.
- a source-qualified ref fails before approval if the alias does not name a
  configured or locally synthesized Bitwarden Secrets Manager source.
- project config sources take precedence over local token fallback. A local
  token alias must not silently override a project-selected source.

The existing `account` field should remain the 1Password account selector. Do
not reuse it for Bitwarden in v1. Bitwarden's native automation identity is a
machine account and access token, and Agent Secret stores that access token
under a local token alias. Reusing `account` for that alias would make mixed
1Password and Bitwarden profiles ambiguous because the existing top-level and
profile-level `account` defaults already apply to 1Password refs.

Bitwarden config should use `source` for the user-facing selector. In this
context, a "Bitwarden source" means "an Agent Secret source whose type is
Bitwarden Secrets Manager." V1 source aliases should live in the top-level
`sources` block. Profile-level source defaults should wait until there is real
usage pressure, because they make mixed-source profiles harder to inspect and
reason about.

## Config Shape

The recommended profile config shape is:

```yaml
version: 1

sources:
  bitwarden:
    work-secrets:
      kind: secrets_manager
      token_alias: work

profiles:
  deploy:
    reason: Deploy with Bitwarden-managed API token
    ttl: 5m
    secrets:
      API_TOKEN:
        ref: bws://<secret-uuid>
        source: work-secrets
```

When a config file has exactly one Bitwarden Secrets Manager source, the
profile secret mapping may omit `source`:

```yaml
version: 1

sources:
  bitwarden:
    work-secrets:
      kind: secrets_manager
      token_alias: work

profiles:
  deploy:
    reason: Deploy with Bitwarden-managed API token
    secrets:
      API_TOKEN: bws://<secret-uuid>
```

The schema should allow scalar refs to remain valid for existing `op://` users:

```yaml
profiles:
  deploy:
    secrets:
      API_TOKEN: op://Example/Deploy/api-token
```

For project profiles, mapping-form `bws://` entries are required only when the
profile or config has multiple Bitwarden Secrets Manager source
configurations. Direct CLI and env-file refs use the same inference rules:
`bws://<uuid>` is valid when unambiguous, and
`bws://<source-alias>/<uuid>` is required when multiple Bitwarden
Secrets Manager sources are available.

When there is no project config source, direct CLI and env-file refs may use a
single locally installed token alias as the default official Bitwarden source:

```bash
agent-secret bitwarden secrets-manager token install --alias work

agent-secret exec \
  --reason "Use test Bitwarden secret" \
  --secret API_TOKEN=bws://<secret-uuid> \
  -- python3 -c 'import hashlib, os; print(hashlib.sha256(os.environ["API_TOKEN"].encode()).hexdigest())'
```

If more than one local token alias is installed, the direct ref must name the
source alias:

```bash
agent-secret exec \
  --reason "Use work Bitwarden secret" \
  --secret API_TOKEN=bws://work/<secret-uuid> \
  -- python3 -c 'import hashlib, os; print(hashlib.sha256(os.environ["API_TOKEN"].encode()).hexdigest())'
```

## Token Lifecycle

V1 should add explicit Bitwarden Secrets Manager token commands:

```bash
agent-secret bitwarden secrets-manager token install --alias work
agent-secret bitwarden secrets-manager token status --alias work
agent-secret bitwarden secrets-manager token remove --alias work
```

Token requirements:

- token values are read with hidden terminal input by default;
- token values can be piped with `--from-stdin` for scripts;
- token values are stored in macOS Keychain under an Agent Secret service name;
- token aliases are local operator labels, not project secrets;
- token aliases are normalized labels, such as `work`, `personal-secrets`, or
  `fixture-prod`;
- `status` reports configured or missing state without revealing the token;
- `remove` deletes local Keychain state;
- the approved child command never receives `BWS_ACCESS_TOKEN`;
- audit events never include token values or token-bearing config paths.

An optional setup-only import from a 1Password ref can be useful later:

```bash
agent-secret bitwarden secrets-manager token install \
  --alias work \
  --from-ref op://Example/BitwardenSecretsManager/access-token
```

That should not be in the first slice. When added, it should be an operator
setup command only. Runtime Bitwarden resolution must not depend on 1Password.

## CLI-Backed Resolver

The v1 resolver should be a small adapter around a user-installed `bws`
executable.

Execution flow:

1. CLI parses the request and sends value-free Bitwarden resource metadata to
   the daemon.
2. Daemon records approval requested metadata.
3. Daemon asks the approver to approve the exact command, cwd, TTL, env alias,
   source alias, token alias, and `bws://` ref.
4. After approval, daemon reads the Bitwarden access token from Keychain.
5. Daemon invokes `bws secret get <uuid> --output json` with
   `BWS_ACCESS_TOKEN` only in the helper subprocess environment.
6. Daemon parses the JSON structurally and retains only the secret value needed
   for env injection.
7. Daemon discards raw Bitwarden JSON promptly.
8. Existing grant delivery injects the approved value into the child command.
9. Audit records source metadata and outcome, never values, notes, or token
   material.

The helper environment should be isolated:

- start from an allowlist, not the daemon's full environment;
- set only `BWS_ACCESS_TOKEN` and `NO_COLOR=1` for the `bws` subprocess;
- do not pass daemon `PATH`, `HOME`, `BWS_SERVER_URL`, `BWS_CONFIG_FILE`, proxy,
  debug, or log variables;
- pass an explicit broker-owned temporary config with `state_opt_out` enabled
  and `server_base` pinned to `https://vault.bitwarden.com`;
- do not read the user's default `bws` profile, config file, or state;
- if live testing proves state is needed to avoid unacceptable auth limits,
  store it only in a broker-owned private directory keyed by source alias;
- force JSON output and no color;
- resolve the helper from an explicit absolute path or fixed system candidates,
  then require either a stable system-owned path or the official Bitwarden
  Developer ID signature before passing token material to `bws`.

`bws run` must not be used. It would create a second command execution path and
could fetch a broader secret set than the approved refs.

## Helper Trust

The daemon should treat `bws` as a helper executable with its own trust surface.

V1 requirements:

- resolve `bws` to an absolute path at daemon startup or first use;
- record helper path and version in diagnostics;
- require `bws` `2.1.0` or newer for the first implementation, then verify
  behavior with command-level checks rather than trusting only the version
  string;
- reject missing or non-executable helper paths;
- accept stable system-owned helper paths and Bitwarden Inc Developer ID signed
  helper binaries, including normal Homebrew installs under `/opt/homebrew`;
- do not pass secret values or access tokens to shell strings;
- invoke `bws` as argv, not through `sh -c`;
- bound helper runtime with context cancellation and request expiry.

Future hardening can reuse existing executable identity primitives if the
helper trust boundary becomes a policy input.

## Approval UI And Audit

Approval UI should show:

- source: Bitwarden Secrets Manager;
- operation: read secret value;
- source alias, such as `work-secrets`;
- token alias, such as `work`;
- API/identity host label for self-hosted setups;
- secret ID;
- delivered environment alias;
- `bws` helper path and version;
- command, resolved executable, executable identity, cwd, reason, TTL, and
  override behavior.

Audit events should include:

- source: `bitwarden-secrets-manager`;
- operation: `secret_resolve_started`, `secret_resolve_completed`, or failure;
- source alias;
- token alias;
- endpoint profile label;
- secret ID;
- delivered env alias;
- helper path and version;
- approval ID and request ID;
- command metadata already used for `exec`.

Audit events must not include:

- access tokens;
- secret values;
- secret notes;
- full raw `bws` JSON;
- raw helper environment;
- token-bearing file paths.

## Error Handling

Bitwarden resolver errors must be value-free and actionable:

- missing token alias;
- missing `bws` executable;
- unsupported `bws` version;
- invalid `bws://` ref;
- Bitwarden auth failed;
- Bitwarden secret not found or not accessible;
- Bitwarden response missing `value`;
- Bitwarden response was not valid JSON;
- request expired before provider fetch completed.

Do not surface raw `bws` output directly. If stderr is needed for diagnosis,
sanitize it first and include only value-free details.

## SDK Path

Bitwarden's Go SDK is a plausible later implementation backend, but it should
not be a v1 dependency.

Known concerns:

- the Go wrapper requires cgo/FFI to the Rust SDK;
- cgo changes CI, release, signing, notarization, and Homebrew packaging;
- the `sdk-sm` repository uses the Bitwarden Software Development Kit License
  Agreement, not a normal permissive library license;
- license terms need review before Agent Secret links, vendors, bundles, or
  redistributes SDK artifacts.

SDK embedding is ruled out for v1. If the SDK path is approved later, it should
replace only the provider adapter. The public ref grammar, approval model,
token storage, audit contract, and tests should stay the same.

## Compatibility

V1 should claim support for official Bitwarden Secrets Manager only. The plan
should not support custom `api_url` or `identity_url` settings, because project
config must not be able to redirect token-bearing `bws` requests. Official
self-hosted Bitwarden deployments should be tracked as a later compatibility
effort with a trusted endpoint model and live smoke fixture.

Vaultwarden should be explicitly unsupported in v1. If Vaultwarden support is
possible later, it should be tracked as a separate compatibility effort with
its own live tests.

## Password Manager Later

Password Manager support should be a separate experimental provider after
Secrets Manager is stable.

Possible future refs:

```text
bw://items/<item-uuid>/login/password
bw://items/<item-uuid>/login/username
bw://items/<item-uuid>/notes
bw://items/<item-uuid>/fields/<field-id>
```

Future rules:

- exact item IDs only;
- no name or search refs;
- no `bw serve` in the first Password Manager version;
- no `BW_SESSION` in project config, daemon environment, or child environment;
- session state, if supported, is daemon-held, in memory, and short-lived;
- metadata inspection is approval-gated because `bw get item` may fetch
  decrypted value-bearing JSON.

This should be documented as weaker than the current 1Password Desktop trust
boundary unless Bitwarden exposes a comparable desktop integration.

## Implementation Plan

### Phase 0: Documentation And Contracts

- Land this planning doc.
- Add a dependency note stating that Bitwarden SDK/CLI artifacts must not be
  bundled or linked until license and packaging review is complete.
- Decide the v1 config schema for source aliases.
- Document that v1 disables `bws` state by default and can add broker-owned
  state only if live testing proves it is needed.

### Phase 1: Source Reference Model

- Add a provider-aware parsed ref type.
- Keep existing `op://` behavior and error compatibility where possible.
- Add `bws://<uuid>` parser and tests.
- Update request DTOs so provider refs are not forced into vault/item/field
  fields.
- Include provider, source alias, and account or token alias in cache and
  reusable approval identity.
- Add a composite daemon resolver and keep `internal/opresolver` unchanged.
- Extend dry-run JSON with source resource metadata.

### Phase 2: Bitwarden Token Store

- Add Keychain token storage for Bitwarden Secrets Manager token aliases.
- Add `agent-secret bitwarden secrets-manager token install/status/remove`.
- Support hidden interactive token install and `--from-stdin` for scripts;
  defer `--from-ref`.
- Add value-redaction tests around token setup commands.
- Add `doctor` diagnostics for token alias configuration and `bws`
  availability.

### Phase 3: Fake Resolver Integration

- Add a fake Bitwarden resolver for broker tests.
- Prove approval-before-fetch.
- Prove denial, expiry, and audit preflight do not call the resolver.
- Prove cache and reusable approvals do not cross source aliases.
- Prove dry-run does not resolve values.

### Phase 4: CLI-Backed `bws` Resolver

- Add `internal/bwsmresolver` or equivalent.
- Resolve approved `bws://<uuid>` refs through `bws secret get`.
- Invoke helper as argv with isolated environment.
- Parse JSON and retain only the value.
- Sanitize provider errors.
- Add fake helper tests for env isolation and response parsing.

### Phase 5: Opt-In Live Smoke

- Add an opt-in test requiring a synthetic Bitwarden Secrets Manager token and
  secret ID.
- Verify one approved secret value reaches only the child environment.
- Verify logs, audit events, help, and diagnostics do not include the token or
  secret value.
- Skip live tests by default in CI.

## Test Plan

Parser tests:

- valid `bws://<uuid>`;
- valid `bws://<source-alias>/<uuid>`;
- missing UUID;
- non-UUID secret ID;
- unexpected path segment;
- unknown source alias;
- wildcard refs;
- names or search strings;
- whitespace and normalization failures.

Request and policy tests:

- Bitwarden refs appear in approval payloads without values;
- bare Bitwarden refs resolve through the single project-configured Bitwarden
  source;
- bare Bitwarden refs resolve through the single local token alias only when no
  project Bitwarden source exists;
- project-configured sources take precedence over local token aliases;
- bare Bitwarden refs fail before approval when multiple Bitwarden source
  configurations exist;
- bare Bitwarden refs fail before approval when multiple local token aliases
  exist and no project source selects one;
- source-qualified refs select the named source;
- denied requests do not fetch;
- expired requests do not fetch;
- dry-run does not fetch;
- force refresh refetches only approved refs;
- reusable approval matching includes provider, source alias, and token alias;
- cache identity includes provider, source alias, and token alias.

Token store tests:

- install reads from hidden prompt or stdin without echoing token;
- status does not print token;
- remove deletes the alias;
- missing alias produces a value-free error;
- token aliases are normalized and validated.

CLI adapter tests:

- fake `bws` sees `BWS_ACCESS_TOKEN`;
- approved child does not see `BWS_ACCESS_TOKEN`;
- helper is invoked without a shell;
- mutable helper paths are rejected before token material is passed to `bws`;
- helper receives only the approved secret ID;
- invalid JSON fails safely;
- missing `value` fails safely;
- stderr is sanitized;
- helper timeout respects request expiry.

Audit and output tests:

- no token values in audit;
- no secret values in audit;
- no raw provider JSON in audit;
- no token values in help or diagnostics;
- source metadata is present and useful.

Live smoke:

- read a synthetic test-only secret by UUID;
- inject it into a child command that checks only hash/length or a sentinel
  comparison without printing the value;
- verify cleanup and audit behavior.

## Sources

- [Bitwarden Password Manager CLI docs](https://bitwarden.com/help/cli/)
- [Bitwarden Password Manager APIs docs][bitwarden-apis]
- [Bitwarden Secrets Manager CLI docs][bws-cli]
- [Bitwarden Secrets Manager SDK docs][bws-sdk]
- [Bitwarden sdk-sm repository](https://github.com/bitwarden/sdk-sm)
- [Bitwarden Go SDK README][bws-go-readme]
- [Bitwarden sdk-sm license](https://github.com/bitwarden/sdk-sm/blob/main/LICENSE)
- [Bitwarden support tracking issue][tracking-issue]
- [GCP provider PR](https://github.com/kovyrin/agent-secret/pull/285)

[bitwarden-apis]: https://bitwarden.com/en-gb/help/bitwarden-apis/
[bws-cli]: https://bitwarden.com/en-gb/help/secrets-manager-cli/
[bws-go-readme]: https://github.com/bitwarden/sdk-sm/tree/main/languages/go
[bws-sdk]: https://bitwarden.com/help/secrets-manager-sdk/
[tracking-issue]: https://github.com/kovyrin/agent-secret/issues/294
