# GCP-Backed Secret Broker Plan

Status: draft planning note.

Last reviewed: 2026-05-27.

## Decision

Agent Secret will add a GCP provider for the existing local approval broker. It
will not become a new cloud secret-management product.

The GCP provider ships in layers:

1. Short-lived Google Cloud capabilities for a single approved command.
2. Approved GCP sessions for multi-command agent workflows.
3. Explicit Google Secret Manager version resolution through the same approval,
   TTL, audit, and command-binding model used for 1Password refs.

The implementation should land `gcp exec` first because it is the smallest
proof of the bootstrap, service-account impersonation, token delivery, Cloud SDK
isolation, cleanup, and audit path. Session support should follow immediately.
For benchmark migration, the first useful product milestone is not merely
"single command works"; it is "`gcp exec` proves minting and `gcp session` lets
benchmark workflows stop relying on ambient `gcloud auth`."

Do not start by replacing 1Password, importing service account keys, or teaching
agents to run `gcloud auth login`. Those paths preserve too much standing
machine-local privilege and make Agent Secret responsible for broad cloud IAM
behavior before the local trust boundary is settled.

## Objective

Agent Secret approves GCP access only for a specific command or session, exact
GCP capability or secret version, human-readable reason, working directory, and
TTL.

## Motivation

The current local workflow is:

1. The user runs `gcloud auth login` or `gcloud auth application-default login`.
2. Google credentials are written into the user's local Cloud SDK or ADC state.
3. Any same-user process that can read those files can use the user's GCP access
   until the credentials expire or refresh.

That is a poor fit for coding agents. It turns one approved task into broad
ambient machine state.

## Relevant Google Cloud Primitives

Google Cloud already has primitives that fit this direction:

- [Service account impersonation](https://cloud.google.com/iam/docs/service-account-impersonation)
  lets an authenticated principal obtain short-lived credentials for a service
  account. Google documents this as a way to temporarily grant elevated access
  and to run local development as a service account.
- [`generateAccessToken`](https://cloud.google.com/iam/docs/create-short-lived-credentials-direct)
  creates OAuth 2.0 access tokens for service accounts. The token has no refresh
  token, so the caller must impersonate again after expiry. The default maximum
  lifetime is 1 hour, but Agent Secret should cap it to the local approval TTL.
- [`gcloud --access-token-file`](https://cloud.google.com/sdk/gcloud/reference)
  lets one `gcloud` invocation authenticate with an access token file and ignore
  active account credentials.
- [Cloud SDK configurations](https://cloud.google.com/sdk/gcloud/reference/topic/configurations)
  are normally stored under the user's home directory, but the location can be
  overridden with `CLOUDSDK_CONFIG`.
- [Cloud SDK startup behavior](https://cloud.google.com/sdk/gcloud/reference/topic/startup)
  maps each `gcloud` property to a `CLOUDSDK_SECTION_PROPERTY` environment
  variable. That makes `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE` a candidate for nested
  `gcloud` calls, but Agent Secret should still prove this with real local
  smokes before relying on it.
- [Secret Manager Secret Accessor](https://cloud.google.com/secret-manager/docs/access-secret-version)
  is the role needed to access a secret version payload.
- [Secret Manager access control guidance](https://docs.cloud.google.com/secret-manager/docs/access-control)
  recommends granting access at the lowest resource level. Granting
  `roles/secretmanager.secretAccessor` on one secret limits access to that
  secret; granting it on a project grants access to every secret in that project.
- [Secret Manager best practices](https://docs.cloud.google.com/secret-manager/docs/best-practices)
  recommend least privilege, secret-level IAM where useful, and pinned secret
  versions instead of relying on `latest` for deployed configuration.
- [Secret Manager audit logging](https://cloud.google.com/secret-manager/docs/audit-logging)
  records `AccessSecretVersion` as a data access log event when data access logs
  are enabled.
- [`gcloud compute ssh`](https://cloud.google.com/sdk/gcloud/reference/compute/ssh)
  is a wrapper around `ssh` that can generate SSH keys and ensure the user's
  public SSH key is present in project metadata. OS Login has a separate
  [`ssh-keys`](https://cloud.google.com/sdk/gcloud/reference/compute/os-login/ssh-keys)
  surface. Benchmark VM access must test these behaviors early because access
  tokens alone might not cover the whole workflow.

## Bootstrap Auth Model

GCP support has a separate root trust problem: something must be allowed to call
IAM Credentials `generateAccessToken`.

Agent Secret should not use the user's existing `gcloud auth login`,
application-default credentials, or normal Cloud SDK configuration as that
bootstrap. Reusing ambient Google auth recreates the standing local credential
problem the feature is meant to remove.

Selected local direction:

1. `agent-secret gcp auth login` asks the trusted app/daemon to start a Google
   OAuth flow for the signed Agent Secret app using the bundled Agent Secret
   Google Desktop OAuth client.
2. The app/daemon owns browser launch, callback handling, authorization-code
   exchange, and token-state handling.
3. The long-lived refresh capability is stored in macOS Keychain under an Agent
   Secret service name.
4. Keychain access is tied to the trusted Agent Secret app/daemon identity.
5. The Google principal behind that grant has only the ability to impersonate
   explicitly approved agent service accounts.
6. Each service account carries the actual benchmark, deploy, or read-only IAM
   permissions.
7. Agent Secret never exports the bootstrap credential to child processes.
8. The CLI never handles refresh-capable token state; it is only the user-facing
   control surface for login, status, and logout.

This treats the bootstrap credential as app-owned OAuth state, not as a normal
human-managed secret ref. Normal 1Password-backed `op://` refs remain the
preferred path for ordinary secret values, but GCP token minting should not ask
agents to fetch or hold the Google bootstrap credential.

The bundled OAuth client is product configuration and app identity, not a GCP
permission boundary. It should be owned by the Agent Secret project and verified
with Google so normal operators do not need to create, export, or share OAuth
client JSON. Desktop OAuth client material is expected to be extractable from an
installed app, so security must come from PKCE, the user's Google login, local
Keychain storage, Token Creator IAM bindings, and the impersonated service
account's IAM policy.

Bootstrap OAuth should request the smallest scopes needed to authenticate the
operator and call IAM Credentials:

- `openid`
- `https://www.googleapis.com/auth/userinfo.email`
- `https://www.googleapis.com/auth/iam`

This is separate from the access-token scopes requested for the impersonated
service account. Profile access-token scopes remain explicit and non-empty;
`https://www.googleapis.com/auth/cloud-platform` may still be the practical
service-account token scope for many `gcloud` workflows, but it should not be
used for the human bootstrap grant.

Agent Secret must support more than one Google bootstrap identity on the same
machine. Keychain entries should be keyed by Google identity or an explicit
operator-defined alias, and GCP profiles should pin the intended bootstrap
identity separately from the impersonated service account:

```yaml
profiles:
  beta-logs:
    reason: Inspect beta logs
    ttl: 5m
    gcp:
      google_account: work
      project: fixture-beta
      service_account: agent-beta-logs@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
```

Approval, cache, and audit metadata should include the Google bootstrap identity
alias and the impersonated service account. Reusable approvals and cached tokens
must not cross Google bootstrap identities, even when project, service account,
scopes, and command match.

Custom OAuth client overrides are an escape hatch, not the normal operator
path. They are useful when an organization requires an internal Google
Workspace OAuth app, custom consent-screen branding, or a controlled client
lifecycle. The intended override UX is explicit install/list/remove commands
that store client material under Agent Secret control:

```bash
agent-secret gcp oauth-client install \
  --name fixture \
  --from-file ~/Downloads/client_secret_....json

agent-secret gcp oauth-client install \
  --name fixture \
  --from-ref op://Fixture/AgentSecretGCP/desktop-client-json

agent-secret gcp auth login \
  --oauth-client fixture \
  --google-account work \
  --expected-email you@fixture.app
```

The `--from-file` path imports a Google Desktop OAuth client JSON downloaded
from Google Auth Platform. The `--from-ref` path resolves the same JSON from
1Password as an operator setup action, then stores the parsed client locally; it
does not expose the OAuth client JSON to agents and does not make 1Password the
runtime source of Google bootstrap refresh tokens. Development-only daemon
environment variables may remain as a low-level escape hatch, but they should
not be the documented team workflow.

Other future options:

- Workforce or Workload Identity Federation may become cleaner for organization
  environments, but it should not block the local MVP.
- A hosted broker is a separate product direction and should stay out of the
  local-first MVP.

Keychain implementation questions remain:

- exact Keychain access-control attributes for the signed app and daemon;
- how `agent-secret gcp auth status` reports setup health without exposing token
  details;
- how `agent-secret gcp auth logout` revokes local Keychain state and, where
  practical, remote Google refresh grants.

## Product Shape

### Layer 1: GCP Capability Broker

This layer brokers temporary Google credentials for commands that need to call
GCP APIs. It has two delivery modes: one-command `gcp exec` and multi-command
`gcp session` / `gcp with-session`.

GCP uses an explicit top-level command group for the MVP:
`agent-secret gcp exec`, `agent-secret gcp session create`,
`agent-secret gcp with-session`, and `agent-secret gcp auth ...`. GCP has
provider-specific auth, Cloud SDK isolation, token files, sessions, and
diagnostics; keeping those surfaces explicit makes the trust boundary visible.
Normal `agent-secret exec` can learn provider resources later after the GCP path
is stable.

#### One-Command `gcp exec`

This is the first implementation target because it proves the provider,
approval, token minting, Cloud SDK isolation, cleanup, and audit path with the
smallest new surface area. It is an implementation milestone, not the end of the
benchmarking migration; multi-command session support comes next.

Example:

```bash
agent-secret gcp exec \
  --profile beta-logs \
  --reason "Inspect beta Cloud Run errors" \
  -- gcloud logging read 'severity>=ERROR' --project fixture-beta
```

`gcp exec` may be profile-backed or fully explicit. A profile-backed request
loads GCP identity fields from the project config. An ad hoc request without a
config-backed profile is allowed for one-command access, but it must provide all
sensitive GCP identity and approval fields explicitly: Google bootstrap identity
alias, intended project, service account, scopes, TTL, and reason. This keeps
live smokes and one-off debugging possible without weakening the reusable
session model.
Ad hoc `gcp exec` approvals may be reusable, but only when the full normalized
request snapshot matches. Reuse must include Google bootstrap identity alias,
intended project, service account, scopes, TTL, delivery mode, resolved
executable, command argv, cwd, and reason. A change to any of those fields must
prompt again.

Ad hoc sketch:

```bash
agent-secret gcp exec \
  --google-account work \
  --project fixture-beta \
  --service-account agent-beta-logs@fixture-beta.iam.gserviceaccount.com \
  --scope https://www.googleapis.com/auth/cloud-platform \
  --ttl 5m \
  --reason "Inspect beta Cloud Run errors" \
  -- gcloud logging read 'severity>=ERROR' --project fixture-beta
```

Profile sketch:

```yaml
version: 1

profiles:
  beta-logs:
    reason: Inspect beta logs
    ttl: 5m
    gcp:
      google_account: work
      project: fixture-beta
      service_account: agent-beta-logs@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
```

The approval prompt should show:

- provider: GCP
- operation: mint access token
- profile default or intended project
- service account
- OAuth scopes
- IAM permissions: determined by the service account and not verified by Agent
  Secret
- requested token lifetime
- command, resolved executable, executable identity, and cwd
- reason and reuse policy

Example approval context:

```text
Command: gcloud logging read ...
Project: fixture-beta
Service account: agent-beta-logs@fixture-beta.iam.gserviceaccount.com
OAuth scope: https://www.googleapis.com/auth/cloud-platform
IAM permissions: determined by this service account; not verified by Agent Secret
```

The prompt must not imply that OAuth scopes or the displayed command prove the
full cloud permission boundary. The service account's IAM policy is the real GCP
permission boundary, and Agent Secret does not perform live IAM policy analysis
in the MVP.

Access-token scopes are required in v1 for both profile-backed and ad hoc GCP
requests. `cloud-platform` will often be the practical `gcloud` scope, but Agent
Secret should not make it an implicit default. A broad OAuth scope is a broad
token audience, even when IAM is the real permission boundary, and it should be
visible in profile config, CLI flags, approval prompts, dry-run output, and audit
events. The schema should support one or more scopes from day one. Profiles use
a `scopes` list, ad hoc `gcp exec` accepts repeated `--scope` flags, and
validation rejects an empty scope list. Scope order should not be significant
for approval reuse, token cache keys, or session token cache keys: normalize
scopes by trimming, validating, deduplicating, and sorting them before building
the approved snapshot. Approval UI, dry-run JSON, and audit output should show
the normalized scope list.

Profile project and resource fields are intended targets, defaults, display
metadata, and audit metadata. They are not an Agent Secret enforcement boundary
for `gcloud` commands. Agent Secret should prepare the approved environment,
such as isolated Cloud SDK state and token delivery, then run the approved
command as provided. It should not parse, reject, rewrite, or police `gcloud`
argv for project or resource consistency, because nested wrappers can change
those arguments in ways Agent Secret cannot reliably observe. The service
account's IAM policy remains the enforceable cloud boundary. Even though project
is not a hard security boundary, every v1 access-token request should include an
explicit intended project through the selected profile or an ad hoc `--project`
flag so approval and audit records are understandable.

The intended project should become the default project in the isolated Cloud SDK
configuration that Agent Secret creates for the approved command or session.
This makes normal `gcloud` commands work without repeating `--project` and keeps
the prepared environment aligned with the approval prompt. Agent Secret still
must not block, rewrite, or remove explicit `gcloud --project ...` arguments
inside the command.

`gcp exec` should not support command allowlists. The approved command argv,
resolved executable, executable identity, and cwd are still displayed, bound to
approval reuse, and audited, but profile policy should be based on the GCP
profile, Google bootstrap identity, impersonated service account, project or
resource hints, cwd or repo policy, TTL, and local approval. Command allowlists
would make repo-local wrappers brittle without becoming the real GCP permission
boundary.

Execution behavior:

1. CLI validates the command and either the selected GCP profile or the explicit
   ad hoc GCP identity fields.
2. CLI and daemon construct a normalized request snapshot containing Google
   bootstrap identity alias, project or resource hints, service account, scopes,
   cwd or repo policy, requested TTL, delivery mode, command argv, resolved
   executable, executable identity, cwd, reason, and display labels.
3. Daemon asks for local approval of that normalized snapshot.
4. Daemon obtains a short-lived service account access token from the approved
   snapshot, not by re-reading profile config after approval.
5. CLI runs the approved command with isolated Cloud SDK state.
6. Agent Secret deletes any broker-owned compatibility files after the command
   exits and clears daemon-held token material when the approval expires.

The approved `gcp exec` snapshot is the source of truth for the command. Later
edits to `agent-secret.yml` must not change the service account, scopes, project
or resource hints, TTL, delivery mode, or command metadata used for that already
approved invocation. This avoids a time-of-check/time-of-use gap between the
approval prompt and token minting.

For direct API clients, the broker should prefer in-memory token delivery through
an approved wrapper or credential helper. For `gcloud`, the official supported
surface is an access-token file, so `gcloud` compatibility may require a narrow
disk exception:

- create a private temporary directory with mode `0700`;
- write only the access token, with mode `0600`;
- pass the path only to the approved child invocation;
- delete the file on command exit, interruption, or startup failure;
- audit the file-backed delivery mode as compatibility behavior;
- keep this exception out of general secret-value delivery.

This is not as clean as pure in-memory delivery, but it still avoids persistent
Cloud SDK account state and does not give every same-user process a refreshable
credential.

Agent Secret should not silently mutate the command argv to add
`--access-token-file`, `--project`, or other `gcloud` flags. The MVP delivery
path should rely on inherited environment and isolated Cloud SDK configuration.
Direct flag injection is acceptable only as an explicit compatibility mode if
the user asks for it or a future narrow integration documents why it is safe.

`gcp exec` should also prove a nested `gcloud` smoke, not only a direct `gcloud`
argv. A command such as `mise run loadtest:production:75` may call `gcloud`
internally. Passing `--access-token-file` to the top-level `mise` command is not
useful; nested `gcloud` processes need inherited configuration.

The compatibility target is:

- set `CLOUDSDK_CONFIG` to a broker-owned private directory;
- configure that isolated Cloud SDK state with the approved intended project as
  the default project;
- set `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE` as the baseline delivery mechanism;
- make nested `gcloud` invocations use the broker token without reading or
  mutating the user's normal Cloud SDK state;
- prove `~/.config/gcloud` and ADC files are unchanged before and after the
  wrapped command.

This environment-backed path should be the MVP default. If inherited Cloud SDK
properties do not cover an important benchmark path, set `auth/access_token_file`
inside the isolated `CLOUDSDK_CONFIG` as the first fallback. If both
environment-backed and isolated-config-backed token delivery fail, add a
broker-owned `gcloud` shim earlier in `PATH`. The shim should refresh or write
the token file, then `exec` the real `gcloud` with the approved session context.
The shim must not print or return the token.

#### Multi-Command `gcp session`

Some agent workflows naturally require several GCP commands under the same
profile:

```bash
agent-secret gcp session create \
  --profile beta-debug \
  --reason "Investigate beta Cloud Run errors"

agent-secret gcp with-session asess_123 -- \
  gcloud run services describe web --region us-central1 --project fixture-beta

agent-secret gcp with-session asess_123 -- \
  gcloud logging read 'resource.type="cloud_run_revision"' \
    --project fixture-beta --limit 50

agent-secret gcp session destroy asess_123
```

The session approval should be scoped to a GCP profile and workflow reason, not
to one command argv. It should show the same provider fields as `gcp exec`,
plus:

- session ID preview or generated handle
- approved command wrapper: `agent-secret gcp with-session`
- project root, defined as the directory containing the discovered or explicit
  `agent-secret.yml` / `.agent-secret.yml`
- session TTL
- max command starts
- caller identity policy
- whether token refresh inside the session is allowed

GCP sessions require a config-backed profile in the first version. The session
root is the directory containing the discovered `agent-secret.yml` or
`.agent-secret.yml`, or the directory containing the explicit `--config PATH`.
`gcp with-session` should be usable from that root or a descendant path and
should fail outside it. This uses Agent Secret's existing project-config
discovery rule instead of introducing a Git-specific repository root. One-off or
ad hoc GCP access without a project config belongs in `gcp exec`, not
multi-command sessions.

Session behavior:

1. `session create` validates the GCP profile and asks for local approval.
2. The daemon snapshots the normalized approved profile into memory, including
   Google bootstrap identity alias, project or resource hints, service account,
   scopes, project root policy, TTL, max command starts, and display labels. It
   does not mint a GCP access token yet.
3. Every `with-session` command must be launched through the trusted CLI.
4. The daemon validates the session ID, local user identity, daemon identity,
   TTL, command-start count, and project root policy before each delivery.
5. The first valid `with-session` command lazily mints token material for that
   concrete command delivery.
6. If a cached token is still valid, the daemon reuses it.
7. If the session is still valid but the token is expired or has less than 20
   percent of its requested lifetime remaining, with a 60-second floor, the
   daemon re-mints it without asking the user again.
8. No token may outlive the Agent Secret session TTL, even if Google would allow
   a longer token lifetime.
9. Session tokens clear when the TTL expires, command starts are exhausted, the
   session is destroyed, or the daemon stops.
10. Each wrapped command gets its own value-free audit events.

The important distinction is that approval reuse and token reuse are separate.
The user approves a bounded GCP resource scope for a session. The daemon may
reuse or refresh token material only inside that approved session scope.
`session_created` records approved session state; `mint_access_token` records
command-bound credential material.

The approved session snapshot is the enforcement source of truth for the life of
the session. Later edits to `agent-secret.yml` must not silently broaden,
narrow, or otherwise change what an existing session can do. `with-session` may
warn if the underlying profile has changed or disappeared, but it should enforce
the approved snapshot until the session expires or is destroyed.

The agent should not receive a token-readable session API. For the first
multi-command version, session use should stay behind `gcp with-session`.
Sessions should not require a strict creator process-tree binding by default:
agent runtimes often launch each command as a sibling process under the same
agent host, so requiring every command to descend from the original
`session create` process would force agents to preserve one long-running shell.
Instead, v1 sessions should bind to the same local user, same Agent Secret
daemon, same approved project root policy, TTL, max uses, and daemon-held
non-token-readable session handle. Each `with-session` call should still record
and audit caller process metadata.

Session handles are sensitive-adjacent metadata. They are not bearer tokens by
themselves and must still pass daemon, local-user, project-root, TTL, and
max-use checks, but they should not become convenient replay material in logs.
CLI output may print the full handle because the user or agent needs it for
`gcp with-session`; audit logs and routine diagnostics should record only a
prefix or stable hash.

Session `max uses` should count approved `with-session` command starts, not
token deliveries, token-file writes, or IAM Credentials mint calls. Token
delivery and refresh counts are implementation details, especially for nested
`gcloud` workflows; command starts are the user-visible approval boundary. Audit
events should still record token mint, reuse, and refresh events separately.

`gcp session list` should show all active GCP sessions owned by the same local
user, regardless of cwd or project root. Listing is operator-visible metadata,
not credential delivery, and hiding sessions by cwd makes the CLI harder to
reason about. Each row should make usability constraints explicit: session handle
prefix, profile, project, service account, Google bootstrap identity alias,
reason, project root, remaining TTL, remaining command starts, and whether the
session is usable from the current cwd. `gcp with-session` still enforces
project-root and other delivery checks before minting or reusing token material.

`gcp session destroy` should also be allowed from any cwd by the same local user
and daemon. Destroying a session reduces access, so it should not require the
same project root policy that credential delivery requires. The destroy event
should audit the caller's cwd, process metadata, and whether cached token
material or token files were cleared.

Sessions should also avoid command allowlists. Session scope is the approved GCP
profile, Google bootstrap identity, impersonated service account, project root
policy, TTL, max uses, trusted `gcp with-session` wrapper, caller identity
policy, and the service account's IAM policy. Command allowlists are brittle for
repo-local wrappers such as `mise`, and IAM remains the real GCP permission
boundary.

Nested `gcloud` support is a first-class session requirement. The common
benchmark UX should work:

```bash
agent-secret gcp with-session asess_123 -- mise run loadtest:production:75
```

The first session version may use one token file valid for the remaining session
TTL if that covers the benchmark workflow. For longer workflows or commands
started near session expiry, Agent Secret should use the broker-owned `gcloud`
shim or credential-helper path so nested `gcloud` calls can refresh inside the
approved session without exposing a token-readable API.

Session expiry behavior should be explicit:

- refuse to start a command when remaining session TTL is below a configured
  minimum token lifetime;
- mint tokens with expiry no later than the session expiry;
- do not refresh after session expiry;
- do not kill an already-started child solely because the session expires, but
  expect later nested `gcloud` calls to fail once no valid token can be issued;
- audit when a session expires while a command is still running.

### Benchmarking MVP Profiles

Benchmark access should be split by IAM role rather than using one broad
service account. Example profiles:

- `fixture-prod-benchmark-run`
- `fixture-prod-benchmark-inspect`
- `fixture-prod-gcp-readonly`
- `fixture-prod-benchmark-vm-access`

The approval UI should not imply OAuth scopes are the main permission boundary.
For `gcloud`, `cloud-platform` may be pragmatic, but the real limit is the
service account's IAM policy. The prompt should show scopes, project, and
service account, and should label broad scopes as broad token audience rather
than broad permission by themselves.

For the first GCP MVP, benchmark VM access may use default
`gcloud compute ssh` behavior. That deliberately accepts the local-state risk
that `gcloud` may create or reuse SSH keys under `~/.ssh`, update OS Login or
project metadata, write known-hosts state, or invoke plain `ssh` after the
Google-side setup. Agent Secret should document and audit that boundary instead
of taking on SSH key lifecycle management in v1. Broker-owned SSH key paths can
be designed later if benchmark VM access becomes a major workflow.

### Token Files And Cleanup

The `gcloud` token file exception is acceptable only as provider compatibility
behavior.

Requirements:

- token directories use mode `0700`;
- token files use mode `0600`;
- token files contain only an access token, not refresh credentials;
- token expiry is no later than the Agent Secret approval or session expiry;
- token files are created only for approved command/session delivery;
- token files are deleted on command exit, startup failure, and signal cleanup;
- session token files are deleted when the session is destroyed or expires;
- daemon startup runs a janitor for stale broker-owned token directories;
- audit events record token file delivery mode without recording paths that
  expose random secret-bearing filenames unless those paths are declared safe
  metadata.

### Audit Event Shape

GCP audit events should remain value-free and include enough metadata for
operator review:

- provider: `gcp`
- operation: `mint_access_token`, `token_reused`, `token_refreshed`,
  `session_created`, `session_destroyed`, `command_started`,
  `command_completed`, `secret_manager_access_started`,
  `secret_manager_access_completed`, or failure variants
- profile project or resource hints
- service account
- OAuth scopes
- token lifetime or remaining TTL in milliseconds
- delivery mode: `token_file`, `session_wrapper`, `gcloud_shim`,
  `credential_helper`, or `env`
- session ID prefix or hash, never the full session handle
- approval ID
- reason
- command argv, resolved executable, executable identity, cwd, and exit status
- Secret Manager project, secret name, and version for `gsm://` refs

Audit events must never include access tokens, refresh credentials, Secret
Manager payloads, SSH private keys, or generated SSH public key material.

### Layer 2: GCP Secret Manager Resolver

This layer lets Agent Secret resolve explicit Secret Manager versions as secret
refs.

Ref sketch:

```text
gsm://projects/fixture-prod/secrets/slack-bot-token/versions/42
gsm://projects/fixture-prod/secrets/beta-api-token/versions/latest
```

Profile sketch:

```yaml
version: 1

profiles:
  beta-deploy:
    reason: Deploy beta
    ttl: 5m
    secrets:
      SLACK_BOT_TOKEN:
        ref: gsm://projects/fixture-prod/secrets/slack-bot-token/versions/42
        gcp_service_account: agent-secret-reader@fixture-prod.iam.gserviceaccount.com
```

The approval prompt should show:

- provider: GCP Secret Manager
- project
- secret name
- version or alias
- service account used to access the secret
- alias delivered to the child process
- command, cwd, reason, TTL, and override behavior

Resolver behavior:

1. Parse and validate `gsm://` refs before approval.
2. Never list or browse secrets as part of a normal `exec` request.
3. After approval, mint or use a constrained Google credential for the selected
   service account.
4. Call Secret Manager `AccessSecretVersion` only for the approved refs.
5. Deliver the resulting value through existing `exec` env injection first.
6. Reuse existing in-memory cache, TTL, force-refresh, and audit behavior.

Policy defaults:

- Prefer pinned numeric versions.
- Permit `latest` only when the profile explicitly opts in. The approval UI must
  show a drift warning because the approved ref can resolve to different secret
  material across runs.
- Prefer secret-level IAM bindings over project-level Secret Accessor.
- Treat project-level Secret Accessor as high scope in the approval UI.
- Do not support wildcard secret refs.
- Do not support list/search APIs in the child-facing broker path.

### Layer 3: Generic Provider Model

The generic abstraction should be "approved resources" rather than only
"secrets." GCP needs both:

- secret resources: Secret Manager payloads that become env vars;
- capability resources: short-lived access tokens used by a command;
- future operation resources: signing, identity tokens, or credential helpers
  that perform an operation without exporting the underlying key.

Internal model sketch:

```text
ProviderResource
  provider: onepassword | gcp
  kind: secret_value | access_token | id_token | operation
  display_ref: value-free string for UI and audit
  policy_ref: normalized identity for reuse/cache keys
  delivery: env | token_file | credential_helper | session_wrapper | session_socket
  ttl
  max_uses
```

Do not weaken the existing approval key. Reuse should still bind to command
argv, resolved executable, executable identity, cwd, resource identities, account
or service account scope, TTL, override behavior, and delivery mode.
For ad hoc `gcp exec`, the full normalized request snapshot is the reuse key; it
must not become a broad reusable approval for a service account.

## Rationale And Boundaries

The GCP provider addresses two concrete Agent Secret use cases: GCP resource
access and explicit Secret Manager refs.

- removes machine-wide `gcloud auth` state from agent workflows;
- turns broad user credentials into narrow service-account capabilities;
- aligns with Google Cloud's short-lived credential model;
- lets teams use GCP IAM and Cloud Audit Logs where secrets already live;
- keeps Agent Secret's local approval UI as the human decision point;
- makes GCP access repeatable through checked-in profiles without checked-in
  secret values.
- makes benchmark workflows usable without requiring a user-wide Cloud SDK login.

This feature stays inside Agent Secret's local approval-broker scope. It does
not become a generic enterprise secret manager.

Risk boundaries:

- GCP auth bootstrapping is a new root trust problem.
- A broker-held Google credential may be more powerful than any one secret.
- `gcloud` compatibility likely needs a temporary token-file exception.
- Secret Manager IAM mistakes can grant broad project-wide secret access.
- Multi-project and organization-policy behavior can make failure modes harder
  to explain than 1Password refs.
- If Agent Secret starts listing or discovering secrets, it becomes a cloud
  inventory and policy tool instead of a focused approval broker.

Agent Secret can broker explicitly requested GCP resources after local approval.
It should not manage GCP IAM, create service accounts, discover available
secrets, or keep unbounded reusable cloud sessions open for agents.

## Roadmap

### Phase 0: Research And Contract

- Add a provider/resource vocabulary to docs without changing runtime behavior.
- Keep provider packaging as an implementation detail behind the
  provider/resource vocabulary.
- Document the token-file exception needed for `gcloud`, including why it does
  not generalize to normal secret delivery.
- Specify the bootstrap auth model and reject ambient Cloud SDK auth as a root
  credential source.
- Use a bundled, Google-verified Agent Secret Desktop OAuth client for normal
  bootstrap login.
- Keep bootstrap OAuth scopes to `openid`, `userinfo.email`, and `auth/iam`;
  do not request `cloud-platform` for the human bootstrap grant.
- Implement `gcp auth login`, `gcp auth status`, and `gcp auth logout` around
  Keychain-held Google OAuth state.
- Add a custom OAuth client install/list/remove surface for teams that need
  their own Google Auth Platform Desktop app, with imports from a Google client
  JSON file or a 1Password `op://` ref.
- Define the nested `gcloud` compatibility contract before implementation.
- Define a GCP profile schema for access tokens and Secret Manager refs.
- Model GCP access-token scopes as a required non-empty list, not a scalar.
- Normalize scopes as an order-insensitive set for approval reuse and token
  cache keys.
- Define high-scope UI warnings for project-level Secret Accessor, `latest`,
  broad OAuth scopes, and long token lifetimes.

### Phase 1: Fake GCP Provider

- Add parser and validation for GCP profile blocks and `gsm://` refs.
- Add synthetic provider tests for approval-before-fetch and audit-before-value.
- Extend dry-run JSON to show provider resources without resolving values.
- Add UI fixtures for GCP access token and Secret Manager requests.
- Keep all tests offline with synthetic values.

### Phase 2: `gcp exec` For `gcloud`

- Support both profile-backed `gcp exec` and ad hoc `gcp exec` with explicit
  Google bootstrap identity alias, intended project, service account, scopes,
  TTL, and reason.
- Require explicit scopes; do not default to `cloud-platform`.
- Support multiple scopes through profile `scopes` lists and repeated ad hoc
  `--scope` flags.
- Normalize scopes by trimming, validating, deduplicating, and sorting before
  approval, token minting, reuse matching, cache keys, and audit output.
- Allow ad hoc `gcp exec` approval reuse only on a full normalized request
  snapshot match.
- Normalize and snapshot the approved `gcp exec` request before approval; use
  that snapshot for token minting, Cloud SDK delivery, cleanup, and audit.
- Implement service account access-token minting behind a mockable interface.
- Run `gcloud` with isolated `CLOUDSDK_CONFIG`.
- Set the approved intended project as the default project inside the isolated
  Cloud SDK configuration.
- Deliver token access through inherited environment and isolated Cloud SDK
  configuration without silently adding `gcloud` flags or policing project
  arguments.
- Prove nested `gcloud` calls work through isolated configuration or
  `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`.
- Clean up token files and isolated config directories.
- Add safe local smoke tests that prove no normal Cloud SDK account is used.
- Add tests proving `~/.config/gcloud` and ADC are unchanged.
- Add tests proving config edits after approval cannot alter the approved
  `gcp exec` snapshot used for minting or delivery.
- Add tests proving missing scopes fail validation for profile-backed and ad hoc
  `gcp exec`.
- Add tests proving missing intended project fails validation for profile-backed
  and ad hoc `gcp exec`.
- Add tests proving the isolated Cloud SDK default project is set to the
  approved intended project without mutating the user's normal Cloud SDK config.
- Add tests proving multiple scopes are preserved in approval snapshots, token
  mint requests, cache keys, and audit output.
- Add tests proving equivalent scope lists with different order or duplicates
  share the same normalized approval and token cache identity.
- Add tests proving two configured Google bootstrap identities remain isolated
  in profile resolution, approval matching, token cache keys, and audit output.
- Require opt-in live integration tests for real IAM Credentials calls.

### Phase 3: `gcp session` And `gcp with-session`

- Add GCP session create, list, destroy, and `with-session` commands.
- Make `gcp session list` show all active GCP sessions owned by the same local
  user, regardless of cwd or project root, while marking whether each is usable
  from the current cwd.
- Allow `gcp session destroy` from any cwd for the same local user and daemon,
  and audit the destroy caller metadata.
- Require a config-backed profile for `gcp session create`; define the session
  project root as the directory containing the discovered or explicit
  `agent-secret.yml` / `.agent-secret.yml`.
- Snapshot normalized approved profile metadata into daemon memory on
  `session create`; use that snapshot as the enforcement source of truth until
  the session expires or is destroyed.
- Mint the first access token lazily on the first valid `with-session` command,
  not during `session create`.
- Cache token material in daemon memory only after the first command delivery.
- Bind session use to the same local user, same Agent Secret daemon, approved
  project root policy, TTL, max uses, and daemon-held non-token-readable session
  handle.
- Audit caller process metadata for every `with-session` command.
- Cache access tokens by approved session, service account, normalized scope set,
  project, and delivery mode.
- Reuse unexpired tokens inside the session without prompting again.
- Re-mint tokens inside the session TTL when token expiry is shorter than the
  approved workflow.
- Support repo-local benchmark commands that invoke nested `gcloud`, such as a
  `mise` task, without leaking token access to the agent.
- Define session expiry behavior while a command is still running.
- Audit session creation, command start, token reuse, token refresh, command
  completion, expiration, and destroy events without token values.
- Keep all session commands fail-closed when local user, daemon identity,
  session-handle, TTL, command-start count, or project-root checks are
  unavailable or mismatched.
- Add tests proving sessions fail after TTL, after max uses, from the wrong
  local user, against the wrong daemon/session handle, and outside configured
  project root.
- If benchmark VM access remains part of the workflow, add a live
  `gcloud compute ssh` smoke that documents the accepted local SSH state and
  Google-side metadata behavior.

### Phase 4: Secret Manager Read Resolver

- Resolve `gsm://.../versions/N` refs through Secret Manager after approval.
- Add profile support for the service account used to access each secret.
- Add audit events that include project, secret name, version, service account,
  and alias, never payload values.
- Add live integration tests gated by synthetic test-only secrets.
- Document IAM setup using secret-level `roles/secretmanager.secretAccessor`.

### Phase 5: Credential Helper Work

- Evaluate Google auth library support for executable-sourced credentials and
  credential configuration files.
- Prefer helper flows for long-running tools that need refresh without exposing
  a broad local login.
- Reuse the GCP session policy model instead of adding a separate ambient
  credential cache.

## Live GCP Test Strategy

Live GCP tests should use a dedicated test project where resources can be
created, mutated, and destroyed without production risk. The project should have
test-only service accounts and IAM bindings that exercise the intended broker
paths.

Start with read-only smokes:

- authenticate two Google bootstrap identities with `agent-secret gcp auth`;
- mint a token for a read-only test service account;
- run `gcloud projects describe` or an equivalent project/resource describe
  command through `gcp exec`;
- run a nested `gcloud` command through a local wrapper or `mise` task;
- verify the user's normal `~/.config/gcloud` and ADC files are unchanged.

Then add session smokes:

- create a GCP session for the read-only profile;
- prove `gcp session create` fails without a config-backed profile;
- prove the session project root is the directory containing the discovered or
  explicit config file;
- prove session creation does not mint a token until the first `with-session`
  command;
- prove edits or deletion of the underlying profile do not change the approved
  session snapshot;
- run multiple `gcp with-session` commands against the test project;
- prove token reuse and token refresh inside the session TTL;
- prove expiration, max-use, wrong-user, wrong-session-handle, and outside-root
  failures.

Add multi-account smokes before calling the auth model complete:

- log in two distinct Google bootstrap identities, such as personal and business
  accounts;
- configure separate profile aliases for each identity;
- prove each profile mints tokens only through the intended bootstrap identity;
- prove approval reuse and token cache keys do not cross identities;
- include a negative test where the wrong bootstrap identity lacks
  `iam.serviceAccounts.getAccessToken` for the target service account.

Add mutating smokes after read-only and session paths are stable:

- create and destroy a small Compute Engine instance in the test project;
- label all live-test resources for cleanup;
- verify cleanup after success, failure, and interruption;
- keep all tests opt-in and value-free in logs.

Add SSH smokes only after the accepted v1 SSH boundary is documented:

- run `gcloud compute ssh` against a disposable test instance;
- record which local SSH files and Google-side metadata change;
- verify the GCP token path still uses Agent Secret, not ambient Cloud SDK auth;
- do not claim broker-owned SSH key cleanup until that becomes a separate
  feature.

## Non-Goals

- No service account key import or activation.
- No normal operator requirement to create, export, or share Google OAuth client
  JSON before first use.
- No `gcloud auth login` or ADC mutation managed by Agent Secret.
- No ambient Cloud SDK auth as the bootstrap credential source.
- No 1Password-stored Google bootstrap credential as the default local auth
  store.
- No wildcard Secret Manager refs.
- No project-wide secret sync in the first GCP Secret Manager resolver.
- No cloud-hosted Agent Secret service.
- No GCP IAM provisioning in the broker.
- No parsing, rewriting, or policing `gcloud` argv for project or resource
  consistency.
- No SSH key lifecycle management in the first GCP MVP.
- No long-lived shell sessions with ambient GCP credentials.
- No token-readable session API for agents in the first multi-command version.
- No `gcp session run` shell-wrapper mode in the first GCP MVP.
- No command that prints access tokens or Secret Manager payloads to stdout.

## Proposed Decision

Build toward a generic provider model, with GCP as the first non-1Password
provider, but ship it in this order:

1. GCP capability broker for approved `gcloud` commands using service account
   impersonation, used to prove token minting and isolated Cloud SDK execution.
2. GCP sessions for multi-command workflows under one approved profile, with
   daemon-side token caching and refresh inside the session TTL, shipped
   immediately after `gcp exec` so benchmark workflows can move off ambient
   `gcloud auth`.
3. GCP Secret Manager read-only resolver for explicit, preferably pinned secret
   versions.
4. Credential-helper support only after the one-command and session paths are
   stable and auditable.

This keeps Agent Secret's core promise intact: no broad ambient credentials, no
unapproved fetches, no raw values in broker output, and no secret source
specific shortcuts that bypass local human approval.

## Google OAuth Verification Demo Script

Use this script for the Google OAuth verification recording for the bundled
Agent Secret Desktop OAuth client. The recording is for Google's reviewer, not
for the public product launch. It should be recorded from a release-candidate
build of the GCP branch before merging GCP support into the normal public
release line.

The video should prove four things:

- Agent Secret has a real public homepage, privacy policy, and terms page.
- The Google consent screen asks for only `openid`, `userinfo.email`, and
  `https://www.googleapis.com/auth/iam`.
- The scary IAM scope is used only so Agent Secret can call IAM Credentials and
  mint short-lived service-account access tokens.
- The approved child command runs with an impersonated service-account token,
  not the human Google account's refresh credential or ambient Cloud SDK auth.

### Recording Setup

Before recording:

1. Use the production Google Auth Platform app in the `agent-secret-release`
   project.
2. Confirm the OAuth app has these URLs:
   - Homepage: `https://agent-secret.sh/`
   - Privacy policy: `https://agent-secret.sh/privacy`
   - Terms of service: `https://agent-secret.sh/terms`
3. Confirm the OAuth app data-access scopes are exactly:
   - `openid`
   - `https://www.googleapis.com/auth/userinfo.email`
   - `https://www.googleapis.com/auth/iam`
4. Use a least-privileged Google account for the demo when possible. That
   account should have `roles/iam.serviceAccountTokenCreator` only on the demo
   service account, not Owner, IAM Admin, or Service Account Admin.
5. Use the dedicated integration project and read-only service account:
   - Project: `agent-secret-integration`
   - Service account:
     `agent-secret-ro@agent-secret-integration.iam.gserviceaccount.com`
6. Make sure the read-only service account has only safe read roles, such as
   `roles/browser`, `roles/logging.viewer`, and
   `roles/serviceusage.serviceUsageViewer`.
7. Revoke any existing Google Account grant for Agent Secret if the recording
   needs to show the full consent screen instead of silently reusing prior
   consent.
8. Close unrelated browser windows, terminals, and notification-heavy apps.
9. Do not show OAuth client secrets, service-account keys, raw access tokens,
   refresh tokens, 1Password item values, or `gcloud auth print-access-token`.

Use a project-local profile like this for the recording:

```yaml
version: 1

profiles:
  gcp-oauth-verification:
    reason: Google OAuth verification read-only GCP smoke
    ttl: 5m
    gcp:
      google_account: verification
      project: agent-secret-integration
      service_account: agent-secret-ro@agent-secret-integration.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
```

The profile uses `cloud-platform` for the impersonated service-account access
token because many `gcloud` commands expect it. This is separate from the human
OAuth login grant, which must stay limited to `openid`, `userinfo.email`, and
`auth/iam`.

### Recording Flow

1. Start on the Agent Secret site.

   Show `https://agent-secret.sh/`, then briefly open the privacy and terms
   links.

   Narration:

   > This is Agent Secret, a local macOS approval broker for coding-agent
   > secrets and short-lived cloud access. The OAuth app's homepage, privacy
   > policy, and terms are published here.

2. Show the local GCP profile.

   In the terminal, show the profile file or `agent-secret profile show` output.
   The important fields are the Google account alias, project, service account,
   and service-account token scopes.

   Narration:

   > This profile contains only metadata. It names the local Google account
   > alias, the intended project, the service account Agent Secret may
   > impersonate, and the scopes for the short-lived service-account token. It
   > does not contain a Google refresh token, access token, service-account key,
   > or OAuth client secret.

3. Start Google login from Agent Secret.

   Run:

   ```bash
   agent-secret gcp auth login \
     --google-account verification \
     --expected-email DEMO_ACCOUNT_EMAIL
   ```

   Show the native Agent Secret preflight window before clicking Open Google.

   Narration:

   > Before opening Google OAuth, Agent Secret shows the exact consent items
   > Google will ask for. The IAM item is required so the local daemon can call
   > IAM Credentials. This grant does not create service accounts, assign IAM
   > roles, or bypass Google IAM.

4. Show the Google consent screen.

   In the browser, show that Google asks for account identity, email address,
   and the IAM policy scope. Approve the scopes.

   Narration:

   > Google labels this IAM scope as managing IAM policies. Agent Secret uses it
   > only to call IAM Credentials `generateAccessToken` for service accounts the
   > selected Google account is already allowed to impersonate. The user's IAM
   > bindings still decide whether this succeeds.

5. Show successful local login state.

   After OAuth returns and the Agent Secret window closes, run:

   ```bash
   agent-secret gcp auth status --google-account verification
   ```

   Narration:

   > The refresh-capable Google OAuth state is stored under Agent Secret's local
   > macOS Keychain access. It is not written into `~/.config/gcloud`, not
   > written into Application Default Credentials, and not passed to child
   > commands.

6. Show dry-run metadata before access.

   Run:

   ```bash
   agent-secret gcp exec --dry-run --json \
     --profile gcp-oauth-verification -- \
     gcloud projects describe agent-secret-integration \
       --format='value(projectId)'
   ```

   Narration:

   > Dry run shows the command and GCP capability Agent Secret would request,
   > without minting a token or contacting Google IAM Credentials.

7. Run a safe read-only command through `gcp exec`.

   Run:

   ```bash
   agent-secret gcp exec --profile gcp-oauth-verification -- \
     gcloud projects describe agent-secret-integration \
       --format='value(projectId)'
   ```

   Approve the native Agent Secret request.

   Narration:

   > This approval is for one command, one project, one service account, one
   > scope set, and a short TTL. After approval, Agent Secret uses the stored
   > Google login only to mint a short-lived access token for the service
   > account shown here. The child `gcloud` command receives that service-account
   > token through isolated Cloud SDK configuration.

8. Show a nested `gcloud` command.

   Run:

   ```bash
   agent-secret gcp exec --profile gcp-oauth-verification -- \
     zsh -lc 'gcloud services list --enabled \
       --project=agent-secret-integration \
       --limit=3 \
       --format="value(config.name)"'
   ```

   Narration:

   > This command goes through a shell wrapper and calls `gcloud` inside the
   > approved environment. Agent Secret does not rewrite `gcloud` arguments; it
   > prepares the isolated environment and lets the approved command run.

9. Optionally show value-free audit metadata.

   If the recording needs stronger proof of the token-mint path, show only
   metadata from the audit log:

   ```bash
   tail -n 50 ~/Library/Logs/agent-secret/audit.jsonl |
     jq 'select(.type | test("^gcp_")) |
       {type, google_account, project, service_account, oauth_scopes, delivery_mode}'
   ```

   Narration:

   > Audit records include the Google account alias, project, service account,
   > scopes, and delivery mode. They do not contain access tokens, refresh
   > tokens, or secret payloads.

10. Close with the permission boundary.

    Narration:

    > Agent Secret's Google OAuth grant is bootstrap authority for token
    > minting, not broad cloud access by itself. The usable GCP permissions come
    > from two Google IAM checks: the signed-in Google account must be allowed
    > to impersonate the service account, and the service account must have the
    > resource permissions needed by the approved command.

### What To Avoid In The Demo

- Do not use an Owner or IAM Admin Google account for the happy-path demo if a
  least-privileged account is available.
- Do not run mutating Compute Engine or IAM commands in the Google verification
  video. Keep the verification command read-only.
- Do not show service-account keys. Agent Secret should not use them.
- Do not show `gcloud auth login`, `gcloud auth application-default login`, or
  ADC setup. Those are the ambient-auth paths the feature avoids.
- Do not imply that the OAuth scope alone limits GCP resources. Say that the
  service account IAM policy is the real resource boundary.
