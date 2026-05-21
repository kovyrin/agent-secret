# GCP-Backed Secret Broker Plan

Status: draft planning note.

Last reviewed: 2026-05-21.

## Decision

Agent Secret will add a GCP provider for the existing local approval broker. It
will not become a new cloud secret-management product.

The GCP provider ships in layers:

1. Short-lived Google Cloud capabilities for a single approved command.
2. Approved GCP sessions for multi-command agent workflows.
3. Explicit Google Secret Manager version resolution through the same approval,
   TTL, audit, and command-binding model used for 1Password refs.

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

Selected local MVP direction:

1. `agent-secret gcp auth login` asks the trusted app/daemon to start a Google
   OAuth flow for the signed Agent Secret app.
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

Other options:

- Workforce or Workload Identity Federation may become cleaner for organization
  environments, but it should not block the local MVP.
- A bootstrap secret stored in 1Password is not the default local UX. It could
  be an explicit bridge for early testing or unusual environments, but it must
  be marked as provider-internal credential material and never exposed as a
  normal `--secret` value.
- A hosted broker is a separate product direction and should stay out of the
  local-first MVP.

Keychain implementation questions remain:

- which OAuth client type and redirect mechanism to use for the local app;
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
smallest new surface area.

Example:

```bash
agent-secret gcp exec \
  --profile beta-logs \
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
      project: fixture-beta
      service_account: agent-beta-logs@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
```

The approval prompt should show:

- provider: GCP
- operation: mint access token
- target project
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

Execution behavior:

1. CLI validates the command and GCP profile.
2. Daemon asks for local approval.
3. Daemon obtains a short-lived service account access token.
4. CLI runs the approved command with isolated Cloud SDK state.
5. Agent Secret deletes any broker-owned compatibility files after the command
   exits and clears daemon-held token material when the approval expires.

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

`gcp exec` should also prove a nested `gcloud` smoke, not only a direct `gcloud`
argv. A command such as `mise run loadtest:production:75` may call `gcloud`
internally. Passing `--access-token-file` to the top-level `mise` command is not
useful; nested `gcloud` processes need inherited configuration.

The compatibility target is:

- set `CLOUDSDK_CONFIG` to a broker-owned private directory;
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

- session ID preview or generated handle prefix
- approved command wrapper: `agent-secret gcp with-session`
- session TTL
- max command uses or max token deliveries
- process ownership policy
- whether token refresh inside the session is allowed

Session behavior:

1. `session create` validates the GCP profile and asks for local approval.
2. The daemon stores only session metadata and cached token material in memory.
3. Every `with-session` command must be launched through the trusted CLI.
4. The daemon validates the session ID, TTL, use count, cwd policy, and process
   ownership before each delivery.
5. If a cached token is still valid, the daemon reuses it.
6. If the session is still valid but the token is expired or has less than 20
   percent of its requested lifetime remaining, with a 60-second floor, the
   daemon re-mints it without asking the user again.
7. No token may outlive the Agent Secret session TTL, even if Google would allow
   a longer token lifetime.
8. Session tokens clear when the TTL expires, use counts are exhausted, the
   session is destroyed, or the daemon stops.
9. Each wrapped command gets its own value-free audit events.

The important distinction is that approval reuse and token reuse are separate.
The user approves a bounded GCP resource scope for a session. The daemon may
reuse or refresh token material only inside that approved session scope.

The agent should not receive a token-readable session API. For the first
multi-command version, session use should stay behind `gcp with-session`, with
the same creator process-tree or owner checks planned for other Agent Secret
session modes.

The first version should not support command allowlists. Session scope is the
approved GCP profile, cwd or repo policy, TTL, max uses, trusted
`gcp with-session` wrapper, process ownership policy, and the service account's
IAM policy. Command allowlists are brittle for repo-local wrappers such as
`mise`, and IAM remains the real GCP permission boundary.

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
- project
- service account
- OAuth scopes
- token lifetime or remaining TTL in milliseconds
- delivery mode: `token_file`, `session_wrapper`, `gcloud_shim`,
  `credential_helper`, or `env`
- session ID prefix or approval ID
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
- Implement `gcp auth login`, `gcp auth status`, and `gcp auth logout` around
  Keychain-held Google OAuth state.
- Define the nested `gcloud` compatibility contract before implementation.
- Define a GCP profile schema for access tokens and Secret Manager refs.
- Define high-scope UI warnings for project-level Secret Accessor, `latest`,
  broad OAuth scopes, and long token lifetimes.

### Phase 1: Fake GCP Provider

- Add parser and validation for GCP profile blocks and `gsm://` refs.
- Add synthetic provider tests for approval-before-fetch and audit-before-value.
- Extend dry-run JSON to show provider resources without resolving values.
- Add UI fixtures for GCP access token and Secret Manager requests.
- Keep all tests offline with synthetic values.

### Phase 2: `gcp exec` For `gcloud`

- Implement service account access-token minting behind a mockable interface.
- Run `gcloud` with isolated `CLOUDSDK_CONFIG`.
- Pass `--access-token-file` to the approved `gcloud` command.
- Prove nested `gcloud` calls work through isolated configuration or
  `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`.
- Clean up token files and isolated config directories.
- Add safe local smoke tests that prove no normal Cloud SDK account is used.
- Add tests proving `~/.config/gcloud` and ADC are unchanged.
- Add tests proving two configured Google bootstrap identities remain isolated
  in profile resolution, approval matching, token cache keys, and audit output.
- Require opt-in live integration tests for real IAM Credentials calls.

### Phase 3: `gcp session` And `gcp with-session`

- Add GCP session create, list, destroy, and `with-session` commands.
- Store session metadata and cached token material in daemon memory only.
- Bind session use to the creator process tree or an equivalent trusted-wrapper
  ownership policy.
- Cache access tokens by approved session, service account, scopes, project, and
  delivery mode.
- Reuse unexpired tokens inside the session without prompting again.
- Re-mint tokens inside the session TTL when token expiry is shorter than the
  approved workflow.
- Support repo-local benchmark commands that invoke nested `gcloud`, such as a
  `mise` task, without leaking token access to the agent.
- Define session expiry behavior while a command is still running.
- Audit session creation, command start, token reuse, token refresh, command
  completion, expiration, and destroy events without token values.
- Keep all session commands fail-closed when peer process checks are unavailable
  or mismatched.
- Add tests proving sessions fail after TTL, from the wrong process, and outside
  configured cwd or repo constraints.
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
- run multiple `gcp with-session` commands against the test project;
- prove token reuse and token refresh inside the session TTL;
- prove expiration, max-use, wrong-process, and wrong-cwd failures.

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
- No `gcloud auth login` or ADC mutation managed by Agent Secret.
- No ambient Cloud SDK auth as the bootstrap credential source.
- No 1Password-stored Google bootstrap credential as the default local auth
  store.
- No wildcard Secret Manager refs.
- No project-wide secret sync in the first GCP Secret Manager resolver.
- No cloud-hosted Agent Secret service.
- No GCP IAM provisioning in the broker.
- No SSH key lifecycle management in the first GCP MVP.
- No long-lived shell sessions with ambient GCP credentials.
- No token-readable session API for agents in the first multi-command version.
- No command that prints access tokens or Secret Manager payloads to stdout.

## Proposed Decision

Build toward a generic provider model, with GCP as the first non-1Password
provider, but ship it in this order:

1. GCP capability broker for approved `gcloud` commands using service account
   impersonation.
2. GCP sessions for multi-command workflows under one approved profile, with
   daemon-side token caching and refresh inside the session TTL.
3. GCP Secret Manager read-only resolver for explicit, preferably pinned secret
   versions.
4. Credential-helper support only after the one-command and session paths are
   stable and auditable.

This keeps Agent Secret's core promise intact: no broad ambient credentials, no
unapproved fetches, no raw values in broker output, and no secret source
specific shortcuts that bypass local human approval.
