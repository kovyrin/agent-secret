# GCP Integration

Agent Secret can broker short-lived Google Cloud access for approved commands
and sessions. The goal is to stop giving agents ambient access through
`gcloud auth login`, `~/.config/gcloud`, or Application Default Credentials
when a workflow only needs a narrow GCP capability for a short time.

GCP support currently targets `gcloud` workflows. It prepares an isolated Cloud
SDK environment, writes a broker-owned short-lived access-token file, runs the
approved command, and cleans up token material when the command or session is
finished.

## How It Works

There are three identities involved:

- The local macOS user running Agent Secret.
- A Google account, such as `you@example.com`, that signs in through Agent
  Secret's app-owned OAuth flow so the daemon can mint service-account tokens.
- A GCP service account that carries the actual resource permissions for the
  command, such as
  `agent-beta-logs@example-project.iam.gserviceaccount.com`.

Agent Secret does not run child commands as the Google account that completed
login. The daemon uses that account only to call Google's IAM Credentials API
and mint a short-lived access token for the configured service account. The
child command receives only the short-lived service-account token through
isolated Cloud SDK environment variables.

This means the service account's IAM roles are the real GCP permission boundary.
OAuth scopes are still required by Google token minting, but the approval UI
must not be read as proof that Agent Secret has verified every resource-level
permission behind the service account.

Agent Secret release builds use a bundled Google OAuth Desktop client for the
GCP login flow. That client identifies the local Agent Secret app to Google; it
does not grant cloud resource access by itself. The login OAuth grant requests
only the minimum Google scopes needed for this flow:

- `openid`
- `https://www.googleapis.com/auth/userinfo.email`
- `https://www.googleapis.com/auth/iam`

Those login scopes are separate from the `scopes` list in a GCP profile.
Profile scopes are the service-account access-token scopes delivered to
`gcloud` after approval, and they remain explicit and non-empty.

## Recommended Team Account Setup

In a team environment, prefer per-user Google identities and narrow IAM
bindings:

- Normal operators can usually use their regular work Google account for
  `agent-secret gcp auth login`.
- GCP admins and organization owners should not use their broad admin account
  for day-to-day Agent Secret login. Use a separate least-privileged Google
  account when the normal account carries Owner, IAM Admin, Service Account
  Admin, or similar broad roles.
- Put Agent Secret users in a Google Group, such as
  `agent-secret-gcp-users@example.com`.
- Grant that group `roles/iam.serviceAccountTokenCreator` only on the exact
  service accounts Agent Secret profiles may impersonate. Prefer
  service-account-level bindings over project, folder, or organization
  bindings.
- Give resource permissions to the target service accounts, not to the human
  login accounts. For example, `agent-prod-readonly` gets read-only production
  roles, while `agent-benchmark-runner` gets only the permissions required for
  benchmark runs.

Do not use 1Password to share a Google username and password, OAuth refresh
token, or service-account key as the team's production GCP authority. Shared
credentials make audit and revocation worse: every operator and every agent
that can access the item acts as the same Google principal. 1Password is still
appropriate for sharing inert configuration, such as project IDs, service
account names, profile snippets, or a team-owned OAuth Desktop client override.

## What The GCP Admin Sets Up

Agent Secret does not create Google Cloud IAM resources. A GCP admin must set
up service accounts, APIs, and IAM bindings before operators can use the
feature.

### 1. Choose Target Projects And Enable APIs

Enable the APIs Agent Secret needs for token minting in the projects that own
the impersonated service accounts:

```bash
gcloud services enable \
  iamcredentials.googleapis.com \
  --project PROJECT_ID
```

Enable any additional APIs that the wrapped `gcloud` commands need, such as
Cloud Logging, Cloud Run, Compute Engine, Secret Manager, or Service Usage.

### 2. Create Narrow Service Accounts

Create separate service accounts for separate capabilities. For example:

- `agent-beta-logs`: read beta logs.
- `agent-prod-readonly`: inspect production metadata.
- `agent-benchmark-runner`: create benchmark resources.
- `agent-compute-ssh`: create VMs and use IAP or OS Login for SSH tests.

Example:

```bash
project="PROJECT_ID"

gcloud iam service-accounts create agent-beta-logs \
  --project "$project" \
  --display-name "Agent Secret beta log reader"
```

Grant the service account only the roles its workflow needs. For log reads:

```bash
sa="agent-beta-logs@$project.iam.gserviceaccount.com"

gcloud projects add-iam-policy-binding "$project" \
  --member "serviceAccount:$sa" \
  --role roles/logging.viewer
```

Use project, folder, organization, or resource-level bindings according to your
normal GCP policy. Agent Secret will display the service account, but it does
not verify whether the service account's roles are broad or narrow.

### 3. Allow Human Bootstrap Accounts To Impersonate The Service Account

Grant each approved human Google account
`roles/iam.serviceAccountTokenCreator` on the service account that Agent Secret
should mint tokens for.

Prefer binding this role on the service account itself, not on the whole
project:

```bash
project="PROJECT_ID"
sa="agent-beta-logs@$project.iam.gserviceaccount.com"
user="you@example.com"

gcloud iam service-accounts add-iam-policy-binding "$sa" \
  --project "$project" \
  --member "user:$user" \
  --role roles/iam.serviceAccountTokenCreator
```

That role includes permission to create short-lived OAuth access tokens for the
service account. Once a user can mint tokens for a service account, they can
access whatever that service account can access, so keep the service account's
own IAM roles narrow.

## What The Local Operator Sets Up

The operator needs Agent Secret installed and `gcloud` available on `PATH`.
Normal operators do not need a Google OAuth client JSON file. The daemon uses
the OAuth Desktop client bundled into the Agent Secret release build.

### Bundled OAuth Client Requirements

This section is for Agent Secret maintainers or teams building with their own
OAuth client. Normal operators can skip it when using an official Agent Secret
release.

The OAuth client must be a Google OAuth Desktop client. Agent Secret opens the
system browser and listens on a loopback callback URL such as
`http://127.0.0.1:<port>/callback`, so do not create a Web client with fixed
authorized redirect URIs for this flow.

The Google Auth Platform app that owns the client must be configured with:

- App audience and branding that allow the intended users to authorize it. For
  a Testing app, add each operator Google account as a test user.
- Data access scopes for `openid`,
  `https://www.googleapis.com/auth/userinfo.email`, and
  `https://www.googleapis.com/auth/iam`.
- The IAM Service Account Credentials API
  (`iamcredentials.googleapis.com`) enabled in the OAuth client project. This
  is separate from enabling the same API in the project that contains the
  target service account.

During login, Google may show the IAM access as an optional checkbox or an
additional-access step. The operator must grant it. Agent Secret rejects OAuth
responses that omit required login scopes so a partial consent cannot be stored
as a usable GCP login.

### Development And Custom OAuth Client Builds

Development builds require the bundled OAuth client too. The build script first
uses `AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_ID` and
`AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_SECRET` when they are already present,
which is the CI and release path. If they are absent, maintainer builds use the
repo-local `bundled-gcp-oauth-client` Agent Secret profile to resolve the
client from 1Password after approval.

Custom deployments may also need to test a team-owned OAuth Desktop client
before the planned Keychain-backed override command exists. In those cases,
the daemon still accepts explicit OAuth client process configuration.

App-bundle builds can embed the bundled client with:

```bash
export AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_ID="GOOGLE_DESKTOP_CLIENT_ID"
export AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_SECRET="GOOGLE_DESKTOP_CLIENT_SECRET"

mise run build
```

Official Agent Secret builds require both values. Local maintainer builds can
also run plain `mise run build`; when the env vars are absent, the build script
re-enters itself through:

```bash
agent-secret exec --profile bundled-gcp-oauth-client -- \
  scripts/build/build-app-bundle.sh
```

If the daemon is already running, stop it first.

```bash
agent-secret daemon stop
```

Start the daemon from a shell that has the OAuth client values:

```bash
export AGENT_SECRET_GCP_OAUTH_CLIENT_ID="GOOGLE_DESKTOP_CLIENT_ID"
export AGENT_SECRET_GCP_OAUTH_CLIENT_SECRET="GOOGLE_DESKTOP_CLIENT_SECRET"

agent-secret daemon start
```

If the Desktop app client does not have a client secret, omit
`AGENT_SECRET_GCP_OAUTH_CLIENT_SECRET`. The client ID is required.

For v1, this is the concrete meaning of "configure the daemon with a Google
OAuth desktop client" in development builds. The values are process
configuration for the local daemon. There is not yet an Agent Secret settings
UI or Keychain-backed configuration store for custom OAuth client material.

Process environment is a pragmatic v1 configuration path, but it is not a
secret vault. Same-user diagnostic tools can usually inspect a running
process's environment on macOS. That is acceptable for a Google Desktop OAuth
client, which Google treats as installed-app material that cannot be kept truly
secret, but it would not be acceptable for service account keys, refresh tokens,
or generated access tokens. Do not put those values in daemon environment.

If you change the OAuth client, restart the daemon. If the daemon starts
without bundled client material or explicit development override values, GCP
auth or token minting will fail until the daemon is restarted with a client.

### 1. Log In A Google Account

Pick a short local alias for the Google account. The alias is stored in Agent
Secret config and audit metadata; it does not need to equal the email address.

```bash
agent-secret gcp auth login \
  --google-account work \
  --expected-email you@example.com
```

Agent Secret first shows a native login warning that lists the Google consent
items, explains the scary IAM wording, and asks the operator to explicitly open
Google login. The window stays open while OAuth is in progress; if Google opens
in the wrong Chrome profile, switch to the right profile and click the open
button again. After the loopback OAuth callback completes, Agent Secret closes
the window automatically.

The OAuth grant does not create service accounts, grant roles, or bypass Google
IAM by itself. It lets Agent Secret use IAM permissions that the selected
Google account already has. Use a least-privileged Google account. Normal
operators can usually use their regular work identity when it only has the
intended Token Creator bindings. Operators whose normal account has Owner, IAM
Admin, Service Account Admin, or similar broad roles should use a separate
least-privileged Google account for Agent Secret.

After confirmation, the daemon runs Google OAuth with PKCE, verifies the
reported email when `--expected-email` is provided, and stores the
refresh-capable GCP login credential in macOS Keychain under Agent Secret's GCP
OAuth service.

Verify the local state:

```bash
agent-secret gcp auth status
```

You should not need to enter the macOS login keychain password for normal Agent
Secret GCP use. If macOS refuses non-interactive access to old or stale GCP
OAuth Keychain state, Agent Secret fails with repair guidance instead of
opening a password prompt. The normal repair is:

```bash
agent-secret gcp auth logout --google-account work
agent-secret gcp auth login --google-account work \
  --expected-email you@example.com
```

### 2. Add A GCP Profile To The Project

Create or edit `agent-secret.yml` at the project root:

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

GCP profile fields:

- `google_account`: local alias created with `gcp auth login`.
- `project`: intended project for approval, token delivery, and Cloud SDK
  defaults.
- `service_account`: service account to impersonate.
- `scopes`: non-empty list of OAuth scopes for the minted access token.

`https://www.googleapis.com/auth/cloud-platform` is often the practical scope
for `gcloud`, but the service account IAM roles still define what the command
can actually do.

Inspect the resolved profile without minting a token:

```bash
agent-secret profile show beta-logs
agent-secret gcp exec --dry-run --profile beta-logs --json -- \
  gcloud logging read 'severity>=ERROR' --project fixture-beta --limit=5
```

### 3. Run One Command With `gcp exec`

```bash
agent-secret gcp exec --profile beta-logs -- \
  gcloud logging read 'severity>=ERROR' \
    --project fixture-beta \
    --limit=5
```

Agent Secret will show a native approval prompt with the command, reason,
project, Google account alias, service account, and scopes. After approval, the
daemon mints a short-lived token for the service account and runs the child
with isolated Cloud SDK state.

If your `gcloud` binary is installed under a user-owned path such as Homebrew or
`~/google-cloud-sdk`, add `--allow-mutable-executable` after reviewing that path.

Ad hoc access is available when there is no profile yet:

```bash
agent-secret gcp exec \
  --google-account work \
  --project fixture-beta \
  --service-account agent-beta-logs@fixture-beta.iam.gserviceaccount.com \
  --scope https://www.googleapis.com/auth/cloud-platform \
  --reason "Inspect beta Cloud Run errors" \
  -- gcloud logging read 'severity>=ERROR' --project fixture-beta --limit=5
```

### 4. Use A Session For Multi-Command Workflows

Use a GCP session when an agent needs multiple commands under the same approved
profile, such as a benchmark or incident investigation.

Sessions require a config-backed profile. They are bound to the project root
containing `agent-secret.yml`, the same local user, the same daemon, TTL, and
max command starts.

```bash
handle="$(
  agent-secret gcp session create \
    --profile beta-logs \
    --max-command-starts 5 \
    --json | jq -r .session_handle
)"

agent-secret gcp with-session "$handle" -- \
  gcloud logging read 'severity>=ERROR' --project fixture-beta --limit=5

agent-secret gcp with-session "$handle" -- \
  gcloud services list --enabled --project fixture-beta --limit=10

agent-secret gcp with-session "$handle" \
  --cwd ./benchmarks \
  --allow-mutable-executable \
  -- \
  mise run loadtest:beta

agent-secret gcp session destroy "$handle"
```

`gcp with-session` prepares the same isolated Cloud SDK environment for each
command. Nested `gcloud` calls from scripts or tools such as `mise` work because
the environment is inherited by child processes.

List active same-user sessions:

```bash
agent-secret gcp session list
agent-secret gcp session list --json
```

The list shows all active same-user sessions, including whether each session is
usable from the current directory. `with-session` is allowed only from the
approved project root or a descendant directory. `session destroy` can be run
from any directory by the same local user because it only reduces access.

Like normal `agent-secret exec`, GCP command execution rejects user-owned or
writable executable paths by default. Use `--allow-mutable-executable` only for
repo-local wrappers or test helpers you already trust.

## What The Child Command Receives

Agent Secret does not write to `~/.config/gcloud` and does not create ADC files.
For each approved command or session use, it prepares environment variables
similar to:

- `CLOUDSDK_CONFIG`: a broker-owned temporary Cloud SDK config directory.
- `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`: a broker-owned `0600` token file.
- `CLOUDSDK_CORE_PROJECT`: the approved project.
- `CLOUDSDK_ACTIVE_CONFIG_NAME`: an isolated config name.

The token file is deleted on command cleanup, session destroy, session expiry,
or daemon startup janitor cleanup. Agent Secret does not expose a command that
prints the token value.

## Custom OAuth Clients

The default product path is the bundled Agent Secret OAuth Desktop client. A
custom client is only needed when an organization wants its own Google consent
screen branding, internal-only OAuth app, or controlled client lifecycle.

The planned custom-client surface is:

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
  --expected-email you@example.com
```

That override should store OAuth client material locally under Agent Secret
control and should not require daemon environment variables. Until that command
exists, use the development override environment variables only for local
testing and custom-client bring-up.

## Troubleshooting

### `GCP OAuth client id is required`

The daemon does not have a bundled OAuth client ID and was not started with an
explicit development override. Use a release build that contains the bundled
OAuth client, or stop the daemon, set the OAuth client environment variables,
and start it again.

### `GCP token minter is unavailable`

The daemon was started without a bundled or explicitly configured GCP OAuth
client ID, so it cannot mint service account tokens. Restart the daemon with a
release build that contains the bundled client or with explicit development
override values.

### `GCP bootstrap credential not found`

The profile's `google_account` alias has not been logged in. Run:

```bash
agent-secret gcp auth login \
  --google-account ALIAS \
  --expected-email you@example.com
```

### Permission denied From Google APIs

Check both sides of the permission model:

- The human Google account must have `roles/iam.serviceAccountTokenCreator` on
  the service account.
- The service account must have the IAM roles needed for the actual `gcloud`
  command.
- `iamcredentials.googleapis.com` must be enabled in both the OAuth client
  project and the project that contains the target service account.
- Any APIs used by the wrapped `gcloud` command must be enabled in the target
  project.

### Missing OAuth Scopes After Login

If `gcp auth login` reports that Google did not grant required scopes, rerun
login and grant every access item Google shows for Agent Secret. For the GCP
broker, the required login scope is `https://www.googleapis.com/auth/iam`.

### Session Is Not Usable From This Cwd

`gcp session create` binds the session to the directory containing the resolved
`agent-secret.yml`. Run `gcp with-session` from that directory or a descendant,
or create a new session for the intended project root.

### `gcloud compute ssh` Writes Local SSH State

Agent Secret brokers the GCP token and Cloud SDK state. It does not manage SSH
keys or host-key files in v1. `gcloud compute ssh` may write OS Login metadata,
SSH keys, or known-hosts entries depending on your flags and Google-side
configuration. Use explicit `gcloud compute ssh` flags and temporary SSH paths
when you need stronger isolation.

## Security Notes

- Do not run `gcloud auth login` as a replacement for Agent Secret GCP auth.
- Do not commit OAuth client JSON, client secrets, refresh tokens, service
  account keys, access tokens, token files, or captured fixtures containing real
  values.
- OAuth client JSON is app identity, not cloud authority, but it should still
  be shared through controlled operator channels such as 1Password or device
  management rather than Git.
- Prefer one service account per capability class instead of one broad service
  account for all agents.
- Prefer service-account-level Token Creator bindings over project-level
  Token Creator bindings.
- Use `--expected-email` during `gcp auth login` to avoid logging in the wrong
  Google account.
- Agent Secret GCP login requests `https://www.googleapis.com/auth/iam`
  instead of `cloud-platform`. Treat `cloud-platform` as a broad profile access
  token scope when a `gcloud` workflow needs it, but remember IAM roles on the
  service account are the real resource boundary.
- Agent Secret does not parse, rewrite, or police `gcloud` arguments inside the
  approved environment. It audits the command and prepares the approved GCP
  environment; GCP IAM enforces cloud permissions.

## Official Google References

- [OAuth 2.0 for iOS and Desktop Apps](https://developers.google.com/identity/protocols/oauth2/native-app)
- [Service account impersonation](https://cloud.google.com/iam/docs/service-account-impersonation)
- [Service Account Token Creator role](https://cloud.google.com/iam/docs/service-account-permissions#service-account-token-creator-role)
- [Create short-lived credentials for a service account](https://cloud.google.com/iam/docs/create-short-lived-credentials-direct)
- [IAM Credentials generateAccessToken](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken)
