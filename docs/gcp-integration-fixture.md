# GCP Integration Fixture

Status: active live test fixture.

Last verified: 2026-05-25.

## Purpose

This project is the live GCP fixture for Agent Secret's GCP provider
integration tests and manual smokes. It is intentionally separate from
production or customer projects.

The fixture proves:

- app/bootstrap Google identities can impersonate narrow service accounts;
- read-only GCP commands work through service-account impersonation;
- compute-oriented commands can be tested separately from read-only commands;
- isolated Cloud SDK token-file delivery works without relying on ambient
  `gcloud` account state inside the wrapped command.

Do not store access tokens, refresh credentials, service-account keys, OAuth
client secrets, or captured secret payloads in this repository.

## Project

- Project ID: `agent-secret-integration`
- Project number: `376669634956`
- Billing: enabled

Enabled APIs required for the current and near-term smokes:

- `cloudresourcemanager.googleapis.com`
- `compute.googleapis.com`
- `iamcredentials.googleapis.com`
- `iap.googleapis.com`
- `logging.googleapis.com`
- `oslogin.googleapis.com`
- `secretmanager.googleapis.com`
- `serviceusage.googleapis.com`

Project metadata:

- `enable-oslogin=TRUE`

Firewall rules:

- `agent-secret-iap-ssh`: allows TCP port 22 from `35.235.240.0/20` only to
  instances tagged `agent-secret-itest-ssh`.

## Bootstrap Google Identities

The following human Google accounts are allowed to impersonate the broker test
service accounts:

- `oleksiy@kovyrin.net`
- `oleksiy.kovyrin@fixture.app`

Both accounts have `roles/iam.serviceAccountTokenCreator` on these service
accounts only:

- `agent-secret-ro@agent-secret-integration.iam.gserviceaccount.com`
- `agent-secret-compute@agent-secret-integration.iam.gserviceaccount.com`

They do not need broad project roles for Agent Secret integration tests. The
service account IAM policy is the test boundary.

During fixture setup, `oleksiy.kovyrin@fixture.app` briefly had
`roles/editor` so the browser session could configure Google Auth Platform.
That broad project binding was removed after OAuth setup was verified.

## Google Auth Platform

OAuth app:

- App name: `Agent Secret Integration`
- User type: External
- Publishing status: Testing
- Support email: `oleksiy.kovyrin@fixture.app`
- Contact email: `oleksiy.kovyrin@fixture.app`

OAuth test users:

- `oleksiy@kovyrin.net`
- `oleksiy.kovyrin@fixture.app`

Configured scopes:

- `openid`
- `https://www.googleapis.com/auth/userinfo.email`
- `https://www.googleapis.com/auth/cloud-platform`

Desktop OAuth client:

- Name: `Agent Secret Local GCP Broker`
- Type: Desktop
- Client ID:
  `376669634956-8ql9omna7ii69l9jvqd7uu5hg6vgcsea.apps.googleusercontent.com`

Do not commit the OAuth client JSON or client secret. For live broker
implementation, keep OAuth client material in Keychain or another private local
bootstrap path and store only non-secret metadata in the repository.

The v1 daemon reads the public desktop OAuth client ID from
`AGENT_SECRET_GCP_OAUTH_CLIENT_ID` or `agent-secretd --gcp-oauth-client-id`.
The client ID is not a credential, but keeping it configurable avoids binding
the generic broker implementation to this test fixture. For fixture smokes, use
the client ID listed above.

## Service Accounts

### Read-Only

Service account:

```text
agent-secret-ro@agent-secret-integration.iam.gserviceaccount.com
```

Project roles:

- `roles/browser`
- `roles/logging.viewer`
- `roles/serviceusage.serviceUsageViewer`

Use this identity for safe live tests such as project describe, enabled API
listing, and log reads.

### Compute Control

Service account:

```text
agent-secret-compute@agent-secret-integration.iam.gserviceaccount.com
```

Project roles:

- `roles/compute.instanceAdmin.v1`
- `roles/compute.networkUser`
- `roles/compute.osLogin`
- `roles/compute.viewer`
- `roles/iap.tunnelResourceAccessor`

Use this identity for later opt-in VM create/destroy and `gcloud compute ssh`
tests. Temporary SSH test VMs should use the `agent-secret-itest-ssh` network
tag so they are reachable through IAP without opening SSH broadly.

### VM Runtime

Service account:

```text
agent-secret-vm-runtime@agent-secret-integration.iam.gserviceaccount.com
```

`agent-secret-compute` has `roles/iam.serviceAccountUser` on this service
account so compute tests can attach it to temporary VMs.

## Verified Smokes

The personal and Fixture Google identities both successfully impersonated the
read-only and compute service accounts.

Read-only project describe:

```bash
sa="agent-secret-ro@agent-secret-integration.iam.gserviceaccount.com"

gcloud projects describe agent-secret-integration \
  --account=oleksiy@kovyrin.net \
  --impersonate-service-account="$sa" \
  --format='value(projectId)'
```

Read-only log read:

```bash
sa="agent-secret-ro@agent-secret-integration.iam.gserviceaccount.com"

gcloud logging read 'timestamp>="2026-01-01T00:00:00Z"' \
  --project=agent-secret-integration \
  --account=oleksiy@kovyrin.net \
  --impersonate-service-account="$sa" \
  --limit=1 \
  --format='value(timestamp)'
```

Compute zone list:

```bash
sa="agent-secret-compute@agent-secret-integration.iam.gserviceaccount.com"

gcloud compute zones list \
  --project=agent-secret-integration \
  --account=oleksiy@kovyrin.net \
  --impersonate-service-account="$sa" \
  --limit=1 \
  --format='value(name)'
```

Repeat those commands with `--account=oleksiy.kovyrin@fixture.app` to verify
the second bootstrap identity.

Disposable VM create, SSH, and delete:

```bash
project="agent-secret-integration"
zone="us-east1-b"
control_sa="agent-secret-compute@agent-secret-integration.iam.gserviceaccount.com"
runtime_sa="agent-secret-vm-runtime@agent-secret-integration.iam.gserviceaccount.com"
name="agent-secret-itest-ssh-$(date +%s)"
tmp="$(mktemp -d)"

cleanup() {
  gcloud compute instances delete "$name" \
    --project="$project" \
    --zone="$zone" \
    --impersonate-service-account="$control_sa" \
    --quiet >/dev/null 2>&1 || true
  rm -rf "$tmp"
}

trap cleanup EXIT

ssh-keygen -q -t rsa -b 3072 -N "" \
  -C "agent-secret-itest" \
  -f "$tmp/google_compute_engine"

gcloud compute instances create "$name" \
  --project="$project" \
  --zone="$zone" \
  --machine-type=e2-micro \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --no-address \
  --tags=agent-secret-itest-ssh \
  --service-account="$runtime_sa" \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --impersonate-service-account="$control_sa" \
  --quiet \
  --format="value(name)"

sleep 45

gcloud compute ssh "$name" \
  --project="$project" \
  --zone="$zone" \
  --tunnel-through-iap \
  --ssh-key-file="$tmp/google_compute_engine" \
  --strict-host-key-checking=no \
  --command="echo agent-secret-ssh-ok" \
  --impersonate-service-account="$control_sa" \
  --quiet
```

The verified SSH smoke printed `agent-secret-ssh-ok` and the cleanup trap
deleted the VM. The first attempt immediately after instance creation failed
with IAP `Failed to lookup instance`; a short wait after create fixed it.

`gcloud compute ssh` may still touch host-key state even when the SSH private
key lives in a temp directory. During verification it wrote one entry to
`~/.ssh/google_compute_known_hosts`; that test entry was removed afterwards.
Future automated tests should either accept this v1 boundary or pass an
isolated SSH known-hosts path through `--ssh-flag`.

Token-file Cloud SDK compatibility smoke:

```bash
sa="agent-secret-ro@agent-secret-integration.iam.gserviceaccount.com"
project="agent-secret-integration"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
umask 077

gcloud auth print-access-token \
  --impersonate-service-account="$sa" > "$tmp/access-token"

mkdir -p "$tmp/cloudsdk"

CLOUDSDK_CONFIG="$tmp/cloudsdk" \
CLOUDSDK_ACTIVE_CONFIG_NAME=default \
CLOUDSDK_AUTH_ACCESS_TOKEN_FILE="$tmp/access-token" \
CLOUDSDK_CORE_PROJECT="$project" \
bash -lc '
  gcloud projects describe "$1" --format="value(projectId)"
  gcloud services list --enabled \
    --project="$1" \
    --filter="config.name:iamcredentials.googleapis.com" \
    --format="value(config.name)"
' bash "$project"
```

This smoke must print only resource metadata, never the token.

## Notes

The local `gcloud` credential for `oleksiy.kovyrin@fixture.app` required a
browser reauthentication before the cross-account smoke. That is acceptable for
fixture setup, but it is not the intended Agent Secret product path. The product
path remains daemon-owned OAuth, Keychain storage, and IAM Credentials minting
without exporting bootstrap credentials to child processes.
