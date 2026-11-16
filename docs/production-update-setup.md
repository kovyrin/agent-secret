# Production update setup

This records the provisioning state observed on 2026-11-16. Recheck the live
configuration before release. No release or stable appcast has been published
as part of this setup.

## GitHub

The repository is `kovyrin/agent-secret`. Automatic promotion is disabled by
the repository variable `AGENT_SECRET_UPDATES_ENABLED=false`.

All three environments require review by `kovyrin`:

- `agent-secret-release-signing` allows `main` and tags matching `v*`.
- `agent-secret-update-promotion` allows `main` and tags matching `v*`.
- `agent-secret-candidate-signing` allows `main` and the temporary
  `kovyrin/automatic-app-updates` branch for the isolated notarized pilot.

Release events use a tag ref even when a job checks out `main`; both production
environments therefore allow release tags. Remove the temporary candidate
branch allowance after validation. Candidate signing has no production update
signing key. Existing repository-level Developer ID and notarization secrets
remain available to the appropriate jobs.

Both production environments contain:

- `AGENT_SECRET_UPDATE_FEED_URL=https://updates.agent-secret.sh/appcast.xml`
- `AGENT_SECRET_UPDATE_PUBLIC_KEY=nbLYHrJHmHN0mBtkdzBNb0WnsAFfsLkfmTH6wQkMr9E=`

The release-signing environment contains `AGENT_SECRET_UPDATE_SIGNING_KEY`.
The pinned Sparkle tool generated this key in macOS Keychain under account
`com.kovyrin.agent-secret.production-updates`, service
`https://sparkle-project.org`. Its private seed was transferred directly to
GitHub through stdin. It was not printed or written to a plaintext file.
The public key above is safe to commit. A separate protected recovery backup
has not yet been verified; complete that before enabling production updates.

The promotion environment also has the R2 bucket and endpoint variables and
the bucket-scoped R2 publishing secrets:

- `AGENT_SECRET_UPDATE_R2_ACCESS_KEY_ID`
- `AGENT_SECRET_UPDATE_R2_SECRET_ACCESS_KEY`

## Cloudflare

The dedicated `agent-secret-updates` bucket was created in the account that
owns `agent-secret.sh`, with the default jurisdiction. The custom domain
`updates.agent-secret.sh` is attached with minimum TLS 1.2. HTTPS delivery was
verified, and the absent `appcast.xml` returns HTTP 404. No appcast has been
uploaded.

The maintainer temporarily extended the existing deployment token after its
initial requests for account token permission groups and zone cache rules
were denied. Setup then completed:

1. Created the account-owned token `Agent Secret update-feed publisher` with
   Object Read and Write access limited to `agent-secret-updates`. Its S3
   credentials were transferred directly into the GitHub promotion
   environment without printing or writing them to plaintext files.
2. Created and verified a cache-bypass rule matching only
   `http.host eq "updates.agent-secret.sh"`, preserving unrelated rules.
3. Verified exact public HTTPS bytes and `Cache-Control: no-store` using a
   disposable object. Conditional creation refused to overwrite the object,
   conditional replacement accepted the current ETag, and a stale ETag was
   rejected. The updated bytes were immediately visible over HTTPS.
4. Deleted the fixture and verified HTTP 404 for both its URL and the absent
   stable appcast. Promotion remains disabled pending candidate approval.

The two temporary setup permissions can now be removed from the original
deployment token: Account API Tokens Edit and Cache Rules Edit. The promotion
workflow uses only the new bucket-scoped credential.

Use the [R2 credential instructions](https://developers.cloudflare.com/r2/api/tokens/)
and [Cache Rules API documentation](https://developers.cloudflare.com/cache/how-to/cache-rules/create-api/).
Do not reuse the broad website deployment token in the promotion workflow.

## Enablement

Finish the checks in [automatic update validation](automatic-update-validation.md)
and follow the [release process](release-process.md). Approve the exact
notarized candidate before publishing. Enable promotion only when its
credential, hosting checks, recovery backup, and signed release artifacts
are ready. Existing installations need one ordinary Homebrew or DMG upgrade
to acquire the updater.
