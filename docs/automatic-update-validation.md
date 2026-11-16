# Automatic update validation

Use a disposable macOS VM with a dedicated console user. The pilot uses the
release bundle identifiers. Install the pilot only inside the VM.

## Build a notarized pilot in CI

In the `agent-secret-candidate-signing` environment, require maintainer
review, allow only `main` and the reviewed feature branch, and set its
`AGENT_SECRET_CANDIDATE_SIGNING_ENABLED` variable to `true`. The job uses the
existing Developer ID and notary credentials. Revoke the feature branch's
environment access after the pilot.

Dispatch the existing CI workflow on the branch at the reviewed commit:

<!-- markdownlint-disable MD013 -->

```bash
gh workflow run ci.yml --ref "$branch" -f candidate_sha="$reviewed_commit_sha"
gh run download "$run_id" -n "notarized-update-pilot-$reviewed_commit_sha" -D pilot
```

<!-- markdownlint-enable MD013 -->

Confirm the exact commit on the approval screen. The job checks that it matches
the dispatch SHA and runs after CI and smoke tests pass. It uploads two
notarized DMGs and a signed localhost feed as a seven-day Actions artifact.
The pilot generates its own Sparkle key. Production release and feed
publication use separate jobs.

## Build and serve the pilot

Set `AGENT_SECRET_CODESIGN_IDENTITY` to an existing Developer ID Application
identity and `AGENT_SECRET_TRUSTED_MISE` to the absolute path to `mise`. For
Gatekeeper validation, set `AGENT_SECRET_NOTARIZE=1` and select an existing
Keychain `AGENT_SECRET_NOTARY_PROFILE`, or supply the existing API key
configuration from [the release process](release-process.md).

```bash
mise exec -- scripts/release/smoke-app-update.sh _dist/update-pilot
```

The output contains the previous-build DMG under `client/` and a signed
appcast and candidate DMG under `feed/`. Both builds have the same display
version. The candidate has the higher `CFBundleVersion`. The script generates
an ephemeral Sparkle signing key and discards its private seed after signing.

Copy the pilot and `scripts/release/serve-update-pilot.py` into the VM. Generate
a short-lived localhost TLS certificate with a `DNS:localhost` subject
alternative name and TLS server authentication usage. Trust the certificate
in the disposable guest user's Keychain only. Run the server in the VM:

```bash
python3 serve-update-pilot.py feed tls/localhost.crt tls/localhost.key
```

Verify TLS and byte identity before opening the updater:

```bash
curl --fail --silent --show-error --cacert tls/localhost.crt \
  https://localhost:8443/appcast.xml | cmp - feed/appcast.xml
```

## Run the signed update drill

1. Install the previous-build DMG in Applications. Verify its signature
   and notarization, then run `agent-secret update status --json`. Record the
   installed build, the CLI and skill symlinks, and the Homebrew receipt if
   applicable.
2. Open Agent Secret. Enable background checks, confirm the login item in
   System Settings, and log out and back in. Compare the outer app and
   nested updater's `--background-updater-status` diagnostics. Turn background
   checks off in System Settings and verify that manual checks still work.
3. Choose Check for Updates. Confirm that Later and Skip Version never
   replace the app. Reopen the UI and click Install Update while a test-only
   approval, provider request, supervised command, or reusable session is
   active. Cancel once while waiting and confirm that the old build remains.
   Repeat and let the protected work finish. Confirm the candidate is
   installed and that `agent-secret daemon start` starts the new broker.
4. Repeat with an active broker in a second console account and a second
   account starting fresh work after the installer acquires the lock. Also
   attempt Homebrew upgrade, reinstall, and uninstall during the update.
   Start work again after installation. Verify the symlinks and helper.
5. Repeat from the old build with a modified appcast, modified embedded
   notes, a feed signed with another test key, and an altered archive.
   Confirm rejection in the native updater and check the app version after
   each test. Use a new pilot key for the wrong-key case.
6. On another run, terminate the updater after consenting and while Sparkle
   is preparing replacement. Restart or log out as applicable. Verify that
   new CLI processes stay excluded until the transaction recovers. Try a
   read-only destination and verify that the updater offers repair guidance.
7. Run one real supervised command in the VM with a test-only provider item.
   Check that injection worked without printing a value.

## Recover an interrupted installation

When an update may still be running, leave the transaction marker in place.
If Check for Updates shows the recovery message, restart the Mac and open Check
for Updates again. The updater verifies the installed signature before
clearing the marker. An interrupted Homebrew transaction may need the restart
even if the old app appears present, because an installer process can outlive
the process that started it.

If the signed app is missing or cannot open, restart first and reinstall
Agent Secret from the signed DMG in the same Applications folder. Then open
Check for Updates to let the updater verify the current bundle and finish
recovery. If there is no updater in the restored app, install a verified
updater-capable build first. Keep the normal app support, Keychain, and audit
files. For the one-time upgrade from a cask that predates the guard, finish all
commands and close sessions in every account using that app before upgrading.

## Recorded development evidence

- Sparkle 2.10.1 loaded from both an ad-hoc bundle and a hardened Developer
  ID bundle. Both passed strict recursive signature verification. The pinned
  tool generated a signed feed from the final signed pilot DMG and embedded
  its notes.
- Go tests exercise exclusion across readers and writer ownership. Protocol
  tests exercise the accepted updater role and deny that same role secret
  requests, session access, and forced broker stops.
- The Developer ID pilot's nested helper successfully retired its adjacent
  idle broker in the VM. With a Ruby writer lease held, its CLI link
  postflight succeeded while two ordinary CLI invocations were refused.
- A separately signed copy of the pilot contained an instrumented updater
  at the exact bundled executable path. It received `untrusted_client`
  for `session.list`, `request.exec`, and `daemon.stop`, and received
  `ok` for `update.quiesce`. The probe used empty synthetic requests and
  logged only whether each response matched its expected type.
- On macOS 27, direct login-item status from the nested helper returned
  `notFound` while the outer app reported `enabled`. The updated helper
  queries the outer app. The VM reported `enabled` before suspension,
  `notRegistered` after suspension, and `enabled` after restoration.
- A Developer ID probe using the shipping installation barrier armed an
  update to build `1.0.35` and was killed before replacement. The marker
  blocked the old CLI and refused same-boot recovery. After a VM reboot, the
  probe verified the installed build, cleared the marker, and the old CLI
  worked again.
- Homebrew upgraded the public notarized cask from `0.0.13` to `0.0.34` in
  the VM. With a `0.0.34` receipt and the signed, Sparkle-upgraded pilot
  staged in `/Applications`, Homebrew refused reinstall and uninstall
  while a separate process held a shared lease. Reinstall and uninstall
  succeeded once the lease was free. The uninstall removed the app, cask
  receipt, marker, and both symlinks that pointed into the app.
  With an interrupt injected immediately after updater suspension, Homebrew
  preserved the signed app and restored registration. The marker remained
  and blocked the CLI. On reboot, the registered updater cleared the marker
  and the CLI ran again.
- The user approved the pilot update in the VM. Sparkle replaced build
  `1.0.34` with `1.0.35` in the guest's Applications folder. The installed
  app passed recursive signature verification, and its code directory hash
  matched the candidate DMG. The nested updater was running after
  replacement, the transaction marker cleared, and the CLI symlink still
  reached the bundle and started the new broker. The guest's existing skill
  link pointed to its separate system-wide installation during this drill.
- Sparkle rejected an appcast with edited embedded notes and a signed appcast
  from another pilot key. The server received the feed requests, and the app
  remained on build `1.0.34`. The release verifier independently rejected
  these appcasts and a DMG with altered bytes.
- The bootstrap scripts refuse to install or uninstall under a competing
  writer lease. The tests confirm the original bundle stays in place and
  that a failed replacement restores the app and its updater registration.
- Isolated promotion fixtures checked cask-first ordering, retry after a
  write failure, first-object creation, and refusal to overwrite a concurrent
  or newer feed. The fixture adapters exercised no live release or bucket.
- The hosted R2 endpoint served exact fixture bytes over HTTPS with
  `Cache-Control: no-store`. Conditional creation and replacement worked, and a
  stale ETag was refused. The fixture was removed and the public appcast still
  returned HTTP 404. See [production update setup](production-update-setup.md).

## Checks still due before release

- **Notarized lifecycle.** Run a quarantined, stapled candidate through
  Gatekeeper and install with explicit approval. Verify the CLI, skill,
  helper, and background registration. The Developer ID pilot covered
  replacement.
- **Homebrew lifecycle.** Install a notarized updater-enabled cask, run its
  in-app update, then verify upgrade, reinstall, and uninstall against its
  original receipt. The VM drill staged the signed candidate over the real
  `0.0.34` receipt.
- **Two console accounts.** Run an active broker in the second account and
  verify deferral. Then try starting fresh work in that account after the
  first account holds the writer lease. The disposable VM has one test user.
- **Install and reminder behavior.** Exercise Later, Skip Version, a real
  busy approval or session, a deferred scheduled reminder, and a read-only
  location in the native UI. Reminder deferral and broker admission have
  automated coverage.
- **Native rejection and interruption.** Approve download of the altered
  pilot archive and verify Sparkle rejects it. Interrupt a separate approved
  Sparkle run after the guard arms, then verify restart and recovery. The
  existing reboot drill used a signed probe.
- **Test-only provider request.** Verify one supervised command can receive
  a test-only secret after updating, without logging its value.
- **First stable promotion.** Verify the signing key's recovery backup, then
  confirm the cask and hosted appcast agree after the maintainer approves and
  publishes the first updater-enabled release.
