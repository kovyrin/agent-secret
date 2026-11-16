# Automatic update research

This research records the options considered for Agent Secret application
updates on 2026-11-15. See [the validation record](automatic-update-validation.md)
for the implementation and subsequent test results.

User decisions: check automatically, require approval for every installation,
install updates inside the native app, and preserve Homebrew support.
Homebrew-only onboarding is an acceptable option, not a selected requirement;
the user explicitly welcomes clean alternatives.

## Recommendation

Use Sparkle 2 for native macOS updating, with a signed feed and signed release
DMGs. Recommend Homebrew as the primary installation method and the same
standard drag-and-drop DMG as a secondary option, sharing one updater.
The main project-specific work is coordinating updates with active approvals,
commands, and memory-only sessions, and providing an updater process that
actually stays alive long enough to check for releases.

The current stable release is
[Sparkle 2.10.1](https://github.com/sparkle-project/Sparkle/releases/tag/2.10.1).
It requires macOS 12 or later, below Agent Secret's macOS 14 minimum. Pin the
reviewed version and its package resolution rather than floating to new
framework versions during release builds.

## Installation choices and native updates

Homebrew-only onboarding would reduce the number of public installation
instructions, but is not necessary to standardize updates. Homebrew and a
direct DMG already install the same signed bundle; both can use Sparkle.
Recommend preserving both, making Homebrew primary, and simplifying custom
bootstrap tooling rather than requiring Homebrew for every new user.
This is a recommendation; removal of existing installer assets is not settled.

The installation and update choices were compared separately:

| Approach | Consequence |
| --- | --- |
| Homebrew plus DMG, Sparkle updates | One artifact/updater, two entry paths. |
| Homebrew only, Sparkle updates | Fewer setup docs; Homebrew required. |
| Homebrew upgrade, Terminal handoff | Less updater code; user leaves app. |
| Native app invokes Homebrew | More process and policy handling. |

Both Sparkle approaches meet the user's in-app installation requirement.
Homebrew does not supply a standalone notification scheduler: its documented
auto-update runs before certain commands and refreshes package definitions,
not Agent Secret itself. A per-user update checker therefore remains needed.
See the [Homebrew manual](https://docs.brew.sh/Manpage#environment).

Wrapping `brew upgrade` would require handling Homebrew ownership, executable
discovery, concurrent package operations, trust prompts, app-management
permissions, cancellation, and postflight failures. Some commands may also
refresh Homebrew or run cleanup. These are extra integration concerns rather
than evidence that Homebrew is unsafe. [Tap trust][tap-trust] is especially
relevant: casks are executable Ruby, and Homebrew 6 requires explicit trust
for non-official sources. A GUI must not silently bypass that choice.

For diagnostics, prefer the supported [JSON interface][brew-query] over
parsing console output or private receipt files:

```sh
brew info --cask --json=v2 kovyrin/agent-secret/agent-secret
brew outdated --cask --json=v2 kovyrin/agent-secret/agent-secret
```

The [cask schema][brew-cask-source] exposes the receipt's installed version,
bundle version, tap, pin, and outdated state. Receipt and bundle versions may
differ after Sparkle updates; test both, and do not rewrite Homebrew receipts
ourselves. The public [Homebrew metadata API][brew-api] covers official core
formulae and casks, not this custom tap. A notifier based only on locally
cached cask data would miss fresh releases until that tap was updated; the
signed Sparkle feed avoids that dependency.

Existing releases need one normal upgrade to gain the updater. Direct installs
do not need to become Homebrew-managed to use Sparkle. If someone chooses that
migration, Homebrew's `--adopt` only accepts identical existing artifacts;
an older app cannot be assumed adoptable. Preserve settings, tokens, audit
logs, and skill links, and never use `--zap` for migration. If shell bootstrap
onboarding is retired, keep existing release URLs working during the transition
and decide asset removal explicitly later. See the
[installation options](https://docs.brew.sh/Manpage#install-options-formulacask-).

Release publication must keep the cask and appcast aligned: expose the native
update only after the verified release artifact and corresponding cask bump
are available. Maintain one build and two references to the same DMG bytes.
This still needs Sparkle/Homebrew coexistence testing. Supporting the ordinary
DMG adds an installation test path but not a second updater implementation.

## Options

| Option | Assessment for Agent Secret |
| --- | --- |
| Sparkle 2 | Best fit: native update UX and existing signed-app distribution. |
| Homebrew only | Simpler lifecycle; native installation requires a wrapper. |
| Signed PKG | Extra installer packaging; no demonstrated need here. |
| Custom updater with TUF | Strong metadata security; more integration work. |
| Sigstore verification | Provenance layer, not a complete installer. |
| Mac App Store | Requires broader distribution and sandboxing changes. |

These assessments are engineering judgments based on the capabilities below.

An Apple-signed PKG can be useful for managed deployment or custom file
placement. It would add packaging and uninstall/receipt concerns to the
current app-bundle model. If used for updates too, Sparkle documents mandatory
authorization, slower relaunch, and reduced generation/key-rotation features.
Sparkle recommends regular app bundles unless custom installation requires a
package; even daemon-based apps do not inherently need PKG distribution.
See [package updates](https://sparkle-project.org/documentation/package-updates/).
For Agent Secret, the existing app's CLI/skill setup is a better starting point.

[TUF](https://theupdateframework.io/docs/security/) specifically addresses
repository compromise, rollback, freeze, and inconsistent metadata using
separate metadata roles and trust rules. It would still leave us responsible
for macOS bundle replacement, relaunch, UI, signing, and broker coordination.
Revisit it if the distribution model expands beyond macOS or needs stronger
repository-freshness guarantees.

[Sigstore](https://docs.sigstore.dev/quickstart/quickstart-cosign/) verifies
artifact signatures, signing identities, certificates, and transparency-log
evidence. It can supplement build provenance; it does not supply the complete
desktop update lifecycle.

Apple's [Mac App Store rules][apple-review] require sandboxing and constrain
installation and update mechanisms. Moving this broker into that distribution
model is a separate product investigation, not a small updater substitution.

## Current repository constraints

- `approver/Sources/AgentSecretApproverApp/AgentSecretApproverMain.swift` runs
  setup when opened normally, then exits. Approval invocations also end after
  their controller finishes. There is no resident menu-bar application today.
- `internal/daemon/process/process_unix.go` and
  `internal/daemon/control/manager.go` implement a detached Go helper, not an
  existing `SMAppService` registration that an updater can simply reuse.
- `scripts/lib/bundle-metadata.sh` defaults `CFBundleVersion` to `1`.
  Update detection needs a monotonically increasing release build version.
- `scripts/build/build-app-bundle.sh` assembles the Swift executable, Go
  binaries, nested daemon bundle, and skill. The outer app is the version unit.
- `internal/daemon/server.go` can retire an old helper after active requests
  finish; this is not yet an atomic admission gate for an update transaction.
- `Casks/agent-secret.rb` links the bundled CLI; `internal/install/install.go`
  installs CLI and skill links. Keeping stable bundle-relative targets lets
  these links continue to follow the replaced app.

## Framework and process integration

Sparkle supports Swift Package Manager, but this project also needs explicit
framework embedding, runpath configuration, preservation of symlinks, and
signing in its custom bundle script. The production Developer ID build and
ad-hoc development build need separate validation: library validation can
prevent an ad-hoc host from loading Sparkle. Do not relax production hardened
runtime policy to accommodate development. See
[Sparkle setup](https://sparkle-project.org/documentation/).

Sparkle's [bundle model](https://sparkle-project.org/documentation/bundles/)
separates the bundle being replaced from the application process being watched.
Its [SPUUpdater initializer][updater-api] accepts `hostBundle` for the outer app
and `applicationBundle` for the process to terminate and relaunch. This supports
investigating a nested updater app without turning the approval process into a
permanent application. Use `SPUUpdater` with a standard user driver;
`SPUStandardUpdaterController` always targets the main bundle.

Apple's [SMAppService][smappservice] supports bundled login items and per-user
launch agents on macOS 13+. Recommend an opt-in updater helper under the app
bundle, visible in System Settings, with preferences in the existing setup
window and no new menu-bar icon. Its enablement status must be respected, and
uninstall must unregister it. See Apple's
[registration and status examples][apple-helper]. A signed integration spike
must prove that replacing the containing app, quitting the updater, and
relaunching its new binary works before choosing the final helper layout.

Sparkle's [CLI](https://sparkle-project.org/documentation/sparkle-cli/) is an
alternative bridge for a custom scheduler, but upstream recommends building it
with a product-specific identifier. Its defaults can install immediately; it
cannot automatically inherit application-specific delegate behavior. A small
native integration gives us clearer lifecycle control.

## User control and broker safety

Sparkle separately controls automatic checking and automatic download/install.
By default it asks about automatic checks on the second launch and does not
silently install by default. For the user's chosen policy, disable automatic
installation with `SUAllowsAutomaticUpdates=NO` and `SUAutomaticallyUpdate=NO`;
do not expose a silent-install checkbox. Keep checking preferences stable
across releases, provide an explicit check action, and require installation
approval for each offered release regardless of the original install method.
See
[Sparkle settings](https://sparkle-project.org/documentation/customization/).

For dockless processes, adopt
[gentle reminders](https://sparkle-project.org/documentation/gentle-reminders/)
so scheduled update prompts do not interfere with approval windows. Keep
[system profiling](https://sparkle-project.org/documentation/system-profiling/)
disabled. Update requests must never include secret references, session tokens,
commands, or customer metadata.

The broker must atomically refuse new work during final replacement and wait
for existing approvals, supervised commands, and live sessions to finish.
Current `ActiveCount()` covers active requests, not idle reusable sessions;
status or PID polling alone cannot establish a safe update window.
Do not persist sessions to survive an upgrade. Do not kill approved children
to make an update convenient. If an installation requires expiring sessions,
make that a separate explicit user choice.

The [Sparkle delegate contract][updater-delegate] is an important limitation:
`shouldPostponeRelaunchForUpdate` is not called on every installation path.
`willInstallUpdateOnQuit` can defer an immediate restart, but Sparkle still
attempts installation when the watched application terminates. Neither is
sufficient alone as the broker's safety gate. Verify manual install,
install-on-quit, logout, helper crash, concurrent command arrival, cancellation,
and restart recovery. User approval alone does not make a busy broker safe to
replace. Defer the approved installation until the gate can be acquired, and
do not arm an install-on-quit path before that condition is satisfied.

## Trust and release publication

Use HTTPS, Developer ID signing and notarization, plus Sparkle Ed25519 signatures
for the final release archive. For a new deployment, also enable
`SUVerifyUpdateBeforeExtraction` and `SURequireSignedFeed`; signed feed support
arrived in Sparkle 2.9. Keep release-note JavaScript disabled.

The signed-feed failure default eventually permits restricted fallback after
20 days. Recommend `SUSignedFeedFailureExpirationInterval=0` to keep failures
strict, accepting that losing the feed key may require manual recovery.
Document this policy, back up the signing key offline, and test recovery.
These defaults
and requirements are documented in [Sparkle settings][settings].

[Sparkle key rotation][sparkle-setup] supports changing the Apple signing
identity or the Ed25519 key in an update, not both simultaneously. With
pre-extraction verification, Ed25519 rotation requires a Developer ID-signed
DMG as the fallback. Reusing our signed DMG format preserves that option.
Strict signed-feed policy still needs its own lost-key recovery drill.

Suggested pipeline, extending existing draft-release verification:

1. Build the complete app with monotonic version metadata.
2. Sign, notarize, and staple the final app and DMG using the existing process.
3. Generate a signed appcast from those exact bytes with pinned Sparkle tools.
4. Upload draft assets, verify signatures and an actual old-to-new update.
5. Publish the release and update the cask from the same artifact checksum.
6. Atomically promote the verified stable feed after the cask is available.

Use a stable HTTPS feed on the project's own domain and versioned GitHub asset
URLs. Prevent a website deployment from editing or replacing the signed feed.
Publishing the feed last prevents clients seeing an unavailable archive.
These are proposed operational safeguards, not features Sparkle supplies.

[Sparkle publication](https://sparkle-project.org/documentation/publishing/)
supports generated appcasts, embedded release notes, OS/architecture bounds,
minimum update versions, channels, and phased rollouts. Seven local cohorts
stagger automatic availability; a user-initiated check bypasses staging.
Use full DMGs initially. Disable automatic delta generation until patching
adds enough value to justify its extra test matrix.

Withdrawing an appcast item can stop subsequent discovery; it does not remotely
undo an installed update or reliably cancel every already-downloaded update.
Recover by publishing a higher-version corrective release. Signed metadata is
not a complete TUF-style defense against withholding/replaying older valid
feeds; do not claim otherwise.

## Homebrew compatibility and remaining proof

Homebrew's [cask cookbook][cask-cookbook] requires `auto_updates true` for an
application that can download and install its own updates. Homebrew's
[current FAQ](https://docs.brew.sh/FAQ) describes version-aware treatment of
such applications and explicit upgrade options. Do not assume old blanket
advice that every self-updating cask is always skipped. The chosen product
policy includes Homebrew installs in the same automatic-check and
per-installation-approval experience. Homebrew pinning alone cannot prevent
an independent app updater; users who pin must also disable that updater.

Before launch, verify self-update followed by Homebrew upgrade/reinstall,
uninstall, CLI and skill symlinks, installed-version reporting, multiple macOS
users sharing `/Applications`, non-writable installations, network loss,
corrupt payloads, invalid signatures, interrupted replacement, and failed
helper restart. A per-user broker gate alone does not protect another logged-in
user's active processes in the shared app bundle; either coordinate all users
or explicitly defer installation when that safety cannot be established.

[apple-review]: https://developer.apple.com/app-store/review/guidelines/#hardware-compatibility
[updater-api]: https://sparkle-project.org/documentation/api-reference/Classes/SPUUpdater.html
[updater-delegate]: https://github.com/sparkle-project/Sparkle/blob/2.10.1/Sparkle/SPUUpdaterDelegate.h
[smappservice]: https://developer.apple.com/documentation/servicemanagement/smappservice
[apple-helper]: https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos
[settings]: https://sparkle-project.org/documentation/customization/
[sparkle-setup]: https://sparkle-project.org/documentation/
[cask-cookbook]: https://docs.brew.sh/Cask-Cookbook#optional-stanzas
[tap-trust]: https://docs.brew.sh/Tap-Trust
[brew-query]: https://docs.brew.sh/Querying-Brew
[brew-cask-source]: https://github.com/Homebrew/brew/blob/HEAD/Library/Homebrew/cask/cask.rb
[brew-api]: https://formulae.brew.sh/docs/api/
