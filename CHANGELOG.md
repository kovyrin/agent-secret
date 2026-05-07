# Changelog

<!-- markdownlint-disable MD024 -->

All notable changes to Agent Secret are recorded here.

This file follows the spirit of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses semantic
version numbers for public releases.

## Changelog Rules

- Add entries under the next pending release as work lands.
- Use clear, user-facing language. Mention implementation details only when
  they matter to an operator or integrator.
- Group entries under these headings when they apply: `Added`, `Changed`,
  `Fixed`, `Removed`, `Security`, and `Internal`.
- Use `Pending` for an unreleased version. Replace `Pending` with the release
  date in `YYYY-MM-DD` form as part of the release commit.
- GitHub release notes are copied from the matching version section in this
  file before a release is published.

## [0.0.8] - Pending

### Added

- `agent-secret --version` now prints the installed CLI version.
- `agent-secret item describe` now performs approval-gated, secret-safe
  1Password item metadata inspection, including text, JSON, and env-ref output
  modes for discovering available field refs without printing values.

### Changed

- The approval app now immediately denies requests while the Mac is locked
  instead of waiting for human approval that cannot happen.
- The approval dialog now maps Esc to Deny and Enter to Allow once.
- The approval dialog now emphasizes the request reason before command,
  project, scope, and secret details.
- The approval dialog now uses a warm reason highlight to make the access
  rationale stand apart from requested secret details.
- The approval dialog now emphasizes the item and field portions of displayed
  1Password references.

### Fixed

- Local development installs now report a changelog-aligned dev version with
  git revision, and bundle builds fail when the requested version does not
  match the latest `CHANGELOG.md` section.
- Profile commands that resolve multiple 1Password refs no longer fail because
  a stale cached 1Password desktop SDK client reports `invalid client id` or
  `no vault matched` while `agent-secret doctor` still looks healthy.
- Long-running daemon sessions can now resolve secrets from different
  1Password desktop accounts in one process instead of reusing the first
  account selected by the SDK.

### Internal

- Documented the temporary 1Password SDK fork, its removal criteria, and the
  package boundary that keeps SDK access contained in `internal/opresolver`.

## [0.0.7] - 2026-05-05

### Added

- Added public release security policy, contribution stance, and a dated
  security-boundary review for the current macOS release candidate.

### Changed

- `agent-secret exec` no longer rejects current-user-writable developer tools
  such as mise-installed commands before approval.
- The README now states the current support boundaries and limitations for the
  initial macOS Apple Silicon release.

### Fixed

- The daemon now retires when the installed daemon executable is replaced, and
  `agent-secret exec` retries once so the command uses the upgraded daemon.
- The daemon now refreshes a cached 1Password desktop SDK client after a stale
  client reports that no vault matched an otherwise valid approved ref.
- The daemon now keeps the owning 1Password SDK client alive for cached desktop
  resolvers, preventing later `invalid client id` failures.
- `agent-secret doctor` now reports and checks the 1Password account from the
  discovered project config when one is present.

## [0.0.6] - 2026-05-04

### Fixed

- Account selection is now bound into each `agent-secret exec` request, so
  `--account`, project config changes, and account environment variables take
  effect even when the per-user daemon is already running.
- With no explicit account, `agent-secret` now detects the single signed-in
  1Password CLI account before falling back to `my.1password.com`.
- The unattended installer now runs post-install diagnostics with the caller's
  original `PATH`, allowing diagnostics to see the same `op` command as the
  user's shell.

## [0.0.5] - 2026-05-04

### Fixed

- The unattended installer now completes even when post-install diagnostics
  report that 1Password desktop integration is not configured yet.

## [0.0.4] - 2026-05-04

### Fixed

- The unattended installer no longer requires Xcode or Command Line Tools for
  `xcrun stapler validate`; release notarization remains verified by CI and
  Gatekeeper.

## [0.0.3] - 2026-05-04

### Fixed

- The setup app now renders the shell PATH command in a dark selectable
  monospace block instead of plain alert text.

## [0.0.2] - 2026-05-04

Follow-up macOS install UX release for clean-machine CLI setup.

### Fixed

- The setup app now finishes command-line tool installation with a one-button
  confirmation instead of returning to the original setup dialog.
- `agent-secret install-cli` now warns when the installed command directory is
  not on `PATH` and shows a zsh one-liner for a clean macOS shell.
- The unattended installer now bases that warning on the caller's original
  `PATH`, not on the installer's sanitized tool `PATH`.

## [0.0.1] - 2026-05-04

Initial macOS-first release for installing and dogfooding Agent Secret as one
local app, CLI, daemon, and bundled coding-agent skill.

### Added

- Local `agent-secret exec` command for running a bounded child process with
  approved 1Password-backed secrets injected into its environment.
- Per-user daemon with private socket storage, peer credential checks, trusted
  CLI binding, and JSONL metadata audit logs.
- Native macOS approval app for reviewing requested secret references, command
  context, account scope, reuse policy, and approval or denial decisions without
  displaying secret values.
- 1Password SDK resolver support with project config, profile-level account
  selection, per-secret account overrides, and opt-in live integration tests.
- Environment-file support for wrapping legacy dotenv-style commands without
  printing raw secret values.
- Reusable approval windows with bounded use counts and short cache lifetimes.
- CLI commands for installing the command shim and bundled agent skill:
  `agent-secret install-cli` and `agent-secret skill-install`.
- Unified `Agent Secret.app` bundle containing the setup UI, CLI binary, daemon
  helper app, app icon, and bundled `agent-secret` coding-agent skill.
- Root `install.sh` and `uninstall.sh` scripts for unattended macOS install,
  upgrade, and removal flows.
- Local and CI release artifact builder for macOS DMGs plus `checksums.txt`.
- Developer ID signing, App Store Connect notarization, stapling, and
  Gatekeeper verification for release DMGs and the app bundle inside them.
- Apple Silicon-only release artifacts for the initial public macOS release.
- Release process documentation that uses this changelog as the source for
  GitHub release notes.

### Security

- Secret values are kept out of help output, approval UI logs, audit records,
  test output, and release documentation.
- Release signing credentials are loaded from GitHub Actions secrets into a
  temporary CI keychain that is deleted after the release artifact job.

### Fixed

- Native approval decisions stay alive long enough to submit after the approval
  window closes.
