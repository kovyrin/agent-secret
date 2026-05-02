# Changelog

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

## [0.0.1] - Pending

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
- Release process documentation that uses this changelog as the source for
  GitHub release notes.

### Security

- Secret values are kept out of help output, approval UI logs, audit records,
  test output, and release documentation.
- Release signing credentials are loaded from GitHub Actions secrets into a
  temporary CI keychain that is deleted after the release artifact job.
