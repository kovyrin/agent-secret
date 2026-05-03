# macOS Distribution Plan

## Goal

Ship Agent Secret as a macOS-first tool that a teammate can install, update, and
use without building from source.

The product should feel like one app:

- One `Agent Secret.app` bundle is the canonical installation.
- The CLI lives inside that app bundle.
- The daemon lives inside that app bundle as a nested helper app.
- The user can install the command-line shim from the app on first launch.
- Agents and automation can install or upgrade with an unattended `curl | bash`
  flow.

## Non-Goals

- No Linux or Windows packaging.
- No system-wide privileged installer for v1.
- No Mac App Store distribution.
- No private distribution channel. The repository and release artifacts can stay
  public.
- No automatic background updater in v1. Re-running the installer or using
  Homebrew later is enough.

## Assumptions

- A paid Apple Developer Program account is available.
- Team-ready releases should be Developer ID signed and notarized before they
  are announced for daily use.
- Unsigned local DMGs are still useful as an intermediate implementation
  checkpoint, but they are not the final team distribution target.

## Target Install Shape

```text
/Applications/Agent Secret.app
  Contents/MacOS/Agent Secret
  Contents/Library/Helpers/AgentSecretDaemon.app
    Contents/MacOS/Agent Secret
  Contents/Resources/bin/agent-secret
  Contents/Resources/skills/agent-secret
```

The CLI shim is a symlink:

```text
~/.local/bin/agent-secret -> /Applications/Agent Secret.app/Contents/Resources/bin/agent-secret
```

The bundled coding-agent skill is also a symlink:

```text
~/.agents/skills/agent-secret -> /Applications/Agent Secret.app/Contents/Resources/skills/agent-secret
```

The app bundle is the version boundary. Updating `Agent Secret.app` updates the
approval UI, daemon, and CLI together.

## User Flows

### Interactive Install

1. User downloads `Agent-Secret-vX.Y.Z.dmg` from GitHub Releases.
2. User opens the DMG and drags `Agent Secret.app` into `/Applications`.
3. User launches `Agent Secret.app`.
4. App shows setup status and offers an `Install Command Line Tool` action.
5. The action creates or refreshes the `~/.local/bin/agent-secret` symlink.
6. App verifies the shim and shows the command to run:

   ```bash
   agent-secret doctor
   ```

The app or CLI can also install the bundled coding-agent skill:

```bash
agent-secret skill-install
```

### Unattended Install

Agents and setup scripts use:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/kovyrin/agent-secret/main/install.sh | sh
```

The installer should:

1. Detect `arm64` or `x86_64`.
2. Resolve the latest release unless `AGENT_SECRET_VERSION` is set.
3. Download the matching release artifact.
4. Verify the checksum, DMG signature, Developer ID Team ID, Gatekeeper
   assessment, notarization ticket, mounted app bundle ID, daemon helper bundle
   ID, and bundled CLI signature.
5. Stop the old per-user daemon if it is running.
6. Copy `Agent Secret.app` to `/Applications` by default.
7. Create or refresh the CLI symlink in `~/.local/bin`.
8. Run `agent-secret doctor`.

Useful installer options:

```bash
AGENT_SECRET_VERSION=v0.3.1 install.sh
AGENT_SECRET_APP_DIR="$HOME/Applications" install.sh
AGENT_SECRET_BIN_DIR="$HOME/.local/bin" install.sh
AGENT_SECRET_SKILLS_DIR="$HOME/.agents/skills" install.sh
```

For local smoke tests, set `AGENT_SECRET_INSTALL_DEV_MODE=1` and point
`AGENT_SECRET_DMG` plus `AGENT_SECRET_CHECKSUMS_FILE` at locally built
artifacts. Unsigned local artifacts must also set
`AGENT_SECRET_ALLOW_UNSIGNED_INSTALL=1`; signed but unstapled local artifacts
can set `AGENT_SECRET_REQUIRE_NOTARIZATION=0`. Production installs pin the
GitHub host, repository, Team ID `B6L7QLWTZW`, and bundle identifiers
`com.kovyrin.agent-secret` and `com.kovyrin.agent-secret.daemon`; overriding
those release trust roots requires development mode and local artifacts.

### Upgrade

The upgrade path is intentionally the same as install:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/kovyrin/agent-secret/main/install.sh | sh
```

The installer replaces the app bundle atomically enough for a user-level tool:
stop daemon, write a temporary app bundle next to the target, move it into
place, recreate the symlink, run diagnostics.

### Uninstall

Users should have both a manual uninstall and an unattended uninstall path.

Manual uninstall:

```bash
agent-secret daemon stop || true
rm -f ~/.local/bin/agent-secret
rm -f ~/.agents/skills/agent-secret
rm -rf "/Applications/Agent Secret.app"
rm -rf "$HOME/Library/Application Support/agent-secret"
```

Unattended uninstall:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/kovyrin/agent-secret/main/uninstall.sh | sh
```

The uninstall script should:

1. Stop the per-user daemon if it is running.
2. Remove the Agent Secret CLI symlink if it points at an Agent Secret app.
3. Remove `Agent Secret.app` from the configured app directory.
4. Remove the Agent Secret skill symlink if it points at the app bundle.
5. Remove `~/Library/Application Support/agent-secret`.
6. Leave audit logs in place unless explicitly requested.

Useful uninstall options:

```bash
AGENT_SECRET_APP_DIR="$HOME/Applications" uninstall.sh
AGENT_SECRET_BIN_DIR="$HOME/.local/bin" uninstall.sh
AGENT_SECRET_SKILLS_DIR="$HOME/.agents/skills" uninstall.sh
AGENT_SECRET_REMOVE_AUDIT_LOGS=1 uninstall.sh
```

For isolated tests, `AGENT_SECRET_SUPPORT_DIR` and `AGENT_SECRET_AUDIT_DIR`
may point at temporary `agent-secret` directories only when
`AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1` is also set. The script refuses
empty, relative, broad, symlinked, and non-`agent-secret` directory targets.

Audit logs are durable by design and should require an explicit separate
removal command:

```bash
rm -rf "$HOME/Library/Logs/agent-secret"
```

## Release Artifact Shape

Each GitHub release should publish:

```text
Agent-Secret-vX.Y.Z-macos-arm64.dmg
Agent-Secret-vX.Y.Z-macos-x86_64.dmg
checksums.txt
```

Initial implementation can publish only `arm64` if that matches the first team
rollout. The release workflow should make the missing architecture explicit in
the README instead of silently pretending it exists.

The DMG should contain:

```text
Agent Secret.app
Applications -> /Applications
```

The ZIP artifact is optional. DMG is the human-friendly install surface; the
unattended installer can also download a ZIP if that is simpler to unpack
reliably in shell.

## Code Changes

### Bundle Layout

- Replace the separate development install layout with one top-level
  `Agent Secret.app`.
- Build the Go CLI to `Contents/Resources/bin/agent-secret`.
- Build the daemon binary into `AgentSecretDaemon.app`.
- Place `AgentSecretDaemon.app` in `Contents/Library/Helpers`.
- Bundle the Agent Secret coding-agent skill in
  `Contents/Resources/skills/agent-secret`.
- Keep the daemon as an app, not a raw background binary, so 1Password Desktop
  sees a stable Agent Secret app identity.

### CLI Discovery

The CLI must be able to find the nested daemon helper relative to itself.

Expected lookup order:

1. If running from inside `Agent Secret.app`, use:

   ```text
   ../../Library/Helpers/AgentSecretDaemon.app
   ```

2. If running through the symlink, resolve the symlink and then use the same
   app-relative path.
3. For development installs, look for
   `~/Applications/Agent Secret.app/Contents/Library/Helpers/AgentSecretDaemon.app`.
4. For unbundled local test binaries only, keep direct sibling binary discovery
   so package tests and ad hoc builds remain easy to run.

### App Setup UI

The app should expose a small setup screen:

- CLI installed: yes/no.
- CLI path.
- Installed app path.
- Daemon status.
- Button: `Install Command Line Tool`.
- Button: `Run Diagnostics`.

The setup UI must not require any 1Password access.

### CLI Install Command

Add an unattended command for scripts:

```bash
agent-secret install-cli
```

Behavior:

- Create parent directory for the target symlink.
- Replace an existing Agent Secret symlink.
- Refuse to overwrite an unrelated regular file unless `--force` is passed.
- Default target: `~/.local/bin/agent-secret`.
- Support:

  ```bash
  agent-secret install-cli --bin-dir ~/.local/bin
  agent-secret install-cli --force
  ```

The app button should call the same internal implementation.

### Skill Install Command

Add an unattended command for installing the bundled coding-agent skill:

```bash
agent-secret skill-install
```

Behavior:

- Create parent directory for the target symlink.
- Link the bundled skill into `~/.agents/skills/agent-secret`.
- Replace an existing Agent Secret symlink.
- Refuse to overwrite an unrelated regular file unless `--force` is passed.
- Default target: `~/.agents/skills/agent-secret`.
- Support:

  ```bash
  agent-secret skill-install --skills-dir ~/.agents/skills
  agent-secret skill-install --force
  ```

### Installer Script

Add `install.sh` at repo root.

Responsibilities:

- Download release metadata from GitHub.
- Select the artifact for the local architecture.
- Verify checksum.
- Mount or unpack the artifact.
- Copy the app bundle.
- Run the bundled CLI's `install-cli`.
- Run the bundled CLI's `skill-install`.
- Run `agent-secret doctor`.

The installer must not depend on Homebrew, 1Password CLI, or repo checkout
state.

## Signing and Notarization

For local development, ad hoc signing is acceptable.

For team distribution, release artifacts must be Developer ID signed and
notarized before the DMG is published. The project has access to a paid Apple
Developer Program account, so signing and notarization should be part of the
release-ready path rather than a vague future option. Current Apple guidance for
software outside the Mac App Store is to use Developer ID signing and
notarization so Gatekeeper can verify the app under default macOS settings.

Release CI will need:

- Developer ID Application certificate.
- Apple notarization credentials stored as GitHub Actions secrets. Prefer an
  App Store Connect API key for CI over an Apple ID password.
- Apple Team ID, key ID, issuer ID, and private API key material.
- Hardened runtime entitlements if required by the app bundle.
- A release job that signs nested code from the inside out:
  - Go binaries.
  - Nested daemon helper app.
  - Main app bundle.
  - DMG.
- Notarization submission.
- Stapling to the app or DMG.
- Verification with `spctl` and `stapler`.

The first release epic can still produce unsigned local artifacts to prove the
bundle layout and installer flow. The first release intended for team use should
complete signing, notarization, stapling, and Gatekeeper verification.

## Homebrew Later

Homebrew should come after GitHub Releases are reliable.

Preferred shape:

```bash
brew tap kovyrin/agent-secret
brew install --cask agent-secret
brew upgrade agent-secret
```

The cask should install the same signed/notarized app bundle from GitHub
Releases and run the CLI symlink step as a post-install action only if Homebrew
allows it cleanly. If that becomes messy, the cask can install only the app and
the README can tell users to run:

```bash
agent-secret install-cli
```

## Implementation Epics

### Epic 1: App Bundle Reshape

Status: Implemented

Deliverables:

- Build script creates one top-level `Agent Secret.app`.
- CLI binary is embedded in the app bundle.
- Daemon helper app is embedded in the app bundle.
- Agent Secret coding-agent skill is embedded in the app bundle.
- Existing `mise run dev:install` installs the new app-bundle layout.
- Existing local `agent-secret exec` smoke still works.

Acceptance checks:

```bash
mise run lint
mise run build
mise run dev:install
agent-secret doctor
agent-secret exec \
  --reason "Install smoke" \
  --secret TOKEN=op://Example/Item/token \
  -- env
```

The smoke should use a real test-only ref locally and must not print the secret
value.

### Epic 2: CLI Symlink Installation

Status: Implemented

Deliverables:

- `agent-secret install-cli`.
- `agent-secret skill-install`.
- App setup UI can install the CLI.
- Help and README document install and upgrade.
- Tests cover symlink creation, replacement, and refusal to overwrite unrelated
  files for the command and skill installers.

Acceptance checks:

```bash
agent-secret install-cli --bin-dir "$TMPDIR/agent-secret-bin"
"$TMPDIR/agent-secret-bin/agent-secret" doctor
agent-secret skill-install --skills-dir "$TMPDIR/agent-secret-skills"
test -f "$TMPDIR/agent-secret-skills/agent-secret/SKILL.md"
```

### Epic 3: Release Artifact Builder

Status: Implemented for local ad-hoc artifacts and tag-triggered signed
artifacts when release secrets are configured

Deliverables:

- Script to produce `Agent-Secret-vX.Y.Z-macos-arm64.dmg`.
- DMG contains app bundle and `/Applications` symlink.
- Checksums are generated.
- CI can build artifacts on tag push after production signing preflight passes.

Acceptance checks:

```bash
scripts/build-release.sh v0.0.0-dev
shasum -a 256 dist/*
hdiutil verify dist/Agent-Secret-v0.0.0-dev-macos-arm64.dmg
```

### Epic 4: Signed and Notarized Releases

Status: Implemented; tag-triggered maintainer releases require Developer ID
certificate and notarization secrets

Deliverables:

- Optional Developer ID signing in local app bundle and release artifact builds.
- Required Developer ID signing and notarization for tag-triggered GitHub
  releases from this repository.
- Release signing preflight before GitHub Actions imports certificates or
  builds artifacts.
- Stapled artifact when `AGENT_SECRET_NOTARIZE=1` is used.
- Gatekeeper verification documented for signed/notarized releases.

Release signing environment:

```bash
AGENT_SECRET_CODESIGN_IDENTITY="Developer ID Application: Example, Inc. (TEAMID)"
AGENT_SECRET_CODESIGN_ENTITLEMENTS=path/to/entitlements.plist
AGENT_SECRET_NOTARIZE=1
AGENT_SECRET_NOTARY_KEY="$(cat AuthKey_KEYID.p8)"
AGENT_SECRET_NOTARY_KEY_ID=KEYID
AGENT_SECRET_NOTARY_ISSUER_ID=ISSUER_UUID
```

`AGENT_SECRET_NOTARY_KEY` may also be a path to a `.p8` API key file. Local
builds without `AGENT_SECRET_CODESIGN_IDENTITY` use ad-hoc signing, and local
builds without `AGENT_SECRET_NOTARIZE=1` do not submit to Apple. Tag-triggered
GitHub releases fail preflight instead of publishing ad-hoc artifacts when any
production signing input is missing.

GitHub release signing imports a Developer ID certificate into a temporary
keychain before building artifacts. Before import, the workflow runs
`scripts/check-release-signing-env.sh`; artifact builds then call
`scripts/build-release.sh "$GITHUB_REF_NAME" --require-production-signing`.
Configure these repository secrets:

```text
AGENT_SECRET_CODESIGN_IDENTITY
AGENT_SECRET_CODESIGN_CERT_P12_BASE64
AGENT_SECRET_CODESIGN_CERT_PASSWORD
AGENT_SECRET_NOTARIZE
AGENT_SECRET_NOTARY_KEY
AGENT_SECRET_NOTARY_KEY_ID
AGENT_SECRET_NOTARY_ISSUER_ID
```

For maintainer releases from this repository, `AGENT_SECRET_CODESIGN_IDENTITY`
is currently:

```text
Developer ID Application: Oleksiy Kovyrin (B6L7QLWTZW)
```

`AGENT_SECRET_CODESIGN_CERT_P12_BASE64` is the base64-encoded `.p12` exported
from Keychain Access. The CI keychain is deleted after the release artifact
step.

Acceptance checks:

```bash
scripts/build-release.sh v0.0.0-dev
scripts/check-release-signing-env.sh
scripts/build-release.sh v0.0.0-dev --require-production-signing
codesign --verify --deep --strict "/Applications/Agent Secret.app"
spctl --assess --type execute --verbose "/Applications/Agent Secret.app"
xcrun stapler validate "/Applications/Agent Secret.app"
```

Only the ad-hoc release builder path can be verified locally without Apple
credentials. The Developer ID path requires the certificate and App Store
Connect API key in the release environment.

### Epic 5: Unattended Installer

Status: Implemented

Deliverables:

- Root `install.sh`.
- Root `uninstall.sh`.
- Version pin support.
- Custom app/bin dir support.
- Checksum verification.
- Clean failure messages for unsupported architecture, missing release, and
  checksum mismatch.
- Uninstall removes app, shim, and application support state while preserving
  audit logs by default.
- Install and uninstall manage the Agent Secret skill symlink.

Acceptance checks:

```bash
AGENT_SECRET_VERSION=v0.0.0-dev ./install.sh
agent-secret doctor
./uninstall.sh
test ! -e ~/.local/bin/agent-secret
```

### Epic 6: Homebrew Cask

Status: Deferred

Deliverables:

- Public tap or cask formula.
- README installation section.
- Upgrade instructions.

Acceptance checks:

```bash
brew install --cask kovyrin/agent-secret/agent-secret
agent-secret doctor
brew upgrade agent-secret
```

## Risks and Decisions

- `/Applications` may require admin permissions on some managed machines. The
  installer should support `~/Applications` as a fallback.
- Shell PATH setup is not solved by installing the symlink. The app and
  installer should warn if the selected bin directory is not on PATH.
- Signing requires careful GitHub Actions secret management, certificate
  import, and keychain cleanup.
- Nested helper signing order matters. Release automation should make signing
  deterministic rather than relying on manual Xcode export behavior.
- The daemon helper must retain the app identity that 1Password Desktop shows
  in the approval prompt.
- DMG is the human surface. The unattended installer can use a ZIP internally if
  it makes checksum and extraction simpler.

## References

- Apple Developer ID overview:
  <https://developer.apple.com/support/developer-id/>
- Apple packaging guidance for direct Mac distribution:
  <https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution>
- Apple notarization guidance:
  <https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution>
