# Release Process

Agent Secret releases are GitHub Releases backed by signed and notarized macOS
DMG artifacts. The changelog is the source of truth for release notes.

## Roles

- `CHANGELOG.md` accumulates notable changes while development happens.
- The release workflow verifies the matching changelog section, builds the
  macOS DMG and `checksums.txt`, and uses that changelog section as draft
  GitHub Release notes.
- The maintainer verifies the draft notes and artifacts before publishing.

## Version Sections

Every release must have one section in `CHANGELOG.md`:

```markdown
## [0.0.1] - Pending
```

Use `Pending` while the release is being accumulated. During the release, change
that heading to the release date:

```markdown
## [0.0.1] - 2026-05-02
```

After publishing, create the next pending section when there is a concrete next
release target. Do not publish a release whose changelog section is empty.
The tag-triggered workflow runs `scripts/release/extract-release-notes.sh` to enforce
this before publishing draft artifacts. Local smoke coverage for this contract
lives in `AGENT_SECRET_IN_MISE=1 scripts/release/test-release-notes.sh`.

## Release Checklist

1. Confirm `main` is clean and current:

   ```bash
   git switch main
   git pull --ff-only
   git status -sb
   ```

1. Review `CHANGELOG.md` for the target version. The section should be
   practical release-note material, not a raw commit log.

1. Audit user-facing docs and the bundled coding-agent skill for every app
   functionality change before tagging. If CLI commands, secret reference
   schemes, setup flows, diagnostics, migration paths, or safe verification
   guidance changed, update `.agents/skills/agent-secret/SKILL.md` in the same
   release. If no skill update is needed, record why in the release prep issue
   or release PR.

1. Replace `Pending` with the release date in `YYYY-MM-DD` form.

1. Run the local checks:

   ```bash
   mise run lint
   mise run build
   ```

1. Run the bounded-session product E2E in
   `docs/session-e2e-validation.md` before tagging. The run must include
   multi-secret session creation from config plus CLI args, same-tree
   `with-session` reuse, and the checkpoint:
   `detached process-tree replay rejected before child spawn`.

1. Run the mixed-install helper recovery smoke before tagging. This catches the
   common local-operator state where the installed release background helper is
   valid but an ad-hoc development CLI is earlier on `PATH`:

   ```bash
   AGENT_SECRET_RELEASE_SMOKE_REQUIRE_INSTALLED_CLI=1 \
     AGENT_SECRET_IN_MISE=1 \
     scripts/release/smoke-stale-dev-cli-diagnostics.sh
   ```

1. Commit and push the changelog date update.

1. Create and push the release tag:

   ```bash
   version="0.0.1"
   git tag "v$version"
   git push origin "v$version"
   ```

   The tag-triggered workflow rejects `v*` tags whose target commit is not the
   current `origin/main` commit before validating signing secrets or building
   release artifacts.

1. Watch the tag-triggered CI run until `Draft Release Artifacts` passes.
   The job rejects tags whose changelog section is missing, still marked
   `Pending`, or empty. It should create or update a draft GitHub Release with
   notes from the dated changelog section and these assets:

   ```text
   Agent-Secret-vX.Y.Z-macos-arm64.dmg
   checksums.txt
   ```

1. Download the draft release assets and verify the DMG:

   ```bash
   shasum -a 256 -c checksums.txt
   codesign --verify --strict --verbose=2 "$artifact"
   codesign -dv --verbose=4 "$artifact" 2>&1 |
     grep '^TeamIdentifier=B6L7QLWTZW$'
   xcrun stapler validate "$artifact"
   spctl --assess --type open \
     --context context:primary-signature \
     --verbose "$artifact"
   hdiutil verify "$artifact"
   ```

1. Mount the DMG and verify the app inside:

   ```bash
   hdiutil attach -readonly -nobrowse \
     -mountpoint "$mount_dir" "$artifact"
   app="$mount_dir/Agent Secret.app"
   cli="$app/Contents/Resources/bin/agent-secret"
   daemon="$app/Contents/Library/Helpers/AgentSecretDaemon.app"
   codesign --verify --deep --strict \
     --verbose=2 "$app"
   codesign -dv --verbose=4 "$app" 2>&1 |
     grep '^TeamIdentifier=B6L7QLWTZW$'
   /usr/libexec/PlistBuddy \
     -c 'Print :CFBundleIdentifier' \
     "$app/Contents/Info.plist" |
     grep '^com.kovyrin.agent-secret$'
   /usr/libexec/PlistBuddy \
     -c 'Print :CFBundleIdentifier' \
     "$daemon/Contents/Info.plist" |
     grep '^com.kovyrin.agent-secret.daemon$'
   test -x "$cli"
   test ! -L "$cli"
   codesign --verify --strict --verbose=2 "$cli"
   xcrun stapler validate "$app"
   spctl --assess --type execute \
     --verbose "$app"
   hdiutil detach "$mount_dir"
   ```

1. Confirm the draft release notes match the dated changelog section for the
    tag:

    ```bash
    version="0.0.1"
    gh release view "v$version" --json body --jq .body
    ```

1. Publish the draft release only after CI and local artifact verification
    pass:

    ```bash
    gh release edit "v$version" --draft=false
    ```

1. Confirm the published release page shows the expected notes and assets.

1. Update the Homebrew cask to the published release before announcing the
    release. Use the SHA-256 digest for the
    `Agent-Secret-vX.Y.Z-macos-arm64.dmg` asset:

    ```bash
    version="0.0.1"
    artifact="Agent-Secret-v${version}-macos-arm64.dmg"
    gh release download "v$version" --pattern "$artifact" --dir "$RUNNER_TEMP"
    shasum -a 256 "$RUNNER_TEMP/$artifact"
    ```

    Then update `Casks/agent-secret.rb`, run the cask checks, and push the cask
    bump:

    ```bash
    brew tap kovyrin/agent-secret https://github.com/kovyrin/agent-secret
    AGENT_SECRET_IN_MISE=1 scripts/release/check-homebrew-cask.sh "v$version"
    brew audit --cask --strict --online --tap=kovyrin/agent-secret agent-secret
    git add Casks/agent-secret.rb
    git commit -m "Bump Homebrew cask to v$version"
    git push origin main
    ```

1. Verify the public Homebrew upgrade path from a fresh tap update:

    ```bash
    brew update
    brew upgrade --cask agent-secret
    brew list --cask --versions agent-secret | grep "$version"
    /opt/homebrew/bin/agent-secret --version | grep "$version"
    /opt/homebrew/bin/agent-secret install-cli --force
    test "$(readlink "$HOME/.local/bin/agent-secret")" = \
      "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret"
    /opt/homebrew/bin/agent-secret doctor
    /opt/homebrew/bin/agent-secret skill-install --force
    ```

    Also run one test-only `agent-secret exec` flow that does not print secret
    values. If the cask check or Homebrew upgrade fails, the release is not
    complete.

## Clean-Machine Release Candidate Drill

Before public announcement, test the latest release candidate on a clean macOS
user account or VM:

1. Install through the human DMG flow by dragging `Agent Secret.app` into
   `/Applications`.
2. Open the app, install command-line tools, and run `agent-secret doctor`.
3. Approve 1Password Desktop SDK authorization and run one test-only
   `agent-secret exec` flow that does not print secret values.
4. Install or upgrade through the pinned release-asset `install.sh` flow for
   the same tag.
5. Confirm `agent-secret doctor`, `agent-secret skill-install`, and the bundled
   skill symlink work after upgrade.
6. Run the pinned `uninstall.sh` flow and confirm it removes the app, command
   symlink, skill symlink, and support state while preserving audit logs by
   default.

Record evidence in the public release prep issue before treating the candidate
as public-announcement ready.

The repeatable UTM-based version of this drill is documented in
`docs/macos-vm-validation.md` and can be launched with
`scripts/validate-utm-clean-install.sh` after the golden VM is prepared.

## Local Release Smoke Scripts

The public docs and release automation contracts are covered by these smoke
scripts:

```bash
AGENT_SECRET_IN_MISE=1 scripts/test-install.sh
AGENT_SECRET_IN_MISE=1 scripts/test-uninstall.sh
AGENT_SECRET_IN_MISE=1 scripts/build/test-build-entitlements.sh
AGENT_SECRET_IN_MISE=1 scripts/release/test-release-signing-env.sh
AGENT_SECRET_IN_MISE=1 scripts/release/test-release-ancestry.sh
AGENT_SECRET_IN_MISE=1 scripts/release/test-release-notes.sh
AGENT_SECRET_IN_MISE=1 scripts/release/test-release-publish.sh
AGENT_SECRET_IN_MISE=1 scripts/release/test-release-version.sh
AGENT_SECRET_IN_MISE=1 scripts/release/test-release-docs.sh
AGENT_SECRET_IN_MISE=1 scripts/release/smoke-stale-dev-cli-diagnostics.sh
AGENT_SECRET_IN_MISE=1 scripts/checks/test-public-docs.sh
AGENT_SECRET_IN_MISE=1 scripts/checks/test-workflow-actions-pinned.sh
AGENT_SECRET_IN_MISE=1 scripts/checks/test-cloudflare-curl-token-handling.sh
AGENT_SECRET_IN_MISE=1 scripts/release/test-homebrew-cask.sh
AGENT_SECRET_IN_MISE=1 scripts/release/test-homebrew-cask-audit.sh
cd approver && swift run agent-secret-app-smoke
```

The live bounded-session product E2E is documented in
`docs/session-e2e-validation.md`. Run it manually before release tags because
it requires the real native approver, test-only 1Password refs, and a macOS
user launchd session for the detached process-tree replay check.

The Homebrew cask should also be checked after every cask bump:

```bash
AGENT_SECRET_IN_MISE=1 scripts/release/check-homebrew-cask.sh vX.Y.Z
brew audit --cask --strict --online --tap=kovyrin/agent-secret agent-secret
```

## Signing Preconditions

Tag-triggered GitHub releases require production signing and notarization.

The tag-triggered release job needs these repository secrets configured:

```text
AGENT_SECRET_CODESIGN_CERT_P12_BASE64
AGENT_SECRET_CODESIGN_CERT_PASSWORD
AGENT_SECRET_CODESIGN_IDENTITY
AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_ID
AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_SECRET
AGENT_SECRET_NOTARIZE
AGENT_SECRET_NOTARY_KEY
AGENT_SECRET_NOTARY_KEY_ID
AGENT_SECRET_NOTARY_ISSUER_ID
```

Do not print, commit, paste, or attach `.p8`, `.p12`, private key, or password
material, or OAuth client material. If a notary API key must be recreated, use
an App Store Connect Team Key and store the downloaded `.p8` directly in
GitHub Secrets.

The bundled GCP OAuth client secrets are build inputs for official Agent Secret
release artifacts. Keep the source values in the maintainer password manager,
copy only the current values into GitHub Actions secrets, and never commit the
values or password-manager references to the repository.

For this repository's maintainer releases, the current Developer ID identity is:

```text
Developer ID Application: Oleksiy Kovyrin (B6L7QLWTZW)
```

Validate local production signing configuration before any signed local release
build:

```bash
scripts/release/check-release-signing-env.sh
AGENT_SECRET_IN_MISE=1 scripts/release/build-release.sh v0.0.0 \
  --require-production-signing
```

## Installer Bootstrap Documentation

Unattended install and uninstall examples should use release-asset bootstrap
scripts:

<!-- markdownlint-disable MD013 -->

```bash
curl -fsSL https://github.com/kovyrin/agent-secret/releases/latest/download/install.sh | sh
curl -fsSL https://github.com/kovyrin/agent-secret/releases/latest/download/uninstall.sh | sh
```

<!-- markdownlint-enable MD013 -->

For pinned installs, fetch the script from the release tag:

<!-- markdownlint-disable MD013 -->

```bash
curl -fsSL https://github.com/kovyrin/agent-secret/releases/download/v0.0.0/install.sh | sh
```

<!-- markdownlint-enable MD013 -->

The tag-triggered release workflow runs
`scripts/release/prepare-bootstrap-scripts.sh` so the published `install.sh`
asset has the release tag baked in and does not require callers to pass
`AGENT_SECRET_VERSION`. Do not pipe `main/install.sh`, `main/uninstall.sh`,
`main` raw GitHub URLs, or branch raw GitHub URLs into a shell for public
install instructions.

## Toolchain Pin Maintenance

The GitHub workflow installs `mise` with
`scripts/checks/install-ci-mise.sh`. The installer downloads the official
release binary with retries, falls back to the GitHub release API if direct
asset downloads keep failing, verifies its SHA-256 digest, and installs it at
`$HOME/.local/share/mise/bin/mise`. When updating the CI toolchain, update these
values together in `.github/workflows/ci.yml`:

- `AGENT_SECRET_MISE_VERSION`
- `AGENT_SECRET_MISE_SHA256_MACOS_ARM64`

The workflow passes the built-in Actions token to `mise run setup` so aqua and
github tool resolution use authenticated GitHub API requests.

Resolve checksums from the official `jdx/mise` release binary for the GitHub
runner architecture:

```bash
version=2026.4.28
curl -fsSLO "https://github.com/jdx/mise/releases/download/v${version}/mise-v${version}-macos-arm64"
shasum -a 256 "mise-v${version}-macos-arm64"
```

Run the workflow pin smoke test after any workflow change:

```bash
AGENT_SECRET_IN_MISE=1 scripts/checks/test-workflow-actions-pinned.sh
```

That smoke test fails if third-party workflow actions are not pinned to full
commit SHAs. It also fails if a future `jdx/mise-action` step does not set both
`version` and `sha256`.

Signed release builds run through the checksum-verified CI `mise` installer and
fixed macOS system tools for signing, notarization, and DMG assembly. Keep the
workflow tool version and checksum pinned when changing release automation.

## Failed Release Runs

If a tag-triggered release fails before publication:

1. Fix the issue on `main`.
2. Use a new tag for the next release attempt when the previous draft assets
   should remain available for debugging.
3. Rerun tag workflows only while the GitHub Release is still a draft. The
   workflow refuses to replace assets on a published release.
4. Delete failed test releases and tags when they are no longer useful:

   ```bash
   gh release delete vX.Y.Z-test.N --cleanup-tag --yes
   git tag -d vX.Y.Z-test.N
   ```
