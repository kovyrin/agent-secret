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
The tag-triggered workflow runs `scripts/extract-release-notes.sh` to enforce
this before publishing draft artifacts. Local smoke coverage for this contract
lives in `AGENT_SECRET_IN_MISE=1 scripts/test-release-notes.sh`.

## Release Checklist

1. Confirm `main` is clean and current:

   ```bash
   git switch main
   git pull --ff-only
   git status -sb
   ```

2. Review `CHANGELOG.md` for the target version. The section should be
   practical release-note material, not a raw commit log.

3. Replace `Pending` with the release date in `YYYY-MM-DD` form.

4. Run the local checks:

   ```bash
   mise run lint
   mise run build
   ```

5. Commit and push the changelog date update.

6. Create and push the release tag:

   ```bash
   version="0.0.1"
   git tag "v$version"
   git push origin "v$version"
   ```

   The tag-triggered workflow rejects `v*` tags whose target commit is not the
   current `origin/main` commit before validating signing secrets or building
   release artifacts.

7. Watch the tag-triggered CI run until `Draft Release Artifacts` passes.
   The job rejects tags whose changelog section is missing, still marked
   `Pending`, or empty. It should create or update a draft GitHub Release with
   notes from the dated changelog section and these assets:

   ```text
   Agent-Secret-vX.Y.Z-macos-arm64.dmg
   Agent-Secret-vX.Y.Z-macos-x86_64.dmg
   checksums.txt
   ```

8. Download the draft release assets and verify the DMG:

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

9. Mount the DMG and verify the app inside:

   ```bash
   hdiutil attach -readonly -nobrowse \
     -mountpoint "$mount_dir" "$artifact"
   app="$mount_dir/Agent Secret.app"
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
   xcrun stapler validate "$app"
   spctl --assess --type execute \
     --verbose "$app"
   hdiutil detach "$mount_dir"
   ```

10. Confirm the draft release notes match the dated changelog section for the
    tag:

    ```bash
    version="0.0.1"
    gh release view "v$version" --json body --jq .body
    ```

11. Publish the draft release only after CI and local artifact verification
    pass:

    ```bash
    gh release edit "v$version" --draft=false
    ```

12. Confirm the published release page shows the expected notes and assets.

## Signing Preconditions

The tag-triggered release job needs these repository secrets configured:

```text
AGENT_SECRET_CODESIGN_CERT_P12_BASE64
AGENT_SECRET_CODESIGN_CERT_PASSWORD
AGENT_SECRET_CODESIGN_IDENTITY
AGENT_SECRET_NOTARIZE
AGENT_SECRET_NOTARY_KEY
AGENT_SECRET_NOTARY_KEY_ID
AGENT_SECRET_NOTARY_ISSUER_ID
```

Do not print, commit, paste, or attach `.p8`, `.p12`, private key, or password
material. If a notary API key must be recreated, use an App Store Connect Team
Key and store the downloaded `.p8` directly in GitHub Secrets.

## Installer Bootstrap Documentation

Unattended install and uninstall examples must fetch `install.sh` or
`uninstall.sh` from an immutable release tag. Pinned installs set
`AGENT_SECRET_VERSION` to that same tag. Latest installs and uninstalls resolve
the latest release tag first, then fetch the script from that tag. Do not pipe
`main/install.sh` or `main/uninstall.sh` into a shell.

## Toolchain Pin Maintenance

The GitHub workflow pins both `jdx/mise-action` and the `mise` binary that the
action downloads. When updating the CI toolchain, update these values together
in `.github/workflows/ci.yml`:

- `AGENT_SECRET_MISE_VERSION`
- `AGENT_SECRET_MISE_SHA256_MACOS_ARM64`
- each release matrix `mise_sha256` value

Resolve checksums from the official `jdx/mise` release archive for every GitHub
runner architecture:

```bash
version=2026.4.28
shasum -a 256 "mise-v${version}-macos-arm64.tar.gz"
shasum -a 256 "mise-v${version}-macos-x64.tar.gz"
```

Run `AGENT_SECRET_IN_MISE=1 scripts/test-workflow-actions-pinned.sh` after any
workflow change. That smoke test fails if a `jdx/mise-action` step does not set
both `version` and `sha256`.

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
