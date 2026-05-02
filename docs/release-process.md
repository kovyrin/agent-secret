# Release Process

Agent Secret releases are GitHub Releases backed by signed and notarized macOS
DMG artifacts. The changelog is the source of truth for release notes.

## Roles

- `CHANGELOG.md` accumulates notable changes while development happens.
- The release workflow builds and uploads the macOS DMG and `checksums.txt`.
- The maintainer copies the matching changelog section into the GitHub release
  notes before publishing.

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

7. Watch the tag-triggered CI run until `Draft Release Artifacts` passes.
   The job should create or update a draft GitHub Release with:

   ```text
   Agent-Secret-vX.Y.Z-macos-arm64.dmg
   Agent-Secret-vX.Y.Z-macos-x86_64.dmg
   checksums.txt
   ```

8. Download the draft release assets and verify the DMG:

   ```bash
   shasum -a 256 -c checksums.txt
   codesign --verify --strict --verbose=2 "$artifact"
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
   codesign --verify --deep --strict \
     --verbose=2 "$mount_dir/Agent Secret.app"
   xcrun stapler validate "$mount_dir/Agent Secret.app"
   spctl --assess --type execute \
     --verbose "$mount_dir/Agent Secret.app"
   hdiutil detach "$mount_dir"
   ```

10. Extract release notes from the matching changelog section:

    ```bash
    version="0.0.1"
    awk -v version="$version" '
      $0 ~ "^## \\[" version "\\]" { emit = 1; next }
      emit && /^## \\[/ { exit }
      emit { print }
    ' CHANGELOG.md > /tmp/agent-secret-release-notes.md
    ```

11. Replace the draft release notes with the changelog-derived notes:

    ```bash
    gh release edit "v$version" \
      --notes-file /tmp/agent-secret-release-notes.md
    ```

12. Publish the draft release only after CI and local artifact verification
    pass:

    ```bash
    gh release edit "v$version" --draft=false
    ```

13. Confirm the published release page shows the expected notes and assets.

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

## Failed Release Runs

If a tag-triggered release fails before publication:

1. Fix the issue on `main`.
2. Use a new tag for the next release attempt when the previous draft assets
   should remain available for debugging.
3. Delete failed test releases and tags when they are no longer useful:

   ```bash
   gh release delete vX.Y.Z-test.N --cleanup-tag --yes
   git tag -d vX.Y.Z-test.N
   ```
