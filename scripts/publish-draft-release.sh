#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "publish draft release: $*" >&2
  exit 1
}

if [ "$#" -lt 2 ]; then
  fail "usage: scripts/publish-draft-release.sh TAG ARTIFACT..."
fi

tag="$1"
shift
artifacts=("$@")
notes="${AGENT_SECRET_RELEASE_NOTES:-macOS arm64 and x86_64 artifacts built from ${GITHUB_SHA:-unknown}.}"

if gh release view "$tag" >/dev/null 2>&1; then
  is_draft="$(gh release view "$tag" --json isDraft --jq .isDraft)"
  if [ "$is_draft" != "true" ]; then
    fail "release $tag is already published; refusing to replace assets"
  fi
  gh release upload "$tag" "${artifacts[@]}" --clobber
else
  gh release create "$tag" \
    "${artifacts[@]}" \
    --draft \
    --verify-tag \
    --title "$tag" \
    --notes "$notes"
fi
