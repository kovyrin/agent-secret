#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
# shellcheck source=scripts/bundle-metadata.sh
# shellcheck disable=SC1091
source "$project_root/scripts/bundle-metadata.sh"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-release-version-test.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  echo "test-release-version: $*" >&2
  exit 1
}

tag_version="v0.3.1"
short_version="$(agent_secret_normalize_short_version "$tag_version")"
bundle_version="${AGENT_SECRET_BUNDLE_VERSION:-$AGENT_SECRET_DEFAULT_BUNDLE_VERSION}"

"$project_root/scripts/build-app-bundle.sh" --version "$tag_version" --output "$tmp_dir"
"$project_root/scripts/check-bundle-metadata.sh" \
  "$tmp_dir/$AGENT_SECRET_APP_NAME.app" \
  "$short_version" \
  "$bundle_version"

app_short_version="$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$tmp_dir/$AGENT_SECRET_APP_NAME.app/Contents/Info.plist")"
if [[ "$app_short_version" == v* ]]; then
  fail "app bundle short version kept tag prefix: $app_short_version"
fi

echo "test-release-version: ok"
