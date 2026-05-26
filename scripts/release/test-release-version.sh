#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
# shellcheck source=scripts/lib/bundle-metadata.sh
# shellcheck disable=SC1091
source "$project_root/scripts/lib/bundle-metadata.sh"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-release-version-test.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  echo "test-release-version: $*" >&2
  exit 1
}

latest_version="$(agent_secret_latest_changelog_version "$project_root/CHANGELOG.md")"
revision="$(agent_secret_git_revision "$project_root")"
tag_version="v$latest_version"
short_version="$(agent_secret_normalize_short_version "$tag_version")"
dev_version="$short_version-dev"
bundle_version="${AGENT_SECRET_BUNDLE_VERSION:-$AGENT_SECRET_DEFAULT_BUNDLE_VERSION}"
release_dir="$tmp_dir/release"
dev_dir="$tmp_dir/dev"

export AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_ID=test-client-id
export AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_SECRET=test-client-secret

"$project_root/scripts/build/build-app-bundle.sh" --version "$tag_version" --output "$release_dir"
"$project_root/scripts/build/check-bundle-metadata.sh" \
  "$release_dir/$AGENT_SECRET_APP_NAME.app" \
  "$short_version" \
  "$bundle_version"

app_short_version="$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$release_dir/$AGENT_SECRET_APP_NAME.app/Contents/Info.plist")"
if [[ "$app_short_version" == v* ]]; then
  fail "app bundle short version kept tag prefix: $app_short_version"
fi
release_cli_version="$("$release_dir/$AGENT_SECRET_APP_NAME.app/Contents/Resources/bin/agent-secret" --version)"
if [[ "$release_cli_version" != "agent-secret $short_version ($revision)" ]]; then
  fail "release CLI version = $release_cli_version"
fi

"$project_root/scripts/build/build-app-bundle.sh" --output "$dev_dir"
"$project_root/scripts/build/check-bundle-metadata.sh" \
  "$dev_dir/$AGENT_SECRET_APP_NAME.app" \
  "$dev_version" \
  "$bundle_version"
dev_cli_version="$("$dev_dir/$AGENT_SECRET_APP_NAME.app/Contents/Resources/bin/agent-secret" --version)"
if [[ "$dev_cli_version" != "agent-secret $dev_version ($revision)" ]]; then
  fail "dev CLI version = $dev_cli_version"
fi

if "$project_root/scripts/build/build-app-bundle.sh" --version v999.999.999 --output "$tmp_dir/mismatch" >/dev/null 2>&1; then
  fail "build accepted version missing from latest changelog section"
fi

echo "test-release-version: ok"
