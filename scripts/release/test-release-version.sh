#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
# shellcheck source=scripts/lib/bundle-metadata.sh
# shellcheck disable=SC1091
source "$project_root/scripts/lib/bundle-metadata.sh"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-release-version-test.XXXXXX")"
release_mounted=0
cleanup() {
  if [[ "$release_mounted" == 1 ]]; then
    hdiutil detach "$release_mount" >/dev/null
  fi
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
bundle_version="$(agent_secret_release_bundle_version "$short_version")"
release_dir="$tmp_dir/release"
release_mount="$tmp_dir/mount"
dev_dir="$tmp_dir/dev"

check_mapping() {
  local version="$1" expected="$2" actual
  actual="$(agent_secret_release_bundle_version "$version")"
  [[ "$actual" == "$expected" ]] || fail "$version mapped to $actual, expected $expected"
}

check_mapping 0.0.34 1.0.34
check_mapping 0.0.35 1.0.35
check_mapping 0.0.99 1.0.99
check_mapping 0.1.0 1.1.0
check_mapping 1.0.0 2.0.0
for invalid in 0.00.34 0.0.100 0.100.0 9999.0.0 0.0.34-dev; do
  if agent_secret_release_bundle_version "$invalid" >/dev/null 2>&1; then
    fail "accepted invalid release build version $invalid"
  fi
done

(
  umask 077
  "$project_root/scripts/release/build-release.sh" "$tag_version" --output "$release_dir"
)
mkdir "$release_mount"
hdiutil attach -readonly -nobrowse -mountpoint "$release_mount" \
  "$release_dir/Agent-Secret-$tag_version-macos-arm64.dmg" >/dev/null
release_mounted=1
release_app="$release_mount/$AGENT_SECRET_APP_NAME.app"
for directory in "$release_app" "$release_app/Contents" "$release_app/Contents/Resources/bin"; do
  [[ "$(stat -f %Lp "$directory")" == 755 ]] || fail "shared release directory has private permissions: $directory"
done
"$project_root/scripts/build/check-bundle-metadata.sh" \
  "$release_app" \
  "$short_version" \
  "$bundle_version"

app_short_version="$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$release_app/Contents/Info.plist")"
if [[ "$app_short_version" == v* ]]; then
  fail "app bundle short version kept tag prefix: $app_short_version"
fi
release_cli="$release_app/Contents/Resources/bin/agent-secret"
release_cli_version="$("$release_cli" --version)"
if [[ "$release_cli_version" != "agent-secret $short_version ($revision)" ]]; then
  fail "release CLI version = $release_cli_version"
fi
mkdir "$tmp_dir/bin"
ln -s "$release_cli" "$tmp_dir/bin/agent-secret"
direct_status="$("$release_cli" update status --json)"
linked_status="$("$tmp_dir/bin/agent-secret" update status --json)"
if [[ "$linked_status" != "$direct_status" ]]; then
  fail "the CLI link did not report the installed build's update status"
fi
if /usr/libexec/PlistBuddy -c "Print :SUFeedURL" "$release_app/Contents/Info.plist" >/dev/null 2>&1; then
  fail "ordinary ad-hoc builds must not connect to an update feed"
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
