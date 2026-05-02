#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/check-bundle-metadata.sh [--app-only] APP_BUNDLE [SHORT_VERSION] [BUNDLE_VERSION]

Verify generated Agent Secret app bundle Info.plist metadata.
USAGE
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
# shellcheck source=scripts/bundle-metadata.sh
source "$project_root/scripts/bundle-metadata.sh"

app_only=0
if [[ "${1:-}" == "--app-only" ]]; then
  app_only=1
  shift
fi

if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 2
fi

app_bundle="$1"
short_version="${2:-${AGENT_SECRET_VERSION:-$AGENT_SECRET_DEFAULT_VERSION}}"
bundle_version="${3:-${AGENT_SECRET_BUNDLE_VERSION:-$AGENT_SECRET_DEFAULT_BUNDLE_VERSION}}"
daemon_bundle="$app_bundle/Contents/Library/Helpers/AgentSecretDaemon.app"
short_version="$(agent_secret_normalize_short_version "$short_version")"

require_command() {
  local name="$1"

  if ! command -v "$name" >/dev/null 2>&1; then
    echo "check-bundle-metadata: required command not found: $name" >&2
    exit 1
  fi
}

plist_value() {
  local plist="$1"
  local key="$2"

  /usr/libexec/PlistBuddy -c "Print :$key" "$plist"
}

assert_plist_value() {
  local plist="$1"
  local key="$2"
  local want="$3"
  local got=""

  got="$(plist_value "$plist" "$key")"
  if [[ "$got" != "$want" ]]; then
    echo "check-bundle-metadata: $plist $key = $got, want $want" >&2
    exit 1
  fi
}

require_command /usr/libexec/PlistBuddy

if [[ ! -d "$app_bundle" ]]; then
  echo "check-bundle-metadata: app bundle not found: $app_bundle" >&2
  exit 1
fi
if [[ "$app_only" -eq 0 && ! -d "$daemon_bundle" ]]; then
  echo "check-bundle-metadata: daemon bundle not found: $daemon_bundle" >&2
  exit 1
fi

app_plist="$app_bundle/Contents/Info.plist"

assert_plist_value "$app_plist" CFBundleDisplayName "$AGENT_SECRET_APP_DISPLAY_NAME"
assert_plist_value "$app_plist" CFBundleExecutable "$AGENT_SECRET_APP_EXECUTABLE"
assert_plist_value "$app_plist" CFBundleIdentifier "$AGENT_SECRET_APP_BUNDLE_ID"
assert_plist_value "$app_plist" CFBundleName "$AGENT_SECRET_APP_NAME"
assert_plist_value "$app_plist" CFBundleShortVersionString "$short_version"
assert_plist_value "$app_plist" CFBundleVersion "$bundle_version"
assert_plist_value "$app_plist" LSApplicationCategoryType "$AGENT_SECRET_APP_CATEGORY"
assert_plist_value "$app_plist" LSMinimumSystemVersion "$AGENT_SECRET_MIN_MACOS_VERSION"

if [[ "$app_only" -eq 0 ]]; then
  daemon_plist="$daemon_bundle/Contents/Info.plist"
  assert_plist_value "$daemon_plist" CFBundleDisplayName "$AGENT_SECRET_APP_DISPLAY_NAME"
  assert_plist_value "$daemon_plist" CFBundleExecutable "$AGENT_SECRET_APP_EXECUTABLE"
  assert_plist_value "$daemon_plist" CFBundleIdentifier "$AGENT_SECRET_DAEMON_BUNDLE_ID"
  assert_plist_value "$daemon_plist" CFBundleName "$AGENT_SECRET_APP_NAME"
  assert_plist_value "$daemon_plist" CFBundleShortVersionString "$short_version"
  assert_plist_value "$daemon_plist" CFBundleVersion "$bundle_version"
  assert_plist_value "$daemon_plist" LSApplicationCategoryType "$AGENT_SECRET_APP_CATEGORY"
  assert_plist_value "$daemon_plist" LSMinimumSystemVersion "$AGENT_SECRET_MIN_MACOS_VERSION"
fi

echo "bundle metadata: ok"
