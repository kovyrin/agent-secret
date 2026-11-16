#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 4 ]]; then
  echo "usage: verify-published-update-bundle.sh DMG RELEASE_VERSION BUILD_VERSION FEED_URL" >&2
  exit 2
fi
archive="$1"
version="$2"
build="$3"
feed_url="$4"

stage="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-update-bundle.XXXXXXXX")"
mounted=0
cleanup() {
  if [[ "$mounted" == 1 ]]; then
    /usr/bin/hdiutil detach "$stage/mounted" >/dev/null
  fi
  rm -rf "$stage"
}
trap cleanup EXIT

requirement='=anchor apple generic and certificate leaf[subject.OU] = "B6L7QLWTZW"'
/usr/bin/codesign --verify --strict -R "$requirement" "$archive"
/usr/bin/xcrun stapler validate "$archive"
mkdir "$stage/mounted"
/usr/bin/hdiutil attach -readonly -nobrowse -mountpoint "$stage/mounted" "$archive" >/dev/null
mounted=1
app="$stage/mounted/Agent Secret.app"
/usr/bin/codesign --verify --deep --strict -R "$requirement"' and identifier "com.kovyrin.agent-secret"' "$app"
/usr/bin/xcrun stapler validate "$app"

plist="$app/Contents/Info.plist"
expect_value() {
  local key="$1" expected="$2" actual
  actual="$(/usr/libexec/PlistBuddy -c "Print :$key" "$plist")"
  if [[ "$actual" != "$expected" ]]; then
    printf 'verify-published-update-bundle: unexpected value for %s\n' "$key" >&2
    exit 1
  fi
}
expect_value CFBundleShortVersionString "$version"
expect_value CFBundleVersion "$build"
expect_value SUPublicEDKey "${AGENT_SECRET_UPDATE_PUBLIC_KEY:?missing update public key}"
expect_value SUFeedURL "$feed_url"
expect_value SURequireSignedFeed true
expect_value SUSignedFeedFailureExpirationInterval 0
expect_value SUVerifyUpdateBeforeExtraction true
expect_value SUAllowsAutomaticUpdates false
expect_value SUAutomaticallyUpdate false
expect_value SUEnableAutomaticChecks true
expect_value SUEnableSystemProfiling false
for helper in Library/LoginItems/AgentSecretUpdater.app Library/Helpers/AgentSecretDaemon.app; do
  plist="$app/Contents/$helper/Contents/Info.plist"
  expect_value CFBundleVersion "$build"
done
