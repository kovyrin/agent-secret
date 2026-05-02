#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
approver_root="$(cd "$script_dir/.." && pwd)"
project_root="$(cd "$approver_root/.." && pwd)"
# shellcheck source=scripts/bundle-metadata.sh
source "$project_root/scripts/bundle-metadata.sh"
dist_dir="$approver_root/dist"
bundle="$dist_dir/$AGENT_SECRET_APP_NAME.app"
binary_name="agent-secret-approver"
version="${AGENT_SECRET_VERSION:-$AGENT_SECRET_DEFAULT_VERSION}"
bundle_version="${AGENT_SECRET_BUNDLE_VERSION:-$AGENT_SECRET_DEFAULT_BUNDLE_VERSION}"

cd "$approver_root"
swift build -c release --product "$binary_name"

rm -rf "$bundle"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp ".build/release/$binary_name" "$bundle/Contents/MacOS/$AGENT_SECRET_APP_EXECUTABLE"
chmod 0755 "$bundle/Contents/MacOS/$AGENT_SECRET_APP_EXECUTABLE"

cat >"$bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>$AGENT_SECRET_APP_DISPLAY_NAME</string>
  <key>CFBundleExecutable</key>
  <string>$AGENT_SECRET_APP_EXECUTABLE</string>
  <key>CFBundleIdentifier</key>
  <string>$AGENT_SECRET_APP_BUNDLE_ID</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>$AGENT_SECRET_INFO_DICTIONARY_VERSION</string>
  <key>CFBundleName</key>
  <string>$AGENT_SECRET_APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$version</string>
  <key>CFBundleVersion</key>
  <string>$bundle_version</string>
  <key>LSApplicationCategoryType</key>
  <string>$AGENT_SECRET_APP_CATEGORY</string>
  <key>LSMinimumSystemVersion</key>
  <string>$AGENT_SECRET_MIN_MACOS_VERSION</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

if command -v codesign >/dev/null 2>&1; then
  codesign --force --sign - "$bundle" >/dev/null
fi
"$project_root/scripts/check-bundle-metadata.sh" --app-only "$bundle" "$version" "$bundle_version"

echo "$bundle"
