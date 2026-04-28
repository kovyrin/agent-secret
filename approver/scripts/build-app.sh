#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
approver_root="$(cd "$script_dir/.." && pwd)"
dist_dir="$approver_root/dist"
bundle="$dist_dir/AgentSecretApprover.app"
binary_name="agent-secret-approver"

cd "$approver_root"
swift build -c release --product "$binary_name"

rm -rf "$bundle"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp ".build/release/$binary_name" "$bundle/Contents/MacOS/$binary_name"
chmod 0755 "$bundle/Contents/MacOS/$binary_name"

cat >"$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>agent-secret-approver</string>
  <key>CFBundleIdentifier</key>
  <string>com.kovyrin.agent-secret.approver</string>
  <key>CFBundleName</key>
  <string>AgentSecretApprover</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

echo "$bundle"
