#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/build-app-bundle.sh [flags]

Build the macOS Agent Secret app bundle.

Flags:
  --version VERSION    Bundle version. Defaults to AGENT_SECRET_VERSION or 0.1.0.
  --output DIR         Output directory. Defaults to ./dist.
  -h, --help           Show this help.
USAGE
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
output_dir="$project_root/dist"
version="${AGENT_SECRET_VERSION:-0.1.0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      if [[ $# -lt 2 || "$2" == "" ]]; then
        echo "build-app-bundle: --version requires a value" >&2
        exit 2
      fi
      version="$2"
      shift 2
      ;;
    --output)
      if [[ $# -lt 2 || "$2" == "" ]]; then
        echo "build-app-bundle: --output requires a directory" >&2
        exit 2
      fi
      output_dir="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "build-app-bundle: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_command() {
  local name="$1"

  if ! command -v "$name" >/dev/null 2>&1; then
    echo "build-app-bundle: required command not found: $name" >&2
    exit 1
  fi
}

require_command go
require_command swift
require_command install
require_command iconutil
require_command sips
require_command codesign

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-bundle.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

bundle_id="com.kovyrin.agent-secret"
daemon_bundle_id="com.kovyrin.agent-secret.daemon"
app_bundle="$output_dir/Agent Secret.app"
daemon_bundle="$tmp_dir/AgentSecretDaemon.app"
icon_png="$tmp_dir/AppIcon.png"
iconset="$tmp_dir/AppIcon.iconset"

make_icon() {
  local icon_source="$1"
  local iconset_dir="$2"
  local out="$3"

  rm -rf "$iconset_dir"
  mkdir -p "$iconset_dir"

  local icon_specs=(
    "16:icon_16x16.png"
    "32:icon_16x16@2x.png"
    "32:icon_32x32.png"
    "64:icon_32x32@2x.png"
    "128:icon_128x128.png"
    "256:icon_128x128@2x.png"
    "256:icon_256x256.png"
    "512:icon_256x256@2x.png"
    "512:icon_512x512.png"
    "1024:icon_512x512@2x.png"
  )
  local spec=""
  for spec in "${icon_specs[@]}"; do
    local size="${spec%%:*}"
    local name="${spec#*:}"
    sips -z "$size" "$size" "$icon_source" --out "$iconset_dir/$name" >/dev/null
  done
  iconutil -c icns "$iconset_dir" -o "$out"
}

build_daemon_app() {
  local binary_path="$1"
  local bundle="$2"

  rm -rf "$bundle"
  mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
  install -m 0755 "$binary_path" "$bundle/Contents/MacOS/Agent Secret"
  cp "$tmp_dir/AppIcon.icns" "$bundle/Contents/Resources/AppIcon.icns"

  cat >"$bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>Agent Secret</string>
  <key>CFBundleExecutable</key>
  <string>Agent Secret</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>$daemon_bundle_id</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Agent Secret</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$version</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.developer-tools</string>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>LSUIElement</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST
}

echo "Building Go commands..."
cd "$project_root"
go build -trimpath -o "$tmp_dir/agent-secret" ./cmd/agent-secret
go build -trimpath -o "$tmp_dir/agent-secretd" ./cmd/agent-secretd

echo "Building Swift app executable..."
cd "$project_root/approver"
swift build -c release --product agent-secret-approver
approver_binary="$project_root/approver/.build/release/agent-secret-approver"
if [[ ! -x "$approver_binary" ]]; then
  echo "build-app-bundle: missing Swift executable $approver_binary" >&2
  exit 1
fi

echo "Creating app icon..."
swift "$project_root/scripts/make-daemon-icon.swift" "$icon_png"
make_icon "$icon_png" "$iconset" "$tmp_dir/AppIcon.icns"

echo "Creating daemon helper app..."
build_daemon_app "$tmp_dir/agent-secretd" "$daemon_bundle"

echo "Creating Agent Secret.app..."
rm -rf "$app_bundle"
mkdir -p \
  "$app_bundle/Contents/MacOS" \
  "$app_bundle/Contents/Resources/bin" \
  "$app_bundle/Contents/Library/Helpers"
install -m 0755 "$approver_binary" "$app_bundle/Contents/MacOS/Agent Secret"
install -m 0755 "$tmp_dir/agent-secret" "$app_bundle/Contents/Resources/bin/agent-secret"
cp "$tmp_dir/AppIcon.icns" "$app_bundle/Contents/Resources/AppIcon.icns"
cp -R "$daemon_bundle" "$app_bundle/Contents/Library/Helpers/AgentSecretDaemon.app"

cat >"$app_bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>Agent Secret</string>
  <key>CFBundleExecutable</key>
  <string>Agent Secret</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>$bundle_id</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Agent Secret</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$version</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.developer-tools</string>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

echo "Ad-hoc signing app bundle..."
codesign --force --sign - "$app_bundle/Contents/Resources/bin/agent-secret" >/dev/null
codesign --force --sign - "$app_bundle/Contents/Library/Helpers/AgentSecretDaemon.app" >/dev/null
codesign --force --sign - "$app_bundle" >/dev/null

echo "$app_bundle"
