#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/build-app-bundle.sh [flags]

Build the macOS Agent Secret app bundle.

Flags:
  --version VERSION    Bundle version. Defaults to AGENT_SECRET_VERSION or bundle metadata.
  --output DIR         Output directory. Defaults to ./dist.
  -h, --help           Show this help.
USAGE
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
# shellcheck source=scripts/bundle-metadata.sh
# shellcheck disable=SC1091
source "$project_root/scripts/bundle-metadata.sh"

if [[ "${AGENT_SECRET_IN_MISE:-}" != "1" ]]; then
  if command -v mise >/dev/null 2>&1; then
    export AGENT_SECRET_IN_MISE=1
    exec mise exec -- "$0" "$@"
  fi
fi

output_dir="$project_root/dist"
version="${AGENT_SECRET_VERSION:-$AGENT_SECRET_DEFAULT_VERSION}"
bundle_version="${AGENT_SECRET_BUNDLE_VERSION:-$AGENT_SECRET_DEFAULT_BUNDLE_VERSION}"
codesign_identity="${AGENT_SECRET_CODESIGN_IDENTITY:-"-"}"
codesign_entitlements="${AGENT_SECRET_CODESIGN_ENTITLEMENTS:-}"
approver_team_id="-"

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

version="$(agent_secret_normalize_short_version "$version")"

require_tool() {
  local name="$1"
  local path="$2"

  if [[ ! -x "$path" ]]; then
    echo "build-app-bundle: required command not found or not executable: $name ($path)" >&2
    exit 1
  fi
}

resolve_path_tool() {
  local name="$1"
  local path=""

  path="$(command -v "$name" || true)"
  if [[ "$path" != /* ]]; then
    echo "build-app-bundle: required command not found on trusted toolchain PATH: $name" >&2
    exit 1
  fi
  require_tool "$name" "$path"
  printf '%s\n' "$path"
}

tool_go="$(resolve_path_tool go)"
tool_swift="/usr/bin/swift"
tool_mktemp="/usr/bin/mktemp"
tool_rm="/bin/rm"
tool_mkdir="/bin/mkdir"
tool_install="/usr/bin/install"
tool_cp="/bin/cp"
tool_sips="/usr/bin/sips"
tool_iconutil="/usr/bin/iconutil"
tool_codesign="/usr/bin/codesign"

require_tool swift "$tool_swift"
require_tool mktemp "$tool_mktemp"
require_tool rm "$tool_rm"
require_tool mkdir "$tool_mkdir"
require_tool install "$tool_install"
require_tool cp "$tool_cp"
require_tool sips "$tool_sips"
require_tool iconutil "$tool_iconutil"
require_tool codesign "$tool_codesign"

run_go() (
  unset GOROOT
  "$tool_go" "$@"
)

selected_goroot="$(run_go env GOROOT)" || {
  echo "build-app-bundle: could not query selected Go toolchain GOROOT" >&2
  exit 1
}
if [[ "${GOROOT:-}" != "" && "$GOROOT" != "$selected_goroot" ]]; then
  echo "build-app-bundle: inherited GOROOT does not match selected Go toolchain" >&2
  echo "build-app-bundle: run from the trusted mise context without overriding GOROOT" >&2
  exit 1
fi

tmp_dir="$("$tool_mktemp" -d "${TMPDIR:-/tmp}/agent-secret-bundle.XXXXXX")"
cleanup() {
  "$tool_rm" -rf "$tmp_dir"
}
trap cleanup EXIT

app_bundle="$output_dir/$AGENT_SECRET_APP_NAME.app"
daemon_bundle="$tmp_dir/AgentSecretDaemon.app"
skill_source="$project_root/.agents/skills/agent-secret"
icon_png="$tmp_dir/AppIcon.png"
iconset="$tmp_dir/AppIcon.iconset"

make_icon() {
  local icon_source="$1"
  local iconset_dir="$2"
  local out="$3"

  "$tool_rm" -rf "$iconset_dir"
  "$tool_mkdir" -p "$iconset_dir"

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
    "$tool_sips" -z "$size" "$size" "$icon_source" --out "$iconset_dir/$name" >/dev/null
  done
  "$tool_iconutil" -c icns "$iconset_dir" -o "$out"
}

sign_path() {
  local path="$1"
  local args=(--force --sign "$codesign_identity")

  if [[ "$codesign_identity" != "-" ]]; then
    args+=(--timestamp --options runtime)
    if [[ "$codesign_entitlements" != "" ]]; then
      args+=(--entitlements "$codesign_entitlements")
    fi
  fi

  args+=("$path")
  "$tool_codesign" "${args[@]}" >/dev/null
}

codesign_team_id() {
  local identity="$1"

  if [[ "$identity" =~ \(([A-Za-z0-9]+)\)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return
  fi

  return 1
}

build_daemon_app() {
  local binary_path="$1"
  local bundle="$2"

  "$tool_rm" -rf "$bundle"
  "$tool_mkdir" -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
  "$tool_install" -m 0755 "$binary_path" "$bundle/Contents/MacOS/$AGENT_SECRET_APP_EXECUTABLE"
  "$tool_cp" "$tmp_dir/AppIcon.icns" "$bundle/Contents/Resources/$AGENT_SECRET_ICON_FILE.icns"

  cat >"$bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>$AGENT_SECRET_APP_DISPLAY_NAME</string>
  <key>CFBundleExecutable</key>
  <string>$AGENT_SECRET_APP_EXECUTABLE</string>
  <key>CFBundleIconFile</key>
  <string>$AGENT_SECRET_ICON_FILE</string>
  <key>CFBundleIdentifier</key>
  <string>$AGENT_SECRET_DAEMON_BUNDLE_ID</string>
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
go_build_flags=(-trimpath)
if [[ "$codesign_identity" != "-" ]]; then
  approver_team_id="$(codesign_team_id "$codesign_identity")" || {
    echo "build-app-bundle: codesign identity must end with a Team ID in parentheses" >&2
    exit 1
  }
fi
go_build_flags+=(-ldflags "-X github.com/kovyrin/agent-secret/internal/daemon.defaultDeveloperIDTeamID=$approver_team_id")
run_go build "${go_build_flags[@]}" -o "$tmp_dir/agent-secret" ./cmd/agent-secret
run_go build "${go_build_flags[@]}" -o "$tmp_dir/agent-secretd" ./cmd/agent-secretd

echo "Building Swift app executable..."
cd "$project_root/approver"
"$tool_swift" build -c release --product agent-secret-approver
approver_binary="$project_root/approver/.build/release/agent-secret-approver"
if [[ ! -x "$approver_binary" ]]; then
  echo "build-app-bundle: missing Swift executable $approver_binary" >&2
  exit 1
fi

echo "Creating app icon..."
"$tool_swift" "$project_root/scripts/make-daemon-icon.swift" "$icon_png"
make_icon "$icon_png" "$iconset" "$tmp_dir/AppIcon.icns"

echo "Creating daemon helper app..."
build_daemon_app "$tmp_dir/agent-secretd" "$daemon_bundle"

echo "Creating Agent Secret.app..."
"$tool_rm" -rf "$app_bundle"
"$tool_mkdir" -p \
  "$app_bundle/Contents/MacOS" \
  "$app_bundle/Contents/Resources/bin" \
  "$app_bundle/Contents/Resources/skills" \
  "$app_bundle/Contents/Library/Helpers"
"$tool_install" -m 0755 "$approver_binary" "$app_bundle/Contents/MacOS/$AGENT_SECRET_APP_EXECUTABLE"
"$tool_install" -m 0755 "$tmp_dir/agent-secret" "$app_bundle/Contents/Resources/bin/agent-secret"
if [[ ! -f "$skill_source/SKILL.md" ]]; then
  echo "build-app-bundle: missing bundled skill at $skill_source" >&2
  exit 1
fi
"$tool_cp" -R "$skill_source" "$app_bundle/Contents/Resources/skills/agent-secret"
"$tool_cp" "$tmp_dir/AppIcon.icns" "$app_bundle/Contents/Resources/$AGENT_SECRET_ICON_FILE.icns"
"$tool_cp" -R "$daemon_bundle" "$app_bundle/Contents/Library/Helpers/AgentSecretDaemon.app"

cat >"$app_bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>$AGENT_SECRET_APP_DISPLAY_NAME</string>
  <key>CFBundleExecutable</key>
  <string>$AGENT_SECRET_APP_EXECUTABLE</string>
  <key>CFBundleIconFile</key>
  <string>$AGENT_SECRET_ICON_FILE</string>
  <key>CFBundleIdentifier</key>
  <string>$AGENT_SECRET_APP_BUNDLE_ID</string>
  <key>AgentSecretExpectedTeamID</key>
  <string>$approver_team_id</string>
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
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

if [[ "$codesign_identity" == "-" ]]; then
  echo "Signing app bundle with ad-hoc identity..."
else
  echo "Signing app bundle with $codesign_identity..."
fi
sign_path "$app_bundle/Contents/Resources/bin/agent-secret"
sign_path "$app_bundle/Contents/Library/Helpers/AgentSecretDaemon.app"
sign_path "$app_bundle"
"$project_root/scripts/check-bundle-metadata.sh" "$app_bundle" "$version" "$bundle_version"

echo "$app_bundle"
