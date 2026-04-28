#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/dev-install.sh [flags]

Build and install the current development version for the current macOS user.

Defaults:
  binaries:      ~/.local/bin
  apps:          ~/Applications/AgentSecretDaemon.app and AgentSecretApprover.app

Flags:
  --bin-dir DIR        Install agent-secret, agent-secretd, and the approver shim into DIR.
  --app-dir DIR        Install AgentSecretDaemon.app and AgentSecretApprover.app into DIR.
  --no-stop-daemon     Do not stop an already-running per-user daemon before replacing binaries.
  -h, --help           Show this help.

Environment:
  AGENT_SECRET_INSTALL_BIN_DIR  Default binary install directory.
  AGENT_SECRET_INSTALL_APP_DIR  Default app install directory.

After install, set AGENT_SECRET_1PASSWORD_ACCOUNT in the shell that will run
agent-secret exec. The daemon inherits that value when it auto-starts.
USAGE
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"

if [[ "${AGENT_SECRET_IN_MISE:-}" != "1" ]]; then
  if command -v mise >/dev/null 2>&1; then
    export AGENT_SECRET_IN_MISE=1
    exec mise exec -- "$0" "$@"
  fi
fi

bin_dir="${AGENT_SECRET_INSTALL_BIN_DIR:-$HOME/.local/bin}"
app_dir="${AGENT_SECRET_INSTALL_APP_DIR:-$HOME/Applications}"
stop_daemon=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir)
      if [[ $# -lt 2 || "$2" == "" ]]; then
        echo "dev-install: --bin-dir requires a directory" >&2
        exit 2
      fi
      bin_dir="$2"
      shift 2
      ;;
    --app-dir)
      if [[ $# -lt 2 || "$2" == "" ]]; then
        echo "dev-install: --app-dir requires a directory" >&2
        exit 2
      fi
      app_dir="$2"
      shift 2
      ;;
    --no-stop-daemon)
      stop_daemon=0
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "dev-install: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_command() {
  local name="$1"

  if ! command -v "$name" >/dev/null 2>&1; then
    echo "dev-install: required command not found: $name" >&2
    exit 1
  fi
}

stop_existing_daemon() {
  if [[ "$stop_daemon" -eq 0 ]]; then
    return
  fi

  local existing_agent_secret=""
  if [[ -x "$bin_dir/agent-secret" ]]; then
    existing_agent_secret="$bin_dir/agent-secret"
  elif command -v agent-secret >/dev/null 2>&1; then
    existing_agent_secret="$(command -v agent-secret)"
  fi

  if [[ "$existing_agent_secret" != "" ]]; then
    "$existing_agent_secret" daemon stop >/dev/null 2>&1 || true
  fi
}

path_contains() {
  local candidate="$1"
  local path_entry=""

  while IFS= read -r -d ':' path_entry; do
    if [[ "$path_entry" == "$candidate" ]]; then
      return 0
    fi
  done < <(printf '%s:' "$PATH")

  return 1
}

require_command go
require_command swift
require_command ditto
require_command install
require_command iconutil
require_command sips
require_command codesign

build_daemon_app() {
  local binary_path="$1"
  local bundle="$2"
  local bundle_executable="Agent Secret"
  local icon_png="$tmp_dir/DaemonAppIcon.png"
  local iconset="$tmp_dir/DaemonAppIcon.iconset"

  rm -rf "$bundle" "$iconset"
  mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources" "$iconset"
  install -m 0755 "$binary_path" "$bundle/Contents/MacOS/$bundle_executable"

  cat >"$bundle/Contents/Info.plist" <<'PLIST'
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
  <string>com.agent-secret.daemon</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Agent Secret</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
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

  swift "$project_root/scripts/make-daemon-icon.swift" "$icon_png"
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
    sips -z "$size" "$size" "$icon_png" --out "$iconset/$name" >/dev/null
  done
  iconutil -c icns "$iconset" -o "$bundle/Contents/Resources/AppIcon.icns"
  codesign --force --sign - "$bundle" >/dev/null
}

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-install.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

echo "Building Go commands..."
cd "$project_root"
go build -trimpath -o "$tmp_dir/agent-secret" ./cmd/agent-secret
go build -trimpath -o "$tmp_dir/agent-secretd" ./cmd/agent-secretd

echo "Building macOS daemon app..."
daemon_bundle="$tmp_dir/AgentSecretDaemon.app"
build_daemon_app "$tmp_dir/agent-secretd" "$daemon_bundle"

echo "Building macOS approver app..."
"$project_root/approver/scripts/build-app.sh"

approver_bundle="$project_root/approver/dist/AgentSecretApprover.app"
if [[ ! -x "$approver_bundle/Contents/MacOS/agent-secret-approver" ]]; then
  echo "dev-install: approver build did not produce $approver_bundle" >&2
  exit 1
fi

stop_existing_daemon

echo "Installing binaries into $bin_dir..."
install -d -m 0755 "$bin_dir"
install -m 0755 "$tmp_dir/agent-secret" "$bin_dir/agent-secret"
install -m 0755 "$tmp_dir/agent-secretd" "$bin_dir/agent-secretd"

echo "Installing apps into $app_dir..."
install -d -m 0755 "$app_dir"
target_daemon_app="$app_dir/AgentSecretDaemon.app"
rm -rf "$target_daemon_app"
ditto "$daemon_bundle" "$target_daemon_app"
chmod 0755 "$target_daemon_app/Contents/MacOS/Agent Secret"

target_app="$app_dir/AgentSecretApprover.app"
rm -rf "$target_app"
ditto "$approver_bundle" "$target_app"
chmod 0755 "$target_app/Contents/MacOS/agent-secret-approver"

echo "Installing approver shim into $bin_dir..."
ln -sfn "$target_app/Contents/MacOS/agent-secret-approver" "$bin_dir/agent-secret-approver"

if ! path_contains "$bin_dir"; then
  echo "dev-install: warning: $bin_dir is not on PATH for this shell" >&2
fi

echo "Installed:"
echo "  $bin_dir/agent-secret"
echo "  $bin_dir/agent-secretd"
echo "  $bin_dir/agent-secret-approver -> $target_app/Contents/MacOS/agent-secret-approver"
echo "  $target_daemon_app"
echo "  $target_app"
