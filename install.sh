#!/bin/sh
set -eu

repo="${AGENT_SECRET_REPO:-kovyrin/agent-secret}"
github_url="${AGENT_SECRET_GITHUB_URL:-https://github.com}"
github_api="${AGENT_SECRET_GITHUB_API:-https://api.github.com}"
app_dir="${AGENT_SECRET_APP_DIR:-/Applications}"
bin_dir="${AGENT_SECRET_BIN_DIR:-$HOME/.local/bin}"
skills_dir="${AGENT_SECRET_SKILLS_DIR:-$HOME/.agents/skills}"
version="${AGENT_SECRET_VERSION:-}"
local_dmg="${AGENT_SECRET_DMG:-}"
local_checksums="${AGENT_SECRET_CHECKSUMS_FILE:-}"
no_stop_daemon="${AGENT_SECRET_NO_STOP_DAEMON:-0}"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-install.XXXXXX")"
mount_dir="$tmp_dir/mount"
mounted=0

cleanup() {
  if [ "$mounted" -eq 1 ]; then
    hdiutil detach "$mount_dir" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

die() {
  echo "agent-secret install: $*" >&2
  exit 1
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    die "required command not found: $1"
  fi
}

detect_arch() {
  case "$(uname -m)" in
    arm64)
      printf '%s\n' "arm64"
      ;;
    x86_64)
      printf '%s\n' "x86_64"
      ;;
    *)
      die "unsupported architecture: $(uname -m)"
      ;;
  esac
}

latest_version() {
  json="$(curl -fsSL "$github_api/repos/$repo/releases/latest")" || die "could not fetch latest GitHub release"
  tag="$(printf '%s\n' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -z "$tag" ]; then
    die "could not find tag_name in latest release response"
  fi
  printf '%s\n' "$tag"
}

download_release_file() {
  file_name="$1"
  destination="$2"
  url="$github_url/$repo/releases/download/$version/$file_name"
  echo "Downloading $url"
  curl -fL --progress-bar "$url" -o "$destination"
}

verify_checksum() {
  checksums="$1"
  file_name="$2"
  file_path="$3"

  expected="$(awk -v file="$file_name" '$2 == file { print $1; found = 1; exit } END { if (!found) exit 1 }' "$checksums")" ||
    die "checksums file does not contain $file_name"
  actual="$(shasum -a 256 "$file_path" | awk '{ print $1 }')"
  if [ "$actual" != "$expected" ]; then
    die "checksum mismatch for $file_name"
  fi
}

stop_existing_daemon() {
  if [ "$no_stop_daemon" = "1" ]; then
    return
  fi

  target_app="$app_dir/Agent Secret.app"
  existing=""
  if [ -x "$target_app/Contents/Resources/bin/agent-secret" ]; then
    existing="$target_app/Contents/Resources/bin/agent-secret"
  elif [ -x "$bin_dir/agent-secret" ]; then
    existing="$bin_dir/agent-secret"
  elif command -v agent-secret >/dev/null 2>&1; then
    existing="$(command -v agent-secret)"
  fi

  if [ -n "$existing" ]; then
    "$existing" daemon stop >/dev/null 2>&1 || true
  fi
}

require_command curl
require_command hdiutil
require_command shasum
require_command ditto

arch="$(detect_arch)"
if [ -z "$version" ] && [ -z "$local_dmg" ]; then
  version="$(latest_version)"
fi

if [ -n "$local_dmg" ]; then
  [ -f "$local_dmg" ] || die "local DMG does not exist: $local_dmg"
  artifact_name="$(basename "$local_dmg")"
  dmg_path="$tmp_dir/$artifact_name"
  cp "$local_dmg" "$dmg_path"
else
  artifact_name="Agent-Secret-$version-macos-$arch.dmg"
  dmg_path="$tmp_dir/$artifact_name"
  download_release_file "$artifact_name" "$dmg_path"
fi

checksums_path="$tmp_dir/checksums.txt"
if [ -n "$local_checksums" ]; then
  [ -f "$local_checksums" ] || die "checksum file does not exist: $local_checksums"
  cp "$local_checksums" "$checksums_path"
else
  [ -n "$version" ] || die "AGENT_SECRET_VERSION is required when AGENT_SECRET_DMG is used without AGENT_SECRET_CHECKSUMS_FILE"
  download_release_file "checksums.txt" "$checksums_path"
fi
verify_checksum "$checksums_path" "$artifact_name" "$dmg_path"

mkdir -p "$mount_dir"
hdiutil attach -quiet -nobrowse -readonly -mountpoint "$mount_dir" "$dmg_path"
mounted=1

source_app="$mount_dir/Agent Secret.app"
[ -d "$source_app" ] || die "DMG does not contain Agent Secret.app"

target_app="$app_dir/Agent Secret.app"
tmp_app="$app_dir/.Agent Secret.app.installing.$$"

stop_existing_daemon

echo "Installing Agent Secret.app into $app_dir"
mkdir -p "$app_dir"
rm -rf "$tmp_app"
ditto "$source_app" "$tmp_app"
rm -rf "$target_app"
mv "$tmp_app" "$target_app"

echo "Installing command symlink into $bin_dir"
"$target_app/Contents/Resources/bin/agent-secret" install-cli --bin-dir "$bin_dir"

echo "Installing Agent Secret skill"
"$target_app/Contents/Resources/bin/agent-secret" skill-install --skills-dir "$skills_dir" --force

echo "Running diagnostics"
"$bin_dir/agent-secret" doctor
