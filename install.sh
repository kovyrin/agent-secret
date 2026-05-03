#!/bin/sh
set -eu
PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

die() {
  echo "agent-secret install: $*" >&2
  exit 1
}

env_is_set() {
  eval "[ \"\${$1+x}\" = x ]"
}

require_dev_mode_for_env() {
  name="$1"
  if [ "$install_dev_mode" != "1" ] && env_is_set "$name"; then
    die "$name requires AGENT_SECRET_INSTALL_DEV_MODE=1"
  fi
}

strip_trailing_slashes() {
  value="$1"
  while [ "$value" != "/" ] && [ "${value%/}" != "$value" ]; do
    value="${value%/}"
  done
  printf '%s\n' "$value"
}

require_custom_install_path_guard() {
  label="$1"
  path="$2"
  default_path="$3"

  if [ "$path" = "$default_path" ]; then
    return
  fi
  if [ "$allow_custom_install_paths" = "1" ]; then
    return
  fi

  die "$label path override requires AGENT_SECRET_ALLOW_CUSTOM_INSTALL_PATHS=1: $path"
}

require_tool() {
  name="$1"
  path="$2"
  if [ ! -x "$path" ]; then
    die "required command not found or not executable: $name ($path)"
  fi
}

configure_tool_paths() {
  tool_curl="/usr/bin/curl"
  tool_hdiutil="/usr/bin/hdiutil"
  tool_shasum="/usr/bin/shasum"
  tool_ditto="/usr/bin/ditto"
  tool_codesign="/usr/bin/codesign"
  tool_spctl="/usr/sbin/spctl"
  tool_xcrun="/usr/bin/xcrun"
  tool_plistbuddy="/usr/libexec/PlistBuddy"

  if [ -z "$install_tool_dir" ]; then
    return
  fi

  case "$install_tool_dir" in
    /*) ;;
    *)
      die "AGENT_SECRET_INSTALL_TOOL_DIR must be absolute: $install_tool_dir"
      ;;
  esac

  tool_curl="$install_tool_dir/curl"
  tool_hdiutil="$install_tool_dir/hdiutil"
  tool_shasum="$install_tool_dir/shasum"
  tool_ditto="$install_tool_dir/ditto"
  tool_codesign="$install_tool_dir/codesign"
  tool_spctl="$install_tool_dir/spctl"
  tool_xcrun="$install_tool_dir/xcrun"
}

is_system_root_alias() {
  case "$1" in
    /etc | /tmp | /var)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

reject_symlinked_parent_dirs() {
  label="$1"
  path="$2"
  current="${path%/*}"

  if [ "$current" = "$path" ] || [ "$current" = "" ]; then
    return
  fi

  while [ "$current" != "/" ]; do
    if [ -L "$current" ] && ! is_system_root_alias "$current"; then
      die "$label path must not contain symlinked parent directories: $current"
    fi

    next="${current%/*}"
    if [ "$next" = "$current" ] || [ "$next" = "" ]; then
      current="/"
    else
      current="$next"
    fi
  done
}

validate_install_dir() {
  label="$1"
  path="$(strip_trailing_slashes "$2")"
  default_path="$(strip_trailing_slashes "$3")"

  require_custom_install_path_guard "$label" "$path" "$default_path"

  if [ "$path" = "" ]; then
    die "$label path is empty"
  fi
  case "$path" in
    /*) ;;
    *)
      die "$label path must be absolute: $path"
      ;;
  esac
  case "$path" in
    "/" | "$HOME")
      die "$label path is too broad: $path"
      ;;
    */../* | */.. | */./* | */.)
      die "$label path must not contain dot segments: $path"
      ;;
  esac
  reject_symlinked_parent_dirs "$label" "$path"
  if [ -L "$path" ]; then
    die "$label path must not be a symlink: $path"
  fi
  if [ -e "$path" ] && [ ! -d "$path" ]; then
    die "$label path is not a directory: $path"
  fi
}

validate_install_paths() {
  validate_install_dir "app" "$app_dir" "$default_app_dir"
  validate_install_dir "bin" "$bin_dir" "$default_bin_dir"
  validate_install_dir "skills" "$skills_dir" "$default_skills_dir"

  app_dir="$(strip_trailing_slashes "$app_dir")"
  bin_dir="$(strip_trailing_slashes "$bin_dir")"
  skills_dir="$(strip_trailing_slashes "$skills_dir")"
}

production_repo="kovyrin/agent-secret"
production_github_url="https://github.com"
production_github_api="https://api.github.com"
production_expected_team_id="B6L7QLWTZW"
production_expected_app_bundle_id="com.kovyrin.agent-secret"
production_expected_daemon_bundle_id="com.kovyrin.agent-secret.daemon"
default_app_dir="/Applications"
default_bin_dir="$HOME/.local/bin"
default_skills_dir="$HOME/.agents/skills"

install_dev_mode="${AGENT_SECRET_INSTALL_DEV_MODE:-0}"
case "$install_dev_mode" in
  0 | 1) ;;
  *)
    die "AGENT_SECRET_INSTALL_DEV_MODE must be 0 or 1"
    ;;
esac

repo="$production_repo"
github_url="$production_github_url"
github_api="$production_github_api"
allow_unsigned_install=0
require_notarization=1
expected_team_id="$production_expected_team_id"
expected_app_bundle_id="$production_expected_app_bundle_id"
expected_daemon_bundle_id="$production_expected_daemon_bundle_id"

if [ "$install_dev_mode" != "1" ]; then
  require_dev_mode_for_env AGENT_SECRET_REPO
  require_dev_mode_for_env AGENT_SECRET_GITHUB_URL
  require_dev_mode_for_env AGENT_SECRET_GITHUB_API
  require_dev_mode_for_env AGENT_SECRET_ALLOW_UNSIGNED_INSTALL
  require_dev_mode_for_env AGENT_SECRET_REQUIRE_NOTARIZATION
  require_dev_mode_for_env AGENT_SECRET_EXPECTED_TEAM_ID
  require_dev_mode_for_env AGENT_SECRET_EXPECTED_APP_BUNDLE_ID
  require_dev_mode_for_env AGENT_SECRET_EXPECTED_DAEMON_BUNDLE_ID
  require_dev_mode_for_env AGENT_SECRET_INSTALL_TOOL_DIR
else
  repo="${AGENT_SECRET_REPO:-$production_repo}"
  github_url="${AGENT_SECRET_GITHUB_URL:-$production_github_url}"
  github_api="${AGENT_SECRET_GITHUB_API:-$production_github_api}"
  allow_unsigned_install="${AGENT_SECRET_ALLOW_UNSIGNED_INSTALL:-0}"
  require_notarization="${AGENT_SECRET_REQUIRE_NOTARIZATION:-1}"
  expected_team_id="${AGENT_SECRET_EXPECTED_TEAM_ID:-$production_expected_team_id}"
  expected_app_bundle_id="${AGENT_SECRET_EXPECTED_APP_BUNDLE_ID:-$production_expected_app_bundle_id}"
  expected_daemon_bundle_id="${AGENT_SECRET_EXPECTED_DAEMON_BUNDLE_ID:-$production_expected_daemon_bundle_id}"
fi

app_dir="${AGENT_SECRET_APP_DIR:-$default_app_dir}"
bin_dir="${AGENT_SECRET_BIN_DIR:-$default_bin_dir}"
skills_dir="${AGENT_SECRET_SKILLS_DIR:-$default_skills_dir}"
version="${AGENT_SECRET_VERSION:-}"
local_dmg="${AGENT_SECRET_DMG:-}"
local_checksums="${AGENT_SECRET_CHECKSUMS_FILE:-}"
no_stop_daemon="${AGENT_SECRET_NO_STOP_DAEMON:-0}"
allow_custom_install_paths="${AGENT_SECRET_ALLOW_CUSTOM_INSTALL_PATHS:-0}"
install_tool_dir="${AGENT_SECRET_INSTALL_TOOL_DIR:-}"
configure_tool_paths

case "$allow_custom_install_paths" in
  0 | 1) ;;
  *)
    die "AGENT_SECRET_ALLOW_CUSTOM_INSTALL_PATHS must be 0 or 1"
    ;;
esac

validate_install_paths

if [ "$install_dev_mode" = "1" ]; then
  echo "agent-secret install: development installer mode enabled" >&2
  [ -n "$local_dmg" ] || die "AGENT_SECRET_INSTALL_DEV_MODE=1 requires AGENT_SECRET_DMG"
  [ -n "$local_checksums" ] || die "AGENT_SECRET_INSTALL_DEV_MODE=1 requires AGENT_SECRET_CHECKSUMS_FILE"
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-install.XXXXXX")"
mount_dir="$tmp_dir/mount"
mounted=0

cleanup() {
  if [ "$mounted" -eq 1 ]; then
    "$tool_hdiutil" detach "$mount_dir" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

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
  json="$("$tool_curl" -fsSL "$github_api/repos/$repo/releases/latest")" || die "could not fetch latest GitHub release"
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
  "$tool_curl" -fL --progress-bar "$url" -o "$destination"
}

verify_checksum() {
  checksums="$1"
  file_name="$2"
  file_path="$3"

  expected="$(awk -v file="$file_name" '$2 == file { print $1; found = 1; exit } END { if (!found) exit 1 }' "$checksums")" ||
    die "checksums file does not contain $file_name"
  actual="$("$tool_shasum" -a 256 "$file_path" | awk '{ print $1 }')"
  if [ "$actual" != "$expected" ]; then
    die "checksum mismatch for $file_name"
  fi
}

verify_dmg_identity() {
  dmg="$1"

  if [ "$allow_unsigned_install" = "1" ]; then
    echo "Skipping release identity verification because AGENT_SECRET_ALLOW_UNSIGNED_INSTALL=1" >&2
    return
  fi

  require_tool codesign "$tool_codesign"
  require_tool spctl "$tool_spctl"
  require_tool xcrun "$tool_xcrun"

  "$tool_codesign" --verify --strict --verbose=2 "$dmg" ||
    die "DMG code signature verification failed"
  verify_team_id "$dmg" "DMG"
  "$tool_spctl" --assess --type open --context context:primary-signature --verbose "$dmg" ||
    die "DMG Gatekeeper assessment failed"
  if [ "$require_notarization" = "1" ]; then
    "$tool_xcrun" stapler validate "$dmg" ||
      die "DMG notarization ticket validation failed"
  fi
}

codesign_team_id() {
  path="$1"
  details="$("$tool_codesign" -dv --verbose=4 "$path" 2>&1)" ||
    die "could not read code signature details for $path"
  printf '%s\n' "$details" |
    awk -F= '$1 == "TeamIdentifier" { print $2; found = 1; exit } END { if (!found) exit 1 }' ||
    die "code signature for $path does not include a TeamIdentifier"
}

verify_team_id() {
  path="$1"
  label="$2"
  team_id="$(codesign_team_id "$path")"
  if [ "$team_id" != "$expected_team_id" ]; then
    die "$label signed by unexpected Team ID: $team_id"
  fi
}

plist_value() {
  plist="$1"
  key="$2"
  "$tool_plistbuddy" -c "Print :$key" "$plist" 2>/dev/null ||
    die "could not read $key from $plist"
}

verify_bundle_identifier() {
  bundle="$1"
  expected="$2"
  label="$3"
  plist="$bundle/Contents/Info.plist"

  [ -f "$plist" ] || die "$label is missing Contents/Info.plist"
  got="$(plist_value "$plist" CFBundleIdentifier)"
  if [ "$got" != "$expected" ]; then
    die "$label has unexpected bundle identifier: $got"
  fi
}

verify_app_identity() {
  app="$1"
  daemon_app="$app/Contents/Library/Helpers/AgentSecretDaemon.app"
  cli="$app/Contents/Resources/bin/agent-secret"

  require_tool PlistBuddy "$tool_plistbuddy"
  verify_bundle_identifier "$app" "$expected_app_bundle_id" "Agent Secret.app"
  [ -d "$daemon_app" ] || die "Agent Secret.app is missing the daemon helper app"
  verify_bundle_identifier "$daemon_app" "$expected_daemon_bundle_id" "AgentSecretDaemon.app"
  [ -x "$cli" ] || die "Agent Secret.app is missing the bundled agent-secret CLI"

  if [ "$allow_unsigned_install" = "1" ]; then
    return
  fi

  "$tool_codesign" --verify --deep --strict --verbose=2 "$app" ||
    die "app code signature verification failed"
  verify_team_id "$app" "Agent Secret.app"
  verify_team_id "$daemon_app" "AgentSecretDaemon.app"
  verify_team_id "$cli" "bundled agent-secret CLI"
  "$tool_spctl" --assess --type execute --verbose "$app" ||
    die "app Gatekeeper assessment failed"
  if [ "$require_notarization" = "1" ]; then
    "$tool_xcrun" stapler validate "$app" ||
      die "app notarization ticket validation failed"
  fi
}

stop_existing_daemon() {
  if [ "$no_stop_daemon" = "1" ]; then
    return
  fi

  target_app="$app_dir/Agent Secret.app"
  existing="$target_app/Contents/Resources/bin/agent-secret"
  if [ ! -d "$target_app" ]; then
    return
  fi

  if (verify_app_identity "$target_app") >/dev/null 2>&1; then
    "$existing" daemon stop >/dev/null 2>&1 || true
  else
    echo "agent-secret install: skipping daemon stop because existing Agent Secret.app could not be verified" >&2
  fi
}

require_tool curl "$tool_curl"
require_tool hdiutil "$tool_hdiutil"
require_tool shasum "$tool_shasum"
require_tool ditto "$tool_ditto"

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
verify_dmg_identity "$dmg_path"

mkdir -p "$mount_dir"
"$tool_hdiutil" attach -quiet -nobrowse -readonly -mountpoint "$mount_dir" "$dmg_path"
mounted=1

source_app="$mount_dir/Agent Secret.app"
[ -d "$source_app" ] || die "DMG does not contain Agent Secret.app"
verify_app_identity "$source_app"

target_app="$app_dir/Agent Secret.app"
tmp_app="$app_dir/.Agent Secret.app.installing.$$"

stop_existing_daemon

echo "Installing Agent Secret.app into $app_dir"
mkdir -p "$app_dir"
rm -rf "$tmp_app"
"$tool_ditto" "$source_app" "$tmp_app"
rm -rf "$target_app"
mv "$tmp_app" "$target_app"

echo "Installing command symlink into $bin_dir"
"$target_app/Contents/Resources/bin/agent-secret" install-cli --bin-dir "$bin_dir"

echo "Installing Agent Secret skill"
"$target_app/Contents/Resources/bin/agent-secret" skill-install --skills-dir "$skills_dir" --force

echo "Running diagnostics"
"$bin_dir/agent-secret" doctor
