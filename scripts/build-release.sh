#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/build-release.sh VERSION [flags]

Build a local macOS DMG release artifact and checksums.txt.

Flags:
  --output DIR                    Output directory. Defaults to ./dist.
  --require-production-signing    Require Developer ID signing and notarization.
  -h, --help                      Show this help.
USAGE
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
output_dir="$project_root/dist"
require_production_signing=0

release_signing_env_present() {
  local name=""

  for name in \
    AGENT_SECRET_CODESIGN_CERT_P12_BASE64 \
    AGENT_SECRET_CODESIGN_CERT_P12_PATH \
    AGENT_SECRET_CODESIGN_CERT_PASSWORD \
    AGENT_SECRET_CODESIGN_ENTITLEMENTS \
    AGENT_SECRET_CODESIGN_IDENTITY \
    AGENT_SECRET_NOTARIZE \
    AGENT_SECRET_NOTARY_ISSUER_ID \
    AGENT_SECRET_NOTARY_KEY \
    AGENT_SECRET_NOTARY_KEY_ID; do
    if [[ "${!name:-}" != "" ]]; then
      return 0
    fi
  done
  return 1
}

if [[ "${AGENT_SECRET_IN_MISE:-}" != "1" ]]; then
  if release_signing_env_present; then
    echo "build-release: refusing to re-exec PATH-discovered mise while release signing environment is present" >&2
    echo "build-release: run from a trusted toolchain context with AGENT_SECRET_IN_MISE=1" >&2
    exit 1
  fi
  if command -v mise >/dev/null 2>&1; then
    export AGENT_SECRET_IN_MISE=1
    exec mise exec -- "$0" "$@"
  fi
fi

codesign_identity="${AGENT_SECRET_CODESIGN_IDENTITY:-"-"}"
notarize="${AGENT_SECRET_NOTARIZE:-0}"
notary_key="${AGENT_SECRET_NOTARY_KEY:-}"
notary_key_id="${AGENT_SECRET_NOTARY_KEY_ID:-}"
notary_issuer_id="${AGENT_SECRET_NOTARY_ISSUER_ID:-}"

if [[ $# -eq 0 ]]; then
  usage >&2
  exit 2
fi

version=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      if [[ $# -lt 2 || "$2" == "" ]]; then
        echo "build-release: --output requires a directory" >&2
        exit 2
      fi
      output_dir="$2"
      shift 2
      ;;
    --require-production-signing)
      require_production_signing=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      echo "build-release: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ "$version" != "" ]]; then
        echo "build-release: version was already set to $version" >&2
        exit 2
      fi
      version="$1"
      shift
      ;;
  esac
done

if [[ "$version" == "" ]]; then
  echo "build-release: VERSION is required" >&2
  exit 2
fi

require_production_release_signing() {
  local missing=0

  if [[ "$codesign_identity" == "" || "$codesign_identity" == "-" ]]; then
    echo "build-release: production release requires AGENT_SECRET_CODESIGN_IDENTITY" >&2
    missing=1
  fi
  if [[ "$notarize" != "1" ]]; then
    echo "build-release: production release requires AGENT_SECRET_NOTARIZE=1" >&2
    missing=1
  fi
  if [[ "$notary_key" == "" ]]; then
    echo "build-release: production release requires AGENT_SECRET_NOTARY_KEY" >&2
    missing=1
  fi
  if [[ "$notary_key_id" == "" ]]; then
    echo "build-release: production release requires AGENT_SECRET_NOTARY_KEY_ID" >&2
    missing=1
  fi
  if [[ "$notary_issuer_id" == "" ]]; then
    echo "build-release: production release requires AGENT_SECRET_NOTARY_ISSUER_ID" >&2
    missing=1
  fi
  if [[ "$missing" -ne 0 ]]; then
    exit 1
  fi
}

if [[ "$require_production_signing" == "1" ]]; then
  require_production_release_signing
fi

require_tool() {
  local name="$1"
  local path="$2"

  if [[ ! -x "$path" ]]; then
    echo "build-release: required command not found or not executable: $name ($path)" >&2
    exit 1
  fi
}

tool_hdiutil="/usr/bin/hdiutil"
tool_ditto="/usr/bin/ditto"
tool_shasum="/usr/bin/shasum"
tool_codesign="/usr/bin/codesign"
tool_xcrun="/usr/bin/xcrun"
tool_mktemp="/usr/bin/mktemp"
tool_rm="/bin/rm"
tool_mkdir="/bin/mkdir"
tool_ln="/bin/ln"
tool_uname="/usr/bin/uname"
tool_chmod="/bin/chmod"

case "$("$tool_uname" -m)" in
  arm64)
    arch="arm64"
    ;;
  x86_64)
    arch="x86_64"
    ;;
  *)
    echo "build-release: unsupported architecture: $("$tool_uname" -m)" >&2
    exit 1
    ;;
esac

require_tool hdiutil "$tool_hdiutil"
require_tool ditto "$tool_ditto"
require_tool shasum "$tool_shasum"
require_tool mktemp "$tool_mktemp"
require_tool rm "$tool_rm"
require_tool mkdir "$tool_mkdir"
require_tool ln "$tool_ln"
require_tool uname "$tool_uname"
require_tool chmod "$tool_chmod"
if [[ "$codesign_identity" != "-" ]]; then
  require_tool codesign "$tool_codesign"
fi
if [[ "$notarize" == "1" ]]; then
  require_tool xcrun "$tool_xcrun"
fi

tmp_dir="$("$tool_mktemp" -d "${TMPDIR:-/tmp}/agent-secret-release.XXXXXX")"
cleanup() {
  "$tool_rm" -rf "$tmp_dir"
}
trap cleanup EXIT

build_dir="$tmp_dir/build"
dmg_root="$tmp_dir/dmg-root"
artifact_name="Agent-Secret-$version-macos-$arch.dmg"
dmg_path="$output_dir/$artifact_name"
checksums_path="$output_dir/checksums.txt"
notary_key_path=""

prepare_notary_key() {
  if [[ "$notary_key" == "" || "$notary_key_id" == "" || "$notary_issuer_id" == "" ]]; then
    echo "build-release: notarization requires AGENT_SECRET_NOTARY_KEY, AGENT_SECRET_NOTARY_KEY_ID, and AGENT_SECRET_NOTARY_ISSUER_ID" >&2
    exit 1
  fi

  if [[ -f "$notary_key" ]]; then
    echo "$notary_key"
    return
  fi

  local key_path="$tmp_dir/AuthKey_${notary_key_id}.p8"
  printf '%s\n' "$notary_key" >"$key_path"
  "$tool_chmod" 0600 "$key_path"
  echo "$key_path"
}

submit_for_notarization() {
  local path="$1"

  if [[ "$notary_key_path" == "" ]]; then
    notary_key_path="$(prepare_notary_key)"
  fi

  "$tool_xcrun" notarytool submit "$path" \
    --key "$notary_key_path" \
    --key-id "$notary_key_id" \
    --issuer "$notary_issuer_id" \
    --wait
}

if [[ "$notarize" == "1" && "$codesign_identity" == "-" ]]; then
  echo "build-release: notarization requires AGENT_SECRET_CODESIGN_IDENTITY" >&2
  exit 1
fi

echo "Building Agent Secret.app for $version..."
"$project_root/scripts/build-app-bundle.sh" --version "$version" --output "$build_dir"

if [[ "$notarize" == "1" ]]; then
  echo "Submitting app bundle for notarization..."
  app_zip="$tmp_dir/AgentSecretApp.zip"
  (
    cd "$build_dir"
    "$tool_ditto" -c -k --keepParent "Agent Secret.app" "$app_zip"
  )
  submit_for_notarization "$app_zip"

  echo "Stapling notarization ticket to app bundle..."
  "$tool_xcrun" stapler staple "$build_dir/Agent Secret.app"
  "$tool_xcrun" stapler validate "$build_dir/Agent Secret.app"
fi

echo "Preparing DMG contents..."
"$tool_rm" -rf "$dmg_root"
"$tool_mkdir" -p "$dmg_root"
"$tool_ditto" "$build_dir/Agent Secret.app" "$dmg_root/Agent Secret.app"
"$tool_ln" -s /Applications "$dmg_root/Applications"

echo "Creating $dmg_path..."
"$tool_mkdir" -p "$output_dir"
"$tool_rm" -f "$dmg_path"
"$tool_hdiutil" create \
  -volname "Agent Secret $version" \
  -srcfolder "$dmg_root" \
  -format UDZO \
  -ov \
  "$dmg_path" >/dev/null

echo "Verifying DMG..."
"$tool_hdiutil" verify "$dmg_path" >/dev/null

if [[ "$codesign_identity" != "-" ]]; then
  echo "Signing DMG with $codesign_identity..."
  "$tool_codesign" --force --sign "$codesign_identity" --timestamp "$dmg_path" >/dev/null
fi

if [[ "$notarize" == "1" ]]; then
  echo "Submitting DMG for notarization..."
  submit_for_notarization "$dmg_path"

  echo "Stapling notarization ticket..."
  "$tool_xcrun" stapler staple "$dmg_path"
  "$tool_xcrun" stapler validate "$dmg_path"
fi

echo "Writing checksums..."
(
  cd "$output_dir"
  "$tool_shasum" -a 256 "$artifact_name" >"$checksums_path"
)

echo "$dmg_path"
echo "$checksums_path"
