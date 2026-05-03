#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/import-codesign-certificate.sh

Import a Developer ID .p12 certificate into a temporary macOS keychain for
non-interactive release signing.

Environment:
  AGENT_SECRET_CODESIGN_CERT_P12_BASE64   Base64-encoded .p12 content.
  AGENT_SECRET_CODESIGN_CERT_P12_PATH     Local .p12 path. Used when base64 is
                                          not set.
  AGENT_SECRET_CODESIGN_CERT_PASSWORD     Password for the .p12 export.
  AGENT_SECRET_CODESIGN_KEYCHAIN_PATH     Optional keychain path.
  AGENT_SECRET_CODESIGN_KEYCHAIN_PASSWORD Optional keychain password.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

die() {
  echo "import-codesign-certificate: $*" >&2
  exit 1
}

require_tool() {
  local name="$1"
  local path="$2"

  if [[ ! -x "$path" ]]; then
    die "required command not found or not executable: $name ($path)"
  fi
}

tool_base64="/usr/bin/base64"
tool_security="/usr/bin/security"
tool_uuidgen="/usr/bin/uuidgen"
tool_mktemp="/usr/bin/mktemp"
tool_rm="/bin/rm"

trim_keychain_path() {
  local path="$1"

  path="${path//\"/}"
  path="${path#"${path%%[![:space:]]*}"}"
  path="${path%"${path##*[![:space:]]}"}"
  printf '%s' "$path"
}

append_keychain_to_search_list() {
  local keychain_path="$1"
  local existing_keychains=()
  local keychain=""

  while IFS= read -r keychain; do
    keychain="$(trim_keychain_path "$keychain")"
    if [[ "$keychain" != "" && "$keychain" != "$keychain_path" ]]; then
      existing_keychains+=("$keychain")
    fi
  done < <("$tool_security" list-keychains -d user)

  "$tool_security" list-keychains -d user -s "$keychain_path" "${existing_keychains[@]}"
}

strip_trailing_slashes() {
  local value="$1"

  while [[ "$value" != "/" && "${value%/}" != "$value" ]]; do
    value="${value%/}"
  done
  printf '%s\n' "$value"
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
  local label="$1"
  local path="$2"
  local current="${path%/*}"
  local next=""

  if [[ "$current" == "$path" || "$current" == "" ]]; then
    return
  fi

  while [[ "$current" != "/" ]]; do
    if [[ -L "$current" ]] && ! is_system_root_alias "$current"; then
      die "$label must not contain symlinked parent directories: $current"
    fi

    next="${current%/*}"
    if [[ "$next" == "$current" || "$next" == "" ]]; then
      current="/"
    else
      current="$next"
    fi
  done
}

validate_keychain_path() {
  local path="$1"
  local trusted_dir="$2"
  local file_name="${path##*/}"

  if [[ "$path" == "" ]]; then
    die "AGENT_SECRET_CODESIGN_KEYCHAIN_PATH is empty"
  fi
  case "$path" in
    /*) ;;
    *)
      die "AGENT_SECRET_CODESIGN_KEYCHAIN_PATH must be absolute: $path"
      ;;
  esac
  case "$path" in
    */../* | */.. | */./* | */.)
      die "AGENT_SECRET_CODESIGN_KEYCHAIN_PATH must not contain dot segments: $path"
      ;;
  esac
  case "$file_name" in
    agent-secret-codesign.keychain-db | agent-secret-codesign-*.keychain-db) ;;
    *)
      die "AGENT_SECRET_CODESIGN_KEYCHAIN_PATH filename must be agent-secret-codesign*.keychain-db: $path"
      ;;
  esac
  case "$path" in
    "$trusted_dir"/*) ;;
    *)
      die "AGENT_SECRET_CODESIGN_KEYCHAIN_PATH must be under trusted temp directory $trusted_dir: $path"
      ;;
  esac
  reject_symlinked_parent_dirs "AGENT_SECRET_CODESIGN_KEYCHAIN_PATH" "$path"
}

require_tool base64 "$tool_base64"
require_tool security "$tool_security"
require_tool uuidgen "$tool_uuidgen"
require_tool mktemp "$tool_mktemp"
require_tool rm "$tool_rm"

trusted_keychain_dir="$(strip_trailing_slashes "${RUNNER_TEMP:-${TMPDIR:-/tmp}}")"
if [[ "$trusted_keychain_dir" == "" ]]; then
  trusted_keychain_dir="/tmp"
fi

cert_base64="${AGENT_SECRET_CODESIGN_CERT_P12_BASE64:-}"
cert_path="${AGENT_SECRET_CODESIGN_CERT_P12_PATH:-}"
cert_password="${AGENT_SECRET_CODESIGN_CERT_PASSWORD:-}"
keychain_path="${AGENT_SECRET_CODESIGN_KEYCHAIN_PATH:-}"
keychain_password="${AGENT_SECRET_CODESIGN_KEYCHAIN_PASSWORD:-}"

if [[ "$cert_base64" == "" && "$cert_path" == "" ]]; then
  die "set AGENT_SECRET_CODESIGN_CERT_P12_BASE64 or AGENT_SECRET_CODESIGN_CERT_P12_PATH"
fi

if [[ "$cert_password" == "" ]]; then
  die "set AGENT_SECRET_CODESIGN_CERT_PASSWORD"
fi

if [[ "$keychain_path" == "" ]]; then
  keychain_path="$trusted_keychain_dir/agent-secret-codesign.keychain-db"
fi
validate_keychain_path "$keychain_path" "$trusted_keychain_dir"

if [[ "$keychain_password" == "" ]]; then
  keychain_password="$("$tool_uuidgen")"
fi

tmp_dir="$("$tool_mktemp" -d "${TMPDIR:-/tmp}/agent-secret-codesign.XXXXXX")"
cleanup() {
  "$tool_rm" -rf "$tmp_dir"
}
trap cleanup EXIT

if [[ "$cert_base64" != "" ]]; then
  cert_path="$tmp_dir/developer-id.p12"
  printf '%s' "$cert_base64" | "$tool_base64" --decode >"$cert_path"
fi

if [[ ! -f "$cert_path" ]]; then
  die "certificate file does not exist: $cert_path"
fi

"$tool_rm" -f "$keychain_path"
"$tool_security" create-keychain -p "$keychain_password" "$keychain_path"
"$tool_security" set-keychain-settings -lut 21600 "$keychain_path"
"$tool_security" unlock-keychain -p "$keychain_password" "$keychain_path"
"$tool_security" import "$cert_path" \
  -k "$keychain_path" \
  -P "$cert_password" \
  -T /usr/bin/codesign \
  -T /usr/bin/productsign >/dev/null
"$tool_security" set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s \
  -k "$keychain_password" \
  "$keychain_path" >/dev/null
append_keychain_to_search_list "$keychain_path"

echo "Imported Developer ID identities:"
"$tool_security" find-identity -v -p codesigning "$keychain_path"
