#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/release/smoke-stale-dev-cli-diagnostics.sh [flags]

Build an ad-hoc development app bundle from the current checkout, ensure the
installed release helper is running, and verify the development CLI reports the
stale-CLI mixed-install diagnostic instead of blaming the trusted helper.

Flags:
  --installed-cli PATH   Installed release CLI path. Defaults to
                         /Applications/Agent Secret.app/Contents/Resources/bin/agent-secret.
  --require-installed-cli
                         Fail instead of skipping when the installed release CLI
                         is unavailable.
  -h, --help             Show this help.
USAGE
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
installed_cli="${AGENT_SECRET_RELEASE_SMOKE_INSTALLED_CLI:-/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret}"
require_installed_cli="${AGENT_SECRET_RELEASE_SMOKE_REQUIRE_INSTALLED_CLI:-0}"

fail() {
  echo "smoke-stale-dev-cli-diagnostics: $*" >&2
  exit 1
}

if [[ "${AGENT_SECRET_STALE_DEV_CLI_SMOKE_BOOTSTRAPPED:-}" != "1" ]] &&
  { [[ "${AGENT_SECRET_IN_MISE:-}" != "1" ]] || ! command -v go >/dev/null 2>&1; }; then
  if command -v mise >/dev/null 2>&1; then
    export AGENT_SECRET_IN_MISE=1
    export AGENT_SECRET_STALE_DEV_CLI_SMOKE_BOOTSTRAPPED=1
    exec mise exec -- "$0" "$@"
  fi
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --installed-cli)
      if [[ $# -lt 2 || "$2" == "" ]]; then
        fail "--installed-cli requires a path"
      fi
      installed_cli="$2"
      shift 2
      ;;
    --require-installed-cli)
      require_installed_cli=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

if [[ ! -x "$installed_cli" ]]; then
  if [[ "$require_installed_cli" != "1" ]]; then
    echo "smoke-stale-dev-cli-diagnostics: skipped; installed release CLI is not executable: $installed_cli"
    exit 0
  fi
  fail "installed release CLI is not executable: $installed_cli"
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-stale-cli-smoke.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

release_repair_json="$tmp_dir/release-repair.json"
if ! "$installed_cli" repair --json >"$release_repair_json"; then
  cat "$release_repair_json" >&2 || true
  fail "installed release CLI could not ensure the release helper is running"
fi
if ! grep -E '"status"[[:space:]]*:[[:space:]]*"(ok|refreshed)"' "$release_repair_json" >/dev/null; then
  cat "$release_repair_json" >&2
  fail "installed release CLI repair did not report ok/refreshed"
fi

build_dir="$tmp_dir/build"
AGENT_SECRET_CODESIGN_IDENTITY="-" \
  AGENT_SECRET_NOTARIZE=0 \
  AGENT_SECRET_BUILD_REVISION="stale-dev-cli-smoke" \
  "$project_root/scripts/build/build-app-bundle.sh" --output "$build_dir" >/dev/null

dev_cli="$build_dir/Agent Secret.app/Contents/Resources/bin/agent-secret"
if [[ ! -x "$dev_cli" ]]; then
  fail "development build did not produce bundled CLI: $dev_cli"
fi

dev_repair_json="$tmp_dir/dev-repair.json"
dev_repair_stderr="$tmp_dir/dev-repair.stderr"
if "$dev_cli" repair --json >"$dev_repair_json" 2>"$dev_repair_stderr"; then
  cat "$dev_repair_json" >&2 || true
  cat "$dev_repair_stderr" >&2 || true
  fail "development CLI unexpectedly trusted the installed release helper"
fi

require_dev_repair_text() {
  local needle="$1"

  if ! grep -F -- "$needle" "$dev_repair_json" >/dev/null; then
    cat "$dev_repair_json" >&2 || true
    cat "$dev_repair_stderr" >&2 || true
    fail "development CLI diagnostic is missing: $needle"
  fi
}

require_dev_repair_text '"status": "repair_required"'
require_dev_repair_text "current CLI is a development/ad-hoc build"
require_dev_repair_text "cannot trust the Agent Secret background helper"
require_dev_repair_text "install-cli --force"

echo "smoke-stale-dev-cli-diagnostics: ok"
