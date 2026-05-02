#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/dev-install.sh [flags]

Build and install the current development version for the current macOS user.

Defaults:
  app:      ~/Applications/Agent Secret.app
  command:  ~/.local/bin/agent-secret -> ~/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret

Flags:
  --bin-dir DIR        Install the agent-secret command symlink into DIR.
  --app-dir DIR        Install Agent Secret.app into DIR.
  --no-stop-daemon     Do not stop an already-running per-user daemon before replacing the app.
  -h, --help           Show this help.

Environment:
  AGENT_SECRET_INSTALL_BIN_DIR  Default command symlink directory.
  AGENT_SECRET_INSTALL_APP_DIR  Default app install directory.

By default agent-secret uses my.1password.com unless OP_ACCOUNT,
AGENT_SECRET_1PASSWORD_ACCOUNT, --account, or project config chooses a
different account.
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

install_symlink() {
  local target="$1"
  local link="$2"

  if [[ -e "$link" && ! -L "$link" ]]; then
    echo "dev-install: refusing to replace non-symlink $link" >&2
    exit 1
  fi
  ln -sfn "$target" "$link"
}

require_command ditto
require_command install

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-install.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

stop_existing_daemon

echo "Building Agent Secret.app..."
"$project_root/scripts/build-app-bundle.sh" --output "$tmp_dir"

source_app="$tmp_dir/Agent Secret.app"
target_app="$app_dir/Agent Secret.app"
target_cli="$target_app/Contents/Resources/bin/agent-secret"
if [[ ! -x "$source_app/Contents/Resources/bin/agent-secret" ]]; then
  echo "dev-install: build did not produce bundled agent-secret command" >&2
  exit 1
fi
if [[ ! -d "$source_app/Contents/Library/Helpers/AgentSecretDaemon.app" ]]; then
  echo "dev-install: build did not produce bundled daemon helper app" >&2
  exit 1
fi

echo "Installing app into $app_dir..."
install -d -m 0755 "$app_dir"
rm -rf "$target_app"
ditto "$source_app" "$target_app"

echo "Removing old split-app development artifacts..."
rm -rf "$app_dir/AgentSecretDaemon.app" "$app_dir/AgentSecretApprover.app"
rm -f "$bin_dir/agent-secretd" "$bin_dir/agent-secret-approver"

echo "Installing command symlink into $bin_dir..."
install -d -m 0755 "$bin_dir"
install_symlink "$target_cli" "$bin_dir/agent-secret"

if ! path_contains "$bin_dir"; then
  echo "dev-install: warning: $bin_dir is not on PATH for this shell" >&2
fi

echo "Installed:"
echo "  $target_app"
echo "  $bin_dir/agent-secret -> $target_cli"
