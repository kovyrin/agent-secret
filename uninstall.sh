#!/bin/sh
set -eu

app_dir="${AGENT_SECRET_APP_DIR:-/Applications}"
bin_dir="${AGENT_SECRET_BIN_DIR:-$HOME/.local/bin}"
remove_audit_logs="${AGENT_SECRET_REMOVE_AUDIT_LOGS:-0}"
no_stop_daemon="${AGENT_SECRET_NO_STOP_DAEMON:-0}"

target_app="$app_dir/Agent Secret.app"
cli_link="$bin_dir/agent-secret"
app_support_dir="${AGENT_SECRET_SUPPORT_DIR:-$HOME/Library/Application Support/agent-secret}"
audit_dir="${AGENT_SECRET_AUDIT_DIR:-$HOME/Library/Logs/agent-secret}"

stop_existing_daemon() {
  if [ "$no_stop_daemon" = "1" ]; then
    return
  fi

  existing=""
  if [ -x "$cli_link" ]; then
    existing="$cli_link"
  elif [ -x "$target_app/Contents/Resources/bin/agent-secret" ]; then
    existing="$target_app/Contents/Resources/bin/agent-secret"
  elif command -v agent-secret >/dev/null 2>&1; then
    existing="$(command -v agent-secret)"
  fi

  if [ -n "$existing" ]; then
    "$existing" daemon stop >/dev/null 2>&1 || true
  fi
}

remove_cli_link() {
  if [ ! -L "$cli_link" ]; then
    if [ -e "$cli_link" ]; then
      echo "agent-secret uninstall: leaving non-symlink $cli_link in place" >&2
    fi
    return
  fi

  target="$(readlink "$cli_link")"
  case "$target" in
    *"Agent Secret.app/Contents/Resources/bin/agent-secret")
      rm -f "$cli_link"
      ;;
    *)
      echo "agent-secret uninstall: leaving unrelated symlink $cli_link -> $target in place" >&2
      ;;
  esac
}

stop_existing_daemon
remove_cli_link

echo "Removing $target_app"
rm -rf "$target_app"

echo "Removing $app_support_dir"
rm -rf "$app_support_dir"

if [ "$remove_audit_logs" = "1" ]; then
  echo "Removing $audit_dir"
  rm -rf "$audit_dir"
else
  echo "Leaving audit logs in place: $audit_dir"
fi
