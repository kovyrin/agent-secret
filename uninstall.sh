#!/bin/sh
set -eu
PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

default_app_dir="/Applications"
default_bin_dir="$HOME/.local/bin"
default_skills_dir="$HOME/.agents/skills"
app_dir="${AGENT_SECRET_APP_DIR:-$default_app_dir}"
bin_dir="${AGENT_SECRET_BIN_DIR:-$default_bin_dir}"
skills_dir="${AGENT_SECRET_SKILLS_DIR:-$default_skills_dir}"
remove_audit_logs="${AGENT_SECRET_REMOVE_AUDIT_LOGS:-0}"
no_stop_daemon="${AGENT_SECRET_NO_STOP_DAEMON:-0}"
allow_custom_uninstall_paths="${AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS:-0}"
force_remove_untrusted_app="${AGENT_SECRET_FORCE_REMOVE_UNTRUSTED_APP:-0}"
expected_team_id="B6L7QLWTZW"
expected_app_bundle_id="com.kovyrin.agent-secret"
expected_daemon_bundle_id="com.kovyrin.agent-secret.daemon"
codesign_path="/usr/bin/codesign"
default_support_dir="$HOME/Library/Application Support/agent-secret"
default_audit_dir="$HOME/Library/Logs/agent-secret"

app_support_dir="${AGENT_SECRET_SUPPORT_DIR-$default_support_dir}"
audit_dir="${AGENT_SECRET_AUDIT_DIR-$default_audit_dir}"

fail() {
  echo "agent-secret uninstall: $*" >&2
  exit 1
}

case "$force_remove_untrusted_app" in
  0 | 1) ;;
  *)
    fail "AGENT_SECRET_FORCE_REMOVE_UNTRUSTED_APP must be 0 or 1"
    ;;
esac

plist_value() {
  plist="$1"
  key="$2"

  /usr/libexec/PlistBuddy -c "Print :$key" "$plist" 2>/dev/null
}

bundle_identifier_matches() {
  bundle="$1"
  expected="$2"
  plist="$bundle/Contents/Info.plist"

  [ -f "$plist" ] || return 1
  got="$(plist_value "$plist" CFBundleIdentifier)" || return 1
  [ "$got" = "$expected" ]
}

codesign_team_id() {
  path="$1"

  details="$("$codesign_path" -dv --verbose=4 "$path" 2>&1)" || return 1
  printf '%s\n' "$details" |
    awk -F= '$1 == "TeamIdentifier" { print $2; found = 1; exit } END { if (!found) exit 1 }'
}

team_id_matches() {
  path="$1"

  team_id="$(codesign_team_id "$path")" || return 1
  [ "$team_id" = "$expected_team_id" ]
}

existing_app_is_trusted() {
  daemon_app="$target_app/Contents/Library/Helpers/AgentSecretDaemon.app"
  cli="$target_app/Contents/Resources/bin/agent-secret"

  [ -x "$cli" ] || return 1
  [ -x /usr/libexec/PlistBuddy ] || return 1
  [ -x "$codesign_path" ] || return 1
  bundle_identifier_matches "$target_app" "$expected_app_bundle_id" || return 1
  [ -d "$daemon_app" ] || return 1
  bundle_identifier_matches "$daemon_app" "$expected_daemon_bundle_id" || return 1
  "$codesign_path" --verify --deep --strict "$target_app" >/dev/null 2>&1 || return 1
  team_id_matches "$target_app" || return 1
  team_id_matches "$daemon_app" || return 1
  team_id_matches "$cli" || return 1
}

stop_existing_daemon() {
  if [ "$no_stop_daemon" = "1" ]; then
    return
  fi

  existing="$target_app/Contents/Resources/bin/agent-secret"
  if [ ! -d "$target_app" ]; then
    return
  fi

  if existing_app_is_trusted; then
    "$existing" daemon stop >/dev/null 2>&1 || true
  else
    echo "agent-secret uninstall: skipping daemon stop because existing Agent Secret.app could not be verified" >&2
  fi
}

remove_app_bundle() {
  echo "Removing $target_app"
  if [ ! -d "$target_app" ]; then
    return
  fi

  if existing_app_is_trusted; then
    rm -rf "$target_app"
    return
  fi

  if [ "$force_remove_untrusted_app" = "1" ]; then
    echo "agent-secret uninstall: force-removing unverified Agent Secret.app: $target_app" >&2
    rm -rf "$target_app"
    return
  fi

  echo "agent-secret uninstall: leaving unverified Agent Secret.app in place: $target_app" >&2
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

remove_skill_link() {
  if [ ! -L "$skill_link" ]; then
    if [ -e "$skill_link" ]; then
      echo "agent-secret uninstall: leaving non-symlink $skill_link in place" >&2
    fi
    return
  fi

  target="$(readlink "$skill_link")"
  case "$target" in
    *"Agent Secret.app/Contents/Resources/skills/agent-secret")
      rm -f "$skill_link"
      ;;
    *)
      echo "agent-secret uninstall: leaving unrelated symlink $skill_link -> $target in place" >&2
      ;;
  esac
}

strip_trailing_slashes() {
  value="$1"
  while [ "$value" != "/" ] && [ "${value%/}" != "$value" ]; do
    value="${value%/}"
  done
  printf '%s\n' "$value"
}

require_custom_path_guard() {
  label="$1"
  path="$2"
  default_path="$3"

  if [ "$path" = "$default_path" ]; then
    return
  fi
  if [ "$allow_custom_uninstall_paths" = "1" ]; then
    return
  fi

  fail "$label path override requires AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1: $path"
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
      fail "$label path must not contain symlinked parent directories: $current"
    fi

    next="${current%/*}"
    if [ "$next" = "$current" ] || [ "$next" = "" ]; then
      current="/"
    else
      current="$next"
    fi
  done
}

validate_agent_secret_dir() {
  label="$1"
  path="$(strip_trailing_slashes "$2")"
  default_path="$(strip_trailing_slashes "$3")"

  require_custom_path_guard "$label" "$path" "$default_path"

  if [ "$path" = "" ]; then
    fail "$label path is empty"
  fi
  case "$path" in
    /*) ;;
    *)
      fail "$label path must be absolute: $path"
      ;;
  esac
  case "$path" in
    "/" | "$HOME")
      fail "$label path is too broad: $path"
      ;;
    */../* | */.. | */./* | */.)
      fail "$label path must not contain dot segments: $path"
      ;;
  esac

  leaf="${path##*/}"
  if [ "$leaf" != "agent-secret" ]; then
    fail "$label path must end with agent-secret: $path"
  fi
  reject_symlinked_parent_dirs "$label" "$path"
  if [ -L "$path" ]; then
    fail "$label path must not be a symlink: $path"
  fi
  if [ -e "$path" ] && [ ! -d "$path" ]; then
    fail "$label path is not a directory: $path"
  fi
}

validate_destination_dir() {
  label="$1"
  path="$(strip_trailing_slashes "$2")"
  default_path="$(strip_trailing_slashes "$3")"

  require_custom_path_guard "$label" "$path" "$default_path"

  if [ "$path" = "" ]; then
    fail "$label path is empty"
  fi
  case "$path" in
    /*) ;;
    *)
      fail "$label path must be absolute: $path"
      ;;
  esac
  case "$path" in
    "/" | "$HOME")
      fail "$label path is too broad: $path"
      ;;
    */../* | */.. | */./* | */.)
      fail "$label path must not contain dot segments: $path"
      ;;
  esac

  reject_symlinked_parent_dirs "$label" "$path"
  if [ -L "$path" ]; then
    fail "$label path must not be a symlink: $path"
  fi
  if [ -e "$path" ] && [ ! -d "$path" ]; then
    fail "$label path is not a directory: $path"
  fi
}

remove_known_support_dir() {
  validate_agent_secret_dir "support" "$app_support_dir" "$default_support_dir"

  echo "Removing $app_support_dir"
  if [ ! -d "$app_support_dir" ]; then
    return
  fi
  rm -f "$app_support_dir/agent-secretd.sock"
  if ! rmdir "$app_support_dir" 2>/dev/null; then
    echo "agent-secret uninstall: leaving non-empty support directory $app_support_dir in place" >&2
  fi
}

remove_known_audit_dir() {
  validate_agent_secret_dir "audit" "$audit_dir" "$default_audit_dir"

  echo "Removing $audit_dir"
  if [ ! -d "$audit_dir" ]; then
    return
  fi
  rm -f "$audit_dir/audit.jsonl"
  if ! rmdir "$audit_dir" 2>/dev/null; then
    echo "agent-secret uninstall: leaving non-empty audit directory $audit_dir in place" >&2
  fi
}

validate_uninstall_paths() {
  validate_destination_dir "app" "$app_dir" "$default_app_dir"
  validate_destination_dir "bin" "$bin_dir" "$default_bin_dir"
  validate_destination_dir "skills" "$skills_dir" "$default_skills_dir"
  validate_agent_secret_dir "support" "$app_support_dir" "$default_support_dir"
  if [ "$remove_audit_logs" = "1" ]; then
    validate_agent_secret_dir "audit" "$audit_dir" "$default_audit_dir"
  fi

  app_dir="$(strip_trailing_slashes "$app_dir")"
  bin_dir="$(strip_trailing_slashes "$bin_dir")"
  skills_dir="$(strip_trailing_slashes "$skills_dir")"
}

validate_uninstall_paths
target_app="$app_dir/Agent Secret.app"
cli_link="$bin_dir/agent-secret"
skill_link="$skills_dir/agent-secret"
stop_existing_daemon
remove_cli_link
remove_skill_link
remove_app_bundle

remove_known_support_dir

if [ "$remove_audit_logs" = "1" ]; then
  remove_known_audit_dir
else
  echo "Leaving audit logs in place: $audit_dir"
fi
