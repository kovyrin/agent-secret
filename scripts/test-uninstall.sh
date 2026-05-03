#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-uninstall-test.XXXXXX")"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  echo "test-uninstall: $*" >&2
  exit 1
}

run_uninstall() {
  local name="$1"
  shift

  mkdir -p "$tmp_dir/$name"
  (
    cd "$project_root"
    env -i \
      PATH="$PATH" \
      HOME="$tmp_dir/$name/home" \
      AGENT_SECRET_NO_STOP_DAEMON=1 \
      "$@" \
      "$project_root/uninstall.sh"
  ) >"$tmp_dir/$name/stdout" 2>"$tmp_dir/$name/stderr"
}

expect_failure() {
  local name="$1"
  local expected="$2"
  shift 2

  if run_uninstall "$name" "$@"; then
    fail "$name succeeded unexpectedly"
  fi
  if ! grep -F "$expected" "$tmp_dir/$name/stderr" >/dev/null; then
    fail "$name stderr did not contain $expected: $(cat "$tmp_dir/$name/stderr")"
  fi
}

make_symlink() {
  local target="$1"
  local link="$2"

  mkdir -p "$(dirname "$link")"
  ln -s "$target" "$link"
}

make_untrusted_app() {
  local app="$1"

  mkdir -p "$app/Contents/Resources/bin"
  printf 'keep\n' >"$app/keep.txt"
  cat >"$app/Contents/Resources/bin/agent-secret" <<'SCRIPT'
#!/bin/sh
printf 'fake-bundled-agent-secret' >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
for arg in "$@"; do
  printf ' %s' "$arg" >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
done
printf '\n' >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
exit 0
SCRIPT
  chmod 755 "$app/Contents/Resources/bin/agent-secret"
}

custom_guard_rejects_override() {
  local run_dir="$tmp_dir/custom-guard"
  local support="$run_dir/important/agent-secret"
  mkdir -p "$support"
  printf 'keep\n' >"$support/keep.txt"

  expect_failure \
    custom-guard \
    "support path override requires AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1" \
    AGENT_SECRET_SUPPORT_DIR="$support"

  if [ ! -f "$support/keep.txt" ]; then
    fail "custom support override removed data without guard"
  fi
}

custom_destination_guard_rejects_override() {
  local run_dir="$tmp_dir/custom-destination-guard"
  local app_dir="$run_dir/apps"
  local app="$app_dir/Agent Secret.app"
  mkdir -p "$app"
  printf 'keep\n' >"$app/keep.txt"

  expect_failure \
    custom-destination-guard \
    "app path override requires AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1" \
    AGENT_SECRET_APP_DIR="$app_dir"

  if [ ! -f "$app/keep.txt" ]; then
    fail "custom app override removed data without guard"
  fi
}

dangerous_paths_are_rejected_even_with_guard() {
  local run_dir="$tmp_dir/dangerous"
  local home="$run_dir/home"
  local audit="$run_dir/not-agent-secret"
  mkdir -p "$home" "$audit"
  printf 'keep\n' >"$home/keep.txt"

  expect_failure \
    dangerous-home \
    "support path is too broad" \
    HOME="$home" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_SUPPORT_DIR="$home"

  expect_failure \
    dangerous-leaf \
    "audit path must end with agent-secret" \
    HOME="$home" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_REMOVE_AUDIT_LOGS=1 \
    AGENT_SECRET_AUDIT_DIR="$audit"

  if [ ! -f "$home/keep.txt" ]; then
    fail "dangerous home path was modified"
  fi
}

dangerous_destination_paths_are_rejected_even_with_guard() {
  local run_dir="$tmp_dir/dangerous-destinations"
  local target="$run_dir/target"
  local link="$run_dir/skills-link"
  mkdir -p "$target"
  make_symlink "$target" "$link"

  expect_failure \
    dangerous-destination-relative \
    "bin path must be absolute" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_BIN_DIR=relative-bin

  expect_failure \
    dangerous-destination-symlink \
    "skills path must not be a symlink" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_SKILLS_DIR="$link"
}

symlinked_parent_dirs_are_rejected() {
  local run_dir="$tmp_dir/symlinked-parents"
  local target="$run_dir/target"
  local link="$run_dir/link-parent"
  mkdir -p "$target"
  printf 'keep\n' >"$target/keep.txt"
  make_symlink "$target" "$link"

  expect_failure \
    symlinked-app-parent \
    "app path must not contain symlinked parent directories" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_APP_DIR="$link/apps"

  expect_failure \
    symlinked-bin-parent \
    "bin path must not contain symlinked parent directories" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_BIN_DIR="$link/bin"

  expect_failure \
    symlinked-skills-parent \
    "skills path must not contain symlinked parent directories" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_SKILLS_DIR="$link/skills"

  expect_failure \
    symlinked-support-parent \
    "support path must not contain symlinked parent directories" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_SUPPORT_DIR="$link/agent-secret"

  expect_failure \
    symlinked-audit-parent \
    "audit path must not contain symlinked parent directories" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_REMOVE_AUDIT_LOGS=1 \
    AGENT_SECRET_AUDIT_DIR="$link/agent-secret"

  if [ ! -f "$target/keep.txt" ]; then
    fail "symlinked parent target was modified"
  fi
}

symlinked_dirs_are_rejected() {
  local run_dir="$tmp_dir/symlink"
  local target="$run_dir/target"
  local link="$run_dir/link/agent-secret"
  mkdir -p "$target"
  printf 'keep\n' >"$target/keep.txt"
  make_symlink "$target" "$link"

  expect_failure \
    symlink \
    "support path must not be a symlink" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_SUPPORT_DIR="$link"

  if [ ! -f "$target/keep.txt" ]; then
    fail "symlink target was modified"
  fi
}

safe_custom_paths_remove_only_known_files() {
  local run_dir="$tmp_dir/safe"
  local home="$run_dir/home"
  local app_dir="$run_dir/apps"
  local bin_dir="$run_dir/bin"
  local skills_dir="$run_dir/skills"
  local support="$run_dir/support/agent-secret"
  local audit="$run_dir/audit/agent-secret"
  local app="$app_dir/Agent Secret.app"

  mkdir -p \
    "$app/Contents/Resources/bin" \
    "$app/Contents/Resources/skills/agent-secret" \
    "$bin_dir" \
    "$skills_dir" \
    "$support" \
    "$audit" \
    "$home"
  touch "$app/Contents/Resources/bin/agent-secret"
  ln -s "$app/Contents/Resources/bin/agent-secret" "$bin_dir/agent-secret"
  ln -s "$app/Contents/Resources/skills/agent-secret" "$skills_dir/agent-secret"
  touch "$support/agent-secretd.sock"
  touch "$audit/audit.jsonl"

  run_uninstall \
    safe \
    HOME="$home" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_FORCE_REMOVE_UNTRUSTED_APP=1 \
    AGENT_SECRET_REMOVE_AUDIT_LOGS=1 \
    AGENT_SECRET_APP_DIR="$app_dir" \
    AGENT_SECRET_BIN_DIR="$bin_dir" \
    AGENT_SECRET_SKILLS_DIR="$skills_dir" \
    AGENT_SECRET_SUPPORT_DIR="$support" \
    AGENT_SECRET_AUDIT_DIR="$audit"

  for path in "$app" "$bin_dir/agent-secret" "$skills_dir/agent-secret" "$support" "$audit"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      fail "safe uninstall left expected removed path in place: $path"
    fi
  done
}

untrusted_app_is_left_in_place_by_default() {
  local run_dir="$tmp_dir/untrusted-app-default"
  local home="$run_dir/home"
  local app_dir="$run_dir/apps"
  local app="$app_dir/Agent Secret.app"
  local bin_dir="$run_dir/bin"
  local skills_dir="$run_dir/skills"
  local support="$run_dir/support/agent-secret"
  local log="$run_dir/uninstall.log"

  mkdir -p "$home" "$bin_dir" "$skills_dir" "$support"
  : >"$log"
  make_untrusted_app "$app"

  run_uninstall \
    untrusted-app-default \
    HOME="$home" \
    AGENT_SECRET_NO_STOP_DAEMON=0 \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_APP_DIR="$app_dir" \
    AGENT_SECRET_BIN_DIR="$bin_dir" \
    AGENT_SECRET_SKILLS_DIR="$skills_dir" \
    AGENT_SECRET_SUPPORT_DIR="$support" \
    AGENT_SECRET_UNINSTALL_TEST_LOG="$log"

  if [ ! -f "$app/keep.txt" ]; then
    fail "uninstaller removed an untrusted app bundle by default"
  fi
  if ! grep -F "leaving unverified Agent Secret.app in place" "$run_dir/stderr" >/dev/null; then
    fail "uninstaller did not report preserving untrusted app: $(cat "$run_dir/stderr")"
  fi
  if grep -F "fake-bundled-agent-secret daemon stop" "$log" >/dev/null; then
    fail "uninstaller executed untrusted bundled agent-secret"
  fi
}

force_removes_untrusted_app_explicitly() {
  local run_dir="$tmp_dir/untrusted-app-force"
  local home="$run_dir/home"
  local app_dir="$run_dir/apps"
  local app="$app_dir/Agent Secret.app"
  local bin_dir="$run_dir/bin"
  local skills_dir="$run_dir/skills"
  local support="$run_dir/support/agent-secret"
  local log="$run_dir/uninstall.log"

  mkdir -p "$home" "$bin_dir" "$skills_dir" "$support"
  : >"$log"
  make_untrusted_app "$app"

  run_uninstall \
    untrusted-app-force \
    HOME="$home" \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_FORCE_REMOVE_UNTRUSTED_APP=1 \
    AGENT_SECRET_APP_DIR="$app_dir" \
    AGENT_SECRET_BIN_DIR="$bin_dir" \
    AGENT_SECRET_SKILLS_DIR="$skills_dir" \
    AGENT_SECRET_SUPPORT_DIR="$support" \
    AGENT_SECRET_UNINSTALL_TEST_LOG="$log"

  if [ -e "$app" ]; then
    fail "explicit force uninstall left untrusted app bundle in place"
  fi
  if ! grep -F "force-removing unverified Agent Secret.app" "$run_dir/stderr" >/dev/null; then
    fail "force uninstall did not report forced app removal: $(cat "$run_dir/stderr")"
  fi
}

untrusted_existing_cli_is_not_used_for_daemon_stop() {
  local run_dir="$tmp_dir/untrusted-existing-cli"
  local home="$run_dir/home"
  local app_dir="$run_dir/apps"
  local bin_dir="$run_dir/bin"
  local skills_dir="$run_dir/skills"
  local support="$run_dir/support/agent-secret"
  local path_bin="$run_dir/path"
  local log="$run_dir/stop.log"

  mkdir -p "$home" "$app_dir" "$bin_dir" "$skills_dir" "$support" "$path_bin"
  : >"$log"

  cat >"$bin_dir/agent-secret" <<'SCRIPT'
#!/bin/sh
printf 'fake-bin-dir-agent-secret' >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
for arg in "$@"; do
  printf ' %s' "$arg" >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
done
printf '\n' >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
exit 0
SCRIPT
  chmod 755 "$bin_dir/agent-secret"

  cat >"$path_bin/agent-secret" <<'SCRIPT'
#!/bin/sh
printf 'fake-path-agent-secret' >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
for arg in "$@"; do
  printf ' %s' "$arg" >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
done
printf '\n' >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
exit 0
SCRIPT
  chmod 755 "$path_bin/agent-secret"

  run_uninstall \
    untrusted-existing-cli \
    HOME="$home" \
    PATH="$path_bin:$PATH" \
    AGENT_SECRET_NO_STOP_DAEMON=0 \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_APP_DIR="$app_dir" \
    AGENT_SECRET_BIN_DIR="$bin_dir" \
    AGENT_SECRET_SKILLS_DIR="$skills_dir" \
    AGENT_SECRET_SUPPORT_DIR="$support" \
    AGENT_SECRET_UNINSTALL_TEST_LOG="$log"

  if grep -E '^fake-(bin-dir|path)-agent-secret daemon stop$' "$log" >/dev/null; then
    fail "uninstaller executed an untrusted existing agent-secret during daemon stop"
  fi
}

fake_path_codesign_is_not_used_for_trust_checks() {
  local run_dir="$tmp_dir/fake-path-codesign"
  local home="$run_dir/home"
  local app_dir="$run_dir/apps"
  local app="$app_dir/Agent Secret.app"
  local daemon_app="$app/Contents/Library/Helpers/AgentSecretDaemon.app"
  local bin_dir="$run_dir/bin"
  local skills_dir="$run_dir/skills"
  local support="$run_dir/support/agent-secret"
  local path_bin="$run_dir/path"
  local log="$run_dir/uninstall.log"

  mkdir -p \
    "$home" \
    "$app/Contents/Resources/bin" \
    "$daemon_app/Contents" \
    "$bin_dir" \
    "$skills_dir" \
    "$support" \
    "$path_bin"
  : >"$log"

  cat >"$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.kovyrin.agent-secret</string>
</dict>
</plist>
PLIST

  cat >"$daemon_app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.kovyrin.agent-secret.daemon</string>
</dict>
</plist>
PLIST

  cat >"$app/Contents/Resources/bin/agent-secret" <<'SCRIPT'
#!/bin/sh
printf 'fake-bundled-agent-secret' >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
for arg in "$@"; do
  printf ' %s' "$arg" >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
done
printf '\n' >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
exit 0
SCRIPT
  chmod 755 "$app/Contents/Resources/bin/agent-secret"

  cat >"$path_bin/codesign" <<'SCRIPT'
#!/bin/sh
printf 'fake-path-codesign' >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
for arg in "$@"; do
  printf ' %s' "$arg" >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
done
printf '\n' >>"$AGENT_SECRET_UNINSTALL_TEST_LOG"
case " $* " in
  *" --verify "*)
    exit 0
    ;;
  *)
    printf 'TeamIdentifier=B6L7QLWTZW\n' >&2
    exit 0
    ;;
esac
SCRIPT
  chmod 755 "$path_bin/codesign"

  run_uninstall \
    fake-path-codesign \
    HOME="$home" \
    PATH="$path_bin:$PATH" \
    AGENT_SECRET_NO_STOP_DAEMON=0 \
    AGENT_SECRET_ALLOW_CUSTOM_UNINSTALL_PATHS=1 \
    AGENT_SECRET_APP_DIR="$app_dir" \
    AGENT_SECRET_BIN_DIR="$bin_dir" \
    AGENT_SECRET_SKILLS_DIR="$skills_dir" \
    AGENT_SECRET_SUPPORT_DIR="$support" \
    AGENT_SECRET_UNINSTALL_TEST_LOG="$log"

  if grep -F "fake-path-codesign" "$log" >/dev/null; then
    fail "uninstaller used codesign from PATH for trust checks"
  fi
  if grep -F "fake-bundled-agent-secret daemon stop" "$log" >/dev/null; then
    fail "uninstaller trusted fake app and executed bundled agent-secret"
  fi
  if [ ! -d "$app" ]; then
    fail "uninstaller removed app after refusing PATH-provided codesign trust"
  fi
}

custom_guard_rejects_override
custom_destination_guard_rejects_override
dangerous_paths_are_rejected_even_with_guard
dangerous_destination_paths_are_rejected_even_with_guard
symlinked_parent_dirs_are_rejected
symlinked_dirs_are_rejected
safe_custom_paths_remove_only_known_files
untrusted_app_is_left_in_place_by_default
force_removes_untrusted_app_explicitly
untrusted_existing_cli_is_not_used_for_daemon_stop
fake_path_codesign_is_not_used_for_trust_checks

echo "test-uninstall: ok"
