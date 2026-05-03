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

custom_guard_rejects_override
custom_destination_guard_rejects_override
dangerous_paths_are_rejected_even_with_guard
dangerous_destination_paths_are_rejected_even_with_guard
symlinked_dirs_are_rejected
safe_custom_paths_remove_only_known_files

echo "test-uninstall: ok"
