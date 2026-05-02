#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-install-test.XXXXXX")"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  echo "test-install: $*" >&2
  exit 1
}

write_fake_tools() {
  local fake_bin="$1"

  mkdir -p "$fake_bin"

  cat >"$fake_bin/codesign" <<'SCRIPT'
#!/bin/sh
printf 'codesign' >>"$AGENT_SECRET_INSTALL_TEST_LOG"
for arg in "$@"; do
  printf ' %s' "$arg" >>"$AGENT_SECRET_INSTALL_TEST_LOG"
done
printf '\n' >>"$AGENT_SECRET_INSTALL_TEST_LOG"
exit "${AGENT_SECRET_INSTALL_TEST_CODESIGN_STATUS:-0}"
SCRIPT

  cat >"$fake_bin/spctl" <<'SCRIPT'
#!/bin/sh
printf 'spctl' >>"$AGENT_SECRET_INSTALL_TEST_LOG"
for arg in "$@"; do
  printf ' %s' "$arg" >>"$AGENT_SECRET_INSTALL_TEST_LOG"
done
printf '\n' >>"$AGENT_SECRET_INSTALL_TEST_LOG"
exit "${AGENT_SECRET_INSTALL_TEST_SPCTL_STATUS:-0}"
SCRIPT

  cat >"$fake_bin/xcrun" <<'SCRIPT'
#!/bin/sh
printf 'xcrun' >>"$AGENT_SECRET_INSTALL_TEST_LOG"
for arg in "$@"; do
  printf ' %s' "$arg" >>"$AGENT_SECRET_INSTALL_TEST_LOG"
done
printf '\n' >>"$AGENT_SECRET_INSTALL_TEST_LOG"
exit "${AGENT_SECRET_INSTALL_TEST_XCRUN_STATUS:-0}"
SCRIPT

  cat >"$fake_bin/ditto" <<'SCRIPT'
#!/bin/sh
cp -R "$1" "$2"
SCRIPT

  cat >"$fake_bin/hdiutil" <<'SCRIPT'
#!/bin/sh
if [ "$1" = "attach" ]; then
  mount_dir=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "-mountpoint" ]; then
      mount_dir="$2"
      shift 2
      continue
    fi
    shift
  done
  if [ "$mount_dir" = "" ]; then
    echo "missing -mountpoint" >&2
    exit 64
  fi
  cli="$mount_dir/Agent Secret.app/Contents/Resources/bin/agent-secret"
  mkdir -p "$(dirname "$cli")"
  cat >"$cli" <<'APP'
#!/bin/sh
case "$1" in
  install-cli)
    bin_dir=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--bin-dir" ]; then
        bin_dir="$2"
        shift 2
        continue
      fi
      shift
    done
    mkdir -p "$bin_dir"
    cat >"$bin_dir/agent-secret" <<'BIN'
#!/bin/sh
if [ "${1:-}" = "doctor" ]; then
  exit 0
fi
exit 0
BIN
    chmod 755 "$bin_dir/agent-secret"
    ;;
  skill-install)
    skills_dir=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--skills-dir" ]; then
        skills_dir="$2"
        shift 2
        continue
      fi
      shift
    done
    mkdir -p "$skills_dir/agent-secret"
    ;;
esac
APP
  chmod 755 "$cli"
  exit 0
fi

if [ "$1" = "detach" ]; then
  exit 0
fi

exit 64
SCRIPT

  chmod 755 "$fake_bin/codesign" "$fake_bin/spctl" "$fake_bin/xcrun" \
    "$fake_bin/ditto" "$fake_bin/hdiutil"
}

make_fixture() {
  local run_dir="$1"
  local artifact="$run_dir/Agent-Secret-test-macos-arm64.dmg"
  local checksums="$run_dir/checksums.txt"

  mkdir -p "$run_dir"
  printf 'synthetic dmg\n' >"$artifact"
  shasum -a 256 "$artifact" | awk '{ print $1 "  Agent-Secret-test-macos-arm64.dmg" }' >"$checksums"
}

run_installer() {
  local name="$1"
  shift
  local run_dir="$tmp_dir/$name"
  local fake_bin="$run_dir/bin"
  local log="$run_dir/tools.log"
  local artifact="$run_dir/Agent-Secret-test-macos-arm64.dmg"
  local checksums="$run_dir/checksums.txt"

  make_fixture "$run_dir"
  write_fake_tools "$fake_bin"
  : >"$log"

  env \
    PATH="$fake_bin:$PATH" \
    AGENT_SECRET_DMG="$artifact" \
    AGENT_SECRET_CHECKSUMS_FILE="$checksums" \
    AGENT_SECRET_APP_DIR="$run_dir/apps" \
    AGENT_SECRET_BIN_DIR="$run_dir/bin-dir" \
    AGENT_SECRET_SKILLS_DIR="$run_dir/skills" \
    AGENT_SECRET_NO_STOP_DAEMON=1 \
    AGENT_SECRET_INSTALL_TEST_LOG="$log" \
    "$@" \
    "$project_root/install.sh"
}

assert_log_contains() {
  local log="$1"
  local pattern="$2"

  if ! grep -F "$pattern" "$log" >/dev/null; then
    echo "---- tool log ----" >&2
    cat "$log" >&2
    fail "missing log pattern: $pattern"
  fi
}

test_identity_checks_run() {
  run_installer signed
  log="$tmp_dir/signed/tools.log"

  assert_log_contains "$log" "codesign --verify --strict --verbose=2"
  assert_log_contains "$log" "spctl --assess --type open --context context:primary-signature --verbose"
  assert_log_contains "$log" "xcrun stapler validate"
  assert_log_contains "$log" "codesign --verify --deep --strict --verbose=2"
  assert_log_contains "$log" "spctl --assess --type execute --verbose"
}

test_identity_failure_stops_install() {
  if run_installer unsigned-fail AGENT_SECRET_INSTALL_TEST_CODESIGN_STATUS=23; then
    fail "installer succeeded when codesign failed"
  fi
  assert_log_contains "$tmp_dir/unsigned-fail/tools.log" "codesign --verify --strict --verbose=2"
}

test_unsigned_override_skips_identity_checks() {
  run_installer unsigned-allowed \
    AGENT_SECRET_ALLOW_UNSIGNED_INSTALL=1 \
    AGENT_SECRET_INSTALL_TEST_CODESIGN_STATUS=23 \
    AGENT_SECRET_INSTALL_TEST_SPCTL_STATUS=23 \
    AGENT_SECRET_INSTALL_TEST_XCRUN_STATUS=23

  log="$tmp_dir/unsigned-allowed/tools.log"
  if [ -s "$log" ]; then
    echo "---- tool log ----" >&2
    cat "$log" >&2
    fail "unsigned override should not call identity verification tools"
  fi
}

test_identity_checks_run
test_identity_failure_stops_install
test_unsigned_override_skips_identity_checks

echo "test-install: ok"
