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

team_id_for_path() {
  case "$1" in
    *.dmg)
      printf '%s\n' "${AGENT_SECRET_INSTALL_TEST_DMG_TEAM_ID:-${AGENT_SECRET_INSTALL_TEST_CODESIGN_TEAM_ID:-B6L7QLWTZW}}"
      ;;
    *AgentSecretDaemon.app)
      printf '%s\n' "${AGENT_SECRET_INSTALL_TEST_DAEMON_TEAM_ID:-${AGENT_SECRET_INSTALL_TEST_CODESIGN_TEAM_ID:-B6L7QLWTZW}}"
      ;;
    */Contents/Resources/bin/agent-secret)
      printf '%s\n' "${AGENT_SECRET_INSTALL_TEST_CLI_TEAM_ID:-${AGENT_SECRET_INSTALL_TEST_CODESIGN_TEAM_ID:-B6L7QLWTZW}}"
      ;;
    *)
      printf '%s\n' "${AGENT_SECRET_INSTALL_TEST_APP_TEAM_ID:-${AGENT_SECRET_INSTALL_TEST_CODESIGN_TEAM_ID:-B6L7QLWTZW}}"
      ;;
  esac
}

for arg in "$@"; do
  if [ "$arg" = "-dv" ]; then
    last=""
    for value in "$@"; do
      last="$value"
    done
    printf 'TeamIdentifier=%s\n' "$(team_id_for_path "$last")" >&2
    break
  fi
done

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

  cat >"$fake_bin/agent-secret" <<'SCRIPT'
#!/bin/sh
printf 'fake-path-agent-secret' >>"$AGENT_SECRET_INSTALL_TEST_LOG"
for arg in "$@"; do
  printf ' %s' "$arg" >>"$AGENT_SECRET_INSTALL_TEST_LOG"
done
printf '\n' >>"$AGENT_SECRET_INSTALL_TEST_LOG"
exit 0
SCRIPT

  cat >"$fake_bin/ditto" <<'SCRIPT'
#!/bin/sh
printf 'ditto %s %s\n' "$1" "$2" >>"$AGENT_SECRET_INSTALL_TEST_LOG"
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
  daemon_app="$mount_dir/Agent Secret.app/Contents/Library/Helpers/AgentSecretDaemon.app"
  mkdir -p "$(dirname "$cli")"
  mkdir -p "$daemon_app/Contents/MacOS"
  cat >"$mount_dir/Agent Secret.app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>${AGENT_SECRET_INSTALL_TEST_APP_BUNDLE_ID:-com.kovyrin.agent-secret}</string>
</dict>
</plist>
PLIST
  cat >"$daemon_app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>${AGENT_SECRET_INSTALL_TEST_DAEMON_BUNDLE_ID:-com.kovyrin.agent-secret.daemon}</string>
</dict>
</plist>
PLIST
  touch "$daemon_app/Contents/MacOS/Agent Secret"
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
    "$fake_bin/agent-secret" \
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
  mkdir -p "$run_dir/bin-dir"
  cat >"$run_dir/bin-dir/agent-secret" <<'SCRIPT'
#!/bin/sh
printf 'fake-bin-dir-agent-secret' >>"$AGENT_SECRET_INSTALL_TEST_LOG"
for arg in "$@"; do
  printf ' %s' "$arg" >>"$AGENT_SECRET_INSTALL_TEST_LOG"
done
printf '\n' >>"$AGENT_SECRET_INSTALL_TEST_LOG"
exit 0
SCRIPT
  chmod 755 "$run_dir/bin-dir/agent-secret"
  : >"$log"

  env \
    PATH="$fake_bin:$PATH" \
    AGENT_SECRET_DMG="$artifact" \
    AGENT_SECRET_CHECKSUMS_FILE="$checksums" \
    AGENT_SECRET_APP_DIR="$run_dir/apps" \
    AGENT_SECRET_BIN_DIR="$run_dir/bin-dir" \
    AGENT_SECRET_SKILLS_DIR="$run_dir/skills" \
    AGENT_SECRET_ALLOW_CUSTOM_INSTALL_PATHS=1 \
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
  assert_log_contains "$log" "codesign -dv --verbose=4"
  assert_log_contains "$log" "spctl --assess --type open --context context:primary-signature --verbose"
  assert_log_contains "$log" "xcrun stapler validate"
  assert_log_contains "$log" "codesign --verify --deep --strict --verbose=2"
  assert_log_contains "$log" "codesign -dv --verbose=4"
  assert_log_contains "$log" "spctl --assess --type execute --verbose"
}

test_identity_failure_stops_install() {
  if run_installer unsigned-fail AGENT_SECRET_INSTALL_TEST_CODESIGN_STATUS=23; then
    fail "installer succeeded when codesign failed"
  fi
  assert_log_contains "$tmp_dir/unsigned-fail/tools.log" "codesign --verify --strict --verbose=2"
}

test_wrong_team_id_stops_install() {
  if run_installer wrong-team AGENT_SECRET_INSTALL_TEST_CODESIGN_TEAM_ID=BADTEAM123; then
    fail "installer succeeded with the wrong Developer ID Team ID"
  fi
  assert_log_contains "$tmp_dir/wrong-team/tools.log" "codesign -dv --verbose=4"
}

test_wrong_app_bundle_id_stops_install() {
  if run_installer wrong-app-bundle \
    AGENT_SECRET_INSTALL_TEST_APP_BUNDLE_ID=com.example.not-agent-secret; then
    fail "installer succeeded with the wrong app bundle identifier"
  fi
  if grep -F "ditto " "$tmp_dir/wrong-app-bundle/tools.log" >/dev/null; then
    fail "installer copied an app with the wrong bundle identifier"
  fi
}

test_wrong_daemon_bundle_id_stops_install() {
  if run_installer wrong-daemon-bundle \
    AGENT_SECRET_INSTALL_TEST_DAEMON_BUNDLE_ID=com.example.not-agent-secret.daemon; then
    fail "installer succeeded with the wrong daemon bundle identifier"
  fi
  if grep -F "ditto " "$tmp_dir/wrong-daemon-bundle/tools.log" >/dev/null; then
    fail "installer copied an app with the wrong daemon bundle identifier"
  fi
}

test_trust_root_overrides_require_dev_mode() {
  if run_installer expected-team-override AGENT_SECRET_EXPECTED_TEAM_ID=BADTEAM123; then
    fail "installer accepted expected Team ID override without dev mode"
  fi
  if run_installer expected-app-bundle-override \
    AGENT_SECRET_EXPECTED_APP_BUNDLE_ID=com.example.not-agent-secret; then
    fail "installer accepted expected app bundle override without dev mode"
  fi
  if run_installer github-url-override AGENT_SECRET_GITHUB_URL=https://example.invalid; then
    fail "installer accepted GitHub URL override without dev mode"
  fi
  if run_installer unsigned-without-dev-mode AGENT_SECRET_ALLOW_UNSIGNED_INSTALL=1; then
    fail "installer accepted unsigned override without dev mode"
  fi
}

test_destination_overrides_require_guard() {
  if run_installer destination-guard AGENT_SECRET_ALLOW_CUSTOM_INSTALL_PATHS=0; then
    fail "installer accepted custom destination overrides without guard"
  fi
  if grep -F "ditto " "$tmp_dir/destination-guard/tools.log" >/dev/null; then
    fail "installer copied an app before rejecting unguarded custom destinations"
  fi
}

test_destination_validation_rejects_bad_paths() {
  local target="$tmp_dir/symlink-target"
  local link="$tmp_dir/symlink-app-dir"

  mkdir -p "$target"
  ln -s "$target" "$link"

  if run_installer relative-app-dir AGENT_SECRET_APP_DIR=relative-apps; then
    fail "installer accepted a relative app destination"
  fi
  if run_installer symlink-app-dir AGENT_SECRET_APP_DIR="$link"; then
    fail "installer accepted a symlinked app destination"
  fi
}

test_destination_validation_rejects_symlinked_parent_dirs() {
  local run_dir="$tmp_dir/symlinked-parents"
  local target="$run_dir/target"
  local link="$run_dir/link-parent"

  mkdir -p "$target"
  printf 'keep\n' >"$target/keep.txt"
  ln -s "$target" "$link"

  if run_installer symlinked-app-parent AGENT_SECRET_APP_DIR="$link/apps"; then
    fail "installer accepted a symlinked app parent"
  fi
  if run_installer symlinked-bin-parent AGENT_SECRET_BIN_DIR="$link/bin"; then
    fail "installer accepted a symlinked bin parent"
  fi
  if run_installer symlinked-skills-parent AGENT_SECRET_SKILLS_DIR="$link/skills"; then
    fail "installer accepted a symlinked skills parent"
  fi
  if [ -e "$target/apps" ] || [ -e "$target/bin" ] || [ -e "$target/skills" ]; then
    fail "installer followed a symlinked parent directory"
  fi
}

test_dev_mode_unsigned_override_skips_identity_checks_for_local_artifacts() {
  run_installer unsigned-allowed \
    AGENT_SECRET_INSTALL_DEV_MODE=1 \
    AGENT_SECRET_ALLOW_UNSIGNED_INSTALL=1 \
    AGENT_SECRET_INSTALL_TEST_CODESIGN_STATUS=23 \
    AGENT_SECRET_INSTALL_TEST_SPCTL_STATUS=23 \
    AGENT_SECRET_INSTALL_TEST_XCRUN_STATUS=23

  log="$tmp_dir/unsigned-allowed/tools.log"
  if grep -E '^(codesign|spctl|xcrun) ' "$log" >/dev/null; then
    echo "---- tool log ----" >&2
    cat "$log" >&2
    fail "unsigned override should not call identity verification tools"
  fi
}

test_untrusted_existing_cli_is_not_used_for_daemon_stop() {
  run_installer untrusted-existing-cli AGENT_SECRET_NO_STOP_DAEMON=0
  log="$tmp_dir/untrusted-existing-cli/tools.log"

  if grep -E '^fake-(bin-dir|path)-agent-secret daemon stop$' "$log" >/dev/null; then
    echo "---- tool log ----" >&2
    cat "$log" >&2
    fail "installer executed an untrusted existing agent-secret during daemon stop"
  fi
}

test_identity_checks_run
test_identity_failure_stops_install
test_wrong_team_id_stops_install
test_wrong_app_bundle_id_stops_install
test_wrong_daemon_bundle_id_stops_install
test_trust_root_overrides_require_dev_mode
test_destination_overrides_require_guard
test_destination_validation_rejects_bad_paths
test_destination_validation_rejects_symlinked_parent_dirs
test_dev_mode_unsigned_override_skips_identity_checks_for_local_artifacts
test_untrusted_existing_cli_is_not_used_for_daemon_stop

echo "test-install: ok"
