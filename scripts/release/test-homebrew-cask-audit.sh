#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
cask="$project_root/Casks/agent-secret.rb"
tap_name="${AGENT_SECRET_HOMEBREW_TEST_TAP:-agent-secret/security-smoke-test}"
tap_user="${tap_name%%/*}"
tap_repo="${tap_name#*/}"
tap_dir="$(brew --repository)/Library/Taps/$tap_user/homebrew-$tap_repo"

fail() {
  echo "test-homebrew-cask-audit: $*" >&2
  exit 1
}

command -v brew >/dev/null 2>&1 || fail "missing required tool: brew"
command -v cp >/dev/null 2>&1 || fail "missing required tool: cp"

if [[ ! -f "$cask" ]]; then
  fail "missing Homebrew cask: $cask"
fi

if ! grep -F 'cask "agent-secret" do' "$cask" >/dev/null; then
  fail "Homebrew cask does not define agent-secret"
fi

cleanup() {
  brew untap "$tap_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
HOMEBREW_NO_AUTO_UPDATE=1 brew tap "$tap_name" "$project_root" >/dev/null
cp "$cask" "$tap_dir/Casks/agent-secret.rb"
HOMEBREW_NO_AUTO_UPDATE=1 brew audit --cask --strict --online --tap="$tap_name" agent-secret

echo "test-homebrew-cask-audit: ok"
