#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
readme="$project_root/README.md"

fail() {
  echo "test-release-docs: $*" >&2
  exit 1
}

require_text() {
  local needle="$1"

  if ! grep -F -- "$needle" "$readme" >/dev/null; then
    fail "README.md is missing expected release documentation: $needle"
  fi
}

reject_text() {
  local needle="$1"

  if grep -F -- "$needle" "$readme" >/dev/null; then
    fail "README.md still contains stale release documentation: $needle"
  fi
}

require_text "AGENT_SECRET_IN_MISE=1 scripts/test-install.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-uninstall.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-release-signing-env.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-release-version.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-release-docs.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-workflow-actions-pinned.sh"
require_text "swift run agent-secret-approver-smoke"
require_text "scripts/check-release-signing-env.sh"
require_text "--require-production-signing"
require_text "Tag-triggered GitHub releases require production"
reject_text "Local and CI builds are ad-hoc signed by default"
reject_text "Developer ID signing and notarization are opt-in release settings"

echo "test-release-docs: ok"
