#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
readme="$project_root/README.md"
release_process="$project_root/docs/release-process.md"
threat_model="$project_root/docs/threat-model.md"

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

require_release_process_text() {
  local needle="$1"

  if ! grep -F -- "$needle" "$release_process" >/dev/null; then
    fail "docs/release-process.md is missing expected release documentation: $needle"
  fi
}

require_threat_model_text() {
  local needle="$1"

  if ! grep -F -- "$needle" "$threat_model" >/dev/null; then
    fail "docs/threat-model.md is missing expected review documentation: $needle"
  fi
}

reject_threat_model_text() {
  local needle="$1"

  if grep -F -- "$needle" "$threat_model" >/dev/null; then
    fail "docs/threat-model.md still contains stale review documentation: $needle"
  fi
}

require_text "AGENT_SECRET_IN_MISE=1 scripts/test-install.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-uninstall.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-release-signing-env.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-release-ancestry.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-release-publish.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-release-version.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-release-docs.sh"
require_text "AGENT_SECRET_IN_MISE=1 scripts/test-workflow-actions-pinned.sh"
require_text "swift run agent-secret-approver-smoke"
require_text "scripts/check-release-signing-env.sh"
require_text "--require-production-signing"
require_text "Tag-triggered GitHub releases require production"
reject_text "Local and CI builds are ad-hoc signed by default"
reject_text "Developer ID signing and notarization are opt-in release settings"

require_release_process_text "## Toolchain Pin Maintenance"
require_release_process_text "reachable from \`origin/main\`"
require_release_process_text "refuses to replace assets on a published release"
require_release_process_text "AGENT_SECRET_MISE_VERSION"
require_release_process_text "scripts/test-workflow-actions-pinned.sh"

require_threat_model_text "## Review Finding Ledger"
require_threat_model_text "Current open findings live in GitHub issues named"
require_threat_model_text "Historical review"
reject_threat_model_text "## Current Finding Map"
reject_threat_model_text "The 2026-05-03 review produced these findings against this model:"
reject_threat_model_text "ASR-021 violates"

echo "test-release-docs: ok"
