#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
readme="$project_root/README.md"
release_process="$project_root/docs/release-process.md"
macos_distribution_plan="$project_root/docs/macos-distribution-plan.md"
session_e2e="$project_root/docs/session-e2e-validation.md"
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

reject_macos_distribution_text() {
  local needle="$1"

  if grep -F -- "$needle" "$macos_distribution_plan" >/dev/null; then
    fail "docs/macos-distribution-plan.md still contains stale release documentation: $needle"
  fi
}

require_release_process_text() {
  local needle="$1"

  if ! grep -F -- "$needle" "$release_process" >/dev/null; then
    fail "docs/release-process.md is missing expected release documentation: $needle"
  fi
}

require_session_e2e_text() {
  local needle="$1"

  if ! grep -F -- "$needle" "$session_e2e" >/dev/null; then
    fail "docs/session-e2e-validation.md is missing expected release coverage: $needle"
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

require_text "## Install"
require_text "agent-secret doctor"
require_text "## Quick Start"
require_text "agent-secret item describe"
require_text "docs/images/approval-request.png"
reject_text "Local and CI builds are ad-hoc signed by default"
reject_text "Developer ID signing and notarization are opt-in release settings"
reject_text "Developer ID Application: Example, Inc. (TEAMID)"
reject_text "AGENT_SECRET_CODESIGN_ENTITLEMENTS"
reject_text "raw.githubusercontent.com/kovyrin/agent-secret/main/install.sh"
reject_text "raw.githubusercontent.com/kovyrin/agent-secret/main/uninstall.sh"
reject_text "AGENT_SECRET_VERSION=\"\$version\" sh"
reject_macos_distribution_text "Developer ID Application: Example, Inc. (TEAMID)"
reject_macos_distribution_text "AGENT_SECRET_CODESIGN_ENTITLEMENTS"
reject_macos_distribution_text "raw.githubusercontent.com/kovyrin/agent-secret/main/install.sh"
reject_macos_distribution_text "raw.githubusercontent.com/kovyrin/agent-secret/main/uninstall.sh"
require_text "https://github.com/kovyrin/agent-secret/releases/latest/download/install.sh | sh"
require_text "https://github.com/kovyrin/agent-secret/releases/latest/download/uninstall.sh | sh"

require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/test-install.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/test-uninstall.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/build/test-build-entitlements.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/release/test-release-signing-env.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/release/test-release-ancestry.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/release/test-release-notes.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/release/test-release-publish.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/release/test-release-version.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/release/test-release-docs.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/release/smoke-stale-dev-cli-diagnostics.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/checks/test-public-docs.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/checks/test-workflow-actions-pinned.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/checks/test-cloudflare-curl-token-handling.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/release/test-homebrew-cask.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/release/test-homebrew-cask-audit.sh"
require_release_process_text "swift run agent-secret-app-smoke"
require_release_process_text "## Toolchain Pin Maintenance"
require_release_process_text "## Installer Bootstrap Documentation"
require_release_process_text "current \`origin/main\` commit"
require_release_process_text "refuses to replace assets on a published release"
require_release_process_text "scripts/release/extract-release-notes.sh"
require_release_process_text "AGENT_SECRET_IN_MISE=1 scripts/release/test-release-notes.sh"
require_release_process_text "scripts/release/check-release-signing-env.sh"
require_release_process_text "scripts/release/prepare-bootstrap-scripts.sh"
require_release_process_text ".agents/skills/agent-secret/SKILL.md"
require_release_process_text "Audit user-facing docs and the bundled coding-agent skill"
require_release_process_text "AGENT_SECRET_RELEASE_SMOKE_REQUIRE_INSTALLED_CLI=1"
require_release_process_text "docs/session-e2e-validation.md"
require_release_process_text "detached process-tree replay rejected before child spawn"
require_release_process_text "--require-production-signing"
require_release_process_text "Tag-triggered GitHub releases require production"
require_release_process_text "AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_ID"
require_release_process_text "AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_SECRET"
require_release_process_text "Developer ID Application: Oleksiy Kovyrin (B6L7QLWTZW)"
require_release_process_text "Do not pipe"
require_release_process_text "\`main/install.sh\`"
require_release_process_text "\`main/uninstall.sh\`"
require_release_process_text "does not require callers to pass"
require_release_process_text "AGENT_SECRET_VERSION"
require_release_process_text "AGENT_SECRET_MISE_VERSION"
require_release_process_text "scripts/checks/test-workflow-actions-pinned.sh"
require_release_process_text "scripts/release/check-homebrew-cask.sh"
require_release_process_text "brew upgrade --cask agent-secret"
require_release_process_text "release is not"

require_session_e2e_text "SESSION_E2E_PROFILE_TOKEN"
require_session_e2e_text "SESSION_E2E_CLI_TOKEN"
require_session_e2e_text "launchctl submit"
require_session_e2e_text "detached process-tree replay rejected before child spawn"
require_session_e2e_text "The same \`session_token\` is rejected before child spawn"

require_threat_model_text "## Review Finding Ledger"
require_threat_model_text "Current open findings live in GitHub issues named"
require_threat_model_text "Historical review"
reject_threat_model_text "## Current Finding Map"
reject_threat_model_text "The 2026-05-03 review produced these findings against this model:"
reject_threat_model_text "ASR-021 violates"

echo "test-release-docs: ok"
