#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"

fail() {
  echo "test-public-docs: $*" >&2
  exit 1
}

docs_files=()
while IFS= read -r -d '' file; do
  docs_files+=("$file")
done < <(find "$project_root/docs" -type f -name '*.md' -print0)

scan_files=(
  "$project_root/README.md"
  "$project_root/.agents/skills/agent-secret/SKILL.md"
  "${docs_files[@]}"
)

private_terms=(
  "account: Fixture"
  "Fixture Preview"
  "fixture.1password.com"
)

for term in "${private_terms[@]}"; do
  matches="$(grep -n -F -- "$term" "${scan_files[@]}" || true)"
  if [ -n "$matches" ]; then
    fail "public docs contain private consumer name '$term': $matches"
  fi
done

echo "test-public-docs: ok"
