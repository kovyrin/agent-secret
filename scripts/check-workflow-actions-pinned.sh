#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

workflow_files=("$@")
if [ ${#workflow_files[@]} -eq 0 ] && [ -d .github/workflows ]; then
  while IFS= read -r -d '' file; do
    workflow_files+=("$file")
  done < <(find .github/workflows -type f \( -name "*.yml" -o -name "*.yaml" \) -print0)
fi

status=0
for file in "${workflow_files[@]}"; do
  [ -f "$file" ] || continue

  line_no=0
  mise_action_line=0
  mise_has_version=0
  mise_has_sha256=0

  finish_mise_action() {
    if [ "$mise_action_line" -eq 0 ]; then
      return
    fi

    if [ "$mise_has_version" -eq 0 ] || [ "$mise_has_sha256" -eq 0 ]; then
      echo "$file:$mise_action_line: jdx/mise-action must pin mise version and sha256" >&2
      status=1
    fi

    mise_action_line=0
    mise_has_version=0
    mise_has_sha256=0
  }

  while IFS= read -r line || [ -n "$line" ]; do
    line_no=$((line_no + 1))

    if [ "$mise_action_line" -ne 0 ] && [[ "$line" =~ ^[[:space:]]*-[[:space:]] ]]; then
      finish_mise_action
    fi

    if [[ "$line" =~ ^[[:space:]-]*uses:[[:space:]]*([^[:space:]#]+) ]]; then
      action="${BASH_REMATCH[1]}"
      action="${action%\"}"
      action="${action#\"}"
      action="${action%\'}"
      action="${action#\'}"

      if [[ "$action" == ./* ]]; then
        continue
      fi

      if [[ "$action" != *@* ]]; then
        echo "$file:$line_no: action must be pinned to a full commit SHA: $action" >&2
        status=1
        continue
      fi

      ref="${action##*@}"
      if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        echo "$file:$line_no: action must be pinned to a full commit SHA: $action" >&2
        status=1
      fi

      if [[ "$action" == jdx/mise-action@* ]]; then
        mise_action_line="$line_no"
      fi
    fi

    if [ "$mise_action_line" -ne 0 ]; then
      if [[ "$line" =~ ^[[:space:]]*version:[[:space:]]*.+$ ]]; then
        mise_has_version=1
      fi
      if [[ "$line" =~ ^[[:space:]]*sha256:[[:space:]]*.+$ ]]; then
        mise_has_sha256=1
      fi
    fi
  done <"$file"
  finish_mise_action
done

if [ "$status" -ne 0 ]; then
  {
    echo
    echo "GitHub Actions workflows must pin third-party actions to immutable 40-character commit SHAs."
    echo "Use \`gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha\` to resolve a tag before updating the workflow."
    echo "jdx/mise-action must also pin the downloaded mise binary with explicit version and sha256 inputs."
  } >&2
fi

exit "$status"
