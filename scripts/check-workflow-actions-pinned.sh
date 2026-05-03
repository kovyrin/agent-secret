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
  while IFS= read -r line || [ -n "$line" ]; do
    line_no=$((line_no + 1))

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
    fi
  done <"$file"
done

if [ "$status" -ne 0 ]; then
  {
    echo
    echo "GitHub Actions workflows must pin third-party actions to immutable 40-character commit SHAs."
    echo "Use \`gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha\` to resolve a tag before updating the workflow."
  } >&2
fi

exit "$status"
