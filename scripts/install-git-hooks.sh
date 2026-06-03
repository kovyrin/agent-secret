#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

hooks_dir="$(git rev-parse --git-path hooks)"
mkdir -p "$hooks_dir"

for hook in .githooks/*; do
  [ -f "$hook" ] || continue
  [ -x "$hook" ] || continue
  cp "$hook" "$hooks_dir/$(basename "$hook")"
  chmod 755 "$hooks_dir/$(basename "$hook")"
done

git config --unset core.hooksPath >/dev/null 2>&1 || true
echo "Installed git hooks into $hooks_dir"
