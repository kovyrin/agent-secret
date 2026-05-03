#!/usr/bin/env bash
set -euo pipefail

remote="${AGENT_SECRET_RELEASE_ANCESTRY_REMOTE:-origin}"
main_branch="${AGENT_SECRET_RELEASE_ANCESTRY_MAIN_BRANCH:-main}"
release_ref="${1:-${GITHUB_REF_NAME:-}}"

fail() {
  echo "release ancestry: $*" >&2
  exit 1
}

if [[ -z "$release_ref" ]]; then
  fail "release tag is required"
fi

case "$release_ref" in
  refs/tags/v*)
    tag_name="${release_ref#refs/tags/}"
    ;;
  v*)
    tag_name="$release_ref"
    ;;
  *)
    fail "release ref must be a v* tag, got $release_ref"
    ;;
esac

tag_ref="refs/tags/$tag_name"
if ! release_commit="$(git rev-parse --verify -q "${tag_ref}^{commit}")"; then
  git fetch --no-tags "$remote" "+refs/tags/${tag_name}:refs/tags/${tag_name}" >/dev/null ||
    fail "could not fetch tag $tag_name from $remote"
  release_commit="$(git rev-parse --verify -q "${tag_ref}^{commit}")" ||
    fail "could not resolve tag $tag_name to a commit"
fi

main_ref="refs/remotes/${remote}/${main_branch}"
if [[ "$(git rev-parse --is-shallow-repository 2>/dev/null || printf 'false')" == "true" ]]; then
  git fetch --unshallow --no-tags "$remote" "+refs/heads/${main_branch}:${main_ref}" >/dev/null ||
    fail "could not fetch $remote/$main_branch"
else
  git fetch --no-tags "$remote" "+refs/heads/${main_branch}:${main_ref}" >/dev/null ||
    fail "could not fetch $remote/$main_branch"
fi

main_commit="$(git rev-parse --verify -q "${main_ref}^{commit}")" ||
  fail "could not resolve $remote/$main_branch"

if ! git merge-base --is-ancestor "$release_commit" "$main_commit"; then
  fail "tag $tag_name targets commit $release_commit, which is not reachable from $remote/$main_branch"
fi

echo "release ancestry: tag $tag_name targets commit $release_commit reachable from $remote/$main_branch"
