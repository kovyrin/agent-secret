#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
# shellcheck source=scripts/lib/bundle-metadata.sh
# shellcheck disable=SC1091
source "$project_root/scripts/lib/bundle-metadata.sh"

fail() {
  printf 'promote-update-feed: %s\n' "$*" >&2
  exit 1
}

tag="${1:-}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "expected a vX.Y.Z release tag"
version="${tag#v}"
build="$(agent_secret_release_bundle_version "$version")"
repository="${GITHUB_REPOSITORY:-kovyrin/agent-secret}"
origin="https://github.com/$repository/releases/download/$tag"
archive="Agent-Secret-$tag-macos-arm64.dmg"
feed_url="${AGENT_SECRET_UPDATE_FEED_URL:?missing feed URL}"
bucket="${AGENT_SECRET_UPDATE_R2_BUCKET:?missing stable feed bucket}"
endpoint="${AGENT_SECRET_UPDATE_R2_ENDPOINT:?missing R2 endpoint}"
[[ "$feed_url" == https://updates.agent-secret.sh/appcast.xml ]] || fail "unexpected stable feed URL"
[[ "$endpoint" =~ ^https://[a-f0-9]{32}\.r2\.cloudflarestorage\.com$ ]] || fail "unexpected R2 endpoint"

stage="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-promote.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT

aws_s3() {
  AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
    aws --no-cli-pager --region auto --endpoint-url "$endpoint" s3api "$@"
}

reject_older_than() {
  local existing="$1" source="$2" latest
  [[ "$existing" == "$version" ]] && return
  agent_secret_release_bundle_version "$existing" >/dev/null
  latest="$(printf '%s\n%s\n' "$existing" "$version" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)"
  [[ "$latest" == "$version" ]] || fail "$tag is older than $source ($existing)"
}

cd "$project_root"
[[ -z "$(git status --porcelain)" ]] || fail "promotion requires a clean runner checkout"
git fetch --no-tags origin refs/heads/main:refs/remotes/origin/main
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] || fail "retry on the latest main"
release="$(gh release view "$tag" --repo "$repository" --json tagName,isDraft,isPrerelease,assets)"
jq -e --arg tag "$tag" --arg archive "$archive" '
  .tagName == $tag and (.isDraft or .isPrerelease | not) and
  (.assets | map(.name) | contains([$archive, "checksums.txt", "appcast.xml"]))
' <<<"$release" >/dev/null || fail "release is not stable and public or is missing assets"

cask="Casks/agent-secret.rb"
cask_version="$(awk -F'"' '/^  version "/ {print $2}' "$cask")"
reject_older_than "$cask_version" "the Homebrew cask"

feed_condition=(--if-none-match '*')
if aws_s3 get-object --bucket "$bucket" --key appcast.xml "$stage/stable.xml" >"$stage/object.json" 2>"$stage/object.err"; then
  etag="$(jq -er '.ETag | select(length > 0)' "$stage/object.json")"
  stable_version="$(go run ./scripts/release "$stage/stable.xml")"
  reject_older_than "$stable_version" "the stable feed"
  feed_condition=(--if-match "$etag")
elif ! grep -Eq '\((NoSuchKey|404)\)' "$stage/object.err"; then
  fail "could not read stable feed state"
fi

for asset in "$archive" checksums.txt appcast.xml; do
  curl --proto '=https' --proto-redir '=https' --fail --silent --show-error --location \
    --retry 3 --output "$stage/$asset" "$origin/$asset"
done
actual_digest="$(/usr/bin/shasum -a 256 "$stage/$archive" | awk '{print $1}')"
expected_digest="$(awk -v file="$archive" '$2 == file {print $1}' "$stage/checksums.txt")"
[[ "$actual_digest" == "$expected_digest" ]] || fail "published DMG checksum mismatch"
asset_digest="$(jq -er --arg archive "$archive" '.assets[] | select(.name == $archive) | .digest' <<<"$release")"
[[ "$asset_digest" == "sha256:$actual_digest" ]] || fail "GitHub DMG asset digest mismatch"
candidate="$(go run ./scripts/release "$stage/appcast.xml" "$stage/$archive" "$origin/$archive")"
[[ "$candidate" == "$version" ]] || fail "published appcast version mismatch"
if [[ "${stable_version:-}" == "$version" ]] && ! cmp -s "$stage/appcast.xml" "$stage/stable.xml"; then
  fail "refusing to change an already published feed version"
fi

"$script_dir/verify-published-update-bundle.sh" "$stage/$archive" "$version" "$build" "$feed_url"

if [[ "$cask_version" == "$version" ]]; then
  "$script_dir/check-homebrew-cask.sh" "$tag" "$cask" "$stage/checksums.txt"
else
  sed -E \
    -e "s/^  version \"[^\"]+\"$/  version \"$version\"/" \
    -e "s/^  sha256 \"[a-f0-9]+\"$/  sha256 \"$actual_digest\"/" \
    "$cask" >"$stage/agent-secret.rb"
  "$script_dir/check-homebrew-cask.sh" "$tag" "$stage/agent-secret.rb" "$stage/checksums.txt"
  ruby -c "$stage/agent-secret.rb"
  cp "$stage/agent-secret.rb" "$cask"
  git add -- "$cask"
  git -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    commit -m "Bump Agent Secret Homebrew cask to $tag" -- "$cask"
  git push origin HEAD:refs/heads/main
fi

if [[ "${stable_version:-}" != "$version" ]]; then
  aws_s3 put-object --bucket "$bucket" --key appcast.xml --body "$stage/appcast.xml" \
    --content-type application/rss+xml --cache-control no-store "${feed_condition[@]}" >/dev/null
fi
curl --proto '=https' --fail --silent --show-error --retry 3 --output "$stage/public.xml" "$feed_url"
cmp -s "$stage/appcast.xml" "$stage/public.xml" || fail "public feed does not match the signed candidate"
go run ./scripts/release "$stage/public.xml" "$stage/$archive" "$origin/$archive"
