#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-promotion-drill.XXXXXXXX")"
trap 'rm -rf "$scratch"' EXIT
fixture="$scratch/fixture"
mkdir -p "$fixture/scripts/release" "$fixture/scripts/lib" "$fixture/Casks" "$scratch/bin"
cp "$script_dir/"{promote-update-feed,check-homebrew-cask}.sh "$fixture/scripts/release/"
cp "$project_root/scripts/lib/bundle-metadata.sh" "$fixture/scripts/lib/"
cp "$project_root/scripts/release/verify_update_feed.go" "$fixture/scripts/release/"
cp "$project_root/go.mod" "$project_root/go.sum" "$fixture/"
sed -E 's/^  version "[^"]+"$/  version "0.0.34"/' "$project_root/Casks/agent-secret.rb" >"$scratch/cask-baseline.rb"
cp "$scratch/cask-baseline.rb" "$fixture/Casks/agent-secret.rb"

export DRILL_ROOT="$scratch"
export DRILL_EVENTS="$scratch/events"
export PATH="$scratch/bin:$PATH"
export AGENT_SECRET_UPDATE_FEED_URL=https://updates.agent-secret.sh/appcast.xml
export AGENT_SECRET_UPDATE_R2_BUCKET=synthetic-fixture
export AGENT_SECRET_UPDATE_R2_ENDPOINT=https://1234567890abcdef1234567890abcdef.r2.cloudflarestorage.com
export GITHUB_REPOSITORY=kovyrin/agent-secret

AGENT_SECRET_UPDATE_PUBLIC_KEY="$(
  node - <<'JS'
const {createHash, generateKeyPairSync, sign} = require("node:crypto")
const {mkdirSync, writeFileSync} = require("node:fs")
const {join} = require("node:path")
const {privateKey, publicKey} = generateKeyPairSync("ed25519")
const base = process.env.DRILL_ROOT
for (const patch of [34, 35, 36]) {
  const release = `0.0.${patch}`
  const tag = `v${release}`
  const archive = `Agent-Secret-${tag}-macos-arm64.dmg`
  const url = `https://github.com/kovyrin/agent-secret/releases/download/${tag}/${archive}`
  const dir = join(base, tag)
  const payload = Buffer.from(`synthetic payload for ${tag}`)
  const archiveSig = sign(null, payload, privateKey).toString("base64")
  const digest = createHash("sha256").update(payload).digest("hex")
  const body = `<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item><sparkle:version>1.0.${patch}</sparkle:version><sparkle:shortVersionString>${release}</sparkle:shortVersionString><description>Fixture notes</description><enclosure url="${url}" length="${payload.length}" sparkle:edSignature="${archiveSig}"/></item></channel></rss>\n`
  const feedSig = sign(null, Buffer.from(body), privateKey).toString("base64")
  mkdirSync(dir)
  writeFileSync(join(dir, archive), payload)
  writeFileSync(join(dir, "checksums.txt"), `${digest}  ${archive}\n`)
  writeFileSync(join(dir, "appcast.xml"), `${body}<!-- sparkle-signatures:\nedSignature: ${feedSig}\nlength: ${Buffer.byteLength(body)}\n-->\n`)
}
process.stdout.write(publicKey.export({type: "spki", format: "der"}).subarray(-32).toString("base64"))
JS
)"
export AGENT_SECRET_UPDATE_PUBLIC_KEY

cat >"$scratch/bin/git" <<'SH'
#!/bin/sh
case "$1" in
  status | fetch | add) ;;
  rev-parse) printf 'fixture-head\n' ;;
  -c) printf 'cask-commit\n' >>"$DRILL_EVENTS" ;;
  push) printf 'cask-push\n' >>"$DRILL_EVENTS" ;;
  *) exit 88 ;;
esac
SH
cat >"$scratch/bin/gh" <<'SH'
#!/bin/sh
tag="$3"
archive="Agent-Secret-${tag}-macos-arm64.dmg"
digest="$(awk '{print $1}' "$DRILL_ROOT/$tag/checksums.txt")"
printf '{"tagName":"%s","isDraft":false,"isPrerelease":false,"assets":[{"name":"%s","digest":"sha256:%s"},{"name":"checksums.txt"},{"name":"appcast.xml"}]}\n' \
  "$tag" "$archive" "$digest"
SH
cat >"$scratch/bin/curl" <<'SH'
#!/bin/sh
while [ "$1" != "--output" ]; do shift; done
output="$2"
url="$3"
case "$url" in
  https://updates.agent-secret.sh/appcast.xml)
    printf 'public-read\n' >>"$DRILL_EVENTS"
    cp "$DRILL_ROOT/stable.xml" "$output"
    ;;
  https://github.com/kovyrin/agent-secret/releases/download/*)
    cp "$DRILL_ROOT/${url#*/releases/download/}" "$output"
    ;;
  *) exit 88 ;;
esac
SH
cat >"$scratch/bin/aws" <<'SH'
#!/bin/sh
while [ "$1" != "s3api" ]; do shift; done
shift
action="$1"
shift
stable="$DRILL_ROOT/stable.xml"
etag() { shasum -a 256 "$stable" | awk '{print $1}'; }
case "$action" in
  get-object)
    if [ ! -e "$stable" ]; then
      echo '(NoSuchKey)' >&2
      exit 1
    fi
    cp "$stable" "$5"
    printf '{"ETag":"%s"}\n' "$(etag)"
    ;;
  put-object)
    printf 'feed-put\n' >>"$DRILL_EVENTS"
    [ "${DRILL_FAIL_PUT:-0}" = 0 ] || exit 1
    if [ "${DRILL_ADVANCE_FEED:-0}" = 1 ]; then cp "$DRILL_ROOT/v0.0.36/appcast.xml" "$stable"; fi
    [ "$5" = "--body" ] || exit 88
    body="$6"
    shift 6
    while [ "$1" != "--if-match" ] && [ "$1" != "--if-none-match" ]; do shift; done
    if [ "$1" = "--if-match" ]; then
      [ "$2" = "$(etag)" ] || exit 1
    else
      [ "$2" = '*' ] && [ ! -e "$stable" ] || exit 1
    fi
    cp "$body" "$stable"
    ;;
  *) exit 88 ;;
esac
SH
cat >"$fixture/scripts/release/verify-published-update-bundle.sh" <<'SH'
#!/bin/sh
printf 'macos-verifier-stub\n' >>"$DRILL_EVENTS"
SH
chmod +x "$scratch/bin/"* "$fixture/scripts/release/verify-published-update-bundle.sh"

promote() { "$fixture/scripts/release/promote-update-feed.sh" "$1" >"$scratch/output" 2>&1; }
reject() {
  if promote "$1"; then
    printf 'promotion unexpectedly accepted %s\n' "$1" >&2
    exit 1
  fi
}
assert_cask_version() {
  if ! grep -Fq "  version \"$1\"" "$fixture/Casks/agent-secret.rb"; then
    printf 'expected cask version %s\n' "$1" >&2
    cat "$scratch/output" >&2
    exit 1
  fi
}

cp "$scratch/v0.0.34/appcast.xml" "$scratch/stable.xml"
DRILL_FAIL_PUT=1 reject v0.0.35
assert_cask_version 0.0.35
cmp "$scratch/v0.0.34/appcast.xml" "$scratch/stable.xml"
printf 'macos-verifier-stub\ncask-commit\ncask-push\nfeed-put\n' | cmp - "$DRILL_EVENTS"

: >"$DRILL_EVENTS"
promote v0.0.35 || {
  cat "$scratch/output" >&2
  exit 1
}
cmp "$scratch/v0.0.35/appcast.xml" "$scratch/stable.xml"
printf 'macos-verifier-stub\nfeed-put\npublic-read\n' | cmp - "$DRILL_EVENTS"

cp "$scratch/cask-baseline.rb" "$fixture/Casks/agent-secret.rb"
cp "$scratch/v0.0.34/appcast.xml" "$scratch/stable.xml"
DRILL_ADVANCE_FEED=1 reject v0.0.35
assert_cask_version 0.0.35
cmp "$scratch/v0.0.36/appcast.xml" "$scratch/stable.xml"
: >"$DRILL_EVENTS"
reject v0.0.35
grep -Fq 'older than the stable feed' "$scratch/output"
test ! -s "$DRILL_EVENTS"
promote v0.0.36 || {
  cat "$scratch/output" >&2
  exit 1
}
assert_cask_version 0.0.36
cmp "$scratch/v0.0.36/appcast.xml" "$scratch/stable.xml"
mv "$scratch/stable.xml" "$scratch/retired-fixture.xml"
cp "$scratch/cask-baseline.rb" "$fixture/Casks/agent-secret.rb"
promote v0.0.35 || {
  cat "$scratch/output" >&2
  exit 1
}
assert_cask_version 0.0.35
cmp "$scratch/v0.0.35/appcast.xml" "$scratch/stable.xml"
echo 'test-update-feed-promotion: ok'
