#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

site_dir="site"
site_url="${AGENT_SECRET_SITE_URL:-https://agent-secret.sh}"
www_url="${AGENT_SECRET_WWW_URL:-https://www.agent-secret.sh}"
cloudflare_project="${AGENT_SECRET_CLOUDFLARE_PAGES_PROJECT:-agent-secret}"
cloudflare_profile="${AGENT_SECRET_CLOUDFLARE_PROFILE:-cloudflare-pages}"
cloudflare_zone="${AGENT_SECRET_CLOUDFLARE_ZONE:-agent-secret.sh}"
demo_video_path="${AGENT_SECRET_DEMO_VIDEO_PATH:-assets/agent-secret-demo-20260603.mp4}"
demo_poster_path="${AGENT_SECRET_DEMO_POSTER_PATH:-assets/agent-secret-demo-poster-20260603.jpg}"
max_asset_bytes="${AGENT_SECRET_CLOUDFLARE_MAX_ASSET_BYTES:-26214400}"
poll_timeout_seconds="${AGENT_SECRET_DEPLOY_POLL_TIMEOUT_SECONDS:-300}"
poll_interval_seconds="${AGENT_SECRET_DEPLOY_POLL_INTERVAL_SECONDS:-5}"
mode="deploy"

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy-site.sh [--check-only]

Default mode validates the site, requires a clean main worktree, pushes main,
polls Cloudflare Pages for the current commit through Agent Secret, and verifies
the live URLs.

--check-only validates locally without requiring a clean worktree, pushing, or
polling Cloudflare.
USAGE
}

log() {
  printf '[deploy-site] %s\n' "$*"
}

fail() {
  printf '[deploy-site] error: %s\n' "$*" >&2
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"
}

file_size_bytes() {
  local file="$1"
  if stat -f '%z' "$file" >/dev/null 2>&1; then
    stat -f '%z' "$file"
  else
    stat -c '%s' "$file"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check-only)
        mode="check-only"
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        fail "unknown argument: $1"
        ;;
    esac
    shift
  done
}

assert_main_branch() {
  local branch
  branch="$(git branch --show-current)"
  [[ "$branch" == "main" ]] || fail "site deploys must run from main, got $branch"
}

assert_clean_worktree() {
  git update-index -q --refresh
  if [[ -n "$(git status --porcelain)" ]]; then
    git status -sb >&2
    fail "worktree must be clean before deployment"
  fi
}

check_asset_sizes() {
  log "checking Cloudflare Pages asset size limit"

  local failed=0
  while IFS= read -r -d '' file; do
    local size
    size="$(file_size_bytes "$file")"
    if ((size > max_asset_bytes)); then
      printf '[deploy-site] asset too large: %s is %.1f MiB; limit is %.1f MiB\n' \
        "$file" \
        "$(awk -v bytes="$size" 'BEGIN { print bytes / 1024 / 1024 }')" \
        "$(awk -v bytes="$max_asset_bytes" 'BEGIN { print bytes / 1024 / 1024 }')" >&2
      failed=1
    fi
  done < <(find "$site_dir" -type f -print0)

  [[ "$failed" == "0" ]] || fail "one or more site assets exceed Cloudflare Pages limits"
}

check_site_links() {
  log "checking static site links"

  python3 - <<'PY'
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

site = Path("site")
errors = []


def resolve_site_path(rel: str) -> Path:
    rel = rel.split("#", 1)[0].split("?", 1)[0].lstrip("/")
    if not rel:
        return site / "index.html"
    candidate = site / rel
    if candidate.exists():
        return candidate
    if not Path(rel).suffix:
        html_candidate = site / f"{rel}.html"
        if html_candidate.exists():
            return html_candidate
    return candidate


class Parser(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.path = path

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        for key in ("href", "src", "poster", "content"):
            value = attrs_dict.get(key)
            if not value:
                continue
            if key == "content" and not (
                value.startswith("https://agent-secret.sh/") or value.startswith("/")
            ):
                continue
            if value.startswith(("http://", "https://")):
                parsed = urlparse(value)
                if parsed.netloc != "agent-secret.sh":
                    continue
                target = resolve_site_path(parsed.path)
            elif value.startswith(("#", "mailto:", "tel:", "data:")):
                continue
            else:
                rel = value.split("#", 1)[0].split("?", 1)[0]
                if not rel:
                    continue
                target = (self.path.parent / rel).resolve()
            if not target.exists():
                errors.append(f"{self.path}: missing {value} -> {target}")


for html in site.glob("*.html"):
    Parser(html).feed(html.read_text())

index = (site / "index.html").read_text()
for anchor in ("demo", "install", "boundary"):
    if f'id="{anchor}"' not in index:
        errors.append(f"index.html missing anchor #{anchor}")

for asset in (
    "assets/agent-secret-demo-20260603.mp4",
    "assets/agent-secret-demo-poster-20260603.jpg",
):
    if not (site / asset).exists():
        errors.append(f"missing demo asset {asset}")

if errors:
    print("\n".join(errors))
    raise SystemExit(1)

print("site-link-check: ok")
PY
}

run_local_checks() {
  require_tool git
  require_tool find
  require_tool awk
  require_tool python3
  require_tool mise

  check_asset_sizes
  check_site_links

  log "running markdownlint"
  mise exec -- npx --no-install markdownlint '**/*.md'

  log "running public docs checks"
  AGENT_SECRET_IN_MISE=1 scripts/checks/test-public-docs.sh
  AGENT_SECRET_IN_MISE=1 scripts/release/test-release-docs.sh
}

push_main() {
  log "pushing main to origin"
  git push origin main
}

poll_cloudflare_deployment() {
  local head_sha="$1"

  require_tool agent-secret
  require_tool jq
  require_tool curl

  log "polling Cloudflare Pages for $head_sha"

  agent-secret exec --profile "$cloudflare_profile" -- bash -s -- \
    "$head_sha" \
    "$cloudflare_project" \
    "$cloudflare_zone" \
    "$poll_timeout_seconds" \
    "$poll_interval_seconds" <<'BASH'
set -euo pipefail

head_sha="$1"
cloudflare_project="$2"
cloudflare_zone="$3"
poll_timeout_seconds="$4"
poll_interval_seconds="$5"
api="https://api.cloudflare.com/client/v4"

account_id="$(
  curl -fsS -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    "$api/accounts" \
    | jq -r '.result[0].id // empty'
)"

if [[ -z "$account_id" ]]; then
  printf '[deploy-site] error: Cloudflare API token did not return an account\n' >&2
  exit 1
fi

deadline=$((SECONDS + poll_timeout_seconds))
seen_deployment=""

while ((SECONDS < deadline)); do
  deployments="$(
    curl -fsS -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      "$api/accounts/$account_id/pages/projects/$cloudflare_project/deployments?per_page=20"
  )"

  row="$(
    printf '%s' "$deployments" \
      | jq -r --arg sha "$head_sha" '
          .result[]
          | select(.deployment_trigger.metadata.commit_hash == $sha)
          | [
              .id,
              .latest_stage.name,
              .latest_stage.status,
              .url
            ]
          | @tsv
        ' \
      | head -n 1
  )"

  if [[ -z "$row" ]]; then
    printf '[deploy-site] waiting for Cloudflare deployment to appear\n'
    sleep "$poll_interval_seconds"
    continue
  fi

  IFS=$'\t' read -r deployment_id stage_name stage_status deployment_url <<<"$row"
  if [[ "$deployment_id" != "$seen_deployment" ]]; then
    printf '[deploy-site] deployment_id=%s url=%s\n' "$deployment_id" "$deployment_url"
    seen_deployment="$deployment_id"
  fi

  printf '[deploy-site] stage=%s status=%s\n' "$stage_name" "$stage_status"

  case "$stage_status" in
    success)
      zone_id="$(
        curl -fsS -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
          "$api/zones?name=$cloudflare_zone" \
          | jq -r '.result[0].id // empty'
      )"

      if [[ -z "$zone_id" ]]; then
        printf '[deploy-site] error: Cloudflare API token could not read zone %s\n' "$cloudflare_zone" >&2
        exit 1
      fi

      printf '[deploy-site] attempting Cloudflare cache purge for %s\n' "$cloudflare_zone"
      if ! purge_result="$(
        curl -sS -X POST \
          -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
          -H "Content-Type: application/json" \
          --data '{"purge_everything":true}' \
          "$api/zones/$zone_id/purge_cache"
      )"; then
        printf '[deploy-site] warning: cache purge request failed; continuing with versioned asset URLs\n' >&2
      elif ! printf '%s' "$purge_result" | jq -e '.success == true' >/dev/null; then
        printf '[deploy-site] warning: cache purge was not accepted; continuing with versioned asset URLs\n' >&2
      else
        printf '[deploy-site] Cloudflare cache purge accepted\n'
      fi
      exit 0
      ;;
    failure)
      printf '[deploy-site] Cloudflare deployment failed; build logs follow\n' >&2
      curl -fsS -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        "$api/accounts/$account_id/pages/projects/$cloudflare_project/deployments/$deployment_id/history/logs" \
        | jq -r '.result.data[]?.line // empty' >&2
      exit 1
      ;;
    *)
      sleep "$poll_interval_seconds"
      ;;
  esac
done

printf '[deploy-site] error: timed out waiting for Cloudflare deployment\n' >&2
exit 1
BASH
}

content_type_for() {
  local url="$1"
  curl -fsSI --max-time 20 "$url" |
    tr -d '\r' |
    sed -n 's/^content-type: //Ip' |
    head -n 1
}

content_type_matches() {
  local path="$1"
  local expected_prefix="$2"
  local url="$site_url$path"
  local content_type

  content_type="$(content_type_for "$url")"
  [[ "$content_type" == "$expected_prefix"* ]]
}

verify_content_type() {
  local path="$1"
  local expected_prefix="$2"
  local url="$site_url$path"
  local content_type

  content_type="$(content_type_for "$url")"
  [[ "$content_type" == "$expected_prefix"* ]] ||
    return 1

  log "verified $path as $content_type"
}

verify_live_site_once() {
  curl -fsS --max-time 20 "$site_url/" | grep -Fq "$demo_video_path" ||
    return 1

  curl -fsS --max-time 20 "$site_url/privacy" >/dev/null || return 1
  curl -fsS --max-time 20 "$site_url/terms" >/dev/null || return 1
  curl -fsS --max-time 20 "$site_url/sitemap.xml" >/dev/null || return 1
  curl -fsS --max-time 20 "$site_url/robots.txt" >/dev/null || return 1

  content_type_matches "/$demo_video_path" "video/mp4" || return 1
  content_type_matches "/$demo_poster_path" "image/jpeg" || return 1

  local www_headers
  www_headers="$(curl -fsSI --max-time 20 "$www_url/" | tr -d '\r')" || return 1
  printf '%s\n' "$www_headers" | grep -Eq '^HTTP/[0-9.]+ 301' || return 1
  printf '%s\n' "$www_headers" | grep -Fqi "location: $site_url/" || return 1
}

verify_live_site() {
  require_tool curl
  require_tool grep
  require_tool sed

  log "verifying live site"

  local deadline
  deadline=$((SECONDS + poll_timeout_seconds))

  while ((SECONDS < deadline)); do
    if verify_live_site_once; then
      verify_content_type "/$demo_video_path" "video/mp4" ||
        fail "$site_url/$demo_video_path returned the wrong content type"
      verify_content_type "/$demo_poster_path" "image/jpeg" ||
        fail "$site_url/$demo_poster_path returned the wrong content type"
      log "live site verification passed"
      return 0
    fi

    log "waiting for production alias to serve the latest deployment"
    sleep "$poll_interval_seconds"
  done

  fail "live site did not serve the latest deployment within ${poll_timeout_seconds}s"
}

deploy() {
  assert_main_branch
  assert_clean_worktree
  run_local_checks

  local head_sha
  head_sha="$(git rev-parse HEAD)"

  push_main
  poll_cloudflare_deployment "$head_sha"
  verify_live_site

  log "deployment complete: $head_sha"
}

parse_args "$@"

case "$mode" in
  check-only)
    run_local_checks
    log "check-only complete"
    ;;
  deploy)
    deploy
    ;;
esac
