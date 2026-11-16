#!/usr/bin/env bash

# shellcheck disable=SC2034
AGENT_SECRET_APP_NAME="Agent Secret"
AGENT_SECRET_APP_DISPLAY_NAME="Agent Secret"
AGENT_SECRET_APP_EXECUTABLE="Agent Secret"
AGENT_SECRET_APP_BUNDLE_ID="com.kovyrin.agent-secret"
AGENT_SECRET_DAEMON_BUNDLE_ID="com.kovyrin.agent-secret.daemon"
AGENT_SECRET_APP_CATEGORY="public.app-category.developer-tools"
AGENT_SECRET_ICON_FILE="AppIcon"
AGENT_SECRET_MIN_MACOS_VERSION="14.0"
AGENT_SECRET_INFO_DICTIONARY_VERSION="6.0"
AGENT_SECRET_UPDATER_BUNDLE_ID="com.kovyrin.agent-secret.updater"

agent_secret_normalize_short_version() {
  local release_version="$1"

  printf '%s\n' "${release_version#v}"
}

agent_secret_release_bundle_version() {
  local version="$1"
  if [[ ! "$version" =~ ^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)$ ]] ||
    [[ "${BASH_REMATCH[1]}" == 9999 ]]; then
    echo "release version cannot be represented in CFBundleVersion: $version" >&2
    return 1
  fi
  printf '%d.%s.%s\n' "$((BASH_REMATCH[1] + 1))" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
}

agent_secret_previous_release_bundle_version() {
  local bundle_version major minor patch
  bundle_version="$(agent_secret_release_bundle_version "$1")" || return 1
  IFS=. read -r major minor patch <<<"$bundle_version"
  if ((patch > 0)); then
    patch=$((patch - 1))
  elif ((minor > 0)); then
    minor=$((minor - 1))
    patch=99
  elif ((major > 1)); then
    major=$((major - 1))
    minor=99
    patch=99
  else
    echo "release has no earlier supported bundle version: $1" >&2
    return 1
  fi
  printf '%d.%d.%d\n' "$major" "$minor" "$patch"
}

agent_secret_latest_changelog_version() {
  local changelog="$1"

  awk '
    /^## \[[0-9]+\.[0-9]+\.[0-9]+\] - / {
      version = $0
      sub(/^## \[/, "", version)
      sub(/\] - .*/, "", version)
      print version
      exit
    }
  ' "$changelog"
}

agent_secret_default_dev_version() {
  local changelog="$1"
  local latest_version=""

  latest_version="$(agent_secret_latest_changelog_version "$changelog")"
  if [[ "$latest_version" == "" ]]; then
    echo "missing top changelog version in $changelog" >&2
    return 1
  fi
  printf '%s-dev\n' "$latest_version"
}

agent_secret_version_base() {
  local version=""

  version="$(agent_secret_normalize_short_version "$1")"
  printf '%s\n' "${version%-dev}"
}

agent_secret_assert_latest_changelog_version() {
  local version="$1"
  local changelog="$2"
  local latest_version=""
  local version_base=""

  latest_version="$(agent_secret_latest_changelog_version "$changelog")"
  if [[ "$latest_version" == "" ]]; then
    echo "missing top changelog version in $changelog" >&2
    return 1
  fi

  version_base="$(agent_secret_version_base "$version")"
  if [[ "$version_base" != "$latest_version" ]]; then
    echo "version $version must match latest changelog section $latest_version" >&2
    return 1
  fi
}

agent_secret_git_revision() {
  local project_root="$1"
  local revision=""

  revision="$(git -C "$project_root" rev-parse --short=12 HEAD)"
  if ! git -C "$project_root" diff --quiet --ignore-submodules -- ||
    ! git -C "$project_root" diff --cached --quiet --ignore-submodules --; then
    revision="$revision-dirty"
  fi
  printf '%s\n' "$revision"
}
