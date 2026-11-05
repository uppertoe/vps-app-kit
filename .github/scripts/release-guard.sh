#!/usr/bin/env bash
# The release guard. A release of the kit is a vX.Y.Z tag, and every app's CI
# runs kitlint and kitgate at the version app-ci.yml names in KIT_TOOLS. This
# script refuses a release whose tag is not the version the workflow runs, so
# the checks apps run can never lag the released kit by mistake. MIN_KIT, the
# oldest kit an app may require, may stay behind the tag but never ahead of it.
#
#   .github/scripts/release-guard.sh v0.8.0            # before pushing the tag
#   .github/scripts/release-guard.sh v0.8.0 path/to/app-ci.yml
#
# It exits 0 when the release may go ahead and 1 with the reason when it may
# not. The release-guard workflow runs it on every tag push.
set -euo pipefail

tag="${1:-}"
workflow="${2:-$(dirname "$0")/../workflows/app-ci.yml}"

if [ -z "$tag" ]; then
  echo "usage: $0 vX.Y.Z [app-ci.yml]" >&2
  exit 2
fi

release='^v[0-9]+\.[0-9]+\.[0-9]+$'
if ! [[ "$tag" =~ $release ]]; then
  echo "release guard: the tag $tag is not a release tag of the form vX.Y.Z" >&2
  exit 1
fi

# Reads one value from the workflow's env block, as the kit's own test does.
value() {
  local v
  v="$(grep -E "^[[:space:]]+$1:[[:space:]]*[^[:space:]]+[[:space:]]*$" "$workflow" | head -n 1 | sed -E 's/^[[:space:]]+[A-Z_]+:[[:space:]]*([^[:space:]]+)[[:space:]]*$/\1/')"
  if [ -z "$v" ]; then
    echo "release guard: $workflow does not set $1" >&2
    exit 1
  fi
  printf '%s\n' "$v"
}

kit_tools="$(value KIT_TOOLS)"
min_kit="$(value MIN_KIT)"
failed=0

if [ "$kit_tools" != "$tag" ]; then
  echo "release guard: the tag is $tag but app-ci.yml runs kitlint and kitgate at KIT_TOOLS $kit_tools; set KIT_TOOLS to $tag and commit before tagging" >&2
  failed=1
fi

if ! [[ "$min_kit" =~ $release ]]; then
  echo "release guard: MIN_KIT is $min_kit; it must be a release tag of the form vX.Y.Z" >&2
  failed=1
elif [ "$(printf '%s\n%s\n' "$min_kit" "$tag" | sort -V | tail -n 1)" != "$tag" ]; then
  echo "release guard: MIN_KIT $min_kit is newer than the release $tag; the oldest kit an app may require cannot be a kit that does not exist yet" >&2
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "release guard: $tag runs kitlint and kitgate at $kit_tools and accepts apps on $min_kit or later"
