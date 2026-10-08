#!/usr/bin/env bash
# Publishes the version in package.json once the "chore: version packages" pull
# request has merged: the vX.Y.Z tag, the GitHub release, and a module proxy
# fetch. Each step is skipped if it already happened, so a failed run can be
# re-run as is.
set -euo pipefail
cd "$(dirname "$0")/.."

version="$(node -p "require('./package.json').version")"
tag="v$version"
module="$(sed -n 's/^module //p' go.mod)"

# From v2 on, Go only resolves the tag if the module path ends in /vN.
major="${version%%.*}"
if [ "$major" -ge 2 ] && [[ "$module" != */v"$major" ]]; then
  echo "$tag needs the module path in go.mod to end in /v$major, not $module" >&2
  exit 1
fi

if ! git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null; then
  if [ -z "$(git config user.email || true)" ]; then
    git config user.name "github-actions[bot]"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
  fi
  git tag -a "$tag" -m "$tag"
  git push origin "$tag"
fi

if ! gh release view "$tag" >/dev/null 2>&1; then
  notes="$(mktemp)"
  awk -v heading="## $version" '
    $0 == heading { found = 1; next }
    found && /^## / { exit }
    found { print }
  ' CHANGELOG.md > "$notes"
  gh release create "$tag" --verify-tag --title "$tag" --notes-file "$notes"
fi

# The first `go get` of a new version otherwise waits on the proxy fetching it.
curl -fs "https://proxy.golang.org/$module/@v/$tag.info" >/dev/null \
  || echo "warning: the module proxy has not picked up $tag yet" >&2
