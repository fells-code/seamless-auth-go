#!/usr/bin/env bash
# Compares the public API against the last release with gorelease, and fails if it
# changed incompatibly while neither the PR title nor a commit declares a breaking
# change. Pre-1.0, gorelease reports incompatible changes but never fails on them,
# and release-please bumps for a break only when a commit says so.
set -euo pipefail
cd "$(dirname "$0")/.."

base="$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)"
if [ -z "$base" ]; then
  echo "No release tag to compare against."
  exit 0
fi

report="$(go run golang.org/x/exp/cmd/gorelease@v0.0.0-20261007192929-f45ad48fbe92 -base="$base")"
echo "$report"
if ! grep -q '^## incompatible changes' <<<"$report"; then
  exit 0
fi

breaking='^[a-z]+(\([^)]*\))?!:|BREAKING[ -]CHANGE'
if grep -Eq "$breaking" <<<"${PR_TITLE:-}" \
  || git log --format=%B "${BASE_SHA:-$base}..HEAD" | grep -Eq "$breaking"; then
  echo "The incompatible change is declared as breaking."
  exit 0
fi

echo "::error::The public API changed incompatibly since $base. Mark the change as breaking (feat!: in the PR title, or a BREAKING CHANGE: footer), or keep the API compatible."
exit 1
