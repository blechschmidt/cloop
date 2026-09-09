#!/usr/bin/env bash
# check-docs.sh — structural checks on the documentation tree.
#
# The published site's navigation is generated from docs/README.md
# (scripts/build-docs.py). That makes the map load-bearing: a page nobody links
# from it is a page no reader can reach from the menu. This script enforces the
# direction the generator cannot — that every page under docs/ IS listed —
# so the two together make the map exhaustive rather than merely ordered.
#
# It runs before `mkdocs build --strict` in `make docs-site` and in CI, because
# the errors here name the file and the fix ("docs/foo/bar.md is listed by no
# section") where the same problem surfacing later reads as a missing nav entry.
#
# Checks:
#   1. every *.md under docs/ is linked from docs/README.md
#   2. every docs/*.md link in docs/README.md resolves to a file
#   3. every relative link between documentation pages resolves
#   4. every embedded image resolves
#
# Anchors are not checked here — `mkdocs build --strict` does that against the
# rendered HTML, which is the only place the answer is real.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
err() { printf '  %s\n' "$*" >&2; fail=1; }

# Markdown link targets in a file, one per line, fenced code blocks excluded.
targets() {
  awk '/^[[:space:]]*(```|~~~)/ { fenced = !fenced; next } !fenced' "$1" \
    | grep -oE '\]\([^)#][^)]*\)' \
    | sed -E 's/^\]\(//; s/\)$//; s/[[:space:]]+"[^"]*"$//' \
    || true
}

# ---------------------------------------------------------------- 1 and 2

echo "==> every page under docs/ is listed in docs/README.md"

listed=$(mktemp); trap 'rm -f "$listed"' EXIT
targets docs/README.md \
  | grep -vE '^([a-z][a-z0-9+.-]*:|//)' \
  | sed 's/#.*//' \
  | grep -E '\.md$' \
  | while read -r t; do
      # Targets in docs/README.md are relative to docs/.
      printf '%s\n' "docs/${t}"
    done \
  | sed -E 's#/\./#/#g' \
  | sort -u > "$listed"

while IFS= read -r page; do
  [ "$page" = "docs/README.md" ] && continue
  grep -qxF "$page" "$listed" || err "$page is listed by no section of docs/README.md"
done < <(find docs -name '*.md' | sort)

while IFS= read -r page; do
  [ -f "$page" ] || err "docs/README.md links $page, which does not exist"
done < "$listed"

# ------------------------------------------------------------------- 3, 4

echo "==> every relative link and image between documentation pages resolves"

while IFS= read -r page; do
  dir=$(dirname "$page")
  while IFS= read -r target; do
    case "$target" in
      ''|http:*|https:*|mailto:*|//*) continue ;;
    esac
    path="${target%%#*}"
    [ -z "$path" ] && continue
    resolved=$(cd "$dir" && printf '%s\n' "$(realpath -m --relative-to="$(git rev-parse --show-toplevel)" "$path")")
    if [ ! -e "$resolved" ]; then
      err "$page -> $target does not resolve ($resolved)"
    fi
  done < <(targets "$page")
done < <(find docs -name '*.md' | sort)

# Images are written as ![alt](path) and caught by the same scan above, since
# the trailing ]( is identical; this only reports the count for the log.
images=$(grep -rhoE '!\[[^]]*\]\([^)]*\)' docs --include='*.md' | wc -l)
echo "==> $images embedded images checked"

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "documentation structure check FAILED" >&2
  exit 1
fi

echo "documentation structure check passed"
