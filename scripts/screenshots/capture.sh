#!/usr/bin/env bash
#
# capture.sh — regenerate docs/screenshots/ from a throwaway demo hub.
#
#     ./scripts/screenshots/capture.sh
#
# Boots the demo hub (see demo-hub.sh — invented projects, its own CLOOP_HOME,
# its own port), photographs it with headless Chromium, tears the hub down
# again, and leaves the PNGs in docs/screenshots/.
#
# It needs Chromium (or Chrome) and node. Both are developer-box tools: this is
# not wired into CI, because a screenshot that regenerates on every push is a
# binary diff on every push.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HERE="$ROOT/scripts/screenshots"
OUT="$ROOT/docs/screenshots"

find_chrome() {
  local c
  for c in /opt/cft/chrome-linux64/chrome \
           /root/.cache/puppeteer/chrome/linux-*/chrome-linux64/chrome \
           /root/.cache/ms-playwright/chromium-*/chrome-linux64/chrome \
           /root/.cache/ms-playwright/chromium-*/chrome-linux/chrome; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  for c in google-chrome chromium chromium-browser; do
    command -v "$c" >/dev/null 2>&1 && { command -v "$c"; return 0; }
  done
  return 1
}

CHROME=${CHROME:-$(find_chrome || true)}
if [ -z "$CHROME" ]; then
  echo "no Chrome/Chromium found — install one, or set CHROME=/path/to/chrome" >&2
  exit 1
fi
command -v node >/dev/null 2>&1 || { echo "node is required" >&2; exit 1; }

cleanup() { "$HERE/demo-hub.sh" down >/dev/null 2>&1 || true; }
trap cleanup EXIT

BASE=$("$HERE/demo-hub.sh" up | tail -1)
echo "==> capturing from $BASE with $CHROME"
node "$HERE/capture.js" "$CHROME" "$BASE" "$OUT"
