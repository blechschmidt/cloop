#!/usr/bin/env bash
# build-icons.sh — rasterise pkg/ui/assets/icon.svg into the icons the hub serves.
#
# The mark is authored once as an SVG and rendered here into the raster formats
# the clients actually accept. The rasters are committed rather than produced at
# build time: `go build` must work on a machine with no SVG toolchain, and
# //go:embed cannot run a converter.
#
# Why each output exists — see pkg/ui/icons.go for where each one is served:
#
#   favicon.ico           16/32/48  the URL a browser probes with no HTML to go
#                                   on: tabs, bookmarks, history, feed readers.
#   apple-touch-icon.png  180       iOS home screen, and one of the two tags
#                                   Meta Ray-Ban Display reads.
#   icon-192.png          192       <link rel=icon> and the web app manifest.
#   icon-512.png          512       manifest install prompt and splash.
#
# Meta Ray-Ban Display accepts "Unicode symbols or high-resolution PNG favicons
# (>= 52x52 px) via <link> tags or Web App Manifest. SVGs are not supported."
# That floor is why the smallest PNG here is 180 and not 32, and why the SVG
# cannot be the only icon. TestIconsMeetDisplayGlassesRequirements re-checks it
# against the committed bytes.
#
# Rendering each size natively from the vector, rather than downscaling one
# large PNG, keeps the arrowhead crisp at 180. The ICO is the exception: its
# three sizes are downsampled with Lanczos from a 256px render, which
# antialiases a 16px glyph better than rendering 16px directly does.
#
# Usage: make icons   (or ./scripts/build-icons.sh)
#
# Requires rsvg-convert (librsvg2-bin) and Python Pillow. Both are build-time
# only — nothing at run time reads them.

set -euo pipefail

cd "$(dirname "$0")/.."

ASSETS=pkg/ui/assets
SRC=$ASSETS/icon.svg

for tool in rsvg-convert python3; do
	command -v "$tool" >/dev/null || {
		echo "build-icons: $tool is required but not installed" >&2
		echo "  Debian/Ubuntu: apt-get install librsvg2-bin python3-pil" >&2
		exit 1
	}
done
python3 -c 'import PIL' 2>/dev/null || {
	echo "build-icons: Python Pillow is required but not importable" >&2
	exit 1
}
test -f "$SRC" || { echo "build-icons: $SRC is missing" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

render() { rsvg-convert -w "$1" -h "$1" "$SRC" -o "$2"; }

echo "==> rendering $SRC"
render 180 "$tmp/180.png"
render 192 "$tmp/192.png"
render 512 "$tmp/512.png"
render 256 "$tmp/256.png"

# Re-encode through Pillow so the committed bytes do not carry librsvg's
# version string or any other producer metadata: the same SVG must yield the
# same bytes on any machine, or the icons show up in every unrelated diff.
python3 - "$tmp" "$ASSETS" <<'PY'
import sys
from PIL import Image

tmp, assets = sys.argv[1], sys.argv[2]

def flatten(path):
    # The mark is opaque by design (see icon.svg), so drop the alpha channel:
    # it halves the file and removes the "transparent corners" failure mode
    # where a launcher composites the icon onto an unknown background.
    return Image.open(path).convert("RGB")

for src, dst in (("180.png", "apple-touch-icon.png"),
                 ("192.png", "icon-192.png"),
                 ("512.png", "icon-512.png")):
    img = flatten(f"{tmp}/{src}")
    img.save(f"{assets}/{dst}", format="PNG", optimize=True)
    print(f"    {dst:24s} {img.width}x{img.height}")

base = flatten(f"{tmp}/256.png")
base.save(f"{assets}/favicon.ico", format="ICO", sizes=[(16, 16), (32, 32), (48, 48)])
print("    favicon.ico              16x16 32x32 48x48")
PY

# The drift stamp. //go:embed cannot notice that icon.svg was edited without the
# rasters being rebuilt, and a stale icon is exactly the kind of mismatch that
# survives review because nobody opens a PNG in a diff. Recording the source
# digest lets a plain Go test catch it with no rasteriser in CI — see
# TestIconsAreInSyncWithTheirSource.
python3 - "$SRC" "$ASSETS/icon.stamp" <<'PY'
import hashlib, sys
src, dst = sys.argv[1], sys.argv[2]
digest = hashlib.sha256(open(src, "rb").read()).hexdigest()
with open(dst, "w") as fh:
    fh.write("# sha256 of icon.svg at the last run of scripts/build-icons.sh.\n")
    fh.write("# Mismatch means the mark changed but the rasters did not: run `make icons`.\n")
    fh.write(digest + "\n")
print(f"    icon.stamp               {digest[:16]}…")
PY

echo "==> icons written to $ASSETS"
