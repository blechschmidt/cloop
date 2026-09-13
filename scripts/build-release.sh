#!/usr/bin/env bash
#
# Build the release artifacts for a tag, in the exact layout `cloop upgrade`
# expects to find on the GitHub release.
#
# That contract is not a convention this script is free to reinterpret. Two
# independent consumers compute the name they will fetch, and neither can
# discover a rename except by failing:
#
#     cloop_<os>_<arch>.tar.gz
#
#   - `cloop upgrade` (pkg/upgrade/upgrade.go, assetNameFor) resolves it
#     against the releases API and verifies the download against a GNU-style
#     `checksums.txt` published beside it.
#   - The bootstrap installer the hub serves at GET /install.sh
#     (pkg/executor/install/bootstrap.go) fetches it from
#     https://github.com/.../releases/latest/download/<name>.
#
# The name carries NO version, and that is load-bearing rather than cosmetic:
# GitHub's /releases/latest/download/ endpoint resolves a *fixed* asset name
# against whatever release is current. It is the only URL that stays valid
# across releases, so it is the only one a `curl … | sh` installer can hardcode
# — and an installer that has to be re-edited for every tag is an installer
# that is wrong between tags. Versioned archives left that URL pointing at an
# asset no release has ever published, i.e. a permanent 404 (Task 20240). The
# version is not lost by dropping it here: it is stamped into the binary by the
# -X ldflag below, which is what `cloop version` and `cloop upgrade` read.
#
# Rename an artifact and both consumers break for every user at once, with
# errors that point at the release rather than at this file — so
# pkg/upgrade/release_assets_test.go and
# pkg/executor/install/bootstrap_release_test.go both run this script in --list
# mode and fail if any of the three ever disagree.
#
# Usage:
#   scripts/build-release.sh <version> [outdir]   build artifacts into outdir
#   scripts/build-release.sh --list               print artifact names only
#
# --list compiles nothing, and takes no version — because the names do not
# depend on one. It exists so the drift gates above can assert the naming
# without paying for five cross-compilations.

set -euo pipefail

# The platforms a release publishes. Adding one here is all that is needed for
# `cloop upgrade` to start working on it; the test asserts the platform this
# binary is *running* on is present, so dropping one is caught rather than
# silently turning that platform's upgrade into "no release asset found".
#
# linux/arm is armv7 (32-bit Raspberry Pi and similar), built because the
# bootstrap installer maps `uname -m` of armv7l/armv7/armhf onto it. Without an
# asset here that mapping resolves to a URL nothing publishes, so the class of
# device the executor fleet most wants to onboard would be told "download
# failed" — the exact failure this file's header is about.
#
# windows/amd64 is deliberately absent: cloop does not compile for it. The
# process-group supervision it kills harnesses with is POSIX-only and carries
# no build tags (pkg/procgroup, pkg/plugin: syscall.Kill, Setpgid, Getpgid;
# pkg/executor/container: syscall.Stat_t), so GOOS=windows fails at type-check.
# pkg/upgrade knows how to unpack a cloop.exe and the branch below knows how to
# name one, which is what makes this worth stating rather than leaving implied
# — the support is written, the platform is not. Publishing a Windows asset
# would take a port, not a line here.
PLATFORMS=(
  linux/amd64
  linux/arm64
  linux/arm
  darwin/amd64
  darwin/arm64
)

GO="${GO:-go}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# artifact_name mirrors pkg/upgrade.assetNameFor and the URL built by
# pkg/executor/install.BootstrapScript. It deliberately takes no version: see
# the header for why the name has to stay constant across releases.
artifact_name() {
  local os="$1" arch="$2"
  printf 'cloop_%s_%s.tar.gz' "$os" "$arch"
}

if [ "${1:-}" = "--list" ]; then
  for platform in "${PLATFORMS[@]}"; do
    printf '%s\n' "$(artifact_name "${platform%/*}" "${platform#*/}")"
  done
  exit 0
fi

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: $0 <version> [outdir]" >&2
  echo "       $0 --list" >&2
  exit 2
fi

OUTDIR="${2:-$REPO_ROOT/dist/release}"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> building cloop $VERSION for ${#PLATFORMS[@]} platforms"

for platform in "${PLATFORMS[@]}"; do
  os="${platform%/*}"
  arch="${platform#*/}"

  binary="cloop"
  [ "$os" = "windows" ] && binary="cloop.exe"

  workdir="$STAGE/$os-$arch"
  mkdir -p "$workdir"

  # The same flags the container image uses (see Dockerfile): CGO_ENABLED=0 so
  # the binary is static — cloop's only C-adjacent dependency is SQLite and it
  # uses the pure-Go modernc.org/sqlite driver precisely so this holds —
  # -trimpath so build-host paths stay out of it, and the -X that stamps the
  # version. Without that -X the released binary reports "dev", and
  # `cloop upgrade --check` compares "dev" against the latest tag and concludes
  # there is nothing to do, forever.
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    "$GO" build -trimpath \
      -ldflags "-s -w -X github.com/blechschmidt/cloop/pkg/version.Version=$VERSION" \
      -o "$workdir/$binary" \
      "$REPO_ROOT"

  # Shipped beside the binary so the tarball is self-describing. The upgrader
  # matches on filepath.Base and ignores everything that is not the binary, so
  # extra entries are free.
  cp "$REPO_ROOT/README.md" "$REPO_ROOT/LICENSE" "$workdir/"

  archive="$OUTDIR/$(artifact_name "$os" "$arch")"

  # --sort, --owner, --group, --numeric-owner and --mtime together make the
  # archive a function of its contents alone: two builds of the same commit
  # produce byte-identical tarballs, so the checksums below can be compared
  # across builders instead of only within one.
  tar --sort=name \
      --owner=0 --group=0 --numeric-owner \
      --mtime="@0" \
      -czf "$archive" \
      -C "$workdir" .

  echo "    $(basename "$archive")"
done

# GNU-style `sha256sum` output: "<hex>  <filename>". pkg/upgrade.parseChecksums
# reads exactly this, and verifies the downloaded tarball against it before
# unpacking anything.
(cd "$OUTDIR" && sha256sum ./*.tar.gz | sed 's| \./| |' > checksums.txt)

echo "==> wrote $OUTDIR/checksums.txt"
cat "$OUTDIR/checksums.txt"
